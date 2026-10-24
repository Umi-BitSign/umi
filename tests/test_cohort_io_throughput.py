"""Real SQLite metadata I/O and shared native verification ownership."""

import asyncio
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import httpx
import pytest

from umi.competition_round_journal import RoundJournal
from umi.competition_verification_reuse import VerificationReuse, verified_replay
from umi.concurrency import run_owned_thread
from umi.protocol import StrictProtocolModel

from .test_competition_chunked_model_backup import reader, restore, selected
from .test_open_competition import policy as policy
from .test_r2_multipart import signer


class ChunkTransport(httpx.AsyncBaseTransport):
    """Exercise native signing, HTTP range checks, pooling and cancellation."""

    def __init__(self, objects, *, block=False):
        self.objects = objects
        self.requests = []
        self.closes = 0
        self.active = 0
        self.block = block
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def handle_async_request(self, request):
        self.requests.append(request)
        assert request.headers["authorization"].startswith("AWS4-HMAC-SHA256 ")
        key = "chunks/" + request.url.path.split("/chunks/", 1)[1]
        raw = self.objects[key]
        headers = {"Content-Length": str(len(raw)), "ETag": '"original-generation"'}
        if request.method == "HEAD":
            return httpx.Response(200, headers=headers)
        assert request.method == "GET"
        assert request.headers["range"] == f"bytes=0-{len(raw) - 1}"
        self.active += 1
        try:
            if self.active == 4:
                self.entered.set()
            if self.block:
                await self.release.wait()
            headers["Content-Range"] = f"bytes 0-{len(raw) - 1}/{len(raw)}"
            return httpx.Response(206, headers=headers, content=raw)
        finally:
            self.active -= 1

    async def aclose(self):
        assert self.active == 0
        self.closes += 1


@pytest.mark.parametrize("operation", ["verify", "materialize"])
async def test_native_chunk_reader_reuses_one_pool_and_completed_bytes(policy, tmp_path, operation):
    from umi.r2_multipart import R2MultipartClient

    case = selected(policy)
    transport = ChunkTransport(case.remote.objects)
    client = R2MultipartClient(signer(), transport=transport)
    actual = reader(case, tmp_path, multipart=client)

    async def run():
        if operation == "verify":
            return await actual.verify()
        return await restore(actual, tmp_path / "archive")

    await run()
    methods = [request.method for request in transport.requests]
    assert methods.count("GET") == len(case.remote.objects)
    # Initial inventory, per-read generation fence and final confirmation remain.
    assert methods.count("HEAD") == 3 * len(case.remote.objects)
    assert transport.closes == 1 and client._connections.client is None
    await run()
    assert sum(request.method == "GET" for request in transport.requests) == methods.count("GET")
    assert transport.closes == 2 and client._connections.client is None


async def test_native_chunk_reader_drains_pool_after_prefetch_cancellation(policy, tmp_path):
    from umi.r2_multipart import R2MultipartClient

    case = selected(policy)
    transport = ChunkTransport(case.remote.objects, block=True)
    client = R2MultipartClient(signer(), transport=transport)
    actual = reader(case, tmp_path, multipart=client)
    task = asyncio.create_task(restore(actual, tmp_path / "archive"))
    try:
        await asyncio.wait_for(transport.entered.wait(), timeout=5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert transport.active == 0
        assert transport.closes == 1 and client._connections.client is None
        assert not list((tmp_path / "archive").glob("*/manifest.json"))
    finally:
        transport.release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.parametrize("encoding", ["UTF-8", "UTF-16"])
def test_byte_accounting_preserves_blob_unicode_numeric_and_null(encoding):
    values = [None, b"", b"\x00\xff", "", "a\x00b", "日本語🙂", 0, -123456789, 1.25, 1e100]
    with sqlite3.connect(":memory:") as db:
        db.execute(f"PRAGMA encoding='{encoding}'")
        for value in values:
            result = db.execute(
                "SELECT "
                + RoundJournal._stored_byte_length("v")
                + ",COALESCE(LENGTH(CAST(v AS BLOB)),0) FROM (SELECT ? AS v)",
                (value,),
            ).fetchone()
            assert result[0] == result[1]


def test_blob_size_accounting_does_not_read_overflow_payload(tmp_path, record_property):
    if not Path("/proc/self/io").exists():
        pytest.skip("Linux per-process byte-read counter qualification")
    path = tmp_path / "metadata.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE metadata (body BLOB)")
        db.executemany("INSERT INTO metadata VALUES (zeroblob(?))", [(8 * 1024**2,)] * 8)

    def measure(expression):
        def reads():
            return int(
                dict(line.split(":", 1) for line in Path("/proc/self/io").read_text().splitlines())[
                    "rchar"
                ]
            )

        with sqlite3.connect(path) as db:
            db.execute("PRAGMA cache_size=-64")
            db.execute("PRAGMA mmap_size=0")
            before = reads()
            value = db.execute("SELECT SUM(" + expression + ") FROM metadata").fetchone()[0]
            return value, reads() - before

    old, old_reads = measure("LENGTH(CAST(body AS BLOB))")
    new, new_reads = measure(RoundJournal._stored_byte_length("body"))
    assert old == new == 64 * 1024**2
    assert old_reads >= 64 * 1024**2
    assert new_reads < old_reads // 4
    record_property("old_query_read_bytes", old_reads)
    record_property("new_query_read_bytes", new_reads)
    record_property("logical_bytes", new)
    print(
        {"old_query_read_bytes": old_reads, "new_query_read_bytes": new_reads, "logical_bytes": new}
    )


class Result(StrictProtocolModel):
    value: int


def test_same_directory_instances_share_first_verification(tmp_path, policy):
    first = VerificationReuse(tmp_path / "shared", owner={"owner": "same"})
    second = VerificationReuse(tmp_path / "shared", owner={"owner": "same"})
    entered, release, started = Event(), Event(), Event()
    calls = []

    @verified_replay("local_shared_owner", Result)
    def calculate(policy):
        calls.append(1)
        entered.set()
        assert release.wait(3)
        return Result(value=7)

    def run(reuse, waiting=False):
        if waiting:
            started.set()
        with reuse.selected():
            return calculate(policy)

    with ThreadPoolExecutor(2) as pool:
        a = pool.submit(run, first)
        assert entered.wait(3)
        b = pool.submit(run, second, True)
        try:
            assert started.wait(3)
            assert not b.done()
        finally:
            release.set()
        assert a.result(3) == b.result(3) == Result(value=7)
    assert calls == [1]


async def test_owned_descendant_can_reenter_shared_directory(tmp_path):
    first = VerificationReuse(tmp_path / "shared", owner={"owner": "same"})
    second = VerificationReuse(tmp_path / "shared", owner={"owner": "same"})

    def child():
        with second.exclusive():
            return "drained"

    with first.exclusive():
        assert await asyncio.wait_for(run_owned_thread(child), 2) == "drained"
