"""Exercise the actual chunk reader across legacy and batched metadata routes."""

import asyncio
import hashlib
import json
from collections import Counter
from urllib.parse import unquote

import httpx
import pytest

from umi.competition_chunked_model_backup import ChunkedModelBackupReader
from umi.r2_multipart import R2MultipartClient
from umi.r2_sigv4 import R2Credentials, R2SigV4

from .test_competition_chunked_model_backup import (
    backup as backup,
)
from .test_competition_chunked_model_backup import (
    policy as policy,
)
from .test_competition_chunked_model_backup import (
    selection,
)


class Provider:
    def __init__(self, case):
        self.case = case
        self.calls = Counter()
        self.batch_status = 200
        self.unavailable = set()
        self.wrong_generation = False

    def handle(self, request):
        if request.url.host == "metadata.example":
            self.calls["batch"] += 1
            if self.batch_status != 200:
                return httpx.Response(self.batch_status)
            body = json.loads(request.content)
            values = []
            for key in body["keys"]:
                raw = self.case.remote.objects.get(key)
                if key in self.unavailable:
                    values.append(dict(key=key, status=503))
                elif raw is None:
                    values.append(dict(key=key, status=404))
                else:
                    values.append(
                        dict(
                            key=key,
                            status=200,
                            size_bytes=len(raw),
                            etag="wrong-generation"
                            if self.wrong_generation
                            else self.case.remote.etags[key],
                        )
                    )
            return httpx.Response(
                200,
                json=dict(
                    schema="umi-r2-head-batch-response/1",
                    nonce=body["nonce"],
                    endpoint=body["endpoint"],
                    bucket=body["bucket"],
                    objects=values,
                ),
            )
        key = unquote(request.url.path).removeprefix("/" + self.case.remote.signer.bucket + "/")
        raw = self.case.remote.objects.get(key)
        if raw is None:
            return httpx.Response(404)
        if request.method == "HEAD":
            self.calls["head"] += 1
            return httpx.Response(
                200,
                headers={
                    "content-length": str(len(raw)),
                    "etag": '"' + self.case.remote.etags[key] + '"',
                },
            )
        assert request.method == "GET"
        self.calls["get"] += 1
        bounds = request.headers["range"].removeprefix("bytes=").split("-")
        start, end = map(int, bounds)
        return httpx.Response(
            206,
            content=raw[start : end + 1],
            headers={
                "content-range": f"bytes {start}-{end}/{len(raw)}",
                "etag": self.case.remote.etags[key],
            },
        )

    def reader(self, root, *, batch, handler=None):
        signer = R2SigV4(
            self.case.remote.signer.endpoint,
            self.case.remote.signer.bucket,
            R2Credentials("A" * 20, "S" * 40, "https://metadata.example" if batch else None),
        )
        client = R2MultipartClient(signer, transport=httpx.MockTransport(handler or self.handle))
        return ChunkedModelBackupReader(
            selection(self.case), policy=self.case.policy, multipart=client, verification_root=root
        )


async def test_transport_upgrade_reuses_all_completed_native_files_and_documents(backup, tmp_path):
    provider = Provider(backup)
    before = await provider.reader(tmp_path, batch=False).verify(
        document_paths=("license.txt", "provenance.txt")
    )
    counts = provider.calls.copy()
    after = await provider.reader(tmp_path, batch=True).verify(
        document_paths=("license.txt", "provenance.txt")
    )
    assert after == before
    assert provider.calls["get"] == counts["get"]
    assert provider.calls["head"] == counts["head"]
    assert provider.calls["batch"] == 2


async def test_item_failure_falls_back_only_that_item_and_never_rehashes_payload(backup, tmp_path):
    provider = Provider(backup)
    await provider.reader(tmp_path, batch=False).verify()
    counts = provider.calls.copy()
    provider.unavailable.add(next(iter(backup.remote.objects)))
    await provider.reader(tmp_path, batch=True).verify()
    assert provider.calls["get"] == counts["get"]
    assert provider.calls["head"] - counts["head"] == 2
    assert provider.calls["batch"] == 2


async def test_bad_proxy_has_one_attempt_per_scan_and_preserves_native_concurrency(
    backup, tmp_path
):
    provider = Provider(backup)
    provider.batch_status = 403
    reader = provider.reader(tmp_path, batch=True)
    reader.metadata_workers = 4
    prototype = next(iter(reader.chunks.values()))
    chunks = {}
    for number in range(40):
        sha = hashlib.sha256(str(number).encode()).hexdigest()
        chunk = prototype.model_copy(update={"sha256": sha, "size_bytes": 1})
        key = reader._key(chunk)
        backup.remote.objects[key] = b"x"
        backup.remote.etags[key] = "generation"
        chunks[sha] = chunk
    events = []
    async with reader.multipart.connection_scope():
        values = await reader._heads(events.append, chunks)
    assert len(values) == 40 and provider.calls == {"batch": 1, "head": 40}
    assert any(v.get("reason_code") == "r2_batch_http_403_fallback_s3" for v in events)
    assert events[-1]["completed_units"] == 40 and events[-1]["status"] == "completed"


async def test_changed_generation_is_not_hidden_by_fallback(backup, tmp_path):
    provider = Provider(backup)
    await provider.reader(tmp_path, batch=False).verify()
    counts = provider.calls.copy()
    provider.wrong_generation = True
    with pytest.raises(ValueError, match="changed"):
        await provider.reader(tmp_path, batch=True).verify()
    assert provider.calls["batch"] == 1
    assert provider.calls["get"] == counts["get"] + 1


async def test_cancelled_batch_drains_request_before_releasing_transport(backup, tmp_path):
    provider = Provider(backup)
    entered = asyncio.Event()
    active = 0

    async def handler(request):
        nonlocal active
        active += 1
        entered.set()
        try:
            await asyncio.Future()
        finally:
            active -= 1

    reader = provider.reader(tmp_path, batch=True, handler=handler)
    async with reader.multipart.connection_scope():
        task = asyncio.create_task(reader._heads(None))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert active == 0
    assert reader.multipart._connections.client is None


async def test_proxy_failure_drains_direct_fallback_and_preserves_concurrency(backup, tmp_path):
    provider = Provider(backup)
    provider.batch_status = 503
    active = maximum = 0

    async def handler(request):
        nonlocal active, maximum
        if request.method != "HEAD":
            return provider.handle(request)
        active += 1
        maximum = max(maximum, active)
        try:
            await asyncio.sleep(0)
            return provider.handle(request)
        finally:
            active -= 1

    reader = provider.reader(tmp_path, batch=True, handler=handler)
    reader.metadata_workers = 2
    events = []
    async with reader.multipart.connection_scope():
        values = await reader._heads(events.append)
    assert len(values) == len(reader.chunks)
    assert maximum == 2 and active == 0 and provider.calls["batch"] == 1
    assert any(v.get("reason_code") == "r2_batch_http_503_fallback_s3" for v in events)
    assert events[-1]["completed_units"] == len(reader.chunks)
