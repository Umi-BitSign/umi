"""Remote I/O overlap with exact per-object ownership and bounded cache admission."""

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event

import httpx
import pytest

from tests.test_competition_remote_proof_store import EvidenceServer, config, store
from umi.competition_remote_proof_store import RemoteProofReference, RemoteProofStore


class GatedBody(httpx.SyncByteStream):
    def __init__(self, server, name, raw):
        self.server, self.name, self.raw = server, name, raw

    def __iter__(self):
        self.server.entered[self.name].set()
        if self.name == "first":
            assert self.server.release.wait(5), "test read was not released"
        yield self.raw


class GatedServer(EvidenceServer):
    def __init__(self):
        super().__init__()
        self.entered = {name: Event() for name in ("first", "second")}
        self.release = Event()
        self.enabled = False

    def send(self, request):
        name = request.url.path.rsplit("/", 1)[-1]
        response = super().send(request)
        if self.enabled and request.method == "GET" and name in self.entered:
            return httpx.Response(
                response.status_code,
                headers=response.headers,
                stream=GatedBody(self, name, response.content),
            )
        return response


@pytest.mark.parametrize("retained", [False, True])
def test_independent_path_reads_overlap_network_io(tmp_path, retained):
    server = GatedServer()
    writer = store(tmp_path / "writer", server)
    writer.put_bytes(b"first", path="first")
    writer.put_bytes(b"second", path="second")
    reader = writer if retained else store(tmp_path / "reader", server, read_only=True)
    reader.evict_cache()
    server.enabled = True
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reader.read_path, "first", maximum=8)
        try:
            assert server.entered["first"].wait(2)
            second = pool.submit(reader.read_path, "second", maximum=8)
            assert server.entered["second"].wait(1), "unrelated GET serialized behind store lock"
            assert second.result(timeout=2) == b"second"
        finally:
            server.release.set()
        assert first.result(timeout=2) == b"first"


@pytest.mark.parametrize("retained", [False, True])
def test_same_object_waiters_reuse_one_completed_fetch(tmp_path, monkeypatch, retained):
    server = GatedServer()
    writer = store(tmp_path / "writer", server)
    writer.put_bytes(b"first", path="first")
    reader = writer if retained else store(tmp_path / "reader", server, read_only=True)
    reader.evict_cache()
    server.calls.clear()
    server.enabled = True
    waiter = Event()
    original = reader._read_slot
    calls = 0

    @contextmanager
    def observe_slot(key):
        nonlocal calls
        calls += 1
        if calls == (3 if retained else 2):
            waiter.set()
        with original(key):
            yield

    monkeypatch.setattr(reader, "_read_slot", observe_slot)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reader.read_path, "first", maximum=8)
        try:
            assert server.entered["first"].wait(2)
            second = pool.submit(reader.read_path, "first", maximum=8)
            assert waiter.wait(2)
        finally:
            server.release.set()
        assert first.result(timeout=2) == second.result(timeout=2) == b"first"
    assert sum(method == "GET" for method, _ in server.calls) == 1
    assert reader._fetch_bytes == 0 and not reader._read_locks


@pytest.mark.parametrize("fail_first", [False, True])
@pytest.mark.parametrize("retained", [False, True])
def test_inflight_bodies_share_the_cache_bound_and_release_on_failure(
    tmp_path, monkeypatch, fail_first, retained
):
    server = GatedServer()
    writer = store(tmp_path / "writer", server)
    writer.put_bytes(b"first", path="first")
    writer.put_bytes(b"second", path="second")
    reader = RemoteProofStore(
        tmp_path / ("writer" if retained else "reader"),
        config(tmp_path, read_only=True).model_copy(update={"maximum_cache_bytes": 8}),
        client=server.client(),
    )
    original = reader._read_capacity
    admitted_second = Event()

    @contextmanager
    def observe_admission(size):
        if size == 6:
            admitted_second.set()
        with original(size) as release:
            yield release

    monkeypatch.setattr(reader, "_read_capacity", observe_admission)
    server.enabled = True
    server.corrupt_get = fail_first
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reader.read_path, "first", maximum=8)
        try:
            assert server.entered["first"].wait(2)
            assert reader._fetch_bytes == 5 and reader._bytes == 0
            server.corrupt_get = False
            second = pool.submit(reader.read_path, "second", maximum=8)
            assert admitted_second.wait(2)
            assert not server.entered["second"].wait(0.05)
            assert reader._fetch_bytes + reader._bytes <= 8
        finally:
            server.release.set()
        if fail_first:
            with pytest.raises(ValueError):
                first.result(timeout=2)
        else:
            assert first.result(timeout=2) == b"first"
        assert second.result(timeout=2) == b"second"
    assert reader._fetch_bytes == 0 and reader._bytes == 6
    assert not reader._pins and not reader._read_locks


def test_damage_recorded_during_fetch_prevents_cache_installation(tmp_path):
    server = GatedServer()
    reader = store(tmp_path / "reader", server)
    reference = reader.put_bytes(b"first", path="first")
    reader.evict_cache()
    server.enabled = True
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(reader.read_bytes, reference, maximum=8)
        try:
            assert server.entered["first"].wait(2)
            reader._hold(RemoteProofReference.model_validate(reference))
        finally:
            server.release.set()
        with pytest.raises(ValueError, match="repair"):
            future.result(timeout=2)
    assert not reader._cache and not reader._pins and not reader._read_locks
    assert reader._bytes == reader._fetch_bytes == 0
    restarted = store(tmp_path / "reader", server)
    with pytest.raises(ValueError, match="repair"):
        restarted.read_bytes(reference, maximum=8)


def test_concurrent_publication_does_not_double_charge_fetched_bytes(tmp_path):
    server = GatedServer()
    writer = store(tmp_path / "writer", server)
    writer.put_bytes(b"first", path="first")
    reader = store(tmp_path / "reader", server)
    server.enabled = True
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(reader.read_path, "first", maximum=8)
        try:
            assert server.entered["first"].wait(2)
            reader.put_bytes(b"first", path="first")
            assert reader._bytes == 5 and reader._fetch_bytes == 5
        finally:
            server.release.set()
        assert future.result(timeout=2) == b"first"
    assert reader._bytes == 5 and reader._fetch_bytes == 0
    assert len(reader._cache) == 1 and not reader._read_locks


def test_independent_pinned_reads_overlap_network_io(tmp_path):
    server = GatedServer()
    reader = store(tmp_path / "reader", server)
    references = {name: reader.put_bytes(name.encode(), path=name) for name in server.entered}
    reader.evict_cache()
    server.enabled = True
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reader.read_bytes, references["first"], maximum=8)
        try:
            assert server.entered["first"].wait(2)
            second = pool.submit(reader.read_bytes, references["second"], maximum=8)
            assert server.entered["second"].wait(1), "unrelated pin serialized behind store lock"
            assert second.result(timeout=2) == b"second"
        finally:
            server.release.set()
        assert first.result(timeout=2) == b"first"
