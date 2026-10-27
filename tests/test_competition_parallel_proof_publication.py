"""Concurrent immutable transfer, unchanged retries and bounded admission."""

import hashlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier, Event, Lock, get_ident

import httpx
import pytest

from umi import competition_remote_proof_store as transport
from umi.competition_reward_proof_archive import RewardProofArchive

from .test_competition_remote_proof_store import EvidenceServer, store


def objects(*values):
    return {hashlib.sha256(raw).hexdigest(): raw for raw in values}


def test_independent_uploads_overlap_outside_the_receipt_lock(tmp_path):
    class Server(EvidenceServer):
        def __init__(self):
            super().__init__()
            self.barrier = Barrier(2)
            self.lock, self.active, self.peak = Lock(), 0, 0

        def send(self, request):
            if request.method != "PUT":
                return super().send(request)
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
            try:
                self.barrier.wait(timeout=3)
                return super().send(request)
            finally:
                with self.lock:
                    self.active -= 1

    server = Server()
    selected = store(tmp_path / "owner", server)
    selected.put_many(objects(b"first", b"second"))
    assert server.peak == 2
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0


def test_each_lane_reuses_and_closes_its_own_http_client(tmp_path, monkeypatch):
    selected = store(tmp_path / "owner", EvidenceServer())
    original = selected.client._new_client
    clients = []
    lock = Lock()

    @contextmanager
    def owned():
        with original() as client:
            with lock:
                clients.append((get_ident(), client))
            yield client

    monkeypatch.setattr(selected.client, "_new_client", owned)
    selected.put_many(objects(*(str(i).encode() for i in range(12))))
    assert len(clients) == 8
    assert all(client.is_closed for _, client in clients)
    assert len({id(client) for _, client in clients}) == len(clients)


def test_failed_graph_reuses_completed_objects_after_restart(tmp_path):
    good = hashlib.sha256(b"good").hexdigest()
    bad = hashlib.sha256(b"bad").hexdigest()

    class Server(EvidenceServer):
        def __init__(self):
            super().__init__()
            self.completed_good = Event()

        def send(self, request):
            if request.method == "PUT" and request.url.path.endswith(bad):
                assert self.completed_good.wait(3)
            response = super().send(request)
            if (
                request.method == "HEAD"
                and request.url.path.endswith(good)
                and response.status_code == 200
            ):
                self.completed_good.set()
            return response

    server = Server()
    server.fail_put_suffix = bad
    selected = store(tmp_path / "owner", server)
    with pytest.raises(OSError):
        selected.put_many(objects(b"good", b"bad"))
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0
    server.fail_put_suffix = None
    server.calls.clear()
    restarted = store(tmp_path / "owner", server)
    restarted.put_many(objects(b"good", b"bad"))
    assert server.calls and all(path.endswith(bad) for _, path in server.calls)
    server.calls.clear()
    store(tmp_path / "owner", server).put_many(objects(b"good", b"bad"))
    assert not server.calls


def test_aggregate_byte_admission_waits_and_still_admits_a_maximum_object(tmp_path, monkeypatch):
    entered, release, waiting = Event(), Event(), Event()

    class Server(EvidenceServer):
        def send(self, request):
            if request.method == "PUT" and not entered.is_set():
                entered.set()
                assert release.wait(3)
            return super().send(request)

    selected = store(tmp_path / "owner", Server())
    monkeypatch.setattr(transport, "MAX_PROOF_OBJECT_BYTES", 10)
    original = transport.TransferProgress.emit

    def observed(progress, state, *, reason=None):
        if reason == "bounded_proof_publication_admission":
            waiting.set()
        return original(progress, state, reason=reason)

    monkeypatch.setattr(transport.TransferProgress, "emit", observed)
    with ThreadPoolExecutor(max_workers=1) as caller:
        result = caller.submit(selected.put_many, objects(b"12345678", b"abcdefgh"))
        try:
            assert entered.wait(3) and waiting.wait(3)
            with selected._lock:
                assert selected._publishing_bytes == 8
                assert len(selected._publishing_keys) == 1
        finally:
            release.set()
        result.result(timeout=3)
    selected.put_bytes(b"0123456789")
    assert selected._publishing_bytes == 0


def test_failed_dependency_does_not_publish_a_frame(tmp_path, monkeypatch):
    server = EvidenceServer()
    selected = store(tmp_path / "owner", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=selected)

    def refuse(_objects):
        raise httpx.ReadError("interrupted dependency transfer")

    monkeypatch.setattr(selected, "put_many", refuse)
    with pytest.raises(httpx.ReadError):
        archive.write("history", "ab" * 32, context={}, fields={"control": b"original"})
    assert not any("/frames/" in key for key in server.objects)
