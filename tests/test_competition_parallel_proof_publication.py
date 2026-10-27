"""Concurrent immutable transfer, unchanged retries and bounded admission."""

import hashlib
import json
import logging
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier, Event, Lock, get_ident

import httpx
import pytest

from umi import competition_remote_proof_store as transport
from umi import competition_reward_proof_archive as archive_module
from umi import competition_transport_verification as transfer_module
from umi.competition_evidence_codec import encode_evidence
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


def test_two_maximum_objects_share_the_active_byte_window(tmp_path, monkeypatch):
    class Server(EvidenceServer):
        def __init__(self):
            super().__init__()
            self.barrier = Barrier(2)

        def send(self, request):
            if request.method == "PUT":
                self.barrier.wait(timeout=3)
            return super().send(request)

    selected = store(tmp_path / "owner", Server())
    monkeypatch.setattr(transport, "MAX_PROOF_OBJECT_BYTES", 10)
    monkeypatch.setattr(transport, "MAX_ACTIVE_PROOF_PUBLICATION_BYTES", 20)
    selected.put_many(objects(b"1234567890", b"abcdefghij"))
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0


def test_each_lane_reuses_and_closes_its_own_http_client(tmp_path, monkeypatch, caplog):
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
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        selected.put_many(objects(*(str(i).encode() for i in range(12))))
    assert len(clients) == 8
    assert all(client.is_closed for _, client in clients)
    assert len({id(client) for _, client in clients}) == len(clients)
    completed = [
        json.loads(record.message)
        for record in caplog.records
        if '"stage":"proof_graph_replication"' in record.message
        and '"status":"completed"' in record.message
    ]
    assert len(completed) == 1
    assert completed[0]["completed_operations"] == completed[0]["total_operations"] == 12
    assert completed[0]["native_operations"] == 12


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
    monkeypatch.setattr(transport, "MAX_ACTIVE_PROOF_PUBLICATION_BYTES", 10)
    original = transport.TransferProgress.emit

    def observed(progress, state, *, reason=None):
        if reason == "proof_publication_byte_budget_wait":
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


def test_encoded_copy_batches_small_graphs_and_reuses_first_batch_after_failure(
    tmp_path, monkeypatch
):
    server = EvidenceServer()
    selected = store(tmp_path / "owner", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=selected)
    monkeypatch.setattr(archive_module, "MAX_EVIDENCE_BYTES", 1024)
    monkeypatch.setattr(archive_module, "MAX_PROOF_OBJECT_BYTES", 2048)
    values = [str(i).encode() * 500 for i in range(4)]
    encoded = [encode_evidence(raw, kind="proof") for raw in values]
    objects = {sha: raw for part in encoded for sha, raw in part.objects.items()}
    parts = tuple(
        (part.sha256, len(raw), part.recipe) for raw, part in zip(values, encoded, strict=True)
    )
    original = selected.put_many
    batches = []

    def interrupted(items):
        batches.append(tuple(items))
        if len(batches) == 2:
            raise OSError("interrupted second batch")
        original(items)

    monkeypatch.setattr(selected, "put_many", interrupted)
    kwargs = dict(context={}, fields={f"field{i}": (part,) for i, part in enumerate(parts)})
    with pytest.raises(OSError, match="interrupted second batch"):
        archive.copy_encoded_transport(
            "history", "ab" * 32, resolve=lambda sha, size: objects[sha], **kwargs
        )
    assert [len(batch) for batch in batches] == [6, 2]
    assert not any("/frames/" in key for key in server.objects)

    monkeypatch.setattr(selected, "put_many", original)
    resolved = []

    def resolve(sha, size):
        resolved.append(sha)
        return objects[sha]

    assert archive.copy_encoded_transport("history", "ab" * 32, resolve=resolve, **kwargs)
    assert resolved == [encoded[-1].sha256]
    readback = archive.read("history", "ab" * 32, bounds={f"field{i}": 500 for i in range(4)})[1]
    assert [readback[f"field{i}"] for i in range(4)] == values


def test_write_batches_fields_and_recipes_before_exact_frame_barrier(tmp_path, monkeypatch):
    server = EvidenceServer()
    selected = store(tmp_path / "owner", server)
    local = RewardProofArchive(tmp_path / "local")
    remote = RewardProofArchive(tmp_path / "remote", remote=selected)
    fields = {f"field{i}": str(i).encode() * 50 for i in range(4)}
    key = "ab" * 32
    local.write("history", key, context={"height": 1}, fields=fields)
    batches, original = [], selected.put_many

    def publish(items):
        assert "proofs/frames/history/" + key not in server.objects
        batches.append(dict(items))
        original(items)

    monkeypatch.setattr(selected, "put_many", publish)
    remote.write("history", key, context={"height": 1}, fields=fields)
    assert len(batches) == 1 and len(batches[0]) == 8
    assert (
        server.objects["proofs/frames/history/" + key]
        == (local.root / "history" / (key + ".json")).read_bytes()
    )


def test_archive_pending_batch_bounds_and_maximum_object(monkeypatch):
    from types import SimpleNamespace

    batches = []
    remote = SimpleNamespace(put_many=lambda items: batches.append(dict(items)))
    monkeypatch.setattr(archive_module, "MAX_PROOF_OBJECT_BYTES", 10)
    monkeypatch.setattr(archive_module, "_MAX_REMOTE_BATCH_OBJECTS", 2)
    batch = archive_module._RemotePublicationBatch(remote)
    for raw in (b"a", b"b", b"c", b"d" * 9, b"e" * 10):
        batch.retain(raw)
    batch.flush()
    assert [list(items.values()) for items in batches] == [
        [b"a", b"b"],
        [b"c", b"d" * 9],
        [b"e" * 10],
    ]
    with pytest.raises(ValueError):
        batch.retain(b"x" * 11)
    assert not batch.objects


def test_restored_graph_uses_bounded_snapshots_without_workers_or_http(
    tmp_path, monkeypatch, caplog
):
    server = EvidenceServer()
    values = objects(*(f"object-{i}".encode() for i in range(257)))
    store(tmp_path / "owner", server).put_many(values)
    reopened = store(tmp_path / "owner", server)
    original = reopened.journal.read_transaction
    snapshots = []

    @contextmanager
    def transaction():
        snapshots.append(1)
        with original() as db:
            yield db

    def forbidden(*args, **kwargs):
        raise AssertionError("completed graph must not create publication workers or HTTP clients")

    monkeypatch.setattr(reopened.journal, "read_transaction", transaction)
    monkeypatch.setattr(transport, "ThreadPoolExecutor", forbidden)
    monkeypatch.setattr(reopened.client, "_new_client", forbidden)
    server.calls.clear()
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        reopened.put_many(values)
    assert len(snapshots) == 2 and not server.calls
    completed = [
        json.loads(record.message)
        for record in caplog.records
        if '"stage":"proof_graph_replication"' in record.message
        and '"status":"completed"' in record.message
    ]
    assert len(completed) == 1
    assert completed[0]["completed_operations"] == 257
    assert completed[0]["native_operations"] == 0


@pytest.mark.parametrize("damage", ["missing_receipt", "observed_corruption"])
def test_restored_graph_preserves_explicit_repair_fences(tmp_path, damage):
    server = EvidenceServer()
    selected = store(tmp_path / "owner", server)
    raw = b"original"
    reference = selected.put_bytes(raw)
    if damage == "missing_receipt":
        key = hashlib.sha256(reference["key"].encode()).hexdigest()
        with selected.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,))
    else:
        selected.evict_cache()
        server.corrupt_get = True
        with pytest.raises(ValueError):
            selected.read_bytes(reference, maximum=len(raw))
        server.corrupt_get = False
    reopened = store(tmp_path / "owner", server)
    server.calls.clear()
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        reopened.put_many(objects(raw))
    assert not server.calls


def test_restored_graph_rejects_mismatched_supplied_bytes(tmp_path):
    server = EvidenceServer()
    selected = store(tmp_path / "owner", server)
    selected.put_many(objects(b"original"))
    server.calls.clear()
    with pytest.raises(ValueError, match="content identity"):
        selected.put_many({hashlib.sha256(b"original").hexdigest(): b"modified"})
    assert not server.calls


@pytest.mark.parametrize("encoded_copy", [False, True])
@pytest.mark.parametrize("failure", [False, True])
def test_export_wall_time_spans_dependency_publication_and_frame(
    tmp_path, monkeypatch, caplog, encoded_copy, failure
):
    now = [100.0]
    monkeypatch.setattr(transfer_module.time, "monotonic", lambda: now[0])
    server = EvidenceServer()
    selected = store(tmp_path / "owner", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=selected)
    put_many, put_bytes = selected.put_many, selected.put_bytes

    def dependencies(items):
        now[0] += 3
        if failure:
            raise OSError("dependency publication interrupted")
        return put_many(items)

    def frame(raw, **kwargs):
        assert kwargs["path"].startswith("frames/")
        now[0] += 2
        return put_bytes(raw, **kwargs)

    monkeypatch.setattr(selected, "put_many", dependencies)
    monkeypatch.setattr(selected, "put_bytes", frame)
    raw, key = b"original", "ab" * 32

    def publish():
        if encoded_copy:
            encoded = encode_evidence(raw, kind="proof")
            return archive.copy_encoded_transport(
                "history",
                key,
                context={},
                fields={"proof": ((encoded.sha256, len(raw), encoded.recipe),)},
                resolve=lambda sha, size: encoded.objects[sha],
            )
        return archive.write("history", key, context={}, fields={"proof": raw})

    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        if failure:
            with pytest.raises(OSError, match="dependency publication interrupted"):
                publish()
        else:
            publish()
    scopes = [
        json.loads(record.message)
        for record in caplog.records
        if '"stage":"proof_archive_export"' in record.message
    ]
    assert scopes[-1]["elapsed_seconds"] == (3 if failure else 5)
    assert scopes[-1]["status"] == ("retrying" if failure else "completed")
    assert scopes[-1]["completed_units"] == (0 if failure else 1)


def test_normal_encoding_fallback_does_not_report_interrupted_or_completed_export(tmp_path, caplog):
    raw = b'{"code":"0x' + b"ab" * 4096 + b'","block":123}'
    archive = RewardProofArchive(tmp_path / "archive")
    key = "ab" * 32
    archive.write("history", key, context={}, fields={"proof": raw})
    alternate = encode_evidence(raw, kind="proof", single_object=True)

    def forbidden(*args):
        raise AssertionError("normal compatibility fallback must not resolve or publish objects")

    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        copied = archive.copy_encoded_transport(
            "history",
            key,
            context={},
            fields={"proof": ((alternate.sha256, len(raw), alternate.recipe),)},
            resolve=forbidden,
        )
    assert copied is False
    assert not any('"stage":"proof_archive_export"' in record.message for record in caplog.records)
    assert archive.read("history", key, bounds={"proof": len(raw)}) == ({}, {"proof": raw})
