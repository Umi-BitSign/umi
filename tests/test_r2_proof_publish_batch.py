"""Batching changes HTTP transport, not object receipts or frame/replay identity."""

import base64
import hashlib
import hmac
import json
import logging
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import httpx
import pytest

from umi import competition_remote_proof_store as store_module
from umi.competition_reward_proof_archive import RewardProofArchive
from umi.r2_evidence import R2EvidenceClient
from umi.r2_publish_batch import KEY_PURPOSE, PUBLISH_BATCH_PATH
from umi.r2_sigv4 import R2Credentials, R2SigV4, load_r2_credentials

from .test_competition_parallel_proof_publication import objects
from .test_competition_remote_proof_store import EvidenceServer, store

ORIGIN = "https://artifacts.example"


class BatchServer(EvidenceServer):
    def __init__(self):
        super().__init__()
        self.batches = []
        self.batch_failure = None
        self.item_failure = None
        self.mutate = None
        self.lock, self.active, self.peak = Lock(), 0, 0
        self.entered, self.release = None, None

    def client(self):
        previous = super().client()
        signer = previous.signer
        return R2EvidenceClient(
            R2SigV4(
                signer.endpoint,
                signer.bucket,
                R2Credentials(
                    signer.credentials.access_key_id,
                    signer.credentials.secret_access_key,
                    proof_publish_batch_origin=ORIGIN,
                ),
            ),
            transport=httpx.MockTransport(self.send),
        )

    def send(self, request):
        if request.method != "POST":
            return super().send(request)
        assert str(request.url) == ORIGIN + PUBLISH_BATCH_PATH
        purpose = hmac.digest(b"secret-access-key-value", KEY_PURPOSE, "sha256")
        signature = hmac.digest(
            purpose, b"POST\n" + PUBLISH_BATCH_PATH.encode() + b"\n" + request.content, "sha256"
        ).hex()
        assert (
            request.headers["authorization"]
            == "UMI-R2-Proof-Publication/1 0123456789ABCDEF:" + signature
        )
        body = json.loads(request.content)
        assert len(body["objects"]) <= 8 and len(request.content) <= 65536
        with self.lock:
            self.batches.append(body)
            self.active += len(body["objects"])
            self.peak = max(self.peak, self.active)
        try:
            if self.entered is not None:
                self.entered.set()
                assert self.release.wait(5)
            if type(self.batch_failure) is int:
                return httpx.Response(self.batch_failure)
            results = []
            for item in body["objects"]:
                key, raw = item["key"], base64.b64decode(item["content_b64"], validate=True)
                assert hashlib.sha256(raw).hexdigest() == item["sha256"]
                assert key == "proofs/objects/" + item["sha256"]
                if self.item_failure is not None and key.endswith(self.item_failure):
                    results.append(dict(key=key, status=503))
                    continue
                prior = self.objects.setdefault(key, raw)
                if prior != raw:
                    results.append(dict(key=key, status=409))
                else:
                    results.append(
                        dict(
                            key=key,
                            status=200,
                            size_bytes=len(raw),
                            etag=hashlib.md5(raw, usedforsecurity=False).hexdigest(),
                            sha256=item["sha256"],
                        )
                    )
            if self.batch_failure == "lost":
                self.batch_failure = None
                raise httpx.ReadError("private lost response diagnostic", request=request)
            result = dict(
                schema="umi-r2-proof-publication-batch-response/1",
                nonce=body["nonce"],
                endpoint=body["endpoint"],
                bucket=body["bucket"],
                objects=results,
            )
            if self.mutate is not None:
                self.mutate(result)
            return httpx.Response(200, json=result)
        finally:
            with self.lock:
                self.active -= len(body["objects"])


def test_exact_receipts_frame_last_old_reader_and_restart_reuse(tmp_path):
    server = BatchServer()
    selected = store(tmp_path / "owner", server)
    archive = RewardProofArchive(tmp_path / "archive", remote=selected)
    local = RewardProofArchive(tmp_path / "local")
    fields = {"one": b"original", "two": b"also original"}
    key = "ab" * 32
    local.write("history", key, context={}, fields=fields)
    archive.write("history", key, context={}, fields=fields)
    assert len(server.batches) == 1
    assert all("/objects/" in item["key"] for item in server.batches[0]["objects"])
    assert (
        server.objects["proofs/frames/history/" + key]
        == (local.root / "history" / (key + ".json")).read_bytes()
    )
    assert server.calls[-1] == ("PUT", "/umi-proof-artifacts/proofs/frames/history/" + key)
    historical = EvidenceServer()
    historical.objects = dict(server.objects)
    old_reader = RewardProofArchive(
        tmp_path / "old-reader", remote=store(tmp_path / "old-receipts", historical, read_only=True)
    )
    assert old_reader.read("history", key, bounds={"one": 100, "two": 100})[1] == fields
    references = [
        selected.reference_for_path(item["key"].removeprefix("proofs/"))
        for item in server.batches[0]["objects"]
    ]
    assert all(value["schema"] == "umi-r2-proof-reference/1" for value in references)
    server.calls.clear()
    server.batches.clear()
    store(tmp_path / "owner", server).put_many(objects(*fields.values()))
    assert not server.calls and not server.batches


def test_partial_success_retains_receipts_before_failed_fallback_and_restart(tmp_path, caplog):
    server = BatchServer()
    bad = hashlib.sha256(b"bad").hexdigest()
    server.item_failure = server.fail_put_suffix = bad
    selected = store(tmp_path / "owner", server)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"), pytest.raises(OSError):
        selected.put_many(objects(b"good", b"bad"))
    assert selected.reference_for_path("objects/" + hashlib.sha256(b"good").hexdigest()) is not None
    assert any('"stage":"proof_publication_fallback"' in row.message for row in caplog.records)
    server.item_failure = server.fail_put_suffix = None
    server.calls.clear()
    server.batches.clear()
    store(tmp_path / "owner", server).put_many(objects(b"good", b"bad"))
    assert len(server.batches) == 1 and len(server.batches[0]["objects"]) == 1
    assert server.batches[0]["objects"][0]["key"].endswith(bad)


def test_lost_reply_uses_conditional_direct_recovery_then_disables_proxy(tmp_path, caplog):
    server = BatchServer()
    server.batch_failure = "lost"
    selected = store(tmp_path / "owner", server)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        selected.put_many(objects(b"first", b"second"))
        selected.put_many(objects(b"third"))
    assert len(server.batches) == 1
    assert sum(method == "PUT" for method, _ in server.calls) == 3
    assert sum(method == "HEAD" for method, _ in server.calls) == 2
    assert selected._publish_batch_failure == "r2_publish_batch_transport_error"
    assert "private lost response diagnostic" not in caplog.text
    progress = [
        json.loads(row.message)
        for row in caplog.records
        if '"stage":"proof_publication_fallback"' in row.message
        and '"status":"completed"' in row.message
    ]
    assert [p["total_units"] for p in progress] == [2, 1]
    server.calls.clear()
    server.batches.clear()
    store(tmp_path / "owner", server).put_many(objects(b"first", b"second", b"third"))
    assert not server.calls and not server.batches


def test_conflict_keeps_other_success_but_never_falls_back_or_publishes_frame(tmp_path):
    server = BatchServer()
    bad = hashlib.sha256(b"bad").hexdigest()
    server.objects["proofs/objects/" + bad] = b"conflict"
    selected = store(tmp_path / "owner", server)
    with pytest.raises(ValueError, match="conflicts"):
        selected.put_many(objects(b"good", b"bad"))
    assert selected.reference_for_path("objects/" + hashlib.sha256(b"good").hexdigest()) is not None
    assert not server.calls
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0


@pytest.mark.parametrize(
    "change",
    [
        lambda r: r.update(nonce="wrong"),
        lambda r: r.update(bucket="foreign"),
        lambda r: r["objects"][0].update(etag="0" * 32),
        lambda r: r["objects"][0].update(size_bytes=True),
        lambda r: r["objects"].reverse(),
        lambda r: r["objects"].pop(),
        lambda r: r.update(extra=True),
    ],
)
def test_malformed_ack_never_credits_any_receipt_or_silently_falls_back(tmp_path, change):
    server = BatchServer()
    server.mutate = change
    selected = store(tmp_path / "owner", server)
    with pytest.raises(ValueError):
        selected.put_many(objects(b"first", b"second"))
    assert not server.calls
    assert selected.reference_for_path("objects/" + hashlib.sha256(b"first").hexdigest()) is None
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0


def test_batch_and_direct_publish_share_global_admission(tmp_path):
    server = BatchServer()
    server.entered, server.release = Event(), Event()
    selected = store(tmp_path / "owner", server)
    a = objects(*(str(i).encode() for i in range(8)))
    with ThreadPoolExecutor(max_workers=3) as pool:
        first = pool.submit(selected.put_many, a)
        assert server.entered.wait(3)
        second = pool.submit(selected.put_many, objects(b"another"))
        direct = pool.submit(selected.put_bytes, b"direct")
        try:
            with selected._lock:
                assert len(selected._publishing_keys) == 8
                assert selected._publishing_bytes == 8
            assert not second.done() and not direct.done()
        finally:
            server.release.set()
        first.result(5)
        second.result(5)
        direct.result(5)
    assert server.peak <= 8
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0


def test_pending_graph_chunks_keep_eight_item_and_32KiB_payload_bounds(tmp_path):
    server = BatchServer()
    selected = store(tmp_path / "owner", server)
    selected.put_many(objects(*(bytes([i]) * 4096 for i in range(19))))
    assert [len(batch["objects"]) for batch in server.batches] == [8, 8, 3]
    assert server.peak <= 8


def test_explicit_selection_preserves_historical_credential_file(tmp_path):
    raw = b"TOKEN_VALUE=private\nACCESS_KEY_ID=0123456789ABCDEF\nSECRET_ACCESS_KEY=secret-access-key-value\nDEFAULT_ENDPOINT=https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com\n"
    original = tmp_path / "original"
    original.write_bytes(raw)
    original.chmod(0o600)
    candidate = tmp_path / "candidate"
    candidate.write_bytes(raw + b"PROOF_PUBLISH_BATCH_ORIGIN=https://artifacts.example\n")
    candidate.chmod(0o600)
    assert load_r2_credentials(original).credentials.proof_publish_batch_origin is None
    assert load_r2_credentials(candidate).credentials.proof_publish_batch_origin == ORIGIN
    assert original.read_bytes() == raw


def test_failed_dependency_keeps_original_frame_barrier(tmp_path):
    server = BatchServer()
    server.mutate = lambda r: r.update(nonce="wrong")
    archive = RewardProofArchive(tmp_path / "archive", remote=store(tmp_path / "owner", server))
    with pytest.raises(ValueError):
        archive.write("history", "ab" * 32, context={}, fields={"proof": b"original"})
    assert not any("/frames/" in key for key in server.objects)


@pytest.mark.parametrize("failure", [None, "lost", 429, "partial", "conflict", "malformed"])
def test_actual_exchange_counts_and_redaction(tmp_path, caplog, failure):
    server = BatchServer()
    server.batch_failure = failure if failure in ("lost", 429) else None
    if failure == "partial":
        server.item_failure = hashlib.sha256(b"first").hexdigest()
    if failure == "conflict":
        server.objects["proofs/objects/" + hashlib.sha256(b"first").hexdigest()] = b"changed"
    if failure == "malformed":
        server.mutate = lambda r: r.update(nonce="wrong")
    selected = store(tmp_path / "owner", server)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        if failure in ("conflict", "malformed"):
            with pytest.raises(ValueError):
                selected.put_many(objects(b"first", b"second"))
        else:
            selected.put_many(objects(b"first", b"second"))
    events = [
        json.loads(row.message)
        for row in caplog.records
        if '"schema":"umi-r2-proof-publication-exchange/1"' in row.message
    ]
    assert len(events) == 1
    event = events[0]
    assert event["frontend_request_attempts"] == 1
    assert event["frontend_responses"] == (0 if failure == "lost" else 1)
    assert event["total_objects"] == 2 and event["elapsed_seconds"] >= 0
    assert event["http_status"] == (None if failure == "lost" else 429 if failure == 429 else 200)
    assert event["acknowledged_objects"] == (
        2 if failure is None else 1 if failure in ("partial", "conflict") else 0
    )
    assert event["conflicting_objects"] == (1 if failure == "conflict" else 0)
    assert event["unavailable_objects"] == (1 if failure == "partial" else 0)
    assert event["fallback_objects"] == (
        2 if failure in ("lost", 429) else 1 if failure == "partial" else 0
    )
    assert event["unknown_objects"] == (2 if failure in ("lost", 429, "malformed") else 0)
    assert "secret-access-key-value" not in caplog.text and ORIGIN not in caplog.text


def test_interrupted_batch_receipt_transaction_preserves_atomic_individual_completions(tmp_path):
    server = BatchServer()
    selected = store(tmp_path / "owner", server)
    with selected.journal.transaction() as db:
        db.execute(
            "CREATE TRIGGER interrupt_batch BEFORE INSERT ON records "
            "WHEN NEW.kind='remote_proof_object' "
            "BEGIN SELECT RAISE(ABORT,'interrupted batch'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="interrupted batch"):
        selected.put_many(objects(b"first", b"second"))
    assert selected.reference_for_path("objects/" + hashlib.sha256(b"first").hexdigest()) is None
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0
    originals = dict(server.objects)
    with selected.journal.transaction() as db:
        db.execute("DROP TRIGGER interrupt_batch")
    store(tmp_path / "owner", server).put_many(objects(b"first", b"second"))
    assert server.objects == originals
    server.batches.clear()
    server.calls.clear()
    store(tmp_path / "owner", server).put_many(objects(b"first", b"second"))
    assert not server.batches and not server.calls


def test_waiting_batch_observes_disable_before_another_proxy_attempt(tmp_path, monkeypatch):
    server = BatchServer()
    server.batch_failure = 503
    server.entered, server.release = Event(), Event()
    waiting = Event()
    original = store_module.TransferProgress.emit

    def observed(progress, status, *, reason=None):
        if reason == "proof_publication_worker_limit_wait":
            waiting.set()
        return original(progress, status, reason=reason)

    monkeypatch.setattr(store_module.TransferProgress, "emit", observed)
    selected = store(tmp_path / "owner", server)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(selected.put_many, objects(*(str(i).encode() for i in range(8))))
        assert server.entered.wait(3)
        second = pool.submit(selected.put_many, objects(b"another"))
        try:
            assert waiting.wait(3)
        finally:
            server.release.set()
        first.result(5)
        second.result(5)
    assert len(server.batches) == 1
    assert selected._publishing_keys == set() and selected._publishing_bytes == 0


def test_failed_telemetry_sink_cannot_undo_acknowledged_publication(tmp_path, monkeypatch):
    from umi import r2_publish_batch

    def fail(*_args, **_kwargs):
        raise RuntimeError("broken diagnostic sink")

    server = BatchServer()
    selected = store(tmp_path / "owner", server)
    monkeypatch.setattr(r2_publish_batch._LOG, "info", fail)
    selected.put_many(objects(b"original"))
    assert (
        selected.reference_for_path("objects/" + hashlib.sha256(b"original").hexdigest())
        is not None
    )
