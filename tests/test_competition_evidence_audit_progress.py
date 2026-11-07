import asyncio
import hashlib
import sqlite3
import threading
import time
from contextlib import contextmanager

import pytest

from umi.competition_evidence_audit_progress import EvidenceAuditProgress
from umi.competition_reward_handoff import _verify_database_integrity
from umi.competition_reward_handoff_reuse import LegacyHandoffVerification, snapshot_identity
from umi.competition_weights import _recovery_journal_snapshot


@contextmanager
def inventory(tmp_path, count=4):
    path = tmp_path / "source.sqlite3"
    values = [bytes([i]) * 100 for i in range(count)]
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE evidence (sha256 TEXT PRIMARY KEY,body BLOB)")
        db.executemany(
            "INSERT INTO evidence VALUES (?,?)",
            [(hashlib.sha256(v).hexdigest(), v) for v in values],
        )
    path.chmod(0o600)
    snapshot = _recovery_journal_snapshot(path)
    context = {"journal": snapshot_identity(snapshot)}

    def recheck():
        if _recovery_journal_snapshot(path) != snapshot:
            raise ValueError("source changed")

    def reopen():
        return LegacyHandoffVerification._for_preparation(
            tmp_path, b"native-test-binding", {"test": True}
        )

    store = reopen()
    # Completion ownership lives outside the source parent in production. This
    # fixture creates its own metadata before taking the source identity again.
    snapshot = _recovery_journal_snapshot(path)
    context = {"journal": snapshot_identity(snapshot)}
    db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
    db.execute("PRAGMA query_only=ON")
    db.execute("BEGIN")
    reads = []

    def verify(key, size):
        reads.append(key)
        raw = db.execute("SELECT body FROM evidence WHERE sha256=?", (key,)).fetchone()[0]
        assert len(raw) == size and hashlib.sha256(raw).hexdigest() == key

    def run(selected=store):
        with selected.reuse.exclusive():
            EvidenceAuditProgress(selected, context, recheck).run(
                "legacy",
                count,
                db.execute("SELECT sha256,length(body) FROM evidence ORDER BY sha256"),
                verify,
            )

    try:
        yield store, reopen, run, reads, context
    finally:
        db.close()


async def test_interrupted_audit_restores_prefix_without_payload_reads(
    tmp_path, monkeypatch, caplog
):
    with inventory(tmp_path) as (store, reopen, run, reads, _):
        remember = store.remember

        def interrupt(stage, key, context, value):
            remember(stage, key, context, value)
            if value["completed"] == 1:
                raise OSError("after durable first item")

        with monkeypatch.context() as patch:
            patch.setattr(store, "remember", interrupt)
            with pytest.raises(OSError, match="first item"):
                run()
        assert len(reads) == 1
        with caplog.at_level("INFO"):
            run(reopen())
            run(reopen())
        assert len(reads) == len(set(reads)) == 4
        assert "legacy_evidence_legacy_restore" in caplog.text
        assert "legacy_evidence_legacy_audit" in caplog.text
        assert len(list(store.reuse.directory.iterdir())) == 3


@pytest.mark.parametrize("damage", ["missing", "corrupt", "last_key", "count", "context"])
async def test_completed_prefix_damage_requires_repair_without_payload_replay(tmp_path, damage):
    with inventory(tmp_path) as (store, reopen, run, reads, context):
        run()
        key = store._key("evidence_frontier", "legacy")
        path = store.reuse.directory / (key + ".json")
        frontier_context = {
            "inventory": context,
            "kind": "legacy",
            "total": 4,
            "order": "key_asc/1",
        }
        if damage == "missing":
            path.unlink()
        elif damage == "corrupt":
            path.write_bytes(b"damaged")
        else:
            saved = store.load("evidence_frontier", "legacy", frontier_context)
            if damage == "last_key":
                saved["last_key"] = "f" * 64
            elif damage == "count":
                saved["completed"] = 5
            else:
                frontier_context["order"] = "changed"
            store.remember("evidence_frontier", "legacy", frontier_context, saved)
        with pytest.raises(OSError, match="repair required"):
            run(reopen())
        assert len(reads) == 4


@pytest.mark.parametrize("count", [0, 100])
async def test_prefix_storage_is_bounded_independently_of_item_count(tmp_path, count):
    with inventory(tmp_path, count) as (store, reopen, run, reads, _):
        run()
        run(reopen())
        assert len(reads) == count
        assert len(list(store.reuse.directory.iterdir())) == 3


async def test_integrity_check_emits_heartbeats_and_drains_on_cancellation(monkeypatch, caplog):
    from umi import competition_work_progress as progress

    class Database:
        def __init__(self):
            self.started = threading.Event()
            self.handler = None
            self.drained = False

        def set_progress_handler(self, handler, interval):
            self.handler = handler
            if handler is None:
                self.drained = True

        def execute(self, statement):
            assert statement == "PRAGMA quick_check"
            self.started.set()
            while not self.handler():
                time.sleep(0.001)
            raise sqlite3.OperationalError("interrupted")

    class Verification:
        def remember(self, *args):
            pytest.fail("cancelled database check retained a successful verdict")

    monkeypatch.setattr(progress, "_HEARTBEAT_SECONDS", 0.01)
    db = Database()
    with caplog.at_level("INFO"):
        task = asyncio.create_task(
            _verify_database_integrity(db, Verification(), {}, lambda: None, already_checked=False)
        )
        try:
            assert await asyncio.wait_for(asyncio.to_thread(db.started.wait, 1), timeout=2)
            await asyncio.sleep(0.035)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        finally:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert db.drained and db.handler is None
    assert '"stage":"legacy_database_integrity"' in caplog.text
    assert '"state":"running"' in caplog.text
