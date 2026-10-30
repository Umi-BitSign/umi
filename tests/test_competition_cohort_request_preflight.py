"""Held historical owners refuse before repeating prepared-round validation."""

import asyncio
import shutil
import sqlite3
from pathlib import Path
from types import SimpleNamespace

import pytest

import umi.competition_cohort_lifecycle as lifecycle
import umi.competition_cohort_lifecycle_host as host
import umi.competition_cohort_request_preflight as preflight
import umi.competition_round_journal as rounds
from umi.competition_cohort_public_progress import CohortProgressSnapshots
from umi.open_competition import digest

COHORT = "12" * 32
BINDING = {"schema": "umi-cohort-request-owner/1", "series": "34" * 32, "cohort": COHORT}
CAPACITY = 1024**2


def owner(root, *, reserved=False, binding=BINDING):
    journal = rounds.RoundJournal(root, binding, maximum_rounds=65536, maximum_bytes=CAPACITY)
    if reserved:
        journal.reserve_records(
            "original", (rounds.RecordReservation("request_phase_binding", COHORT, 1024),)
        )
    journal.put("request_phase_binding", COHORT, {"original": True})
    return journal


def check(root, *, binding=BINDING):
    return preflight.preflight_request_owner(root, binding, COHORT, maximum_bytes=CAPACITY)


def retained(root):
    return {path.name: path.read_bytes() for path in root.iterdir()}


@pytest.mark.parametrize("reserved", [False, True], ids=["journal0", "journal2"])
def test_repeat_read_only_preflight_preserves_native_journal(tmp_path, monkeypatch, reserved):
    journal = owner(tmp_path / "requests", reserved=reserved)
    before = retained(journal.root)

    def no_mkdir(*_args, **_kwargs):
        pytest.fail("read-only preflight attempted to create a directory")

    monkeypatch.setattr(Path, "mkdir", no_mkdir)
    for _ in range(2):
        assert check(journal.root) is None
    assert retained(journal.root) == before


def test_missing_owner_does_not_create_initialization_paths(tmp_path):
    root = tmp_path / "not-created" / "cohort" / "requests"
    assert check(root) is None
    assert not root.parent.parent.exists()


def test_legacy_journal_without_capacity_counters_is_read_without_migration(tmp_path):
    journal = owner(tmp_path / "requests")
    with journal.transaction() as db:
        for name in rounds._capacity_triggers():
            db.execute('DROP TRIGGER "' + name + '"')
        for name in rounds._CAPACITY_TABLES:
            db.execute('DROP TABLE "' + name + '"')
        db.execute("PRAGMA application_id=0")
    before = retained(journal.root)
    check(journal.root)
    assert retained(journal.root) == before


@pytest.mark.parametrize(
    "damage", ["empty", "missing_lock", "wrong_binding", "header", "missing_index"]
)
def test_existing_incomplete_or_changed_owner_refuses_without_mutation(tmp_path, damage):
    root = tmp_path / "requests"
    if damage == "empty":
        root.mkdir(mode=0o700)
    else:
        journal = owner(
            root, binding={**BINDING, "series": "56" * 32} if damage == "wrong_binding" else BINDING
        )
        if damage == "missing_lock":
            journal.lock_path.unlink()
        elif damage == "header":
            journal.path.write_bytes(b"not a database")
        elif damage == "missing_index":
            with journal.transaction() as db:
                db.execute("DROP INDEX records_capacity_lengths")
    before = retained(root)
    with pytest.raises(preflight.RequestOwnerRepairRequired) as result:
        check(root)
    assert result.value.reason_code in {
        "request_owner_journal_incomplete",
        "request_owner_binding_changed",
        "request_owner_journal_invalid",
    }
    assert retained(root) == before


@pytest.mark.parametrize("reserved", [False, True], ids=["journal0", "journal2"])
def test_native_hold_is_preserved_and_never_read_through(tmp_path, reserved):
    journal = owner(tmp_path / "requests", reserved=reserved)
    with pytest.raises(ValueError, match="conflict retained"):
        journal.put("request_phase_binding", COHORT, {"changed": True})
    before = retained(journal.root)
    for _ in range(2):
        with pytest.raises(preflight.RequestOwnerRepairRequired) as result:
            check(journal.root)
        assert result.value.reason_code == "request_owner_conflict_held"
        with pytest.raises(ValueError, match="conflict held"):
            journal.get("request_phase_binding", COHORT)
    assert retained(journal.root) == before


def test_current_canonical_corruption_is_not_reused_after_success(tmp_path):
    journal = owner(tmp_path / "requests")
    check(journal.root)
    with journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=? AND id=?",
            (b'{ "original":true}', "request_phase_binding", COHORT),
        )
    before = retained(journal.root)
    with pytest.raises(preflight.RequestOwnerRepairRequired, match="journal_invalid"):
        check(journal.root)
    assert retained(journal.root) == before


def test_live_rollback_writer_allows_committed_read_only_snapshot(tmp_path):
    journal = owner(tmp_path / "requests")
    with journal.transaction() as db:
        db.execute("INSERT INTO records VALUES ('other','uncommitted',?)", (b"{}",))
        assert Path(str(journal.path) + "-journal").exists()
        check(journal.root)
    assert journal.get("other", "uncommitted") == {}
    check(journal.root)


def test_exclusive_writer_is_retryable_and_not_latched_as_repair(tmp_path, monkeypatch):
    journal = owner(tmp_path / "requests")
    native_read = rounds.RoundJournal.read_transaction
    monkeypatch.setattr(
        preflight._RequestOwnerReadOnly,
        "read_transaction",
        lambda self: native_read(self, wait=False),
    )
    with sqlite3.connect(journal.path, isolation_level=None) as db:
        db.execute("BEGIN EXCLUSIVE")
        try:
            with pytest.raises(sqlite3.OperationalError) as result:
                check(journal.root)
            code = getattr(result.value, "sqlite_errorcode", None)
            if code is None:  # Python 3.10 exposes SQLite errors only through their message.
                assert str(result.value) == "database is locked"
            else:
                assert code & 0xFF == sqlite3.SQLITE_BUSY
        finally:
            db.rollback()
    check(journal.root)


def test_disappearing_read_only_root_is_never_recreated(tmp_path, monkeypatch):
    journal = owner(tmp_path / "requests")
    native_private = rounds._private

    def vanished(path, **kwargs):
        assert kwargs == {"create": False}
        shutil.rmtree(path)
        return native_private(path, **kwargs)

    monkeypatch.setattr(rounds, "_private", vanished)
    with pytest.raises(FileNotFoundError):
        check(journal.root)
    assert not journal.root.exists()


@pytest.mark.parametrize("state", ["new", "retained", "held"])
def test_host_preflight_precedes_large_declaration_and_preserves_later_read(
    tmp_path, monkeypatch, state
):
    node = host.LifecycleHost.__new__(host.LifecycleHost)
    node.root = tmp_path / "lifecycle"
    node.service = SimpleNamespace(config=SimpleNamespace(series={"selected": "series"}))
    node.config = SimpleNamespace(
        maximum_state_bytes=CAPACITY,
        sources=SimpleNamespace(round_directory=str(tmp_path / "rounds")),
    )
    node.declaration_bytes = 1024
    binding = {**BINDING, "series": digest(node.service.config.series)}
    root = node.root / COHORT / "requests"
    if state != "new":
        journal = owner(root, binding=binding)
        if state == "held":
            with pytest.raises(ValueError, match="conflict retained"):
                journal.put("request_phase_binding", COHORT, {"changed": True})
    reads = []

    def declaration(*args, **kwargs):
        reads.append((args, kwargs))
        raise RuntimeError("full declaration validation still required")

    monkeypatch.setattr(host, "read_private_model", declaration)
    monkeypatch.setattr(host, "authorize_memory", lambda *_args: None)
    if state == "held":
        with pytest.raises(preflight.RequestOwnerRepairRequired, match="conflict_held"):
            node._request_source(COHORT)
        assert reads == []
    else:
        with pytest.raises(RuntimeError, match="full declaration validation still required"):
            node._request_source(COHORT)
        assert len(reads) == 1
        if state == "new":
            assert not root.exists()


@pytest.mark.asyncio
@pytest.mark.parametrize("repair", [False, True], ids=["busy_retry", "repair_required"])
async def test_lifecycle_reports_native_repair_separately_and_clears_it_on_next_success(
    monkeypatch, repair
):
    node = lifecycle.CohortLifecycleService.__new__(lifecycle.CohortLifecycleService)
    for name, value in {
        "cohort": COHORT,
        "phase": "requests",
        "stage": "phase_start",
        "sequence": 1,
        "plan_sequence": 6,
        "target_block": None,
        "last_progress": None,
        "expected_round_sha256": None,
    }.items():
        setattr(node, name, value)
    error = (
        preflight.RequestOwnerRepairRequired("request_owner_conflict_held", 0.25)
        if repair
        else sqlite3.OperationalError("database is locked")
    )
    calls = []

    async def tick():
        calls.append(1)
        if len(calls) == 1:
            raise error
        return {"status": "settlement_handoff_published"}

    async def sample():
        await asyncio.Event().wait()

    node.tick, node.sample_service = tick, sample
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(lifecycle, "PUBLIC_COHORT_PROGRESS", snapshots)
    reports, public = [], []

    def report(value):
        reports.append(value)
        public.append(snapshots.snapshot(COHORT))

    await node.run(asyncio.Event(), poll_seconds=0.01, sample_seconds=0.01, report=report)
    assert reports[0]["status"] == (
        "cohort_lifecycle_repair_required" if repair else "cohort_lifecycle_retry"
    )
    assert bool(reports[0].get("repair_required")) is repair
    if repair:
        assert reports[0]["reason_code"] == "request_owner_conflict_held"
        assert reports[0]["completed"] == 0 and reports[0]["total"] == 1
        assert reports[0]["elapsed_seconds"] == 0.25
        assert reports[0]["eta_seconds"] is None
        assert reports[0]["eta_basis"] == "native_request_owner_repair_required"
    assert "repair_required" not in reports[1]
    assert reports[1]["status"] == "settlement_handoff_published"
    assert bool(public[0]["components"]["lifecycle"].get("repair_required")) is repair
    assert "repair_required" not in public[1]["components"]["lifecycle"]
