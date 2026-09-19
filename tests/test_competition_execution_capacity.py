from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier

import pytest

from umi import competition_execution as execution
from umi.protocol import canonical_json_bytes

from .test_competition_execution import boundary, run_job
from .test_competition_execution import setup as setup
from .test_competition_runner import runtime as runtime
from .test_competition_shared_incumbent import forbidden, run
from .test_competition_shared_incumbent import shared as shared
from .test_open_competition import policy as policy
from .test_open_competition import wallet

_BATCH = "ab" * 32


def jobs_for(setup):
    job = setup[1]
    return (job, job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address}))


def allowance(job):
    runs = 1 if isinstance(job, execution.EndpointIncumbentJob) else 2
    return len(canonical_json_bytes(job)) + runs * len(job.cases) * 48 * 1024 + 4096


def usage(journal):
    with journal._transaction() as db:
        return journal._usage(db)


def retained(journal):
    with sqlite3.connect(journal.path) as db:
        tables = [
            row[0]
            for row in db.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        ]
        return {name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall() for name in tables}


def assert_unmigrated(journal):
    with sqlite3.connect(journal.path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
        assert not db.execute(
            "SELECT name FROM sqlite_master WHERE name LIKE 'reservation_%'"
        ).fetchall()
        assert dict(db.execute("SELECT * FROM metadata")) == {
            "policy": execution.digest(journal.policy)
        }


def test_batch_reserves_exact_jobs_without_claiming_execution(setup, tmp_path):
    jobs = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, jobs)
    assert receipt == journal.reservation(_BATCH)
    assert receipt["generation"] == 2
    assert receipt["batch_id"] == _BATCH
    assert receipt["journal_path"] == str(journal.path.resolve())
    assert receipt["chain_submission_authorized"] is False
    assert {item["reserved_bytes"] for item in receipt["jobs"]} == {allowance(job) for job in jobs}
    for job in jobs:
        assert journal.status(execution.execution_key(job)) is None
    before = usage(journal)
    assert before[0] == len(jobs)
    assert before[1] > sum(allowance(job) for job in jobs)
    for job in jobs:
        assert journal.reserve(job) is None
        assert journal.status(execution.execution_key(job))["status"] == "running"
        assert usage(journal) == before
    assert journal.reservation(_BATCH) == receipt


def test_exact_and_reordered_batch_retries_charge_once_across_reopen(setup, tmp_path):
    jobs = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    first = journal.reserve_jobs(_BATCH, iter(jobs))
    before = retained(journal), usage(journal)
    assert journal.reserve_jobs(_BATCH, reversed(jobs)) == first
    reopened = execution.ExecutionJournal(journal.path.parent, setup[0])
    assert reopened.reserve_jobs(_BATCH, jobs) == first
    assert (retained(journal), usage(journal)) == before


def test_shared_pending_jobs_charge_new_batch_metadata_only(setup, tmp_path):
    jobs = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    journal.reserve_jobs(_BATCH, jobs)
    before = usage(journal)
    receipt = journal.reserve_jobs("cd" * 32, jobs)
    raw = canonical_json_bytes(
        {key: value for key, value in receipt.items() if key != "receipt_sha256"}
    )
    assert usage(journal) == (before[0], before[1] + 64 + len(raw))


def test_exact_fit_one_byte_short_and_one_job_short_are_atomic(setup, tmp_path):
    jobs = jobs_for(setup)
    probe = execution.ExecutionJournal(tmp_path / "probe", setup[0])
    probe.reserve_jobs(_BATCH, jobs)
    count, used = usage(probe)
    # All three directory names have equal encoded length, so identity/path
    # metadata consumes the same number of bytes, without guessing its overhead.
    exact = execution.ExecutionJournal(
        tmp_path / "exact", setup[0], maximum_jobs=count, maximum_bytes=used
    )
    exact.reserve_jobs(_BATCH, jobs)
    assert usage(exact) == (count, used)
    for job in jobs:
        exact.reserve(job)
        assert usage(exact) == (count, used)
    for directory, limits in (
        ("short", {"maximum_jobs": count, "maximum_bytes": used - 1}),
        ("count", {"maximum_jobs": count - 1, "maximum_bytes": used}),
    ):
        rejected = execution.ExecutionJournal(tmp_path / directory, setup[0], **limits)
        before = retained(rejected)
        with pytest.raises(ValueError, match="capacity exhausted"):
            rejected.reserve_jobs(_BATCH, jobs)
        assert retained(rejected) == before
        assert_unmigrated(rejected)


@pytest.mark.parametrize("failure", ["invalid", "duplicate", "iterator"])
def test_partial_batch_validation_rolls_back_jobs_receipt_and_migration(setup, tmp_path, failure):
    jobs = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    before = retained(journal)

    def supplied():
        yield jobs[0]
        if failure == "iterator":
            raise RuntimeError("source interrupted")
        if failure == "duplicate":
            yield jobs[0]
        else:
            yield jobs[1].model_copy(
                update={"evaluator_hotkey": wallet("Alice").hotkey.ss58_address}
            )

    with pytest.raises((ValueError, RuntimeError)):
        journal.reserve_jobs(_BATCH, supplied())
    assert retained(journal) == before
    assert_unmigrated(journal)


def test_conflicts_never_change_first_receipt_or_pending_job(setup, tmp_path):
    jobs = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, jobs)
    before = retained(journal)
    changed = jobs[0].model_copy(update={"cases": tuple(reversed(jobs[0].cases))})
    for batch, incoming in ((_BATCH, jobs[:1]), ("cd" * 32, (changed,))):
        with pytest.raises(ValueError, match="different"):
            journal.reserve_jobs(batch, incoming)
        assert retained(journal) == before
    with pytest.raises(ValueError, match="different assignment"):
        journal.reserve(changed)
    assert journal.reservation(_BATCH) == receipt
    assert journal.status(execution.execution_key(jobs[0])) is None


def test_ordinary_admission_cannot_spend_pending_job_capacity(setup, tmp_path):
    first, second = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0], maximum_jobs=2)
    journal.reserve_jobs(_BATCH, (first,))
    journal.reserve(second)
    before = usage(journal)
    unrelated = first.model_copy(update={"round": first.round.model_copy(update={"sequence": 2})})
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reserve(unrelated)
    journal.reserve(first)
    assert usage(journal) == before


def test_new_batch_counts_existing_ordinary_jobs(setup, tmp_path):
    first, second = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0], maximum_jobs=1)
    journal.reserve(first)
    with pytest.raises(ValueError, match="drain running"):
        journal.reserve_jobs(_BATCH, (second,))
    assert_unmigrated(journal)
    journal.fail(first)
    before = retained(journal)
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reserve_jobs(_BATCH, (second,))
    assert retained(journal) == before
    assert_unmigrated(journal)


def test_migration_and_batch_retry_preserve_failed_no_rerun_status(setup, tmp_path):
    job = setup[1]
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    journal.reserve(job)
    journal.fail(job, cancelled=True)
    status = journal.status(execution.execution_key(job))
    receipt = journal.reserve_jobs(_BATCH, (job,))
    assert journal.status(execution.execution_key(job)) == status
    assert journal.reserve_jobs(_BATCH, (job,)) == receipt
    with pytest.raises(ValueError, match="automatic rerun refused"):
        journal.reserve(job)


@pytest.mark.parametrize(
    "table",
    [
        "metadata",
        "jobs",
        "steps",
        "pending_steps",
        "endpoint_incumbents",
        "reservation_batches",
        "reservation_jobs",
    ],
)
@pytest.mark.parametrize("generation", [None, 1])
def test_preopened_legacy_connections_cannot_mutate_any_participating_table(
    setup, tmp_path, table, generation
):
    job = setup[1]
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    with sqlite3.connect(journal.path) as old:
        if generation is not None:
            old.create_function("umi_execution_writer_generation", 0, lambda: generation)
        old.execute("SELECT * FROM jobs").fetchall()
        journal.reserve_jobs(_BATCH, (job,))
        before = retained(journal)
        statements = {
            "metadata": ("INSERT INTO metadata VALUES (?,?)", ("legacy", "writer")),
            "jobs": (
                "INSERT INTO jobs VALUES (?,?,?,'running',NULL)",
                ("ff" * 32, canonical_json_bytes(job), allowance(job)),
            ),
            "steps": ("INSERT INTO steps VALUES (?,?,?)", ("ff" * 32, 0, b"{}")),
            "pending_steps": ("INSERT INTO pending_steps VALUES (?,?)", ("ff" * 32, b"{}")),
            "endpoint_incumbents": (
                "INSERT INTO endpoint_incumbents VALUES (?,?)",
                ("ff" * 32, "ee" * 32),
            ),
            "reservation_batches": (
                "INSERT INTO reservation_batches VALUES (?,?)",
                ("ff" * 32, b"{}"),
            ),
            "reservation_jobs": (
                "INSERT INTO reservation_jobs VALUES (?,?,?)",
                ("ff" * 32, canonical_json_bytes(job), allowance(job)),
            ),
        }
        with pytest.raises(sqlite3.DatabaseError, match=r"generation|no such function"):
            old.execute(*statements[table])
        old.rollback()
        assert retained(journal) == before


def test_pending_to_running_consumption_rolls_back_on_insert_failure(setup, tmp_path, monkeypatch):
    job = setup[1]
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, (job,))
    before = retained(journal)
    transaction = journal._transaction

    @contextmanager
    def failed_insert():
        with transaction() as db:

            class Connection:
                def execute(self, sql, *args):
                    if sql.startswith("INSERT INTO jobs VALUES"):
                        assert not db.execute("SELECT 1 FROM reservation_jobs").fetchone()
                        raise sqlite3.OperationalError("injected job insertion failure")
                    return db.execute(sql, *args)

            yield Connection()

    with monkeypatch.context() as patch:
        patch.setattr(journal, "_transaction", failed_insert)
        with pytest.raises(sqlite3.OperationalError, match="injected"):
            journal.reserve(job)
    assert retained(journal) == before
    assert journal.reservation(_BATCH) == receipt
    assert journal.status(execution.execution_key(job)) is None


@pytest.mark.parametrize("same_batch", [False, True])
def test_cross_instance_batches_serialize_capacity_and_first_receipt(setup, tmp_path, same_batch):
    jobs = jobs_for(setup)
    journals = tuple(
        execution.ExecutionJournal(tmp_path / "journal", setup[0], maximum_jobs=1) for _ in range(2)
    )
    barrier = Barrier(2)

    def reserve(index):
        barrier.wait(timeout=5)
        try:
            return journals[index].reserve_jobs(
                _BATCH if same_batch or index == 0 else "cd" * 32,
                (jobs[0 if same_batch else index],),
            )
        except ValueError as error:
            return error

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, range(2)))
    if same_batch:
        assert results[0] == results[1]
        assert isinstance(results[0], dict)
    else:
        assert sum(isinstance(value, dict) for value in results) == 1
        assert (
            sum(
                isinstance(value, ValueError) and "capacity exhausted" in str(value)
                for value in results
            )
            == 1
        )
    assert usage(journals[0])[0] == 1


def test_reopen_rejects_capacity_below_pending_obligations(setup, tmp_path):
    jobs = jobs_for(setup)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, jobs)
    count, used = usage(journal)
    for limits in ({"maximum_jobs": count - 1}, {"maximum_bytes": used - 1}):
        with pytest.raises(ValueError, match="capacity exhausted"):
            execution.ExecutionJournal(journal.path.parent, setup[0], **limits)
    assert journal.reservation(_BATCH) == receipt


def test_existing_object_revalidation_rejects_reduced_capacity(setup, tmp_path):
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, jobs_for(setup))
    count, used = usage(journal)
    journal.maximum_bytes = used - 1
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reservation(_BATCH)
    journal.maximum_bytes = used
    journal.maximum_jobs = count - 1
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reservation(_BATCH)
    journal.maximum_jobs = count
    assert journal.reservation(_BATCH) == receipt


def test_empty_cohort_is_explicit_and_metadata_still_consumes_capacity(setup, tmp_path):
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, ())
    assert receipt["jobs"] == []
    count, used = usage(journal)
    assert count == 0 and used > 0
    assert journal.reserve_jobs(_BATCH, iter(())) == receipt
    journal.maximum_bytes = used
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.reserve_jobs("cd" * 32, ())
    assert usage(journal) == (count, used)
    assert journal.reservation("cd" * 32) is None


@pytest.mark.parametrize("damage", ["missing", "changed", "duplicate"])
def test_receipt_revalidation_detects_missing_or_corrupt_obligations_without_repair(
    setup, tmp_path, damage
):
    job = setup[1]
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    journal.reserve_jobs(_BATCH, (job,))
    key = execution.execution_key(job)
    if damage == "duplicate":
        journal.reserve(job)
    with journal._transaction() as db:
        if damage != "duplicate":
            db.execute("DELETE FROM reservation_jobs WHERE id=?", (key,))
        if damage in {"changed", "duplicate"}:
            supplied = (
                job.model_copy(update={"cases": tuple(reversed(job.cases))})
                if damage == "changed"
                else job
            )
            db.execute(
                "INSERT INTO reservation_jobs VALUES (?,?,?)",
                (key, canonical_json_bytes(supplied), allowance(supplied)),
            )
    before = retained(journal)
    with pytest.raises(ValueError, match="obligation"):
        journal.reservation(_BATCH)
    with pytest.raises(ValueError, match="obligation"):
        journal.reserve_jobs(_BATCH, (job,))
    assert retained(journal) == before


def test_receipt_is_immutable_even_for_a_current_generation_connection(setup, tmp_path):
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, (setup[1],))
    for statement in (
        "DELETE FROM reservation_batches WHERE id=?",
        "UPDATE reservation_batches SET document=x'7b7d' WHERE id=?",
    ):
        with (
            pytest.raises(sqlite3.IntegrityError, match="immutable"),
            journal._transaction() as db,
        ):
            db.execute(statement, (_BATCH,))
    assert journal.reservation(_BATCH) == receipt


def test_missing_capability_fence_is_not_recreated_silently(setup, tmp_path):
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    journal.reserve_jobs(_BATCH, (setup[1],))
    with sqlite3.connect(journal.path) as db:
        db.execute("DROP TRIGGER generation_metadata_update")
    with pytest.raises(ValueError, match="capability schema"):
        execution.ExecutionJournal(journal.path.parent, setup[0])


async def test_reserved_model_runs_once_and_replays_complete_evidence_unchanged(
    setup, tmp_path, monkeypatch
):
    job = setup[1]
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    receipt = journal.reserve_jobs(_BATCH, (job,))
    first, journal = await run_job(setup, tmp_path)
    monkeypatch.setattr(execution, "verify_runtime", forbidden)
    monkeypatch.setattr(execution, "execute_offline_case", forbidden)
    second, _ = await run_job(setup, tmp_path, source=forbidden)
    assert canonical_json_bytes(second) == canonical_json_bytes(first)
    assert journal.reservation(_BATCH) == receipt
    assert journal.reserve_jobs(_BATCH, (job,)) == receipt


async def test_reserved_shared_incumbent_keeps_original_receipts_and_source(
    shared, tmp_path, monkeypatch
):
    policy, jobs, _, _, calls = shared
    journal = execution.ExecutionJournal(tmp_path / "shared", policy)
    receipt = journal.reserve_jobs(_BATCH, jobs)
    first, journal = await run(shared, tmp_path)
    monkeypatch.setattr(execution, "verify_runtime", forbidden)
    monkeypatch.setattr(execution, "execute_offline_case", forbidden)
    second, journal = await run(shared, tmp_path, job=jobs[1], source=forbidden, prepare=forbidden)
    assert second.steps == first.steps
    assert len([call for call in calls if isinstance(call, dict)]) == len(jobs[0].cases)
    assert journal.reservation(_BATCH) == receipt
    with sqlite3.connect(journal.path) as db:
        assert db.execute("SELECT source_job FROM endpoint_incumbents").fetchall() == [
            (execution.execution_key(jobs[0]),)
        ]
        assert not db.execute("SELECT 1 FROM reservation_jobs").fetchone()


async def test_failed_pending_observation_survives_migration(setup, tmp_path):
    calls = 0

    async def fail_finished_boundary():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise RuntimeError("finished boundary unavailable")
        return boundary()

    with pytest.raises(RuntimeError, match="unavailable"):
        await run_job(setup, tmp_path, source=fail_finished_boundary)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    before = retained(journal)
    journal.reserve_jobs(_BATCH, (setup[1],))
    after = retained(journal)
    for table in ("jobs", "steps", "pending_steps", "endpoint_incumbents"):
        assert after[table] == before[table]
    assert journal.status(execution.execution_key(setup[1]))["pending_observations"] == 1
