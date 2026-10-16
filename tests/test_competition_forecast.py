"""Forecast history is durable diagnostics; native work and authorization stay native."""

import hashlib
import json
import logging
import shutil
import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_work_progress as progress
from umi.competition_forecast import (
    ForecastCapacityRequired,
    ForecastLedger,
    ForecastRepairRequired,
    forecast_scope,
    restore_forecast_snapshot,
)


@pytest.fixture
def clock(monkeypatch):
    value = SimpleNamespace(now=100.0, wall=1_700_000_000.0)
    monkeypatch.setattr(
        progress,
        "time",
        SimpleNamespace(
            monotonic=lambda: value.now, time_ns=lambda: round(value.wall * 1_000_000_000)
        ),
    )
    return value


@pytest.fixture
def events(monkeypatch):
    records = []

    class Capture(logging.Handler):
        def emit(self, record):
            records.append(json.loads(record.getMessage()))

    logger = logging.Logger("isolated-forecasts", level=logging.INFO)
    logger.addHandler(Capture())
    monkeypatch.setattr(progress, "_LOG", logger)
    return records


def scope(ledger, work="b" * 64):
    return forecast_scope(ledger, cohort="a" * 64, work_sha256=work, operation="review")


def advance(clock, seconds):
    clock.now += seconds
    clock.wall += seconds


def test_restart_gaps_revisions_misses_and_one_completion(tmp_path, clock, events, monkeypatch):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    monkeypatch.setenv("INVOCATION_ID", "1" * 32)
    with scope(ledger):
        meter = progress.WorkProgress("model_review", 3, unit="models")
        advance(clock, 10)
        meter.advance()
        meter.interrupt()
    key = ledger.scopes()[0]
    issued = [r for r in ledger.records(key) if r["kind"] == "forecast"]
    assert issued[-1]["finish_unix_ms"] == 1_700_000_030_000
    assert issued[-1]["raw_sample_seconds"] == [10]
    assert issued[-1]["scope_kind"] == "substage_only"
    ledger.close()

    advance(clock, 100)  # Service downtime is not lost or counted as native throughput.
    ledger = ForecastLedger(directory)
    pending = ledger.status(key, observed_unix_ms=round(clock.wall * 1000))
    assert pending["overdue_unfinished_forecasts"] == 1
    assert pending["completion_examples"] == 0
    assert pending["elapsed_including_gaps_seconds"] == 110
    monkeypatch.setenv("INVOCATION_ID", "2" * 32)
    with scope(ledger), progress.WorkProgress("model_review", 3, unit="models") as meter:
        for _ in range(3):
            advance(clock, 2)
            meter.advance()
    result = ledger.status(key)
    assert result["outcome"] == "completed"
    assert result["elapsed_including_gaps_seconds"] == 116
    assert result["first_forecast_error_seconds"] == 86
    assert result["missed_forecasts"] == 1
    assert [r for r in ledger.records(key) if r["kind"] == "forecast"][: len(issued)] == issued
    attempts = [r for r in ledger.records(key) if r["kind"] == "attempt_started"]
    assert {r["invocation"] for r in attempts} == {"1" * 32, "2" * 32}
    repeated_start = clock.wall
    with scope(ledger), progress.WorkProgress("model_review", 3, unit="models") as meter:
        for _ in range(3):
            advance(clock, 1)
            meter.advance()
    assert ledger.status(key)["completion_examples"] == 1
    assert ledger.status(key)["elapsed_including_gaps_seconds"] == 116
    success = [
        r
        for r in ledger.records(key)
        if r["kind"] == "attempt_terminal" and r["state"] == "completed"
    ]
    assert len(success) == 2  # Retained repeat attempts still count as one completed scope.
    assert success[0]["observed_unix_ms"] == round(repeated_start * 1000)
    ledger.close()


def test_nested_unbound_work_cannot_alias_different_inputs(tmp_path, clock, events):
    ledger = ForecastLedger(tmp_path / "diagnostics")
    with scope(ledger), progress.WorkProgress("outer_review", 1, unit="reviews") as outer:
        with progress.WorkProgress("model_review", 1, unit="models") as inner:
            inner.advance()
        with (
            scope(ledger, "c" * 64),
            progress.WorkProgress("model_review", 1, unit="models") as bound,
        ):
            bound.advance()
        outer.advance()
    assert len(ledger.scopes()) == 2
    inner_events = [e for e in events if e["work_id"] == inner.identity]
    assert all("forecast_accounting" not in event for event in inner_events)
    assert events[-1]["forecast_accounting"]["completion_examples"] == 1
    ledger.close()


@pytest.mark.parametrize("damage", ["body", "tail", "database", "schema"])
def test_damaged_records_require_explicit_repair_and_exact_restore(tmp_path, clock, events, damage):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    with scope(ledger):
        meter = progress.WorkProgress("review", 2, unit="items")
        advance(clock, 5)
        meter.advance()
        meter.interrupt()
    key = ledger.scopes()[0]
    original_records = ledger.records(key)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    ledger.close()
    path = directory / "forecasts.sqlite3"
    if damage == "database":
        path.unlink()
        damaged_sha = None
    else:
        db = sqlite3.connect(path)
        with db:
            if damage == "body":
                db.execute("UPDATE events SET body=? WHERE sequence=1", (b"{}",))
            elif damage == "tail":
                db.execute("DELETE FROM events WHERE sequence=(SELECT MAX(sequence) FROM events)")
            else:
                db.execute("PRAGMA user_version=99")
        db.close()
        damaged_sha = hashlib.sha256(path.read_bytes()).hexdigest()
    with pytest.raises(ForecastRepairRequired):
        ForecastLedger(directory)
    restored = restore_forecast_snapshot(directory, snapshot, receipt, damaged_sha256=damaged_sha)
    assert restored["status"] == "restored"
    assert restored["unarchived_records_reconstructed"] is False
    again = restore_forecast_snapshot(directory, snapshot, receipt, damaged_sha256=damaged_sha)
    assert again["status"] == "already_restored"
    ledger = ForecastLedger(directory)
    assert ledger.records(key) == original_records
    assert (
        ledger.status(key, observed_unix_ms=1_700_000_100_000)["overdue_unfinished_forecasts"] == 1
    )
    if damaged_sha:
        assert (directory / ("damaged-" + damaged_sha + ".sqlite3")).is_file()
    ledger.close()


def test_capacity_keeps_issued_forecasts_and_native_failure(tmp_path, clock, events):
    ledger = ForecastLedger(tmp_path / "diagnostics", maximum_bytes=64 * 1024)
    with scope(ledger):
        meter = progress.WorkProgress("review", 2, unit="items")
        advance(clock, 5)
        meter.advance()
    key = ledger.scopes()[0]
    retained = ledger.records(key)
    with pytest.raises(ForecastCapacityRequired):
        for i in range(100):
            ledger.append(str(i), "padding", "bounded_test", {"payload": "x" * 8000})
    assert ledger.records(key) == retained
    failure = RuntimeError("native failure stays native")
    with (
        pytest.raises(RuntimeError) as caught,
        scope(ledger),
        progress.WorkProgress("other_review", 2, unit="items"),
    ):
        raise failure
    assert caught.value is failure
    assert events[-1]["forecast_accounting"]["status"] == "capacity_required"
    ledger.close()


def test_interrupted_append_rolls_back_and_live_owner_refuses_restore(tmp_path, clock, events):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    with scope(ledger), progress.WorkProgress("review", 0, unit="items"):
        pass
    key = ledger.scopes()[0]
    original = ledger.records(key)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    with pytest.raises(BlockingIOError):
        restore_forecast_snapshot(directory, snapshot, receipt, damaged_sha256=None)
    ledger.db.execute("BEGIN IMMEDIATE")
    ledger.db.execute("DELETE FROM events")
    ledger.close()  # sqlite rolls back the uncommitted interrupted operation.
    ledger = ForecastLedger(directory)
    assert ledger.records(key) == original
    assert ledger.status(key)["completion_examples"] == 1
    ledger.close()


def test_scope_cannot_claim_rewards_or_invent_completion_on_counter_mismatch(
    tmp_path, clock, events
):
    ledger = ForecastLedger(tmp_path / "diagnostics")
    with scope(ledger), progress.WorkProgress("review", 2, unit="items") as meter:
        meter.advance()
    key = ledger.scopes()[0]
    assert ledger.status(key)["outcome"] == "unfinished"
    assert ledger.status(key)["completion_examples"] == 0
    assert all(not r["certification_authority"] for r in ledger.records(key))
    ledger.close()


def test_each_issued_absolute_finish_is_retained_and_stall_withdraws_future_eta(
    tmp_path, clock, events
):
    ledger = ForecastLedger(tmp_path / "diagnostics")
    with scope(ledger):
        meter = progress.WorkProgress("review", 4, unit="items")
        advance(clock, 10)
        meter.advance()
        advance(clock, 15)
        meter.emit("running")
        advance(clock, 20)
        meter.emit("running")
        meter.interrupt()
    records = ledger.records(ledger.scopes()[0])
    forecasts = [r for r in records if r["kind"] == "forecast"]
    assert [r["finish_unix_ms"] for r in forecasts] == [
        None,
        1_700_000_040_000,
        1_700_000_055_000,
        None,
    ]
    assert forecasts[-1]["eta_basis"] == "stalled_rate_invalidated"
    assert (
        ledger.status(ledger.scopes()[0], observed_unix_ms=1_700_000_100_000)[
            "overdue_unfinished_forecasts"
        ]
        == 2
    )
    ledger.close()


def test_diagnostic_capacity_can_expand_without_evicting_previous_records(tmp_path):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory, maximum_bytes=64 * 1024)
    with pytest.raises(ForecastCapacityRequired):
        for i in range(100):
            ledger.append(str(i), "padding", "bounded_test", {"payload": "x" * 8000})
    before = ledger.records("padding")
    ledger.close()
    ledger = ForecastLedger(directory, maximum_bytes=128 * 1024)
    ledger.append("later", "padding", "bounded_test", {"certification_authority": True})
    assert ledger.records("padding")[:-1] == before
    assert ledger.records("padding")[-1]["certification_authority"] is False
    ledger.close()


def test_missing_whole_diagnostic_directory_is_not_reinitialized(tmp_path):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    ledger.close()
    shutil.rmtree(directory)
    with pytest.raises(ForecastRepairRequired, match="previously initialized"):
        ForecastLedger(directory)


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_snapshot_repair_never_overwrites_pending_sqlite_recovery(tmp_path, suffix):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    ledger.close()
    path = directory / "forecasts.sqlite3"
    prior = path.read_bytes()
    sidecar = directory / (path.name + suffix)
    sidecar.write_bytes(b"pending native SQLite recovery")
    with pytest.raises(ForecastRepairRequired, match="SQLite recovery"):
        restore_forecast_snapshot(directory, snapshot, receipt, damaged_sha256=receipt["sha256"])
    assert path.read_bytes() == prior
    assert sidecar.read_bytes() == b"pending native SQLite recovery"


def test_repeat_forecasts_are_not_compared_with_preceding_completion(tmp_path, clock, events):
    ledger = ForecastLedger(tmp_path / "diagnostics")
    with scope(ledger), progress.WorkProgress("review", 2, unit="items") as meter:
        meter.advance()
        meter.advance()
    key = ledger.scopes()[0]
    assert ledger.status(key)["first_forecast_error_seconds"] is None
    advance(clock, 100)
    with scope(ledger), progress.WorkProgress("review", 2, unit="items") as meter:
        advance(clock, 10)
        meter.advance()
        advance(clock, 100)
        meter.advance()
    result = ledger.status(key)
    assert result["completion_examples"] == 1
    assert result["issued_forecasts"] == 0
    assert result["repeat_attempt_forecasts_excluded"] == 1
    assert result["first_forecast_error_seconds"] is None
    ledger.close()


def test_backward_wall_clock_withdraws_elapsed_and_error_claims(tmp_path, clock, events):
    ledger = ForecastLedger(tmp_path / "diagnostics")
    with scope(ledger), progress.WorkProgress("review", 2, unit="items") as meter:
        advance(clock, 10)
        meter.advance()
        clock.wall -= 20
        clock.now += 10
        meter.advance()
    result = ledger.status(ledger.scopes()[0])
    assert result["clock_regression"] is True
    assert result["elapsed_including_gaps_seconds"] is None
    assert result["first_forecast_error_seconds"] is None
    assert result["missed_forecasts"] is None
    assert result["completion_examples"] == 1
    ledger.close()


def test_conflicting_damage_preservation_refuses_before_replacing_original(tmp_path):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    ledger.close()
    path = directory / "forecasts.sqlite3"
    path.write_bytes(b"retained damaged bytes")
    prior = hashlib.sha256(path.read_bytes()).hexdigest()
    preserved = directory / ("damaged-" + prior + ".sqlite3")
    preserved.write_bytes(b"conflicting bytes")
    with pytest.raises(ForecastRepairRequired, match="preservation identity conflicts"):
        restore_forecast_snapshot(directory, snapshot, receipt, damaged_sha256=prior)
    assert path.read_bytes() == b"retained damaged bytes"
    assert preserved.read_bytes() == b"conflicting bytes"


def test_committed_terminal_is_completion_even_if_following_diagnostics_fail(
    tmp_path, clock, events, monkeypatch
):
    directory = tmp_path / "diagnostics"
    ledger = ForecastLedger(directory)
    original_append = ledger.append

    def fail_after_commit(identity, key, kind, values):
        result = original_append(identity, key, kind, values)
        if kind == "attempt_terminal" and values["state"] == "completed":
            raise OSError("diagnostic failure after durable success")
        return result

    monkeypatch.setattr(ledger, "append", fail_after_commit)
    with scope(ledger), progress.WorkProgress("review", 1, unit="items") as meter:
        advance(clock, 10)
        meter.advance()
    key = ledger.scopes()[0]
    ledger.close()
    ledger = ForecastLedger(directory)
    assert ledger.status(key)["completion_examples"] == 1
    assert ledger.status(key)["elapsed_including_gaps_seconds"] == 10
    advance(clock, 100)
    with scope(ledger), progress.WorkProgress("review", 1, unit="items") as meter:
        advance(clock, 10)
        meter.advance()
    assert ledger.status(key)["completion_examples"] == 1
    assert ledger.status(key)["elapsed_including_gaps_seconds"] == 10
    ledger.close()


def test_python310_sqlite_capacity_diagnostic_preserves_native_success(
    tmp_path, events, monkeypatch
):
    ledger = ForecastLedger(tmp_path / "diagnostics")
    original = ledger.db

    class OlderConnection:
        def execute(self, sql, *args):
            if sql.startswith("INSERT"):
                raise sqlite3.OperationalError("database or disk is full")
            return original.execute(sql, *args)

        def rollback(self):
            original.rollback()

    with monkeypatch.context() as selected:
        selected.setattr(ledger, "db", OlderConnection())
        with scope(ledger), progress.WorkProgress("review", 1, unit="items") as meter:
            meter.advance()
    assert events[-1]["state"] == "completed"
    assert events[-1]["forecast_accounting"]["status"] == "capacity_required"
    assert ledger.scopes() == []
    ledger.close()
