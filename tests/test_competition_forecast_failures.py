"""Lost diagnostic observations cannot become healthy calibration after restart."""

import hashlib
import os
import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_forecast as module
from umi import competition_work_progress as progress
from umi.competition_forecast import ForecastLedger, forecast_scope
from umi.competition_reward_history_progress import HistoryProgress


def initial(ledger):
    ledger.append("start", "scope", "scope_started", {"observed_unix_ms": 1000})
    ledger.append(
        "forecast", "scope", "forecast", {"observed_unix_ms": 2000, "finish_unix_ms": 5000}
    )


def terminal(ledger, when):
    ledger.append(
        "completed-" + str(when),
        "scope",
        "attempt_terminal",
        {"observed_unix_ms": when, "state": "completed"},
    )


class FailedInsert:
    def __init__(self, connection):
        self.connection = connection

    def execute(self, sql, *args):
        if sql.startswith("INSERT"):
            raise sqlite3.OperationalError("disk I/O error")
        return self.connection.execute(sql, *args)

    def rollback(self):
        return self.connection.rollback()


@pytest.mark.parametrize("marker_failure", [False, True])
def test_lost_terminal_and_failed_gap_write_never_reopen_healthy(
    tmp_path, monkeypatch, marker_failure
):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)
    connection = ledger.db
    ledger.db = FailedInsert(connection)
    with monkeypatch.context() as patch:
        if marker_failure:

            def fail(*args):
                raise OSError("coverage marker unavailable")

            patch.setattr(module, "write_health", fail)
        with pytest.raises(sqlite3.OperationalError, match="disk I/O error"):
            terminal(ledger, 3000)
        assert ledger.status("scope")["accounting_coverage_complete"] is False
        ledger.db = connection
        # A failing marker write remains in force through graceful shutdown.
        ledger.close()
    ledger = ForecastLedger(root)
    terminal(ledger, 10000)
    result = ledger.status("scope")
    assert result["accounting_coverage_complete"] is False
    assert result["accounting_gap_count"] >= 1
    assert result["calibration_eligible"] is False
    assert result["duration_sample_eligible"] is False
    ledger.close()


def test_encoding_failure_is_retained_as_coverage_loss(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)
    with pytest.raises(TypeError):
        ledger.append("bad", "scope", "forecast", {"unencodable": object()})
    ledger.close()
    ledger = ForecastLedger(root)
    terminal(ledger, 10000)
    assert ledger.status("scope")["calibration_eligible"] is False
    assert ledger.status("scope")["accounting_first_gap"]["reason"] == "unretained_observation"
    ledger.close()


def test_unclean_session_is_conservatively_incomplete_without_marker_update(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)
    # Model an abrupt process exit after the last committed SQLite transaction,
    # without calling the ledger's graceful session close.
    ledger.db.close()
    os.close(ledger.owner)
    ledger.db = ledger.owner = None
    ledger = ForecastLedger(root)
    terminal(ledger, 10000)
    result = ledger.status("scope")
    assert result["calibration_eligible"] is False
    assert result["accounting_first_gap"]["reason"] == "unclean_accounting_session"
    ledger.close()


def test_work_consumer_failure_does_not_replace_native_success_or_disappear(tmp_path, monkeypatch):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    clock = [1.0]
    monkeypatch.setattr(
        progress,
        "time",
        SimpleNamespace(monotonic=lambda: clock[0], time_ns=lambda: int(clock[0] * 10**9)),
    )
    append = ledger.append

    def broken_terminal(identity, scope, kind, values):
        if kind == "attempt_terminal":
            raise OSError("consumer lost terminal before append")
        return append(identity, scope, kind, values)

    monkeypatch.setattr(ledger, "append", broken_terminal)
    with (
        forecast_scope(ledger, cohort="a" * 64, work_sha256="b" * 64, operation="review"),
        progress.WorkProgress("review", 3, unit="items") as meter,
    ):
        for _ in range(3):
            clock[0] += 2
            meter.advance()
    key = ledger.scopes()[0]
    ledger.close()
    ledger = ForecastLedger(root)
    assert ledger.status(key)["accounting_coverage_complete"] is False
    assert ledger.status(key)["accounting_first_gap"]["reason"] == "consumer_observation_failed"
    ledger.close()


def test_native_consumer_failure_does_not_replace_native_progress(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)

    def broken_observation(body):
        raise OSError("consumer lost native observation")

    meter = HistoryProgress(100)
    meter.forecast = SimpleNamespace(ledger=ledger, observe=broken_observation)
    meter.start(119, 100)
    meter.report(SimpleNamespace(_next=100), "running", force=True)
    assert meter.latest["state"] == "running"
    assert meter.latest["forecast_accounting"]["status"] == "repair_required"
    ledger.close()
    ledger = ForecastLedger(root)
    assert ledger.status("scope")["accounting_coverage_complete"] is False
    ledger.close()


def test_existing_health_without_session_marker_migrates_conservatively(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)
    before = ledger.records("scope")
    ledger.close()
    health = module.read_health(ledger.health_path)
    health.pop("session_open")
    module.write_health(ledger.health_path, health)
    ledger = ForecastLedger(root)
    assert ledger.records("scope") == before
    assert ledger.status("scope")["accounting_coverage_complete"] is False
    ledger.close()
    ledger = ForecastLedger(root)
    assert ledger.status("scope")["accounting_gap_count"] == 1
    ledger.close()


@pytest.mark.parametrize("failure", ["open_session_write", "sqlite_verification"])
def test_failed_startup_cannot_reuse_prior_clean_coverage(tmp_path, monkeypatch, failure):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)
    ledger.close()

    def fail(*args):
        raise OSError("startup diagnostic storage unavailable")

    with monkeypatch.context() as patch:
        if failure == "open_session_write":
            patch.setattr(module, "write_health", fail)
        else:
            patch.setattr(ForecastLedger, "_verify", fail)
        with pytest.raises(module.ForecastRepairRequired):
            ForecastLedger(root)
    if failure == "open_session_write":
        with pytest.raises(module.ForecastRepairRequired, match="initialization marker changed"):
            ForecastLedger(root)
    else:
        ledger = ForecastLedger(root)
        assert ledger.status("scope")["accounting_coverage_complete"] is False
        ledger.close()


@pytest.mark.parametrize("raw", [b"original damaged bytes", b"x" * 26])
def test_opening_damaged_initialization_preserves_bytes_before_pinned_repair(tmp_path, raw):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    initial(ledger)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    marker = ledger.marker
    ledger.close()
    marker.write_bytes(raw)
    with pytest.raises(module.ForecastRepairRequired, match="initialization marker changed"):
        ForecastLedger(root)
    assert marker.read_bytes() == raw
    prior, _ = module.stream_file(root / "forecasts.sqlite3", maximum_bytes=1024**2)
    checksum = hashlib.sha256(raw).hexdigest()
    module.restore_forecast_snapshot(
        root, snapshot, receipt, damaged_sha256=prior, damaged_initialized_sha256=checksum
    )
    assert marker.with_name(marker.name + ".damaged-" + checksum).read_bytes() == raw
    ledger = ForecastLedger(root)
    assert ledger.status("scope")["accounting_coverage_complete"] is False
    ledger.close()
