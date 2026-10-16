"""Actual native progress emissions retain forecasts across gaps and restarts."""

from types import SimpleNamespace

import pytest

from umi import competition_history_forecast as module
from umi import competition_reward_history_progress as progress_module
from umi.competition_forecast import ForecastLedger


@pytest.fixture
def clock(monkeypatch):
    now = [1.0]
    monkeypatch.setattr(progress_module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(module, "time", SimpleNamespace(time_ns=lambda: int(now[0] * 10**9)))
    return now


def meter(ledger):
    progress = progress_module.HistoryProgress(100)
    progress.forecast = module.HistoryForecast(
        ledger,
        {"series_sha256": "a" * 64, "checkpoint_owner": "b" * 64, "first_block": 100},
    )
    return progress, SimpleNamespace(_next=100)


def ordered(progress, reader, count):
    for height in range(reader._next, reader._next + count):
        progress.native_finished(height)
        progress.applied(height)
    reader._next += count
    progress.report(reader, "pending", force=True)


def test_issued_native_eta_retained_with_wall_gaps_and_first_completion(tmp_path, clock):
    ledger = ForecastLedger(tmp_path / "accounting")
    try:
        progress, reader = meter(ledger)
        progress.start(119, 100)
        progress.report(reader, "running", force=True)
        progress.native_start()
        clock[0] = 6
        ordered(progress, reader, 5)
        scope = progress.forecast.scope
        issued = ledger.records(scope)[-1]
        assert issued["finish_unix_ms"] == 21000
        assert issued["native_progress"]["native_applied"] == 5
        assert issued["chain_growth_included"] is False
        assert issued["activation_work_included"] is False
        clock[0] = 10
        progress.report(reader, "retrying", error_type="OSError", force=True)
        progress.finish()
        clock[0] = 110
        progress.start(119, reader._next)
        progress.report(reader, "running", force=True)
        assert progress.latest["eta_seconds"] is None
        assert ledger.status(scope, observed_unix_ms=110000)["overdue_unfinished_forecasts"] == 1
        progress.native_start()
        clock[0] = 116
        ordered(progress, reader, 15)
        progress.report(reader, "completed", force=True)
        progress.report(reader, "completed", force=True)
        status = ledger.status(scope, observed_unix_ms=116000)
        assert status["completion_examples"] == 1
        assert status["elapsed_including_gaps_seconds"] == 115
        assert status["first_forecast_error_seconds"] == 95
        assert issued in ledger.records(scope)
        assert any(
            record.get("native_progress", {}).get("error_type") == "OSError"
            for record in ledger.records(scope)
        )
    finally:
        ledger.close()


def test_restart_keeps_original_forecast_but_restoration_cannot_supply_native_rate(
    tmp_path, clock, monkeypatch
):
    directory = tmp_path / "accounting"
    monkeypatch.setenv("INVOCATION_ID", "1" * 32)
    ledger = ForecastLedger(directory)
    progress, reader = meter(ledger)
    progress.start(119, 100)
    progress.native_start()
    clock[0] = 6
    ordered(progress, reader, 5)
    scope = progress.forecast.scope
    ledger.close()
    monkeypatch.setenv("INVOCATION_ID", "2" * 32)
    clock[0] = 100
    ledger = ForecastLedger(directory)
    try:
        restarted, reader = meter(ledger)
        restarted.start(119, 100)
        restarted.report(reader, "running", force=True)
        restarted.restore_start(100, 5)
        reader._next = 105
        restarted.restored_completed = 5
        clock[0] = 105
        restarted.report(reader, "pending", force=True)
        assert restarted.forecast.scope == scope
        assert restarted.latest["native_applied"] == 0
        assert restarted.latest["blocks_per_second"] is None
        assert restarted.latest["forecast_accounting"]["elapsed_including_gaps_seconds"] == 99
        records = ledger.records(scope)
        invocations = {r["invocation"] for r in records}
        assert invocations == {"1" * 32, "2" * 32}
        restore = records[-1]
        assert restore["substage_finish_unix_ms"] == 105000
        assert restore["substage_outcome_basis"] == (
            "retained_observation_only_no_independent_completion_event"
        )
    finally:
        ledger.close()


def test_changed_target_retains_unfinished_old_interval_and_does_not_credit_restored_prefix(
    tmp_path, clock
):
    ledger = ForecastLedger(tmp_path / "accounting")
    try:
        progress, reader = meter(ledger)
        progress.start(119, 100)
        progress.native_start()
        clock[0] = 6
        ordered(progress, reader, 5)
        old_scope = progress.forecast.scope
        progress.finish()
        clock[0] = 10
        progress.start(129, 105)
        progress.report(reader, "running", force=True)
        assert progress.forecast.scope != old_scope
        assert progress.latest["native_applied"] == 0
        assert progress.latest["blocks_per_second"] is None
        old = ledger.records(old_scope)[-1]
        assert old["reason"] == "changed_target"
        assert old["completion_observed"] is False
        assert ledger.status(old_scope, observed_unix_ms=50000)["outcome"] == "unfinished"
    finally:
        ledger.close()


def test_ahead_verified_blocks_cannot_change_retained_native_eta(tmp_path, clock):
    ledger = ForecastLedger(tmp_path / "accounting")
    try:
        progress, reader = meter(ledger)
        progress.start(119, 100)
        progress.native_start()
        clock[0] = 11
        ordered(progress, reader, 3)
        for height in range(103, 110):
            progress.native_finished(height)
        progress.report(reader, "pending", force=True)
        event = ledger.records(progress.forecast.scope)[-1]
        payload = event["native_progress"]
        assert payload["native_completed"] == 10
        assert payload["native_applied"] == 3
        assert payload["blocks_per_second"] == 0.3
        assert event["finish_unix_ms"] == 11000 + round(17 / 0.3 * 1000)
    finally:
        ledger.close()


def test_accounting_failure_is_reported_without_losing_native_completion(tmp_path, monkeypatch):
    ledger = ForecastLedger(tmp_path / "accounting")
    try:
        progress, reader = meter(ledger)

        def unavailable(*args, **kwargs):
            raise OSError("diagnostics unavailable")

        monkeypatch.setattr(ledger, "append", unavailable)
        progress.start(119, 100)
        reader._next = 120
        progress.report(reader, "completed", force=True)
        assert progress.latest["state"] == "completed"
        assert progress.latest["percent"] == 100
        assert progress.latest["forecast_accounting"]["status"] == "repair_required"
    finally:
        ledger.close()


def test_unchanged_unknown_heartbeats_do_not_grow_ledger_but_new_errors_are_retained(
    tmp_path, clock
):
    ledger = ForecastLedger(tmp_path / "accounting")
    try:
        progress, reader = meter(ledger)
        progress.start(119, 100)
        progress.restore_start(100, 20)
        clock[0] = 400
        progress.report(reader, "running", force=True)
        head = ledger.head
        clock[0] = 430
        progress.report(reader, "running", force=True)
        assert ledger.head == head
        assert progress.latest["forecast_accounting"]["observation_retention"] == (
            "unchanged_unknown_heartbeat"
        )
        assert progress.latest["forecast_accounting"]["elapsed_including_gaps_seconds"] == 30
        clock[0] = 440
        progress.report(reader, "retrying", error_type="OSError", force=True)
        assert ledger.head != head
        assert ledger.records(progress.forecast.scope)[-1]["native_progress"]["error_type"] == (
            "OSError"
        )
    finally:
        ledger.close()


def test_each_numeric_forecast_survives_even_without_new_progress(tmp_path, clock):
    ledger = ForecastLedger(tmp_path / "accounting")
    try:
        progress, reader = meter(ledger)
        progress.start(119, 100)
        progress.native_start()
        clock[0] = 6
        ordered(progress, reader, 5)
        first = ledger.records(progress.forecast.scope)[-1]
        clock[0] = 7
        progress.report(reader, "running", force=True)
        second = ledger.records(progress.forecast.scope)[-1]
        assert first["finish_unix_ms"] == 21000
        assert second["finish_unix_ms"] == 25000
        assert ledger.status(progress.forecast.scope)["issued_forecasts"] == 2
    finally:
        ledger.close()
