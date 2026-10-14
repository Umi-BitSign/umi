"""Resume telemetry must not mistake fast restored rows for fresh work rate."""

import logging

from umi import competition_reward_history_origin_migration as migration


def report(monkeypatch, caplog, **values):
    monkeypatch.setattr(migration.time, "monotonic", lambda: 100.0)
    caplog.set_level(logging.INFO)
    migration._report(total=100, started=0.0, last_changed=99.0, **values)
    return caplog.records[-1].args


def test_restore_does_not_create_optimistic_new_work_eta(monkeypatch, caplog):
    value = report(monkeypatch, caplog, done=90, restored=89, state="running")
    assert value["percent"] == 90
    assert value["eta_seconds"] is None
    assert value["planning_eta_seconds"] == [0.4, 2.5]


def test_measured_rate_uses_only_new_completed_work(monkeypatch, caplog):
    value = report(monkeypatch, caplog, done=90, restored=80, state="running")
    assert value["eta_seconds"] == 100
    assert "new_blocks" in value["eta_basis"]


def test_stalled_eta_withdrawn_and_completed_eta_zero(monkeypatch, caplog):
    value = report(monkeypatch, caplog, done=90, restored=80, state="stalled")
    assert value["eta_seconds"] is None
    assert value["planning_eta_seconds"] is None
    assert value["eta_basis"] == "withdrawn_repair_or_retry_required"
    value = report(monkeypatch, caplog, done=100, restored=100, state="completed")
    assert value["percent"] == 100
    assert value["eta_seconds"] == 0
    assert value["eta_basis"] == "complete"
