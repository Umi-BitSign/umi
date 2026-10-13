"""Measured history progress does not turn receipt restoration into proof speed."""

from types import SimpleNamespace

from umi import competition_reward_history_progress as module


def test_planning_measured_stalled_retry_and_restoration_rates(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.report(reader, "running")
    assert progress.latest["planning_eta_seconds"] == [50.0, 1000.0]
    reader._next = 150
    progress.restored_completed = 50
    now[0] = 10
    progress.report(reader, "running")
    assert progress.latest["blocks_per_second"] is None
    assert progress.latest["percent"] == 50
    progress.native_start()
    now[0] = 15
    progress.native_completed = 5
    reader._next = 155
    progress.report(reader, "running")
    assert progress.latest["blocks_per_second"] == 1.0
    assert progress.latest["eta_seconds"] == 45.0
    now[0] = 76
    progress.report(reader, "running")
    assert progress.latest["state"] == "stalled"
    assert progress.latest["eta_seconds"] is None
    progress.report(reader, "retrying", error_type="ConnectionError")
    assert progress.latest["eta_seconds"] is None
    progress.finish()
    now[0] = 2000
    progress.start(199, 155)
    progress.report(reader, "running")
    assert progress.latest["state"] == "running"
    assert progress.latest["elapsed_seconds"] == 76


def test_logging_failure_is_not_native_failure(monkeypatch):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)

    def failed(*args, **kwargs):
        raise OSError("broken diagnostics sink")

    monkeypatch.setattr(module.logger, "info", failed)
    progress.start(199, 100)
    progress.report(reader, "running", force=True)
    assert progress.latest["total_blocks"] == 100
    reader._next = 200
    progress.report(reader, "completed", force=True)
    assert progress.latest["eta_seconds"] == 0
    assert progress.latest["percent"] == 100


def test_changed_goal_resets_rate_but_not_completed_interval(monkeypatch):
    progress = module.HistoryProgress(10)
    reader = SimpleNamespace(_next=11)
    progress.start(10, 10)
    progress.native_completed = 1
    progress.finish()
    progress.start(20, 11)
    progress.report(reader, "running")
    assert progress.latest["completed_blocks"] == 1
    assert progress.latest["total_blocks"] == 11
    assert progress.latest["native_completed"] == 0
