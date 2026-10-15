"""History completion estimates include retry wall time, never restored proofs."""

from types import SimpleNamespace

import pytest

from umi import competition_reward_history_progress as module


@pytest.fixture
def clock(monkeypatch):
    now = [0.0]
    monkeypatch.setattr(module, "time", SimpleNamespace(monotonic=lambda: now[0]))
    return now


def advance(progress, reader, count):
    for height in range(reader._next, reader._next + count):
        progress.native_finished(height)
        progress.applied(height)
    reader._next += count
    progress.report(reader, "running")


def test_cold_restore_and_native_rates_are_separate(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.report(reader, "running")
    assert progress.latest["stage"] == "history_preparation"
    assert progress.latest["planning_eta_seconds"] == [50.0, 1000.0]
    progress.restore_start(100, 50)
    clock[0] = 10
    reader._next = 125
    progress.restored_completed = 25
    progress.report(reader, "running")
    assert progress.latest["stage"] == "checkpoint_restore"
    assert progress.latest["stage_completed_blocks"] == 25
    assert progress.latest["stage_total_blocks"] == 50
    assert progress.latest["stage_eta_seconds"] == 10
    assert progress.latest["stage_eta_scope"] == "current_checkpoint_restore_batch_only"
    assert progress.latest["eta_seconds"] is None
    clock[0] = 20
    reader._next = 150
    progress.restored_completed = 50
    progress.report(reader, "running")
    assert progress.latest["stage_eta_seconds"] == 0
    assert progress.latest["blocks_per_second"] is None
    progress.native_start()
    clock[0] = 25
    advance(progress, reader, 5)
    assert progress.latest["blocks_per_second"] == 1
    assert progress.latest["eta_seconds"] == 45
    assert progress.latest["elapsed_seconds"] == 25
    assert progress.latest["native_wall_elapsed_seconds"] == 5
    assert progress.latest["eta_basis"] == "measured_ordered_native_blocks_per_wall_second"


def test_checkpoint_export_preserves_enclosing_restore_progress_and_eta(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.restore_start(100, 50)
    clock[0] = 10
    reader._next = 125
    progress.stage = "checkpoint_export"
    progress.report(reader, "running")
    assert progress.latest["stage"] == "checkpoint_export"
    assert progress.latest["active_block"] == 125
    assert progress.latest["stage_completed_blocks"] == 25
    assert progress.latest["stage_total_blocks"] == 50
    assert progress.latest["stage_eta_seconds"] == 10
    assert progress.latest["stage_eta_scope"] == "current_checkpoint_restore_batch_only"
    assert progress.latest["eta_seconds"] is None
    assert progress.latest["native_completed"] == 0
    clock[0] = 71
    progress.report(reader, "running")
    assert progress.latest["state"] == "stalled"
    assert progress.latest["stage_eta_seconds"] is None
    assert progress.latest["stage_eta_basis"] == "withdrawn_stalled_retrying_or_stopped"


@pytest.mark.parametrize("parallel", [False, True])
def test_retry_cooldown_and_chunk_gaps_are_in_wall_eta(clock, parallel):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100, verification_profile=object() if parallel else None)
    progress.start(199, 100)
    progress.native_start()
    clock[0] = 5
    advance(progress, reader, 5)
    assert progress.latest["eta_seconds"] == 95
    clock[0] = 10
    progress.report(reader, "retrying", error_type="ValidatorChainError")
    progress.finish()
    clock[0] = 110
    progress.start(199, reader._next)
    progress.report(reader, "running")
    assert progress.latest["stage"] == "native_history"
    assert progress.latest["elapsed_seconds"] == 110
    assert progress.latest["active_elapsed_seconds"] == 10
    assert progress.latest["eta_seconds"] is None  # No renewed progress yet.
    progress.native_start()
    clock[0] = 115
    advance(progress, reader, 5)
    assert progress.latest["native_elapsed_seconds"] == 15
    assert progress.latest["native_verified_blocks_per_second"] == pytest.approx(10 / 15)
    assert progress.latest["blocks_per_second"] == pytest.approx(10 / 115)
    assert progress.latest["eta_seconds"] == pytest.approx(90 * 115 / 10)
    progress.report(reader, "pending")
    progress.finish()
    clock[0] = 125
    progress.start(199, reader._next)
    progress.native_start()
    clock[0] = 130
    advance(progress, reader, 5)
    assert progress.latest["blocks_per_second"] == pytest.approx(15 / 130)
    assert progress.latest["stage"] == "native_history"


def test_verification_ahead_of_ordered_prefix_cannot_inflate_eta(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.native_start()
    clock[0] = 10
    for height in range(100, 110):
        progress.native_finished(height)
    for height in range(100, 103):
        progress.applied(height)
    reader._next = 103
    progress.report(reader, "running")
    assert progress.latest["native_verified_blocks_per_second"] == 1
    assert progress.latest["blocks_per_second"] == 0.3
    assert progress.latest["verified_ahead_of_applied_blocks"] == 7
    assert progress.latest["eta_seconds"] == pytest.approx(97 / 0.3)


def test_stall_withdraws_eta_until_ordered_progress_returns(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.native_start()
    clock[0] = 5
    advance(progress, reader, 5)
    clock[0] = 66
    progress.report(reader, "running")
    assert progress.latest["state"] == "stalled"
    assert progress.latest["eta_seconds"] is None
    progress.finish()
    clock[0] = 70
    progress.start(199, reader._next)
    progress.native_start()
    progress.report(reader, "running")
    assert progress.latest["eta_seconds"] is None
    clock[0] = 75
    advance(progress, reader, 1)
    assert progress.latest["eta_seconds"] == pytest.approx(94 * 75 / 6)


def test_same_restore_retry_includes_cooldown_in_substage(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.restore_start(100, 50)
    clock[0] = 10
    progress.report(reader, "retrying")
    progress.finish()
    clock[0] = 110
    progress.start(199, 100)
    progress.restore_start(100, 50)
    progress.report(reader, "running")
    assert progress.latest["stage_planning_eta_seconds"] is None
    assert progress.latest["stage_eta_seconds"] is None
    clock[0] = 120
    reader._next = 110
    progress.report(reader, "running")
    assert progress.latest["stage_elapsed_seconds"] == 120
    assert progress.latest["stage_eta_seconds"] == 480
    assert progress.latest["blocks_per_second"] is None


def test_short_same_target_passes_do_not_hide_no_progress_stall(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    for now in (0, 25, 50, 75):
        clock[0] = now
        progress.start(199, reader._next)
        progress.report(reader, "running")
        progress.finish()
    assert progress.latest["state"] == "stalled"
    assert progress.latest["elapsed_seconds"] == 75
    assert progress.latest["eta_seconds"] is None
    assert progress.latest["planning_eta_seconds"] is None
    clock[0] = 80
    progress.start(199, reader._next)
    progress.native_start()
    clock[0] = 85
    advance(progress, reader, 5)
    assert progress.latest["state"] == "running"
    assert progress.latest["eta_seconds"] == 95


def test_advancing_exact_ancestry_avoids_false_stall_but_stale_samples_withdraw_eta(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.restore_start(100, 50)
    sample = {
        "anchor_evidence_sha256": "ab" * 32,
        "target_block": 149,
        "state": "running",
        "completed_links": 10,
        "elapsed_seconds": 50,
        "eta_seconds": 100,
        "eta_scope": "current_owned_ancestry_only_excludes_block_proofs_and_rewards",
    }
    for now, completed in ((50, 10), (100, 20)):
        clock[0] = now
        progress.report(
            reader, "running", ancestry_progress={**sample, "completed_links": completed}
        )
        assert progress.latest["state"] == "running"
        assert progress.latest["stage_eta_seconds"] == 100
        assert progress.latest["eta_seconds"] is None
        assert progress.latest["native_completed"] == progress.latest["applied_blocks"] == 0
    for now, completed in ((161, 20), (170, 19), (180, 20)):
        clock[0] = now
        progress.report(
            reader, "running", ancestry_progress={**sample, "completed_links": completed}
        )
        assert progress.latest["state"] == "stalled"
        assert progress.latest["stage_eta_seconds"] is None
    clock[0] = 190
    progress.report(reader, "running", ancestry_progress={**sample, "completed_links": 21})
    assert progress.latest["state"] == "running"
    assert progress.latest["stage_eta_seconds"] == 100
    progress.restore_start(100, 50)
    progress.report(reader, "running")
    assert progress.latest["stage"] == "checkpoint_restore"
    assert progress.latest["ancestry_progress"] is None


def test_live_ancestry_watch_only_observes_active_selected_target(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    telemetry = SimpleNamespace(
        active=True,
        latest={
            "anchor_evidence_sha256": "ab" * 32,
            "target_block": 150,
            "state": "running",
            "completed_links": 50,
        },
    )
    with progress.watch_ancestry(telemetry, 149):
        clock[0] = 61
        progress.report(reader, "running")
        assert progress.latest["state"] == "stalled"
        telemetry.latest["target_block"] = 149
        progress.report(reader, "running")
        assert progress.latest["state"] == "running"
        telemetry.active = False
        telemetry.latest["completed_links"] = 100
        clock[0] = 122
        progress.report(reader, "running")
        assert progress.latest["state"] == "stalled"
    telemetry.active = True
    telemetry.latest["completed_links"] = 150
    progress.report(reader, "running")
    assert progress.latest["state"] == "stalled"


def test_target_change_and_explicit_cursor_reset_start_fresh_timing(clock):
    progress = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    progress.start(199, 100)
    progress.native_start()
    clock[0] = 5
    advance(progress, reader, 5)
    progress.finish()
    clock[0] = 100
    progress.start(299, reader._next)
    progress.report(reader, "running")
    assert progress.latest["elapsed_seconds"] == 0
    assert progress.latest["active_elapsed_seconds"] == 0
    assert progress.latest["native_completed"] == 0
    assert progress.latest["verified_blocks"] == progress.latest["completed_blocks"] == 5
    assert progress.latest["stage"] == "history_preparation"
    progress.native_start()
    clock[0] = 105
    advance(progress, reader, 5)
    progress.finish()
    clock[0] = 200
    reader._next = 100
    progress.start(299, 100, repair=True)
    progress.report(reader, "running")
    assert progress.latest["stage"] == "scoped_checkpoint_repair"
    assert progress.latest["elapsed_seconds"] == 0
    assert progress.latest["native_completed"] == 0
    assert progress.latest["verified_blocks"] == 10


def test_restarted_reader_restores_completed_checkpoints_without_old_rate(clock):
    original = module.HistoryProgress(100)
    reader = SimpleNamespace(_next=100)
    original.start(109, 100)
    original.native_start()
    clock[0] = 10
    advance(original, reader, 10)
    original.report(reader, "completed")
    original.finish()
    clock[0] = 1000
    original.start(109, reader._next)
    original.report(reader, "completed")
    assert original.latest["elapsed_seconds"] == 10
    assert original.latest["native_wall_elapsed_seconds"] == 10
    assert original.latest["eta_seconds"] == 0
    original.finish()
    clock[0] = 1001
    original.start(109, reader._next)
    original.report(reader, "completed")
    assert original.latest["elapsed_seconds"] == 10
    original.finish()
    restarted = module.HistoryProgress(100)
    reader._next = 100
    restarted.start(109, 100)
    restarted.restore_start(100, 10)
    for height in range(100, 110):
        restarted.record("verified", height)
        restarted.applied(height)
    clock[0] = 1005
    reader._next = 110
    restarted.restored_completed = 10
    restarted.report(reader, "completed")
    assert restarted.latest["elapsed_seconds"] == 4
    assert restarted.latest["native_completed"] == 0
    assert restarted.latest["blocks_per_second"] is None
    assert restarted.latest["stage_eta_seconds"] == restarted.latest["eta_seconds"] == 0


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
