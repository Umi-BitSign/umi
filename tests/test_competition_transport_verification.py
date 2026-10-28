"""Private transport receipts: scoped repairs, trust boundaries and truthful progress."""

import os

import pytest

from umi import competition_transport_verification as transport
from umi.competition_cohort_public_progress import EXECUTION_JOB_SCOPE, execution_job_scope
from umi.private_files import PrivateStateBusyError


def test_transfer_monitor_keeps_job_and_work_identity_after_scope_exit():
    events = []
    with execution_job_scope("a" * 64):
        meter = transport.TransferProgress("model", 1, events.append)
    assert EXECUTION_JOB_SCOPE.get() is None
    meter.emit("waiting")
    meter.advance(1)
    assert {event["job_sha256"] for event in events} == {"a" * 64}
    assert {event["pid"] for event in events} == {os.getpid()}
    assert {event["work_id"] for event in events} == {meter.public_work_id}
    with execution_job_scope("invalid private text"):
        invalid = transport.TransferProgress("model", 1, events.append)
    invalid.emit("waiting")
    assert events[-1]["job_sha256"] is None
    assert events[-1]["work_id"] != meter.public_work_id


def test_checkpoint_repair_is_visible_and_does_not_touch_unchanged_slot(tmp_path):
    events = []
    with (
        transport.TransferProgress("check", 10, events.append) as progress,
        transport.ByteCheckpoints(tmp_path / "state", {"abi": 1}, progress) as saved,
    ):
        saved.remember("a", [1], "a" * 64)
        saved.remember("b", [2], "b" * 64)
        saved.path("a").unlink()
        assert saved.load("a", [1]) is None
        assert events[-1]["status"] == "repair_required"
        assert events[-1]["planning_eta_seconds"] is None
        assert saved.load("b", [2]) == "b" * 64
        progress.advance(10)
        saved.remember("a", [1], "a" * 64)
        assert events[-1]["status"] == "repair_completed"
    assert events[-1]["status"] == "completed"


@pytest.mark.parametrize("damage", [b"", b"{", b"[]", b"null", b"\xff", b"{}"])
def test_damaged_checkpoint_native_repair_is_explicit(tmp_path, damage):
    events = []
    with transport.ByteCheckpoints(
        tmp_path / "state", {}, transport.TransferProgress("check", 1, events.append)
    ) as saved:
        saved.remember("slot", [1], "a" * 64)
        saved.path("slot").write_bytes(damage)
        assert saved.load("slot", [1]) is None
        assert events[-1]["reason_code"] == "byte_receipt_damaged"
        saved.remember("slot", [1], "a" * 64)
        assert events[-1]["status"] == "repair_completed"


@pytest.mark.parametrize("damage", ["missing", "changed"])
def test_completion_marker_repairs_from_good_receipt_without_native_reads(tmp_path, damage):
    events = []
    with transport.ByteCheckpoints(
        tmp_path / "state", {}, transport.TransferProgress("check", 1, events.append)
    ) as saved:
        saved.remember("slot", [1], "a" * 64)
        marker = saved.path("slot").with_suffix(".complete")
        if damage == "missing":
            marker.unlink()
        else:
            marker.write_bytes(b"corrupt")
        assert saved.load("slot", [1]) == "a" * 64
        assert [event["status"] for event in events] == ["repair_required", "repair_completed"]
        assert marker.read_text() == saved.path("slot").stem


@pytest.mark.parametrize("target", ["receipt", "marker"])
@pytest.mark.parametrize("fault", ["symlink", "hardlink", "public", "fifo"])
def test_unsafe_checkpoint_refuses_without_overwrite(tmp_path, target, fault):
    events = []
    with transport.ByteCheckpoints(
        tmp_path / "state", {}, transport.TransferProgress("check", 1, events.append)
    ) as saved:
        saved.remember("slot", [1], "a" * 64)
        path = saved.path("slot")
        if target == "marker":
            path = path.with_suffix(".complete")
        if fault == "symlink":
            path.unlink()
            path.symlink_to(tmp_path / "absent")
        elif fault == "hardlink":
            os.link(path, tmp_path / "linked")
        elif fault == "public":
            path.chmod(0o644)
        else:
            path.unlink()
            os.mkfifo(path, 0o600)
        with pytest.raises((ValueError, OSError)):
            saved.load("slot", [1])
        assert events[-1]["status"] == "refused"


def test_checkpoint_lock_is_exclusive_and_releases_on_interrupt(tmp_path):
    progress = transport.TransferProgress("check", 1)
    with (
        pytest.raises(KeyboardInterrupt),
        transport.ByteCheckpoints(tmp_path / "state", {}, progress),
    ):
        with (
            pytest.raises(PrivateStateBusyError),
            transport.ByteCheckpoints(tmp_path / "state", {}, progress),
        ):
            pass
        raise KeyboardInterrupt
    with transport.ByteCheckpoints(tmp_path / "state", {}, progress):
        pass


def test_changed_abi_or_identity_repairs_only_that_record(tmp_path):
    events = []
    progress = transport.TransferProgress("check", 1, events.append)
    with transport.ByteCheckpoints(tmp_path / "state", {"abi": 1}, progress) as saved:
        saved.remember("slot", [1], "a" * 64)
        assert saved.load("slot", [2]) is None
        assert events[-1]["reason_code"] == "byte_verification_dependencies_changed"
    with transport.ByteCheckpoints(tmp_path / "state", {"abi": 2}, progress) as saved:
        assert saved.load("slot", [1]) is None
        assert events[-1]["reason_code"] == "byte_verification_dependencies_changed"


def test_progress_excludes_restored_bytes_and_withdraws_stale_eta(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    with transport.TransferProgress("check", 100, events.append) as progress:
        assert events[-1]["planning_eta_seconds"] is not None
        progress.advance(40, restored=True)
        now[0] += 10
        progress.advance(20)
        assert events[-1]["eta_seconds"] == 20
        assert events[-1]["native_bytes"] == 20
        assert events[-1]["restored_bytes"] == 40
        progress.emit("retrying", reason="transport_unavailable")
        assert events[-1]["eta_seconds"] is None
        now[0] += 61
        progress.emit("running")
        assert events[-1]["status"] == "stalled"
        assert events[-1]["eta_seconds"] is None
        progress.advance(40)
    assert events[-1]["percent"] == 100
    assert events[-1]["eta_scope"] == "current_transfer_substage"
    assert not events[-1]["certification_authority"]


def test_long_case_budget_does_not_become_a_sixty_second_transfer_stall(monkeypatch):
    now, events = [100.0], []
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    progress = transport.TransferProgress(
        "model_pair_execution", 12, events.append, unit="case_role_steps", idle_stall_seconds=600
    )
    now[0] += 30
    progress.advance(1)
    now[0] += 90
    progress.emit("running")
    assert events[-1]["status"] == "running" and events[-1]["eta_seconds"] is not None
    now[0] += 600
    progress.emit("running")
    assert events[-1]["status"] == "stalled" and events[-1]["eta_seconds"] is None


@pytest.mark.parametrize("interval", [0, -1, True, float("nan"), float("inf")])
def test_progress_rejects_invalid_idle_budget(interval):
    with pytest.raises(ValueError, match="idle stall interval"):
        transport.TransferProgress("case", 1, idle_stall_seconds=interval)


def test_failed_full_read_never_reports_completed():
    events = []
    with (
        pytest.raises(ValueError),
        transport.TransferProgress("check", 10, events.append) as progress,
    ):
        progress.advance(10)
        raise ValueError("checksum failure")
    assert all(event["percent"] < 100 for event in events)
    assert events[-1]["status"] == "retrying"


def test_progress_sink_failure_cannot_change_native_result():
    def report(_):
        raise RuntimeError("unavailable sink")

    with transport.TransferProgress("check", 1, report) as progress:
        progress.advance(1)


def test_progress_throttles_hot_loop_and_has_heartbeat(monkeypatch):
    events = []
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    with transport.TransferProgress("check", 100, events.append) as progress:
        for _ in range(50):
            progress.advance(1)
        assert len(events) == 2
        now[0] += 11
        progress.advance(1)
        assert len(events) == 3
        progress.advance(49)
    assert events[-1]["status"] == "completed"


def test_timestamp_wait_precedes_verification_and_is_bounded(monkeypatch):
    calls = iter([123, 123, 124])
    events = []
    monkeypatch.setattr(transport, "_publication_clock_ns", lambda: next(calls))
    monkeypatch.setattr(transport.time, "sleep", lambda _: None)
    assert transport.verification_tick(123, transport.TransferProgress("check", 1, events.append))
    assert events[0]["status"] == "waiting"
    monkeypatch.setattr(transport, "_publication_clock_ns", lambda: 123)
    assert not transport.verification_tick(
        123, transport.TransferProgress("check", 1, events.append)
    )
    assert events[-1]["reason_code"] == "byte_identity_clock_not_advanced_reuse_disabled"


def test_abi_stays_compatible_when_manifest_qualification_changes(monkeypatch):
    monkeypatch.setattr(transport, "runtime_identity", lambda: "stable-qualified-abi")
    assert transport.verifier_semantics() == [transport.BYTE_VERIFIER_ABI, "stable-qualified-abi"]


def test_generation_reset_keeps_total_elapsed_and_restarts_rate(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    with transport.TransferProgress("upload", 100, events.append) as progress:
        now[0] += 5
        progress.advance(50)
        now[0] += 5
        progress.set_completed(0)
        assert events[-1]["elapsed_seconds"] == 10
        assert events[-1]["measured_elapsed_seconds"] == 0
        now[0] += 2
        progress.advance(20)
        assert events[-1]["eta_seconds"] == 8
        assert events[-1]["elapsed_seconds"] == 12


def test_counted_migration_planning_scales_with_remaining_work(monkeypatch):
    monkeypatch.setattr(transport.time, "monotonic", lambda: 100.0)
    events = []
    with transport.TransferProgress("migration", 20, events.append, unit="files") as progress:
        assert events[-1]["planning_eta_seconds"] == [20, 6000]
        assert events[-1]["planning_seconds_per_unit"] == [1, 300]
        progress.advance(5, restored=True)
        assert events[-1]["planning_eta_seconds"] == [15, 4500]
        progress.emit("repair_required", reason="original_missing")
        assert events[-1]["eta_seconds"] is None
        assert events[-1]["planning_eta_seconds"] is None


def test_child_counts_keep_parent_active_without_claiming_export_completion(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    with transport.TransferProgress("transfer_export", 512, events.append, unit="blocks") as parent:
        child = parent.child_report()
        event = {
            "stage": "transfer",
            "status": "running",
            "completed_units": 1,
            "total_units": 256,
            "unit": "blocks",
        }
        now[0] += 50
        child(event)
        now[0] += 50
        child({**event, "completed_units": 2})
        parent.emit("running")
        assert events[-1]["status"] == "running"
        assert events[-1]["completed_units"] == events[-1]["native_units"] == 0
        assert events[-1]["percent"] == 0
        assert events[-1]["active_child"]["completed_units"] == 2
        now[0] += 61
        child({**event, "completed_units": 2})  # heartbeat cannot refresh activity
        parent.emit("running")
        assert events[-1]["status"] == "stalled"
        assert events[-1]["eta_seconds"] is None
        child({**event, "completed_units": 256, "status": "completed"})
        assert events[-1]["status"] == "running"
        assert events[-1]["completed_units"] == 0
        parent.advance(256)
        assert events[-1]["active_child"] is None
        following = parent.child_report()
        now[0] += 61
        following({**event, "completed_units": 0, "status": "started"})
        parent.emit("running")
        assert events[-1]["status"] == "stalled"
        following(event)  # a new window has its own increasing count
        assert events[-1]["status"] == "running"
        assert events[-1]["completed_units"] == 256
        parent.advance(256)
    assert events[-1]["status"] == "completed"


@pytest.mark.parametrize("state", ["stalled", "retrying", "refused", "repair_required"])
@pytest.mark.parametrize("failed_count", [1, 5])
def test_child_failed_progress_withdraws_parent_eta(monkeypatch, state, failed_count):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    parent = transport.TransferProgress("parent", 100, events.append, unit="blocks")
    parent.advance(10)
    child = parent.child_report()
    now[0] += 10
    child(
        {
            "stage": "child",
            "status": "running",
            "completed_units": 1,
            "total_units": 10,
            "unit": "blocks",
            "eta_seconds": 90,
        }
    )
    assert events[-1]["eta_seconds"] is not None
    child(
        {
            "stage": "child",
            "status": state,
            "completed_units": failed_count,
            "total_units": 10,
            "unit": "blocks",
        }
    )
    assert events[-1]["status"] == state
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["completed_units"] == 10


@pytest.mark.parametrize("child_eta", [None, 0])
def test_unfinished_child_without_forecast_withdraws_parent_eta(monkeypatch, child_eta):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    parent = transport.TransferProgress("parent", 100, events.append, unit="blocks")
    parent.advance(10)
    now[0] += 10
    parent.emit("running")
    assert events[-1]["eta_seconds"] is not None
    child = parent.child_report()
    child(
        {
            "stage": "confirmation",
            "status": "running",
            "completed_units": 1,
            "total_units": 10,
            "unit": "objects",
            "eta_seconds": child_eta,
        }
    )
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["eta_basis"] == "required_child_scope_incomplete"
    assert events[-1]["completed_units"] == 10


def test_child_forecast_cannot_replace_unmeasured_parent_work():
    events = []
    parent = transport.TransferProgress("parent", 100, events.append, unit="blocks")
    child = parent.child_report()
    child(
        {
            "stage": "child",
            "status": "running",
            "completed_units": 1,
            "total_units": 10,
            "unit": "objects",
            "eta_seconds": 90,
        }
    )
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["eta_basis"] == "waiting_for_parent_and_required_child_samples"


def test_child_planning_range_keeps_parent_forecast_as_planning(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    parent = transport.TransferProgress("parent", 100, events.append, unit="blocks")
    now[0] += 10
    parent.advance(10)
    child = parent.child_report()
    child(
        {
            "stage": "r2_read",
            "status": "running",
            "completed_units": 1,
            "total_units": 10,
            "unit": "objects",
            "planning_eta_seconds": [20, 300],
        }
    )
    event = events[-1]
    assert event["eta_seconds"] is None
    assert event["planning_eta_seconds"] == [90, 300]
    assert event["eta_basis"] == "planning_parent_and_required_child_work"
    assert event["active_child"]["planning_eta_seconds"] == [20, 300]


def test_child_planning_range_retains_unmeasured_parent_work():
    events = []
    parent = transport.TransferProgress("parent", 100, events.append, unit="blocks")
    child = parent.child_report()
    child(
        {
            "stage": "r2_read",
            "status": "running",
            "completed_units": 1,
            "total_units": 10,
            "unit": "objects",
            "planning_eta_seconds": [20, 300],
        }
    )
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["planning_eta_seconds"] == [100, 30000]
    assert events[-1]["eta_basis"] == "planning_parent_and_required_child_work"


def test_operation_tail_prevents_zero_eta_after_last_large_payload(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    with transport.TransferProgress("bytes", 1000, events.append, total_operations=10) as progress:
        now[0] += 10
        progress.advance(1000)
        now[0] += 2
        progress.advance_operations(2)
        progress.emit("running")
        assert events[-1]["eta_seconds"] == 8
        assert events[-1]["operation_eta_seconds"] == 8
        now[0] += 10
        progress.advance_operations(8)
    assert events[-1]["status"] == "completed"
    assert events[-1]["eta_seconds"] == 0


def test_bulk_weight_transfer_is_not_a_per_metadata_file_cost(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    p = transport.TransferProgress("materialize", 1000, events.append, total_operations=401)
    now[0] += 1000
    p.advance(900)
    now[0] += 1
    p.advance_operations(1)
    p.emit("running")
    event = events[-1]
    assert event["native_byte_seconds"] == 1000
    assert event["native_operation_seconds"] == 1
    assert event["operation_eta_seconds"] == 400
    assert event["eta_seconds"] == pytest.approx(100 / 0.9 + 400)
    assert event["eta_basis"] == "separate_native_byte_time_and_operation_overhead"
    # Tiny metadata operations measure their own cost, never the preceding
    # thousand-second weight transfer. No byte or completion count is invented.
    now[0] += 0.2
    p.advance(20)
    now[0] += 0.1
    p.advance_operations(100)
    p.emit("running")
    assert events[-1]["operation_eta_seconds"] == pytest.approx(300 * 1.1 / 101)
    assert events[-1]["completed_units"] == 920
    assert events[-1]["completed_operations"] == 101


def test_started_heartbeats_with_no_work_withdraw_forecast(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    p = transport.TransferProgress("read", 1000, events.append)
    p.emit("started")
    now[0] += 61
    p.emit("started")
    assert events[-1]["status"] == "stalled"
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["planning_eta_seconds"] is None


def test_reset_discards_previous_byte_and_operation_rates(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    p = transport.TransferProgress("read", 1000, total_operations=10)
    now[0] += 100
    p.advance(500)
    now[0] += 5
    p.advance_operations(3)
    p.set_completed(0)
    assert p.byte_seconds == p.operation_seconds == 0
    assert p.completed_operations == p.native_operations == 0


def test_restored_operations_do_not_inflate_rate_and_incomplete_exit_retries(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    with transport.TransferProgress("bytes", 1000, events.append, total_operations=10) as progress:
        now[0] += 10
        progress.advance(1000, restored=True)
        progress.advance_operations(8, restored=True)
        progress.emit("running")
        assert events[-1]["eta_seconds"] is None
        assert events[-1]["native_operations"] == 0
    assert events[-1]["status"] == "retrying"


def test_alternating_child_scopes_preserve_liveness_without_heartbeat_refresh(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    parent = transport.TransferProgress("models", 10, events.append, unit="models")
    child = parent.child_report()

    def send(stage, count, total=1000, **kwargs):
        child(
            dict(
                stage=stage,
                status="running",
                completed_units=count,
                total_units=total,
                unit="bytes",
                **kwargs,
            )
        )

    send("bytes", 900)
    now[0] += 50
    send("metadata", 1, total=10)
    assert events[-1]["status"] == "running"
    now[0] += 50
    send("bytes", 901)
    assert events[-1]["status"] == "running"
    now[0] += 61
    send("bytes", 901)
    parent.emit("running")
    assert events[-1]["status"] == "stalled"
    send("bytes", 0, elapsed_seconds=0)
    parent.emit("running")
    assert events[-1]["status"] == "stalled"
    # A genuinely restarted stage has an explicit zero-start, then new work.
    child(
        dict(
            stage="bytes",
            status="started",
            completed_units=0,
            total_units=1000,
            unit="bytes",
            elapsed_seconds=0,
        )
    )
    now[0] += 1
    send("bytes", 1, elapsed_seconds=1)
    assert events[-1]["status"] == "running"
    assert events[-1]["completed_units"] == 0


def test_required_child_withdraws_parent_zero_eta(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(transport.time, "monotonic", lambda: now[0])
    events = []
    parent = transport.TransferProgress("bytes", 100, events.append)
    now[0] += 10
    parent.advance(100)
    child = parent.child_report()
    child(
        dict(stage="confirm", status="started", completed_units=0, total_units=10, unit="objects")
    )
    parent.emit("running")
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["eta_basis"] == "required_child_scope_incomplete"
