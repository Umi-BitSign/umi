"""Inventory is planning only; component forecasts must represent unequal work."""

import pytest

from umi.competition_model_batch_progress import (
    ModelBatchProgress,
    ModelReviewWork,
    ModelWorkInventory,
)

from .test_competition_chunked_model_backup import selected, selection
from .test_open_competition import policy as policy


def test_inventory_counts_exact_files_chunks_and_namespace_without_payload_reads(policy):
    a = selected(policy, weights=b"a" * 100)
    b = selected(policy, weights=b"b" * 200)
    c = selected(policy, weights=b"b" * 200, object_key_prefix="preservation/v1/")
    inventory = ModelWorkInventory()
    first = inventory.add(selection(a), metadata_only=False)
    second = inventory.add(selection(b), metadata_only=False)
    other_namespace = inventory.add(selection(c), metadata_only=False)
    assert first.potential_payload_bytes == first.declared_bytes
    assert second.potential_payload_bytes == 200
    assert second.declared_bytes > second.potential_payload_bytes
    assert first.generation_heads == second.generation_heads == 14
    assert other_namespace.potential_payload_bytes == other_namespace.declared_bytes
    assert not a.remote.reads and not a.remote.heads
    assert not b.remote.reads and not c.remote.heads


def test_inventory_tracking_bound_degrades_planning_without_refusing_work(policy, monkeypatch):
    monkeypatch.setattr("umi.competition_model_batch_progress._MAX_TRACKED_FILES", 1)
    case = selected(policy)
    inventory = ModelWorkInventory()
    a = inventory.add(selection(case), metadata_only=False)
    b = inventory.add(selection(case), metadata_only=False)
    assert len(inventory.seen) == 1
    assert not a.reuse_inventory_complete and not b.reuse_inventory_complete
    assert 0 < b.potential_payload_bytes < a.potential_payload_bytes
    assert inventory.add(selection(case), metadata_only=True).potential_payload_bytes == 0
    assert not case.remote.reads


def work(payload, *, declared=None):
    return ModelReviewWork(
        "ab" * 32, (payload or 100) if declared is None else declared, payload, 10, 10, True
    )


def completed(report, *, native, verification, initial=5, final=5):
    for stage, elapsed in (
        ("chunked_model_remote_metadata", initial),
        ("chunked_model_generation_confirmation", final),
    ):
        report(
            {
                "stage": stage,
                "status": "completed",
                "completed_units": 5,
                "total_units": 5,
                "unit": "objects",
                "elapsed_seconds": elapsed,
            }
        )
    report(
        {
            "stage": "chunked_model_verification",
            "status": "completed",
            "completed_units": native,
            "total_units": native,
            "unit": "bytes",
            "native_bytes": native,
            "restored_bytes": 0,
            "elapsed_seconds": verification + final,
        }
    )


def parent(events):
    return [e for e in events if e.get("stage") == "batch"][-1]


def test_component_forecast_represents_large_remaining_model_and_separate_heads():
    events = []
    with ModelBatchProgress(
        "batch", (work(3 * 1024**2), work(0), work(30 * 1024**2)), events.append
    ) as batch:
        completed(batch.child_report(0), native=3 * 1024**2, verification=100)
        batch.advance(0, 111)
        completed(batch.child_report(1), native=0, verification=1)
        batch.advance(1, 12)
        event = parent(events)
        assert event["eta_seconds"] == pytest.approx(1002)
        assert event["estimated_finish_utc"]
        assert event["eta_basis"] == "planning_native_components_unchanged_generations"
        c = event["component_work"]
        assert c["potential_payload_bytes_remaining"] == 30 * 1024**2
        assert c["generation_HEAD_operations_remaining"] == 10
        assert c["generation_HEAD_operations_observed"] == 20
        assert c["native_payload_bytes_observed"] == 3 * 1024**2
        assert not c["probability_coverage_calibrated"]
        assert not c["active_partial_work_credited"]
        assert "boot_adoption_and_upload_recovery" in event["eta_scope"]


def test_late_child_is_bound_to_original_model_not_parent_counter():
    events = []
    with ModelBatchProgress("batch", (work(3 * 1024**2), work(0)), events.append) as batch:
        first, second = batch.child_report(0), batch.child_report(1)
        completed(first, native=3 * 1024**2, verification=100)
        batch.advance(0, 111)
        # The next reporter exists before an earlier child's late delivery.
        completed(first, native=3 * 1024**2, verification=100)
        completed(second, native=0, verification=1)
        batch.advance(1, 12)
    event = parent(events)
    assert event["status"] == "completed" and event["eta_seconds"] == 0
    assert event["component_work"]["native_payload_bytes_observed"] == 3 * 1024**2
    assert event["component_work"]["generation_HEAD_operations_observed"] == 20


@pytest.mark.parametrize("cause", ["repair", "unexpected_native_bytes"])
def test_completed_native_repair_replans_but_active_repair_withdraws(cause):
    events = []
    with ModelBatchProgress("batch", (work(0), work(0)), events.append) as batch:
        report = batch.child_report(0)
        if cause == "repair":
            report(
                {
                    "stage": "chunked_model_verification",
                    "status": "repair_required",
                    "reason_code": "shared_file_byte_check_incomplete_or_missing",
                }
            )
            batch.progress.emit("running")
            assert parent(events)["eta_seconds"] is None
            assert parent(events)["eta_basis"] == "withdrawn_active_native_repair"
        completed(report, native=1 if cause == "unexpected_native_bytes" else 0, verification=1)
        batch.advance(0, 12)
        event = parent(events)
        assert event["eta_seconds"] is not None
        assert event["eta_basis"] == "planning_native_components_after_completed_repair"
        assert event["component_work"]["work_plan_revised_models"] == 1
        assert not event["certification_authority"]


def test_stall_withdraws_component_and_model_count_estimates():
    events = []
    with ModelBatchProgress("batch", (work(0), work(0)), events.append) as batch:
        completed(batch.child_report(0), native=0, verification=1)
        batch.advance(0, 12)
        assert parent(events)["eta_seconds"] is not None
        batch.progress.emit("stalled")
        event = parent(events)
        assert event["eta_seconds"] is None and event["planning_eta_seconds"] is None
        assert event["eta_basis"] == "withdrawn_stalled_or_retrying"


def test_forecast_revisions_survive_restart_and_count_one_completed_scope(tmp_path):
    from umi.competition_forecast import ForecastLedger, forecast_scope

    ledger = ForecastLedger(tmp_path / "forecasts")
    events = []
    for _ in range(2):
        with (
            forecast_scope(ledger, cohort="a" * 64, work_sha256="b" * 64, operation="model_batch"),
            ModelBatchProgress("batch", (work(0), work(0)), events.append) as batch,
        ):
            for index in range(2):
                completed(batch.child_report(index), native=0, verification=1)
                batch.advance(index, 12)
    key = ledger.scopes()[0]
    rows = ledger.records(key)
    forecasts = [r for r in rows if r["kind"] == "forecast" and r["eta_seconds"] is not None]
    assert forecasts and all(r["classification"] == "planning_scenario" for r in forecasts)
    assert all(r["rate_semantics"] == "umi-model-batch-native-components/1" for r in forecasts)
    assert all(r["finish_range_unix_ms"] for r in forecasts)
    assert ledger.status(key)["completion_examples"] == 1
    ledger.close()
    restored = ForecastLedger(tmp_path / "forecasts")
    assert restored.records(key) == rows
    assert restored.status(key)["completion_examples"] == 1
    restored.close()


def test_new_invocation_and_metadata_only_export_do_not_borrow_payload_rates():
    events = []
    with ModelBatchProgress("batch", (work(0), work(0)), events.append) as batch:
        assert parent(events)["eta_seconds"] is None
        assert parent(events)["planning_eta_seconds"]
        report = batch.child_report(0)
        for stage in ("chunked_model_remote_metadata", "chunked_model_generation_confirmation"):
            report(
                {
                    "stage": stage,
                    "status": "completed",
                    "completed_units": 5,
                    "total_units": 5,
                    "unit": "objects",
                    "elapsed_seconds": 5,
                }
            )
        batch.advance(0, 12)
        assert parent(events)["eta_seconds"] == pytest.approx(12)
    with ModelBatchProgress("batch", (work(0), work(0)), events.append):
        event = parent(events)
        assert event["eta_seconds"] is None
        assert event["component_work"]["completed_component_models"] == 0


def test_rate_window_is_bounded_but_complete_work_counts_are_retained():
    events = []
    with ModelBatchProgress("batch", tuple(work(0) for _ in range(100)), events.append) as batch:
        for index in range(100):
            completed(batch.child_report(index), native=0, verification=1)
            batch.advance(index, 12)
        assert not batch.events
    event = parent(events)
    counts = event["component_work"]
    assert counts["completed_component_models"] == counts["component_rate_window_max_models"] == 64
    assert counts["generation_HEAD_operations_observed"] == 1000
    assert counts["declared_bytes_completed"] == counts["declared_bytes_total"] == 10000
    assert counts["generation_HEAD_operations_remaining"] == 0
    assert event["completed_units"] == 100


@pytest.mark.parametrize("failure", ["capacity", "damaged"])
def test_diagnostic_ledger_failure_is_visible_and_does_not_block_native_completion(failure):
    from umi.competition_forecast import ForecastCapacityRequired, forecast_scope

    class BrokenLedger:
        def append(self, *_args):
            if failure == "capacity":
                raise ForecastCapacityRequired("test capacity")
            raise OSError("test damaged accounting")

        def note_failure(self, *_args, **_kwargs):
            raise OSError("test health storage also unavailable")

    events = []
    with (
        forecast_scope(BrokenLedger(), cohort="a" * 64, work_sha256="b" * 64, operation="batch"),
        ModelBatchProgress("batch", (work(0),), events.append) as batch,
    ):
        completed(batch.child_report(0), native=0, verification=1)
        batch.advance(0, 12)
    event = parent(events)
    assert event["status"] == "completed" and event["eta_seconds"] == 0
    assert event["forecast_accounting"]["status"] == (
        "capacity_required" if failure == "capacity" else "repair_required"
    )
