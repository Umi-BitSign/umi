from collections import OrderedDict
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_api as api
from umi import competition_cohort_public_progress as module
from umi.competition_cohort_public_progress import CohortProgressSnapshots

C = "c" * 64


def test_progress_is_bounded_redacted_and_returns_independent_snapshots():
    state = CohortProgressSnapshots(maximum_cohorts=1)
    state.record(
        "certification",
        dict(
            cohort_sha256=C,
            completed=2,
            total=3,
            percent=200 / 3,
            eta_seconds=30,
            eta_basis="measured",
            private_input="secret",
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "model_certification" and result["completed"] == 2
    assert 0 < result["eta_seconds"] <= 30
    assert "secret" not in str(result)
    result["components"]["certification"]["completed"] = 0
    assert state.snapshot(C)["completed"] == 2
    state.record("work", dict(cohort_sha256="d" * 64, stage="payload"))
    assert state.snapshot(C)["percent"] is None


def test_acceptance_planning_range_counts_down_without_external_work(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record(
        "acceptance",
        dict(
            cohort_sha256=C,
            stage="promotion",
            status="running",
            planning_eta_seconds=[30, 120],
            eta_basis="planning_previous_stage_durations",
            eta_samples=5,
        ),
    )
    now[0] = 60.0
    current = state.snapshot(C)["components"]["acceptance"]
    assert current["planning_eta_seconds"] == [0, 70]
    assert current["eta_samples"] == 5
    now[0] = 131.0
    overdue = state.snapshot(C)["components"]["acceptance"]
    assert overdue["planning_eta_seconds"] is None
    assert overdue["eta_basis"] == "planning_range_exceeded_retrying"
    assert overdue["stalled_or_retrying"] is True


def test_certification_planning_range_counts_down_on_public_reads(monkeypatch):
    now = [10.0]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record(
        "intake_certification",
        dict(
            cohort_sha256=C,
            completed=82,
            total=83,
            percent=100 * 82 / 83,
            elapsed_seconds=20,
            planning_eta_seconds=[30, 1200],
            eta_basis="planning_30_to_1200_seconds_per_remaining_certificate",
        ),
    )
    now[0] = 30.0
    current = state.snapshot(C)
    assert current["planning_eta_seconds"] == [10, 1180]
    assert current["components"]["intake_certification"]["elapsed_seconds"] == 20
    now[0] = 1211.0
    overdue = state.snapshot(C)
    assert overdue["planning_eta_seconds"] is None
    assert overdue["stalled_or_retrying"] is True


def test_restart_is_unknown_and_stale_or_overdue_measurements_withdraw_eta(monkeypatch):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    assert state.snapshot(C)["percent"] is None
    state.record(
        "certification",
        dict(
            cohort_sha256=C,
            completed=1,
            total=2,
            percent=50,
            eta_seconds=20,
            estimated_finish_unix_ms=12345,
        ),
    )
    now[0] = 31
    assert state.snapshot(C)["eta_basis"] == "forecast_overdue"
    assert state.snapshot(C)["eta_seconds"] is None
    now[0] = 200
    stale = state.snapshot(C)
    assert stale["completed"] == 1 and stale["eta_basis"] == "stale_observation"
    assert stale["estimated_finish_unix_ms"] is None
    assert CohortProgressSnapshots().snapshot(C)["percent"] is None


def test_later_phase_never_reuses_intake_percentage_or_finished_previous_work(monkeypatch):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record(
        "certification", dict(cohort_sha256=C, completed=3, total=3, percent=100, eta_seconds=0)
    )
    state.record("work", dict(cohort_sha256=C, stage="prepare", state="completed", percent=100))
    now[0] = 20
    state.record("lifecycle", dict(cohort_sha256=C, phase="requests", stage="dispatch"))
    result = state.snapshot(C)
    assert result["phase"] == "requests" and result["stage"] == "dispatch"
    assert result["percent"] is None and result["overall_percent"] is None
    now[0] = 21
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            stage="challenge_batch",
            state="running",
            completed=2,
            total=10,
            percent=20,
            eta_seconds=80,
        ),
    )
    assert state.snapshot(C)["percent"] == 20
    assert state.snapshot(C)["stage"] == "challenge_batch"


def test_hold_does_not_hide_intake_certification_and_active_operation_elapsed(monkeypatch):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, stage="automatic_progression_held"))
    state.record(
        "intake_certification",
        dict(
            cohort_sha256=C,
            completed=2,
            total=4,
            percent=50,
            selection_scope="latest_model_submissions",
        ),
    )
    state.record("acceptance", dict(cohort_sha256=C, stage="promotion", status="running"))
    now[0] = 40
    result = state.snapshot(C)
    assert result["percent"] == 50
    assert result["components"]["acceptance"]["elapsed_seconds"] == 30
    assert result["overall_eta_seconds"] is None


def test_completed_intake_certification_yields_to_progression_hold_and_new_work():
    state = CohortProgressSnapshots()
    state.record(
        "lifecycle",
        dict(
            cohort_sha256=C,
            stage="automatic_progression_held",
            status="automatic_progression_held",
            completed=0,
            total=1,
            percent=0,
            eta_seconds=None,
            eta_basis="awaiting_qualified_release_and_explicit_hold_removal",
        ),
    )
    state.record(
        "intake_certification",
        dict(cohort_sha256=C, completed=82, total=82, percent=100, eta_seconds=0),
    )
    result = state.snapshot(C)
    assert result["stage"] == "automatic_progression_held"
    assert result["completed"] == 0 and result["total"] == 1
    assert result["eta_seconds"] is None
    assert result["components"]["intake_certification"]["completed"] == 82

    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=1,
            stage="model_acceptance_export",
            state="running",
            completed=1,
            total=2,
            percent=50,
        ),
    )
    assert state.snapshot(C)["stage"] == "model_acceptance_export"

    state.record(
        "intake_certification",
        dict(cohort_sha256=C, completed=82, total=83, percent=100 * 82 / 83),
    )
    assert state.snapshot(C)["stage"] == "model_certification"


@pytest.mark.parametrize("stage", ["model_acceptance_review_quorum", "model_promotion_copy"])
def test_stale_intake_count_yields_to_current_acceptance_work(monkeypatch, stage):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, stage="automatic_progression_held"))
    state.record(
        "intake_certification",
        dict(cohort_sha256=C, completed=54, total=79, percent=100 * 54 / 79),
    )
    now[0] = 140
    state.record(
        "acceptance",
        dict(cohort_sha256=C, stage="review_quorum", status="running", total=1),
    )
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=1,
            stage=stage,
            state="running",
            completed=0,
            total=1,
            percent=0,
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == stage
    assert result["completed"] == 0 and result["percent"] == 0
    assert not result["stalled_or_retrying"]
    assert result["components"]["intake_certification"]["stale"]
    assert result["components"]["intake_certification"]["completed"] == 54


def test_active_verification_overrides_certificate_idle_stall():
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, stage="automatic_progression_held"))
    state.record(
        "intake_certification",
        dict(
            cohort_sha256=C,
            completed=77,
            total=82,
            blocked_count=0,
            repair_required=False,
            stalled_or_retrying=True,
            eta_basis="certificate_completion_idle",
        ),
    )
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=1,
            stage="remote_model_verification",
            state="running",
            completed=3,
            total=4,
            percent=75,
            stalled_or_retrying=False,
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "remote_model_verification"
    assert result["percent"] == 75
    assert result["stalled_or_retrying"] is False
    assert result["components"]["intake_certification"]["completed"] == 77


def test_current_acceptance_remains_visible_with_another_submission_blocked():
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, stage="automatic_progression_held"))
    state.record(
        "intake_certification",
        dict(
            cohort_sha256=C,
            completed=57,
            total=66,
            blocked_count=1,
            stalled_or_retrying=True,
            eta_basis="blocked_acceptance_stage",
        ),
    )
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=2,
            stage="model_promotion_copy",
            state="running",
            completed=3,
            total=10,
            percent=30,
            stalled_or_retrying=False,
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "model_promotion_copy"
    assert result["percent"] == 30
    assert result["blocked_count"] == 1
    assert result["components"]["intake_certification"]["completed"] == 57


def test_stale_intake_count_uses_live_acceptance_only_until_work_refreshes(monkeypatch):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record("intake_certification", dict(cohort_sha256=C, completed=54, total=79, percent=68))
    state.record(
        "work",
        dict(cohort_sha256=C, stage="model_acceptance_review_quorum", state="running"),
    )
    now[0] = 140
    state.record(
        "acceptance", dict(cohort_sha256=C, stage="review_quorum", status="running", total=1)
    )
    result = state.snapshot(C)
    assert result["stage"] == "model_acceptance_review_quorum"
    assert result["components"]["work"]["stale"]
    state.record(
        "work", dict(cohort_sha256=C, stage="local_model_retirement", state="running", work_id=2)
    )
    result = state.snapshot(C)
    assert result["stage"] == "model_acceptance_review_quorum"
    assert result["components"]["work"]["stage"] == "local_model_retirement"
    assert not result["stale"]
    now[0] = 270
    result = state.snapshot(C)
    assert result["stage"] == "model_certification"
    assert result["eta_basis"] == "stale_observation"
    assert result["stalled_or_retrying"]


def test_nested_transfer_remains_current_after_acceptance_heartbeat_ages(monkeypatch):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, stage="automatic_progression_held"))
    state.record("intake_certification", dict(cohort_sha256=C, completed=54, total=79))
    now[0] = 140
    state.record("acceptance", dict(cohort_sha256=C, stage="promotion", status="running", total=1))
    now[0] = 270
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=3,
            stage="r2_response_read",
            state="running",
            completed=16384,
            total=67108864,
            percent=0.0244140625,
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "r2_response_read"
    assert result["completed"] == 16384
    assert not result["stalled_or_retrying"]
    assert result["components"]["acceptance"]["stale"]
    assert result["components"]["intake_certification"]["completed"] == 54
    now[0] = 400
    assert state.snapshot(C)["eta_basis"] == "stale_observation"


async def test_progress_api_is_available_without_capture_or_database(monkeypatch):
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(api, "PUBLIC_COHORT_PROGRESS", snapshots)
    monkeypatch.setattr(api, "CohortAdmissionQueue", lambda _: None)
    snapshots.record(
        "certification",
        dict(cohort_sha256=C, completed=92, total=103, percent=100 * 92 / 103, eta_seconds=300),
    )

    async def forbidden():
        raise AssertionError("progress must not query finality or owned journals")

    app = FastAPI()
    app.include_router(
        api.cohort_routes(
            SimpleNamespace(bindings={C: "authority"}), forbidden, maximum_body_bytes=1024
        )
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="http://test"
    ) as client:
        response = await client.get(f"/v1/competition/cohorts/{C}/progress")
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        assert response.json()["completed"] == 92
        assert response.json()["certification_authority"] is False
        assert (await client.get(f"/v1/competition/cohorts/{'d' * 64}/progress")).status_code == 404


def test_execution_counts_are_separate_from_certification_and_current_native_work(monkeypatch):
    now = [10]
    monkeypatch.setattr(module.time, "monotonic", lambda: now[0])
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, phase="requests", stage="progress_sampling"))
    state.record(
        "execution",
        dict(
            cohort_sha256=C,
            stage="model_evaluation",
            completed=3,
            total=103,
            percent=100 * 3 / 103,
            exported_executions=94,
            exported_inferences=64,
            reused_incumbent_observations=30,
            exported_comparisons=40,
            projected_executions=1236,
            eta_seconds=None,
            eta_basis="insufficient_completed_assignment_rate_samples",
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "model_evaluation" and result["completed"] == 3
    assert result["exported_executions"] == 94
    assert result["exported_inferences"] == 64
    assert result["reused_incumbent_observations"] == 30
    assert result["overall_percent"] is None and result["overall_eta_seconds"] is None
    for old_stage in (
        "model_acceptance_export",
        "preparation_result_publication",
        "lifecycle_history_publication",
        "chunked_model_verification_commit",
    ):
        state.record(
            "work",
            dict(
                cohort_sha256=C, stage=old_stage, state="running", completed=0, total=1, percent=0
            ),
        )
        result = state.snapshot(C)
        assert result["stage"] == "model_evaluation" and result["completed"] == 3
        assert result["components"]["work"]["stage"] == old_stage
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            stage="native_phase_review",
            state="running",
            completed=1,
            total=4,
            percent=25,
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "native_phase_review"
    assert result["components"]["execution"]["completed"] == 3
    now[0] = 200
    assert state.snapshot(C)["components"]["execution"]["stale"]
    state.record("lifecycle", dict(cohort_sha256=C, phase="review", stage="decision_certification"))
    assert state.snapshot(C)["stage"] != "model_evaluation"


def test_active_transfer_stays_visible_between_short_completed_work(monkeypatch):
    from umi.competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS, PUBLIC_COHORT_SCOPE
    from umi.competition_transport_verification import TransferProgress
    from umi.competition_work_progress import WorkProgress

    monkeypatch.setattr(PUBLIC_COHORT_PROGRESS, "entries", OrderedDict())
    with (
        WorkProgress("model_promotion", 1, unit="models", cohort=C),
        TransferProgress("remote_model_verification", 100, report=lambda _: None) as transfer,
    ):
        transfer.advance(50)
        transfer.emit("running")
        with WorkProgress("history_publication", 1, unit="histories", cohort=C) as short:
            short.advance()
        snapshot = PUBLIC_COHORT_PROGRESS.snapshot(C)
        work = snapshot["components"]["work"]
        assert work["stage"] == "remote_model_verification"
        assert (work["completed"], work["total"], work["percent"]) == (50, 100, 50)
        assert PUBLIC_COHORT_SCOPE.get() == C
    assert PUBLIC_COHORT_SCOPE.get() is None
    assert not PUBLIC_COHORT_PROGRESS.entries[C]["active_work"]


def test_active_work_inventory_remains_bounded():
    state = CohortProgressSnapshots()
    for number in range(100):
        state.record("work", dict(cohort_sha256=C, work_id=number, state="running", stage="copy"))
    assert len(state.entries[C]["active_work"]) == 32


def test_request_rest_clock_is_not_hidden_by_unrelated_work():
    state = CohortProgressSnapshots()
    state.record(
        "lifecycle",
        dict(
            cohort_sha256=C,
            phase="preparation",
            stage="request_start",
            status="waiting_request_rest",
        ),
    )
    state.record(
        "request_start",
        dict(
            cohort_sha256=C,
            ready=False,
            not_before_unix_ms=12345,
            completed=10,
            total=100,
            percent=10,
            eta_seconds=90,
            eta_scope="request_rest_wait_only",
        ),
    )
    state.record(
        "work",
        dict(cohort_sha256=C, stage="model_acceptance_publication", state="started", work_id=1),
    )
    result = state.snapshot(C)
    assert result["stage"] == "waiting_request_rest"
    assert result["not_before_unix_ms"] == 12345
    assert result["percent"] == 10 and 0 < result["eta_seconds"] <= 90
    assert result["overall_eta_seconds"] is None


def test_completed_certification_yields_to_phase_review_despite_concurrent_export():
    state = CohortProgressSnapshots()
    state.record("lifecycle", dict(cohort_sha256=C, phase="intake", stage="progress_review"))
    state.record(
        "certification", dict(cohort_sha256=C, completed=103, total=103, percent=100, eta_seconds=0)
    )
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=1,
            stage="intake_progress_quorum",
            state="waiting",
            completed=0,
            total=1,
            percent=0,
            eta_seconds=30,
            eta_basis="measured",
        ),
    )
    state.record(
        "work",
        dict(
            cohort_sha256=C,
            work_id=2,
            stage="model_acceptance_export",
            state="running",
            completed=1,
            total=1,
            percent=100,
            eta_seconds=0,
        ),
    )
    result = state.snapshot(C)
    assert result["stage"] == "intake_progress_quorum"
    assert result["percent"] == 0 and 0 < result["eta_seconds"] <= 30
    assert result["components"]["certification"]["percent"] == 100


async def test_awaited_transfer_inherits_cohort_and_restores_scope_on_failure():
    from umi.competition_cohort_public_progress import PUBLIC_COHORT_SCOPE
    from umi.competition_transport_verification import TransferProgress
    from umi.competition_work_progress import await_progress

    async def transfer():
        with TransferProgress("verify", 10, report=lambda _: None) as progress:
            assert progress.public_cohort == C
            raise RuntimeError("provider unavailable")

    with pytest.raises(RuntimeError, match="provider unavailable"):
        await await_progress(transfer(), stage="promotion", cohort=C)
    assert PUBLIC_COHORT_SCOPE.get() is None
