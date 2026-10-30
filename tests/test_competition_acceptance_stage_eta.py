"""Acceptance substages expose scoped planning ETAs and learn completed costs."""

from collections import defaultdict, deque
from types import SimpleNamespace

from umi import competition_cohort_model_acceptance_worker as acceptance_module
from umi import competition_work_progress as work_module
from umi.competition_cohort_public_progress import CohortProgressSnapshots


def test_acceptance_stage_planning_is_live_and_uses_completed_current_process_samples(
    monkeypatch,
):
    cohort = "a" * 64
    submission = "b" * 64
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(acceptance_module, "PUBLIC_COHORT_PROGRESS", snapshots)
    monkeypatch.setattr(work_module, "PUBLIC_COHORT_PROGRESS", snapshots)
    recorded, owners = [], []
    worker = object.__new__(acceptance_module.ModelAcceptanceWorker)
    worker._stage_durations = defaultdict(lambda: deque(maxlen=16))
    worker.owner = SimpleNamespace(
        intake=SimpleNamespace(
            model_certification_progress=SimpleNamespace(
                operation=lambda *args, **kwargs: recorded.append((args, kwargs)),
                acceptance_owner=lambda cohort, stage: owners.append((cohort, stage)),
            )
        )
    )
    for _ in range(5):
        with worker._stage(cohort, submission, "promotion"):
            live = snapshots.snapshot(cohort)
            assert live["components"]["acceptance"]["planning_eta_seconds"][1] <= 1200
            assert live["components"]["work"]["planning_eta_seconds"][1] <= 1200
    with worker._stage(cohort, submission, "promotion"):
        live = snapshots.snapshot(cohort)
        acceptance = live["components"]["acceptance"]
        assert acceptance["eta_samples"] == 5
        assert acceptance["eta_basis"].startswith("planning_current_process_completed_stage")
        assert acceptance["planning_eta_seconds"][1] <= 600
    assert len(recorded) == 6
    assert owners == [(cohort, "promotion")] * 6
