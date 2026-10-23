from umi.competition_model_certification_progress import ModelCertificationProgress


def inventory(done=1, scope="original"):
    return dict(
        cohort_sha256="c",
        roster_sha256=scope,
        completed=done,
        total=3,
        pending_submission_sha256s=tuple("abc"[done:]),
    )


def test_progress_resets_rate_after_replacement_or_restart_without_losing_counts():
    state = ModelCertificationProgress()
    assert state.report(inventory(), now=10)["percent"] == 100 / 3
    measured = state.report(inventory(2), now=30)
    assert measured["eta_seconds"] == 20 and measured["sample_certificates"] == 1
    replacement = state.report(inventory(2, scope="replacement"), now=40)
    assert replacement["completed"] == 2 and replacement["eta_seconds"] is None
    restarted = ModelCertificationProgress().report(inventory(2), now=50)
    assert restarted["completed"] == 2 and restarted["eta_seconds"] is None


def test_known_failure_withdraws_eta_and_successful_retry_restores_measurement():
    state = ModelCertificationProgress()
    state.report(inventory(), now=10)
    state.operation("c", "c", "intent_preparation", error_type="ValueError")
    blocked = state.report(inventory(2), now=30)
    assert blocked["blocked_count"] == 1 and blocked["eta_seconds"] is None
    assert blocked["eta_basis"] == "blocked_acceptance_stage"
    state.operation("c", "c", "payload")
    assert state.report(inventory(2), now=31)["blocked_count"] == 1
    state.operation("c", "c", "intent_preparation")
    assert state.report(inventory(2), now=40)["eta_seconds"] == 30


def test_missing_previously_completed_certificate_is_an_explicit_repair():
    state = ModelCertificationProgress()
    state.report(inventory(2), now=10)
    damaged = state.report(inventory(1), now=20)
    assert damaged["repair_required"] and damaged["eta_seconds"] is None
    assert damaged["eta_basis"] == "acceptance_inventory_repair_required"
