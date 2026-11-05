from types import SimpleNamespace

import pytest

from umi.competition_cohort_intake import CohortAdmissionClosed, CohortIntake
from umi.competition_cohort_intake_window import SequentialIntakeWindow
from umi.open_competition import digest

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import policy as policy
from .test_competition_cohort_recovery import recovery as recovery


def test_window_opens_only_immediate_successor_after_requests(recovery):
    plan = recovery[0]
    plans = [plan.model_copy(update={"sequence": n}) for n in (7, 8, 9, 10, 11)]
    authority = "b" * 64
    window = SequentialIntakeWindow(8, {digest(p): authority for p in plans})

    def observe(p, phase, revision=0):
        window.observe(
            p,
            SimpleNamespace(
                cohort_sha256=digest(p),
                authority_sha256=authority,
                sequence=revision,
                tip_sha256=str(revision),
                phase=phase,
            ),
        )

    for p in plans:
        observe(p, "complete" if p.sequence == 7 else "intake")
    assert window.status(digest(plans[1]))["new_admissions_open"]
    assert not window.status(digest(plans[2]))["new_admissions_open"]
    observe(plans[1], "preparation", 1)
    assert not window.status(digest(plans[2]))["new_admissions_open"]
    observe(plans[1], "requests", 2)
    assert window.status(digest(plans[2]))["new_admissions_open"]
    assert not window.status(digest(plans[3]))["new_admissions_open"]
    observe(plans[2], "requests", 1)
    assert window.status(digest(plans[3]))["new_admissions_open"]
    assert not window.status(digest(plans[4]))["new_admissions_open"]
    # An older observation cannot close an already advanced predecessor.
    observe(plans[2], "intake", 0)
    assert window.status(digest(plans[3]))["new_admissions_open"]


def enable_window(intake, scenario):
    config = intake.config.model_copy(
        update={"sequential_intake_from_sequence": scenario["intake_history"].plan.sequence}
    )
    # Existing state binding remains usable; no reset, rewrite or migration.
    return CohortIntake(config, scenario["policy"])


def test_native_admission_rejects_new_request_without_predecessor(intake, scenario):
    enabled = enable_window(intake, scenario)
    history = scenario["intake_history"]
    request = request_for(scenario)
    with (
        enabled._connection() as (db, store),
        pytest.raises(CohortAdmissionClosed, match="predecessor"),
    ):
        enabled.require_new_admission(db, history, request, store=store)
    assert enabled.admission_status(digest(history.plan))["new_admissions_open"] is False


def test_exact_accepted_reservation_survives_window_change_and_restart(intake, scenario):
    history = scenario["intake_history"]
    request = request_for(scenario)
    with intake._connection() as (db, store):
        intake.require_new_admission(db, history, request, store=store)
    enabled = enable_window(intake, scenario)
    with enabled._connection() as (db, store):
        enabled.require_new_admission(db, history, request, store=store)
        with pytest.raises(CohortAdmissionClosed):
            enabled.require_new_admission(
                db, history, request_for(scenario, sequence=2), store=store
            )
    assert enabled.has_admission_permit(request)


def test_existing_participation_stays_valid_but_replacement_is_held(intake, scenario):
    request = request_for(scenario)
    receipt = intake.retain(request, capture_at(210))
    enabled = enable_window(intake, scenario)
    assert enabled.retain(request, capture_at(210)) == receipt
    with pytest.raises(CohortAdmissionClosed, match="predecessor"):
        enabled.retain(request_for(scenario, sequence=2), capture_at(220))
