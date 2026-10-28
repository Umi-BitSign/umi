import pytest

from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver

from .test_competition_cohort_model_acceptance import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_acceptance import (
    capture_at,
    certify,
    observe,
)
from .test_competition_cohort_model_acceptance import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_acceptance import (
    policy as policy,
)
from .test_competition_cohort_model_acceptance import (
    prepared as prepared,
)
from .test_competition_cohort_model_acceptance import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_acceptance import (
    recovery as recovery,
)
from .test_competition_cohort_model_acceptance import (
    runtime as runtime,
)

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


def test_model_seal_restart_never_rechecks_unchanged_certificates(prepared, monkeypatch):
    import umi.competition_cohort_seal_reuse as reuse

    owner, cohort, subs, inputs = prepared
    for sub in subs:
        owner.publish(certify(owner, cohort, sub, inputs), capture_at(220))
    tip = history_tip(owner.intake.history(cohort))
    seal = owner.intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)

    def unexpected(*args, **kwargs):
        raise AssertionError("completed certificate or consent re-read")

    monkeypatch.setattr(reuse, "read_publication", unexpected)
    monkeypatch.setattr(reuse, "read_participation", unexpected)
    reopened = CohortIntake(
        owner.intake.config, owner.intake.policy, eligible_tracks=("endpoint", "model")
    )
    assert reopened.sealed(cohort, tip) == seal


def test_native_phase_rollback_keeps_completed_participations_and_certificates(
    prepared, monkeypatch
):
    import umi.competition_cohort_seal_reuse as reuse

    owner, cohort, subs, inputs = prepared
    for sub in subs:
        owner.publish(certify(owner, cohort, sub, inputs), capture_at(220))
    phase = CohortIntakePhaseObserver(owner.intake)
    for block in range(200, 300, 5):
        observe(phase, cohort, block)
    original = reuse.IntakeSealReuse.record_created

    def interrupted(self, *args):
        original(self, *args)
        raise InterruptedError("fixture abort before seal/service transaction commit")

    monkeypatch.setattr(reuse.IntakeSealReuse, "record_created", interrupted)
    with pytest.raises(InterruptedError):
        observe(phase, cohort, 300)
    with owner.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_intake_seals").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT COUNT(*) FROM intake_seal_reuse_results WHERE kind='seal'"
            ).fetchone()[0]
            == 0
        )
        assert (
            db.execute(
                "SELECT COUNT(*) FROM intake_seal_reuse_results WHERE kind='acceptance'"
            ).fetchone()[0]
            == 2
        )
    monkeypatch.setattr(reuse.IntakeSealReuse, "record_created", original)

    def unexpected(*args, **kwargs):
        raise AssertionError("completed native work replayed after transaction rollback")

    monkeypatch.setattr(reuse, "read_publication", unexpected)
    monkeypatch.setattr(reuse, "read_participation", unexpected)
    assert observe(phase, cohort, 305).seal is not None


def test_unselected_acceptance_does_not_invalidate_completed_seal(prepared, monkeypatch):
    import umi.competition_cohort_seal_reuse as reuse

    owner, cohort, subs, inputs = prepared
    for sub in subs:
        owner.publish(certify(owner, cohort, sub, inputs), capture_at(220))
    tip = history_tip(owner.intake.history(cohort))
    expected = owner.intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    with owner.intake._connection() as (db, _):
        raw = db.execute("SELECT body FROM cohort_model_acceptances LIMIT 1").fetchone()[0]
        db.execute("INSERT INTO cohort_model_acceptances VALUES (?,?,?)", (cohort, "00" * 32, raw))

    def unexpected(*args, **kwargs):
        raise AssertionError("unselected certificate invalidated the sealed roster")

    monkeypatch.setattr(reuse.IntakeSealReuse, "build", unexpected)
    assert owner.intake.sealed(cohort, tip) == expected
