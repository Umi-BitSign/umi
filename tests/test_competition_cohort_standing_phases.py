"""Native phase recovery without extension signatures; not reward qualification."""

import pytest
from pydantic import ValidationError

from umi.competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from umi.competition_cohort_intake import CohortIntake, history_tip
from umi.competition_cohort_intake_phase import CohortIntakePhaseObserver
from umi.competition_cohort_participation import admit_recovery_participant
from umi.competition_cohort_recovery import (
    PHASES,
    CohortRecoveryAuthority,
    SignedCohortRecoveryAuthority,
    StandingCohortRecoveryAuthority,
    admit_recoverable_cohort,
    apply_recovery_transition,
    propose_recovery_transition,
    verify_recovery_authority,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_consumers as consumers
from .test_competition_cohort_coordinator import Harness
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_open_competition import policy as policy
from .test_open_competition import wallet

legacy_scenario = consumers.scenario


def standing(plan, policy):
    body = StandingCohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/2",
        policy_sha256=digest(policy),
        cohort_sha256s=(digest(plan),),
        issued_at_block=150,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
        timing_rule="targets_without_extension_signatures",
    )
    signed = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    genesis, state = admit_recoverable_cohort(plan, signed, policy, admitted_at_block=160)
    return signed, genesis, state


@pytest.fixture
def scenario(legacy_scenario, policy):
    # Re-sign the exact new authority and miner consent, never reinterpret v1.
    old = legacy_scenario["intake_history"]
    authority, genesis, _ = standing(old.plan, policy)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=old.plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    consent_body = legacy_scenario["consent"].consent.model_copy(
        update={"authority_sha256": digest(authority.authority)}
    )
    consent = legacy_scenario["consent"].__class__(
        consent=consent_body, signature=sign_object(consent_body, wallet("Alice"))
    )
    return {**legacy_scenario, "intake_history": history, "consent": consent}


@pytest.fixture
def harness(tmp_path, recovery, policy):
    plan, _, _ = recovery
    authority, _, state = standing(plan, policy)
    h = Harness(tmp_path, (plan, authority, state), policy)
    yield h
    h.db.close()


def test_explicit_format_preserves_legacy_signed_bytes(recovery, policy):
    plan, old, _ = recovery
    raw = canonical_json_bytes(old)
    assert canonical_json_bytes(SignedCohortRecoveryAuthority.model_validate_json(raw)) == raw
    assert isinstance(verify_recovery_authority(old, policy), CohortRecoveryAuthority)
    new, _, _ = standing(plan, policy)
    assert isinstance(verify_recovery_authority(new, policy), StandingCohortRecoveryAuthority)
    with pytest.raises(ValueError):
        verify_recovery_authority(new.model_copy(update={"signatures": old.signatures}), policy)
    assert "maximum_extension_step_blocks" not in type(new.authority).model_fields
    with pytest.raises(ValidationError):
        StandingCohortRecoveryAuthority.model_validate_json(canonical_json_bytes(old.authority))


@pytest.mark.parametrize("phase", PHASES)
def test_every_phase_waits_through_repeated_ten_hour_and_longer_outages(harness, phase):
    h = harness
    h.advance_to(phase)
    state = h.state
    original = canonical_json_bytes(state)
    for gap in (3000, 6000, 1000000):
        h.block = state.targets[PHASES.index(phase)].target_block + gap
        h.unavailable = gap
        assert h.tick(h.restart())["status"] == "waiting_phase_progress"
        assert canonical_json_bytes(h.state) == original
    assert not any(x.operation == "extend" for x in h.attempts)
    h.complete = True
    h.tick()
    assert h.state.sequence == state.sequence + 1
    assert h.attempts[-1].operation == "close_phase"
    assert h.state.cohort_sha256 == state.cohort_sha256


@pytest.mark.parametrize("phase", ("intake", "requests"))
def test_no_early_closure_or_double_outage_credit(harness, phase):
    h = harness
    h.advance_to(phase)
    target = h.state.targets[PHASES.index(phase)].target_block
    h.unavailable = 3000
    h.block = target + 2999
    assert h.tick()["status"] == "waiting_phase_progress"
    h.complete = True
    with pytest.raises(ValueError, match="restoring unavailable service"):
        h.tick()
    h.block += 1
    h.tick()
    assert h.attempts[-1].observed_at_block == target + 3000
    h.complete = False
    h.unavailable = 0
    h.tick(h.restart())
    assert len(h.attempts) == PHASES.index(phase) + 1


def test_partial_closure_signing_recovers_original_intent_after_long_outage(harness):
    h = harness
    h.block, h.unavailable, h.complete, h.fail_sign = 3300, 3000, True, True
    with pytest.raises(OSError, match="certifier unavailable"):
        h.tick()
    original = canonical_json_bytes(h.attempts[-1])
    h.block += 1000000
    h.fail_sign = False
    h.tick(h.restart())
    assert canonical_json_bytes(h.attempts[-1]) == original
    assert h.state.sequence == 1 and h.state.phase == "preparation"


def test_lost_closure_publication_ack_does_not_repeat_transition(harness):
    h = harness
    h.block, h.complete, h.fail_publish_sequence = 3000, True, 1
    with pytest.raises(OSError, match="acknowledgement"):
        h.tick()
    assert h.state.sequence == 1
    h.block += 3000
    h.complete, h.fail_publish_sequence = False, None
    h.tick(h.restart())
    assert h.state.sequence == 1
    assert len(h.attempts) == 1
    assert len(h.publications[-1].transitions) == 1


@pytest.mark.parametrize("extension", (None, 1, 3000))
def test_standing_authority_cannot_issue_extension_transactions(harness, extension):
    h = harness
    with pytest.raises(ValueError, match="no extension signatures"):
        propose_recovery_transition(
            h.state,
            h.authority.authority,
            operation="extend",
            observed_at_block=10000,
            evidence_sha256="ab" * 32,
            extension_blocks=extension,
        )


def test_revocation_remains_effective_after_original_expiry(harness):
    h = harness
    proposal = propose_recovery_transition(
        h.state,
        h.authority.authority,
        operation="revoke",
        observed_at_block=10000,
        evidence_sha256="ab" * 32,
    )
    revoked = apply_recovery_transition(h.state, signed_transition(proposal), h.authority, h.policy)
    assert revoked.phase == "revoked"
    with pytest.raises(ValueError, match="completed or revoked"):
        propose_recovery_transition(
            revoked,
            h.authority.authority,
            operation="close_phase",
            observed_at_block=20000,
            evidence_sha256="ac" * 32,
        )


def test_native_admission_after_original_expiry_needs_no_extension(scenario):
    history = scenario["intake_history"]
    request = request_for(scenario, block=10000)
    admitted = admit_recovery_participant(
        request.signed_submission,
        request.consent,
        history,
        scenario["policy"],
        capture_at(10000).snapshot,
        expected_tip_sha256=history_tip(history),
        current_block=10000,
    )
    assert admitted.admitted_at_block == 10000
    assert not history.transitions


def test_native_intake_restores_ten_hour_outage_without_new_authority(intake, scenario):
    history = scenario["intake_history"]
    cohort, tip = digest(history.plan), history_tip(history)
    intake.retain(request_for(scenario), capture_at(210))
    observer = CohortIntakePhaseObserver(intake)

    def observe(block):
        return observer.observe(cohort, capture_at(block), serving=True, expected_tip_sha256=tip)

    first = observe(210)
    assert first.seal is None
    for block in range(220, 251, 10):
        assert observe(block).seal is None
    # Restart both native intake and the service observer after ten hours.
    intake = CohortIntake(intake.config, scenario["policy"])
    observer = CohortIntakePhaseObserver(intake)
    recovered = observe(3250)
    assert recovered.seal is None and recovered.service.unavailable_blocks >= 3000
    earliest = history.plan.initial_targets[0].target_block + recovered.service.unavailable_blocks
    for block in range(3260, earliest, 10):
        assert observe(block).seal is None
    completed = observe(earliest)
    assert completed.seal is not None
    assert completed.seal.observation.block == earliest
    assert intake.history(cohort) == history
    assert completed.progress.completion == "complete"
    assert observe(earliest + 10000).seal == completed.seal
    with pytest.raises(ValueError, match="selected current tip"):
        verify_cohort_history(
            history,
            scenario["policy"],
            expected_tip_sha256="00" * 32,
            current_block=earliest,
        )
