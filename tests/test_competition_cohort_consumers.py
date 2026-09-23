from __future__ import annotations

from fractions import Fraction

import pytest
from pydantic import ValidationError

from umi.competition_cohort_evaluation import (
    RecoverableEvaluationRound,
    RecoverableRoundParticipant,
    replay_recoverable_evaluation,
)
from umi.competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipationConsent,
    SignedCohortParticipationConsent,
    admit_recovery_participant,
    verify_participant_admission,
)
from umi.competition_cohort_recovery import (
    CohortRecoveryAuthority,
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
    propose_recovery_transition,
)
from umi.open_competition import (
    EvaluationRound,
    digest,
    replay_evaluation,
    sign_object,
    validate_admission,
)
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import (
    ledger as ledger,
)
from .test_competition_cohort_recovery import (
    recovery as recovery,
)
from .test_competition_cohort_recovery import (
    signatures,
    signed_transition,
)
from .test_open_competition import (
    attested,
    result_for,
    round_for,
    snapshot,
    submission,
    suite_for,
    wallet,
)
from .test_open_competition import (
    policy as policy,
)


def tip(history):
    return digest(history.transitions[-1].transition if history.transitions else history.genesis)


def transition(history, policy, operation, block, *, extension=None):
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=tip(history), current_block=block
    )
    proposal = propose_recovery_transition(
        view.state,
        history.authority.authority,
        operation=operation,
        observed_at_block=block,
        extension_blocks=extension,
        evidence_sha256=f"{len(history.transitions) + 1:064x}",
    )
    return history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(proposal))}
    )


@pytest.fixture
def scenario(recovery, policy):
    old_plan, _, _ = recovery
    suite = suite_for(policy)
    plan = old_plan.model_copy(update={"suite_sha256": digest(suite)})
    body = CohortRecoveryAuthority(
        schema="umi-cohort-recovery-authority/1",
        policy_sha256=digest(policy),
        cohort_sha256s=(digest(plan),),
        issued_at_block=150,
        minimum_recovery_margin_blocks=20,
        maximum_extension_step_blocks=1200,
        lifetime="until_completed_or_revoked",
        closure_rule="quorum_certified_phase_completion",
    )
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    genesis, _ = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    signed = submission(policy)
    consent_body = CohortParticipationConsent(
        schema="umi-cohort-participation-consent/1",
        cohort_sha256=digest(plan),
        authority_sha256=digest(body),
        submission_sha256=digest(signed.submission),
        hotkey=signed.submission.hotkey,
        signed_at_block=200,
        lifetime="until_cohort_completed_or_revoked",
        timing_rule="quorum_recovery_history/1",
        original_submission_expiry_does_not_end_participation=True,
    )
    consent = SignedCohortParticipationConsent(
        consent=consent_body, signature=sign_object(consent_body, wallet("Alice"))
    )
    snap = snapshot(210)
    admission_body = admit_recovery_participant(
        signed, consent, history, policy, snap, expected_tip_sha256=tip(history), current_block=210
    )
    admission = AttestedCohortParticipantAdmission(
        admission=admission_body, signatures=signatures(admission_body)
    )
    intake_history = history
    history = transition(history, policy, "close_phase", 300)
    round_ = RecoverableEvaluationRound(
        schema="umi-recoverable-evaluation-round/1",
        policy_sha256=digest(policy),
        cohort_sha256=digest(plan),
        intake_closure_sha256=tip(history),
        sequence=5,
        suite_sha256=digest(suite),
        incumbent_model_sha256="b2" * 32,
        runtime_sha256=policy.evaluation_runtime_sha256,
        eligible_tracks=("endpoint", "model"),
        participants=(
            RecoverableRoundParticipant(
                submission_sha256=digest(signed.submission), admission_sha256=digest(admission_body)
            ),
        ),
        prepared_at_block=350,
    )
    history = transition(history, policy, "close_phase", 390)
    history = transition(history, policy, "extend", 480, extension=1200)
    history = transition(history, policy, "close_phase", 1680)
    history = transition(history, policy, "close_phase", 1770)
    result = result_for(signed, round_, suite).result.model_copy(update={"finished_block": 1600})
    return dict(
        signed=signed,
        consent=consent,
        admission=admission,
        admission_snapshot=snap,
        history=history,
        round_=round_,
        suite=suite,
        policy=policy,
        attested=attested(result),
        intake_history=intake_history,
    )


def replay(scenario, **updates):
    values = {k: v for k, v in scenario.items() if k != "intake_history"}
    values.update(expected_tip_sha256=tip(scenario["history"]), current_block=5000)
    values.update(updates)
    return replay_recoverable_evaluation(**values)


def test_native_score_replay_survives_expired_original_policy_and_submission(scenario):
    old_bytes = canonical_json_bytes(scenario["signed"])
    candidate, incumbent = replay(scenario)
    assert set(candidate.values()) == {Fraction(1)}
    assert set(incumbent.values()) == {Fraction(0)}
    assert canonical_json_bytes(scenario["signed"]) == old_bytes
    assert scenario["signed"].submission.valid_through_block == 900
    assert scenario["policy"].valid_through_block == 1000


def test_existing_legacy_round_and_admission_still_expire(scenario):
    p, suite, sub = scenario["policy"], scenario["suite"], scenario["signed"]
    old = round_for(p, suite, (sub,))
    result = result_for(sub, old, suite)
    with pytest.raises(ValueError, match="premature or expired"):
        replay_evaluation(result, sub, old, suite, p, current_block=5000)
    with pytest.raises(ValueError, match="policy is not current"):
        validate_admission(sub, p, snapshot(5000), 5000)
    with pytest.raises(ValidationError):
        EvaluationRound.model_validate_json(canonical_json_bytes(scenario["round_"]))


def test_fresh_consent_admits_during_extended_intake_after_old_expiry(scenario):
    h = transition(scenario["intake_history"], scenario["policy"], "extend", 1600, extension=1200)
    body = scenario["consent"].consent.model_copy(update={"signed_at_block": 1610})
    consent = SignedCohortParticipationConsent(
        consent=body, signature=sign_object(body, wallet("Alice"))
    )
    accepted = admit_recovery_participant(
        scenario["signed"],
        consent,
        h,
        scenario["policy"],
        snapshot(1610),
        expected_tip_sha256=tip(h),
        current_block=1610,
    )
    assert accepted.admitted_at_block == 1610
    assert accepted.uid == 6
    assert accepted.submission_sha256 == digest(scenario["signed"].submission)


@pytest.mark.parametrize(
    "damage",
    [
        "wrong_miner",
        "wrong_submission",
        "wrong_authority",
        "wrong_cohort",
        "future_consent",
        "old_terms",
        "stale_snapshot",
        "unregistered",
        "missing_opt_in",
    ],
)
def test_extended_admission_requires_explicit_exact_consent(scenario, damage):
    values = scenario.copy()
    h = values["intake_history"]
    sub, consent, snap = values["signed"], values["consent"], values["admission_snapshot"]
    body = consent.consent
    if damage == "wrong_miner":
        body = body.model_copy(update={"hotkey": wallet("Bob").hotkey.ss58_address})
    elif damage == "wrong_submission":
        body = body.model_copy(update={"submission_sha256": "f1" * 32})
    elif damage == "wrong_authority":
        body = body.model_copy(update={"authority_sha256": "f1" * 32})
    elif damage == "wrong_cohort":
        body = body.model_copy(update={"cohort_sha256": "f1" * 32})
    elif damage == "future_consent":
        body = body.model_copy(update={"signed_at_block": 211})
    elif damage == "old_terms":
        b = sub.submission.model_copy(update={"accepted_terms_sha256": "f1" * 32})
        sub = sub.model_copy(update={"submission": b, "signature": sign_object(b, wallet("Alice"))})
    elif damage == "stale_snapshot":
        snap = snapshot(199)
    elif damage == "unregistered":
        snap = snap.model_copy(update={"registrations": ()})
    elif damage == "missing_opt_in":
        body = body.model_copy(
            update={"original_submission_expiry_does_not_end_participation": False}
        )
    with pytest.raises(ValueError):
        # Sign even the altered body, proving scope checks are independent of crypto.
        name = "Bob" if damage == "wrong_miner" else "Alice"
        consent = SignedCohortParticipationConsent(
            consent=body, signature=sign_object(body, wallet(name))
        )
        admit_recovery_participant(
            sub, consent, h, values["policy"], snap, expected_tip_sha256=tip(h), current_block=210
        )


@pytest.mark.parametrize(
    "damage",
    [
        "wrong_tip",
        "prefix",
        "future_history",
        "bad_genesis_signature",
        "missing_transition",
        "duplicate_phase_evidence",
    ],
)
def test_portable_history_requires_current_complete_authenticated_chain(scenario, damage):
    h = scenario["history"]
    expected = tip(h)
    block = 5000
    if damage == "wrong_tip":
        expected = "f1" * 32
    elif damage == "prefix":
        h = h.model_copy(update={"transitions": h.transitions[:-1]})
    elif damage == "future_history":
        block = 1700
    elif damage == "bad_genesis_signature":
        h = h.model_copy(update={"genesis_signatures": signatures(h.plan)})
    elif damage == "missing_transition":
        h = h.model_copy(update={"transitions": h.transitions[1:]})
    else:
        h = transition(scenario["intake_history"], scenario["policy"], "extend", 300)
        view = verify_cohort_history(
            h, scenario["policy"], expected_tip_sha256=tip(h), current_block=320
        )
        first = h.transitions[0].transition
        body = propose_recovery_transition(
            view.state,
            h.authority.authority,
            operation="extend",
            observed_at_block=320,
            evidence_sha256=first.evidence_sha256,
        )
        h = h.model_copy(update={"transitions": (*h.transitions, signed_transition(body))})
        expected = tip(h)
    with pytest.raises(ValueError):
        verify_cohort_history(
            h, scenario["policy"], expected_tip_sha256=expected, current_block=block
        )


@pytest.mark.parametrize("finished", [390, 1681, 1770, 5001])
def test_outputs_outside_closed_request_phase_do_not_score(scenario, finished):
    bad = attested(scenario["attested"].result.model_copy(update={"finished_block": finished}))
    with pytest.raises(ValueError, match="certified phase interval"):
        replay(scenario, attested=bad)


def test_preserves_successful_responses_recorded_before_outage(scenario):
    earlier = attested(scenario["attested"].result.model_copy(update={"finished_block": 420}))
    assert replay(scenario, attested=earlier) == replay(scenario)


def test_altered_outputs_require_new_native_quorum_signatures(scenario):
    original = scenario["attested"]
    outputs = list(original.result.candidate)
    outputs[0] = outputs[0].model_copy(update={"hypothesis": "changed"})
    changed = original.model_copy(
        update={
            "result": original.result.model_copy(update={"candidate": tuple(outputs)}),
        }
    )
    with pytest.raises(ValueError, match="invalid competition signature"):
        replay(scenario, attested=changed)


@pytest.mark.parametrize("failure", ["infrastructure_failure", "miner_failure"])
def test_native_failure_classification_is_preserved(scenario, failure):
    original = scenario["attested"].result
    outputs = tuple(
        o.model_copy(update={"status": failure, "hypothesis": ""}) for o in original.candidate
    )
    changed = attested(original.model_copy(update={"candidate": outputs}))
    if failure == "infrastructure_failure":
        with pytest.raises(ValueError, match="infrastructure failure voids evaluation"):
            replay(scenario, attested=changed)
    else:
        assert set(replay(scenario, attested=changed)[0].values()) == {Fraction(0)}


def test_no_scores_before_reference_release_is_certified(scenario):
    h = scenario["history"].model_copy(update={"transitions": scenario["history"].transitions[:-1]})
    with pytest.raises(ValueError, match="no certified closure: reference_reveal"):
        replay(scenario, history=h, expected_tip_sha256=tip(h))


@pytest.mark.parametrize(
    "field", ["runtime_sha256", "model_revision", "round_sha256", "submission_sha256"]
)
def test_phase_extensions_do_not_relax_result_bindings(scenario, field):
    bad = attested(scenario["attested"].result.model_copy(update={field: "f1" * 32}))
    with pytest.raises(ValueError, match="binding differs"):
        replay(scenario, attested=bad)


def test_no_new_admission_to_closed_intake_even_if_target_extended(scenario):
    h = scenario["history"]
    with pytest.raises(ValueError, match="intake is not open"):
        admit_recovery_participant(
            scenario["signed"],
            scenario["consent"],
            h,
            scenario["policy"],
            snapshot(5000),
            expected_tip_sha256=tip(h),
            current_block=5000,
        )


def test_quorum_cannot_backdate_admission_using_stale_intake_prefix(scenario):
    h = scenario["intake_history"]
    p = scenario["policy"]
    snap = snapshot(5000)
    # A complete current history exposes that this apparently open prefix was
    # superseded at block 300, before the purported admission at block 5,000.
    body = admit_recovery_participant(
        scenario["signed"],
        scenario["consent"],
        h,
        p,
        snap,
        expected_tip_sha256=tip(h),
        current_block=5000,
    )
    signed = AttestedCohortParticipantAdmission(admission=body, signatures=signatures(body))
    with pytest.raises(ValueError, match="superseded schedule observation"):
        verify_participant_admission(
            signed,
            scenario["signed"],
            scenario["consent"],
            scenario["history"],
            p,
            snap,
            expected_tip_sha256=tip(scenario["history"]),
            current_block=5000,
        )


def test_revoked_cohort_cannot_gain_score_authority(scenario):
    h = transition(scenario["history"], scenario["policy"], "revoke", 1800)
    with pytest.raises(ValueError, match="revoked"):
        replay(scenario, history=h, expected_tip_sha256=tip(h))


def test_request_closure_and_reveal_cannot_share_a_block(scenario):
    h = scenario["history"].model_copy(update={"transitions": scenario["history"].transitions[:-1]})
    with pytest.raises(ValueError, match="reveal must follow"):
        transition(h, scenario["policy"], "close_phase", 1680)


def test_store_exports_only_committed_decisions_with_certified_genesis(ledger, recovery, policy):
    plan, authority, _ = recovery
    genesis, _ = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
    cohort = digest(plan)
    pending = ledger.reserve(
        cohort, phase="intake", operation="extend", observed_at_block=300, evidence_sha256="a5" * 32
    )
    history = ledger.export_history(cohort, genesis_signatures=signatures(genesis))
    assert not history.transitions
    state = ledger.commit(signed_transition(pending))
    history = ledger.export_history(cohort, genesis_signatures=signatures(genesis))
    assert len(history.transitions) == 1
    assert (
        verify_cohort_history(
            history, policy, expected_tip_sha256=state.tip_sha256, current_block=5000
        ).state
        == state
    )
    with pytest.raises(ValueError):
        ledger.export_history(cohort, genesis_signatures=signatures(genesis, ("Charlie",)))
