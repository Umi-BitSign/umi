"""Append-only benchmark amendment preserves original admissions and signed clocks."""

import pytest

from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipantAdmission,
    CohortParticipationConsent,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
    verify_participant_admission,
)
from umi.competition_cohort_recovery import apply_recovery_transition, propose_recovery_transition
from umi.competition_cohort_suite_adoption import (
    authenticated_evaluation_suite,
    prepare_evaluation_suite_adoption,
    selected_evaluation_suite,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_request_rule_adoption import original as original
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as policy


def proposal(history, policy, **changes):
    last = history.transitions[-1].transition if history.transitions else history.genesis
    values = dict(
        expected_tip_sha256=digest(last),
        current_block=220,
        suite_sha256="91" * 32,
        selection_manifest_sha256="92" * 32,
    )
    return prepare_evaluation_suite_adoption(history, policy, **(values | changes))


def test_amendment_retains_original_identity_targets_and_old_bytes(original, policy):
    history, state = original
    before = canonical_json_bytes(history)
    transition = proposal(history, policy)
    signed = signed_transition(transition)
    amended = history.model_copy(update={"transitions": (signed,)})
    applied = apply_recovery_transition(state, signed, history.authority, policy)
    assert transition.schema_ == "umi-cohort-recovery-transition/5"
    assert transition.is_policy_adoption and not transition.requires_progress_evidence
    assert applied.phase == "intake" and applied.targets == state.targets
    assert applied.cohort_sha256 == state.cohort_sha256 == digest(history.plan)
    assert applied.not_before_block == state.not_before_block
    assert canonical_json_bytes(amended.plan) == canonical_json_bytes(history.plan)
    assert canonical_json_bytes(history) == before
    assert b"evaluation_suite_adoption" not in before
    assert b"evaluation_suite_adoption" not in canonical_json_bytes(state)
    assert (
        authenticated_evaluation_suite(
            amended, policy, expected_tip_sha256=digest(transition), current_block=220
        )
        == "91" * 32
    )
    assert (
        authenticated_evaluation_suite(
            history, policy, expected_tip_sha256=digest(history.genesis), current_block=220
        )
        == history.plan.suite_sha256
    )

    def no_ordinary_evidence(_):
        pytest.fail("suite amendment cannot fabricate phase progress or outage credit")

    restored, outage, unavailable = replay_cohort_decisions(amended, policy, no_ordinary_evidence)
    assert restored == applied and outage == unavailable == 0


def test_replacement_chain_requires_exact_prior_selected_suite(original, policy):
    history, state = original
    first = proposal(history, policy)
    amended = history.model_copy(update={"transitions": (signed_transition(first),)})
    second = proposal(amended, policy, current_block=230, suite_sha256="93" * 32)
    assert second.evaluation_suite_adoption.previous_suite_sha256 == "91" * 32
    applied = apply_recovery_transition(state, signed_transition(first), history.authority, policy)
    old = second.evaluation_suite_adoption.model_copy(
        update={"previous_suite_sha256": history.plan.suite_sha256}
    )
    with pytest.raises(ValueError, match="conflicts with history"):
        propose_recovery_transition(
            applied,
            history.authority.authority,
            operation="adopt_evaluation_suite",
            observed_at_block=230,
            evidence_sha256=digest(old),
            evaluation_suite_adoption=old,
        )
    complete = amended.model_copy(
        update={"transitions": (*amended.transitions, signed_transition(second))}
    )
    view = verify_cohort_history(
        complete, policy, expected_tip_sha256=digest(second), current_block=230
    )
    assert selected_evaluation_suite(history.plan, view.state) == "93" * 32


@pytest.mark.parametrize("phase", ["preparation", "requests", "evidence", "complete", "revoked"])
def test_started_or_completed_evaluation_cannot_acquire_new_suite(original, policy, phase):
    history, state = original
    adoption = proposal(history, policy).evaluation_suite_adoption
    changed = state.model_copy(update={"phase": phase})
    with pytest.raises(ValueError, match=r"unavailable|completed or revoked"):
        propose_recovery_transition(
            changed,
            history.authority.authority,
            operation="adopt_evaluation_suite",
            observed_at_block=220,
            evidence_sha256=digest(adoption),
            evaluation_suite_adoption=adoption,
        )


def test_amendment_cannot_change_clocks_or_fork_selected_tip(original, policy):
    history, state = original
    original_transition = proposal(history, policy)
    tampered = original_transition.model_copy(
        update={
            "targets": tuple(
                target.model_copy(update={"target_block": target.target_block + 1})
                for target in original_transition.targets
            )
        }
    )
    with pytest.raises(ValueError, match="forks history"):
        apply_recovery_transition(state, signed_transition(tampered), history.authority, policy)
    with pytest.raises(ValueError, match="selected current tip"):
        proposal(history, policy, expected_tip_sha256="ef" * 32)


def test_native_intake_replay_keeps_old_model_admission_receipt_and_journal(
    original, policy, tmp_path
):
    history, _ = original
    cohort = digest(history.plan)
    config = CohortIntakeConfig(
        directory=str(tmp_path / "intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=cohort, authority_sha256=digest(history.authority.authority)
            ),
        ),
    )
    intake = CohortIntake(config, policy, eligible_tracks=("model",), initialize=True)
    intake.publish(history, capture_at(210))
    signed = submission(policy, bundle=bundle_at(tmp_path / "model"))
    consent = CohortParticipationConsent(
        schema="umi-cohort-participation-consent/1",
        cohort_sha256=cohort,
        authority_sha256=digest(history.authority.authority),
        submission_sha256=digest(signed.submission),
        hotkey=signed.submission.hotkey,
        signed_at_block=210,
        lifetime="until_cohort_completed_or_revoked",
        timing_rule="quorum_recovery_history/1",
        original_submission_expiry_does_not_end_participation=True,
    )
    request = CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=consent,
            signature=sign_object(consent, wallet("Alice")),
        ),
    )
    receipt = intake.retain(request, capture_at(210))
    admission = CohortParticipantAdmission.model_validate(receipt["proposed_admission"])
    certificate = AttestedCohortParticipantAdmission(
        admission=admission, signatures=signatures(admission)
    )
    original_bytes = (
        canonical_json_bytes(request),
        canonical_json_bytes(certificate),
        canonical_json_bytes(receipt),
    )
    records = intake.export_records(cohort, maximum_bytes=8 * 1024**2, maximum_records=10)
    transition = proposal(history, policy)
    amended = history.model_copy(update={"transitions": (signed_transition(transition),)})
    intake.publish(amended, capture_at(220))
    reopened = CohortIntake(config, policy, eligible_tracks=("model",))
    assert reopened.receipt(request) == receipt
    assert reopened.export_records(cohort, maximum_bytes=8 * 1024**2, maximum_records=10) == records
    assert (
        verify_participant_admission(
            certificate,
            signed,
            request.consent,
            amended,
            policy,
            capture_at(210).snapshot,
            expected_tip_sha256=digest(transition),
            current_block=220,
        )
        == admission
    )
    assert (
        canonical_json_bytes(request),
        canonical_json_bytes(certificate),
        canonical_json_bytes(receipt),
    ) == original_bytes
    # The certified round must use the adopted suite while keeping the exact
    # original model admission and incumbent identity. Downstream execution
    # schedules both incumbent and candidates from this one round/suite.
    from umi.competition_cohort_evaluation import (
        RecoverableEvaluationRound,
        RecoverableRoundParticipant,
        verify_recoverable_round_participant,
    )

    state = verify_cohort_history(
        amended, policy, expected_tip_sha256=digest(transition), current_block=220
    ).state
    closures = []
    for block in (300, 390):
        closing = propose_recovery_transition(
            state,
            history.authority.authority,
            operation="close_phase",
            observed_at_block=block,
            evidence_sha256=f"{block:064x}",
        )
        closures.append(signed_transition(closing))
        state = apply_recovery_transition(state, closures[-1], history.authority, policy)
    prepared_history = amended.model_copy(update={"transitions": (*amended.transitions, *closures)})
    round_ = RecoverableEvaluationRound(
        schema="umi-recoverable-evaluation-round/1",
        policy_sha256=digest(policy),
        cohort_sha256=cohort,
        intake_closure_sha256=digest(closures[0].transition),
        sequence=history.plan.sequence,
        suite_sha256=transition.evaluation_suite_adoption.suite_sha256,
        incumbent_model_sha256="bc" * 32,
        runtime_sha256=policy.evaluation_runtime_sha256,
        eligible_tracks=("model",),
        participants=(
            RecoverableRoundParticipant(
                submission_sha256=digest(signed.submission),
                admission_sha256=digest(admission),
            ),
        ),
        prepared_at_block=350,
    )
    for selected_suite, valid in ((round_.suite_sha256, True), (history.plan.suite_sha256, False)):
        selected_round = round_.model_copy(update={"suite_sha256": selected_suite})
        args = dict(
            signed=signed,
            round_=selected_round,
            policy=policy,
            consent=request.consent,
            admission=certificate,
            admission_snapshot=capture_at(210).snapshot,
            history=prepared_history,
            expected_tip_sha256=digest(closures[-1].transition),
            current_block=400,
        )
        if valid:
            assert verify_recoverable_round_participant(**args).state == state
        else:
            with pytest.raises(ValueError, match="identity or consent binding"):
                verify_recoverable_round_participant(**args)


@pytest.mark.parametrize("transport_kind", ["legacy", "direct"])
async def test_published_model_client_reads_new_suite_history_without_changing_upload_route(
    original, policy, transport_kind
):
    import httpx

    from umi.competition_cohort_model_client import fetch_model_delivery_profile
    from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
    from umi.competition_cohort_recovery import ModelDeliveryProfile, cohort_model_delivery

    history, _ = original
    expected = cohort_model_delivery(history.plan)
    if transport_kind == "direct":
        expected = ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=64 * 1024**2,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        )
        delivery = prepare_model_delivery_adoption(
            history,
            policy,
            expected_tip_sha256=digest(history.genesis),
            current_block=210,
            delivery=expected,
            legacy_inventory_sha256="a1" * 32,
            preservation_inventory_sha256="a2" * 32,
        )
        history = history.model_copy(update={"transitions": (signed_transition(delivery),)})
    suite = proposal(history, policy)
    amended = history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(suite))}
    )
    calls = []

    def handle(request):
        calls.append((request.method, request.url.path))
        return httpx.Response(
            200, content=canonical_json_bytes(amended), headers={"content-type": "application/json"}
        )

    result = await fetch_model_delivery_profile(
        origin="https://intake.example",
        policy=policy,
        cohort_sha256=digest(history.plan),
        transport=httpx.MockTransport(handle),
        retry_seconds=0.001,
        report=lambda _: None,
    )
    assert result == expected
    assert calls == [("GET", f"/v1/competition/cohorts/{digest(history.plan)}/history")]
