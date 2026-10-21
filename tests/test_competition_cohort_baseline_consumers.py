"""Native history/preparation consumers; finality, R2 and inference are fixtures."""

import hashlib

import pytest

from umi import competition_store
from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
    direct_model_object_key,
)
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeBinding,
    CohortIntakeConfig,
    history_tip,
)
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelAcceptancePublication,
    ModelArtifactReviewInputs,
)
from umi.competition_cohort_model_acceptance_store import CohortModelAcceptances
from umi.competition_cohort_participation import (
    CohortParticipantAdmission,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_preparation_owner import CohortPreparation
from umi.competition_cohort_recovery import (
    ModelDeliveryProfile,
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_publication import PublicationReplayLimits, build_cutoff_publication
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_baseline_history import (
    base_policy as base_policy,
)
from .test_competition_cohort_baseline_history import (
    certify,
)
from .test_competition_cohort_baseline_history import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_baseline_history import (
    model_case as model_case,
)
from .test_competition_cohort_baseline_history import (
    model_parent_context as model_parent_context,
)
from .test_competition_cohort_baseline_history import (
    policy as policy,
)
from .test_competition_cohort_baseline_history import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_baseline_history import (
    recovery as recovery,
)
from .test_competition_cohort_baseline_history import (
    retained_case as retained_case,
)
from .test_competition_cohort_baseline_history import (
    review_case as review_case,
)
from .test_competition_cohort_baseline_history import (
    runtime as runtime,
)
from .test_competition_cohort_intake import capture_at, seal_and_close
from .test_competition_cohort_recovery import signatures
from .test_competition_review_history import attest
from .test_competition_two_task_profile import launch_suite
from .test_open_competition import round_for, snapshot, submission, wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("model_case", [("best", 2)], indirect=True),
]


@pytest.mark.parametrize("model_parent_context", [None, "89" * 32], indirect=True)
def test_independent_review_history_accepts_winner_without_intake_authority(
    retained_case, model_case, tmp_path, monkeypatch
):
    source, review, _, b = retained_case
    archive = model_case[-1]
    original = b["scenarios"][0]["artifacts"][0].job.incumbent
    limits = PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_evidence_bytes=1_000_000,
        maximum_certificate_bytes=1_000_000,
    )
    peer = EvaluatorReviewStore(tmp_path / "independent-history", source.policy, limits=limits)
    peer.initialize_baseline(original, archive)
    certificate = certify(review)
    signed_bytes = canonical_json_bytes(certificate)

    def no_payload(*args, **kwargs):
        raise AssertionError("reviewed winner history must reuse completed model verification")

    monkeypatch.setattr(competition_store, "verify_preserved_bundle", no_payload)
    expected = source.apply_cohort_baseline(certificate, observed_block=230)
    actual = peer.apply_cohort_baseline(certificate, observed_block=231)
    assert actual == expected
    assert canonical_json_bytes(certificate) == signed_bytes
    assert actual["schema"] == "umi-model-baseline/4"
    assert actual["contributor_hotkey"] == review.candidate.contributor_hotkey

    member = b["roster"].participants[0].record
    signed = member.request.signed_submission
    suite = launch_suite(source.policy)
    future = round_for(source.policy, suite, (signed,), digest(review.model))
    schedule = future.public_schedule.model_copy(
        update={
            name: value + 200
            for name, value in future.public_schedule.model_dump().items()
            if name.endswith("_block")
        }
    )
    future = future.model_copy(
        update={
            "public_schedule": schedule,
            "eligible_tracks": ("model",),
            "submission_close_block": 320,
            "evaluation_close_block": 340,
            "reveal_block": 350,
            "valid_through_block": 400,
        }
    )
    # A promotion receipt must not bypass this role's independent roster proof.
    with pytest.raises(ValueError, match="review cutoff receipt missing"):
        peer.reviewed_promotion_head(digest(future), maximum_bytes=1_000_000)
    registration = snapshot(320)
    cutoff = build_cutoff_publication(
        policy=source.policy,
        round_=future,
        submissions=(signed,),
        registration_snapshot=registration,
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(source.policy),
            round_sha256=digest(future),
            evidence_cutoff_block=360,
        ),
        limits=limits,
    )
    peer.observe_cutoff(attest(cutoff), (signed,), snapshot=registration, observed_block=321)
    reopened = EvaluatorReviewStore(peer.directory, source.policy, limits=limits)
    selected = reopened.reviewed_promotion_head(digest(future), maximum_bytes=1_000_000)
    assert selected.model_sha256 == digest(review.model)
    assert selected.sequence == review.previous.sequence + 1
    assert (
        reopened.reviewed_promotion_at(
            digest(future),
            review.previous.promotion_sha256,
            maximum_bytes=1_000_000,
        )
        == review.previous
    )

    def no_observation():
        raise AssertionError("a completed retry must retain its original observation")

    assert reopened.apply_cohort_baseline(certificate, observed_block=no_observation) == expected
    with pytest.raises(ValueError, match="cannot authorize intake operations"):
        reopened.admit(member.request.signed_submission, member.snapshot, member.snapshot.block)


@pytest.mark.parametrize("model_parent_context", [None, "89" * 32], indirect=True)
def test_model_only_direct_round_selects_winner_and_keeps_signed_ancestry(
    retained_case, model_case, tmp_path, monkeypatch
):
    source, review, _, b = retained_case
    policy = source.policy
    old_history = b["history"]
    delivery = ModelDeliveryProfile(
        schema="umi-model-delivery-profile/1",
        mechanism="direct_r2_multipart_v1",
        part_size_bytes=5 * 1024**2,
        maximum_concurrent_parts=2,
        capability_ttl_seconds=900,
    )
    plan = RecoverableCohortPlan.model_validate_json(
        canonical_json_bytes(
            old_history.plan.model_copy(
                update={
                    "schema_": "umi-recoverable-cohort-plan/4",
                    "sequence": 6,
                    "eligible_tracks": ("model",),
                    "service_pool_bps": 0,
                    "model_delivery": delivery,
                    "request_tail_rule": "original_request_12h_with_completed_miner/1",
                }
            )
        )
    )
    cohort = digest(plan)
    authority_body = old_history.authority.authority.model_copy(
        update={"cohort_sha256s": (cohort,)}
    )
    authority = SignedCohortRecoveryAuthority(
        authority=authority_body, signatures=signatures(authority_body)
    )
    genesis, _ = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    intake = CohortIntake(
        CohortIntakeConfig(
            directory=str(tmp_path / "model-only-intake"),
            cohorts=(
                CohortIntakeBinding(cohort_sha256=cohort, authority_sha256=digest(authority_body)),
            ),
        ),
        policy,
        eligible_tracks=("model",),
        initialize=True,
    )
    intake.publish(history, capture_at(210))
    # Retain a model declared against an older parent, exactly as the miner signed it.
    record = next(
        p.record
        for p in b["roster"].participants
        if p.record.request.signed_submission.submission.hotkey
        != review.candidate.contributor_hotkey
    )
    signed = record.request.signed_submission
    original_signed = canonical_json_bytes(signed)
    consent = record.request.consent.consent.model_copy(
        update={"cohort_sha256": cohort, "authority_sha256": digest(authority_body)}
    )
    request = CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )
    endpoint = submission(policy, name="Bob")
    endpoint_consent = consent.model_copy(
        update={
            "submission_sha256": digest(endpoint.submission),
            "hotkey": endpoint.submission.hotkey,
        }
    )
    with pytest.raises(ValueError, match="submission track is not open"):
        intake.retain(
            CohortParticipationRequest(
                signed_submission=endpoint,
                consent=SignedCohortParticipationConsent(
                    consent=endpoint_consent,
                    signature=sign_object(endpoint_consent, wallet("Bob")),
                ),
            ),
            capture_at(210),
        )
    receipt = intake.retain(request, capture_at(210))
    admission = CohortParticipantAdmission.model_validate(receipt["proposed_admission"])
    queue = CohortAdmissionQueue(intake)
    for name in ("Charlie", "Dave"):
        queue.publish_vote(
            CohortAdmissionVote(
                admission=admission, signature=sign_object(admission, wallet(name))
            ),
            capture_at(210),
        )

    # R2 provider identity is a fixture; model bytes, signatures and admission are native.
    bundle = signed.submission.model_bundle
    archive = model_case[-1]
    payload_bytes = b"".join(
        (archive / digest(bundle) / "model" / file.path).read_bytes() for file in bundle.files
    )
    key = direct_model_object_key(cohort, digest(request), "a1" * 32)
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=cohort,
        hotkey=signed.submission.hotkey,
        payload=DirectModelPayload(
            schema="umi-direct-model-payload/1",
            upload_sha256=digest(request),
            model_sha256=digest(bundle),
            payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
            total_bytes=len(payload_bytes),
            file_count=len(bundle.files),
            part_size_bytes=delivery.part_size_bytes,
            total_parts=1,
        ),
        attempt_id="a1" * 32,
        generation=1,
        object_key_sha256=hashlib.sha256(key.encode()).hexdigest(),
        provider_upload_id_sha256="b2" * 32,
        created_at_unix_ms=1_800_000_000_000,
    )
    artifact = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    acceptances = CohortModelAcceptances(intake, archive, review_artifact=lambda _: artifact)
    inputs = ModelArtifactReviewInputs(
        model_sha256=digest(bundle),
        rights_evidence={"fixture": "native reviewed license and provenance"},
        reconstruction_evidence={"fixture": "independent reconstruction"},
    )
    acceptance = acceptances.prepare(cohort, digest(signed.submission), inputs, capture_at(220))
    acceptances.publish(
        ModelAcceptancePublication(
            certificate=CertifiedModelArtifactAcceptance(
                acceptance=acceptance, signatures=signatures(acceptance)
            ),
            inputs=inputs,
        ),
        capture_at(220),
    )
    review = review.model_copy(update={"target_cohort_sha256": cohort})
    winner = source.apply_cohort_baseline(certify(review), observed_block=230)
    closed, evidence, _ = seal_and_close(intake, {"intake_history": history, "policy": policy})
    intake.publish(closed, capture_at(300), closure_input=evidence)
    owner = CohortPreparation(queue, source)
    prepared = owner.prepare(cohort, capture_at(330), expected_tip_sha256=history_tip(closed))
    assert prepared.promotion_head.model_sha256 == winner["model_sha256"]
    assert prepared.roster.round.incumbent_model_sha256 == digest(review.model)
    assert prepared.roster.round.eligible_tracks == ("model",)
    assert plan.service_pool_bps == 0
    assert plan.model_delivery == delivery
    retained = prepared.roster.participants[0].record.request.signed_submission
    assert canonical_json_bytes(retained) == original_signed
    assert bundle.parent_baseline_sha256 != prepared.roster.round.incumbent_model_sha256

    def no_payload(*args, **kwargs):
        raise AssertionError("restarting a prepared successor must not reverify model payloads")

    monkeypatch.setattr(competition_store, "verify_preserved_bundle", no_payload)
    replay_store = CompetitionStore(source.directory, policy)

    def no_current_head(*args, **kwargs):
        raise AssertionError("a retained successor must not select a new incumbent")

    monkeypatch.setattr(replay_store, "reviewed_promotion_head", no_current_head)
    restarted = CohortPreparation(CohortAdmissionQueue(intake), replay_store)
    assert (
        restarted.retained(cohort, expected_tip_sha256=history_tip(closed), current_block=100_330)
        == prepared
    )
