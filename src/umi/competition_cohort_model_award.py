"""Replay model awards from a complete roster and preserved, reviewed artifacts.

The signed authority selects this rule before miner consent. An award does not
promote a reference model or transfer authorship. Rights reviewers must retain
their original review evidence and verify permission to distribute the bundle.
"""

from __future__ import annotations

from fractions import Fraction
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_endpoint_archive import read_endpoint_object
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
from .competition_cohort_quality import ClosedQualityReview, ExactQuality
from .competition_cohort_quality_signing import CohortQualityManifest, review_quality_manifest
from .competition_cohort_recovery import Block, ModelRewardCohortAuthority, verify_recovery_quorum
from .open_competition import Hotkey, Signature, digest, identity, model_content_digest
from .private_files import read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class ModelArtifactAcceptance(StrictProtocolModel):
    """Independent rights and reconstruction review of a complete model entry.

    The acceptance ordinal is assigned durably when all files and reviews are
    ready, before intake closes. It is not a miner-supplied upload timestamp.
    """

    schema_: Literal["umi-cohort-model-artifact-acceptance/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    submission_sha256: Hex32
    model_sha256: Hex32
    content_sha256: Hex32
    recipient_hotkey: Hotkey
    rights_evidence_sha256: Hex32
    reconstruction_evidence_sha256: Hex32
    accepted_at_block: Block
    accepted_ordinal: Annotated[int, Field(ge=1, le=2**53 - 1)]
    rights_and_reconstruction_passed: Literal[True]


class CertifiedModelArtifactAcceptance(StrictProtocolModel):
    acceptance: ModelArtifactAcceptance
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ModelAwardCandidate(StrictProtocolModel):
    submission_sha256: Hex32
    model_sha256: Hex32
    content_sha256: Hex32
    recipient_hotkey: Hotkey
    acceptance_sha256: Hex32
    quality_sha256: Hex32
    aggregate: ExactQuality
    baseline_aggregate: ExactQuality
    eligible: bool


class CohortModelAward(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-award/1"] = Field(alias="schema")
    policy_sha256: Hex32
    authority_sha256: Hex32
    round_sha256: Hex32
    roster_sha256: Hex32
    quality_manifest_sha256: Hex32
    baseline_model_sha256: Hex32
    runtime_sha256: Hex32
    suite_sha256: Hex32
    rule: Literal["baseline_or_better_best_score_first_complete/1"]
    acceptances: Annotated[tuple[CertifiedModelArtifactAcceptance, ...], Field(max_length=512)]
    candidates: Annotated[tuple[ModelAwardCandidate, ...], Field(max_length=512)]
    winner_submission_sha256: Hex32 | None
    recipient_hotkey: Hotkey | None
    reference_promotion_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


class PendingModelAward(ValueError):
    """An accepted model still needs complete evidence; elapsed time changes nothing."""


def _fraction(value: ExactQuality) -> Fraction:
    result = Fraction(int(value.numerator), int(value.denominator))
    if not 0 <= result <= 1:
        raise ValueError("model award quality must be normalized")
    return result


def build_model_award(
    benchmark: CohortQualityManifest,
    review: ClosedQualityReview,
    acceptances: tuple[CertifiedModelArtifactAcceptance, ...],
    archive: Path,
) -> CohortModelAward:
    """Replay every model before choosing one recipient for the whole model pool.

    The archive is selected by the host, never by a submission or package path.
    All bundle bytes are checked locally. The signed acceptance binds the
    independent rights/reconstruction decision; quality is replayed separately.
    """
    view = verify_cohort_history(
        review.history,
        review.policy,
        expected_tip_sha256=review.expected_tip_sha256,
        current_block=review.current_block,
    )
    authority = review.history.authority.authority
    if not isinstance(authority, ModelRewardCohortAuthority) or view.state.phase == "revoked":
        raise ValueError("model awards require the selected version 3 cohort authority")
    outcomes = review_quality_manifest(benchmark, review)
    models = tuple(r for r in outcomes if r.track == "model")
    accepted = tuple(
        CertifiedModelArtifactAcceptance.model_validate_json(canonical_json_bytes(a))
        for a in acceptances
    )
    if tuple(a.acceptance.submission_sha256 for a in accepted) != tuple(
        r.submission_sha256 for r in models
    ):
        raise PendingModelAward(
            "model artifact acceptances must cover the entire sealed model roster"
        )
    ordinals = [a.acceptance.accepted_ordinal for a in accepted]
    if len(ordinals) != len(set(ordinals)):
        raise ValueError("complete model acceptances must have unique retained ordinals")
    ordered = sorted(accepted, key=lambda a: a.acceptance.accepted_ordinal)
    blocks = [a.acceptance.accepted_at_block for a in ordered]
    if blocks != sorted(blocks):
        raise ValueError("model acceptance ordinals contradict their certified block order")
    participants = {
        digest(p.record.request.signed_submission.submission): p for p in review.roster.participants
    }
    candidates, choices = [], []
    baseline = None
    content_quality = {}
    for result, certificate in zip(models, accepted, strict=True):
        a = certificate.acceptance
        p = participants[result.submission_sha256]
        sub = p.record.request.signed_submission.submission
        bundle = sub.model_bundle
        if bundle is None or sub.track != "model":
            raise ValueError("model award requires a separate model submission")
        content = model_content_digest(bundle)
        if (
            a.policy_sha256 != digest(review.policy)
            or a.cohort_sha256 != view.state.cohort_sha256
            or a.authority_sha256 != digest(authority)
            or a.model_sha256 != digest(bundle)
            or a.content_sha256 != content
            or identity(a.recipient_hotkey) != identity(sub.hotkey)
            or not p.admission.admission.admitted_at_block
            <= a.accepted_at_block
            <= view.closure("intake").observed_at_block
            or a.rights_evidence_sha256 == "0" * 64
            or a.reconstruction_evidence_sha256 == "0" * 64
        ):
            raise ValueError("model artifact acceptance differs from the original complete entry")
        verify_recovery_quorum(a, certificate.signatures, review.policy)
        if identity(sub.hotkey) in {identity(s.hotkey) for s in certificate.signatures}:
            raise ValueError("model submitters cannot certify their own artifact acceptance")
        # Retain the original review documents in portable reward packages too.
        # A signed digest without its evidence is insufficient for recovery.
        read_endpoint_object(review.objects, a.rights_evidence_sha256)
        read_endpoint_object(review.objects, a.reconstruction_evidence_sha256)
        verify_preserved_bundle(bundle, archive, review.policy)
        order = SignedRecoverableEvaluationOrder.model_validate_json(
            read_endpoint_object(review.objects, result.order_sha256)
        ).order
        if digest(order.incumbent) != review.roster.round.incumbent_model_sha256:
            raise ValueError("paired baseline differs from the frozen model")
        verify_preserved_bundle(order.incumbent, archive, review.policy)
        if result.reason is not None or result.candidate is None or result.incumbent is None:
            raise PendingModelAward("model quality remains unresolved")
        if result.quality_rule != "paired_baseline_metric/1" or any(
            r.candidate_basis != "measured_model_execution" for r in result.runs
        ):
            raise ValueError("endpoint content cannot establish model award eligibility")
        score, reference = (
            _fraction(result.candidate.aggregate),
            _fraction(result.incumbent.aggregate),
        )
        if baseline is not None and baseline != result.incumbent:
            raise PendingModelAward("paired model evaluations disagree on the frozen baseline")
        baseline = result.incumbent
        if content in content_quality and content_quality[content] != result.candidate:
            raise PendingModelAward("duplicate model content has inconsistent quality")
        content_quality[content] = result.candidate
        candidates.append(
            ModelAwardCandidate(
                submission_sha256=result.submission_sha256,
                model_sha256=digest(bundle),
                content_sha256=content,
                recipient_hotkey=sub.hotkey,
                acceptance_sha256=digest(certificate),
                quality_sha256=digest(result),
                aggregate=result.candidate.aggregate,
                baseline_aggregate=result.incumbent.aggregate,
                eligible=score >= reference,
            )
        )
        if score >= reference:
            choices.append((-score, a.accepted_ordinal, result.submission_sha256, sub.hotkey))
    winner = min(choices) if choices else None
    return CohortModelAward(
        schema="umi-cohort-model-award/1",
        policy_sha256=digest(review.policy),
        authority_sha256=digest(authority),
        round_sha256=digest(review.roster.round),
        roster_sha256=digest(review.roster),
        quality_manifest_sha256=digest(benchmark),
        baseline_model_sha256=review.roster.round.incumbent_model_sha256,
        runtime_sha256=review.roster.round.runtime_sha256,
        suite_sha256=digest(review.suite),
        rule=authority.model_reward_rule,
        acceptances=accepted,
        candidates=tuple(candidates),
        winner_submission_sha256=winner[2] if winner else None,
        recipient_hotkey=winner[3] if winner else None,
    )


def read_model_acceptances(
    directory: Path, review: ClosedQualityReview
) -> tuple[CertifiedModelArtifactAcceptance, ...]:
    """Load one retained complete acceptance per selected model; never skip missing files."""
    cohort = digest(review.history.plan)
    return tuple(
        read_private_model(
            directory / cohort / (digest(p.record.request.signed_submission.submission) + ".json"),
            CertifiedModelArtifactAcceptance,
            maximum_bytes=256 * 1024,
        )
        for p in review.roster.participants
        if p.record.request.signed_submission.submission.track == "model"
    )
