"""Replay model awards from a complete roster and preserved, reviewed artifacts.

The signed authority selects this rule before miner consent. An award does not
promote a reference model or transfer authorship. Rights reviewers must retain
their original review evidence and verify permission to distribute the bundle.
"""

from __future__ import annotations

from collections.abc import Callable
from fractions import Fraction
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, TypeAdapter, model_serializer, model_validator

from .competition_artifacts import verify_preserved_bundle
from .competition_cohort_endpoint_archive import read_endpoint_object
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    verify_model_acceptance,
)
from .competition_cohort_orders import SignedRecoverableEvaluationOrder
from .competition_cohort_quality import ClosedQualityReview, ExactQuality
from .competition_cohort_quality_signing import CohortQualityManifest, review_quality_manifest
from .competition_cohort_recovery import ModelRewardCohortAuthority
from .competition_cohort_roster import RecoverableRosterParticipant
from .open_competition import Hotkey, digest, model_content_digest
from .private_files import read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


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


class ModelAwardEvidence(StrictProtocolModel):
    policy_sha256: Hex32
    authority_sha256: Hex32
    round_sha256: Hex32
    roster_sha256: Hex32
    quality_manifest_sha256: Hex32
    baseline_model_sha256: Hex32
    runtime_sha256: Hex32
    suite_sha256: Hex32
    acceptances: Annotated[tuple[CertifiedModelArtifactAcceptance, ...], Field(max_length=512)]
    candidates: Annotated[tuple[ModelAwardCandidate, ...], Field(max_length=512)]
    skipped_participants: Annotated[tuple[Hex32, ...], Field(max_length=512)] | None = None
    reference_promotion_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.skipped_participants is None:
            value.pop("skipped_participants", None)
        return value


class CohortModelAward(ModelAwardEvidence):
    schema_: Literal["umi-cohort-model-award/1"] = Field(alias="schema")
    rule: Literal["baseline_or_better_best_score_first_complete/1"]
    winner_submission_sha256: Hex32 | None
    recipient_hotkey: Hotkey | None


class ModelScoreCredit(StrictProtocolModel):
    content_sha256: Hex32
    submission_sha256: Hex32
    recipient_hotkey: Hotkey
    score: ExactQuality


class ProportionalModelAward(ModelAwardEvidence):
    schema_: Literal["umi-cohort-model-award/2"] = Field(alias="schema")
    rule: Literal["baseline_or_better_proportional_score_first_complete/1"]
    credits: Annotated[tuple[ModelScoreCredit, ...], Field(max_length=512)]
    zero_total_rule: Literal["equal_per_distinct_eligible_content"] = (
        "equal_per_distinct_eligible_content"
    )


class QualityBucketCredit(StrictProtocolModel):
    bucket_index: Annotated[int, Field(ge=0, le=9999)]
    lower_bound_bps: Annotated[int, Field(ge=0, le=9999)]
    upper_bound_bps: Annotated[int, Field(ge=1, le=10000)]
    member_submission_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    content_sha256: Hex32
    submission_sha256: Hex32
    recipient_hotkey: Hotkey
    score: ExactQuality


class QualityBucketModelAward(ModelAwardEvidence):
    schema_: Literal["umi-cohort-model-award/3"] = Field(alias="schema")
    rule: Literal["baseline_or_better_quality_bucket_best_score_first_complete/1"]
    bucket_width_bps: Annotated[int, Field(ge=1, le=10000)]
    credits: Annotated[tuple[QualityBucketCredit, ...], Field(max_length=512)]
    zero_total_rule: Literal["equal_per_occupied_quality_bucket"] = (
        "equal_per_occupied_quality_bucket"
    )

    @model_validator(mode="after")
    def canonical_buckets(self):
        indices = [credit.bucket_index for credit in self.credits]
        if indices != sorted(set(indices)):
            raise ValueError("model quality bucket credits must be unique and ordered")
        maximum_index = (10000 + self.bucket_width_bps - 1) // self.bucket_width_bps - 1
        candidates = {candidate.submission_sha256: candidate for candidate in self.candidates}
        certificates = {
            certificate.acceptance.submission_sha256: certificate
            for certificate in self.acceptances
        }
        ordinals = {
            submission: certificate.acceptance.accepted_ordinal
            for submission, certificate in certificates.items()
        }
        if (
            len(candidates) != len(self.candidates)
            or len(certificates) != len(self.acceptances)
            or set(candidates) != set(certificates)
            or len(set(ordinals.values())) != len(ordinals)
        ):
            raise ValueError("model quality bucket evidence has inconsistent roster identities")
        ordered_blocks = [
            certificates[submission].acceptance.accepted_at_block
            for submission in sorted(ordinals, key=ordinals.__getitem__)
        ]
        if ordered_blocks != sorted(ordered_blocks):
            raise ValueError("model quality bucket acceptance order contradicts block order")
        baselines = {candidate.baseline_aggregate for candidate in self.candidates}
        if len(baselines) > 1:
            raise ValueError("model quality bucket evidence has inconsistent baselines")
        for submission, candidate in candidates.items():
            acceptance = certificates[submission].acceptance
            score = Fraction(
                int(candidate.aggregate.numerator), int(candidate.aggregate.denominator)
            )
            baseline = Fraction(
                int(candidate.baseline_aggregate.numerator),
                int(candidate.baseline_aggregate.denominator),
            )
            if (
                not 0 <= score <= 1
                or not 0 <= baseline <= 1
                or candidate.eligible != (score >= baseline)
                or candidate.acceptance_sha256 != digest(certificates[submission])
                or (
                    candidate.model_sha256,
                    candidate.content_sha256,
                    candidate.recipient_hotkey,
                )
                != (
                    acceptance.model_sha256,
                    acceptance.content_sha256,
                    acceptance.recipient_hotkey,
                )
            ):
                raise ValueError("model quality bucket candidate is not canonical")
        canonical_content: dict[str, ModelAwardCandidate] = {}
        for submission in sorted(candidates, key=ordinals.__getitem__):
            candidate = candidates[submission]
            canonical_content.setdefault(candidate.content_sha256, candidate)
        expected: dict[int, list[ModelAwardCandidate]] = {}
        for candidate in canonical_content.values():
            if not candidate.eligible:
                continue
            index = quality_bucket_index(
                Fraction(int(candidate.aggregate.numerator), int(candidate.aggregate.denominator)),
                self.bucket_width_bps,
            )
            expected.setdefault(index, []).append(candidate)
        expected_members: dict[int, list[str]] = {}
        for candidate in candidates.values():
            canonical = canonical_content[candidate.content_sha256]
            if not canonical.eligible:
                continue
            index = quality_bucket_index(
                Fraction(int(canonical.aggregate.numerator), int(canonical.aggregate.denominator)),
                self.bucket_width_bps,
            )
            expected_members.setdefault(index, []).append(candidate.submission_sha256)
        if indices != sorted(expected):
            raise ValueError("model quality bucket credits omit or add an eligible band")
        for credit in self.credits:
            members = expected[credit.bucket_index]
            winner = min(
                members,
                key=lambda candidate: (
                    -Fraction(
                        int(candidate.aggregate.numerator),
                        int(candidate.aggregate.denominator),
                    ),
                    ordinals[candidate.submission_sha256],
                    candidate.submission_sha256,
                ),
            )
            if (
                credit.bucket_index > maximum_index
                or credit.lower_bound_bps != credit.bucket_index * self.bucket_width_bps
                or credit.upper_bound_bps
                != min((credit.bucket_index + 1) * self.bucket_width_bps, 10000)
                or credit.member_submission_sha256s
                != tuple(sorted(set(credit.member_submission_sha256s)))
                or credit.submission_sha256 not in credit.member_submission_sha256s
                or credit.member_submission_sha256s
                != tuple(sorted(expected_members[credit.bucket_index]))
                or (
                    credit.content_sha256,
                    credit.submission_sha256,
                    credit.recipient_hotkey,
                    credit.score,
                )
                != (
                    winner.content_sha256,
                    winner.submission_sha256,
                    winner.recipient_hotkey,
                    winner.aggregate,
                )
            ):
                raise ValueError("model quality bucket credit is not canonical")
        return self


ModelAward = Annotated[
    CohortModelAward | ProportionalModelAward | QualityBucketModelAward,
    Field(discriminator="schema_"),
]
MODEL_AWARD_ADAPTER = TypeAdapter(ModelAward)
ModelArtifactVerifier = Callable[
    [CertifiedModelArtifactAcceptance, RecoverableRosterParticipant], None
]


class PendingModelAward(ValueError):
    """An accepted model still needs complete evidence; elapsed time changes nothing."""


def _fraction(value: ExactQuality) -> Fraction:
    result = Fraction(int(value.numerator), int(value.denominator))
    if not 0 <= result <= 1:
        raise ValueError("model award quality must be normalized")
    return result


def quality_bucket_index(score: Fraction, width_bps: int) -> int:
    """Map exact normalized quality into fixed pre-intake basis-point bands."""
    if not 0 <= score <= 1 or not 1 <= width_bps <= 10000:
        raise ValueError("invalid model quality bucket input")
    bucket_count = (10000 + width_bps - 1) // width_bps
    return min((score * 10000) // width_bps, bucket_count - 1)


def build_model_award(
    benchmark: CohortQualityManifest,
    review: ClosedQualityReview,
    acceptances: tuple[CertifiedModelArtifactAcceptance, ...],
    archive: Path,
    *,
    verify_artifact: ModelArtifactVerifier | None = None,
) -> CohortModelAward | ProportionalModelAward | QualityBucketModelAward:
    """Replay every model and apply the rule selected before intake.

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
    legacy_content_quality = {}
    for result, certificate in zip(models, accepted, strict=True):
        a = certificate.acceptance
        p = participants[result.submission_sha256]
        sub = p.record.request.signed_submission.submission
        bundle = sub.model_bundle
        if bundle is None or sub.track != "model":
            raise ValueError("model award requires a separate model submission")
        content = model_content_digest(bundle)
        verify_model_acceptance(
            certificate,
            p.record,
            review.history,
            review.policy,
            maximum_block=view.closure("intake").observed_at_block,
        )
        # Retain the original review documents in portable reward packages too.
        # A signed digest without its evidence is insufficient for recovery.
        read_endpoint_object(review.objects, a.rights_evidence_sha256)
        read_endpoint_object(review.objects, a.reconstruction_evidence_sha256)
        if verify_artifact is None:
            verify_preserved_bundle(bundle, archive, review.policy)
        else:
            verify_artifact(certificate, p)
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
        if (
            authority.model_reward_rule
            != "baseline_or_better_quality_bucket_best_score_first_complete/1"
        ):
            if (
                content in legacy_content_quality
                and legacy_content_quality[content] != result.candidate
            ):
                raise PendingModelAward("duplicate model content has inconsistent quality")
            legacy_content_quality[content] = result.candidate
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
    evidence = dict(
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
        skipped_participants=tuple(
            digest(p)
            for p in review.closure.skipped
            if participants[p.submission_sha256].record.request.signed_submission.submission.track
            == "model"
        )
        if review.closure.schema_ == "umi-cohort-request-closure/3"
        else None,
    )
    if authority.model_reward_rule == "baseline_or_better_best_score_first_complete/1":
        winner = min(choices) if choices else None
        return CohortModelAward(
            schema="umi-cohort-model-award/1",
            **evidence,
            winner_submission_sha256=winner[2] if winner else None,
            recipient_hotkey=winner[3] if winner else None,
        )
    # One paid identity per canonical content. Preserve the first complete
    # acceptance's attribution; aliases cannot steal or multiply its credit.
    by_submission = {c.submission_sha256: c for c in candidates}
    if authority.model_reward_rule == "baseline_or_better_proportional_score_first_complete/1":
        distinct = {}
        for certificate in ordered:
            candidate = by_submission[certificate.acceptance.submission_sha256]
            if candidate.eligible:
                distinct.setdefault(candidate.content_sha256, candidate)
        return ProportionalModelAward(
            schema="umi-cohort-model-award/2",
            **evidence,
            credits=tuple(
                ModelScoreCredit(
                    content_sha256=content,
                    submission_sha256=candidate.submission_sha256,
                    recipient_hotkey=candidate.recipient_hotkey,
                    score=candidate.aggregate,
                )
                for content, candidate in sorted(distinct.items())
            ),
        )
    canonical_content = {}
    for certificate in ordered:
        candidate = by_submission[certificate.acceptance.submission_sha256]
        canonical_content.setdefault(candidate.content_sha256, candidate)
    distinct = {
        content: candidate for content, candidate in canonical_content.items() if candidate.eligible
    }
    width = authority.model_quality_bucket_width_bps
    if width is None:
        raise ValueError("bucketed model rewards require a signed bucket width")
    buckets: dict[int, list[ModelAwardCandidate]] = {}
    for candidate in distinct.values():
        index = quality_bucket_index(_fraction(candidate.aggregate), width)
        buckets.setdefault(index, []).append(candidate)
    bucket_members: dict[int, list[str]] = {}
    for candidate in candidates:
        canonical = canonical_content[candidate.content_sha256]
        if not canonical.eligible:
            continue
        index = quality_bucket_index(_fraction(canonical.aggregate), width)
        bucket_members.setdefault(index, []).append(candidate.submission_sha256)
    ordinals_by_submission = {
        certificate.acceptance.submission_sha256: certificate.acceptance.accepted_ordinal
        for certificate in ordered
    }
    credits = []
    for index, members in sorted(buckets.items()):
        winner = min(
            members,
            key=lambda candidate: (
                -_fraction(candidate.aggregate),
                ordinals_by_submission[candidate.submission_sha256],
                candidate.submission_sha256,
            ),
        )
        credits.append(
            QualityBucketCredit(
                bucket_index=index,
                lower_bound_bps=index * width,
                upper_bound_bps=min((index + 1) * width, 10000),
                member_submission_sha256s=tuple(sorted(bucket_members[index])),
                content_sha256=winner.content_sha256,
                submission_sha256=winner.submission_sha256,
                recipient_hotkey=winner.recipient_hotkey,
                score=winner.aggregate,
            )
        )
    return QualityBucketModelAward(
        schema="umi-cohort-model-award/3",
        **evidence,
        bucket_width_bps=width,
        credits=tuple(credits),
    )


def read_model_acceptances(
    directory: Path, review: ClosedQualityReview
) -> tuple[CertifiedModelArtifactAcceptance, ...]:
    """Load every completed model's acceptance; certified unperformed entries earn no award."""
    cohort = digest(review.history.plan)
    completed = {p.submission_sha256 for p in review.closure.participants}
    return tuple(
        read_private_model(
            directory / cohort / (digest(p.record.request.signed_submission.submission) + ".json"),
            CertifiedModelArtifactAcceptance,
            maximum_bytes=256 * 1024,
        )
        for p in review.roster.participants
        if p.record.request.signed_submission.submission.track == "model"
        and digest(p.record.request.signed_submission.submission) in completed
    )
