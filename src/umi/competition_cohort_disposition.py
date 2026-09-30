"""Complete assigned-evaluator review for recoverable scores and voids.

Missing observations remain pending. This layer cannot select retries, establish
publication timing, authorize a terminal scheduler transition or admit rewards.
The phase owner must separately prove complete obligations and attempt selection.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_endpoint import RecoverableEndpointPairedEvidence
from .competition_cohort_execution import RecoverableExecutionJob, RecoverableExecutionObservation
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_orders import (
    SignedRecoverableEvaluationOrder,
    recoverable_order_job,
    verify_recoverable_order,
)
from .competition_cohort_outcomes import (
    RecoverableExecutedEvaluation,
    RecoverableObservationEvidence,
    recoverable_observations,
    replay_recoverable_executed_evaluation,
)
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
)
from .competition_outcome_classification import PairedObservationOutputs, observation_void_reason
from .open_competition import (
    CompetitionPolicy,
    EvaluationSuite,
    Hotkey,
    RegistrationSnapshot,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_DISPOSITION_BYTES = 64 * 1024**2
RecoverableVoidReason = Literal[
    "infrastructure_failure", "incumbent_failure", "observation_disagreement"
]


@dataclass(frozen=True)
class RecoverableReviewContext:
    """Caller-owned history selection; this container is not a proof capability."""

    policy: CompetitionPolicy
    suite: EvaluationSuite
    consent: SignedCohortParticipationConsent
    admission: AttestedCohortParticipantAdmission
    admission_snapshot: RegistrationSnapshot
    history: CohortRecoveryHistory
    expected_tip_sha256: str
    current_block: int

    def verify_order(
        self, signed: SignedRecoverableEvaluationOrder
    ) -> SignedRecoverableEvaluationOrder:
        return verify_recoverable_order(
            signed,
            self.policy,
            self.consent,
            self.admission,
            self.admission_snapshot,
            self.history,
            expected_tip_sha256=self.expected_tip_sha256,
            current_block=self.current_block,
        )

    def observations(
        self, evidence: RecoverableObservationEvidence
    ) -> RecoverableExecutionObservation:
        return recoverable_observations(
            evidence,
            self.suite,
            self.policy,
            self.consent,
            self.admission,
            self.admission_snapshot,
            self.history,
            expected_tip_sha256=self.expected_tip_sha256,
            current_block=self.current_block,
        )

    def scored(
        self, evidence: RecoverableExecutedEvaluation, order: SignedRecoverableEvaluationOrder
    ) -> tuple[dict[str, Fraction], dict[str, Fraction]]:
        return replay_recoverable_executed_evaluation(
            evidence,
            order.order.submission,
            order.order.round,
            self.suite,
            self.policy,
            self.consent,
            self.admission,
            self.admission_snapshot,
            self.history,
            expected_tip_sha256=self.expected_tip_sha256,
            current_block=self.current_block,
        )


class RecoverableExecutionAnnouncement(StrictProtocolModel):
    schema_: Literal["umi-recoverable-execution-announcement/1"] = Field(alias="schema")
    order_sha256: Hex32
    evaluator_hotkey: Hotkey
    evidence: RecoverableObservationEvidence


class SignedRecoverableExecutionAnnouncement(StrictProtocolModel):
    announcement: RecoverableExecutionAnnouncement
    signature: Signature


class RecoverableEvaluationVoid(StrictProtocolModel):
    schema_: Literal["umi-recoverable-evaluation-void/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    order_sha256: Hex32
    submission_sha256: Hex32
    suite_sha256: Hex32
    reason: RecoverableVoidReason
    observations: Annotated[
        tuple[SignedRecoverableExecutionAnnouncement, ...], Field(min_length=1, max_length=64)
    ]
    chain_submission_authorized: Literal[False] = False


class AttestedRecoverableEvaluationVoid(StrictProtocolModel):
    void: RecoverableEvaluationVoid
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class RecoverableVoidEvidence(StrictProtocolModel):
    schema_: Literal["umi-recoverable-void-evidence/1"] = Field(alias="schema")
    certificate: AttestedRecoverableEvaluationVoid
    chain_submission_authorized: Literal[False] = False


class RecoverableOrderedOutcome(StrictProtocolModel):
    schema_: Literal["umi-recoverable-ordered-outcome/1"] = Field(alias="schema")
    order: SignedRecoverableEvaluationOrder
    evidence: Annotated[
        RecoverableExecutedEvaluation | RecoverableVoidEvidence, Field(discriminator="schema_")
    ]
    chain_submission_authorized: Literal[False] = False


@dataclass(frozen=True)
class RecoverableOutcomeDecision:
    order_sha256: str
    submission_sha256: str
    void_reason: RecoverableVoidReason | None
    candidate_quality: dict[str, Fraction] | None
    incumbent_quality: dict[str, Fraction] | None


def _bounded(value: StrictProtocolModel) -> bytes:
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_DISPOSITION_BYTES:
        raise ValueError("recoverable outcome exceeds its byte bound")
    return raw


def recoverable_void_decision_sha256(void: RecoverableEvaluationVoid) -> str:
    """Keep one decision identity across valid observation-signature variants."""
    void = RecoverableEvaluationVoid.model_validate_json(_bounded(void))
    body = void.model_dump(mode="json", by_alias=True, exclude={"observations"})
    body["observations"] = [
        signed.announcement.model_dump(mode="json", by_alias=True) for signed in void.observations
    ]
    return hashlib.sha256(
        b"umi-recoverable-void-decision-v1\0" + canonical_json_bytes(body)
    ).hexdigest()


def _evidence_job(evidence: RecoverableObservationEvidence) -> RecoverableExecutionJob:
    return (
        evidence.incumbent.job
        if isinstance(evidence, RecoverableEndpointPairedEvidence)
        else evidence.job
    )


def _assigned_artifact(
    evidence: RecoverableObservationEvidence, order: SignedRecoverableEvaluationOrder
) -> None:
    job = _evidence_job(evidence)
    if job != recoverable_order_job(order.order, job.evaluator_hotkey):
        raise ValueError("retained execution differs from its assigned recoverable order")


def propose_recoverable_void(
    order: SignedRecoverableEvaluationOrder,
    observations: tuple[SignedRecoverableExecutionAnnouncement, ...],
    context: RecoverableReviewContext,
) -> RecoverableEvaluationVoid:
    """Derive a review proposal from every assigned evaluator's signed evidence."""
    order = context.verify_order(order)
    if (
        not 1 <= len(observations) <= 64
        or sum(len(canonical_json_bytes(o)) for o in observations) > MAX_DISPOSITION_BYTES
    ):
        raise ValueError("invalid recoverable observation count or byte size")
    observations = tuple(
        sorted(
            (
                SignedRecoverableExecutionAnnouncement.model_validate_json(canonical_json_bytes(o))
                for o in observations
            ),
            key=lambda o: identity(o.announcement.evaluator_hotkey),
        )
    )
    keys = tuple(identity(o.announcement.evaluator_hotkey) for o in observations)
    if keys != tuple(identity(k) for k in order.order.evaluators):
        raise ValueError("void review requires exactly all assigned evaluator observations")
    views = []
    for signed in observations:
        body = signed.announcement
        verify_signature(body, signed.signature)
        if body.order_sha256 != digest(order.order) or identity(body.evaluator_hotkey) != identity(
            signed.signature.hotkey
        ):
            raise ValueError("recoverable observation signer or order differs")
        if identity(body.evaluator_hotkey) != identity(
            _evidence_job(body.evidence).evaluator_hotkey
        ):
            raise ValueError("observation signer differs from its execution evaluator")
        _assigned_artifact(body.evidence, order)
        view = context.observations(body.evidence)
        if len(view.candidate) != len(order.order.cases) or len(view.incumbent) != len(
            order.order.cases
        ):
            raise ValueError("void review requires complete paired observations")
        views.append(PairedObservationOutputs(view.candidate, view.incumbent))
    reason = observation_void_reason(tuple(views), context.policy)
    result = RecoverableEvaluationVoid(
        schema="umi-recoverable-evaluation-void/1",
        policy_sha256=digest(context.policy),
        round_sha256=digest(order.order.round),
        order_sha256=digest(order.order),
        submission_sha256=digest(order.order.submission.submission),
        suite_sha256=digest(context.suite),
        reason=reason,
        observations=observations,
    )
    _bounded(result)
    return result


def validate_own_recoverable_void(
    proposed: RecoverableEvaluationVoid,
    order: SignedRecoverableEvaluationOrder,
    own_observation: SignedRecoverableExecutionAnnouncement,
    evaluator_hotkey: str,
    context: RecoverableReviewContext,
) -> RecoverableEvaluationVoid:
    """Retain the reviewer's exact local signed observation before voting."""
    proposed = RecoverableEvaluationVoid.model_validate_json(_bounded(proposed))
    own = SignedRecoverableExecutionAnnouncement.model_validate_json(_bounded(own_observation))
    if proposed != propose_recoverable_void(order, proposed.observations, context):
        raise ValueError("void proposal differs from complete observation replay")
    if (
        identity(own.announcement.evaluator_hotkey) != identity(evaluator_hotkey)
        or own not in proposed.observations
    ):
        raise ValueError("void proposal does not retain the exact local observation")
    return proposed


def verify_recoverable_void(
    certificate: AttestedRecoverableEvaluationVoid,
    order: SignedRecoverableEvaluationOrder,
    context: RecoverableReviewContext,
) -> AttestedRecoverableEvaluationVoid:
    certificate = AttestedRecoverableEvaluationVoid.model_validate_json(_bounded(certificate))
    expected = propose_recoverable_void(order, certificate.void.observations, context)
    if certificate.void != expected:
        raise ValueError("void certificate differs from complete observation replay")
    keys = []
    for signature in certificate.signatures:
        verify_signature(certificate.void, signature)
        keys.append(identity(signature.hotkey))
    if sorted(keys) != [identity(o.announcement.evaluator_hotkey) for o in expected.observations]:
        raise ValueError("void decision requires exactly its assigned observation signers")
    return certificate


def replay_recoverable_ordered_outcome(
    outcome: RecoverableOrderedOutcome,
    context: RecoverableReviewContext,
) -> RecoverableOutcomeDecision:
    """Review an outcome against the full order; grant no scheduler/weight authority."""
    outcome = RecoverableOrderedOutcome.model_validate_json(_bounded(outcome))
    order = context.verify_order(outcome.order)
    if isinstance(outcome.evidence, RecoverableVoidEvidence):
        certificate = verify_recoverable_void(outcome.evidence.certificate, order, context)
        return RecoverableOutcomeDecision(
            digest(order.order),
            digest(order.order.submission.submission),
            certificate.void.reason,
            None,
            None,
        )
    evidence = outcome.evidence
    keys = [identity(run.run.evaluator_hotkey) for run in evidence.receipts.evaluator_runs]
    if sorted(keys) != [identity(k) for k in order.order.evaluators]:
        raise ValueError("scored outcome requires exactly all assigned evaluator receipts")
    for artifact in evidence.executions:
        _assigned_artifact(artifact, order)
    candidate, incumbent = context.scored(evidence, order)
    return RecoverableOutcomeDecision(
        digest(order.order), digest(order.order.submission.submission), None, candidate, incumbent
    )
