"""Reference-free evaluator assignments for recoverable cohort evidence.

These signed orders bind the complete evaluator set. They do not establish
original publication time, fence a replacement writer or authorize live delivery.
The owning scheduler must retain the selected order before dispatch or invocation.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_evaluation import (
    RecoverableEvaluationRound,
    verify_recoverable_round_participant,
)
from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_execution import ExecutionCase
from .competition_runner import OfflineRuntime
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    ModelBundle,
    RegistrationSnapshot,
    Signature,
    SignedSubmission,
    digest,
    has_case_coverage,
    identity,
    validate_bundle_policy,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_ORDER_BYTES = 16 * 1024**2


class RecoverableEvaluationOrder(StrictProtocolModel):
    schema_: Literal["umi-recoverable-evaluation-order/1"] = Field(alias="schema")
    round: RecoverableEvaluationRound
    preparation_closure_sha256: Hex32
    submission: SignedSubmission
    incumbent: ModelBundle
    runtime: OfflineRuntime
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]
    evaluators: Annotated[tuple[Hotkey, ...], Field(min_length=1, max_length=64)]
    chain_submission_authorized: Literal[False] = False


class SignedRecoverableEvaluationOrder(StrictProtocolModel):
    order: RecoverableEvaluationOrder
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def recoverable_order_job(
    order: RecoverableEvaluationOrder, evaluator: str
) -> RecoverableExecutionJob:
    """Project one exact job; this unsigned projection grants no invocation authority."""
    order = RecoverableEvaluationOrder.model_validate_json(canonical_json_bytes(order))
    if identity(evaluator) not in {identity(k) for k in order.evaluators}:
        raise ValueError("evaluator is not assigned by the recoverable order")
    return RecoverableExecutionJob(
        schema="umi-recoverable-execution-job/1",
        mode="paired_model"
        if order.submission.submission.track == "model"
        else "endpoint_incumbent",
        round=order.round,
        preparation_closure_sha256=order.preparation_closure_sha256,
        submission=order.submission,
        incumbent=order.incumbent,
        runtime=order.runtime,
        cases=order.cases,
        evaluator_hotkey=evaluator,
    )


def verify_recoverable_order(
    signed: SignedRecoverableEvaluationOrder,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> SignedRecoverableEvaluationOrder:
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_ORDER_BYTES:
        raise ValueError("recoverable evaluation order exceeds its byte bound")
    signed = SignedRecoverableEvaluationOrder.model_validate_json(raw)
    verify_recoverable_order_body(
        signed.order,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    verify_recovery_quorum(signed.order, signed.signatures, policy)
    miner = identity(signed.order.submission.submission.hotkey)
    if any(identity(s.hotkey) == miner for s in signed.signatures):
        raise ValueError("a submitting hotkey cannot authorize its own order")
    return signed


def verify_recoverable_order_body(
    order: RecoverableEvaluationOrder,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> RecoverableEvaluationOrder:
    """Validate the reference-free body before reserving a signing decision."""
    raw = canonical_json_bytes(order)
    if len(raw) > MAX_ORDER_BYTES:
        raise ValueError("recoverable evaluation order exceeds its byte bound")
    order = RecoverableEvaluationOrder.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    view = verify_recoverable_round_participant(
        order.submission,
        order.round,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    keys = tuple(identity(k) for k in order.evaluators)
    if keys != tuple(sorted(set(keys))) or any(k not in groups for k in keys):
        raise ValueError("order evaluators must be canonical authorized identities")
    if len({groups[k] for k in keys}) != len(keys) or len(keys) < policy.required_evaluator_groups:
        raise ValueError("order requires distinct independent evaluator groups")
    miner = identity(order.submission.submission.hotkey)
    if miner in keys:
        raise ValueError("a submitting hotkey cannot authorize or evaluate its own order")
    if (
        order.preparation_closure_sha256 != digest(view.closure("preparation"))
        or digest(order.incumbent) != order.round.incumbent_model_sha256
        or digest(order.runtime) != order.round.runtime_sha256
        or len({c.case_id for c in order.cases}) != len(order.cases)
        or not has_case_coverage(order.cases, policy)
    ):
        raise ValueError("recoverable order preparation, runtime, model or case binding differs")
    validate_bundle_policy(order.incumbent, policy)
    if order.submission.submission.track == "model":
        validate_bundle_policy(order.submission.submission.model_bundle, policy)
    return order
