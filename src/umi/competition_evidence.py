"""Independent evaluator run receipts for open-competition settlement.

This module strengthens, but does not replace, the existing ``AttestedResult``
wire contract.  A common result remains the co-signed transcript used by the
conflict ledger.  Each signer additionally commits to its own bounded run,
including its timing and an external execution-evidence identity.

Signatures authenticate statements.  Neither a signature nor an evidence
digest proves that an execution happened; production callers must retain and
independently inspect the referenced execution evidence.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Any, Literal, TypeVar

from pydantic import Field, model_validator
from typing_extensions import Self

from .crypto import sign_response_digest, verify_response_signature
from .open_competition import (
    AttestedResult,
    Block,
    CaseOutput,
    CompetitionPolicy,
    EvaluationRound,
    EvaluationSuite,
    Hotkey,
    Signature,
    SignedSubmission,
    _quality,
    digest,
    identity,
    replay_evaluation,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_RUN_DIGEST_DOMAIN = b"umi-competition-evaluator-run-v1\0"
_EVIDENCE_DIGEST_DOMAIN = b"umi-competition-independent-evaluation-v1\0"
_ZERO_SHA256 = "0" * 64
_ModelT = TypeVar("_ModelT", bound=StrictProtocolModel)


class EvaluatorRunRecord(StrictProtocolModel):
    """One evaluator's signed claim about one independent paired run."""

    schema_: Literal["umi-competition-evaluator-run/1"] = Field(alias="schema")
    evaluator_hotkey: Hotkey
    policy_sha256: Hex32
    round_sha256: Hex32
    submission_sha256: Hex32
    common_result_sha256: Hex32
    suite_sha256: Hex32
    model_revision: Hex32
    incumbent_model_sha256: Hex32
    runtime_sha256: Hex32
    started_block: Block
    finished_block: Block
    candidate: Annotated[tuple[CaseOutput, ...], Field(min_length=3, max_length=2048)]
    incumbent: Annotated[tuple[CaseOutput, ...], Field(min_length=3, max_length=2048)]
    execution_evidence_sha256: Hex32

    @model_validator(mode="after")
    def validate_run_shape(self) -> Self:
        if self.finished_block < self.started_block:
            raise ValueError("evaluator run interval is reversed")
        if self.execution_evidence_sha256 == _ZERO_SHA256:
            raise ValueError("evaluator run requires an execution-evidence identity")
        candidate_ids = [output.case_id for output in self.candidate]
        incumbent_ids = [output.case_id for output in self.incumbent]
        if len(set(candidate_ids)) != len(candidate_ids) or candidate_ids != incumbent_ids:
            raise ValueError("paired evaluator outputs must cover the same unique cases in order")
        return self


class SignedEvaluatorRunRecord(StrictProtocolModel):
    run: EvaluatorRunRecord
    signature: Signature


class IndependentEvaluationEvidence(StrictProtocolModel):
    """The unchanged common transcript plus one independently signed run per signer."""

    schema_: Literal["umi-competition-independent-evaluation/1"] = Field(alias="schema")
    attested_result: AttestedResult
    evaluator_runs: Annotated[
        tuple[SignedEvaluatorRunRecord, ...],
        Field(min_length=1, max_length=64),
    ]


def _canonical_model(model_type: type[_ModelT], value: _ModelT) -> _ModelT:
    """Revalidate instances that may have come from unsafe Pydantic helpers."""

    return model_type.model_validate_json(canonical_json_bytes(value), strict=True)


def evaluator_run_digest(run: EvaluatorRunRecord) -> str:
    """Return the domain-separated digest signed by one evaluator."""

    run = _canonical_model(EvaluatorRunRecord, run)
    return hashlib.sha256(_RUN_DIGEST_DOMAIN + canonical_json_bytes(run)).hexdigest()


def independent_evidence_digest(evidence: IndependentEvaluationEvidence) -> str:
    """Return a content digest for one complete independent-evidence object."""

    evidence = _canonical_model(IndependentEvaluationEvidence, evidence)
    return hashlib.sha256(_EVIDENCE_DIGEST_DOMAIN + canonical_json_bytes(evidence)).hexdigest()


def sign_evaluator_run(run: EvaluatorRunRecord, wallet: Any) -> Signature:
    """Sign a run with the explicitly supplied evaluator hotkey."""

    import bittensor as bt

    run = _canonical_model(EvaluatorRunRecord, run)
    signer = bt.resolve_signer(wallet, role="hotkey")
    if identity(signer.ss58_address) != identity(run.evaluator_hotkey):
        raise ValueError("evaluator run signer does not control the named hotkey")
    scheme, signature = sign_response_digest(wallet, evaluator_run_digest(run))
    return Signature(hotkey=signer.ss58_address, scheme=scheme, signature=signature)


def verify_evaluator_run(signed_run: SignedEvaluatorRunRecord) -> None:
    """Verify only a run's signer binding and domain-separated signature."""

    signed_run = _canonical_model(SignedEvaluatorRunRecord, signed_run)
    run, signature = signed_run.run, signed_run.signature
    if identity(signature.hotkey) != identity(run.evaluator_hotkey):
        raise ValueError("evaluator run signer does not control the named hotkey")
    if not verify_response_signature(
        evaluator_run_digest(run),
        hotkey_ss58=signature.hotkey,
        scheme=signature.scheme,
        signature=signature.signature,
    ):
        raise ValueError("invalid evaluator run signature")


def _same_observation(left: CaseOutput, right: CaseOutput) -> bool:
    return (
        left.case_id == right.case_id
        and left.status == right.status
        and left.hypothesis == right.hypothesis
    )


def _resource_eligible(output: CaseOutput, policy: CompetitionPolicy) -> bool:
    return (
        output.status == "ok"
        and output.elapsed_ms <= policy.maximum_inference_ms
        and len(output.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes
    )


@dataclass(frozen=True)
class EvaluationRunScope:
    """Bindings derived by a round verifier, not an authorization by themselves."""

    round_sha256: str
    incumbent_model_sha256: str
    runtime_sha256: str
    started_after_block: int
    finished_by_block: int


def _validate_run_bindings(
    run: EvaluatorRunRecord,
    *,
    common: AttestedResult,
    signed: SignedSubmission,
    scope: EvaluationRunScope,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
) -> None:
    result = common.result
    submission = signed.submission
    expected = {
        "policy_sha256": digest(policy),
        "round_sha256": scope.round_sha256,
        "submission_sha256": digest(submission),
        "common_result_sha256": digest(result),
        "suite_sha256": digest(suite),
        "model_revision": submission.model_revision,
        "incumbent_model_sha256": scope.incumbent_model_sha256,
        "runtime_sha256": scope.runtime_sha256,
    }
    if any(getattr(run, field) != value for field, value in expected.items()):
        raise ValueError("evaluator run identity, model or runtime binding mismatch")
    if not (
        scope.started_after_block
        < run.started_block
        <= run.finished_block
        <= result.finished_block
        <= scope.finished_by_block
    ):
        raise ValueError("evaluator run interval is outside the frozen evaluation window")

    suite_ids = [case.case_id for case in suite.cases]
    for own, recorded in ((run.candidate, result.candidate), (run.incumbent, result.incumbent)):
        if [output.case_id for output in own] != suite_ids:
            raise ValueError("evaluator run does not cover the complete suite in canonical order")
        for own_output, recorded_output in zip(own, recorded, strict=True):
            if not _same_observation(own_output, recorded_output):
                raise ValueError("evaluator run output disagrees with the common result")
            if _resource_eligible(own_output, policy) != _resource_eligible(
                recorded_output, policy
            ):
                raise ValueError("evaluator run resource eligibility disagrees by case")


def replay_independent_evaluation(
    evidence: IndependentEvaluationEvidence,
    signed: SignedSubmission,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    current_block: int,
) -> tuple[dict[str, Fraction], dict[str, Fraction]]:
    """Replay one settlement-eligible result with independent run receipts.

    This is intentionally separate from historical certificate intake.  A
    caller should preserve a valid legacy ``AttestedResult`` for conflict
    detection even when this stronger settlement check rejects its run
    evidence.
    """

    if type(current_block) is not int or not 0 <= current_block <= 2**53 - 1:
        raise ValueError("invalid current block")
    policy = _canonical_model(CompetitionPolicy, policy)
    signed = _canonical_model(SignedSubmission, signed)
    round_ = _canonical_model(EvaluationRound, round_)
    suite = _canonical_model(EvaluationSuite, suite)
    evidence = _canonical_model(IndependentEvaluationEvidence, evidence)
    common = evidence.attested_result

    common_quality = replay_evaluation(
        common,
        signed,
        round_,
        suite,
        policy,
        current_block=current_block,
    )
    return replay_evaluator_run_agreement(
        evidence,
        signed,
        suite,
        policy,
        scope=EvaluationRunScope(
            round_sha256=digest(round_),
            incumbent_model_sha256=round_.incumbent_model_sha256,
            runtime_sha256=round_.runtime_sha256,
            started_after_block=round_.submission_close_block,
            finished_by_block=round_.evaluation_close_block,
        ),
        common_quality=common_quality,
    )


def replay_evaluator_run_agreement(
    evidence: IndependentEvaluationEvidence,
    signed: SignedSubmission,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    scope: EvaluationRunScope,
    common_quality: tuple[dict[str, Fraction], dict[str, Fraction]],
) -> tuple[dict[str, Fraction], dict[str, Fraction]]:
    """Compare receipts after the caller authenticates the round and result.

    Both legacy and recoverable consumers derive the scope from their native
    authority checks. This agreement check grants no settlement or weight
    authority and does not inspect the referenced execution artifacts.
    """
    common = evidence.attested_result
    policy_groups = {identity(item.hotkey): item.control_group for item in policy.evaluators}
    submitting_key = identity(signed.submission.hotkey)
    common_keys = {identity(signature.hotkey) for signature in common.signatures}
    run_keys: set[str] = set()
    run_groups: set[str] = set()

    for signed_run in evidence.evaluator_runs:
        verify_evaluator_run(signed_run)
        run = signed_run.run
        key = identity(run.evaluator_hotkey)
        group = policy_groups.get(key)
        if group is None:
            raise ValueError("unauthorized evaluator run signer")
        if key == submitting_key:
            raise ValueError("a submitting hotkey cannot evaluate its own submission")
        if key in run_keys or group in run_groups:
            raise ValueError("duplicate evaluator run or control group")
        _validate_run_bindings(
            run,
            common=common,
            signed=signed,
            scope=scope,
            suite=suite,
            policy=policy,
        )
        candidate = _quality(run.candidate, suite, policy)
        incumbent = _quality(run.incumbent, suite, policy, incumbent=True)
        if (candidate, incumbent) != common_quality:
            raise ValueError("evaluator run exact scores disagree with the common result")
        run_keys.add(key)
        run_groups.add(group)

    if run_keys != common_keys:
        raise ValueError("common-result signers and evaluator runs do not match")
    if len(run_groups) < policy.required_evaluator_groups:
        raise ValueError("insufficient independent evaluator run evidence")
    return common_quality


__all__ = [
    "EvaluatorRunRecord",
    "IndependentEvaluationEvidence",
    "SignedEvaluatorRunRecord",
    "evaluator_run_digest",
    "independent_evidence_digest",
    "replay_independent_evaluation",
    "sign_evaluator_run",
    "verify_evaluator_run",
]
