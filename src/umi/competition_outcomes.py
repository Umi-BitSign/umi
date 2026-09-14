"""Typed scored/void outcome bindings for complete-roster settlement replay."""

from __future__ import annotations

from pydantic import TypeAdapter

from .competition_evidence import (
    IndependentEvaluationEvidence,
    independent_evidence_digest,
    replay_independent_evaluation,
)
from .competition_settlement import SettlementResultBinding, SettlementVoidBinding
from .competition_void import (
    VoidEvaluationEvidence,
    replay_void_evidence,
    void_decision_digest,
    void_evidence_digest,
)
from .open_competition import digest
from .protocol import canonical_json_bytes

OutcomeEvidence = IndependentEvaluationEvidence | VoidEvaluationEvidence
_OUTCOME = TypeAdapter(OutcomeEvidence)


def parse_outcome(value):
    return _OUTCOME.validate_json(canonical_json_bytes(value), strict=True)


def outcome_digest(value):
    return (
        void_evidence_digest(value)
        if isinstance(value, VoidEvaluationEvidence)
        else independent_evidence_digest(value)
    )


def outcome_decision_digest(value):
    return (
        void_decision_digest(value.certificate.void)
        if isinstance(value, VoidEvaluationEvidence)
        else digest(value.attested_result.result)
    )


def outcome_storage(value):
    if isinstance(value, (VoidEvaluationEvidence, SettlementVoidBinding)):
        return "void_evaluation_evidence", "decision"
    return "independent_evaluation_evidence", "result"


def binding_ids(binding):
    if isinstance(binding, SettlementVoidBinding):
        return binding.void_decision_sha256, binding.void_evidence_sha256
    return binding.result_sha256, binding.independent_evidence_sha256


def outcome_binding(submission_id, evidence, first_observed_block):
    ids = (outcome_decision_digest(evidence), outcome_digest(evidence))
    if isinstance(evidence, VoidEvaluationEvidence):
        return SettlementVoidBinding(
            submission_sha256=submission_id,
            void_decision_sha256=ids[0],
            void_evidence_sha256=ids[1],
            first_observed_block=first_observed_block,
        )
    return SettlementResultBinding(
        submission_sha256=submission_id,
        result_sha256=ids[0],
        independent_evidence_sha256=ids[1],
        first_observed_block=first_observed_block,
    )


def replay_outcome(evidence, signed, round_, suite, policy, *, current_block):
    if isinstance(evidence, VoidEvaluationEvidence):
        if evidence.order.order.round != round_ or evidence.order.order.submission != signed:
            raise ValueError("void evidence differs from the exact frozen roster entry")
        return replay_void_evidence(
            evidence, suite=suite, policy=policy, current_block=current_block
        )
    return replay_independent_evaluation(
        evidence, signed, round_, suite, policy, current_block=current_block
    )
