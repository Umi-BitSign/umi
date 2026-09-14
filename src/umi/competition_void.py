"""Explicit, independently reviewed void outcomes for complete evaluation attempts.

A void carries every assigned evaluator's signed observations and a separate
quorum over the deterministic disposition. It assigns no score, promotion or
weight authority. Missing observations do not become a void certificate.
Settlement must separately enforce its retained first-arrival cutoff and check
each evaluator's own local execution before using this evidence.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .competition_observations import SignedExecutionAnnouncement, execution_observations
from .open_competition import (
    CompetitionPolicy,
    EvaluationSuite,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_VOID_BYTES = 64 * 1024**2
VoidReason = Literal["infrastructure_failure", "incumbent_failure", "observation_disagreement"]


class EvaluationVoid(StrictProtocolModel):
    schema_: Literal["umi-competition-evaluation-void/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    order_sha256: Hex32
    submission_sha256: Hex32
    suite_sha256: Hex32
    reason: VoidReason
    observations: Annotated[
        tuple[SignedExecutionAnnouncement, ...], Field(min_length=1, max_length=64)
    ]
    chain_submission_authorized: Literal[False] = False


class AttestedEvaluationVoid(StrictProtocolModel):
    void: EvaluationVoid
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def _eligible(output, policy):
    return (
        output.status == "ok"
        and output.elapsed_ms <= policy.maximum_inference_ms
        and len(output.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes
    )


def _reason(views, policy):
    if any(
        o.status == "infrastructure_failure"
        for v in views
        for role in ("candidate", "incumbent")
        for o in v[role]
    ):
        return "infrastructure_failure"
    if any(not _eligible(o, policy) for v in views for o in v["incumbent"]):
        return "incumbent_failure"
    for role in ("candidate", "incumbent"):
        for outputs in zip(*(v[role] for v in views), strict=True):
            if (
                len({(o.case_id, o.status, o.hypothesis, _eligible(o, policy)) for o in outputs})
                != 1
            ):
                return "observation_disagreement"
    raise ValueError("complete agreeing scored observations cannot be voided")


def propose_evaluation_void(
    *, signed_order, observations, suite, policy, current_block, legacy=None
):
    """Reconstruct an unsigned disposition from all independently signed attempts."""
    # Lazy import keeps the worker free to use this contract for its void branch.
    from .competition_evaluator import order_job, validate_order

    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    signed_order = validate_order(signed_order, policy, legacy)
    order = signed_order.order
    if not 1 <= len(observations) <= 64:
        raise ValueError("invalid void observation count")
    if sum(len(canonical_json_bytes(o)) for o in observations) > MAX_VOID_BYTES:
        raise ValueError("void observations exceed their byte bound")
    observations = tuple(
        SignedExecutionAnnouncement.model_validate_json(canonical_json_bytes(o))
        for o in observations
    )
    observations = tuple(
        sorted(observations, key=lambda o: identity(o.announcement.evaluator_hotkey))
    )
    keys = tuple(identity(o.announcement.evaluator_hotkey) for o in observations)
    if keys != tuple(identity(k) for k in order.evaluators):
        raise ValueError("void requires exactly all assigned evaluator observations")
    views = []
    for signed in observations:
        body = signed.announcement
        verify_signature(body, signed.signature)
        if body.order_sha256 != digest(order) or identity(signed.signature.hotkey) != identity(
            body.evaluator_hotkey
        ):
            raise ValueError("void observation signer or order mismatch")
        view = execution_observations(body.evidence, suite, policy, current_block=current_block)
        if view["job"] != order_job(order, body.evaluator_hotkey, policy, legacy):
            raise ValueError("void observation differs from the assigned execution")
        views.append(view)
    proposed = EvaluationVoid(
        schema="umi-competition-evaluation-void/1",
        policy_sha256=digest(policy),
        round_sha256=digest(order.round),
        order_sha256=digest(order),
        submission_sha256=digest(order.submission.submission),
        suite_sha256=digest(suite),
        reason=_reason(views, policy),
        observations=observations,
    )
    if len(canonical_json_bytes(proposed)) > MAX_VOID_BYTES:
        raise ValueError("void evidence exceeds its byte bound")
    return proposed


def validate_own_void(proposed, *, own_observation, evaluator_hotkey, **context):
    """Check exact local observations before a caller may sign a void proposal."""
    proposed = EvaluationVoid.model_validate_json(canonical_json_bytes(proposed))
    expected = propose_evaluation_void(observations=proposed.observations, **context)
    if proposed != expected:
        raise ValueError("void proposal differs from independent observation replay")
    own_observation = SignedExecutionAnnouncement.model_validate_json(
        canonical_json_bytes(own_observation)
    )
    if (
        identity(own_observation.announcement.evaluator_hotkey) != identity(evaluator_hotkey)
        or own_observation not in proposed.observations
    ):
        raise ValueError("void proposal does not retain this evaluator's exact local observation")
    return proposed


def verify_evaluation_void(attested, **context):
    """Authenticate a void decision; this is never a scoring or promotion result."""
    raw = canonical_json_bytes(attested)
    if len(raw) > MAX_VOID_BYTES:
        raise ValueError("void certificate exceeds its byte bound")
    attested = AttestedEvaluationVoid.model_validate_json(raw)
    expected = propose_evaluation_void(observations=attested.void.observations, **context)
    if attested.void != expected:
        raise ValueError("void certificate differs from independent observation replay")
    keys = []
    for signature in attested.signatures:
        verify_signature(attested.void, signature)
        keys.append(identity(signature.hotkey))
    if sorted(keys) != [identity(o.announcement.evaluator_hotkey) for o in expected.observations]:
        raise ValueError("void decision requires exactly its independent observation signers")
    return attested
