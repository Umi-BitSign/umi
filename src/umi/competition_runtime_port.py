"""Quorum review of an unrewarded reference model's entrypoint-only runtime port.

The certificate attests a reviewed port and its qualification evidence. Byte
equality of the other assets does not prove semantic equivalence of programs.
This path never grants contributor credit or replaces an earned model baseline.
"""

from __future__ import annotations

import hashlib
from typing import Annotated, Literal

from pydantic import Field

from .competition_policy_lineage import PolicyLineage, validate_operational_successor
from .open_competition import (
    Block,
    CompetitionPolicy,
    Hex32,
    ModelBundle,
    Signature,
    digest,
    identity,
    validate_bundle_policy,
    verify_signature,
)
from .protocol import StrictProtocolModel, canonical_json_bytes


class RuntimePortReview(StrictProtocolModel):
    schema_: Literal["umi-unrewarded-runtime-port-review/1"] = Field(alias="schema")
    policy_sha256: Hex32
    source_policy_sha256: Hex32
    previous_promotion_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    original: ModelBundle
    replacement: ModelBundle
    entrypoint: Annotated[str, Field(min_length=1, max_length=240)]
    qualification_sha256: Hex32
    source_review_sha256: Hex32
    offline_reconstruction_passed: Literal[True]
    not_before_block: Block
    valid_through_block: Block


class SignedRuntimePortReview(StrictProtocolModel):
    review: RuntimePortReview
    source_signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]
    target_signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class RuntimePortReceipt(StrictProtocolModel):
    certificate: SignedRuntimePortReview
    observed_block: Block


def baseline_record_digest(record: dict) -> str:
    return hashlib.sha256(b"umi-baseline-history-v1\0" + canonical_json_bytes(record)).hexdigest()


def runtime_port_record(review: RuntimePortReview) -> dict:
    # Signer ordering, extra valid signatures and local arrival times cannot
    # fork the shared head. Those belong to the separately retained receipt.
    return {
        "schema": "umi-model-baseline/3",
        "sequence": review.sequence,
        "policy_sha256": review.policy_sha256,
        "model_sha256": digest(review.replacement),
        "contributor_hotkey": None,
        "previous_promotion_sha256": review.previous_promotion_sha256,
        "kind": "runtime_port_no_reward",
        "review": review.model_dump(mode="json", by_alias=True),
    }


def _quorum(review: RuntimePortReview, signatures, policy: CompetitionPolicy) -> None:
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen = set()
    for signature in signatures:
        group = groups.get(identity(signature.hotkey))
        if group is None or group in seen:
            raise ValueError("runtime port has unauthorized or duplicate evaluator groups")
        verify_signature(review, signature)
        seen.add(group)
    if len(seen) < policy.required_evaluator_groups:
        raise ValueError("runtime port lacks the evaluator quorum")


def verify_runtime_port(
    certificate: SignedRuntimePortReview, lineage: PolicyLineage
) -> SignedRuntimePortReview:
    certificate = SignedRuntimePortReview.model_validate_json(canonical_json_bytes(certificate))
    review = certificate.review
    if not all(lineage.admits(p) for p in (review.policy_sha256, review.source_policy_sha256)):
        raise ValueError("runtime port policies are outside the admitted lineage")
    source = lineage.policy(review.source_policy_sha256)
    target = lineage.policy(review.policy_sha256)
    validate_operational_successor(target, source)
    if source.evaluation_runtime_sha256 == target.evaluation_runtime_sha256:
        raise ValueError("runtime port requires a different successor runtime")
    if (
        not target.valid_from_block
        <= review.not_before_block
        <= review.valid_through_block
        <= target.valid_through_block
    ):
        raise ValueError("runtime port application window is outside its policy")
    if "0" * 64 in (review.qualification_sha256, review.source_review_sha256):
        raise ValueError("runtime port requires qualification and source review evidence")
    old, new = review.original, review.replacement
    validate_bundle_policy(old, source)
    validate_bundle_policy(new, target)
    old_files, new_files = {f.path: f for f in old.files}, {f.path: f for f in new.files}
    if (
        old_files.keys() != new_files.keys()
        or review.entrypoint not in old_files
        or old_files[review.entrypoint].role != "inference"
        or new_files[review.entrypoint].role != "inference"
        or old_files[review.entrypoint].sha256 == new_files[review.entrypoint].sha256
        or any(old_files[p] != new_files[p] for p in old_files if p != review.entrypoint)
        or new.parent_baseline_sha256 != digest(old)
        or old.profile != new.profile
        or old.license_id != new.license_id
    ):
        raise ValueError("runtime port may change only its declared inference entrypoint")
    _quorum(review, certificate.source_signatures, source)
    _quorum(review, certificate.target_signatures, target)
    return certificate
