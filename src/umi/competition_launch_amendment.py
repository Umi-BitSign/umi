"""Authenticated replacement of an unconsumed first-cohort schedule."""

from typing import Annotated, Literal

from pydantic import Field

from .competition_launch import PublicLaunchIdentity
from .competition_policy_lineage import submission_policy_admitted
from .open_competition import (
    CompetitionPolicy,
    Hex32,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .protocol import StrictProtocolModel, canonical_json_bytes


class LaunchAmendment(StrictProtocolModel):
    schema_: Literal["umi-competition-launch-amendment/1"] = Field(alias="schema")
    policy_sha256: Hex32
    previous_launch_sha256: Hex32
    replacement: PublicLaunchIdentity
    effective_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    reason: Literal["accelerate_first_cohort_continuous_intake"]


class SignedLaunchAmendment(StrictProtocolModel):
    amendment: LaunchAmendment
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def verify_launch_amendment(
    signed: SignedLaunchAmendment,
    previous: PublicLaunchIdentity,
    replacement: PublicLaunchIdentity,
    policy: CompetitionPolicy,
) -> None:
    """Verify authorization and scope; the store separately checks unused state."""
    signed = SignedLaunchAmendment.model_validate_json(canonical_json_bytes(signed))
    amendment = signed.amendment
    old, new = previous.round_schedule, replacement.round_schedule
    # A schedule amendment signed under a deal-preserving predecessor stays valid: the
    # signature is over the amendment bytes, and every scope clause below is re-checked
    # against the live policy on each open.
    if (
        not submission_policy_admitted(policy, amendment.policy_sha256)
        or amendment.previous_launch_sha256 != digest(previous)
        or amendment.replacement != replacement
        or previous.round_stride_blocks is not None
        or replacement.round_stride_blocks is None
        or previous.eligible_tracks != replacement.eligible_tracks
        or old.intake_opened_block != new.intake_opened_block
        or not policy.valid_from_block
        <= new.intake_opened_block
        <= amendment.effective_block
        < new.roster_close_earliest_block
        < old.roster_close_earliest_block
        or new.round_valid_through_block > policy.valid_through_block
        or new.evaluation_close_block > old.evaluation_close_block
    ):
        raise ValueError("launch amendment changes unauthorized semantics")
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen = set()
    for signature in signed.signatures:
        key = identity(signature.hotkey)
        if key not in groups or groups[key] in seen:
            raise ValueError("launch amendment has unauthorized or duplicate evaluator groups")
        verify_signature(amendment, signature)
        seen.add(groups[key])
    if len(seen) < policy.required_evaluator_groups:
        raise ValueError("launch amendment lacks the policy evaluator quorum")
