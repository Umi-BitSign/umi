"""Authenticated schedule changes that preserve already consumed cohorts."""

import json
from itertools import pairwise
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_launch import PublicLaunchIdentity
from .competition_policy_lineage import submission_policy_admitted
from .open_competition import (
    CompetitionPolicy,
    EvaluationRound,
    Hex32,
    Signature,
    digest,
    identity,
    verify_signature,
)
from .protocol import StrictProtocolModel, canonical_json_bytes


class LaunchAmendment(StrictProtocolModel):
    schema_: Literal["umi-competition-launch-amendment/1", "umi-competition-launch-amendment/2"] = (
        Field(alias="schema")
    )
    policy_sha256: Hex32
    previous_launch_sha256: Hex32
    replacement: PublicLaunchIdentity
    effective_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    reason: Literal["accelerate_first_cohort_continuous_intake", "extend_future_cohort_windows"]
    first_replaced_cycle: Annotated[int, Field(ge=1, le=2**53 - 1)] | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.first_replaced_cycle is None:
            value.pop("first_replaced_cycle", None)
        return value

    @model_validator(mode="after")
    def version_scope(self):
        future = self.schema_ == "umi-competition-launch-amendment/2"
        if future != (self.reason == "extend_future_cohort_windows") or future != (
            self.first_replaced_cycle is not None
        ):
            raise ValueError("launch amendment version differs from its scope")
        return self


def _verify_future_windows(amendment, previous, replacement, policy):
    if previous.round_stride_blocks is None or replacement.round_stride_blocks is None:
        raise ValueError("future amendment requires continuous cohorts")
    original = previous.schedule_for_cycle(amendment.first_replaced_cycle)
    preceding = previous.schedule_for_cycle(amendment.first_replaced_cycle - 1)
    new = replacement.round_schedule
    if not (
        policy.valid_from_block <= new.intake_opened_block
        and preceding.round_valid_through_block
        < amendment.effective_block
        < original.roster_close_earliest_block
        <= new.roster_close_earliest_block
        and replacement.round_stride_blocks >= previous.round_stride_blocks
        and new.round_valid_through_block <= policy.valid_through_block
    ):
        raise ValueError("future amendment must follow prior cohorts and precede unused intake")
    fields = (
        "roster_close_earliest_block",
        "roster_close_latest_block",
        "work_signing_close_block",
        "evaluation_close_block",
        "protected_reference_reveal_block",
        "evidence_cutoff_block",
        "round_valid_through_block",
    )
    for start, end in pairwise(fields):
        if getattr(new, end) - getattr(new, start) < getattr(original, end) - getattr(
            original, start
        ):
            raise ValueError("future amendment cannot shorten a cohort phase")


def verify_future_history(connection, previous, amendment):
    """Check the quiesced store before appending a future-only launch identity."""
    boundary = previous.schedule_for_cycle(amendment.first_replaced_cycle)
    rounds = {}
    for key, raw in connection.execute("SELECT digest,body FROM rounds"):
        round_ = EvaluationRound.model_validate_json(raw)
        if digest(round_) != key or canonical_json_bytes(round_) != raw:
            raise ValueError("stored competition round is corrupt")
        if (
            round_.public_schedule.roster_close_earliest_block
            >= boundary.roster_close_earliest_block
            or round_.public_schedule.round_valid_through_block >= amendment.effective_block
        ):
            raise ValueError("future amendment cannot change a prepared or active cohort")
        rounds[key] = round_
    # Every evidence/index entry must still have its original retained round.
    for table in (
        "suite_usage",
        "public_schedule_usage",
        "evidence_cutoff_schedules",
        "round_conflicts",
        "settlement_disputes",
    ):
        if any(key not in rounds for (key,) in connection.execute(f"SELECT round FROM {table}")):
            raise ValueError("future amendment has unbound retained cohort evidence")
    for suite, raw in connection.execute("SELECT suite,body FROM round_preparations"):
        body = json.loads(raw)
        round_ = EvaluationRound.model_validate_json(
            canonical_json_bytes(body["cutoff_publication"]["round"])
        )
        if (
            canonical_json_bytes(body) != raw
            or round_.suite_sha256 != suite
            or rounds.get(digest(round_)) != round_
        ):
            raise ValueError("future amendment has unbound retained preparation")


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
        or previous.eligible_tracks != replacement.eligible_tracks
        or old.intake_opened_block != new.intake_opened_block
    ):
        raise ValueError("launch amendment changes unauthorized semantics")
    if amendment.reason == "extend_future_cohort_windows":
        _verify_future_windows(amendment, previous, replacement, policy)
    elif (
        previous.round_stride_blocks is not None
        or replacement.round_stride_blocks is None
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
