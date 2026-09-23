"""Immutable intake membership, bound to one authoritative schedule generation.

An intake seal stops new receipts at its selected history tip. It is a locally
verified phase result, not a quorum admission certificate or a round. Independent
certifiers must verify registration proofs and service availability as well.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake_records import read_participation, replay_participation
from .competition_cohort_recovery import CohortRecoveryTransition, verify_recovery_quorum
from .competition_execution import ExecutionBoundary
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    RegistrationSnapshot,
    Track,
    digest,
    identity,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class EmptyCohortIntake(ValueError):
    """No currently registered participant can be selected; keep intake open."""


class CohortIntakeSelection(StrictProtocolModel):
    consent_sha256: Hex32
    submission_sha256: Hex32
    record_sha256: Hex32
    hotkey: Hotkey
    track: Track
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    uid: Annotated[int, Field(ge=0, le=255)]


class CohortIntakeSeal(StrictProtocolModel):
    schema_: Literal["umi-cohort-intake-seal/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    policy_sha256: Hex32
    recovery_tip_sha256: Hex32
    observation: ExecutionBoundary
    snapshot: RegistrationSnapshot
    record_count: Annotated[int, Field(ge=0, le=1_000_000)]
    records_sha256: Hex32
    selected: Annotated[tuple[CohortIntakeSelection, ...], Field(min_length=1, max_length=512)]

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple((identity(s.hotkey), s.track) for s in self.selected)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("sealed intake selections must be unique and ordered")
        if len(self.selected) > self.record_count:
            raise ValueError("sealed selections exceed the retained record count")
        if (
            self.observation.block != self.snapshot.block
            or self.observation.block_hash != self.snapshot.block_hash
            or self.observation.snapshot_sha256 != digest(self.snapshot)
        ):
            raise ValueError("sealed registration observation differs from its snapshot")
        return self


def build_intake_seal(
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    observation: ExecutionBoundary,
    snapshot: RegistrationSnapshot,
    records: Iterable[tuple[str, bytes]],
    *,
    expected_tip_sha256: str,
) -> CohortIntakeSeal:
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=expected_tip_sha256,
        current_block=observation.block,
    )
    if view.state.phase != "intake" or observation.block < view.state.targets[0].target_block:
        raise ValueError("intake cannot be sealed before its target or outside intake")
    registrations = {identity(r.hotkey): r.uid for r in snapshot.registrations}
    if len(registrations) != len(snapshot.registrations):
        raise ValueError("sealed snapshot repeats a registered hotkey")
    selected = {}
    previous = ""
    count = 0
    hasher = hashlib.sha256(b"umi-cohort-intake-records-v1\0")
    for key, raw in records:
        retained = read_participation(raw)
        admission = replay_participation(retained, history, policy)
        if (
            key <= previous
            or key != admission.consent_sha256
            or admission.admitted_at_block > observation.block
        ):
            raise ValueError("sealed consent order, identity or observation differs")
        previous = key
        count += 1
        record_hash = digest(retained)
        hasher.update(bytes.fromhex(key) + bytes.fromhex(record_hash))
        sub = retained.request.signed_submission.submission
        account = identity(sub.hotkey)
        uid = registrations.get(account)
        if uid is None or uid >= policy.maximum_uids:
            continue
        selection = CohortIntakeSelection(
            consent_sha256=key,
            submission_sha256=digest(sub),
            record_sha256=record_hash,
            hotkey=sub.hotkey,
            track=sub.track,
            sequence=sub.sequence,
            uid=uid,
        )
        slot = (account, sub.track)
        prior = selected.get(slot)
        if prior is None or prior.sequence < selection.sequence:
            selected[slot] = selection
        elif prior.sequence == selection.sequence:
            raise ValueError("sealed intake contains conflicting submission sequences")
    if not selected:
        raise EmptyCohortIntake("intake has no eligible selected participants")
    return CohortIntakeSeal(
        schema="umi-cohort-intake-seal/1",
        cohort_sha256=digest(history.plan),
        policy_sha256=digest(policy),
        recovery_tip_sha256=expected_tip_sha256,
        observation=observation,
        snapshot=snapshot,
        record_count=count,
        records_sha256=hasher.hexdigest(),
        selected=tuple(selected[k] for k in sorted(selected)),
    )


def verify_intake_closure(
    seal: CohortIntakeSeal,
    transition: CohortRecoveryTransition,
    evidence: CohortDecisionInput,
    policy: CompetitionPolicy,
) -> None:
    evidence = CohortDecisionInput.model_validate_json(canonical_json_bytes(evidence))
    progress = evidence.progress.progress
    verify_recovery_quorum(progress, evidence.progress.signatures, policy)
    if (
        transition.operation != "close_phase"
        or transition.phase != "intake"
        or transition.cohort_sha256 != seal.cohort_sha256
        or transition.predecessor_sha256 != seal.recovery_tip_sha256
        or transition.evidence_sha256 != digest(evidence)
        or transition.observed_at_block != evidence.observation.block
        or progress.cohort_sha256 != seal.cohort_sha256
        or progress.recovery_tip_sha256 != seal.recovery_tip_sha256
        or progress.phase != "intake"
        or progress.completion != "complete"
        or progress.phase_result_sha256 != digest(seal)
        or progress.evidence_sha256 != digest(seal)
        or not seal.observation.block <= progress.observed_at_block <= evidence.observation.block
        or evidence.observation.block - progress.observed_at_block
        > policy.maximum_snapshot_age_blocks
    ):
        raise ValueError("intake closure differs from its retained seal and authenticated progress")
