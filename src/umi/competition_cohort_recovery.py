"""Opt-in cohort recovery contracts and deterministic phase transitions.

These records do not alter legacy round/request signatures or authorize a chain
transaction. Consumers must explicitly adopt this contract and verify their own
phase-completion evidence. A schedule target alone never closes a phase.
"""

from __future__ import annotations

from itertools import pairwise
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

Block = Annotated[int, Field(ge=0, le=2**53 - 1)]
Phase = Literal[
    "intake",
    "preparation",
    "requests",
    "reference_reveal",
    "evidence",
    "review",
    "certification",
    "first_admission",
]
PHASES: tuple[Phase, ...] = (
    "intake",
    "preparation",
    "requests",
    "reference_reveal",
    "evidence",
    "review",
    "certification",
    "first_admission",
)
RecoveryOperation = Literal["extend", "close_phase", "revoke"]


class PhaseTarget(StrictProtocolModel):
    phase: Phase
    target_block: Block


Targets = Annotated[tuple[PhaseTarget, ...], Field(min_length=8, max_length=8)]


def _targets(values: tuple[PhaseTarget, ...]) -> None:
    if tuple(v.phase for v in values) != PHASES or any(
        a.target_block >= b.target_block for a, b in pairwise(values)
    ):
        raise ValueError("cohort targets must contain every ordered phase exactly once")


class RecoverableCohortPlan(StrictProtocolModel):
    """Stable identity created before intake; target revisions keep this digest."""

    schema_: Literal["umi-recoverable-cohort-plan/1"] = Field(alias="schema")
    policy_sha256: Hex32
    launch_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**32 - 1)]
    suite_sha256: Hex32
    not_before_block: Block
    initial_targets: Targets

    @model_validator(mode="after")
    def ordered(self) -> Self:
        _targets(self.initial_targets)
        if self.not_before_block >= self.initial_targets[0].target_block:
            raise ValueError("cohort starts before its first phase target")
        return self


class CohortRecoveryAuthority(StrictProtocolModel):
    """Explicit quorum consent to finish these cohorts despite later expiry."""

    schema_: Literal["umi-cohort-recovery-authority/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=512)]
    issued_at_block: Block
    minimum_recovery_margin_blocks: Annotated[int, Field(ge=1, le=7200)]
    maximum_extension_step_blocks: Annotated[int, Field(ge=1, le=72000)]
    lifetime: Literal["until_completed_or_revoked"]
    closure_rule: Literal["quorum_certified_phase_completion"]
    elapsed_target_cancels_cohort: Literal[False] = False
    historical_request_bytes_mutable: Literal[False] = False

    @model_validator(mode="after")
    def bounds(self) -> Self:
        if self.cohort_sha256s != tuple(sorted(set(self.cohort_sha256s))):
            raise ValueError("recovery cohort identities must be unique and sorted")
        if self.maximum_extension_step_blocks < self.minimum_recovery_margin_blocks:
            raise ValueError("recovery step cannot be smaller than the recovery margin")
        return self


class SignedCohortRecoveryAuthority(StrictProtocolModel):
    authority: CohortRecoveryAuthority
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class CohortRecoveryGenesis(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovery-genesis/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    authority_sha256: Hex32
    admitted_at_block: Block


class CohortRecoveryTransition(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovery-transition/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    authority_sha256: Hex32
    sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    predecessor_sha256: Hex32
    phase: Phase
    operation: RecoveryOperation
    extension_blocks: Annotated[int, Field(ge=1, le=72000)] | None
    observed_at_block: Block
    evidence_sha256: Hex32
    targets: Targets

    @model_validator(mode="after")
    def ordered(self) -> Self:
        _targets(self.targets)
        if self.evidence_sha256 == "0" * 64:
            raise ValueError("phase decisions require retained evidence")
        if (self.operation == "extend") != (self.extension_blocks is not None):
            raise ValueError("only an extension specifies additional blocks")
        return self


class SignedCohortRecoveryTransition(StrictProtocolModel):
    transition: CohortRecoveryTransition
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class CohortRecoveryState(StrictProtocolModel):
    """Derived data; reconstruct from authenticated genesis and transitions."""

    schema_: Literal["umi-cohort-recovery-state/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    authority_sha256: Hex32
    sequence: Annotated[int, Field(ge=0, le=2**53 - 1)]
    tip_sha256: Hex32
    observed_at_block: Block
    not_before_block: Block
    phase: Phase | Literal["complete", "revoked"]
    targets: Targets

    @model_validator(mode="after")
    def ordered(self) -> Self:
        _targets(self.targets)
        return self


def verify_recovery_quorum(
    body: StrictProtocolModel,
    signatures: tuple[Signature, ...],
    policy: CompetitionPolicy,
) -> None:
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    accounts = [identity(s.hotkey) for s in signatures]
    if accounts != sorted(set(accounts)):
        raise ValueError("recovery signatures must be unique and account-sorted")
    seen: set[str] = set()
    for signature in signatures:
        group = groups.get(identity(signature.hotkey))
        if group is None or group in seen:
            raise ValueError("recovery signer is unauthorized or repeats a control group")
        verify_signature(body, signature)
        seen.add(group)
    if len(seen) < policy.required_evaluator_groups:
        raise ValueError("cohort recovery lacks the policy evaluator quorum")


def verify_recovery_authority(
    signed: SignedCohortRecoveryAuthority,
    policy: CompetitionPolicy,
) -> CohortRecoveryAuthority:
    signed = SignedCohortRecoveryAuthority.model_validate_json(canonical_json_bytes(signed))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    body = signed.authority
    if (
        body.policy_sha256 != digest(policy)
        or not policy.valid_from_block <= body.issued_at_block <= policy.valid_through_block
    ):
        raise ValueError("recovery authority was not issued under the selected policy")
    verify_recovery_quorum(body, signed.signatures, policy)
    return body


def admit_recoverable_cohort(
    plan: RecoverableCohortPlan,
    signed: SignedCohortRecoveryAuthority,
    policy: CompetitionPolicy,
    *,
    admitted_at_block: int,
) -> tuple[CohortRecoveryGenesis, CohortRecoveryState]:
    """Pre-admit scheduled cohorts while policy/authority consent is current.

    The explicit recovery grant survives that policy's ordinary intake interval
    for these already admitted cohort identities. It cannot admit another one.
    """
    plan = RecoverableCohortPlan.model_validate_json(canonical_json_bytes(plan))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    authority = verify_recovery_authority(signed, policy)
    if (
        digest(plan) not in authority.cohort_sha256s
        or plan.policy_sha256 != digest(policy)
        or type(admitted_at_block) is not int
        or not authority.issued_at_block <= admitted_at_block <= policy.valid_through_block
        or not policy.valid_from_block
        <= plan.not_before_block
        < plan.initial_targets[-1].target_block
        <= policy.valid_through_block
    ):
        raise ValueError("cohort lacks timely explicit admission to recovery")
    genesis = CohortRecoveryGenesis(
        schema="umi-cohort-recovery-genesis/1",
        cohort_sha256=digest(plan),
        authority_sha256=digest(authority),
        admitted_at_block=admitted_at_block,
    )
    state = CohortRecoveryState(
        schema="umi-cohort-recovery-state/1",
        cohort_sha256=genesis.cohort_sha256,
        authority_sha256=genesis.authority_sha256,
        sequence=0,
        tip_sha256=digest(genesis),
        observed_at_block=admitted_at_block,
        not_before_block=plan.not_before_block,
        phase=PHASES[0],
        targets=plan.initial_targets,
    )
    return genesis, state


def _revised_targets(
    state: CohortRecoveryState,
    authority: CohortRecoveryAuthority,
    operation: RecoveryOperation,
    observed_at_block: int,
    extension_blocks: int | None,
) -> tuple[PhaseTarget, ...]:
    if state.phase not in PHASES:
        raise ValueError("completed or revoked cohort cannot acquire new work or extensions")
    index = PHASES.index(state.phase)
    target = state.targets[index].target_block
    if operation == "extend":
        if type(extension_blocks) is not int or not (
            1 <= extension_blocks <= authority.maximum_extension_step_blocks
        ):
            raise ValueError("extension exceeds the authorized step")
        # A quorum may restore lost service time even before the old target is
        # near. Consumers attest the lost interval in evidence; this contract
        # limits each step, never the number or aggregate length of extensions.
        shift = extension_blocks
        first = index
    elif operation == "close_phase":
        if state.phase in {"intake", "requests"} and observed_at_block < target:
            raise ValueError("cannot shorten an announced participant window")
        # Late completion preserves every following phase's existing budget.
        # The target of the closed phase remains historical; completion time is
        # separately recorded, rather than backdating it to the old target.
        shift, first = max(0, observed_at_block - target), index + 1
    elif operation == "revoke":
        shift, first = 0, len(PHASES)
    else:
        raise ValueError("unsupported cohort recovery operation")
    return tuple(
        PhaseTarget(phase=v.phase, target_block=v.target_block + (shift if i >= first else 0))
        for i, v in enumerate(state.targets)
    )


def propose_recovery_transition(
    state: CohortRecoveryState,
    authority: CohortRecoveryAuthority,
    *,
    operation: RecoveryOperation,
    observed_at_block: int,
    evidence_sha256: str,
    extension_blocks: int | None = None,
) -> CohortRecoveryTransition:
    """Pure proposal. Reserve exact bytes durably before asking authorities to sign."""
    state = CohortRecoveryState.model_validate_json(canonical_json_bytes(state))
    authority = CohortRecoveryAuthority.model_validate_json(canonical_json_bytes(authority))
    if (
        state.authority_sha256 != digest(authority)
        or state.cohort_sha256 not in authority.cohort_sha256s
        or type(observed_at_block) is not int
        or not state.observed_at_block <= observed_at_block <= 2**53 - 1
    ):
        raise ValueError("recovery proposal scope or finalized observation differs")
    if operation != "revoke" and observed_at_block < state.not_before_block:
        raise ValueError("cohort has not reached its announced start")
    if operation == "extend" and extension_blocks is None:
        if state.phase not in PHASES:
            raise ValueError("completed or revoked cohort cannot acquire new work or extensions")
        target = state.targets[PHASES.index(state.phase)].target_block
        margin = authority.minimum_recovery_margin_blocks
        if observed_at_block < target - margin:
            raise ValueError("cohort phase is not approaching its recovery margin")
        extension_blocks = min(
            authority.maximum_extension_step_blocks,
            max(margin, observed_at_block + margin - target),
        )
    if operation != "extend" and extension_blocks is not None:
        raise ValueError("only an extension specifies additional blocks")
    return CohortRecoveryTransition(
        schema="umi-cohort-recovery-transition/1",
        cohort_sha256=state.cohort_sha256,
        authority_sha256=state.authority_sha256,
        sequence=state.sequence + 1,
        predecessor_sha256=state.tip_sha256,
        phase=state.phase,
        operation=operation,
        observed_at_block=observed_at_block,
        evidence_sha256=evidence_sha256,
        extension_blocks=extension_blocks,
        targets=_revised_targets(state, authority, operation, observed_at_block, extension_blocks),
    )


def apply_recovery_transition(
    state: CohortRecoveryState,
    signed: SignedCohortRecoveryTransition,
    authority: SignedCohortRecoveryAuthority,
    policy: CompetitionPolicy,
) -> CohortRecoveryState:
    """Verify one next decision against a previously verified state.

    No check rejects a decision merely because an earlier target or the original
    policy's intake interval has passed. Live consumers still need their owned
    finalized observation and phase-specific evidence/authorization checks.
    """
    signed = SignedCohortRecoveryTransition.model_validate_json(canonical_json_bytes(signed))
    body = verify_recovery_authority(authority, policy)
    transition = signed.transition
    expected = propose_recovery_transition(
        state,
        body,
        operation=transition.operation,
        observed_at_block=transition.observed_at_block,
        evidence_sha256=transition.evidence_sha256,
        extension_blocks=transition.extension_blocks,
    )
    if transition != expected:
        raise ValueError("recovery decision forks history or changes an unauthorized phase")
    verify_recovery_quorum(transition, signed.signatures, policy)
    phase = state.phase
    if transition.operation == "close_phase":
        i = PHASES.index(phase) + 1
        phase = PHASES[i] if i < len(PHASES) else "complete"
    elif transition.operation == "revoke":
        phase = "revoked"
    return CohortRecoveryState(
        schema="umi-cohort-recovery-state/1",
        cohort_sha256=state.cohort_sha256,
        authority_sha256=state.authority_sha256,
        sequence=transition.sequence,
        tip_sha256=digest(transition),
        observed_at_block=transition.observed_at_block,
        not_before_block=state.not_before_block,
        phase=phase,
        targets=transition.targets,
    )
