"""Portable authenticated cohort history for opt-in deadline consumers.

The caller supplies the expected current tip from its authoritative publication
or durable local state, and an owned finalized block. Signatures alone cannot
prove that a supplied prefix is the latest history or prove chain freshness.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_recovery import (
    CohortRecoveryGenesis,
    CohortRecoveryState,
    CohortRecoveryTransition,
    Phase,
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    SignedCohortRecoveryTransition,
    admit_recoverable_cohort,
    apply_recovery_transition,
    verify_recovery_quorum,
)
from .open_competition import CompetitionPolicy, Signature
from .protocol import StrictProtocolModel, canonical_json_bytes


class CohortRecoveryHistory(StrictProtocolModel):
    schema_: Literal["umi-cohort-recovery-history/1"] = Field(alias="schema")
    plan: RecoverableCohortPlan
    authority: SignedCohortRecoveryAuthority
    genesis: CohortRecoveryGenesis
    genesis_signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]
    transitions: tuple[SignedCohortRecoveryTransition, ...]


@dataclass(frozen=True)
class RecoveryHistoryView:
    """Derived data, not a live signing/transaction capability."""

    state: CohortRecoveryState
    closed_phases: tuple[CohortRecoveryTransition, ...]

    def closure(self, phase: Phase) -> CohortRecoveryTransition:
        for decision in self.closed_phases:
            if decision.phase == phase:
                return decision
        raise ValueError(f"cohort phase has no certified closure: {phase}")


def verify_cohort_history(
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> RecoveryHistoryView:
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    genesis, state = admit_recoverable_cohort(
        history.plan,
        history.authority,
        policy,
        admitted_at_block=history.genesis.admitted_at_block,
    )
    if genesis != history.genesis:
        raise ValueError("recovery history has a different admission")
    verify_recovery_quorum(genesis, history.genesis_signatures, policy)
    seen = set()
    closures = []
    for signed in history.transitions:
        decision = signed.transition
        identity = (decision.phase, decision.operation, decision.evidence_sha256)
        if identity in seen:
            raise ValueError("recovery history applies the same phase evidence twice")
        state = apply_recovery_transition(state, signed, history.authority, policy)
        seen.add(identity)
        if decision.operation == "close_phase":
            closures.append(decision)
    if state.tip_sha256 != expected_tip_sha256:
        raise ValueError("recovery history is not the selected current tip")
    if type(current_block) is not int or not state.observed_at_block <= current_block <= 2**53 - 1:
        raise ValueError("recovery history is ahead of the owned finalized observation")
    return RecoveryHistoryView(state=state, closed_phases=tuple(closures))
