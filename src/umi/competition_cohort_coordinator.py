"""Automatic phase decisions driven by retained, quorum-authenticated progress.

The service owner supplies native phase observers, independent certifiers, an
owned finality provider and a monotonic history publisher. These ports must not
infer completion from a target block or an operator's status JSON. Phase
producers fence further admissions/work before certifying an immutable result.
This controller neither changes legacy schedules nor submits chain weights.
"""

from __future__ import annotations

import asyncio
import sqlite3
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from typing import Annotated, Literal, Protocol

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_chain import RegistrationCapture
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import (
    PHASES,
    Block,
    CohortRecoveryAuthority,
    CohortRecoveryState,
    CohortRecoveryTransition,
    Phase,
    SignedCohortRecoveryTransition,
    admit_recoverable_cohort,
    apply_recovery_transition,
    propose_recovery_transition,
    verify_recovery_quorum,
)
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_execution import ExecutionBoundary, execution_boundary
from .open_competition import CompetitionPolicy, Signature, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class CohortPhaseProgress(StrictProtocolModel):
    schema_: Literal["umi-cohort-phase-progress/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    recovery_tip_sha256: Hex32
    phase: Phase
    observed_at_block: Block
    # Phase-local cumulative unavailable service, never a per-poll increment.
    unavailable_blocks: Block
    completion: Literal["pending", "complete"]
    phase_result_sha256: Hex32 | None
    evidence_sha256: Hex32

    @model_validator(mode="after")
    def result_binding(self) -> Self:
        if (self.completion == "complete") != (self.phase_result_sha256 is not None):
            raise ValueError("completed phase requires its immutable result identity")
        if "0" * 64 in {self.evidence_sha256, self.phase_result_sha256}:
            raise ValueError("phase progress requires nonempty evidence")
        return self


class AttestedCohortPhaseProgress(StrictProtocolModel):
    progress: CohortPhaseProgress
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class CohortDecisionInput(StrictProtocolModel):
    schema_: Literal["umi-cohort-decision-input/1"] = Field(alias="schema")
    progress: AttestedCohortPhaseProgress
    observation: ExecutionBoundary


def _choice(
    state: CohortRecoveryState,
    authority: CohortRecoveryAuthority,
    policy: CompetitionPolicy,
    evidence: CohortDecisionInput,
    restored: int,
    prior_unavailable: int,
) -> tuple[CohortRecoveryTransition | None, int]:
    """Replay the decision at its retained observation, not at a later retry's head."""
    checkpoint = evidence.progress.progress
    verify_recovery_quorum(checkpoint, evidence.progress.signatures, policy)
    block = evidence.observation.block
    if (
        checkpoint.cohort_sha256 != state.cohort_sha256
        or checkpoint.recovery_tip_sha256 != state.tip_sha256
        or checkpoint.phase != state.phase
        or checkpoint.unavailable_blocks < max(restored, prior_unavailable)
        or not state.observed_at_block <= checkpoint.observed_at_block <= block
        or block - checkpoint.observed_at_block > policy.maximum_snapshot_age_blocks
    ):
        raise ValueError("phase progress is stale, regressed or belongs to another history")
    if block < state.not_before_block:
        return None, 0
    target = state.targets[PHASES.index(state.phase)].target_block
    window = state.phase in {"intake", "requests"}
    missing = checkpoint.unavailable_blocks - restored
    if checkpoint.completion == "complete":
        if window and checkpoint.observed_at_block < target + missing:
            raise ValueError("participant window closed before restoring unavailable service")
        if state.phase == "reference_reveal" and block <= state.observed_at_block:
            return None, 0
        operation, extension, restored_now = "close_phase", None, 0
    elif missing:
        restored_now = min(missing, authority.maximum_extension_step_blocks)
        operation, extension = "extend", restored_now
    elif block >= target:
        operation, extension, restored_now = "extend", None, 0
    else:
        # Incomplete work before its target is normal. Extending every nearly
        # finished window would keep a healthy cohort open forever.
        return None, 0
    return propose_recovery_transition(
        state,
        authority,
        operation=operation,
        observed_at_block=block,
        evidence_sha256=digest(evidence),
        extension_blocks=extension,
    ), restored_now


def replay_cohort_decisions(
    history: CohortRecoveryHistory,
    policy: CompetitionPolicy,
    decision_source: Callable[[str], CohortDecisionInput],
) -> tuple[CohortRecoveryState, int, int]:
    """Authenticate progress and recover exact phase-local outage compensation.

    Signed target differences alone cannot distinguish outage compensation from
    ordinary scheduling margin. Consumers need the original decision inputs.
    """
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    last = history.transitions[-1].transition if history.transitions else history.genesis
    verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=digest(last),
        current_block=(
            history.transitions[-1].transition.observed_at_block
            if history.transitions
            else history.genesis.admitted_at_block
        ),
    )
    if history.plan.policy_sha256 != digest(policy):
        raise ValueError("cohort coordinator policy differs from its admitted policy")
    _, state = admit_recoverable_cohort(
        history.plan,
        history.authority,
        policy,
        admitted_at_block=history.genesis.admitted_at_block,
    )
    restored = prior_unavailable = 0
    for signed in history.transitions:
        if signed.transition.operation == "revoke":
            # Explicit revocation has separate quorum authorization. It is
            # never inferred from stalled work or an unavailable observer.
            state = apply_recovery_transition(state, signed, history.authority, policy)
            restored = prior_unavailable = 0
            continue
        evidence = decision_source(signed.transition.evidence_sha256)
        expected, credit = _choice(
            state,
            history.authority.authority,
            policy,
            evidence,
            restored,
            prior_unavailable,
        )
        if signed.transition != expected:
            raise ValueError("retained phase decision differs from its authenticated progress")
        updated = apply_recovery_transition(state, signed, history.authority, policy)
        restored = restored + credit if updated.phase == state.phase else 0
        prior_unavailable = (
            evidence.progress.progress.unavailable_blocks if updated.phase == state.phase else 0
        )
        state = updated
    return state, restored, prior_unavailable


class RecoveryFinality(Protocol):
    async def collect(self) -> RegistrationCapture: ...


ProgressObserver = Callable[
    [CohortRecoveryState, RegistrationCapture], Awaitable[AttestedCohortPhaseProgress]
]
DecisionCertifier = Callable[
    [CohortRecoveryTransition, CohortDecisionInput], Awaitable[SignedCohortRecoveryTransition]
]
HistoryPublisher = Callable[[CohortRecoveryHistory], Awaitable[None]]


class CohortRecoveryCoordinator:
    """One admitted cohort's restartable control loop, sharing its owner's store.

    Certifiers must retain their own vote intent and validate native phase
    evidence before signing. History publication must be idempotent and reject
    rollback. A pending decision can finish after an outage using its retained
    observation; fresh observations are required only for new decisions.
    """

    def __init__(
        self,
        store: CohortRecoveryStore,
        cohort: str,
        policy: CompetitionPolicy,
        genesis_signatures: tuple[Signature, ...],
        provider: RecoveryFinality,
        observe: ProgressObserver,
        certify: DecisionCertifier,
        publish: HistoryPublisher,
    ) -> None:
        self.store, self.cohort, self.provider = store, cohort, provider
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.genesis_signatures = genesis_signatures
        self.observe, self.certify, self.publish = observe, certify, publish
        self.serial = asyncio.Lock()
        self._history()

    def _history(self) -> tuple[CohortRecoveryHistory, CohortRecoveryState, int, int]:
        history = self.store.export_history(self.cohort, genesis_signatures=self.genesis_signatures)
        state, restored, prior_unavailable = replay_cohort_decisions(
            history,
            self.policy,
            lambda key: self.store.source(self.cohort, key, CohortDecisionInput),
        )
        return history, state, restored, prior_unavailable

    async def tick(self) -> dict:
        async with self.serial:
            history, state, restored, prior_unavailable = self._history()
            # Complete a lost publication acknowledgement before creating more
            # work. This also republishes a terminal cohort after a restart.
            await self.publish(history)
            current, pending = self.store.status(self.cohort)
            if current != state:
                return self._report(current, "history_changed_retry")
            if state.phase in {"complete", "revoked"}:
                return self._report(state, state.phase)
            if pending is not None and pending.operation == "revoke":
                return self._report(state, "awaiting_revocation_certificate")
            if pending is None:
                capture = await self.provider.collect()
                observation = execution_boundary(capture)
                progress = await self.observe(state, capture)
                evidence = CohortDecisionInput(
                    schema="umi-cohort-decision-input/1", progress=progress, observation=observation
                )
                proposal, _ = _choice(
                    state,
                    history.authority.authority,
                    self.policy,
                    evidence,
                    restored,
                    prior_unavailable,
                )
                if proposal is None:
                    return self._report(state, "waiting_phase_progress")
                key = self.store.retain_source(self.cohort, evidence)
                pending = self.store.reserve(
                    self.cohort,
                    phase=proposal.phase,
                    operation=proposal.operation,
                    observed_at_block=proposal.observed_at_block,
                    evidence_sha256=key,
                    extension_blocks=proposal.extension_blocks,
                )
            current, retained = self.store.status(self.cohort)
            if current != state or pending != retained:
                return self._report(current, "history_changed_retry")
            if pending.operation == "revoke":
                return self._report(state, "awaiting_revocation_certificate")
            evidence = self.store.source(self.cohort, pending.evidence_sha256, CohortDecisionInput)
            expected, _ = _choice(
                state,
                history.authority.authority,
                self.policy,
                evidence,
                restored,
                prior_unavailable,
            )
            if pending != expected:
                raise ValueError("reserved cohort decision differs from its retained source")
            signed = await self.certify(pending, evidence)
            if signed.transition != pending:
                raise ValueError("certifier returned another cohort decision")
            self.store.commit(signed)
            history, state, _, _ = self._history()
            await self.publish(history)
            return self._report(state, "phase_decision_published")

    def _report(self, state: CohortRecoveryState, status: str) -> dict:
        return dict(
            status=status,
            cohort_sha256=self.cohort,
            phase=state.phase,
            sequence=state.sequence,
            tip_sha256=state.tip_sha256,
            chain_submission_authorized=False,
        )


async def poll_recovery_cohorts(
    coordinators: Sequence[CohortRecoveryCoordinator],
    stop: asyncio.Event,
    report: Callable[[dict], None],
    *,
    poll_seconds: float = 5,
) -> None:
    """Service task; the enclosing lifespan owns finality providers and process locks."""
    if not coordinators or not 0 < poll_seconds <= 60:
        raise ValueError("recovery polling needs cohorts and a bounded poll interval")

    async def run(coordinator: CohortRecoveryCoordinator) -> None:
        while not stop.is_set():
            try:
                result = await coordinator.tick()
            except (
                OSError,
                ValueError,
                RuntimeError,
                sqlite3.Error,
                asyncio.TimeoutError,
            ) as error:
                result = dict(
                    status="cohort_recovery_retry",
                    cohort_sha256=coordinator.cohort,
                    error_type=type(error).__name__,
                    chain_submission_authorized=False,
                )
            report(result)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)

    # Separate owned loops keep one provider's delay from stopping other
    # cohorts. Service cancellation joins every loop before its ports close.
    tasks = [asyncio.create_task(run(coordinator)) for coordinator in coordinators]
    stopper = asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait([*tasks, stopper], return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
    finally:
        for task in [*tasks, stopper]:
            task.cancel()
        await asyncio.gather(*tasks, stopper, return_exceptions=True)
