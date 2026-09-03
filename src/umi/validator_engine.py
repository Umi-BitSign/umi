"""Restart-safe orchestration over the durable validator control plane.

The engine deliberately has no wallet, chain client, HTTP client, call builder, or
submission method.  A stage adapter owns its external effect and returns only a
typed, idempotent state decision.  The engine validates that decision against the
exact recovered work item before the control plane commits it.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from types import MappingProxyType

from .validator_state import (
    STAGE_ORDER,
    StageAdapter,
    StageCompletion,
    StagePending,
    StageResult,
    StageWorkItem,
    TerminalDecision,
    TerminalOutcome,
    ValidatorControlPlane,
    WindowRecord,
    WindowStage,
)


class ValidatorEngineError(RuntimeError):
    """Base class for stable orchestration failures."""


class NoActiveWindowError(ValidatorEngineError):
    """Raised when a terminal run is requested without an active window."""


class MissingStageAdapterError(ValidatorEngineError):
    """Raised before mutation when the pending stage has no configured adapter."""

    def __init__(self, stage: WindowStage) -> None:
        super().__init__(f"no adapter is configured for stage {stage.value}")
        self.stage = stage


class AdapterExecutionError(ValidatorEngineError):
    """Raised when an adapter fails before returning a state decision."""

    def __init__(self, stage: WindowStage) -> None:
        super().__init__(f"adapter failed at stage {stage.value}")
        self.stage = stage


class AdapterResultError(ValidatorEngineError):
    """Raised when an adapter decision is not bound to the recovered work."""

    def __init__(self, stage: WindowStage, message: str) -> None:
        super().__init__(f"invalid result for stage {stage.value}: {message}")
        self.stage = stage


class StepLimitExceeded(ValidatorEngineError):
    """Raised when a bounded terminal run does not terminate."""


class EngineStepStatus(str, Enum):
    IDLE = "idle"
    WAITING = "waiting"
    ADVANCED = "advanced"
    TERMINAL = "terminal"


@dataclass(frozen=True, slots=True)
class EngineStep:
    status: EngineStepStatus
    work: StageWorkItem | None
    result: StageResult | None
    window: WindowRecord | None
    pending_reason_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, EngineStepStatus):
            raise TypeError("engine-step status must be an EngineStepStatus")
        if self.status is EngineStepStatus.IDLE:
            if any(
                value is not None
                for value in (
                    self.work,
                    self.result,
                    self.window,
                    self.pending_reason_code,
                )
            ):
                raise ValueError("an idle engine step cannot carry stage state")
            return
        if self.work is None or self.window is None:
            raise ValueError("a non-idle engine step requires work and a window")
        if self.status is EngineStepStatus.WAITING:
            if self.result is not None or self.pending_reason_code is None:
                raise ValueError("a waiting step requires only a pending reason")
            return
        if self.result is None or self.pending_reason_code is not None:
            raise ValueError("an advanced or terminal step requires only a stage result")

    @property
    def terminal(self) -> bool:
        return self.status is EngineStepStatus.TERMINAL


@dataclass(frozen=True, slots=True)
class EngineRun:
    window: WindowRecord
    steps: tuple[EngineStep, ...]

    def __post_init__(self) -> None:
        if self.window.is_active:
            raise ValueError("an engine terminal run must end with a terminal window")
        if not self.steps or not self.steps[-1].terminal:
            raise ValueError("an engine terminal run must end with a terminal step")


class ValidatorEngine:
    """Execute one recovered validator stage at a time.

    One in-process lock covers recovery, adapter execution, binding validation, and
    persistence.  Cross-process safety remains in :class:`ValidatorControlPlane`;
    adapters must make their own external effects idempotent under the operation ID
    they return, because no local database can atomically commit a remote effect.
    """

    def __init__(
        self,
        control_plane: ValidatorControlPlane,
        adapters: Mapping[WindowStage, StageAdapter],
    ) -> None:
        if not isinstance(control_plane, ValidatorControlPlane):
            raise TypeError("control_plane must be a ValidatorControlPlane")
        if not isinstance(adapters, Mapping):
            raise TypeError("adapters must be a stage-to-adapter mapping")
        configured: dict[WindowStage, StageAdapter] = {}
        for stage, adapter in adapters.items():
            if not isinstance(stage, WindowStage):
                raise TypeError("adapter keys must be WindowStage values")
            if not callable(getattr(adapter, "execute", None)):
                raise TypeError(f"adapter for {stage.value} must define execute(work)")
            configured[stage] = adapter
        self._control_plane = control_plane
        self._adapters = MappingProxyType(configured)
        self._lock = asyncio.Lock()

    @property
    def configured_stages(self) -> tuple[WindowStage, ...]:
        return tuple(stage for stage in STAGE_ORDER if stage in self._adapters)

    async def run_once(self) -> EngineStep:
        """Recover and execute at most one pending stage.

        An adapter exception or invalid result leaves the authoritative stage
        untouched.  Cancellation is propagated directly and likewise performs no
        state transition.
        """

        async with self._lock:
            return await self._run_once_locked()

    async def run_until_terminal(self, *, maximum_steps: int = 7) -> EngineRun:
        """Run one active window sequentially to a terminal state.

        The explicit step ceiling prevents a bad adapter configuration from
        becoming an unbounded retry loop.  A version 0.1 window requires at most
        seven adapter decisions from its first stage.
        """

        if (
            isinstance(maximum_steps, bool)
            or not isinstance(maximum_steps, int)
            or not 1 <= maximum_steps <= len(STAGE_ORDER)
        ):
            raise ValueError(f"maximum_steps must be between 1 and {len(STAGE_ORDER)}")
        async with self._lock:
            recovery = self._control_plane.recovery_state()
            if recovery.active_window is None:
                raise NoActiveWindowError("no active validator window")
            target_window_id = recovery.active_window.plan.window_id
            steps: list[EngineStep] = []
            for _ in range(maximum_steps):
                step = await self._run_once_locked(expected_window_id=target_window_id)
                if step.status is EngineStepStatus.IDLE:
                    raise ValidatorEngineError("active window disappeared before terminal state")
                if step.status is EngineStepStatus.WAITING:
                    if step.pending_reason_code is None:
                        raise RuntimeError("waiting engine step lost its reason code")
                    raise StagePending(step.pending_reason_code)
                steps.append(step)
                if step.terminal:
                    if step.window is None:
                        raise RuntimeError("terminal engine step lost its window record")
                    return EngineRun(window=step.window, steps=tuple(steps))
            raise StepLimitExceeded(
                f"window {target_window_id} did not terminate within {maximum_steps} steps"
            )

    async def _run_once_locked(
        self,
        *,
        expected_window_id: str | None = None,
    ) -> EngineStep:
        recovery = self._control_plane.recovery_state()
        work = recovery.pending_work
        if work is None:
            return EngineStep(
                status=EngineStepStatus.IDLE,
                work=None,
                result=None,
                window=None,
            )
        if expected_window_id is not None and work.window.plan.window_id != expected_window_id:
            raise ValidatorEngineError("a different active window appeared during the run")
        adapter = self._adapters.get(work.stage)
        if adapter is None:
            raise MissingStageAdapterError(work.stage)
        try:
            result = await adapter.execute(work)
        except asyncio.CancelledError:
            raise
        except StagePending as pending:
            return EngineStep(
                status=EngineStepStatus.WAITING,
                work=work,
                result=None,
                window=work.window,
                pending_reason_code=pending.reason_code,
            )
        except Exception as error:
            raise AdapterExecutionError(work.stage) from error
        self._validate_result(work, result)
        updated = self._control_plane.apply_result(result)
        return EngineStep(
            status=(
                EngineStepStatus.TERMINAL if not updated.is_active else EngineStepStatus.ADVANCED
            ),
            work=work,
            result=result,
            window=updated,
        )

    @staticmethod
    def _validate_result(work: StageWorkItem, result: object) -> None:
        window_id = work.window.plan.window_id
        if isinstance(result, StageCompletion):
            if result.window_id != window_id:
                raise AdapterResultError(work.stage, "completion binds a different window")
            if result.completed_stage is not work.stage:
                raise AdapterResultError(work.stage, "completion binds a different stage")
            if work.stage is WindowStage.COMMIT_AND_TERMINAL_STATE:
                raise AdapterResultError(work.stage, "terminal stage requires a terminal decision")
            return
        if isinstance(result, TerminalDecision):
            if result.window_id != window_id:
                raise AdapterResultError(work.stage, "terminal decision binds a different window")
            if result.stage is not work.stage:
                raise AdapterResultError(work.stage, "terminal decision binds a different stage")
            if (
                result.outcome
                in {
                    TerminalOutcome.CALIBRATION_NO_WEIGHT,
                    TerminalOutcome.APPLIED,
                    TerminalOutcome.FAILED,
                }
                and work.stage is not WindowStage.COMMIT_AND_TERMINAL_STATE
            ):
                raise AdapterResultError(
                    work.stage,
                    f"{result.outcome.value} is only valid at the terminal stage",
                )
            return
        raise AdapterResultError(
            work.stage,
            "adapter returned neither StageCompletion nor TerminalDecision",
        )


__all__ = [
    "AdapterExecutionError",
    "AdapterResultError",
    "EngineRun",
    "EngineStep",
    "EngineStepStatus",
    "MissingStageAdapterError",
    "NoActiveWindowError",
    "StepLimitExceeded",
    "ValidatorEngine",
    "ValidatorEngineError",
]
