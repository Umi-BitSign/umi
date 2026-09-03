"""Responsive, restart-safe scheduling shell for the validator engine.

The service owns no chain, wallet, network, finality, or plan-construction logic.
Its source boundary may yield only a plan that was independently finalized and
verified.  Each tick either remains idle or advances exactly one engine stage, so
an external supervisor always regains control between protocol stages.
"""

from __future__ import annotations

import asyncio
import math
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable

from .validator_engine import EngineStep, EngineStepStatus, ValidatorEngine
from .validator_state import (
    MAX_OPERATION_ID_BYTES,
    PauseScope,
    ValidatorControlPlane,
    WindowPlan,
    WindowRecord,
)

MIN_POLL_SECONDS = 0.01
MAX_POLL_SECONDS = 300.0
_START_OPERATION_PREFIX = "umi-window-start-v1"
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")


class ValidatorServiceError(RuntimeError):
    """Base class for stable scheduler failures."""


class WindowPlanSourceError(ValidatorServiceError):
    """The plan source returned a value outside its narrow protocol."""


class ScoringPolicyMismatchError(ValidatorServiceError):
    """A recovered or proposed window binds another scoring policy."""


class WindowPlanOrderError(ValidatorServiceError):
    """A proposed plan skips or reorders the persistent window sequence."""


class ServiceTickStatus(str, Enum):
    NO_PLAN = "no_plan"
    INTAKE_PAUSED = "intake_paused"
    STAGE_WAITING = "stage_waiting"
    STAGE_ADVANCED = "stage_advanced"
    WINDOW_TERMINAL = "window_terminal"


@dataclass(frozen=True, slots=True)
class ServiceTick:
    """Typed result of one responsive scheduling iteration."""

    status: ServiceTickStatus
    step: EngineStep | None = None
    started_window: WindowRecord | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.status, ServiceTickStatus):
            raise TypeError("tick status must be a ServiceTickStatus")
        stage_status = self.status in {
            ServiceTickStatus.STAGE_WAITING,
            ServiceTickStatus.STAGE_ADVANCED,
            ServiceTickStatus.WINDOW_TERMINAL,
        }
        if stage_status != (self.step is not None):
            raise ValueError("tick status and engine step disagree")
        if not stage_status and self.started_window is not None:
            raise ValueError("an idle tick cannot carry a started window")
        if self.step is not None:
            if self.step.status is EngineStepStatus.IDLE:
                raise ValueError("a service stage tick cannot carry an idle engine step")
            if (self.status is ServiceTickStatus.STAGE_WAITING) != (
                self.step.status is EngineStepStatus.WAITING
            ):
                raise ValueError("tick waiting status disagrees with its engine step")
            if (self.status is ServiceTickStatus.WINDOW_TERMINAL) != self.step.terminal:
                raise ValueError("tick terminal status disagrees with its engine step")
        if self.started_window is not None and not self.started_window.is_active:
            raise ValueError("a newly started window must be active")
        if self.started_window is not None:
            if self.step is None or self.step.work is None:
                raise ValueError("a started-window tick must identify its engine work")
            if self.started_window.plan.window_id != self.step.work.window.plan.window_id:
                raise ValueError("started window and engine work bind different windows")

    @property
    def started(self) -> bool:
        return self.started_window is not None


@runtime_checkable
class WindowPlanSource(Protocol):
    """Source of at most one independently finalized and verified next plan."""

    async def next_plan(self) -> WindowPlan | None:
        """Return the next verified plan, or ``None`` when none is ready."""


WaitFunction = Callable[[asyncio.Event, float], Awaitable[None]]


class ValidatorService:
    """Serialize plan intake and one-stage engine progress across restart-safe ticks."""

    def __init__(
        self,
        *,
        control_plane: ValidatorControlPlane,
        engine: ValidatorEngine,
        plan_source: WindowPlanSource,
        scoring_policy_hash: str,
        wait: WaitFunction | None = None,
    ) -> None:
        if not isinstance(control_plane, ValidatorControlPlane):
            raise TypeError("control_plane must be a ValidatorControlPlane")
        if not isinstance(engine, ValidatorEngine):
            raise TypeError("engine must be a ValidatorEngine")
        if not callable(getattr(plan_source, "next_plan", None)):
            raise TypeError("plan_source must define next_plan()")
        if (
            not isinstance(scoring_policy_hash, str)
            or _HEX32_RE.fullmatch(scoring_policy_hash) is None
        ):
            raise ValueError("scoring policy hash must be 32 lowercase hexadecimal bytes")
        if wait is not None and not callable(wait):
            raise TypeError("wait must be an async callable")
        self._control_plane = control_plane
        self._engine = engine
        self._plan_source = plan_source
        self.scoring_policy_hash = scoring_policy_hash
        self._wait: WaitFunction = wait or _wait_for_stop
        self._tick_lock = asyncio.Lock()

    async def tick(self) -> ServiceTick:
        """Recover first, then advance at most one engine stage.

        An active window is always serviced and returned before the source can be
        queried.  With no active window, an intake pause likewise returns without
        touching the source.  Adapter, control-plane, and source exceptions are
        intentionally allowed to propagate to supervision.
        """

        async with self._tick_lock:
            recovery = self._control_plane.recovery_state()
            if recovery.active_window is not None:
                self._require_policy(recovery.active_window.plan)
                return await self._stage_tick(started_window=None)

            intake = next(
                state for state in recovery.controls if state.scope is PauseScope.WINDOW_INTAKE
            )
            if intake.paused:
                return ServiceTick(status=ServiceTickStatus.INTAKE_PAUSED)

            plan = await self._plan_source.next_plan()
            if plan is None:
                return ServiceTick(status=ServiceTickStatus.NO_PLAN)
            if not isinstance(plan, WindowPlan):
                raise WindowPlanSourceError("plan source returned neither WindowPlan nor None")
            self._require_policy(plan)
            self._require_next_index(plan)
            started = self._control_plane.start_window(
                plan,
                operation_id=start_window_operation_id(plan),
                metadata={"source": "verified_window_plan"},
            )
            return await self._stage_tick(started_window=started)

    async def run(
        self,
        stop_event: asyncio.Event,
        *,
        poll_seconds: float = 1.0,
    ) -> None:
        """Tick until stopped, waiting on a monotonic event-loop deadline.

        The default wait is interruptible by ``stop_event`` and uses asyncio's
        monotonic loop clock.  Task cancellation and all tick failures propagate;
        the loop performs no retry classification of its own.
        """

        if not isinstance(stop_event, asyncio.Event):
            raise TypeError("stop_event must be an asyncio.Event")
        delay = _poll_seconds(poll_seconds)
        while not stop_event.is_set():
            await self.tick()
            if stop_event.is_set():
                break
            await self._wait(stop_event, delay)

    async def _stage_tick(self, *, started_window: WindowRecord | None) -> ServiceTick:
        step = await self._engine.run_once()
        if step.status is EngineStepStatus.IDLE:
            raise ValidatorServiceError("active window disappeared before its engine stage")
        return ServiceTick(
            status={
                EngineStepStatus.WAITING: ServiceTickStatus.STAGE_WAITING,
                EngineStepStatus.ADVANCED: ServiceTickStatus.STAGE_ADVANCED,
                EngineStepStatus.TERMINAL: ServiceTickStatus.WINDOW_TERMINAL,
            }[step.status],
            step=step,
            started_window=started_window,
        )

    def _require_policy(self, plan: WindowPlan) -> None:
        if plan.scoring_policy_hash != self.scoring_policy_hash:
            raise ScoringPolicyMismatchError(
                "window scoring-policy hash differs from the configured hash"
            )

    def _require_next_index(self, plan: WindowPlan) -> None:
        windows = self._control_plane.list_windows()
        expected = windows[-1].plan.window_index + 1 if windows else 0
        if plan.window_index != expected:
            raise WindowPlanOrderError(
                f"next window index must be {expected}, got {plan.window_index}"
            )


def start_window_operation_id(plan: WindowPlan) -> str:
    """Return the deterministic idempotency key for one durable window start."""

    if not isinstance(plan, WindowPlan):
        raise TypeError("plan must be a WindowPlan")
    value = f"{_START_OPERATION_PREFIX}/{plan.window_id}"
    if len(value.encode()) > MAX_OPERATION_ID_BYTES:
        raise ValueError("window-start operation ID exceeds its byte ceiling")
    return value


def _poll_seconds(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise TypeError("poll_seconds must be a finite number")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError("poll_seconds must be finite")
    if not MIN_POLL_SECONDS <= result <= MAX_POLL_SECONDS:
        raise ValueError(f"poll_seconds must be between {MIN_POLL_SECONDS} and {MAX_POLL_SECONDS}")
    return result


async def _wait_for_stop(stop_event: asyncio.Event, delay: float) -> None:
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=delay)
    except asyncio.TimeoutError:
        return


__all__ = [
    "MAX_POLL_SECONDS",
    "MIN_POLL_SECONDS",
    "ScoringPolicyMismatchError",
    "ServiceTick",
    "ServiceTickStatus",
    "ValidatorService",
    "ValidatorServiceError",
    "WaitFunction",
    "WindowPlanOrderError",
    "WindowPlanSource",
    "WindowPlanSourceError",
    "start_window_operation_id",
]
