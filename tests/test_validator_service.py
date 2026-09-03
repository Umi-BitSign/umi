from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from pathlib import Path

import pytest

from umi.validator_engine import AdapterExecutionError, ValidatorEngine
from umi.validator_service import (
    MAX_POLL_SECONDS,
    MIN_POLL_SECONDS,
    ScoringPolicyMismatchError,
    ServiceTickStatus,
    ValidatorService,
    WindowPlanOrderError,
    WindowPlanSourceError,
    start_window_operation_id,
)
from umi.validator_state import (
    PauseScope,
    StageCompletion,
    StagePending,
    ValidatorControlPlane,
    WindowPlan,
    WindowStage,
)

POLICY_HASH = "ee" * 32


def _plan(index: int = 0, *, policy_hash: str = POLICY_HASH) -> WindowPlan:
    return WindowPlan(
        window_id=f"{index + 1:02x}" * 32,
        window_index=index,
        scoring_policy_hash=policy_hash,
        announcement_block=1_000 + index * 360,
        proposal_close_block=1_030 + index * 360,
        closing_block=1_045 + index * 360,
        selection_round=100 + index * 100,
        issue_close_round=110 + index * 100,
        response_close_round=120 + index * 100,
        reveal_round=130 + index * 100,
    )


@dataclass
class PlanSource:
    values: list[object]
    calls: int = 0

    async def next_plan(self):
        self.calls += 1
        return self.values.pop(0) if self.values else None


@dataclass
class CompletionAdapter:
    calls: list[WindowStage] = field(default_factory=list)
    entered: asyncio.Event | None = None
    release: asyncio.Event | None = None
    active: int = 0
    maximum_active: int = 0

    async def execute(self, work):
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        try:
            self.calls.append(work.stage)
            if self.entered is not None and len(self.calls) == 1:
                self.entered.set()
                if self.release is None:
                    raise RuntimeError("blocking adapter has no release event")
                await self.release.wait()
            return StageCompletion(
                operation_id=(f"service-stage/{work.window.plan.window_id}/{work.stage.value}"),
                window_id=work.window.plan.window_id,
                completed_stage=work.stage,
                evidence_sha256=f"{list(WindowStage).index(work.stage) + 1:02x}" * 32,
                metadata={"source": "service-test"},
            )
        finally:
            self.active -= 1


def _service(
    control: ValidatorControlPlane,
    source: object,
    adapters: dict[WindowStage, object],
    *,
    wait=None,
) -> ValidatorService:
    return ValidatorService(
        control_plane=control,
        engine=ValidatorEngine(control, adapters),
        plan_source=source,  # type: ignore[arg-type]
        scoring_policy_hash=POLICY_HASH,
        wait=wait,
    )


@pytest.mark.asyncio
async def test_tick_starts_verified_plan_and_advances_exactly_one_stage(tmp_path: Path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = PlanSource([_plan()])
    pool = CompletionAdapter()
    assignment = CompletionAdapter()
    service = _service(
        control,
        source,
        {
            WindowStage.POOL_AND_SELECTION: pool,
            WindowStage.ASSIGNMENT: assignment,
        },
    )

    first = await service.tick()

    assert first.status is ServiceTickStatus.STAGE_ADVANCED
    assert first.started
    assert first.started_window is not None
    assert first.started_window.stage is WindowStage.POOL_AND_SELECTION
    assert first.step is not None and first.step.work is not None
    assert first.step.work.stage is WindowStage.POOL_AND_SELECTION
    assert control.active_window() is not None
    assert control.active_window().stage is WindowStage.ASSIGNMENT  # type: ignore[union-attr]
    assert source.calls == 1
    assert pool.calls == [WindowStage.POOL_AND_SELECTION]
    assert assignment.calls == []
    assert control.list_operations()[0].operation_id == start_window_operation_id(_plan())

    second = await service.tick()

    assert second.status is ServiceTickStatus.STAGE_ADVANCED
    assert not second.started
    assert second.step is not None and second.step.work is not None
    assert second.step.work.stage is WindowStage.ASSIGNMENT
    assert source.calls == 1
    assert assignment.calls == [WindowStage.ASSIGNMENT]


@pytest.mark.asyncio
async def test_restart_recovers_committed_start_before_source_is_touched(
    tmp_path: Path,
) -> None:
    path = tmp_path / "validator.sqlite3"
    plan = _plan()
    control = ValidatorControlPlane(path)
    source = PlanSource([plan])
    adapter = CompletionAdapter()
    service = _service(
        control,
        source,
        {WindowStage.POOL_AND_SELECTION: adapter},
    )
    real_start = control.start_window

    def commit_then_lose_acknowledgement(plan_value, *, operation_id, metadata=None):
        real_start(
            plan_value,
            operation_id=operation_id,
            metadata=metadata,
        )
        raise OSError("lost start acknowledgement")

    control.start_window = commit_then_lose_acknowledgement  # type: ignore[method-assign]
    with pytest.raises(OSError, match="acknowledgement"):
        await service.tick()

    assert source.calls == 1
    assert adapter.calls == []
    reopened = ValidatorControlPlane(path)
    assert reopened.active_window() is not None
    assert reopened.list_operations()[0].operation_id == start_window_operation_id(plan)

    class SourceMustNotRun:
        calls = 0

        async def next_plan(self):
            self.calls += 1
            raise AssertionError("source advanced while a recovered window was active")

    replacement_source = SourceMustNotRun()
    replacement_adapter = CompletionAdapter()
    recovered = await _service(
        reopened,
        replacement_source,
        {WindowStage.POOL_AND_SELECTION: replacement_adapter},
    ).tick()

    assert recovered.status is ServiceTickStatus.STAGE_ADVANCED
    assert not recovered.started
    assert replacement_source.calls == 0
    assert replacement_adapter.calls == [WindowStage.POOL_AND_SELECTION]
    repeated_start = reopened.start_window(
        plan,
        operation_id=start_window_operation_id(plan),
        metadata={"source": "verified_window_plan"},
    )
    assert repeated_start.plan == plan
    assert repeated_start.stage is WindowStage.POOL_AND_SELECTION


@pytest.mark.asyncio
async def test_active_window_is_run_before_source_even_when_intake_is_paused(
    tmp_path: Path,
) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    plan = _plan()
    control.start_window(plan, operation_id="manual-start")
    control.pause(
        PauseScope.WINDOW_INTAKE,
        reason_code="operator_pause",
        operation_id="pause-intake",
    )
    source = PlanSource([_plan(1)])
    adapter = CompletionAdapter()

    tick = await _service(
        control,
        source,
        {WindowStage.POOL_AND_SELECTION: adapter},
    ).tick()

    assert tick.status is ServiceTickStatus.STAGE_ADVANCED
    assert source.calls == 0
    assert adapter.calls == [WindowStage.POOL_AND_SELECTION]


@pytest.mark.asyncio
async def test_pending_stage_is_a_pollable_service_wait_not_a_failure(tmp_path: Path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    plan = _plan()
    source = PlanSource([plan, _plan(1)])
    calls = 0

    class PendingAdapter:
        async def execute(self, _work):
            nonlocal calls
            calls += 1
            raise StagePending("response_close_pending")

    service = _service(
        control,
        source,
        {WindowStage.POOL_AND_SELECTION: PendingAdapter()},
    )
    first = await service.tick()
    second = await service.tick()

    assert first.status is ServiceTickStatus.STAGE_WAITING
    assert first.started
    assert first.step is not None
    assert first.step.pending_reason_code == "response_close_pending"
    assert second.status is ServiceTickStatus.STAGE_WAITING
    assert not second.started
    assert source.calls == 1
    assert calls == 2
    assert control.active_window() is not None
    assert control.active_window().stage is WindowStage.POOL_AND_SELECTION  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_paused_intake_does_not_call_source_without_an_active_window(
    tmp_path: Path,
) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    control.pause(
        PauseScope.WINDOW_INTAKE,
        reason_code="operator_pause",
        operation_id="pause-intake",
    )
    source = PlanSource([_plan()])

    tick = await _service(control, source, {}).tick()

    assert tick.status is ServiceTickStatus.INTAKE_PAUSED
    assert tick.step is None
    assert source.calls == 0
    assert control.list_windows() == ()


@pytest.mark.asyncio
async def test_concurrent_ticks_are_serial_and_source_advances_only_once(
    tmp_path: Path,
) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = PlanSource([_plan(), _plan(1)])
    entered = asyncio.Event()
    release = asyncio.Event()
    adapter = CompletionAdapter(entered=entered, release=release)
    service = _service(
        control,
        source,
        {
            WindowStage.POOL_AND_SELECTION: adapter,
            WindowStage.ASSIGNMENT: adapter,
        },
    )

    first_task = asyncio.create_task(service.tick())
    await entered.wait()
    second_task = asyncio.create_task(service.tick())
    await asyncio.sleep(0)
    assert source.calls == 1
    assert not second_task.done()
    release.set()
    first, second = await asyncio.gather(first_task, second_task)

    assert first.started
    assert first.step is not None and first.step.work is not None
    assert first.step.work.stage is WindowStage.POOL_AND_SELECTION
    assert not second.started
    assert second.step is not None and second.step.work is not None
    assert second.step.work.stage is WindowStage.ASSIGNMENT
    assert source.calls == 1
    assert adapter.maximum_active == 1
    assert control.active_window() is not None
    assert control.active_window().stage is WindowStage.REQUEST_TRANSCRIPT  # type: ignore[union-attr]


@pytest.mark.asyncio
@pytest.mark.parametrize("case", ["policy", "first_index", "wrong_type"])
async def test_bad_source_plan_is_rejected_without_starting_a_window(
    tmp_path: Path,
    case: str,
) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    value: object
    expected: type[Exception]
    if case == "policy":
        value = _plan(policy_hash="ff" * 32)
        expected = ScoringPolicyMismatchError
    elif case == "first_index":
        value = _plan(1)
        expected = WindowPlanOrderError
    else:
        value = {"not": "a WindowPlan"}
        expected = WindowPlanSourceError
    source = PlanSource([value])

    with pytest.raises(expected):
        await _service(control, source, {}).tick()

    assert source.calls == 1
    assert control.list_windows() == ()


@pytest.mark.asyncio
async def test_recovered_policy_mismatch_fails_before_engine_or_source(tmp_path: Path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    control.start_window(
        _plan(policy_hash="ff" * 32),
        operation_id="wrong-policy-start",
    )
    source = PlanSource([None])
    adapter = CompletionAdapter()

    with pytest.raises(ScoringPolicyMismatchError):
        await _service(
            control,
            source,
            {WindowStage.POOL_AND_SELECTION: adapter},
        ).tick()

    assert source.calls == 0
    assert adapter.calls == []


@pytest.mark.asyncio
async def test_adapter_and_source_failures_are_not_swallowed(tmp_path: Path) -> None:
    active_control = ValidatorControlPlane(tmp_path / "active.sqlite3")
    active_control.start_window(_plan(), operation_id="start")

    class FailingAdapter:
        async def execute(self, _work):
            raise ConnectionError("stage unavailable")

    source = PlanSource([None])
    with pytest.raises(AdapterExecutionError) as adapter_failure:
        await _service(
            active_control,
            source,
            {WindowStage.POOL_AND_SELECTION: FailingAdapter()},
        ).tick()
    assert isinstance(adapter_failure.value.__cause__, ConnectionError)
    assert source.calls == 0

    class FailingSource:
        async def next_plan(self):
            raise OSError("finality backend unavailable")

    empty_control = ValidatorControlPlane(tmp_path / "empty.sqlite3")
    with pytest.raises(OSError, match="finality backend"):
        await _service(empty_control, FailingSource(), {}).tick()


@pytest.mark.asyncio
async def test_run_uses_injected_wait_and_stops_gracefully(tmp_path: Path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = PlanSource([None])
    waits: list[float] = []

    async def stop_after_one_wait(stop_event: asyncio.Event, delay: float) -> None:
        waits.append(delay)
        stop_event.set()

    service = _service(control, source, {}, wait=stop_after_one_wait)
    stop = asyncio.Event()
    await service.run(stop, poll_seconds=0.25)

    assert source.calls == 1
    assert waits == [0.25]
    assert stop.is_set()


@pytest.mark.asyncio
async def test_default_wait_is_interrupted_promptly_by_stop_event(tmp_path: Path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = PlanSource([None])
    service = _service(control, source, {})
    stop = asyncio.Event()

    task = asyncio.create_task(service.run(stop, poll_seconds=MAX_POLL_SECONDS))
    while source.calls == 0:
        await asyncio.sleep(0)
    stop.set()
    await asyncio.wait_for(task, timeout=1)

    assert task.result() is None


@pytest.mark.asyncio
async def test_run_task_cancellation_is_propagated(tmp_path: Path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = PlanSource([None])
    waiting = asyncio.Event()

    async def wait_forever(_stop_event: asyncio.Event, _delay: float) -> None:
        waiting.set()
        await asyncio.Event().wait()

    service = _service(control, source, {}, wait=wait_forever)
    task = asyncio.create_task(service.run(asyncio.Event(), poll_seconds=1))
    await waiting.wait()
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "value, error",
    [
        (True, TypeError),
        ("1", TypeError),
        (float("nan"), ValueError),
        (float("inf"), ValueError),
        (MIN_POLL_SECONDS / 2, ValueError),
        (MAX_POLL_SECONDS + 1, ValueError),
    ],
)
async def test_poll_interval_is_finite_and_bounded(
    tmp_path: Path,
    value: object,
    error: type[Exception],
) -> None:
    service = _service(
        ValidatorControlPlane(tmp_path / "validator.sqlite3"),
        PlanSource([None]),
        {},
    )
    stop = asyncio.Event()
    stop.set()

    with pytest.raises(error):
        await service.run(stop, poll_seconds=value)  # type: ignore[arg-type]
