from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

import pytest

from umi.validator_engine import (
    AdapterExecutionError,
    AdapterResultError,
    EngineStepStatus,
    MissingStageAdapterError,
    NoActiveWindowError,
    StepLimitExceeded,
    ValidatorEngine,
)
from umi.validator_state import (
    STAGE_ORDER,
    PauseScope,
    StageCompletion,
    StagePending,
    TerminalDecision,
    TerminalOutcome,
    ValidatorControlPlane,
    WindowPlan,
    WindowStage,
)


def _plan(index: int = 0) -> WindowPlan:
    return WindowPlan(
        window_id=f"{index + 1:02x}" * 32,
        window_index=index,
        scoring_policy_hash="ee" * 32,
        announcement_block=1_000 + index * 360,
        proposal_close_block=1_030 + index * 360,
        closing_block=1_045 + index * 360,
        selection_round=100 + index * 100,
        issue_close_round=110 + index * 100,
        response_close_round=120 + index * 100,
        reveal_round=130 + index * 100,
    )


def _control(tmp_path, *, index: int = 0) -> tuple[ValidatorControlPlane, WindowPlan]:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    plan = _plan(index)
    control.start_window(plan, operation_id=f"start-{index}")
    return control, plan


@dataclass
class CompletionAdapter:
    calls: list[WindowStage] = field(default_factory=list)
    delay: float = 0
    active: int = 0
    maximum_active: int = 0

    async def execute(self, work):
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        try:
            if self.delay:
                await asyncio.sleep(self.delay)
            self.calls.append(work.stage)
            return StageCompletion(
                operation_id=f"complete-{work.window.plan.window_id}-{work.stage.value}",
                window_id=work.window.plan.window_id,
                completed_stage=work.stage,
                evidence_sha256=f"{STAGE_ORDER.index(work.stage) + 1:02x}" * 32,
            )
        finally:
            self.active -= 1


@dataclass
class CalibrationTerminalAdapter:
    calls: list[WindowStage] = field(default_factory=list)
    submission_allowed: list[bool] = field(default_factory=list)

    async def execute(self, work):
        self.calls.append(work.stage)
        self.submission_allowed.append(work.weight_submission_allowed)
        return TerminalDecision(
            operation_id=f"terminal-{work.window.plan.window_id}",
            window_id=work.window.plan.window_id,
            stage=work.stage,
            outcome=TerminalOutcome.CALIBRATION_NO_WEIGHT,
            evidence_sha256="aa" * 32,
            audit_release_block=2_000,
        )


def _all_adapters(
    completion: CompletionAdapter | None = None,
    terminal: CalibrationTerminalAdapter | None = None,
):
    completion = completion or CompletionAdapter()
    terminal = terminal or CalibrationTerminalAdapter()
    return {
        **{stage: completion for stage in STAGE_ORDER[:-1]},
        WindowStage.COMMIT_AND_TERMINAL_STATE: terminal,
    }


@pytest.mark.asyncio
async def test_run_once_recovers_and_commits_exactly_one_stage(tmp_path) -> None:
    control, plan = _control(tmp_path)
    pool = CompletionAdapter()
    assignment = CompletionAdapter()
    engine = ValidatorEngine(
        control,
        {
            WindowStage.POOL_AND_SELECTION: pool,
            WindowStage.ASSIGNMENT: assignment,
        },
    )

    step = await engine.run_once()

    assert step.status is EngineStepStatus.ADVANCED
    assert step.work is not None and step.work.stage is WindowStage.POOL_AND_SELECTION
    assert step.window is not None and step.window.stage is WindowStage.ASSIGNMENT
    assert pool.calls == [WindowStage.POOL_AND_SELECTION]
    assert assignment.calls == []
    assert control.get_window(plan.window_id).stage is WindowStage.ASSIGNMENT


@pytest.mark.asyncio
async def test_run_until_terminal_is_sequential_and_bounded(tmp_path) -> None:
    control, _plan_value = _control(tmp_path)
    completion = CompletionAdapter(delay=0.001)
    terminal = CalibrationTerminalAdapter()
    engine = ValidatorEngine(control, _all_adapters(completion, terminal))

    run = await engine.run_until_terminal()

    assert run.window.terminal_outcome is TerminalOutcome.CALIBRATION_NO_WEIGHT
    assert len(run.steps) == len(STAGE_ORDER)
    assert [step.work.stage for step in run.steps if step.work is not None] == list(STAGE_ORDER)
    assert completion.calls == list(STAGE_ORDER[:-1])
    assert terminal.calls == [WindowStage.COMMIT_AND_TERMINAL_STATE]
    assert all(step.status is EngineStepStatus.ADVANCED for step in run.steps[:-1])
    assert run.steps[-1].status is EngineStepStatus.TERMINAL


@pytest.mark.asyncio
async def test_adapter_exception_leaves_stage_unchanged_for_restart_retry(tmp_path) -> None:
    path = tmp_path / "validator.sqlite3"
    control, plan = _control(tmp_path)

    class FailingAdapter:
        async def execute(self, _work):
            raise ConnectionError("remote stage failed")

    with pytest.raises(AdapterExecutionError) as failure:
        await ValidatorEngine(
            control,
            {WindowStage.POOL_AND_SELECTION: FailingAdapter()},
        ).run_once()
    assert isinstance(failure.value.__cause__, ConnectionError)
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION
    assert [item.operation_type for item in control.list_operations()] == ["start_window"]

    reopened = ValidatorControlPlane(path)
    replacement = CompletionAdapter()
    step = await ValidatorEngine(
        reopened,
        {WindowStage.POOL_AND_SELECTION: replacement},
    ).run_once()
    assert step.window is not None and step.window.stage is WindowStage.ASSIGNMENT
    assert replacement.calls == [WindowStage.POOL_AND_SELECTION]


@pytest.mark.asyncio
async def test_expected_stage_pending_is_waiting_without_mutation(tmp_path) -> None:
    control, plan = _control(tmp_path)

    class PendingAdapter:
        async def execute(self, _work):
            raise StagePending("assignment_anchor_pending")

    engine = ValidatorEngine(
        control,
        {WindowStage.POOL_AND_SELECTION: PendingAdapter()},
    )
    step = await engine.run_once()

    assert step.status is EngineStepStatus.WAITING
    assert step.pending_reason_code == "assignment_anchor_pending"
    assert step.result is None
    assert step.work is not None and step.work.stage is WindowStage.POOL_AND_SELECTION
    assert step.window == step.work.window
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION
    assert [item.operation_type for item in control.list_operations()] == ["start_window"]

    with pytest.raises(StagePending, match="assignment_anchor_pending"):
        await engine.run_until_terminal()


@pytest.mark.asyncio
async def test_committed_transition_survives_unknown_engine_return_outcome(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "validator.sqlite3"
    control, plan = _control(tmp_path)
    real_apply = control.apply_result

    def apply_then_lose_response(result):
        real_apply(result)
        raise OSError("process lost the local acknowledgement")

    monkeypatch.setattr(control, "apply_result", apply_then_lose_response)
    with pytest.raises(OSError, match="acknowledgement"):
        await ValidatorEngine(
            control,
            {WindowStage.POOL_AND_SELECTION: CompletionAdapter()},
        ).run_once()

    reopened = ValidatorControlPlane(path)
    assert reopened.get_window(plan.window_id).stage is WindowStage.ASSIGNMENT
    assignment = CompletionAdapter()
    step = await ValidatorEngine(
        reopened,
        {WindowStage.ASSIGNMENT: assignment},
    ).run_once()
    assert step.window is not None and step.window.stage is WindowStage.REQUEST_TRANSCRIPT
    assert assignment.calls == [WindowStage.ASSIGNMENT]


@pytest.mark.asyncio
async def test_missing_adapter_fails_before_state_mutation(tmp_path) -> None:
    control, plan = _control(tmp_path)
    engine = ValidatorEngine(control, {})

    with pytest.raises(MissingStageAdapterError) as failure:
        await engine.run_once()

    assert failure.value.stage is WindowStage.POOL_AND_SELECTION
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_result", ["wrong_window", "wrong_stage", "wrong_type"])
async def test_wrong_completion_binding_never_mutates_the_pending_stage(
    tmp_path,
    bad_result: str,
) -> None:
    control, plan = _control(tmp_path)

    class WrongAdapter:
        async def execute(self, work):
            if bad_result == "wrong_type":
                return {"not": "a stage result"}
            return StageCompletion(
                operation_id=f"bad-{bad_result}",
                window_id=(
                    "ff" * 32 if bad_result == "wrong_window" else work.window.plan.window_id
                ),
                completed_stage=(
                    WindowStage.ASSIGNMENT
                    if bad_result == "wrong_stage"
                    else WindowStage.POOL_AND_SELECTION
                ),
                evidence_sha256="11" * 32,
            )

    with pytest.raises(AdapterResultError):
        await ValidatorEngine(
            control,
            {WindowStage.POOL_AND_SELECTION: WrongAdapter()},
        ).run_once()
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION
    assert [item.operation_type for item in control.list_operations()] == ["start_window"]


@pytest.mark.asyncio
async def test_terminal_decision_must_bind_the_exact_recovered_stage(tmp_path) -> None:
    control, plan = _control(tmp_path)

    class WrongTerminalAdapter:
        async def execute(self, work):
            return TerminalDecision(
                operation_id="wrong-terminal-stage",
                window_id=work.window.plan.window_id,
                stage=WindowStage.ASSIGNMENT,
                outcome=TerminalOutcome.VOID,
                reason_code="canary_hit",
            )

    with pytest.raises(AdapterResultError, match="different stage"):
        await ValidatorEngine(
            control,
            {WindowStage.POOL_AND_SELECTION: WrongTerminalAdapter()},
        ).run_once()
    assert control.get_window(plan.window_id).is_active


@pytest.mark.asyncio
async def test_terminal_stage_rejects_a_nonterminal_completion(tmp_path) -> None:
    control, plan = _control(tmp_path)
    for index, stage in enumerate(STAGE_ORDER[:-1]):
        control.advance_window(
            plan.window_id,
            completed_stage=stage,
            evidence_sha256=f"{index + 1:02x}" * 32,
            operation_id=f"manual-{stage.value}",
        )

    with pytest.raises(AdapterResultError, match="requires a terminal decision"):
        await ValidatorEngine(
            control,
            {WindowStage.COMMIT_AND_TERMINAL_STATE: CompletionAdapter()},
        ).run_once()
    assert control.get_window(plan.window_id).stage is WindowStage.COMMIT_AND_TERMINAL_STATE
    assert control.get_window(plan.window_id).is_active


@pytest.mark.asyncio
async def test_weight_submission_pause_is_propagated_to_terminal_adapter(tmp_path) -> None:
    control, plan = _control(tmp_path)
    for index, stage in enumerate(STAGE_ORDER[:-1]):
        control.advance_window(
            plan.window_id,
            completed_stage=stage,
            evidence_sha256=f"{index + 1:02x}" * 32,
            operation_id=f"manual-{stage.value}",
        )
    control.pause(
        PauseScope.WEIGHT_SUBMISSION,
        reason_code="runtime_upgrade_incompatible",
        operation_id="runtime-pause",
    )
    terminal = CalibrationTerminalAdapter()

    step = await ValidatorEngine(
        control,
        {WindowStage.COMMIT_AND_TERMINAL_STATE: terminal},
    ).run_once()

    assert terminal.submission_allowed == [False]
    assert step.status is EngineStepStatus.TERMINAL
    assert step.window is not None
    assert step.window.terminal_outcome is TerminalOutcome.CALIBRATION_NO_WEIGHT
    assert control.control_state(PauseScope.WEIGHT_SUBMISSION).paused


@pytest.mark.asyncio
async def test_concurrent_run_once_calls_never_execute_adapters_in_parallel(tmp_path) -> None:
    control, _plan_value = _control(tmp_path)
    adapter = CompletionAdapter(delay=0.01)
    engine = ValidatorEngine(
        control,
        {
            WindowStage.POOL_AND_SELECTION: adapter,
            WindowStage.ASSIGNMENT: adapter,
        },
    )

    first, second = await asyncio.gather(engine.run_once(), engine.run_once())

    assert adapter.maximum_active == 1
    assert [first.work.stage, second.work.stage] == [
        WindowStage.POOL_AND_SELECTION,
        WindowStage.ASSIGNMENT,
    ]
    assert control.active_window().stage is WindowStage.REQUEST_TRANSCRIPT  # type: ignore[union-attr]


@pytest.mark.asyncio
async def test_idle_and_step_limit_outcomes_are_explicit(tmp_path) -> None:
    empty = ValidatorControlPlane(tmp_path / "empty.sqlite3")
    idle = await ValidatorEngine(empty, {}).run_once()
    assert idle.status is EngineStepStatus.IDLE
    with pytest.raises(NoActiveWindowError):
        await ValidatorEngine(empty, {}).run_until_terminal()

    control = ValidatorControlPlane(tmp_path / "active.sqlite3")
    control.start_window(_plan(), operation_id="start")
    engine = ValidatorEngine(control, _all_adapters())
    with pytest.raises(StepLimitExceeded):
        await engine.run_until_terminal(maximum_steps=1)
    assert control.active_window().stage is WindowStage.ASSIGNMENT  # type: ignore[union-attr]
