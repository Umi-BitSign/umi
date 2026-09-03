from __future__ import annotations

import sqlite3

import pytest

from umi.validator_state import (
    MAX_METADATA_BYTES,
    STAGE_ORDER,
    IdempotencyConflict,
    IncidentSpec,
    IncidentStatus,
    PauseScope,
    PersistenceError,
    StageAdapter,
    StageCompletion,
    TerminalOutcome,
    TransitionError,
    ValidatorControlPlane,
    WindowPlan,
    WindowStage,
)


class _Clock:
    def __init__(self) -> None:
        self.value = 1_000_000

    def __call__(self) -> int:
        self.value += 1
        return self.value


def _plan(
    index: int,
    *,
    round_start: int | None = None,
    announcement_block: int | None = None,
) -> WindowPlan:
    round_start = 100 + index * 100 if round_start is None else round_start
    announcement_block = 1_000 + index * 360 if announcement_block is None else announcement_block
    return WindowPlan(
        window_id=f"{index + 1:02x}" * 32,
        window_index=index,
        scoring_policy_hash="ee" * 32,
        announcement_block=announcement_block,
        proposal_close_block=announcement_block + 30,
        closing_block=announcement_block + 45,
        selection_round=round_start,
        issue_close_round=round_start + 10,
        response_close_round=round_start + 20,
        reveal_round=round_start + 30,
    )


def _advance_to_terminal_stage(
    control: ValidatorControlPlane,
    window_id: str,
) -> None:
    for index, stage in enumerate(STAGE_ORDER[:-1], start=1):
        record = control.advance_window(
            window_id,
            completed_stage=stage,
            evidence_sha256=f"{index:02x}" * 32,
            operation_id=f"advance-{index}",
        )
        assert record.stage is STAGE_ORDER[index]


def test_canonical_stage_graph_reaches_a_durable_calibration_terminal(tmp_path) -> None:
    path = tmp_path / "validator.sqlite3"
    clock = _Clock()
    control = ValidatorControlPlane(path, clock_ns=clock)
    plan = _plan(0)

    started = control.start_window(plan, operation_id="start-0")
    assert started.stage is WindowStage.POOL_AND_SELECTION
    assert started.is_active

    _advance_to_terminal_stage(control, plan.window_id)
    work = control.pending_work()
    assert work is not None
    assert work.stage is WindowStage.COMMIT_AND_TERMINAL_STATE
    assert tuple(item.stage for item in work.completed_evidence) == STAGE_ORDER[:-1]
    assert work.weight_submission_allowed

    terminal = control.terminate_window(
        plan.window_id,
        outcome=TerminalOutcome.CALIBRATION_NO_WEIGHT,
        evidence_sha256="aa" * 32,
        audit_release_block=2_000,
        operation_id="terminal-0",
    )
    assert terminal.terminal_outcome is TerminalOutcome.CALIBRATION_NO_WEIGHT
    assert not terminal.is_active
    assert control.active_window() is None

    reopened = ValidatorControlPlane(path, clock_ns=clock)
    recovery = reopened.recovery_state()
    assert recovery.active_window is None
    assert recovery.pending_work is None
    assert reopened.get_window(plan.window_id) == terminal
    assert (
        reopened.terminate_window(
            plan.window_id,
            outcome=TerminalOutcome.CALIBRATION_NO_WEIGHT,
            evidence_sha256="aa" * 32,
            audit_release_block=2_000,
            operation_id="terminal-0",
        )
        == terminal
    )
    operations = reopened.list_operations()
    assert [item.operation_type for item in operations] == [
        "start_window",
        *("advance_window" for _ in STAGE_ORDER[:-1]),
        "terminate_window",
    ]


def test_stage_completion_is_typed_idempotent_and_rejects_illegal_edges(tmp_path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3", clock_ns=_Clock())
    plan = _plan(0)
    first = control.start_window(plan, operation_id="start")
    assert control.start_window(plan, operation_id="start") == first

    with pytest.raises(IdempotencyConflict):
        control.start_window(_plan(1), operation_id="start")
    with pytest.raises(TransitionError, match="not assignment"):
        control.advance_window(
            plan.window_id,
            completed_stage=WindowStage.ASSIGNMENT,
            evidence_sha256="11" * 32,
            operation_id="wrong-edge",
        )

    completion = StageCompletion(
        operation_id="pool-complete",
        window_id=plan.window_id,
        completed_stage=WindowStage.POOL_AND_SELECTION,
        evidence_sha256="22" * 32,
    )
    advanced = control.apply_completion(completion)
    assert advanced.stage is WindowStage.ASSIGNMENT
    assert control.apply_completion(completion) == advanced

    with pytest.raises(IdempotencyConflict):
        control.advance_window(
            plan.window_id,
            completed_stage=WindowStage.ASSIGNMENT,
            evidence_sha256="33" * 32,
            operation_id="pool-complete",
        )
    with pytest.raises(TransitionError, match="commit-and-terminal-state"):
        control.terminate_window(
            plan.window_id,
            outcome=TerminalOutcome.APPLIED,
            evidence_sha256="44" * 32,
            audit_release_block=2_000,
            operation_id="early-applied",
        )


@pytest.mark.asyncio
async def test_adapter_boundary_returns_a_completion_without_owning_effects(tmp_path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3", clock_ns=_Clock())
    plan = _plan(0)
    control.start_window(plan, operation_id="start")

    class Adapter:
        async def execute(self, work):
            return StageCompletion(
                operation_id="adapter-pool",
                window_id=work.window.plan.window_id,
                completed_stage=work.stage,
                evidence_sha256="55" * 32,
            )

    adapter = Adapter()
    assert isinstance(adapter, StageAdapter)
    work = control.pending_work()
    assert work is not None
    control.apply_result(await adapter.execute(work))
    assert control.active_window().stage is WindowStage.ASSIGNMENT  # type: ignore[union-attr]


def test_one_active_window_consecutive_indices_and_nonoverlapping_rounds(tmp_path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3", clock_ns=_Clock())
    first = _plan(10)
    control.start_window(first, operation_id="start-10")

    with pytest.raises(TransitionError, match="already active"):
        control.start_window(_plan(11), operation_id="active-overlap")
    control.terminate_window(
        first.window_id,
        outcome=TerminalOutcome.SKIPPED,
        reason_code="insufficient_publishers",
        operation_id="skip-10",
    )

    with pytest.raises(TransitionError, match="index must be 11"):
        control.start_window(_plan(12), operation_id="index-gap")
    with pytest.raises(TransitionError, match="round intervals overlap"):
        control.start_window(
            _plan(11, round_start=first.reveal_round),
            operation_id="round-overlap",
        )
    with pytest.raises(TransitionError, match="block intervals overlap"):
        control.start_window(
            _plan(11, announcement_block=first.closing_block),
            operation_id="block-overlap",
        )

    second = _plan(11)
    record = control.start_window(second, operation_id="start-11")
    assert record.plan.window_index == 11
    assert [item.plan.window_index for item in control.list_windows()] == [10, 11]


def test_incident_void_pause_resolution_and_explicit_resume_survive_restart(tmp_path) -> None:
    path = tmp_path / "validator.sqlite3"
    clock = _Clock()
    control = ValidatorControlPlane(path, clock_ns=clock)
    plan = _plan(0)
    control.start_window(plan, operation_id="start")
    incident = IncidentSpec(
        incident_id="canary-window-0",
        reason_code="canary_hit",
        metadata={"challenge_id": "opaque-1"},
    )
    control.terminate_window(
        plan.window_id,
        outcome=TerminalOutcome.VOID,
        reason_code="canary_hit",
        operation_id="void-with-incident",
        incident=incident,
        pause_scopes=(PauseScope.WINDOW_INTAKE, PauseScope.WEIGHT_SUBMISSION),
    )

    reopened = ValidatorControlPlane(path, clock_ns=clock)
    recovery = reopened.recovery_state()
    assert [item.incident_id for item in recovery.open_incidents] == ["canary-window-0"]
    assert all(state.paused for state in recovery.controls)
    with pytest.raises(TransitionError, match="intake is paused"):
        reopened.start_window(_plan(1), operation_id="blocked-start")

    holds = {state.scope: state.active_holds[0].hold_id for state in recovery.controls}
    weight_hold = holds[PauseScope.WEIGHT_SUBMISSION]
    intake_hold = holds[PauseScope.WINDOW_INTAKE]
    with pytest.raises(TransitionError, match="resolved before"):
        reopened.resume(
            PauseScope.WEIGHT_SUBMISSION,
            hold_id=weight_hold,
            resolution_code="delivery_path_repaired",
            operation_id="resume-too-soon",
        )

    resolved = reopened.resolve_incident(
        incident.incident_id,
        resolution_code="delivery_path_repaired",
        operation_id="resolve-canary",
    )
    assert resolved.status is IncidentStatus.RESOLVED
    reopened.resume(
        PauseScope.WEIGHT_SUBMISSION,
        hold_id=weight_hold,
        resolution_code="delivery_path_repaired",
        operation_id="resume-weight",
    )
    assert not reopened.control_state(PauseScope.WEIGHT_SUBMISSION).paused
    assert reopened.control_state(PauseScope.WINDOW_INTAKE).paused
    reopened.resume(
        PauseScope.WINDOW_INTAKE,
        hold_id=intake_hold,
        resolution_code="delivery_path_repaired",
        operation_id="resume-intake",
    )
    assert reopened.start_window(_plan(1), operation_id="start-1").is_active


def test_multiple_pause_holds_must_each_be_released(tmp_path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3", clock_ns=_Clock())
    first = control.pause(
        PauseScope.WEIGHT_SUBMISSION,
        reason_code="runtime_upgrade_incompatible",
        operation_id="runtime-hold",
    )
    assert first.paused
    second = control.pause(
        PauseScope.WEIGHT_SUBMISSION,
        reason_code="legacy_weight_state_active",
        operation_id="legacy-hold",
    )
    assert [hold.hold_id for hold in second.active_holds] == ["runtime-hold", "legacy-hold"]
    with pytest.raises(TransitionError, match="paused by"):
        control.require_submission_allowed()

    still_paused = control.resume(
        PauseScope.WEIGHT_SUBMISSION,
        hold_id="runtime-hold",
        resolution_code="runtime_fixture_passed",
        operation_id="release-runtime",
    )
    assert still_paused.paused
    assert [hold.hold_id for hold in still_paused.active_holds] == ["legacy-hold"]
    unpaused = control.resume(
        PauseScope.WEIGHT_SUBMISSION,
        hold_id="legacy-hold",
        resolution_code="legacy_queue_cleared",
        operation_id="release-legacy",
    )
    assert not unpaused.paused
    control.require_submission_allowed()


def test_uncommitted_sqlite_work_is_rolled_back_and_recovery_resumes_exact_stage(tmp_path) -> None:
    path = tmp_path / "validator.sqlite3"
    clock = _Clock()
    control = ValidatorControlPlane(path, clock_ns=clock)
    plan = _plan(0)
    control.start_window(plan, operation_id="start")
    control.advance_window(
        plan.window_id,
        completed_stage=WindowStage.POOL_AND_SELECTION,
        evidence_sha256="66" * 32,
        operation_id="pool",
    )

    connection = sqlite3.connect(path)
    connection.execute("BEGIN IMMEDIATE")
    connection.execute(
        "UPDATE windows SET stage = ? WHERE window_id = ?",
        (WindowStage.REQUEST_TRANSCRIPT.value, plan.window_id),
    )
    connection.close()

    recovered = ValidatorControlPlane(path, clock_ns=clock).recovery_state()
    assert recovered.active_window is not None
    assert recovered.active_window.stage is WindowStage.ASSIGNMENT
    assert recovered.pending_work is not None
    assert [item.stage for item in recovered.pending_work.completed_evidence] == [
        WindowStage.POOL_AND_SELECTION
    ]


def test_startup_rejects_a_committed_stage_without_its_evidence_prefix(tmp_path) -> None:
    path = tmp_path / "validator.sqlite3"
    clock = _Clock()
    control = ValidatorControlPlane(path, clock_ns=clock)
    plan = _plan(0)
    control.start_window(plan, operation_id="start")
    control.advance_window(
        plan.window_id,
        completed_stage=WindowStage.POOL_AND_SELECTION,
        evidence_sha256="77" * 32,
        operation_id="pool",
    )
    connection = sqlite3.connect(path)
    connection.execute("DELETE FROM stage_evidence")
    connection.commit()
    connection.close()

    with pytest.raises(PersistenceError, match="complete prefix"):
        ValidatorControlPlane(path, clock_ns=clock)


def test_control_inputs_are_bounded_and_canonical(tmp_path) -> None:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3", clock_ns=_Clock())
    with pytest.raises(ValueError, match="byte ceiling"):
        control.start_window(
            _plan(0),
            operation_id="start",
            metadata={"payload": "x" * (MAX_METADATA_BYTES + 1)},
        )
    with pytest.raises(ValueError, match="canonical reason"):
        control.pause(
            PauseScope.WEIGHT_SUBMISSION,
            reason_code="Not Canonical",
            operation_id="bad-reason",
        )
    with pytest.raises(ValueError, match="unique"):
        control.record_incident(
            IncidentSpec(incident_id="duplicate-scope", reason_code="canary_hit"),
            operation_id="duplicate-scope-op",
            pause_scopes=(PauseScope.WINDOW_INTAKE, PauseScope.WINDOW_INTAKE),
        )
