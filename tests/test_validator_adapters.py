from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import pytest

from umi.protocol import canonical_json_bytes
from umi.validator_adapters import (
    ADAPTER_RESULT_SCHEMA,
    CompleteStageEffect,
    JournalStageAdapter,
    StageEffectBindingError,
    StageEffectResult,
    StageReceiptBindingError,
    TerminalStageEffect,
    stage_operation_id,
)
from umi.validator_engine import AdapterExecutionError, EngineStepStatus, ValidatorEngine
from umi.validator_journal import StageObjectInput, ValidatorStageJournal
from umi.validator_state import (
    IncidentSpec,
    PauseScope,
    StageCompletion,
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


def _started(tmp_path: Path) -> tuple[ValidatorControlPlane, WindowPlan]:
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    plan = _plan()
    control.start_window(plan, operation_id="start-window-0")
    return control, plan


def _object(label: str) -> StageObjectInput:
    return StageObjectInput(
        canonical_json_bytes({"label": label}),
        "application/json",
    )


@dataclass
class CompletionEffect:
    label: str = "pool"
    calls: list[tuple[str, WindowStage]] = field(default_factory=list)
    works: list[object] = field(default_factory=list)

    async def perform(self, *, operation_id, work):
        self.calls.append((operation_id, work.stage))
        self.works.append(work)
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=work.stage,
            objects=(_object(self.label),),
            metadata={"nested": {"answer": 42}, "stage": work.stage.value},
            decision=CompleteStageEffect(),
        )


@pytest.mark.asyncio
async def test_receipt_first_completion_is_exact_and_retry_does_not_rerun_effect(
    tmp_path: Path,
) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")
    effect = CompletionEffect()
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=effect,
    )
    real_apply = control.apply_result

    def assert_receipt_before_state_mutation(result):
        record = journal.load(plan.window_id, WindowStage.POOL_AND_SELECTION)
        assert record.evidence_sha256 == result.evidence_sha256
        return real_apply(result)

    control.apply_result = assert_receipt_before_state_mutation  # type: ignore[method-assign]
    step = await ValidatorEngine(
        control,
        {WindowStage.POOL_AND_SELECTION: adapter},
    ).run_once()

    expected_operation = stage_operation_id(plan.window_id, WindowStage.POOL_AND_SELECTION)
    assert effect.calls == [(expected_operation, WindowStage.POOL_AND_SELECTION)]
    assert step.status is EngineStepStatus.ADVANCED
    assert isinstance(step.result, StageCompletion)
    record = journal.load(plan.window_id, WindowStage.POOL_AND_SELECTION)
    assert step.result.operation_id == record.receipt.operation_id == expected_operation
    assert step.result.evidence_sha256 == record.evidence_sha256
    assert step.result.metadata == {
        "nested": {"answer": 42},
        "stage": "pool_and_selection",
    }
    assert record.receipt.metadata["schema"] == ADAPTER_RESULT_SCHEMA
    assert record.receipt.metadata["kind"] == "completion"
    assert journal.read_object(record.receipt.objects[0]) == _object("pool").data

    original_work = effect.works[0]
    repeated = await adapter.execute(original_work)  # type: ignore[arg-type]
    assert repeated == step.result
    assert effect.calls == [(expected_operation, WindowStage.POOL_AND_SELECTION)]
    assert real_apply(repeated) == step.window


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_binding", ["operation", "window", "stage", "type"])
async def test_effect_bindings_fail_before_a_receipt_or_state_mutation(
    tmp_path: Path,
    bad_binding: str,
) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")

    class WrongEffect:
        async def perform(self, *, operation_id, work):
            if bad_binding == "type":
                return {"not": "a StageEffectResult"}
            return StageEffectResult(
                operation_id="wrong-operation" if bad_binding == "operation" else operation_id,
                window_id="ff" * 32 if bad_binding == "window" else plan.window_id,
                stage=(
                    WindowStage.ASSIGNMENT
                    if bad_binding == "stage"
                    else WindowStage.POOL_AND_SELECTION
                ),
                objects=(_object("wrong"),),
                metadata={},
                decision=CompleteStageEffect(),
            )

    with pytest.raises(AdapterExecutionError) as failure:
        await ValidatorEngine(
            control,
            {
                WindowStage.POOL_AND_SELECTION: JournalStageAdapter(
                    stage=WindowStage.POOL_AND_SELECTION,
                    journal=journal,
                    effect=WrongEffect(),
                )
            },
        ).run_once()

    assert isinstance(failure.value.__cause__, StageEffectBindingError)
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION
    assert journal.load_window(plan.window_id) == ()


@pytest.mark.asyncio
async def test_existing_receipt_binding_failure_never_invokes_effect(tmp_path: Path) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")
    metadata = StageEffectResult(
        operation_id=stage_operation_id(plan.window_id, WindowStage.POOL_AND_SELECTION),
        window_id=plan.window_id,
        stage=WindowStage.POOL_AND_SELECTION,
        objects=(_object("selection"),),
        metadata={},
        decision=CompleteStageEffect(),
    ).receipt_metadata()
    journal.record(
        window_id=plan.window_id,
        stage=WindowStage.POOL_AND_SELECTION,
        operation_id="wrong-operation",
        objects=(_object("selection"),),
        metadata=metadata,
    )
    effect = CompletionEffect()

    with pytest.raises(StageReceiptBindingError, match="operation ID"):
        await JournalStageAdapter(
            stage=WindowStage.POOL_AND_SELECTION,
            journal=journal,
            effect=effect,
        ).execute(control.pending_work())  # type: ignore[arg-type]

    assert effect.calls == []
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION


@pytest.mark.asyncio
async def test_missing_prior_journal_receipt_fails_closed(tmp_path: Path) -> None:
    control, plan = _started(tmp_path)
    control.advance_window(
        plan.window_id,
        completed_stage=WindowStage.POOL_AND_SELECTION,
        evidence_sha256="11" * 32,
        operation_id="legacy-pool-completion",
    )
    effect = CompletionEffect(label="assignment")

    with pytest.raises(StageReceiptBindingError, match="stage boundary"):
        await JournalStageAdapter(
            stage=WindowStage.ASSIGNMENT,
            journal=ValidatorStageJournal(tmp_path / "journal"),
            effect=effect,
        ).execute(control.pending_work())  # type: ignore[arg-type]

    assert effect.calls == []
    assert control.get_window(plan.window_id).stage is WindowStage.ASSIGNMENT


@pytest.mark.asyncio
async def test_terminal_receipt_preserves_audit_reason_incident_scopes_and_metadata(
    tmp_path: Path,
) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")
    captured_work: list[object] = []
    calls = 0

    class VoidEffect:
        async def perform(self, *, operation_id, work):
            nonlocal calls
            calls += 1
            captured_work.append(work)
            return StageEffectResult(
                operation_id=operation_id,
                window_id=plan.window_id,
                stage=work.stage,
                objects=(_object("canary-incident"),),
                metadata={"comparison_count": 128, "source": "publisher-a"},
                decision=TerminalStageEffect(
                    outcome=TerminalOutcome.VOID,
                    reason_code="canary_hit",
                    audit_release_block=2_222,
                    incident=IncidentSpec(
                        incident_id="window-0-canary-hit",
                        reason_code="canary_hit",
                        metadata={"challenge_id": "opaque-1"},
                    ),
                    pause_scopes=(
                        PauseScope.WINDOW_INTAKE,
                        PauseScope.WEIGHT_SUBMISSION,
                    ),
                ),
            )

    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=VoidEffect(),
    )
    step = await ValidatorEngine(
        control,
        {WindowStage.POOL_AND_SELECTION: adapter},
    ).run_once()

    assert step.status is EngineStepStatus.TERMINAL
    assert isinstance(step.result, TerminalDecision)
    assert step.result.outcome is TerminalOutcome.VOID
    assert step.result.reason_code == "canary_hit"
    assert step.result.audit_release_block == 2_222
    assert (
        step.result.evidence_sha256
        == journal.load(
            plan.window_id,
            WindowStage.POOL_AND_SELECTION,
        ).evidence_sha256
    )
    assert step.result.metadata == {"comparison_count": 128, "source": "publisher-a"}
    assert step.result.incident == IncidentSpec(
        incident_id="window-0-canary-hit",
        reason_code="canary_hit",
        metadata={"challenge_id": "opaque-1"},
    )
    assert step.result.pause_scopes == (
        PauseScope.WEIGHT_SUBMISSION,
        PauseScope.WINDOW_INTAKE,
    )
    assert control.get_incident("window-0-canary-hit").reason_code == "canary_hit"
    assert control.control_state(PauseScope.WINDOW_INTAKE).paused
    assert control.control_state(PauseScope.WEIGHT_SUBMISSION).paused

    repeated = await adapter.execute(captured_work[0])  # type: ignore[arg-type]
    assert repeated == step.result
    assert calls == 1
    assert control.apply_result(repeated) == step.window


def test_result_types_reject_illegal_terminal_and_evidence_shapes() -> None:
    operation_id = stage_operation_id("01" * 32, WindowStage.POOL_AND_SELECTION)
    with pytest.raises(ValueError, match="at least one"):
        StageEffectResult(
            operation_id=operation_id,
            window_id="01" * 32,
            stage=WindowStage.POOL_AND_SELECTION,
            objects=(),
            metadata={},
            decision=CompleteStageEffect(),
        )
    with pytest.raises(ValueError, match="only valid at the terminal stage"):
        StageEffectResult(
            operation_id=operation_id,
            window_id="01" * 32,
            stage=WindowStage.POOL_AND_SELECTION,
            objects=(_object("early-applied"),),
            metadata={},
            decision=TerminalStageEffect(
                outcome=TerminalOutcome.APPLIED,
                audit_release_block=1,
            ),
        )
    with pytest.raises(ValueError, match="requires a TerminalStageEffect"):
        StageEffectResult(
            operation_id=stage_operation_id(
                "01" * 32,
                WindowStage.COMMIT_AND_TERMINAL_STATE,
            ),
            window_id="01" * 32,
            stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
            objects=(_object("terminal"),),
            metadata={},
            decision=CompleteStageEffect(),
        )
    with pytest.raises(ValueError, match="requires a reason"):
        TerminalStageEffect(
            outcome=TerminalOutcome.SKIPPED,
            audit_release_block=1,
        )


@pytest.mark.asyncio
async def test_engine_sqlite_and_journal_recover_crash_between_receipt_and_transition(
    tmp_path: Path,
) -> None:
    database = tmp_path / "validator.sqlite3"
    journal_root = tmp_path / "journal"
    control, plan = _started(tmp_path)
    first_journal = ValidatorStageJournal(journal_root)
    effect = CompletionEffect(label="durable-selection")
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=first_journal,
        effect=effect,
    )

    def crash_before_sqlite(_result):
        assert len(first_journal.load_window(plan.window_id)) == 1
        raise OSError("simulated crash after durable receipt")

    control.apply_result = crash_before_sqlite  # type: ignore[method-assign]
    with pytest.raises(OSError, match="simulated crash"):
        await ValidatorEngine(
            control,
            {WindowStage.POOL_AND_SELECTION: adapter},
        ).run_once()

    assert len(effect.calls) == 1
    assert ValidatorControlPlane(database).get_window(plan.window_id).stage is (
        WindowStage.POOL_AND_SELECTION
    )

    class MustNotRunAgain:
        calls = 0

        async def perform(self, *, operation_id, work):
            self.calls += 1
            raise AssertionError(f"effect reran for {operation_id} at {work.stage.value}")

    replacement_effect = MustNotRunAgain()
    restarted_control = ValidatorControlPlane(database)
    restarted_journal = ValidatorStageJournal(journal_root)
    restarted = ValidatorEngine(
        restarted_control,
        {
            WindowStage.POOL_AND_SELECTION: JournalStageAdapter(
                stage=WindowStage.POOL_AND_SELECTION,
                journal=restarted_journal,
                effect=replacement_effect,
            )
        },
    )
    recovered = await restarted.run_once()

    assert replacement_effect.calls == 0
    assert recovered.status is EngineStepStatus.ADVANCED
    assert recovered.window is not None
    assert recovered.window.stage is WindowStage.ASSIGNMENT
    receipt = restarted_journal.load(plan.window_id, WindowStage.POOL_AND_SELECTION)
    recovery = restarted_control.recovery_state()
    assert recovery.pending_work is not None
    assert recovery.pending_work.completed_evidence[0].evidence_sha256 == receipt.evidence_sha256
    operations = restarted_control.list_operations()
    assert [item.operation_type for item in operations] == ["start_window", "advance_window"]
    assert operations[-1].operation_id == stage_operation_id(
        plan.window_id,
        WindowStage.POOL_AND_SELECTION,
    )


@pytest.mark.asyncio
async def test_after_receipt_hook_runs_for_new_and_recovered_receipts(
    tmp_path: Path,
) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")

    @dataclass
    class HookEffect(CompletionEffect):
        hook_records: list[tuple[str, str]] = field(default_factory=list)

        async def after_receipt(self, *, record, work):
            self.hook_records.append((record.receipt.operation_id, work.window.plan.window_id))

    effect = HookEffect()
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=effect,
    )
    work = control.pending_work()
    assert work is not None

    first = await adapter.execute(work)
    recovered = await adapter.execute(work)

    expected_operation = stage_operation_id(
        plan.window_id,
        WindowStage.POOL_AND_SELECTION,
    )
    assert first == recovered
    assert effect.calls == [(expected_operation, WindowStage.POOL_AND_SELECTION)]
    assert effect.hook_records == [
        (expected_operation, plan.window_id),
        (expected_operation, plan.window_id),
    ]


@pytest.mark.asyncio
async def test_after_receipt_hook_failure_recovers_without_reperforming_effect(
    tmp_path: Path,
) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")

    @dataclass
    class RecoveringHookEffect(CompletionEffect):
        hook_calls: int = 0

        async def after_receipt(self, *, record, work):
            self.hook_calls += 1
            if self.hook_calls == 1:
                raise OSError("simulated material-store crash")

    effect = RecoveringHookEffect()
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=effect,
    )

    with pytest.raises(OSError, match="material-store crash"):
        await adapter.execute(control.pending_work())  # type: ignore[arg-type]

    assert len(effect.calls) == 1
    assert len(journal.load_window(plan.window_id)) == 1
    assert control.get_window(plan.window_id).stage is WindowStage.POOL_AND_SELECTION

    recovered = await adapter.execute(control.pending_work())  # type: ignore[arg-type]
    assert isinstance(recovered, StageCompletion)
    assert len(effect.calls) == 1
    assert effect.hook_calls == 2


def test_sync_after_receipt_hook_is_rejected(tmp_path: Path) -> None:
    class UnsafeHookEffect(CompletionEffect):
        def after_receipt(self, *, record, work):
            return None

    with pytest.raises(TypeError, match="after_receipt must be async"):
        JournalStageAdapter(
            stage=WindowStage.POOL_AND_SELECTION,
            journal=ValidatorStageJournal(tmp_path / "journal"),
            effect=UnsafeHookEffect(),
        )


@pytest.mark.asyncio
async def test_generic_receipt_observer_runs_after_effect_hook_and_recovers(
    tmp_path: Path,
) -> None:
    control, plan = _started(tmp_path)
    journal = ValidatorStageJournal(tmp_path / "journal")
    sequence: list[str] = []

    class HookedEffect(CompletionEffect):
        async def after_receipt(self, *, record, work):
            sequence.append(f"effect:{record.receipt.stage}")

    class RecoveringObserver:
        calls = 0

        async def after_receipt(self, *, record, work):
            self.calls += 1
            sequence.append(f"observer:{record.receipt.stage}")
            if self.calls == 1:
                raise OSError("simulated incident publisher crash")

    effect = HookedEffect()
    observer = RecoveringObserver()
    adapter = JournalStageAdapter(
        stage=WindowStage.POOL_AND_SELECTION,
        journal=journal,
        effect=effect,
        receipt_observer=observer,
    )
    work = control.pending_work()
    assert work is not None

    with pytest.raises(OSError, match="publisher crash"):
        await adapter.execute(work)
    recovered = await adapter.execute(work)

    assert isinstance(recovered, StageCompletion)
    assert len(effect.calls) == 1
    assert observer.calls == 2
    assert sequence == [
        "effect:pool_and_selection",
        "observer:pool_and_selection",
        "effect:pool_and_selection",
        "observer:pool_and_selection",
    ]
    assert journal.load(plan.window_id, WindowStage.POOL_AND_SELECTION).receipt.stage == (
        "pool_and_selection"
    )


def test_sync_receipt_observer_is_rejected(tmp_path: Path) -> None:
    class UnsafeObserver:
        def after_receipt(self, *, record, work):
            return None

    with pytest.raises(TypeError, match="receipt observer after_receipt must be async"):
        JournalStageAdapter(
            stage=WindowStage.POOL_AND_SELECTION,
            journal=ValidatorStageJournal(tmp_path / "journal"),
            effect=CompletionEffect(),
            receipt_observer=UnsafeObserver(),
        )
