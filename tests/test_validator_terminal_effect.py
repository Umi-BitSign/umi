from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from umi.calibration_bundle import (
    STAGE_IDS,
    calibration_stage_replay_hook_id,
    verify_calibration_bundle,
)
from umi.chain_evidence import FinalizedSnapshotRef
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator_adapters import (
    CompleteStageEffect,
    JournalStageAdapter,
    StageEffectResult,
    stage_operation_id,
)
from umi.validator_journal import StageObjectInput, ValidatorStageJournal
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageEvidence,
    StagePending,
    StageWorkItem,
    TerminalDecision,
    TerminalOutcome,
    WindowPlan,
    WindowRecord,
    WindowStage,
)
from umi.validator_terminal_effect import (
    CalibrationNoWeightTerminalEffect,
    ReplayCalibrationBundleVerifier,
    replay_terminal_stage_receipt,
)

from .test_calibration_bundle import (
    CHAIN_SPEC_SHA256,
    FINALITY_VERIFIER_SHA256,
    PROOF_VERIFIER_SHA256,
    TARGET_TRIPLE,
    VALIDATOR,
    WINDOW_ID,
    _interval,
    _policy,
    _ports,
    _sign,
)


class _Capture:
    def __init__(self, interval, *, fail: bool = False) -> None:
        self.validator_account_id32 = VALIDATOR
        self.interval = interval
        self.fail = fail
        self.calls: list[tuple[int, int]] = []

    async def capture(self, *, start_block: int, end_block: int):
        self.calls.append((start_block, end_block))
        if self.fail:
            raise AssertionError("completed bundle recovery must not recapture the chain")
        return self.interval


def _plan(policy) -> WindowPlan:
    return WindowPlan(
        window_id=WINDOW_ID,
        window_index=0,
        scoring_policy_hash=scoring_policy_hash(policy),
        announcement_block=1_000,
        proposal_close_block=1_001,
        closing_block=1_002,
        selection_round=100,
        issue_close_round=110,
        response_close_round=120,
        reveal_round=130,
    )


def _records(journal: ValidatorStageJournal, plan: WindowPlan):
    result = []
    for index, stage in enumerate(WindowStage):
        if stage is WindowStage.COMMIT_AND_TERMINAL_STATE:
            break
        payload = canonical_json_bytes({"fixture": stage.value, "index": index})
        effect = StageEffectResult(
            operation_id=stage_operation_id(plan.window_id, stage),
            window_id=plan.window_id,
            stage=stage,
            objects=(StageObjectInput(payload, f"application/vnd.umi.test-{stage.value}"),),
            metadata={"fixture": stage.value},
            decision=CompleteStageEffect(),
        )
        result.append(
            journal.record(
                window_id=plan.window_id,
                stage=stage,
                operation_id=effect.operation_id,
                objects=effect.objects,
                metadata=effect.receipt_metadata(),
            )
        )
    return tuple(result)


def _work(plan: WindowPlan, records) -> StageWorkItem:
    return StageWorkItem(
        window=WindowRecord(
            plan=plan,
            stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=6,
        ),
        completed_evidence=tuple(
            StageEvidence(
                window_id=plan.window_id,
                stage=WindowStage(item.receipt.stage),
                evidence_sha256=item.evidence_sha256,
                recorded_at_unix_ns=index + 1,
            )
            for index, item in enumerate(records)
        ),
        controls=tuple(ControlState(scope=scope, active_holds=()) for scope in PauseScope),
    )


def _verification_ports(policy):
    base = _ports(policy=policy)
    hooks = {
        calibration_stage_replay_hook_id(policy, stage): (
            replay_terminal_stage_receipt
            if stage == WindowStage.COMMIT_AND_TERMINAL_STATE.value
            else lambda **_values: True
        )
        for stage in STAGE_IDS
    }
    return replace(base, stage_replay_hooks=hooks)


def _effect(
    tmp_path: Path,
    *,
    policy,
    journal,
    capture,
    close,
    bundle_writer=None,
):
    ports = _verification_ports(policy)
    kwargs = {}
    if bundle_writer is not None:
        kwargs["bundle_writer"] = bundle_writer
    return CalibrationNoWeightTerminalEffect(
        policy=policy,
        journal=journal,
        no_weight_capture=capture,
        weight_close_resolver=lambda **_values: close,
        bundle_root=tmp_path / "bundles",
        bundle_verifier=ReplayCalibrationBundleVerifier(ports),
        validator_account=VALIDATOR,
        signature_scheme="ed25519",
        manifest_signer=_sign,
        software_revisions={
            "umi": "test",
            "runtime": "test",
            "target_triple": TARGET_TRIPLE,
            "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
            "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
            "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
        },
        **kwargs,
    )


@pytest.mark.asyncio
async def test_terminal_receipt_precedes_signed_bundle_and_recovers_without_recapture(
    tmp_path: Path,
) -> None:
    policy = _policy()
    interval = await _interval()
    close = interval.scan.end_snapshot
    journal = ValidatorStageJournal(tmp_path / "journal")
    plan = _plan(policy)
    records = _records(journal, plan)
    work = _work(plan, records)
    capture = _Capture(interval)
    effect = _effect(
        tmp_path,
        policy=policy,
        journal=journal,
        capture=capture,
        close=close,
    )
    adapter = JournalStageAdapter(
        stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
        journal=journal,
        effect=effect,
    )

    result = await adapter.execute(work)

    assert isinstance(result, TerminalDecision)
    assert result.outcome is TerminalOutcome.CALIBRATION_NO_WEIGHT
    assert result.audit_release_block == close.block_number
    assert capture.calls == [(plan.announcement_block, close.block_number)]
    final_root = tmp_path / "bundles" / plan.window_id
    verified = await verify_calibration_bundle(
        final_root,
        ports=_verification_ports(policy),
    )
    assert verified.manifest.weight_commit_close_block_hash == close.block_hash
    assert len(journal.load_window(plan.window_id)) == 7

    restarted_capture = _Capture(interval, fail=True)
    restarted = _effect(
        tmp_path,
        policy=policy,
        journal=ValidatorStageJournal(tmp_path / "journal"),
        capture=restarted_capture,
        close=close,
    )
    repeated = await JournalStageAdapter(
        stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
        journal=restarted.journal,
        effect=restarted,
    ).execute(work)
    assert repeated == result
    assert restarted_capture.calls == []


@pytest.mark.asyncio
async def test_finality_pending_creates_no_terminal_receipt(tmp_path: Path) -> None:
    policy = _policy()
    interval = await _interval()
    journal = ValidatorStageJournal(tmp_path / "journal")
    plan = _plan(policy)
    records = _records(journal, plan)
    work = _work(plan, records)
    capture = _Capture(None)
    close = interval.scan.end_snapshot
    adapter = JournalStageAdapter(
        stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
        journal=journal,
        effect=_effect(
            tmp_path,
            policy=policy,
            journal=journal,
            capture=capture,
            close=close,
        ),
    )

    with pytest.raises(StagePending, match="weight_commit_close_finality_pending"):
        await adapter.execute(work)
    assert len(journal.load_window(plan.window_id)) == 6


@pytest.mark.asyncio
async def test_crash_after_terminal_receipt_retries_bundle_publication(tmp_path: Path) -> None:
    policy = _policy()
    interval = await _interval()
    close = interval.scan.end_snapshot
    journal = ValidatorStageJournal(tmp_path / "journal")
    plan = _plan(policy)
    records = _records(journal, plan)
    work = _work(plan, records)

    def failed_writer(*_args, **_kwargs):
        raise RuntimeError("simulated bundle write crash")

    first = _effect(
        tmp_path,
        policy=policy,
        journal=journal,
        capture=_Capture(interval),
        close=close,
        bundle_writer=failed_writer,
    )
    with pytest.raises(RuntimeError, match="simulated bundle write crash"):
        await JournalStageAdapter(
            stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
            journal=journal,
            effect=first,
        ).execute(work)
    assert len(journal.load_window(plan.window_id)) == 7
    assert not (tmp_path / "bundles" / plan.window_id).exists()

    recovered = _effect(
        tmp_path,
        policy=policy,
        journal=ValidatorStageJournal(tmp_path / "journal"),
        capture=_Capture(interval),
        close=close,
    )
    result = await JournalStageAdapter(
        stage=WindowStage.COMMIT_AND_TERMINAL_STATE,
        journal=recovered.journal,
        effect=recovered,
    ).execute(work)
    assert result.outcome is TerminalOutcome.CALIBRATION_NO_WEIGHT
    assert (tmp_path / "bundles" / plan.window_id / "manifest.json").exists()


def test_terminal_effect_rejects_an_unbound_close_snapshot(tmp_path: Path) -> None:
    policy = _policy()
    journal = ValidatorStageJournal(tmp_path / "journal")
    capture = type("Capture", (), {"validator_account_id32": VALIDATOR, "capture": None})()
    with pytest.raises(TypeError, match="capture"):
        _effect(
            tmp_path,
            policy=policy,
            journal=journal,
            capture=capture,
            close=FinalizedSnapshotRef(
                block_number=1_001,
                block_hash="0x" + "01" * 32,
                parent_hash="0x" + "02" * 32,
                state_root="0x" + "03" * 32,
            ),
        )
