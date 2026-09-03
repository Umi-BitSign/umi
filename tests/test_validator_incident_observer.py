from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from umi.calibration_bundle import STAGE_IDS, calibration_stage_replay_hook_id
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator_adapters import (
    CompleteStageEffect,
    JournalStageAdapter,
    StageEffectResult,
    TerminalStageEffect,
    stage_operation_id,
)
from umi.validator_incident_bundle import verify_incident_bundle
from umi.validator_incident_observer import (
    ReplayIncidentBundleVerifier,
    ShadowIncidentReceiptObserver,
)
from umi.validator_journal import StageObjectInput, ValidatorStageJournal
from umi.validator_state import (
    ControlState,
    IncidentSpec,
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
            raise AssertionError("verified bundle recovery must not recapture chain evidence")
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


def _work(journal: ValidatorStageJournal, plan: WindowPlan) -> StageWorkItem:
    prior_records = []
    for stage in (
        WindowStage.POOL_AND_SELECTION,
        WindowStage.ASSIGNMENT,
        WindowStage.REQUEST_TRANSCRIPT,
    ):
        payload = canonical_json_bytes({"fixture": stage.value})
        effect = StageEffectResult(
            operation_id=stage_operation_id(plan.window_id, stage),
            window_id=plan.window_id,
            stage=stage,
            objects=(StageObjectInput(payload, "application/json"),),
            metadata={"fixture": stage.value},
            decision=CompleteStageEffect(),
        )
        prior_records.append(
            journal.record(
                window_id=plan.window_id,
                stage=stage,
                operation_id=effect.operation_id,
                objects=effect.objects,
                metadata=effect.receipt_metadata(),
            )
        )
    return StageWorkItem(
        window=WindowRecord(
            plan=plan,
            stage=WindowStage.SEALED_RESPONSE,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=3,
        ),
        completed_evidence=tuple(
            StageEvidence(
                window_id=plan.window_id,
                stage=WindowStage(record.receipt.stage),
                evidence_sha256=record.evidence_sha256,
                recorded_at_unix_ns=index + 1,
            )
            for index, record in enumerate(prior_records)
        ),
        controls=tuple(ControlState(scope=scope, active_holds=()) for scope in PauseScope),
    )


class _TerminalEffect:
    def __init__(self) -> None:
        self.calls = 0

    async def perform(self, *, operation_id, work):
        self.calls += 1
        payload = canonical_json_bytes({"reason_code": "response_anchor_failed"})
        return StageEffectResult(
            operation_id=operation_id,
            window_id=work.window.plan.window_id,
            stage=work.stage,
            objects=(StageObjectInput(payload, "application/json"),),
            metadata={"response_set_root": "11" * 32},
            decision=TerminalStageEffect(
                outcome=TerminalOutcome.SKIPPED,
                audit_release_block=1_001,
                reason_code="response_anchor_failed",
                incident=IncidentSpec(
                    incident_id="test/response-anchor/incident",
                    reason_code="response_anchor_failed",
                    metadata={"stage": "sealed_response"},
                ),
            ),
        )


def _verification_ports(policy):
    base = _ports(policy=policy)
    return replace(
        base,
        stage_replay_hooks={
            calibration_stage_replay_hook_id(policy, stage): lambda **_values: True
            for stage in STAGE_IDS
        },
    )


def _observer(tmp_path: Path, *, policy, journal, capture):
    return ShadowIncidentReceiptObserver(
        policy=policy,
        journal=journal,
        no_weight_capture=capture,
        bundle_root=tmp_path / "bundles",
        bundle_verifier=ReplayIncidentBundleVerifier(_verification_ports(policy)),
        validator_account=VALIDATOR,
        signature_scheme="ed25519",
        manifest_signer=_sign,
        software_revisions={
            "umi": "test",
            "target_triple": TARGET_TRIPLE,
            "storage_proof_verifier_sha256": PROOF_VERIFIER_SHA256,
            "finality_verifier_sha256": FINALITY_VERIFIER_SHA256,
            "finality_chain_spec_sha256": CHAIN_SPEC_SHA256,
        },
    )


@pytest.mark.asyncio
async def test_early_terminal_receipt_is_not_returned_until_incident_bundle_verifies(
    tmp_path: Path,
) -> None:
    policy = _policy()
    interval = await _interval()
    journal = ValidatorStageJournal(tmp_path / "journal")
    plan = _plan(policy)
    work = _work(journal, plan)
    capture = _Capture(interval)
    effect = _TerminalEffect()
    adapter = JournalStageAdapter(
        stage=WindowStage.SEALED_RESPONSE,
        journal=journal,
        effect=effect,
        receipt_observer=_observer(
            tmp_path,
            policy=policy,
            journal=journal,
            capture=capture,
        ),
    )

    result = await adapter.execute(work)

    assert isinstance(result, TerminalDecision)
    assert result.outcome is TerminalOutcome.SKIPPED
    assert effect.calls == 1
    assert capture.calls == [(1_000, 1_001)]
    verified = await verify_incident_bundle(
        tmp_path / "bundles" / WINDOW_ID,
        ports=_verification_ports(policy),
    )
    assert verified.manifest.highest_stage == "sealed_response"
    assert [item.status for item in verified.manifest.stages[4:]] == [
        "not_reached",
        "not_reached",
        "not_reached",
    ]


@pytest.mark.asyncio
async def test_pending_release_recovers_receipt_without_reperforming_or_republishing(
    tmp_path: Path,
) -> None:
    policy = _policy()
    interval = await _interval()
    journal = ValidatorStageJournal(tmp_path / "journal")
    plan = _plan(policy)
    work = _work(journal, plan)
    effect = _TerminalEffect()
    pending = JournalStageAdapter(
        stage=WindowStage.SEALED_RESPONSE,
        journal=journal,
        effect=effect,
        receipt_observer=_observer(
            tmp_path,
            policy=policy,
            journal=journal,
            capture=_Capture(None),
        ),
    )

    with pytest.raises(StagePending, match="incident_audit_release_finality_pending"):
        await pending.execute(work)
    assert effect.calls == 1
    assert len(journal.load_window(WINDOW_ID)) == 4

    class MustNotRun:
        async def perform(self, *, operation_id, work):
            raise AssertionError("terminal effect reran despite a durable receipt")

    recovered_capture = _Capture(interval)
    recovered = JournalStageAdapter(
        stage=WindowStage.SEALED_RESPONSE,
        journal=ValidatorStageJournal(tmp_path / "journal"),
        effect=MustNotRun(),
        receipt_observer=_observer(
            tmp_path,
            policy=policy,
            journal=ValidatorStageJournal(tmp_path / "journal"),
            capture=recovered_capture,
        ),
    )
    result = await recovered.execute(work)
    assert isinstance(result, TerminalDecision)
    assert recovered_capture.calls == [(1_000, 1_001)]

    no_recapture = _Capture(interval, fail=True)
    repeated = JournalStageAdapter(
        stage=WindowStage.SEALED_RESPONSE,
        journal=ValidatorStageJournal(tmp_path / "journal"),
        effect=MustNotRun(),
        receipt_observer=_observer(
            tmp_path,
            policy=policy,
            journal=ValidatorStageJournal(tmp_path / "journal"),
            capture=no_recapture,
        ),
    )
    assert await repeated.execute(work) == result
    assert no_recapture.calls == []
