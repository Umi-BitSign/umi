from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator_adapters import (
    CompleteStageEffect,
    StageEffectResult,
    TerminalStageEffect,
    stage_operation_id,
)
from umi.validator_journal import StageObjectInput, ValidatorStageJournal
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_protocol_state import ValidatorProtocolStateStore
from umi.validator_readiness import (
    ProofBackedPriorWindowReadiness,
    ReadinessEvidenceError,
    VerifiedPublishedBundle,
)
from umi.validator_state import STAGE_ORDER, TerminalOutcome, WindowStage

from .test_validator_weight_build_effect import _fixture


class _BundleVerifier:
    def __init__(self, binding: VerifiedPublishedBundle) -> None:
        self.binding = binding
        self.calls = 0

    async def verify(self, _root):
        self.calls += 1
        return self.binding


class _Finality:
    def __init__(self, policy, block: VerifiedFinalizedBlock) -> None:
        self.chain_observation = policy.implementation_pins.live_chain
        pin = policy.implementation_pins.finality_verifier
        assert pin is not None
        self.finality_verifier_sha256 = next(iter(pin.release_sha256_by_target.values()))
        self.block = block

    async def verified_block_at(self, height: int):
        return self.block if height == self.block.height else None


def _terminal_window(tmp_path):
    source_root = tmp_path / "source"
    source_root.mkdir()
    fixture = _fixture(source_root)
    journal = ValidatorStageJournal(tmp_path / "readiness-journal")
    terminal_record = None
    audit_release = fixture.work.window.plan.closing_block + 100
    for stage in STAGE_ORDER[: STAGE_ORDER.index(WindowStage.WEIGHT_BUILD)]:
        decision = (
            TerminalStageEffect(
                outcome=TerminalOutcome.VOID,
                audit_release_block=audit_release,
                reason_code="canary_hit",
            )
            if stage is WindowStage.REVEAL_AND_SCORE
            else CompleteStageEffect()
        )
        object_bytes = canonical_json_bytes(
            {"schema": "umi-readiness-test-stage/1", "stage": stage.value}
        )
        effect = StageEffectResult(
            operation_id=stage_operation_id(fixture.work.window.plan.window_id, stage),
            window_id=fixture.work.window.plan.window_id,
            stage=stage,
            objects=(StageObjectInput(object_bytes, "application/json"),),
            metadata={"test_stage": stage.value},
            decision=decision,
        )
        record = journal.record(
            window_id=fixture.work.window.plan.window_id,
            stage=stage,
            operation_id=effect.operation_id,
            objects=effect.objects,
            metadata=effect.receipt_metadata(),
        )
        if stage is WindowStage.REVEAL_AND_SCORE:
            terminal_record = record
    assert terminal_record is not None
    previous = replace(
        fixture.work.window,
        stage=WindowStage.REVEAL_AND_SCORE,
        terminal_outcome=TerminalOutcome.VOID,
        terminal_reason_code="canary_hit",
        terminal_evidence_sha256=terminal_record.evidence_sha256,
        audit_release_block=audit_release,
        revision=fixture.work.window.revision + 1,
    )
    block = VerifiedFinalizedBlock(
        height=audit_release,
        block_hash="0x" + "ab" * 32,
        state_root="0x" + "cd" * 32,
        timestamp_ms=1_800_000_000_000,
        scoring_policy_hash=scoring_policy_hash(fixture.policy),
        chain_observation=fixture.policy.implementation_pins.live_chain,
        finality_verifier_sha256=fixture.capture.identity.finality_verifier_sha256,
        finality_evidence=b"readiness-finality-evidence",
        finality_evidence_sha256=__import__("hashlib")
        .sha256(b"readiness-finality-evidence")
        .hexdigest(),
    )
    binding = VerifiedPublishedBundle(
        manifest_sha256="ef" * 32,
        window_id=previous.plan.window_id,
        window_index=previous.plan.window_index,
        scoring_policy_hash=previous.plan.scoring_policy_hash,
        terminal_classification="void",
        highest_stage=WindowStage.REVEAL_AND_SCORE.value,
        audit_release_block=audit_release,
        audit_release_block_hash=block.block_hash,
        reason_codes=("canary_hit",),
    )
    bundle_root = tmp_path / "bundles"
    (bundle_root / previous.plan.window_id).mkdir(parents=True)
    return fixture, journal, previous, block, binding, bundle_root


def _resolved(fixture):
    state = fixture.store.audit()
    return SimpleNamespace(
        policy=fixture.policy,
        result=SimpleNamespace(
            window_id=fixture.work.window.plan.window_id,
            window_index=fixture.work.window.plan.window_index,
            scoring_policy_hash=scoring_policy_hash(fixture.policy),
        ),
        resulting_protocol_state_digest=state.state_digest.hex(),
        protocol_transition_result={"spent": {"resulting_root": state.spent_registry.root.hex()}},
    )


@pytest.mark.asyncio
async def test_prior_readiness_requires_bundle_replay_reveal_state_and_finality(
    tmp_path, monkeypatch
) -> None:
    fixture, journal, previous, block, binding, bundle_root = _terminal_window(tmp_path)
    resolved = _resolved(fixture)
    monkeypatch.setattr("umi.validator_readiness.ResolvedRevealStage", SimpleNamespace)
    monkeypatch.setattr(
        "umi.validator_readiness.resolve_reveal_stage_record",
        lambda *_args: resolved,
    )
    verifier = _BundleVerifier(binding)
    port = ProofBackedPriorWindowReadiness(
        policy=fixture.policy,
        protocol_state=fixture.store,
        journal=journal,
        bundle_root=bundle_root,
        bundle_verifier=verifier,
        finality=_Finality(fixture.policy, block),
    )

    checkpoint = await port.verified_reveal_and_spent(previous)

    assert checkpoint is not None
    assert checkpoint.window_id == previous.plan.window_id
    assert checkpoint.reveal_round == previous.plan.reveal_round
    assert checkpoint.spent_root == fixture.store.snapshot.spent_registry.root.hex()
    assert checkpoint.checkpoint_block_hash == binding.audit_release_block_hash
    assert verifier.calls == 1
    evidence = __import__("json").loads(checkpoint.evidence)
    assert evidence["bundle_manifest_sha256"] == binding.manifest_sha256
    assert evidence["protocol_state_digest"] == fixture.store.snapshot.state_digest.hex()


@pytest.mark.asyncio
async def test_prior_readiness_does_not_invent_early_terminal_state_transition(
    tmp_path, monkeypatch
) -> None:
    fixture, journal, previous, block, binding, bundle_root = _terminal_window(tmp_path)
    empty = ValidatorProtocolStateStore(tmp_path / "empty-state.sqlite3")
    monkeypatch.setattr("umi.validator_readiness.ResolvedRevealStage", SimpleNamespace)
    monkeypatch.setattr(
        "umi.validator_readiness.resolve_reveal_stage_record",
        lambda *_args: _resolved(fixture),
    )
    port = ProofBackedPriorWindowReadiness(
        policy=fixture.policy,
        protocol_state=empty,
        journal=journal,
        bundle_root=bundle_root,
        bundle_verifier=_BundleVerifier(binding),
        finality=_Finality(fixture.policy, block),
    )
    try:
        assert await port.verified_reveal_and_spent(previous) is None
    finally:
        empty.close()


@pytest.mark.asyncio
async def test_prior_readiness_waits_for_public_bundle(tmp_path) -> None:
    fixture, journal, previous, block, binding, bundle_root = _terminal_window(tmp_path)
    (bundle_root / previous.plan.window_id).rmdir()
    verifier = _BundleVerifier(binding)
    port = ProofBackedPriorWindowReadiness(
        policy=fixture.policy,
        protocol_state=fixture.store,
        journal=journal,
        bundle_root=bundle_root,
        bundle_verifier=verifier,
        finality=_Finality(fixture.policy, block),
    )

    assert await port.verified_reveal_and_spent(previous) is None
    assert verifier.calls == 0


@pytest.mark.asyncio
async def test_prior_readiness_rejects_release_block_substitution(tmp_path, monkeypatch) -> None:
    fixture, journal, previous, block, binding, bundle_root = _terminal_window(tmp_path)
    resolved = _resolved(fixture)
    monkeypatch.setattr("umi.validator_readiness.ResolvedRevealStage", SimpleNamespace)
    monkeypatch.setattr(
        "umi.validator_readiness.resolve_reveal_stage_record",
        lambda *_args: resolved,
    )
    finality = _Finality(fixture.policy, replace(block, block_hash="0x" + "99" * 32))
    port = ProofBackedPriorWindowReadiness(
        policy=fixture.policy,
        protocol_state=fixture.store,
        journal=journal,
        bundle_root=bundle_root,
        bundle_verifier=_BundleVerifier(binding),
        finality=finality,
    )

    with pytest.raises(ReadinessEvidenceError, match="prior_release_block_mismatch"):
        await port.verified_reveal_and_spent(previous)


@pytest.mark.asyncio
async def test_prior_readiness_rejects_bundle_reason_substitution(tmp_path) -> None:
    fixture, journal, previous, block, binding, bundle_root = _terminal_window(tmp_path)
    verifier = _BundleVerifier(replace(binding, reason_codes=("another_reason",)))
    port = ProofBackedPriorWindowReadiness(
        policy=fixture.policy,
        protocol_state=fixture.store,
        journal=journal,
        bundle_root=bundle_root,
        bundle_verifier=verifier,
        finality=_Finality(fixture.policy, block),
    )

    with pytest.raises(ReadinessEvidenceError, match="prior_bundle_reason_mismatch"):
        await port.verified_reveal_and_spent(previous)
