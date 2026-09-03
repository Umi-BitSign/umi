from __future__ import annotations

import hashlib
import json
from dataclasses import replace

import bittensor as bt
import pytest

from tests.test_publisher_availability import (
    _fake_inspect_factory,
    _write_bundle,
)
from tests.test_validator_closing_snapshot import (
    FINALITY,
    FINALITY_VERIFIER,
    _FakeProofs,
    _FakeRuntime,
    _Finality,
    _live_policy,
    _values,
    _work,
)
from umi.encoding import account_id32
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.publisher_availability import AvailabilityWorkflowError
from umi.publisher_availability_authority import (
    VerifiedQualificationObservation,
    authorize_candidate_qualification,
    protocol_state_genesis_evidence,
)
from umi.registries import SpentCohortBatch
from umi.validator_closing_snapshot import ProofBackedClosingSnapshotCollector
from umi.validator_protocol_state import (
    ProtocolStatePolicyLimits,
    ValidatorProtocolStateStore,
    decode_protocol_state_snapshot,
    encode_protocol_state_snapshot,
)
from umi.validator_state import WindowPlan
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, WindowClock


def _window_work(policy, *, window_index: int):
    work = _work(policy)
    selection_round = bt.timelock.current_round() + 200 + window_index
    selection_timestamp_ms = QUICKNET_GENESIS_MS + (selection_round - 1) * QUICKNET_PERIOD_MS
    announcement_timestamp_ms = selection_timestamp_ms - 1_000 * (
        policy.clock.anchor_blocks * policy.clock.target_block_interval_seconds
        + policy.clock.selection_finality_buffer_seconds
    )
    clock = WindowClock(
        activation_block=policy.activation_block,
        window_stride_blocks=policy.clock.window_stride_blocks,
        proposal_blocks=policy.clock.proposal_blocks,
        anchor_blocks=policy.clock.anchor_blocks,
        target_block_interval_seconds=policy.clock.target_block_interval_seconds,
        selection_finality_buffer_seconds=policy.clock.selection_finality_buffer_seconds,
        issue_allowance_seconds=policy.clock.issue_allowance_seconds,
        response_window_seconds=policy.clock.response_window_seconds,
        delivery_grace_seconds=policy.clock.delivery_grace_seconds,
        reveal_margin_seconds=policy.clock.reveal_margin_seconds,
    )
    schedule = clock.derive(
        window_index,
        netuid=78,
        announcement_block_hash="0x" + "aa" * 32,
        announcement_timestamp_ms=announcement_timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    plan = WindowPlan.from_schedule(schedule, scoring_policy_hash=scoring_policy_hash(policy))
    return replace(work, window=replace(work.window, plan=plan))


async def _proof_material(tmp_path, monkeypatch, *, window_index: int = 0):
    policy = _live_policy()
    work = _window_work(policy, window_index=window_index)
    values, _hotkeys, _root = _values(policy, work)
    finality = _Finality(policy, work)
    announcement_height = work.window.plan.announcement_block
    announcement_timestamp_ms = (
        QUICKNET_GENESIS_MS
        + (work.window.plan.selection_round - 1) * QUICKNET_PERIOD_MS
        - 1_000
        * (
            policy.clock.anchor_blocks * policy.clock.target_block_interval_seconds
            + policy.clock.selection_finality_buffer_seconds
        )
    )
    finality.blocks[announcement_height] = replace(
        finality.blocks[announcement_height],
        timestamp_ms=announcement_timestamp_ms,
    )
    collected = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=finality,
        proofs=_FakeProofs(values),
    )(work)
    loaded = _write_bundle(tmp_path / "candidate", policy, work.window.plan)
    monkeypatch.setattr(
        "umi.publisher_availability.inspect_media_pinned",
        _fake_inspect_factory(policy),
    )
    monkeypatch.setattr(
        "umi.validator_closing_snapshot.bittensor_core.Runtime",
        lambda *_args, **_kwargs: _FakeRuntime(),
    )
    proof = json.loads(collected.announcement_proof_evidence_bytes)
    observation = VerifiedQualificationObservation(
        block_number=proof["finality"]["block_number"],
        block_hash=proof["finality"]["block_hash"],
        finality_evidence_bytes=FINALITY,
    )
    return policy, work, loaded, collected, observation


def _genesis_state_bytes(tmp_path) -> bytes:
    path = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(path) as store:
        return encode_protocol_state_snapshot(store.audit())


def _genesis_continuity(state_bytes: bytes, *, loaded, policy) -> bytes:
    return protocol_state_genesis_evidence(
        protocol_state_bytes=state_bytes,
        protocol_state=decode_protocol_state_snapshot(state_bytes),
        window_id=loaded.manifest.window.window_id,
        policy_hash=scoring_policy_hash(policy),
    )


def _prior_continuity(state_bytes: bytes, *, policy) -> bytes:
    state = decode_protocol_state_snapshot(state_bytes)
    assert state.last_window_id is not None
    return canonical_json_bytes(
        {
            "schema": "umi-validator-prior-window-readiness/1",
            "protocol": "umi-asl/0.1",
            "window_id": state.last_window_id.hex(),
            "window_index": state.last_window_index,
            "reveal_round": state.spent_registry.last_reveal_round,
            "scoring_policy_hash": scoring_policy_hash(policy),
            "terminal_outcome": "calibration_no_weight",
            "terminal_stage": "commit_and_terminal_state",
            "terminal_stage_evidence_sha256": "11" * 32,
            "reveal_stage_evidence_sha256": "22" * 32,
            "bundle_manifest_sha256": "33" * 32,
            "audit_release_block": 123,
            "audit_release_block_hash": "0x" + "44" * 32,
            "audit_release_state_root": "0x" + "55" * 32,
            "finality_verifier_sha256": "66" * 32,
            "finality_evidence_sha256": "77" * 32,
            "protocol_state_digest": state.state_digest.hex(),
            "spent_root": state.spent_registry.root.hex(),
            "spent_last_reveal_round": state.spent_registry.last_reveal_round,
        }
    )


@pytest.mark.asyncio
async def test_proof_authority_replays_complete_permit_set_and_protocol_state(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _work_item, loaded, collected, observation = await _proof_material(
        tmp_path,
        monkeypatch,
    )
    validator = next(
        item.validator_hotkey
        for item in collected.announcement_snapshot.validators
        if item.validator_permit
    )
    state_bytes = _genesis_state_bytes(tmp_path)
    authorized = authorize_candidate_qualification(
        loaded=loaded,
        policy=policy,
        validator_hotkey=validator,
        announcement_snapshot_bytes=collected.announcement_snapshot_bytes,
        announcement_proof_evidence_bytes=collected.announcement_proof_evidence_bytes,
        protocol_state_bytes=state_bytes,
        protocol_state_continuity_evidence_bytes=_genesis_continuity(
            state_bytes,
            loaded=loaded,
            policy=policy,
        ),
        observation=observation,
        storage_proof_verifier=lambda **_kwargs: True,
        finality_verifier=lambda **_kwargs: True,
        finality_verifier_sha256=FINALITY_VERIFIER,
    )

    expected_active = sorted(
        (
            item.validator_hotkey
            for item in collected.announcement_snapshot.validators
            if item.validator_permit
        ),
        key=account_id32,
    )
    assert authorized.authority.context.active_validator_hotkeys == expected_active
    assert authorized.authority.context.spent_leaves == []
    assert len(authorized.authority.authority_objects) == 5


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["omit_validator", "fake_permit"])
async def test_tampered_announcement_set_fails_before_signing(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
    mutation: str,
) -> None:
    policy, _work_item, loaded, collected, observation = await _proof_material(
        tmp_path,
        monkeypatch,
    )
    validator = next(
        item.validator_hotkey
        for item in collected.announcement_snapshot.validators
        if item.validator_permit
    )
    document = json.loads(collected.announcement_snapshot_bytes)
    if mutation == "omit_validator":
        document["validators"].pop()
    else:
        document["validators"][0]["validator_permit"] = not document["validators"][0][
            "validator_permit"
        ]

    with pytest.raises(
        AvailabilityWorkflowError,
        match="qualification_announcement_authority_invalid",
    ):
        state_bytes = _genesis_state_bytes(tmp_path)
        authorize_candidate_qualification(
            loaded=loaded,
            policy=policy,
            validator_hotkey=validator,
            announcement_snapshot_bytes=canonical_json_bytes(document),
            announcement_proof_evidence_bytes=collected.announcement_proof_evidence_bytes,
            protocol_state_bytes=state_bytes,
            protocol_state_continuity_evidence_bytes=_genesis_continuity(
                state_bytes,
                loaded=loaded,
                policy=policy,
            ),
            observation=observation,
            storage_proof_verifier=lambda **_kwargs: True,
            finality_verifier=lambda **_kwargs: True,
            finality_verifier_sha256=FINALITY_VERIFIER,
        )


@pytest.mark.asyncio
async def test_complete_protocol_state_exposes_hidden_spent_video_before_signing(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, work, loaded, collected, observation = await _proof_material(
        tmp_path,
        monkeypatch,
        window_index=1,
    )
    validator = next(
        item.validator_hotkey
        for item in collected.announcement_snapshot.validators
        if item.validator_permit
    )
    video = next(item for item in loaded.manifest.objects if item.kind == "video")
    state_path = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(state_path) as store:
        store.apply_window(
            operation_id=hashlib.sha256(b"prior-operation").digest(),
            window_index=0,
            window_id=hashlib.sha256(b"prior-window").digest(),
            reveal_round=work.window.plan.reveal_round - 1,
            evidence_digest=hashlib.sha256(b"prior-evidence").digest(),
            spent_cohort_batches=(
                SpentCohortBatch(
                    batch_commitment=hashlib.sha256(b"prior-batch").digest(),
                    video_hashes=(bytes.fromhex(video.sha256),),
                    frame_digests=(hashlib.sha256(b"prior-frame").digest(),),
                    revealed_script_hashes=(hashlib.sha256(b"prior-script").digest(),),
                ),
            ),
            objective_fault_findings=(),
            scored_batches=(),
            issued_miner_roots=(),
            policy_limits=ProtocolStatePolicyLimits(
                rolling_batch_count=policy.limits.rolling_batch_count,
                score_max_age_windows=policy.limits.score_max_age_windows,
                publisher_fault_cooldown_windows=(policy.limits.publisher_fault_cooldown_windows),
            ),
        )
        state_bytes = encode_protocol_state_snapshot(store.audit())

    with pytest.raises(AvailabilityWorkflowError, match="candidate_public_content_spent"):
        authorize_candidate_qualification(
            loaded=loaded,
            policy=policy,
            validator_hotkey=validator,
            announcement_snapshot_bytes=collected.announcement_snapshot_bytes,
            announcement_proof_evidence_bytes=collected.announcement_proof_evidence_bytes,
            protocol_state_bytes=state_bytes,
            protocol_state_continuity_evidence_bytes=_prior_continuity(
                state_bytes,
                policy=policy,
            ),
            observation=observation,
            storage_proof_verifier=lambda **_kwargs: True,
            finality_verifier=lambda **_kwargs: True,
            finality_verifier_sha256=FINALITY_VERIFIER,
        )


@pytest.mark.asyncio
async def test_fresh_empty_protocol_database_cannot_authorize_a_later_window(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, _work_item, loaded, collected, observation = await _proof_material(
        tmp_path,
        monkeypatch,
        window_index=1,
    )
    validator = next(
        item.validator_hotkey
        for item in collected.announcement_snapshot.validators
        if item.validator_permit
    )
    state_bytes = _genesis_state_bytes(tmp_path)
    continuity = protocol_state_genesis_evidence(
        protocol_state_bytes=state_bytes,
        protocol_state=decode_protocol_state_snapshot(state_bytes),
        window_id=loaded.manifest.window.window_id,
        policy_hash=scoring_policy_hash(policy),
    )

    with pytest.raises(
        AvailabilityWorkflowError,
        match="qualification_protocol_state_not_reconciled",
    ):
        authorize_candidate_qualification(
            loaded=loaded,
            policy=policy,
            validator_hotkey=validator,
            announcement_snapshot_bytes=collected.announcement_snapshot_bytes,
            announcement_proof_evidence_bytes=collected.announcement_proof_evidence_bytes,
            protocol_state_bytes=state_bytes,
            protocol_state_continuity_evidence_bytes=continuity,
            observation=observation,
            storage_proof_verifier=lambda **_kwargs: True,
            finality_verifier=lambda **_kwargs: True,
            finality_verifier_sha256=FINALITY_VERIFIER,
        )


@pytest.mark.asyncio
async def test_substituted_prior_readiness_cannot_authorize_protocol_state(
    tmp_path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy, work, loaded, collected, observation = await _proof_material(
        tmp_path,
        monkeypatch,
        window_index=1,
    )
    validator = next(
        item.validator_hotkey
        for item in collected.announcement_snapshot.validators
        if item.validator_permit
    )
    state_path = (tmp_path / "protocol-state.sqlite3").absolute()
    with ValidatorProtocolStateStore(state_path) as store:
        store.apply_window(
            operation_id=hashlib.sha256(b"prior-empty-operation").digest(),
            window_index=0,
            window_id=hashlib.sha256(b"prior-empty-window").digest(),
            reveal_round=work.window.plan.reveal_round - 1,
            evidence_digest=hashlib.sha256(b"prior-empty-evidence").digest(),
            spent_cohort_batches=(),
            objective_fault_findings=(),
            scored_batches=(),
            issued_miner_roots=(),
            policy_limits=ProtocolStatePolicyLimits(
                rolling_batch_count=policy.limits.rolling_batch_count,
                score_max_age_windows=policy.limits.score_max_age_windows,
                publisher_fault_cooldown_windows=(policy.limits.publisher_fault_cooldown_windows),
            ),
        )
        state_bytes = encode_protocol_state_snapshot(store.audit())
    continuity = json.loads(_prior_continuity(state_bytes, policy=policy))
    continuity["protocol_state_digest"] = "ff" * 32

    with pytest.raises(
        AvailabilityWorkflowError,
        match="qualification_protocol_state_continuity_mismatch",
    ):
        authorize_candidate_qualification(
            loaded=loaded,
            policy=policy,
            validator_hotkey=validator,
            announcement_snapshot_bytes=collected.announcement_snapshot_bytes,
            announcement_proof_evidence_bytes=collected.announcement_proof_evidence_bytes,
            protocol_state_bytes=state_bytes,
            protocol_state_continuity_evidence_bytes=canonical_json_bytes(continuity),
            observation=observation,
            storage_proof_verifier=lambda **_kwargs: True,
            finality_verifier=lambda **_kwargs: True,
            finality_verifier_sha256=FINALITY_VERIFIER,
        )
