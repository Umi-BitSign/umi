from __future__ import annotations

import asyncio
import hashlib
import os
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

import bittensor as bt
import pytest

from umi.encoding import account_id32
from umi.policy import (
    PolicyImplementationPins,
    PublisherControlGroup,
    PublisherRegistryEntry,
    ScoringPolicy,
    ValidatorRegistryEntry,
    scoring_policy_hash,
)
from umi.validator_plans import (
    DeterministicWindowPlanSource,
    ObservationCacheError,
    ObservationCacheLimits,
    ObservationConflict,
    PlanPolicyError,
    PlanStateError,
    ReadinessPortError,
    VerifiedBlockPortError,
    VerifiedFinalizedBlock,
    VerifiedPriorWindowCheckpoint,
)
from umi.validator_state import TerminalOutcome, ValidatorControlPlane, WindowPlan
from umi.window import QUICKNET_GENESIS_MS, WindowClock

FINALITY_DIGEST = "1f" * 32


def _address(uri: str) -> str:
    return bt.sp_core.Keypair.create_from_uri(uri).ss58_address


def _live_policy(*, activation_block: int = 1_000) -> ScoringPolicy:
    group_rows = [(f"{index:064x}", _address(f"//Group{index}")) for index in range(1, 4)]
    groups = [
        PublisherControlGroup(control_group_id=group_id, administrator=administrator)
        for group_id, administrator in group_rows
    ]
    publishers = [
        PublisherRegistryEntry(
            publisher_hotkey=_address(f"//Publisher{index}"),
            owner_coldkey=administrator,
            control_group_id=group_id,
        )
        for index, (group_id, administrator) in enumerate(group_rows, start=1)
    ]
    publishers.sort(key=lambda item: account_id32(item.publisher_hotkey))
    validators = [
        ValidatorRegistryEntry(
            validator_hotkey=_address(f"//Validator{index}"),
            administrator_id=f"{100 + index:064x}",
        )
        for index in range(4)
    ]
    validators.sort(key=lambda item: account_id32(item.validator_hotkey))
    policy = ScoringPolicy.launch(
        translation_weights_active=False,
        activation_block=activation_block,
        minimum_publisher_collateral_alpha_rao=1_000_000_000,
        soak_start_window_index=7,
        validator_capacity_set_root="aa" * 32,
        validator_cost_schedule_hash="bb" * 32,
        implementation_pins=PolicyImplementationPins.local_rehearsal(),
        validator_registry=validators,
        control_group_registry=groups,
        publisher_registry=publishers,
    )
    data = policy.model_dump(mode="json", by_alias=True)
    pins = data["implementation_pins"]
    pins["pin_profile"] = "live_shadow_calibration"
    pins["conformance_fixtures_verified"] = True
    pins["conformance_execution_report_sha256"] = "0f" * 32
    pins["scoring"]["normalization_fixture_set_sha256"] = "10" * 32
    pins["media"]["frame_digest_fixture_set_sha256"] = "11" * 32
    pins["timelock"]["portable_envelope_fixture_set_sha256"] = "12" * 32
    pins["chain"]["chain_fixture_set_sha256"] = "13" * 32
    pins["rules"]["mirror_discovery_rule_sha256"] = "14" * 32
    pins["live_chain"] = {
        "network": "finney",
        "genesis_block_hash": "15" * 32,
        "runtime_spec_version": 452,
        "transaction_version": 1,
        "state_version": 1,
        "metadata_sha256": "16" * 32,
        "subtensor_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "live_chain_fixture_set_sha256": "17" * 32,
    }
    pins["storage_proof_verifier"] = {
        "protocol": "umi-substrate-proof-verifier/1",
        "polkadot_sdk_revision": "cacb4310f20c7cac83eb3ccd8ed5a5ad4212608a",
        "source_tree_sha256": "18" * 32,
        "cargo_lock_sha256": "19" * 32,
        "proof_fixture_set_sha256": "1a" * 32,
        "release_sha256_by_target": {"aarch64-apple-darwin": "1b" * 32},
    }
    pins["finality_verifier"] = {
        "profile": "smoldot-verifier-attested-finality/1",
        "evidence_class": "verifier_attested_finality",
        "offline_finality_proof": False,
        "source_revision": "finality-verifier-v1",
        "source_tree_sha256": "1d" * 32,
        "cargo_lock_sha256": "1e" * 32,
        "finality_fixture_set_sha256": "1f" * 32,
        "release_sha256_by_target": {"aarch64-apple-darwin": FINALITY_DIGEST},
        "chain_spec_source_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "chain_spec_sha256": "20" * 32,
        "expected_genesis_hash": "15" * 32,
        "bootstrap_kind": "grandpa_warp_sync_checkpoint",
        "bootstrap_block_number": 1,
        "bootstrap_block_hash": "24" * 32,
    }
    return ScoringPolicy.model_validate(data)


def _block(
    policy: ScoringPolicy,
    index: int,
    *,
    block_byte: str | None = None,
    timestamp_ms: int | None = None,
    policy_hash: str | None = None,
    finality_digest: str = FINALITY_DIGEST,
    chain_observation=None,
    evidence: bytes | None = None,
    height: int | None = None,
) -> VerifiedFinalizedBlock:
    block_byte = block_byte or f"{index + 1:02x}"
    evidence = evidence or f"verified-grandpa-justification-{index}".encode()
    return VerifiedFinalizedBlock(
        height=(
            height
            if height is not None
            else policy.activation_block + index * policy.clock.window_stride_blocks
        ),
        block_hash="0x" + block_byte * 32,
        state_root="0x" + f"{index + 101:02x}" * 32,
        timestamp_ms=(
            timestamp_ms
            if timestamp_ms is not None
            else QUICKNET_GENESIS_MS
            + 10_000_000
            + index
            * policy.clock.window_stride_blocks
            * policy.clock.target_block_interval_seconds
            * 1_000
        ),
        scoring_policy_hash=policy_hash or scoring_policy_hash(policy),
        chain_observation=chain_observation or policy.implementation_pins.live_chain,
        finality_verifier_sha256=finality_digest,
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )


def _checkpoint(previous, *, evidence: bytes = b"verified-reveal-and-spent"):
    block_height = max(
        previous.plan.closing_block + 1,
        previous.audit_release_block or 0,
    )
    return VerifiedPriorWindowCheckpoint(
        window_id=previous.plan.window_id,
        window_index=previous.plan.window_index,
        reveal_round=previous.plan.reveal_round,
        spent_root="ab" * 32,
        checkpoint_block_height=block_height,
        checkpoint_block_hash="0x" + "cd" * 32,
        checkpoint_state_root="0x" + "de" * 32,
        evidence=evidence,
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )


@dataclass
class FinalizedPort:
    head: int
    blocks: dict[int, object]
    head_calls: int = 0
    block_calls: list[int] = field(default_factory=list)
    entered: asyncio.Event | None = None
    release: asyncio.Event | None = None
    active: int = 0
    maximum_active: int = 0

    async def finalized_head_height(self):
        self.head_calls += 1
        return self.head

    async def verified_block_at(self, height: int):
        self.active += 1
        self.maximum_active = max(self.maximum_active, self.active)
        try:
            self.block_calls.append(height)
            if self.entered is not None and len(self.block_calls) == 1:
                self.entered.set()
                if self.release is None:
                    raise RuntimeError("blocking port has no release event")
                await self.release.wait()
            value = self.blocks.get(height)
            if isinstance(value, list):
                return value.pop(0)
            return value
        finally:
            self.active -= 1


@dataclass
class ReadinessPort:
    values: list[object] = field(default_factory=list)
    calls: list[str] = field(default_factory=list)

    async def verified_reveal_and_spent(self, previous):
        self.calls.append(previous.plan.window_id)
        return self.values.pop(0) if self.values else None


def _source(
    tmp_path: Path,
    *,
    policy: ScoringPolicy,
    control: ValidatorControlPlane,
    port: object,
    readiness: object | None = None,
    cache_name: str = "observations.sqlite3",
    limits: ObservationCacheLimits | None = None,
) -> DeterministicWindowPlanSource:
    return DeterministicWindowPlanSource(
        policy=policy,
        control_plane=control,
        finalized_blocks=port,  # type: ignore[arg-type]
        prior_readiness=readiness or ReadinessPort(),  # type: ignore[arg-type]
        observation_cache_path=tmp_path / cache_name,
        cache_limits=limits,
    )


def _clock(policy: ScoringPolicy) -> WindowClock:
    return WindowClock(
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


@pytest.mark.asyncio
async def test_plan_waits_for_head_then_repeats_exact_window_clock_derivation(
    tmp_path: Path,
) -> None:
    policy = _live_policy()
    block = _block(policy, 0)
    port = FinalizedPort(head=policy.activation_block - 1, blocks={block.height: block})
    readiness = ReadinessPort()
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=port,
        readiness=readiness,
    )

    assert await source.next_plan() is None
    assert port.block_calls == []
    port.head = policy.activation_block
    first = await source.next_plan()
    second = await source.next_plan()

    expected = WindowPlan.from_schedule(
        _clock(policy).derive(
            0,
            netuid=policy.netuid,
            announcement_block_hash=block.block_hash,
            announcement_timestamp_ms=block.timestamp_ms,
            scoring_policy_hash=scoring_policy_hash(policy),
        ),
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    assert first == second == expected
    assert first is not None and first.announcement_block == policy.activation_block
    assert port.block_calls == [policy.activation_block, policy.activation_block]
    assert readiness.calls == []
    assert control.list_windows() == ()
    mode = os.stat(tmp_path / "observations.sqlite3").st_mode
    assert mode & 0o022 == 0


@pytest.mark.asyncio
async def test_pending_observation_survives_restart_and_detects_header_drift(
    tmp_path: Path,
) -> None:
    policy = _live_policy()
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    original = _block(policy, 0)
    first = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(original.height, {original.height: original}),
    )
    expected = await first.next_plan()

    restarted = _source(
        tmp_path,
        policy=policy,
        control=ValidatorControlPlane(tmp_path / "validator.sqlite3"),
        port=FinalizedPort(original.height, {original.height: original}),
    )
    assert await restarted.next_plan() == expected

    changed = _block(policy, 0, block_byte="ff")
    adversarial = _source(
        tmp_path,
        policy=policy,
        control=ValidatorControlPlane(tmp_path / "validator.sqlite3"),
        port=FinalizedPort(original.height, {original.height: changed}),
    )
    with pytest.raises(ObservationConflict, match="changed"):
        await adversarial.next_plan()


@pytest.mark.asyncio
async def test_finalized_head_regression_is_rejected_across_restart(tmp_path: Path) -> None:
    policy = _live_policy()
    block = _block(policy, 0)
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block.height, {block.height: block}),
    )
    assert await source.next_plan() is not None

    regressed = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block.height - 1, {block.height: block}),
    )
    with pytest.raises(ObservationConflict, match="regressed"):
        await regressed.next_plan()


@pytest.mark.asyncio
async def test_prior_terminal_window_requires_exact_reveal_and_spent_checkpoint(
    tmp_path: Path,
) -> None:
    policy = _live_policy()
    block0 = _block(policy, 0)
    block1 = _block(policy, 1)
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    initial = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block0.height, {block0.height: block0}),
    )
    plan0 = await initial.next_plan()
    assert plan0 is not None
    control.start_window(plan0, operation_id="start-0")
    control.terminate_window(
        plan0.window_id,
        outcome=TerminalOutcome.VOID,
        reason_code="canary_hit",
        evidence_sha256="cc" * 32,
        audit_release_block=plan0.closing_block + 10,
        operation_id="void-0",
    )
    previous = control.get_window(plan0.window_id)
    readiness = ReadinessPort([None, _checkpoint(previous)])
    port = FinalizedPort(block1.height, {block1.height: block1})
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=port,
        readiness=readiness,
    )

    assert await source.next_plan() is None
    assert port.head_calls == 0
    plan1 = await source.next_plan()

    assert plan1 is not None and plan1.window_index == 1
    assert plan1.announcement_block == block1.height
    assert readiness.calls == [plan0.window_id, plan0.window_id]
    assert port.block_calls == [block1.height]


@pytest.mark.asyncio
async def test_mismatched_readiness_checkpoint_is_rejected(tmp_path: Path) -> None:
    policy = _live_policy()
    block0 = _block(policy, 0)
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    first = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block0.height, {block0.height: block0}),
    )
    plan = await first.next_plan()
    assert plan is not None
    control.start_window(plan, operation_id="start")
    control.terminate_window(
        plan.window_id,
        outcome=TerminalOutcome.SKIPPED,
        reason_code="resource_limit",
        operation_id="skip",
    )
    previous = control.get_window(plan.window_id)
    checkpoint = _checkpoint(previous)
    wrong = VerifiedPriorWindowCheckpoint(
        window_id="ff" * 32,
        window_index=checkpoint.window_index,
        reveal_round=checkpoint.reveal_round,
        spent_root=checkpoint.spent_root,
        checkpoint_block_height=checkpoint.checkpoint_block_height,
        checkpoint_block_hash=checkpoint.checkpoint_block_hash,
        checkpoint_state_root=checkpoint.checkpoint_state_root,
        evidence=checkpoint.evidence,
        evidence_sha256=checkpoint.evidence_sha256,
    )
    next_block = _block(policy, 1)
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(next_block.height, {next_block.height: next_block}),
        readiness=ReadinessPort([wrong]),
    )

    with pytest.raises(ReadinessPortError, match="another window"):
        await source.next_plan()


@pytest.mark.asyncio
async def test_active_window_is_refused_without_calling_ports(tmp_path: Path) -> None:
    policy = _live_policy()
    block = _block(policy, 0)
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block.height, {block.height: block}),
    )
    plan = await source.next_plan()
    assert plan is not None
    control.start_window(plan, operation_id="start")
    port = FinalizedPort(block.height, {block.height: block})
    restarted = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=port,
    )

    with pytest.raises(PlanStateError, match="active"):
        await restarted.next_plan()
    assert port.head_calls == 0


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "case, error",
    [
        ("missing_block", VerifiedBlockPortError),
        ("wrong_height", VerifiedBlockPortError),
        ("wrong_policy", PlanPolicyError),
        ("wrong_runtime", PlanPolicyError),
        ("wrong_verifier", PlanPolicyError),
    ],
)
async def test_verified_block_port_bindings_fail_closed(
    tmp_path: Path,
    case: str,
    error: type[Exception],
) -> None:
    policy = _live_policy()
    height = policy.activation_block
    value: object = _block(policy, 0)
    if case == "missing_block":
        value = None
    elif case == "wrong_height":
        value = _block(policy, 0, height=height + 1)
    elif case == "wrong_policy":
        value = _block(policy, 0, policy_hash="ff" * 32)
    elif case == "wrong_runtime":
        pin = policy.implementation_pins.live_chain
        assert pin is not None
        value = _block(
            policy,
            0,
            chain_observation=pin.model_copy(
                update={"runtime_spec_version": pin.runtime_spec_version + 1}
            ),
        )
    elif case == "wrong_verifier":
        value = _block(policy, 0, finality_digest="ff" * 32)
    source = _source(
        tmp_path,
        policy=policy,
        control=ValidatorControlPlane(tmp_path / "validator.sqlite3"),
        port=FinalizedPort(height, {height: value}),
    )

    with pytest.raises(error):
        await source.next_plan()


def test_verified_records_enforce_timestamp_and_content_addressed_evidence() -> None:
    policy = _live_policy()
    with pytest.raises(ValueError, match="predates pinned Quicknet"):
        _block(policy, 0, timestamp_ms=QUICKNET_GENESIS_MS - 1)
    evidence = b"evidence"
    with pytest.raises(ValueError, match="digest does not reproduce"):
        VerifiedFinalizedBlock(
            height=policy.activation_block,
            block_hash="0x" + "11" * 32,
            state_root="0x" + "22" * 32,
            timestamp_ms=QUICKNET_GENESIS_MS,
            scoring_policy_hash=scoring_policy_hash(policy),
            chain_observation=policy.implementation_pins.live_chain,
            finality_verifier_sha256=FINALITY_DIGEST,
            finality_evidence=evidence,
            finality_evidence_sha256="00" * 32,
        )


@pytest.mark.asyncio
async def test_source_serializes_concurrent_plan_reads(tmp_path: Path) -> None:
    policy = _live_policy()
    block = _block(policy, 0)
    entered = asyncio.Event()
    release = asyncio.Event()
    port = FinalizedPort(
        block.height,
        {block.height: block},
        entered=entered,
        release=release,
    )
    source = _source(
        tmp_path,
        policy=policy,
        control=ValidatorControlPlane(tmp_path / "validator.sqlite3"),
        port=port,
    )

    first = asyncio.create_task(source.next_plan())
    await entered.wait()
    second = asyncio.create_task(source.next_plan())
    await asyncio.sleep(0)
    assert not second.done()
    release.set()
    first_plan, second_plan = await asyncio.gather(first, second)

    assert first_plan == second_plan
    assert port.maximum_active == 1
    assert port.block_calls == [block.height, block.height]


@pytest.mark.asyncio
async def test_cache_object_and_count_limits_are_enforced(tmp_path: Path) -> None:
    policy = _live_policy()
    block0 = _block(policy, 0, evidence=b"evidence-longer-than-four")
    constrained = ObservationCacheLimits(
        maximum_observations=1,
        maximum_evidence_bytes=4,
        maximum_total_evidence_bytes=4,
        maximum_database_bytes=1024 * 1024,
    )
    source = _source(
        tmp_path,
        policy=policy,
        control=ValidatorControlPlane(tmp_path / "validator.sqlite3"),
        port=FinalizedPort(block0.height, {block0.height: block0}),
        limits=constrained,
    )
    with pytest.raises(ObservationCacheError, match="evidence"):
        await source.next_plan()

    count_root = tmp_path / "count"
    count_root.mkdir()
    control = ValidatorControlPlane(count_root / "validator.sqlite3")
    block0 = _block(policy, 0, evidence=b"one")
    first = _source(
        count_root,
        policy=policy,
        control=control,
        port=FinalizedPort(block0.height, {block0.height: block0}),
        limits=ObservationCacheLimits(
            maximum_observations=1,
            maximum_evidence_bytes=32,
            maximum_total_evidence_bytes=64,
            maximum_database_bytes=1024 * 1024,
        ),
    )
    plan0 = await first.next_plan()
    assert plan0 is not None
    control.start_window(plan0, operation_id="start")
    control.terminate_window(
        plan0.window_id,
        outcome=TerminalOutcome.VOID,
        reason_code="canary_hit",
        operation_id="void",
    )
    previous = control.get_window(plan0.window_id)
    block1 = _block(policy, 1, evidence=b"two")
    second = _source(
        count_root,
        policy=policy,
        control=control,
        port=FinalizedPort(block1.height, {block1.height: block1}),
        readiness=ReadinessPort([_checkpoint(previous)]),
        limits=ObservationCacheLimits(
            maximum_observations=1,
            maximum_evidence_bytes=32,
            maximum_total_evidence_bytes=64,
            maximum_database_bytes=1024 * 1024,
        ),
    )
    with pytest.raises(ObservationCacheError, match="count limit"):
        await second.next_plan()


def test_startup_audit_rejects_tampered_evidence_and_unsafe_paths(tmp_path: Path) -> None:
    policy = _live_policy()
    block = _block(policy, 0)
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block.height, {block.height: block}),
    )
    asyncio.run(source.next_plan())
    database = tmp_path / "observations.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute("UPDATE evidence_objects SET data = ?", (b"tampered",))
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ObservationCacheError, match=r"corrupt|length"):
        _source(
            tmp_path,
            policy=policy,
            control=control,
            port=FinalizedPort(block.height, {block.height: block}),
        )

    symlink_root = tmp_path / "symlink"
    symlink_root.mkdir()
    outside = tmp_path / "outside.sqlite3"
    outside.write_bytes(b"")
    (symlink_root / "observations.sqlite3").symlink_to(outside)
    with pytest.raises(ObservationCacheError, match="symlinks"):
        _source(
            symlink_root,
            policy=policy,
            control=ValidatorControlPlane(symlink_root / "validator.sqlite3"),
            port=FinalizedPort(block.height, {block.height: block}),
        )


def test_startup_audit_rejects_schema_and_finalized_head_tampering(
    tmp_path: Path,
) -> None:
    policy = _live_policy()
    block = _block(policy, 0)
    control = ValidatorControlPlane(tmp_path / "validator.sqlite3")
    source = _source(
        tmp_path,
        policy=policy,
        control=control,
        port=FinalizedPort(block.height, {block.height: block}),
    )
    asyncio.run(source.next_plan())
    database = tmp_path / "observations.sqlite3"
    connection = sqlite3.connect(database)
    try:
        connection.execute(
            "CREATE TRIGGER unexpected_trigger AFTER INSERT ON cache_meta BEGIN SELECT 1; END"
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ObservationCacheError, match="schema objects changed"):
        _source(
            tmp_path,
            policy=policy,
            control=control,
            port=FinalizedPort(block.height, {block.height: block}),
        )

    connection = sqlite3.connect(database)
    try:
        connection.execute("DROP TRIGGER unexpected_trigger")
        connection.execute(
            "UPDATE cache_meta SET value = ? WHERE key = 'highest_finalized_head'",
            (str(block.height - 1),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(ObservationCacheError, match="predates an observation"):
        _source(
            tmp_path,
            policy=policy,
            control=control,
            port=FinalizedPort(block.height, {block.height: block}),
        )


def test_startup_refuses_policy_mismatch_and_nonzero_history_origin(tmp_path: Path) -> None:
    policy = _live_policy()
    wrong_plan = WindowPlan(
        window_id="11" * 32,
        window_index=0,
        scoring_policy_hash="ff" * 32,
        announcement_block=1_000,
        proposal_close_block=1_030,
        closing_block=1_045,
        selection_round=100,
        issue_close_round=110,
        response_close_round=120,
        reveal_round=130,
    )
    wrong_control = ValidatorControlPlane(tmp_path / "wrong.sqlite3")
    wrong_control.start_window(wrong_plan, operation_id="wrong-policy")
    with pytest.raises(PlanPolicyError, match="another scoring policy"):
        _source(
            tmp_path,
            policy=policy,
            control=wrong_control,
            port=FinalizedPort(policy.activation_block, {}),
            cache_name="wrong-cache.sqlite3",
        )

    gap_plan = WindowPlan(
        window_id="22" * 32,
        window_index=5,
        scoring_policy_hash=scoring_policy_hash(policy),
        announcement_block=2_800,
        proposal_close_block=2_830,
        closing_block=2_845,
        selection_round=200,
        issue_close_round=210,
        response_close_round=220,
        reveal_round=230,
    )
    gap_control = ValidatorControlPlane(tmp_path / "gap.sqlite3")
    gap_control.start_window(gap_plan, operation_id="gap")
    with pytest.raises(PlanStateError, match="zero-based complete prefix"):
        _source(
            tmp_path,
            policy=policy,
            control=gap_control,
            port=FinalizedPort(policy.activation_block, {}),
            cache_name="gap-cache.sqlite3",
        )
