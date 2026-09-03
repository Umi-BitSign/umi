from __future__ import annotations

import hashlib
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.encoding import account_id32
from umi.policy import ScoringPolicy, scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator_chain import (
    DecodedStorageClaim,
    FinalizedRuntimePin,
    MultiStorageEvidence,
    PinnedRuntimeContext,
    StorageClaim,
    StorageReadSpec,
    VerifiedStorageBatch,
)
from umi.validator_chain_scan import (
    FinalityAttestationReplayBinding,
    VerifiedFinalizedBlockIdentity,
)
from umi.validator_closing_snapshot import (
    ANNOUNCEMENT_VALIDATOR_EVIDENCE_SCHEMA,
    CLOSING_SNAPSHOT_COLLECTOR_REVISION,
    CLOSING_SNAPSHOT_EVIDENCE_SCHEMA,
    AnnouncementValidatorProofEvidence,
    ClosingSnapshotCollectorError,
    ClosingSnapshotProofEvidence,
    ProofBackedClosingSnapshotCollector,
    replay_announcement_validator_storage,
    replay_closing_snapshot_storage,
    validate_replayed_announcement_validator_snapshot,
    validate_replayed_closing_snapshot,
)
from umi.validator_plans import VerifiedFinalizedBlock
from umi.validator_state import (
    ControlState,
    PauseScope,
    StageWorkItem,
    WindowPlan,
    WindowRecord,
    WindowStage,
)

from .test_shadow import _fixture, _schedule, _wallet

METADATA = b"fake-runtime-metadata-v1"
RUNTIME_VERSION = canonical_json_bytes(
    {"specVersion": 452, "stateVersion": 1, "transactionVersion": 1}
)
FINALITY = canonical_json_bytes({"schema": "test-finality", "sequence": 0})
BLOCK_HASH = "0x" + "44" * 32
PARENT_HASH = "0x" + "33" * 32
STATE_ROOT = "0x" + "55" * 32
PARENT_STATE_ROOT = "0x" + "22" * 32
EXTRINSICS_ROOT = "0x" + "66" * 32
FINALITY_VERIFIER = "77" * 32
ACCEPTANCE_DOMAIN = b"umi-grandpa-finality-supervisor-accept-v2\0"


def _acceptance_receipt(
    *,
    height: int,
    block_hash: str,
    accepted_at_unix_ms: int,
) -> bytes:
    evidence_sha256 = hashlib.sha256(FINALITY).hexdigest()
    previous = bytes(32)
    acceptance_digest = hashlib.sha256(
        ACCEPTANCE_DOMAIN
        + previous
        + height.to_bytes(8, "big")
        + bytes.fromhex(block_hash[2:])
        + bytes.fromhex(evidence_sha256)
        + (0).to_bytes(8, "big")
        + (0).to_bytes(8, "big")
        + b"\x00"
        + accepted_at_unix_ms.to_bytes(8, "big")
    ).hexdigest()
    return canonical_json_bytes(
        {
            "schema": "umi-grandpa-finality-acceptance/1",
            "height": height,
            "block_hash": block_hash,
            "evidence_sha256": evidence_sha256,
            "segment_index": 0,
            "segment_sequence": 0,
            "restart_gap_before": False,
            "accepted_at_unix_ms": accepted_at_unix_ms,
            "previous_acceptance_digest": previous.hex(),
            "acceptance_digest": acceptance_digest,
        }
    )


def _live_policy() -> ScoringPolicy:
    rehearsal, _signers = _fixture()
    data = rehearsal.policy.model_dump(mode="json", by_alias=True)
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
        "metadata_sha256": hashlib.sha256(METADATA).hexdigest(),
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
        "source_revision": "test-finality-v1",
        "source_tree_sha256": "1d" * 32,
        "cargo_lock_sha256": "1e" * 32,
        "finality_fixture_set_sha256": "1f" * 32,
        "release_sha256_by_target": {"aarch64-apple-darwin": FINALITY_VERIFIER},
        "chain_spec_source_revision": "da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        "chain_spec_sha256": "20" * 32,
        "expected_genesis_hash": "15" * 32,
        "bootstrap_kind": "grandpa_warp_sync_checkpoint",
        "bootstrap_block_number": 1,
        "bootstrap_block_hash": "24" * 32,
    }
    return ScoringPolicy.model_validate(data)


def _work(policy: ScoringPolicy) -> StageWorkItem:
    announcement_timestamp, schedule = _schedule(policy)
    del announcement_timestamp
    plan = WindowPlan.from_schedule(
        schedule,
        scoring_policy_hash=scoring_policy_hash(policy),
    )
    return StageWorkItem(
        window=WindowRecord(
            plan=plan,
            stage=WindowStage.POOL_AND_SELECTION,
            terminal_outcome=None,
            terminal_reason_code=None,
            terminal_evidence_sha256=None,
            audit_release_block=None,
            created_at_unix_ns=1,
            updated_at_unix_ns=1,
            revision=0,
        ),
        completed_evidence=(),
        controls=tuple(ControlState(scope=scope, active_holds=()) for scope in PauseScope),
    )


class _FakeRuntime:
    def storage_key(self, pallet: str, item: str, params: list[object]) -> bytes:
        return hashlib.sha256(
            b"test-storage-key-v1\0"
            + canonical_json_bytes({"item": item, "pallet": pallet, "params": params})
        ).digest()

    def storage_entry(self, _pallet: str, item: str):
        optional = {
            "Axons",
            "CommitmentOf",
            "HotkeyRoot",
            "HotkeySuccessor",
            "MinerCollateral",
            "Uids",
        }
        return SimpleNamespace(
            modifier="Optional" if item in optional else "Default",
            default_bytes=canonical_json_bytes(False),
            value_type=item,
        )

    def decode(self, _value_type: str, encoded: bytes, *, strict: bool) -> object:
        assert strict
        return json.loads(encoded)

    def constant(self, pallet: str, name: str) -> int:
        assert (pallet, name) == ("System", "SS58Prefix")
        return 42


class _FakeProofs:
    def __init__(self, values: dict[tuple[str, str, tuple[object, ...]], object]) -> None:
        self.values = values
        self.runtime: PinnedRuntimeContext | None = None
        self.calls: list[tuple[StorageReadSpec, ...]] = []
        self.batch_index = 0

    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext:
        self.runtime = PinnedRuntimeContext(
            snapshot=snapshot,
            pin=pin,
            metadata_bytes=METADATA,
            runtime_version_bytes=RUNTIME_VERSION,
            _runtime=_FakeRuntime(),
        )
        return self.runtime

    async def storage_reads(
        self,
        runtime: PinnedRuntimeContext,
        specs: tuple[StorageReadSpec, ...],
    ) -> VerifiedStorageBatch:
        assert runtime is self.runtime
        self.calls.append(specs)
        keyed = sorted(
            ((runtime.storage_key(spec.pallet, spec.item, spec.params), spec) for spec in specs),
            key=lambda item: item[0],
        )
        claims: list[StorageClaim] = []
        reads: list[DecodedStorageClaim] = []
        for key, spec in keyed:
            value = self.values[(spec.pallet, spec.item, spec.params)]
            raw = None if value is None else canonical_json_bytes(value)
            claims.append(StorageClaim(storage_key=key, value=raw))
            reads.append(
                DecodedStorageClaim(
                    spec=spec,
                    storage_key=key,
                    raw_value=raw,
                    decoded_value=value,
                )
            )
        self.batch_index += 1
        evidence = MultiStorageEvidence(
            snapshot=runtime.snapshot,
            claims=claims,
            proof=(f"proof-{self.batch_index}".encode(),),
            verifier=lambda **_kwargs: True,
        )
        return VerifiedStorageBatch(runtime=runtime, evidence=evidence, reads=tuple(reads))


class _HeightAwareProofs(_FakeProofs):
    def __init__(
        self,
        values_by_height: dict[int, dict[tuple[str, str, tuple[object, ...]], object]],
    ) -> None:
        self.values_by_height = values_by_height
        super().__init__(next(iter(values_by_height.values())))

    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext:
        self.values = self.values_by_height[snapshot.block_number]
        return await super().pinned_runtime(snapshot, pin)


class _Finality:
    def __init__(self, policy: ScoringPolicy, work: StageWorkItem) -> None:
        live = policy.implementation_pins.live_chain
        assert live is not None
        self.identities = {}
        self.blocks = {}
        self.bindings = {}
        self.acceptance_receipts = {}
        publication_ms = 1_692_803_367_000 + (work.window.plan.selection_round - 1) * 3_000
        for height, block_hash, parent_hash, state_root, timestamp_ms, accepted_at in (
            (
                work.window.plan.announcement_block,
                "0x" + "aa" * 32,
                "0x" + "a9" * 32,
                "0x" + "ab" * 32,
                publication_ms - 10_000,
                publication_ms - 2_000,
            ),
            (
                work.window.plan.closing_block,
                BLOCK_HASH,
                PARENT_HASH,
                STATE_ROOT,
                publication_ms - 5_000,
                publication_ms - 1,
            ),
        ):
            parent = FinalizedSnapshotRef(
                block_number=height - 1,
                block_hash=parent_hash,
                parent_hash="0x" + "11" * 32,
                state_root=PARENT_STATE_ROOT,
            )
            snapshot = FinalizedSnapshotRef(
                block_number=height,
                block_hash=block_hash,
                parent_hash=parent_hash,
                state_root=state_root,
            )
            self.identities[height] = VerifiedFinalizedBlockIdentity(
                snapshot=snapshot,
                parent_snapshot=parent,
                extrinsics_root=EXTRINSICS_ROOT,
                finality_verifier_sha256=FINALITY_VERIFIER,
                finality_evidence_sha256=hashlib.sha256(FINALITY).hexdigest(),
            )
            self.blocks[height] = VerifiedFinalizedBlock(
                height=height,
                block_hash=block_hash,
                state_root=state_root,
                timestamp_ms=timestamp_ms,
                scoring_policy_hash=scoring_policy_hash(policy),
                chain_observation=live,
                finality_verifier_sha256=FINALITY_VERIFIER,
                finality_evidence=FINALITY,
                finality_evidence_sha256=hashlib.sha256(FINALITY).hexdigest(),
            )
            self.bindings[height] = FinalityAttestationReplayBinding(
                minimum_finalized_block=height,
                maximum_records=10,
                startup_timeout_seconds=60,
                expected_sequence=0,
                previous_number=None,
                previous_timestamp_ms=None,
            )
            self.acceptance_receipts[height] = _acceptance_receipt(
                height=height,
                block_hash=block_hash,
                accepted_at_unix_ms=accepted_at,
            )
        self.block_value = self.blocks[work.window.plan.closing_block]

    async def verified_block_at(self, height: int):
        if height == self.block_value.height:
            return self.block_value
        return self.blocks.get(height)

    async def verified_scan_interval(self, start_height: int, end_height: int):
        assert start_height == end_height
        height = start_height
        return SimpleNamespace(
            identities=(self.identities[height],),
            attestations=(FINALITY,),
            replay_bindings=(self.bindings[height],),
            acceptance_receipts=(self.acceptance_receipts[height],),
        )

    async def verified_acceptance_time_at(self, height: int):
        return json.loads(self.acceptance_receipts[height])["accepted_at_unix_ms"]

    async def verified_acceptance_receipt_at(self, height: int):
        return self.acceptance_receipts.get(height)


def _values(policy: ScoringPolicy, work: StageWorkItem) -> tuple[dict, list[str], str]:
    miner = _wallet("//ClosingSnapshotMiner").hotkey.ss58_address
    root = _wallet("//ClosingSnapshotRoot").hotkey.ss58_address
    hotkeys = [
        *(item.publisher_hotkey for item in policy.publisher_registry),
        *(item.validator_hotkey for item in policy.validator_registry),
        miner,
    ]
    assert len({account_id32(value) for value in hotkeys}) == len(hotkeys)
    permits = [False] * len(hotkeys)
    validator_accounts = {account_id32(item.validator_hotkey) for item in policy.validator_registry}
    for uid, hotkey in enumerate(hotkeys):
        permits[uid] = account_id32(hotkey) in validator_accounts
    values: dict[tuple[str, str, tuple[object, ...]], object] = {
        ("SubtensorModule", "NetworksAdded", (78,)): True,
        ("SubtensorModule", "SubnetworkN", (78,)): len(hotkeys),
        ("SubtensorModule", "ValidatorPermit", (78,)): permits,
    }
    for uid, hotkey in enumerate(hotkeys):
        values[("SubtensorModule", "Keys", (78, uid))] = hotkey
        values[("SubtensorModule", "Uids", (78, hotkey))] = uid
        values[("SubtensorModule", "HotkeyRoot", (78, hotkey))] = root if hotkey == miner else None
        values[("SubtensorModule", "HotkeySuccessor", (78, hotkey))] = None
        values[("SubtensorModule", "Axons", (78, hotkey))] = (
            {
                "block": work.window.plan.closing_block - 1,
                "version": 1,
                "ip": int.from_bytes(bytes((203, 0, 113, 8)), "big"),
                "port": 8091,
                "ip_type": 4,
                "protocol": 4,
                "placeholder1": 0,
                "placeholder2": 0,
            }
            if hotkey == miner
            else None
        )
    for index, entry in enumerate(policy.publisher_registry):
        values[("SubtensorModule", "Owner", (entry.publisher_hotkey,))] = entry.owner_coldkey
        values[
            (
                "SubtensorModule",
                "MinerCollateral",
                (78, entry.publisher_hotkey, entry.owner_coldkey),
            )
        ] = {
            "locked": policy.minimum_publisher_collateral_alpha_rao + index,
            "drain_ratio": 0,
            "min_locked": policy.minimum_publisher_collateral_alpha_rao,
            "earned": 0,
        }
        values[("Commitments", "CommitmentOf", (78, entry.publisher_hotkey))] = {
            "deposit": 0,
            "block": work.window.plan.closing_block,
            "info": {"fields": [{"Sha256": "0x" + f"{index + 1:064x}"}]},
        }
    return values, hotkeys, root


@pytest.mark.asyncio
async def test_collector_proves_complete_snapshot_and_retains_replay_inputs() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, hotkeys, root = _values(policy, work)
    proofs = _FakeProofs(values)
    result = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=proofs,
        maximum_storage_keys_per_proof=3,
    )(work)

    snapshot = result.snapshot
    assert snapshot.collector_revision == CLOSING_SNAPSHOT_COLLECTOR_REVISION
    assert snapshot.closing_block_hash == BLOCK_HASH
    assert [item.hotkey for item in snapshot.neurons] == hotkeys
    assert snapshot.neurons[-1].root == root
    assert snapshot.neurons[-1].serving_url == "https://203.0.113.8:8091"
    assert sum(item.validator_permit for item in snapshot.validators) == 4
    assert all(item.registered for item in snapshot.publishers)
    assert all(
        item.locked_collateral_alpha_rao >= policy.minimum_publisher_collateral_alpha_rao
        for item in snapshot.publishers
    )
    assert [item.pool_manifest_sha256 for item in snapshot.publishers] == [
        f"{index + 1:064x}" for index in range(len(policy.publisher_registry))
    ]
    evidence = ClosingSnapshotProofEvidence.model_validate_json(result.proof_evidence_bytes)
    assert evidence.schema_ == CLOSING_SNAPSHOT_EVIDENCE_SCHEMA
    assert evidence.total_unique_storage_keys == sum(
        len(batch.claims) for batch in evidence.proof_batches
    )
    announcement_evidence = AnnouncementValidatorProofEvidence.model_validate_json(
        result.announcement_proof_evidence_bytes
    )
    assert announcement_evidence.schema_ == ANNOUNCEMENT_VALIDATOR_EVIDENCE_SCHEMA
    assert announcement_evidence.total_unique_storage_keys == sum(
        len(batch.claims) for batch in announcement_evidence.proof_batches
    )
    assert (
        len(evidence.proof_batches) + len(announcement_evidence.proof_batches)
        == len(proofs.calls)
        > 3
    )
    assert canonical_json_bytes(evidence) == result.proof_evidence_bytes
    assert hashlib.sha256(result.proof_evidence_bytes).hexdigest() == (
        snapshot.proof_evidence_sha256
    )


@pytest.mark.asyncio
async def test_collector_keeps_announcement_and_closing_permit_sets_separate() -> None:
    policy = _live_policy()
    work = _work(policy)
    announcement_values, hotkeys, _root = _values(policy, work)
    closing_values = dict(announcement_values)
    closing_permits = list(announcement_values[("SubtensorModule", "ValidatorPermit", (78,))])
    changed_validator = policy.validator_registry[-1].validator_hotkey
    closing_permits[hotkeys.index(changed_validator)] = False
    closing_values[("SubtensorModule", "ValidatorPermit", (78,))] = closing_permits
    proofs = _HeightAwareProofs(
        {
            work.window.plan.announcement_block: announcement_values,
            work.window.plan.closing_block: closing_values,
        }
    )

    result = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=proofs,
    )(work)

    announcement = {
        account_id32(item.validator_hotkey): item.validator_permit
        for item in result.announcement_snapshot.validators
    }
    closing = {
        account_id32(item.validator_hotkey): item.validator_permit
        for item in result.snapshot.validators
    }
    changed_account = account_id32(changed_validator)
    assert announcement[changed_account] is True
    assert closing[changed_account] is False


@pytest.mark.asyncio
async def test_announcement_authority_can_be_collected_before_closing_reads() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    proofs = _FakeProofs(values)
    collector = ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=proofs,
    )

    snapshot, snapshot_bytes, proof_bytes = await collector.collect_announcement_validators(
        work.window.plan
    )

    assert snapshot.announcement_block == work.window.plan.announcement_block
    assert canonical_json_bytes(snapshot) == snapshot_bytes
    assert hashlib.sha256(proof_bytes).hexdigest() == snapshot.proof_evidence_sha256
    assert proofs.runtime is not None
    assert proofs.runtime.snapshot.block_number == work.window.plan.announcement_block
    item_names = {spec.item for call in proofs.calls for spec in call}
    assert item_names == {"NetworksAdded", "SubnetworkN", "ValidatorPermit", "Uids", "Keys"}


@pytest.mark.asyncio
async def test_announcement_authority_rejects_wrong_policy_before_proof_reads() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    proofs = _FakeProofs(values)
    collector = ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=proofs,
    )
    wrong = replace(work.window.plan, scoring_policy_hash="ff" * 32)

    with pytest.raises(ClosingSnapshotCollectorError, match="policy_binding_mismatch"):
        await collector.collect_announcement_validators(wrong)

    assert proofs.runtime is None
    assert proofs.calls == []


@pytest.mark.asyncio
async def test_collector_fails_closed_on_uid_inverse_mismatch() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, hotkeys, _root = _values(policy, work)
    values[("SubtensorModule", "Uids", (78, hotkeys[0]))] = 1
    with pytest.raises(ClosingSnapshotCollectorError, match="uid_inverse_mismatch"):
        await ProofBackedClosingSnapshotCollector(
            policy=policy,
            finality=_Finality(policy, work),
            proofs=_FakeProofs(values),
        )(work)


@pytest.mark.asyncio
async def test_collector_fails_closed_on_finality_binding_mismatch() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    finality = _Finality(policy, work)
    finality.block_value = replace(finality.block_value, state_root="0x" + "99" * 32)
    with pytest.raises(ClosingSnapshotCollectorError, match="closing_finality_binding_mismatch"):
        await ProofBackedClosingSnapshotCollector(
            policy=policy,
            finality=finality,
            proofs=_FakeProofs(values),
        )(work)


@pytest.mark.asyncio
async def test_malformed_commitment_is_retained_but_not_treated_as_anchor() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    publisher = policy.publisher_registry[0]
    values[("Commitments", "CommitmentOf", (78, publisher.publisher_hotkey))] = {
        "deposit": 0,
        "block": work.window.plan.closing_block,
        "info": {"fields": [{"Raw128": "0x1234"}]},
    }
    result = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=_FakeProofs(values),
    )(work)
    row = next(
        item
        for item in result.snapshot.publishers
        if account_id32(item.publisher_hotkey) == account_id32(publisher.publisher_hotkey)
    )
    assert row.pool_manifest_sha256 is None
    assert row.anchor_inclusion_block is None
    assert publisher.publisher_hotkey.encode() in result.proof_evidence_bytes


@pytest.mark.asyncio
async def test_absent_collateral_is_objectively_ineligible_zero() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    publisher = policy.publisher_registry[0]
    values[
        (
            "SubtensorModule",
            "MinerCollateral",
            (78, publisher.publisher_hotkey, publisher.owner_coldkey),
        )
    ] = None
    result = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=_FakeProofs(values),
    )(work)
    row = next(
        item
        for item in result.snapshot.publishers
        if account_id32(item.publisher_hotkey) == account_id32(publisher.publisher_hotkey)
    )
    assert row.locked_collateral_alpha_rao == 0
    assert row.minimum_locked_collateral_alpha_rao == 0


@pytest.mark.asyncio
async def test_invalid_axon_is_not_a_reachability_filter_or_serving_record() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, hotkeys, _root = _values(policy, work)
    miner = hotkeys[-1]
    values[("SubtensorModule", "Axons", (78, miner))]["ip_type"] = 6
    result = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=_FakeProofs(values),
    )(work)
    assert result.snapshot.neurons[-1].serving_url is None


@pytest.mark.asyncio
async def test_wrong_stage_and_policy_binding_are_rejected_before_network_reads() -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    collector = ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=_FakeProofs(values),
    )
    wrong = replace(work, window=replace(work.window, stage=WindowStage.ASSIGNMENT))
    with pytest.raises(ClosingSnapshotCollectorError, match="wrong_stage"):
        await collector(wrong)
    wrong_policy = replace(
        work,
        window=replace(
            work.window,
            plan=replace(work.window.plan, scoring_policy_hash="ff" * 32),
        ),
    )
    with pytest.raises(ClosingSnapshotCollectorError, match="policy_binding_mismatch"):
        await collector(wrong_policy)


@pytest.mark.asyncio
async def test_retained_storage_proofs_replay_and_tampering_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _live_policy()
    work = _work(policy)
    values, _hotkeys, _root = _values(policy, work)
    result = await ProofBackedClosingSnapshotCollector(
        policy=policy,
        finality=_Finality(policy, work),
        proofs=_FakeProofs(values),
    )(work)
    monkeypatch.setattr(
        "umi.validator_closing_snapshot.bittensor_core.Runtime",
        lambda *_a, **_k: _FakeRuntime(),
    )
    replayed = replay_closing_snapshot_storage(
        result.proof_evidence_bytes,
        verifier=lambda **_kwargs: True,
    )
    assert len(replayed.reads) == replayed.evidence.total_unique_storage_keys
    closing = validate_replayed_closing_snapshot(
        result.snapshot_bytes,
        replayed,
        policy=policy,
    )
    assert closing == result.snapshot
    replayed_announcement = replay_announcement_validator_storage(
        result.announcement_proof_evidence_bytes,
        verifier=lambda **_kwargs: True,
    )
    announcement = validate_replayed_announcement_validator_snapshot(
        result.announcement_snapshot_bytes,
        replayed_announcement,
        policy=policy,
    )
    assert announcement == result.announcement_snapshot

    tampered = json.loads(result.proof_evidence_bytes)
    tampered["proof_batches"][0]["claims"][0]["storage_key"] = "0x" + "00" * 32
    with pytest.raises(ClosingSnapshotCollectorError, match="storage_key_derivation_mismatch"):
        replay_closing_snapshot_storage(
            canonical_json_bytes(tampered),
            verifier=lambda **_kwargs: True,
        )

    def reject(**_kwargs):
        return False

    with pytest.raises(ClosingSnapshotCollectorError, match="storage_proof_verification_failed"):
        replay_closing_snapshot_storage(result.proof_evidence_bytes, verifier=reject)

    tampered_announcement = json.loads(result.announcement_proof_evidence_bytes)
    tampered_announcement["proof_batches"][0]["claims"][0]["storage_key"] = "0x" + "00" * 32
    with pytest.raises(
        ClosingSnapshotCollectorError,
        match="announcement_storage_key_derivation_mismatch",
    ):
        replay_announcement_validator_storage(
            canonical_json_bytes(tampered_announcement),
            verifier=lambda **_kwargs: True,
        )

    tampered_closing_acceptance = json.loads(result.proof_evidence_bytes)
    tampered_closing_acceptance["finality"]["accepted_at_unix_ms"] += 1
    with pytest.raises(
        ClosingSnapshotCollectorError,
        match="closing_proof_evidence_invalid",
    ):
        replay_closing_snapshot_storage(
            canonical_json_bytes(tampered_closing_acceptance),
            verifier=lambda **_kwargs: True,
        )

    tampered_announcement_acceptance = json.loads(result.announcement_proof_evidence_bytes)
    tampered_announcement_acceptance["finality"]["accepted_at_unix_ms"] += 1
    with pytest.raises(
        ClosingSnapshotCollectorError,
        match="announcement_proof_evidence_invalid",
    ):
        replay_announcement_validator_storage(
            canonical_json_bytes(tampered_announcement_acceptance),
            verifier=lambda **_kwargs: True,
        )
