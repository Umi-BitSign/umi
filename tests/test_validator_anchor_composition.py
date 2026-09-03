from __future__ import annotations

import hashlib
import sqlite3
from typing import Any

import pytest

from umi.grandpa_finality import (
    CARGO_LOCK_SHA256,
    EVIDENCE_CLASS,
    FIXTURE_SET_SHA256,
    RECORD_SCHEMA,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
    GrandpaFinalityObserver,
)
from umi.grandpa_finality_supervisor import (
    DurableGrandpaFinalityPort,
    GrandpaFinalitySupervisorLimits,
)
from umi.policy import (
    FinalityVerifierPin,
    LiveChainObservationPin,
    ScoringPolicy,
    scoring_policy_hash,
)
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.substrate_proof import SubprocessStorageProofVerifier
from umi.validator_anchor_composition import (
    BittensorAnchorCompositionError,
    build_production_bittensor_anchor_ports,
)
from umi.validator_anchor_ports import (
    GRANDPA_ROUND_EVIDENCE_SCHEMA,
    BittensorAnchorBindingError,
    BittensorAnchorPorts,
    GrandpaQuicknetRoundError,
    GrandpaQuicknetRoundPort,
)
from umi.validator_extrinsics import (
    ANCHOR_INTENT_SCHEMA,
    ExtrinsicOperation,
    ValidatorExtrinsicJournal,
)
from umi.validator_plans import VerifiedFinalizedBlock
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, quicknet_round_at_ms

from .factories import dev_wallet
from .test_grandpa_finality_supervisor import _attestation, _header, _write_observer
from .test_policy import _live_shadow_policy_data

TARGET = "aarch64-apple-darwin"


def _policy() -> ScoringPolicy:
    return ScoringPolicy.model_validate(_live_shadow_policy_data())


def _compact(value: int) -> bytes:
    if value < 1 << 6:
        return bytes([value << 2])
    if value < 1 << 14:
        return ((value << 2) | 1).to_bytes(2, "little")
    return ((value << 2) | 2).to_bytes(4, "little")


def _attested_block(
    policy: ScoringPolicy,
    *,
    height: int = 100,
    timestamp_ms: int = QUICKNET_GENESIS_MS + QUICKNET_PERIOD_MS,
    record_timestamp_ms: int | None = None,
    record_state_root: str | None = None,
) -> VerifiedFinalizedBlock:
    live = policy.implementation_pins.live_chain
    finality = policy.implementation_pins.finality_verifier
    assert live is not None and finality is not None
    parent = bytes.fromhex("31" * 32)
    state = bytes.fromhex("32" * 32)
    extrinsics = bytes.fromhex("33" * 32)
    scale_header = parent + _compact(height) + state + extrinsics + b"\x00"
    block_hash = "0x" + hashlib.blake2b(scale_header, digest_size=32).hexdigest()
    state_root = "0x" + state.hex()
    record: dict[str, Any] = {
        "schema": RECORD_SCHEMA,
        "request_id": "34" * 32,
        "evidence_class": EVIDENCE_CLASS,
        "offline_finality_proof": False,
        "source_revision": finality.source_revision,
        "sequence": 0,
        "chain_spec_sha256": finality.chain_spec_sha256,
        "genesis_hash": "0x" + finality.expected_genesis_hash,
        "bootstrap_block_number": finality.bootstrap_block_number,
        "bootstrap_block_hash": "0x" + finality.bootstrap_block_hash,
        "bootstrap_source": "grandpa_checkpoint",
        "bootstrap_selected": True,
        "startup_finalized_block_number": height,
        "startup_finalized_block_hash": block_hash,
        "block": {
            "number": height,
            "hash": block_hash,
            "parent_hash": "0x" + parent.hex(),
            "state_root": record_state_root or state_root,
            "extrinsics_root": "0x" + extrinsics.hex(),
            "scale_header": "0x" + scale_header.hex(),
            "timestamp_ms": (timestamp_ms if record_timestamp_ms is None else record_timestamp_ms),
        },
        "ancestry": [
            {
                "number": height,
                "hash": block_hash,
                "parent_hash": "0x" + parent.hex(),
            }
        ],
        "ancestry_complete_since_previous": False,
        "previous_finalized_hash": None,
        "previous_transcript_digest": "0" * 64,
    }
    record["transcript_digest"] = hashlib.sha256(
        b"umi-grandpa-finality-attestation-v1\0" + canonical_json_bytes(record)
    ).hexdigest()
    evidence = canonical_json_bytes(record)
    return VerifiedFinalizedBlock(
        height=height,
        block_hash=block_hash,
        state_root=record_state_root or state_root,
        timestamp_ms=timestamp_ms,
        scoring_policy_hash=scoring_policy_hash(policy),
        chain_observation=live,
        finality_verifier_sha256=finality.release_sha256_by_target[TARGET],
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )


class BlockPort:
    def __init__(self, block: VerifiedFinalizedBlock | None) -> None:
        self.block = block
        self.calls: list[int] = []

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None:
        self.calls.append(height)
        return self.block


def _rounds(policy: ScoringPolicy, block_port: BlockPort) -> GrandpaQuicknetRoundPort:
    live = policy.implementation_pins.live_chain
    finality = policy.implementation_pins.finality_verifier
    assert live is not None and finality is not None
    return GrandpaQuicknetRoundPort(
        finality=block_port,
        scoring_policy_sha256=scoring_policy_hash(policy),
        chain_observation=live,
        finality_pin=finality,
        finality_verifier_sha256=finality.release_sha256_by_target[TARGET],
    )


async def test_grandpa_round_port_uses_exact_authenticated_timestamp_boundary() -> None:
    policy = _policy()
    timestamp = QUICKNET_GENESIS_MS + QUICKNET_PERIOD_MS
    block = _attested_block(policy, timestamp_ms=timestamp)
    port = BlockPort(block)

    result = await _rounds(policy, port).verified_round_at(block.height, block.block_hash)

    assert result is not None
    assert result.timestamp_ms == timestamp
    assert result.quicknet_round == quicknet_round_at_ms(timestamp) == 2
    assert result.state_root == block.state_root
    assert result.finality_evidence_sha256 == block.finality_evidence_sha256
    decoded = __import__("json").loads(result.evidence_bytes)
    assert decoded["schema"] == GRANDPA_ROUND_EVIDENCE_SCHEMA
    assert decoded["block_hash"] == block.block_hash
    assert decoded["finality_evidence_sha256"] == block.finality_evidence_sha256
    assert port.calls == [block.height]


async def test_grandpa_round_port_is_restart_stable_and_read_only() -> None:
    policy = _policy()
    block = _attested_block(policy)

    before = await _rounds(policy, BlockPort(block)).verified_round_at(
        block.height, block.block_hash
    )
    after = await _rounds(policy, BlockPort(block)).verified_round_at(
        block.height, block.block_hash
    )

    assert before == after


async def test_grandpa_round_port_restarts_from_durable_store_and_detects_row_tamper(
    tmp_path,
) -> None:
    genesis = "50" * 32
    scoring_digest = "51" * 32
    binary = tmp_path / "observer"
    binary_digest = _write_observer(binary)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    chain_spec_digest = hashlib.sha256(b"{}").hexdigest()
    observer = GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=binary_digest,
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=chain_spec_digest,
        expected_genesis_hash="0x" + genesis,
        bootstrap_block_number=1,
        bootstrap_block_hash="0x" + "49" * 32,
        record_timeout_seconds=5,
    )
    chain = LiveChainObservationPin(
        network="finney",
        genesis_block_hash=genesis,
        runtime_spec_version=452,
        transaction_version=1,
        state_version=1,
        metadata_sha256="52" * 32,
        subtensor_revision="53" * 20,
        live_chain_fixture_set_sha256="54" * 32,
    )
    finality_pin = FinalityVerifierPin(
        profile="smoldot-verifier-attested-finality/1",
        evidence_class=EVIDENCE_CLASS,
        offline_finality_proof=False,
        source_revision=SOURCE_REVISION,
        source_tree_sha256=SOURCE_TREE_SHA256,
        cargo_lock_sha256=CARGO_LOCK_SHA256,
        finality_fixture_set_sha256=FIXTURE_SET_SHA256,
        release_sha256_by_target={TARGET: binary_digest},
        chain_spec_source_revision="53" * 20,
        chain_spec_sha256=chain_spec_digest,
        expected_genesis_hash=genesis,
        bootstrap_kind="grandpa_warp_sync_checkpoint",
        bootstrap_block_number=1,
        bootstrap_block_hash="49" * 32,
    )
    state_path = tmp_path / "finality.sqlite3"

    def open_store() -> DurableGrandpaFinalityPort:
        return DurableGrandpaFinalityPort(
            observer=observer,
            state_path=state_path,
            scoring_policy_digest=scoring_digest,
            chain_observation=chain,
            finality_verifier_sha256=binary_digest,
            initial_minimum_finalized_block=10,
            startup_timeout_seconds=1,
            limits=GrandpaFinalitySupervisorLimits(maximum_records_per_process=2),
        )

    store = open_store()
    binding = store.next_run_binding()
    attestation = _attestation(
        observer,
        binding,
        block=_header(10, parent_hash="0x" + genesis, seed=10),
        sequence=0,
        previous=None,
    )
    store.accept_attestation(binding, attestation)

    first = await GrandpaQuicknetRoundPort(
        finality=store,
        scoring_policy_sha256=scoring_digest,
        chain_observation=chain,
        finality_pin=finality_pin,
        finality_verifier_sha256=binary_digest,
    ).verified_round_at(attestation.block.number, attestation.block.hash)
    restarted = open_store()
    second = await GrandpaQuicknetRoundPort(
        finality=restarted,
        scoring_policy_sha256=scoring_digest,
        chain_observation=chain,
        finality_pin=finality_pin,
        finality_verifier_sha256=binary_digest,
    ).verified_round_at(attestation.block.number, attestation.block.hash)
    assert first == second

    with sqlite3.connect(state_path) as connection:
        connection.execute(
            "UPDATE finalized_headers SET timestamp_ms = timestamp_ms + 1 WHERE height = 10"
        )
    with pytest.raises(GrandpaQuicknetRoundError, match="finality_block_identity_mismatch"):
        await GrandpaQuicknetRoundPort(
            finality=restarted,
            scoring_policy_sha256=scoring_digest,
            chain_observation=chain,
            finality_pin=finality_pin,
            finality_verifier_sha256=binary_digest,
        ).verified_round_at(attestation.block.number, attestation.block.hash)


async def test_grandpa_round_port_rejects_tampered_or_unavailable_evidence() -> None:
    policy = _policy()
    block = _attested_block(policy)
    tampered_timestamp = _attested_block(
        policy,
        timestamp_ms=block.timestamp_ms,
        record_timestamp_ms=block.timestamp_ms + 1,
    )
    with pytest.raises(GrandpaQuicknetRoundError, match="finality_block_identity_mismatch"):
        await _rounds(policy, BlockPort(tampered_timestamp)).verified_round_at(
            tampered_timestamp.height,
            tampered_timestamp.block_hash,
        )

    tampered_header = _attested_block(policy, record_state_root="0x" + "44" * 32)
    with pytest.raises(
        GrandpaQuicknetRoundError,
        match="finality_scale_header_identity_mismatch",
    ):
        await _rounds(policy, BlockPort(tampered_header)).verified_round_at(
            tampered_header.height,
            tampered_header.block_hash,
        )

    assert (
        await _rounds(policy, BlockPort(None)).verified_round_at(block.height, block.block_hash)
        is None
    )
    with pytest.raises(GrandpaQuicknetRoundError, match="verified_block_identity_mismatch"):
        await _rounds(policy, BlockPort(block)).verified_round_at(block.height, "0x" + "45" * 32)


class InertProofVerifier(SubprocessStorageProofVerifier):
    def __init__(self, expected_sha256: str) -> None:
        self._expected_sha256 = expected_sha256

    def __call__(self, **_kwargs: Any) -> bool:
        raise AssertionError("composition must not execute a proof verifier")

    def verify_extrinsics_root(self, **_kwargs: Any) -> bool:
        raise AssertionError("composition must not execute a proof verifier")


class InertFinality(DurableGrandpaFinalityPort):
    def __init__(self, policy: ScoringPolicy, finality_digest: str) -> None:
        live = policy.implementation_pins.live_chain
        assert live is not None
        self._scoring_policy_digest = scoring_policy_hash(policy)
        self._chain_observation = live
        self._finality_verifier_sha256 = finality_digest

    async def verified_block_at(self, _height: int) -> VerifiedFinalizedBlock | None:
        raise AssertionError("composition must not query finality")


class InertRaw:
    async def rpc_request(self, _method: str, _params: list[Any]) -> Any:
        raise AssertionError("composition must not make an RPC request")


class InertSubstrate:
    def __init__(self) -> None:
        self.raw = InertRaw()
        self.broadcasts = 0

    async def compose(self, _call: Any) -> Any:
        raise AssertionError("composition must not compose a call")

    async def prepare(self, _call: Any, **_kwargs: Any) -> Any:
        raise AssertionError("composition must not prepare a call")

    async def submit_signature(self, *_args: Any, **_kwargs: Any) -> Any:
        self.broadcasts += 1
        raise AssertionError("composition must not broadcast")


class InertClient:
    endpoint = "wss://entrypoint-finney.opentensor.ai:443"

    def __init__(self) -> None:
        self._substrate = InertSubstrate()


def _operation(address: str) -> ExtrinsicOperation:
    return ExtrinsicOperation(
        schema="umi-validator-extrinsic-operation/1",
        protocol=PROTOCOL_VERSION,
        operation="assignment_anchor",
        window_id="46" * 32,
        validator_hotkey=address,
        request={
            "schema": ANCHOR_INTENT_SCHEMA,
            "call": "Commitments.set_commitment",
            "netuid": 78,
            "anchor_kind": "assignment_set",
            "field": {"type": "Data::Sha256", "sha256": "47" * 32},
        },
    )


def _production_dependencies(policy: ScoringPolicy):
    proof_pin = policy.implementation_pins.storage_proof_verifier
    finality_pin = policy.implementation_pins.finality_verifier
    assert proof_pin is not None and finality_pin is not None
    proof_digest = proof_pin.release_sha256_by_target[TARGET]
    finality_digest = finality_pin.release_sha256_by_target[TARGET]
    return (
        InertProofVerifier(proof_digest),
        InertFinality(policy, finality_digest),
        finality_digest,
    )


async def test_production_composition_is_inert_and_exposes_only_bound_anchor_ports(
    tmp_path,
) -> None:
    policy = _policy()
    signer = dev_wallet("//Validator0").hotkey
    client = InertClient()
    journal = ValidatorExtrinsicJournal(tmp_path / "extrinsics")
    proof, finality, finality_digest = _production_dependencies(policy)

    adapter = build_production_bittensor_anchor_ports(
        policy=policy,
        target_triple=TARGET,
        subtensor=client,
        signer=signer,
        journal=journal,
        sidecar_root=tmp_path / "anchor-evidence",
        finality=finality,
        storage_proof_verifier=proof,
        finality_verifier_sha256=finality_digest,
    )

    assert isinstance(adapter, BittensorAnchorPorts)
    assert client._substrate.broadcasts == 0
    assert not hasattr(adapter, "sign")
    assert not hasattr(adapter, "submit_signature")
    ports = adapter(_operation(signer.ss58_address))
    with pytest.raises(BittensorAnchorBindingError, match="persisted prepared evidence"):
        await ports.sign(b"not-a-persisted-payload", _operation(signer.ss58_address).operation_id)
    assert client._substrate.broadcasts == 0


def test_production_composition_rejects_wrong_release_or_store_binding(tmp_path) -> None:
    policy = _policy()
    signer = dev_wallet("//Validator0").hotkey
    journal = ValidatorExtrinsicJournal(tmp_path / "extrinsics")
    proof, finality, finality_digest = _production_dependencies(policy)
    proof._expected_sha256 = "48" * 32
    with pytest.raises(BittensorAnchorCompositionError, match="storage-proof verifier"):
        build_production_bittensor_anchor_ports(
            policy=policy,
            target_triple=TARGET,
            subtensor=InertClient(),
            signer=signer,
            journal=journal,
            sidecar_root=tmp_path / "anchor-evidence",
            finality=finality,
            storage_proof_verifier=proof,
            finality_verifier_sha256=finality_digest,
        )

    proof, finality, finality_digest = _production_dependencies(policy)
    finality._scoring_policy_digest = "49" * 32
    with pytest.raises(BittensorAnchorCompositionError, match="durable finality store"):
        build_production_bittensor_anchor_ports(
            policy=policy,
            target_triple=TARGET,
            subtensor=InertClient(),
            signer=signer,
            journal=journal,
            sidecar_root=tmp_path / "anchor-evidence-2",
            finality=finality,
            storage_proof_verifier=proof,
            finality_verifier_sha256=finality_digest,
        )


def test_production_composition_rejects_unregistered_signer_and_overlapping_store(
    tmp_path,
) -> None:
    policy = _policy()
    journal = ValidatorExtrinsicJournal(tmp_path / "extrinsics")
    proof, finality, finality_digest = _production_dependencies(policy)
    with pytest.raises(BittensorAnchorCompositionError, match="validator registry"):
        build_production_bittensor_anchor_ports(
            policy=policy,
            target_triple=TARGET,
            subtensor=InertClient(),
            signer=dev_wallet("//NotRegistered").hotkey,
            journal=journal,
            sidecar_root=tmp_path / "anchor-evidence",
            finality=finality,
            storage_proof_verifier=proof,
            finality_verifier_sha256=finality_digest,
        )

    with pytest.raises(BittensorAnchorCompositionError, match="must be disjoint"):
        build_production_bittensor_anchor_ports(
            policy=policy,
            target_triple=TARGET,
            subtensor=InertClient(),
            signer=dev_wallet("//Validator0").hotkey,
            journal=journal,
            sidecar_root=journal.root / "sidecars",
            finality=finality,
            storage_proof_verifier=proof,
            finality_verifier_sha256=finality_digest,
        )
