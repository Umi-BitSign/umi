from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from types import SimpleNamespace
from typing import Any

import bittensor as bt
import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.policy import PublisherRegistryEntry, ValidatorRegistryEntry
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.release_chain_evidence import (
    RELEASE_OBSERVATION_EVIDENCE_PROFILE,
    RELEASE_OBSERVATION_EVIDENCE_SCHEMA,
    RUNTIME_METADATA_AUTHENTICATION,
    RUNTIME_VERSION_AUTHENTICATION,
    ReleaseChainEvidenceError,
    collect_release_observation_evidence,
    replay_release_observation_evidence,
)
from umi.validator_chain import (
    DecodedStorageClaim,
    FinalizedRuntimePin,
    MultiStorageEvidence,
    PinnedRuntimeContext,
    StorageClaim,
    StorageReadSpec,
    VerifiedStorageBatch,
)

_METADATA = b"fixture-runtime-metadata"
_RUNTIME_VERSION = canonical_json_bytes(
    {"specVersion": 452, "stateVersion": 1, "transactionVersion": 1}
)
_STATE_ROOT = "0x" + "42" * 32
_PARENT_HASH = "0x" + "24" * 32
_BLOCK_HASH = "0x" + "84" * 32
_BLOCK_NUMBER = 1_000
_COLLATERAL_FLOOR = 1_000_000_000


class _RuntimeCodec:
    def __init__(self, *_args: object, **_kwargs: object) -> None:
        pass

    def storage_key(self, pallet: str, item: str, params: list[object]) -> bytes:
        return hashlib.sha256(
            b"umi-release-evidence-test-key-v1\0"
            + canonical_json_bytes({"item": item, "pallet": pallet, "params": params})
        ).digest()

    def storage_entry(self, _pallet: str, item: str) -> Any:
        return SimpleNamespace(modifier="Optional", default_bytes=b"", value_type=item)

    def decode(self, _value_type: str, encoded: bytes, *, strict: bool) -> object:
        assert strict
        return json.loads(encoded)

    def constant(self, pallet: str, name: str) -> int:
        assert (pallet, name) == ("System", "SS58Prefix")
        return 42


class _ProofVerifier:
    def __init__(self, *, accept: bool = True) -> None:
        self.accept = accept
        self.calls: list[
            tuple[bytes, tuple[tuple[bytes, bytes | None], ...], tuple[bytes, ...]]
        ] = []

    def verify_many(
        self,
        *,
        state_root: bytes,
        items: tuple[tuple[bytes, bytes | None], ...],
        proof: tuple[bytes, ...],
    ) -> bool:
        self.calls.append((state_root, items, proof))
        return self.accept and state_root == bytes.fromhex(_STATE_ROOT[2:])


def _wallet(uri: str) -> str:
    return bt.sp_core.Keypair.create_from_uri(uri).ss58_address


@pytest.fixture
def registries() -> tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]]:
    validators = [
        ValidatorRegistryEntry(
            validator_hotkey=_wallet(f"//ReleaseObservationValidator{index}"),
            administrator_id=hashlib.sha256(f"admin-{index}".encode()).hexdigest(),
        )
        for index in range(4)
    ]
    publishers = [
        PublisherRegistryEntry(
            publisher_hotkey=_wallet(f"//ReleaseObservationPublisher{index}"),
            owner_coldkey=_wallet(f"//ReleaseObservationOwner{index}"),
            control_group_id=hashlib.sha256(f"group-{index}".encode()).hexdigest(),
        )
        for index in range(3)
    ]
    return validators, publishers


def _state_values(
    validators: Sequence[ValidatorRegistryEntry],
    publishers: Sequence[PublisherRegistryEntry],
) -> dict[tuple[str, str, tuple[object, ...]], object]:
    values: dict[tuple[str, str, tuple[object, ...]], object] = {
        ("System", "LastRuntimeUpgrade", ()): {
            "spec_name": "node-subtensor",
            "spec_version": 452,
        },
        ("SubtensorModule", "NetworksAdded", (78,)): True,
        ("SubtensorModule", "SubtokenEnabled", (78,)): True,
        ("SubtensorModule", "FirstEmissionBlockNumber", (78,)): 999,
        ("SubtensorModule", "MechanismCountCurrent", (78,)): 1,
        ("SubtensorModule", "CommitRevealWeightsEnabled", (78,)): True,
        ("SubtensorModule", "CommitRevealWeightsVersion", ()): 4,
        ("SubtensorModule", "SubnetworkN", (78,)): len(validators) + len(publishers),
        ("SubtensorModule", "ValidatorPermit", (78,)): [
            *([True] * len(validators)),
            *([False] * len(publishers)),
        ],
    }
    for uid, entry in enumerate(validators):
        values[("SubtensorModule", "Uids", (78, entry.validator_hotkey))] = uid
        values[("SubtensorModule", "Keys", (78, uid))] = entry.validator_hotkey
    for uid, entry in enumerate(publishers, start=len(validators)):
        values[("SubtensorModule", "Uids", (78, entry.publisher_hotkey))] = uid
        values[("SubtensorModule", "Keys", (78, uid))] = entry.publisher_hotkey
        values[("SubtensorModule", "Owner", (entry.publisher_hotkey,))] = entry.owner_coldkey
        values[
            (
                "SubtensorModule",
                "MinerCollateral",
                (78, entry.publisher_hotkey, entry.owner_coldkey),
            )
        ] = {
            "drain_ratio": 0,
            "earned": 0,
            "locked": _COLLATERAL_FLOOR,
            "min_locked": _COLLATERAL_FLOOR,
        }
    return values


def _evidence_document(
    validators: Sequence[ValidatorRegistryEntry],
    publishers: Sequence[PublisherRegistryEntry],
) -> dict[str, Any]:
    codec = _RuntimeCodec()
    claims = []
    for (pallet, item, params), value in _state_values(validators, publishers).items():
        claims.append(
            {
                "item": item,
                "pallet": pallet,
                "params": list(params),
                "raw_value": "0x" + canonical_json_bytes(value).hex(),
                "storage_key": "0x" + codec.storage_key(pallet, item, list(params)).hex(),
            }
        )
    claims.sort(key=lambda claim: bytes.fromhex(claim["storage_key"][2:]))
    return {
        "block_hash": _BLOCK_HASH,
        "block_number": _BLOCK_NUMBER,
        "evidence_profile": RELEASE_OBSERVATION_EVIDENCE_PROFILE,
        "finality_attestation_sha256": hashlib.sha256(b"attestation").hexdigest(),
        "mechanism_id": 0,
        "netuid": 78,
        "network": "finney",
        "parent_hash": _PARENT_HASH,
        "proof_batches": [
            {
                "claims": claims,
                "proof_nodes": ["0x" + b"fixture-proof".hex()],
            }
        ],
        "protocol": PROTOCOL_VERSION,
        "runtime": {
            "metadata_authentication": RUNTIME_METADATA_AUTHENTICATION,
            "metadata_sha256": hashlib.sha256(_METADATA).hexdigest(),
            "runtime_version": "0x" + _RUNTIME_VERSION.hex(),
            "spec_version": 452,
            "ss58_prefix": 42,
            "state_version": 1,
            "transaction_version": 1,
            "version_authentication": RUNTIME_VERSION_AUTHENTICATION,
        },
        "schema": RELEASE_OBSERVATION_EVIDENCE_SCHEMA,
        "state_root": _STATE_ROOT,
        "timestamp_ms": 12_000_000,
        "total_unique_storage_keys": len(claims),
    }


def _replay(
    monkeypatch: pytest.MonkeyPatch,
    document: Mapping[str, Any],
    validators: Sequence[ValidatorRegistryEntry],
    publishers: Sequence[PublisherRegistryEntry],
    *,
    verifier: _ProofVerifier | None = None,
) -> object:
    monkeypatch.setattr("umi.release_chain_evidence.bittensor_core.Runtime", _RuntimeCodec)
    return replay_release_observation_evidence(
        canonical_json_bytes(document),
        metadata_bytes=_METADATA,
        verifier=verifier or _ProofVerifier(),
        validator_registry=validators,
        publisher_registry=publishers,
        minimum_publisher_collateral_alpha_rao=_COLLATERAL_FLOOR,
    )


def _claim(document: Mapping[str, Any], item: str) -> dict[str, Any]:
    matches = [
        value
        for batch in document["proof_batches"]
        for value in batch["claims"]
        if value["item"] == item
    ]
    assert len(matches) == 1
    return matches[0]


def _replace_claim_value(document: Mapping[str, Any], item: str, value: object) -> None:
    _claim(document, item)["raw_value"] = "0x" + canonical_json_bytes(value).hex()


def test_replay_accepts_exact_minimal_proof_backed_release_observation_state(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
) -> None:
    validators, publishers = registries
    verifier = _ProofVerifier()
    replayed = _replay(
        monkeypatch,
        _evidence_document(validators, publishers),
        validators,
        publishers,
        verifier=verifier,
    )

    assert replayed.evidence.block_hash == _BLOCK_HASH
    assert len(replayed.values) == 9 + 2 * len(validators) + 4 * len(publishers)
    assert len(verifier.calls) == 1
    assert verifier.calls[0][0] == bytes.fromhex(_STATE_ROOT[2:])


@pytest.mark.parametrize(
    ("item", "value", "reason"),
    [
        ("NetworksAdded", False, "release_observation_subnet_not_registered"),
        ("SubtokenEnabled", 0, "release_observation_subtoken_enabled_invalid"),
        ("FirstEmissionBlockNumber", 0, "release_observation_subnet_not_active"),
        ("FirstEmissionBlockNumber", _BLOCK_NUMBER + 1, "release_observation_subnet_not_active"),
        ("MechanismCountCurrent", 2, "release_observation_mechanism_topology_mismatch"),
        ("CommitRevealWeightsEnabled", False, "release_observation_commit_reveal_disabled"),
        ("CommitRevealWeightsVersion", 3, "release_observation_commit_reveal_version_mismatch"),
    ],
)
def test_replay_rejects_false_topology_and_release_observation_values(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
    item: str,
    value: object,
    reason: str,
) -> None:
    validators, publishers = registries
    document = _evidence_document(validators, publishers)
    _replace_claim_value(document, item, value)

    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == reason


def test_replay_accepts_started_subnet_with_root_emission_disabled(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
) -> None:
    validators, publishers = registries
    document = _evidence_document(validators, publishers)
    _replace_claim_value(document, "SubtokenEnabled", False)

    replayed = _replay(monkeypatch, document, validators, publishers)

    assert replayed.values[("SubtensorModule", "SubtokenEnabled", (78,))] is False


def test_replay_rejects_false_registry_owner_and_collateral_facts(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
) -> None:
    validators, publishers = registries

    document = _evidence_document(validators, publishers)
    permits = [False, True, True, True, False, False, False]
    _replace_claim_value(document, "ValidatorPermit", permits)
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_validator_registry_mismatch"

    document = _evidence_document(validators, publishers)
    owner = next(
        claim for claim in document["proof_batches"][0]["claims"] if claim["item"] == "Owner"
    )
    owner["raw_value"] = "0x" + canonical_json_bytes(_wallet("//WrongOwner")).hex()
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_publisher_owner_mismatch"

    document = _evidence_document(validators, publishers)
    collateral = next(
        claim
        for claim in document["proof_batches"][0]["claims"]
        if claim["item"] == "MinerCollateral"
    )
    value = json.loads(bytes.fromhex(collateral["raw_value"][2:]))
    value["locked"] = _COLLATERAL_FLOOR - 1
    collateral["raw_value"] = "0x" + canonical_json_bytes(value).hex()
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_publisher_collateral_below_floor"


def test_replay_rejects_tampered_proof_header_key_metadata_and_runtime_version(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
) -> None:
    validators, publishers = registries
    document = _evidence_document(validators, publishers)
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(
            monkeypatch,
            document,
            validators,
            publishers,
            verifier=_ProofVerifier(accept=False),
        )
    assert error.value.reason_code == "release_observation_storage_proof_not_verified"

    document = _evidence_document(validators, publishers)
    document["state_root"] = "0x" + "99" * 32
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_storage_proof_not_verified"

    document = _evidence_document(validators, publishers)
    _claim(document, "NetworksAdded")["storage_key"] = "0x" + "10" * 32
    document["proof_batches"][0]["claims"].sort(
        key=lambda claim: bytes.fromhex(claim["storage_key"][2:])
    )
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_storage_key_derivation_mismatch"

    document = _evidence_document(validators, publishers)
    document["runtime"]["metadata_sha256"] = hashlib.sha256(b"wrong metadata").hexdigest()
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_runtime_metadata_mismatch"

    document = _evidence_document(validators, publishers)
    document["runtime"]["runtime_version"] = (
        "0x"
        + canonical_json_bytes(
            {"specVersion": 451, "stateVersion": 1, "transactionVersion": 1}
        ).hex()
    )
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_chain_evidence_invalid"


def test_replay_requires_the_exact_minimal_claim_set(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
) -> None:
    validators, publishers = registries
    document = _evidence_document(validators, publishers)
    claims = document["proof_batches"][0]["claims"]
    claims.remove(_claim(document, "NetworksAdded"))
    document["total_unique_storage_keys"] -= 1
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_required_storage_read_missing"

    document = _evidence_document(validators, publishers)
    extra = {
        "item": "UnrelatedStorage",
        "pallet": "SubtensorModule",
        "params": [78],
        "raw_value": "0x" + canonical_json_bytes(True).hex(),
    }
    extra["storage_key"] = (
        "0x" + _RuntimeCodec().storage_key(extra["pallet"], extra["item"], extra["params"]).hex()
    )
    document["proof_batches"][0]["claims"].append(extra)
    document["proof_batches"][0]["claims"].sort(
        key=lambda claim: bytes.fromhex(claim["storage_key"][2:])
    )
    document["total_unique_storage_keys"] += 1
    with pytest.raises(ReleaseChainEvidenceError) as error:
        _replay(monkeypatch, document, validators, publishers)
    assert error.value.reason_code == "release_observation_storage_claim_set_mismatch"


class _FixtureCollector:
    def __init__(self, runtime: PinnedRuntimeContext, values: Mapping[tuple[Any, ...], object]):
        self.runtime = runtime
        self.values = values
        self.batch = 0

    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext:
        assert snapshot == self.runtime.snapshot
        assert pin == self.runtime.pin
        return self.runtime

    async def storage_reads(
        self,
        runtime: PinnedRuntimeContext,
        specs: Sequence[StorageReadSpec],
    ) -> VerifiedStorageBatch:
        assert runtime == self.runtime
        keyed = sorted(
            ((runtime.storage_key(spec.pallet, spec.item, spec.params), spec) for spec in specs),
            key=lambda item: item[0],
        )
        reads = []
        claims = []
        for key, spec in keyed:
            value = self.values[(spec.pallet, spec.item, spec.params)]
            raw = canonical_json_bytes(value)
            claims.append(StorageClaim(key, raw))
            reads.append(DecodedStorageClaim(spec, key, raw, value))
        self.batch += 1
        evidence = MultiStorageEvidence(
            snapshot=runtime.snapshot,
            claims=claims,
            proof=(f"collector-proof-{self.batch}".encode(),),
            verifier=lambda **_kwargs: True,
        )
        return VerifiedStorageBatch(runtime, evidence, tuple(reads))


@pytest.mark.asyncio
async def test_collector_output_replays_through_the_canonical_model(
    monkeypatch: pytest.MonkeyPatch,
    registries: tuple[list[ValidatorRegistryEntry], list[PublisherRegistryEntry]],
) -> None:
    validators, publishers = registries
    snapshot = FinalizedSnapshotRef(
        block_number=_BLOCK_NUMBER,
        block_hash=_BLOCK_HASH,
        parent_hash=_PARENT_HASH,
        state_root=_STATE_ROOT,
    )
    pin = FinalizedRuntimePin(
        metadata_sha256=hashlib.sha256(_METADATA).hexdigest(),
        spec_version=452,
        transaction_version=1,
    )
    runtime = PinnedRuntimeContext(
        snapshot=snapshot,
        pin=pin,
        metadata_bytes=_METADATA,
        runtime_version_bytes=_RUNTIME_VERSION,
        _runtime=_RuntimeCodec(),
    )
    collector = _FixtureCollector(runtime, _state_values(validators, publishers))
    encoded = await collect_release_observation_evidence(
        snapshot=snapshot,
        timestamp_ms=12_000_000,
        finality_attestation_sha256=hashlib.sha256(b"attestation").hexdigest(),
        runtime_pin=pin,
        proofs=collector,
        validator_registry=validators,
        publisher_registry=publishers,
    )

    monkeypatch.setattr("umi.release_chain_evidence.bittensor_core.Runtime", _RuntimeCodec)
    replayed = replay_release_observation_evidence(
        encoded,
        metadata_bytes=_METADATA,
        verifier=_ProofVerifier(),
        validator_registry=validators,
        publisher_registry=publishers,
        minimum_publisher_collateral_alpha_rao=_COLLATERAL_FLOOR,
    )
    assert canonical_json_bytes(replayed.evidence) == encoded
    assert len(replayed.evidence.proof_batches) == 3

    with pytest.raises(ValueError, match="lowercase SHA-256"):
        await collect_release_observation_evidence(
            snapshot=snapshot,
            timestamp_ms=12_000_000,
            finality_attestation_sha256="AA" * 32,
            runtime_pin=pin,
            proofs=collector,
            validator_registry=validators,
            publisher_registry=publishers,
        )
