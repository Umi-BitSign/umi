from __future__ import annotations

import hashlib
import json
from typing import Any

import bittensor as bt
import pytest
from bittensor import UnsignedExtrinsic

from umi.chain_evidence import (
    FinalizedBlockRecord,
    FinalizedCallRecord,
    FinalizedEventRecord,
    FinalizedSnapshotRef,
    StorageEvidence,
)
from umi.grandpa_finality_supervisor import (
    ACCEPTANCE_RECEIPT_SCHEMA,
    VerifiedFinalityScanInterval,
    _acceptance_digest,
)
from umi.protocol import PROTOCOL_VERSION, canonical_json_bytes
from umi.validator_anchor_evidence import DurableAnchorScanEvidenceStore
from umi.validator_anchor_ports import (
    ANCHOR_FINALITY_EVIDENCE_SCHEMA,
    BittensorAnchorBindingError,
    BittensorAnchorPortError,
    BittensorAnchorPorts,
    DurablePreparedAnchorReader,
    PersistedPreparedAnchorPort,
    VerifiedRoundAtBlock,
)
from umi.validator_assignments import FrozenRoot
from umi.validator_chain import FinalizedRuntimePin, PinnedRuntimeContext, VerifiedStorageRead
from umi.validator_chain_scan import (
    CapturedFinalizedBlockInterval,
    FinalityAttestationReplayBinding,
    FinalizedBlockScanEvidence,
    FinalizedCommitmentCallBinding,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    VerifiedFinalizedBlockIdentity,
    finalized_block_body_sha256,
)
from umi.validator_extrinsics import (
    ANCHOR_INTENT_SCHEMA,
    ExtrinsicOperation,
    ExtrinsicState,
    ReconcileOutcome,
    ReconcileQuery,
    ValidatorExtrinsicJournal,
)
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .factories import dev_wallet

ROOT = "11" * 32
OTHER_ROOT = "22" * 32
METADATA = b"allowlisted-runtime-metadata"
PIN = FinalizedRuntimePin(
    metadata_sha256=hashlib.sha256(METADATA).hexdigest(),
    spec_version=452,
    transaction_version=1,
)
GENESIS_HASH = (9_999).to_bytes(32, "big").hex()
FINALITY_VERIFIER_SHA256 = "aa" * 32
SIGNER_KEYPAIR = dev_wallet("//AnchorPorts").hotkey


def _hash(value: int) -> str:
    return "0x" + value.to_bytes(32, "big").hex()


def _snapshot(height: int) -> FinalizedSnapshotRef:
    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=_hash(height),
        parent_hash=_hash(height - 1),
        state_root=_hash(10_000 + height),
    )


def _timestamp_for_round(round_number: int) -> int:
    return QUICKNET_GENESIS_MS + (round_number - 2) * QUICKNET_PERIOD_MS + 1


def _operation(kind: str = "assignment_set", *, root: str = ROOT) -> ExtrinsicOperation:
    return ExtrinsicOperation(
        schema="umi-validator-extrinsic-operation/1",
        protocol=PROTOCOL_VERSION,
        operation={
            "assignment_set": "assignment_anchor",
            "request_set": "request_anchor",
            "response_set": "response_anchor",
        }[kind],
        window_id="33" * 32,
        validator_hotkey=SIGNER_KEYPAIR.ss58_address,
        request={
            "schema": ANCHOR_INTENT_SCHEMA,
            "call": "Commitments.set_commitment",
            "netuid": 78,
            "anchor_kind": kind,
            "field": {"type": "Data::Sha256", "sha256": root},
        },
    )


class FakeRuntime:
    def __init__(self) -> None:
        self.signed_data: bytes | None = None
        self.last_call_data: bytes | None = None
        self.extrinsic_version = 4

    def compose_call(self, module: str, function: str, params: dict[str, Any]) -> bytes:
        assert (module, function) == ("Commitments", "set_commitment")
        assert set(params) == {"netuid", "info"}
        field = params["info"]["fields"]
        assert len(field) == 1 and set(field[0]) == {"Sha256"}
        return b"\x12\x00" + int(params["netuid"]).to_bytes(2, "little") + bytes(field[0]["Sha256"])

    def decode_call(self, data: bytes) -> dict[str, Any]:
        assert data[:2] == b"\x12\x00"
        return {
            "call_index": "0x1200",
            "call_module": "Commitments",
            "call_function": "set_commitment",
            "call_args": [
                {"name": "netuid", "type": "NetUid", "value": int.from_bytes(data[2:4], "little")},
                {
                    "name": "info",
                    "type": "CommitmentInfo",
                    "value": {"fields": [{"Sha256": "0x" + data[4:].hex()}]},
                },
            ],
        }

    @staticmethod
    def signature_payload_parts(**_kwargs: Any) -> tuple[bytes, bytes]:
        return b":exact-extra", b":exact-additional"

    @staticmethod
    def signature_payload(call_data: bytes, **_kwargs: Any) -> bytes:
        return bytes(call_data) + b":exact-extra:exact-additional"

    @staticmethod
    def signed_extension_identifiers() -> tuple[str, ...]:
        return ()

    @staticmethod
    def encode_era(_era: Any) -> bytes:
        return b"\x05\x06"

    def encode_signed_extrinsic(
        self,
        call_data: bytes,
        *,
        public_key: bytes,
        signature: bytes,
        signature_version: int,
        era: dict[str, int],
        nonce: int,
        tip: int,
        tip_asset_id: int | None,
        metadata_hash_enabled: bool,
    ) -> tuple[bytes, bytes]:
        assert tip == 0 and tip_asset_id is None and metadata_hash_enabled is False
        body = (
            b"signed-anchor"
            + call_data
            + public_key
            + bytes([signature_version])
            + signature
            + era["current"].to_bytes(8, "little")
            + nonce.to_bytes(8, "little")
        )
        self.signed_data = body
        self.last_call_data = call_data
        return body, hashlib.blake2b(body, digest_size=32).digest()

    def storage_key(self, pallet: str, item: str, params: list[Any]) -> bytes:
        assert (pallet, item, params) == (
            "Commitments",
            "CommitmentOf",
            [78, SIGNER_KEYPAIR.ss58_address],
        )
        return b"commitment-storage-key"


class FakeEvidence:
    def __init__(self) -> None:
        self.height = 100
        self.runtime = FakeRuntime()
        self.storage_root: str | None = None
        self.storage_block: int | None = None
        self.storage_error: Exception | None = None
        self.runtime_calls: list[tuple[int, FinalizedRuntimePin]] = []

    async def finalized_snapshot(self) -> FinalizedSnapshotRef:
        return _snapshot(self.height)

    async def pinned_runtime(
        self,
        snapshot: FinalizedSnapshotRef,
        pin: FinalizedRuntimePin,
    ) -> PinnedRuntimeContext:
        assert snapshot == _snapshot(self.height)
        assert pin == PIN
        self.runtime_calls.append((snapshot.block_number, pin))
        return PinnedRuntimeContext(
            snapshot=snapshot,
            pin=pin,
            metadata_bytes=METADATA,
            runtime_version_bytes=b'{"specVersion":452,"transactionVersion":1}',
            _runtime=self.runtime,
        )

    async def storage_read(
        self,
        runtime: PinnedRuntimeContext,
        pallet: str,
        item: str,
        params=(),
    ) -> VerifiedStorageRead:
        if self.storage_error is not None:
            raise self.storage_error
        key = runtime.storage_key(pallet, item, params)
        decoded = None
        raw = None
        if self.storage_root is not None:
            assert self.storage_block is not None
            decoded = {
                "block": self.storage_block,
                "deposit": 0,
                "info": {"fields": [{"Sha256": "0x" + self.storage_root}]},
            }
            raw = b"encoded-commitment:" + bytes.fromhex(self.storage_root)
        proof = StorageEvidence(
            snapshot=runtime.snapshot,
            storage_key=key,
            value=raw,
            proof=(b"proof-node-one", b"proof-node-two"),
            verifier=lambda **_kwargs: True,
        )
        return VerifiedStorageRead(
            runtime=runtime,
            pallet=pallet,
            item=item,
            params=tuple(params),
            evidence=proof,
            decoded_value=decoded,
        )


class RecordingSigner:
    def __init__(self) -> None:
        self.ss58_address = SIGNER_KEYPAIR.ss58_address
        self.public_key = SIGNER_KEYPAIR.public_key
        self.crypto_type = SIGNER_KEYPAIR.crypto_type
        self.payloads: list[bytes] = []

    def sign(self, payload: bytes) -> bytes:
        self.payloads.append(payload)
        return SIGNER_KEYPAIR.sign(payload)


class FakeSubstrate:
    def __init__(self, evidence: FakeEvidence, signer: RecordingSigner) -> None:
        self.evidence = evidence
        self.signer = signer
        self.compose_calls: list[Any] = []
        self.prepare_calls: list[dict[str, Any]] = []
        self.find_calls: list[tuple[str, str]] = []
        self.submit_calls: list[tuple[dict[str, Any], bytes, bool, bool]] = []
        self.inclusions: dict[int, bool] = {}
        self.submit_success = True
        self.unsigned_spec_version = PIN.spec_version
        self.genesis_hash = "0x" + GENESIS_HASH
        self.tamper_signing_payload = False

    async def compose(self, call: Any) -> bytes:
        self.compose_calls.append(call)
        return self.evidence.runtime.compose_call(call.module, call.function, call.params)

    async def prepare(self, call_data: bytes, **kwargs: Any) -> UnsignedExtrinsic:
        self.prepare_calls.append(dict(kwargs))
        current = self.evidence.height
        included_in_extrinsic, included_in_signed_data = (
            self.evidence.runtime.signature_payload_parts()
        )
        payload = bytes(call_data) + included_in_extrinsic + included_in_signed_data
        if self.tamper_signing_payload:
            payload = b"unrelated signing oracle payload"
        return UnsignedExtrinsic(
            call_data=bytes(call_data),
            address=self.signer.ss58_address,
            public_key=self.signer.public_key,
            crypto_type=self.signer.crypto_type,
            era={"period": kwargs["period"], "current": current},
            nonce=7,
            tip=kwargs["tip"],
            tip_asset_id=None,
            genesis_hash=self.genesis_hash,
            era_block_hash=_hash(current),
            spec_version=self.unsigned_spec_version,
            transaction_version=PIN.transaction_version,
            metadata_hash=kwargs["metadata_hash"],
            payload=payload,
            payload_json={
                "address": self.signer.ss58_address,
                "blockHash": _hash(current),
                "genesisHash": self.genesis_hash,
                "method": "0x" + bytes(call_data).hex(),
                "nonce": "0x00000007",
                "specVersion": "0x" + self.unsigned_spec_version.to_bytes(4, "big").hex(),
                "tip": "0x" + (0).to_bytes(16, "big").hex(),
                "transactionVersion": ("0x" + PIN.transaction_version.to_bytes(4, "big").hex()),
                "era": "0x0506",
                "version": 4,
            },
            included_in_extrinsic=included_in_extrinsic,
            included_in_signed_data=included_in_signed_data,
        )

    async def block_hash(self, height: int) -> str:
        return _hash(height)

    async def find_extrinsic(self, extrinsic_hash: str, block_hash: str):
        self.find_calls.append((extrinsic_hash, block_hash))
        height = int(block_hash[2:], 16)
        if height not in self.inclusions:
            return None
        success = self.inclusions[height]
        return bt.ExtrinsicResult(
            success=success,
            message="Success" if success else "Commitment rejected",
            block_hash=block_hash,
            extrinsic_id=f"{height}-0000",
            events=[
                {
                    "extrinsic_idx": 0,
                    "module_id": "System",
                    "event_id": "ExtrinsicSuccess" if success else "ExtrinsicFailed",
                }
            ],
        )

    async def submit_signature(
        self,
        unsigned: UnsignedExtrinsic,
        signature: bytes,
        *,
        wait_for_inclusion: bool,
        wait_for_finalization: bool,
    ) -> bt.ExtrinsicResult:
        self.submit_calls.append(
            (
                unsigned.to_dict(),
                signature,
                wait_for_inclusion,
                wait_for_finalization,
            )
        )
        return bt.ExtrinsicResult(success=self.submit_success, message="Submitted")


class FakeRounds:
    def __init__(self) -> None:
        self.values: dict[int, int] = {}
        self.calls: list[tuple[int, str]] = []
        self.mismatch = False
        self.evidence_mismatch = False
        self.unavailable = False

    async def verified_round_at(
        self,
        block_number: int,
        block_hash: str,
    ) -> VerifiedRoundAtBlock | None:
        self.calls.append((block_number, block_hash))
        if self.unavailable:
            return None
        return VerifiedRoundAtBlock(
            block_number=block_number,
            block_hash=_hash(block_number + 1) if self.mismatch else block_hash,
            state_root=_snapshot(block_number).state_root,
            timestamp_ms=_timestamp_for_round(self.values[block_number]),
            quicknet_round=self.values[block_number],
            finality_verifier_sha256=FINALITY_VERIFIER_SHA256,
            finality_evidence_sha256=hashlib.sha256(
                f"verified-finality:{block_number}".encode()
            ).hexdigest()
            if not self.evidence_mismatch
            else "bb" * 32,
            evidence_bytes=f"verified-round:{block_number}".encode(),
        )


class FakeFinality:
    def __init__(self) -> None:
        self.unavailable = False
        self.calls: list[tuple[int, int]] = []

    async def verified_scan_interval(
        self,
        start_height: int,
        end_height: int,
    ) -> VerifiedFinalityScanInterval | None:
        self.calls.append((start_height, end_height))
        if self.unavailable:
            return None
        identities = []
        attestations = []
        bindings = []
        acceptance_receipts = []
        previous_acceptance_digest = bytes(32)
        for height in range(start_height, end_height + 1):
            attestation = f"verified-finality:{height}".encode()
            evidence_sha256 = hashlib.sha256(attestation).hexdigest()
            identity = VerifiedFinalizedBlockIdentity(
                snapshot=_snapshot(height),
                parent_snapshot=_snapshot(height - 1),
                extrinsics_root=_hash(20_000 + height),
                finality_verifier_sha256="aa" * 32,
                finality_evidence_sha256=evidence_sha256,
            )
            identities.append(identity)
            attestations.append(attestation)
            bindings.append(
                FinalityAttestationReplayBinding(
                    minimum_finalized_block=height,
                    maximum_records=1,
                    startup_timeout_seconds=1,
                    expected_sequence=0,
                    previous_number=None,
                    previous_timestamp_ms=None,
                )
            )
            accepted_at_unix_ms = 2_000_000_000_000 + height
            acceptance_digest = _acceptance_digest(
                previous_acceptance_digest,
                height=height,
                block_hash=identity.snapshot.block_hash,
                evidence_digest=bytes.fromhex(evidence_sha256),
                segment_index=0,
                sequence=height - start_height,
                restart_gap=False,
                accepted_at_unix_ms=accepted_at_unix_ms,
            )
            acceptance_receipts.append(
                canonical_json_bytes(
                    {
                        "schema": ACCEPTANCE_RECEIPT_SCHEMA,
                        "height": height,
                        "block_hash": identity.snapshot.block_hash,
                        "evidence_sha256": evidence_sha256,
                        "segment_index": 0,
                        "segment_sequence": height - start_height,
                        "restart_gap_before": False,
                        "accepted_at_unix_ms": accepted_at_unix_ms,
                        "previous_acceptance_digest": previous_acceptance_digest.hex(),
                        "acceptance_digest": acceptance_digest.hex(),
                    }
                )
            )
            previous_acceptance_digest = acceptance_digest
        return VerifiedFinalityScanInterval(
            identities=tuple(identities),
            attestations=tuple(attestations),
            replay_bindings=tuple(bindings),
            acceptance_receipts=tuple(acceptance_receipts),
        )


class FakeScanner:
    def __init__(self, substrate: FakeSubstrate, evidence: FakeEvidence) -> None:
        self.substrate = substrate
        self.evidence = evidence
        self.calls: list[tuple[int, int]] = []
        self.wrong_origin = False
        self.duplicate_inclusion = False

    async def capture_blocks(
        self,
        identities,
        *,
        finality_attestations,
        finality_replay_bindings,
        start_block: int,
        end_block: int,
    ) -> CapturedFinalizedBlockInterval:
        self.calls.append((start_block, end_block))
        runtime = self.evidence.runtime
        assert runtime.signed_data is not None and runtime.last_call_data is not None
        blocks = []
        captured = []
        for identity, attestation, binding in zip(
            identities,
            finality_attestations,
            finality_replay_bindings,
            strict=True,
        ):
            height = identity.snapshot.block_number
            included = height in self.substrate.inclusions
            raws = (
                (runtime.signed_data, runtime.signed_data)
                if included and self.duplicate_inclusion
                else (runtime.signed_data,)
                if included
                else ()
            )
            body = RawFinalizedBlockBody(
                block_hash=identity.snapshot.block_hash,
                parent_hash=identity.snapshot.parent_hash,
                state_root=identity.snapshot.state_root,
                extrinsics_root=identity.extrinsics_root,
                extrinsics=raws,
                body_sha256=finalized_block_body_sha256(raws),
            )
            calls = ()
            decoded_events = ()
            if included:
                origin = b"x" * 32 if self.wrong_origin else SIGNER_KEYPAIR.public_key
                calls = tuple(
                    FinalizedCallRecord(
                        snapshot=identity.snapshot,
                        extrinsic_index=index,
                        call_hash="0x"
                        + hashlib.blake2b(runtime.last_call_data, digest_size=32).hexdigest(),
                        module="Commitments",
                        function="set_commitment",
                        successful=self.substrate.inclusions[height],
                        recursive_decode_complete=True,
                        declared_child_count=0,
                        call_path=(),
                        signer_account_id32=origin,
                        effective_origin_account_id32=origin,
                    )
                    for index in range(len(raws))
                )
                decoded_events = tuple(
                    FinalizedEventRecord(
                        snapshot=identity.snapshot,
                        event_index=index,
                        payload_sha256=hashlib.sha256(
                            f"status:{height}:{index}".encode()
                        ).hexdigest(),
                        module="System",
                        event=(
                            "ExtrinsicSuccess"
                            if self.substrate.inclusions[height]
                            else "ExtrinsicFailed"
                        ),
                        extrinsic_index=index,
                    )
                    for index in range(len(raws))
                )
            block = FinalizedBlockRecord(
                snapshot=identity.snapshot,
                extrinsic_count=len(raws),
                event_count=len(decoded_events),
                calls=calls,
                events=decoded_events,
            )
            events_value = f"proof-backed-events:{height}".encode()
            events = RawFinalizedEventStorage(
                block_hash=identity.snapshot.block_hash,
                state_root=identity.snapshot.state_root,
                storage_key=b"system-events-key",
                value=events_value,
                proof=(f"events-proof:{height}".encode(),),
                value_sha256=hashlib.sha256(events_value).hexdigest(),
            )
            blocks.append(block)
            captured.append(
                FinalizedBlockScanEvidence(
                    identity=identity,
                    finality_attestation=attestation,
                    finality_replay_binding=binding,
                    runtime_pin=PIN,
                    runtime_metadata_bytes=METADATA,
                    runtime_version_bytes=b'{"specVersion":452,"transactionVersion":1}',
                    body=body,
                    event_storage=events,
                    decoded_block=block,
                    commitment_calls=(
                        tuple(
                            FinalizedCommitmentCallBinding(
                                extrinsic_index=index,
                                call_hash=call.call_hash,
                                netuid=78,
                                field_sha256=ROOT,
                            )
                            for index, call in enumerate(calls)
                        )
                    ),
                )
            )
        return CapturedFinalizedBlockInterval(
            blocks=tuple(blocks),
            evidence=tuple(captured),
        )


def _adapter(
    tmp_path,
) -> tuple[
    BittensorAnchorPorts,
    FakeSubstrate,
    FakeEvidence,
    RecordingSigner,
    FakeRounds,
    ValidatorExtrinsicJournal,
    DurablePreparedAnchorReader,
    FakeFinality,
    FakeScanner,
    DurableAnchorScanEvidenceStore,
]:
    evidence = FakeEvidence()
    signer = RecordingSigner()
    substrate = FakeSubstrate(evidence, signer)
    rounds = FakeRounds()
    journal = ValidatorExtrinsicJournal(tmp_path / "anchor-journal")
    prepared = DurablePreparedAnchorReader(journal.root)
    finality = FakeFinality()
    scanner = FakeScanner(substrate, evidence)
    sidecars = DurableAnchorScanEvidenceStore(tmp_path / "anchor-scan-evidence")
    adapter = BittensorAnchorPorts(
        subtensor=substrate,
        signer=signer,
        evidence=evidence,
        runtime_pin=PIN,
        rounds=rounds,
        prepared=prepared,
        finality=finality,
        scanner=scanner,
        sidecars=sidecars,
        genesis_hash=GENESIS_HASH,
        finality_verifier_sha256=FINALITY_VERIFIER_SHA256,
    )
    return (
        adapter,
        substrate,
        evidence,
        signer,
        rounds,
        journal,
        prepared,
        finality,
        scanner,
        sidecars,
    )


def _fresh_adapter(
    substrate: FakeSubstrate,
    evidence: FakeEvidence,
    signer: RecordingSigner,
    rounds: FakeRounds,
    prepared: PersistedPreparedAnchorPort,
    finality: FakeFinality,
    scanner: FakeScanner,
    sidecars: DurableAnchorScanEvidenceStore,
) -> BittensorAnchorPorts:
    return BittensorAnchorPorts(
        subtensor=substrate,
        signer=signer,
        evidence=evidence,
        runtime_pin=PIN,
        rounds=rounds,
        prepared=prepared,
        finality=finality,
        scanner=scanner,
        sidecars=sidecars,
        genesis_hash=GENESIS_HASH,
        finality_verifier_sha256=FINALITY_VERIFIER_SHA256,
    )


async def _prepared_signed(
    adapter: BittensorAnchorPorts,
    journal: ValidatorExtrinsicJournal,
    operation: ExtrinsicOperation,
) -> tuple[Any, UnsignedExtrinsic, bytes, str]:
    prepared = await journal.advance(operation, adapter(operation))
    assert prepared.state is ExtrinsicState.PREPARED
    signed = await journal.advance(operation, adapter(operation))
    assert signed.state is ExtrinsicState.SIGNED
    unsigned = signed.unsigned
    signature = signed.signature
    extrinsic_hash = signed.receipt.expected_signed_extrinsic_hash
    assert signature is not None and extrinsic_hash is not None
    ports = adapter(operation)
    return ports, unsigned, signature, extrinsic_hash


@pytest.mark.parametrize("kind", ["assignment_set", "request_set", "response_set"])
async def test_prepares_only_the_exact_generated_sha256_commitment(kind: str, tmp_path) -> None:
    (
        adapter,
        substrate,
        _evidence,
        _signer,
        _rounds,
        _journal,
        _reader,
        _finality,
        _scanner,
        _sidecars,
    ) = _adapter(tmp_path)
    operation = _operation(kind)
    ports = adapter(operation)

    unsigned = await ports.prepare(operation)
    prepared = await ports.verify_prepared_call(operation, unsigned)

    assert len(substrate.compose_calls) == 1
    call = substrate.compose_calls[0]
    assert (call.module, call.function) == ("Commitments", "set_commitment")
    assert call.params == {
        "netuid": 78,
        "info": {"fields": [{"Sha256": bytes.fromhex(ROOT)}]},
    }
    assert substrate.prepare_calls == [
        {
            "address": SIGNER_KEYPAIR.ss58_address,
            "crypto_type": SIGNER_KEYPAIR.crypto_type,
            "period": 64,
            "tip": 0,
            "metadata_hash": None,
        }
    ]
    assert unsigned.call_data == b"\x12\x00\x4e\x00" + bytes.fromhex(ROOT)
    assert prepared.module == "Commitments"
    assert prepared.function == "set_commitment"
    assert prepared.netuid == 78
    assert prepared.anchor_kind == kind
    assert prepared.field_sha256 == ROOT
    assert prepared.runtime_spec_version == PIN.spec_version
    assert prepared.transaction_version == PIN.transaction_version
    assert prepared.runtime_metadata_sha256 == PIN.metadata_sha256


async def test_runtime_or_call_drift_fails_before_any_signing(tmp_path) -> None:
    adapter, substrate, _evidence, signer, _rounds, _journal, _reader, *_ = _adapter(
        tmp_path / "runtime"
    )
    substrate.unsigned_spec_version = PIN.spec_version + 1
    with pytest.raises(BittensorAnchorBindingError, match="runtime is not allowlisted"):
        await adapter(_operation()).prepare(_operation())
    assert signer.payloads == []

    adapter, substrate, _evidence, signer, _rounds, _journal, _reader, *_ = _adapter(
        tmp_path / "genesis"
    )
    substrate.genesis_hash = _hash(8_888)
    with pytest.raises(BittensorAnchorBindingError, match="genesis hash"):
        await adapter(_operation()).prepare(_operation())
    assert signer.payloads == []

    adapter, substrate, _evidence, signer, _rounds, _journal, _reader, *_ = _adapter(
        tmp_path / "payload"
    )
    substrate.tamper_signing_payload = True
    with pytest.raises(BittensorAnchorBindingError, match="signing payload differs"):
        await adapter(_operation()).prepare(_operation())
    assert signer.payloads == []

    adapter, substrate, evidence, signer, _rounds, _journal, _reader, *_ = _adapter(
        tmp_path / "call"
    )

    def wrong_compose(_module: str, _function: str, _params: dict[str, Any]) -> bytes:
        return b"wrong-call-bytes"

    evidence.runtime.compose_call = wrong_compose  # type: ignore[method-assign]
    with pytest.raises(BittensorAnchorPortError):
        await adapter(_operation()).prepare(_operation())
    assert signer.payloads == []


async def test_sign_and_submit_are_bound_to_the_journal_reconciliation_interlock(
    tmp_path,
) -> None:
    adapter, substrate, _evidence, signer, _rounds, journal, _reader, *_ = _adapter(tmp_path)
    operation = _operation()
    prepared_entry = await journal.advance(operation, adapter(operation))
    assert prepared_entry.state is ExtrinsicState.PREPARED
    ports = adapter(operation)
    unsigned = prepared_entry.unsigned

    with pytest.raises(BittensorAnchorBindingError, match="another operation"):
        await ports.sign(unsigned.payload, "ff" * 32)
    with pytest.raises(BittensorAnchorBindingError, match="persisted SDK payload"):
        await ports.sign(b"another payload", operation.operation_id)
    assert signer.payloads == []

    signature = await ports.sign(unsigned.payload, operation.operation_id)
    assert signer.payloads == [unsigned.payload]
    assert ports.derive_signed_hash is not None
    expected_hash = await ports.derive_signed_hash(unsigned, signature)

    with pytest.raises(BittensorAnchorBindingError, match="not authorized"):
        await ports.submit(unsigned, signature)
    assert substrate.submit_calls == []

    reconciliation = await ports.reconcile(
        ReconcileQuery(
            operation=operation,
            unsigned=unsigned,
            signature=signature,
            expected_extrinsic_hash=expected_hash,
            era_birth_block=100,
            era_death_block=164,
        )
    )
    assert reconciliation.outcome == ReconcileOutcome.NOT_FOUND.value

    with pytest.raises(BittensorAnchorBindingError, match="differs"):
        await ports.submit(unsigned, b"x" * 64)
    submitted = await ports.submit(unsigned, signature)
    assert submitted.extrinsic_hash == expected_hash
    assert len(substrate.submit_calls) == 1
    assert substrate.submit_calls[0][0] == unsigned.to_dict()
    assert substrate.submit_calls[0][1:] == (signature, False, False)

    with pytest.raises(BittensorAnchorBindingError, match="not authorized"):
        await ports.submit(unsigned, signature)


async def test_fresh_adapter_requires_the_exact_durable_prepared_payload(tmp_path) -> None:
    (
        adapter,
        substrate,
        evidence,
        signer,
        rounds,
        journal,
        _reader,
        finality,
        scanner,
        sidecars,
    ) = _adapter(tmp_path / "restart")
    operation = _operation()
    prepared_entry = await journal.advance(operation, adapter(operation))
    unsigned = prepared_entry.unsigned

    restarted = _fresh_adapter(
        substrate,
        evidence,
        signer,
        rounds,
        DurablePreparedAnchorReader(journal.root),
        finality,
        scanner,
        sidecars,
    )
    signature = await restarted(operation).sign(
        unsigned.payload,
        operation.operation_id,
    )
    assert len(signature) in {64, 65}
    assert signer.payloads == [unsigned.payload]

    with pytest.raises(BittensorAnchorBindingError, match="persisted SDK payload"):
        await restarted(operation).sign(
            unsigned.payload[:-1] + bytes([unsigned.payload[-1] ^ 1]),
            operation.operation_id,
        )

    missing, _substrate, _evidence, missing_signer, _rounds, _journal, _reader, *_ = _adapter(
        tmp_path / "missing"
    )
    unpersisted = await missing(operation).prepare(operation)
    with pytest.raises(BittensorAnchorBindingError, match="missing or invalid"):
        await missing(operation).sign(unpersisted.payload, operation.operation_id)
    assert missing_signer.payloads == []


async def test_substituted_or_changed_prepared_receipt_fails_closed(tmp_path) -> None:
    (
        adapter,
        substrate,
        evidence,
        signer,
        rounds,
        journal,
        reader,
        finality,
        scanner,
        sidecars,
    ) = _adapter(tmp_path)
    operation = _operation()
    prepared_entry = await journal.advance(operation, adapter(operation))

    class SubstitutingReader:
        def prepared_anchor(self, _operation_id: str):
            return prepared_entry

    substituted_operation = _operation(root=OTHER_ROOT)
    substituted = _fresh_adapter(
        substrate,
        evidence,
        signer,
        rounds,
        SubstitutingReader(),
        finality,
        scanner,
        sidecars,
    )
    with pytest.raises(BittensorAnchorBindingError, match="another operation"):
        await substituted(substituted_operation).sign(
            prepared_entry.unsigned.payload,
            substituted_operation.operation_id,
        )

    prepared_entry.path.write_bytes(prepared_entry.path.read_bytes() + b"\n")
    changed = _fresh_adapter(
        substrate,
        evidence,
        signer,
        rounds,
        reader,
        finality,
        scanner,
        sidecars,
    )
    with pytest.raises(BittensorAnchorBindingError, match="does not match its bytes"):
        await changed(operation).sign(
            prepared_entry.unsigned.payload,
            operation.operation_id,
        )
    assert signer.payloads == []


async def test_reconciliation_requires_exact_inclusion_and_proof_backed_storage(tmp_path) -> None:
    adapter, substrate, evidence, _signer, _rounds, journal, _reader, *_ = _adapter(tmp_path)
    operation = _operation()
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.height = 102
    substrate.inclusions[101] = True
    evidence.storage_root = ROOT
    evidence.storage_block = 101

    reconciled = await ports.reconcile(
        ReconcileQuery(
            operation=operation,
            unsigned=unsigned,
            signature=signature,
            expected_extrinsic_hash=expected_hash,
            era_birth_block=100,
            era_death_block=164,
        )
    )

    assert reconciled.outcome == ReconcileOutcome.FINALIZED_SUCCESS.value
    assert reconciled.extrinsic_hash == expected_hash
    assert (reconciled.inclusion_block, reconciled.inclusion_block_hash) == (101, _hash(101))
    assert reconciled.finalized_head_block == 102
    assert reconciled.finalized_head_hash == _hash(102)
    assert reconciled.scan_start_block == 100
    assert reconciled.scan_end_block == 102
    assert [
        (item["number"], item["hash"], item["matched_indices"])
        for item in reconciled.scan["blocks"]
    ] == [
        (100, _hash(100), []),
        (101, _hash(101), [0]),
        (102, _hash(102), []),
    ]
    storage = reconciled.scan["storage"]
    assert storage["matches_anchor"] is True
    assert storage["commitment_block"] == 101
    assert storage["runtime"]["metadata_sha256"] == PIN.metadata_sha256
    assert storage["proof_node_count"] == 2
    assert reconciled.scan["sidecar"]["operation_id"] == operation.operation_id
    inclusion = reconciled.scan["matched_inclusions"][0]
    assert inclusion["successful"] is True
    assert inclusion["module"] == "Commitments"
    assert inclusion["function"] == "set_commitment"
    assert inclusion["field_sha256"] == ROOT
    assert substrate.find_calls == []


async def test_proof_bound_scan_rejects_wrong_origin_and_duplicate_bytes(tmp_path) -> None:
    (
        adapter,
        substrate,
        evidence,
        _signer,
        _rounds,
        journal,
        _reader,
        _finality,
        scanner,
        _sidecars,
    ) = _adapter(tmp_path / "origin")
    operation = _operation()
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.height = 101
    substrate.inclusions[101] = True
    evidence.storage_root = ROOT
    evidence.storage_block = 101
    scanner.wrong_origin = True
    with pytest.raises(BittensorAnchorBindingError, match="exact root anchor call"):
        await ports.reconcile(
            ReconcileQuery(operation, unsigned, signature, expected_hash, 100, 164)
        )

    (
        adapter,
        substrate,
        evidence,
        _signer,
        _rounds,
        journal,
        _reader,
        _finality,
        scanner,
        _sidecars,
    ) = _adapter(tmp_path / "duplicate")
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.height = 101
    substrate.inclusions[101] = True
    evidence.storage_root = ROOT
    evidence.storage_block = 101
    scanner.duplicate_inclusion = True
    reconciled = await ports.reconcile(
        ReconcileQuery(operation, unsigned, signature, expected_hash, 100, 164)
    )
    assert reconciled.outcome == ReconcileOutcome.UNKNOWN.value
    assert reconciled.inclusion_block is None
    assert len(reconciled.scan["matched_inclusions"]) == 2


async def test_anchor_sidecar_content_address_collision_fails_before_reconciliation(
    tmp_path,
) -> None:
    adapter, substrate, evidence, _signer, _rounds, journal, _reader, *_ = _adapter(tmp_path)
    operation = _operation()
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.height = 101
    substrate.inclusions[101] = True
    evidence.storage_root = ROOT
    evidence.storage_block = 101
    assert evidence.runtime.signed_data is not None
    object_path = (
        tmp_path
        / "anchor-scan-evidence"
        / "objects"
        / hashlib.sha256(evidence.runtime.signed_data).hexdigest()
    )
    object_path.write_bytes(b"collision")

    with pytest.raises(BittensorAnchorPortError, match="sidecar persistence failed"):
        await ports.reconcile(
            ReconcileQuery(operation, unsigned, signature, expected_hash, 100, 164)
        )


@pytest.mark.parametrize(
    ("storage_root", "storage_block"),
    [(OTHER_ROOT, 101), (ROOT, 100), (None, None)],
)
async def test_successful_inclusion_without_matching_proven_state_is_unknown(
    storage_root: str | None,
    storage_block: int | None,
    tmp_path,
) -> None:
    adapter, substrate, evidence, _signer, _rounds, journal, _reader, *_ = _adapter(tmp_path)
    operation = _operation()
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.height = 102
    substrate.inclusions[101] = True
    evidence.storage_root = storage_root
    evidence.storage_block = storage_block

    reconciled = await ports.reconcile(
        ReconcileQuery(operation, unsigned, signature, expected_hash, 100, 164)
    )

    assert reconciled.outcome == ReconcileOutcome.UNKNOWN.value
    assert reconciled.inclusion_block is None
    assert reconciled.inclusion_block_hash is None
    with pytest.raises(BittensorAnchorBindingError, match="not authorized"):
        await ports.submit(unsigned, signature)


async def test_finalized_failure_is_reported_but_unavailable_proof_fails_closed(
    tmp_path,
) -> None:
    adapter, substrate, evidence, _signer, _rounds, journal, _reader, *_ = _adapter(
        tmp_path / "failure"
    )
    operation = _operation()
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.height = 101
    substrate.inclusions[101] = False
    failed = await ports.reconcile(
        ReconcileQuery(operation, unsigned, signature, expected_hash, 100, 164)
    )
    assert failed.outcome == ReconcileOutcome.FINALIZED_FAILURE.value
    assert failed.inclusion_block == 101

    adapter, substrate, evidence, _signer, _rounds, journal, _reader, *_ = _adapter(
        tmp_path / "unavailable"
    )
    ports, unsigned, signature, expected_hash = await _prepared_signed(adapter, journal, operation)
    evidence.storage_error = RuntimeError("proof backend unavailable")
    with pytest.raises(BittensorAnchorPortError, match="commitment proof failed"):
        await ports.reconcile(
            ReconcileQuery(operation, unsigned, signature, expected_hash, 100, 164)
        )


async def _finalized_entry(tmp_path, *, final_height: int = 101):
    adapter, substrate, evidence, signer, rounds, journal, _reader, *_ = _adapter(tmp_path)
    operation = _operation()

    assert (await journal.advance(operation, adapter(operation))).state is ExtrinsicState.PREPARED
    assert (await journal.advance(operation, adapter(operation))).state is ExtrinsicState.SIGNED
    submitted = await journal.advance(operation, adapter(operation))
    assert submitted.state is ExtrinsicState.SUBMITTED
    assert len(substrate.submit_calls) == 1

    evidence.height = final_height
    substrate.inclusions[101] = True
    evidence.storage_root = ROOT
    evidence.storage_block = 101
    finalized = await journal.advance(operation, adapter(operation))
    assert finalized.state is ExtrinsicState.FINALIZED_SUCCESS
    assert len(signer.payloads) == 1
    return adapter, operation, finalized, rounds


async def test_full_journal_lifecycle_submits_once_and_verifies_exact_round_boundary(
    tmp_path,
) -> None:
    adapter, operation, finalized, rounds = await _finalized_entry(tmp_path, final_height=101)
    rounds.values[101] = 900
    frozen = FrozenRoot("assignment_set", ROOT, "44" * 32, None)  # type: ignore[arg-type]

    proof = await adapter.verify_anchor(operation, frozen, finalized, None)

    assert proof.inclusion_block == proof.finalized_head_block == 101
    assert proof.inclusion_block_hash == proof.finalized_head_hash == _hash(101)
    assert proof.inclusion_round == proof.finalized_round == 900
    assert rounds.calls == [(101, _hash(101))]
    evidence = json.loads(proof.evidence_bytes)
    assert evidence["schema"] == ANCHOR_FINALITY_EVIDENCE_SCHEMA
    assert evidence["operation_id"] == operation.operation_id
    assert evidence["root"] == ROOT


async def test_anchor_round_evidence_mismatch_or_unavailability_fails_closed(tmp_path) -> None:
    adapter, operation, finalized, rounds = await _finalized_entry(tmp_path, final_height=102)
    rounds.values.update({101: 900, 102: 901})
    frozen = FrozenRoot("assignment_set", ROOT, "44" * 32, None)  # type: ignore[arg-type]

    proof = await adapter.verify_anchor(operation, frozen, finalized, None)
    assert (proof.inclusion_round, proof.finalized_round) == (900, 901)
    assert rounds.calls == [(101, _hash(101)), (102, _hash(102))]

    rounds.calls.clear()
    rounds.mismatch = True
    with pytest.raises(BittensorAnchorBindingError, match="another block"):
        await adapter.verify_anchor(operation, frozen, finalized, None)

    rounds.mismatch = False
    rounds.evidence_mismatch = True
    with pytest.raises(BittensorAnchorBindingError, match="replay sidecar finality"):
        await adapter.verify_anchor(operation, frozen, finalized, None)

    rounds.evidence_mismatch = False
    rounds.unavailable = True
    with pytest.raises(BittensorAnchorPortError, match="unavailable"):
        await adapter.verify_anchor(operation, frozen, finalized, None)


async def test_missing_or_tampered_anchor_scan_sidecar_fails_closed(tmp_path) -> None:
    missing_root = tmp_path / "missing"
    adapter, operation, finalized, rounds = await _finalized_entry(
        missing_root,
        final_height=101,
    )
    rounds.values[101] = 900
    frozen = FrozenRoot("assignment_set", ROOT, "44" * 32, None)  # type: ignore[arg-type]
    sidecar_ref = finalized.receipt.reconciliation.scan["sidecar"]
    manifest_path = missing_root / "anchor-scan-evidence" / "objects" / sidecar_ref["sha256"]
    manifest_path.unlink()
    with pytest.raises(BittensorAnchorPortError, match="sidecar replay failed"):
        await adapter.verify_anchor(operation, frozen, finalized, None)

    tampered_root = tmp_path / "tampered"
    adapter, operation, finalized, rounds = await _finalized_entry(
        tampered_root,
        final_height=101,
    )
    rounds.values[101] = 900
    sidecar_ref = finalized.receipt.reconciliation.scan["sidecar"]
    manifest_path = tampered_root / "anchor-scan-evidence" / "objects" / sidecar_ref["sha256"]
    manifest = json.loads(manifest_path.read_bytes())
    signed_path = (
        tampered_root / "anchor-scan-evidence" / "objects" / manifest["signed_extrinsic"]["sha256"]
    )
    signed_path.write_bytes(b"tampered-signed-extrinsic")
    with pytest.raises(BittensorAnchorPortError, match="sidecar replay failed"):
        await adapter.verify_anchor(operation, frozen, finalized, None)
