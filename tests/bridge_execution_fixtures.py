"""Synthetic proof/codec fixtures for loop tests, never chain-valid transactions."""

import hashlib
import json
from types import SimpleNamespace

from umi.bridge.signing import BridgeSigningState
from umi.chain_evidence import FinalizedSnapshotRef, StorageEvidence
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import ExecutedRuntimeContext
from umi.validator_chain import (
    DecodedStorageClaim,
    FinalizedRuntimePin,
    MultiStorageEvidence,
    StorageClaim,
    StorageReadSpec,
    VerifiedStorageBatch,
)


def signing_state(obs, state, *, nonce=7):
    snapshot = FinalizedSnapshotRef(
        obs.block_number, obs.block_hash, "0x" + "ff" * 32, "0x" + "55" * 32
    )

    class Codec:
        def storage_key(self, pallet, item, params):
            return canonical_json_bytes([pallet, item, params])

        def storage_entry(self, pallet, item):
            return SimpleNamespace(modifier="Default", default_bytes=b"0", value_type=item)

        def decode(self, value_type, encoded, *, strict):
            assert strict is True
            return json.loads(encoded)

        def compose_call(self, module, function, params):
            journal = state.load()
            assert journal.phase == "preparing"
            assert module == "SubtensorModule" and function == "set_mechanism_weights"
            assert params == {
                "netuid": 78,
                "mecid": 0,
                "dests": list(range(256)),
                "weights": [w for _, w in journal.attempt.expected_row],
                "version_key": 4294967296,
            }
            return canonical_json_bytes(params)

        def signature_payload(self, call, **options):
            assert options["nonce"] == nonce
            assert options["era"] == {"period": 8, "current": obs.block_number}
            assert options["era_block_hash"] == bytes.fromhex(obs.block_hash[2:])
            return b"synthetic-payload:" + call

        def encode_signed_extrinsic(self, call, **options):
            assert options["nonce"] == nonce
            assert options["era"] == {"period": 8, "current": obs.block_number}
            encoded = b"synthetic-signed:" + call + options["signature"]
            return encoded, hashlib.blake2b(encoded, digest_size=32).digest()

    codec = Codec()
    runtime = ExecutedRuntimeContext(
        snapshot=snapshot,
        pin=FinalizedRuntimePin(
            hashlib.sha256(b"metadata").hexdigest(), obs.runtime_spec_version, 1
        ),
        metadata_bytes=b"metadata",
        runtime_version_bytes=b"{}",
        _runtime=codec,
        code_evidence=StorageEvidence(
            snapshot=snapshot,
            storage_key=b":code",
            value=b"code",
            proof=(b"fixture",),
            verifier=lambda **kw: True,
        ),
        executor_sha256="a" * 64,
    )
    specs = [
        StorageReadSpec("System", "Account", (obs.validator_hotkey,)),
        StorageReadSpec("Timestamp", "Now"),
    ]
    decoded = [{"nonce": nonce}, obs.block_timestamp_ms]
    reads = tuple(
        DecodedStorageClaim(
            spec,
            runtime.storage_key(spec.pallet, spec.item, spec.params),
            canonical_json_bytes(value),
            value,
        )
        for spec, value in zip(specs, decoded, strict=True)
    )
    claims = sorted(
        (StorageClaim(r.storage_key, r.raw_value) for r in reads), key=lambda c: c.storage_key
    )
    proof = MultiStorageEvidence(
        snapshot=snapshot, claims=claims, proof=(b"fixture",), verifier=lambda **kw: True
    )
    return BridgeSigningState(
        obs.validator_hotkey, runtime, VerifiedStorageBatch(runtime, proof, reads)
    )
