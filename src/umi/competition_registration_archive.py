"""Replay retained registration storage with the native multiproof verifier.

The archived JSON supplies untrusted bytes only. The caller supplies an exact
snapshot from its owned historical finality record. This never establishes
present registration, current execution timing, or transaction authority.
"""

from __future__ import annotations

import hashlib
import json

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import (
    _hotkey,
    _uint,
    model_burn_storage_reads,
    verified_model_burn_destination,
)
from .open_competition import CompetitionPolicy, Registration, RegistrationSnapshot, digest
from .protocol import canonical_json_bytes
from .validator_chain import FinalizedProofCollector, FinalizedRuntimePin, StorageReadSpec

MAX_ARCHIVE_BYTES = 64 * 1024**2
MAX_METADATA_BYTES = 16 * 1024**2


class RegistrationArchive:
    """Bounded immutable RPC answers; requests cannot fall back to the network."""

    def __init__(self, raw: bytes, metadata: bytes):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_ARCHIVE_BYTES:
            raise ValueError("registration archive exceeds its byte bound")
        if type(metadata) is not bytes or not 0 < len(metadata) <= MAX_METADATA_BYTES:
            raise ValueError("registration archive metadata exceeds its byte bound")
        body = json.loads(raw)
        required = {
            "schema",
            "snapshot",
            "finality",
            "runtime_metadata_sha256",
            "runtime_version",
            "storage_batches",
        }
        if (
            not isinstance(body, dict)
            or set(body) - {"storage_codec_mode"} != required
            or body["schema"] != "umi-competition-registration-evidence/1"
            or canonical_json_bytes(body) != raw
        ):
            raise ValueError("registration archive is not canonical native evidence")
        if hashlib.sha256(metadata).hexdigest() != body["runtime_metadata_sha256"]:
            raise ValueError("registration archive metadata digest differs")
        self.snapshot = RegistrationSnapshot.model_validate_json(
            canonical_json_bytes(body["snapshot"])
        )
        self.finality = body["finality"]
        self.metadata, self.version = metadata, body["runtime_version"]
        self.codec_mode = body.get("storage_codec_mode")
        self.evidence_sha256 = hashlib.sha256(raw).hexdigest()
        batches = body["storage_batches"]
        if not isinstance(batches, list) or len(batches) != 3:
            raise ValueError("registration archive requires exactly three storage batches")
        self.values, self.proofs, self.roots = {}, {}, set()
        for batch in batches:
            if not isinstance(batch, dict) or set(batch) != {"state_root", "claims", "proof"}:
                raise ValueError("registration archive batch shape differs")
            if not isinstance(batch["state_root"], str):
                raise ValueError("registration archive state root is invalid")
            self.roots.add(batch["state_root"])
            claims = batch["claims"]
            if not isinstance(claims, list) or not 1 <= len(claims) <= 256:
                raise ValueError("registration archive claim count differs")
            keys = []
            for claim in claims:
                if not isinstance(claim, dict) or set(claim) != {"key", "value"}:
                    raise ValueError("registration archive claim shape differs")
                key = claim["key"]
                if not isinstance(key, str) or not 2 < len(key) <= 8194:
                    raise ValueError("registration archive key is invalid")
                # The collector validates canonical hex and all raw value/proof bounds.
                if key in self.values:
                    raise ValueError("registration archive repeats a storage claim")
                keys.append(key)
                self.values[key] = claim["value"]
            if keys != sorted(keys):
                raise ValueError("registration archive claims are not ordered")
            self.proofs[tuple(keys)] = batch["proof"]
        self.used_keys, self.used_batches = set(), set()

    async def request(self, method, params):
        if not params or params[-1] != self.snapshot.block_hash:
            raise ValueError("registration replay requested another block")
        if method == "state_getRuntimeVersion" and len(params) == 1:
            return self.version
        if method == "state_getMetadata" and len(params) == 1:
            return "0x" + self.metadata.hex()
        if method == "state_getStorageAt" and len(params) == 2:
            key = params[0]
            if key not in self.values:
                raise ValueError("registration archive lacks a required storage claim")
            self.used_keys.add(key)
            return self.values[key]
        if method == "state_getReadProof" and len(params) == 2:
            keys = tuple(params[0])
            if keys not in self.proofs:
                raise ValueError("registration archive lacks the exact proof batch")
            self.used_batches.add(keys)
            return {"at": self.snapshot.block_hash, "proof": self.proofs[keys]}
        raise ValueError("registration archive has no requested RPC capability")

    def consumed(self):
        if self.used_keys != set(self.values) or self.used_batches != set(self.proofs):
            raise ValueError("registration archive contains unused claims or proof batches")


async def replay_registration_archive(
    archive: RegistrationArchive,
    *,
    snapshot: FinalizedSnapshotRef,
    policy: CompetitionPolicy,
    pin: FinalizedRuntimePin,
    proofs: FinalizedProofCollector,
    reviewed_codec: bool,
    timestamp_ms: int,
) -> RegistrationSnapshot:
    if (
        archive.snapshot.block != snapshot.block_number
        or archive.snapshot.block_hash != snapshot.block_hash
        or archive.roots != {snapshot.state_root}
        or archive.codec_mode != ("reviewed_storage_codec/1" if reviewed_codec else None)
    ):
        raise ValueError("registration archive differs from owned finality or codec mode")
    collector = proofs.with_evidence_rpc(archive)
    runtime = (
        await collector.storage_codec_runtime(snapshot, pin, archive.metadata)
        if reviewed_codec
        else await collector.pinned_runtime(snapshot, pin)
    )

    async def read(specs):
        batch = await collector.storage_reads(runtime, specs)
        if any(
            r.raw_value is None
            and not (
                policy.unallocated_model_burn is not None
                and r.spec == StorageReadSpec("SubtensorModule", "RecycleOrBurn", (78,))
                and r.decoded_value == "Burn"
            )
            for r in batch.reads
        ):
            raise ValueError("registration archive storage membership is incomplete")
        return {r.spec: r.decoded_value for r in batch.reads}

    values = await read(
        (
            StorageReadSpec("Timestamp", "Now"),
            StorageReadSpec("SubtensorModule", "NetworksAdded", (78,)),
            StorageReadSpec("SubtensorModule", "SubnetworkN", (78,)),
            *model_burn_storage_reads(policy),
        )
    )
    if (
        _uint(values[StorageReadSpec("Timestamp", "Now")], 2**53 - 1) != timestamp_ms
        or values[StorageReadSpec("SubtensorModule", "NetworksAdded", (78,))] is not True
    ):
        raise ValueError("registration archive timestamp or subnet differs")
    count = _uint(values[StorageReadSpec("SubtensorModule", "SubnetworkN", (78,))], 256)
    if not count:
        raise ValueError("registration archive contains no registrations")
    keys = await read(
        tuple(StorageReadSpec("SubtensorModule", "Keys", (78, uid)) for uid in range(count))
    )
    hotkeys = tuple(
        _hotkey(keys[StorageReadSpec("SubtensorModule", "Keys", (78, uid))]) for uid in range(count)
    )
    if len(set(hotkeys)) != count:
        raise ValueError("registration archive repeats a hotkey")
    inverse = await read(
        tuple(StorageReadSpec("SubtensorModule", "Uids", (78, key)) for key in hotkeys)
    )
    for uid, hotkey in enumerate(hotkeys):
        if _uint(inverse[StorageReadSpec("SubtensorModule", "Uids", (78, hotkey))], 255) != uid:
            raise ValueError("registration archive inverse mapping differs")
    registrations = tuple(
        Registration(uid=uid, hotkey=hotkey) for uid, hotkey in enumerate(hotkeys)
    )
    rebuilt = RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=snapshot.block_number,
        block_hash=snapshot.block_hash,
        registrations=registrations,
        burn_destination=verified_model_burn_destination(policy, values, registrations),
    )
    archive.consumed()
    if digest(rebuilt) != digest(archive.snapshot):
        raise ValueError("registration archive snapshot differs from its verified claims")
    return rebuilt
