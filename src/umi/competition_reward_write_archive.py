"""Replay complete control blocks using retained bytes and owned finality.

The archive is untrusted input. Only the native slot, runtime, body and event
verifiers can recreate an owned observation. Historical state RPCs are not used
as a fallback; ancestry recovery may still read headers from the chain.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .competition_reward_control_archive import (
    MAX_CONTROL_METADATA_BYTES,
    HistoricalRewardControlProvider,
)
from .competition_reward_control_writes import (
    MAX_WRITE_EVIDENCE_BYTES,
    OwnedRewardControlWrites,
    _control_block_identity,
    _proved_writes,
)
from .concurrency import run_owned_thread
from .protocol import canonical_json_bytes
from .runtime_metadata import collect_executed_runtime
from .validator_chain_scan import (
    FinalizedBlockScanner,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    ScanLimits,
    finalized_block_body_sha256,
)


def _hex(value: Any, maximum: int, *, empty: bool = False) -> bytes:
    if type(value) is not str or not (0 if empty else 2) <= len(value) <= 2 * maximum:
        raise ValueError("control write archive hex exceeds its bound")
    try:
        raw = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError("control write archive has invalid hex") from error
    if raw.hex() != value:
        raise ValueError("control write archive hex is not canonical")
    return raw


class _WriteArchive:
    def __init__(self, raw: bytes):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_WRITE_EVIDENCE_BYTES:
            raise ValueError("control write archive exceeds its byte bound")
        body = json.loads(raw)
        required = {
            "schema",
            "finality_provenance",
            "slot_evidence_sha256",
            "header",
            "parent_header",
            "extrinsics",
            "runtime_metadata",
            "runtime_version",
            "runtime_execution",
            "events",
            "chain_submission_authorized",
        }
        if (
            not isinstance(body, dict)
            or set(body) != required
            or body["schema"] != "umi-historical-control-writes/1"
            or body["finality_provenance"] != "owned_finalized_ancestry"
            or body["chain_submission_authorized"] is not False
            or canonical_json_bytes(body) != raw
        ):
            raise ValueError("control write archive is not exact native evidence")
        self.body = body
        limits = ScanLimits()
        entries = body["extrinsics"]
        if type(entries) is not list or len(entries) > limits.maximum_extrinsics_per_block:
            raise ValueError("control write archive has invalid extrinsic count")
        self.extrinsics = tuple(_hex(v, limits.maximum_extrinsic_bytes) for v in entries)
        if sum(map(len, self.extrinsics)) > limits.maximum_block_body_bytes:
            raise ValueError("control write archive block body exceeds its bound")
        events = body["events"]
        if type(events) is not dict or set(events) != {"key", "value", "proof"}:
            raise ValueError("control write archive has invalid event fields")
        self.event_key = _hex(events["key"], 4096)
        self.event_value = (
            None
            if events["value"] is None
            else _hex(events["value"], limits.maximum_event_storage_bytes, empty=True)
        )
        if type(events["proof"]) is not list or not (
            0 < len(events["proof"]) <= limits.maximum_event_proof_nodes
        ):
            raise ValueError("control write archive has invalid event proof count")
        self.event_proof = tuple(
            _hex(v, limits.maximum_event_proof_node_bytes) for v in events["proof"]
        )
        if sum(map(len, self.event_proof)) > limits.maximum_event_proof_bytes:
            raise ValueError("control write archive event proof exceeds its bound")
        self.metadata = _hex(body["runtime_metadata"], MAX_CONTROL_METADATA_BYTES)
        self.version_bytes = _hex(body["runtime_version"], 64 * 1024)
        self.version = json.loads(self.version_bytes)
        if (
            type(self.version) is not dict
            or canonical_json_bytes(self.version) != self.version_bytes
        ):
            raise ValueError("control write runtime version is not canonical")
        self.parent = None
        self.used: set[str] = set()

    def bind_parent(self, parent, executor_sha256: str | None) -> None:
        self.parent = parent
        execution = self.body["runtime_execution"]
        if executor_sha256 is None:
            if execution is not None:
                raise ValueError("control write archive requires its approved runtime executor")
            return
        if (
            type(execution) is not dict
            or set(execution)
            != {
                "executor_sha256",
                "block",
                "block_hash",
                "parent_hash",
                "state_root",
                "key",
                "value",
                "proof",
            }
            or type(execution["block"]) is not int
            or (
                execution["executor_sha256"],
                execution["block"],
                execution["block_hash"],
                execution["parent_hash"],
                execution["state_root"],
                execution["key"],
            )
            != (
                executor_sha256,
                parent.block_number,
                parent.block_hash,
                parent.parent_hash,
                parent.state_root,
                "0x3a636f6465",
            )
        ):
            raise ValueError("control write archive runtime execution binds another parent")

    async def request(self, method, params):
        if self.parent is None or not params or params[-1] != self.parent.block_hash:
            raise ValueError("control write runtime replay requested another block")
        execution = self.body["runtime_execution"]
        if execution is None:
            if method == "state_getMetadata" and len(params) == 1:
                self.used.add("metadata")
                return "0x" + self.metadata.hex()
            if method == "state_getRuntimeVersion" and len(params) == 1:
                self.used.add("version")
                return self.version
        else:
            if method == "state_getStorageAt" and tuple(params) == (
                "0x3a636f6465",
                self.parent.block_hash,
            ):
                self.used.add("code")
                return execution["value"]
            if (
                method == "state_getReadProof"
                and len(params) == 2
                and tuple(params[0]) == ("0x3a636f6465",)
            ):
                self.used.add("code_proof")
                return {"at": self.parent.block_hash, "proof": execution["proof"]}
        raise ValueError("control write archive cannot make this RPC request")

    def consumed(self) -> None:
        expected = (
            {"metadata", "version"}
            if self.body["runtime_execution"] is None
            else {"code", "code_proof"}
        )
        if self.used != expected:
            raise ValueError("control write archive contains unused runtime evidence")


class _ArchivePort:
    def __init__(self, archive, identity, runtime):
        self.archive, self.identity, self.runtime = archive, identity, runtime

    async def execution_runtime_at(self, identity):
        if identity != self.identity or self.runtime.snapshot != identity.parent_snapshot:
            raise ValueError("control write archive runtime differs from selected parent")
        return self.runtime

    async def block_body_at(self, identity):
        if identity != self.identity:
            raise ValueError("control write archive body differs from selected block")
        return RawFinalizedBlockBody(
            identity.snapshot.block_hash,
            identity.snapshot.parent_hash,
            identity.snapshot.state_root,
            identity.extrinsics_root,
            self.archive.extrinsics,
            finalized_block_body_sha256(self.archive.extrinsics),
        )

    async def event_storage_at(self, identity, storage_key):
        if identity != self.identity or storage_key != self.archive.event_key:
            raise ValueError("control write archive events differ from selected key")
        return RawFinalizedEventStorage(
            identity.snapshot.block_hash,
            identity.snapshot.state_root,
            storage_key,
            self.archive.event_value,
            self.archive.event_proof,
            hashlib.sha256(self.archive.event_value or b"").hexdigest(),
        )


async def review_control_writes(
    provider: HistoricalRewardControlProvider,
    *,
    slot_evidence: bytes,
    slot_metadata: bytes,
    evidence: bytes,
) -> OwnedRewardControlWrites:
    """Recreate historical writes after restart without coordinator/state RPCs."""
    if not isinstance(provider, HistoricalRewardControlProvider):
        raise TypeError("control write replay requires the historical native provider")
    archive = await run_owned_thread(_WriteArchive, evidence)
    if hashlib.sha256(slot_evidence).hexdigest() != archive.body["slot_evidence_sha256"]:
        raise ValueError("control write archive names another slot proof")
    slot = await provider.review_control(slot_evidence, slot_metadata)
    async with provider._lock:
        if provider._closed or not provider._owned:
            raise ValueError("control write replay requires a running owned provider")
        await provider._resolve_control_header(slot.snapshot, archive.body["header"])
        identity = _control_block_identity(
            provider, slot, archive.body["header"], archive.body["parent_header"]
        )
        archive.bind_parent(
            identity.parent_snapshot, provider.config.runtime_metadata_binary_sha256
        )
        if provider._runtime_executor is None:
            runtime = await provider._proofs.with_evidence_rpc(archive).pinned_runtime(
                identity.parent_snapshot, provider._runtime_pin
            )
        else:
            runtime = await collect_executed_runtime(
                provider._runtime_proofs.with_evidence_rpc(archive),
                provider._runtime_executor,
                identity.parent_snapshot,
            )
        provider._validate_runtime_context(runtime, identity.parent_snapshot)
        if (
            runtime.metadata_bytes != archive.metadata
            or runtime.runtime_version_bytes != archive.version_bytes
        ):
            raise ValueError("control write archive runtime differs from native replay")
        verifier = provider._proofs._verifier
        scanner = FinalizedBlockScanner(
            _ArchivePort(archive, identity, runtime),
            extrinsics_root_verifier=verifier.verify_extrinsics_root,
            event_proof_verifier=verifier,
            supported_runtime_pins=(runtime.pin,),
        )
        block, bindings = await scanner.decode_block_commitments(identity)
        archive.consumed()
        return _proved_writes(slot, block, bindings, evidence)
