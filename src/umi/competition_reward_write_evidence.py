"""Exact retained block proof parser and offline body/event port."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .canonical_proof import canonical_proof_matches
from .competition_reward_control_evidence import MAX_CONTROL_METADATA_BYTES
from .competition_reward_history_effects import MAX_WRITE_EVIDENCE_BYTES
from .protocol import canonical_json_bytes
from .validator_chain_scan import (
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
            or not canonical_proof_matches(body, raw)
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
