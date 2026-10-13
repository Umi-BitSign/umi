"""Exact retained slot proof parser; no chain authority or network fallback."""

from __future__ import annotations

import hashlib
import json

from .canonical_proof import canonical_proof_matches
from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import _hotkey, _uint
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header

MAX_CONTROL_ARCHIVE_BYTES = 32 * 1024**2
MAX_CONTROL_METADATA_BYTES = 16 * 1024**2


def archive_header_hint(raw: bytes) -> tuple[FinalizedSnapshotRef, str]:
    """Read only a target hint; the parent authenticates it before dispatch.

    Complete format, hashes, runtime and proof checks remain in the shared
    kernel. Parsing this bounded hint neither checks nor grants slot authority.
    """
    if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTROL_ARCHIVE_BYTES:
        raise ValueError("reward control archive exceeds its byte bound")
    try:
        encoded = json.loads(raw)["finality"]["block"]["scale_header"]
    except (TypeError, KeyError) as error:
        raise ValueError("reward control archive has no header hint") from error
    header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
    return FinalizedSnapshotRef(
        header["number"], header["hash"], header["parent_hash"], header["state_root"]
    ), encoded


class _Archive:
    """Exact bounded answers for proof replay, with no network fallback."""

    def __init__(self, raw: bytes, metadata: bytes):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTROL_ARCHIVE_BYTES:
            raise ValueError("reward control archive exceeds its byte bound")
        if type(metadata) is not bytes or not 0 < len(metadata) <= MAX_CONTROL_METADATA_BYTES:
            raise ValueError("reward control metadata exceeds its byte bound")
        body = json.loads(raw)
        required = {
            "schema",
            "config_sha256",
            "block",
            "block_hash",
            "state_root",
            "control_hotkey",
            "control_sha256",
            "committed_at_block",
            "finality",
            "runtime_metadata_sha256",
            "runtime_version",
            "storage_codec_mode",
            "runtime_execution",
            "claims",
            "proof",
            "chain_submission_authorized",
        }
        if (
            not isinstance(body, dict)
            or set(body) != required
            or type(body["schema"]) is not str
            or body["schema"]
            not in {
                "umi-reward-control-observation/1",
                "umi-historical-reward-control-observation/1",
            }
            or body["chain_submission_authorized"] is not False
            or not canonical_proof_matches(body, raw)
            or hashlib.sha256(metadata).hexdigest() != body["runtime_metadata_sha256"]
        ):
            raise ValueError("reward control archive is not exact native evidence")
        finality = body["finality"]
        if (
            not isinstance(finality, dict)
            or finality.get("evidence_class")
            != (
                "verifier_attested_finality"
                if body["schema"] == "umi-reward-control-observation/1"
                else "owned_finalized_ancestry"
            )
            or finality.get("offline_finality_proof") is not False
            or not isinstance(finality.get("block"), dict)
        ):
            raise ValueError("reward control archive has no original finalized header")
        encoded = finality["block"].get("scale_header")
        header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        _uint(body["block"], 2**53 - 1)
        if body["committed_at_block"] is not None:
            _uint(body["committed_at_block"], body["block"])
        self.snapshot = FinalizedSnapshotRef(
            header["number"], header["hash"], header["parent_hash"], header["state_root"]
        )
        if (body["block"], body["block_hash"], body["state_root"]) != (
            self.snapshot.block_number,
            self.snapshot.block_hash,
            self.snapshot.state_root,
        ):
            raise ValueError("reward control archive differs from its header")
        self.body, self.metadata, self.encoded = body, metadata, encoded
        self.evidence_sha256 = hashlib.sha256(raw).hexdigest()
        self.hotkey = _hotkey(body["control_hotkey"])
        claims = body["claims"]
        if not isinstance(claims, list) or len(claims) != 3:
            raise ValueError("reward control archive must contain exactly three claims")
        self.values = {}
        for claim in claims:
            if not isinstance(claim, dict) or set(claim) != {"key", "value"}:
                raise ValueError("reward control archive claim is malformed")
            key = claim["key"]
            if type(key) is not str or not 2 < len(key) <= 8194 or key in self.values:
                raise ValueError("reward control archive repeats or misnames a claim")
            self.values[key] = claim["value"]
        if list(self.values) != sorted(self.values):
            raise ValueError("reward control archive claims are not ordered")
        self.proofs = {tuple(self.values): body["proof"]}
        execution = body["runtime_execution"]
        if execution is not None:
            if (
                not isinstance(execution, dict)
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
                or (
                    execution["block"],
                    execution["block_hash"],
                    execution["parent_hash"],
                    execution["state_root"],
                    execution["key"],
                )
                != (
                    self.snapshot.block_number,
                    self.snapshot.block_hash,
                    self.snapshot.parent_hash,
                    self.snapshot.state_root,
                    "0x3a636f6465",
                )
                or execution["key"] in self.values
            ):
                raise ValueError("archived runtime execution binds a different block or key")
            self.values[execution["key"]] = execution["value"]
            self.proofs[(execution["key"],)] = execution["proof"]
        self.used_keys, self.used_batches = set(), set()

    async def request(self, method, params):
        if not params or params[-1] != self.snapshot.block_hash:
            raise ValueError("reward control replay requested another block")
        if method == "state_getRuntimeVersion" and len(params) == 1:
            return self.body["runtime_version"]
        if method == "state_getMetadata" and len(params) == 1:
            return "0x" + self.metadata.hex()
        if method == "state_getStorageAt" and len(params) == 2:
            key = params[0]
            if key not in self.values:
                raise ValueError("reward control archive omits a requested claim")
            self.used_keys.add(key)
            return self.values[key]
        if method == "state_getReadProof" and len(params) == 2:
            keys = tuple(params[0])
            if keys not in self.proofs:
                raise ValueError("reward control archive omits the requested proof batch")
            self.used_batches.add(keys)
            return {"at": self.snapshot.block_hash, "proof": self.proofs[keys]}
        raise ValueError("reward control archive cannot make this RPC request")

    def consumed(self) -> None:
        if self.used_keys != set(self.values) or self.used_batches != set(self.proofs):
            raise ValueError("reward control archive contains unused proof evidence")
