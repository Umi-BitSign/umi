"""Bounded semantic projection of already authenticated original history.

This module grants no proof authority. Its caller must authenticate the original
successful export and every retained source identity first. Large unchanged hex
proof/code objects stay referenced, while the native scanner decodes the exact
extrinsics, events and execution metadata. No cryptographic verifier is replaced
with an always-successful callback.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from dataclasses import asdict
from types import SimpleNamespace

from . import validator_chain
from .chain_evidence import FinalizedSnapshotRef
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    decode_evidence,
    inspect_recipe,
)
from .competition_reward_history_effects import checked_control_effects, control_block_identity
from .competition_reward_write_evidence import _ArchivePort
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header
from .validator_chain import FinalizedRuntimePin, PinnedRuntimeContext
from .validator_chain_scan import (
    FinalizedBlockScanner,
    RawFinalizedBlockBody,
    RawFinalizedEventStorage,
    ScanLimits,
    finalized_block_body_sha256,
)

_FIELDS = {"slot_evidence": 32 * 1024**2, "slot_metadata": 16 * 1024**2, "evidence": 256 * 1024**2}
_MAX_CACHE_BYTES = 16 * 1024**2


class OriginalHistoryProjection:
    """Read exact source records; do not expand irrelevant verified proof bytes.

    ``record`` must be a bounded immutable original-owner reader. ``frame`` is
    the authenticated successful export, already matched to this native journal.
    Dependencies include skipped objects: later changes invalidate reuse too.
    """

    def __init__(self, record, *, identity=None):
        self.record = record
        self.identity = identity
        self._cache = OrderedDict()
        self._cache_bytes = 0
        self.keys = set()
        self._references = {}

    def _get(self, kind, key):
        self.keys.add((kind, key))
        return self.record(kind, key)

    def _object(self, key, size):
        self.keys.add(("control_history_object", key))
        revision = None if self.identity is None else self.identity("control_history_object", key)
        cache_key = key, size, revision
        cached = self._cache.get(cache_key)
        if cached is not None:
            self._cache.move_to_end(cache_key)
            return cached
        value = self._get("control_history_object", key)
        if (
            type(value) is not dict
            or set(value) != {"hex"}
            or type(value["hex"]) is not str
            or len(value["hex"]) != 2 * size
        ):
            raise ValueError("original projection object shape changed")
        raw = bytes.fromhex(value["hex"])
        if raw.hex() != value["hex"] or hashlib.sha256(raw).hexdigest() != key:
            raise ValueError("original projection object identity changed")
        if len(raw) <= _MAX_CACHE_BYTES:
            while self._cache and (
                self._cache_bytes + len(raw) > _MAX_CACHE_BYTES or len(self._cache) >= 4096
            ):
                _, old = self._cache.popitem(last=False)
                self._cache_bytes -= len(old)
            self._cache[cache_key] = raw
            self._cache_bytes += len(raw)
        return raw

    def _parts(self, height, exported):
        self.keys = set()
        self._references = {}
        frame = self._get("control_history_block", str(height))
        if type(frame) is not dict or set(frame) != set(_FIELDS):
            raise ValueError("original projection frame changed")
        result = {}
        for name, maximum in _FIELDS.items():
            refs = frame[name]
            if (
                type(refs) is not list
                or not 0 < len(refs) <= (maximum + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
                or [part["sha256"] for part in exported["fields"][name]] != refs
            ):
                raise ValueError("successful export differs from original journal frame")
            parts, total = [], 0
            for sha, claimed in zip(refs, exported["fields"][name], strict=True):
                chunk = self._get("control_history_chunk", sha)
                if type(chunk) is not dict or set(chunk) != {"length", "recipe_hex"}:
                    raise ValueError("original projection recipe changed")
                encoded = chunk["recipe_hex"]
                if type(encoded) is not str or len(encoded) > 8 * 1024**2:
                    raise ValueError("original projection recipe exceeds bound")
                raw = bytes.fromhex(encoded)
                if (
                    raw.hex() != encoded
                    or chunk["length"] != claimed["expanded_bytes"]
                    or hashlib.sha256(raw).hexdigest() != claimed["recipe_sha256"]
                ):
                    raise ValueError("successful export differs from original recipe")
                segments = inspect_recipe(raw, expanded_bytes=chunk["length"], kind="proof")
                self.keys.update(("control_history_object", key) for _, key, _ in segments)
                total += chunk["length"]
                if total > maximum:
                    raise ValueError("original projection expansion exceeds bound")
                parts.append((sha, raw, chunk["length"], segments))
            result[name] = parts
        return result

    def _json(self, parts):
        output = bytearray()
        for _, _, _, segments in parts:
            for mode, key, size in segments:
                if mode == "b":
                    output.extend(self._object(key, size))
                else:
                    # These appear only inside quoted native hexadecimal strings.
                    marker = "__umi_original_hex_" + str(len(self._references)) + "__"
                    self._references[marker] = (key, size)
                    output.extend(marker.encode())
                if len(output) > 256 * 1024**2:
                    raise ValueError("original projection JSON exceeds bound")
        return json.loads(output)

    def _hex(self, value, maximum, *, prefix=False, empty=False):
        if type(value) is not str:
            raise ValueError("original projection requires hexadecimal bytes")
        if prefix:
            if not value.startswith("0x"):
                raise ValueError("original projection hex prefix changed")
            value = value[2:]
        if value in self._references:
            key, size = self._references[value]
            if not (0 if empty else 1) <= size <= maximum:
                raise ValueError("original projection object exceeds field bound")
            return self._object(key, size)
        if not (0 if empty else 2) <= len(value) <= 2 * maximum:
            raise ValueError("original projection hex exceeds field bound")
        raw = bytes.fromhex(value)
        if raw.hex() != value:
            raise ValueError("original projection hex is not canonical")
        return raw

    def _sha(self, value):
        raw = self._hex(value, 32)
        if len(raw) != 32:
            raise ValueError("original projection digest changed")
        return raw.hex()

    def _digest(self, parts):
        if len(parts) == 1:
            return parts[0][0]
        # Legacy frames do not retain a whole-field hash for split payloads.
        # Only these uncommon larger fields require their original full expansion.
        checksum = hashlib.sha256()
        for sha, recipe, length, _ in parts:
            checksum.update(
                decode_evidence(
                    recipe, sha256=sha, expanded_bytes=length, kind="proof", resolve=self._object
                )
            )
        return checksum.hexdigest()

    def derive(self, height, exported, *, hotkey, chain_sha256, finality_sha256):
        """Reconstruct every native write/unresolved effect, without issuing it."""
        parts = self._parts(height, exported)
        slot, write = self._json(parts["slot_evidence"]), self._json(parts["evidence"])
        if (
            slot["schema"]
            not in {
                "umi-historical-reward-control-observation/1",
                "umi-reward-control-observation/1",
            }
            or slot["chain_submission_authorized"] is not False
            or slot["control_hotkey"] != hotkey
            or self._sha(slot["config_sha256"]) != chain_sha256
            or write["schema"] != "umi-historical-control-writes/1"
            or write["chain_submission_authorized"] is not False
            or write["finality_provenance"] != "owned_finalized_ancestry"
        ):
            raise ValueError("original projection domain changed")
        header = (
            "0x"
            + self._hex(
                slot["finality"]["block"]["scale_header"], MAXIMUM_HEADER_BYTES, prefix=True
            ).hex()
        )
        decoded = _decode_header(header, maximum_bytes=MAXIMUM_HEADER_BYTES)
        snapshot = FinalizedSnapshotRef(
            decoded["number"], decoded["hash"], decoded["parent_hash"], decoded["state_root"]
        )
        slot_sha, write_sha = self._digest(parts["slot_evidence"]), self._digest(parts["evidence"])
        if (
            snapshot.block_number != height
            or slot["block"] != height
            or "0x" + self._sha(slot["block_hash"][2:]) != snapshot.block_hash
            or "0x" + self._sha(slot["state_root"][2:]) != snapshot.state_root
            or self._sha(write["slot_evidence_sha256"]) != slot_sha
            or self._sha(slot["runtime_metadata_sha256"]) != self._digest(parts["slot_metadata"])
        ):
            raise ValueError("original projection block binding changed")
        identity = control_block_identity(
            snapshot,
            "0x" + self._hex(write["header"], MAXIMUM_HEADER_BYTES, prefix=True).hex(),
            "0x" + self._hex(write["parent_header"], MAXIMUM_HEADER_BYTES, prefix=True).hex(),
            slot_header=header,
            finality_sha256=finality_sha256,
            evidence_sha256=slot_sha,
        )
        metadata = self._hex(write["runtime_metadata"], 16 * 1024**2)
        version_bytes = self._hex(write["runtime_version"], 64 * 1024)
        version = json.loads(version_bytes)
        pin = FinalizedRuntimePin(
            hashlib.sha256(metadata).hexdigest(),
            version["specVersion"],
            version["transactionVersion"],
            version["stateVersion"],
        )
        codec = validator_chain.bittensor_core.Runtime(
            metadata, pin.spec_version, pin.transaction_version, ss58_format=pin.ss58_prefix
        )
        runtime = PinnedRuntimeContext(
            identity.parent_snapshot, pin, metadata, version_bytes, codec
        )
        limits = ScanLimits()
        if (
            type(write["extrinsics"]) is not list
            or len(write["extrinsics"]) > limits.maximum_extrinsics_per_block
        ):
            raise ValueError("original projection extrinsic count exceeds native bounds")
        extrinsics = tuple(
            self._hex(v, limits.maximum_extrinsic_bytes) for v in write["extrinsics"]
        )
        if sum(map(len, extrinsics)) > limits.maximum_block_body_bytes:
            raise ValueError("original projection block body exceeds native bounds")
        event_value = (
            None
            if write["events"]["value"] is None
            else self._hex(write["events"]["value"], limits.maximum_event_storage_bytes, empty=True)
        )
        event_key = self._hex(write["events"]["key"], 4096)
        if (
            type(write["events"]["proof"]) is not list
            or not 0 < len(write["events"]["proof"]) <= limits.maximum_event_proof_nodes
        ):
            raise ValueError("original projection event proof count exceeds native bounds")
        event_proof = tuple(
            self._hex(v, limits.maximum_event_proof_node_bytes) for v in write["events"]["proof"]
        )
        if sum(map(len, event_proof)) > limits.maximum_event_proof_bytes:
            raise ValueError("original projection event proof exceeds native bounds")
        port = _ArchivePort(SimpleNamespace(), identity, runtime)

        def prohibited(*args, **kwargs):
            raise AssertionError("semantic projection must not invoke proof verification")

        scanner = FinalizedBlockScanner(
            port,
            extrinsics_root_verifier=prohibited,
            event_proof_verifier=prohibited,
            supported_runtime_pins=(pin,),
        )
        body = RawFinalizedBlockBody(
            snapshot.block_hash,
            snapshot.parent_hash,
            snapshot.state_root,
            identity.extrinsics_root,
            extrinsics,
            finalized_block_body_sha256(extrinsics),
        )
        events = RawFinalizedEventStorage(
            snapshot.block_hash,
            snapshot.state_root,
            event_key,
            event_value,
            event_proof,
            hashlib.sha256(event_value or b"").hexdigest(),
        )
        block, _, _, bindings = scanner._decode_verified_block(
            identity, runtime, body, events, None, None
        )
        control = None if slot["control_sha256"] is None else self._sha(slot["control_sha256"])
        committed = slot["committed_at_block"]
        writes, unresolved = checked_control_effects(
            snapshot, hotkey, control, committed, block, bindings
        )
        return {
            "snapshot": asdict(snapshot),
            "header": header,
            "control_sha256": control,
            "committed_at_block": committed,
            "slot_evidence_sha256": slot_sha,
            "slot_metadata_sha256": self._digest(parts["slot_metadata"]),
            "write_evidence_sha256": write_sha,
            "writes": [[v.extrinsic_index, v.decision_sha256] for v in writes],
            "unresolved_extrinsics": list(unresolved),
        }
