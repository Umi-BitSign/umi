"""Coordinator-owned chain capture for one signed bootstrap result.

The collector reads exact finalized objects by hash, binds them to an attestation
already accepted into the coordinator's durable smoldot store, and writes one
canonical :class:`BootstrapChainCapture`.  It has no wallet, signing, call
composition, or submission capability.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import json
import os
import re
import sqlite3
import stat
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Protocol

import bittensor_core

from .audit import _read_bounded_regular_file
from .bootstrap_result_intake import (
    BOOTSTRAP_CHAIN_BLOCK_SCHEMA,
    BOOTSTRAP_CHAIN_CAPTURE_SCHEMA,
    MAX_BLOCK_BODY_BYTES,
    MAX_CAPTURE_BYTES,
    MAX_EVENTS_BYTES,
    MAX_EXTRINSIC_BYTES,
    MAX_EXTRINSICS,
    MAX_FINALITY_ANCESTRY_HEADERS,
    MAX_FINALITY_BYTES,
    MAX_METADATA_BYTES,
    MAX_OWNER_CLI_BYTES,
    MAX_PROOF_BYTES,
    MAX_PROOF_NODE_BYTES,
    MAX_PROOF_NODES,
    MAX_RAW_RPC_CAPTURE_BYTES,
    MAX_RUNTIME_VERSION_BYTES,
    BootstrapChainCapture,
    CapturedBootstrapBlock,
    CapturedFinality,
    CapturedHeader,
    CapturedRuntime,
    CapturedSystemEvents,
    _body_sha256,
    _parse_owner_cli_response,
)
from .calibration_bundle import FinalityReplayBindingObject, RuntimePinObject
from .grandpa_finality import (
    CARGO_LOCK_SHA256,
    EVIDENCE_CLASS,
    FIXTURE_SET_SHA256,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
    GrandpaFinalityLimits,
    GrandpaFinalityObserver,
)
from .grandpa_finality_supervisor import (
    ACCEPTANCE_RECEIPT_SCHEMA,
    STORE_SCHEMA,
    STORE_SCHEMA_VERSION,
    GrandpaFinalitySupervisorLimits,
    parse_finality_acceptance_receipt,
)
from .protocol import PROTOCOL_VERSION, canonical_json_bytes
from .validator_chain import BittensorRawJsonRpc, RawJsonRpc
from .validator_chain_scan import FinalityAttestationReplayBinding
from .validator_supervisor_publication import (
    MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES,
    SignedSupervisorBootstrapResult,
    parse_canonical_signed_supervisor_bootstrap_result,
)

DEFAULT_FINNEY_RPC_ENDPOINT = "wss://entrypoint-finney.opentensor.ai:443"
BOOTSTRAP_RAW_RPC_CAPTURE_SCHEMA = "umi-bootstrap-raw-rpc-capture/1"

_APPLICATION_ID = 0x554D4946
_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^0x(?:[0-9a-f]{2})*$")
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_MAX_JSON_INTEGER = (1 << 53) - 1
_MAX_STORE_CONFIG_BYTES = 64 * 1024
_MAX_STORE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_RECORDED_RPC_CALLS = 16
_MAX_RPC_TRANSCRIPT_BYTES = 72 * 1024 * 1024
_DEFAULT_BRIDGE_CONCURRENCY = 8
_MAX_BRIDGE_CONCURRENCY = 32


class BootstrapChainCaptureError(RuntimeError):
    """Stable, non-sensitive failure at the coordinator capture boundary."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class OwnedFinalityEvidence:
    """One attestation and local acceptance exported from the durable store."""

    attested_header: CapturedHeader
    ancestry: tuple[tuple[int, str, str], ...]
    attestation: bytes
    replay_binding: FinalityAttestationReplayBinding
    acceptance_receipt: bytes

    def __post_init__(self) -> None:
        if not self.attestation or len(self.attestation) > MAX_FINALITY_BYTES:
            raise ValueError("owned finality attestation size is invalid")
        if not self.ancestry or len(self.ancestry) > MAX_FINALITY_ANCESTRY_HEADERS:
            raise ValueError("owned finality ancestry size is invalid")
        if self.ancestry[-1] != (
            self.attested_header.number,
            self.attested_header.block_hash,
            self.attested_header.parent_hash,
        ):
            raise ValueError("owned finality ancestry does not end at its attested head")
        receipt = parse_finality_acceptance_receipt(self.acceptance_receipt)
        if (
            receipt.height != self.attested_header.number
            or receipt.block_hash != self.attested_header.block_hash
            or receipt.evidence_sha256 != hashlib.sha256(self.attestation).hexdigest()
        ):
            raise ValueError("owned finality acceptance binds another attestation")


class OwnedFinalityPort(Protocol):
    async def evidence_at_or_after(
        self,
        minimum_height: int,
        maximum_height: int,
    ) -> OwnedFinalityEvidence:
        """Return the earliest accepted attestation in the inclusive interval."""


class RuntimeKeyFactory(Protocol):
    def __call__(self, metadata: bytes, version: Mapping[str, Any]) -> bytes:
        """Return the runtime-derived System.Events storage key."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _strict_mapping(value: Any, reason_code: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise BootstrapChainCaptureError(reason_code)
    return value


def _strict_sequence(value: Any, reason_code: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise BootstrapChainCaptureError(reason_code)
    return value


def _hash(value: Any, reason_code: str) -> str:
    if not isinstance(value, str) or _HASH_RE.fullmatch(value) is None:
        raise BootstrapChainCaptureError(reason_code)
    return value


def _hex_bytes(
    value: Any,
    reason_code: str,
    maximum_bytes: int,
    *,
    allow_empty: bool = False,
) -> bytes:
    if (
        not isinstance(value, str)
        or _HEX_RE.fullmatch(value) is None
        or len(value) > 2 + maximum_bytes * 2
    ):
        raise BootstrapChainCaptureError(reason_code)
    raw = bytes.fromhex(value[2:])
    if not raw and not allow_empty:
        raise BootstrapChainCaptureError(reason_code)
    return raw


def _block_number(value: Any, reason_code: str) -> int:
    if not isinstance(value, str) or not value.startswith("0x"):
        raise BootstrapChainCaptureError(reason_code)
    try:
        number = int(value, 16)
    except ValueError as error:
        raise BootstrapChainCaptureError(reason_code) from error
    if number <= 0 or number > _MAX_JSON_INTEGER:
        raise BootstrapChainCaptureError(reason_code)
    return number


def _captured_header(
    value: Any,
    *,
    expected_number: int,
    expected_hash: str,
    reason_prefix: str,
) -> CapturedHeader:
    header = _strict_mapping(value, f"{reason_prefix}_header_invalid")
    if set(header) != {"number", "parentHash", "stateRoot", "extrinsicsRoot", "digest"}:
        raise BootstrapChainCaptureError(f"{reason_prefix}_header_invalid")
    digest = _strict_mapping(header.get("digest"), f"{reason_prefix}_header_invalid")
    logs = _strict_sequence(digest.get("logs"), f"{reason_prefix}_header_invalid")
    if set(digest) != {"logs"} or len(logs) > 256:
        raise BootstrapChainCaptureError(f"{reason_prefix}_header_invalid")
    normalized_logs: list[str] = []
    total = 0
    for item in logs:
        raw = _hex_bytes(
            item,
            f"{reason_prefix}_header_invalid",
            1024 * 1024,
            allow_empty=False,
        )
        total += len(raw)
        if total > 1024 * 1024:
            raise BootstrapChainCaptureError(f"{reason_prefix}_header_limit")
        normalized_logs.append(item)
    try:
        captured = CapturedHeader(
            number=_block_number(header.get("number"), f"{reason_prefix}_number_invalid"),
            block_hash=expected_hash,
            parent_hash=_hash(header.get("parentHash"), f"{reason_prefix}_parent_invalid"),
            state_root=_hash(header.get("stateRoot"), f"{reason_prefix}_state_root_invalid"),
            extrinsics_root=_hash(
                header.get("extrinsicsRoot"),
                f"{reason_prefix}_extrinsics_root_invalid",
            ),
            digest_logs=normalized_logs,
        )
    except ValueError as error:
        raise BootstrapChainCaptureError(f"{reason_prefix}_header_hash_mismatch") from error
    if captured.number != expected_number:
        raise BootstrapChainCaptureError(f"{reason_prefix}_number_mismatch")
    return captured


def _runtime_system_events_key(metadata: bytes, version: Mapping[str, Any]) -> bytes:
    def integer(name: str, *, maximum: int = _MAX_JSON_INTEGER) -> int:
        value = version.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
            raise BootstrapChainCaptureError("execution_runtime_version_invalid")
        return value

    spec = integer("specVersion")
    transaction = integer("transactionVersion")
    state = integer("stateVersion", maximum=255)
    if state != 1:
        raise BootstrapChainCaptureError("execution_runtime_state_version_unsupported")
    try:
        runtime = bittensor_core.Runtime(metadata, spec, transaction, ss58_format=42)
        if runtime.constant("System", "SS58Prefix") != 42:
            raise ValueError("unexpected SS58 prefix")
        key = runtime.storage_key("System", "Events", [])
    except Exception as error:
        raise BootstrapChainCaptureError("execution_runtime_initialization_failed") from error
    if not isinstance(key, bytes) or not key or len(key) > 512:
        raise BootstrapChainCaptureError("system_events_key_invalid")
    return key


class _RecordingRpc:
    def __init__(self, rpc: RawJsonRpc) -> None:
        self._rpc = rpc
        self.records: list[dict[str, Any]] = []
        self._encoded_bytes = 0

    async def request(self, method: str, params: Sequence[Any]) -> Any:
        result = await self._rpc.request(method, params)
        record = {"method": method, "params": list(params), "result": result}
        try:
            encoded = canonical_json_bytes(record)
        except Exception as error:
            raise BootstrapChainCaptureError("rpc_transcript_value_invalid") from error
        if len(self.records) >= _MAX_RECORDED_RPC_CALLS:
            raise BootstrapChainCaptureError("rpc_transcript_call_limit")
        self._encoded_bytes += len(encoded)
        if self._encoded_bytes > _MAX_RPC_TRANSCRIPT_BYTES:
            raise BootstrapChainCaptureError("rpc_transcript_size_limit")
        self.records.append(record)
        return result


class DurableOwnedFinalityReader:
    """Read and replay selected records from an existing supervisor SQLite store."""

    def __init__(
        self,
        *,
        state_path: Path,
        finality_verifier: Path,
        chain_spec: Path,
    ) -> None:
        self._path = state_path
        config = self._read_config()
        self._limits = self._parse_store_config(config)
        observer_config = _strict_mapping(config["observer"], "finality_store_config_invalid")
        try:
            self._observer = GrandpaFinalityObserver(
                binary_path=finality_verifier,
                expected_binary_sha256=config["finality_verifier_sha256"],
                chain_spec_path=chain_spec,
                expected_chain_spec_sha256=observer_config["chain_spec_sha256"],
                expected_genesis_hash=observer_config["genesis_hash"],
                bootstrap_block_number=observer_config["bootstrap_block_number"],
                bootstrap_block_hash=observer_config["bootstrap_block_hash"],
                limits=GrandpaFinalityLimits(),
            )
        except Exception as error:
            raise BootstrapChainCaptureError("finality_store_artifact_pin_mismatch") from error

    def _safe_stat(self) -> os.stat_result:
        if not self._path.is_absolute():
            raise BootstrapChainCaptureError("finality_state_path_not_absolute")
        try:
            info = self._path.lstat()
        except OSError as error:
            raise BootstrapChainCaptureError("finality_state_unavailable") from error
        if (
            self._path.is_symlink()
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_mode & 0o077
        ):
            raise BootstrapChainCaptureError("finality_state_unsafe")
        total = info.st_size
        for suffix in ("-wal", "-shm"):
            candidate = Path(f"{self._path}{suffix}")
            if not candidate.exists():
                continue
            sidecar = candidate.lstat()
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(sidecar.st_mode)
                or sidecar.st_mode & 0o077
            ):
                raise BootstrapChainCaptureError("finality_state_unsafe")
            total += sidecar.st_size
        if total > _MAX_STORE_BYTES:
            raise BootstrapChainCaptureError("finality_state_size_limit")
        return info

    @contextlib.contextmanager
    def _connect(self) -> Any:
        before = self._safe_stat()
        connection: sqlite3.Connection | None = None
        try:
            connection = sqlite3.connect(
                f"file:{self._path}?mode=ro",
                uri=True,
                timeout=5.0,
            )
            connection.row_factory = sqlite3.Row
            connection.execute("PRAGMA query_only = ON")
            connection.execute("PRAGMA trusted_schema = OFF")
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            yield connection
        except sqlite3.DatabaseError as error:
            raise BootstrapChainCaptureError("finality_state_read_failed") from error
        finally:
            if connection is not None:
                connection.close()
            after = self._safe_stat()
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise BootstrapChainCaptureError("finality_state_replaced_during_read")

    def _read_config(self) -> Mapping[str, Any]:
        with self._connect() as connection:
            if connection.execute("PRAGMA application_id").fetchone()[0] != _APPLICATION_ID:
                raise BootstrapChainCaptureError("finality_store_schema_mismatch")
            if connection.execute("PRAGMA user_version").fetchone()[0] != STORE_SCHEMA_VERSION:
                raise BootstrapChainCaptureError("finality_store_schema_mismatch")
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise BootstrapChainCaptureError("finality_store_integrity_failed")
            if connection.execute("PRAGMA foreign_key_check").fetchall():
                raise BootstrapChainCaptureError("finality_store_integrity_failed")
            rows = connection.execute(
                "SELECT key, value FROM store_meta WHERE key IN ('config', 'config_sha256')"
            ).fetchall()
        values = {row["key"]: bytes(row["value"]) for row in rows}
        encoded = values.get("config")
        expected = values.get("config_sha256")
        if (
            encoded is None
            or expected is None
            or not encoded
            or len(encoded) > _MAX_STORE_CONFIG_BYTES
            or len(expected) != 32
            or hashlib.sha256(encoded).digest() != expected
        ):
            raise BootstrapChainCaptureError("finality_store_config_invalid")
        try:
            decoded = json.loads(encoded, object_pairs_hook=_unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise BootstrapChainCaptureError("finality_store_config_invalid") from error
        if not isinstance(decoded, Mapping) or canonical_json_bytes(decoded) != encoded:
            raise BootstrapChainCaptureError("finality_store_config_invalid")
        return decoded

    @staticmethod
    def _parse_store_config(config: Mapping[str, Any]) -> GrandpaFinalitySupervisorLimits:
        expected_keys = {
            "schema",
            "scoring_policy_hash",
            "chain_observation",
            "finality_verifier_sha256",
            "observer",
            "initial_minimum_finalized_block",
            "startup_timeout_seconds",
            "limits",
        }
        if set(config) != expected_keys or config.get("schema") != STORE_SCHEMA:
            raise BootstrapChainCaptureError("finality_store_config_invalid")
        if (
            not isinstance(config.get("scoring_policy_hash"), str)
            or _SHA256_RE.fullmatch(config["scoring_policy_hash"]) is None
            or not isinstance(config.get("finality_verifier_sha256"), str)
            or _SHA256_RE.fullmatch(config["finality_verifier_sha256"]) is None
        ):
            raise BootstrapChainCaptureError("finality_store_config_invalid")
        chain = _strict_mapping(config.get("chain_observation"), "finality_store_config_invalid")
        if chain.get("network") != "finney" or chain.get("genesis_block_hash") != (
            "2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
        ):
            raise BootstrapChainCaptureError("finality_store_network_mismatch")
        observer = _strict_mapping(config.get("observer"), "finality_store_config_invalid")
        required_observer = {
            "evidence_class": EVIDENCE_CLASS,
            "offline_finality_proof": False,
            "source_revision": SOURCE_REVISION,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "cargo_lock_sha256": CARGO_LOCK_SHA256,
            "fixture_set_sha256": FIXTURE_SET_SHA256,
            "binary_sha256": config["finality_verifier_sha256"],
            "genesis_hash": "0x" + chain["genesis_block_hash"],
        }
        if any(observer.get(key) != value for key, value in required_observer.items()):
            raise BootstrapChainCaptureError("finality_store_observer_pin_mismatch")
        for key in ("chain_spec_sha256",):
            if (
                not isinstance(observer.get(key), str)
                or _SHA256_RE.fullmatch(observer[key]) is None
            ):
                raise BootstrapChainCaptureError("finality_store_config_invalid")
        for key in ("bootstrap_block_number", "initial_minimum_finalized_block"):
            source = observer if key == "bootstrap_block_number" else config
            value = source.get(key)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 < value <= (_MAX_JSON_INTEGER)
            ):
                raise BootstrapChainCaptureError("finality_store_config_invalid")
        if (
            not isinstance(observer.get("bootstrap_block_hash"), str)
            or _HASH_RE.fullmatch(observer["bootstrap_block_hash"]) is None
        ):
            raise BootstrapChainCaptureError("finality_store_config_invalid")
        startup = config.get("startup_timeout_seconds")
        if isinstance(startup, bool) or not isinstance(startup, int) or not 1 <= startup <= 86_400:
            raise BootstrapChainCaptureError("finality_store_config_invalid")
        limits = _strict_mapping(config.get("limits"), "finality_store_config_invalid")
        try:
            parsed = GrandpaFinalitySupervisorLimits(**dict(limits))
        except (TypeError, ValueError) as error:
            raise BootstrapChainCaptureError("finality_store_config_invalid") from error
        if parsed.maximum_database_bytes > _MAX_STORE_BYTES:
            raise BootstrapChainCaptureError("finality_store_size_limit_too_large")
        return parsed

    def _read_evidence(self, minimum_height: int, maximum_height: int) -> OwnedFinalityEvidence:
        if not 0 < minimum_height <= maximum_height <= _MAX_JSON_INTEGER:
            raise ValueError("finality lookup interval is invalid")
        if maximum_height - minimum_height > MAX_FINALITY_ANCESTRY_HEADERS:
            raise ValueError("finality lookup interval exceeds the bridge limit")
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT h.*, s.minimum_finalized_block, s.maximum_records,
                       s.startup_timeout_seconds
                FROM finalized_headers AS h
                JOIN observer_segments AS s USING(segment_index)
                WHERE h.height BETWEEN ? AND ?
                ORDER BY h.height LIMIT 1
                """,
                (minimum_height, maximum_height),
            ).fetchone()
            if row is None:
                raise BootstrapChainCaptureError("owned_finality_head_unavailable")
            prior = None
            if row["segment_sequence"] > 0:
                prior = connection.execute(
                    """
                    SELECT * FROM finalized_headers
                    WHERE segment_index = ? AND segment_sequence = ?
                    """,
                    (row["segment_index"], row["segment_sequence"] - 1),
                ).fetchone()
                if prior is None:
                    raise BootstrapChainCaptureError("owned_finality_prior_missing")
            elif (
                row["previous_finalized_hash"] is not None
                or row["previous_transcript_digest"] != "0" * 64
            ):
                raise BootstrapChainCaptureError("owned_finality_first_record_invalid")

        binding = FinalityAttestationReplayBinding(
            minimum_finalized_block=row["minimum_finalized_block"],
            maximum_records=row["maximum_records"],
            startup_timeout_seconds=row["startup_timeout_seconds"],
            expected_sequence=row["segment_sequence"],
            previous_number=None if prior is None else prior["height"],
            previous_timestamp_ms=None if prior is None else prior["timestamp_ms"],
            previous_hash=None if prior is None else prior["block_hash"],
            previous_digest="0" * 64 if prior is None else prior["transcript_digest"],
        )
        attestation_bytes = bytes(row["canonical_evidence"])
        try:
            attestation = self._observer.validate_attestation(
                attestation_bytes,
                minimum_finalized_block=binding.minimum_finalized_block,
                maximum_records=binding.maximum_records,
                startup_timeout_seconds=binding.startup_timeout_seconds,
                expected_sequence=binding.expected_sequence,
                previous_hash=binding.previous_hash,
                previous_digest=binding.previous_digest,
                previous_number=binding.previous_number,
                previous_timestamp_ms=binding.previous_timestamp_ms,
            )
        except Exception as error:
            raise BootstrapChainCaptureError("owned_finality_attestation_invalid") from error
        expected_row = (
            attestation.block.number,
            attestation.block.hash,
            attestation.block.parent_hash,
            attestation.block.state_root,
            attestation.block.extrinsics_root,
            attestation.block.timestamp_ms,
            attestation.block.scale_header,
            hashlib.sha256(attestation_bytes).hexdigest(),
            attestation.transcript_digest,
            attestation.previous_transcript_digest,
            attestation.previous_finalized_hash,
            int(attestation.ancestry_complete_since_previous),
        )
        actual_row = (
            row["height"],
            row["block_hash"],
            row["parent_hash"],
            row["state_root"],
            row["extrinsics_root"],
            row["timestamp_ms"],
            row["scale_header"],
            row["evidence_sha256"],
            row["transcript_digest"],
            row["previous_transcript_digest"],
            row["previous_finalized_hash"],
            row["ancestry_complete"],
        )
        if actual_row != expected_row:
            raise BootstrapChainCaptureError("owned_finality_row_mismatch")
        receipt = canonical_json_bytes(
            {
                "schema": ACCEPTANCE_RECEIPT_SCHEMA,
                "height": row["height"],
                "block_hash": row["block_hash"],
                "evidence_sha256": row["evidence_sha256"],
                "segment_index": row["segment_index"],
                "segment_sequence": row["segment_sequence"],
                "restart_gap_before": bool(row["restart_gap_before"]),
                "accepted_at_unix_ms": row["accepted_at_unix_ms"],
                "previous_acceptance_digest": row["previous_acceptance_digest"],
                "acceptance_digest": row["acceptance_digest"],
            }
        )
        try:
            parse_finality_acceptance_receipt(receipt)
            attested_header = CapturedHeader(
                number=attestation.block.number,
                block_hash=attestation.block.hash,
                parent_hash=attestation.block.parent_hash,
                state_root=attestation.block.state_root,
                extrinsics_root=attestation.block.extrinsics_root,
                digest_logs=_digest_logs_from_scale_header(attestation.block.scale_header),
            )
        except ValueError as error:
            raise BootstrapChainCaptureError("owned_finality_acceptance_invalid") from error
        return OwnedFinalityEvidence(
            attested_header=attested_header,
            ancestry=attestation.ancestry,
            attestation=attestation_bytes,
            replay_binding=binding,
            acceptance_receipt=receipt,
        )

    async def evidence_at_or_after(
        self,
        minimum_height: int,
        maximum_height: int,
    ) -> OwnedFinalityEvidence:
        return await asyncio.to_thread(self._read_evidence, minimum_height, maximum_height)


def _digest_logs_from_scale_header(scale_header: str) -> list[str]:
    """Extract digest items from a SCALE header already validated by the observer."""

    raw = _hex_bytes(scale_header, "owned_finality_scale_header_invalid", 1024 * 1024)
    if len(raw) < 98:
        raise BootstrapChainCaptureError("owned_finality_scale_header_invalid")
    offset = 32
    first = raw[offset]
    mode = first & 3
    if mode == 0:
        number_length = 1
    elif mode == 1:
        number_length = 2
    elif mode == 2:
        number_length = 4
    else:
        number_length = (first >> 2) + 5
    offset += number_length + 64
    count, consumed = _decode_compact(raw[offset:], "owned_finality_digest_invalid")
    offset += consumed
    if count > 256:
        raise BootstrapChainCaptureError("owned_finality_digest_limit")
    logs: list[str] = []
    for _ in range(count):
        start = offset
        if offset >= len(raw):
            raise BootstrapChainCaptureError("owned_finality_digest_invalid")
        variant = raw[offset]
        offset += 1
        if variant == 0:
            length, used = _decode_compact(raw[offset:], "owned_finality_digest_invalid")
            offset += used + length
        elif variant in {4, 5, 6}:
            offset += 4
            length, used = _decode_compact(raw[offset:], "owned_finality_digest_invalid")
            offset += used + length
        elif variant == 8:
            pass
        else:
            raise BootstrapChainCaptureError("owned_finality_digest_invalid")
        if offset > len(raw):
            raise BootstrapChainCaptureError("owned_finality_digest_invalid")
        logs.append("0x" + raw[start:offset].hex())
    if offset != len(raw):
        raise BootstrapChainCaptureError("owned_finality_digest_invalid")
    return logs


def _decode_compact(raw: bytes, reason_code: str) -> tuple[int, int]:
    if not raw:
        raise BootstrapChainCaptureError(reason_code)
    mode = raw[0] & 3
    if mode == 0:
        return raw[0] >> 2, 1
    if mode == 1:
        if len(raw) < 2:
            raise BootstrapChainCaptureError(reason_code)
        return int.from_bytes(raw[:2], "little") >> 2, 2
    if mode == 2:
        if len(raw) < 4:
            raise BootstrapChainCaptureError(reason_code)
        return int.from_bytes(raw[:4], "little") >> 2, 4
    length = (raw[0] >> 2) + 4
    if length > 8 or len(raw) < length + 1:
        raise BootstrapChainCaptureError(reason_code)
    return int.from_bytes(raw[1 : length + 1], "little"), length + 1


@dataclass(frozen=True, slots=True)
class _Target:
    role: str
    block_number: int
    block_hash: str
    extrinsic_index: int


class BootstrapChainCollector:
    def __init__(
        self,
        *,
        rpc: RawJsonRpc,
        finality: OwnedFinalityPort,
        runtime_key_factory: RuntimeKeyFactory = _runtime_system_events_key,
        bridge_concurrency: int = _DEFAULT_BRIDGE_CONCURRENCY,
    ) -> None:
        if not callable(getattr(rpc, "request", None)):
            raise TypeError("rpc must implement RawJsonRpc")
        if not callable(getattr(finality, "evidence_at_or_after", None)):
            raise TypeError("finality must implement OwnedFinalityPort")
        if not callable(runtime_key_factory):
            raise TypeError("runtime_key_factory must be callable")
        if (
            isinstance(bridge_concurrency, bool)
            or not isinstance(bridge_concurrency, int)
            or not 1 <= bridge_concurrency <= _MAX_BRIDGE_CONCURRENCY
        ):
            raise ValueError("bridge concurrency is outside the safe range")
        self._rpc = rpc
        self._finality = finality
        self._runtime_key_factory = runtime_key_factory
        self._bridge_concurrency = bridge_concurrency
        self._header_cache: dict[int, CapturedHeader] = {}

    async def collect(
        self,
        *,
        signed: SignedSupervisorBootstrapResult,
        owner_cli_response: bytes,
        preserved_owner_rpc_capture: bytes | None = None,
    ) -> BootstrapChainCapture:
        owner = _parse_owner_cli_response(owner_cli_response)
        result = signed.result
        owner_reference = result.owner_fence_receipt.extrinsic
        if owner_reference is not None and (
            owner_reference.block_number != owner.block_number
            or owner_reference.block_hash != owner.block_hash
            or owner_reference.extrinsic_index != owner.extrinsic_index
        ):
            raise BootstrapChainCaptureError("owner_cli_result_reference_mismatch")
        if preserved_owner_rpc_capture is not None and (
            not preserved_owner_rpc_capture
            or len(preserved_owner_rpc_capture) > MAX_RAW_RPC_CAPTURE_BYTES // 2
        ):
            raise BootstrapChainCaptureError("owner_rpc_capture_size_invalid")
        targets = (
            _Target(
                role="owner_fence",
                block_number=owner.block_number,
                block_hash=owner.block_hash,
                extrinsic_index=owner.extrinsic_index,
            ),
            _Target(
                role="manifest_anchor",
                block_number=result.submission_receipt.anchor.block_number,
                block_hash=result.submission_receipt.anchor.block_hash,
                extrinsic_index=result.submission_receipt.anchor.extrinsic_index,
            ),
            _Target(
                role="weight_call",
                block_number=result.submission_receipt.weight_call.block_number,
                block_hash=result.submission_receipt.weight_call.block_hash,
                extrinsic_index=result.submission_receipt.weight_call.extrinsic_index,
            ),
        )
        if len({(item.block_hash, item.extrinsic_index) for item in targets}) != 3:
            raise BootstrapChainCaptureError("bootstrap_target_reference_repeated")
        blocks: list[CapturedBootstrapBlock] = []
        for target in targets:
            blocks.append(
                await self._collect_block(
                    target,
                    preserved_source=(
                        preserved_owner_rpc_capture if target.role == "owner_fence" else None
                    ),
                )
            )
        try:
            capture = BootstrapChainCapture(
                schema=BOOTSTRAP_CHAIN_CAPTURE_SCHEMA,
                protocol=PROTOCOL_VERSION,
                network="finney",
                netuid=78,
                mechanism_id=0,
                submission_id=result.submission_id,
                blocks=blocks,
            )
        except ValueError as error:
            raise BootstrapChainCaptureError("bootstrap_chain_capture_invalid") from error
        if len(canonical_json_bytes(capture)) > MAX_CAPTURE_BYTES:
            raise BootstrapChainCaptureError("bootstrap_chain_capture_size_limit")
        return capture

    async def _collect_block(
        self,
        target: _Target,
        *,
        preserved_source: bytes | None,
    ) -> CapturedBootstrapBlock:
        recorder = _RecordingRpc(self._rpc)
        canonical_hash = _hash(
            await recorder.request("chain_getBlockHash", (target.block_number,)),
            "target_block_hash_invalid",
        )
        if canonical_hash != target.block_hash:
            raise BootstrapChainCaptureError("target_block_hash_mismatch")
        header = _captured_header(
            await recorder.request("chain_getHeader", (target.block_hash,)),
            expected_number=target.block_number,
            expected_hash=target.block_hash,
            reason_prefix="target",
        )
        self._header_cache[header.number] = header
        parent_number = target.block_number - 1
        parent_hash = _hash(
            await recorder.request("chain_getBlockHash", (parent_number,)),
            "parent_block_hash_invalid",
        )
        if parent_hash != header.parent_hash:
            raise BootstrapChainCaptureError("parent_block_hash_mismatch")
        parent = _captured_header(
            await recorder.request("chain_getHeader", (parent_hash,)),
            expected_number=parent_number,
            expected_hash=parent_hash,
            reason_prefix="parent",
        )
        self._header_cache[parent.number] = parent

        block_response = _strict_mapping(
            await recorder.request("chain_getBlock", (target.block_hash,)),
            "target_block_body_invalid",
        )
        if set(block_response).difference({"block", "justifications"}):
            raise BootstrapChainCaptureError("target_block_body_invalid")
        block = _strict_mapping(block_response.get("block"), "target_block_body_invalid")
        if set(block) != {"header", "extrinsics"}:
            raise BootstrapChainCaptureError("target_block_body_invalid")
        body_header = _captured_header(
            block.get("header"),
            expected_number=target.block_number,
            expected_hash=target.block_hash,
            reason_prefix="body",
        )
        if body_header != header:
            raise BootstrapChainCaptureError("target_block_body_header_mismatch")
        encoded_extrinsics = _strict_sequence(
            block.get("extrinsics"),
            "target_block_extrinsics_invalid",
        )
        if not encoded_extrinsics or len(encoded_extrinsics) > MAX_EXTRINSICS:
            raise BootstrapChainCaptureError("target_block_extrinsics_limit")
        extrinsics: list[bytes] = []
        total_body_bytes = 0
        for item in encoded_extrinsics:
            raw = _hex_bytes(item, "target_extrinsic_invalid", MAX_EXTRINSIC_BYTES)
            total_body_bytes += len(raw)
            if total_body_bytes > MAX_BLOCK_BODY_BYTES:
                raise BootstrapChainCaptureError("target_block_body_size_limit")
            extrinsics.append(raw)
        if target.extrinsic_index >= len(extrinsics):
            raise BootstrapChainCaptureError("target_extrinsic_index_invalid")

        version_value = _strict_mapping(
            await recorder.request("state_getRuntimeVersion", (parent_hash,)),
            "execution_runtime_version_invalid",
        )
        try:
            version_bytes = canonical_json_bytes(dict(version_value))
        except Exception as error:
            raise BootstrapChainCaptureError("execution_runtime_version_invalid") from error
        if len(version_bytes) > MAX_RUNTIME_VERSION_BYTES:
            raise BootstrapChainCaptureError("execution_runtime_version_limit")
        metadata = _hex_bytes(
            await recorder.request("state_getMetadata", (parent_hash,)),
            "execution_runtime_metadata_invalid",
            MAX_METADATA_BYTES,
        )
        storage_key = self._runtime_key_factory(metadata, version_value)
        if not isinstance(storage_key, bytes) or not storage_key or len(storage_key) > 512:
            raise BootstrapChainCaptureError("system_events_key_invalid")
        key_hex = "0x" + storage_key.hex()
        events = _hex_bytes(
            await recorder.request("state_getStorageAt", (key_hex, target.block_hash)),
            "system_events_value_invalid",
            MAX_EVENTS_BYTES,
        )
        proof_response = _strict_mapping(
            await recorder.request(
                "state_getReadProof",
                ([key_hex], target.block_hash),
            ),
            "system_events_proof_invalid",
        )
        if (
            set(proof_response) != {"at", "proof"}
            or _hash(
                proof_response.get("at"),
                "system_events_proof_invalid",
            )
            != target.block_hash
        ):
            raise BootstrapChainCaptureError("system_events_proof_block_mismatch")
        proof_values = _strict_sequence(
            proof_response.get("proof"),
            "system_events_proof_invalid",
        )
        if not proof_values or len(proof_values) > MAX_PROOF_NODES:
            raise BootstrapChainCaptureError("system_events_proof_limit")
        proof_nodes: list[bytes] = []
        seen: set[bytes] = set()
        proof_bytes = 0
        for value in proof_values:
            node = _hex_bytes(value, "system_events_proof_invalid", MAX_PROOF_NODE_BYTES)
            proof_bytes += len(node)
            if node in seen or proof_bytes > MAX_PROOF_BYTES:
                raise BootstrapChainCaptureError("system_events_proof_limit")
            seen.add(node)
            proof_nodes.append(node)

        finality = await self._finality.evidence_at_or_after(
            target.block_number,
            target.block_number + MAX_FINALITY_ANCESTRY_HEADERS,
        )
        identity = (header.number, header.block_hash, header.parent_hash)
        if identity in finality.ancestry:
            descendant_headers: list[CapturedHeader] = []
        else:
            descendant_headers = await self._descendant_bridge(
                header,
                finality.attested_header,
            )
        raw_capture_value: dict[str, Any] = {
            "schema": BOOTSTRAP_RAW_RPC_CAPTURE_SCHEMA,
            "role": target.role,
            "target": {
                "block_number": target.block_number,
                "block_hash": target.block_hash,
                "extrinsic_index": target.extrinsic_index,
            },
            "rpc_calls": recorder.records,
            "preserved_source": None,
        }
        if preserved_source is not None:
            raw_capture_value["preserved_source"] = {
                "sha256": hashlib.sha256(preserved_source).hexdigest(),
                "size_bytes": len(preserved_source),
                "bytes_hex": "0x" + preserved_source.hex(),
            }
        raw_capture = canonical_json_bytes(raw_capture_value)
        if len(raw_capture) > MAX_RAW_RPC_CAPTURE_BYTES:
            raise BootstrapChainCaptureError("raw_rpc_capture_size_limit")
        target_bytes = extrinsics[target.extrinsic_index]
        try:
            return CapturedBootstrapBlock(
                schema=BOOTSTRAP_CHAIN_BLOCK_SCHEMA,
                role=target.role,
                header=header,
                extrinsic_index=target.extrinsic_index,
                target_extrinsic_sha256=hashlib.sha256(target_bytes).hexdigest(),
                target_extrinsic_blake2b256=(
                    "0x" + hashlib.blake2b(target_bytes, digest_size=32).hexdigest()
                ),
                body_sha256=_body_sha256(extrinsics),
                extrinsics_hex=["0x" + item.hex() for item in extrinsics],
                raw_rpc_capture_hex="0x" + raw_capture.hex(),
                raw_rpc_capture_sha256=hashlib.sha256(raw_capture).hexdigest(),
                runtime=CapturedRuntime(
                    execution_parent_header=parent,
                    pin=RuntimePinObject(
                        metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                        spec_version=_runtime_integer(version_value, "specVersion"),
                        transaction_version=_runtime_integer(
                            version_value,
                            "transactionVersion",
                        ),
                        state_version=_runtime_integer(version_value, "stateVersion"),
                        ss58_prefix=42,
                    ),
                    metadata_hex="0x" + metadata.hex(),
                    metadata_sha256=hashlib.sha256(metadata).hexdigest(),
                    runtime_version_hex="0x" + version_bytes.hex(),
                    runtime_version_sha256=hashlib.sha256(version_bytes).hexdigest(),
                ),
                system_events=CapturedSystemEvents(
                    storage_key_hex=key_hex,
                    value_hex="0x" + events.hex(),
                    value_sha256=hashlib.sha256(events).hexdigest(),
                    proof_node_hex=["0x" + item.hex() for item in proof_nodes],
                ),
                finality=CapturedFinality(
                    attestation_hex="0x" + finality.attestation.hex(),
                    attestation_sha256=hashlib.sha256(finality.attestation).hexdigest(),
                    replay_binding=FinalityReplayBindingObject.from_evidence(
                        finality.replay_binding
                    ),
                    acceptance_receipt_hex="0x" + finality.acceptance_receipt.hex(),
                    acceptance_receipt_sha256=hashlib.sha256(
                        finality.acceptance_receipt
                    ).hexdigest(),
                    descendant_headers=descendant_headers,
                ),
            )
        except ValueError as error:
            raise BootstrapChainCaptureError("captured_bootstrap_block_invalid") from error

    async def _descendant_bridge(
        self,
        target: CapturedHeader,
        attested: CapturedHeader,
    ) -> list[CapturedHeader]:
        count = attested.number - target.number
        if not 1 <= count <= MAX_FINALITY_ANCESTRY_HEADERS:
            raise BootstrapChainCaptureError("finality_descendant_bridge_limit")
        result: list[CapturedHeader] = []
        for start in range(target.number + 1, attested.number + 1, self._bridge_concurrency):
            numbers = range(start, min(start + self._bridge_concurrency, attested.number + 1))
            chunk = await asyncio.gather(*(self._header_at(number) for number in numbers))
            result.extend(chunk)
        previous = target
        for header in result:
            if header.number != previous.number + 1 or header.parent_hash != previous.block_hash:
                raise BootstrapChainCaptureError("finality_descendant_bridge_not_contiguous")
            previous = header
        if result[-1] != attested:
            raise BootstrapChainCaptureError("finality_descendant_bridge_head_mismatch")
        return result

    async def _header_at(self, number: int) -> CapturedHeader:
        cached = self._header_cache.get(number)
        if cached is not None:
            return cached
        block_hash = _hash(
            await self._rpc.request("chain_getBlockHash", (number,)),
            "bridge_block_hash_invalid",
        )
        header = _captured_header(
            await self._rpc.request("chain_getHeader", (block_hash,)),
            expected_number=number,
            expected_hash=block_hash,
            reason_prefix="bridge",
        )
        self._header_cache[number] = header
        return header


def _runtime_integer(version: Mapping[str, Any], key: str) -> int:
    value = version.get(key)
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise BootstrapChainCaptureError("execution_runtime_version_invalid")
    return value


async def collect_bootstrap_chain_capture(
    *,
    signed_result_bytes: bytes,
    owner_cli_response_bytes: bytes,
    rpc: RawJsonRpc,
    finality: OwnedFinalityPort,
    preserved_owner_rpc_capture: bytes | None = None,
    runtime_key_factory: RuntimeKeyFactory = _runtime_system_events_key,
    bridge_concurrency: int = _DEFAULT_BRIDGE_CONCURRENCY,
) -> BootstrapChainCapture:
    try:
        signed = parse_canonical_signed_supervisor_bootstrap_result(signed_result_bytes)
    except ValueError as error:
        raise BootstrapChainCaptureError("signed_bootstrap_result_invalid") from error
    collector = BootstrapChainCollector(
        rpc=rpc,
        finality=finality,
        runtime_key_factory=runtime_key_factory,
        bridge_concurrency=bridge_concurrency,
    )
    return await collector.collect(
        signed=signed,
        owner_cli_response=owner_cli_response_bytes,
        preserved_owner_rpc_capture=preserved_owner_rpc_capture,
    )


def write_new_chain_capture(path: Path, capture: BootstrapChainCapture) -> None:
    payload = canonical_json_bytes(capture)
    if not payload or len(payload) > MAX_CAPTURE_BYTES:
        raise BootstrapChainCaptureError("bootstrap_chain_capture_size_limit")
    path = path.absolute()
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise BootstrapChainCaptureError("bootstrap_chain_capture_parent_unsafe")
    descriptor = -1
    temporary: Path | None = None
    try:
        descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(name)
        os.fchmod(descriptor, 0o600)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short capture write")
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise BootstrapChainCaptureError("bootstrap_chain_capture_already_exists") from error
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        if _read_bounded_regular_file(path, MAX_CAPTURE_BYTES) != payload:
            raise BootstrapChainCaptureError("bootstrap_chain_capture_write_mismatch")
    except BootstrapChainCaptureError:
        raise
    except OSError as error:
        raise BootstrapChainCaptureError("bootstrap_chain_capture_write_failed") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary is not None:
            with contextlib.suppress(OSError):
                temporary.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umi-bootstrap-chain-capture",
        description="Collect proof-carrying chain material for one signed bootstrap result",
    )
    parser.add_argument("--signed-result", type=Path, required=True)
    parser.add_argument("--owner-cli-result", type=Path, required=True)
    parser.add_argument("--owner-raw-rpc-capture", type=Path)
    parser.add_argument("--state-db", type=Path, required=True)
    parser.add_argument("--finality-verifier", type=Path, required=True)
    parser.add_argument("--chain-spec", type=Path, required=True)
    parser.add_argument("--rpc-endpoint", default=DEFAULT_FINNEY_RPC_ENDPOINT)
    parser.add_argument("--bridge-concurrency", type=int, default=_DEFAULT_BRIDGE_CONCURRENCY)
    parser.add_argument("--output", type=Path, required=True)
    return parser


async def _run(args: argparse.Namespace) -> int:
    finality = DurableOwnedFinalityReader(
        state_path=args.state_db.absolute(),
        finality_verifier=args.finality_verifier.absolute(),
        chain_spec=args.chain_spec.absolute(),
    )
    rpc = BittensorRawJsonRpc(SimpleNamespace(endpoint=args.rpc_endpoint))
    preserved = (
        None
        if args.owner_raw_rpc_capture is None
        else _read_bounded_regular_file(
            args.owner_raw_rpc_capture,
            MAX_RAW_RPC_CAPTURE_BYTES // 2,
        )
    )
    capture = await collect_bootstrap_chain_capture(
        signed_result_bytes=_read_bounded_regular_file(
            args.signed_result,
            MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES,
        ),
        owner_cli_response_bytes=_read_bounded_regular_file(
            args.owner_cli_result,
            MAX_OWNER_CLI_BYTES,
        ),
        rpc=rpc,
        finality=finality,
        preserved_owner_rpc_capture=preserved,
        bridge_concurrency=args.bridge_concurrency,
    )
    write_new_chain_capture(args.output, capture)
    print(
        canonical_json_bytes(
            {
                "output": str(args.output.absolute()),
                "sha256": hashlib.sha256(canonical_json_bytes(capture)).hexdigest(),
                "status": "bootstrap_chain_capture_complete",
                "submission_id": capture.submission_id,
            }
        ).decode("utf-8")
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    return asyncio.run(_run(_parser().parse_args(argv)))


__all__ = [
    "BOOTSTRAP_RAW_RPC_CAPTURE_SCHEMA",
    "DEFAULT_FINNEY_RPC_ENDPOINT",
    "BootstrapChainCaptureError",
    "BootstrapChainCollector",
    "DurableOwnedFinalityReader",
    "OwnedFinalityEvidence",
    "collect_bootstrap_chain_capture",
    "main",
    "write_new_chain_capture",
]


if __name__ == "__main__":
    raise SystemExit(main())
