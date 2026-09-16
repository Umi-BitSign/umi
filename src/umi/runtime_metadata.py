"""Derive a codec from proof-backed Wasm without trusting RPC metadata.

This is a read-only building block. The signing path requires a separate signed
authorization that explicitly binds the execution verifier, plus matching
installed configuration. Constructing this codec does not grant that authority.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import subprocess
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

import bittensor_core

from .chain_evidence import FinalizedSnapshotRef, StorageEvidence
from .pinned_artifact import PinnedArtifact, PinnedArtifactError, staged_pinned_artifacts
from .protocol import canonical_json_bytes
from .validator_chain import FinalizedRuntimePin, PinnedRuntimeContext

MAX_CODE_BYTES = 8 * 1024**2
MAX_METADATA_BYTES = 16 * 1024**2
MAX_RESPONSE_BYTES = 2 * MAX_METADATA_BYTES + 4096
_HASH = re.compile(r"^[0-9a-f]{64}$")
_HEX = re.compile(r"^(?:[0-9a-f]{2})+$")
_FIELDS = frozenset(
    {
        "schema",
        "runtime_code_sha256",
        "metadata_sha256",
        "metadata_hex",
        "spec_version",
        "transaction_version",
        "state_version",
        "chain_submission_authorized",
    }
)


class RuntimeMetadataError(RuntimeError):
    def __init__(self, reason_code: str):
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class ExecutedRuntimeContext(PinnedRuntimeContext):
    code_evidence: StorageEvidence
    executor_sha256: str

    def __post_init__(self):
        PinnedRuntimeContext.__post_init__(self)
        if (
            not isinstance(self.code_evidence, StorageEvidence)
            or self.code_evidence.snapshot != self.snapshot
            or self.code_evidence.verified_state_root != self.snapshot.state_root
            or self.code_evidence.storage_key != b":code"
            or not self.code_evidence.value
            or not isinstance(self.executor_sha256, str)
            or not _HASH.fullmatch(self.executor_sha256)
        ):
            raise RuntimeMetadataError("executed_runtime_binding_invalid")

    @property
    def storage_codec_mode(self) -> str:
        return "executed_runtime/1"


class RuntimeMetadataExecutor:
    """Execute only :code already authenticated by a storage-proof collector."""

    def __init__(self, *, binary_path: Path, expected_sha256: str, timeout_seconds: float = 15):
        if not isinstance(binary_path, Path) or not binary_path.is_absolute():
            raise ValueError("runtime executor path must be absolute")
        if not isinstance(expected_sha256, str) or not _HASH.fullmatch(expected_sha256):
            raise ValueError("runtime executor digest must be SHA-256 hexadecimal")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 45
        ):
            raise ValueError("runtime executor timeout must be in (0, 45]")
        self.binary_path = binary_path
        self.expected_sha256 = expected_sha256
        self.timeout_seconds = timeout_seconds

    def execute(self, snapshot: FinalizedSnapshotRef, evidence: StorageEvidence):
        if (
            not isinstance(snapshot, FinalizedSnapshotRef)
            or not isinstance(evidence, StorageEvidence)
            or evidence.snapshot != snapshot
            or evidence.verified_state_root != snapshot.state_root
            or evidence.storage_key != b":code"
            or not isinstance(evidence.value, bytes)
            or not 0 < len(evidence.value) <= MAX_CODE_BYTES
        ):
            raise RuntimeMetadataError("runtime_code_evidence_invalid")
        raw = self._invoke(evidence.value)
        if (
            not raw
            or len(raw) > MAX_RESPONSE_BYTES
            or raw.count(b"\n") != 1
            or not raw.endswith(b"\n")
        ):
            raise RuntimeMetadataError("runtime_execution_response_invalid")
        try:
            value = json.loads(raw)
            if (
                not isinstance(value, dict)
                or set(value) != _FIELDS
                or value["schema"] != "umi-runtime-metadata-execution/1"
                or value["chain_submission_authorized"] is not False
                or value["runtime_code_sha256"] != hashlib.sha256(evidence.value).hexdigest()
                or not isinstance(value["metadata_hex"], str)
                or len(value["metadata_hex"]) > 2 * MAX_METADATA_BYTES
                or not _HEX.fullmatch(value["metadata_hex"])
            ):
                raise ValueError("response binding")
            for name in ("spec_version", "transaction_version"):
                if type(value[name]) is not int or not 0 < value[name] < 2**32:
                    raise ValueError("runtime version")
            if type(value["state_version"]) is not int or value["state_version"] != 1:
                raise ValueError("state version")
            metadata = bytes.fromhex(value["metadata_hex"])
            if not metadata.startswith(b"meta") or len(metadata) < 5:
                raise ValueError("metadata header")
            pin = FinalizedRuntimePin(
                metadata_sha256=value["metadata_sha256"],
                spec_version=value["spec_version"],
                transaction_version=value["transaction_version"],
                state_version=value["state_version"],
            )
            if hashlib.sha256(metadata).hexdigest() != pin.metadata_sha256:
                raise ValueError("metadata digest")
            runtime = bittensor_core.Runtime(
                metadata, pin.spec_version, pin.transaction_version, ss58_format=pin.ss58_prefix
            )
            if (
                runtime.spec_version != pin.spec_version
                or runtime.transaction_version != pin.transaction_version
                or runtime.constant("System", "SS58Prefix") != pin.ss58_prefix
            ):
                raise ValueError("codec binding")
            return ExecutedRuntimeContext(
                snapshot=snapshot,
                pin=pin,
                metadata_bytes=metadata,
                runtime_version_bytes=canonical_json_bytes(
                    {
                        "specVersion": pin.spec_version,
                        "transactionVersion": pin.transaction_version,
                        "stateVersion": pin.state_version,
                    }
                ),
                _runtime=runtime,
                code_evidence=evidence,
                executor_sha256=self.expected_sha256,
            )
        except (ValueError, TypeError, KeyError, RuntimeError) as error:
            raise RuntimeMetadataError("runtime_execution_response_invalid") from error

    def _invoke(self, code: bytes) -> bytes:
        specification = PinnedArtifact(
            "runtime-metadata",
            self.binary_path,
            self.expected_sha256,
            maximum_bytes=128 * 1024**2,
            executable=True,
        )
        try:
            with staged_pinned_artifacts((specification,)) as staged:
                process = subprocess.Popen(
                    [str(staged["runtime-metadata"])],
                    stdin=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    close_fds=True,
                    start_new_session=True,
                    env={"LANG": "C", "LC_ALL": "C"},
                )
                try:
                    stdout, _ = process.communicate(code, timeout=self.timeout_seconds)
                except subprocess.TimeoutExpired as error:
                    with suppress(ProcessLookupError):
                        os.killpg(process.pid, signal.SIGKILL)
                    process.communicate()
                    raise RuntimeMetadataError("runtime_execution_timeout") from error
                if process.returncode:
                    raise RuntimeMetadataError("runtime_execution_failed")
                return stdout
        except PinnedArtifactError as error:
            raise RuntimeMetadataError(error.reason_code) from error
        except OSError as error:
            raise RuntimeMetadataError("runtime_executor_unavailable") from error
