"""Content-pinned Substrate LayoutV1 storage-proof verification.

Python does not implement the Substrate trie.  This adapter delegates only the
pure proof check to UMI's pinned Rust helper, using a bounded one-shot NDJSON
exchange.  It performs no RPC, signing, composition, or chain mutation.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import signal
import subprocess
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

from .pinned_artifact import PinnedArtifact, PinnedArtifactError, staged_pinned_artifacts

REQUEST_SCHEMA = "umi-substrate-proof/1"
EXTRINSICS_ROOT_REQUEST_SCHEMA = "umi-substrate-extrinsics-root/1"
RESPONSE_SCHEMA = "umi-substrate-proof-result/1"
STATE_VERSION = 1

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CODES = frozenset(
    {
        "invalid_input",
        "unsupported_state_version",
        "duplicate_node",
        "invalid_proof",
        "invalid_extrinsics_root",
    }
)


class SubstrateProofVerifierError(RuntimeError):
    """A stable, fail-closed verifier boundary error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"Substrate proof verifier failed: {reason_code}")


@dataclass(frozen=True, slots=True)
class SubstrateProofLimits:
    """Local bounds mirrored by the Rust verifier."""

    maximum_binary_bytes: int = 64 * 1024 * 1024
    maximum_items: int = 4_096
    maximum_key_bytes: int = 512
    maximum_value_bytes: int = 16 * 1024 * 1024
    maximum_proof_nodes: int = 4_096
    maximum_proof_node_bytes: int = 2 * 1024 * 1024
    maximum_proof_bytes: int = 32 * 1024 * 1024
    maximum_extrinsics: int = 4_096
    maximum_extrinsic_bytes: int = 16 * 1024 * 1024
    maximum_block_body_bytes: int = 64 * 1024 * 1024
    maximum_request_bytes: int = 160 * 1024 * 1024
    maximum_response_bytes: int = 4 * 1024

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


class SubprocessStorageProofVerifier:
    """Verify state proofs with an absolute, SHA-256-pinned Rust executable.

    The process is deliberately one-shot: EOF after the single request makes
    lifecycle and timeout handling unambiguous.  The Rust binary itself supports
    persistent NDJSON for a future supervised worker without changing the wire
    schema.
    """

    def __init__(
        self,
        *,
        binary_path: str | os.PathLike[str],
        expected_sha256: str,
        timeout_seconds: float = 5.0,
        limits: SubstrateProofLimits | None = None,
    ) -> None:
        path = Path(binary_path)
        if not path.is_absolute():
            raise ValueError("binary_path must be absolute")
        if not isinstance(expected_sha256, str) or _SHA256_RE.fullmatch(expected_sha256) is None:
            raise ValueError("expected_sha256 must be lowercase hexadecimal without a prefix")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or timeout_seconds <= 0
        ):
            raise ValueError("timeout_seconds must be a positive finite number")
        if limits is not None and not isinstance(limits, SubstrateProofLimits):
            raise TypeError("limits must be SubstrateProofLimits or None")

        self._binary_path = path
        self._expected_sha256 = expected_sha256
        self._timeout_seconds = float(timeout_seconds)
        self._limits = limits or SubstrateProofLimits()
        self._assert_binary_integrity()

    @property
    def binary_path(self) -> Path:
        return self._binary_path

    @property
    def expected_sha256(self) -> str:
        return self._expected_sha256

    def _assert_binary_integrity(self) -> None:
        try:
            with self._staged_binary():
                pass
        except PinnedArtifactError as error:
            raise SubstrateProofVerifierError(error.reason_code) from error

    def _staged_binary(self):
        return staged_pinned_artifacts(
            (
                PinnedArtifact(
                    name="binary",
                    source=self._binary_path,
                    expected_sha256=self._expected_sha256,
                    maximum_bytes=self._limits.maximum_binary_bytes,
                    executable=True,
                ),
            )
        )

    @staticmethod
    def _require_bytes(value: object, *, field: str, allow_empty: bool = False) -> bytes:
        if not isinstance(value, bytes) or (not value and not allow_empty):
            requirement = "bytes" if allow_empty else "non-empty bytes"
            raise ValueError(f"{field} must be {requirement}")
        return value

    @staticmethod
    def _request_id(
        *,
        state_root: bytes,
        items: tuple[tuple[bytes, bytes | None], ...],
        proof: tuple[bytes, ...],
    ) -> str:
        digest = hashlib.sha256(b"umi-substrate-proof-request-v1\0")
        digest.update(state_root)
        digest.update(len(items).to_bytes(4, "big"))
        for key, value in items:
            digest.update(len(key).to_bytes(8, "big"))
            digest.update(key)
            if value is None:
                digest.update(b"\x00")
            else:
                digest.update(b"\x01")
                digest.update(len(value).to_bytes(8, "big"))
                digest.update(value)
        digest.update(len(proof).to_bytes(4, "big"))
        for node in proof:
            digest.update(len(node).to_bytes(8, "big"))
            digest.update(node)
        return digest.hexdigest()

    @staticmethod
    def _extrinsics_root_request_id(
        *,
        expected_root: bytes,
        extrinsics: tuple[bytes, ...],
        state_version: int,
    ) -> str:
        digest = hashlib.sha256(b"umi-substrate-extrinsics-root-request-v1\0")
        digest.update(state_version.to_bytes(1, "big"))
        digest.update(expected_root)
        digest.update(len(extrinsics).to_bytes(4, "big"))
        for extrinsic in extrinsics:
            digest.update(len(extrinsic).to_bytes(8, "big"))
            digest.update(extrinsic)
        return digest.hexdigest()

    def _preflight(
        self,
        *,
        state_root: bytes,
        items: tuple[tuple[bytes, bytes | None], ...],
        proof: tuple[bytes, ...],
    ) -> tuple[tuple[bytes, bytes | None], ...]:
        self._require_bytes(state_root, field="state_root")
        if len(state_root) != 32:
            raise ValueError("state_root must contain exactly 32 bytes")
        if not isinstance(items, tuple) or not items or len(items) > self._limits.maximum_items:
            raise ValueError("items must be a non-empty bounded tuple")

        checked_items: list[tuple[bytes, bytes | None]] = []
        for index, item in enumerate(items):
            if not isinstance(item, tuple) or len(item) != 2:
                raise ValueError(f"items[{index}] must be a (key, value) tuple")
            key = self._require_bytes(item[0], field=f"items[{index}].key")
            if len(key) > self._limits.maximum_key_bytes:
                raise ValueError(f"items[{index}].key exceeds the byte limit")
            value = item[1]
            if value is not None:
                value = self._require_bytes(value, field=f"items[{index}].value", allow_empty=True)
                if len(value) > self._limits.maximum_value_bytes:
                    raise ValueError(f"items[{index}].value exceeds the byte limit")
            checked_items.append((key, value))
        checked_items.sort(key=lambda item: item[0])
        if any(left[0] == right[0] for left, right in pairwise(checked_items)):
            raise ValueError("items must contain unique storage keys")

        if not isinstance(proof, tuple) or not proof:
            raise ValueError("proof must be a non-empty tuple")
        if len(proof) > self._limits.maximum_proof_nodes:
            raise ValueError("proof exceeds the node-count limit")
        proof_bytes = 0
        seen_nodes: set[bytes] = set()
        for index, node in enumerate(proof):
            node = self._require_bytes(node, field=f"proof[{index}]")
            if len(node) > self._limits.maximum_proof_node_bytes:
                raise ValueError(f"proof[{index}] exceeds the node byte limit")
            proof_bytes += len(node)
            if proof_bytes > self._limits.maximum_proof_bytes:
                raise ValueError("proof exceeds the total byte limit")
            if node in seen_nodes:
                raise ValueError("proof contains a duplicate node")
            seen_nodes.add(node)
        return tuple(checked_items)

    def _invoke(self, request_bytes: bytes, *, request_id: str) -> bool:
        if len(request_bytes) > self._limits.maximum_request_bytes:
            raise ValueError("encoded proof request exceeds the byte limit")

        try:
            with self._staged_binary() as staged:
                return self._invoke_staged(
                    staged["binary"],
                    request_bytes=request_bytes,
                    request_id=request_id,
                )
        except PinnedArtifactError as error:
            raise SubstrateProofVerifierError(error.reason_code) from error

    def _invoke_staged(
        self,
        executable: Path,
        *,
        request_bytes: bytes,
        request_id: str,
    ) -> bool:

        process: subprocess.Popen[bytes]
        try:
            process = subprocess.Popen(
                [os.fspath(executable)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env={"LANG": "C", "LC_ALL": "C"},
            )
        except OSError as error:
            raise SubstrateProofVerifierError("sidecar_start_failed") from error
        try:
            stdout, _ = process.communicate(
                input=request_bytes + b"\n", timeout=self._timeout_seconds
            )
        except subprocess.TimeoutExpired as error:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (AttributeError, OSError):
                process.kill()
            process.communicate()
            raise SubstrateProofVerifierError("sidecar_timeout") from error

        if process.returncode != 0:
            raise SubstrateProofVerifierError("sidecar_failed")
        if (
            not stdout
            or len(stdout) > self._limits.maximum_response_bytes
            or not stdout.endswith(b"\n")
            or stdout.count(b"\n") != 1
        ):
            raise SubstrateProofVerifierError("invalid_sidecar_response")
        try:
            response = json.loads(stdout[:-1])
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SubstrateProofVerifierError("invalid_sidecar_response") from error
        if not isinstance(response, dict):
            raise SubstrateProofVerifierError("invalid_sidecar_response")
        if response.get("schema") != RESPONSE_SCHEMA or response.get("request_id") != request_id:
            raise SubstrateProofVerifierError("invalid_sidecar_response")
        if response.get("ok") is True:
            if set(response) != {"schema", "request_id", "ok"}:
                raise SubstrateProofVerifierError("invalid_sidecar_response")
            return True
        if response.get("ok") is not False or set(response) != {
            "schema",
            "request_id",
            "ok",
            "error_code",
        }:
            raise SubstrateProofVerifierError("invalid_sidecar_response")
        error_code = response.get("error_code")
        if not isinstance(error_code, str) or error_code not in _ERROR_CODES:
            raise SubstrateProofVerifierError("invalid_sidecar_response")
        raise SubstrateProofVerifierError(error_code)

    def verify_many(
        self,
        *,
        state_root: bytes,
        items: tuple[tuple[bytes, bytes | None], ...],
        proof: tuple[bytes, ...],
    ) -> bool:
        """Verify one proof covering unique storage claims at one state root."""

        checked_items = self._preflight(state_root=state_root, items=items, proof=proof)
        request_id = self._request_id(state_root=state_root, items=checked_items, proof=proof)
        request = {
            "schema": REQUEST_SCHEMA,
            "request_id": request_id,
            "state_version": STATE_VERSION,
            "state_root": f"0x{state_root.hex()}",
            "items": [
                {
                    "key": f"0x{key.hex()}",
                    "value": None if value is None else f"0x{value.hex()}",
                }
                for key, value in checked_items
            ],
            "proof": [f"0x{node.hex()}" for node in proof],
        }
        request_bytes = json.dumps(
            request, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        return self._invoke(request_bytes, request_id=request_id)

    def __call__(
        self,
        *,
        state_root: bytes,
        storage_key: bytes,
        expected_value: bytes | None,
        proof: tuple[bytes, ...],
    ) -> bool:
        """Implement :class:`umi.chain_evidence.StorageProofVerifier`."""

        return self.verify_many(
            state_root=state_root,
            items=((storage_key, expected_value),),
            proof=proof,
        )

    def verify_extrinsics_root(
        self,
        *,
        expected_root: bytes,
        extrinsics: tuple[bytes, ...],
        state_version: int,
    ) -> bool:
        """Verify one ordered block body against its finalized header root."""

        expected_root = self._require_bytes(expected_root, field="expected_root")
        if len(expected_root) != 32:
            raise ValueError("expected_root must contain exactly 32 bytes")
        if isinstance(state_version, bool) or not isinstance(state_version, int):
            raise TypeError("state_version must be an integer")
        if state_version != STATE_VERSION:
            raise ValueError(f"state_version must equal {STATE_VERSION}")
        if not isinstance(extrinsics, tuple):
            raise TypeError("extrinsics must be a tuple of exact bytes")
        if len(extrinsics) > self._limits.maximum_extrinsics:
            raise ValueError("extrinsics exceed the count limit")
        total_bytes = 0
        checked: list[bytes] = []
        for index, value in enumerate(extrinsics):
            exact = self._require_bytes(value, field=f"extrinsics[{index}]")
            if len(exact) > self._limits.maximum_extrinsic_bytes:
                raise ValueError(f"extrinsics[{index}] exceeds the byte limit")
            total_bytes += len(exact)
            if total_bytes > self._limits.maximum_block_body_bytes:
                raise ValueError("extrinsics exceed the block-body byte limit")
            checked.append(exact)
        values = tuple(checked)
        request_id = self._extrinsics_root_request_id(
            expected_root=expected_root,
            extrinsics=values,
            state_version=state_version,
        )
        request = {
            "schema": EXTRINSICS_ROOT_REQUEST_SCHEMA,
            "request_id": request_id,
            "state_version": state_version,
            "expected_root": f"0x{expected_root.hex()}",
            "extrinsics": [f"0x{value.hex()}" for value in values],
        }
        request_bytes = json.dumps(
            request, ensure_ascii=True, separators=(",", ":"), sort_keys=True
        ).encode("ascii")
        return self._invoke(request_bytes, request_id=request_id)


__all__ = [
    "EXTRINSICS_ROOT_REQUEST_SCHEMA",
    "REQUEST_SCHEMA",
    "RESPONSE_SCHEMA",
    "STATE_VERSION",
    "SubprocessStorageProofVerifier",
    "SubstrateProofLimits",
    "SubstrateProofVerifierError",
]
