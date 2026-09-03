"""Owned GRANDPA finality observation through a pinned smoldot sidecar.

The sidecar connects to Substrate peers itself.  This adapter never accepts a
provider RPC URL and never treats an RPC server's `finalized` label as proof.
smoldot does not export the GRANDPA proof bytes through its public API, so the
records are verifier attestations rather than portable offline proofs.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import selectors
import signal
import subprocess
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path

import rfc8785

from .pinned_artifact import PinnedArtifact, PinnedArtifactError, staged_pinned_artifacts

REQUEST_SCHEMA = "umi-grandpa-finality-observer/1"
RECORD_SCHEMA = "umi-grandpa-finality-attestation/1"
EVIDENCE_CLASS = "verifier_attested_finality"
SOURCE_REVISION = (
    "subtensor-chain-spec:da06f033663896ef2fdbbfc3ecc68ca908fba0f5;"
    "subxt-lightclient:0.50.3@49ea25dcf81a6c764ed6d341679211a396191cc8+"
    "umi-database-input-v1;"
    "smoldot-light:1.3.2@5fe9121f81a58454542ac69a44c4d73f00f30283+"
    "umi-database-bootstrap-v1+lru-0.18.4-rustsec-2026-0253;"
    "smoldot:2.2.0@90e94869a7fbd617d28990da3005eaa906bc3862+"
    "umi-header-consensus-disambiguation-v1"
)
SOURCE_TREE_SHA256 = "3bd630238cdc042572999b5058fadc63f6ca51ea7835b0f42023793a7abc0002"
CARGO_LOCK_SHA256 = "9d6ba175a232ddb051c0ce795dc500562b05b48f57bb29a33344aad1eef87f8c"
FIXTURE_SET_SHA256 = "b5522352dc04cbd88eb7916ba95e65330c89915619e292f3512ed3acebd11655"
FINNEY_CHAIN_SPEC_SOURCE_REVISION = "da06f033663896ef2fdbbfc3ecc68ca908fba0f5"
FINNEY_CHAIN_SPEC_SHA256 = "f280b687a838ad73bf4e825a03f2807ee4363c3d13a5cb55a1f7f5c876b7f105"
FINNEY_GENESIS_HASH = "2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
FINNEY_BOOTSTRAP_BLOCK_NUMBER = 8_867_448
FINNEY_BOOTSTRAP_BLOCK_HASH = "511948e96e1d479d0a92d89bb976638780f2c65a93a5d5be710f22ee15c60200"

_REQUEST_DOMAIN = b"umi-grandpa-finality-observer-request-v1\0"
_TRANSCRIPT_DOMAIN = b"umi-grandpa-finality-attestation-v1\0"
_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_HASH_RE = re.compile(r"^0x[0-9a-f]{64}$")
_HEX_RE = re.compile(r"^0x(?:[0-9a-f]{2})+$")

_TOP_LEVEL_KEYS = frozenset(
    {
        "schema",
        "request_id",
        "evidence_class",
        "offline_finality_proof",
        "source_revision",
        "sequence",
        "chain_spec_sha256",
        "genesis_hash",
        "bootstrap_block_number",
        "bootstrap_block_hash",
        "bootstrap_source",
        "bootstrap_selected",
        "startup_finalized_block_number",
        "startup_finalized_block_hash",
        "block",
        "ancestry",
        "ancestry_complete_since_previous",
        "previous_finalized_hash",
        "previous_transcript_digest",
        "transcript_digest",
    }
)
_BLOCK_KEYS = frozenset(
    {
        "number",
        "hash",
        "parent_hash",
        "state_root",
        "extrinsics_root",
        "scale_header",
        "timestamp_ms",
    }
)
_ANCESTRY_KEYS = frozenset({"number", "hash", "parent_hash"})


class GrandpaFinalityObserverError(RuntimeError):
    """A stable, fail-closed observer boundary error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(f"GRANDPA finality observer failed: {reason_code}")


@dataclass(frozen=True, slots=True)
class GrandpaFinalityLimits:
    maximum_binary_bytes: int = 256 * 1024 * 1024
    maximum_chain_spec_bytes: int = 64 * 1024 * 1024
    maximum_header_bytes: int = 1024 * 1024
    maximum_ancestry_blocks: int = 16_384
    maximum_record_bytes: int = 16 * 1024 * 1024
    maximum_records: int = 100_000

    def __post_init__(self) -> None:
        for field_name in self.__dataclass_fields__:
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")


@dataclass(frozen=True, slots=True)
class FinalizedHeader:
    number: int
    hash: str
    parent_hash: str
    state_root: str
    extrinsics_root: str
    scale_header: str
    timestamp_ms: int


@dataclass(frozen=True, slots=True)
class FinalityAttestation:
    sequence: int
    bootstrap_source: str
    bootstrap_selected: bool
    startup_finalized_block_number: int
    startup_finalized_block_hash: str
    block: FinalizedHeader
    ancestry: tuple[tuple[int, str, str], ...]
    ancestry_complete_since_previous: bool
    previous_finalized_hash: str | None
    previous_transcript_digest: str
    transcript_digest: str
    canonical_bytes: bytes


def _positive_int(value: object, *, field: str, maximum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise GrandpaFinalityObserverError(f"invalid_{field}")
    if maximum is not None and value > maximum:
        raise GrandpaFinalityObserverError(f"invalid_{field}")
    return value


def _decode_compact_number(data: bytes) -> tuple[int, int]:
    if not data:
        raise GrandpaFinalityObserverError("truncated_header")
    first = data[0]
    mode = first & 0b11
    if mode == 0:
        return first >> 2, 1
    if mode == 1:
        if len(data) < 2:
            raise GrandpaFinalityObserverError("truncated_header")
        value = int.from_bytes(data[:2], "little") >> 2
        if value < 1 << 6:
            raise GrandpaFinalityObserverError("noncanonical_block_number")
        return value, 2
    if mode == 2:
        if len(data) < 4:
            raise GrandpaFinalityObserverError("truncated_header")
        value = int.from_bytes(data[:4], "little") >> 2
        if value < 1 << 14:
            raise GrandpaFinalityObserverError("noncanonical_block_number")
        return value, 4
    length = (first >> 2) + 4
    if length > 8 or len(data) < length + 1:
        raise GrandpaFinalityObserverError("unsupported_block_number")
    encoded = data[1 : length + 1]
    value = int.from_bytes(encoded, "little")
    if value < 1 << 30 or encoded[-1] == 0:
        raise GrandpaFinalityObserverError("noncanonical_block_number")
    return value, length + 1


def _decode_header(scale_header: object, *, maximum_bytes: int) -> dict[str, object]:
    if not isinstance(scale_header, str) or _HEX_RE.fullmatch(scale_header) is None:
        raise GrandpaFinalityObserverError("invalid_scale_header")
    encoded = bytes.fromhex(scale_header[2:])
    if len(encoded) > maximum_bytes or len(encoded) < 98:
        raise GrandpaFinalityObserverError("invalid_header_size")
    number, compact_length = _decode_compact_number(encoded[32:])
    roots_offset = 32 + compact_length
    if len(encoded) < roots_offset + 65:
        raise GrandpaFinalityObserverError("truncated_header")
    return {
        "number": number,
        "hash": f"0x{hashlib.blake2b(encoded, digest_size=32).hexdigest()}",
        "parent_hash": f"0x{encoded[:32].hex()}",
        "state_root": f"0x{encoded[roots_offset : roots_offset + 32].hex()}",
        "extrinsics_root": f"0x{encoded[roots_offset + 32 : roots_offset + 64].hex()}",
    }


class GrandpaFinalityObserver:
    """Run and validate a hash-pinned smoldot finality observer."""

    def __init__(
        self,
        *,
        binary_path: str | os.PathLike[str],
        expected_binary_sha256: str,
        chain_spec_path: str | os.PathLike[str],
        expected_chain_spec_sha256: str,
        expected_genesis_hash: str,
        bootstrap_block_number: int,
        bootstrap_block_hash: str,
        record_timeout_seconds: float = 900.0,
        limits: GrandpaFinalityLimits | None = None,
    ) -> None:
        self._limits = limits or GrandpaFinalityLimits()
        self._binary_path = self._validate_absolute_path(binary_path, field="binary")
        self._chain_spec_path = self._validate_absolute_path(chain_spec_path, field="chain_spec")
        self._expected_binary_sha256 = self._validate_sha256(expected_binary_sha256, field="binary")
        self._expected_chain_spec_sha256 = self._validate_sha256(
            expected_chain_spec_sha256, field="chain_spec"
        )
        if (
            not isinstance(expected_genesis_hash, str)
            or _HASH_RE.fullmatch(expected_genesis_hash) is None
        ):
            raise ValueError("expected_genesis_hash must be a lowercase 0x-prefixed hash")
        self._expected_genesis_hash = expected_genesis_hash
        if isinstance(bootstrap_block_number, bool) or not isinstance(bootstrap_block_number, int):
            raise TypeError("bootstrap_block_number must be an integer")
        if not 0 < bootstrap_block_number <= (1 << 53) - 1:
            raise ValueError("bootstrap_block_number is outside the canonical JSON range")
        self._bootstrap_block_number = bootstrap_block_number
        self._bootstrap_block_hash = bootstrap_block_hash
        if _HASH_RE.fullmatch(self._bootstrap_block_hash) is None:
            raise ValueError("bootstrap_block_hash must be a lowercase 0x-prefixed hash")
        if self._bootstrap_block_hash == expected_genesis_hash:
            raise ValueError("bootstrap_block_hash must identify a non-genesis checkpoint")
        if (
            isinstance(record_timeout_seconds, bool)
            or not isinstance(record_timeout_seconds, (int, float))
            or not math.isfinite(record_timeout_seconds)
            or record_timeout_seconds <= 0
        ):
            raise ValueError("record_timeout_seconds must be a positive finite number")
        self._record_timeout_seconds = float(record_timeout_seconds)
        self._assert_file_integrity(
            self._binary_path,
            expected_sha256=self._expected_binary_sha256,
            maximum_bytes=self._limits.maximum_binary_bytes,
            executable=True,
            reason_prefix="binary",
        )
        self._assert_file_integrity(
            self._chain_spec_path,
            expected_sha256=self._expected_chain_spec_sha256,
            maximum_bytes=self._limits.maximum_chain_spec_bytes,
            executable=False,
            reason_prefix="chain_spec",
        )

    @property
    def expected_binary_sha256(self) -> str:
        """Return the release digest this observer rechecks before every run."""

        return self._expected_binary_sha256

    @property
    def expected_chain_spec_sha256(self) -> str:
        """Return the exact raw chain-spec digest accepted by this observer."""

        return self._expected_chain_spec_sha256

    @property
    def expected_genesis_hash(self) -> str:
        """Return the lowercase, ``0x``-prefixed expected genesis hash."""

        return self._expected_genesis_hash

    @property
    def bootstrap_block_number(self) -> int:
        """Return the policy-bound smoldot bootstrap height."""

        return self._bootstrap_block_number

    @property
    def bootstrap_block_hash(self) -> str:
        """Return the policy-bound smoldot bootstrap hash."""

        return self._bootstrap_block_hash

    @classmethod
    def from_policy_pin(
        cls,
        pin: object,
        *,
        target_triple: str,
        binary_path: str | os.PathLike[str],
        chain_spec_path: str | os.PathLike[str],
        record_timeout_seconds: float = 900.0,
        limits: GrandpaFinalityLimits | None = None,
    ) -> GrandpaFinalityObserver:
        """Construct only from an exact reviewed ``FinalityVerifierPin``.

        This is the production constructor boundary. It prevents startup code
        from supplying a chain specification or bootstrap independently of the
        scoring policy while the release hash binds the executable build.
        """

        from .policy import FinalityVerifierPin

        if not isinstance(pin, FinalityVerifierPin):
            raise TypeError("pin must be a FinalityVerifierPin")
        expected_build = {
            "source_revision": SOURCE_REVISION,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "cargo_lock_sha256": CARGO_LOCK_SHA256,
            "finality_fixture_set_sha256": FIXTURE_SET_SHA256,
        }
        if any(getattr(pin, field) != value for field, value in expected_build.items()):
            raise GrandpaFinalityObserverError("policy_build_pin_mismatch")
        expected_chain = {
            "chain_spec_source_revision": FINNEY_CHAIN_SPEC_SOURCE_REVISION,
            "chain_spec_sha256": FINNEY_CHAIN_SPEC_SHA256,
            "expected_genesis_hash": FINNEY_GENESIS_HASH,
            "bootstrap_kind": "grandpa_warp_sync_checkpoint",
            "bootstrap_block_number": FINNEY_BOOTSTRAP_BLOCK_NUMBER,
            "bootstrap_block_hash": FINNEY_BOOTSTRAP_BLOCK_HASH,
        }
        if any(getattr(pin, field) != value for field, value in expected_chain.items()):
            raise GrandpaFinalityObserverError("policy_chain_pin_mismatch")
        try:
            binary_sha256 = pin.release_sha256_by_target[target_triple]
        except KeyError as error:
            raise GrandpaFinalityObserverError("policy_target_missing") from error
        return cls(
            binary_path=binary_path,
            expected_binary_sha256=binary_sha256,
            chain_spec_path=chain_spec_path,
            expected_chain_spec_sha256=pin.chain_spec_sha256,
            expected_genesis_hash=f"0x{pin.expected_genesis_hash}",
            bootstrap_block_number=pin.bootstrap_block_number,
            bootstrap_block_hash=f"0x{pin.bootstrap_block_hash}",
            record_timeout_seconds=record_timeout_seconds,
            limits=limits,
        )

    @staticmethod
    def _validate_absolute_path(value: str | os.PathLike[str], *, field: str) -> Path:
        path = Path(value)
        if not path.is_absolute():
            raise ValueError(f"{field}_path must be absolute")
        return path

    @staticmethod
    def _validate_sha256(value: object, *, field: str) -> str:
        if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
            raise ValueError(f"expected_{field}_sha256 must be lowercase hexadecimal")
        return value

    @staticmethod
    def _assert_file_integrity(
        path: Path,
        *,
        expected_sha256: str,
        maximum_bytes: int,
        executable: bool,
        reason_prefix: str,
    ) -> None:
        try:
            with staged_pinned_artifacts(
                (
                    PinnedArtifact(
                        name=reason_prefix,
                        source=path,
                        expected_sha256=expected_sha256,
                        maximum_bytes=maximum_bytes,
                        executable=executable,
                    ),
                )
            ):
                pass
        except PinnedArtifactError as error:
            raise GrandpaFinalityObserverError(error.reason_code) from error

    def _staged_inputs(self):
        return staged_pinned_artifacts(
            (
                PinnedArtifact(
                    name="binary",
                    source=self._binary_path,
                    expected_sha256=self._expected_binary_sha256,
                    maximum_bytes=self._limits.maximum_binary_bytes,
                    executable=True,
                ),
                PinnedArtifact(
                    name="chain_spec",
                    source=self._chain_spec_path,
                    expected_sha256=self._expected_chain_spec_sha256,
                    maximum_bytes=self._limits.maximum_chain_spec_bytes,
                ),
            )
        )

    def _config(
        self,
        *,
        minimum_finalized_block: int,
        maximum_records: int,
        startup_timeout_seconds: int,
        chain_spec_path: Path | None = None,
    ) -> tuple[dict[str, object], bytes]:
        if (
            isinstance(minimum_finalized_block, bool)
            or not isinstance(minimum_finalized_block, int)
            or minimum_finalized_block <= self._bootstrap_block_number
            or minimum_finalized_block > (1 << 53) - 1
        ):
            raise ValueError("minimum_finalized_block must advance beyond the GRANDPA checkpoint")
        if (
            isinstance(maximum_records, bool)
            or not isinstance(maximum_records, int)
            or not 1 <= maximum_records <= self._limits.maximum_records
        ):
            raise ValueError("maximum_records is outside the configured limit")
        if (
            isinstance(startup_timeout_seconds, bool)
            or not isinstance(startup_timeout_seconds, int)
            or not 1 <= startup_timeout_seconds <= 86_400
        ):
            raise ValueError("startup_timeout_seconds must be between 1 and 86400")
        payload: dict[str, object] = {
            "schema": REQUEST_SCHEMA,
            "chain_spec_path": str(chain_spec_path or self._chain_spec_path),
            "chain_spec_sha256": self._expected_chain_spec_sha256,
            "expected_genesis_hash": self._expected_genesis_hash,
            "bootstrap_block_number": self._bootstrap_block_number,
            "bootstrap_block_hash": self._bootstrap_block_hash,
            "minimum_finalized_block": minimum_finalized_block,
            "maximum_records": maximum_records,
            "startup_timeout_seconds": startup_timeout_seconds,
            "maximum_chain_spec_bytes": self._limits.maximum_chain_spec_bytes,
            "maximum_header_bytes": self._limits.maximum_header_bytes,
            "maximum_ancestry_blocks": self._limits.maximum_ancestry_blocks,
            "maximum_record_bytes": self._limits.maximum_record_bytes,
        }
        request_binding = dict(payload)
        request_binding.pop("chain_spec_path")
        request_id = hashlib.sha256(_REQUEST_DOMAIN + rfc8785.dumps(request_binding)).hexdigest()
        payload["request_id"] = request_id
        encoded = rfc8785.dumps(payload)
        if len(encoded) > 64 * 1024:
            raise GrandpaFinalityObserverError("config_size_limit")
        return payload, encoded

    @staticmethod
    def _terminate(process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
            process.wait(timeout=1.0)
        except (OSError, subprocess.TimeoutExpired):
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except OSError:
                process.kill()
            process.wait()

    def attestations(
        self,
        *,
        minimum_finalized_block: int,
        maximum_records: int = 1,
        startup_timeout_seconds: int = 600,
        stop_requested: Callable[[], bool] | None = None,
    ) -> Iterator[FinalityAttestation]:
        """Yield a bounded run of locally verified finality attestations."""

        if stop_requested is not None and not callable(stop_requested):
            raise TypeError("stop_requested must be callable")

        self._config(
            minimum_finalized_block=minimum_finalized_block,
            maximum_records=maximum_records,
            startup_timeout_seconds=startup_timeout_seconds,
        )
        staging = self._staged_inputs()
        try:
            staged = staging.__enter__()
        except PinnedArtifactError as error:
            raise GrandpaFinalityObserverError(error.reason_code) from error
        try:
            config, encoded_config = self._config(
                minimum_finalized_block=minimum_finalized_block,
                maximum_records=maximum_records,
                startup_timeout_seconds=startup_timeout_seconds,
                chain_spec_path=staged["chain_spec"],
            )
        except Exception:
            staging.__exit__(None, None, None)
            raise
        try:
            process = subprocess.Popen(
                [str(staged["binary"])],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                close_fds=True,
                start_new_session=True,
                env={"LANG": "C", "LC_ALL": "C"},
            )
        except OSError as error:
            staging.__exit__(None, None, None)
            raise GrandpaFinalityObserverError("spawn_failed") from error
        assert process.stdin is not None
        assert process.stdout is not None
        try:
            process.stdin.write(encoded_config)
            process.stdin.close()
        except OSError as error:
            self._terminate(process)
            staging.__exit__(None, None, None)
            raise GrandpaFinalityObserverError("config_write_failed") from error

        expected_sequence = 0
        previous_hash: str | None = None
        previous_digest = "0" * 64
        previous_number: int | None = None
        previous_timestamp_ms: int | None = None
        buffer = bytearray()
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        try:
            while expected_sequence < maximum_records:
                if stop_requested is not None and stop_requested():
                    return
                deadline = time.monotonic() + self._record_timeout_seconds
                line: bytes | None = None
                while line is None:
                    if stop_requested is not None and stop_requested():
                        return
                    newline = buffer.find(b"\n")
                    if newline >= 0:
                        line = bytes(buffer[:newline])
                        del buffer[: newline + 1]
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise GrandpaFinalityObserverError("record_timeout")
                    poll_seconds = min(remaining, 0.25) if stop_requested is not None else remaining
                    if not selector.select(poll_seconds):
                        if time.monotonic() >= deadline:
                            raise GrandpaFinalityObserverError("record_timeout")
                        continue
                    chunk = os.read(process.stdout.fileno(), 64 * 1024)
                    if not chunk:
                        break
                    buffer.extend(chunk)
                    if len(buffer) > self._limits.maximum_record_bytes + 1:
                        raise GrandpaFinalityObserverError("record_size_limit")
                if line is None:
                    break
                attestation = self._parse_record(
                    line,
                    config=config,
                    expected_sequence=expected_sequence,
                    previous_hash=previous_hash,
                    previous_digest=previous_digest,
                    previous_number=previous_number,
                    previous_timestamp_ms=previous_timestamp_ms,
                )
                yield attestation
                expected_sequence += 1
                previous_hash = attestation.block.hash
                previous_digest = attestation.transcript_digest
                previous_number = attestation.block.number
                previous_timestamp_ms = attestation.block.timestamp_ms

            try:
                return_code = process.wait(timeout=2.0)
            except subprocess.TimeoutExpired as error:
                raise GrandpaFinalityObserverError("observer_did_not_exit") from error
            if return_code != 0:
                raise GrandpaFinalityObserverError("observer_failed")
            tail = process.stdout.read(self._limits.maximum_record_bytes + 1)
            if expected_sequence != maximum_records or buffer.strip() or tail.strip():
                raise GrandpaFinalityObserverError("record_count_mismatch")
        finally:
            selector.close()
            self._terminate(process)
            staging.__exit__(None, None, None)

    def validate_attestation(
        self,
        encoded: bytes,
        *,
        minimum_finalized_block: int,
        maximum_records: int,
        startup_timeout_seconds: int,
        expected_sequence: int,
        previous_hash: str | None,
        previous_digest: str,
        previous_number: int | None,
        previous_timestamp_ms: int | None,
    ) -> FinalityAttestation:
        """Revalidate one persisted record under its exact observer-run binding."""

        config, _ = self._config(
            minimum_finalized_block=minimum_finalized_block,
            maximum_records=maximum_records,
            startup_timeout_seconds=startup_timeout_seconds,
        )
        return self._parse_record(
            encoded,
            config=config,
            expected_sequence=expected_sequence,
            previous_hash=previous_hash,
            previous_digest=previous_digest,
            previous_number=previous_number,
            previous_timestamp_ms=previous_timestamp_ms,
        )

    def _parse_record(
        self,
        encoded: bytes,
        *,
        config: dict[str, object],
        expected_sequence: int,
        previous_hash: str | None,
        previous_digest: str,
        previous_number: int | None,
        previous_timestamp_ms: int | None,
    ) -> FinalityAttestation:
        if not encoded or len(encoded) > self._limits.maximum_record_bytes:
            raise GrandpaFinalityObserverError("record_size_limit")
        try:
            record = json.loads(
                encoded,
                parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()),
            )
        except (UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
            raise GrandpaFinalityObserverError("invalid_record_json") from error
        if not isinstance(record, dict) or frozenset(record) != _TOP_LEVEL_KEYS:
            raise GrandpaFinalityObserverError("invalid_record_shape")
        try:
            canonical_record = rfc8785.dumps(record)
        except rfc8785.CanonicalizationError as error:
            raise GrandpaFinalityObserverError("invalid_record_json") from error
        if canonical_record != encoded:
            raise GrandpaFinalityObserverError("record_not_canonical")
        fixed = {
            "schema": RECORD_SCHEMA,
            "request_id": config["request_id"],
            "evidence_class": EVIDENCE_CLASS,
            "offline_finality_proof": False,
            "source_revision": SOURCE_REVISION,
            "chain_spec_sha256": self._expected_chain_spec_sha256,
            "genesis_hash": self._expected_genesis_hash,
            "bootstrap_block_number": self._bootstrap_block_number,
            "bootstrap_block_hash": self._bootstrap_block_hash,
            "bootstrap_source": "grandpa_checkpoint",
            "bootstrap_selected": True,
        }
        if any(record[key] != value for key, value in fixed.items()):
            raise GrandpaFinalityObserverError("record_pin_mismatch")
        sequence = _positive_int(record["sequence"], field="sequence")
        if sequence != expected_sequence:
            raise GrandpaFinalityObserverError("sequence_mismatch")
        if record["previous_finalized_hash"] != previous_hash:
            raise GrandpaFinalityObserverError("previous_hash_mismatch")
        if record["previous_transcript_digest"] != previous_digest:
            raise GrandpaFinalityObserverError("previous_digest_mismatch")
        if (
            not isinstance(record["transcript_digest"], str)
            or _SHA256_RE.fullmatch(record["transcript_digest"]) is None
        ):
            raise GrandpaFinalityObserverError("invalid_transcript_digest")
        unsigned = dict(record)
        digest = unsigned.pop("transcript_digest")
        try:
            canonical_unsigned = rfc8785.dumps(unsigned)
        except rfc8785.CanonicalizationError as error:
            raise GrandpaFinalityObserverError("invalid_record_json") from error
        expected_digest = hashlib.sha256(_TRANSCRIPT_DOMAIN + canonical_unsigned).hexdigest()
        if digest != expected_digest:
            raise GrandpaFinalityObserverError("transcript_digest_mismatch")

        block = record["block"]
        if not isinstance(block, dict) or frozenset(block) != _BLOCK_KEYS:
            raise GrandpaFinalityObserverError("invalid_block_shape")
        decoded = _decode_header(
            block["scale_header"], maximum_bytes=self._limits.maximum_header_bytes
        )
        if any(block[field] != decoded[field] for field in decoded):
            raise GrandpaFinalityObserverError("header_field_mismatch")
        block_number = _positive_int(block["number"], field="block_number")
        timestamp_ms = _positive_int(block["timestamp_ms"], field="timestamp_ms")
        if block_number < int(config["minimum_finalized_block"]):
            raise GrandpaFinalityObserverError("below_minimum_finalized_block")
        startup_finalized_block_number = _positive_int(
            record["startup_finalized_block_number"], field="startup_finalized_block_number"
        )
        startup_finalized_block_hash = record["startup_finalized_block_hash"]
        if (
            startup_finalized_block_number < self._bootstrap_block_number
            or startup_finalized_block_number > block_number
            or not isinstance(startup_finalized_block_hash, str)
            or _HASH_RE.fullmatch(startup_finalized_block_hash) is None
            or (
                startup_finalized_block_number == self._bootstrap_block_number
                and startup_finalized_block_hash != self._bootstrap_block_hash
            )
            or (
                startup_finalized_block_number == block_number
                and startup_finalized_block_hash != block["hash"]
            )
        ):
            raise GrandpaFinalityObserverError("invalid_startup_finalized_head")

        ancestry_value = record["ancestry"]
        if (
            not isinstance(ancestry_value, list)
            or not ancestry_value
            or len(ancestry_value) > self._limits.maximum_ancestry_blocks
        ):
            raise GrandpaFinalityObserverError("invalid_ancestry")
        ancestry: list[tuple[int, str, str]] = []
        for item in ancestry_value:
            if not isinstance(item, dict) or frozenset(item) != _ANCESTRY_KEYS:
                raise GrandpaFinalityObserverError("invalid_ancestry")
            number = _positive_int(item["number"], field="ancestry_number")
            hash_value = item["hash"]
            parent_value = item["parent_hash"]
            if (
                not isinstance(hash_value, str)
                or _HASH_RE.fullmatch(hash_value) is None
                or not isinstance(parent_value, str)
                or _HASH_RE.fullmatch(parent_value) is None
            ):
                raise GrandpaFinalityObserverError("invalid_ancestry")
            ancestry.append((number, hash_value, parent_value))
        if ancestry[-1] != (block_number, block["hash"], block["parent_hash"]):
            raise GrandpaFinalityObserverError("ancestry_target_mismatch")

        complete = record["ancestry_complete_since_previous"]
        if not isinstance(complete, bool):
            raise GrandpaFinalityObserverError("invalid_ancestry_complete")
        if previous_number is None:
            if complete or len(ancestry) != 1:
                raise GrandpaFinalityObserverError("invalid_bootstrap_ancestry")
        else:
            if not complete or block_number <= previous_number:
                raise GrandpaFinalityObserverError("finality_rollback")
            if previous_timestamp_ms is None or timestamp_ms < previous_timestamp_ms:
                raise GrandpaFinalityObserverError("timestamp_rollback")
            if (
                ancestry[0][0] != previous_number + 1
                or ancestry[0][2] != previous_hash
                or len(ancestry) != block_number - previous_number
            ):
                raise GrandpaFinalityObserverError("ancestry_gap")
            for left, right in pairwise(ancestry):
                if right[0] != left[0] + 1 or right[2] != left[1]:
                    raise GrandpaFinalityObserverError("noncontiguous_ancestry")

        finalized = FinalizedHeader(
            number=block_number,
            hash=block["hash"],
            parent_hash=block["parent_hash"],
            state_root=block["state_root"],
            extrinsics_root=block["extrinsics_root"],
            scale_header=block["scale_header"],
            timestamp_ms=timestamp_ms,
        )
        return FinalityAttestation(
            sequence=sequence,
            bootstrap_source=record["bootstrap_source"],
            bootstrap_selected=record["bootstrap_selected"],
            startup_finalized_block_number=startup_finalized_block_number,
            startup_finalized_block_hash=startup_finalized_block_hash,
            block=finalized,
            ancestry=tuple(ancestry),
            ancestry_complete_since_previous=complete,
            previous_finalized_hash=previous_hash,
            previous_transcript_digest=previous_digest,
            transcript_digest=digest,
            canonical_bytes=encoded,
        )


__all__ = [
    "CARGO_LOCK_SHA256",
    "EVIDENCE_CLASS",
    "FINNEY_BOOTSTRAP_BLOCK_HASH",
    "FINNEY_BOOTSTRAP_BLOCK_NUMBER",
    "FINNEY_CHAIN_SPEC_SHA256",
    "FINNEY_CHAIN_SPEC_SOURCE_REVISION",
    "FINNEY_GENESIS_HASH",
    "FIXTURE_SET_SHA256",
    "RECORD_SCHEMA",
    "REQUEST_SCHEMA",
    "SOURCE_REVISION",
    "SOURCE_TREE_SHA256",
    "FinalityAttestation",
    "FinalizedHeader",
    "GrandpaFinalityLimits",
    "GrandpaFinalityObserver",
    "GrandpaFinalityObserverError",
]
