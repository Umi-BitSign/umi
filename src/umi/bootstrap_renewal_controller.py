"""Crash-safe coordinator for the temporary direct bootstrap row.

The validator supervisor deliberately accepts only signed, finite leases.  This
controller is the equally narrow coordinator-side half of that design: after one
reviewed bootstrap result it renews only the byte-identical service row, using the
same manifest, owner-fence receipt, and pinned worker release.  It never owns the
validator key and never submits a chain call.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import hmac
import os
import re
import secrets
import signal
import stat
import sys
from collections.abc import Callable, Sequence
from datetime import datetime, timezone
from itertools import pairwise
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol
from urllib.parse import urlsplit

import bittensor as bt
import httpx
from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_direct_weights import (
    DIRECT_FULL_ROW_SIZE,
    DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
    BittensorDirectBootstrapChain,
    DirectBootstrapOperationalPreflight,
    DirectBootstrapTransitionAuthorization,
    OwnerFenceReceipt,
    build_direct_operational_preflight,
    sign_direct_transition_authorization,
    validate_direct_bootstrap_preflight,
)
from .bootstrap_weight_operator import BootstrapChainSnapshot
from .bootstrap_weights import (
    SignedBootstrapEligibilityManifest,
    bootstrap_policy_hash,
    verify_signed_bootstrap_eligibility_manifest,
)
from .crypto import sign_response_digest
from .encoding import account_id32
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .public_pilot_upload import upload_public_pilot_file
from .validator_supervisor import (
    MAX_JSON_SAFE_INTEGER,
    MAX_SUPERVISOR_DIRECTIVES_PER_PAGE,
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
    SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
    SUPERVISOR_DIRECTIVE_SCHEMA,
    SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
    SignedSupervisorDirective,
    SupervisorDirective,
    SupervisorDirectivePage,
    SupervisorDirectiveSignature,
    SupervisorOperatorInputTarget,
    SupervisorReleaseTarget,
    parse_canonical_signed_supervisor_directive,
    parse_canonical_supervisor_directive_page,
    parse_canonical_validator_supervisor_config,
    supervisor_directive_digest,
    supervisor_directive_sha256,
    verify_signed_supervisor_directive_history,
)
from .validator_supervisor_adapters import (
    SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
    SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
    SupervisorBootstrapInputBundle,
)
from .validator_supervisor_publication import (
    MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES,
    SignedSupervisorBootstrapResult,
    parse_canonical_signed_supervisor_bootstrap_result,
)

BOOTSTRAP_RENEWAL_CONFIG_SCHEMA = "umi-bootstrap-renewal-config/1"
BOOTSTRAP_RENEWAL_STATE_SCHEMA = "umi-bootstrap-renewal-state/1"
BOOTSTRAP_RENEWAL_TRANSACTION_SCHEMA = "umi-bootstrap-renewal-transaction/1"
BOOTSTRAP_RENEWAL_STATUS_SCHEMA = "umi-bootstrap-renewal-status/1"

# The temporary service-weight worker was reviewed and released at this revision.
# A later worker requires an explicit new controller release and operator review.
PINNED_BOOTSTRAP_WORKER_REVISION = "57857fce807d8ebecdf491718886b67e6d216196"
UID200_SUBMISSION_NAMESPACE = "3a3a007c6c1d2208688d18abff6e9b82"
EXPECTED_RATE_LIMIT_BLOCKS = 100
EXPECTED_ACTIVITY_CUTOFF_BLOCKS = 360
DIRECT_SUBMISSION_ERA_BLOCKS = 8
MAX_RENEWAL_FILE_BYTES = 16 * 1024 * 1024

_HEX16_RE = re.compile(r"^[0-9a-f]{32}$")
_HEX20_RE = re.compile(r"^[0-9a-f]{40}$")


class BootstrapRenewalError(RuntimeError):
    """Stable fail-closed controller rejection."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class PinnedFile(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=4_096)]
    sha256: Hex32

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or path != Path(os.path.normpath(value)):
            raise ValueError("pinned file path must be absolute and normalized")
        return value


class CoordinatorWalletBinding(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=4_096)]
    name: Annotated[str, Field(min_length=1, max_length=128)]
    hotkey: Annotated[str, Field(min_length=1, max_length=128)]

    @field_validator("path")
    @classmethod
    def validate_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or path != Path(os.path.normpath(value)):
            raise ValueError("coordinator wallet path must be absolute and normalized")
        return value


class BootstrapRenewalConfig(StrictProtocolModel):
    """Static pins for one UID 200 bootstrap-renewal channel."""

    schema_: Literal[BOOTSTRAP_RENEWAL_CONFIG_SCHEMA] = Field(alias="schema")
    network: Literal["finney"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    validator_uid: Literal[200]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    submission_id_prefix: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    worker_umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    signed_manifest: PinnedFile
    owner_fence_receipt: PinnedFile
    release_target: PinnedFile
    validator_supervisor_config: PinnedFile
    seed_directives: Annotated[list[PinnedFile], Field(min_length=2, max_length=64)]
    seed_result_submission_id: Hex32
    coordinator_wallet: CoordinatorWalletBinding
    input_upload_secret_path: Annotated[str, Field(min_length=1, max_length=4_096)]
    input_upload_origin: Annotated[str, Field(min_length=1, max_length=512)]
    input_public_origin: Annotated[str, Field(min_length=1, max_length=512)]
    result_public_origin: Annotated[str, Field(min_length=1, max_length=512)]
    state_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    directive_route_root: Annotated[str, Field(min_length=1, max_length=4_096)]
    poll_seconds: Annotated[int, Field(ge=5, le=60)] = 12
    authorization_lifetime_blocks: Annotated[int, Field(ge=24, le=96)] = 48
    maximum_checkpoint_age_blocks: Annotated[int, Field(ge=1, le=8)] = 4
    minimum_deadline_headroom_blocks: Annotated[int, Field(ge=24, le=96)] = 48

    @field_validator("validator_hotkey", "coordinator_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @field_validator("input_upload_secret_path", "state_root", "directive_route_root")
    @classmethod
    def validate_absolute_path(cls, value: str) -> str:
        path = Path(value)
        if not path.is_absolute() or path != Path(os.path.normpath(value)):
            raise ValueError("renewal paths must be absolute and normalized")
        return value

    @field_validator("input_upload_origin", "input_public_origin", "result_public_origin")
    @classmethod
    def validate_origin(cls, value: str) -> str:
        return _canonical_https_origin(value)

    @model_validator(mode="after")
    def validate_fixed_profile(self) -> Self:
        if self.submission_id_prefix != UID200_SUBMISSION_NAMESPACE:
            raise ValueError("UID 200 submission namespace does not match the assigned prefix")
        if self.worker_umi_git_revision != PINNED_BOOTSTRAP_WORKER_REVISION:
            raise ValueError("renewal controller permits only its reviewed worker release")
        roots = [Path(self.state_root), Path(self.directive_route_root)]
        if roots[0] == roots[1] or roots[0] in roots[1].parents or roots[1] in roots[0].parents:
            raise ValueError("renewal state and public directive roots must be disjoint")
        if self.minimum_deadline_headroom_blocks < self.authorization_lifetime_blocks:
            raise ValueError("deadline headroom must cover the complete authorization lease")
        return self


RenewalPhase = Literal["prepared", "input_published", "directive_published"]
RenewalStatusName = Literal[
    "waiting_for_rate_limit",
    "prepared",
    "input_published",
    "directive_published",
    "result_verified",
    "retry_after_no_effect",
    "hard_sunset_covered",
    "terminal",
]


class BootstrapRenewalTransaction(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_RENEWAL_TRANSACTION_SCHEMA] = Field(alias="schema")
    submission_id: Hex32
    phase: RenewalPhase
    prior_sequence: Annotated[int, Field(ge=2, le=MAX_JSON_SAFE_INTEGER)]
    prior_directive_sha256: Hex32
    checkpoint_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)]
    checkpoint_block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    authorization_sha256: Hex32
    input_bundle_sha256: Hex32
    input_bundle_size_bytes: Annotated[
        int, Field(gt=0, le=MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES)
    ]
    directive_sequence: Annotated[int, Field(ge=3, le=MAX_JSON_SAFE_INTEGER)]
    directive_sha256: Hex32
    valid_through_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)]

    @model_validator(mode="after")
    def validate_sequence(self) -> Self:
        if self.directive_sequence != self.prior_sequence + 1:
            raise ValueError("renewal transaction is not sequence-contiguous")
        return self


class BootstrapRenewalState(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_RENEWAL_STATE_SCHEMA] = Field(alias="schema")
    generation: Annotated[int, Field(ge=0, le=MAX_JSON_SAFE_INTEGER)]
    head_sequence: Annotated[int, Field(ge=2, le=MAX_JSON_SAFE_INTEGER)]
    head_directive_sha256: Hex32
    last_verified_submission_id: Hex32
    last_update_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)]
    transaction: BootstrapRenewalTransaction | None
    abandoned_submission_count: Annotated[int, Field(ge=0, le=MAX_JSON_SAFE_INTEGER)] = 0
    completed_through_hard_sunset: bool = False
    terminal_reason: Annotated[str, Field(min_length=1, max_length=128)] | None = None


class BootstrapRenewalStatus(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_RENEWAL_STATUS_SCHEMA] = Field(alias="schema")
    status: RenewalStatusName
    reason_code: Annotated[str, Field(min_length=1, max_length=128)]
    finalized_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)] | None
    last_update_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)]
    next_eligible_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)]
    active_through_block: Annotated[int, Field(gt=0, le=MAX_JSON_SAFE_INTEGER)]
    head_sequence: Annotated[int, Field(ge=2, le=MAX_JSON_SAFE_INTEGER)]
    submission_id: Hex32 | None


class RenewalChainReader(Protocol):
    async def __call__(self) -> BootstrapChainSnapshot: ...


class RenewalOperationalBuilder(Protocol):
    async def __call__(
        self,
        authorization: DirectBootstrapTransitionAuthorization,
        snapshot: BootstrapChainSnapshot,
    ) -> DirectBootstrapOperationalPreflight: ...


class RenewalInputPublisher(Protocol):
    async def __call__(self, source: Path, digest: str, size: int) -> str: ...


class RenewalResultFetcher(Protocol):
    async def __call__(self, submission_id: str) -> bytes | None: ...


def _canonical_https_origin(value: str) -> str:
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or port not in {None, 443}
        or parsed.netloc != parsed.hostname
    ):
        raise ValueError("origin must be a normalized credential-free HTTPS origin")
    return value


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _validator_participant(snapshot: BootstrapChainSnapshot, hotkey: str) -> Any:
    matches = [
        item for item in snapshot.participants if account_id32(item.hotkey) == account_id32(hotkey)
    ]
    if len(matches) != 1:
        raise BootstrapRenewalError("renewal_validator_mapping_changed")
    return matches[0]


def _expected_row(signed: SignedBootstrapEligibilityManifest) -> list[list[int]]:
    eligible = {entry.uid for entry in signed.manifest.entries}
    return [[uid, 65_535 if uid in eligible else 0] for uid in range(DIRECT_FULL_ROW_SIZE)]


def validate_renewal_snapshot(
    snapshot: BootstrapChainSnapshot,
    *,
    signed_manifest: SignedBootstrapEligibilityManifest,
    subnet_owner_hotkey: str | bytes,
    validator_hotkey: str,
    validator_uid: int,
) -> int:
    """Require the exact fenced runtime, mappings, row, and sole active writer."""

    gates = (
        (snapshot.mechanism_count, 1, "renewal_mechanism_count_changed"),
        (snapshot.commit_reveal_enabled, False, "renewal_commit_reveal_changed"),
        (snapshot.commit_reveal_version, 4, "renewal_commit_reveal_version_changed"),
        (snapshot.reveal_period_epochs, 1, "renewal_reveal_period_changed"),
        (snapshot.tempo, 360, "renewal_tempo_changed"),
        (
            snapshot.activity_cutoff_blocks,
            EXPECTED_ACTIVITY_CUTOFF_BLOCKS,
            "renewal_activity_cutoff_changed",
        ),
        (
            snapshot.weights_set_rate_limit,
            EXPECTED_RATE_LIMIT_BLOCKS,
            "renewal_weights_rate_limit_changed",
        ),
        (
            snapshot.weights_version_key,
            DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
            "renewal_weights_version_changed",
        ),
        (snapshot.min_allowed_weights, 256, "renewal_min_allowed_weights_changed"),
        (snapshot.max_allowed_uids, 256, "renewal_max_allowed_uids_changed"),
    )
    for actual, expected, reason in gates:
        if actual != expected:
            raise BootstrapRenewalError(reason)
    if snapshot.total_pending_commit_count or snapshot.validator_has_pending_commit:
        raise BootstrapRenewalError("renewal_pending_entry_exists")
    if sorted(item.uid for item in snapshot.participants) != list(range(256)):
        raise BootstrapRenewalError("renewal_uid_domain_changed")
    owner = next((item for item in snapshot.participants if item.uid == 0), None)
    if owner is None or account_id32(owner.hotkey) != account_id32(subnet_owner_hotkey):
        raise BootstrapRenewalError("renewal_owner_mapping_changed")
    validator = _validator_participant(snapshot, validator_hotkey)
    if validator.uid != validator_uid or not validator.validator_permit:
        raise BootstrapRenewalError("renewal_validator_permit_or_uid_changed")
    if any(
        item.uid != validator_uid
        and item.validator_permit
        and item.last_update + snapshot.activity_cutoff_blocks >= snapshot.block_number
        for item in snapshot.participants
    ):
        raise BootstrapRenewalError("renewal_other_active_validator")
    by_uid = {item.uid: item for item in snapshot.participants}
    for entry in signed_manifest.manifest.entries:
        participant = by_uid.get(entry.uid)
        if (
            participant is None
            or account_id32(participant.hotkey) != account_id32(entry.miner_hotkey)
            or participant.origin != entry.origin
            or participant.validator_permit
        ):
            raise BootstrapRenewalError("renewal_miner_mapping_changed")
    if snapshot.validator_mechid0_row != _expected_row(signed_manifest):
        raise BootstrapRenewalError("renewal_row_changed")
    active = {account_id32(item) for item in snapshot.active_mechid0_row_hotkeys}
    if active != {account_id32(validator_hotkey)}:
        raise BootstrapRenewalError("renewal_other_active_validator_or_row_missing")
    return validator.last_update


def _read_regular(path: Path, maximum_bytes: int, *, expected_sha256: str | None = None) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BootstrapRenewalError("renewal_artifact_unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise BootstrapRenewalError("renewal_artifact_unsafe")
        payload = b""
        while len(payload) <= maximum_bytes:
            chunk = os.read(descriptor, min(64 * 1024, maximum_bytes + 1 - len(payload)))
            if not chunk:
                break
            payload += chunk
        after = os.fstat(descriptor)
        if (
            len(payload) != metadata.st_size
            or after.st_dev != metadata.st_dev
            or after.st_ino != metadata.st_ino
            or after.st_size != metadata.st_size
            or after.st_mtime_ns != metadata.st_mtime_ns
        ):
            raise BootstrapRenewalError("renewal_artifact_changed")
    finally:
        os.close(descriptor)
    if expected_sha256 is not None and not hmac.compare_digest(_sha256(payload), expected_sha256):
        raise BootstrapRenewalError("renewal_artifact_hash_mismatch")
    return payload


def _load_pinned(pin: PinnedFile, model: type[Any]) -> Any:
    payload = _read_regular(Path(pin.path), MAX_RENEWAL_FILE_BYTES, expected_sha256=pin.sha256)
    try:
        value = model.model_validate_json(payload)
    except Exception as error:
        raise BootstrapRenewalError("renewal_pinned_artifact_invalid") from error
    if canonical_json_bytes(value) != payload:
        raise BootstrapRenewalError("renewal_pinned_artifact_noncanonical")
    return value


def _load_coordinator_upload_secret(path: Path, wallet_root: Path) -> bytes:
    """Load the coordinator-owned upload key even when the daemon runs as root."""

    try:
        wallet_owner = wallet_root.stat(follow_symlinks=False).st_uid
    except OSError as error:
        raise BootstrapRenewalError("renewal_coordinator_wallet_unavailable") from error
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise BootstrapRenewalError("renewal_input_upload_secret_unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid not in {0, wallet_owner}
            or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o600}
            or metadata.st_size > 65
        ):
            raise BootstrapRenewalError("renewal_input_upload_secret_unsafe")
        payload = os.read(descriptor, 66)
        if len(payload) != metadata.st_size:
            raise BootstrapRenewalError("renewal_input_upload_secret_changed")
    finally:
        os.close(descriptor)
    try:
        encoded = payload.decode("ascii").strip()
    except UnicodeDecodeError as error:
        raise BootstrapRenewalError("renewal_input_upload_secret_invalid") from error
    if re.fullmatch(r"[0-9a-f]{64}", encoded) is None:
        raise BootstrapRenewalError("renewal_input_upload_secret_invalid")
    return bytes.fromhex(encoded)


def _write_new(path: Path, payload: bytes, *, mode: int = 0o600) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags, mode)
    except FileExistsError as error:
        raise BootstrapRenewalError("renewal_output_exists") from error
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    except OSError as error:
        with contextlib.suppress(OSError):
            os.close(descriptor)
        with contextlib.suppress(OSError):
            path.unlink()
        raise BootstrapRenewalError("renewal_output_write_failed") from error
    else:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _replace_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}"
    _write_new(temporary, payload)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as error:
        with contextlib.suppress(OSError):
            temporary.unlink()
        raise BootstrapRenewalError("renewal_state_replace_failed") from error


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _parse_signed_directive(payload: bytes) -> SignedSupervisorDirective:
    try:
        return parse_canonical_signed_supervisor_directive(payload)
    except Exception as error:
        raise BootstrapRenewalError("renewal_signed_directive_invalid") from error


def _parse_result(payload: bytes) -> SignedSupervisorBootstrapResult:
    try:
        return parse_canonical_signed_supervisor_bootstrap_result(payload)
    except Exception as error:
        raise BootstrapRenewalError("renewal_signed_result_invalid") from error


class RenewalProcessLock:
    """One nonblocking singleton lock for a controller state root."""

    def __init__(self, state_root: Path) -> None:
        self.path = state_root / "renewal-controller.lock"
        self._descriptor = -1

    def acquire(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        descriptor = os.open(
            self.path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise BootstrapRenewalError("renewal_process_lock_unsafe")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(descriptor)
            raise BootstrapRenewalError("renewal_controller_already_running") from error
        except Exception:
            os.close(descriptor)
            raise
        os.ftruncate(descriptor, 0)
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        self._descriptor = descriptor

    def close(self) -> None:
        if self._descriptor >= 0:
            with contextlib.suppress(OSError):
                fcntl.flock(self._descriptor, fcntl.LOCK_UN)
            os.close(self._descriptor)
            self._descriptor = -1

    def __enter__(self) -> RenewalProcessLock:
        self.acquire()
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()


class RootOwnedDirectiveFeedPublisher:
    """Install verified cursor pages using create-first, atomic per-route swaps."""

    def __init__(self, route_root: Path, *, trusted_owner_uid: int = 0) -> None:
        self.route_root = route_root
        self.trusted_owner_uid = trusted_owner_uid

    def _require_directory(self, path: Path) -> None:
        try:
            metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise BootstrapRenewalError("renewal_directive_route_unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != self.trusted_owner_uid
            or metadata.st_mode & 0o022
        ):
            raise BootstrapRenewalError("renewal_directive_route_unsafe")

    def _route(self, account: str, sequence: int, cursor: str) -> Path:
        return self.route_root / account / "after" / str(sequence) / f"{cursor}.json"

    def _ensure_route_directory(self, path: Path) -> None:
        try:
            relative = path.relative_to(self.route_root)
        except ValueError as error:
            raise BootstrapRenewalError("renewal_directive_route_invalid") from error
        current = self.route_root
        self._require_directory(current)
        for part in relative.parts:
            current = current / part
            try:
                os.mkdir(current, 0o755)
                _fsync_directory(current.parent)
            except FileExistsError:
                pass
            except OSError as error:
                raise BootstrapRenewalError("renewal_directive_route_unavailable") from error
            self._require_directory(current)

    def _read_page(self, path: Path) -> bytes:
        payload = _read_regular(path, MAX_SUPERVISOR_DOCUMENT_BYTES)
        metadata = path.stat(follow_symlinks=False)
        if metadata.st_uid != self.trusted_owner_uid or metadata.st_mode & 0o222:
            raise BootstrapRenewalError("renewal_directive_page_unsafe")
        try:
            parse_canonical_supervisor_directive_page(payload)
        except Exception as error:
            raise BootstrapRenewalError("renewal_directive_page_invalid") from error
        return payload

    def _write_new_public(self, path: Path, payload: bytes) -> None:
        self._require_directory(path.parent)
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags, 0o444)
        try:
            os.fchmod(descriptor, 0o444)
            view = memoryview(payload)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("short page write")
                view = view[written:]
            os.fsync(descriptor)
        except OSError as error:
            os.close(descriptor)
            with contextlib.suppress(OSError):
                path.unlink()
            raise BootstrapRenewalError("renewal_directive_page_write_failed") from error
        else:
            os.close(descriptor)
        _fsync_directory(path.parent)

    def _atomic_page(
        self,
        path: Path,
        *,
        old_payload: bytes | None,
        new_payload: bytes,
    ) -> None:
        if path.exists():
            current = self._read_page(path)
            if hmac.compare_digest(current, new_payload):
                return
            if old_payload is None or not hmac.compare_digest(current, old_payload):
                raise BootstrapRenewalError("renewal_directive_page_race")
        elif old_payload is not None:
            raise BootstrapRenewalError("renewal_directive_page_missing")
        stage = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}"
        self._write_new_public(stage, new_payload)
        try:
            os.replace(stage, path)
            _fsync_directory(path.parent)
        except OSError as error:
            with contextlib.suppress(OSError):
                stage.unlink()
            raise BootstrapRenewalError("renewal_directive_page_replace_failed") from error

    @staticmethod
    def page_for_cursor(
        history: Sequence[SignedSupervisorDirective],
        cursor_sequence: int,
    ) -> SupervisorDirectivePage:
        if cursor_sequence < 1 or cursor_sequence > len(history):
            raise BootstrapRenewalError("renewal_directive_cursor_invalid")
        cursor = history[cursor_sequence - 1]
        following = list(
            history[cursor_sequence : cursor_sequence + MAX_SUPERVISOR_DIRECTIVES_PER_PAGE]
        )
        if following:
            head = following[-1]
            more = head.directive.sequence < history[-1].directive.sequence
        else:
            head = cursor
            more = False
        return SupervisorDirectivePage(
            schema=SUPERVISOR_DIRECTIVE_PAGE_SCHEMA,
            after_sequence=cursor_sequence,
            after_directive_sha256=cursor.directive_sha256,
            directives=following,
            more=more,
            head=head,
        )

    def verify_history(self, history: Sequence[SignedSupervisorDirective]) -> None:
        account = account_id32(history[0].directive.validator_hotkeys[0]).hex()
        for sequence in range(1, len(history) + 1):
            cursor = history[sequence - 1].directive_sha256
            path = self._route(account, sequence, cursor)
            expected = canonical_json_bytes(self.page_for_cursor(history, sequence))
            if not hmac.compare_digest(self._read_page(path), expected):
                raise BootstrapRenewalError("renewal_directive_feed_drift")

    def publish(
        self,
        old_history: Sequence[SignedSupervisorDirective],
        new_directive: SignedSupervisorDirective,
    ) -> None:
        if not old_history:
            raise BootstrapRenewalError("renewal_directive_history_empty")
        history = [*old_history, new_directive]
        account = account_id32(new_directive.directive.validator_hotkeys[0]).hex()
        new_sequence = new_directive.directive.sequence
        new_cursor_path = self._route(account, new_sequence, new_directive.directive_sha256)
        self._ensure_route_directory(new_cursor_path.parent)
        new_cursor_payload = canonical_json_bytes(self.page_for_cursor(history, new_sequence))
        self._atomic_page(new_cursor_path, old_payload=None, new_payload=new_cursor_payload)

        # Install link targets before exposing pages which reference them.  Only
        # the last 65 cursors can change when one directive is appended.
        first_changed = max(1, new_sequence - MAX_SUPERVISOR_DIRECTIVES_PER_PAGE - 1)
        for sequence in range(new_sequence - 1, first_changed - 1, -1):
            cursor = history[sequence - 1].directive_sha256
            path = self._route(account, sequence, cursor)
            old_payload = canonical_json_bytes(self.page_for_cursor(old_history, sequence))
            new_payload = canonical_json_bytes(self.page_for_cursor(history, sequence))
            self._atomic_page(path, old_payload=old_payload, new_payload=new_payload)
        self.verify_history(history)


class BootstrapRenewalController:
    """One serialized, restart-safe renewal state machine."""

    def __init__(
        self,
        config: BootstrapRenewalConfig,
        *,
        wallet: Any | None = None,
        chain_reader: RenewalChainReader | None = None,
        operational_builder: RenewalOperationalBuilder | None = None,
        input_publisher: RenewalInputPublisher | None = None,
        result_fetcher: RenewalResultFetcher | None = None,
        feed_publisher: RootOwnedDirectiveFeedPublisher | None = None,
        random_suffix: Callable[[], str] | None = None,
        trusted_route_owner_uid: int = 0,
    ) -> None:
        if not isinstance(config, BootstrapRenewalConfig):
            raise TypeError("config must be a BootstrapRenewalConfig")
        self.config = config
        self.state_root = Path(config.state_root)
        self.state_path = self.state_root / "renewal-state.json"
        self.history_root = self.state_root / "directives"
        self.transactions_root = self.state_root / "transactions"
        self.signed_manifest = _load_pinned(
            config.signed_manifest, SignedBootstrapEligibilityManifest
        )
        self.owner_fence_receipt = _load_pinned(config.owner_fence_receipt, OwnerFenceReceipt)
        self.release_target = _load_pinned(config.release_target, SupervisorReleaseTarget)
        supervisor_payload = _read_regular(
            Path(config.validator_supervisor_config.path),
            MAX_SUPERVISOR_DOCUMENT_BYTES,
            expected_sha256=config.validator_supervisor_config.sha256,
        )
        try:
            self.supervisor_config = parse_canonical_validator_supervisor_config(supervisor_payload)
        except Exception as error:
            raise BootstrapRenewalError("renewal_supervisor_config_invalid") from error
        self.seed_history = [
            _parse_signed_directive(
                _read_regular(
                    Path(pin.path),
                    MAX_SUPERVISOR_DOCUMENT_BYTES,
                    expected_sha256=pin.sha256,
                )
            )
            for pin in config.seed_directives
        ]
        self._validate_static_bindings()
        self.wallet = wallet or bt.Wallet(
            name=config.coordinator_wallet.name,
            hotkey=config.coordinator_wallet.hotkey,
            path=config.coordinator_wallet.path,
        )
        signer = bt.resolve_signer(self.wallet, role="hotkey")
        if account_id32(signer.ss58_address) != account_id32(config.coordinator_hotkey):
            raise BootstrapRenewalError("renewal_coordinator_wallet_mismatch")
        self.chain = BittensorDirectBootstrapChain(
            finalized_timeout_seconds=20.0,
            # The controller release is intentionally newer than the immutable
            # worker.  Static release-target validation below is its code pin;
            # the worker independently verifies its own checkout again.
            direct_checkout_verifier=lambda _authorization: None,
        )
        self.chain_reader = chain_reader or self._read_chain
        self.operational_builder = operational_builder or self._build_operational
        self.input_publisher = input_publisher or self._publish_input
        self.result_fetcher = result_fetcher or self._fetch_result
        self.feed = feed_publisher or RootOwnedDirectiveFeedPublisher(
            Path(config.directive_route_root), trusted_owner_uid=trusted_route_owner_uid
        )
        self.random_suffix = random_suffix or (lambda: secrets.token_hex(16))

    def _validate_static_bindings(self) -> None:
        try:
            verify_signed_bootstrap_eligibility_manifest(self.signed_manifest)
        except Exception as error:
            raise BootstrapRenewalError("renewal_signed_manifest_invalid") from error
        policy = self.signed_manifest.manifest.policy
        if (
            policy.coordinator_hotkey != self.config.coordinator_hotkey
            or policy.translation_weights_active
            or not policy.service_weights_active
            or bootstrap_policy_hash(policy) != self.signed_manifest.manifest.policy_sha256
        ):
            raise BootstrapRenewalError("renewal_manifest_policy_mismatch")
        if (
            self.release_target.umi_git_revision != self.config.worker_umi_git_revision
            or self.release_target.entrypoint_profile != "umi-bootstrap-weight-validator/2"
            or self.release_target != self.seed_history[-1].directive.release
        ):
            raise BootstrapRenewalError("renewal_release_target_mismatch")
        supervisor = self.supervisor_config
        if (
            supervisor.network != "finney"
            or supervisor.netuid != 78
            or supervisor.mechanism_id != 0
            or account_id32(supervisor.validator_hotkey)
            != account_id32(self.config.validator_hotkey)
            or supervisor.channel_id != self.seed_history[0].directive.channel_id
            or supervisor.signature_threshold != 1
            or len(supervisor.trusted_authorities) != 1
            or account_id32(supervisor.trusted_authorities[0].hotkey)
            != account_id32(self.config.coordinator_hotkey)
            or "bootstrap_service_weights" not in supervisor.allowed_modes
            or self.config.input_public_origin not in supervisor.release_origins
        ):
            raise BootstrapRenewalError("renewal_supervisor_binding_mismatch")
        previous: SignedSupervisorDirective | None = None
        for index, signed in enumerate(self.seed_history, start=1):
            directive = signed.directive
            if (
                directive.sequence != index
                or directive.validator_hotkeys != [self.config.validator_hotkey]
                or (previous is None) != (directive.previous_directive_sha256 is None)
                or (
                    previous is not None
                    and directive.previous_directive_sha256 != previous.directive_sha256
                )
            ):
                raise BootstrapRenewalError("renewal_seed_history_not_contiguous")
            try:
                verify_signed_supervisor_directive_history(
                    signed,
                    config=supervisor,
                    finalized_block=max(
                        directive.issued_at_block,
                        self.signed_manifest.manifest.frozen_at_block,
                    ),
                )
            except Exception as error:
                raise BootstrapRenewalError("renewal_seed_directive_invalid") from error
            previous = signed
        head = self.seed_history[-1]
        if (
            head.directive.mode != "bootstrap_service_weights"
            or head.directive.policy_sha256 != self.signed_manifest.manifest.policy_sha256
            or head.directive.operator_inputs is None
        ):
            raise BootstrapRenewalError("renewal_seed_head_is_not_bootstrap")

    async def _read_chain(self) -> BootstrapChainSnapshot:
        return await self.chain.direct_snapshot(
            self.signed_manifest,
            validator_hotkey=self.config.validator_hotkey,
        )

    async def _build_operational(
        self,
        authorization: DirectBootstrapTransitionAuthorization,
        snapshot: BootstrapChainSnapshot,
    ) -> DirectBootstrapOperationalPreflight:
        owner = next((item for item in snapshot.participants if item.uid == 0), None)
        if owner is None:
            raise BootstrapRenewalError("renewal_owner_uid_missing")
        checked_at = datetime.fromtimestamp(snapshot.block_timestamp_ms / 1_000, tz=timezone.utc)
        try:
            chain = validate_direct_bootstrap_preflight(
                self.signed_manifest,
                snapshot,
                authorization=authorization,
                subnet_owner_hotkey=owner.hotkey,
                validator_hotkey=self.config.validator_hotkey,
                now=checked_at,
            )
            return await build_direct_operational_preflight(self.signed_manifest, chain)
        except BootstrapRenewalError:
            raise
        except Exception as error:
            raise BootstrapRenewalError("renewal_operational_preflight_failed") from error

    async def _publish_input(self, source: Path, digest: str, size: int) -> str:
        if size > MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES:
            raise BootstrapRenewalError("renewal_input_bundle_too_large")
        try:
            secret = _load_coordinator_upload_secret(
                Path(self.config.input_upload_secret_path),
                Path(self.config.coordinator_wallet.path),
            )
            uploaded_digest, uploaded_size, public_url = await asyncio.to_thread(
                upload_public_pilot_file,
                source,
                path=f"/validator-bootstrap-inputs/{digest}.json",
                content_type="application/json",
                maximum_bytes=MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES,
                upload_origin=self.config.input_upload_origin,
                public_origin=self.config.input_public_origin,
                secret=secret,
            )
        except Exception as error:
            raise BootstrapRenewalError("renewal_input_upload_failed") from error
        if uploaded_digest != digest or uploaded_size != size:
            raise BootstrapRenewalError("renewal_input_upload_identity_mismatch")
        return public_url

    async def _fetch_result(self, submission_id: str) -> bytes | None:
        url = f"{self.config.result_public_origin}/validator-bootstrap-results/{submission_id}.json"
        try:
            async with (
                httpx.AsyncClient(
                    timeout=httpx.Timeout(30.0, connect=10.0), follow_redirects=False
                ) as client,
                client.stream("GET", url, headers={"Accept-Encoding": "identity"}) as response,
            ):
                if response.status_code == 404:
                    return None
                if response.status_code != 200 or response.headers.get("Content-Encoding"):
                    raise BootstrapRenewalError("renewal_result_fetch_failed")
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_raw():
                    size += len(chunk)
                    if size > MAX_SUPERVISOR_BOOTSTRAP_RESULT_BYTES:
                        raise BootstrapRenewalError("renewal_result_size_limit")
                    chunks.append(chunk)
                return b"".join(chunks)
        except BootstrapRenewalError:
            raise
        except Exception as error:
            raise BootstrapRenewalError("renewal_result_fetch_failed") from error

    def _load_state(self) -> BootstrapRenewalState:
        payload = _read_regular(self.state_path, MAX_RENEWAL_FILE_BYTES)
        try:
            state = BootstrapRenewalState.model_validate_json(payload)
        except Exception as error:
            raise BootstrapRenewalError("renewal_state_invalid") from error
        if canonical_json_bytes(state) != payload:
            raise BootstrapRenewalError("renewal_state_noncanonical")
        return state

    def _store_state(self, state: BootstrapRenewalState) -> BootstrapRenewalState:
        updated = state.model_copy(update={"generation": state.generation + 1})
        _replace_private(self.state_path, canonical_json_bytes(updated))
        return updated

    def _history_path(self, sequence: int) -> Path:
        return self.history_root / f"{sequence:016d}.json"

    def _load_history(self, state: BootstrapRenewalState) -> list[SignedSupervisorDirective]:
        history: list[SignedSupervisorDirective] = []
        for sequence in range(1, state.head_sequence + 1):
            history.append(
                _parse_signed_directive(
                    _read_regular(self._history_path(sequence), MAX_SUPERVISOR_DOCUMENT_BYTES)
                )
            )
        if (
            history[-1].directive_sha256 != state.head_directive_sha256
            or history[-1].directive.sequence != state.head_sequence
        ):
            raise BootstrapRenewalError("renewal_history_state_mismatch")
        for before, after in pairwise(history):
            if (
                after.directive.sequence != before.directive.sequence + 1
                or after.directive.previous_directive_sha256 != before.directive_sha256
            ):
                raise BootstrapRenewalError("renewal_history_not_contiguous")
        return history

    def _transaction_path(self, submission_id: str, name: str) -> Path:
        return self.transactions_root / submission_id / name

    def _load_transaction_artifact(
        self,
        transaction: BootstrapRenewalTransaction,
        name: str,
        model: type[Any],
        expected_sha256: str | None = None,
    ) -> Any:
        payload = _read_regular(
            self._transaction_path(transaction.submission_id, name),
            MAX_RENEWAL_FILE_BYTES,
            expected_sha256=expected_sha256,
        )
        try:
            value = model.model_validate_json(payload)
        except Exception as error:
            raise BootstrapRenewalError("renewal_transaction_artifact_invalid") from error
        if canonical_json_bytes(value) != payload:
            raise BootstrapRenewalError("renewal_transaction_artifact_noncanonical")
        return value

    def _new_submission_id(self) -> str:
        suffix = self.random_suffix()
        if _HEX16_RE.fullmatch(suffix) is None:
            raise BootstrapRenewalError("renewal_random_suffix_invalid")
        submission_id = self.config.submission_id_prefix + suffix
        if (self.transactions_root / submission_id).exists():
            raise BootstrapRenewalError("renewal_submission_id_collision")
        return submission_id

    def _sign_directive(self, directive: SupervisorDirective) -> SignedSupervisorDirective:
        scheme, signature = sign_response_digest(
            self.wallet,
            supervisor_directive_digest(directive),
        )
        detached = SupervisorDirectiveSignature(
            hotkey=self.config.coordinator_hotkey,
            signature_scheme=scheme,
            signature=signature,
        )
        signed = SignedSupervisorDirective(
            schema=SUPERVISOR_SIGNED_DIRECTIVE_SCHEMA,
            directive=directive,
            directive_sha256=supervisor_directive_sha256(directive),
            directive_digest=supervisor_directive_digest(directive).hex(),
            signatures=[detached],
        )
        try:
            verify_signed_supervisor_directive_history(
                signed,
                config=self.supervisor_config,
                finalized_block=directive.issued_at_block,
            )
        except Exception as error:
            raise BootstrapRenewalError("renewal_directive_signature_invalid") from error
        return signed

    def _verify_result_binding(
        self,
        signed_result: SignedSupervisorBootstrapResult,
        transaction: BootstrapRenewalTransaction,
        snapshot: BootstrapChainSnapshot,
    ) -> int:
        authorization = self._load_transaction_artifact(
            transaction,
            "transition-authorization.json",
            DirectBootstrapTransitionAuthorization,
            transaction.authorization_sha256,
        )
        checkpoint = self._load_transaction_artifact(
            transaction,
            "drain-checkpoint.json",
            DirectBootstrapOperationalPreflight,
        )
        directive = self._load_transaction_artifact(
            transaction,
            "signed-directive.json",
            SignedSupervisorDirective,
        )
        result = signed_result.result
        if (
            result.submission_id != transaction.submission_id
            or result.directive_sha256 != transaction.directive_sha256
            or result.release_manifest_sha256 != self.release_target.release_manifest_sha256
            or account_id32(result.validator_hotkey) != account_id32(self.config.validator_hotkey)
            or result.signed_manifest != self.signed_manifest
            or result.owner_fence_receipt != self.owner_fence_receipt
            or result.transition_authorization != authorization
            or result.drain_checkpoint != checkpoint
            or directive.directive_sha256 != transaction.directive_sha256
            or directive.directive.sequence != transaction.directive_sequence
            or result.submission_receipt.weight_call.block_number
            != result.submission_receipt.observed_last_update
            or not (
                authorization.valid_from_block
                <= result.submission_receipt.weight_call.block_number
                <= authorization.expires_at_block
            )
        ):
            raise BootstrapRenewalError("renewal_result_binding_mismatch")
        observed_last_update = validate_renewal_snapshot(
            snapshot,
            signed_manifest=self.signed_manifest,
            subnet_owner_hotkey=bytes.fromhex(
                self.owner_fence_receipt.call_material.preflight.subnet_owner_hotkey_account_id32[
                    2:
                ]
            ),
            validator_hotkey=self.config.validator_hotkey,
            validator_uid=self.config.validator_uid,
        )
        if observed_last_update != result.submission_receipt.observed_last_update:
            raise BootstrapRenewalError("renewal_result_chain_state_ambiguous")
        return observed_last_update

    async def initialize(self) -> BootstrapRenewalState | None:
        """Adopt one already verified result as the renewal high-water mark."""

        if self.state_path.exists():
            return self._load_state()
        result_payload = await self.result_fetcher(self.config.seed_result_submission_id)
        if result_payload is None:
            return None
        result = _parse_result(result_payload)
        head = self.seed_history[-1]
        seed_bundle = SupervisorBootstrapInputBundle(
            schema=SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
            profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
            signed_manifest=result.result.signed_manifest,
            transition_authorization=result.result.transition_authorization,
            drain_checkpoint=result.result.drain_checkpoint,
            owner_fence_receipt=result.result.owner_fence_receipt,
        )
        seed_bundle_bytes = canonical_json_bytes(seed_bundle)
        seed_target = head.directive.operator_inputs
        if (
            result.result.submission_id != self.config.seed_result_submission_id
            or result.result.directive_sha256 != head.directive_sha256
            or result.result.release_manifest_sha256 != self.release_target.release_manifest_sha256
            or result.result.transition_authorization.umi_git_revision
            != self.config.worker_umi_git_revision
            or result.result.signed_manifest != self.signed_manifest
            or result.result.owner_fence_receipt != self.owner_fence_receipt
            or account_id32(result.result.validator_hotkey)
            != account_id32(self.config.validator_hotkey)
            or seed_target is None
            or seed_target.bundle_sha256 != _sha256(seed_bundle_bytes)
            or seed_target.bundle_size_bytes != len(seed_bundle_bytes)
            or seed_target.bundle_url
            != (
                f"{self.config.input_public_origin}/validator-bootstrap-inputs/"
                f"{_sha256(seed_bundle_bytes)}.json"
            )
        ):
            raise BootstrapRenewalError("renewal_seed_result_binding_mismatch")
        snapshot = await self.chain_reader()
        last_update = validate_renewal_snapshot(
            snapshot,
            signed_manifest=self.signed_manifest,
            subnet_owner_hotkey=bytes.fromhex(
                self.owner_fence_receipt.call_material.preflight.subnet_owner_hotkey_account_id32[
                    2:
                ]
            ),
            validator_hotkey=self.config.validator_hotkey,
            validator_uid=self.config.validator_uid,
        )
        if last_update != result.result.submission_receipt.observed_last_update:
            raise BootstrapRenewalError("renewal_seed_result_not_current")
        self.state_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.history_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.transactions_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        for signed in self.seed_history:
            target = self._history_path(signed.directive.sequence)
            payload = canonical_json_bytes(signed)
            if target.exists():
                if not hmac.compare_digest(
                    _read_regular(target, MAX_SUPERVISOR_DOCUMENT_BYTES), payload
                ):
                    raise BootstrapRenewalError("renewal_seed_history_conflict")
            else:
                _write_new(target, payload)
        self.feed.verify_history(self.seed_history)
        state = BootstrapRenewalState(
            schema=BOOTSTRAP_RENEWAL_STATE_SCHEMA,
            generation=0,
            head_sequence=head.directive.sequence,
            head_directive_sha256=head.directive_sha256,
            last_verified_submission_id=result.result.submission_id,
            last_update_block=last_update,
            transaction=None,
        )
        try:
            _write_new(self.state_path, canonical_json_bytes(state))
        except BootstrapRenewalError as error:
            if error.reason_code != "renewal_output_exists":
                raise
            return self._load_state()
        return state

    async def _prepare(
        self,
        state: BootstrapRenewalState,
        snapshot: BootstrapChainSnapshot,
    ) -> tuple[BootstrapRenewalState, BootstrapRenewalStatus]:
        block = snapshot.block_number
        hard_sunset = self.signed_manifest.manifest.policy.hard_sunset_block
        expires = min(block + self.config.authorization_lifetime_blocks, hard_sunset - 1)
        if expires - block < 2 * DIRECT_SUBMISSION_ERA_BLOCKS + 2:
            return self._terminal(state, "renewal_hard_sunset_headroom_insufficient", block)
        submission_id = self._new_submission_id()
        try:
            authorization = sign_direct_transition_authorization(
                self.signed_manifest,
                weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
                submission_id=submission_id,
                umi_git_revision=self.config.worker_umi_git_revision,
                signed_at_block=block,
                valid_from_block=block,
                expires_at_block=expires,
                validator_hotkey=self.config.validator_hotkey,
                validator_uid=self.config.validator_uid,
                wallet=self.wallet,
            )
            checkpoint = await self.operational_builder(authorization, snapshot)
        except BootstrapRenewalError:
            raise
        except Exception as error:
            raise BootstrapRenewalError("renewal_preparation_failed") from error
        if (
            checkpoint.chain.snapshot.block_number != block
            or checkpoint.chain.snapshot.block_hash != snapshot.block_hash
            or checkpoint.chain.prior_row_classification != "active_exact_direct_row"
        ):
            raise BootstrapRenewalError("renewal_checkpoint_snapshot_mismatch")
        bundle = SupervisorBootstrapInputBundle(
            schema=SUPERVISOR_BOOTSTRAP_INPUT_BUNDLE_SCHEMA,
            profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
            signed_manifest=self.signed_manifest,
            transition_authorization=authorization,
            drain_checkpoint=checkpoint,
            owner_fence_receipt=self.owner_fence_receipt,
        )
        bundle_bytes = canonical_json_bytes(bundle)
        bundle_sha256 = _sha256(bundle_bytes)
        if len(bundle_bytes) > MAX_SUPERVISOR_OPERATOR_INPUT_BUNDLE_BYTES:
            raise BootstrapRenewalError("renewal_input_bundle_too_large")
        input_target = SupervisorOperatorInputTarget(
            artifact_type="canonical_json",
            profile=SUPERVISOR_BOOTSTRAP_INPUT_PROFILE,
            bundle_url=(
                f"{self.config.input_public_origin}/validator-bootstrap-inputs/{bundle_sha256}.json"
            ),
            bundle_sha256=bundle_sha256,
            bundle_size_bytes=len(bundle_bytes),
        )
        directive = SupervisorDirective(
            schema=SUPERVISOR_DIRECTIVE_SCHEMA,
            channel_id=self.supervisor_config.channel_id,
            sequence=state.head_sequence + 1,
            previous_directive_sha256=state.head_directive_sha256,
            issued_at_block=block,
            valid_from_block=block,
            valid_through_block=expires,
            network="finney",
            netuid=78,
            mechanism_id=0,
            mode="bootstrap_service_weights",
            validator_hotkeys=[self.config.validator_hotkey],
            policy_sha256=self.signed_manifest.manifest.policy_sha256,
            release=self.release_target,
            operator_inputs=input_target,
        )
        signed_directive = self._sign_directive(directive)
        transaction_root = self.transactions_root / submission_id
        transaction_root.mkdir(mode=0o700, parents=True, exist_ok=False)
        artifacts: tuple[tuple[str, object], ...] = (
            ("transition-authorization.json", authorization),
            ("drain-checkpoint.json", checkpoint),
            ("bootstrap-inputs.json", bundle),
            ("bootstrap-input-target.json", input_target),
            ("directive.json", directive),
            ("signed-directive.json", signed_directive),
        )
        for name, value in artifacts:
            _write_new(transaction_root / name, canonical_json_bytes(value))
        transaction = BootstrapRenewalTransaction(
            schema=BOOTSTRAP_RENEWAL_TRANSACTION_SCHEMA,
            submission_id=submission_id,
            phase="prepared",
            prior_sequence=state.head_sequence,
            prior_directive_sha256=state.head_directive_sha256,
            checkpoint_block=block,
            checkpoint_block_hash=snapshot.block_hash,
            authorization_sha256=_sha256(canonical_json_bytes(authorization)),
            input_bundle_sha256=bundle_sha256,
            input_bundle_size_bytes=len(bundle_bytes),
            directive_sequence=directive.sequence,
            directive_sha256=signed_directive.directive_sha256,
            valid_through_block=expires,
        )
        state = self._store_state(state.model_copy(update={"transaction": transaction}))
        return state, self._status("prepared", "renewal_prepared", block, state)

    def _status(
        self,
        status: RenewalStatusName,
        reason: str,
        block: int | None,
        state: BootstrapRenewalState,
    ) -> BootstrapRenewalStatus:
        sunset = self.signed_manifest.manifest.policy.hard_sunset_block
        return BootstrapRenewalStatus(
            schema=BOOTSTRAP_RENEWAL_STATUS_SCHEMA,
            status=status,
            reason_code=reason,
            finalized_block=block,
            last_update_block=state.last_update_block,
            next_eligible_block=state.last_update_block + EXPECTED_RATE_LIMIT_BLOCKS,
            active_through_block=min(
                state.last_update_block + EXPECTED_ACTIVITY_CUTOFF_BLOCKS,
                sunset - 1,
            ),
            head_sequence=state.head_sequence,
            submission_id=(None if state.transaction is None else state.transaction.submission_id),
        )

    def _terminal(
        self,
        state: BootstrapRenewalState,
        reason: str,
        block: int | None,
    ) -> tuple[BootstrapRenewalState, BootstrapRenewalStatus]:
        terminal = self._store_state(state.model_copy(update={"terminal_reason": reason}))
        return terminal, self._status("terminal", reason, block, terminal)

    def _abandon_unpublished(
        self,
        state: BootstrapRenewalState,
        block: int,
        reason: str,
    ) -> tuple[BootstrapRenewalState, BootstrapRenewalStatus]:
        updated = self._store_state(
            state.model_copy(
                update={
                    "transaction": None,
                    "abandoned_submission_count": state.abandoned_submission_count + 1,
                }
            )
        )
        return updated, self._status("retry_after_no_effect", reason, block, updated)

    def _advance_expired_no_effect(
        self,
        state: BootstrapRenewalState,
        transaction: BootstrapRenewalTransaction,
        block: int,
    ) -> tuple[BootstrapRenewalState, BootstrapRenewalStatus]:
        history = self._load_history(state)
        pending = self._load_transaction_artifact(
            transaction,
            "signed-directive.json",
            SignedSupervisorDirective,
        )
        if pending.directive_sha256 != transaction.directive_sha256:
            raise BootstrapRenewalError("renewal_transaction_directive_mismatch")
        self.feed.verify_history([*history, pending])
        updated = self._store_state(
            state.model_copy(
                update={
                    "head_sequence": transaction.directive_sequence,
                    "head_directive_sha256": transaction.directive_sha256,
                    "transaction": None,
                    "abandoned_submission_count": state.abandoned_submission_count + 1,
                }
            )
        )
        return updated, self._status(
            "retry_after_no_effect",
            "renewal_directive_expired_without_chain_effect",
            block,
            updated,
        )

    async def step(self) -> BootstrapRenewalStatus:
        """Advance at most one durable phase."""

        state = self._load_state()
        if state.terminal_reason is not None:
            return self._status("terminal", state.terminal_reason, None, state)
        if state.completed_through_hard_sunset:
            return self._status("hard_sunset_covered", "renewal_hard_sunset_covered", None, state)
        snapshot = await self.chain_reader()
        try:
            current_last_update = validate_renewal_snapshot(
                snapshot,
                signed_manifest=self.signed_manifest,
                subnet_owner_hotkey=bytes.fromhex(
                    self.owner_fence_receipt.call_material.preflight.subnet_owner_hotkey_account_id32[
                        2:
                    ]
                ),
                validator_hotkey=self.config.validator_hotkey,
                validator_uid=self.config.validator_uid,
            )
        except BootstrapRenewalError as error:
            _state, status = self._terminal(state, error.reason_code, snapshot.block_number)
            return status
        block = snapshot.block_number
        transaction = state.transaction
        if transaction is None:
            history = self._load_history(state)
            try:
                self.feed.verify_history(history)
            except BootstrapRenewalError as error:
                _state, status = self._terminal(state, error.reason_code, block)
                return status
            if current_last_update != state.last_update_block:
                _state, status = self._terminal(state, "renewal_unattributed_last_update", block)
                return status
            sunset = self.signed_manifest.manifest.policy.hard_sunset_block
            if state.last_update_block + EXPECTED_ACTIVITY_CUTOFF_BLOCKS >= sunset - 1:
                updated = self._store_state(
                    state.model_copy(update={"completed_through_hard_sunset": True})
                )
                return self._status(
                    "hard_sunset_covered", "renewal_hard_sunset_covered", block, updated
                )
            eligible = state.last_update_block + EXPECTED_RATE_LIMIT_BLOCKS
            if block < eligible:
                return self._status(
                    "waiting_for_rate_limit", "renewal_rate_limit_not_elapsed", block, state
                )
            latest_safe = (
                state.last_update_block
                + EXPECTED_ACTIVITY_CUTOFF_BLOCKS
                - self.config.minimum_deadline_headroom_blocks
            )
            if block > latest_safe:
                _state, status = self._terminal(state, "renewal_refresh_deadline_missed", block)
                return status
            _state, status = await self._prepare(state, snapshot)
            return status

        if transaction.prior_sequence != state.head_sequence or (
            transaction.prior_directive_sha256 != state.head_directive_sha256
        ):
            _state, status = self._terminal(state, "renewal_transaction_head_mismatch", block)
            return status
        if transaction.phase != "directive_published" and (
            current_last_update != state.last_update_block
        ):
            _state, status = self._terminal(state, "renewal_chain_effect_before_directive", block)
            return status

        if transaction.phase in {"prepared", "input_published"} and (
            block - transaction.checkpoint_block > self.config.maximum_checkpoint_age_blocks
        ):
            _state, status = self._abandon_unpublished(
                state, block, "renewal_checkpoint_expired_before_publication"
            )
            return status

        if transaction.phase == "prepared":
            source = self._transaction_path(transaction.submission_id, "bootstrap-inputs.json")
            public_url = await self.input_publisher(
                source,
                transaction.input_bundle_sha256,
                transaction.input_bundle_size_bytes,
            )
            target = self._load_transaction_artifact(
                transaction,
                "bootstrap-input-target.json",
                SupervisorOperatorInputTarget,
            )
            if public_url != target.bundle_url:
                _state, status = self._terminal(
                    state, "renewal_input_publication_url_mismatch", block
                )
                return status
            updated_transaction = transaction.model_copy(update={"phase": "input_published"})
            state = self._store_state(state.model_copy(update={"transaction": updated_transaction}))
            return self._status("input_published", "renewal_input_bundle_published", block, state)

        if transaction.phase == "input_published":
            history = self._load_history(state)
            signed = self._load_transaction_artifact(
                transaction,
                "signed-directive.json",
                SignedSupervisorDirective,
            )
            if signed.directive_sha256 != transaction.directive_sha256:
                _state, status = self._terminal(
                    state, "renewal_transaction_directive_mismatch", block
                )
                return status
            history_path = self._history_path(transaction.directive_sequence)
            signed_bytes = canonical_json_bytes(signed)
            if history_path.exists():
                if not hmac.compare_digest(
                    _read_regular(history_path, MAX_SUPERVISOR_DOCUMENT_BYTES), signed_bytes
                ):
                    _state, status = self._terminal(
                        state, "renewal_directive_history_conflict", block
                    )
                    return status
            else:
                _write_new(history_path, signed_bytes)
            self.feed.publish(history, signed)
            updated_transaction = transaction.model_copy(update={"phase": "directive_published"})
            state = self._store_state(state.model_copy(update={"transaction": updated_transaction}))
            return self._status("directive_published", "renewal_directive_published", block, state)

        result_payload = await self.result_fetcher(transaction.submission_id)
        if result_payload is None:
            if block <= transaction.valid_through_block:
                reason = (
                    "renewal_result_pending_after_chain_effect"
                    if current_last_update != state.last_update_block
                    else "renewal_result_pending"
                )
                return self._status("directive_published", reason, block, state)
            if current_last_update != state.last_update_block:
                _state, status = self._terminal(
                    state, "renewal_effect_ambiguous_after_result_expiry", block
                )
                return status
            _state, status = self._advance_expired_no_effect(state, transaction, block)
            return status

        signed_result = _parse_result(result_payload)
        if snapshot.block_number < signed_result.result.submission_receipt.observation_block:
            return self._status(
                "directive_published", "renewal_result_ahead_of_chain_reader", block, state
            )
        try:
            new_last_update = self._verify_result_binding(signed_result, transaction, snapshot)
        except BootstrapRenewalError as error:
            _state, status = self._terminal(state, error.reason_code, block)
            return status
        if new_last_update <= state.last_update_block:
            _state, status = self._terminal(
                state, "renewal_result_did_not_advance_last_update", block
            )
            return status
        history = self._load_history(state)
        signed = self._load_transaction_artifact(
            transaction,
            "signed-directive.json",
            SignedSupervisorDirective,
        )
        if signed.directive_sha256 != transaction.directive_sha256:
            _state, status = self._terminal(state, "renewal_transaction_directive_mismatch", block)
            return status
        self.feed.verify_history([*history, signed])
        state = self._store_state(
            state.model_copy(
                update={
                    "head_sequence": transaction.directive_sequence,
                    "head_directive_sha256": transaction.directive_sha256,
                    "last_verified_submission_id": transaction.submission_id,
                    "last_update_block": new_last_update,
                    "transaction": None,
                }
            )
        )
        return self._status("result_verified", "renewal_signed_result_verified", block, state)


def load_bootstrap_renewal_config(path: Path) -> BootstrapRenewalConfig:
    if not path.is_absolute() or path != Path(os.path.normpath(path)):
        raise BootstrapRenewalError("renewal_config_path_invalid")
    payload = _read_regular(path, MAX_SUPERVISOR_DOCUMENT_BYTES)
    metadata = path.stat(follow_symlinks=False)
    if (
        metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or stat.S_IMODE(metadata.st_mode) not in {0o400, 0o440, 0o600, 0o640}
    ):
        raise BootstrapRenewalError("renewal_config_file_unsafe")
    try:
        config = BootstrapRenewalConfig.model_validate_json(payload)
    except Exception as error:
        raise BootstrapRenewalError("renewal_config_invalid") from error
    if canonical_json_bytes(config) != payload:
        raise BootstrapRenewalError("renewal_config_noncanonical")
    return config


async def run_bootstrap_renewal_controller(
    controller: BootstrapRenewalController,
    *,
    stop_event: asyncio.Event,
) -> None:
    while not stop_event.is_set():
        try:
            state = await controller.initialize()
            if state is None:
                output: object = {
                    "reason_code": "renewal_seed_result_pending",
                    "schema": BOOTSTRAP_RENEWAL_STATUS_SCHEMA,
                    "status": "waiting_for_seed_result",
                    "submission_id": controller.config.seed_result_submission_id,
                }
            else:
                output = await controller.step()
            print(canonical_json_bytes(output).decode("utf-8"), flush=True)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            reason = (
                error.reason_code
                if isinstance(error, BootstrapRenewalError)
                else "renewal_reconcile_failed"
            )
            print(
                canonical_json_bytes(
                    {
                        "reason_code": reason,
                        "schema": BOOTSTRAP_RENEWAL_STATUS_SCHEMA,
                        "status": "holding",
                    }
                ).decode("utf-8"),
                flush=True,
            )
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(stop_event.wait(), timeout=controller.config.poll_seconds)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the fail-closed UID 200 bootstrap renewal controller"
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check-config", "initialize", "once", "run", "status"):
        command = commands.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
    return parser


async def _run_command(args: argparse.Namespace) -> int:
    config = load_bootstrap_renewal_config(args.config)
    controller = BootstrapRenewalController(config)
    if args.command == "check-config":
        print(
            canonical_json_bytes(
                {
                    "coordinator_hotkey": config.coordinator_hotkey,
                    "schema": BOOTSTRAP_RENEWAL_STATUS_SCHEMA,
                    "status": "config_ok",
                    "validator_hotkey": config.validator_hotkey,
                }
            ).decode("utf-8")
        )
        return 0
    if args.command == "status":
        state = controller._load_state()
        print(
            canonical_json_bytes(
                controller._status(
                    "terminal"
                    if state.terminal_reason
                    else (
                        "hard_sunset_covered"
                        if state.completed_through_hard_sunset
                        else "waiting_for_rate_limit"
                    ),
                    state.terminal_reason
                    or (
                        "renewal_hard_sunset_covered"
                        if state.completed_through_hard_sunset
                        else "renewal_state_loaded"
                    ),
                    None,
                    state,
                )
            ).decode("utf-8")
        )
        return 0
    with RenewalProcessLock(Path(config.state_root)):
        if args.command == "initialize":
            state = await controller.initialize()
            if state is None:
                print(
                    canonical_json_bytes(
                        {
                            "reason_code": "renewal_seed_result_pending",
                            "schema": BOOTSTRAP_RENEWAL_STATUS_SCHEMA,
                            "status": "waiting_for_seed_result",
                        }
                    ).decode("utf-8")
                )
                return 2
            print(
                canonical_json_bytes(
                    controller._status(
                        "waiting_for_rate_limit",
                        "renewal_initialized",
                        None,
                        state,
                    )
                ).decode("utf-8")
            )
            return 0
        state = await controller.initialize()
        if state is None:
            raise BootstrapRenewalError("renewal_seed_result_pending")
        if args.command == "once":
            print(canonical_json_bytes(await controller.step()).decode("utf-8"))
            return 0
        stop_event = asyncio.Event()
        loop = asyncio.get_running_loop()
        installed: list[signal.Signals] = []
        for item in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(item, stop_event.set)
                installed.append(item)
            except (NotImplementedError, RuntimeError):
                pass
        try:
            await run_bootstrap_renewal_controller(controller, stop_event=stop_event)
        finally:
            for item in installed:
                loop.remove_signal_handler(item)
        return 0


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        return asyncio.run(_run_command(args))
    except BootstrapRenewalError as error:
        print(error.reason_code, file=sys.stderr)
        return 2


def main() -> None:
    raise SystemExit(run_cli())


__all__ = [
    "BOOTSTRAP_RENEWAL_CONFIG_SCHEMA",
    "BOOTSTRAP_RENEWAL_STATE_SCHEMA",
    "BOOTSTRAP_RENEWAL_STATUS_SCHEMA",
    "EXPECTED_ACTIVITY_CUTOFF_BLOCKS",
    "EXPECTED_RATE_LIMIT_BLOCKS",
    "PINNED_BOOTSTRAP_WORKER_REVISION",
    "UID200_SUBMISSION_NAMESPACE",
    "BootstrapRenewalConfig",
    "BootstrapRenewalController",
    "BootstrapRenewalError",
    "BootstrapRenewalState",
    "BootstrapRenewalStatus",
    "BootstrapRenewalTransaction",
    "CoordinatorWalletBinding",
    "PinnedFile",
    "RenewalProcessLock",
    "RootOwnedDirectiveFeedPublisher",
    "load_bootstrap_renewal_config",
    "run_bootstrap_renewal_controller",
    "run_cli",
    "validate_renewal_snapshot",
]


if __name__ == "__main__":  # pragma: no cover
    main()
