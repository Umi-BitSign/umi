"""Small, self-contained SN78 bootstrap validator.

Every participating validator consumes the same coordinator-signed lease and
eligibility manifest.  The only validator-specific input is its existing
hotkey wallet.  The process submits only the manifest's exact 256-entry row,
checks the applied row from finalized chain state, renews it before the runtime
activity cutoff, and stops at the signed hard sunset.

This is intentionally not an updater or remote-control plane.  A lease cannot
select a command, arguments, image, or validator.  It authorizes one pinned
source revision and one fixed row for any currently permitted SN78 validator.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import fcntl
import hashlib
import os
import re
import stat
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import bittensor as bt
from bittensor._generated import storage
from pydantic import Field, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_direct_weights import (
    DIRECT_FULL_ROW_SIZE,
    DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
)
from .bootstrap_weight_operator import (
    _MAX_FINALIZED_FUTURE_SKEW_MS,
    _MAX_FINALIZED_HEAD_AGE_MS,
    BittensorBootstrapChain,
    BootstrapChainParticipant,
    BootstrapChainSnapshot,
    BootstrapExtrinsicReference,
    BootstrapOperatorError,
    _datetime_ms,
    _exact_sha256_commitment,
    _successful_extrinsic,
    probe_bootstrap_health,
    replay_bootstrap_pilots,
)
from .bootstrap_weights import (
    U16_MAX,
    SignedBootstrapEligibilityManifest,
    bootstrap_policy_hash,
    verify_signed_bootstrap_eligibility_manifest,
)
from .chain_evidence import build_sha256_commitment_call
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .policy import umi_source_tree_sha256
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

SIMPLE_BOOTSTRAP_LEASE_BODY_SCHEMA = "umi-simple-bootstrap-lease-body/1"
SIMPLE_BOOTSTRAP_LEASE_SCHEMA = "umi-simple-bootstrap-lease/1"
SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA = "umi-simple-bootstrap-journal/1"
SIMPLE_BOOTSTRAP_STATUS_SCHEMA = "umi-simple-bootstrap-status/1"
SIMPLE_BOOTSTRAP_PROFILE = "direct_full_row/1"
SIMPLE_BOOTSTRAP_MANIFEST_SHA256 = (
    "7901ff0aeeb01e46556b26676969a41ba1d8a5a7e77164116a0b08db49189c4c"
)
SIMPLE_BOOTSTRAP_POLICY_SHA256 = "546704feeb029f7667340e418dfe899545df16925d0a1562f1e87d88abc41082"
SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK = 9_075_171
SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION = 455
SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS = 360
SIMPLE_BOOTSTRAP_DEFAULT_REFRESH_MARGIN_BLOCKS = 120
SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD = 8
SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS = 16
_LEASE_DOMAIN = b"umi-simple-bootstrap-lease-v1\0"
_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")
_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1


class SimpleBootstrapError(RuntimeError):
    """Stable non-sensitive service error."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class SimpleBootstrapLeaseBody(StrictProtocolModel):
    """Common authorization for one immutable bootstrap release and row."""

    schema_: Literal[SIMPLE_BOOTSTRAP_LEASE_BODY_SCHEMA] = Field(alias="schema")
    profile: Literal[SIMPLE_BOOTSTRAP_PROFILE]
    manifest_sha256: Literal[SIMPLE_BOOTSTRAP_MANIFEST_SHA256]
    policy_sha256: Literal[SIMPLE_BOOTSTRAP_POLICY_SHA256]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    valid_from_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    hard_sunset_block: Literal[SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK]
    required_runtime_spec_version: Literal[SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION]
    weights_version_key: Literal[DIRECT_MINIMUM_WEIGHTS_VERSION_KEY]
    required_mechanism_count: Literal[1]
    required_commit_reveal_enabled: Literal[False]
    required_commit_reveal_version: Literal[4]
    required_reveal_period_epochs: Literal[1]
    required_tempo: Literal[360]
    required_activity_cutoff_blocks: Literal[SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS]
    required_weights_set_rate_limit: Literal[100]
    required_min_allowed_weights: Literal[256]
    required_max_allowed_uids: Literal[256]
    require_validator_permit: Literal[True]
    allow_any_permitted_validator: Literal[True]
    require_public_pilot_replay: Literal[True]
    require_fresh_endpoint_health: Literal[True]
    refresh_margin_blocks: Annotated[int, Field(ge=30, le=180)]

    @field_validator("coordinator_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if self.valid_from_block >= self.hard_sunset_block:
            raise ValueError("simple bootstrap lease interval is empty")
        if self.refresh_margin_blocks >= self.required_activity_cutoff_blocks:
            raise ValueError("simple bootstrap refresh margin reaches the activity cutoff")
        return self


class SignedSimpleBootstrapLease(StrictProtocolModel):
    schema_: Literal[SIMPLE_BOOTSTRAP_LEASE_SCHEMA] = Field(alias="schema")
    body: SimpleBootstrapLeaseBody
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]


class SimpleActiveRow(StrictProtocolModel):
    hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    uid: Annotated[int, Field(ge=0, le=255)]
    last_update: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    row: Annotated[list[list[int]], Field(max_length=256)]

    @field_validator("hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


class SimpleBootstrapObservation(StrictProtocolModel):
    snapshot: BootstrapChainSnapshot
    runtime_spec_version: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    subnet_owner_hotkey_account_id32: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    manifest_anchor_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)] | None
    warning_codes: Annotated[list[str], Field(max_length=16)] = Field(default_factory=list)
    active_rows: Annotated[list[SimpleActiveRow], Field(max_length=256)]

    @model_validator(mode="after")
    def validate_active_rows(self) -> Self:
        if self.warning_codes != sorted(set(self.warning_codes)):
            raise ValueError("simple bootstrap observation warnings are not canonical")
        accounts = [account_id32(item.hotkey) for item in self.active_rows]
        if accounts != sorted(set(accounts)):
            raise ValueError("simple bootstrap active rows are not uniquely sorted")
        if accounts != [account_id32(value) for value in self.snapshot.active_mechid0_row_hotkeys]:
            raise ValueError("simple bootstrap active-row evidence is incomplete")
        return self


class SimpleBootstrapDecision(StrictProtocolModel):
    action: Literal["wait", "submit", "sunset"]
    reason_code: Annotated[str, Field(min_length=1, max_length=128)]
    finalized_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    next_action_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)] | None


class ValidatedSimpleBootstrap(StrictProtocolModel):
    observation: SimpleBootstrapObservation
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=255)]
    validator_last_update: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    expected_row: Annotated[list[list[int]], Field(min_length=256, max_length=256)]
    warning_codes: Annotated[list[str], Field(max_length=256)]
    decision: SimpleBootstrapDecision

    @property
    def snapshot(self) -> BootstrapChainSnapshot:
        """Compatibility view used by the existing health probe."""

        return self.observation.snapshot


class SimpleBootstrapJournal(StrictProtocolModel):
    schema_: Literal[SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA] = Field(alias="schema")
    phase: Literal[
        "submitting",
        "outcome_unknown",
        "anchor_submitting",
        "anchor_outcome_unknown",
        "anchor_applied",
        "anchor_not_applied",
        "applied",
        "recovered_applied",
        "not_applied",
        "ambiguous_effect",
    ]
    lease_sha256: Hex32
    manifest_sha256: Literal[SIMPLE_BOOTSTRAP_MANIFEST_SHA256]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    attempt_id: Hex32
    preflight_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    prior_last_update: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    manifest_anchor_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)] | None = None
    anchor_call: BootstrapExtrinsicReference | None = None
    weight_call: BootstrapExtrinsicReference | None = None
    observation_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)] | None = None
    updated_at: datetime

    @field_validator("validator_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        anchor_terminal = {
            "anchor_applied",
            "anchor_not_applied",
            "submitting",
            "outcome_unknown",
            "applied",
            "recovered_applied",
            "not_applied",
            "ambiguous_effect",
        }
        if (self.manifest_anchor_block is not None) != (
            self.phase in anchor_terminal and self.phase != "anchor_not_applied"
        ):
            raise ValueError("simple bootstrap journal anchor does not match its phase")
        if self.anchor_call is not None and (
            self.manifest_anchor_block != self.anchor_call.block_number
            or self.phase in {"anchor_submitting", "anchor_not_applied"}
        ):
            raise ValueError("simple bootstrap journal anchor call is invalid")
        if (self.weight_call is not None) != (self.phase == "applied"):
            raise ValueError("simple bootstrap journal call does not match its phase")
        terminal = {
            "anchor_applied",
            "anchor_not_applied",
            "applied",
            "recovered_applied",
            "not_applied",
            "ambiguous_effect",
        }
        if (self.observation_block is not None) != (self.phase in terminal):
            raise ValueError("simple bootstrap journal observation does not match its phase")
        return self


class SimpleBootstrapStatus(StrictProtocolModel):
    schema_: Literal[SIMPLE_BOOTSTRAP_STATUS_SCHEMA] = Field(alias="schema")
    status: Literal["waiting", "submitted", "sunset", "error"]
    reason_code: Annotated[str, Field(min_length=1, max_length=128)]
    finalized_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)] | None
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=255)] | None
    next_action_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)] | None
    warning_codes: Annotated[list[str], Field(max_length=256)] = Field(default_factory=list)
    journal_phase: (
        Literal[
            "submitting",
            "outcome_unknown",
            "anchor_submitting",
            "anchor_outcome_unknown",
            "anchor_applied",
            "anchor_not_applied",
            "applied",
            "recovered_applied",
            "not_applied",
            "ambiguous_effect",
        ]
        | None
    ) = None
    weight_call: BootstrapExtrinsicReference | None = None


def simple_bootstrap_lease_digest(body: SimpleBootstrapLeaseBody) -> bytes:
    if not isinstance(body, SimpleBootstrapLeaseBody):
        raise TypeError("body must be a SimpleBootstrapLeaseBody")
    return hashlib.sha256(_LEASE_DOMAIN + canonical_json_bytes(body)).digest()


def build_simple_bootstrap_lease_body(
    signed_manifest: SignedBootstrapEligibilityManifest,
    *,
    umi_git_revision: str,
    valid_from_block: int,
    refresh_margin_blocks: int = SIMPLE_BOOTSTRAP_DEFAULT_REFRESH_MARGIN_BLOCKS,
) -> SimpleBootstrapLeaseBody:
    """Build the common unsigned lease that the coordinator signs once."""

    _verify_historical_manifest(signed_manifest)
    if not _REVISION_RE.fullmatch(umi_git_revision):
        raise ValueError("UMI git revision must be 40 lowercase hexadecimal characters")
    return SimpleBootstrapLeaseBody(
        schema=SIMPLE_BOOTSTRAP_LEASE_BODY_SCHEMA,
        profile=SIMPLE_BOOTSTRAP_PROFILE,
        manifest_sha256=signed_manifest.manifest_sha256,
        policy_sha256=bootstrap_policy_hash(signed_manifest.manifest.policy),
        coordinator_hotkey=signed_manifest.coordinator_hotkey,
        umi_git_revision=umi_git_revision,
        valid_from_block=valid_from_block,
        hard_sunset_block=signed_manifest.manifest.policy.hard_sunset_block,
        required_runtime_spec_version=SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION,
        weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        required_mechanism_count=1,
        required_commit_reveal_enabled=False,
        required_commit_reveal_version=4,
        required_reveal_period_epochs=1,
        required_tempo=360,
        required_activity_cutoff_blocks=SIMPLE_BOOTSTRAP_ACTIVITY_CUTOFF_BLOCKS,
        required_weights_set_rate_limit=100,
        required_min_allowed_weights=256,
        required_max_allowed_uids=256,
        require_validator_permit=True,
        allow_any_permitted_validator=True,
        require_public_pilot_replay=True,
        require_fresh_endpoint_health=True,
        refresh_margin_blocks=refresh_margin_blocks,
    )


def sign_simple_bootstrap_lease(
    body: SimpleBootstrapLeaseBody,
    *,
    wallet: Any,
) -> SignedSimpleBootstrapLease:
    signer = bt.resolve_signer(wallet, role="hotkey")
    if account_id32(signer.ss58_address) != account_id32(body.coordinator_hotkey):
        raise ValueError("lease signer is not the manifest coordinator")
    scheme, signature = sign_response_digest(wallet, simple_bootstrap_lease_digest(body))
    return verify_simple_bootstrap_lease(
        SignedSimpleBootstrapLease(
            schema=SIMPLE_BOOTSTRAP_LEASE_SCHEMA,
            body=body,
            signature_scheme=scheme,
            signature=signature,
        ),
        signed_manifest=None,
        expected_revision=body.umi_git_revision,
        current_block=body.valid_from_block,
    )


def verify_simple_bootstrap_lease(
    signed_lease: SignedSimpleBootstrapLease,
    *,
    signed_manifest: SignedBootstrapEligibilityManifest | None,
    expected_revision: str,
    current_block: int,
) -> SignedSimpleBootstrapLease:
    if not isinstance(signed_lease, SignedSimpleBootstrapLease):
        raise TypeError("signed_lease must be a SignedSimpleBootstrapLease")
    body = signed_lease.body
    if body.umi_git_revision != expected_revision:
        raise ValueError("simple bootstrap lease targets another UMI revision")
    if not body.valid_from_block <= current_block < body.hard_sunset_block:
        raise ValueError("simple bootstrap lease is inactive at this block")
    if signed_manifest is not None:
        _verify_historical_manifest(signed_manifest)
        if (
            body.manifest_sha256 != signed_manifest.manifest_sha256
            or body.policy_sha256 != bootstrap_policy_hash(signed_manifest.manifest.policy)
            or account_id32(body.coordinator_hotkey)
            != account_id32(signed_manifest.coordinator_hotkey)
            or body.hard_sunset_block != signed_manifest.manifest.policy.hard_sunset_block
        ):
            raise ValueError("simple bootstrap lease binds another manifest or policy")
    if not verify_response_signature(
        simple_bootstrap_lease_digest(body),
        hotkey_ss58=body.coordinator_hotkey,
        scheme=signed_lease.signature_scheme,
        signature=signed_lease.signature,
    ):
        raise ValueError("simple bootstrap lease signature is invalid")
    return signed_lease


def verify_simple_bootstrap_checkout(repository: Path | None = None) -> str:
    """Return HEAD only for the real, clean checkout containing this module."""

    image_revision = os.environ.get("UMI_IMAGE_REVISION_PATH")
    image_source = os.environ.get("UMI_IMAGE_SOURCE_TREE_SHA256")
    if bool(image_revision) != bool(image_source):
        raise SimpleBootstrapError("image_identity_environment_incomplete")
    if image_revision is not None and image_source is not None:
        if repository is not None:
            raise SimpleBootstrapError("image_identity_does_not_accept_repository")
        return _verify_simple_bootstrap_image(Path(image_revision), image_source)

    module_root = Path(__file__).resolve().parents[2]
    expected_root = repository.resolve() if repository is not None else module_root
    if expected_root != module_root:
        raise SimpleBootstrapError("source_checkout_does_not_contain_running_module")
    # The immutable installed checkout is deliberately owned by root while the
    # service normally runs as the operator account.  Scope Git's ownership
    # exception to this one already-resolved path instead of changing global
    # configuration or trusting an operator-provided safe.directory entry.
    git = ["git", "-c", f"safe.directory={expected_root}"]
    try:
        top = subprocess.run(
            [*git, "rev-parse", "--show-toplevel"],
            cwd=expected_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        revision = subprocess.run(
            [*git, "rev-parse", "HEAD"],
            cwd=expected_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        status = subprocess.run(
            [*git, "status", "--porcelain=v1", "--untracked-files=all"],
            cwd=expected_root,
            check=True,
            capture_output=True,
            text=True,
            timeout=20,
        ).stdout
    except (OSError, subprocess.SubprocessError) as error:
        raise SimpleBootstrapError("source_checkout_identity_unavailable") from error
    if Path(top).resolve() != expected_root:
        raise SimpleBootstrapError("source_checkout_root_mismatch")
    if not _REVISION_RE.fullmatch(revision):
        raise SimpleBootstrapError("source_checkout_revision_invalid")
    if status:
        raise SimpleBootstrapError("source_checkout_is_not_clean")
    return revision


def _verify_simple_bootstrap_image(revision_path: Path, expected_source_sha256: str) -> str:
    """Verify immutable identity inside an externally authenticated OCI release."""

    configured_revision = os.environ.get("UMI_GIT_REVISION", "")
    if not _REVISION_RE.fullmatch(configured_revision):
        raise SimpleBootstrapError("image_git_revision_invalid")
    if re.fullmatch(r"[0-9a-f]{64}", expected_source_sha256) is None:
        raise SimpleBootstrapError("image_source_tree_sha256_invalid")
    if (
        not revision_path.is_absolute()
        or revision_path != Path(os.path.normpath(revision_path))
        or revision_path.is_symlink()
    ):
        raise SimpleBootstrapError("image_revision_path_unsafe")
    try:
        if revision_path.resolve(strict=True) != revision_path:
            raise SimpleBootstrapError("image_revision_path_unsafe")
        descriptor = os.open(
            revision_path,
            os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
    except SimpleBootstrapError:
        raise
    except OSError as error:
        raise SimpleBootstrapError("image_revision_marker_unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) != 0o444
            or metadata.st_nlink != 1
            or metadata.st_size != 41
        ):
            raise SimpleBootstrapError("image_revision_marker_unsafe")
        payload = os.read(descriptor, 42)
    finally:
        os.close(descriptor)
    if payload != configured_revision.encode("ascii") + b"\n":
        raise SimpleBootstrapError("image_revision_marker_mismatch")
    if umi_source_tree_sha256() != expected_source_sha256:
        raise SimpleBootstrapError("image_source_tree_mismatch")
    return configured_revision


def _verify_historical_manifest(signed: SignedBootstrapEligibilityManifest) -> None:
    if signed.manifest_sha256 != SIMPLE_BOOTSTRAP_MANIFEST_SHA256:
        raise ValueError("simple bootstrap manifest is not the frozen launch manifest")
    if bootstrap_policy_hash(signed.manifest.policy) != SIMPLE_BOOTSTRAP_POLICY_SHA256:
        raise ValueError("simple bootstrap policy is not the frozen launch policy")
    # Omitting current_block intentionally verifies the signed historical state
    # at its frozen block.  The common lease is the explicit TTL/transport bridge.
    verify_signed_bootstrap_eligibility_manifest(
        signed,
        expected_coordinator_hotkey=signed.manifest.policy.coordinator_hotkey,
    )


def _expected_row(signed: SignedBootstrapEligibilityManifest) -> list[list[int]]:
    eligible = {entry.uid for entry in signed.manifest.entries}
    return [[uid, U16_MAX if uid in eligible else 0] for uid in range(DIRECT_FULL_ROW_SIZE)]


def _participant(snapshot: BootstrapChainSnapshot, hotkey: str) -> BootstrapChainParticipant:
    matches = [
        value
        for value in snapshot.participants
        if account_id32(value.hotkey) == account_id32(hotkey)
    ]
    if len(matches) != 1:
        raise SimpleBootstrapError("validator_not_uniquely_registered")
    return matches[0]


def validate_simple_bootstrap_observation(
    signed_manifest: SignedBootstrapEligibilityManifest,
    signed_lease: SignedSimpleBootstrapLease,
    observation: SimpleBootstrapObservation,
    *,
    validator_hotkey: str,
    expected_revision: str,
    now: datetime | None = None,
) -> ValidatedSimpleBootstrap:
    snapshot = observation.snapshot
    verify_simple_bootstrap_lease(
        signed_lease,
        signed_manifest=signed_manifest,
        expected_revision=expected_revision,
        current_block=snapshot.block_number,
    )
    now_ms = _datetime_ms(now or datetime.now(timezone.utc))
    if snapshot.block_timestamp_ms < now_ms - _MAX_FINALIZED_HEAD_AGE_MS:
        raise SimpleBootstrapError("finalized_head_stale")
    if snapshot.block_timestamp_ms > now_ms + _MAX_FINALIZED_FUTURE_SKEW_MS:
        raise SimpleBootstrapError("finalized_head_future_dated")
    body = signed_lease.body
    gates = (
        (
            observation.runtime_spec_version,
            body.required_runtime_spec_version,
            "runtime_spec_version_changed",
        ),
        (snapshot.mechanism_count, body.required_mechanism_count, "mechanism_count_changed"),
        (
            snapshot.commit_reveal_enabled,
            body.required_commit_reveal_enabled,
            "commit_reveal_state_changed",
        ),
        (
            snapshot.commit_reveal_version,
            body.required_commit_reveal_version,
            "commit_reveal_version_changed",
        ),
        (
            snapshot.reveal_period_epochs,
            body.required_reveal_period_epochs,
            "reveal_period_changed",
        ),
        (snapshot.tempo, body.required_tempo, "tempo_changed"),
        (
            snapshot.activity_cutoff_blocks,
            body.required_activity_cutoff_blocks,
            "activity_cutoff_changed",
        ),
        (
            snapshot.weights_set_rate_limit,
            body.required_weights_set_rate_limit,
            "weights_rate_limit_changed",
        ),
        (snapshot.weights_version_key, body.weights_version_key, "weights_version_changed"),
        (
            snapshot.min_allowed_weights,
            body.required_min_allowed_weights,
            "minimum_weights_changed",
        ),
        (snapshot.max_allowed_uids, body.required_max_allowed_uids, "maximum_uids_changed"),
    )
    for actual, expected, reason in gates:
        if actual != expected:
            raise SimpleBootstrapError(reason)
    if snapshot.block_time_seconds != 12.0:
        raise SimpleBootstrapError("block_time_changed")
    if snapshot.manifest_frozen_block_hash != signed_manifest.manifest.frozen_at_block_hash:
        raise SimpleBootstrapError("manifest_frozen_block_hash_changed")
    if snapshot.total_pending_commit_count or snapshot.validator_has_pending_commit:
        raise SimpleBootstrapError("pending_commit_exists")
    if sorted(item.uid for item in snapshot.participants) != list(range(DIRECT_FULL_ROW_SIZE)):
        raise SimpleBootstrapError("uid_domain_changed")
    owner_account = bytes.fromhex(observation.subnet_owner_hotkey_account_id32[2:])
    owner = next((item for item in snapshot.participants if item.uid == 0), None)
    if owner is None or account_id32(owner.hotkey) != owner_account:
        raise SimpleBootstrapError("subnet_owner_uid_zero_mapping_changed")
    validator = _participant(snapshot, validator_hotkey)
    if not validator.validator_permit:
        raise SimpleBootstrapError("validator_permit_missing")
    expected = _expected_row(signed_manifest)
    if expected[validator.uid][1] != 0:
        raise SimpleBootstrapError("validator_is_an_eligible_miner")
    by_uid = {item.uid: item for item in snapshot.participants}
    for entry in signed_manifest.manifest.entries:
        current = by_uid.get(entry.uid)
        if (
            current is None
            or account_id32(current.hotkey) != account_id32(entry.miner_hotkey)
            or current.origin != entry.origin
            or current.validator_permit
        ):
            raise SimpleBootstrapError("eligible_miner_mapping_changed")
    positive_count = len(signed_manifest.manifest.entries)
    if snapshot.max_weights_limit == 0 or positive_count * snapshot.max_weights_limit < U16_MAX:
        raise SimpleBootstrapError("row_exceeds_max_weight_ratio")
    warnings = sorted(
        set(observation.warning_codes)
        | ({"manifest_anchor_missing"} if observation.manifest_anchor_block is None else set())
        | {
            (
                "own_active_non_umi_row_detected"
                if account_id32(active.hotkey) == account_id32(validator.hotkey)
                else f"other_active_non_umi_row_uid_{active.uid}"
            )
            for active in observation.active_rows
            if active.row != expected
        }
    )

    rate_ready_block = validator.last_update + snapshot.weights_set_rate_limit
    refresh_block = (
        validator.last_update + snapshot.activity_cutoff_blocks - body.refresh_margin_blocks
    )
    own_row_exact = snapshot.validator_mechid0_row == expected
    own_active = any(
        account_id32(item.hotkey) == account_id32(validator.hotkey)
        for item in observation.active_rows
    )
    if (
        own_row_exact
        and own_active
        and validator.last_update + snapshot.activity_cutoff_blocks >= body.hard_sunset_block - 1
    ):
        decision = SimpleBootstrapDecision(
            action="wait",
            reason_code="hard_sunset_covered",
            finalized_block=snapshot.block_number,
            next_action_block=body.hard_sunset_block,
        )
    elif snapshot.block_number + SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD >= (body.hard_sunset_block):
        decision = SimpleBootstrapDecision(
            action="sunset",
            reason_code="hard_sunset_reached",
            finalized_block=snapshot.block_number,
            next_action_block=None,
        )
    elif own_row_exact and own_active and snapshot.block_number < refresh_block:
        decision = SimpleBootstrapDecision(
            action="wait",
            reason_code="exact_row_active",
            finalized_block=snapshot.block_number,
            next_action_block=refresh_block,
        )
    elif snapshot.block_number < rate_ready_block:
        decision = SimpleBootstrapDecision(
            action="wait",
            reason_code="weights_rate_limit_not_elapsed",
            finalized_block=snapshot.block_number,
            next_action_block=rate_ready_block,
        )
    else:
        decision = SimpleBootstrapDecision(
            action="submit",
            reason_code="exact_row_refresh_due",
            finalized_block=snapshot.block_number,
            next_action_block=snapshot.block_number,
        )
    return ValidatedSimpleBootstrap(
        observation=observation,
        validator_hotkey=validator.hotkey,
        validator_uid=validator.uid,
        validator_last_update=validator.last_update,
        expected_row=expected,
        warning_codes=warnings,
        decision=decision,
    )


def build_simple_bootstrap_call(
    validated: ValidatedSimpleBootstrap,
    *,
    call_builder: Callable[..., Any] = bt.calls.SubtensorModule.set_mechanism_weights,
) -> Any:
    if validated.decision.action != "submit":
        raise SimpleBootstrapError("simple_bootstrap_submission_not_due")
    dests = list(range(DIRECT_FULL_ROW_SIZE))
    weights = [pair[1] for pair in validated.expected_row]
    raw = call_builder(
        netuid=78,
        mecid=0,
        dests=dests,
        weights=weights,
        version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
    )
    if raw.module != "SubtensorModule" or raw.function != "set_mechanism_weights":
        raise SimpleBootstrapError("raw_weight_call_shape_mismatch")
    if raw.params != {
        "netuid": 78,
        "mecid": 0,
        "dests": dests,
        "weights": weights,
        "version_key": DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
    }:
        raise SimpleBootstrapError("raw_weight_call_parameters_changed")
    return raw


class BittensorSimpleBootstrapChain(BittensorBootstrapChain):
    """Collect the base snapshot plus each active row at the same finalized block."""

    async def observation_with_client(
        self,
        client: Any,
        signed_manifest: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
    ) -> SimpleBootstrapObservation:
        snapshot = await self._snapshot(
            client,
            signed_manifest,
            validator_hotkey=validator_hotkey,
        )
        pinned = await client.at(snapshot.block_number)
        info = await pinned.block_info()
        if (
            getattr(info, "number", None) != snapshot.block_number
            or getattr(info, "hash", None) != snapshot.block_hash
        ):
            raise SimpleBootstrapError("active_row_snapshot_changed")
        owner, commitment, runtime_upgrade = await asyncio.gather(
            pinned.query(storage.SubtensorModule.SubnetOwnerHotkey, [78]),
            pinned.query(storage.Commitments.CommitmentOf, [78, validator_hotkey]),
            pinned.query(storage.System.LastRuntimeUpgrade),
        )
        owner_account = _account_bytes(owner)
        runtime_spec_version = _runtime_spec_version(runtime_upgrade)
        manifest_anchor_block, commitment_warning = _manifest_anchor_state(
            commitment,
            signed_manifest.manifest_sha256,
        )
        active_accounts = {account_id32(value) for value in snapshot.active_mechid0_row_hotkeys}
        active_participants = sorted(
            (
                item
                for item in snapshot.participants
                if account_id32(item.hotkey) in active_accounts
            ),
            key=lambda item: account_id32(item.hotkey),
        )
        rows = await asyncio.gather(
            *(
                pinned.query(storage.SubtensorModule.Weights, [78, item.uid])
                for item in active_participants
            )
        )
        active_rows = [
            SimpleActiveRow(
                hotkey=item.hotkey,
                uid=item.uid,
                last_update=item.last_update,
                row=_weight_row(row),
            )
            for item, row in zip(active_participants, rows, strict=True)
        ]
        return SimpleBootstrapObservation(
            snapshot=snapshot,
            runtime_spec_version=runtime_spec_version,
            subnet_owner_hotkey_account_id32="0x" + owner_account.hex(),
            manifest_anchor_block=manifest_anchor_block,
            warning_codes=[] if commitment_warning is None else [commitment_warning],
            active_rows=active_rows,
        )

    async def observation(
        self,
        signed_manifest: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
    ) -> SimpleBootstrapObservation:
        async with self.client_factory("finney") as client:
            return await self.observation_with_client(
                client,
                signed_manifest,
                validator_hotkey=validator_hotkey,
            )


def reconcile_simple_bootstrap_journal(
    journal: SimpleBootstrapJournal | None,
    validated: ValidatedSimpleBootstrap,
    *,
    lease_sha256: str,
    now: datetime | None = None,
) -> SimpleBootstrapJournal | None:
    if journal is None:
        return None
    # A signed release may renew the lease while preserving this v1 worker's
    # compile-time manifest, row, mechanism, version, and sunset.  Reconcile an
    # unfinished attempt across that update instead of discarding its possible
    # chain effect.  The lease hash remains in the journal as audit context; the
    # manifest and validator bindings are the safety-critical identities here.
    if journal.manifest_sha256 != SIMPLE_BOOTSTRAP_MANIFEST_SHA256 or account_id32(
        journal.validator_hotkey
    ) != account_id32(validated.validator_hotkey):
        raise SimpleBootstrapError("local_journal_binding_mismatch")
    if journal.phase in {
        "anchor_applied",
        "anchor_not_applied",
        "applied",
        "recovered_applied",
        "not_applied",
    }:
        return journal
    snapshot = validated.snapshot
    if journal.phase == "ambiguous_effect" and not (
        snapshot.validator_mechid0_row == validated.expected_row
        and validated.validator_last_update > journal.prior_last_update
    ):
        raise SimpleBootstrapError("prior_submission_effect_is_ambiguous")
    if journal.phase in {"anchor_submitting", "anchor_outcome_unknown"}:
        if validated.observation.manifest_anchor_block is not None:
            return journal.model_copy(
                update={
                    "phase": "anchor_applied",
                    "manifest_anchor_block": validated.observation.manifest_anchor_block,
                    "observation_block": snapshot.block_number,
                    "updated_at": now or datetime.now(timezone.utc),
                }
            )
        if snapshot.block_number <= (
            journal.preflight_block + SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS
        ):
            raise SimpleBootstrapError("prior_anchor_outcome_still_unknown")
        return journal.model_copy(
            update={
                "phase": "anchor_not_applied",
                "observation_block": snapshot.block_number,
                "updated_at": now or datetime.now(timezone.utc),
            }
        )
    if (
        snapshot.validator_mechid0_row == validated.expected_row
        and validated.validator_last_update > journal.prior_last_update
    ):
        # The exact authorized row is the receipt.  Attribution to this process
        # or another holder of the same validator hotkey does not change the
        # chain effect, so recover without inventing inclusion metadata.
        return journal.model_copy(
            update={
                "phase": "recovered_applied",
                "observation_block": snapshot.block_number,
                "updated_at": now or datetime.now(timezone.utc),
            }
        )
    if snapshot.block_number <= journal.preflight_block + SIMPLE_BOOTSTRAP_UNKNOWN_EFFECT_BLOCKS:
        raise SimpleBootstrapError("prior_submission_outcome_still_unknown")
    return journal.model_copy(
        update={
            "phase": "not_applied",
            "observation_block": snapshot.block_number,
            "updated_at": now or datetime.now(timezone.utc),
        }
    )


async def run_simple_bootstrap_iteration(
    signed_manifest: SignedBootstrapEligibilityManifest,
    signed_lease: SignedSimpleBootstrapLease,
    *,
    wallet: Any,
    chain: BittensorSimpleBootstrapChain,
    expected_revision: str,
    journal_path: Path,
    pilots_verified: bool,
) -> tuple[SimpleBootstrapStatus, bool]:
    signer = bt.resolve_signer(wallet, role="hotkey")
    validator_hotkey = signer.ss58_address
    lease_sha256 = hashlib.sha256(canonical_json_bytes(signed_lease)).hexdigest()
    async with chain.client_factory("finney") as client:
        observation = await chain.observation_with_client(
            client,
            signed_manifest,
            validator_hotkey=validator_hotkey,
        )
        if observation.snapshot.block_number >= signed_lease.body.hard_sunset_block:
            return (
                SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status="sunset",
                    reason_code="hard_sunset_reached",
                    finalized_block=observation.snapshot.block_number,
                    validator_hotkey=validator_hotkey,
                    validator_uid=None,
                    next_action_block=None,
                ),
                pilots_verified,
            )
        validated = validate_simple_bootstrap_observation(
            signed_manifest,
            signed_lease,
            observation,
            validator_hotkey=validator_hotkey,
            expected_revision=expected_revision,
            now=chain.clock(),
        )
        existing = _load_optional_journal(journal_path)
        reconciled = reconcile_simple_bootstrap_journal(
            existing,
            validated,
            lease_sha256=lease_sha256,
            now=chain.clock(),
        )
        if reconciled is not None and reconciled != existing:
            _replace_canonical(journal_path, reconciled)
        if reconciled is not None and reconciled.phase == "ambiguous_effect":
            raise SimpleBootstrapError("prior_submission_effect_is_ambiguous")
        if (
            validated.decision.action == "sunset"
            and validated.decision.reason_code == "hard_sunset_reached"
        ):
            return (
                SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status="sunset",
                    reason_code=validated.decision.reason_code,
                    finalized_block=validated.snapshot.block_number,
                    validator_hotkey=validator_hotkey,
                    validator_uid=validated.validator_uid,
                    next_action_block=validated.decision.next_action_block,
                    warning_codes=validated.warning_codes,
                ),
                pilots_verified,
            )
        if observation.manifest_anchor_block is None:
            anchor_attempt_id = hashlib.sha256(
                b"umi-simple-bootstrap-anchor-attempt-v1\0"
                + bytes.fromhex(lease_sha256)
                + account_id32(validator_hotkey)
                + validated.snapshot.block_number.to_bytes(8, "big")
            ).hexdigest()
            anchor_journal = SimpleBootstrapJournal(
                schema=SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA,
                phase="anchor_submitting",
                lease_sha256=lease_sha256,
                manifest_sha256=signed_manifest.manifest_sha256,
                validator_hotkey=validator_hotkey,
                attempt_id=anchor_attempt_id,
                preflight_block=validated.snapshot.block_number,
                prior_last_update=validated.validator_last_update,
                updated_at=chain.clock(),
            )
            _replace_canonical(journal_path, anchor_journal)
            try:
                anchor_result = await client.submit_call(
                    build_sha256_commitment_call(signed_manifest.manifest_sha256),
                    wallet,
                    signer="hotkey",
                    period=SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                )
                anchor_call = _successful_extrinsic(
                    anchor_result,
                    reason="simple_bootstrap_manifest_anchor_failed",
                )
            except Exception:
                _replace_canonical(
                    journal_path,
                    anchor_journal.model_copy(
                        update={
                            "phase": "anchor_outcome_unknown",
                            "updated_at": chain.clock(),
                        }
                    ),
                )
                raise
            observation = await chain.observation_with_client(
                client,
                signed_manifest,
                validator_hotkey=validator_hotkey,
            )
            if observation.manifest_anchor_block != anchor_call.block_number:
                _replace_canonical(
                    journal_path,
                    anchor_journal.model_copy(
                        update={
                            "phase": "anchor_outcome_unknown",
                            "updated_at": chain.clock(),
                        }
                    ),
                )
                raise SimpleBootstrapError("finalized_manifest_anchor_mismatch")
            anchor_journal = anchor_journal.model_copy(
                update={
                    "phase": "anchor_applied",
                    "manifest_anchor_block": anchor_call.block_number,
                    "anchor_call": anchor_call,
                    "observation_block": observation.snapshot.block_number,
                    "updated_at": chain.clock(),
                }
            )
            _replace_canonical(journal_path, anchor_journal)
            reconciled = anchor_journal
            validated = validate_simple_bootstrap_observation(
                signed_manifest,
                signed_lease,
                observation,
                validator_hotkey=validator_hotkey,
                expected_revision=expected_revision,
                now=chain.clock(),
            )
        if validated.decision.action != "submit":
            return (
                SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status="sunset" if validated.decision.action == "sunset" else "waiting",
                    reason_code=validated.decision.reason_code,
                    finalized_block=validated.snapshot.block_number,
                    validator_hotkey=validator_hotkey,
                    validator_uid=validated.validator_uid,
                    next_action_block=validated.decision.next_action_block,
                    warning_codes=validated.warning_codes,
                    journal_phase=(None if reconciled is None else reconciled.phase),
                ),
                pilots_verified,
            )
        if not pilots_verified:
            await replay_bootstrap_pilots(signed_manifest)
            pilots_verified = True
        await probe_bootstrap_health(signed_manifest, validated, clock=chain.clock)
        # Repeat every mutable finalized input after the network probes.
        observation = await chain.observation_with_client(
            client,
            signed_manifest,
            validator_hotkey=validator_hotkey,
        )
        validated = validate_simple_bootstrap_observation(
            signed_manifest,
            signed_lease,
            observation,
            validator_hotkey=validator_hotkey,
            expected_revision=expected_revision,
            now=chain.clock(),
        )
        if validated.decision.action != "submit":
            return (
                SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status="waiting",
                    reason_code="submission_no_longer_due",
                    finalized_block=validated.snapshot.block_number,
                    validator_hotkey=validator_hotkey,
                    validator_uid=validated.validator_uid,
                    next_action_block=validated.decision.next_action_block,
                    warning_codes=validated.warning_codes,
                ),
                pilots_verified,
            )
        if observation.manifest_anchor_block is None:
            raise SimpleBootstrapError("manifest_anchor_missing_before_weight_call")
        raw_call = build_simple_bootstrap_call(validated)
        attempt_id = hashlib.sha256(
            b"umi-simple-bootstrap-attempt-v1\0"
            + bytes.fromhex(lease_sha256)
            + account_id32(validator_hotkey)
            + validated.snapshot.block_number.to_bytes(8, "big")
        ).hexdigest()
        journal = SimpleBootstrapJournal(
            schema=SIMPLE_BOOTSTRAP_JOURNAL_SCHEMA,
            phase="submitting",
            lease_sha256=lease_sha256,
            manifest_sha256=signed_manifest.manifest_sha256,
            validator_hotkey=validator_hotkey,
            attempt_id=attempt_id,
            preflight_block=validated.snapshot.block_number,
            prior_last_update=validated.validator_last_update,
            manifest_anchor_block=observation.manifest_anchor_block,
            updated_at=chain.clock(),
        )
        _replace_canonical(journal_path, journal)
        try:
            result = await client.submit_call(
                raw_call,
                wallet,
                signer="hotkey",
                period=SIMPLE_BOOTSTRAP_SUBMISSION_ERA_PERIOD,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
            weight_call = _successful_extrinsic(
                result,
                reason="simple_bootstrap_weight_call_failed",
            )
        except Exception:
            _replace_canonical(
                journal_path,
                journal.model_copy(
                    update={"phase": "outcome_unknown", "updated_at": chain.clock()}
                ),
            )
            raise
        after = await chain.observation_with_client(
            client,
            signed_manifest,
            validator_hotkey=validator_hotkey,
        )
        post = validate_simple_bootstrap_observation(
            signed_manifest,
            signed_lease,
            after,
            validator_hotkey=validator_hotkey,
            expected_revision=expected_revision,
            now=chain.clock(),
        )
        if (
            after.snapshot.block_number < weight_call.block_number
            or after.snapshot.validator_mechid0_row != validated.expected_row
            or post.validator_last_update != weight_call.block_number
        ):
            _replace_canonical(
                journal_path,
                journal.model_copy(
                    update={"phase": "outcome_unknown", "updated_at": chain.clock()}
                ),
            )
            raise SimpleBootstrapError("finalized_weight_application_mismatch")
        applied = journal.model_copy(
            update={
                "phase": "applied",
                "weight_call": weight_call,
                "observation_block": after.snapshot.block_number,
                "updated_at": chain.clock(),
            }
        )
        _replace_canonical(journal_path, applied)
        return (
            SimpleBootstrapStatus(
                schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                status="submitted",
                reason_code="exact_row_applied",
                finalized_block=after.snapshot.block_number,
                validator_hotkey=validator_hotkey,
                validator_uid=validated.validator_uid,
                next_action_block=(
                    weight_call.block_number
                    + after.snapshot.activity_cutoff_blocks
                    - signed_lease.body.refresh_margin_blocks
                ),
                warning_codes=post.warning_codes,
                journal_phase="applied",
                weight_call=weight_call,
            ),
            pilots_verified,
        )


async def run_simple_bootstrap_service(
    signed_manifest: SignedBootstrapEligibilityManifest,
    signed_lease: SignedSimpleBootstrapLease,
    *,
    wallet: Any,
    chain: BittensorSimpleBootstrapChain,
    expected_revision: str,
    journal_path: Path,
    poll_seconds: float,
    once: bool = False,
) -> int:
    pilots_verified = False
    while True:
        delay_seconds = poll_seconds
        try:
            status, pilots_verified = await run_simple_bootstrap_iteration(
                signed_manifest,
                signed_lease,
                wallet=wallet,
                chain=chain,
                expected_revision=expected_revision,
                journal_path=journal_path,
                pilots_verified=pilots_verified,
            )
            _print_canonical(status)
            if status.status == "sunset" or once:
                return 0
            if status.finalized_block is not None and status.next_action_block is not None:
                blocks = max(1, status.next_action_block - status.finalized_block - 2)
                delay_seconds = min(poll_seconds, max(15.0, blocks * 12.0))
        except (BootstrapOperatorError, OSError, RuntimeError, TypeError, ValueError) as error:
            reason = getattr(error, "reason_code", "simple_bootstrap_iteration_failed")
            signer = bt.resolve_signer(wallet, role="hotkey")
            _print_canonical(
                SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status="error",
                    reason_code=reason,
                    finalized_block=None,
                    validator_hotkey=signer.ss58_address,
                    validator_uid=None,
                    next_action_block=None,
                )
            )
            if once:
                return 2
            delay_seconds = max(60.0, poll_seconds)
        await asyncio.sleep(delay_seconds)


def _account_bytes(value: Any) -> bytes:
    candidate = getattr(value, "value", value)
    if isinstance(candidate, str) and candidate.startswith("0x"):
        return account_id32(bytes.fromhex(candidate[2:]))
    return account_id32(candidate)


def _manifest_anchor_state(value: Any, expected_sha256: str) -> tuple[int | None, str | None]:
    raw = getattr(value, "value", value)
    if raw is None:
        return None, None
    try:
        return _exact_sha256_commitment(value, expected_sha256), None
    except BootstrapOperatorError:
        # An older validator may have a different, otherwise ordinary
        # commitment.  The new process replaces it before setting weights.
        # Malformed storage is not treated as an old commitment.
        if not isinstance(raw, Mapping):
            raise
        block = raw.get("block")
        info = raw.get("info")
        fields = info.get("fields") if isinstance(info, Mapping) else None
        if (
            isinstance(block, bool)
            or not isinstance(block, int)
            or block <= 0
            or not isinstance(fields, Sequence)
            or isinstance(fields, (str, bytes, bytearray))
            or len(fields) != 1
        ):
            raise
        field = fields[0]
        if not isinstance(field, Mapping) or set(field) != {"Sha256"}:
            raise
        encoded_digest = field["Sha256"]
        if isinstance(encoded_digest, bytes):
            digest = encoded_digest
        elif isinstance(encoded_digest, str) and encoded_digest.startswith("0x"):
            try:
                digest = bytes.fromhex(encoded_digest[2:])
            except ValueError:
                raise
        else:
            raise
        if len(digest) != 32:
            raise
        return None, "existing_commitment_will_be_replaced"


def _weight_row(value: Any) -> list[list[int]]:
    raw = getattr(value, "value", value)
    if raw is None:
        return []
    return [[int(pair[0]), int(pair[1])] for pair in raw]


def _runtime_spec_version(value: Any) -> int:
    raw = getattr(value, "value", value)
    if not isinstance(raw, Mapping):
        raise SimpleBootstrapError("runtime_spec_version_invalid")
    version = raw.get("spec_version", raw.get("specVersion"))
    if (
        isinstance(version, bool)
        or not isinstance(version, int)
        or version <= 0
        or version > _MAX_JSON_SAFE_INTEGER
    ):
        raise SimpleBootstrapError("runtime_spec_version_invalid")
    return version


def _read_model(path: Path, model: type[Any], maximum_bytes: int = 4 * 1024 * 1024) -> Any:
    flags = os.O_RDONLY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_size <= 0
            or metadata.st_size > maximum_bytes
        ):
            raise SimpleBootstrapError("input_file_unsafe")
        payload = os.read(descriptor, maximum_bytes + 1)
    finally:
        os.close(descriptor)
    return model.model_validate_json(payload)


def _load_optional_journal(path: Path) -> SimpleBootstrapJournal | None:
    if not path.exists():
        return None
    return _read_model(path, SimpleBootstrapJournal, 1024 * 1024)


def _replace_canonical(path: Path, value: Any) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    payload = canonical_json_bytes(value)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()


def _print_canonical(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")
    sys.stdout.buffer.flush()


class _ProcessLock:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.descriptor = -1

    def __enter__(self) -> None:
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.descriptor = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(self.descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            os.close(self.descriptor)
            self.descriptor = -1
            raise SimpleBootstrapError("another_simple_bootstrap_service_is_running") from error

    def __exit__(self, *_args: Any) -> None:
        if self.descriptor >= 0:
            os.close(self.descriptor)


def _env_or(value: str | None, name: str) -> str:
    result = value if value is not None else os.environ.get(name, "")
    if not result:
        raise SimpleBootstrapError(f"{name.lower()}_missing")
    return result


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m umi.simple_bootstrap_validator",
        description="Run the common-lease SN78 bootstrap validator",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    create = commands.add_parser("create-lease-body")
    create.add_argument("--manifest", type=Path, required=True)
    create.add_argument("--umi-git-revision", required=True)
    create.add_argument("--valid-from-block", type=int, required=True)
    create.add_argument(
        "--refresh-margin-blocks",
        type=int,
        default=SIMPLE_BOOTSTRAP_DEFAULT_REFRESH_MARGIN_BLOCKS,
    )
    create.add_argument("--output", type=Path, required=True)
    sign = commands.add_parser("sign-lease")
    sign.add_argument("--body", type=Path, required=True)
    sign.add_argument("--output", type=Path, required=True)
    sign.add_argument("--wallet-name", required=True)
    sign.add_argument("--hotkey", required=True)
    sign.add_argument("--wallet-path", default="~/.bittensor/wallets")
    verify = commands.add_parser("verify-lease")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--lease", type=Path, required=True)
    verify.add_argument("--expected-revision", required=True)
    verify.add_argument(
        "--current-block",
        type=int,
        help=(
            "optional live block for interval validation; defaults to the lease's "
            "valid-from block for offline release-asset verification"
        ),
    )
    for name in ("run", "status"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path)
        command.add_argument("--lease", type=Path)
        command.add_argument("--expected-revision")
        command.add_argument("--wallet-name")
        command.add_argument("--hotkey")
        command.add_argument("--wallet-path")
        command.add_argument(
            "--state-dir",
            type=Path,
            default=Path("/var/lib/umi-simple-bootstrap"),
        )
    run = commands.choices["run"]
    run.add_argument("--poll-seconds", type=float, default=300.0)
    run.add_argument("--once", action="store_true")
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if args.command == "create-lease-body":
            signed = _read_model(args.manifest, SignedBootstrapEligibilityManifest)
            body = build_simple_bootstrap_lease_body(
                signed,
                umi_git_revision=args.umi_git_revision,
                valid_from_block=args.valid_from_block,
                refresh_margin_blocks=args.refresh_margin_blocks,
            )
            _replace_canonical(args.output, body)
            _print_canonical(body)
            return 0
        if args.command == "sign-lease":
            body = _read_model(args.body, SimpleBootstrapLeaseBody)
            wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
            signed_lease = sign_simple_bootstrap_lease(body, wallet=wallet)
            _replace_canonical(args.output, signed_lease)
            _print_canonical(signed_lease)
            return 0
        if args.command == "verify-lease":
            signed = _read_model(args.manifest, SignedBootstrapEligibilityManifest)
            lease = _read_model(args.lease, SignedSimpleBootstrapLease)
            result = verify_simple_bootstrap_lease(
                lease,
                signed_manifest=signed,
                expected_revision=args.expected_revision,
                current_block=(
                    lease.body.valid_from_block
                    if args.current_block is None
                    else args.current_block
                ),
            )
            _print_canonical(result)
            return 0
        manifest_path = Path(
            _env_or(str(args.manifest) if args.manifest is not None else None, "UMI_MANIFEST_PATH")
        )
        lease_path = Path(
            _env_or(str(args.lease) if args.lease is not None else None, "UMI_LEASE_PATH")
        )
        signed = _read_model(manifest_path, SignedBootstrapEligibilityManifest)
        lease = _read_model(lease_path, SignedSimpleBootstrapLease)
        actual_revision = verify_simple_bootstrap_checkout()
        configured_revision = args.expected_revision or os.environ.get("UMI_GIT_REVISION")
        if configured_revision is not None and configured_revision != actual_revision:
            raise SimpleBootstrapError("configured_revision_differs_from_running_checkout")
        expected_revision = actual_revision
        wallet_name = _env_or(args.wallet_name, "UMI_WALLET_NAME")
        hotkey = _env_or(args.hotkey, "UMI_HOTKEY")
        wallet_path = _env_or(args.wallet_path, "UMI_WALLET_PATH")
        if not _REVISION_RE.fullmatch(expected_revision):
            raise SimpleBootstrapError("umi_git_revision_invalid")
        wallet = bt.Wallet(name=wallet_name, hotkey=hotkey, path=wallet_path)
        state_dir = args.state_dir.resolve()
        if args.command == "status":
            signer = bt.resolve_signer(wallet, role="hotkey")
            chain = BittensorSimpleBootstrapChain()
            observation = asyncio.run(
                chain.observation(signed, validator_hotkey=signer.ss58_address)
            )
            if observation.snapshot.block_number >= lease.body.hard_sunset_block:
                status = SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status="sunset",
                    reason_code="hard_sunset_reached",
                    finalized_block=observation.snapshot.block_number,
                    validator_hotkey=signer.ss58_address,
                    validator_uid=None,
                    next_action_block=None,
                )
            else:
                validated = validate_simple_bootstrap_observation(
                    signed,
                    lease,
                    observation,
                    validator_hotkey=signer.ss58_address,
                    expected_revision=expected_revision,
                    now=chain.clock(),
                )
                lease_sha256 = hashlib.sha256(canonical_json_bytes(lease)).hexdigest()
                journal = reconcile_simple_bootstrap_journal(
                    _load_optional_journal(state_dir / "journal.json"),
                    validated,
                    lease_sha256=lease_sha256,
                    now=chain.clock(),
                )
                status = SimpleBootstrapStatus(
                    schema=SIMPLE_BOOTSTRAP_STATUS_SCHEMA,
                    status=("sunset" if validated.decision.action == "sunset" else "waiting"),
                    reason_code=validated.decision.reason_code,
                    finalized_block=validated.snapshot.block_number,
                    validator_hotkey=validated.validator_hotkey,
                    validator_uid=validated.validator_uid,
                    next_action_block=validated.decision.next_action_block,
                    warning_codes=validated.warning_codes,
                    journal_phase=None if journal is None else journal.phase,
                )
            _print_canonical(status)
            return 0
        if not 5 <= args.poll_seconds <= 300:
            raise SimpleBootstrapError("poll_seconds_out_of_range")
        with _ProcessLock(state_dir / "service.lock"):
            return asyncio.run(
                run_simple_bootstrap_service(
                    signed,
                    lease,
                    wallet=wallet,
                    chain=BittensorSimpleBootstrapChain(),
                    expected_revision=expected_revision,
                    journal_path=state_dir / "journal.json",
                    poll_seconds=args.poll_seconds,
                    once=args.once,
                )
            )
    except (
        BootstrapOperatorError,
        OSError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        reason = getattr(error, "reason_code", "simple_bootstrap_validator_failed")
        parser.exit(2, f"simple bootstrap validator failed: {reason}\n")
    return 0


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()


__all__ = [
    "SIMPLE_BOOTSTRAP_HARD_SUNSET_BLOCK",
    "SIMPLE_BOOTSTRAP_LEASE_BODY_SCHEMA",
    "SIMPLE_BOOTSTRAP_LEASE_SCHEMA",
    "SIMPLE_BOOTSTRAP_MANIFEST_SHA256",
    "SIMPLE_BOOTSTRAP_RUNTIME_SPEC_VERSION",
    "BittensorSimpleBootstrapChain",
    "SignedSimpleBootstrapLease",
    "SimpleBootstrapDecision",
    "SimpleBootstrapError",
    "SimpleBootstrapLeaseBody",
    "SimpleBootstrapObservation",
    "ValidatedSimpleBootstrap",
    "build_simple_bootstrap_call",
    "build_simple_bootstrap_lease_body",
    "run_simple_bootstrap_iteration",
    "run_simple_bootstrap_service",
    "sign_simple_bootstrap_lease",
    "simple_bootstrap_lease_digest",
    "validate_simple_bootstrap_observation",
    "verify_simple_bootstrap_lease",
]
