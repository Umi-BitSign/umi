"""Permit-bound direct full-row bootstrap weight transition for SN78.

This module is deliberately separate from the CRv4 bootstrap operator.  It is
usable only while commit-reveal is disabled and ``MinAllowedWeights`` and
``MaxAllowedUids`` both equal 256.  The generated runtime call contains every
UID from 0 through 255, including zero weights.  It never passes the row
through a Bittensor convenience helper that may remove those zero entries.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import hmac
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import bittensor as bt
from bittensor._generated import storage
from pydantic import Field, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_weight_operator import (
    _FINNEY_GENESIS_HASH,
    _MAX_FINALIZED_FUTURE_SKEW_MS,
    _MAX_FINALIZED_HEAD_AGE_MS,
    _MAX_INPUT_BYTES,
    _MAX_JSON_SAFE_INTEGER,
    _MAX_RECEIPT_BYTES,
    _SUBMISSION_ERA_PERIOD,
    BittensorBootstrapChain,
    BootstrapChainSnapshot,
    BootstrapExtrinsicReference,
    BootstrapHealthReceiptSet,
    BootstrapManifestAnchorObservation,
    BootstrapOperatorError,
    BootstrapPilotReplaySet,
    _bool,
    _datetime_ms,
    _first_finalized_header,
    _load_canonical,
    _pending_commit_summary,
    _print_canonical,
    _successful_extrinsic,
    _uint,
    _validate_finalized_block,
    _write_new_canonical,
    probe_bootstrap_health,
    replay_bootstrap_pilots,
)
from .bootstrap_weights import (
    U16_MAX,
    SignedBootstrapEligibilityManifest,
    bootstrap_policy_hash,
    verify_signed_bootstrap_eligibility_manifest,
)
from .chain_evidence import MECHANISM_ID, NETUID, build_sha256_commitment_call
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes

DIRECT_PREFLIGHT_SCHEMA = "umi-bootstrap-direct-preflight/2"
DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA = "umi-bootstrap-direct-operational-preflight/2"
DIRECT_CALL_MATERIAL_SCHEMA = "umi-bootstrap-direct-call-material/2"
DIRECT_SUBMISSION_RECEIPT_SCHEMA = "umi-bootstrap-direct-submission-receipt/2"
DIRECT_TRANSITION_AUTHORIZATION_SCHEMA = "umi-bootstrap-direct-transition-authorization/2"
DIRECT_SUBMISSION_JOURNAL_SCHEMA = "umi-bootstrap-direct-submission-journal/2"
OWNER_FENCE_PREFLIGHT_SCHEMA = "umi-bootstrap-owner-fence-preflight/1"
OWNER_FENCE_CALL_MATERIAL_SCHEMA = "umi-bootstrap-owner-fence-call-material/1"
OWNER_FENCE_RECEIPT_SCHEMA = "umi-bootstrap-owner-fence-receipt/1"
OWNER_FENCE_JOURNAL_SCHEMA = "umi-bootstrap-owner-fence-journal/1"
DIRECT_TRANSITION_PROFILE = "direct_full_row/2"
DIRECT_LIVE_SUBMIT_ACKNOWLEDGEMENT = "SUBMIT SN78 DIRECT FULL BOOTSTRAP ROW"
OWNER_FENCE_LIVE_SUBMIT_ACKNOWLEDGEMENT = "APPLY SN78 DIRECT BOOTSTRAP OWNER FENCE"
DIRECT_FULL_ROW_SIZE = 256
DIRECT_MINIMUM_WEIGHTS_VERSION_KEY = 1 << 32
_DIRECT_AUTHORIZATION_DOMAIN = b"umi-bootstrap-direct-transition-authorization-v2\0"
_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class DirectBootstrapTransitionAuthorization(StrictProtocolModel):
    """Coordinator-signed authorization for one validator and one manifest."""

    schema_: Literal[DIRECT_TRANSITION_AUTHORIZATION_SCHEMA] = Field(alias="schema")
    transition_profile: Literal[DIRECT_TRANSITION_PROFILE]
    submission_id: Hex32
    manifest_sha256: Hex32
    original_policy_sha256: Hex32
    original_commit_stop_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    original_hard_sunset_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=255)]
    umi_git_revision: Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
    weights_version_key: Literal[DIRECT_MINIMUM_WEIGHTS_VERSION_KEY]
    signed_at_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    valid_from_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    expires_at_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    required_commit_reveal_enabled: Literal[False]
    required_mechanism_count: Literal[1]
    required_min_allowed_weights: Literal[256]
    required_max_allowed_uids: Literal[256]
    required_validator_permit: Literal[True]
    overrides_manifest_ttl_for_direct_transport: Literal[True]
    overrides_original_commit_stop_for_direct_transport: Literal[True]
    single_use: Literal[True]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @field_validator("coordinator_hotkey", "validator_hotkey")
    @classmethod
    def validate_coordinator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_interval(self) -> Self:
        if not self.signed_at_block <= self.valid_from_block <= self.expires_at_block:
            raise ValueError("direct transition authorization block interval is invalid")
        return self


def _direct_authorization_unsigned(
    authorization: DirectBootstrapTransitionAuthorization,
) -> dict[str, Any]:
    return {
        "schema": DIRECT_TRANSITION_AUTHORIZATION_SCHEMA,
        "transition_profile": DIRECT_TRANSITION_PROFILE,
        "submission_id": authorization.submission_id,
        "manifest_sha256": authorization.manifest_sha256,
        "original_policy_sha256": authorization.original_policy_sha256,
        "original_commit_stop_block": authorization.original_commit_stop_block,
        "original_hard_sunset_block": authorization.original_hard_sunset_block,
        "coordinator_hotkey": authorization.coordinator_hotkey,
        "validator_hotkey": authorization.validator_hotkey,
        "validator_uid": authorization.validator_uid,
        "umi_git_revision": authorization.umi_git_revision,
        "weights_version_key": authorization.weights_version_key,
        "signed_at_block": authorization.signed_at_block,
        "valid_from_block": authorization.valid_from_block,
        "expires_at_block": authorization.expires_at_block,
        "required_commit_reveal_enabled": False,
        "required_mechanism_count": 1,
        "required_min_allowed_weights": 256,
        "required_max_allowed_uids": 256,
        "required_validator_permit": True,
        "overrides_manifest_ttl_for_direct_transport": True,
        "overrides_original_commit_stop_for_direct_transport": True,
        "single_use": True,
    }


def direct_transition_authorization_digest(
    authorization: DirectBootstrapTransitionAuthorization,
) -> bytes:
    if not isinstance(authorization, DirectBootstrapTransitionAuthorization):
        raise TypeError("authorization must be a DirectBootstrapTransitionAuthorization")
    unsigned = canonical_json_bytes(_direct_authorization_unsigned(authorization))
    return hashlib.sha256(_DIRECT_AUTHORIZATION_DOMAIN + unsigned).digest()


def sign_direct_transition_authorization(
    signed: SignedBootstrapEligibilityManifest,
    *,
    weights_version_key: int,
    submission_id: str,
    umi_git_revision: str,
    signed_at_block: int,
    valid_from_block: int,
    expires_at_block: int,
    validator_hotkey: str,
    validator_uid: int,
    wallet: Any,
) -> DirectBootstrapTransitionAuthorization:
    """Authorize only the direct transport change while preserving miner consent."""

    try:
        # The original signature and opt-ins remain the consent source.  Their
        # short health/manifest TTLs are intentionally replaced by this signed,
        # narrowly scoped direct-transport interval; fresh mapping and health
        # evidence is still mandatory at each direct submission.
        verify_signed_bootstrap_eligibility_manifest(signed)
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("direct_authorization_manifest_invalid") from error
    signer = bt.resolve_signer(wallet, role="hotkey")
    if account_id32(signer.ss58_address) != account_id32(signed.manifest.policy.coordinator_hotkey):
        raise BootstrapOperatorError("direct_authorization_signer_mismatch")
    scheme = bt.wallets.format_crypto_type(signer.crypto_type)
    if scheme not in {"sr25519", "ed25519"}:
        raise BootstrapOperatorError("direct_authorization_signature_scheme_invalid")
    provisional = DirectBootstrapTransitionAuthorization(
        schema=DIRECT_TRANSITION_AUTHORIZATION_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        submission_id=submission_id,
        manifest_sha256=signed.manifest_sha256,
        original_policy_sha256=signed.manifest.policy_sha256,
        original_commit_stop_block=signed.manifest.policy.commit_stop_block,
        original_hard_sunset_block=signed.manifest.policy.hard_sunset_block,
        coordinator_hotkey=signer.ss58_address,
        validator_hotkey=validator_hotkey,
        validator_uid=validator_uid,
        umi_git_revision=umi_git_revision,
        weights_version_key=weights_version_key,
        signed_at_block=signed_at_block,
        valid_from_block=valid_from_block,
        expires_at_block=expires_at_block,
        required_commit_reveal_enabled=False,
        required_mechanism_count=1,
        required_min_allowed_weights=256,
        required_max_allowed_uids=256,
        required_validator_permit=True,
        overrides_manifest_ttl_for_direct_transport=True,
        overrides_original_commit_stop_for_direct_transport=True,
        single_use=True,
        signature_scheme=scheme,
        signature="0x" + "00" * 64,
    )
    _validate_direct_authorization_bounds(signed, provisional)
    signed_scheme, signature = sign_response_digest(
        wallet,
        direct_transition_authorization_digest(provisional),
    )
    if signed_scheme != scheme:
        raise BootstrapOperatorError("direct_authorization_signature_scheme_changed")
    return verify_direct_transition_authorization(
        signed,
        provisional.model_copy(update={"signature": signature}),
        current_block=valid_from_block,
    )


def verify_direct_transition_authorization(
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
    *,
    current_block: int,
) -> DirectBootstrapTransitionAuthorization:
    """Verify manifest binding, narrow override, interval, and coordinator signature."""

    if not isinstance(authorization, DirectBootstrapTransitionAuthorization):
        raise TypeError("authorization must be a DirectBootstrapTransitionAuthorization")
    verify_signed_bootstrap_eligibility_manifest(signed)
    _validate_direct_authorization_bounds(signed, authorization)
    if not authorization.valid_from_block <= current_block <= authorization.expires_at_block:
        raise ValueError("direct transition authorization is not active at this block")
    if not verify_response_signature(
        direct_transition_authorization_digest(authorization),
        hotkey_ss58=authorization.coordinator_hotkey,
        scheme=authorization.signature_scheme,
        signature=authorization.signature,
    ):
        raise ValueError("direct transition authorization signature is invalid")
    return authorization


def _validate_direct_authorization_bounds(
    signed: SignedBootstrapEligibilityManifest,
    authorization: DirectBootstrapTransitionAuthorization,
) -> None:
    manifest = signed.manifest
    policy = manifest.policy
    if not hmac.compare_digest(authorization.manifest_sha256, signed.manifest_sha256):
        raise ValueError("direct transition authorization binds another manifest")
    if not hmac.compare_digest(authorization.original_policy_sha256, manifest.policy_sha256):
        raise ValueError("direct transition authorization binds another original policy")
    if (
        authorization.original_commit_stop_block != policy.commit_stop_block
        or authorization.original_hard_sunset_block != policy.hard_sunset_block
    ):
        raise ValueError("direct transition authorization policy interval is invalid")
    if account_id32(authorization.coordinator_hotkey) != account_id32(policy.coordinator_hotkey):
        raise ValueError("direct transition authorization signer is not the coordinator")
    if any(
        entry.uid == authorization.validator_uid
        or account_id32(entry.miner_hotkey) == account_id32(authorization.validator_hotkey)
        for entry in manifest.entries
    ):
        raise ValueError("direct transition validator is also an eligible miner")
    if authorization.weights_version_key <= policy.weights_version_key:
        raise ValueError("direct transition version key does not supersede the original policy")
    if not (manifest.frozen_at_block <= authorization.signed_at_block < policy.hard_sunset_block):
        raise ValueError("direct transition authorization starts outside the hard sunset")
    if not (
        authorization.valid_from_block <= authorization.expires_at_block < policy.hard_sunset_block
    ):
        raise ValueError("direct transition authorization exceeds the hard sunset")


def verify_direct_runtime_checkout(
    authorization: DirectBootstrapTransitionAuthorization,
    *,
    repository: Path | None = None,
    image_revision_path: Path = Path("/opt/umi-image-revision"),
) -> None:
    """Fail closed unless code identity matches the transition authorization."""

    if not isinstance(authorization, DirectBootstrapTransitionAuthorization):
        raise TypeError("authorization must be a DirectBootstrapTransitionAuthorization")
    root = (repository or Path.cwd()).resolve()
    try:
        top = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=root,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        revision = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=top,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout.strip()
        dirty = subprocess.run(
            ["git", "status", "--porcelain", "--untracked-files=all"],
            cwd=top,
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        marker = image_revision_path
        try:
            marker_stat = marker.stat()
            marker_bytes = marker.read_bytes()
        except OSError as error:
            raise BootstrapOperatorError("direct_runtime_checkout_unverifiable") from error
        expected_owner = 0 if marker == Path("/opt/umi-image-revision") else os.getuid()
        if (
            not stat.S_ISREG(marker_stat.st_mode)
            or marker_stat.st_uid != expected_owner
            or marker_stat.st_mode & 0o222
            or len(marker_bytes) != 41
            or not marker_bytes.endswith(b"\n")
        ):
            raise BootstrapOperatorError("direct_image_revision_marker_invalid") from None
        try:
            revision = marker_bytes[:-1].decode("ascii")
        except UnicodeDecodeError as error:
            raise BootstrapOperatorError("direct_image_revision_marker_invalid") from error
        if _GIT_REVISION_RE.fullmatch(revision) is None:
            raise BootstrapOperatorError("direct_image_revision_marker_invalid") from None
        dirty = ""
    if revision != authorization.umi_git_revision:
        raise BootstrapOperatorError("direct_runtime_revision_mismatch")
    if dirty:
        raise BootstrapOperatorError("direct_runtime_checkout_dirty")


class OwnerFencePreflight(StrictProtocolModel):
    """One coherent finalized observation before the atomic owner fence."""

    schema_: Literal[OWNER_FENCE_PREFLIGHT_SCHEMA] = Field(alias="schema")
    network: Literal["finney"]
    netuid: Literal[78]
    block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_hash: BlockHash
    subnet_owner_coldkey_account_id32: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    subnet_owner_hotkey_account_id32: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    mechanism_count: Literal[1]
    max_allowed_uids: Literal[256]
    subnetwork_n: Literal[256]
    pending_commit_count: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    tempo: Annotated[int, Field(gt=0, le=U16_MAX)]
    last_epoch_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    pending_epoch_at: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    admin_freeze_window: Annotated[int, Field(ge=0, le=U16_MAX)]
    blocks_until_next_auto_epoch: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    admin_submission_window_has_era_headroom: bool
    weights_version_key_rate_limit_tempos: Annotated[int, Field(ge=0)]
    weights_version_key_rate_limit_blocks: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    weights_version_key_last_update_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    weights_version_key_rate_limit_ready: bool
    owner_hyperparam_rate_limit_tempos: Annotated[int, Field(ge=0, le=U16_MAX)]
    owner_hyperparam_rate_limit_blocks: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    min_allowed_weights_last_update_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    commit_reveal_enabled_last_update_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    owner_hyperparam_rate_limits_ready: bool
    current_weights_version_key: Annotated[int, Field(ge=0)]
    current_min_allowed_weights: Annotated[int, Field(ge=0, le=U16_MAX)]
    current_commit_reveal_enabled: bool
    target_weights_version_key: Literal[DIRECT_MINIMUM_WEIGHTS_VERSION_KEY]
    target_min_allowed_weights: Literal[256]
    target_commit_reveal_enabled: Literal[False]
    target_state_classification: Literal["requires_submission", "already_applied"]
    sdk_finalized_reads_verified: Literal[True]
    storage_proofs_verified: Literal[False] = False

    @model_validator(mode="after")
    def validate_timing_gates(self) -> Self:
        if self.weights_version_key_rate_limit_blocks != (
            self.tempo * self.weights_version_key_rate_limit_tempos
        ):
            raise ValueError("owner fence WVK rate-limit arithmetic is invalid")
        if self.owner_hyperparam_rate_limit_blocks != (
            self.tempo * self.owner_hyperparam_rate_limit_tempos
        ):
            raise ValueError("owner fence hyperparameter rate-limit arithmetic is invalid")
        if self.target_state_classification == "requires_submission" and not all(
            (
                self.admin_submission_window_has_era_headroom,
                self.weights_version_key_rate_limit_ready,
                self.owner_hyperparam_rate_limits_ready,
            )
        ):
            raise ValueError("owner fence requires an open, rate-limit-ready submission window")
        current = (
            self.current_weights_version_key,
            self.current_min_allowed_weights,
            self.current_commit_reveal_enabled,
        )
        expected = (
            DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
            DIRECT_FULL_ROW_SIZE,
            False,
        )
        if self.target_state_classification == "already_applied":
            if current != expected:
                raise ValueError("owner fence already-applied classification is inconsistent")
        elif current != (1, 1, True):
            raise ValueError("owner fence starting state is not the expected legacy tuple")
        return self


class OwnerFenceCallMaterial(StrictProtocolModel):
    """Exact ordered inner calls and raw atomic outer call identity."""

    schema_: Literal[OWNER_FENCE_CALL_MATERIAL_SCHEMA] = Field(alias="schema")
    preflight_sha256: Hex32
    preflight: OwnerFencePreflight
    call_module: Literal["Utility"]
    call_function: Literal["batch_all"]
    ordered_inner_calls: Literal[
        [
            "AdminUtils.sudo_set_weights_version_key",
            "AdminUtils.sudo_set_min_allowed_weights",
            "AdminUtils.sudo_set_commit_reveal_weights_enabled",
        ]
    ]
    target_weights_version_key: Literal[DIRECT_MINIMUM_WEIGHTS_VERSION_KEY]
    target_min_allowed_weights: Literal[256]
    target_commit_reveal_enabled: Literal[False]

    @model_validator(mode="after")
    def validate_preflight_hash(self) -> Self:
        if hashlib.sha256(canonical_json_bytes(self.preflight)).hexdigest() != (
            self.preflight_sha256
        ):
            raise ValueError("owner fence preflight hash is invalid")
        return self


class OwnerFenceReceipt(StrictProtocolModel):
    """Finalized success plus exact post-batch storage verification."""

    schema_: Literal[OWNER_FENCE_RECEIPT_SCHEMA] = Field(alias="schema")
    classification: Literal["applied", "already_applied"]
    call_material_sha256: Hex32
    call_material: OwnerFenceCallMaterial
    extrinsic: BootstrapExtrinsicReference | None = None
    observation_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    observation_block_hash: BlockHash
    observed_weights_version_key: Literal[DIRECT_MINIMUM_WEIGHTS_VERSION_KEY]
    observed_min_allowed_weights: Literal[256]
    observed_commit_reveal_enabled: Literal[False]
    source_snapshot_pending_commit_count: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    observed_pending_commit_count: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    batch_all_finalized_success: bool
    all_storage_targets_verified: Literal[True]
    sdk_finalized_reads_verified: Literal[True]
    storage_proofs_verified: Literal[False] = False
    created_at: datetime

    @model_validator(mode="after")
    def validate_material_hash(self) -> Self:
        if hashlib.sha256(canonical_json_bytes(self.call_material)).hexdigest() != (
            self.call_material_sha256
        ):
            raise ValueError("owner fence call material hash is invalid")
        preflight = self.call_material.preflight
        if self.source_snapshot_pending_commit_count != preflight.pending_commit_count:
            raise ValueError("owner fence source pending count does not match its preflight")
        if self.extrinsic is not None and self.observation_block < self.extrinsic.block_number:
            raise ValueError("owner fence observation predates inclusion")
        if self.classification == "applied":
            if self.extrinsic is None or self.batch_all_finalized_success is not True:
                raise ValueError("applied owner fence lacks a finalized batch")
            if preflight.target_state_classification != "requires_submission":
                raise ValueError("applied owner fence does not start from a submission preflight")
            if preflight.block_number >= self.extrinsic.block_number:
                raise ValueError("owner fence submission does not follow its source snapshot")
            if (
                self.observation_block == self.extrinsic.block_number
                and self.observation_block_hash != self.extrinsic.block_hash
            ):
                raise ValueError("owner fence inclusion observation block hash is inconsistent")
        elif self.extrinsic is not None or self.batch_all_finalized_success:
            raise ValueError("already-applied owner fence claims a submitted batch")
        else:
            if preflight.target_state_classification != "already_applied":
                raise ValueError("already-applied owner fence lacks a fenced-state preflight")
            if (
                self.observation_block != preflight.block_number
                or self.observation_block_hash != preflight.block_hash
            ):
                raise ValueError("already-applied owner fence observation is not its preflight")
            if (
                self.observed_weights_version_key,
                self.observed_min_allowed_weights,
                self.observed_commit_reveal_enabled,
            ) != (
                preflight.current_weights_version_key,
                preflight.current_min_allowed_weights,
                preflight.current_commit_reveal_enabled,
            ):
                raise ValueError("already-applied owner fence tuple is not its preflight")
            if self.observed_pending_commit_count != preflight.pending_commit_count:
                raise ValueError("already-applied owner fence pending count is not its preflight")
        return self


class OwnerFenceJournal(StrictProtocolModel):
    """Durable owner-coldkey high-water record; any existing file blocks retry."""

    schema_: Literal[OWNER_FENCE_JOURNAL_SCHEMA] = Field(alias="schema")
    phase: Literal[
        "claimed",
        "material_written",
        "submission_finalized",
        "applied",
        "already_applied",
    ]
    owner_coldkey_account_id32: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    call_material_sha256: Hex32 | None = None
    extrinsic: BootstrapExtrinsicReference | None = None
    receipt_sha256: Hex32 | None = None
    updated_at: datetime

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        rank = {
            "claimed": 0,
            "material_written": 1,
            "submission_finalized": 2,
            "applied": 3,
            "already_applied": 3,
        }[self.phase]
        if (self.call_material_sha256 is not None) != (rank >= 1):
            raise ValueError("owner fence journal material does not match its phase")
        if self.phase == "already_applied":
            if self.extrinsic is not None:
                raise ValueError("already-applied owner fence journal has an extrinsic")
        elif (self.extrinsic is not None) != (rank >= 2):
            raise ValueError("owner fence journal extrinsic does not match its phase")
        if (self.receipt_sha256 is not None) != (rank >= 3):
            raise ValueError("owner fence journal receipt does not match its phase")
        return self


def _owner_fence_state_paths(state_dir: Path, owner_account: bytes) -> tuple[Path, Path]:
    stem = f"owner-fence-{NETUID}-{DIRECT_MINIMUM_WEIGHTS_VERSION_KEY}-{owner_account.hex()}"
    return state_dir / f".{stem}.lock", state_dir / f"{stem}.json"


def _validate_owner_fence_paths(
    *,
    receipt_output: Path,
    call_material_output: Path,
    state_dir: Path,
    lock_path: Path,
    journal_path: Path,
) -> None:
    """Reject output layouts that can turn reserved state files into directories."""

    receipt = receipt_output.resolve()
    material = call_material_output.resolve()
    state = state_dir.resolve()
    lock = lock_path.resolve()
    journal = journal_path.resolve()

    if (
        len({receipt, material, state, lock, journal}) != 5
        or receipt in material.parents
        or material in receipt.parents
        or receipt in state.parents
        or material in state.parents
        or lock in receipt.parents
        or journal in receipt.parents
        or lock in material.parents
        or journal in material.parents
    ):
        raise BootstrapOperatorError("owner_fence_output_state_paths_overlap")


def build_owner_fence_call(
    preflight: OwnerFencePreflight,
) -> tuple[OwnerFenceCallMaterial, Any]:
    """Build one all-or-nothing owner call in the required guard order."""

    if not isinstance(preflight, OwnerFencePreflight):
        raise TypeError("preflight must be an OwnerFencePreflight")
    inner = [
        bt.calls.AdminUtils.sudo_set_weights_version_key(
            netuid=NETUID,
            weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        ),
        bt.calls.AdminUtils.sudo_set_min_allowed_weights(
            netuid=NETUID,
            min_allowed_weights=DIRECT_FULL_ROW_SIZE,
        ),
        bt.calls.AdminUtils.sudo_set_commit_reveal_weights_enabled(
            netuid=NETUID,
            enabled=False,
        ),
    ]
    expected = [
        (
            "AdminUtils",
            "sudo_set_weights_version_key",
            {"netuid": NETUID, "weights_version_key": DIRECT_MINIMUM_WEIGHTS_VERSION_KEY},
        ),
        (
            "AdminUtils",
            "sudo_set_min_allowed_weights",
            {"netuid": NETUID, "min_allowed_weights": DIRECT_FULL_ROW_SIZE},
        ),
        (
            "AdminUtils",
            "sudo_set_commit_reveal_weights_enabled",
            {"netuid": NETUID, "enabled": False},
        ),
    ]
    for call, (module, function, params) in zip(inner, expected, strict=True):
        if call.module != module or call.function != function or call.params != params:
            raise BootstrapOperatorError("owner_fence_inner_call_mismatch")
    outer = bt.calls.Utility.batch_all(calls=inner)
    if (
        outer.module != "Utility"
        or outer.function != "batch_all"
        or outer.params.get("calls") != inner
        or len(outer.params["calls"]) != 3
    ):
        raise BootstrapOperatorError("owner_fence_outer_call_mismatch")
    material = OwnerFenceCallMaterial(
        schema=OWNER_FENCE_CALL_MATERIAL_SCHEMA,
        preflight_sha256=hashlib.sha256(canonical_json_bytes(preflight)).hexdigest(),
        preflight=preflight,
        call_module="Utility",
        call_function="batch_all",
        ordered_inner_calls=[
            "AdminUtils.sudo_set_weights_version_key",
            "AdminUtils.sudo_set_min_allowed_weights",
            "AdminUtils.sudo_set_commit_reveal_weights_enabled",
        ],
        target_weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        target_min_allowed_weights=DIRECT_FULL_ROW_SIZE,
        target_commit_reveal_enabled=False,
    )
    return material, outer


async def collect_owner_fence_preflight_with_client(
    client: Any,
    *,
    expected_owner_coldkey: str,
    finalized_timeout_seconds: float = 20.0,
) -> OwnerFencePreflight:
    """Read all owner-fence inputs from one finalized Finney block."""

    if not 0 < finalized_timeout_seconds <= 300:
        raise ValueError("finalized timeout must be in (0, 300] seconds")
    try:
        expected_owner = account_id32(expected_owner_coldkey)
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("owner_fence_expected_coldkey_invalid") from error
    substrate = getattr(client, "_substrate", None)
    block_hash_reader = getattr(substrate, "block_hash", None)
    if not callable(block_hash_reader):
        raise BootstrapOperatorError("chain_identity_reader_missing")
    if await block_hash_reader(0) != _FINNEY_GENESIS_HASH:
        raise BootstrapOperatorError("chain_is_not_finney")
    header = await _first_finalized_header(client, finalized_timeout_seconds)
    block_number = _uint(
        getattr(header, "number", None),
        "owner_fence_finalized_block_invalid",
        minimum=1,
    )
    pinned = await client.at(block_number)
    if _uint(getattr(pinned, "block", None), "owner_fence_snapshot_block_invalid") != (
        block_number
    ):
        raise BootstrapOperatorError("owner_fence_snapshot_block_mismatch")
    direct = storage.SubtensorModule
    (
        block_info,
        owner_coldkey,
        owner_hotkey,
        mechanism_count,
        max_allowed_uids,
        subnetwork_n,
        weights_version_key,
        min_allowed_weights,
        commit_reveal_enabled,
        pending_commits,
        tempo,
        last_epoch_block,
        pending_epoch_at,
        admin_freeze_window,
        weights_version_key_rate_limit,
        weights_version_key_last_update,
        owner_hyperparam_rate_limit,
        min_allowed_weights_last_update,
        commit_reveal_last_update,
    ) = await asyncio.gather(
        pinned.block_info(),
        pinned.query(direct.SubnetOwner, [NETUID]),
        pinned.query(direct.SubnetOwnerHotkey, [NETUID]),
        pinned.query(direct.MechanismCountCurrent, [NETUID]),
        pinned.query(direct.MaxAllowedUids, [NETUID]),
        pinned.query(direct.SubnetworkN, [NETUID]),
        pinned.query(direct.WeightsVersionKey, [NETUID]),
        pinned.query(direct.MinAllowedWeights, [NETUID]),
        pinned.query(direct.CommitRevealWeightsEnabled, [NETUID]),
        pinned.read("timelocked_weight_commits", netuid=NETUID, mechid=MECHANISM_ID),
        pinned.query(direct.Tempo, [NETUID]),
        pinned.query(direct.LastEpochBlock, [NETUID]),
        pinned.query(direct.PendingEpochAt, [NETUID]),
        pinned.query(direct.AdminFreezeWindow),
        pinned.query(direct.WeightsVersionKeyRateLimit),
        pinned.query(
            direct.TransactionKeyLastBlock,
            [expected_owner_coldkey, NETUID, 4],
        ),
        pinned.query(direct.OwnerHyperparamRateLimit),
        pinned.query(
            direct.LastRateLimitedBlock,
            [{"OwnerHyperparamUpdate": [NETUID, {"MinAllowedWeights": None}]}],
        ),
        pinned.query(
            direct.LastRateLimitedBlock,
            [{"OwnerHyperparamUpdate": [NETUID, {"CommitRevealEnabled": None}]}],
        ),
    )
    block_hash, _ = _validate_finalized_block(header, block_info, block_number)
    try:
        observed_owner = _account_bytes(owner_coldkey)
        observed_owner_hotkey = _account_bytes(owner_hotkey)
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("owner_fence_owner_mapping_invalid") from error
    if observed_owner != expected_owner:
        raise BootstrapOperatorError("owner_fence_signer_is_not_subnet_owner_coldkey")
    mechanism_count_value = _uint(
        mechanism_count,
        "owner_fence_mechanism_count_invalid",
        maximum=U16_MAX,
    )
    if mechanism_count_value != 1:
        raise BootstrapOperatorError("owner_fence_mechanism_count_mismatch")
    max_allowed_uids_value = _uint(
        max_allowed_uids,
        "owner_fence_max_allowed_uids_invalid",
        minimum=1,
        maximum=U16_MAX,
    )
    if max_allowed_uids_value != DIRECT_FULL_ROW_SIZE:
        raise BootstrapOperatorError("owner_fence_max_allowed_uids_mismatch")
    subnetwork_n_value = _uint(
        subnetwork_n,
        "owner_fence_subnetwork_n_invalid",
        minimum=1,
        maximum=U16_MAX,
    )
    if subnetwork_n_value != DIRECT_FULL_ROW_SIZE:
        raise BootstrapOperatorError("owner_fence_subnetwork_n_mismatch")
    pending_count, _ = _pending_commit_summary(
        pending_commits,
        validator_hotkey=observed_owner_hotkey,
    )
    current_wvk = _uint(weights_version_key, "owner_fence_weights_version_key_invalid")
    current_min = _uint(
        min_allowed_weights,
        "owner_fence_min_allowed_weights_invalid",
        maximum=U16_MAX,
    )
    current_cr = _bool(commit_reveal_enabled, "owner_fence_commit_reveal_invalid")
    tempo_value = _uint(tempo, "owner_fence_tempo_invalid", minimum=1, maximum=U16_MAX)
    last_epoch_value = _uint(last_epoch_block, "owner_fence_last_epoch_block_invalid")
    pending_epoch_value = _uint(pending_epoch_at or 0, "owner_fence_pending_epoch_invalid")
    freeze_window_value = _uint(
        admin_freeze_window,
        "owner_fence_admin_freeze_window_invalid",
        maximum=U16_MAX,
    )
    blocks_until_epoch = max(0, last_epoch_value + tempo_value - block_number)
    admin_headroom = (
        not (pending_epoch_value > block_number)
        and blocks_until_epoch >= freeze_window_value + _SUBMISSION_ERA_PERIOD
    )
    wvk_rate_tempos = _uint(
        weights_version_key_rate_limit,
        "owner_fence_wvk_rate_limit_invalid",
    )
    wvk_rate_blocks = tempo_value * wvk_rate_tempos
    if wvk_rate_blocks > _MAX_JSON_SAFE_INTEGER:
        raise BootstrapOperatorError("owner_fence_wvk_rate_limit_overflow")
    wvk_last = _uint(
        weights_version_key_last_update,
        "owner_fence_wvk_last_update_invalid",
    )
    if wvk_last > block_number:
        raise BootstrapOperatorError("owner_fence_wvk_last_update_in_future")
    wvk_ready = wvk_last == 0 or block_number - wvk_last >= wvk_rate_blocks
    owner_rate_tempos = _uint(
        owner_hyperparam_rate_limit,
        "owner_fence_owner_rate_limit_invalid",
        maximum=U16_MAX,
    )
    owner_rate_blocks = tempo_value * owner_rate_tempos
    min_last = _uint(
        min_allowed_weights_last_update,
        "owner_fence_min_allowed_weights_last_update_invalid",
    )
    cr_last = _uint(
        commit_reveal_last_update,
        "owner_fence_commit_reveal_last_update_invalid",
    )
    if min_last > block_number or cr_last > block_number:
        raise BootstrapOperatorError("owner_fence_owner_last_update_in_future")
    owner_rates_ready = all(
        last == 0 or block_number - last >= owner_rate_blocks for last in (min_last, cr_last)
    )
    already_applied = (
        current_wvk == DIRECT_MINIMUM_WEIGHTS_VERSION_KEY
        and current_min == DIRECT_FULL_ROW_SIZE
        and current_cr is False
    )
    if not already_applied:
        if (current_wvk, current_min, current_cr) != (1, 1, True):
            raise BootstrapOperatorError("owner_fence_starting_state_mismatch")
        if not admin_headroom:
            raise BootstrapOperatorError("owner_fence_admin_freeze_window_or_headroom")
        if not wvk_ready:
            raise BootstrapOperatorError("owner_fence_wvk_rate_limit_not_elapsed")
        if not owner_rates_ready:
            raise BootstrapOperatorError("owner_fence_owner_rate_limit_not_elapsed")
    return OwnerFencePreflight(
        schema=OWNER_FENCE_PREFLIGHT_SCHEMA,
        network="finney",
        netuid=NETUID,
        block_number=block_number,
        block_hash=block_hash,
        subnet_owner_coldkey_account_id32="0x" + observed_owner.hex(),
        subnet_owner_hotkey_account_id32="0x" + observed_owner_hotkey.hex(),
        mechanism_count=mechanism_count_value,
        max_allowed_uids=max_allowed_uids_value,
        subnetwork_n=subnetwork_n_value,
        pending_commit_count=pending_count,
        tempo=tempo_value,
        last_epoch_block=last_epoch_value,
        pending_epoch_at=pending_epoch_value,
        admin_freeze_window=freeze_window_value,
        blocks_until_next_auto_epoch=blocks_until_epoch,
        admin_submission_window_has_era_headroom=admin_headroom,
        weights_version_key_rate_limit_tempos=wvk_rate_tempos,
        weights_version_key_rate_limit_blocks=wvk_rate_blocks,
        weights_version_key_last_update_block=wvk_last,
        weights_version_key_rate_limit_ready=wvk_ready,
        owner_hyperparam_rate_limit_tempos=owner_rate_tempos,
        owner_hyperparam_rate_limit_blocks=owner_rate_blocks,
        min_allowed_weights_last_update_block=min_last,
        commit_reveal_enabled_last_update_block=cr_last,
        owner_hyperparam_rate_limits_ready=owner_rates_ready,
        current_weights_version_key=current_wvk,
        current_min_allowed_weights=current_min,
        current_commit_reveal_enabled=current_cr,
        target_weights_version_key=DIRECT_MINIMUM_WEIGHTS_VERSION_KEY,
        target_min_allowed_weights=DIRECT_FULL_ROW_SIZE,
        target_commit_reveal_enabled=False,
        target_state_classification=(
            "already_applied" if already_applied else "requires_submission"
        ),
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
    )


async def collect_owner_fence_preflight(
    *,
    expected_owner_coldkey: str,
    client_factory: Callable[[str], Any] | None = None,
    finalized_timeout_seconds: float = 20.0,
) -> OwnerFencePreflight:
    factory = client_factory or (lambda network: bt.Client(network))
    async with factory("finney") as client:
        return await collect_owner_fence_preflight_with_client(
            client,
            expected_owner_coldkey=expected_owner_coldkey,
            finalized_timeout_seconds=finalized_timeout_seconds,
        )


async def attest_owner_fence(
    *,
    expected_owner_coldkey: str,
    receipt_output: Path,
    call_material_output: Path,
    state_dir: Path,
    client_factory: Callable[[str], Any] | None = None,
    finalized_timeout_seconds: float = 20.0,
    clock: Callable[[], datetime] | None = None,
) -> OwnerFenceReceipt:
    """Record finalized fenced state after a separately submitted stock btcli batch.

    This command is read-only with respect to the chain.  It records no external
    extrinsic claim because the finalized storage tuple alone cannot establish
    which transaction applied it.
    """

    if receipt_output.exists() or call_material_output.exists():
        raise BootstrapOperatorError("owner_fence_attestation_output_exists")
    try:
        owner_account = account_id32(expected_owner_coldkey)
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("owner_fence_expected_coldkey_invalid") from error
    lock_path, journal_path = _owner_fence_state_paths(state_dir, owner_account)
    _validate_owner_fence_paths(
        receipt_output=receipt_output,
        call_material_output=call_material_output,
        state_dir=state_dir,
        lock_path=lock_path,
        journal_path=journal_path,
    )
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if journal_path.exists():
        raise BootstrapOperatorError("owner_fence_claim_exists_reconcile_required")
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise BootstrapOperatorError("owner_fence_attestation_already_in_progress") from error
    now = clock or (lambda: datetime.now(timezone.utc))
    factory = client_factory or (lambda network: bt.Client(network))
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        async with factory("finney") as client:
            preflight = await collect_owner_fence_preflight_with_client(
                client,
                expected_owner_coldkey=expected_owner_coldkey,
                finalized_timeout_seconds=finalized_timeout_seconds,
            )
        if preflight.target_state_classification != "already_applied":
            raise BootstrapOperatorError("owner_fence_external_batch_not_applied")
        material, _ = build_owner_fence_call(preflight)
        claimed = OwnerFenceJournal(
            schema=OWNER_FENCE_JOURNAL_SCHEMA,
            phase="claimed",
            owner_coldkey_account_id32="0x" + owner_account.hex(),
            updated_at=now(),
        )
        _write_new_canonical(journal_path, claimed, maximum_bytes=_MAX_RECEIPT_BYTES)
        _write_new_canonical(
            call_material_output,
            material,
            maximum_bytes=_MAX_INPUT_BYTES,
        )
        material_hash = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
        material_written = OwnerFenceJournal(
            schema=OWNER_FENCE_JOURNAL_SCHEMA,
            phase="material_written",
            owner_coldkey_account_id32="0x" + owner_account.hex(),
            call_material_sha256=material_hash,
            updated_at=now(),
        )
        _replace_canonical(
            journal_path,
            material_written,
            maximum_bytes=_MAX_RECEIPT_BYTES,
        )
        receipt = OwnerFenceReceipt(
            schema=OWNER_FENCE_RECEIPT_SCHEMA,
            classification="already_applied",
            call_material_sha256=material_hash,
            call_material=material,
            extrinsic=None,
            observation_block=preflight.block_number,
            observation_block_hash=preflight.block_hash,
            observed_weights_version_key=preflight.current_weights_version_key,
            observed_min_allowed_weights=preflight.current_min_allowed_weights,
            observed_commit_reveal_enabled=preflight.current_commit_reveal_enabled,
            source_snapshot_pending_commit_count=preflight.pending_commit_count,
            observed_pending_commit_count=preflight.pending_commit_count,
            batch_all_finalized_success=False,
            all_storage_targets_verified=True,
            sdk_finalized_reads_verified=True,
            storage_proofs_verified=False,
            created_at=now(),
        )
        _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
        receipt_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
        terminal = OwnerFenceJournal(
            schema=OWNER_FENCE_JOURNAL_SCHEMA,
            phase="already_applied",
            owner_coldkey_account_id32="0x" + owner_account.hex(),
            call_material_sha256=material_hash,
            receipt_sha256=receipt_hash,
            updated_at=now(),
        )
        _replace_canonical(journal_path, terminal, maximum_bytes=_MAX_RECEIPT_BYTES)
        return receipt
    finally:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            lock_path.unlink()


async def submit_owner_fence(
    *,
    wallet: Any,
    receipt_output: Path,
    call_material_output: Path,
    state_dir: Path,
    live_submit: bool,
    acknowledgement: str,
    client_factory: Callable[[str], Any] | None = None,
    finalized_timeout_seconds: float = 20.0,
    clock: Callable[[], datetime] | None = None,
) -> OwnerFenceReceipt:
    """Apply the atomic owner fence once, or attest its exact existing state."""

    if live_submit is not True or acknowledgement != OWNER_FENCE_LIVE_SUBMIT_ACKNOWLEDGEMENT:
        raise BootstrapOperatorError("owner_fence_live_submit_acknowledgement_missing")
    if receipt_output.exists() or call_material_output.exists():
        raise BootstrapOperatorError("owner_fence_submission_output_exists")
    signer = bt.resolve_signer(wallet, role="coldkey")
    owner_coldkey = signer.ss58_address
    owner_account = account_id32(owner_coldkey)
    lock_path, journal_path = _owner_fence_state_paths(state_dir, owner_account)
    _validate_owner_fence_paths(
        receipt_output=receipt_output,
        call_material_output=call_material_output,
        state_dir=state_dir,
        lock_path=lock_path,
        journal_path=journal_path,
    )
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    if journal_path.exists():
        raise BootstrapOperatorError("owner_fence_claim_exists_reconcile_required")
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise BootstrapOperatorError("owner_fence_submission_already_in_progress") from error
    now = clock or (lambda: datetime.now(timezone.utc))
    factory = client_factory or (lambda network: bt.Client(network))
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        async with factory("finney") as client:
            preflight = await collect_owner_fence_preflight_with_client(
                client,
                expected_owner_coldkey=owner_coldkey,
                finalized_timeout_seconds=finalized_timeout_seconds,
            )
            material, raw_call = build_owner_fence_call(preflight)
            claimed = OwnerFenceJournal(
                schema=OWNER_FENCE_JOURNAL_SCHEMA,
                phase="claimed",
                owner_coldkey_account_id32="0x" + owner_account.hex(),
                updated_at=now(),
            )
            _write_new_canonical(journal_path, claimed, maximum_bytes=_MAX_RECEIPT_BYTES)
            _write_new_canonical(
                call_material_output,
                material,
                maximum_bytes=_MAX_INPUT_BYTES,
            )
            material_hash = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
            journal = OwnerFenceJournal(
                schema=OWNER_FENCE_JOURNAL_SCHEMA,
                phase="material_written",
                owner_coldkey_account_id32="0x" + owner_account.hex(),
                call_material_sha256=material_hash,
                updated_at=now(),
            )
            _replace_canonical(journal_path, journal, maximum_bytes=_MAX_RECEIPT_BYTES)

            if preflight.target_state_classification == "already_applied":
                receipt = OwnerFenceReceipt(
                    schema=OWNER_FENCE_RECEIPT_SCHEMA,
                    classification="already_applied",
                    call_material_sha256=material_hash,
                    call_material=material,
                    extrinsic=None,
                    observation_block=preflight.block_number,
                    observation_block_hash=preflight.block_hash,
                    observed_weights_version_key=preflight.current_weights_version_key,
                    observed_min_allowed_weights=preflight.current_min_allowed_weights,
                    observed_commit_reveal_enabled=preflight.current_commit_reveal_enabled,
                    source_snapshot_pending_commit_count=preflight.pending_commit_count,
                    observed_pending_commit_count=preflight.pending_commit_count,
                    batch_all_finalized_success=False,
                    all_storage_targets_verified=True,
                    sdk_finalized_reads_verified=True,
                    storage_proofs_verified=False,
                    created_at=now(),
                )
                _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
                receipt_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
                terminal = OwnerFenceJournal(
                    schema=OWNER_FENCE_JOURNAL_SCHEMA,
                    phase="already_applied",
                    owner_coldkey_account_id32="0x" + owner_account.hex(),
                    call_material_sha256=material_hash,
                    receipt_sha256=receipt_hash,
                    updated_at=now(),
                )
                _replace_canonical(journal_path, terminal, maximum_bytes=_MAX_RECEIPT_BYTES)
                return receipt

            result = await client.submit_call(
                raw_call,
                wallet,
                signer="coldkey",
                period=_SUBMISSION_ERA_PERIOD,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
            extrinsic = _successful_extrinsic(result, reason="owner_fence_batch_all_failed")
            submitted = OwnerFenceJournal(
                schema=OWNER_FENCE_JOURNAL_SCHEMA,
                phase="submission_finalized",
                owner_coldkey_account_id32="0x" + owner_account.hex(),
                call_material_sha256=material_hash,
                extrinsic=extrinsic,
                updated_at=now(),
            )
            _replace_canonical(journal_path, submitted, maximum_bytes=_MAX_RECEIPT_BYTES)
            observation = await collect_owner_fence_preflight_with_client(
                client,
                expected_owner_coldkey=owner_coldkey,
                finalized_timeout_seconds=finalized_timeout_seconds,
            )
            if observation.block_number < extrinsic.block_number:
                raise BootstrapOperatorError("owner_fence_observation_precedes_inclusion")
            if observation.target_state_classification != "already_applied":
                raise BootstrapOperatorError("owner_fence_storage_targets_not_applied")
            receipt = OwnerFenceReceipt(
                schema=OWNER_FENCE_RECEIPT_SCHEMA,
                classification="applied",
                call_material_sha256=material_hash,
                call_material=material,
                extrinsic=extrinsic,
                observation_block=observation.block_number,
                observation_block_hash=observation.block_hash,
                observed_weights_version_key=observation.current_weights_version_key,
                observed_min_allowed_weights=observation.current_min_allowed_weights,
                observed_commit_reveal_enabled=observation.current_commit_reveal_enabled,
                source_snapshot_pending_commit_count=preflight.pending_commit_count,
                observed_pending_commit_count=observation.pending_commit_count,
                batch_all_finalized_success=True,
                all_storage_targets_verified=True,
                sdk_finalized_reads_verified=True,
                storage_proofs_verified=False,
                created_at=now(),
            )
            _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
            receipt_hash = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
            terminal = OwnerFenceJournal(
                schema=OWNER_FENCE_JOURNAL_SCHEMA,
                phase="applied",
                owner_coldkey_account_id32="0x" + owner_account.hex(),
                call_material_sha256=material_hash,
                extrinsic=extrinsic,
                receipt_sha256=receipt_hash,
                updated_at=now(),
            )
            _replace_canonical(journal_path, terminal, maximum_bytes=_MAX_RECEIPT_BYTES)
            return receipt
    finally:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            lock_path.unlink()


class DirectBootstrapPreflight(StrictProtocolModel):
    """One finalized validator, mapping, runtime-gate, and exact-row observation."""

    schema_: Literal[DIRECT_PREFLIGHT_SCHEMA] = Field(alias="schema")
    transition_profile: Literal[DIRECT_TRANSITION_PROFILE]
    manifest_sha256: Hex32
    policy_sha256: Hex32
    transition_authorization: DirectBootstrapTransitionAuthorization
    transition_authorization_sha256: Hex32
    snapshot: BootstrapChainSnapshot
    subnet_owner_hotkey_account_id32: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=255)]
    prior_row_classification: Literal["empty", "inactive", "active_exact_direct_row"]
    eligible_miner_count: Annotated[int, Field(gt=0, le=255)]
    full_row_uids: Annotated[list[int], Field(min_length=256, max_length=256)]
    full_row_weights: Annotated[list[int], Field(min_length=256, max_length=256)]
    expected_applied_row: Annotated[list[list[int]], Field(min_length=256, max_length=256)]

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        expected_uids, _ = _direct_full_row(self.snapshot, self.validator_hotkey, ())
        # The empty-entry call above checks only the full UID domain.  Manifest
        # membership is checked against the material embedded in this model.
        if self.full_row_uids != expected_uids:
            raise ValueError("direct bootstrap destinations are not exactly 0 through 255")
        if len(self.full_row_weights) != DIRECT_FULL_ROW_SIZE or any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= U16_MAX
            for value in self.full_row_weights
        ):
            raise ValueError("direct bootstrap weights are not a 256-entry u16 row")
        if self.expected_applied_row != [
            [uid, weight]
            for uid, weight in zip(self.full_row_uids, self.full_row_weights, strict=True)
        ]:
            raise ValueError("direct bootstrap expected row differs from its raw input row")
        if sum(value > 0 for value in self.full_row_weights) != self.eligible_miner_count:
            raise ValueError("direct bootstrap positive count differs from eligibility count")
        if any(value not in {0, U16_MAX} for value in self.full_row_weights):
            raise ValueError("direct bootstrap row contains a non-binary weight")
        owner = bytes.fromhex(self.subnet_owner_hotkey_account_id32[2:])
        owner_participant = next(
            (item for item in self.snapshot.participants if account_id32(item.hotkey) == owner),
            None,
        )
        if owner_participant is None or owner_participant.uid != 0:
            raise ValueError("direct bootstrap subnet owner is not registered at UID 0")
        validator = next(
            (
                item
                for item in self.snapshot.participants
                if account_id32(item.hotkey) == account_id32(self.validator_hotkey)
            ),
            None,
        )
        if (
            validator is None
            or validator.uid != self.validator_uid
            or not validator.validator_permit
        ):
            raise ValueError("direct bootstrap signer mapping or validator permit is invalid")
        authorization_bytes = canonical_json_bytes(self.transition_authorization)
        if hashlib.sha256(authorization_bytes).hexdigest() != self.transition_authorization_sha256:
            raise ValueError("direct transition authorization hash is invalid")
        if (
            self.transition_authorization.manifest_sha256 != self.manifest_sha256
            or self.transition_authorization.original_policy_sha256 != self.policy_sha256
            or self.transition_authorization.weights_version_key
            != self.snapshot.weights_version_key
            or account_id32(self.transition_authorization.validator_hotkey)
            != account_id32(self.validator_hotkey)
            or self.transition_authorization.validator_uid != self.validator_uid
        ):
            raise ValueError("direct transition authorization is not bound to the preflight")
        return self


class DirectBootstrapOperationalPreflight(StrictProtocolModel):
    """Manifest, pilot replay, endpoint health, and finalized chain evidence."""

    schema_: Literal[DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA] = Field(alias="schema")
    transition_profile: Literal[DIRECT_TRANSITION_PROFILE]
    signed_manifest: SignedBootstrapEligibilityManifest
    chain: DirectBootstrapPreflight
    pilot_replay: BootstrapPilotReplaySet
    health: BootstrapHealthReceiptSet

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        manifest = self.signed_manifest.manifest
        expected = self.signed_manifest.manifest_sha256
        if (
            self.chain.manifest_sha256 != expected
            or self.pilot_replay.manifest_sha256 != expected
            or self.health.manifest_sha256 != expected
        ):
            raise ValueError("direct operational evidence binds different manifests")
        if self.chain.policy_sha256 != manifest.policy_sha256:
            raise ValueError("direct chain evidence binds another policy")
        if (
            self.health.checked_at_block != self.chain.snapshot.block_number
            or self.health.checked_at_block_hash != self.chain.snapshot.block_hash
        ):
            raise ValueError("direct health evidence binds another finalized snapshot")
        if len(self.pilot_replay.receipts) != len(manifest.entries) or len(
            self.health.receipts
        ) != len(manifest.entries):
            raise ValueError("direct operational evidence does not cover every eligible miner")
        for entry, replay, health in zip(
            manifest.entries,
            self.pilot_replay.receipts,
            self.health.receipts,
            strict=True,
        ):
            binding = (account_id32(entry.miner_hotkey), entry.uid, entry.origin)
            if (
                account_id32(replay.miner_hotkey),
                replay.uid,
                replay.origin,
            ) != binding or (
                account_id32(health.miner_hotkey),
                health.uid,
                health.origin,
            ) != binding:
                raise ValueError("direct operational evidence order or mapping is invalid")
            if replay.pilot_id != entry.pilot_id or replay.manifest_sha256 != entry.pilot_id:
                raise ValueError("direct pilot replay binds another pilot")
            if health.endpoint != entry.origin + "/healthz":
                raise ValueError("direct health evidence binds another endpoint")
        return self


class DirectBootstrapCallMaterial(StrictProtocolModel):
    """Canonical evidence and exact raw ``set_mechanism_weights`` parameters."""

    schema_: Literal[DIRECT_CALL_MATERIAL_SCHEMA] = Field(alias="schema")
    transition_profile: Literal[DIRECT_TRANSITION_PROFILE]
    operational_preflight_sha256: Hex32
    manifest_sha256: Hex32
    pilot_replay_sha256: Hex32
    health_receipts_sha256: Hex32
    operational_preflight: DirectBootstrapOperationalPreflight
    manifest_anchor: BootstrapManifestAnchorObservation | None = None
    call_module: Literal["SubtensorModule"]
    call_function: Literal["set_mechanism_weights"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    dests: Annotated[list[int], Field(min_length=256, max_length=256)]
    weights: Annotated[list[int], Field(min_length=256, max_length=256)]
    weights_version_key: Annotated[int, Field(gt=0)]
    expected_applied_row: Annotated[list[list[int]], Field(min_length=256, max_length=256)]

    @model_validator(mode="after")
    def validate_material(self) -> Self:
        encoded = canonical_json_bytes(self.operational_preflight)
        chain = self.operational_preflight.chain
        if hashlib.sha256(encoded).hexdigest() != self.operational_preflight_sha256:
            raise ValueError("direct call material preflight hash is invalid")
        if self.manifest_sha256 != chain.manifest_sha256:
            raise ValueError("direct call material binds another manifest")
        if (
            hashlib.sha256(
                canonical_json_bytes(self.operational_preflight.pilot_replay)
            ).hexdigest()
            != self.pilot_replay_sha256
        ):
            raise ValueError("direct call material pilot replay hash is invalid")
        if (
            hashlib.sha256(canonical_json_bytes(self.operational_preflight.health)).hexdigest()
            != self.health_receipts_sha256
        ):
            raise ValueError("direct call material health hash is invalid")
        if (
            self.dests != chain.full_row_uids
            or self.weights != chain.full_row_weights
            or self.expected_applied_row != chain.expected_applied_row
            or self.weights_version_key != chain.snapshot.weights_version_key
        ):
            raise ValueError("direct call parameters differ from finalized preflight")
        if self.manifest_anchor is not None and (
            self.manifest_anchor.manifest_sha256 != self.manifest_sha256
            or self.manifest_anchor.observation_block > chain.snapshot.block_number
        ):
            raise ValueError("direct call material anchor is not bound to its preflight")
        return self


class DirectBootstrapSubmissionReceipt(StrictProtocolModel):
    """Terminal finalized classification for one direct full-row call."""

    schema_: Literal[DIRECT_SUBMISSION_RECEIPT_SCHEMA] = Field(alias="schema")
    transition_profile: Literal[DIRECT_TRANSITION_PROFILE]
    classification: Literal["applied", "failed"]
    reason_codes: Annotated[list[str], Field(max_length=16)]
    manifest_sha256: Hex32
    call_material_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=255)]
    anchor: BootstrapExtrinsicReference
    weight_call: BootstrapExtrinsicReference
    observation_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    observation_block_hash: BlockHash
    expected_applied_row: Annotated[list[list[int]], Field(min_length=256, max_length=256)]
    observed_applied_row: Annotated[list[list[int]], Field(max_length=256)]
    observed_last_update: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    finalized_inclusion_verified: Literal[True]
    subnet_owner_mapping_verified: bool
    subnet_owner_uid_verified: bool
    validator_mapping_verified: bool
    validator_uid_verified: bool
    validator_permit_verified: bool
    destination_mappings_verified: bool
    applied_row_verified: bool
    last_update_verified: bool
    sdk_finalized_reads_verified: Literal[True]
    storage_proofs_verified: Literal[False] = False
    created_at: datetime

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_classification(self) -> Self:
        checks = (
            self.subnet_owner_mapping_verified,
            self.subnet_owner_uid_verified,
            self.validator_mapping_verified,
            self.validator_uid_verified,
            self.validator_permit_verified,
            self.destination_mappings_verified,
            self.applied_row_verified,
            self.last_update_verified,
        )
        if self.reason_codes != sorted(set(self.reason_codes)):
            raise ValueError("direct receipt reason codes must be unique and sorted")
        if self.classification == "applied":
            if self.reason_codes or not all(checks):
                raise ValueError("applied direct receipt contains a failed check")
        elif not self.reason_codes or all(checks):
            raise ValueError("failed direct receipt does not identify a failed check")
        return self


class DirectBootstrapSubmissionJournal(StrictProtocolModel):
    """Durable high-water state that prevents retries after an ambiguous effect."""

    schema_: Literal[DIRECT_SUBMISSION_JOURNAL_SCHEMA] = Field(alias="schema")
    transition_profile: Literal[DIRECT_TRANSITION_PROFILE]
    submission_id: Hex32
    phase: Literal[
        "claimed",
        "anchor_finalized",
        "material_written",
        "weight_finalized",
        "applied",
        "failed",
    ]
    manifest_sha256: Hex32
    transition_authorization_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    anchor: BootstrapExtrinsicReference | None = None
    call_material_sha256: Hex32 | None = None
    weight_call: BootstrapExtrinsicReference | None = None
    receipt_sha256: Hex32 | None = None
    updated_at: datetime

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_phase(self) -> Self:
        rank = {
            "claimed": 0,
            "anchor_finalized": 1,
            "material_written": 2,
            "weight_finalized": 3,
            "applied": 4,
            "failed": 4,
        }[self.phase]
        if (self.anchor is not None) != (rank >= 1):
            raise ValueError("direct journal anchor does not match its phase")
        if (self.call_material_sha256 is not None) != (rank >= 2):
            raise ValueError("direct journal material does not match its phase")
        if (self.weight_call is not None) != (rank >= 3):
            raise ValueError("direct journal weight call does not match its phase")
        if (self.receipt_sha256 is not None) != (rank >= 4):
            raise ValueError("direct journal receipt does not match its phase")
        return self


def validate_direct_bootstrap_preflight(
    signed: SignedBootstrapEligibilityManifest,
    snapshot: BootstrapChainSnapshot,
    *,
    authorization: DirectBootstrapTransitionAuthorization,
    subnet_owner_hotkey: str | bytes,
    validator_hotkey: str,
    now: datetime | None = None,
    require_submission_ready: bool = True,
) -> DirectBootstrapPreflight:
    """Validate all direct-transition gates without performing chain I/O."""

    if not isinstance(snapshot, BootstrapChainSnapshot):
        raise TypeError("snapshot must be a BootstrapChainSnapshot")
    try:
        owner_account = _account_bytes(subnet_owner_hotkey)
        validator_account = account_id32(validator_hotkey)
    except ValueError as error:
        raise BootstrapOperatorError("direct_validator_or_owner_hotkey_invalid") from error
    if snapshot.manifest_frozen_block_hash != signed.manifest.frozen_at_block_hash:
        raise BootstrapOperatorError("manifest_frozen_block_hash_mismatch")
    try:
        verify_signed_bootstrap_eligibility_manifest(
            signed,
            expected_coordinator_hotkey=signed.manifest.policy.coordinator_hotkey,
        )
        verify_direct_transition_authorization(
            signed,
            authorization,
            current_block=snapshot.block_number,
        )
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("signed_manifest_or_direct_authorization_invalid") from error

    policy = signed.manifest.policy
    if require_submission_ready:
        _require_direct_submission_headroom(authorization, policy, snapshot.block_number)
    now_ms = _datetime_ms(now or datetime.now(timezone.utc))
    if snapshot.block_timestamp_ms < now_ms - _MAX_FINALIZED_HEAD_AGE_MS:
        raise BootstrapOperatorError("finalized_head_stale")
    if snapshot.block_timestamp_ms > now_ms + _MAX_FINALIZED_FUTURE_SKEW_MS:
        raise BootstrapOperatorError("finalized_head_future_dated")
    gates = (
        (snapshot.mechanism_count, 1, "mechanism_count_mismatch"),
        (snapshot.commit_reveal_enabled, False, "direct_requires_commit_reveal_disabled"),
        (snapshot.commit_reveal_version, 4, "direct_commit_reveal_version_mismatch"),
        (snapshot.reveal_period_epochs, 1, "direct_reveal_period_mismatch"),
        (snapshot.tempo, 360, "direct_tempo_mismatch"),
        (snapshot.activity_cutoff_blocks, 360, "direct_activity_cutoff_mismatch"),
        (snapshot.block_time_seconds, 12.0, "direct_block_time_mismatch"),
        (
            snapshot.weights_version_key,
            authorization.weights_version_key,
            "direct_weights_version_key_mismatch",
        ),
        (snapshot.min_allowed_weights, 256, "direct_requires_min_allowed_weights_256"),
        (snapshot.max_allowed_uids, 256, "direct_requires_max_allowed_uids_256"),
    )
    for actual, expected, reason in gates:
        if actual != expected:
            raise BootstrapOperatorError(reason)
    if snapshot.validator_has_pending_commit:
        raise BootstrapOperatorError("validator_pending_commit_exists")
    if snapshot.total_pending_commit_count:
        raise BootstrapOperatorError("direct_pending_commits_not_drained")

    by_uid = {item.uid: item for item in snapshot.participants}
    if sorted(by_uid) != list(range(DIRECT_FULL_ROW_SIZE)):
        raise BootstrapOperatorError("direct_uid_domain_is_not_exactly_0_through_255")
    owner = next(
        (item for item in snapshot.participants if account_id32(item.hotkey) == owner_account),
        None,
    )
    if owner is None:
        raise BootstrapOperatorError("subnet_owner_hotkey_not_registered")
    if owner.uid != 0:
        raise BootstrapOperatorError("subnet_owner_hotkey_is_not_uid_0")
    validator = next(
        (item for item in snapshot.participants if account_id32(item.hotkey) == validator_account),
        None,
    )
    if validator is None:
        raise BootstrapOperatorError("authorized_validator_hotkey_not_registered")
    if account_id32(authorization.validator_hotkey) != validator_account:
        raise BootstrapOperatorError("authorized_validator_hotkey_mismatch")
    if authorization.validator_uid != validator.uid:
        raise BootstrapOperatorError("authorized_validator_uid_mismatch")
    if not validator.validator_permit:
        raise BootstrapOperatorError("authorized_validator_lacks_validator_permit")
    if (
        require_submission_ready
        and validator.last_update + snapshot.weights_set_rate_limit > snapshot.block_number
    ):
        raise BootstrapOperatorError("weights_rate_limit_not_elapsed")

    full_uids, full_weights = _direct_full_row(
        snapshot,
        validator_hotkey,
        signed.manifest.entries,
    )
    expected_row = [[uid, weight] for uid, weight in zip(full_uids, full_weights, strict=True)]
    for entry in signed.manifest.entries:
        participant = by_uid[entry.uid]
        if account_id32(participant.hotkey) != account_id32(entry.miner_hotkey):
            raise BootstrapOperatorError("eligible_miner_hotkey_mismatch")
        if participant.validator_permit:
            raise BootstrapOperatorError("eligible_miner_has_validator_permit")
        if participant.origin != entry.origin:
            raise BootstrapOperatorError("eligible_miner_origin_mismatch")
    if full_weights[validator.uid] != 0:
        raise BootstrapOperatorError("authorized_validator_is_eligible_miner")
    positives = len(signed.manifest.entries)
    if snapshot.max_weights_limit == 0 or positives * snapshot.max_weights_limit < U16_MAX:
        raise BootstrapOperatorError("row_exceeds_max_weight_ratio")

    if not snapshot.validator_mechid0_row:
        prior: Literal["empty", "inactive", "active_exact_direct_row"] = "empty"
    elif validator.last_update + snapshot.activity_cutoff_blocks < snapshot.block_number:
        prior = "inactive"
    elif snapshot.validator_mechid0_row == expected_row:
        prior = "active_exact_direct_row"
    else:
        raise BootstrapOperatorError("validator_previous_row_active_and_not_exact")
    active_accounts = {account_id32(hotkey) for hotkey in snapshot.active_mechid0_row_hotkeys}
    active_permitted_others = {
        account_id32(item.hotkey)
        for item in snapshot.participants
        if account_id32(item.hotkey) != validator_account
        and item.validator_permit
        and item.last_update + snapshot.activity_cutoff_blocks >= snapshot.block_number
    }
    if active_permitted_others:
        raise BootstrapOperatorError("pre_direct_other_active_permitted_validators_not_drained")
    if prior == "active_exact_direct_row":
        if active_accounts != {validator_account}:
            raise BootstrapOperatorError("other_active_rows_not_drained")
    elif active_accounts:
        raise BootstrapOperatorError("pre_direct_active_rows_not_drained")

    return DirectBootstrapPreflight(
        schema=DIRECT_PREFLIGHT_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        manifest_sha256=signed.manifest_sha256,
        policy_sha256=bootstrap_policy_hash(policy),
        transition_authorization=authorization,
        transition_authorization_sha256=hashlib.sha256(
            canonical_json_bytes(authorization)
        ).hexdigest(),
        snapshot=snapshot,
        subnet_owner_hotkey_account_id32="0x" + owner_account.hex(),
        validator_hotkey=validator.hotkey,
        validator_uid=validator.uid,
        prior_row_classification=prior,
        eligible_miner_count=positives,
        full_row_uids=full_uids,
        full_row_weights=full_weights,
        expected_applied_row=expected_row,
    )


async def build_direct_operational_preflight(
    signed: SignedBootstrapEligibilityManifest,
    chain: DirectBootstrapPreflight,
    *,
    fetch_bytes: Callable[[str, int], Any] | None = None,
    health_request: Callable[[str], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> DirectBootstrapOperationalPreflight:
    replay, health = await asyncio.gather(
        replay_bootstrap_pilots(signed, fetch_bytes=fetch_bytes),
        probe_bootstrap_health(signed, chain, request=health_request, clock=clock),
    )
    return DirectBootstrapOperationalPreflight(
        schema=DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        signed_manifest=signed,
        chain=chain,
        pilot_replay=replay,
        health=health,
    )


def build_direct_bootstrap_call_material(
    operational: DirectBootstrapOperationalPreflight,
    *,
    manifest_anchor: BootstrapManifestAnchorObservation | None = None,
    call_builder: Callable[..., Any] = bt.calls.SubtensorModule.set_mechanism_weights,
) -> tuple[DirectBootstrapCallMaterial, Any]:
    """Build an unsigned raw runtime call without zero filtering or chain I/O."""

    if not isinstance(operational, DirectBootstrapOperationalPreflight):
        raise TypeError("operational must be a DirectBootstrapOperationalPreflight")
    chain = operational.chain
    raw_call = call_builder(
        netuid=NETUID,
        mecid=MECHANISM_ID,
        dests=list(chain.full_row_uids),
        weights=list(chain.full_row_weights),
        version_key=chain.snapshot.weights_version_key,
    )
    if raw_call.module != "SubtensorModule" or raw_call.function != "set_mechanism_weights":
        raise BootstrapOperatorError("direct_raw_weight_call_shape_mismatch")
    params = raw_call.params
    if (
        params.get("netuid") != NETUID
        or params.get("mecid") != MECHANISM_ID
        or params.get("dests") != list(range(DIRECT_FULL_ROW_SIZE))
        or params.get("weights") != chain.full_row_weights
        or params.get("version_key") != chain.snapshot.weights_version_key
    ):
        raise BootstrapOperatorError("direct_raw_weight_call_parameter_mismatch")
    # Defend the property that makes the transition fence effective: the raw
    # runtime call must still contain all zero entries.
    if len(params["dests"]) != DIRECT_FULL_ROW_SIZE or len(params["weights"]) != (
        DIRECT_FULL_ROW_SIZE
    ):
        raise BootstrapOperatorError("direct_raw_weight_call_was_filtered")

    operational_bytes = canonical_json_bytes(operational)
    material = DirectBootstrapCallMaterial(
        schema=DIRECT_CALL_MATERIAL_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        operational_preflight_sha256=hashlib.sha256(operational_bytes).hexdigest(),
        manifest_sha256=chain.manifest_sha256,
        pilot_replay_sha256=hashlib.sha256(
            canonical_json_bytes(operational.pilot_replay)
        ).hexdigest(),
        health_receipts_sha256=hashlib.sha256(canonical_json_bytes(operational.health)).hexdigest(),
        operational_preflight=operational,
        manifest_anchor=manifest_anchor,
        call_module=raw_call.module,
        call_function=raw_call.function,
        netuid=NETUID,
        mechanism_id=MECHANISM_ID,
        dests=list(params["dests"]),
        weights=list(params["weights"]),
        weights_version_key=params["version_key"],
        expected_applied_row=chain.expected_applied_row,
    )
    return material, raw_call


class BittensorDirectBootstrapChain(BittensorBootstrapChain):
    """Collect coherent finalized state for a permit-bound direct transition."""

    def __init__(
        self,
        *,
        direct_checkout_verifier: Callable[[DirectBootstrapTransitionAuthorization], None]
        | None = None,
        **kwargs: Any,
    ) -> None:
        super().__init__(**kwargs)
        self.direct_checkout_verifier = direct_checkout_verifier or verify_direct_runtime_checkout

    async def direct_preflight_with_client(
        self,
        client: Any,
        signed: SignedBootstrapEligibilityManifest,
        *,
        authorization: DirectBootstrapTransitionAuthorization,
        validator_hotkey: str,
        require_submission_ready: bool = True,
    ) -> DirectBootstrapPreflight:
        snapshot = await self._snapshot(client, signed, validator_hotkey=validator_hotkey)
        pinned = await client.at(snapshot.block_number)
        info, owner = await asyncio.gather(
            pinned.block_info(),
            pinned.query(storage.SubtensorModule.SubnetOwnerHotkey, [NETUID]),
        )
        if (
            getattr(info, "number", None) != snapshot.block_number
            or getattr(info, "hash", None) != snapshot.block_hash
        ):
            raise BootstrapOperatorError("direct_owner_snapshot_mismatch")
        return validate_direct_bootstrap_preflight(
            signed,
            snapshot,
            authorization=authorization,
            subnet_owner_hotkey=owner,
            validator_hotkey=validator_hotkey,
            now=self.clock(),
            require_submission_ready=require_submission_ready,
        )

    async def direct_operational_preflight_with_client(
        self,
        client: Any,
        signed: SignedBootstrapEligibilityManifest,
        *,
        authorization: DirectBootstrapTransitionAuthorization,
        validator_hotkey: str,
        fetch_bytes: Callable[[str, int], Any] | None = None,
        health_request: Callable[[str], Any] | None = None,
    ) -> DirectBootstrapOperationalPreflight:
        self.direct_checkout_verifier(authorization)
        chain = await self.direct_preflight_with_client(
            client,
            signed,
            authorization=authorization,
            validator_hotkey=validator_hotkey,
        )
        return await build_direct_operational_preflight(
            signed,
            chain,
            fetch_bytes=fetch_bytes,
            health_request=health_request,
            clock=self.clock,
        )

    async def direct_operational_preflight(
        self,
        signed: SignedBootstrapEligibilityManifest,
        *,
        authorization: DirectBootstrapTransitionAuthorization,
        validator_hotkey: str,
        fetch_bytes: Callable[[str, int], Any] | None = None,
        health_request: Callable[[str], Any] | None = None,
    ) -> DirectBootstrapOperationalPreflight:
        async with self.client_factory("finney") as client:
            return await self.direct_operational_preflight_with_client(
                client,
                signed,
                authorization=authorization,
                validator_hotkey=validator_hotkey,
                fetch_bytes=fetch_bytes,
                health_request=health_request,
            )


def classify_direct_bootstrap_application(
    material: DirectBootstrapCallMaterial,
    *,
    anchor: BootstrapExtrinsicReference,
    weight_call: BootstrapExtrinsicReference,
    observation: DirectBootstrapPreflight,
    created_at: datetime | None = None,
) -> DirectBootstrapSubmissionReceipt:
    """Classify exact finalized post-call state without performing chain I/O."""

    if weight_call.block_number > observation.snapshot.block_number:
        raise BootstrapOperatorError("direct_observation_precedes_weight_call")
    if material.manifest_anchor is None or material.manifest_anchor.anchor != anchor:
        raise BootstrapOperatorError("direct_result_anchor_mismatch")
    if material.manifest_sha256 != observation.manifest_sha256:
        raise BootstrapOperatorError("direct_result_manifest_mismatch")
    before = material.operational_preflight.chain
    authorization = before.transition_authorization
    observed_owner_account = bytes.fromhex(observation.subnet_owner_hotkey_account_id32[2:])
    owner_mapping_ok = (
        before.subnet_owner_hotkey_account_id32 == observation.subnet_owner_hotkey_account_id32
    )
    mappings_ok = _manifest_mappings_match(
        material.operational_preflight.signed_manifest,
        observation.snapshot,
    )
    row_ok = observation.snapshot.validator_mechid0_row == material.expected_applied_row
    participant = next(
        (
            item
            for item in observation.snapshot.participants
            if account_id32(item.hotkey) == account_id32(observation.validator_hotkey)
        ),
        None,
    )
    owner_participant = next(
        (
            item
            for item in observation.snapshot.participants
            if account_id32(item.hotkey) == observed_owner_account
        ),
        None,
    )
    observed_last_update = 0 if participant is None else participant.last_update
    owner_uid_ok = owner_participant is not None and owner_participant.uid == 0
    validator_mapping_ok = (
        account_id32(before.validator_hotkey) == account_id32(observation.validator_hotkey)
        and account_id32(authorization.validator_hotkey)
        == account_id32(observation.validator_hotkey)
        and participant is not None
        and account_id32(participant.hotkey) == account_id32(observation.validator_hotkey)
    )
    validator_uid_ok = (
        before.validator_uid == observation.validator_uid
        and authorization.validator_uid == observation.validator_uid
        and participant is not None
        and participant.uid == observation.validator_uid
    )
    permit_ok = participant is not None and participant.validator_permit
    last_update_ok = observed_last_update == weight_call.block_number
    reasons: list[str] = []
    if not owner_mapping_ok:
        reasons.append("subnet_owner_mapping_changed")
    if not owner_uid_ok:
        reasons.append("subnet_owner_uid_changed")
    if not validator_mapping_ok:
        reasons.append("validator_mapping_changed")
    if not validator_uid_ok:
        reasons.append("validator_uid_changed")
    if not permit_ok:
        reasons.append("validator_permit_missing")
    if not mappings_ok:
        reasons.append("destination_mapping_changed")
    if not row_ok:
        reasons.append("applied_row_mismatch")
    if not last_update_ok:
        reasons.append("last_update_mismatch")
    return DirectBootstrapSubmissionReceipt(
        schema=DIRECT_SUBMISSION_RECEIPT_SCHEMA,
        transition_profile=DIRECT_TRANSITION_PROFILE,
        classification="failed" if reasons else "applied",
        reason_codes=sorted(reasons),
        manifest_sha256=material.manifest_sha256,
        call_material_sha256=hashlib.sha256(canonical_json_bytes(material)).hexdigest(),
        validator_hotkey=observation.validator_hotkey,
        validator_uid=observation.validator_uid,
        anchor=anchor,
        weight_call=weight_call,
        observation_block=observation.snapshot.block_number,
        observation_block_hash=observation.snapshot.block_hash,
        expected_applied_row=material.expected_applied_row,
        observed_applied_row=observation.snapshot.validator_mechid0_row,
        observed_last_update=observed_last_update,
        finalized_inclusion_verified=True,
        subnet_owner_mapping_verified=owner_mapping_ok,
        subnet_owner_uid_verified=owner_uid_ok,
        validator_mapping_verified=validator_mapping_ok,
        validator_uid_verified=validator_uid_ok,
        validator_permit_verified=permit_ok,
        destination_mappings_verified=mappings_ok,
        applied_row_verified=row_ok,
        last_update_verified=last_update_ok,
        sdk_finalized_reads_verified=True,
        storage_proofs_verified=False,
        created_at=created_at or datetime.now(timezone.utc),
    )


async def submit_direct_bootstrap_weights(
    signed: SignedBootstrapEligibilityManifest,
    *,
    authorization: DirectBootstrapTransitionAuthorization,
    wallet: Any,
    chain: BittensorDirectBootstrapChain,
    receipt_output: Path,
    call_material_output: Path,
    state_dir: Path,
    live_submit: bool,
    acknowledgement: str,
    fetch_bytes: Callable[[str, int], Any] | None = None,
    health_request: Callable[[str], Any] | None = None,
    call_builder: Callable[..., Any] = bt.calls.SubtensorModule.set_mechanism_weights,
    before_first_effect: Callable[[], None] | None = None,
    finalized_snapshot_guard: Callable[[int, str, int], Awaitable[None]] | None = None,
) -> DirectBootstrapSubmissionReceipt:
    """Anchor, submit one raw direct row, and verify its finalized applied state."""

    if live_submit is not True or acknowledgement != DIRECT_LIVE_SUBMIT_ACKNOWLEDGEMENT:
        raise BootstrapOperatorError("direct_live_submit_acknowledgement_missing")
    if receipt_output.exists() or call_material_output.exists():
        raise BootstrapOperatorError("direct_submission_output_exists")
    if receipt_output.resolve() == call_material_output.resolve():
        raise BootstrapOperatorError("direct_submission_outputs_overlap")
    signer = bt.resolve_signer(wallet, role="hotkey")
    validator_hotkey = signer.ss58_address
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    authorization_hash = hashlib.sha256(canonical_json_bytes(authorization)).hexdigest()
    state_stem = f"direct-{authorization_hash}-{account_id32(validator_hotkey).hex()}"
    lock_path = state_dir / f".{state_stem}.lock"
    journal_path = state_dir / f"{state_stem}.json"
    if journal_path.exists():
        raise BootstrapOperatorError("direct_submission_claim_exists_reconcile_required")
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise BootstrapOperatorError("direct_submission_already_in_progress") from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        async with chain.client_factory("finney") as client:
            before = await chain.direct_operational_preflight_with_client(
                client,
                signed,
                authorization=authorization,
                validator_hotkey=validator_hotkey,
                fetch_bytes=fetch_bytes,
                health_request=health_request,
            )
            if finalized_snapshot_guard is not None:
                await finalized_snapshot_guard(
                    before.chain.snapshot.block_number,
                    before.chain.snapshot.block_hash,
                    _SUBMISSION_ERA_PERIOD * 2,
                )
            if before_first_effect is not None:
                before_first_effect()
            journal = DirectBootstrapSubmissionJournal(
                schema=DIRECT_SUBMISSION_JOURNAL_SCHEMA,
                transition_profile=DIRECT_TRANSITION_PROFILE,
                submission_id=authorization.submission_id,
                phase="claimed",
                manifest_sha256=signed.manifest_sha256,
                transition_authorization_sha256=authorization_hash,
                validator_hotkey=validator_hotkey,
                updated_at=chain.clock(),
            )
            _write_new_canonical(journal_path, journal, maximum_bytes=_MAX_RECEIPT_BYTES)
            anchor_result = await client.submit_call(
                build_sha256_commitment_call(signed.manifest_sha256),
                wallet,
                signer="hotkey",
                period=_SUBMISSION_ERA_PERIOD,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
            anchor = _successful_extrinsic(anchor_result, reason="direct_manifest_anchor_failed")
            if not _in_direct_submission_interval(
                authorization,
                signed.manifest.policy,
                anchor.block_number,
            ):
                raise BootstrapOperatorError("direct_manifest_anchor_outside_authorization")
            journal = journal.model_copy(
                update={"phase": "anchor_finalized", "anchor": anchor, "updated_at": chain.clock()}
            )
            _replace_canonical(journal_path, journal, maximum_bytes=_MAX_RECEIPT_BYTES)

            after_anchor_chain = await chain.direct_preflight_with_client(
                client,
                signed,
                authorization=authorization,
                validator_hotkey=validator_hotkey,
            )
            if (
                after_anchor_chain.subnet_owner_hotkey_account_id32
                != before.chain.subnet_owner_hotkey_account_id32
            ):
                raise BootstrapOperatorError("direct_subnet_owner_changed_after_anchor")
            anchor_observation = await chain.verify_manifest_anchor_with_client(
                client,
                signed,
                validator_hotkey=validator_hotkey,
                anchor=anchor,
                post_anchor=after_anchor_chain,
            )
            health = await probe_bootstrap_health(
                signed,
                after_anchor_chain,
                request=health_request,
                clock=chain.clock,
            )
            operational = DirectBootstrapOperationalPreflight(
                schema=DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA,
                transition_profile=DIRECT_TRANSITION_PROFILE,
                signed_manifest=signed,
                chain=after_anchor_chain,
                pilot_replay=before.pilot_replay,
                health=health,
            )
            material, raw_call = build_direct_bootstrap_call_material(
                operational,
                manifest_anchor=anchor_observation,
                call_builder=call_builder,
            )
            if finalized_snapshot_guard is not None:
                await finalized_snapshot_guard(
                    after_anchor_chain.snapshot.block_number,
                    after_anchor_chain.snapshot.block_hash,
                    _SUBMISSION_ERA_PERIOD,
                )
            _write_new_canonical(
                call_material_output,
                material,
                maximum_bytes=_MAX_INPUT_BYTES,
            )
            material_sha256 = hashlib.sha256(canonical_json_bytes(material)).hexdigest()
            journal = journal.model_copy(
                update={
                    "phase": "material_written",
                    "call_material_sha256": material_sha256,
                    "updated_at": chain.clock(),
                }
            )
            _replace_canonical(journal_path, journal, maximum_bytes=_MAX_RECEIPT_BYTES)
            result = await client.submit_call(
                raw_call,
                wallet,
                signer="hotkey",
                period=_SUBMISSION_ERA_PERIOD,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
            weight_call = _successful_extrinsic(result, reason="direct_weight_call_failed")
            if not _in_direct_submission_interval(
                authorization,
                signed.manifest.policy,
                weight_call.block_number,
            ):
                raise BootstrapOperatorError("direct_weight_call_outside_authorization")
            journal = journal.model_copy(
                update={
                    "phase": "weight_finalized",
                    "weight_call": weight_call,
                    "updated_at": chain.clock(),
                }
            )
            _replace_canonical(journal_path, journal, maximum_bytes=_MAX_RECEIPT_BYTES)
            observation = await chain.direct_preflight_with_client(
                client,
                signed,
                authorization=authorization,
                validator_hotkey=validator_hotkey,
                require_submission_ready=False,
            )
            if finalized_snapshot_guard is not None:
                await finalized_snapshot_guard(
                    observation.snapshot.block_number,
                    observation.snapshot.block_hash,
                    0,
                )
            if observation.snapshot.block_number < weight_call.block_number:
                raise BootstrapOperatorError("direct_post_call_snapshot_not_finalized")
            receipt = classify_direct_bootstrap_application(
                material,
                anchor=anchor,
                weight_call=weight_call,
                observation=observation,
                created_at=chain.clock(),
            )
            _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
            receipt_sha256 = hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
            journal = journal.model_copy(
                update={
                    "phase": receipt.classification,
                    "receipt_sha256": receipt_sha256,
                    "updated_at": chain.clock(),
                }
            )
            _replace_canonical(journal_path, journal, maximum_bytes=_MAX_RECEIPT_BYTES)
            if receipt.classification != "applied":
                raise BootstrapOperatorError("direct_weight_call_not_applied_exactly")
            return receipt
    finally:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            lock_path.unlink()


def _direct_full_row(
    snapshot: BootstrapChainSnapshot,
    validator_hotkey: str,
    entries: Sequence[Any],
) -> tuple[list[int], list[int]]:
    del validator_hotkey
    if sorted(item.uid for item in snapshot.participants) != list(range(DIRECT_FULL_ROW_SIZE)):
        raise BootstrapOperatorError("direct_uid_domain_is_not_exactly_0_through_255")
    eligible = {entry.uid for entry in entries}
    return list(range(DIRECT_FULL_ROW_SIZE)), [
        U16_MAX if uid in eligible else 0 for uid in range(DIRECT_FULL_ROW_SIZE)
    ]


def _manifest_mappings_match(
    signed: SignedBootstrapEligibilityManifest,
    snapshot: BootstrapChainSnapshot,
) -> bool:
    by_uid = {item.uid: item for item in snapshot.participants}
    return all(
        (participant := by_uid.get(entry.uid)) is not None
        and account_id32(participant.hotkey) == account_id32(entry.miner_hotkey)
        and participant.origin == entry.origin
        and not participant.validator_permit
        for entry in signed.manifest.entries
    )


def _in_direct_submission_interval(
    authorization: DirectBootstrapTransitionAuthorization,
    policy: Any,
    block_number: int,
) -> bool:
    """Return whether the explicit direct override permits this exact block."""

    return (
        authorization.valid_from_block <= block_number <= authorization.expires_at_block
        and block_number < policy.hard_sunset_block
    )


def _require_direct_submission_headroom(
    authorization: DirectBootstrapTransitionAuthorization,
    policy: Any,
    block_number: int,
) -> None:
    if not _in_direct_submission_interval(authorization, policy, block_number):
        raise BootstrapOperatorError("direct_submission_snapshot_outside_authorization")
    latest_possible = block_number + _SUBMISSION_ERA_PERIOD
    if not _in_direct_submission_interval(authorization, policy, latest_possible):
        raise BootstrapOperatorError("direct_submission_era_lacks_authorization_headroom")


def _account_bytes(value: Any) -> bytes:
    candidate = getattr(value, "value", value)
    if isinstance(candidate, str) and candidate.startswith("0x"):
        try:
            decoded = bytes.fromhex(candidate[2:])
        except ValueError as error:
            raise ValueError("account is not valid hexadecimal") from error
        return account_id32(decoded)
    return account_id32(candidate)


def _replace_canonical(path: Path, value: Any, *, maximum_bytes: int) -> None:
    encoded = canonical_json_bytes(value)
    if not encoded or len(encoded) > maximum_bytes:
        raise BootstrapOperatorError("direct_journal_size_invalid")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        os.write(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        with contextlib.suppress(OSError):
            temporary.unlink()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umi-bootstrap-direct-weights",
        description="Build and submit a permit-bound SN78 direct full bootstrap row",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    authorize = commands.add_parser("authorize-transition")
    authorize.add_argument("--manifest", type=Path, required=True)
    authorize.add_argument("--submission-id", required=True)
    authorize.add_argument("--weights-version-key", type=int, required=True)
    authorize.add_argument("--umi-git-revision", required=True)
    authorize.add_argument("--signed-at-block", type=int, required=True)
    authorize.add_argument("--valid-from-block", type=int, required=True)
    authorize.add_argument("--expires-at-block", type=int, required=True)
    authorize.add_argument("--validator-hotkey", required=True)
    authorize.add_argument("--validator-uid", type=int, required=True)
    authorize.add_argument("--output", type=Path, required=True)
    authorize.add_argument("--wallet-name", required=True)
    authorize.add_argument("--hotkey", required=True)
    authorize.add_argument("--wallet-path", default="~/.bittensor/wallets")

    verify = commands.add_parser("verify-authorization")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--authorization", type=Path, required=True)
    verify.add_argument("--current-block", type=int, required=True)

    inspect_journal = commands.add_parser("inspect-journal")
    inspect_journal.add_argument("--journal", type=Path, required=True)
    inspect_owner_journal = commands.add_parser("inspect-owner-fence-journal")
    inspect_owner_journal.add_argument("--journal", type=Path, required=True)

    owner_fence = commands.add_parser("build-owner-fence")
    owner_fence.add_argument("--owner-coldkey", required=True)
    owner_fence.add_argument("--output", type=Path, required=True)
    owner_fence.add_argument("--finalized-timeout", type=float, default=20.0)

    submit_owner_fence = commands.add_parser("submit-owner-fence")
    submit_owner_fence.add_argument("--receipt-output", type=Path, required=True)
    submit_owner_fence.add_argument("--call-material-output", type=Path, required=True)
    submit_owner_fence.add_argument("--state-dir", type=Path, required=True)
    submit_owner_fence.add_argument("--finalized-timeout", type=float, default=20.0)
    submit_owner_fence.add_argument("--live-submit", action="store_true")
    submit_owner_fence.add_argument("--acknowledgement", required=True)
    submit_owner_fence.add_argument("--wallet-name", required=True)
    submit_owner_fence.add_argument("--wallet-path", default="~/.bittensor/wallets")

    attest_owner_fence = commands.add_parser("attest-owner-fence")
    attest_owner_fence.add_argument("--owner-coldkey", required=True)
    attest_owner_fence.add_argument("--receipt-output", type=Path, required=True)
    attest_owner_fence.add_argument("--call-material-output", type=Path, required=True)
    attest_owner_fence.add_argument("--state-dir", type=Path, required=True)
    attest_owner_fence.add_argument("--finalized-timeout", type=float, default=20.0)

    for name in ("preflight", "build-call"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", type=Path, required=True)
        command.add_argument("--authorization", type=Path, required=True)
        command.add_argument("--validator-hotkey", required=True)
        command.add_argument("--output", type=Path, required=True)
        command.add_argument("--finalized-timeout", type=float, default=20.0)
    submit = commands.add_parser("submit")
    submit.add_argument("--manifest", type=Path, required=True)
    submit.add_argument("--authorization", type=Path, required=True)
    submit.add_argument("--receipt-output", type=Path, required=True)
    submit.add_argument("--call-material-output", type=Path, required=True)
    submit.add_argument("--state-dir", type=Path, required=True)
    submit.add_argument("--finalized-timeout", type=float, default=20.0)
    submit.add_argument("--live-submit", action="store_true")
    submit.add_argument("--acknowledgement", required=True)
    submit.add_argument("--wallet-name", required=True)
    submit.add_argument("--hotkey", required=True)
    submit.add_argument("--wallet-path", default="~/.bittensor/wallets")
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if args.command == "inspect-journal":
            journal = _load_canonical(args.journal, DirectBootstrapSubmissionJournal)
            _print_canonical(journal)
            return 0
        if args.command == "inspect-owner-fence-journal":
            journal = _load_canonical(args.journal, OwnerFenceJournal)
            _print_canonical(journal)
            return 0
        if args.command == "build-owner-fence":
            preflight = asyncio.run(
                collect_owner_fence_preflight(
                    expected_owner_coldkey=args.owner_coldkey,
                    finalized_timeout_seconds=args.finalized_timeout,
                )
            )
            material, _ = build_owner_fence_call(preflight)
            _write_new_canonical(args.output, material, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(material)
            return 0
        if args.command == "submit-owner-fence":
            wallet = bt.Wallet(name=args.wallet_name, path=args.wallet_path)
            receipt = asyncio.run(
                submit_owner_fence(
                    wallet=wallet,
                    receipt_output=args.receipt_output,
                    call_material_output=args.call_material_output,
                    state_dir=args.state_dir,
                    live_submit=args.live_submit,
                    acknowledgement=args.acknowledgement,
                    finalized_timeout_seconds=args.finalized_timeout,
                )
            )
            _print_canonical(receipt)
            return 0
        if args.command == "attest-owner-fence":
            receipt = asyncio.run(
                attest_owner_fence(
                    expected_owner_coldkey=args.owner_coldkey,
                    receipt_output=args.receipt_output,
                    call_material_output=args.call_material_output,
                    state_dir=args.state_dir,
                    finalized_timeout_seconds=args.finalized_timeout,
                )
            )
            _print_canonical(receipt)
            return 0
        signed = _load_canonical(args.manifest, SignedBootstrapEligibilityManifest)
        if args.command == "authorize-transition":
            wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
            result = sign_direct_transition_authorization(
                signed,
                weights_version_key=args.weights_version_key,
                submission_id=args.submission_id,
                umi_git_revision=args.umi_git_revision,
                signed_at_block=args.signed_at_block,
                valid_from_block=args.valid_from_block,
                expires_at_block=args.expires_at_block,
                validator_hotkey=args.validator_hotkey,
                validator_uid=args.validator_uid,
                wallet=wallet,
            )
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
            return 0
        authorization = _load_canonical(
            args.authorization,
            DirectBootstrapTransitionAuthorization,
        )
        if args.command == "verify-authorization":
            result = verify_direct_transition_authorization(
                signed,
                authorization,
                current_block=args.current_block,
            )
            _print_canonical(result)
            return 0
        chain = BittensorDirectBootstrapChain(finalized_timeout_seconds=args.finalized_timeout)
        if args.command in {"preflight", "build-call"}:
            operational = asyncio.run(
                chain.direct_operational_preflight(
                    signed,
                    authorization=authorization,
                    validator_hotkey=args.validator_hotkey,
                )
            )
            if args.command == "preflight":
                _write_new_canonical(args.output, operational, maximum_bytes=_MAX_INPUT_BYTES)
                _print_canonical(operational)
            else:
                material, _ = build_direct_bootstrap_call_material(operational)
                _write_new_canonical(args.output, material, maximum_bytes=_MAX_INPUT_BYTES)
                _print_canonical(material)
        elif args.command == "submit":
            wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
            receipt = asyncio.run(
                submit_direct_bootstrap_weights(
                    signed,
                    authorization=authorization,
                    wallet=wallet,
                    chain=chain,
                    receipt_output=args.receipt_output,
                    call_material_output=args.call_material_output,
                    state_dir=args.state_dir,
                    live_submit=args.live_submit,
                    acknowledgement=args.acknowledgement,
                )
            )
            _print_canonical(receipt)
        else:  # pragma: no cover
            raise BootstrapOperatorError("direct_unknown_command")
    except (
        BootstrapOperatorError,
        OSError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        reason = getattr(error, "reason_code", "direct_bootstrap_operator_failed")
        parser.exit(2, f"direct bootstrap weight operator failed: {reason}\n")
    return 0


def main() -> None:
    raise SystemExit(run_cli())


__all__ = [
    "DIRECT_CALL_MATERIAL_SCHEMA",
    "DIRECT_FULL_ROW_SIZE",
    "DIRECT_LIVE_SUBMIT_ACKNOWLEDGEMENT",
    "DIRECT_OPERATIONAL_PREFLIGHT_SCHEMA",
    "DIRECT_PREFLIGHT_SCHEMA",
    "DIRECT_SUBMISSION_RECEIPT_SCHEMA",
    "DIRECT_TRANSITION_PROFILE",
    "BittensorDirectBootstrapChain",
    "DirectBootstrapCallMaterial",
    "DirectBootstrapOperationalPreflight",
    "DirectBootstrapPreflight",
    "DirectBootstrapSubmissionReceipt",
    "OwnerFenceCallMaterial",
    "OwnerFenceJournal",
    "OwnerFencePreflight",
    "OwnerFenceReceipt",
    "attest_owner_fence",
    "build_direct_bootstrap_call_material",
    "build_direct_operational_preflight",
    "classify_direct_bootstrap_application",
    "submit_direct_bootstrap_weights",
    "validate_direct_bootstrap_preflight",
]


if __name__ == "__main__":
    main()
