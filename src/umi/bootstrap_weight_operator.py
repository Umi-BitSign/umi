"""Fail-closed operator for temporary SN78 public-service bootstrap weights.

The module keeps policy and signature construction separate from live chain
effects.  ``preflight`` and ``build-call`` are read-only.  ``submit`` requires an
explicit acknowledgement, anchors the signed manifest hash first, then builds a
raw mechanism-aware CRv4 call from one fresh finalized schedule snapshot.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import hashlib
import inspect
import ipaddress
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import AsyncIterator, Callable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

import bittensor as bt
import httpx
from bittensor._generated import storage
from pydantic import Field, ValidationError, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_weights import (
    BOOTSTRAP_WEIGHT_POLICY_SCHEMA,
    U16_MAX,
    BootstrapEligibilityEntry,
    BootstrapOptIn,
    BootstrapWeightPolicy,
    SignedBootstrapEligibilityManifest,
    bootstrap_policy_hash,
    build_bootstrap_eligibility_manifest,
    sign_bootstrap_eligibility_manifest,
    sign_bootstrap_opt_in,
    verify_bootstrap_opt_in,
    verify_signed_bootstrap_eligibility_manifest,
)
from .chain import _header_hash, _public_axon_origin, _timestamp_ms
from .chain_evidence import (
    COMMIT_REVEAL_VERSION,
    MECHANISM_ID,
    NETUID,
    BuiltCRv4WeightCommit,
    WeightScheduleSnapshot,
    build_crv4_weight_commit,
    build_sha256_commitment_call,
)
from .crypto import sign_response_digest, verify_response_signature
from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH
from .observer_pilot_feed import (
    MAX_PILOT_FEED_BYTES,
    VerifiedComponentPilot,
    _bundle_refs,
    _load_pilot,
)
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes

BOOTSTRAP_PREFLIGHT_SCHEMA = "umi-bootstrap-weight-preflight/1"
BOOTSTRAP_CALL_MATERIAL_SCHEMA = "umi-bootstrap-weight-call-material/1"
BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA = "umi-bootstrap-weight-submission-receipt/1"
BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA = "umi-bootstrap-pilot-replay-set/1"
BOOTSTRAP_HEALTH_SET_SCHEMA = "umi-bootstrap-health-set/1"
BOOTSTRAP_CUTOVER_CHECKPOINT_SCHEMA = "umi-bootstrap-cutover-checkpoint/1"
BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA = "umi-bootstrap-operational-preflight/1"
BOOTSTRAP_TERMINAL_OBSERVATION_SCHEMA = "umi-bootstrap-terminal-observation/1"
BOOTSTRAP_SUNSET_STATUS_SCHEMA = "umi-bootstrap-sunset-status/1"
BOOTSTRAP_TERMINAL_SIGNATURE_SCHEMA = "umi-bootstrap-terminal-signature/1"
BOOTSTRAP_SUNSET_SIGNATURE_SCHEMA = "umi-bootstrap-sunset-signature/1"
LIVE_SUBMIT_ACKNOWLEDGEMENT = "SUBMIT SN78 BOOTSTRAP SERVICE WEIGHTS"

_TERMINAL_SIGNATURE_DOMAIN = b"umi-bootstrap-terminal-v1\0"
_SUNSET_SIGNATURE_DOMAIN = b"umi-bootstrap-sunset-v1\0"

_FINNEY_GENESIS_HASH = f"0x{FINNEY_GENESIS_HASH}"
_MAX_INPUT_BYTES = 4 * 1024 * 1024
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_JSON_SAFE_INTEGER = (1 << 53) - 1
_MAX_U64 = (1 << 64) - 1
_MAX_FINALIZED_HEAD_AGE_MS = 120_000
_MAX_FINALIZED_FUTURE_SKEW_MS = 30_000
_MAX_HEALTH_BODY_BYTES = 64 * 1024
_HTTP_TIMEOUT_SECONDS = 15.0
_SUBMISSION_ERA_PERIOD = 8
_MAX_TERMINAL_SCAN_BLOCKS = 2_048
_GIT_REVISION_RE = re.compile(r"^[0-9a-f]{40}$")


class BootstrapOperatorError(RuntimeError):
    """Stable, non-sensitive failure from bootstrap operator work."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class BootstrapChainParticipant(StrictProtocolModel):
    hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    uid: Annotated[int, Field(ge=0, le=U16_MAX)]
    validator_permit: bool
    origin: Annotated[str, Field(min_length=1, max_length=128)] | None
    last_update: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]

    @field_validator("hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


class BootstrapChainSnapshot(StrictProtocolModel):
    """Values consumed by one bootstrap preflight from one finalized block."""

    network: Literal["finney"]
    genesis_block_hash: Literal[_FINNEY_GENESIS_HASH]
    block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_hash: BlockHash
    block_timestamp_ms: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    manifest_frozen_block_hash: BlockHash
    mechanism_count: Annotated[int, Field(ge=0, le=U16_MAX)]
    commit_reveal_enabled: bool
    commit_reveal_version: Annotated[int, Field(ge=0, le=U16_MAX)]
    reveal_period_epochs: Annotated[int, Field(ge=0, le=_MAX_U64)]
    weights_version_key: Annotated[int, Field(ge=0, le=_MAX_U64)]
    min_allowed_weights: Annotated[int, Field(ge=0, le=U16_MAX)]
    max_weights_limit: Annotated[int, Field(ge=0, le=U16_MAX)]
    max_allowed_uids: Annotated[int, Field(gt=0, le=U16_MAX)]
    weights_set_rate_limit: Annotated[int, Field(ge=0, le=_MAX_U64)]
    activity_cutoff_blocks: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    validator_mechid0_row: Annotated[list[list[int]], Field(max_length=U16_MAX)]
    validator_has_pending_commit: bool
    total_pending_commit_count: Annotated[int, Field(ge=0, le=_MAX_U64)]
    active_mechid0_row_hotkeys: Annotated[list[str], Field(max_length=65_536)]
    storage_proofs_verified: Literal[False] = False
    tempo: Annotated[int, Field(gt=0, le=U16_MAX)]
    last_epoch_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    pending_epoch_at: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    subnet_epoch_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    blocks_since_last_step: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_time_seconds: Annotated[float, Field(gt=0, le=60)]
    participants: Annotated[list[BootstrapChainParticipant], Field(min_length=1, max_length=65_536)]

    @model_validator(mode="after")
    def validate_snapshot(self) -> Self:
        if self.last_epoch_block > self.block_number:
            raise ValueError("last_epoch_block cannot follow the finalized snapshot")
        if self.blocks_since_last_step > self.block_number:
            raise ValueError("blocks_since_last_step cannot exceed the finalized block")
        if len({item.uid for item in self.participants}) != len(self.participants):
            raise ValueError("bootstrap chain snapshot contains a duplicate UID")
        accounts = [account_id32(item.hotkey) for item in self.participants]
        if len(set(accounts)) != len(accounts):
            raise ValueError("bootstrap chain snapshot contains a duplicate hotkey")
        if any(len(item) != 2 for item in self.validator_mechid0_row):
            raise ValueError("validator MechId 0 row contains an invalid pair")
        row_uids = [item[0] for item in self.validator_mechid0_row]
        if len(set(row_uids)) != len(row_uids):
            raise ValueError("validator MechId 0 row contains a duplicate UID")
        if any(
            not 0 <= uid <= U16_MAX or not 0 <= weight <= U16_MAX
            for uid, weight in self.validator_mechid0_row
        ):
            raise ValueError("validator MechId 0 row contains an invalid u16 value")
        active_accounts = [account_id32(item) for item in self.active_mechid0_row_hotkeys]
        if active_accounts != sorted(set(active_accounts)):
            raise ValueError("active MechId 0 row hotkeys must be unique and sorted")
        return self


class BootstrapWeightPreflight(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_PREFLIGHT_SCHEMA] = Field(alias="schema")
    manifest_sha256: Hex32
    policy_sha256: Hex32
    snapshot: BootstrapChainSnapshot
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    validator_uid: Annotated[int, Field(ge=0, le=U16_MAX)]
    prior_row_classification: Literal["empty", "inactive", "active_prior_bootstrap"]
    prior_terminal_sha256: Hex32 | None = None
    clean_cutover_enforced: bool
    eligible_miner_count: Annotated[int, Field(gt=0, le=256)]
    quantized_uids: Annotated[list[int], Field(min_length=1, max_length=256)]
    quantized_weights: Annotated[list[int], Field(min_length=1, max_length=256)]

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_row(self) -> Self:
        if len(self.quantized_uids) != len(self.quantized_weights):
            raise ValueError("bootstrap preflight row is not parallel")
        if self.eligible_miner_count != len(self.quantized_uids):
            raise ValueError("bootstrap preflight miner count does not match its row")
        if self.quantized_uids != sorted(set(self.quantized_uids)):
            raise ValueError("bootstrap preflight UIDs must be unique and sorted")
        if any(weight != U16_MAX for weight in self.quantized_weights):
            raise ValueError("bootstrap preflight weights must all equal 65535")
        return self


class BootstrapCutoverCheckpoint(StrictProtocolModel):
    """SDK-finalized observations for the manifest-bound clean cutover."""

    schema_: Literal[BOOTSTRAP_CUTOVER_CHECKPOINT_SCHEMA] = Field(alias="schema")
    policy_sha256: Hex32
    published_at_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    published_at_block_hash: BlockHash
    published_weights_version_key: Literal[0]
    checkpoint_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    checkpoint_block_hash: BlockHash
    checkpoint_weights_version_key: Literal[1]
    mechanism_count: Literal[1]
    commit_reveal_enabled: Literal[True]
    commit_reveal_version: Literal[4]
    reveal_period_epochs: Literal[1]
    tempo: Literal[360]
    activity_cutoff_blocks: Literal[360]
    total_pending_commit_count: Literal[0]
    active_mechid0_row_hotkeys: Annotated[list[str], Field(max_length=0)]
    storage_proofs_verified: Literal[False] = False

    @model_validator(mode="after")
    def validate_transition(self) -> Self:
        if self.published_weights_version_key == self.checkpoint_weights_version_key:
            raise ValueError("WeightsVersionKey did not change after policy publication")
        if self.published_at_block >= self.checkpoint_block:
            raise ValueError("cutover checkpoint does not follow policy publication")
        return self


class BootstrapPilotReplayReceipt(StrictProtocolModel):
    pilot_id: Hex32
    manifest_sha256: Hex32
    bundle_bytes: Annotated[int, Field(gt=0, le=MAX_PILOT_FEED_BYTES)]
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    uid: Annotated[int, Field(ge=0, le=U16_MAX)]
    origin: Annotated[str, Field(min_length=1, max_length=128)]
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    campaign_id: Hex32
    outcome_classification: Literal["ok"]
    deterministic_replay_verified: Literal[True]
    coordinator_signature_verified: Literal[True]
    storage_proofs_verified: Literal[False]

    @field_validator("miner_hotkey", "coordinator_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


class BootstrapPilotReplaySet(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA] = Field(alias="schema")
    manifest_sha256: Hex32
    public_evidence_origin: Annotated[str, Field(min_length=1, max_length=8_192)]
    receipts: Annotated[list[BootstrapPilotReplayReceipt], Field(min_length=1, max_length=256)]


class BootstrapHealthReceipt(StrictProtocolModel):
    miner_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    uid: Annotated[int, Field(ge=0, le=U16_MAX)]
    origin: Annotated[str, Field(min_length=1, max_length=128)]
    endpoint: Annotated[str, Field(min_length=1, max_length=160)]
    checked_at_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    checked_at_block_hash: BlockHash
    status_code: Literal[200]
    body_sha256: Hex32
    body_size_bytes: Annotated[int, Field(ge=0, le=_MAX_HEALTH_BODY_BYTES)]
    tls_certificate_sha256: Hex32
    redirect_policy: Literal["disabled"]
    tls_server_authentication: Literal["system_trust_store/1"]
    checked_at: datetime

    @field_validator("miner_hotkey")
    @classmethod
    def validate_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value


class BootstrapHealthReceiptSet(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_HEALTH_SET_SCHEMA] = Field(alias="schema")
    manifest_sha256: Hex32
    checked_at_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    checked_at_block_hash: BlockHash
    receipts: Annotated[list[BootstrapHealthReceipt], Field(min_length=1, max_length=256)]


class BootstrapOperationalPreflight(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA] = Field(alias="schema")
    signed_manifest: SignedBootstrapEligibilityManifest
    cutover: BootstrapCutoverCheckpoint
    chain: BootstrapWeightPreflight
    pilot_replay: BootstrapPilotReplaySet
    health: BootstrapHealthReceiptSet

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        expected = self.signed_manifest.manifest_sha256
        if (
            self.chain.manifest_sha256 != expected
            or self.pilot_replay.manifest_sha256 != expected
            or self.health.manifest_sha256 != expected
        ):
            raise ValueError("operational preflight components bind different manifests")
        if self.cutover.policy_sha256 != self.chain.policy_sha256:
            raise ValueError("cutover checkpoint binds another policy")
        manifest = self.signed_manifest.manifest
        policy = manifest.policy
        if self.cutover.published_at_block != policy.published_at_block or (
            self.cutover.checkpoint_weights_version_key != policy.weights_version_key
        ):
            raise ValueError("cutover checkpoint does not match the signed policy")
        if not policy.activation_block <= self.cutover.checkpoint_block < policy.commit_stop_block:
            raise ValueError("cutover checkpoint is outside the active policy interval")
        if (
            self.health.checked_at_block != self.chain.snapshot.block_number
            or self.health.checked_at_block_hash != self.chain.snapshot.block_hash
        ):
            raise ValueError("health receipt set binds another chain snapshot")
        entries = manifest.entries
        if len(self.pilot_replay.receipts) != len(entries) or len(self.health.receipts) != len(
            entries
        ):
            raise ValueError("operational evidence does not cover every manifest entry")
        for entry, replay, health in zip(
            entries,
            self.pilot_replay.receipts,
            self.health.receipts,
            strict=True,
        ):
            expected_binding = (account_id32(entry.miner_hotkey), entry.uid, entry.origin)
            if (
                account_id32(replay.miner_hotkey),
                replay.uid,
                replay.origin,
            ) != expected_binding or (
                account_id32(health.miner_hotkey),
                health.uid,
                health.origin,
            ) != expected_binding:
                raise ValueError("operational evidence order or entry binding is invalid")
            if replay.pilot_id != entry.pilot_id or replay.manifest_sha256 != entry.pilot_id:
                raise ValueError("pilot replay binds another pilot")
            if health.endpoint != entry.origin + "/healthz":
                raise ValueError("health receipt binds another endpoint")
        return self


class BootstrapHealthHTTPResult(StrictProtocolModel):
    requested_url: Annotated[str, Field(min_length=1, max_length=160)]
    final_url: Annotated[str, Field(min_length=1, max_length=160)]
    status_code: Annotated[int, Field(ge=100, le=599)]
    body: bytes
    tls_certificate_sha256: Hex32


async def replay_bootstrap_pilots(
    signed: SignedBootstrapEligibilityManifest,
    *,
    fetch_bytes: Callable[[str, int], Any] | None = None,
) -> BootstrapPilotReplaySet:
    """Download and independently replay every manifest-bound component pilot."""

    fetch = fetch_bytes or _https_get_bytes
    policy = signed.manifest.policy
    receipts: list[BootstrapPilotReplayReceipt] = []
    for entry in signed.manifest.entries:
        pilot = await _download_and_replay_pilot(
            policy.public_evidence_origin,
            entry.pilot_id,
            fetch_bytes=fetch,
        )
        receipts.append(_pilot_replay_receipt(pilot, entry=entry, policy=policy))
    return BootstrapPilotReplaySet(
        schema=BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA,
        manifest_sha256=signed.manifest_sha256,
        public_evidence_origin=policy.public_evidence_origin,
        receipts=receipts,
    )


async def probe_bootstrap_health(
    signed: SignedBootstrapEligibilityManifest,
    chain: BootstrapWeightPreflight,
    *,
    request: Callable[[str], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> BootstrapHealthReceiptSet:
    """Probe every exact chain-announced ``/healthz`` endpoint without redirects."""

    requester = request or _https_health_request
    now = clock or (lambda: datetime.now(timezone.utc))
    receipts: list[BootstrapHealthReceipt] = []
    for entry in signed.manifest.entries:
        endpoint = entry.origin + "/healthz"
        raw = await requester(endpoint)
        result = (
            raw
            if isinstance(raw, BootstrapHealthHTTPResult)
            else BootstrapHealthHTTPResult.model_validate(raw)
        )
        if (
            result.requested_url != endpoint
            or httpx.URL(result.final_url) != httpx.URL(endpoint)
            or result.status_code != 200
        ):
            raise BootstrapOperatorError("miner_health_check_failed")
        if len(result.body) > _MAX_HEALTH_BODY_BYTES:
            raise BootstrapOperatorError("miner_health_body_limit")
        receipts.append(
            BootstrapHealthReceipt(
                miner_hotkey=entry.miner_hotkey,
                uid=entry.uid,
                origin=entry.origin,
                endpoint=endpoint,
                checked_at_block=chain.snapshot.block_number,
                checked_at_block_hash=chain.snapshot.block_hash,
                status_code=200,
                body_sha256=hashlib.sha256(result.body).hexdigest(),
                body_size_bytes=len(result.body),
                tls_certificate_sha256=result.tls_certificate_sha256,
                redirect_policy="disabled",
                tls_server_authentication="system_trust_store/1",
                checked_at=now(),
            )
        )
    return BootstrapHealthReceiptSet(
        schema=BOOTSTRAP_HEALTH_SET_SCHEMA,
        manifest_sha256=signed.manifest_sha256,
        checked_at_block=chain.snapshot.block_number,
        checked_at_block_hash=chain.snapshot.block_hash,
        receipts=receipts,
    )


async def build_operational_preflight(
    signed: SignedBootstrapEligibilityManifest,
    cutover: BootstrapCutoverCheckpoint,
    chain: BootstrapWeightPreflight,
    *,
    fetch_bytes: Callable[[str, int], Any] | None = None,
    health_request: Callable[[str], Any] | None = None,
    clock: Callable[[], datetime] | None = None,
) -> BootstrapOperationalPreflight:
    """Replay pilot evidence and collect fresh health receipts for one chain snapshot."""

    replay, health = await asyncio.gather(
        replay_bootstrap_pilots(signed, fetch_bytes=fetch_bytes),
        probe_bootstrap_health(signed, chain, request=health_request, clock=clock),
    )
    return BootstrapOperationalPreflight(
        schema=BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA,
        signed_manifest=signed,
        cutover=cutover,
        chain=chain,
        pilot_replay=replay,
        health=health,
    )


class BootstrapWeightScheduleEvidence(StrictProtocolModel):
    block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_hash: BlockHash
    tempo: Annotated[int, Field(gt=0, le=U16_MAX)]
    last_epoch_block: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    pending_epoch_at: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    subnet_epoch_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    blocks_since_last_step: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    reveal_period_epochs: Annotated[int, Field(gt=0, le=_MAX_U64)]
    block_time: Annotated[float, Field(gt=0, le=60)]
    weights_version_key: Annotated[int, Field(gt=0, le=_MAX_U64)]
    commit_reveal_enabled: Literal[True]
    commit_reveal_version: Literal[4]
    mechanism_count: Literal[1]

    def core_schedule(self) -> WeightScheduleSnapshot:
        return WeightScheduleSnapshot(
            block_number=self.block_number,
            block_hash=self.block_hash,
            tempo=self.tempo,
            last_epoch_block=self.last_epoch_block,
            pending_epoch_at=self.pending_epoch_at,
            subnet_epoch_index=self.subnet_epoch_index,
            blocks_since_last_step=self.blocks_since_last_step,
            reveal_period_epochs=self.reveal_period_epochs,
            block_time=self.block_time,
        )


class BootstrapManifestAnchorObservation(StrictProtocolModel):
    manifest_sha256: Hex32
    anchor: BootstrapExtrinsicReference
    observation_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    observation_block_hash: BlockHash
    stored_commitment_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    field_count: Literal[1]
    field_type: Literal["Data::Sha256"]
    field_sha256: Hex32
    sdk_finalized_read_verified: Literal[True]
    storage_proofs_verified: Literal[False] = False

    @model_validator(mode="after")
    def validate_anchor(self) -> Self:
        if self.manifest_sha256 != self.field_sha256:
            raise ValueError("manifest anchor observation contains another digest")
        if self.stored_commitment_block != self.anchor.block_number:
            raise ValueError("manifest anchor storage value names another block")
        if self.observation_block < self.anchor.block_number:
            raise ValueError("manifest anchor observation predates inclusion")
        return self


class BootstrapWeightCallMaterial(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_CALL_MATERIAL_SCHEMA] = Field(alias="schema")
    preflight_sha256: Hex32
    manifest_sha256: Hex32
    pilot_replay_sha256: Hex32
    health_receipts_sha256: Hex32
    operational_preflight: BootstrapOperationalPreflight
    manifest_anchor: BootstrapManifestAnchorObservation | None = None
    schedule: BootstrapWeightScheduleEvidence
    schedule_block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    schedule_block_hash: BlockHash
    hotkey_public_key: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    uids: Annotated[list[int], Field(min_length=1, max_length=256)]
    weights: Annotated[list[int], Field(min_length=1, max_length=256)]
    weights_version_key: Annotated[int, Field(gt=0, le=_MAX_U64)]
    ciphertext: Annotated[str, Field(pattern=r"^0x[0-9a-f]+$", max_length=262_146)]
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_U64)]
    call_module: Literal["SubtensorModule"]
    call_function: Literal["commit_timelocked_mechanism_weights"]
    netuid: Literal[78]
    mechanism_id: Literal[0]
    commit_reveal_version: Literal[4]

    @model_validator(mode="after")
    def validate_preflight_hashes(self) -> Self:
        operational = canonical_json_bytes(self.operational_preflight)
        if hashlib.sha256(operational).hexdigest() != self.preflight_sha256:
            raise ValueError("call material preflight hash is invalid")
        if self.manifest_sha256 != self.operational_preflight.chain.manifest_sha256:
            raise ValueError("call material binds another manifest")
        if (
            hashlib.sha256(
                canonical_json_bytes(self.operational_preflight.pilot_replay)
            ).hexdigest()
            != self.pilot_replay_sha256
        ):
            raise ValueError("call material pilot replay hash is invalid")
        if (
            hashlib.sha256(canonical_json_bytes(self.operational_preflight.health)).hexdigest()
            != self.health_receipts_sha256
        ):
            raise ValueError("call material health receipt hash is invalid")
        chain = self.operational_preflight.chain
        if (
            self.schedule_block_number != self.schedule.block_number
            or self.schedule_block_hash != self.schedule.block_hash
            or self.weights_version_key != self.schedule.weights_version_key
            or self.weights_version_key != chain.snapshot.weights_version_key
            or self.uids != chain.quantized_uids
            or self.weights != chain.quantized_weights
            or self.hotkey_public_key != "0x" + account_id32(chain.validator_hotkey).hex()
        ):
            raise ValueError("call material core inputs do not match the preflight")
        if self.schedule.core_schedule().block_number < chain.snapshot.block_number:
            raise ValueError("call material schedule predates its finalized preflight")
        if self.manifest_anchor is not None and (
            self.manifest_anchor.manifest_sha256 != self.manifest_sha256
            or self.manifest_anchor.observation_block > chain.snapshot.block_number
        ):
            raise ValueError("call material anchor observation is not bound to its preflight")
        return self


class BootstrapExtrinsicReference(StrictProtocolModel):
    extrinsic_id: Annotated[str, Field(min_length=1, max_length=128)]
    block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    extrinsic_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_hash: BlockHash

    @model_validator(mode="after")
    def validate_extrinsic_id(self) -> Self:
        if self.extrinsic_id != f"{self.block_number}-{self.extrinsic_index:04d}":
            raise ValueError("extrinsic ID is not canonical BLOCK-INDEX")
        return self


class BootstrapWeightSubmissionReceipt(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA] = Field(alias="schema")
    status: Literal[
        "anchor_finalized_commit_not_submitted",
        "commit_finalized_pending_terminal_verification",
        "commit_finalized_nonconforming",
    ]
    reason_code: Annotated[str, Field(min_length=1, max_length=128)] | None
    manifest_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    anchor: BootstrapExtrinsicReference
    commit: BootstrapExtrinsicReference | None
    call_material_sha256: Hex32 | None
    commit_epoch_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)] | None = None
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_U64)] | None = None
    ciphertext_sha256: Hex32 | None = None
    exact_commit_entry_observed: bool = False
    submission_era_period: Literal[8]
    storage_proofs_verified: Literal[False] = False
    terminal_verification_complete: Literal[False] = False
    created_at: datetime

    @field_validator("validator_hotkey")
    @classmethod
    def validate_validator_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_terminal_fields(self) -> Self:
        if self.status == "commit_finalized_pending_terminal_verification":
            if (
                self.reason_code is not None
                or self.commit is None
                or self.call_material_sha256 is None
                or self.commit_epoch_index is None
                or self.reveal_round is None
                or self.ciphertext_sha256 is None
                or not self.exact_commit_entry_observed
            ):
                raise ValueError("successful bootstrap receipt is missing commit evidence")
        elif self.status == "commit_finalized_nonconforming":
            if self.reason_code is None or self.commit is None or self.call_material_sha256 is None:
                raise ValueError("nonconforming bootstrap receipt is missing evidence")
        elif self.reason_code is None or self.commit is not None:
            raise ValueError("partial bootstrap receipt has inconsistent fields")
        if self.commit is None and any(
            value is not None
            for value in (self.commit_epoch_index, self.reveal_round, self.ciphertext_sha256)
        ):
            raise ValueError("receipt has commit details without a commit")
        return self


class BootstrapTerminalEvent(StrictProtocolModel):
    block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_hash: BlockHash
    event_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    extrinsic_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)] | None
    event: Literal["TimelockedWeightsCommitted", "TimelockedWeightsRevealed"]
    commitment_blake2b256: Hex32 | None = None
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_U64)] | None = None
    payload_sha256: Hex32

    @model_validator(mode="after")
    def validate_event_fields(self) -> Self:
        if self.event == "TimelockedWeightsCommitted":
            if self.commitment_blake2b256 is None or self.reveal_round is None:
                raise ValueError("commit event lacks ciphertext and reveal-round binding")
        elif self.commitment_blake2b256 is not None or self.reveal_round is not None:
            raise ValueError("reveal event contains commit-only fields")
        return self


class BootstrapRevealPeriodObservation(StrictProtocolModel):
    block_number: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    block_hash: BlockHash
    reveal_period_epochs: Annotated[int, Field(ge=0, le=_MAX_U64)]


class BootstrapTerminalObservation(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_TERMINAL_OBSERVATION_SCHEMA] = Field(alias="schema")
    classification: Literal["pending", "applied", "failed"]
    reason_codes: Annotated[list[str], Field(max_length=32)]
    policy_sha256: Hex32
    manifest_sha256: Hex32
    call_material_sha256: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    commit: BootstrapExtrinsicReference
    commit_epoch_index: Annotated[int, Field(ge=0, le=_MAX_JSON_SAFE_INTEGER)]
    reveal_round: Annotated[int, Field(gt=0, le=_MAX_U64)]
    ciphertext_sha256: Hex32
    observation_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    observation_block_hash: BlockHash
    expected_row: Annotated[list[list[int]], Field(min_length=1, max_length=256)]
    observed_row: Annotated[list[list[int]], Field(max_length=256)]
    mapping_checks_passed: bool
    validator_pending_commit: bool
    exact_epoch_entry_present: bool
    exact_epoch_queue_removal_observed: bool
    commit_event_unique_and_bound: bool
    duplicate_commit_absent: bool
    reveal_event_unique_and_bound: bool
    reveal_period_history_stable: bool
    row_matches_expected: bool
    sdk_finalized_reads_verified: Literal[True]
    commit_events: Annotated[list[BootstrapTerminalEvent], Field(max_length=4)]
    reveal_events: Annotated[list[BootstrapTerminalEvent], Field(max_length=4)]
    reveal_period_history: Annotated[
        list[BootstrapRevealPeriodObservation], Field(min_length=1, max_length=2_049)
    ]
    event_interval_start: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    event_interval_end: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    event_storage_proofs_verified: Literal[False] = False
    exact_queue_removal_sdk_observed: bool
    row_storage_proof_verified: Literal[False] = False
    protocol_terminal_classification_verified: bool

    @field_validator("validator_hotkey")
    @classmethod
    def validate_terminal_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def validate_terminal_observation(self) -> Self:
        if self.event_interval_start > self.event_interval_end:
            raise ValueError("terminal event interval is reversed")
        if self.classification == "pending":
            if not self.validator_pending_commit or not self.exact_epoch_entry_present:
                raise ValueError("pending classification lacks its exact queue entry")
            if (
                self.exact_epoch_queue_removal_observed
                or self.exact_queue_removal_sdk_observed
                or self.protocol_terminal_classification_verified
            ):
                raise ValueError("pending classification cannot be terminal")
        elif self.classification == "applied":
            required = (
                self.exact_epoch_queue_removal_observed,
                self.exact_queue_removal_sdk_observed,
                self.commit_event_unique_and_bound,
                self.duplicate_commit_absent,
                self.reveal_event_unique_and_bound,
                self.reveal_period_history_stable,
                self.mapping_checks_passed,
                self.row_matches_expected,
                self.protocol_terminal_classification_verified,
            )
            if (
                self.reason_codes
                or not all(required)
                or self.validator_pending_commit
                or self.exact_epoch_entry_present
            ):
                raise ValueError("applied classification lacks complete SDK evidence")
        elif (
            not self.reason_codes
            or not self.protocol_terminal_classification_verified
            or not self.exact_epoch_queue_removal_observed
            or not self.exact_queue_removal_sdk_observed
            or self.exact_epoch_entry_present
        ):
            raise ValueError("failed classification lacks a terminal reason or removal")
        return self


class SignedBootstrapTerminalObservation(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_TERMINAL_SIGNATURE_SCHEMA] = Field(alias="schema")
    observation: BootstrapTerminalObservation
    observation_sha256: Hex32
    observation_digest: Hex32
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def validate_signature(self) -> Self:
        body = canonical_json_bytes(self.observation)
        digest = hashlib.sha256(_TERMINAL_SIGNATURE_DOMAIN + body).digest()
        if (
            hashlib.sha256(body).hexdigest() != self.observation_sha256
            or digest.hex() != self.observation_digest
            or account_id32(self.validator_hotkey)
            != account_id32(self.observation.validator_hotkey)
            or not verify_response_signature(
                digest,
                hotkey_ss58=self.validator_hotkey,
                scheme=self.signature_scheme,
                signature=self.signature,
            )
        ):
            raise ValueError("bootstrap terminal signature is invalid")
        return self


class BootstrapSunsetStatus(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_SUNSET_STATUS_SCHEMA] = Field(alias="schema")
    status: Literal[
        "pre_activation",
        "commit_interval_open",
        "commits_closed_awaiting_sunset",
        "sunset_clean_sdk_observation",
        "sunset_incident_sdk_observation",
    ]
    policy_sha256: Hex32
    policy_coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    manifest_sha256: Hex32
    observation_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    observation_block_hash: BlockHash
    commit_stop_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    hard_sunset_block: Annotated[int, Field(gt=0, le=_MAX_JSON_SAFE_INTEGER)]
    # This observer does not accept a published, signed applied-terminal index, so
    # it must not independently claim that service weights are live.
    service_weights_active: Literal[False] = False
    total_pending_commit_count: Annotated[int, Field(ge=0, le=_MAX_U64)]
    active_mechid0_row_hotkeys: Annotated[list[str], Field(max_length=65_536)]
    subnet_emission_enabled: bool
    storage_proofs_verified: Literal[False] = False


class SignedBootstrapSunsetStatus(StrictProtocolModel):
    schema_: Literal[BOOTSTRAP_SUNSET_SIGNATURE_SCHEMA] = Field(alias="schema")
    status: BootstrapSunsetStatus
    status_sha256: Hex32
    status_digest: Hex32
    coordinator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    signature_scheme: Literal["sr25519", "ed25519"]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]

    @model_validator(mode="after")
    def validate_signature(self) -> Self:
        body = canonical_json_bytes(self.status)
        digest = hashlib.sha256(_SUNSET_SIGNATURE_DOMAIN + body).digest()
        if (
            hashlib.sha256(body).hexdigest() != self.status_sha256
            or digest.hex() != self.status_digest
            or account_id32(self.coordinator_hotkey)
            != account_id32(self.status.policy_coordinator_hotkey)
            or not verify_response_signature(
                digest,
                hotkey_ss58=self.coordinator_hotkey,
                scheme=self.signature_scheme,
                signature=self.signature,
            )
        ):
            raise ValueError("bootstrap sunset signature is invalid")
        return self


def validate_bootstrap_preflight(
    signed: SignedBootstrapEligibilityManifest,
    snapshot: BootstrapChainSnapshot,
    *,
    validator_hotkey: str,
    require_clean_cutover: bool = False,
    prior_terminal: BootstrapTerminalObservation | None = None,
    now: datetime | None = None,
) -> BootstrapWeightPreflight:
    """Validate one complete, finalized snapshot without chain I/O."""

    if not isinstance(snapshot, BootstrapChainSnapshot):
        raise TypeError("snapshot must be a BootstrapChainSnapshot")
    if snapshot.manifest_frozen_block_hash != signed.manifest.frozen_at_block_hash:
        raise BootstrapOperatorError("manifest_frozen_block_hash_mismatch")
    try:
        verify_signed_bootstrap_eligibility_manifest(
            signed,
            expected_coordinator_hotkey=signed.manifest.policy.coordinator_hotkey,
            current_block=snapshot.block_number,
        )
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("signed_manifest_invalid_or_stale") from error

    policy = signed.manifest.policy
    if snapshot.block_number >= policy.commit_stop_block:
        raise BootstrapOperatorError("bootstrap_commit_interval_closed")
    observed_now = now or datetime.now(timezone.utc)
    now_ms = _datetime_ms(observed_now)
    if snapshot.block_timestamp_ms < now_ms - _MAX_FINALIZED_HEAD_AGE_MS:
        raise BootstrapOperatorError("finalized_head_stale")
    if snapshot.block_timestamp_ms > now_ms + _MAX_FINALIZED_FUTURE_SKEW_MS:
        raise BootstrapOperatorError("finalized_head_future_dated")
    expected_scalars = (
        (snapshot.mechanism_count, 1, "mechanism_count_mismatch"),
        (snapshot.commit_reveal_enabled, True, "commit_reveal_disabled"),
        (snapshot.commit_reveal_version, COMMIT_REVEAL_VERSION, "commit_reveal_version_mismatch"),
        (snapshot.reveal_period_epochs, 1, "reveal_period_mismatch"),
        (snapshot.weights_version_key, policy.weights_version_key, "weights_version_key_mismatch"),
        (snapshot.tempo, 360, "tempo_mismatch"),
        (snapshot.activity_cutoff_blocks, 360, "activity_cutoff_mismatch"),
        (snapshot.block_time_seconds, 12.0, "block_time_mismatch"),
    )
    for actual, expected, reason in expected_scalars:
        if actual != expected:
            raise BootstrapOperatorError(reason)
    if snapshot.validator_has_pending_commit:
        raise BootstrapOperatorError("validator_pending_commit_exists")
    if require_clean_cutover:
        if snapshot.total_pending_commit_count:
            raise BootstrapOperatorError("pre_bootstrap_pending_commits_exist")
        if snapshot.active_mechid0_row_hotkeys:
            raise BootstrapOperatorError("pre_bootstrap_active_rows_exist")

    by_account = {account_id32(item.hotkey): item for item in snapshot.participants}
    validator = by_account.get(account_id32(validator_hotkey))
    if validator is None:
        raise BootstrapOperatorError("validator_not_registered")
    if not validator.validator_permit:
        raise BootstrapOperatorError("validator_permit_missing")
    prior_terminal_sha256: str | None = None
    if snapshot.validator_mechid0_row:
        if validator.last_update + snapshot.activity_cutoff_blocks >= snapshot.block_number:
            if (
                prior_terminal is None
                or prior_terminal.classification != "applied"
                or prior_terminal.policy_sha256 != bootstrap_policy_hash(policy)
                or account_id32(prior_terminal.validator_hotkey) != account_id32(validator.hotkey)
                or prior_terminal.observed_row != snapshot.validator_mechid0_row
                or prior_terminal.observation_block > snapshot.block_number
            ):
                raise BootstrapOperatorError("previous_validator_row_active")
            prior_row_classification: Literal["empty", "inactive", "active_prior_bootstrap"] = (
                "active_prior_bootstrap"
            )
            prior_terminal_sha256 = hashlib.sha256(canonical_json_bytes(prior_terminal)).hexdigest()
        else:
            prior_row_classification = "inactive"
    else:
        prior_row_classification = "empty"
    if validator.last_update + snapshot.weights_set_rate_limit > snapshot.block_number:
        raise BootstrapOperatorError("weights_rate_limit_not_elapsed")

    manifest_accounts: set[bytes] = set()
    for entry in signed.manifest.entries:
        account = account_id32(entry.miner_hotkey)
        participant = by_account.get(account)
        if participant is None:
            raise BootstrapOperatorError("eligible_miner_not_registered")
        if participant.validator_permit:
            raise BootstrapOperatorError("eligible_miner_has_validator_permit")
        if participant.uid != entry.uid:
            raise BootstrapOperatorError("eligible_miner_uid_mismatch")
        if participant.origin != entry.origin:
            raise BootstrapOperatorError("eligible_miner_origin_mismatch")
        manifest_accounts.add(account)
    if account_id32(validator_hotkey) in manifest_accounts:
        raise BootstrapOperatorError("validator_is_eligible_miner")

    row = signed.manifest.quantized_row
    if len(row) < snapshot.min_allowed_weights:
        raise BootstrapOperatorError("row_below_min_allowed_weights")
    if len(row) > snapshot.max_allowed_uids or any(
        item.uid >= snapshot.max_allowed_uids for item in row
    ):
        raise BootstrapOperatorError("row_exceeds_uid_limit")
    if snapshot.max_weights_limit == 0 or len(row) * snapshot.max_weights_limit < U16_MAX:
        raise BootstrapOperatorError("row_exceeds_max_weight_ratio")
    quantized_total = len(row) * U16_MAX
    if snapshot.max_weights_limit * quantized_total < U16_MAX * U16_MAX:
        raise BootstrapOperatorError("row_exceeds_max_weight_ratio")

    return BootstrapWeightPreflight(
        schema=BOOTSTRAP_PREFLIGHT_SCHEMA,
        manifest_sha256=signed.manifest_sha256,
        policy_sha256=bootstrap_policy_hash(policy),
        snapshot=snapshot,
        validator_hotkey=validator.hotkey,
        validator_uid=validator.uid,
        prior_row_classification=prior_row_classification,
        prior_terminal_sha256=prior_terminal_sha256,
        clean_cutover_enforced=require_clean_cutover,
        eligible_miner_count=len(row),
        quantized_uids=[item.uid for item in row],
        quantized_weights=[item.value for item in row],
    )


def build_bootstrap_weight_call_material(
    preflight: BootstrapOperationalPreflight,
    *,
    schedule_snapshot: BootstrapWeightScheduleEvidence | WeightScheduleSnapshot | None = None,
    manifest_anchor: BootstrapManifestAnchorObservation | None = None,
    call_builder: Callable[..., BuiltCRv4WeightCommit] = build_crv4_weight_commit,
) -> tuple[BootstrapWeightCallMaterial, BuiltCRv4WeightCommit]:
    """Build exact unsigned CRv4 material from one explicit schedule snapshot."""

    if not isinstance(preflight, BootstrapOperationalPreflight):
        raise TypeError("preflight must be a BootstrapOperationalPreflight")
    snapshot = preflight.chain.snapshot
    if isinstance(schedule_snapshot, BootstrapWeightScheduleEvidence):
        schedule_evidence = schedule_snapshot
    else:
        schedule_core = schedule_snapshot or WeightScheduleSnapshot(
            block_number=snapshot.block_number,
            block_hash=snapshot.block_hash,
            tempo=snapshot.tempo,
            last_epoch_block=snapshot.last_epoch_block,
            pending_epoch_at=snapshot.pending_epoch_at,
            subnet_epoch_index=snapshot.subnet_epoch_index,
            blocks_since_last_step=snapshot.blocks_since_last_step,
            reveal_period_epochs=snapshot.reveal_period_epochs,
            block_time=snapshot.block_time_seconds,
        )
        schedule_evidence = BootstrapWeightScheduleEvidence(
            block_number=schedule_core.block_number,
            block_hash=schedule_core.block_hash,
            tempo=schedule_core.tempo,
            last_epoch_block=schedule_core.last_epoch_block,
            pending_epoch_at=schedule_core.pending_epoch_at,
            subnet_epoch_index=schedule_core.subnet_epoch_index,
            blocks_since_last_step=schedule_core.blocks_since_last_step,
            reveal_period_epochs=schedule_core.reveal_period_epochs,
            block_time=schedule_core.block_time,
            weights_version_key=snapshot.weights_version_key,
            commit_reveal_enabled=True,
            commit_reveal_version=COMMIT_REVEAL_VERSION,
            mechanism_count=1,
        )
    schedule = schedule_evidence.core_schedule()
    if schedule.tempo != 360 or schedule.reveal_period_epochs != 1 or schedule.block_time != 12.0:
        raise BootstrapOperatorError("weight_schedule_runtime_mismatch")
    if schedule.block_number < snapshot.block_number:
        raise BootstrapOperatorError("weight_schedule_precedes_finalized_preflight")
    hotkey_public_key = account_id32(preflight.chain.validator_hotkey)
    built = call_builder(
        schedule=schedule,
        uids=preflight.chain.quantized_uids,
        weights=preflight.chain.quantized_weights,
        weights_version_key=preflight.chain.snapshot.weights_version_key,
        hotkey_public_key=hotkey_public_key,
        netuid=NETUID,
    )
    if (
        built.schedule != schedule
        or list(built.uids) != preflight.chain.quantized_uids
        or list(built.weights) != preflight.chain.quantized_weights
        or built.weights_version_key != snapshot.weights_version_key
        or built.hotkey_public_key != hotkey_public_key
        or built.netuid != NETUID
    ):
        raise BootstrapOperatorError("weight_builder_output_binding_mismatch")
    if built.raw_call.module != "SubtensorModule" or built.raw_call.function != (
        "commit_timelocked_mechanism_weights"
    ):
        raise BootstrapOperatorError("raw_weight_call_shape_mismatch")
    params = built.raw_call.params
    if (
        params.get("netuid") != NETUID
        or params.get("mecid") != MECHANISM_ID
        or params.get("commit") != built.ciphertext
        or params.get("reveal_round") != built.reveal_round
        or params.get("commit_reveal_version") != COMMIT_REVEAL_VERSION
    ):
        raise BootstrapOperatorError("raw_weight_call_parameter_mismatch")
    preflight_bytes = canonical_json_bytes(preflight)
    material = BootstrapWeightCallMaterial(
        schema=BOOTSTRAP_CALL_MATERIAL_SCHEMA,
        preflight_sha256=hashlib.sha256(preflight_bytes).hexdigest(),
        manifest_sha256=preflight.chain.manifest_sha256,
        pilot_replay_sha256=hashlib.sha256(
            canonical_json_bytes(preflight.pilot_replay)
        ).hexdigest(),
        health_receipts_sha256=hashlib.sha256(canonical_json_bytes(preflight.health)).hexdigest(),
        operational_preflight=preflight,
        manifest_anchor=manifest_anchor,
        schedule=schedule_evidence,
        schedule_block_number=schedule.block_number,
        schedule_block_hash=schedule.block_hash,
        hotkey_public_key="0x" + hotkey_public_key.hex(),
        uids=list(built.uids),
        weights=list(built.weights),
        weights_version_key=built.weights_version_key,
        ciphertext="0x" + built.ciphertext.hex(),
        reveal_round=built.reveal_round,
        call_module=built.raw_call.module,
        call_function=built.raw_call.function,
        netuid=NETUID,
        mechanism_id=MECHANISM_ID,
        commit_reveal_version=COMMIT_REVEAL_VERSION,
    )
    return material, built


class BittensorBootstrapChain:
    """Read one internally checked finalized Finney snapshot for preflight."""

    def __init__(
        self,
        *,
        client_factory: Callable[[str], Any] | None = None,
        finalized_timeout_seconds: float = 20.0,
        clock: Callable[[], datetime] | None = None,
        checkout_verifier: Callable[[BootstrapWeightPolicy], None] | None = None,
    ) -> None:
        if finalized_timeout_seconds <= 0 or finalized_timeout_seconds > 300:
            raise ValueError("finalized timeout must be in (0, 300] seconds")
        self.client_factory = client_factory or (lambda network: bt.Client(network))
        self.finalized_timeout_seconds = float(finalized_timeout_seconds)
        self.clock = clock or (lambda: datetime.now(timezone.utc))
        self.checkout_verifier = checkout_verifier or verify_runtime_checkout

    async def preflight(
        self,
        signed: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
        require_clean_cutover: bool = False,
        prior_terminal: BootstrapTerminalObservation | None = None,
    ) -> BootstrapWeightPreflight:
        async with self.client_factory("finney") as client:
            return await self.preflight_with_client(
                client,
                signed,
                validator_hotkey=validator_hotkey,
                require_clean_cutover=require_clean_cutover,
                prior_terminal=prior_terminal,
            )

    async def preflight_with_client(
        self,
        client: Any,
        signed: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
        require_clean_cutover: bool = False,
        prior_terminal: BootstrapTerminalObservation | None = None,
    ) -> BootstrapWeightPreflight:
        snapshot = await self._snapshot(client, signed, validator_hotkey=validator_hotkey)
        return validate_bootstrap_preflight(
            signed,
            snapshot,
            validator_hotkey=validator_hotkey,
            require_clean_cutover=require_clean_cutover,
            prior_terminal=prior_terminal,
            now=self.clock(),
        )

    async def operational_preflight(
        self,
        signed: SignedBootstrapEligibilityManifest,
        *,
        cutover: BootstrapCutoverCheckpoint,
        validator_hotkey: str,
        require_clean_cutover: bool = False,
        prior_terminal: BootstrapTerminalObservation | None = None,
        fetch_bytes: Callable[[str, int], Any] | None = None,
        health_request: Callable[[str], Any] | None = None,
    ) -> BootstrapOperationalPreflight:
        """Run chain, historical cutover, pilot, and endpoint checks read-only."""

        async with self.client_factory("finney") as client:
            return await self.operational_preflight_with_client(
                client,
                signed,
                cutover=cutover,
                validator_hotkey=validator_hotkey,
                require_clean_cutover=require_clean_cutover,
                prior_terminal=prior_terminal,
                fetch_bytes=fetch_bytes,
                health_request=health_request,
            )

    async def operational_preflight_with_client(
        self,
        client: Any,
        signed: SignedBootstrapEligibilityManifest,
        *,
        cutover: BootstrapCutoverCheckpoint,
        validator_hotkey: str,
        require_clean_cutover: bool = False,
        prior_terminal: BootstrapTerminalObservation | None = None,
        fetch_bytes: Callable[[str, int], Any] | None = None,
        health_request: Callable[[str], Any] | None = None,
    ) -> BootstrapOperationalPreflight:
        self.checkout_verifier(signed.manifest.policy)
        chain = await self.preflight_with_client(
            client,
            signed,
            validator_hotkey=validator_hotkey,
            require_clean_cutover=require_clean_cutover,
            prior_terminal=prior_terminal,
        )
        observed_cutover = await self.cutover_checkpoint_with_client(
            client,
            signed.manifest.policy,
            checkpoint_block=cutover.checkpoint_block,
        )
        if observed_cutover != cutover:
            raise BootstrapOperatorError("cutover_checkpoint_replay_mismatch")
        return await build_operational_preflight(
            signed,
            observed_cutover,
            chain,
            fetch_bytes=fetch_bytes,
            health_request=health_request,
            clock=self.clock,
        )

    async def cutover_checkpoint_with_client(
        self,
        client: Any,
        policy: BootstrapWeightPolicy,
        *,
        checkpoint_block: int,
    ) -> BootstrapCutoverCheckpoint:
        """Check the policy publication and frozen clean-cutover blocks."""

        if not isinstance(policy, BootstrapWeightPolicy):
            raise TypeError("policy must be a BootstrapWeightPolicy")
        if not policy.activation_block <= checkpoint_block < policy.commit_stop_block:
            raise BootstrapOperatorError("cutover_checkpoint_block_outside_policy")
        substrate = getattr(client, "_substrate", None)
        block_hash_reader = getattr(substrate, "block_hash", None)
        if not callable(block_hash_reader):
            raise BootstrapOperatorError("chain_identity_reader_missing")
        published_hash, frozen_hash = await asyncio.gather(
            block_hash_reader(policy.published_at_block),
            block_hash_reader(checkpoint_block),
        )
        if not _is_block_hash(published_hash) or not _is_block_hash(frozen_hash):
            raise BootstrapOperatorError("cutover_block_hash_unavailable")
        published = await client.at(policy.published_at_block)
        frozen = await client.at(checkpoint_block)
        direct = storage.SubtensorModule
        published_wvk = await published.query(direct.WeightsVersionKey, [NETUID])
        values = await asyncio.gather(
            frozen.subnets.metagraph(netuid=NETUID, commitments=False),
            frozen.query(direct.MechanismCountCurrent, [NETUID]),
            frozen.query(direct.CommitRevealWeightsEnabled, [NETUID]),
            frozen.query(direct.CommitRevealWeightsVersion),
            frozen.query(direct.RevealPeriodEpochs, [NETUID]),
            frozen.query(direct.WeightsVersionKey, [NETUID]),
            frozen.query(direct.ActivityCutoffFactorMilli, [NETUID]),
            frozen.query(direct.Tempo, [NETUID]),
            frozen.query(direct.ValidatorPermit, [NETUID]),
            frozen.query(direct.LastUpdate, [NETUID]),
            frozen.read("timelocked_weight_commits", netuid=NETUID, mechid=MECHANISM_ID),
        )
        (
            metagraph,
            mechanism_count,
            cr_enabled,
            cr_version,
            reveal_period,
            frozen_wvk,
            activity_factor,
            tempo,
            permits,
            last_updates,
            pending,
        ) = values
        frozen_block = checkpoint_block
        participants = _participants(
            metagraph,
            block_number=frozen_block,
            permits=permits,
            last_updates=last_updates,
        )
        rows = await asyncio.gather(
            *(frozen.query(direct.Weights, [NETUID, item.uid]) for item in participants)
        )
        tempo_value = _uint(tempo, "cutover_tempo_invalid", minimum=1, maximum=U16_MAX)
        factor = _uint(activity_factor, "cutover_activity_factor_invalid")
        cutoff = max(1, factor * tempo_value // 1_000)
        active = sorted(
            (
                item.hotkey
                for item, row in zip(participants, rows, strict=True)
                if _weight_row(row) and item.last_update + cutoff >= frozen_block
            ),
            key=account_id32,
        )
        pending_count, _ = _pending_commit_summary(
            pending,
            validator_hotkey=policy.coordinator_hotkey,
        )
        try:
            return BootstrapCutoverCheckpoint(
                schema=BOOTSTRAP_CUTOVER_CHECKPOINT_SCHEMA,
                policy_sha256=bootstrap_policy_hash(policy),
                published_at_block=policy.published_at_block,
                published_at_block_hash=published_hash,
                published_weights_version_key=_uint(
                    published_wvk,
                    "published_weights_version_key_invalid",
                ),
                checkpoint_block=frozen_block,
                checkpoint_block_hash=frozen_hash,
                checkpoint_weights_version_key=_uint(
                    frozen_wvk,
                    "frozen_weights_version_key_invalid",
                ),
                mechanism_count=_uint(
                    mechanism_count,
                    "cutover_mechanism_count_invalid",
                    maximum=U16_MAX,
                ),
                commit_reveal_enabled=_bool(cr_enabled, "cutover_commit_reveal_invalid"),
                commit_reveal_version=_uint(
                    cr_version,
                    "cutover_commit_reveal_version_invalid",
                    maximum=U16_MAX,
                ),
                reveal_period_epochs=_uint(reveal_period, "cutover_reveal_period_invalid"),
                tempo=tempo_value,
                activity_cutoff_blocks=cutoff,
                total_pending_commit_count=pending_count,
                active_mechid0_row_hotkeys=active,
                storage_proofs_verified=False,
            )
        except ValidationError as error:
            raise BootstrapOperatorError("clean_cutover_checkpoint_failed") from error

    async def verify_manifest_anchor_with_client(
        self,
        client: Any,
        signed: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
        anchor: BootstrapExtrinsicReference,
        post_anchor: BootstrapWeightPreflight,
    ) -> BootstrapManifestAnchorObservation:
        """Repeat the exact live commitment read after anchor finality."""

        if post_anchor.snapshot.block_number < anchor.block_number:
            raise BootstrapOperatorError("manifest_anchor_observation_precedes_inclusion")
        pinned = await client.at(post_anchor.snapshot.block_number)
        info = await pinned.block_info()
        if (
            _uint(getattr(info, "number", None), "manifest_anchor_block_invalid")
            != post_anchor.snapshot.block_number
            or getattr(info, "hash", None) != post_anchor.snapshot.block_hash
        ):
            raise BootstrapOperatorError("manifest_anchor_snapshot_mismatch")
        value = await pinned.query(
            storage.Commitments.CommitmentOf,
            [NETUID, validator_hotkey],
        )
        stored_block = _exact_sha256_commitment(value, signed.manifest_sha256)
        if stored_block != anchor.block_number:
            raise BootstrapOperatorError("manifest_anchor_storage_block_mismatch")
        return BootstrapManifestAnchorObservation(
            manifest_sha256=signed.manifest_sha256,
            anchor=anchor,
            observation_block=post_anchor.snapshot.block_number,
            observation_block_hash=post_anchor.snapshot.block_hash,
            stored_commitment_block=stored_block,
            field_count=1,
            field_type="Data::Sha256",
            field_sha256=signed.manifest_sha256,
            sdk_finalized_read_verified=True,
            storage_proofs_verified=False,
        )

    async def current_schedule_with_client(
        self,
        client: Any,
        policy: BootstrapWeightPolicy,
    ) -> BootstrapWeightScheduleEvidence:
        """Read one explicit current-head schedule for the CRv4 builder."""

        head_reader = getattr(client, "block", None)
        if not callable(head_reader):
            raise BootstrapOperatorError("current_head_reader_missing")
        block_number = _uint(await head_reader(), "current_head_invalid", minimum=1)
        pinned = await client.at(block_number)
        direct = storage.SubtensorModule
        (
            info,
            tempo,
            last_epoch,
            pending_epoch,
            epoch,
            since,
            reveal,
            weights_version,
            cr_enabled,
            cr_version,
            mechanism_count,
            block_time,
        ) = await asyncio.gather(
            pinned.block_info(),
            pinned.query(direct.Tempo, [NETUID]),
            pinned.query(direct.LastEpochBlock, [NETUID]),
            pinned.query(direct.PendingEpochAt, [NETUID]),
            pinned.query(direct.SubnetEpochIndex, [NETUID]),
            pinned.query(direct.BlocksSinceLastStep, [NETUID]),
            pinned.query(direct.RevealPeriodEpochs, [NETUID]),
            pinned.query(direct.WeightsVersionKey, [NETUID]),
            pinned.query(direct.CommitRevealWeightsEnabled, [NETUID]),
            pinned.query(direct.CommitRevealWeightsVersion),
            pinned.query(direct.MechanismCountCurrent, [NETUID]),
            _block_time(getattr(client, "_substrate", None)),
        )
        if _uint(getattr(info, "number", None), "current_head_info_invalid") != block_number:
            raise BootstrapOperatorError("current_head_snapshot_mismatch")
        block_hash = getattr(info, "hash", None)
        if not _is_block_hash(block_hash):
            raise BootstrapOperatorError("current_head_hash_invalid")
        schedule = BootstrapWeightScheduleEvidence(
            block_number=block_number,
            block_hash=block_hash,
            tempo=_uint(tempo, "current_tempo_invalid", minimum=1, maximum=U16_MAX),
            last_epoch_block=_uint(last_epoch, "current_last_epoch_invalid"),
            pending_epoch_at=_uint(pending_epoch or 0, "current_pending_epoch_invalid"),
            subnet_epoch_index=_uint(epoch, "current_epoch_index_invalid"),
            blocks_since_last_step=_uint(since, "current_blocks_since_step_invalid"),
            reveal_period_epochs=_uint(reveal, "current_reveal_period_invalid"),
            block_time=block_time,
            weights_version_key=_uint(weights_version, "current_weights_version_invalid"),
            commit_reveal_enabled=_bool(cr_enabled, "current_commit_reveal_invalid"),
            commit_reveal_version=_uint(
                cr_version,
                "current_commit_reveal_version_invalid",
                maximum=U16_MAX,
            ),
            mechanism_count=_uint(
                mechanism_count,
                "current_mechanism_count_invalid",
                maximum=U16_MAX,
            ),
        )
        if (
            schedule.tempo != 360
            or schedule.reveal_period_epochs != 1
            or schedule.block_time != 12.0
        ):
            raise BootstrapOperatorError("weight_schedule_runtime_mismatch")
        if (
            schedule.weights_version_key != policy.weights_version_key
            or schedule.commit_reveal_enabled is not True
            or schedule.commit_reveal_version != COMMIT_REVEAL_VERSION
            or schedule.mechanism_count != 1
        ):
            raise BootstrapOperatorError("weight_schedule_chain_state_mismatch")
        return schedule

    async def _snapshot(
        self,
        client: Any,
        signed: SignedBootstrapEligibilityManifest,
        *,
        validator_hotkey: str,
        allow_missing_validator: bool = False,
    ) -> BootstrapChainSnapshot:
        substrate = getattr(client, "_substrate", None)
        block_hash_reader = getattr(substrate, "block_hash", None)
        if not callable(block_hash_reader):
            raise BootstrapOperatorError("chain_identity_reader_missing")
        genesis_hash = await block_hash_reader(0)
        if genesis_hash != _FINNEY_GENESIS_HASH:
            raise BootstrapOperatorError("chain_is_not_finney")
        header = await _first_finalized_header(client, self.finalized_timeout_seconds)
        block_number = _uint(getattr(header, "number", None), "finalized_block_invalid", minimum=1)
        pinned = await client.at(block_number)
        if _uint(getattr(pinned, "block", None), "snapshot_block_invalid") != block_number:
            raise BootstrapOperatorError("snapshot_block_mismatch")
        frozen_hash = await block_hash_reader(signed.manifest.frozen_at_block)
        if not _is_block_hash(frozen_hash):
            raise BootstrapOperatorError("manifest_frozen_block_unavailable")

        direct = storage.SubtensorModule
        results = await asyncio.gather(
            pinned.block_info(),
            pinned.subnets.metagraph(netuid=NETUID, commitments=False),
            pinned.query(direct.MechanismCountCurrent, [NETUID]),
            pinned.query(direct.CommitRevealWeightsEnabled, [NETUID]),
            pinned.query(direct.CommitRevealWeightsVersion),
            pinned.query(direct.RevealPeriodEpochs, [NETUID]),
            pinned.query(direct.WeightsVersionKey, [NETUID]),
            pinned.query(direct.MinAllowedWeights, [NETUID]),
            pinned.query(direct.MaxWeightsLimit, [NETUID]),
            pinned.query(direct.MaxAllowedUids, [NETUID]),
            pinned.query(direct.WeightsSetRateLimit, [NETUID]),
            pinned.query(direct.ActivityCutoffFactorMilli, [NETUID]),
            pinned.query(direct.Tempo, [NETUID]),
            pinned.query(direct.LastEpochBlock, [NETUID]),
            pinned.query(direct.PendingEpochAt, [NETUID]),
            pinned.query(direct.SubnetEpochIndex, [NETUID]),
            pinned.query(direct.BlocksSinceLastStep, [NETUID]),
            pinned.query(direct.ValidatorPermit, [NETUID]),
            pinned.query(direct.LastUpdate, [NETUID]),
            pinned.read("timelocked_weight_commits", netuid=NETUID, mechid=MECHANISM_ID),
            _block_time(substrate),
        )
        (
            block_info,
            metagraph,
            mechanism_count,
            commit_reveal_enabled,
            commit_reveal_version,
            reveal_period,
            weights_version,
            minimum,
            maximum,
            max_allowed_uids,
            weights_rate_limit,
            activity_factor,
            tempo,
            last_epoch,
            pending_epoch,
            epoch_index,
            blocks_since_last_step,
            permits,
            last_updates,
            pending_commits,
            block_time,
        ) = results
        block_hash, timestamp_ms = _validate_finalized_block(header, block_info, block_number)
        participants = _participants(
            metagraph,
            block_number=block_number,
            permits=permits,
            last_updates=last_updates,
        )
        validator_matches = [
            item
            for item in participants
            if account_id32(item.hotkey) == account_id32(validator_hotkey)
        ]
        if len(validator_matches) == 1:
            validator = validator_matches[0]
            validator_row = await pinned.query(direct.Weights, [NETUID, validator.uid])
        elif allow_missing_validator and not validator_matches:
            validator = None
            validator_row = []
        else:
            raise BootstrapOperatorError("validator_not_uniquely_registered")
        tempo_value = _uint(tempo, "tempo_invalid", minimum=1, maximum=U16_MAX)
        factor_value = _uint(activity_factor, "activity_cutoff_factor_invalid")
        cutoff_value = max(1, factor_value * tempo_value // 1_000)
        all_rows = await asyncio.gather(
            *(pinned.query(direct.Weights, [NETUID, item.uid]) for item in participants)
        )
        parsed_rows = [_weight_row(value) for value in all_rows]
        active_row_hotkeys = sorted(
            (
                item.hotkey
                for item, row in zip(participants, parsed_rows, strict=True)
                if row and item.last_update + cutoff_value >= block_number
            ),
            key=account_id32,
        )
        pending_count, validator_pending = _pending_commit_summary(
            pending_commits,
            validator_hotkey=validator_hotkey,
        )
        return BootstrapChainSnapshot(
            network="finney",
            genesis_block_hash=genesis_hash,
            block_number=block_number,
            block_hash=block_hash,
            block_timestamp_ms=timestamp_ms,
            manifest_frozen_block_hash=frozen_hash,
            mechanism_count=_uint(mechanism_count, "mechanism_count_invalid", maximum=U16_MAX),
            commit_reveal_enabled=_bool(commit_reveal_enabled, "commit_reveal_enabled_invalid"),
            commit_reveal_version=_uint(
                commit_reveal_version,
                "commit_reveal_version_invalid",
                maximum=U16_MAX,
            ),
            reveal_period_epochs=_uint(reveal_period, "reveal_period_invalid"),
            weights_version_key=_uint(weights_version, "weights_version_key_invalid"),
            min_allowed_weights=_uint(minimum, "min_allowed_weights_invalid", maximum=U16_MAX),
            max_weights_limit=_uint(maximum, "max_weights_limit_invalid", maximum=U16_MAX),
            max_allowed_uids=_uint(
                max_allowed_uids,
                "max_allowed_uids_invalid",
                minimum=1,
                maximum=U16_MAX,
            ),
            weights_set_rate_limit=_uint(
                weights_rate_limit,
                "weights_set_rate_limit_invalid",
            ),
            activity_cutoff_blocks=cutoff_value,
            validator_mechid0_row=_weight_row(validator_row),
            validator_has_pending_commit=validator_pending,
            total_pending_commit_count=pending_count,
            active_mechid0_row_hotkeys=active_row_hotkeys,
            storage_proofs_verified=False,
            tempo=tempo_value,
            last_epoch_block=_uint(last_epoch, "last_epoch_block_invalid"),
            pending_epoch_at=_uint(pending_epoch or 0, "pending_epoch_at_invalid"),
            subnet_epoch_index=_uint(epoch_index, "subnet_epoch_index_invalid"),
            blocks_since_last_step=_uint(
                blocks_since_last_step,
                "blocks_since_last_step_invalid",
            ),
            block_time_seconds=block_time,
            participants=participants,
        )


async def observe_bootstrap_terminal(
    signed: SignedBootstrapEligibilityManifest,
    receipt: BootstrapWeightSubmissionReceipt,
    material: BootstrapWeightCallMaterial,
    *,
    chain: BittensorBootstrapChain,
) -> BootstrapTerminalObservation:
    """Classify one exact commit from repeatable finalized SDK observations."""

    chain.checkout_verifier(signed.manifest.policy)
    _verify_historical_signed_manifest(signed)
    if receipt.commit is None or receipt.call_material_sha256 is None:
        raise BootstrapOperatorError("terminal_receipt_has_no_commit")
    material_bytes = canonical_json_bytes(material)
    material_sha256 = hashlib.sha256(material_bytes).hexdigest()
    if (
        receipt.status != "commit_finalized_pending_terminal_verification"
        or receipt.manifest_sha256 != signed.manifest_sha256
        or material.manifest_sha256 != signed.manifest_sha256
        or receipt.call_material_sha256 != material_sha256
        or receipt.commit_epoch_index is None
        or receipt.reveal_round != material.reveal_round
        or receipt.ciphertext_sha256
        != hashlib.sha256(bytes.fromhex(material.ciphertext[2:])).hexdigest()
        or not receipt.exact_commit_entry_observed
        or account_id32(receipt.validator_hotkey)
        != account_id32(material.operational_preflight.chain.validator_hotkey)
        or material.manifest_anchor is None
        or material.manifest_anchor.anchor != receipt.anchor
    ):
        raise BootstrapOperatorError("terminal_input_binding_mismatch")
    commit_block = _extrinsic_block_number(receipt.commit)
    async with chain.client_factory("finney") as client:
        snapshot = await chain._snapshot(
            client,
            signed,
            validator_hotkey=receipt.validator_hotkey,
            allow_missing_validator=True,
        )
        if snapshot.block_number < commit_block:
            raise BootstrapOperatorError("terminal_observation_precedes_commit")
        if snapshot.block_number - commit_block > _MAX_TERMINAL_SCAN_BLOCKS:
            raise BootstrapOperatorError("terminal_event_scan_interval_limit")
        pinned = await client.at(snapshot.block_number)
        pending_now = await pinned.read(
            "timelocked_weight_commits",
            netuid=NETUID,
            mechid=MECHANISM_ID,
        )
        commit_events, reveal_events, period_history = await _scan_bootstrap_weight_events(
            client,
            start_block=commit_block,
            end_block=snapshot.block_number,
            validator_hotkey=receipt.validator_hotkey,
        )

    expected_row = [
        [uid, weight] for uid, weight in zip(material.uids, material.weights, strict=True)
    ]
    exact_present, any_validator_entry = _exact_pending_entry_present(
        pending_now,
        epoch=receipt.commit_epoch_index,
        validator_hotkey=receipt.validator_hotkey,
        commit_block=commit_block,
        ciphertext_sha256=receipt.ciphertext_sha256,
        reveal_round=material.reveal_round,
    )
    validator_matches = [
        item
        for item in snapshot.participants
        if account_id32(item.hotkey) == account_id32(receipt.validator_hotkey)
    ]
    validator_mapping_passed = (
        len(validator_matches) == 1
        and validator_matches[0].uid == material.operational_preflight.chain.validator_uid
        and validator_matches[0].validator_permit
    )
    destination_mappings_passed = _manifest_mappings_current(signed, snapshot)
    mapping_checks_passed = validator_mapping_passed and destination_mappings_passed
    expected_commitment_hash = hashlib.blake2b(
        bytes.fromhex(material.ciphertext[2:]),
        digest_size=32,
    ).hexdigest()
    commit_bound = (
        len(commit_events) == 1
        and commit_events[0].block_number == commit_block
        and commit_events[0].block_hash == receipt.commit.block_hash
        and commit_events[0].extrinsic_index == receipt.commit.extrinsic_index
        and commit_events[0].commitment_blake2b256 == expected_commitment_hash
        and commit_events[0].reveal_round == material.reveal_round
    )
    duplicate_absent = len(commit_events) == 1
    reveal_bound = len(reveal_events) == 1 and reveal_events[0].block_number >= commit_block
    period_stable = all(
        item.reveal_period_epochs == material.schedule.reveal_period_epochs
        for item in period_history
    )
    row_matches = snapshot.validator_mechid0_row == expected_row
    exact_removed = not exact_present
    reasons: list[str] = []
    if not period_stable:
        reasons.append("reveal_period_changed")
    if not destination_mappings_passed:
        reasons.append("destination_mapping_changed")
    if not validator_mapping_passed:
        reasons.append("validator_mapping_changed")
    if not commit_bound:
        reasons.append("commit_event_not_unique_or_mismatched")
    if exact_present:
        classification: Literal["pending", "applied", "failed"] = "pending"
        if not any_validator_entry or not snapshot.validator_has_pending_commit:
            reasons.append("pending_queue_summary_mismatch")
    else:
        if any_validator_entry or snapshot.validator_has_pending_commit:
            reasons.append("unexpected_validator_pending_entry")
        if not reveal_bound:
            reasons.append("reveal_event_not_unique")
        if not row_matches:
            reasons.append("applied_row_mismatch")
        classification = "failed" if reasons else "applied"
    return BootstrapTerminalObservation(
        schema=BOOTSTRAP_TERMINAL_OBSERVATION_SCHEMA,
        classification=classification,
        reason_codes=sorted(set(reasons)),
        policy_sha256=bootstrap_policy_hash(signed.manifest.policy),
        manifest_sha256=signed.manifest_sha256,
        call_material_sha256=material_sha256,
        validator_hotkey=receipt.validator_hotkey,
        commit=receipt.commit,
        commit_epoch_index=receipt.commit_epoch_index,
        reveal_round=material.reveal_round,
        ciphertext_sha256=receipt.ciphertext_sha256,
        observation_block=snapshot.block_number,
        observation_block_hash=snapshot.block_hash,
        expected_row=expected_row,
        observed_row=snapshot.validator_mechid0_row,
        mapping_checks_passed=mapping_checks_passed,
        validator_pending_commit=snapshot.validator_has_pending_commit,
        exact_epoch_entry_present=exact_present,
        exact_epoch_queue_removal_observed=exact_removed,
        commit_event_unique_and_bound=commit_bound,
        duplicate_commit_absent=duplicate_absent,
        reveal_event_unique_and_bound=reveal_bound,
        reveal_period_history_stable=period_stable,
        row_matches_expected=row_matches,
        sdk_finalized_reads_verified=True,
        commit_events=commit_events,
        reveal_events=reveal_events,
        reveal_period_history=period_history,
        event_interval_start=commit_block,
        event_interval_end=snapshot.block_number,
        event_storage_proofs_verified=False,
        exact_queue_removal_sdk_observed=exact_removed,
        row_storage_proof_verified=False,
        protocol_terminal_classification_verified=classification != "pending",
    )


def sign_bootstrap_terminal_observation(
    observation: BootstrapTerminalObservation,
    *,
    wallet: Any,
) -> SignedBootstrapTerminalObservation:
    signer = bt.resolve_signer(wallet, role="hotkey")
    if account_id32(signer.ss58_address) != account_id32(observation.validator_hotkey):
        raise BootstrapOperatorError("terminal_signer_mismatch")
    body = canonical_json_bytes(observation)
    digest = hashlib.sha256(_TERMINAL_SIGNATURE_DOMAIN + body).digest()
    scheme, signature = sign_response_digest(wallet, digest)
    return SignedBootstrapTerminalObservation(
        schema=BOOTSTRAP_TERMINAL_SIGNATURE_SCHEMA,
        observation=observation,
        observation_sha256=hashlib.sha256(body).hexdigest(),
        observation_digest=digest.hex(),
        validator_hotkey=signer.ss58_address,
        signature_scheme=scheme,
        signature=signature,
    )


async def observe_bootstrap_sunset(
    signed: SignedBootstrapEligibilityManifest,
    *,
    validator_hotkey: str,
    chain: BittensorBootstrapChain,
) -> BootstrapSunsetStatus:
    """Report policy time and global SDK-observed row and queue state."""

    chain.checkout_verifier(signed.manifest.policy)
    _verify_historical_signed_manifest(signed)
    async with chain.client_factory("finney") as client:
        snapshot = await chain._snapshot(
            client,
            signed,
            validator_hotkey=validator_hotkey,
            allow_missing_validator=True,
        )
        pinned = await client.at(snapshot.block_number)
        subnet_emission_enabled = _bool_or_zero_one(
            await pinned.read("subnet_emission_enabled", netuid=NETUID),
            "subnet_emission_enabled_invalid",
        )
    policy = signed.manifest.policy
    if snapshot.block_number < policy.activation_block:
        status: Literal[
            "pre_activation",
            "commit_interval_open",
            "commits_closed_awaiting_sunset",
            "sunset_clean_sdk_observation",
            "sunset_incident_sdk_observation",
        ] = "pre_activation"
    elif snapshot.block_number < policy.commit_stop_block:
        status = "commit_interval_open"
    elif snapshot.block_number < policy.hard_sunset_block:
        status = "commits_closed_awaiting_sunset"
    elif (
        snapshot.total_pending_commit_count
        or snapshot.active_mechid0_row_hotkeys
        or subnet_emission_enabled
    ):
        status = "sunset_incident_sdk_observation"
    else:
        status = "sunset_clean_sdk_observation"
    return BootstrapSunsetStatus(
        schema=BOOTSTRAP_SUNSET_STATUS_SCHEMA,
        status=status,
        policy_sha256=bootstrap_policy_hash(policy),
        policy_coordinator_hotkey=policy.coordinator_hotkey,
        manifest_sha256=signed.manifest_sha256,
        observation_block=snapshot.block_number,
        observation_block_hash=snapshot.block_hash,
        commit_stop_block=policy.commit_stop_block,
        hard_sunset_block=policy.hard_sunset_block,
        service_weights_active=False,
        total_pending_commit_count=snapshot.total_pending_commit_count,
        active_mechid0_row_hotkeys=snapshot.active_mechid0_row_hotkeys,
        subnet_emission_enabled=subnet_emission_enabled,
        storage_proofs_verified=False,
    )


def sign_bootstrap_sunset_status(
    status: BootstrapSunsetStatus,
    *,
    wallet: Any,
) -> SignedBootstrapSunsetStatus:
    signer = bt.resolve_signer(wallet, role="hotkey")
    if account_id32(signer.ss58_address) != account_id32(status.policy_coordinator_hotkey):
        raise BootstrapOperatorError("sunset_signer_mismatch")
    body = canonical_json_bytes(status)
    digest = hashlib.sha256(_SUNSET_SIGNATURE_DOMAIN + body).digest()
    scheme, signature = sign_response_digest(wallet, digest)
    return SignedBootstrapSunsetStatus(
        schema=BOOTSTRAP_SUNSET_SIGNATURE_SCHEMA,
        status=status,
        status_sha256=hashlib.sha256(body).hexdigest(),
        status_digest=digest.hex(),
        coordinator_hotkey=signer.ss58_address,
        signature_scheme=scheme,
        signature=signature,
    )


async def submit_bootstrap_weights(
    signed: SignedBootstrapEligibilityManifest,
    *,
    cutover: BootstrapCutoverCheckpoint,
    wallet: Any,
    chain: BittensorBootstrapChain,
    receipt_output: Path,
    call_material_output: Path,
    state_dir: Path,
    live_submit: bool,
    acknowledgement: str,
    require_clean_cutover: bool = False,
    prior_terminal: BootstrapTerminalObservation | None = None,
    fetch_bytes: Callable[[str, int], Any] | None = None,
    health_request: Callable[[str], Any] | None = None,
    call_builder: Callable[..., BuiltCRv4WeightCommit] = build_crv4_weight_commit,
) -> BootstrapWeightSubmissionReceipt:
    """Serialize one validator/policy submission before any network side effect."""

    if live_submit is not True or acknowledgement != LIVE_SUBMIT_ACKNOWLEDGEMENT:
        raise BootstrapOperatorError("live_submit_acknowledgement_missing")
    signer = bt.resolve_signer(wallet, role="hotkey")
    state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock_name = (
        f".submit-{bootstrap_policy_hash(signed.manifest.policy)}-"
        f"{account_id32(signer.ss58_address).hex()}.lock"
    )
    lock_path = state_dir / lock_name
    try:
        descriptor = os.open(lock_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as error:
        raise BootstrapOperatorError("submission_already_in_progress") from error
    try:
        os.write(descriptor, f"pid={os.getpid()}\n".encode("ascii"))
        os.fsync(descriptor)
        return await _submit_bootstrap_weights_unlocked(
            signed,
            cutover=cutover,
            wallet=wallet,
            chain=chain,
            receipt_output=receipt_output,
            call_material_output=call_material_output,
            live_submit=live_submit,
            acknowledgement=acknowledgement,
            require_clean_cutover=require_clean_cutover,
            prior_terminal=prior_terminal,
            fetch_bytes=fetch_bytes,
            health_request=health_request,
            call_builder=call_builder,
        )
    finally:
        os.close(descriptor)
        with contextlib.suppress(OSError):
            lock_path.unlink()


async def _submit_bootstrap_weights_unlocked(
    signed: SignedBootstrapEligibilityManifest,
    *,
    cutover: BootstrapCutoverCheckpoint,
    wallet: Any,
    chain: BittensorBootstrapChain,
    receipt_output: Path,
    call_material_output: Path,
    live_submit: bool,
    acknowledgement: str,
    require_clean_cutover: bool = False,
    prior_terminal: BootstrapTerminalObservation | None = None,
    fetch_bytes: Callable[[str, int], Any] | None = None,
    health_request: Callable[[str], Any] | None = None,
    call_builder: Callable[..., BuiltCRv4WeightCommit] = build_crv4_weight_commit,
) -> BootstrapWeightSubmissionReceipt:
    """Anchor and submit once, returning a pending terminal-classification receipt."""

    if live_submit is not True or acknowledgement != LIVE_SUBMIT_ACKNOWLEDGEMENT:
        raise BootstrapOperatorError("live_submit_acknowledgement_missing")
    if receipt_output.exists() or call_material_output.exists():
        raise BootstrapOperatorError("submission_output_exists")
    if receipt_output.resolve() == call_material_output.resolve():
        raise BootstrapOperatorError("submission_outputs_overlap")
    signer = bt.resolve_signer(wallet, role="hotkey")
    validator_hotkey = signer.ss58_address
    async with chain.client_factory("finney") as client:
        pre_anchor = await chain.operational_preflight_with_client(
            client,
            signed,
            cutover=cutover,
            validator_hotkey=validator_hotkey,
            require_clean_cutover=require_clean_cutover,
            prior_terminal=prior_terminal,
            fetch_bytes=fetch_bytes,
            health_request=health_request,
        )
        _require_submission_headroom(signed, pre_anchor.chain.snapshot.block_number)
        anchor_call = build_sha256_commitment_call(signed.manifest_sha256)
        anchor_result = await client.submit_call(
            anchor_call,
            wallet,
            signer="hotkey",
            period=_SUBMISSION_ERA_PERIOD,
            wait_for_inclusion=True,
            wait_for_finalization=True,
        )
        anchor = _successful_extrinsic(anchor_result, reason="manifest_anchor_failed")
        anchor_block = _extrinsic_block_number(anchor)
        if not _in_submission_interval(signed, anchor_block):
            receipt = _partial_submission_receipt(
                signed,
                validator_hotkey=validator_hotkey,
                anchor=anchor,
                reason_code="manifest_anchor_inclusion_outside_policy",
            )
            _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
            raise BootstrapOperatorError("manifest_anchor_inclusion_outside_policy")
        material_digest: str | None = None
        commit: BootstrapExtrinsicReference | None = None
        commit_epoch_index: int | None = None
        try:
            post_chain = await chain.preflight_with_client(
                client,
                signed,
                validator_hotkey=validator_hotkey,
                require_clean_cutover=require_clean_cutover,
                prior_terminal=prior_terminal,
            )
            _require_submission_headroom(signed, post_chain.snapshot.block_number)
            anchor_observation = await chain.verify_manifest_anchor_with_client(
                client,
                signed,
                validator_hotkey=validator_hotkey,
                anchor=anchor,
                post_anchor=post_chain,
            )
            post_health = await probe_bootstrap_health(
                signed,
                post_chain,
                request=health_request,
                clock=chain.clock,
            )
            post_anchor = BootstrapOperationalPreflight(
                schema=BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA,
                signed_manifest=signed,
                cutover=pre_anchor.cutover,
                chain=post_chain,
                pilot_replay=pre_anchor.pilot_replay,
                health=post_health,
            )
            schedule = await chain.current_schedule_with_client(client, signed.manifest.policy)
            _require_submission_headroom(signed, schedule.block_number)
            material, built = build_bootstrap_weight_call_material(
                post_anchor,
                schedule_snapshot=schedule,
                manifest_anchor=anchor_observation,
                call_builder=call_builder,
            )
            material_bytes = canonical_json_bytes(material)
            material_digest = hashlib.sha256(material_bytes).hexdigest()
            _write_new_canonical(
                call_material_output,
                material,
                maximum_bytes=_MAX_INPUT_BYTES,
            )
            commit_result = await client.submit_call(
                built.raw_call,
                wallet,
                signer="hotkey",
                period=_SUBMISSION_ERA_PERIOD,
                wait_for_inclusion=True,
                wait_for_finalization=True,
            )
            commit = _successful_extrinsic(commit_result, reason="weight_commit_failed")
            commit_block = _extrinsic_block_number(commit)
            commit_snapshot = await client.at(commit_block)
            commit_info = await commit_snapshot.block_info()
            if getattr(commit_info, "hash", None) != commit.block_hash:
                raise BootstrapOperatorError("weight_commit_block_hash_mismatch")
            pending_at_inclusion = await commit_snapshot.read(
                "timelocked_weight_commits",
                netuid=NETUID,
                mechid=MECHANISM_ID,
            )
            commit_epoch_index = _exact_pending_entry_epoch(
                pending_at_inclusion,
                validator_hotkey=validator_hotkey,
                commit_block=commit_block,
                ciphertext=built.ciphertext,
                reveal_round=built.reveal_round,
            )
        except Exception as error:
            reason_code = getattr(error, "reason_code", "post_anchor_weight_commit_failed")
            if commit is None:
                receipt = _partial_submission_receipt(
                    signed,
                    validator_hotkey=validator_hotkey,
                    anchor=anchor,
                    reason_code=str(reason_code)[:128],
                    call_material_sha256=material_digest,
                )
            else:
                receipt = BootstrapWeightSubmissionReceipt(
                    schema=BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA,
                    status="commit_finalized_nonconforming",
                    reason_code=str(reason_code)[:128],
                    manifest_sha256=signed.manifest_sha256,
                    validator_hotkey=validator_hotkey,
                    anchor=anchor,
                    commit=commit,
                    call_material_sha256=material_digest,
                    commit_epoch_index=None,
                    reveal_round=built.reveal_round,
                    ciphertext_sha256=hashlib.sha256(built.ciphertext).hexdigest(),
                    exact_commit_entry_observed=False,
                    submission_era_period=_SUBMISSION_ERA_PERIOD,
                    storage_proofs_verified=False,
                    terminal_verification_complete=False,
                    created_at=datetime.now(timezone.utc),
                )
            _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
            raise BootstrapOperatorError("post_anchor_weight_commit_failed") from error

    if commit is None or commit_epoch_index is None:  # pragma: no cover
        raise BootstrapOperatorError("weight_commit_evidence_missing")
    commit_block = _extrinsic_block_number(commit)
    if not _in_submission_interval(signed, commit_block):
        receipt = BootstrapWeightSubmissionReceipt(
            schema=BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA,
            status="commit_finalized_nonconforming",
            reason_code="weight_commit_inclusion_outside_policy",
            manifest_sha256=signed.manifest_sha256,
            validator_hotkey=validator_hotkey,
            anchor=anchor,
            commit=commit,
            call_material_sha256=material_digest,
            commit_epoch_index=commit_epoch_index,
            reveal_round=built.reveal_round,
            ciphertext_sha256=hashlib.sha256(built.ciphertext).hexdigest(),
            exact_commit_entry_observed=True,
            submission_era_period=_SUBMISSION_ERA_PERIOD,
            storage_proofs_verified=False,
            terminal_verification_complete=False,
            created_at=datetime.now(timezone.utc),
        )
        _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
        raise BootstrapOperatorError("weight_commit_inclusion_outside_policy")

    receipt = BootstrapWeightSubmissionReceipt(
        schema=BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA,
        status="commit_finalized_pending_terminal_verification",
        reason_code=None,
        manifest_sha256=signed.manifest_sha256,
        validator_hotkey=validator_hotkey,
        anchor=anchor,
        commit=commit,
        call_material_sha256=material_digest,
        commit_epoch_index=commit_epoch_index,
        reveal_round=built.reveal_round,
        ciphertext_sha256=hashlib.sha256(built.ciphertext).hexdigest(),
        exact_commit_entry_observed=True,
        submission_era_period=_SUBMISSION_ERA_PERIOD,
        storage_proofs_verified=False,
        terminal_verification_complete=False,
        created_at=datetime.now(timezone.utc),
    )
    _write_new_canonical(receipt_output, receipt, maximum_bytes=_MAX_RECEIPT_BYTES)
    return receipt


async def _collect_cutover_checkpoint(
    chain: BittensorBootstrapChain,
    policy: BootstrapWeightPolicy,
    *,
    checkpoint_block: int,
) -> BootstrapCutoverCheckpoint:
    async with chain.client_factory("finney") as client:
        header = await _first_finalized_header(client, chain.finalized_timeout_seconds)
        if _uint(getattr(header, "number", None), "finalized_block_invalid", minimum=1) < (
            checkpoint_block
        ):
            raise BootstrapOperatorError("cutover_checkpoint_not_finalized")
        return await chain.cutover_checkpoint_with_client(
            client,
            policy,
            checkpoint_block=checkpoint_block,
        )


async def _operational_preflight_and_schedule(
    chain: BittensorBootstrapChain,
    signed: SignedBootstrapEligibilityManifest,
    *,
    cutover: BootstrapCutoverCheckpoint,
    validator_hotkey: str,
    require_clean_cutover: bool,
    include_schedule: bool,
    prior_terminal: BootstrapTerminalObservation | None = None,
) -> tuple[BootstrapOperationalPreflight, BootstrapWeightScheduleEvidence | None]:
    async with chain.client_factory("finney") as client:
        operational = await chain.operational_preflight_with_client(
            client,
            signed,
            cutover=cutover,
            validator_hotkey=validator_hotkey,
            require_clean_cutover=require_clean_cutover,
            prior_terminal=prior_terminal,
        )
        schedule = (
            await chain.current_schedule_with_client(client, signed.manifest.policy)
            if include_schedule
            else None
        )
        if schedule is not None:
            _require_submission_headroom(signed, schedule.block_number)
        return operational, schedule


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umi-bootstrap-weights",
        description="Build and audit temporary SN78 service bootstrap weights",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    policy = commands.add_parser("policy", help="write one canonical bootstrap policy")
    policy.add_argument("--campaign-id", required=True)
    policy.add_argument("--public-evidence-origin", required=True)
    policy.add_argument("--coordinator-hotkey", required=True)
    policy.add_argument("--umi-git-revision", required=True)
    policy.add_argument("--weights-version-key", type=int, required=True)
    policy.add_argument("--published-at-block", type=int, required=True)
    policy.add_argument("--activation-block", type=int, required=True)
    policy.add_argument("--commit-stop-block", type=int, required=True)
    policy.add_argument("--hard-sunset-block", type=int, required=True)
    policy.add_argument("--health-ttl-blocks", type=int, required=True)
    policy.add_argument("--manifest-ttl-blocks", type=int, required=True)
    policy.add_argument("--output", type=Path, required=True)

    cutover = commands.add_parser("cutover", help="build a reusable clean-cutover checkpoint")
    cutover.add_argument("--policy", type=Path, required=True)
    cutover.add_argument("--checkpoint-block", type=int, required=True)
    cutover.add_argument("--output", type=Path, required=True)
    cutover.add_argument("--finalized-timeout", type=float, default=20.0)

    opt_in = commands.add_parser("opt-in", help="sign one policy-bound miner opt-in")
    opt_in.add_argument("--policy", type=Path, required=True)
    opt_in.add_argument("--pilot-id", required=True)
    opt_in.add_argument("--signed-at-block", type=int, required=True)
    opt_in.add_argument("--output", type=Path, required=True)
    _wallet_arguments(opt_in)

    entry = commands.add_parser("entry", help="bind a verified opt-in to pilot and health data")
    entry.add_argument("--policy", type=Path, required=True)
    entry.add_argument("--opt-in", type=Path, required=True)
    entry.add_argument("--uid", type=int, required=True)
    entry.add_argument("--origin", required=True)
    entry.add_argument("--pilot-block", type=int, required=True)
    entry.add_argument("--health-block", type=int, required=True)
    entry.add_argument("--output", type=Path, required=True)

    manifest = commands.add_parser("manifest", help="build and coordinator-sign a manifest")
    manifest.add_argument("--policy", type=Path, required=True)
    manifest.add_argument("--entry", type=Path, action="append", required=True)
    manifest.add_argument("--frozen-at-block", type=int, required=True)
    manifest.add_argument("--frozen-at-block-hash", required=True)
    manifest.add_argument("--output", type=Path, required=True)
    _wallet_arguments(manifest)

    verify = commands.add_parser("verify-manifest", help="verify a signed manifest")
    verify.add_argument("--manifest", type=Path, required=True)
    verify.add_argument("--current-block", type=int)

    preflight = commands.add_parser("preflight", help="run a read-only finalized-chain check")
    preflight.add_argument("--manifest", type=Path, required=True)
    preflight.add_argument("--cutover-checkpoint", type=Path, required=True)
    preflight.add_argument("--validator-hotkey", required=True)
    preflight.add_argument("--finalized-timeout", type=float, default=20.0)
    preflight.add_argument("--require-clean-current-state", action="store_true")
    preflight.add_argument("--prior-terminal", type=Path)

    build = commands.add_parser("build-call", help="preflight and build an unsigned CRv4 call")
    build.add_argument("--manifest", type=Path, required=True)
    build.add_argument("--cutover-checkpoint", type=Path, required=True)
    build.add_argument("--validator-hotkey", required=True)
    build.add_argument("--output", type=Path, required=True)
    build.add_argument("--finalized-timeout", type=float, default=20.0)
    build.add_argument("--require-clean-current-state", action="store_true")
    build.add_argument("--prior-terminal", type=Path)

    submit = commands.add_parser("submit", help="anchor and submit bootstrap weights")
    submit.add_argument("--manifest", type=Path, required=True)
    submit.add_argument("--cutover-checkpoint", type=Path, required=True)
    submit.add_argument("--receipt-output", type=Path, required=True)
    submit.add_argument("--call-material-output", type=Path, required=True)
    submit.add_argument("--state-dir", type=Path, required=True)
    submit.add_argument("--finalized-timeout", type=float, default=20.0)
    submit.add_argument("--live-submit", action="store_true")
    submit.add_argument("--acknowledgement", required=True)
    submit.add_argument("--require-clean-current-state", action="store_true")
    submit.add_argument("--prior-terminal", type=Path)
    _wallet_arguments(submit)

    terminal = commands.add_parser("terminal", help="observe a submitted commit terminal state")
    terminal.add_argument("--manifest", type=Path, required=True)
    terminal.add_argument("--receipt", type=Path, required=True)
    terminal.add_argument("--call-material", type=Path, required=True)
    terminal.add_argument("--output", type=Path, required=True)
    terminal.add_argument("--finalized-timeout", type=float, default=20.0)
    _wallet_arguments(terminal)

    sunset = commands.add_parser("sunset-status", help="observe bootstrap cutoff and sunset state")
    sunset.add_argument("--manifest", type=Path, required=True)
    sunset.add_argument("--validator-hotkey", required=True)
    sunset.add_argument("--output", type=Path, required=True)
    sunset.add_argument("--finalized-timeout", type=float, default=20.0)
    _wallet_arguments(sunset)
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        if args.command == "policy":
            result = BootstrapWeightPolicy(
                schema=BOOTSTRAP_WEIGHT_POLICY_SCHEMA,
                network="finney",
                netuid=NETUID,
                mechanism_id=MECHANISM_ID,
                translation_weights_active=False,
                service_weights_active=True,
                campaign_id=args.campaign_id,
                public_evidence_origin=args.public_evidence_origin,
                coordinator_hotkey=args.coordinator_hotkey,
                umi_git_revision=args.umi_git_revision,
                weights_version_key=args.weights_version_key,
                published_at_block=args.published_at_block,
                activation_block=args.activation_block,
                commit_stop_block=args.commit_stop_block,
                hard_sunset_block=args.hard_sunset_block,
                health_ttl_blocks=args.health_ttl_blocks,
                manifest_ttl_blocks=args.manifest_ttl_blocks,
            )
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        elif args.command == "cutover":
            policy = _load_canonical(args.policy, BootstrapWeightPolicy)
            verify_runtime_checkout(policy)
            chain = BittensorBootstrapChain(finalized_timeout_seconds=args.finalized_timeout)
            result = asyncio.run(
                _collect_cutover_checkpoint(
                    chain,
                    policy,
                    checkpoint_block=args.checkpoint_block,
                )
            )
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        elif args.command == "opt-in":
            policy = _load_canonical(args.policy, BootstrapWeightPolicy)
            wallet = _wallet(args)
            result = sign_bootstrap_opt_in(
                policy,
                pilot_id=args.pilot_id,
                wallet=wallet,
                signed_at_block=args.signed_at_block,
            )
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        elif args.command == "entry":
            policy = _load_canonical(args.policy, BootstrapWeightPolicy)
            opt_in = _load_canonical(args.opt_in, BootstrapOptIn)
            verify_bootstrap_opt_in(opt_in, policy=policy)
            result = BootstrapEligibilityEntry(
                pilot_id=opt_in.pilot_id,
                miner_hotkey=opt_in.miner_hotkey,
                uid=args.uid,
                origin=args.origin,
                pilot_block=args.pilot_block,
                health_block=args.health_block,
                utility=1,
                opt_in=opt_in,
            )
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        elif args.command == "manifest":
            policy = _load_canonical(args.policy, BootstrapWeightPolicy)
            entries = [_load_canonical(path, BootstrapEligibilityEntry) for path in args.entry]
            result = sign_bootstrap_eligibility_manifest(
                build_bootstrap_eligibility_manifest(
                    policy,
                    entries,
                    frozen_at_block=args.frozen_at_block,
                    frozen_at_block_hash=args.frozen_at_block_hash,
                ),
                wallet=_wallet(args),
            )
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        elif args.command == "verify-manifest":
            signed = _load_canonical(args.manifest, SignedBootstrapEligibilityManifest)
            result = verify_signed_bootstrap_eligibility_manifest(
                signed,
                current_block=args.current_block,
            )
            _print_canonical(result)
        elif args.command in {"preflight", "build-call"}:
            signed = _load_canonical(args.manifest, SignedBootstrapEligibilityManifest)
            cutover = _load_canonical(args.cutover_checkpoint, BootstrapCutoverCheckpoint)
            prior_terminal = _load_prior_terminal(args.prior_terminal)
            chain = BittensorBootstrapChain(finalized_timeout_seconds=args.finalized_timeout)
            operational, schedule = asyncio.run(
                _operational_preflight_and_schedule(
                    chain,
                    signed,
                    cutover=cutover,
                    validator_hotkey=args.validator_hotkey,
                    require_clean_cutover=args.require_clean_current_state,
                    include_schedule=args.command == "build-call",
                    prior_terminal=prior_terminal,
                )
            )
            if args.command == "preflight":
                _print_canonical(operational)
            else:
                if schedule is None:  # pragma: no cover
                    raise BootstrapOperatorError("current_schedule_missing")
                material, _built = build_bootstrap_weight_call_material(
                    operational,
                    schedule_snapshot=schedule,
                )
                _write_new_canonical(args.output, material, maximum_bytes=_MAX_INPUT_BYTES)
                _print_canonical(material)
        elif args.command == "submit":
            signed = _load_canonical(args.manifest, SignedBootstrapEligibilityManifest)
            cutover = _load_canonical(args.cutover_checkpoint, BootstrapCutoverCheckpoint)
            prior_terminal = _load_prior_terminal(args.prior_terminal)
            receipt = asyncio.run(
                submit_bootstrap_weights(
                    signed,
                    cutover=cutover,
                    wallet=_wallet(args),
                    chain=BittensorBootstrapChain(finalized_timeout_seconds=args.finalized_timeout),
                    receipt_output=args.receipt_output,
                    call_material_output=args.call_material_output,
                    state_dir=args.state_dir,
                    live_submit=args.live_submit,
                    acknowledgement=args.acknowledgement,
                    require_clean_cutover=args.require_clean_current_state,
                    prior_terminal=prior_terminal,
                )
            )
            _print_canonical(receipt)
        elif args.command == "terminal":
            signed = _load_canonical(args.manifest, SignedBootstrapEligibilityManifest)
            receipt = _load_canonical(args.receipt, BootstrapWeightSubmissionReceipt)
            material = _load_canonical(args.call_material, BootstrapWeightCallMaterial)
            observation = asyncio.run(
                observe_bootstrap_terminal(
                    signed,
                    receipt,
                    material,
                    chain=BittensorBootstrapChain(finalized_timeout_seconds=args.finalized_timeout),
                )
            )
            result = sign_bootstrap_terminal_observation(observation, wallet=_wallet(args))
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        elif args.command == "sunset-status":
            signed = _load_canonical(args.manifest, SignedBootstrapEligibilityManifest)
            status = asyncio.run(
                observe_bootstrap_sunset(
                    signed,
                    validator_hotkey=args.validator_hotkey,
                    chain=BittensorBootstrapChain(finalized_timeout_seconds=args.finalized_timeout),
                )
            )
            result = sign_bootstrap_sunset_status(status, wallet=_wallet(args))
            _write_new_canonical(args.output, result, maximum_bytes=_MAX_INPUT_BYTES)
            _print_canonical(result)
        else:  # pragma: no cover
            raise BootstrapOperatorError("unknown_command")
    except (
        BootstrapOperatorError,
        OSError,
        RuntimeError,
        TypeError,
        ValidationError,
        ValueError,
    ) as error:
        reason = getattr(error, "reason_code", "bootstrap_operator_failed")
        parser.exit(2, f"bootstrap weight operator failed: {reason}\n")
    return 0


def main() -> None:
    raise SystemExit(run_cli())


def _wallet_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")


def _wallet(args: argparse.Namespace) -> Any:
    return bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)


def verify_runtime_checkout(
    policy: BootstrapWeightPolicy,
    *,
    repository: Path | None = None,
    image_revision_path: Path = Path("/opt/umi-image-revision"),
) -> None:
    """Fail closed unless this process runs from the clean policy-pinned revision."""

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
            raise BootstrapOperatorError("runtime_checkout_unverifiable") from error
        expected_owner = 0 if marker == Path("/opt/umi-image-revision") else os.getuid()
        if (
            not stat.S_ISREG(marker_stat.st_mode)
            or marker_stat.st_uid != expected_owner
            or marker_stat.st_mode & 0o222
            or len(marker_bytes) != 41
            or not marker_bytes.endswith(b"\n")
        ):
            raise BootstrapOperatorError("image_revision_marker_invalid") from None
        try:
            revision = marker_bytes[:-1].decode("ascii")
        except UnicodeDecodeError as error:
            raise BootstrapOperatorError("image_revision_marker_invalid") from error
        if _GIT_REVISION_RE.fullmatch(revision) is None:
            raise BootstrapOperatorError("image_revision_marker_invalid") from None
        dirty = ""
    if revision != policy.umi_git_revision:
        raise BootstrapOperatorError("runtime_revision_mismatch")
    if dirty:
        raise BootstrapOperatorError("runtime_checkout_dirty")


def _load_canonical(path: Path, model_type: type[Any]) -> Any:
    raw = path.read_bytes()
    if not raw or len(raw) > _MAX_INPUT_BYTES:
        raise BootstrapOperatorError("input_size_invalid")
    value = model_type.model_validate_json(raw, strict=True)
    if canonical_json_bytes(value) != raw:
        raise BootstrapOperatorError("input_not_canonical")
    return value


def _load_prior_terminal(path: Path | None) -> BootstrapTerminalObservation | None:
    if path is None:
        return None
    signed = _load_canonical(path, SignedBootstrapTerminalObservation)
    if signed.observation.classification != "applied":
        raise BootstrapOperatorError("prior_terminal_not_applied")
    return signed.observation


def _write_new_canonical(path: Path, value: Any, *, maximum_bytes: int) -> None:
    encoded = canonical_json_bytes(value)
    if not encoded or len(encoded) > maximum_bytes:
        raise BootstrapOperatorError("output_size_invalid")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _print_canonical(value: Any) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(value) + b"\n")


async def _download_and_replay_pilot(
    public_origin: str,
    pilot_id: str,
    *,
    fetch_bytes: Callable[[str, int], Any],
) -> VerifiedComponentPilot:
    manifest_url = f"{public_origin}/api/v1/pilots/{pilot_id}/bundle/manifest.json"
    manifest_bytes = await fetch_bytes(manifest_url, _MAX_INPUT_BYTES)
    if hashlib.sha256(manifest_bytes).hexdigest() != pilot_id:
        raise BootstrapOperatorError("pilot_manifest_hash_mismatch")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapOperatorError("pilot_manifest_json_invalid") from error
    if not isinstance(manifest, dict) or canonical_json_bytes(manifest) != manifest_bytes:
        raise BootstrapOperatorError("pilot_manifest_noncanonical")
    try:
        references = _bundle_refs(manifest)
    except ValueError as error:
        raise BootstrapOperatorError("pilot_manifest_schema_invalid") from error
    declared_total = len(manifest_bytes) + sum(reference.size_bytes for reference in references)
    if declared_total > MAX_PILOT_FEED_BYTES:
        raise BootstrapOperatorError("pilot_bundle_size_limit")

    with tempfile.TemporaryDirectory(prefix="umi-bootstrap-pilot-") as temporary:
        root, objects = _private_pilot_bundle_directories(temporary)
        _write_private_pilot_replay_file(root / "manifest.json", manifest_bytes)
        for reference in references:
            object_url = (
                f"{public_origin}/api/v1/pilots/{pilot_id}/bundle/objects/{reference.sha256}"
            )
            body = await fetch_bytes(object_url, reference.size_bytes)
            if len(body) != reference.size_bytes:
                raise BootstrapOperatorError("pilot_object_size_mismatch")
            if hashlib.sha256(body).hexdigest() != reference.sha256:
                raise BootstrapOperatorError("pilot_object_hash_mismatch")
            _write_private_pilot_replay_file(objects / reference.sha256, body)
        try:
            return _load_pilot(root, public_origin)
        except (OSError, TypeError, ValueError) as error:
            raise BootstrapOperatorError("pilot_deterministic_replay_failed") from error


def _private_pilot_bundle_directories(temporary: str | Path) -> tuple[Path, Path]:
    """Create replay paths with fixed permissions regardless of the process umask."""

    root = Path(temporary) / "bundle"
    objects = root / "objects"
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    objects.mkdir(mode=0o700)
    objects.chmod(0o700)
    return root, objects


def _write_private_pilot_replay_file(path: Path, data: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        os.fchmod(handle.fileno(), 0o600)
        handle.write(data)


def _pilot_replay_receipt(
    pilot: VerifiedComponentPilot,
    *,
    entry: BootstrapEligibilityEntry,
    policy: BootstrapWeightPolicy,
) -> BootstrapPilotReplayReceipt:
    public = pilot.public_endpoint
    if public is None:
        raise BootstrapOperatorError("pilot_lacks_public_endpoint_evidence")
    attestation = public.attestation
    if pilot.pilot_id != entry.pilot_id or pilot.manifest_sha256 != entry.pilot_id:
        raise BootstrapOperatorError("pilot_id_mismatch")
    if account_id32(pilot.miner_hotkey) != account_id32(entry.miner_hotkey):
        raise BootstrapOperatorError("pilot_miner_hotkey_mismatch")
    if account_id32(attestation.coordinator_hotkey) != account_id32(policy.coordinator_hotkey):
        raise BootstrapOperatorError("pilot_coordinator_mismatch")
    if attestation.campaign_id != policy.campaign_id:
        raise BootstrapOperatorError("pilot_campaign_mismatch")
    if attestation.expected_miner_uid != entry.uid:
        raise BootstrapOperatorError("pilot_uid_mismatch")
    if attestation.announced_origin != entry.origin or attestation.contacted_origin != entry.origin:
        raise BootstrapOperatorError("pilot_origin_mismatch")
    if attestation.chain_observation.block_number != entry.pilot_block:
        raise BootstrapOperatorError("pilot_block_mismatch")
    if (
        attestation.outcome_classification != "ok"
        or not attestation.miner_signed_envelope_verified
        or not attestation.miner_signed_plaintext_verified
    ):
        raise BootstrapOperatorError("pilot_outcome_not_successful")
    return BootstrapPilotReplayReceipt(
        pilot_id=pilot.pilot_id,
        manifest_sha256=pilot.manifest_sha256,
        bundle_bytes=pilot.bundle_bytes,
        miner_hotkey=pilot.miner_hotkey,
        uid=attestation.expected_miner_uid,
        origin=attestation.announced_origin,
        coordinator_hotkey=attestation.coordinator_hotkey,
        campaign_id=attestation.campaign_id,
        outcome_classification="ok",
        deterministic_replay_verified=True,
        coordinator_signature_verified=True,
        storage_proofs_verified=False,
    )


async def _https_get_bytes(url: str, maximum_bytes: int) -> bytes:
    if maximum_bytes < 0 or maximum_bytes > MAX_PILOT_FEED_BYTES:
        raise BootstrapOperatorError("http_response_limit_invalid")
    timeout = httpx.Timeout(_HTTP_TIMEOUT_SECONDS)
    async with (
        httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client,
        client.stream(
            "GET",
            url,
            headers={"accept": "application/octet-stream"},
        ) as response,
    ):
        if response.status_code != 200 or str(response.url) != url:
            raise BootstrapOperatorError("public_evidence_fetch_failed")
        declared = response.headers.get("content-length")
        if declared is not None:
            try:
                declared_size = int(declared)
            except ValueError as error:
                raise BootstrapOperatorError("public_evidence_length_invalid") from error
            if declared_size < 0 or declared_size > maximum_bytes:
                raise BootstrapOperatorError("public_evidence_size_limit")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > maximum_bytes:
                raise BootstrapOperatorError("public_evidence_size_limit")
    return bytes(body)


async def _https_health_request(url: str) -> BootstrapHealthHTTPResult:
    timeout = httpx.Timeout(_HTTP_TIMEOUT_SECONDS)
    async with (
        httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=False,
            trust_env=False,
        ) as client,
        client.stream("GET", url, headers={"accept": "application/json"}) as response,
    ):
        stream = response.extensions.get("network_stream")
        extra_info = getattr(stream, "get_extra_info", None)
        ssl_object = extra_info("ssl_object") if callable(extra_info) else None
        certificate = (
            ssl_object.getpeercert(binary_form=True)
            if ssl_object is not None and callable(getattr(ssl_object, "getpeercert", None))
            else None
        )
        if not isinstance(certificate, bytes) or not certificate:
            raise BootstrapOperatorError("miner_health_tls_certificate_missing")
        body = bytearray()
        async for chunk in response.aiter_bytes():
            body.extend(chunk)
            if len(body) > _MAX_HEALTH_BODY_BYTES:
                raise BootstrapOperatorError("miner_health_body_limit")
        return BootstrapHealthHTTPResult(
            requested_url=url,
            final_url=str(response.url),
            status_code=response.status_code,
            body=bytes(body),
            tls_certificate_sha256=hashlib.sha256(certificate).hexdigest(),
        )


async def _first_finalized_header(client: Any, timeout: float) -> Any:
    stream: AsyncIterator[Any] = client.blocks(finalized=True)
    try:
        return await asyncio.wait_for(anext(stream), timeout=timeout)
    except asyncio.TimeoutError as error:
        raise BootstrapOperatorError("finalized_head_timeout") from error
    finally:
        close = getattr(stream, "aclose", None)
        if callable(close):
            with contextlib.suppress(Exception):
                result = close()
                if inspect.isawaitable(result):
                    await result


async def _block_time(substrate: Any) -> float:
    reader = getattr(substrate, "block_time", None)
    if not callable(reader):
        raise BootstrapOperatorError("block_time_reader_missing")
    value = await reader()
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 < value <= 60:
        raise BootstrapOperatorError("block_time_invalid")
    return float(value)


def _validate_finalized_block(header: Any, info: Any, block_number: int) -> tuple[str, int]:
    if _uint(getattr(info, "number", None), "block_info_number_invalid") != block_number:
        raise BootstrapOperatorError("block_info_number_mismatch")
    raw_header = _mapping(getattr(header, "raw", None), "subscription_header_invalid")
    info_header = _mapping(getattr(info, "header", None), "block_info_header_invalid")
    block_hash = getattr(info, "hash", None)
    if not _is_block_hash(block_hash):
        raise BootstrapOperatorError("block_hash_invalid")
    try:
        if _header_hash(raw_header, "subscription header") != block_hash:
            raise BootstrapOperatorError("subscription_header_hash_mismatch")
        if _header_hash(info_header, "block-info header") != block_hash:
            raise BootstrapOperatorError("block_info_header_hash_mismatch")
    except ValueError as error:
        raise BootstrapOperatorError("finalized_header_invalid") from error
    return block_hash, _timestamp_ms(getattr(info, "timestamp", None))


def _participants(
    metagraph: Any,
    *,
    block_number: int,
    permits: Any,
    last_updates: Any,
) -> list[BootstrapChainParticipant]:
    if _uint(getattr(metagraph, "netuid", None), "metagraph_netuid_invalid") != NETUID:
        raise BootstrapOperatorError("metagraph_netuid_mismatch")
    if _uint(getattr(metagraph, "mechid", None), "metagraph_mechanism_invalid") != MECHANISM_ID:
        raise BootstrapOperatorError("metagraph_mechanism_mismatch")
    if _uint(getattr(metagraph, "block", None), "metagraph_block_invalid") != block_number:
        raise BootstrapOperatorError("metagraph_block_mismatch")
    neurons = _sequence(getattr(metagraph, "neurons", None), "metagraph_neurons_invalid")
    permits_seq = _sequence(permits, "validator_permits_invalid")
    updates_seq = _sequence(last_updates, "last_updates_invalid")
    if len(neurons) != len(permits_seq) or len(neurons) != len(updates_seq):
        raise BootstrapOperatorError("metagraph_column_length_mismatch")
    result: list[BootstrapChainParticipant] = []
    for neuron in neurons:
        uid = _uint(getattr(neuron, "uid", None), "participant_uid_invalid", maximum=U16_MAX)
        if uid >= len(neurons):
            raise BootstrapOperatorError("participant_uid_out_of_range")
        hotkey = str(getattr(neuron, "hotkey", ""))
        try:
            account_id32(hotkey)
        except ValueError as error:
            raise BootstrapOperatorError("participant_hotkey_invalid") from error
        direct_permit = _bool(permits_seq[uid], "validator_permit_invalid")
        typed_permit = _bool(
            getattr(neuron, "validator_permit", None),
            "typed_validator_permit_invalid",
        )
        if direct_permit != typed_permit:
            raise BootstrapOperatorError("validator_permit_mismatch")
        direct_update = _uint(last_updates[uid], "last_update_invalid")
        typed_update = _uint(getattr(neuron, "last_update", None), "typed_last_update_invalid")
        if direct_update != typed_update or direct_update > block_number:
            raise BootstrapOperatorError("last_update_mismatch")
        axon = getattr(neuron, "axon", None)
        origin = None
        if axon is not None:
            try:
                origin = _axon_origin(axon)
            except (TypeError, ValueError):
                origin = None
        result.append(
            BootstrapChainParticipant(
                hotkey=hotkey,
                uid=uid,
                validator_permit=direct_permit,
                origin=origin,
                last_update=direct_update,
            )
        )
    return sorted(result, key=lambda item: item.uid)


def _axon_origin(value: Any) -> str:
    if isinstance(value, str):
        return _public_axon_origin(value)
    if isinstance(value, Mapping):
        raw_ip = value.get("ip")
        raw_port = value.get("port")
        raw_type = value.get("ip_type")
    else:
        raw_ip = getattr(value, "ip", None)
        raw_port = getattr(value, "port", None)
        raw_type = getattr(value, "ip_type", None)
    port = _uint(raw_port, "axon_port_invalid", minimum=1, maximum=65_535)
    if isinstance(raw_ip, bool) or not isinstance(raw_ip, (int, str)):
        raise ValueError("axon IP is invalid")
    try:
        address = ipaddress.ip_address(raw_ip)
    except ValueError:
        if not isinstance(raw_ip, str) or not raw_ip.isdecimal():
            raise
        address = ipaddress.ip_address(int(raw_ip))
    if raw_type is not None and _uint(raw_type, "axon_ip_type_invalid") != address.version:
        raise ValueError("axon IP version is inconsistent")
    host = f"[{address.compressed}]" if address.version == 6 else address.compressed
    return _public_axon_origin(f"{host}:{port}")


def _participant_by_hotkey(
    participants: Sequence[BootstrapChainParticipant],
    hotkey: str,
) -> BootstrapChainParticipant:
    expected = account_id32(hotkey)
    matches = [item for item in participants if account_id32(item.hotkey) == expected]
    if len(matches) != 1:
        raise BootstrapOperatorError("validator_not_uniquely_registered")
    return matches[0]


def _manifest_mappings_current(
    signed: SignedBootstrapEligibilityManifest,
    snapshot: BootstrapChainSnapshot,
) -> bool:
    by_account = {account_id32(item.hotkey): item for item in snapshot.participants}
    return all(
        (participant := by_account.get(account_id32(entry.miner_hotkey))) is not None
        and participant.uid == entry.uid
        and participant.validator_permit is False
        and participant.origin == entry.origin
        for entry in signed.manifest.entries
    )


async def _scan_bootstrap_weight_events(
    client: Any,
    *,
    start_block: int,
    end_block: int,
    validator_hotkey: str,
) -> tuple[
    list[BootstrapTerminalEvent],
    list[BootstrapTerminalEvent],
    list[BootstrapRevealPeriodObservation],
]:
    substrate = getattr(client, "_substrate", None)
    block_hash_reader = getattr(substrate, "block_hash", None)
    event_reader = getattr(substrate, "events", None)
    if not callable(block_hash_reader) or not callable(event_reader):
        raise BootstrapOperatorError("terminal_event_reader_missing")
    commits: list[BootstrapTerminalEvent] = []
    reveals: list[BootstrapTerminalEvent] = []
    periods: list[BootstrapRevealPeriodObservation] = []
    for block_number in range(start_block, end_block + 1):
        block_hash = await block_hash_reader(block_number)
        if not _is_block_hash(block_hash):
            raise BootstrapOperatorError("terminal_event_block_hash_missing")
        pinned = await client.at(block_number)
        info, period = await asyncio.gather(
            pinned.block_info(),
            pinned.query(storage.SubtensorModule.RevealPeriodEpochs, [NETUID]),
        )
        if (
            _uint(getattr(info, "number", None), "terminal_period_block_invalid") != block_number
            or getattr(info, "hash", None) != block_hash
        ):
            raise BootstrapOperatorError("terminal_period_snapshot_mismatch")
        periods.append(
            BootstrapRevealPeriodObservation(
                block_number=block_number,
                block_hash=block_hash,
                reveal_period_epochs=_uint(period, "terminal_reveal_period_invalid"),
            )
        )
        raw_events = await event_reader(block_hash)
        for index, raw in enumerate(_sequence(raw_events, "terminal_events_invalid")):
            event_name = _matching_weight_event(raw, validator_hotkey=validator_hotkey)
            if event_name is None:
                continue
            commitment_hash, event_reveal_round = _terminal_event_commit_fields(
                raw,
                event=event_name,
            )
            try:
                payload = canonical_json_bytes(_event_jsonable(raw))
            except (TypeError, ValueError) as error:
                raise BootstrapOperatorError("terminal_event_payload_noncanonical") from error
            record = BootstrapTerminalEvent(
                block_number=block_number,
                block_hash=block_hash,
                event_index=index,
                extrinsic_index=_optional_event_extrinsic_index(raw),
                event=event_name,
                commitment_blake2b256=commitment_hash,
                reveal_round=event_reveal_round,
                payload_sha256=hashlib.sha256(payload).hexdigest(),
            )
            (commits if event_name == "TimelockedWeightsCommitted" else reveals).append(record)
            if len(commits) > 4 or len(reveals) > 4:
                raise BootstrapOperatorError("terminal_weight_event_count_limit")
    return commits, reveals, periods


def _matching_weight_event(
    raw: Any,
    *,
    validator_hotkey: str,
) -> Literal["TimelockedWeightsCommitted", "TimelockedWeightsRevealed"] | None:
    outer = _mapping(raw, "terminal_event_invalid")
    nested_raw = outer.get("event", outer)
    nested = _mapping(nested_raw, "terminal_event_payload_invalid")
    module = nested.get("module_id", outer.get("module_id"))
    event = nested.get("event_id", outer.get("event_id"))
    if module != "SubtensorModule" or event not in {
        "TimelockedWeightsCommitted",
        "TimelockedWeightsRevealed",
    }:
        return None
    attributes = nested.get("attributes", outer.get("attributes"))
    if isinstance(attributes, Mapping):
        account = next(
            (attributes[name] for name in ("who", "hotkey", "account") if name in attributes),
            None,
        )
        target = next(
            (
                attributes[name]
                for name in ("netuid", "netuid_index", "network")
                if name in attributes
            ),
            None,
        )
    else:
        values = _sequence(attributes, "terminal_event_attributes_invalid")
        account_index = 0 if event == "TimelockedWeightsCommitted" else 1
        target_index = 1 if event == "TimelockedWeightsCommitted" else 0
        account = values[account_index] if len(values) > account_index else None
        target = values[target_index] if len(values) > target_index else None
    try:
        target_index_value = _uint(target, "terminal_event_target_invalid", maximum=U16_MAX)
        target_netuid = target_index_value % 4_096
        target_mechanism = target_index_value // 4_096
        account_matches = account_id32(account) == account_id32(validator_hotkey)
    except (TypeError, ValueError):
        return None
    if not account_matches or target_netuid != NETUID or target_mechanism != MECHANISM_ID:
        return None
    return event


def _optional_event_extrinsic_index(raw: Any) -> int | None:
    outer = _mapping(raw, "terminal_event_invalid")
    value = outer.get("extrinsic_idx", outer.get("extrinsic_index"))
    if value is None:
        return None
    return _uint(value, "terminal_event_extrinsic_index_invalid")


def _terminal_event_commit_fields(
    raw: Any,
    *,
    event: Literal["TimelockedWeightsCommitted", "TimelockedWeightsRevealed"],
) -> tuple[str | None, int | None]:
    if event == "TimelockedWeightsRevealed":
        return None, None
    outer = _mapping(raw, "terminal_event_invalid")
    nested = _mapping(outer.get("event", outer), "terminal_event_payload_invalid")
    attributes = nested.get("attributes", outer.get("attributes"))
    if isinstance(attributes, Mapping):
        raw_hash = attributes.get("commitment_hash", attributes.get("commit_hash"))
        raw_round = attributes.get("reveal_round")
    else:
        values = _sequence(attributes, "terminal_event_attributes_invalid")
        raw_hash = values[2] if len(values) > 2 else None
        raw_round = values[3] if len(values) > 3 else None
    return (
        _digest_hex(raw_hash, "terminal_event_commitment_hash_invalid"),
        _uint(raw_round, "terminal_event_reveal_round_invalid", minimum=1),
    )


def _digest_hex(value: Any, reason: str) -> str:
    if isinstance(value, bytes):
        decoded = value
    elif isinstance(value, str):
        encoded = value.removeprefix("0x")
        try:
            decoded = bytes.fromhex(encoded)
        except ValueError as error:
            raise BootstrapOperatorError(reason) from error
    else:
        raise BootstrapOperatorError(reason)
    if len(decoded) != 32:
        raise BootstrapOperatorError(reason)
    return decoded.hex()


def _event_jsonable(value: Any) -> Any:
    if isinstance(value, bytes):
        return "0x" + value.hex()
    if isinstance(value, Mapping):
        return {str(key): _event_jsonable(item) for key, item in value.items()}
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_event_jsonable(item) for item in value]
    if value is None or isinstance(value, (str, int, bool, float)):
        return value
    candidate = getattr(value, "value", None)
    if candidate is not None and candidate is not value:
        return _event_jsonable(candidate)
    raise BootstrapOperatorError("terminal_event_payload_noncanonical")


def _pending_commit_summary(value: Any, *, validator_hotkey: str) -> tuple[int, bool]:
    epochs = _mapping(value, "pending_weight_commits_invalid")
    expected = account_id32(validator_hotkey)
    count = 0
    found = False
    for epoch, entries in epochs.items():
        _uint(epoch, "pending_weight_commit_epoch_invalid")
        for entry in _sequence(entries, "pending_weight_commit_entries_invalid"):
            count += 1
            candidate: Any
            if isinstance(entry, Mapping):
                candidate = entry.get("hotkey")
            elif isinstance(entry, Sequence) and not isinstance(entry, (str, bytes, bytearray)):
                candidate = entry[0] if entry else None
            else:
                raise BootstrapOperatorError("pending_weight_commit_entry_invalid")
            try:
                account = account_id32(candidate)
            except (TypeError, ValueError) as error:
                raise BootstrapOperatorError("pending_weight_commit_hotkey_invalid") from error
            if account == expected:
                found = True
    return count, found


def _exact_pending_entry_epoch(
    value: Any,
    *,
    validator_hotkey: str,
    commit_block: int,
    ciphertext: bytes,
    reveal_round: int,
) -> int:
    epochs = _mapping(value, "pending_weight_commits_invalid")
    expected_account = account_id32(validator_hotkey)
    matches: list[int] = []
    validator_entries = 0
    for raw_epoch, raw_entries in epochs.items():
        epoch = _uint(raw_epoch, "pending_weight_commit_epoch_invalid")
        for raw_entry in _sequence(raw_entries, "pending_weight_commit_entries_invalid"):
            entry = _mapping(raw_entry, "pending_weight_commit_entry_invalid")
            try:
                is_validator = account_id32(entry.get("hotkey")) == expected_account
            except (TypeError, ValueError) as error:
                raise BootstrapOperatorError("pending_weight_commit_hotkey_invalid") from error
            if not is_validator:
                continue
            validator_entries += 1
            if (
                _uint(entry.get("commit_block"), "pending_commit_block_invalid") == commit_block
                and _uint(entry.get("reveal_round"), "pending_reveal_round_invalid") == reveal_round
                and _ciphertext_bytes(entry.get("ciphertext")) == ciphertext
            ):
                matches.append(epoch)
    if validator_entries != 1 or len(matches) != 1:
        raise BootstrapOperatorError("exact_pending_commit_entry_not_unique")
    return matches[0]


def _exact_pending_entry_present(
    value: Any,
    *,
    epoch: int,
    validator_hotkey: str,
    commit_block: int,
    ciphertext_sha256: str,
    reveal_round: int,
) -> tuple[bool, bool]:
    """Return (exact entry present at epoch, any validator entry present)."""

    epochs = _mapping(value, "pending_weight_commits_invalid")
    expected_account = account_id32(validator_hotkey)
    exact = False
    any_validator = False
    exact_count = 0
    for raw_epoch, raw_entries in epochs.items():
        observed_epoch = _uint(raw_epoch, "pending_weight_commit_epoch_invalid")
        for raw_entry in _sequence(raw_entries, "pending_weight_commit_entries_invalid"):
            entry = _mapping(raw_entry, "pending_weight_commit_entry_invalid")
            try:
                matches_validator = account_id32(entry.get("hotkey")) == expected_account
            except (TypeError, ValueError) as error:
                raise BootstrapOperatorError("pending_weight_commit_hotkey_invalid") from error
            if not matches_validator:
                continue
            any_validator = True
            try:
                ciphertext = _ciphertext_bytes(entry.get("ciphertext"))
                entry_digest = hashlib.sha256(ciphertext).hexdigest()
            except BootstrapOperatorError:
                entry_digest = ""
            if (
                observed_epoch == epoch
                and _uint(entry.get("commit_block"), "pending_commit_block_invalid") == commit_block
                and _uint(entry.get("reveal_round"), "pending_reveal_round_invalid") == reveal_round
                and entry_digest == ciphertext_sha256
            ):
                exact_count += 1
                exact = True
    if exact_count > 1:
        raise BootstrapOperatorError("exact_pending_commit_entry_not_unique")
    return exact, any_validator


def _ciphertext_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        raise BootstrapOperatorError("pending_commit_ciphertext_invalid")
    encoded = value.removeprefix("0x")
    try:
        decoded = bytes.fromhex(encoded)
    except ValueError as error:
        raise BootstrapOperatorError("pending_commit_ciphertext_invalid") from error
    if not decoded:
        raise BootstrapOperatorError("pending_commit_ciphertext_invalid")
    return decoded


def _weight_row(value: Any) -> list[list[int]]:
    result: list[list[int]] = []
    for item in _sequence(value, "validator_weight_row_invalid"):
        pair = _sequence(item, "validator_weight_pair_invalid")
        if len(pair) != 2:
            raise BootstrapOperatorError("validator_weight_pair_invalid")
        result.append(
            [
                _uint(pair[0], "validator_weight_uid_invalid", maximum=U16_MAX),
                _uint(pair[1], "validator_weight_value_invalid", maximum=U16_MAX),
            ]
        )
    return result


def _exact_sha256_commitment(value: Any, expected_sha256: str) -> int:
    commitment = _mapping(value, "manifest_anchor_storage_invalid")
    block = _uint(commitment.get("block"), "manifest_anchor_storage_block_invalid", minimum=1)
    info = _mapping(commitment.get("info"), "manifest_anchor_storage_info_invalid")
    fields = _sequence(info.get("fields"), "manifest_anchor_storage_fields_invalid")
    if len(fields) != 1:
        raise BootstrapOperatorError("manifest_anchor_storage_field_count_invalid")
    field = _mapping(fields[0], "manifest_anchor_storage_field_invalid")
    if set(field) != {"Sha256"}:
        raise BootstrapOperatorError("manifest_anchor_storage_field_type_invalid")
    raw_digest = field["Sha256"]
    if isinstance(raw_digest, bytes):
        digest = raw_digest
    elif isinstance(raw_digest, str) and raw_digest.startswith("0x"):
        try:
            digest = bytes.fromhex(raw_digest[2:])
        except ValueError as error:
            raise BootstrapOperatorError("manifest_anchor_storage_digest_invalid") from error
    else:
        raise BootstrapOperatorError("manifest_anchor_storage_digest_invalid")
    if len(digest) != 32 or digest.hex() != expected_sha256:
        raise BootstrapOperatorError("manifest_anchor_storage_digest_mismatch")
    return block


def _successful_extrinsic(value: Any, *, reason: str) -> BootstrapExtrinsicReference:
    if getattr(value, "success", None) is not True:
        raise BootstrapOperatorError(reason)
    extrinsic_id = getattr(value, "extrinsic_id", None)
    block_hash = getattr(value, "block_hash", None)
    if not isinstance(extrinsic_id, str) or not extrinsic_id or not _is_block_hash(block_hash):
        raise BootstrapOperatorError(f"{reason}_evidence_missing")
    prefix, separator, suffix = extrinsic_id.partition("-")
    if separator != "-" or not prefix.isdecimal() or not suffix.isdecimal():
        raise BootstrapOperatorError(f"{reason}_evidence_missing")
    try:
        return BootstrapExtrinsicReference(
            extrinsic_id=extrinsic_id,
            block_number=_uint(int(prefix), reason, minimum=1),
            extrinsic_index=_uint(int(suffix), reason),
            block_hash=block_hash,
        )
    except ValidationError as error:
        raise BootstrapOperatorError(f"{reason}_evidence_missing") from error


def _extrinsic_block_number(reference: BootstrapExtrinsicReference) -> int:
    return reference.block_number


def _in_submission_interval(
    signed: SignedBootstrapEligibilityManifest,
    block_number: int,
) -> bool:
    policy = signed.manifest.policy
    return (
        policy.activation_block <= block_number < policy.commit_stop_block
        and block_number >= signed.manifest.frozen_at_block
        and block_number - signed.manifest.frozen_at_block <= policy.manifest_ttl_blocks
    )


def _require_submission_headroom(
    signed: SignedBootstrapEligibilityManifest,
    block_number: int,
) -> None:
    latest_possible = block_number + _SUBMISSION_ERA_PERIOD
    if not _in_submission_interval(signed, block_number):
        raise BootstrapOperatorError("submission_snapshot_outside_policy")
    if latest_possible >= signed.manifest.policy.commit_stop_block or (
        latest_possible - signed.manifest.frozen_at_block
        > signed.manifest.policy.manifest_ttl_blocks
    ):
        raise BootstrapOperatorError("submission_era_lacks_policy_headroom")


def _partial_submission_receipt(
    signed: SignedBootstrapEligibilityManifest,
    *,
    validator_hotkey: str,
    anchor: BootstrapExtrinsicReference,
    reason_code: str,
    call_material_sha256: str | None = None,
) -> BootstrapWeightSubmissionReceipt:
    return BootstrapWeightSubmissionReceipt(
        schema=BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA,
        status="anchor_finalized_commit_not_submitted",
        reason_code=reason_code,
        manifest_sha256=signed.manifest_sha256,
        validator_hotkey=validator_hotkey,
        anchor=anchor,
        commit=None,
        call_material_sha256=call_material_sha256,
        submission_era_period=_SUBMISSION_ERA_PERIOD,
        storage_proofs_verified=False,
        terminal_verification_complete=False,
        created_at=datetime.now(timezone.utc),
    )


def _datetime_ms(value: datetime) -> int:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise TypeError("now must be a timezone-aware datetime")
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    delta = value.astimezone(timezone.utc) - epoch
    return delta.days * 86_400_000 + delta.seconds * 1_000 + delta.microseconds // 1_000


def _verify_historical_signed_manifest(signed: SignedBootstrapEligibilityManifest) -> None:
    try:
        verify_signed_bootstrap_eligibility_manifest(
            signed,
            expected_coordinator_hotkey=signed.manifest.policy.coordinator_hotkey,
            current_block=signed.manifest.frozen_at_block,
        )
    except (TypeError, ValueError) as error:
        raise BootstrapOperatorError("signed_manifest_invalid") from error


def _uint(value: Any, reason: str, *, minimum: int = 0, maximum: int = _MAX_U64) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise BootstrapOperatorError(reason)
    return value


def _bool(value: Any, reason: str) -> bool:
    if not isinstance(value, bool):
        raise BootstrapOperatorError(reason)
    return value


def _bool_or_zero_one(value: Any, reason: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise BootstrapOperatorError(reason)


def _mapping(value: Any, reason: str) -> Mapping[Any, Any]:
    if not isinstance(value, Mapping):
        raise BootstrapOperatorError(reason)
    return value


def _sequence(value: Any, reason: str) -> Sequence[Any]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(value, Sequence):
        raise BootstrapOperatorError(reason)
    return value


def _is_block_hash(value: Any) -> bool:
    if not isinstance(value, str) or len(value) != 66 or not value.startswith("0x"):
        return False
    try:
        return bytes.fromhex(value[2:]).hex() == value[2:]
    except ValueError:
        return False


__all__ = [
    "BOOTSTRAP_CALL_MATERIAL_SCHEMA",
    "BOOTSTRAP_CUTOVER_CHECKPOINT_SCHEMA",
    "BOOTSTRAP_HEALTH_SET_SCHEMA",
    "BOOTSTRAP_OPERATIONAL_PREFLIGHT_SCHEMA",
    "BOOTSTRAP_PILOT_REPLAY_SET_SCHEMA",
    "BOOTSTRAP_PREFLIGHT_SCHEMA",
    "BOOTSTRAP_SUBMISSION_RECEIPT_SCHEMA",
    "BOOTSTRAP_SUNSET_SIGNATURE_SCHEMA",
    "BOOTSTRAP_SUNSET_STATUS_SCHEMA",
    "BOOTSTRAP_TERMINAL_OBSERVATION_SCHEMA",
    "BOOTSTRAP_TERMINAL_SIGNATURE_SCHEMA",
    "LIVE_SUBMIT_ACKNOWLEDGEMENT",
    "BittensorBootstrapChain",
    "BootstrapChainParticipant",
    "BootstrapChainSnapshot",
    "BootstrapCutoverCheckpoint",
    "BootstrapHealthHTTPResult",
    "BootstrapHealthReceipt",
    "BootstrapHealthReceiptSet",
    "BootstrapManifestAnchorObservation",
    "BootstrapOperationalPreflight",
    "BootstrapOperatorError",
    "BootstrapPilotReplayReceipt",
    "BootstrapPilotReplaySet",
    "BootstrapRevealPeriodObservation",
    "BootstrapSunsetStatus",
    "BootstrapTerminalEvent",
    "BootstrapTerminalObservation",
    "BootstrapWeightCallMaterial",
    "BootstrapWeightPreflight",
    "BootstrapWeightScheduleEvidence",
    "BootstrapWeightSubmissionReceipt",
    "SignedBootstrapSunsetStatus",
    "SignedBootstrapTerminalObservation",
    "build_bootstrap_weight_call_material",
    "build_operational_preflight",
    "main",
    "observe_bootstrap_sunset",
    "observe_bootstrap_terminal",
    "probe_bootstrap_health",
    "replay_bootstrap_pilots",
    "run_cli",
    "sign_bootstrap_sunset_status",
    "sign_bootstrap_terminal_observation",
    "submit_bootstrap_weights",
    "validate_bootstrap_preflight",
    "verify_runtime_checkout",
]


if __name__ == "__main__":
    main()
