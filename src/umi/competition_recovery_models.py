"""Versioned recovery archive models. Parsing grants no host or chain authority."""

from __future__ import annotations

import hashlib
import re
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .encoding import account_id32
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes

_SNAPSHOT_DOMAIN = b"umi-legacy-bootstrap-snapshot-v1\0"
_SAFE_PART = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")


class CompetitionRecoveryError(ValueError):
    pass


class RecoveryLimits(StrictProtocolModel):
    schema_: Literal["umi-legacy-bootstrap-recovery-limits/1"] = Field(alias="schema")
    maximum_files: Annotated[int, Field(ge=1, le=65536)]
    maximum_directories: Annotated[int, Field(ge=1, le=65536)]
    maximum_depth: Annotated[int, Field(ge=1, le=8)]
    maximum_file_bytes: Annotated[int, Field(ge=1, le=16 * 1024**2)]
    maximum_total_bytes: Annotated[int, Field(ge=1, le=512 * 1024**2)]
    maximum_checkpoint_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**2)]
    maximum_checkpoints: Annotated[int, Field(ge=1, le=4096)]

    @model_validator(mode="after")
    def bounded_total(self) -> Self:
        if self.maximum_total_bytes < self.maximum_file_bytes:
            raise ValueError("recovery total limit is smaller than its per-file limit")
        return self


class LegacyFileReference(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=2048)]
    sha256: Hex32
    size_bytes: Annotated[int, Field(ge=0, le=16 * 1024**2)]
    mode: Literal[0o400, 0o600]

    @field_validator("path")
    @classmethod
    def safe_relative_path(cls, value: str) -> str:
        _parts(value)
        return value


class LegacyEffect(StrictProtocolModel):
    path: Annotated[str, Field(min_length=1, max_length=2048)]
    classification: Literal[
        "prepared_without_effect_intent",
        "retained_anchor_receipt",
        "retained_weight_receipt",
        "retained_bridge_receipt",
        "retained_recovered_effect",
        "proven_current_anchor",
        "proven_current_weight",
        "proven_superseded_weight",
        "unresolved",
    ]
    manifest_sha256: Hex32 | None
    minimum_effect_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    minimum_observation_block: Annotated[int, Field(ge=0, le=2**53 - 1)] = 0
    reason: Annotated[str, Field(min_length=1, max_length=128)]


class LegacySnapshotManifest(StrictProtocolModel):
    schema_: Literal["umi-legacy-bootstrap-snapshot/1"] = Field(alias="schema")
    validator_hotkey: Annotated[str, Field(min_length=1, max_length=256)]
    accepted_sequence: Annotated[int, Field(ge=1, le=2**53 - 1)]
    accepted_directive_sha256: Hex32
    accepted_at_finalized_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    config_sha256: Hex32
    installation_sha256: Hex32
    files: Annotated[list[LegacyFileReference], Field(max_length=65536)]
    directories: Annotated[list[str], Field(max_length=65536)]
    effects: Annotated[list[LegacyEffect], Field(max_length=65536)]
    holds: Annotated[list[str], Field(max_length=65536)]
    snapshot_does_not_prove_service_stopped: Literal[True] = True
    chain_submission_authorized: Literal[False] = False

    @field_validator("validator_hotkey")
    @classmethod
    def public_hotkey(cls, value: str) -> str:
        account_id32(value)
        return value

    @model_validator(mode="after")
    def canonical_lists(self) -> Self:
        for values in (
            [item.path for item in self.files],
            self.directories,
            [item.path for item in self.effects],
            self.holds,
        ):
            if values != sorted(set(values)):
                raise ValueError("snapshot lists must be uniquely sorted")
        for value in self.directories:
            _parts(value)
        return self


def _parts(value: str) -> tuple[str, ...]:
    parts = tuple(value.split("/"))
    if not parts or any(not _SAFE_PART.fullmatch(item) or item in {".", ".."} for item in parts):
        raise CompetitionRecoveryError("unsafe legacy relative path")
    return parts


class RecoveryContextReference(StrictProtocolModel):
    kind: Literal["manifest", "lease", "owned_observation"]
    sha256: Hex32
    size_bytes: Annotated[int, Field(gt=0, le=64 * 1024**2)]


class RecoveryCheckpointBody(StrictProtocolModel):
    schema_: Literal["umi-successor-recovery-checkpoint/1"] = Field(alias="schema")
    legacy_snapshot_sha256: Hex32
    legacy_snapshot: LegacySnapshotManifest
    context: Annotated[list[RecoveryContextReference], Field(max_length=4096)]
    finalized_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    finalized_block_hash: BlockHash
    genesis_hash: BlockHash
    chain_config_sha256: Hex32
    owned_observation_sha256: Hex32
    reconciled_effects: Annotated[list[LegacyEffect], Field(max_length=65536)]
    holds: Annotated[list[str], Field(max_length=65536)]
    prior_effects_reconciled: bool
    pending_queue_absence_proven: Literal[False] = False
    historical_authorizations_reactivated: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def cross_bindings(self) -> Self:
        if (
            self.legacy_snapshot_sha256
            != hashlib.sha256(
                _SNAPSHOT_DOMAIN + canonical_json_bytes(self.legacy_snapshot)
            ).hexdigest()
        ):
            raise ValueError("checkpoint snapshot digest mismatch")
        if self.prior_effects_reconciled != (not self.holds):
            raise ValueError("checkpoint disposition does not match its holds")
        keys = [(item.kind, item.sha256) for item in self.context]
        if keys != sorted(set(keys)) or self.holds != sorted(set(self.holds)):
            raise ValueError("checkpoint references and holds must be canonical")
        if [item.path for item in self.reconciled_effects] != [
            item.path for item in self.legacy_snapshot.effects
        ]:
            raise ValueError("checkpoint effects do not cover the snapshot")
        observed = [item for item in self.context if item.kind == "owned_observation"]
        if len(observed) != 1 or observed[0].sha256 != self.owned_observation_sha256:
            raise ValueError("checkpoint owned observation reference mismatch")
        return self


class PreparedRecoveryCheckpoint(StrictProtocolModel):
    schema_: Literal["umi-prepared-successor-recovery-checkpoint/1"] = Field(alias="schema")
    checkpoint_path: str
    checkpoint_sha256: Hex32
    legacy_snapshot_sha256: Hex32
    prior_effects_reconciled: bool
    holds: list[str]
    chain_submission_authorized: Literal[False] = False


class BridgeRecoveryOutcome(StrictProtocolModel):
    """A retained result summary, never a substitute for fresh proof collection."""

    path: Annotated[str, Field(min_length=1, max_length=2048)]
    attempt_id: Hex32
    journal_sha256: Hex32
    disposition: Literal["applied", "failed", "expired_nonce_available"]
    resolution_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    resolution_block_hash: BlockHash
    extrinsic_index: Annotated[int, Field(ge=0, le=2**32 - 1)] | None
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)] | None
    verified_head_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    verified_head_hash: BlockHash

    @model_validator(mode="after")
    def outcome_binding(self) -> Self:
        _parts(self.path)
        expiry = self.disposition == "expired_nonce_available"
        if expiry != (self.nonce is not None) or expiry != (self.extrinsic_index is None):
            raise ValueError("bridge recovery outcome has inconsistent fields")
        if self.resolution_block > self.verified_head_block or (
            self.resolution_block == self.verified_head_block
            and self.resolution_block_hash != self.verified_head_hash
        ):
            raise ValueError("bridge recovery outcome exceeds its verified head")
        return self


class TransactionRecoveryEffect(LegacyEffect):
    classification: Literal[
        "prepared_without_effect_intent",
        "retained_anchor_receipt",
        "retained_weight_receipt",
        "retained_bridge_receipt",
        "retained_recovered_effect",
        "proven_current_anchor",
        "proven_current_weight",
        "proven_superseded_weight",
        "unresolved",
        "proven_failed_bridge_call",
        "proven_expired_bridge_attempt",
    ]


class TransactionRecoveryCheckpointBody(RecoveryCheckpointBody):
    schema_: Literal["umi-successor-recovery-checkpoint/2"] = Field(alias="schema")
    reconciled_effects: Annotated[list[TransactionRecoveryEffect], Field(max_length=65536)]
    bridge_outcomes: Annotated[list[BridgeRecoveryOutcome], Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def outcome_coverage(self) -> Self:
        paths = [item.path for item in self.bridge_outcomes]
        if paths != sorted(set(paths)):
            raise ValueError("checkpoint bridge outcomes must be uniquely sorted")
        expected = {
            item.path
            for item in self.legacy_snapshot.effects
            if item.reason == "registration_bridge_transaction_proof_required"
        }
        if set(paths) != expected:
            raise ValueError("checkpoint outcomes do not cover version-2 bridge records")
        files = {item.path: item for item in self.legacy_snapshot.files}
        for item in self.bridge_outcomes:
            if item.path not in files or files[item.path].sha256 != item.journal_sha256:
                raise ValueError("checkpoint outcome journal bytes changed")
            if item.verified_head_block > self.finalized_block or (
                item.verified_head_block == self.finalized_block
                and item.verified_head_hash != self.finalized_block_hash
            ):
                raise ValueError("checkpoint observation predates outcome collection")
        return self


def recovery_checkpoint_digest(body: RecoveryCheckpointBody) -> str:
    domains = {
        RecoveryCheckpointBody: b"umi-successor-recovery-checkpoint-v1\0",
        TransactionRecoveryCheckpointBody: b"umi-successor-recovery-checkpoint-v2\0",
    }
    if type(body) not in domains:
        raise CompetitionRecoveryError("unsupported recovery checkpoint type")
    return hashlib.sha256(domains[type(body)] + canonical_json_bytes(body)).hexdigest()
