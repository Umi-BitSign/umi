"""Stopped-state preservation of both historical bootstrap worker journals.

This module never starts a legacy worker or submits a transaction. Historical
SDK receipts are retained claims. Successor readiness additionally needs an
owned storage observation and a live stopped-host lease. The old 16-block
timeout does not establish the mortality of an unrecorded signed extrinsic.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, field_validator, model_validator
from typing_extensions import Self

from .bootstrap_direct_weights import (
    DirectBootstrapCallMaterial,
    DirectBootstrapOperationalPreflight,
    DirectBootstrapSubmissionJournal,
    DirectBootstrapSubmissionReceipt,
    DirectBootstrapTransitionAuthorization,
    verify_direct_transition_authorization,
)
from .bootstrap_weights import (
    SignedBootstrapEligibilityManifest,
    bootstrap_policy_hash,
    verify_signed_bootstrap_eligibility_manifest,
)
from .competition_bridge_recovery import (
    HISTORY as BRIDGE_HISTORY,
)
from .competition_bridge_recovery import (
    JOURNAL as BRIDGE_JOURNAL,
)
from .competition_bridge_recovery import (
    audit_bridge_history,
)
from .encoding import account_id32
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .simple_bootstrap_validator import (
    SignedSimpleBootstrapLease,
    SimpleBootstrapJournal,
    verify_simple_bootstrap_lease,
)
from .validator_supervisor_publication import parse_canonical_signed_supervisor_bootstrap_result
from .validator_supervisor_worker import (
    BootstrapWorkerInputs,
    SupervisorBootstrapAuthorizationClaim,
    SupervisorBootstrapPublicationReceipt,
    SupervisorWorkerJournal,
)

_SNAPSHOT_DOMAIN = b"umi-legacy-bootstrap-snapshot-v1\0"
_CHECKPOINT_DOMAIN = b"umi-successor-recovery-checkpoint-v1\0"
_HEX = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PART = re.compile(r"^[A-Za-z0-9_.-]{1,256}$")
_CAPABILITY_TOKEN = object()


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


@dataclass(frozen=True, slots=True)
class LegacySnapshot:
    manifest: LegacySnapshotManifest
    _files: dict[str, bytes] = field(repr=False)
    _identities: dict[Path, tuple[int, ...]] = field(repr=False)
    _directory_entries: dict[Path, tuple[str, ...]] = field(repr=False)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_SNAPSHOT_DOMAIN + canonical_json_bytes(self.manifest)).hexdigest()


def _parts(value: str) -> tuple[str, ...]:
    parts = tuple(value.split("/"))
    if not parts or any(not _SAFE_PART.fullmatch(item) or item in {".", ".."} for item in parts):
        raise CompetitionRecoveryError("unsafe legacy relative path")
    return parts


def _fingerprint(info: os.stat_result) -> tuple[int, ...]:
    return (
        info.st_dev,
        info.st_ino,
        info.st_mode,
        info.st_uid,
        info.st_gid,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    )


def _open_path(path: Path, *, writable: bool = False) -> int:
    if not path.is_absolute() or path != Path(os.path.normpath(path)) or path == Path("/"):
        raise CompetitionRecoveryError("recovery path must be explicit and normalized")
    flags = os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    parent = os.open("/", flags | os.O_RDONLY | os.O_DIRECTORY)
    try:
        for name in path.parts[1:-1]:
            child = os.open(name, flags | os.O_RDONLY | os.O_DIRECTORY, dir_fd=parent)
            os.close(parent)
            parent = child
        return os.open(path.name, flags | (os.O_RDWR if writable else os.O_RDONLY), dir_fd=parent)
    finally:
        os.close(parent)


class _SnapshotReader:
    def __init__(
        self,
        root: Path,
        owner: int,
        limits: RecoveryLimits,
        *,
        directory_modes: frozenset[int] = frozenset({0o700, 0o500}),
        file_modes: frozenset[int] = frozenset({0o400, 0o600}),
        reference_mode: int | None = None,
    ):
        self.root, self.owner, self.limits = root, owner, limits
        self.directory_modes = directory_modes
        self.file_modes = file_modes
        self.reference_mode = reference_mode
        self.files: dict[str, bytes] = {}
        self.refs: list[LegacyFileReference] = []
        self.identities: dict[Path, tuple[int, ...]] = {}
        self.entries: dict[Path, tuple[str, ...]] = {}
        self.total = 0
        self.locks: list[int] = []

    def read(self, path: Path, depth: int = 0) -> None:
        descriptor = _open_path(path)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != self.owner:
                raise CompetitionRecoveryError("legacy state owner mismatch")
            if stat.S_ISDIR(info.st_mode):
                if stat.S_IMODE(info.st_mode) not in self.directory_modes:
                    raise CompetitionRecoveryError("legacy directory is not private")
                if (
                    depth > self.limits.maximum_depth
                    or len(self.entries) >= self.limits.maximum_directories
                ):
                    raise CompetitionRecoveryError("legacy directory limit exceeded")
                # scandir stops at the bound instead of materializing an unbounded directory.
                names: list[str] = []
                with os.scandir(descriptor) as listing:
                    for entry in listing:
                        _parts(entry.name)
                        names.append(entry.name)
                        if len(names) > self.limits.maximum_files + self.limits.maximum_directories:
                            raise CompetitionRecoveryError("legacy directory entry limit exceeded")
                self.entries[path] = tuple(sorted(names))
                self.identities[path] = _fingerprint(info)
                for name in self.entries[path]:
                    self.read(path / name, depth + 1)
                return
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) not in self.file_modes
            ):
                raise CompetitionRecoveryError(
                    "legacy file must be a private single-link regular file"
                )
            if (
                len(self.files) >= self.limits.maximum_files
                or info.st_size > self.limits.maximum_file_bytes
            ):
                raise CompetitionRecoveryError("legacy file limit exceeded")
            if self.total + info.st_size > self.limits.maximum_total_bytes:
                raise CompetitionRecoveryError("legacy aggregate byte limit exceeded")
            relative = path.relative_to(self.root).as_posix()
            if relative.endswith(".lock"):
                # Locks contain no authority, but acquiring the original inode catches a
                # still-running worker even before the separate host lease is checked.
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.locks.append(descriptor)
                descriptor = -1
                reader = self.locks[-1]
            else:
                reader = descriptor
            data = bytearray()
            while chunk := os.read(
                reader, min(65536, self.limits.maximum_file_bytes + 1 - len(data))
            ):
                data.extend(chunk)
                if len(data) > self.limits.maximum_file_bytes:
                    raise CompetitionRecoveryError("legacy file grew beyond its byte limit")
            if len(data) != info.st_size or _fingerprint(info) != _fingerprint(os.fstat(reader)):
                raise CompetitionRecoveryError("legacy file changed while reading")
            self.total += len(data)
            self.files[relative] = bytes(data)
            self.identities[path] = _fingerprint(info)
            self.refs.append(
                LegacyFileReference(
                    path=relative,
                    sha256=hashlib.sha256(data).hexdigest(),
                    size_bytes=len(data),
                    mode=(
                        stat.S_IMODE(info.st_mode)
                        if self.reference_mode is None
                        else self.reference_mode
                    ),
                )
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def close(self) -> None:
        for descriptor in self.locks:
            os.close(descriptor)
        self.locks.clear()


def _unchanged(snapshot: LegacySnapshot) -> None:
    for path, expected in snapshot._identities.items():
        descriptor = _open_path(path)
        try:
            if _fingerprint(os.fstat(descriptor)) != expected:
                raise CompetitionRecoveryError("legacy state changed after snapshot")
            if path in snapshot._directory_entries:
                with os.scandir(descriptor) as listing:
                    actual: list[str] = []
                    for item in listing:
                        actual.append(item.name)
                        if len(actual) > len(snapshot._directory_entries[path]):
                            raise CompetitionRecoveryError(
                                "legacy directory changed after snapshot"
                            )
                if tuple(sorted(actual)) != snapshot._directory_entries[path]:
                    raise CompetitionRecoveryError("legacy directory changed after snapshot")
        finally:
            os.close(descriptor)


def _model(payload: bytes, model: type[Any]) -> Any:
    value = model.model_validate_json(payload)
    if canonical_json_bytes(value) != payload:
        raise CompetitionRecoveryError("legacy JSON is not canonical")
    return value


def _full_row(signed: SignedBootstrapEligibilityManifest) -> list[list[int]]:
    eligible = {entry.uid for entry in signed.manifest.entries}
    return [[uid, 65535 if uid in eligible else 0] for uid in range(256)]


def _historical_inputs(files: dict[str, bytes], prefix: str, journal: SupervisorWorkerJournal):
    manifest_bytes = files[prefix + "signed-manifest.json"]
    auth_bytes = files[prefix + "direct-transition-authorization.json"]
    drain_bytes = files[prefix + "drain-checkpoint.json"]
    if (
        hashlib.sha256(manifest_bytes).hexdigest() != journal.manifest_input_sha256
        or hashlib.sha256(auth_bytes).hexdigest() != journal.transition_authorization_input_sha256
        or hashlib.sha256(drain_bytes).hexdigest() != journal.drain_checkpoint_input_sha256
    ):
        raise CompetitionRecoveryError("legacy input hash mismatch")
    signed = _model(manifest_bytes, SignedBootstrapEligibilityManifest)
    auth = _model(auth_bytes, DirectBootstrapTransitionAuthorization)
    drain = _model(drain_bytes, DirectBootstrapOperationalPreflight)
    verify_direct_transition_authorization(signed, auth, current_block=auth.valid_from_block)
    if (
        account_id32(auth.validator_hotkey) != account_id32(journal.validator_hotkey)
        or bootstrap_policy_hash(signed.manifest.policy) != journal.policy_sha256
        or drain.signed_manifest != signed
        or drain.chain.transition_authorization != auth
        or drain.chain.policy_sha256 != journal.policy_sha256
        or not auth.valid_from_block
        <= journal.valid_from_block
        <= journal.valid_through_block
        <= auth.expires_at_block
        or (
            journal.intent_finalized_block is not None
            and not journal.valid_from_block
            <= journal.intent_finalized_block
            <= journal.valid_through_block
        )
    ):
        raise CompetitionRecoveryError("legacy historical authority binding mismatch")
    return BootstrapWorkerInputs(signed, auth, drain, manifest_bytes, auth_bytes, drain_bytes)


def _validate_retained_output(
    journal: SupervisorWorkerJournal,
    inputs: BootstrapWorkerInputs,
    receipt: DirectBootstrapSubmissionReceipt,
    material: DirectBootstrapCallMaterial,
    direct: DirectBootstrapSubmissionJournal,
) -> None:
    # Match the legacy completed-output contract over the descriptor-read
    # snapshot. The old helper reopens the inner journal by pathname.
    authorization_hash = hashlib.sha256(
        canonical_json_bytes(inputs.transition_authorization)
    ).hexdigest()
    if (
        receipt.classification != "applied"
        or receipt.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or receipt.validator_uid != inputs.transition_authorization.validator_uid
        or account_id32(receipt.validator_hotkey)
        != account_id32(inputs.transition_authorization.validator_hotkey)
        or account_id32(receipt.validator_hotkey) != account_id32(journal.validator_hotkey)
        or receipt.call_material_sha256
        != hashlib.sha256(canonical_json_bytes(material)).hexdigest()
        or material.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or material.operational_preflight.chain.policy_sha256 != journal.policy_sha256
        or material.operational_preflight.signed_manifest != inputs.signed_manifest
        or material.operational_preflight.chain.transition_authorization
        != inputs.transition_authorization
        or direct.phase != "applied"
        or direct.submission_id != inputs.transition_authorization.submission_id
        or direct.manifest_sha256 != inputs.signed_manifest.manifest_sha256
        or direct.transition_authorization_sha256 != authorization_hash
        or account_id32(direct.validator_hotkey) != account_id32(journal.validator_hotkey)
        or direct.call_material_sha256 != receipt.call_material_sha256
        or direct.anchor != receipt.anchor
        or direct.weight_call != receipt.weight_call
        or direct.receipt_sha256 != hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
    ):
        raise CompetitionRecoveryError("retained completed output binding mismatch")


def _classify(
    files: dict[str, bytes],
    hotkey: str,
    sequence: int,
    directive_sha256: str,
    manifests: tuple[SignedBootstrapEligibilityManifest, ...],
    leases: tuple[SignedSimpleBootstrapLease, ...],
) -> tuple[list[LegacyEffect], list[str]]:
    effects: list[LegacyEffect] = []
    holds: set[str] = set()
    recognized: set[str] = set()
    supplied_manifests = {item.manifest_sha256: item for item in manifests}
    supplied_leases = {
        hashlib.sha256(canonical_json_bytes(item)).hexdigest(): item for item in leases
    }
    for item in manifests:
        verify_signed_bootstrap_eligibility_manifest(item)
    for path, data in files.items():
        if path.endswith(".lock"):
            recognized.add(path)
            if data:
                holds.add("nonempty_legacy_lock_file")
        elif path.endswith(".json"):
            value = json.loads(data)
            if canonical_json_bytes(value) != data:
                raise CompetitionRecoveryError("legacy JSON is not canonical")
    if BRIDGE_JOURNAL in files:
        bridge = audit_bridge_history(files, hotkey=hotkey)
        recognized.update(bridge.recognized)
        holds.update(bridge.holds)
        for path, journal in bridge.attempts:
            receipt = journal.weight_call
            effects.append(
                LegacyEffect(
                    path=path,
                    classification="retained_bridge_receipt" if receipt else "unresolved",
                    manifest_sha256=None,
                    minimum_effect_block=receipt.block_number
                    if receipt
                    else journal.attempt.preflight_block,
                    minimum_observation_block=max(
                        journal.last_observed_block,
                        receipt.block_number if receipt else journal.attempt.preflight_block,
                    ),
                    reason="registration_bridge_finalized_reference_retained"
                    if receipt
                    else "registration_bridge_attempt_mortality_unknown",
                )
            )
    if "journal.json" in files:
        recognized.add("journal.json")
        journal = _model(files["journal.json"], SimpleBootstrapJournal)
        if account_id32(journal.validator_hotkey) != account_id32(hotkey):
            raise CompetitionRecoveryError("common journal belongs to another validator")
        signed = supplied_manifests.get(journal.manifest_sha256)
        lease = supplied_leases.get(journal.lease_sha256)
        reason = "common_historical_context_missing"
        category = "unresolved"
        if signed is not None and lease is not None:
            verify_simple_bootstrap_lease(
                lease,
                signed_manifest=signed,
                expected_revision=lease.body.umi_git_revision,
                current_block=journal.preflight_block,
            )
            if journal.phase == "applied":
                category, reason = (
                    "retained_weight_receipt",
                    "common_finalized_weight_reference_retained",
                )
            elif journal.phase == "anchor_applied" and journal.anchor_call is not None:
                category, reason = (
                    "retained_anchor_receipt",
                    "common_finalized_anchor_reference_retained",
                )
            elif journal.phase == "recovered_applied":
                category, reason = (
                    "retained_recovered_effect",
                    "common_recovered_effect_without_extrinsic_mortality",
                )
            else:
                reason = "common_unrecorded_extrinsic_mortality_or_effect_unresolved"
        if category in {"unresolved", "retained_recovered_effect"}:
            holds.add(reason)
        effects.append(
            LegacyEffect(
                path="journal.json",
                classification=category,
                manifest_sha256=journal.manifest_sha256,
                minimum_effect_block=journal.weight_call.block_number
                if journal.weight_call
                else (journal.manifest_anchor_block or journal.preflight_block),
                minimum_observation_block=journal.observation_block or journal.preflight_block,
                reason=reason,
            )
        )
    transactions: dict[str, SupervisorWorkerJournal] = {}
    claims: dict[str, SupervisorBootstrapAuthorizationClaim] = {}
    for path, payload in files.items():
        parts = _parts(path)
        if len(parts) == 3 and parts[0] == "bootstrap-transactions" and parts[2] == "journal.json":
            if not _HEX.fullmatch(parts[1]):
                raise CompetitionRecoveryError("legacy directive directory is invalid")
            journal = _model(payload, SupervisorWorkerJournal)
            if (
                journal.directive_sha256 != parts[1]
                or account_id32(journal.validator_hotkey) != account_id32(hotkey)
                or journal.sequence > sequence
                or (journal.sequence == sequence and journal.directive_sha256 != directive_sha256)
            ):
                raise CompetitionRecoveryError(
                    "explicit journal hotkey or high-water binding mismatch"
                )
            transactions[parts[1]] = journal
        elif (
            len(parts) == 2
            and parts[0] == "bootstrap-authorizations"
            and parts[1].startswith("claim-")
            and parts[1].endswith(".json")
        ):
            claim = _model(payload, SupervisorBootstrapAuthorizationClaim)
            if (
                parts[1] != f"claim-{claim.submission_id}.json"
                or account_id32(claim.validator_hotkey) != account_id32(hotkey)
                or claim.sequence > sequence
                or (claim.sequence == sequence and claim.directive_sha256 != directive_sha256)
            ):
                raise CompetitionRecoveryError("global claim hotkey or high-water binding mismatch")
            claims[path] = claim
            recognized.add(path)
    matched_claims: set[str] = set()
    for directive, journal in sorted(transactions.items()):
        prefix = f"bootstrap-transactions/{directive}/"
        path = prefix + "journal.json"
        recognized.add(path)
        try:
            inputs = _historical_inputs(files, prefix, journal)
        except KeyError:
            holds.add("explicit_input_snapshot_incomplete")
            effects.append(
                LegacyEffect(
                    path=path,
                    classification="unresolved",
                    manifest_sha256=None,
                    minimum_effect_block=journal.intent_finalized_block or 0,
                    reason="explicit_input_snapshot_incomplete",
                )
            )
            continue
        recognized.update(
            prefix + name
            for name in (
                "signed-manifest.json",
                "direct-transition-authorization.json",
                "drain-checkpoint.json",
            )
        )
        auth = inputs.transition_authorization
        claim_path = f"bootstrap-authorizations/claim-{auth.submission_id}.json"
        claim = claims.get(claim_path)
        if claim is not None:
            if (
                claim.directive_sha256 != directive
                or claim.sequence != journal.sequence
                or claim.transition_authorization_sha256
                != journal.transition_authorization_input_sha256
                or claim.manifest_sha256 != inputs.signed_manifest.manifest_sha256
                or (
                    journal.intent_finalized_block is not None
                    and claim.intent_finalized_block != journal.intent_finalized_block
                )
                or not journal.valid_from_block
                <= claim.intent_finalized_block
                <= journal.valid_through_block
            ):
                raise CompetitionRecoveryError("global claim differs from its transaction")
            matched_claims.add(claim_path)
        inner = (
            "bootstrap-authorizations/operator-state/direct-"
            f"{journal.transition_authorization_input_sha256}-{account_id32(hotkey).hex()}.json"
        )
        category, reason = "unresolved", "explicit_effect_intent_unresolved"
        effect_block = journal.intent_finalized_block or 0
        observation_floor = effect_block
        if journal.phase == "prepared" and claim is None and inner not in files:
            category, reason = (
                "prepared_without_effect_intent",
                "explicit_prepared_without_global_claim",
            )
        elif claim is None:
            reason = "explicit_effect_without_global_claim"
        elif journal.phase in {"completed", "effect_intent"}:
            try:
                receipt = _model(
                    files[prefix + "submission-receipt.json"], DirectBootstrapSubmissionReceipt
                )
                material = _model(files[prefix + "call-material.json"], DirectBootstrapCallMaterial)
                direct = _model(files[inner], DirectBootstrapSubmissionJournal)
                _validate_retained_output(journal, inputs, receipt, material, direct)
                if journal.phase == "completed" and (
                    journal.receipt_sha256
                    != hashlib.sha256(canonical_json_bytes(receipt)).hexdigest()
                    or journal.call_material_sha256
                    != hashlib.sha256(canonical_json_bytes(material)).hexdigest()
                ):
                    raise CompetitionRecoveryError("completed journal output digest mismatch")
                if direct.weight_call is None:
                    raise CompetitionRecoveryError("completed inner journal lacks weight reference")
                category, reason = "retained_weight_receipt", "explicit_completed_output_replayed"
                effect_block = receipt.weight_call.block_number
                observation_floor = max(receipt.observation_block, effect_block)
                recognized.update(
                    {prefix + "submission-receipt.json", prefix + "call-material.json", inner}
                )
                result_path = prefix + "signed-bootstrap-result.json"
                publication_path = prefix + "publication-receipt.json"
                if result_path in files:
                    signed_result = parse_canonical_signed_supervisor_bootstrap_result(
                        files[result_path]
                    )
                    result = signed_result.result
                    if (
                        result.directive_sha256 != directive
                        or result.release_manifest_sha256 != journal.release_manifest_sha256
                        or result.signed_manifest != inputs.signed_manifest
                        or result.transition_authorization != auth
                        or result.drain_checkpoint != inputs.drain_checkpoint
                        or result.call_material != material
                        or result.submission_receipt != receipt
                        or result.submission_journal != direct
                    ):
                        raise CompetitionRecoveryError("legacy signed result output mismatch")
                    recognized.add(result_path)
                    if publication_path in files:
                        publication = _model(
                            files[publication_path], SupervisorBootstrapPublicationReceipt
                        )
                        if (
                            publication.submission_id != auth.submission_id
                            or publication.directive_sha256 != directive
                            or account_id32(publication.validator_hotkey) != account_id32(hotkey)
                            or publication.signed_result_sha256
                            != hashlib.sha256(files[result_path]).hexdigest()
                            or publication.signed_result_size_bytes != len(files[result_path])
                        ):
                            raise CompetitionRecoveryError(
                                "legacy publication receipt binding mismatch"
                            )
                        recognized.add(publication_path)
            except KeyError:
                reason = "explicit_completed_output_incomplete"
        if category == "unresolved":
            holds.add(reason)
        effects.append(
            LegacyEffect(
                path=path,
                classification=category,
                manifest_sha256=inputs.signed_manifest.manifest_sha256,
                minimum_effect_block=effect_block,
                minimum_observation_block=observation_floor,
                reason=reason,
            )
        )
    if set(claims) - matched_claims:
        holds.add("orphan_global_authorization_claim")
    for path in files:
        if path not in recognized:
            # Unknown outputs, orphan inner journals and temporary writes are
            # retained. They cannot be silently excluded from migration.
            holds.add("unclassified_legacy_file")
            effects.append(
                LegacyEffect(
                    path=path,
                    classification="unresolved",
                    manifest_sha256=None,
                    minimum_effect_block=0,
                    reason="unclassified_legacy_file",
                )
            )
    if not effects:
        holds.add("legacy_worker_state_empty")
    return sorted(effects, key=lambda item: item.path), sorted(holds)


@contextmanager
def snapshot_legacy_bootstrap(
    state_root: Path,
    *,
    expected_hotkey: str,
    service_uid: int,
    accepted_sequence: int,
    accepted_directive_sha256: str,
    accepted_at_finalized_block: int,
    config_sha256: str,
    installation_sha256: str,
    limits: RecoveryLimits,
    historical_manifests: tuple[SignedBootstrapEligibilityManifest, ...] = (),
    historical_leases: tuple[SignedSimpleBootstrapLease, ...] = (),
):
    """Retain exact bytes while holding any existing legacy worker lock inodes.

    This read-only context supplies no stopped-host or submission capability.
    A caller outside the host migration path can only obtain an inspection.
    """
    limits = _model(canonical_json_bytes(limits), RecoveryLimits)
    account_id32(expected_hotkey)
    if type(service_uid) is not int or service_uid < 0:
        raise CompetitionRecoveryError("invalid service UID")
    reader = _SnapshotReader(state_root, service_uid, limits)
    try:
        reader.read(state_root)
        effects, holds = _classify(
            reader.files,
            expected_hotkey,
            accepted_sequence,
            accepted_directive_sha256,
            historical_manifests,
            historical_leases,
        )
        for directory in reader.entries:
            if directory == state_root:
                continue
            relative = directory.relative_to(state_root).as_posix()
            parts = _parts(relative)
            allowed = relative in {
                "bootstrap-transactions",
                "bootstrap-authorizations",
                "bootstrap-authorizations/operator-state",
                BRIDGE_HISTORY,
            }
            if len(parts) == 2 and parts[0] == "bootstrap-transactions":
                allowed = bool(_HEX.fullmatch(parts[1]))
                if relative + "/journal.json" not in reader.files:
                    holds.append("legacy_transaction_directory_without_journal")
            if not allowed:
                holds.append("unclassified_legacy_directory")
        if (
            "service.lock" in reader.files
            and not {"journal.json", BRIDGE_JOURNAL} & reader.files.keys()
        ):
            holds.append("common_lock_without_journal")
        manifest = LegacySnapshotManifest(
            schema="umi-legacy-bootstrap-snapshot/1",
            validator_hotkey=expected_hotkey,
            accepted_sequence=accepted_sequence,
            accepted_directive_sha256=accepted_directive_sha256,
            accepted_at_finalized_block=accepted_at_finalized_block,
            config_sha256=config_sha256,
            installation_sha256=installation_sha256,
            files=sorted(reader.refs, key=lambda item: item.path),
            directories=sorted(
                path.relative_to(state_root).as_posix()
                for path in reader.entries
                if path != state_root
            ),
            effects=effects,
            holds=sorted(set(holds)),
        )
        snapshot = LegacySnapshot(manifest, reader.files, reader.identities, reader.entries)
        _unchanged(snapshot)
        yield snapshot
        _unchanged(snapshot)
    finally:
        reader.close()


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


@dataclass(frozen=True, slots=True)
class VerifiedRecoveryCheckpoint:
    checkpoint_sha256: str
    validator_hotkey: str
    accepted_sequence: int
    accepted_directive_sha256: str
    legacy_snapshot_sha256: str
    finalized_block: int
    finalized_block_hash: str
    genesis_hash: str
    installation_sha256: str
    _body: RecoveryCheckpointBody = field(repr=False)
    _stopped: Any = field(repr=False)
    _observation: Any = field(repr=False)
    _snapshot: LegacySnapshot = field(repr=False)
    _issuer: object = field(default=None, repr=False)
    _binding: str = field(default="", repr=False)


VerifiedLegacyRecoveryCheckpoint = VerifiedRecoveryCheckpoint


def _capability_binding(capability: VerifiedRecoveryCheckpoint) -> str:
    values = {
        name: getattr(capability, name)
        for name in capability.__dataclass_fields__
        if not name.startswith("_")
    }
    values["body_sha256"] = hashlib.sha256(canonical_json_bytes(capability._body)).hexdigest()
    values["snapshot_sha256"] = capability._snapshot.sha256
    values["source_identities"] = {
        str(path): [str(part) for part in value]
        for path, value in capability._snapshot._identities.items()
    }
    values["source_directory_entries"] = {
        str(path): list(entries)
        for path, entries in capability._snapshot._directory_entries.items()
    }
    return hashlib.sha256(canonical_json_bytes(values)).hexdigest()


def _check_stopped(stopped: Any) -> None:
    # A JSON object, Protocol implementation or caller-supplied boolean cannot
    # replace the kernel-checked stopped-host lease issued by the host adapter.
    from .competition_host_upgrade import StoppedSupervisor

    if type(stopped) is not StoppedSupervisor:
        raise CompetitionRecoveryError("recovery requires the owned stopped-host lease")
    stopped.recheck_stopped()


def _check_owned(observation: Any, stopped: Any) -> None:
    from .competition_chain_state import validate_owned_weight_observation

    validate_owned_weight_observation(observation)
    if account_id32(observation.validator_hotkey) != account_id32(stopped.validator_hotkey):
        raise CompetitionRecoveryError("owned observation belongs to another validator")
    if observation.block < stopped.accepted_at_finalized_block:
        raise CompetitionRecoveryError("owned observation predates the accepted high-water block")


def _reconcile_snapshot(
    snapshot: LegacySnapshot,
    observation: Any,
    manifests: tuple[SignedBootstrapEligibilityManifest, ...],
):
    manifests_by_digest = {item.manifest_sha256: item for item in manifests}
    for path, content in snapshot._files.items():
        if path.endswith("/signed-manifest.json"):
            signed = _model(content, SignedBootstrapEligibilityManifest)
            manifests_by_digest[signed.manifest_sha256] = signed
    holds = set(snapshot.manifest.holds)
    effects: list[LegacyEffect] = []
    bridge = None
    bridge_proven = False
    if BRIDGE_JOURNAL in snapshot._files:
        bridge = audit_bridge_history(snapshot._files, hotkey=snapshot.manifest.validator_hotkey)
        current = bridge.current
        if current.weight_call is not None:
            receipt = current.weight_call
            writers = [p for p in current.attempt.roster if p.hotkey == current.validator_hotkey]
            bridge_proven = (
                not bridge.holds
                and observation.block >= max(current.last_observed_block, receipt.block_number)
                and (
                    observation.block != receipt.block_number
                    or observation.block_hash == receipt.block_hash
                )
                and observation.validator_last_update == receipt.block_number
                and tuple(tuple(pair) for pair in current.attempt.expected_row)
                == observation.validator_row
                and len(writers) == 1
                and writers[0].uid == observation.validator_uid
            )
            if not bridge_proven:
                holds.add("registration_bridge_latest_effect_not_proven")
    for effect in snapshot.manifest.effects:
        update = effect
        if observation.block < effect.minimum_observation_block:
            holds.add("owned_observation_predates_historical_record")
            effects.append(update)
            continue
        if effect.classification == "retained_bridge_receipt":
            if bridge_proven:
                update = effect.model_copy(
                    update={
                        "classification": "proven_current_weight"
                        if effect.path == BRIDGE_JOURNAL
                        else "proven_superseded_weight",
                        "reason": "owned_finality_proves_latest_bridge_row"
                        if effect.path == BRIDGE_JOURNAL
                        else "terminal_bridge_history_precedes_proven_latest_row",
                    }
                )
            effects.append(update)
            continue
        if effect.classification in {"retained_anchor_receipt", "retained_weight_receipt"}:
            signed = manifests_by_digest.get(effect.manifest_sha256)
            anchor_ok = (
                effect.manifest_sha256 == observation.manifest_anchor_sha256
                and observation.manifest_anchor_block is not None
                and observation.manifest_anchor_block <= observation.block
            )
            if not anchor_ok:
                holds.add("historical_manifest_anchor_not_proven")
            elif effect.classification == "retained_anchor_receipt":
                if observation.manifest_anchor_block < effect.minimum_effect_block:
                    holds.add("historical_anchor_reference_not_reached")
                else:
                    update = effect.model_copy(
                        update={
                            "classification": "proven_current_anchor",
                            "reason": "owned_finality_proves_current_manifest_anchor",
                        }
                    )
            elif (
                effect.path == "journal.json"
                and bridge_proven
                and bridge.attempts
                and bridge.attempts[0][1].attempt.prior_last_update == effect.minimum_effect_block
            ):
                # This exact terminal journal was archived at bridge handoff.
                # All subsequent attempts retain terminal receipts, each next
                # preflight binds the prior LastUpdate, and the latest effect
                # is now proven by owned storage. No uncertain intent is cleared.
                update = effect.model_copy(
                    update={
                        "classification": "proven_superseded_weight",
                        "reason": "terminal_common_receipt_precedes_proven_bridge_history",
                    }
                )
            elif (
                signed is None
                or tuple(tuple(item) for item in _full_row(signed)) != observation.validator_row
                or observation.validator_last_update < effect.minimum_effect_block
                or observation.validator_last_update > observation.block
            ):
                holds.add("historical_weight_effect_not_proven")
            else:
                if effect.path != "journal.json":
                    prefix = effect.path.removesuffix("journal.json")
                    authorization = _model(
                        snapshot._files[prefix + "direct-transition-authorization.json"],
                        DirectBootstrapTransitionAuthorization,
                    )
                    if authorization.validator_uid != observation.validator_uid:
                        holds.add("historical_validator_uid_mapping_changed")
                update = effect.model_copy(
                    update={
                        "classification": "proven_current_weight",
                        "reason": "owned_finality_proves_current_historical_row",
                    }
                )
        effects.append(update)
    if observation.commit_reveal_enabled:
        holds.add("current_commit_reveal_transport_not_historical_direct_profile")
    return effects, sorted(holds)


def _snapshot_kwargs(stopped: Any, limits: RecoveryLimits, manifests: tuple, leases: tuple) -> dict:
    return dict(
        expected_hotkey=stopped.validator_hotkey,
        service_uid=stopped.service_uid,
        accepted_sequence=stopped.accepted_sequence,
        accepted_directive_sha256=stopped.accepted_directive_sha256,
        accepted_at_finalized_block=stopped.accepted_at_finalized_block,
        config_sha256=stopped.config_sha256,
        installation_sha256=stopped.installation_sha256,
        limits=limits,
        historical_manifests=manifests,
        historical_leases=leases,
    )


def _check_current_manifest(snapshot: LegacySnapshot, stopped: Any) -> None:
    expected_bridge = getattr(stopped, "expected_registration_bridge_policy_sha256", None)
    if expected_bridge is not None:
        if not isinstance(expected_bridge, str) or not _HEX.fullmatch(expected_bridge):
            raise CompetitionRecoveryError("stopped host bridge policy binding is invalid")
        if stopped.expected_manifest_sha256 is not None or BRIDGE_JOURNAL not in snapshot._files:
            raise CompetitionRecoveryError("stopped bridge host lacks its historical journal")
        bridge = audit_bridge_history(snapshot._files, hotkey=stopped.validator_hotkey)
        if (
            bridge.current.attempt is not None
            and bridge.current.attempt.policy_sha256 != expected_bridge
        ):
            raise CompetitionRecoveryError("bridge journal differs from installed signed policy")
        return
    expected = stopped.expected_manifest_sha256
    if not isinstance(expected, str) or not _HEX.fullmatch(expected):
        raise CompetitionRecoveryError("stopped host lacks authenticated historical manifest")
    if "journal.json" in snapshot._files:
        journal = _model(snapshot._files["journal.json"], SimpleBootstrapJournal)
        if journal.manifest_sha256 != expected:
            raise CompetitionRecoveryError("common journal differs from installed manifest")
    current = f"bootstrap-transactions/{stopped.accepted_directive_sha256}/signed-manifest.json"
    if current in snapshot._files:
        signed = _model(snapshot._files[current], SignedBootstrapEligibilityManifest)
        if signed.manifest_sha256 != expected:
            raise CompetitionRecoveryError(
                "current explicit journal differs from installed manifest"
            )
    if not any(item.manifest_sha256 == expected for item in snapshot.manifest.effects):
        raise CompetitionRecoveryError(
            "installed manifest has no retained historical worker context"
        )


def _context_payloads(manifests: tuple, leases: tuple, observation: Any, limits: RecoveryLimits):
    if len(manifests) + len(leases) + 1 > min(limits.maximum_files, 4096):
        raise CompetitionRecoveryError("historical context count exceeds limit")
    objects: dict[str, bytes] = {}
    refs: list[RecoveryContextReference] = []
    total_bytes = 0
    for kind, values in (
        ("manifest", manifests),
        ("lease", leases),
        ("owned_observation", (observation.evidence,)),
    ):
        for value in values:
            payload = value if isinstance(value, bytes) else canonical_json_bytes(value)
            if not 0 < len(payload) <= limits.maximum_file_bytes:
                raise CompetitionRecoveryError("historical context byte limit exceeded")
            sha = hashlib.sha256(payload).hexdigest()
            if any(item.kind == kind and item.sha256 == sha for item in refs):
                raise CompetitionRecoveryError("historical context contains duplicate entries")
            if sha not in objects:
                total_bytes += len(payload)
                if total_bytes > limits.maximum_total_bytes:
                    raise CompetitionRecoveryError(
                        "historical context aggregate byte limit exceeded"
                    )
            refs.append(RecoveryContextReference(kind=kind, sha256=sha, size_bytes=len(payload)))
            objects[sha] = payload
    return sorted(refs, key=lambda item: (item.kind, item.sha256)), objects


def _write_new_at(directory: int, name: str, payload: bytes) -> None:
    descriptor = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o400,
        dir_fd=directory,
    )
    try:
        offset = 0
        while offset < len(payload):
            count = os.write(descriptor, payload[offset:])
            if count <= 0:
                raise CompetitionRecoveryError("checkpoint write made no progress")
            offset += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _archive_root(root: Path, *, service_uid: int, limits: RecoveryLimits):
    descriptor = _open_path(root)
    lock = -1
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != service_uid
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise CompetitionRecoveryError("checkpoint root must be an owned private directory")
        try:
            lock = os.open(
                "recovery.lock",
                os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600,
                dir_fd=descriptor,
            )
            if os.getuid() == 0 and service_uid != 0:
                os.fchown(lock, service_uid, -1)
        except FileExistsError:
            lock = os.open(
                "recovery.lock", os.O_RDWR | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor
            )
        lock_info = os.fstat(lock)
        if (
            not stat.S_ISREG(lock_info.st_mode)
            or lock_info.st_uid != service_uid
            or lock_info.st_nlink != 1
            or stat.S_IMODE(lock_info.st_mode) != 0o600
            or lock_info.st_size != 0
        ):
            raise CompetitionRecoveryError("checkpoint archive lock is unsafe")
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        count = 0
        with os.scandir(descriptor) as listing:
            for entry in listing:
                if entry.name == "recovery.lock":
                    continue
                if not _HEX.fullmatch(entry.name):
                    raise CompetitionRecoveryError("checkpoint root contains an unknown entry")
                count += 1
                if count > limits.maximum_checkpoints:
                    raise CompetitionRecoveryError("checkpoint archive capacity exceeded")
        yield descriptor, count
    finally:
        if lock >= 0:
            os.close(lock)
        os.close(descriptor)


def _archive(
    body: RecoveryCheckpointBody,
    objects: dict[str, bytes],
    root: Path,
    owner: int,
    limits: RecoveryLimits,
) -> Path:
    payload = canonical_json_bytes(body)
    if (
        limits.maximum_depth < 2
        or limits.maximum_directories < 2
        or len(payload) > min(limits.maximum_checkpoint_bytes, limits.maximum_file_bytes)
        or sum(len(item) for item in objects.values()) + len(payload) > limits.maximum_total_bytes
        or len(objects) + 1 > limits.maximum_files
    ):
        raise CompetitionRecoveryError("checkpoint aggregate byte limit exceeded")
    sha = hashlib.sha256(_CHECKPOINT_DOMAIN + payload).hexdigest()
    target = root / sha
    with _archive_root(root, service_uid=owner, limits=limits) as (parent, count):
        try:
            existing = os.stat(sha, dir_fd=parent, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None:
            loaded, retained = _load_archive(
                target, expected_sha256=sha, owner=owner, limits=limits
            )
            if loaded != body or retained != objects:
                raise CompetitionRecoveryError("checkpoint hash directory contains different data")
            return target
        if count >= limits.maximum_checkpoints:
            raise CompetitionRecoveryError("checkpoint archive capacity exceeded")
        # The 0700 partial remains for inspection after an interrupted write.
        # Acceptance requires a complete 0500 tree. No target is ever replaced.
        os.mkdir(sha, mode=0o700, dir_fd=parent)
        archive = os.open(sha, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
        try:
            if os.getuid() == 0 and owner != 0:
                os.fchown(archive, owner, -1)
            os.mkdir("objects", mode=0o700, dir_fd=archive)
            object_dir = os.open(
                "objects", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=archive
            )
            try:
                if os.getuid() == 0 and owner != 0:
                    os.fchown(object_dir, owner, -1)
                for name, content in sorted(objects.items()):
                    _write_new_at(object_dir, name, content)
                    if os.getuid() == 0 and owner != 0:
                        os.chown(name, owner, -1, dir_fd=object_dir, follow_symlinks=False)
                os.fchmod(object_dir, 0o500)
                os.fsync(object_dir)
            finally:
                os.close(object_dir)
            _write_new_at(archive, "checkpoint.json", payload)
            if os.getuid() == 0 and owner != 0:
                os.chown("checkpoint.json", owner, -1, dir_fd=archive, follow_symlinks=False)
            os.fchmod(archive, 0o500)
            os.fsync(archive)
            os.fsync(parent)
        finally:
            os.close(archive)
    return target


def _load_archive(
    path: Path,
    *,
    expected_sha256: str,
    owner: int,
    limits: RecoveryLimits,
    shared_readonly: bool = False,
):
    if path.name != expected_sha256 or not _HEX.fullmatch(expected_sha256):
        raise CompetitionRecoveryError("checkpoint path digest mismatch")
    reader = _SnapshotReader(
        path,
        owner,
        limits,
        directory_modes=frozenset({0o555}) if shared_readonly else frozenset({0o700, 0o500}),
        file_modes=frozenset({0o444}) if shared_readonly else frozenset({0o400, 0o600}),
        reference_mode=0o400 if shared_readonly else None,
    )
    try:
        reader.read(path)
        for directory in reader.entries:
            expected_mode = 0o555 if shared_readonly else 0o500
            if stat.S_IMODE(os.stat(directory, follow_symlinks=False).st_mode) != expected_mode:
                raise CompetitionRecoveryError("checkpoint is incomplete or mutable")
        if set(reader.entries) != {path, path / "objects"}:
            raise CompetitionRecoveryError("checkpoint directory set is invalid")
        payload = reader.files.get("checkpoint.json", b"")
        if not 0 < len(payload) <= limits.maximum_checkpoint_bytes:
            raise CompetitionRecoveryError("checkpoint manifest is missing or oversized")
        body = _model(payload, RecoveryCheckpointBody)
        if hashlib.sha256(_CHECKPOINT_DOMAIN + payload).hexdigest() != expected_sha256:
            raise CompetitionRecoveryError("checkpoint body digest mismatch")
        sizes: dict[str, int] = {}
        for item in [*body.legacy_snapshot.files, *body.context]:
            previous = sizes.setdefault(item.sha256, item.size_bytes)
            if previous != item.size_bytes:
                raise CompetitionRecoveryError("checkpoint object has conflicting sizes")
        if set(reader.files) != {"checkpoint.json", *(f"objects/{sha}" for sha in sizes)}:
            raise CompetitionRecoveryError("checkpoint object set is incomplete or unexpected")
        objects = {}
        for sha, size in sizes.items():
            content = reader.files[f"objects/{sha}"]
            if len(content) != size or hashlib.sha256(content).hexdigest() != sha:
                raise CompetitionRecoveryError("checkpoint object is corrupt")
            objects[sha] = content
        expected_file_mode = 0o400
        if any(item.mode != expected_file_mode for item in reader.refs):
            raise CompetitionRecoveryError("checkpoint object is mutable")
        manifest = LegacySnapshot(
            body.legacy_snapshot, reader.files, reader.identities, reader.entries
        )
        _unchanged(manifest)
        return body, objects
    finally:
        reader.close()


def prepare_recovery_checkpoint(
    stopped: Any,
    observation: Any,
    *,
    destination_root: Path,
    limits: RecoveryLimits,
    historical_manifests: tuple[SignedBootstrapEligibilityManifest, ...] = (),
    historical_leases: tuple[SignedSimpleBootstrapLease, ...] = (),
) -> PreparedRecoveryCheckpoint:
    """Archive stopped historical state; unresolved effects produce a held checkpoint."""
    _check_stopped(stopped)
    _check_owned(observation, stopped)
    for root in (stopped.worker_state_root, stopped.state_root):
        if (
            destination_root == root
            or root in destination_root.parents
            or destination_root in root.parents
        ):
            raise CompetitionRecoveryError("checkpoint destination overlaps live state")
    with snapshot_legacy_bootstrap(
        stopped.worker_state_root,
        **_snapshot_kwargs(stopped, limits, historical_manifests, historical_leases),
    ) as snapshot:
        _check_stopped(stopped)
        _check_current_manifest(snapshot, stopped)
        effects, holds = _reconcile_snapshot(snapshot, observation, historical_manifests)
        refs, objects = _context_payloads(
            historical_manifests, historical_leases, observation, limits
        )
        for content in snapshot._files.values():
            objects[hashlib.sha256(content).hexdigest()] = content
        body = RecoveryCheckpointBody(
            schema="umi-successor-recovery-checkpoint/1",
            legacy_snapshot_sha256=snapshot.sha256,
            legacy_snapshot=snapshot.manifest,
            context=refs,
            finalized_block=observation.block,
            finalized_block_hash=observation.block_hash,
            genesis_hash=observation.genesis_hash,
            chain_config_sha256=observation.chain_config_sha256,
            owned_observation_sha256=observation.evidence_sha256,
            reconciled_effects=effects,
            holds=holds,
            prior_effects_reconciled=not holds,
        )
        _check_owned(observation, stopped)
        _check_stopped(stopped)
        _unchanged(snapshot)
        target = _archive(body, objects, destination_root, stopped.service_uid, limits)
        _check_stopped(stopped)
        _check_owned(observation, stopped)
        _unchanged(snapshot)
        return PreparedRecoveryCheckpoint(
            schema="umi-prepared-successor-recovery-checkpoint/1",
            checkpoint_path=str(target),
            checkpoint_sha256=target.name,
            legacy_snapshot_sha256=snapshot.sha256,
            prior_effects_reconciled=not holds,
            holds=holds,
        )


def load_retained_checkpoint_archive(
    path: Path,
    *,
    expected_sha256: str,
    owner: int,
    limits: RecoveryLimits,
) -> tuple[RecoveryCheckpointBody, dict[str, bytes]]:
    """Read a bounded, hash-bound archive. This grants no host or chain authority."""
    if type(owner) is not int or owner < 0:
        raise CompetitionRecoveryError("invalid checkpoint owner")
    limits = _model(canonical_json_bytes(limits), RecoveryLimits)
    return _load_archive(path, expected_sha256=expected_sha256, owner=owner, limits=limits)


def load_installed_retained_checkpoint_archive(
    path: Path,
    *,
    expected_sha256: str,
    owner: int,
    limits: RecoveryLimits,
) -> tuple[RecoveryCheckpointBody, dict[str, bytes]]:
    """Read a root-sealed copy projected read-only into a successor worker.

    The stopped source archive remains private 0500/0400. This separate loader
    accepts only the installed 0555/0444 representation and changes no content
    digest or recovery authority.
    """
    if type(owner) is not int or owner < 0:
        raise CompetitionRecoveryError("invalid checkpoint owner")
    limits = _model(canonical_json_bytes(limits), RecoveryLimits)
    return _load_archive(
        path,
        expected_sha256=expected_sha256,
        owner=owner,
        limits=limits,
        shared_readonly=True,
    )


def copy_retained_checkpoint_archive(
    path: Path,
    *,
    expected_sha256: str,
    owner: int,
    destination_root: Path,
    destination_owner: int,
    limits: RecoveryLimits,
) -> Path:
    """Copy exact verified archive bytes under a new owner, without deleting either copy.

    A privileged host can retain its own copy at the stopped acceptance boundary.
    Copying integrity-checked bytes does not promote the report into authority.
    """
    if type(destination_owner) is not int or destination_owner < 0:
        raise CompetitionRecoveryError("invalid destination owner")
    if destination_root == path or path in destination_root.parents:
        raise CompetitionRecoveryError("checkpoint copy destination overlaps the source")
    body, objects = load_retained_checkpoint_archive(
        path, expected_sha256=expected_sha256, owner=owner, limits=limits
    )
    result = _archive(body, objects, destination_root, destination_owner, limits)
    # Re-read both copies before handing a hash to the host acceptance step.
    if load_retained_checkpoint_archive(
        path, expected_sha256=expected_sha256, owner=owner, limits=limits
    ) != (body, objects):
        raise CompetitionRecoveryError("checkpoint source changed during copy")
    if load_retained_checkpoint_archive(
        result, expected_sha256=expected_sha256, owner=destination_owner, limits=limits
    ) != (body, objects):
        raise CompetitionRecoveryError("checkpoint destination readback mismatch")
    return result


def verify_recovery_checkpoint(
    checkpoint_path: Path,
    *,
    expected_checkpoint_sha256: str,
    stopped: Any,
    observation: Any,
    limits: RecoveryLimits,
) -> VerifiedRecoveryCheckpoint:
    """Recheck archive, original files, stopped host and fresh owned chain state."""
    _check_stopped(stopped)
    _check_owned(observation, stopped)
    body, objects = _load_archive(
        checkpoint_path,
        expected_sha256=expected_checkpoint_sha256,
        owner=stopped.service_uid,
        limits=limits,
    )
    if body.holds or not body.prior_effects_reconciled:
        raise CompetitionRecoveryError("historical effects remain unresolved")
    if body.finalized_block > observation.block or (
        body.finalized_block == observation.block
        and body.finalized_block_hash != observation.block_hash
    ):
        raise CompetitionRecoveryError("recovery finalized observation rolled back or changed")
    if (
        body.genesis_hash != observation.genesis_hash
        or body.chain_config_sha256 != observation.chain_config_sha256
    ):
        raise CompetitionRecoveryError("recovery chain observation configuration changed")
    manifests = tuple(
        _model(objects[item.sha256], SignedBootstrapEligibilityManifest)
        for item in body.context
        if item.kind == "manifest"
    )
    leases = tuple(
        _model(objects[item.sha256], SignedSimpleBootstrapLease)
        for item in body.context
        if item.kind == "lease"
    )
    with snapshot_legacy_bootstrap(
        stopped.worker_state_root, **_snapshot_kwargs(stopped, limits, manifests, leases)
    ) as snapshot:
        _check_current_manifest(snapshot, stopped)
        if (
            snapshot.sha256 != body.legacy_snapshot_sha256
            or snapshot.manifest != body.legacy_snapshot
        ):
            raise CompetitionRecoveryError(
                "current historical snapshot differs from the checkpoint"
            )
        _, holds = _reconcile_snapshot(snapshot, observation, manifests)
        if holds:
            raise CompetitionRecoveryError(
                "fresh chain observation does not reconcile historical effects"
            )
        for ref in body.legacy_snapshot.files:
            if snapshot._files[ref.path] != objects[ref.sha256]:
                raise CompetitionRecoveryError("retained historical bytes changed")
        _check_stopped(stopped)
        _check_owned(observation, stopped)
        capability = VerifiedRecoveryCheckpoint(
            expected_checkpoint_sha256,
            stopped.validator_hotkey,
            stopped.accepted_sequence,
            stopped.accepted_directive_sha256,
            snapshot.sha256,
            observation.block,
            observation.block_hash,
            observation.genesis_hash,
            stopped.installation_sha256,
            body,
            stopped,
            observation,
            snapshot,
            _CAPABILITY_TOKEN,
        )
        object.__setattr__(capability, "_binding", _capability_binding(capability))
        return capability


def validate_checkpoint_for_successor(
    checkpoint: VerifiedRecoveryCheckpoint,
    *,
    validator_hotkey: str,
    predecessor_directive_sha256: str,
    minimum_finalized_block: int,
) -> None:
    """Require an authentic, current stopped checkpoint before successor acceptance."""
    if (
        type(checkpoint) is not VerifiedRecoveryCheckpoint
        or checkpoint._issuer is not _CAPABILITY_TOKEN
        or checkpoint._binding != _capability_binding(checkpoint)
        or account_id32(checkpoint.validator_hotkey) != account_id32(validator_hotkey)
        or checkpoint.accepted_directive_sha256 != predecessor_directive_sha256
        or type(minimum_finalized_block) is not int
        or checkpoint.finalized_block < minimum_finalized_block
    ):
        raise CompetitionRecoveryError("invalid successor recovery checkpoint capability")
    _check_stopped(checkpoint._stopped)
    _check_owned(checkpoint._observation, checkpoint._stopped)
    _unchanged(checkpoint._snapshot)
