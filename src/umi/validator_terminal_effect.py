"""Crash-safe terminal effect for a live shadow ``calibration_no_weight`` window.

The terminal boundary is intentionally read-only with respect to Subtensor.  It
waits for the proof-derived weight-commit close, captures the complete finalized
announcement-to-close interval, and journals a compact semantic binding before it
signs or publishes an audit bundle.  Bundle publication happens only from the
adapter's ``after_receipt`` hook, so a signed public artifact can never authorize a
control-plane transition that lacks a durable terminal receipt.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any, Literal, Protocol, runtime_checkable

from pydantic import Field, JsonValue, model_validator
from typing_extensions import Self

from .calibration_bundle import (
    MAX_CALIBRATION_OBJECT_BYTES,
    VALIDATOR_TERMINAL_STAGE_MEDIA_TYPE,
    VALIDATOR_TERMINAL_STAGE_SCHEMA,
    CalibrationBundleManifest,
    CalibrationObjectInput,
    CalibrationStageInput,
    CalibrationVerificationPorts,
    VerifiedCalibrationBundle,
    calibration_stage_replay_hook_id,
    verify_calibration_bundle,
    write_calibration_bundle,
)
from .chain_evidence import FinalizedSnapshotRef
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, StrictProtocolModel, canonical_json_bytes
from .validator_adapters import StageEffectResult, TerminalStageEffect
from .validator_journal import StageJournalRecord, StageObjectInput, ValidatorStageJournal
from .validator_no_weight import LiveNoWeightCapturePort
from .validator_state import StagePending, StageWorkItem, TerminalOutcome, WindowStage

_BLOCK_CHAIN_DOMAIN = b"umi-validator-no-weight-semantic-chain-v1\0"
TERMINAL_STAGE_SCHEMA = VALIDATOR_TERMINAL_STAGE_SCHEMA
TERMINAL_STAGE_MEDIA_TYPE = VALIDATOR_TERMINAL_STAGE_MEDIA_TYPE


class TerminalEffectError(RuntimeError):
    """Stable fail-closed terminal capture or publication failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


class TerminalStageDocument(StrictProtocolModel):
    """Compact receipt object bound to the proof-bearing scan in the bundle."""

    schema_: Literal[TERMINAL_STAGE_SCHEMA] = Field(alias="schema")
    protocol: Literal[PROTOCOL_VERSION]
    window_id: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    window_index: Annotated[int, Field(ge=0)]
    scoring_policy_hash: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    validator_account_id32: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    announcement_block: Annotated[int, Field(gt=0)]
    weight_commit_close_snapshot: dict[str, JsonValue]
    scanned_blocks: Annotated[int, Field(gt=1)]
    scanned_calls: Annotated[int, Field(ge=0)]
    scanned_events: Annotated[int, Field(ge=0)]
    scan_evidence_chain_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    translation_weights_active: Literal[False]
    weight_submission_performed: Literal[False]
    terminal_classification: Literal["calibration_no_weight"]

    @model_validator(mode="after")
    def validate_close_snapshot(self) -> Self:
        _snapshot_from_json(self.weight_commit_close_snapshot)
        return self

    @property
    def close_snapshot(self) -> FinalizedSnapshotRef:
        return _snapshot_from_json(self.weight_commit_close_snapshot)


@runtime_checkable
class WeightBuildCloseResolver(Protocol):
    """Replay the authoritative weight receipt and return its exact close block."""

    def __call__(
        self,
        *,
        policy: ScoringPolicy,
        receipt: StageJournalRecord,
        objects: Mapping[str, bytes],
    ) -> FinalizedSnapshotRef: ...


@runtime_checkable
class CalibrationBundleVerifierPort(Protocol):
    async def verify(self, root: Path) -> CalibrationBundleManifest: ...


@dataclass(frozen=True, slots=True)
class ReplayCalibrationBundleVerifier:
    """Production bundle-verifier adapter with all policy-pinned replay ports."""

    ports: CalibrationVerificationPorts

    def __post_init__(self) -> None:
        if not isinstance(self.ports, CalibrationVerificationPorts):
            raise TypeError("ports must be CalibrationVerificationPorts")

    async def verify(self, root: Path) -> CalibrationBundleManifest:
        verified = await verify_calibration_bundle(root, ports=self.ports)
        if not isinstance(verified, VerifiedCalibrationBundle):
            raise TerminalEffectError("bundle_verifier_result_invalid")
        return verified.manifest


class CalibrationNoWeightTerminalEffect:
    """Produce and publish one proof-bearing shadow terminal result."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        journal: ValidatorStageJournal,
        no_weight_capture: LiveNoWeightCapturePort,
        weight_close_resolver: WeightBuildCloseResolver,
        bundle_root: str | Path,
        bundle_verifier: CalibrationBundleVerifierPort,
        validator_account: str | bytes,
        signature_scheme: Literal["sr25519", "ed25519"],
        manifest_signer: Callable[[bytes], bytes],
        software_revisions: Mapping[str, str],
        bundle_writer: Callable[..., Path] = write_calibration_bundle,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be a ScoringPolicy")
        if policy.translation_weights_active:
            raise ValueError("calibration terminal effect requires an inactive policy")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be a ValidatorStageJournal")
        if not isinstance(no_weight_capture, LiveNoWeightCapturePort) and not callable(
            getattr(no_weight_capture, "capture", None)
        ):
            raise TypeError("no_weight_capture must implement capture")
        if not callable(weight_close_resolver):
            raise TypeError("weight_close_resolver must be callable")
        if not callable(getattr(bundle_verifier, "verify", None)):
            raise TypeError("bundle_verifier must implement verify")
        if signature_scheme not in {"sr25519", "ed25519"}:
            raise ValueError("manifest signature scheme is unsupported")
        if not callable(manifest_signer) or not callable(bundle_writer):
            raise TypeError("bundle signer and writer must be callable")
        revisions = dict(software_revisions)
        if not revisions or any(
            not isinstance(key, str)
            or not key.strip()
            or not isinstance(value, str)
            or not value.strip()
            for key, value in revisions.items()
        ):
            raise ValueError("software revisions must contain non-empty strings")

        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.journal = journal
        self.no_weight_capture = no_weight_capture
        self.weight_close_resolver = weight_close_resolver
        self.bundle_root = Path(bundle_root)
        self.bundle_verifier = bundle_verifier
        self.validator_account_id32 = account_id32(validator_account)
        if self.validator_account_id32 != no_weight_capture.validator_account_id32:
            raise ValueError("no-weight capture belongs to another validator")
        self.signature_scheme = signature_scheme
        self.manifest_signer = manifest_signer
        self.software_revisions = dict(sorted(revisions.items()))
        self.bundle_writer = bundle_writer
        self._captured: dict[str, Any] = {}
        _prepare_directory(self.bundle_root)
        _prepare_directory(self.bundle_root / ".locks")
        _prepare_directory(self.bundle_root / ".staging")

    async def perform(
        self,
        *,
        operation_id: str,
        work: StageWorkItem,
    ) -> StageEffectResult:
        if work.stage is not WindowStage.COMMIT_AND_TERMINAL_STATE:
            raise TerminalEffectError("terminal_effect_wrong_stage")
        plan = work.window.plan
        if plan.scoring_policy_hash != self.policy_hash:
            raise TerminalEffectError("terminal_policy_hash_mismatch")
        close = self._weight_close(plan.window_id)
        captured = await self.no_weight_capture.capture(
            start_block=plan.announcement_block,
            end_block=close.block_number,
        )
        if captured is None:
            raise StagePending("weight_commit_close_finality_pending")
        document = _terminal_document(
            policy_hash=self.policy_hash,
            validator_account_id32=self.validator_account_id32,
            work=work,
            close=close,
            captured=captured,
        )
        self._captured[plan.window_id] = captured
        encoded = canonical_json_bytes(document)
        return StageEffectResult(
            operation_id=operation_id,
            window_id=plan.window_id,
            stage=work.stage,
            objects=(StageObjectInput(encoded, TERMINAL_STAGE_MEDIA_TYPE),),
            metadata={
                "announcement_block": plan.announcement_block,
                "terminal_stage_sha256": hashlib.sha256(encoded).hexdigest(),
                "translation_weights_active": False,
                "weight_commit_close_block": close.block_number,
                "weight_commit_close_block_hash": close.block_hash,
                "weight_commit_close_state_root": close.state_root,
                "weight_submission_performed": False,
            },
            decision=TerminalStageEffect(
                outcome=TerminalOutcome.CALIBRATION_NO_WEIGHT,
                audit_release_block=close.block_number,
            ),
        )

    async def after_receipt(
        self,
        *,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        if record.receipt.stage != WindowStage.COMMIT_AND_TERMINAL_STATE.value:
            raise TerminalEffectError("terminal_receipt_stage_mismatch")
        plan = work.window.plan
        document = self._load_terminal_document(record)
        close = self._weight_close(plan.window_id)
        if document.close_snapshot != close:
            raise TerminalEffectError("terminal_close_snapshot_changed")
        if await self._verify_existing_bundle(work=work, close=close):
            self._captured.pop(plan.window_id, None)
            return
        captured = self._captured.pop(plan.window_id, None)
        if captured is None:
            captured = await self.no_weight_capture.capture(
                start_block=plan.announcement_block,
                end_block=close.block_number,
            )
        if captured is None:
            raise StagePending("terminal_bundle_scan_recovery_pending")
        if (
            _terminal_document(
                policy_hash=self.policy_hash,
                validator_account_id32=self.validator_account_id32,
                work=work,
                close=close,
                captured=captured,
            )
            != document
        ):
            raise TerminalEffectError("terminal_scan_recovery_mismatch")
        await self._publish_bundle(work=work, close=close, captured=captured)

    async def _verify_existing_bundle(self, *, work, close) -> bool:
        window_id = work.window.plan.window_id
        final_root = self.bundle_root / window_id
        if not final_root.exists():
            return False
        lock_path = self.bundle_root / ".locks" / f"{window_id}.lock"
        with _exclusive_lock(lock_path):
            if not final_root.exists():
                return False
            manifest = await self.bundle_verifier.verify(final_root)
            _validate_manifest_binding(
                manifest,
                policy_hash=self.policy_hash,
                work=work,
                close=close,
                validator_account_id32=self.validator_account_id32,
            )
            return True

    def _weight_close(self, window_id: str) -> FinalizedSnapshotRef:
        records = self.journal.load_window(window_id)
        if len(records) < 6:
            raise TerminalEffectError("weight_build_receipt_missing")
        weight = records[5]
        if weight.receipt.stage != WindowStage.WEIGHT_BUILD.value:
            raise TerminalEffectError("weight_build_receipt_order_mismatch")
        objects = {item.sha256: self.journal.read_object(item) for item in weight.receipt.objects}
        try:
            close = self.weight_close_resolver(
                policy=self.policy,
                receipt=weight,
                objects=objects,
            )
        except Exception as error:
            raise TerminalEffectError("weight_close_replay_failed") from error
        if not isinstance(close, FinalizedSnapshotRef):
            raise TerminalEffectError("weight_close_replay_result_invalid")
        return close

    def _load_terminal_document(self, record: StageJournalRecord) -> TerminalStageDocument:
        matches = [
            item for item in record.receipt.objects if item.media_type == TERMINAL_STAGE_MEDIA_TYPE
        ]
        if len(matches) != 1 or len(record.receipt.objects) != 1:
            raise TerminalEffectError("terminal_receipt_object_set_invalid")
        encoded = self.journal.read_object(matches[0])
        try:
            document = TerminalStageDocument.model_validate_json(encoded)
        except ValueError as error:
            raise TerminalEffectError("terminal_receipt_object_invalid") from error
        if canonical_json_bytes(document) != encoded:
            raise TerminalEffectError("terminal_receipt_object_noncanonical")
        return document

    async def _publish_bundle(self, *, work, close, captured) -> None:
        window_id = work.window.plan.window_id
        final_root = self.bundle_root / window_id
        lock_path = self.bundle_root / ".locks" / f"{window_id}.lock"
        with _exclusive_lock(lock_path):
            if final_root.exists():
                manifest = await self.bundle_verifier.verify(final_root)
                _validate_manifest_binding(
                    manifest,
                    policy_hash=self.policy_hash,
                    work=work,
                    close=close,
                    validator_account_id32=self.validator_account_id32,
                )
                return
            staging_parent = self.bundle_root / ".staging"
            staging = Path(tempfile.mkdtemp(prefix=f".{window_id}.", dir=staging_parent))
            try:
                records = self.journal.load_window(window_id)
                if len(records) != 7:
                    raise TerminalEffectError("terminal_bundle_receipt_prefix_incomplete")
                stages = tuple(
                    CalibrationStageInput(
                        receipt_bytes=item.receipt_bytes,
                        objects=tuple(
                            CalibrationObjectInput(
                                self.journal.read_object(reference),
                                reference.media_type,
                            )
                            for reference in item.receipt.objects
                        ),
                        replay_hook_id=calibration_stage_replay_hook_id(
                            self.policy,
                            item.receipt.stage,
                        ),
                    )
                    for item in records
                )
                self.bundle_writer(
                    staging,
                    policy=self.policy,
                    window_id=window_id,
                    window_index=work.window.plan.window_index,
                    software_revisions=self.software_revisions,
                    validator_account=self.validator_account_id32,
                    weight_commit_close_snapshot=close,
                    audit_release_snapshot=close,
                    no_weight_scan=captured,
                    stages=stages,
                    signature_scheme=self.signature_scheme,
                    manifest_signer=self.manifest_signer,
                    maximum_object_bytes=MAX_CALIBRATION_OBJECT_BYTES,
                    maximum_bundle_bytes=self.policy.limits.maximum_audit_bundle_bytes,
                )
                manifest = await self.bundle_verifier.verify(staging)
                _validate_manifest_binding(
                    manifest,
                    policy_hash=self.policy_hash,
                    work=work,
                    close=close,
                    validator_account_id32=self.validator_account_id32,
                )
                try:
                    os.rename(staging, final_root)
                except OSError as error:
                    if (
                        error.errno not in {errno.EEXIST, errno.ENOTEMPTY}
                        or not final_root.exists()
                    ):
                        raise
                    existing = await self.bundle_verifier.verify(final_root)
                    _validate_manifest_binding(
                        existing,
                        policy_hash=self.policy_hash,
                        work=work,
                        close=close,
                        validator_account_id32=self.validator_account_id32,
                    )
                else:
                    staging = Path()
                    _fsync_directory(self.bundle_root)
            finally:
                if staging != Path() and staging.exists():
                    _remove_staging_directory(staging, staging_parent, window_id)


def replay_terminal_stage_receipt(
    *,
    policy: ScoringPolicy,
    evidence: Any,
    receipt: Any,
    objects: Mapping[str, bytes],
) -> bool:
    """Replay the compact terminal receipt; raw chain replay is bundle-global."""

    try:
        if (
            not isinstance(policy, ScoringPolicy)
            or policy.translation_weights_active
            or evidence.stage_id != WindowStage.COMMIT_AND_TERMINAL_STATE.value
            or receipt.stage != WindowStage.COMMIT_AND_TERMINAL_STATE.value
            or evidence.window_id != receipt.window_id
        ):
            return False
        references = {item.sha256: item for item in receipt.objects}
        if set(objects) != set(references) or len(references) != 1:
            return False
        reference = next(iter(references.values()))
        if reference.media_type != TERMINAL_STAGE_MEDIA_TYPE:
            return False
        encoded = objects[reference.sha256]
        document = TerminalStageDocument.model_validate_json(encoded)
        if canonical_json_bytes(document) != encoded:
            return False
        metadata = receipt.metadata
        effect = metadata.get("metadata")
        terminal = metadata.get("terminal")
        return bool(
            metadata.get("schema") == "umi-validator-adapter-result/1"
            and metadata.get("kind") == "terminal"
            and isinstance(effect, Mapping)
            and isinstance(terminal, Mapping)
            and document.window_id == receipt.window_id
            and document.scoring_policy_hash == scoring_policy_hash(policy)
            and document.translation_weights_active is False
            and effect.get("terminal_stage_sha256") == hashlib.sha256(encoded).hexdigest()
            and effect.get("announcement_block") == document.announcement_block
            and effect.get("weight_commit_close_block") == document.close_snapshot.block_number
            and effect.get("weight_commit_close_block_hash") == document.close_snapshot.block_hash
            and effect.get("weight_commit_close_state_root") == document.close_snapshot.state_root
            and effect.get("translation_weights_active") is False
            and effect.get("weight_submission_performed") is False
            and terminal.get("outcome") == "calibration_no_weight"
            and terminal.get("reason_code") is None
            and terminal.get("audit_release_block") == document.close_snapshot.block_number
        )
    except (AttributeError, KeyError, TypeError, ValueError):
        return False


def _terminal_document(*, policy_hash, validator_account_id32, work, close, captured):
    plan = work.window.plan
    return build_terminal_stage_document(
        policy_hash=policy_hash,
        validator_account=validator_account_id32,
        window_id=plan.window_id,
        window_index=plan.window_index,
        announcement_block=plan.announcement_block,
        close=close,
        captured=captured,
    )


def build_terminal_stage_document(
    *,
    policy_hash: str,
    validator_account: str | bytes,
    window_id: str,
    window_index: int,
    announcement_block: int,
    close: FinalizedSnapshotRef,
    captured: Any,
) -> TerminalStageDocument:
    """Build the canonical terminal/scan binding used by receipt and bundle tests."""

    validator_account_id32 = account_id32(validator_account)
    scan = captured.scan
    if (
        scan.start_snapshot.block_number != announcement_block
        or scan.end_snapshot != close
        or scan.validator_account_id32 != validator_account_id32
        or scan.netuid != 78
        or scan.mechanism_id != 0
        or scan.scanned_blocks <= 1
        or len(captured.blocks) != scan.scanned_blocks
        or len(captured.evidence) != scan.scanned_blocks
    ):
        raise TerminalEffectError("terminal_no_weight_scan_binding_invalid")
    return TerminalStageDocument(
        schema=TERMINAL_STAGE_SCHEMA,
        protocol=PROTOCOL_VERSION,
        window_id=window_id,
        window_index=window_index,
        scoring_policy_hash=policy_hash,
        validator_account_id32=validator_account_id32.hex(),
        announcement_block=announcement_block,
        weight_commit_close_snapshot=_snapshot_json(close),
        scanned_blocks=scan.scanned_blocks,
        scanned_calls=scan.scanned_calls,
        scanned_events=scan.scanned_events,
        scan_evidence_chain_sha256=_scan_evidence_chain_sha256(captured.evidence),
        translation_weights_active=False,
        weight_submission_performed=False,
        terminal_classification="calibration_no_weight",
    )


def _scan_evidence_chain_sha256(evidence) -> str:
    material = []
    for item in evidence:
        try:
            snapshot = item.identity.snapshot
            parent_snapshot = item.identity.parent_snapshot
            runtime_pin = item.runtime_pin
            body_sha256 = item.body.body_sha256
            event_value_sha256 = item.event_storage.value_sha256
            extrinsics_root = item.identity.extrinsics_root
            finality_verifier_sha256 = item.identity.finality_verifier_sha256
        except (AttributeError, TypeError) as error:
            raise TerminalEffectError("terminal_scan_evidence_invalid") from error
        material.append(
            {
                "snapshot": _snapshot_json(snapshot),
                "parent_snapshot": _snapshot_json(parent_snapshot),
                "extrinsics_root": extrinsics_root,
                "finality_verifier_sha256": finality_verifier_sha256,
                "runtime_pin": {
                    "metadata_sha256": runtime_pin.metadata_sha256,
                    "spec_version": runtime_pin.spec_version,
                    "transaction_version": runtime_pin.transaction_version,
                    "state_version": runtime_pin.state_version,
                    "ss58_prefix": runtime_pin.ss58_prefix,
                },
                "body_sha256": body_sha256,
                "event_value_sha256": event_value_sha256,
            }
        )
    return hashlib.sha256(_BLOCK_CHAIN_DOMAIN + canonical_json_bytes(material)).hexdigest()


def _snapshot_json(snapshot: FinalizedSnapshotRef) -> dict[str, JsonValue]:
    if not isinstance(snapshot, FinalizedSnapshotRef):
        raise TypeError("snapshot must be a FinalizedSnapshotRef")
    return {
        "block_number": snapshot.block_number,
        "block_hash": snapshot.block_hash,
        "parent_hash": snapshot.parent_hash,
        "state_root": snapshot.state_root,
    }


def _snapshot_from_json(value: Mapping[str, JsonValue]) -> FinalizedSnapshotRef:
    if not isinstance(value, Mapping) or set(value) != {
        "block_number",
        "block_hash",
        "parent_hash",
        "state_root",
    }:
        raise ValueError("terminal close snapshot is malformed")
    return FinalizedSnapshotRef(
        block_number=value["block_number"],
        block_hash=value["block_hash"],
        parent_hash=value["parent_hash"],
        state_root=value["state_root"],
    )


def _validate_manifest_binding(
    manifest: CalibrationBundleManifest,
    *,
    policy_hash: str,
    work: StageWorkItem,
    close: FinalizedSnapshotRef,
    validator_account_id32: bytes,
) -> None:
    if not isinstance(manifest, CalibrationBundleManifest):
        raise TerminalEffectError("bundle_verifier_manifest_invalid")
    if (
        manifest.window_id != work.window.plan.window_id
        or manifest.window_index != work.window.plan.window_index
        or manifest.scoring_policy_hash != policy_hash
        or manifest.validator_account_id32 != validator_account_id32.hex()
        or manifest.announcement_block != work.window.plan.announcement_block
        or manifest.weight_commit_close_block != close.block_number
        or manifest.weight_commit_close_block_hash != close.block_hash
        or manifest.audit_release_block != close.block_number
        or manifest.audit_release_block_hash != close.block_hash
        or manifest.translation_weights_active
        or manifest.weight_submission_performed
        or manifest.terminal_classification != "calibration_no_weight"
    ):
        raise TerminalEffectError("published_bundle_binding_mismatch")


def _prepare_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("bundle publication path must be a real directory")


@contextmanager
def _exclusive_lock(path: Path):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise TerminalEffectError("bundle_lock_not_regular")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _remove_staging_directory(path: Path, parent: Path, window_id: str) -> None:
    if (
        path.parent != parent
        or not path.name.startswith(f".{window_id}.")
        or path.is_symlink()
        or not path.is_dir()
    ):
        raise TerminalEffectError("unsafe_staging_cleanup_target")
    shutil.rmtree(path)
    _fsync_directory(parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "TERMINAL_STAGE_MEDIA_TYPE",
    "TERMINAL_STAGE_SCHEMA",
    "CalibrationBundleVerifierPort",
    "CalibrationNoWeightTerminalEffect",
    "ReplayCalibrationBundleVerifier",
    "TerminalEffectError",
    "TerminalStageDocument",
    "WeightBuildCloseResolver",
    "build_terminal_stage_document",
    "replay_terminal_stage_receipt",
]
