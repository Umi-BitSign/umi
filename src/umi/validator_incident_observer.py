"""Receipt-first publication of live shadow incident bundles.

The observer is attached to every journal stage adapter.  Completion receipts and
successful terminal outcomes are ignored.  An early terminal receipt remains the
active control-plane stage until the complete announcement-to-release no-weight
scan is finalized, a signed incident bundle is written, and that bundle passes an
independent replay verifier.  Restart therefore cannot lose a skipped or void
window between its durable receipt and public evidence.
"""

from __future__ import annotations

import errno
import fcntl
import os
import shutil
import stat
import tempfile
from collections.abc import Callable, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from .calibration_bundle import (
    MAX_CALIBRATION_OBJECT_BYTES,
    CalibrationObjectInput,
    CalibrationStageInput,
    CalibrationVerificationPorts,
    calibration_stage_replay_hook_id,
)
from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .validator_adapters import stage_result_from_receipt
from .validator_incident_bundle import (
    IncidentBundleManifest,
    VerifiedIncidentBundle,
    verify_incident_bundle,
    write_incident_bundle,
)
from .validator_journal import StageJournalRecord, ValidatorStageJournal
from .validator_no_weight import LiveNoWeightCapturePort
from .validator_state import (
    StageCompletion,
    StagePending,
    StageWorkItem,
    TerminalDecision,
    TerminalOutcome,
)


class IncidentObserverError(RuntimeError):
    """Stable fail-closed incident publication failure."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@runtime_checkable
class IncidentBundleVerifierPort(Protocol):
    async def verify(self, root: Path) -> IncidentBundleManifest: ...


@dataclass(frozen=True, slots=True)
class ReplayIncidentBundleVerifier:
    """Production incident verifier using the calibration replay port set."""

    ports: CalibrationVerificationPorts

    def __post_init__(self) -> None:
        if not isinstance(self.ports, CalibrationVerificationPorts):
            raise TypeError("ports must be CalibrationVerificationPorts")

    async def verify(self, root: Path) -> IncidentBundleManifest:
        verified = await verify_incident_bundle(root, ports=self.ports)
        if not isinstance(verified, VerifiedIncidentBundle):
            raise IncidentObserverError("incident_verifier_result_invalid")
        return verified.manifest


class ShadowIncidentReceiptObserver:
    """Publish every skipped, void, or failed shadow receipt before transition."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        journal: ValidatorStageJournal,
        no_weight_capture: LiveNoWeightCapturePort,
        bundle_root: str | Path,
        bundle_verifier: IncidentBundleVerifierPort,
        validator_account: str | bytes,
        signature_scheme: Literal["sr25519", "ed25519"],
        manifest_signer: Callable[[bytes], bytes],
        software_revisions: Mapping[str, str],
        bundle_writer: Callable[..., Path] = write_incident_bundle,
    ) -> None:
        if not isinstance(policy, ScoringPolicy):
            raise TypeError("policy must be ScoringPolicy")
        if policy.translation_weights_active:
            raise ValueError("shadow incident observer requires an inactive policy")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be ValidatorStageJournal")
        if not isinstance(no_weight_capture, LiveNoWeightCapturePort) and not callable(
            getattr(no_weight_capture, "capture", None)
        ):
            raise TypeError("no_weight_capture must implement capture")
        if not callable(getattr(bundle_verifier, "verify", None)):
            raise TypeError("bundle_verifier must implement verify")
        if signature_scheme not in {"sr25519", "ed25519"}:
            raise ValueError("manifest signature scheme is unsupported")
        if not callable(manifest_signer) or not callable(bundle_writer):
            raise TypeError("incident signer and writer must be callable")
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
        self.bundle_root = Path(bundle_root)
        self.bundle_verifier = bundle_verifier
        self.validator_account_id32 = account_id32(validator_account)
        if self.validator_account_id32 != no_weight_capture.validator_account_id32:
            raise ValueError("no-weight capture belongs to another validator")
        self.signature_scheme = signature_scheme
        self.manifest_signer = manifest_signer
        self.software_revisions = dict(sorted(revisions.items()))
        self.bundle_writer = bundle_writer
        _prepare_directory(self.bundle_root)
        _prepare_directory(self.bundle_root / ".locks")
        _prepare_directory(self.bundle_root / ".staging")

    async def after_receipt(
        self,
        *,
        record: StageJournalRecord,
        work: StageWorkItem,
    ) -> None:
        """Block an early terminal transition until its incident bundle is durable."""

        if not isinstance(record, StageJournalRecord) or not isinstance(work, StageWorkItem):
            raise TypeError("incident observer requires a journal record and stage work")
        if (
            record.receipt.window_id != work.window.plan.window_id
            or record.receipt.stage != work.stage.value
        ):
            raise IncidentObserverError("incident_receipt_work_mismatch")
        result = stage_result_from_receipt(record, work=work)
        if isinstance(result, StageCompletion):
            return
        if not isinstance(result, TerminalDecision):
            raise IncidentObserverError("incident_receipt_result_invalid")
        if result.outcome in {
            TerminalOutcome.CALIBRATION_NO_WEIGHT,
            TerminalOutcome.APPLIED,
        }:
            return
        if result.outcome not in {
            TerminalOutcome.SKIPPED,
            TerminalOutcome.VOID,
            TerminalOutcome.FAILED,
        }:
            raise IncidentObserverError("incident_terminal_outcome_unsupported")
        if result.reason_code is None:
            raise IncidentObserverError("incident_reason_missing")

        plan = work.window.plan
        if plan.scoring_policy_hash != self.policy_hash:
            raise IncidentObserverError("incident_policy_hash_mismatch")
        if result.audit_release_block <= plan.announcement_block:
            raise IncidentObserverError("incident_release_not_after_announcement")
        if await self._verify_existing_bundle(work=work, decision=result):
            return
        captured = await self.no_weight_capture.capture(
            start_block=plan.announcement_block,
            end_block=result.audit_release_block,
        )
        if captured is None:
            raise StagePending("incident_audit_release_finality_pending")
        if captured.scan.end_snapshot.block_number != result.audit_release_block:
            raise IncidentObserverError("incident_capture_release_mismatch")
        await self._publish_bundle(work=work, decision=result, captured=captured)

    async def _verify_existing_bundle(
        self,
        *,
        work: StageWorkItem,
        decision: TerminalDecision,
    ) -> bool:
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
                decision=decision,
                validator_account_id32=self.validator_account_id32,
            )
            return True

    async def _publish_bundle(self, *, work, decision, captured) -> None:
        plan = work.window.plan
        window_id = plan.window_id
        final_root = self.bundle_root / window_id
        lock_path = self.bundle_root / ".locks" / f"{window_id}.lock"
        with _exclusive_lock(lock_path):
            if final_root.exists():
                manifest = await self.bundle_verifier.verify(final_root)
                _validate_manifest_binding(
                    manifest,
                    policy_hash=self.policy_hash,
                    work=work,
                    decision=decision,
                    validator_account_id32=self.validator_account_id32,
                )
                return
            records = self.journal.load_window(window_id)
            expected_count = len(work.completed_evidence) + 1
            if len(records) != expected_count or records[-1].receipt.stage != work.stage.value:
                raise IncidentObserverError("incident_receipt_prefix_incomplete")
            stages = tuple(
                CalibrationStageInput(
                    receipt_bytes=item.receipt_bytes,
                    objects=tuple(
                        CalibrationObjectInput(
                            self.journal.read_object(reference), reference.media_type
                        )
                        for reference in item.receipt.objects
                    ),
                    replay_hook_id=calibration_stage_replay_hook_id(
                        self.policy, item.receipt.stage
                    ),
                )
                for item in records
            )
            incident = (
                {
                    "incident_id": decision.incident.incident_id,
                    "reason_code": decision.incident.reason_code,
                    "metadata": dict(decision.incident.metadata),
                }
                if decision.incident is not None
                else None
            )
            staging_parent = self.bundle_root / ".staging"
            staging = Path(tempfile.mkdtemp(prefix=f".{window_id}.", dir=staging_parent))
            try:
                self.bundle_writer(
                    staging,
                    policy=self.policy,
                    window_id=window_id,
                    window_index=plan.window_index,
                    software_revisions=self.software_revisions,
                    validator_account=self.validator_account_id32,
                    audit_release_snapshot=captured.scan.end_snapshot,
                    no_weight_scan=captured,
                    stages=stages,
                    terminal_classification=decision.outcome.value,
                    reason_code=decision.reason_code,
                    incident=incident,
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
                    decision=decision,
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
                        decision=decision,
                        validator_account_id32=self.validator_account_id32,
                    )
                else:
                    staging = Path()
                    _fsync_directory(self.bundle_root)
            finally:
                if staging != Path() and staging.exists():
                    _remove_staging_directory(staging, staging_parent, window_id)


def _validate_manifest_binding(
    manifest: IncidentBundleManifest,
    *,
    policy_hash: str,
    work: StageWorkItem,
    decision: TerminalDecision,
    validator_account_id32: bytes,
) -> None:
    plan = work.window.plan
    if not isinstance(manifest, IncidentBundleManifest):
        raise IncidentObserverError("incident_verifier_manifest_invalid")
    if (
        manifest.window_id != plan.window_id
        or manifest.window_index != plan.window_index
        or manifest.scoring_policy_hash != policy_hash
        or manifest.validator_account_id32 != validator_account_id32.hex()
        or manifest.announcement_block != plan.announcement_block
        or manifest.terminal_stage != work.stage.value
        or manifest.highest_stage != work.stage.value
        or manifest.terminal_classification != decision.outcome.value
        or manifest.audit_release_block != decision.audit_release_block
        or decision.reason_code not in manifest.reason_codes
        or manifest.translation_weights_active
        or manifest.weight_submission_performed
    ):
        raise IncidentObserverError("published_incident_bundle_binding_mismatch")


def _prepare_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("incident publication path must be a real directory")


@contextmanager
def _exclusive_lock(path: Path):
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, 0o600)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise IncidentObserverError("incident_bundle_lock_not_regular")
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
        raise IncidentObserverError("unsafe_incident_staging_cleanup_target")
    shutil.rmtree(path)
    _fsync_directory(parent)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "IncidentBundleVerifierPort",
    "IncidentObserverError",
    "ReplayIncidentBundleVerifier",
    "ShadowIncidentReceiptObserver",
]
