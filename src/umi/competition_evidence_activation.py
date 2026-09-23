"""Stopped activation transaction for a prepared evidence store and host anchor.

The live anchor directory is exchanged once with the prepared directory. Its
root-owned receipt selects the physical evidence store, so restart cannot pair
an old receipt with a new database. The original anchor and database are retained.
This module never stops/starts services, changes units, signs, or contacts RPC.
The Linux host caller must hold its verified stopped-service lease throughout.
"""

from __future__ import annotations

import ctypes
import hashlib
import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

from .competition_evidence_prepare import _write_control
from .competition_evidence_stopped import StoppedEvidenceMigration
from .competition_host_activation import (
    SuccessorInstallationReceipt,
    validate_evidence_migration_receipt,
)
from .competition_supervisor import parse_canonical_successor_operator_consent
from .competition_upgrade import _open_without_links
from .file_identity import file_fingerprint
from .protocol import canonical_json_bytes


def _validate_lease(lease, plan, config):
    if type(lease) is not StoppedEvidenceMigration:
        raise ValueError("atomic evidence selection needs a genuine stopped migration lease")
    lease.validate_scope(plan, config)


@dataclass(frozen=True)
class EvidenceActivationPlan:
    live_source: Path
    prepared_source: Path
    transaction_root: Path
    original_receipt_sha256: str
    candidate_receipt_sha256: str
    compatibility_sha256: str

    def encoded(self):
        return canonical_json_bytes(
            {
                "schema": "umi-weight-evidence-activation-plan/1",
                "live_source": str(self.live_source),
                "prepared_source": str(self.prepared_source),
                "transaction_root": str(self.transaction_root),
                "original_receipt_sha256": self.original_receipt_sha256,
                "candidate_receipt_sha256": self.candidate_receipt_sha256,
                "compatibility_sha256": self.compatibility_sha256,
            }
        )


def _root_linux():
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("evidence activation requires root on the stopped Linux host")


def _root_owner_uid() -> int:
    return 0


def _root_control(path, *, maximum=1024**2):
    descriptor = _open_without_links(path)
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != _root_owner_uid()
            or info.st_nlink != 1
            or info.st_mode & 0o777 != 0o444
            or not 0 < info.st_size <= maximum
        ):
            raise ValueError("migration control is not root-sealed")
        raw = os.read(descriptor, maximum + 1)
        if len(raw) != info.st_size or file_fingerprint(os.fstat(descriptor)) != file_fingerprint(
            info
        ):
            raise ValueError("migration control changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _receipt(root):
    raw = _root_control(root / "anchor" / "installation-receipt.json")
    value = SuccessorInstallationReceipt.model_validate_json(raw, strict=True)
    if canonical_json_bytes(value) != raw:
        raise ValueError("migration receipt must be canonical")
    return value, hashlib.sha256(raw).hexdigest()


def _exchange(parent, left, right):
    _root_linux()
    function = getattr(ctypes.CDLL(None, use_errno=True), "renameat2", None)
    if function is None:
        raise ValueError("atomic evidence activation requires renameat2")
    function.argtypes = (
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    )
    function.restype = ctypes.c_int
    if function(parent, os.fsencode(left), parent, os.fsencode(right), 2):
        raise OSError(ctypes.get_errno(), "atomic evidence activation exchange failed")


def _private_transaction_root(path):
    descriptor = _open_without_links(path)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != _root_owner_uid()
        or info.st_mode & 0o777 != 0o700
    ):
        os.close(descriptor)
        raise ValueError("migration transaction directory must be private and root-owned")
    return descriptor


def publish_stopped_evidence_activation(
    plan: EvidenceActivationPlan, *, config, lease: StoppedEvidenceMigration
):
    """Publish or resume one exact exchange, never exchange back on retry.

    This requires a caller-owned live stopped capability, not an API/CLI accepting
    an operator assertion. Tests substitute the operating-system layer only.
    The pending root record is fsynced before exchange. A crash after exchange
    is recognized by both exact receipt hashes and completed without rollback.
    """
    _root_linux()
    for path in (plan.live_source, plan.prepared_source, plan.transaction_root):
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            raise ValueError("migration paths must be normalized and absolute")
    if (
        plan.live_source.parent != plan.prepared_source.parent
        or plan.live_source == plan.prepared_source
    ):
        raise ValueError("atomic activation needs distinct sibling source directories")
    if plan.transaction_root.is_relative_to(
        plan.live_source
    ) or plan.transaction_root.is_relative_to(plan.prepared_source):
        raise ValueError("migration transaction cannot live inside exchanged inputs")
    _validate_lease(lease, plan, config)
    parent = _open_without_links(plan.live_source.parent)
    transaction = _private_transaction_root(plan.transaction_root)
    try:
        # Caller owns the global host-operation lock; never overwrite a different
        # transaction or guess whether an unrelated prepared directory is ours.
        allowed = {
            "drain-plan.json",
            ".drain-plan.json.pending",
            "drain-complete.json",
            ".drain-complete.json.pending",
            "activation-plan.json",
            ".activation-plan.json.pending",
            "activation-complete.json",
            ".activation-complete.json.pending",
            # The root service driver holds the validator across anchor and
            # runtime selection. Its separately validated records survive retry.
            "HOLD",
            "HOLD.released",
            "original-supervisor.conf",
            ".original-supervisor.conf.pending",
            "original-cleanup.service",
            ".original-cleanup.service.pending",
            "service-selection.json",
            ".service-selection.json.pending",
            "service-publication.json",
            ".service-publication.json.pending",
            "service-start.json",
            ".service-start.json.pending",
            "service-start-complete.json",
            ".service-start-complete.json.pending",
        }
        if set(os.listdir(transaction)) - allowed:
            raise ValueError("migration transaction has unexpected files")
        _write_control(transaction, "activation-plan.json", plan.encoded())
        left, left_hash = _receipt(plan.live_source)
        right, right_hash = _receipt(plan.prepared_source)
        before = (plan.original_receipt_sha256, plan.candidate_receipt_sha256)
        after = tuple(reversed(before))
        if (left_hash, right_hash) not in {before, after} or before[0] == before[1]:
            raise ValueError("migration anchor pair differs from the recorded transaction")
        candidate_root, candidate = (
            (plan.prepared_source, right)
            if (left_hash, right_hash) == before
            else (plan.live_source, left)
        )
        if (
            candidate.evidence_migration is None
            or candidate.evidence_migration.compatibility_sha256 != plan.compatibility_sha256
        ):
            raise ValueError("candidate lacks this exact compatibility root seal")
        consent_raw = _root_control(candidate_root / "anchor" / "operator-consent.json")
        limits_raw = _root_control(candidate_root / "anchor" / "worker-limits.json")
        consent = parse_canonical_successor_operator_consent(consent_raw)
        validate_evidence_migration_receipt(
            candidate, config=config, consent=consent, worker_limits_bytes=limits_raw
        )
        if (
            hashlib.sha256(
                bytes.fromhex(candidate.evidence_migration.original_receipt_hex)
            ).hexdigest()
            != plan.original_receipt_sha256
        ):
            raise ValueError("migration original root receipt differs")
        lease.recheck()
        if (left_hash, right_hash) == before:
            _exchange(parent, plan.live_source.name, plan.prepared_source.name)
            os.fsync(parent)
        # A root record is not sufficient to restart a used candidate. The lease
        # reaudits both stores and validates unchanged original retained state.
        lease.recheck()
        if (_receipt(plan.live_source)[1], _receipt(plan.prepared_source)[1]) != after:
            raise ValueError("migration exchange readback differs")
        result = {
            "schema": "umi-weight-evidence-activation/1",
            "plan_sha256": hashlib.sha256(plan.encoded()).hexdigest(),
            "selected_receipt_sha256": plan.candidate_receipt_sha256,
            "retained_original_receipt_sha256": plan.original_receipt_sha256,
            "chain_submission_authorized": False,
            "service_started": False,
        }
        _write_control(transaction, "activation-complete.json", canonical_json_bytes(result))
        lease.recheck()
        return result
    finally:
        os.close(transaction)
        os.close(parent)


def seal_prepared_evidence_installation(plan, *, config, receipt, lease):
    """Seal the exact prepared root receipt while the stopped capability is live.

    Input rendering and directory preparation remain separate. Every existing
    root control must match the proposed receipt; this function never repairs or
    overwrites different bytes. Old root controls remain in the original anchor.
    """
    _root_linux()
    _validate_lease(lease, plan, config)
    if hashlib.sha256(canonical_json_bytes(receipt)).hexdigest() != plan.candidate_receipt_sha256:
        raise ValueError("proposed migration receipt differs from activation plan")
    anchor = plan.prepared_source / "anchor"
    # Imports are explicit; these are shared host checks, not alternate parsers.
    from .competition_host_activation import (
        _verify_receipt_controls,
        _verify_retained_recovery_body,
        _write_root_receipt_once,
    )
    from .competition_recovery import load_installed_retained_checkpoint_archive
    from .validator_supervisor import parse_canonical_signed_supervisor_directive

    consent = parse_canonical_successor_operator_consent(
        _root_control(anchor / "operator-consent.json")
    )
    limits_bytes = _root_control(anchor / "worker-limits.json")
    original_signed = parse_canonical_signed_supervisor_directive(
        _root_control(anchor / "legacy-signed-directive.json")
    )
    _verify_receipt_controls(
        receipt,
        config=config,
        consent=consent,
        legacy_signed=original_signed,
        host_bytes=_root_control(anchor / "signed-host-artifact.json", maximum=32 * 1024**2),
        worker_limits_bytes=limits_bytes,
        observer_config_bytes=_root_control(anchor / "observer-config.json"),
    )
    recovery, _ = load_installed_retained_checkpoint_archive(
        anchor / "recovery" / receipt.checkpoint_sha256,
        expected_sha256=receipt.checkpoint_sha256,
        owner=0,
        limits=receipt.recovery_limits,
    )
    _verify_retained_recovery_body(receipt, recovery)
    # Full archive/control checks can outlast a proof; hold_stopped_evidence_migration
    # must have audited these before its post-audit capture. Expiry here holds the
    # transaction rather than extending freshness or selecting partial inputs.
    lease.recheck()
    _write_root_receipt_once(anchor / "installation-receipt.json", canonical_json_bytes(receipt))
    lease.recheck()
    return receipt
