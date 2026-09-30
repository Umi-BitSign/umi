"""Finish one prepared, stopped evidence migration through verified startup.

The root migration runner supplies an audited candidate, a genuine eligible
replacement and native observation/container adapters. This composes sealing,
anchor exchange, runtime publication and startup under one operator mutex.
Preparation, grant issuance and stopping the old service precede this boundary.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path

from .competition_chain_state import OwnedCompetitionChainObservation
from .competition_coordinator_namespace import ensure_coordinator_host_view
from .competition_evidence_activation import (
    EvidenceActivationPlan,
    _receipt,
    publish_stopped_evidence_activation,
    seal_prepared_evidence_installation,
)
from .competition_evidence_resume import _load, _resume
from .competition_evidence_rollover import EligibleEvidenceRollover
from .competition_evidence_service import (
    _held,
    _private_record,
    publish_stopped_evidence_service,
)
from .competition_evidence_stopped import hold_stopped_evidence_migration
from .competition_host_activation import SuccessorInstallationReceipt
from .competition_host_anchor import successor_activation_source_root
from .competition_host_artifacts import SignedSuccessorHostArtifact, VerifiedHostTree
from .competition_host_upgrade import _require_root_linux
from .competition_supervisor import SuccessorSupervisorOperatorConsent
from .competition_supervisor_observer import SuccessorHostObserverConfig
from .competition_switch_recovery import exclusive_upgrade_operation
from .competition_upgrade import _Reader
from .protocol import canonical_json_bytes
from .validator_supervisor import (
    ValidatorSupervisorConfig,
    parse_canonical_validator_supervisor_config,
)


@dataclass(frozen=True)
class PreparedEvidenceHandoff:
    """Inputs only; every authority is checked again by the native operations."""

    plan: EvidenceActivationPlan
    config_path: Path
    unit_name: str
    candidate_receipt: SuccessorInstallationReceipt
    consent: SuccessorSupervisorOperatorConsent
    worker_limits_bytes: bytes
    verified_host_tree: VerifiedHostTree
    signed_host: SignedSuccessorHostArtifact
    observer_config: SuccessorHostObserverConfig


async def _publish(
    inputs: PreparedEvidenceHandoff,
    config: ValidatorSupervisorConfig,
    reader: _Reader,
    *,
    eligible_replacement: EligibleEvidenceRollover | None,
    observe_after_audit: Callable[[], Awaitable[OwnedCompetitionChainObservation]],
    verify_worker_stopped: Callable[[], Awaitable[None]],
) -> None:
    plan, receipt = inputs.plan, inputs.candidate_receipt
    # Canonical parse rejects mutated model instances before a service lease or
    # filesystem change; hashes bind even recovery to the same complete target.
    receipt = SuccessorInstallationReceipt.model_validate_json(
        canonical_json_bytes(receipt), strict=True
    )
    if (
        hashlib.sha256(canonical_json_bytes(receipt)).hexdigest() != plan.candidate_receipt_sha256
        or receipt.source_config_sha256 != hashlib.sha256(canonical_json_bytes(config)).hexdigest()
        or receipt.evidence_migration is None
    ):
        raise ValueError("prepared handoff differs from the selected receipt or configuration")
    if (
        plan.live_source != successor_activation_source_root(config)
        or plan.compatibility_sha256 != receipt.evidence_migration.compatibility_sha256
        or plan.original_receipt_sha256
        != hashlib.sha256(
            bytes.fromhex(receipt.evidence_migration.original_receipt_hex)
        ).hexdigest()
    ):
        raise ValueError("prepared handoff differs from the installed source or predecessor")
    try:
        recorded = _private_record(plan.transaction_root, "activation-plan.json")
    except FileNotFoundError:
        pass
    else:
        if recorded != plan.encoded():
            raise ValueError("prepared handoff differs from the retained activation plan")
    _held(inputs.unit_name, plan.transaction_root, receipt.host_manifest_sha256)
    reader.unchanged()
    async with hold_stopped_evidence_migration(
        plan,
        config=config,
        unit_name=inputs.unit_name,
        service_uid=receipt.evidence_migration.service_uid,
        candidate_receipt=receipt,
        consent=inputs.consent,
        worker_limits_bytes=inputs.worker_limits_bytes,
        verified_host_tree=inputs.verified_host_tree,
        observer_config=inputs.observer_config,
        observe_after_audit=observe_after_audit,
        verify_worker_stopped=verify_worker_stopped,
        eligible_replacement=eligible_replacement,
    ) as lease:
        reader.unchanged()
        selected = _receipt(plan.live_source)[1]
        if selected == plan.original_receipt_sha256:
            seal_prepared_evidence_installation(plan, config=config, receipt=receipt, lease=lease)
        elif selected != plan.candidate_receipt_sha256:
            raise ValueError("prepared handoff has an unrelated selected anchor")
        # The exchange routine recognizes both exact anchor orientations. A
        # restart after exchange never seals the retained original as candidate.
        publish_stopped_evidence_activation(plan, config=config, lease=lease)
        publish_stopped_evidence_service(
            plan,
            config_path=inputs.config_path,
            unit_name=inputs.unit_name,
            verified_host_tree=inputs.verified_host_tree,
            signed_host=inputs.signed_host,
            lease=lease,
        )
        reader.unchanged()
    # No reload or start is allowed before all three native lease locks close.


def finish_stopped_evidence_handoff(
    inputs: PreparedEvidenceHandoff,
    *,
    eligible_replacement: EligibleEvidenceRollover | None,
    observe_after_audit: Callable[[], Awaitable[OwnedCompetitionChainObservation]],
    verify_worker_stopped: Callable[[], Awaitable[None]],
    startup_timeout_seconds: int = 600,
) -> dict:
    """Finish/recover the prepared transaction without a manual startup step.

    After durable runtime publication, recovery authenticates that publication and
    the current selected process. It does not depend on an expired pre-publication
    proof, reread a now-mutated weight journal, or stop a successfully started host.
    Before publication, every retry needs a fresh native replacement capability.
    """
    _require_root_linux()
    if type(startup_timeout_seconds) is not int or not 1 <= startup_timeout_seconds <= 3600:
        raise ValueError("invalid evidence startup timeout")
    # Namespace setup must precede creation of any asyncio executor threads.
    ensure_coordinator_host_view(unit_name=inputs.unit_name, config_path=inputs.config_path)
    with exclusive_upgrade_operation(inputs.unit_name):
        return _finish_locked(
            inputs,
            eligible_replacement=eligible_replacement,
            observe_after_audit=observe_after_audit,
            verify_worker_stopped=verify_worker_stopped,
            startup_timeout_seconds=startup_timeout_seconds,
        )


def _finish_locked(
    inputs: PreparedEvidenceHandoff,
    *,
    eligible_replacement: EligibleEvidenceRollover | None,
    observe_after_audit: Callable[[], Awaitable[OwnedCompetitionChainObservation]],
    verify_worker_stopped: Callable[[], Awaitable[None]],
    startup_timeout_seconds: int,
) -> dict:
    """Shared with the full root runner while it retains the same operator mutex."""
    try:
        _private_record(inputs.plan.transaction_root, "service-publication.json")
    except FileNotFoundError:
        reader = _Reader(0)
        raw = reader.file(
            inputs.config_path,
            "evidence_handoff_config",
            1024**2,
            modes={0o400, 0o440, 0o600, 0o640},
        )
        config = parse_canonical_validator_supervisor_config(raw)
        asyncio.run(
            _publish(
                inputs,
                config,
                reader,
                eligible_replacement=eligible_replacement,
                observe_after_audit=observe_after_audit,
                verify_worker_stopped=verify_worker_stopped,
            )
        )
    # _load checks the entire native anchor, staged host, immutable records,
    # original process-lock identity and selected runtime. A record's mere
    # existence is never used as permission to release the persistent hold.
    selection = _load(inputs.config_path, inputs.unit_name, inputs.plan.transaction_root)
    if selection.activation != inputs.plan:
        raise ValueError("published handoff belongs to another activation plan")
    return _resume(selection, startup_timeout_seconds)
