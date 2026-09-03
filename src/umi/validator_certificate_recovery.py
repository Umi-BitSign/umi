"""Content-addressed reconciliation for a terminal certificate-breach window.

The live pool stage cannot invent retirement state when a certified child object
is missing.  This module is the deliberately separate recovery boundary: after
the incident bundle is public, it accepts only bytes whose hashes were committed
by that original certified pool graph, opens ground truth at the original reveal
round, applies an empty-score protocol transition, and releases exactly the
incident-created intake hold.  It never reopens scoring or changes the terminal
window outcome.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import re
import stat
from collections.abc import Awaitable, Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from .artifacts import PublicBatchManifest
from .audit import EvidenceStore
from .crypto import (
    SealedResponse,
    TimelockDecryptionError,
    parse_sealed_response,
)
from .drand import DrandPulse, DrandVerificationError
from .encoding import account_id32, raw_sha256, sha256_domain
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import (
    PoolManifest,
    parse_pool_manifest_bytes,
    verify_availability_certificate_member,
    verify_pool_artifacts,
)
from .protocol import (
    PROTOCOL_VERSION,
    GroundTruthPayload,
    base64url_encode,
    canonical_json_bytes,
)
from .registries import (
    PublisherFaultFinding,
    PublisherRevealEvidence,
    PublisherRevealOutcome,
    SpentCohortBatch,
    classify_publisher_reveal,
)
from .substrate_proof import SubprocessStorageProofVerifier, SubstrateProofVerifierError
from .validator_bundle_ports import (
    BundlePortCompositionError,
    build_production_calibration_bundle_verifier,
)
from .validator_incident_bundle import (
    IncidentBundleManifest,
    VerifiedIncidentBundle,
    verify_incident_bundle,
)
from .validator_journal import ValidatorStageJournal
from .validator_live import (
    LiveValidatorError,
    LiveValidatorPaths,
    load_live_policy,
    load_live_validator_config,
    validate_live_startup,
)
from .validator_live_ports import TLERevealDecryptAdapter
from .validator_pool_effect import (
    POOL_CERTIFICATE_BREACH_SCHEMA,
    AnnouncementValidatorSnapshot,
    ClosingSnapshot,
    PoolAnchorRetrievalEvidence,
    PoolCertificateBreachEvidence,
)
from .validator_protocol_state import (
    ProtocolStatePolicyLimits,
    ValidatorProtocolStateStore,
    decode_protocol_state_snapshot,
    encode_protocol_state_snapshot,
)
from .validator_state import (
    IncidentStatus,
    PauseScope,
    TerminalOutcome,
    ValidatorControlPlane,
    WindowStage,
)

CERTIFICATE_BREACH_RECONCILIATION_SCHEMA = "umi-certificate-breach-reconciliation/1"
MAX_RECOVERED_OBJECT_BYTES = 64 * 1024 * 1024
MAX_RECOVERY_TOTAL_BYTES = 512 * 1024 * 1024
_HEX32_RE = re.compile(r"^[0-9a-f]{64}$")

RecoveryDecryptor = Callable[[SealedResponse, DrandPulse], Awaitable[bytes]]


class CertificateBreachRecoveryError(RuntimeError):
    """Recovered inputs cannot authorize the one narrow state transition."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


async def reconcile_certificate_breach(
    *,
    policy: ScoringPolicy,
    paths: LiveValidatorPaths,
    incident_root: Path,
    verified_incident: VerifiedIncidentBundle,
    recovered_objects_root: Path,
    reveal_pulse_bytes: bytes,
    decrypt: RecoveryDecryptor,
) -> Mapping[str, Any]:
    """Apply one idempotent no-score retirement/fault transition and resume intake."""

    if not isinstance(policy, ScoringPolicy) or policy.translation_weights_active:
        raise TypeError("certificate recovery requires an inactive ScoringPolicy")
    if not isinstance(paths, LiveValidatorPaths):
        raise TypeError("certificate recovery paths must be LiveValidatorPaths")
    if not isinstance(verified_incident, VerifiedIncidentBundle):
        raise TypeError("certificate recovery requires a verified incident bundle")
    if not callable(decrypt):
        raise TypeError("certificate recovery decryptor must be callable")
    manifest = verified_incident.manifest
    if not isinstance(manifest, IncidentBundleManifest):
        raise TypeError("verified incident contains another manifest type")
    if (
        manifest.terminal_stage != WindowStage.POOL_AND_SELECTION.value
        or manifest.terminal_classification != TerminalOutcome.SKIPPED.value
        or manifest.reason_codes != ["certificate_breach"]
        or manifest.scoring_policy_hash != scoring_policy_hash(policy)
        or verified_incident.policy != policy
    ):
        raise CertificateBreachRecoveryError("recovery_incident_not_certificate_breach")
    expected_incident_root = paths.incident_bundles / manifest.window_id
    try:
        if incident_root.resolve(strict=True) != expected_incident_root.resolve(strict=True):
            raise CertificateBreachRecoveryError("recovery_incident_path_mismatch")
    except OSError as error:
        raise CertificateBreachRecoveryError("recovery_incident_path_invalid") from error

    journal = ValidatorStageJournal(paths.stage_journal)
    records = journal.load_window(manifest.window_id)
    if len(records) != 1 or records[0].receipt.stage != WindowStage.POOL_AND_SELECTION.value:
        raise CertificateBreachRecoveryError("recovery_local_receipt_prefix_invalid")
    record = records[0]
    if not verified_incident.reached_stages:
        raise CertificateBreachRecoveryError("recovery_incident_stage_missing")
    reached = verified_incident.reached_stages[0]
    bundle_store = EvidenceStore(incident_root)
    _stored_manifest, stored_manifest_bytes = bundle_store.load_manifest_with_bytes()
    if stored_manifest_bytes != canonical_json_bytes(manifest):
        raise CertificateBreachRecoveryError("recovery_incident_manifest_mismatch")
    bundled_refs = {item.sha256: item for item in manifest.objects}
    bundled_receipt = bundle_store.read(
        bundled_refs[reached.receipt_object.sha256].model_dump(mode="json")
    )
    if (
        reached.receipt_object.sha256 != hashlib.sha256(record.receipt_bytes).hexdigest()
        or bundled_receipt != record.receipt_bytes
    ):
        raise CertificateBreachRecoveryError("recovery_incident_receipt_mismatch")
    payloads: dict[str, bytes] = {}
    for item in record.receipt.objects:
        local_bytes = journal.read_object(item)
        bundle_ref = bundled_refs.get(item.sha256)
        if bundle_ref is None:
            raise CertificateBreachRecoveryError("recovery_incident_payload_missing")
        bundled_bytes = bundle_store.read(bundle_ref.model_dump(mode="json"))
        if bundled_bytes != local_bytes:
            raise CertificateBreachRecoveryError("recovery_incident_payload_mismatch")
        payloads[item.sha256] = local_bytes
    breach_rows: list[tuple[PoolCertificateBreachEvidence, bytes]] = []
    for reference in record.receipt.objects:
        if reference.media_type != "application/json":
            continue
        data = payloads[reference.sha256]
        try:
            decoded = json.loads(data)
        except (UnicodeDecodeError, json.JSONDecodeError):
            continue
        if isinstance(decoded, dict) and decoded.get("schema") == POOL_CERTIFICATE_BREACH_SCHEMA:
            try:
                breach = PoolCertificateBreachEvidence.model_validate_json(data)
            except ValueError as error:
                raise CertificateBreachRecoveryError(
                    "recovery_certificate_breach_evidence_invalid"
                ) from error
            if canonical_json_bytes(breach) != data:
                raise CertificateBreachRecoveryError(
                    "recovery_certificate_breach_evidence_noncanonical"
                )
            breach_rows.append((breach, data))
    if len(breach_rows) != 1:
        raise CertificateBreachRecoveryError("recovery_certificate_breach_cardinality")
    breach, breach_bytes = breach_rows[0]
    breach_digest = hashlib.sha256(breach_bytes).hexdigest()
    terminal = record.receipt.metadata.get("terminal")
    incident = terminal.get("incident") if isinstance(terminal, dict) else None
    incident_id = incident.get("incident_id") if isinstance(incident, dict) else None
    if (
        breach.window_id != manifest.window_id
        or breach.window_index != manifest.window_index
        or breach.validator_hotkey != _validator_hotkey(policy, manifest.validator_account_id32)
        or not isinstance(incident_id, str)
        or verified_incident.terminal.incident is None
        or verified_incident.terminal.incident.incident_id != incident_id
    ):
        raise CertificateBreachRecoveryError("recovery_certificate_breach_binding_invalid")

    try:
        pulse_json = json.loads(reveal_pulse_bytes)
        pulse = DrandPulse.from_json(
            pulse_json,
            expected_round=breach.window.reveal_round,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, DrandVerificationError) as error:
        raise CertificateBreachRecoveryError("recovery_reveal_pulse_invalid") from error
    if canonical_json_bytes(pulse_json) != reveal_pulse_bytes:
        raise CertificateBreachRecoveryError("recovery_reveal_pulse_noncanonical")

    control = ValidatorControlPlane(paths.control_plane)
    window = control.get_window(manifest.window_id)
    if (
        window.terminal_outcome is not TerminalOutcome.SKIPPED
        or window.terminal_reason_code != "certificate_breach"
        or window.terminal_evidence_sha256 != record.evidence_sha256
    ):
        raise CertificateBreachRecoveryError("recovery_local_terminal_mismatch")
    local_incident = control.get_incident(incident_id)
    if local_incident.window_id != manifest.window_id or local_incident.reason_code != (
        "certificate_breach"
    ):
        raise CertificateBreachRecoveryError("recovery_local_incident_mismatch")
    initial_holds = tuple(
        item
        for item in control.control_state(PauseScope.WINDOW_INTAKE).active_holds
        if item.incident_id == incident_id
    )
    if len(initial_holds) > 1 or (
        local_incident.status is IncidentStatus.OPEN and len(initial_holds) != 1
    ):
        raise CertificateBreachRecoveryError("recovery_intake_hold_cardinality")
    if (
        local_incident.status is IncidentStatus.RESOLVED
        and local_incident.resolution_code != "certificate_artifacts_reconciled"
    ):
        raise CertificateBreachRecoveryError("recovery_incident_resolution_mismatch")

    source = breach.source_objects
    if {item.sha256 for item in source} != set(payloads) - {breach_digest}:
        raise CertificateBreachRecoveryError("recovery_breach_source_index_mismatch")
    closing = ClosingSnapshot.model_validate_json(payloads[breach.closing_snapshot.sha256])
    announcement = AnnouncementValidatorSnapshot.model_validate_json(
        payloads[breach.announcement_validator_snapshot.sha256]
    )
    retrieval = PoolAnchorRetrievalEvidence.model_validate_json(
        payloads[breach.artifact_retrieval_evidence.sha256]
    )
    prior_bytes = payloads[breach.prior_protocol_state.sha256]
    prior_state = decode_protocol_state_snapshot(prior_bytes)
    if prior_state.state_digest.hex() != breach.protocol_state_digest:
        raise CertificateBreachRecoveryError("recovery_prior_state_mismatch")

    source_refs = {item.sha256: item for item in record.receipt.objects}
    used: dict[str, tuple[bytes, str]] = {
        digest: (data, source_refs[digest].media_type) for digest, data in payloads.items()
    }

    def load_committed(
        digest: str,
        media_type: str,
        *,
        maximum_bytes: int,
        expected_size_bytes: int | None = None,
    ) -> bytes:
        existing = used.get(digest)
        if existing is not None:
            if existing[1] != media_type:
                raise CertificateBreachRecoveryError("recovery_object_media_type_conflict")
            data = existing[0]
        elif digest in bundled_refs:
            reference = bundled_refs[digest]
            if reference.media_type != media_type:
                raise CertificateBreachRecoveryError("recovery_object_media_type_conflict")
            data = bundle_store.read(reference.model_dump(mode="json"))
        else:
            data = _read_recovered_object(
                recovered_objects_root,
                digest,
                maximum_bytes=maximum_bytes,
            )
        if len(data) > maximum_bytes or (
            expected_size_bytes is not None and len(data) != expected_size_bytes
        ):
            raise CertificateBreachRecoveryError("recovery_object_size_mismatch")
        if hashlib.sha256(data).hexdigest() != digest:
            raise CertificateBreachRecoveryError("recovery_object_digest_mismatch")
        used[digest] = (data, media_type)
        return data

    active_validators = tuple(
        item.validator_hotkey for item in announcement.validators if item.validator_permit
    )
    qualified = [item for item in retrieval.anchor_outcomes if item.status == "qualified"]
    if not qualified:
        raise CertificateBreachRecoveryError("recovery_qualified_pool_missing")
    pools: list[tuple[bytes, PoolManifest]] = []
    certificates: set[bytes] = set()
    for outcome in qualified:
        raw = load_committed(
            outcome.sha256,
            "application/json",
            maximum_bytes=policy.limits.maximum_manifest_bytes,
        )
        try:
            parsed = parse_pool_manifest_bytes(raw, policy=policy)
            if account_id32(parsed.publisher_hotkey) != account_id32(outcome.publisher_hotkey):
                raise ValueError("publisher mismatch")
            verify_availability_certificate_member(
                parsed.availability_certificate,
                parsed.body(),
                active_validator_hotkeys=active_validators,
                policy=policy,
            )
            _require_chain_eligible_pool(
                policy=policy,
                closing=closing,
                prior_state=prior_state,
                window_index=manifest.window_index,
                pool=parsed,
                pool_sha256=outcome.sha256,
            )
        except (TypeError, ValueError) as error:
            raise CertificateBreachRecoveryError("recovery_qualified_pool_invalid") from error
        pools.append((raw, parsed))
        certificates.add(canonical_json_bytes(parsed.availability_certificate))
    if len(certificates) != 1:
        raise CertificateBreachRecoveryError("recovery_quorum_certificate_conflict")

    spent: list[SpentCohortBatch] = []
    findings: list[PublisherFaultFinding] = []
    plaintexts: list[bytes] = []
    for _raw, pool in pools:
        publics: dict[str, PublicBatchManifest] = {}
        envelopes: dict[str, bytes] = {}
        for entry in pool.batches:
            public_bytes = load_committed(
                entry.public_manifest_sha256,
                "application/json",
                maximum_bytes=policy.limits.maximum_manifest_bytes,
            )
            envelope_bytes = load_committed(
                entry.ciphertext_sha256,
                "application/octet-stream",
                maximum_bytes=policy.limits.maximum_ground_truth_envelope_bytes,
            )
            try:
                public = PublicBatchManifest.model_validate_json(public_bytes)
                if canonical_json_bytes(public) != public_bytes:
                    raise ValueError("noncanonical public manifest")
            except ValueError as error:
                raise CertificateBreachRecoveryError("recovery_public_manifest_invalid") from error
            publics[entry.batch_id] = public
            envelopes[entry.batch_id] = envelope_bytes
        try:
            verify_pool_artifacts(
                pool.body(),
                public_manifests=publics,
                ciphertexts=envelopes,
                policy=policy,
            )
        except (TypeError, ValueError) as error:
            raise CertificateBreachRecoveryError("recovery_pool_artifacts_invalid") from error
        group = next(
            item.control_group_id
            for item in policy.publisher_registry
            if account_id32(item.publisher_hotkey) == account_id32(pool.publisher_hotkey)
        )
        for entry in pool.batches:
            public = publics[entry.batch_id]
            envelope_bytes = envelopes[entry.batch_id]
            if breach.artifact_kind == "video" and entry.batch_id == breach.batch_id:
                matching_items = [
                    item for item in public.items if item.challenge_id == breach.challenge_id
                ]
                if (
                    len(matching_items) != 1
                    or matching_items[0].media.sha256 != breach.expected_sha256
                    or matching_items[0].media.size_bytes != breach.expected_size_bytes
                ):
                    raise CertificateBreachRecoveryError(
                        "recovery_certificate_breach_target_mismatch"
                    )
                load_committed(
                    breach.expected_sha256,
                    "video/mp4",
                    maximum_bytes=policy.limits.maximum_clip_size_bytes,
                    expected_size_bytes=breach.expected_size_bytes,
                )
            sealed = parse_sealed_response(
                base64url_encode(envelope_bytes),
                reveal_round=entry.reveal_round,
                sha256_hex=entry.ciphertext_sha256,
            )
            plaintext: bytes | None = None
            failure: TimelockDecryptionError | None = None
            try:
                plaintext = await decrypt(sealed, pulse)
            except TimelockDecryptionError as error:
                failure = error
            if plaintext is not None:
                plaintexts.append(plaintext)
            reveal = PublisherRevealEvidence(
                control_group_id=group,
                pool_entry=entry,
                public_manifest=public,
                sealed_ground_truth=sealed,
                reveal_pulse=pulse,
                anchored_eligibility_evidence_sha256=record.evidence_sha256,
                outcome=(
                    PublisherRevealOutcome.TIMELOCK_DECRYPTION_FAILED
                    if failure is not None
                    else PublisherRevealOutcome.DECRYPTED
                ),
                decrypted_bytes=plaintext,
                decryption_error=failure,
                prior_spent_leaves=prior_state.spent_registry.leaves,
            )
            findings.extend(classify_publisher_reveal(reveal, policy=policy))
            scripts: tuple[str, ...] = ()
            if plaintext is not None:
                try:
                    ground_truth = GroundTruthPayload.model_validate_json(plaintext)
                except ValueError:
                    ground_truth = None
                if ground_truth is not None and canonical_json_bytes(ground_truth) == plaintext:
                    scripts = tuple(
                        script
                        for item in ground_truth.items
                        for script in item.retirement_script_sha256s
                    )
            spent.append(
                SpentCohortBatch(
                    batch_commitment=entry.batch_commitment,
                    video_hashes=tuple(item.media.sha256 for item in public.items),
                    frame_digests=tuple(item.media.frame_digest for item in public.items),
                    revealed_script_hashes=scripts,
                )
            )

    used_refs = sorted(
        (
            {
                "sha256": digest,
                "media_type": media_type,
                "size_bytes": len(data),
            }
            for digest, (data, media_type) in used.items()
        ),
        key=lambda item: bytes.fromhex(item["sha256"]),
    )
    revealed_refs = sorted(
        (
            {
                "sha256": digest,
                "media_type": "application/json",
                "size_bytes": len(data),
            }
            for digest, data in {
                hashlib.sha256(data).hexdigest(): data for data in plaintexts
            }.items()
        ),
        key=lambda item: bytes.fromhex(item["sha256"]),
    )
    recovery_binding = canonical_json_bytes(
        {
            "schema": CERTIFICATE_BREACH_RECONCILIATION_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": manifest.window_id,
            "window_index": manifest.window_index,
            "incident_id": incident_id,
            "incident_bundle_manifest_sha256": hashlib.sha256(
                canonical_json_bytes(manifest)
            ).hexdigest(),
            "terminal_pool_receipt_sha256": hashlib.sha256(record.receipt_bytes).hexdigest(),
            "terminal_pool_evidence_sha256": record.evidence_sha256,
            "certificate_breach_evidence_sha256": breach_digest,
            "reveal_pulse_sha256": hashlib.sha256(reveal_pulse_bytes).hexdigest(),
            "recovered_source_objects": used_refs,
            "revealed_ground_truth_objects": revealed_refs,
            "scoring_performed": False,
        }
    )
    transition_operation = sha256_domain(
        b"umi-certificate-breach-reconcile-v1\0",
        recovery_binding,
    )
    evidence_digest = sha256_domain(
        b"umi-certificate-breach-recovery-evidence-v1\0",
        bytes.fromhex(record.evidence_sha256),
        bytes.fromhex(pulse.evidence_digest),
        hashlib.sha256(recovery_binding).digest(),
    )
    protocol = ValidatorProtocolStateStore(paths.protocol_state)
    try:
        before = protocol.snapshot
        if before.last_window_index == manifest.window_index - 1:
            if before.state_digest != prior_state.state_digest:
                raise CertificateBreachRecoveryError("recovery_protocol_state_prior_mismatch")
        elif before.last_window_index != manifest.window_index:
            raise CertificateBreachRecoveryError("recovery_protocol_state_head_invalid")
        applied = protocol.apply_window(
            operation_id=transition_operation,
            window_index=manifest.window_index,
            window_id=manifest.window_id,
            reveal_round=pulse.round,
            evidence_digest=evidence_digest,
            spent_cohort_batches=tuple(
                sorted(spent, key=lambda item: raw_sha256(item.batch_commitment, field="batch"))
            ),
            objective_fault_findings=tuple(
                sorted(
                    {item.leaf: item for item in findings}.values(),
                    key=lambda item: item.leaf,
                )
            ),
            scored_batches=(),
            issued_miner_roots=(),
            policy_limits=ProtocolStatePolicyLimits(
                rolling_batch_count=policy.limits.rolling_batch_count,
                score_max_age_windows=policy.limits.score_max_age_windows,
                publisher_fault_cooldown_windows=(policy.limits.publisher_fault_cooldown_windows),
            ),
        )
    finally:
        protocol.close()

    recovery_root = paths.root / "certificate-breach-reconciliations" / manifest.window_id
    store = EvidenceStore(
        recovery_root,
        maximum_object_bytes=MAX_RECOVERED_OBJECT_BYTES,
        maximum_total_object_bytes=MAX_RECOVERY_TOTAL_BYTES,
    )
    retained = [store.add_bytes(data, media_type) for data, media_type in used.values()]
    retained.extend(store.add_bytes(data, "application/json") for data in plaintexts)
    retained.extend(
        (
            store.add_bytes(reveal_pulse_bytes, "application/json"),
            store.add_bytes(record.receipt_bytes, "application/json"),
            store.add_bytes(recovery_binding, "application/json"),
            store.add_bytes(applied.request_bytes, "application/json"),
            store.add_bytes(applied.result_bytes, "application/json"),
            store.add_bytes(encode_protocol_state_snapshot(applied.snapshot), "application/json"),
        )
    )
    retained_by_digest = {item.sha256: item for item in retained}
    if len(retained_by_digest) != len(retained):
        for item in retained:
            if retained_by_digest[item.sha256].media_type != item.media_type:
                raise CertificateBreachRecoveryError("recovery_object_media_type_conflict")
    object_rows = sorted(
        (
            {
                "sha256": item.sha256,
                "media_type": item.media_type,
                "size_bytes": item.size_bytes,
            }
            for item in retained_by_digest.values()
        ),
        key=lambda item: bytes.fromhex(item["sha256"]),
    )
    report = {
        "schema": CERTIFICATE_BREACH_RECONCILIATION_SCHEMA,
        "protocol": PROTOCOL_VERSION,
        "window_id": manifest.window_id,
        "window_index": manifest.window_index,
        "incident_id": incident_id,
        "reason_code": "certificate_breach",
        "original_terminal_outcome": "skipped",
        "scoring_performed": False,
        "transition_operation_id": transition_operation.hex(),
        "transition_evidence_sha256": evidence_digest.hex(),
        "protocol_transition_request_sha256": hashlib.sha256(applied.request_bytes).hexdigest(),
        "protocol_transition_result_sha256": hashlib.sha256(applied.result_bytes).hexdigest(),
        "resulting_protocol_state_digest": applied.snapshot.state_digest.hex(),
        "objects": object_rows,
    }
    existing_report: Mapping[str, Any] | None = None
    if (recovery_root / "manifest.json").exists():
        existing_report = store.load_manifest()
        if existing_report != report:
            raise CertificateBreachRecoveryError("recovery_report_conflict")
    else:
        store.write_manifest(report)

    resolution_metadata = {
        "reconciliation_manifest_sha256": hashlib.sha256(canonical_json_bytes(report)).hexdigest(),
        "resulting_protocol_state_digest": applied.snapshot.state_digest.hex(),
        "scoring_performed": False,
    }
    if local_incident.status is IncidentStatus.RESOLVED and (
        local_incident.resolution_metadata_json
        != canonical_json_bytes(resolution_metadata).decode("utf-8")
    ):
        raise CertificateBreachRecoveryError("recovery_incident_resolution_mismatch")
    control.resolve_incident(
        incident_id,
        resolution_code="certificate_artifacts_reconciled",
        operation_id=f"certificate-breach.{manifest.window_id}.resolve",
        metadata=resolution_metadata,
    )
    holds = [
        item
        for item in control.control_state(PauseScope.WINDOW_INTAKE).active_holds
        if item.incident_id == incident_id
    ]
    if len(holds) == 1:
        control.resume(
            PauseScope.WINDOW_INTAKE,
            hold_id=holds[0].hold_id,
            resolution_code="certificate_artifacts_reconciled",
            operation_id=f"certificate-breach.{manifest.window_id}.resume-intake",
        )
    elif holds:
        raise CertificateBreachRecoveryError("recovery_intake_hold_cardinality")
    elif local_incident.status is IncidentStatus.OPEN:
        raise CertificateBreachRecoveryError("recovery_matching_intake_hold_missing")
    final_window = control.get_window(manifest.window_id)
    if (
        final_window.terminal_outcome is not TerminalOutcome.SKIPPED
        or final_window.terminal_reason_code != "certificate_breach"
    ):
        raise CertificateBreachRecoveryError("recovery_changed_terminal_window")
    return report


def _validator_hotkey(policy: ScoringPolicy, account_hex: str) -> str:
    account = bytes.fromhex(account_hex)
    matches = [
        item.validator_hotkey
        for item in policy.validator_registry
        if account_id32(item.validator_hotkey) == account
    ]
    if len(matches) != 1:
        raise CertificateBreachRecoveryError("recovery_validator_registry_mismatch")
    return matches[0]


def _require_chain_eligible_pool(
    *,
    policy: ScoringPolicy,
    closing: ClosingSnapshot,
    prior_state: Any,
    window_index: int,
    pool: PoolManifest,
    pool_sha256: str,
) -> None:
    account = account_id32(pool.publisher_hotkey)
    policy_rows = {account_id32(item.publisher_hotkey): item for item in policy.publisher_registry}
    closing_rows = {account_id32(item.publisher_hotkey): item for item in closing.publishers}
    registered = policy_rows.get(account)
    row = closing_rows.get(account)
    if (
        registered is None
        or row is None
        or not row.registered
        or account_id32(row.owner_coldkey) != account_id32(registered.owner_coldkey)
        or row.control_group_id != registered.control_group_id
        or row.locked_collateral_alpha_rao < policy.minimum_publisher_collateral_alpha_rao
        or row.minimum_locked_collateral_alpha_rao < policy.minimum_publisher_collateral_alpha_rao
        or row.pool_manifest_sha256 != pool_sha256
        or row.anchor_inclusion_block is None
        or row.anchor_inclusion_block > closing.closing_block
        or not prior_state.publisher_faults.is_eligible(
            registered.control_group_id,
            window_index,
        )
    ):
        raise ValueError("pool was not eligible at the original closing block")


def _read_recovered_object(root: Path, digest: str, *, maximum_bytes: int) -> bytes:
    if not isinstance(root, Path) or not root.is_absolute():
        raise CertificateBreachRecoveryError("recovery_object_root_unsafe")
    if _HEX32_RE.fullmatch(digest) is None:
        raise CertificateBreachRecoveryError("recovery_object_digest_invalid")
    directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        directory = os.open(root, directory_flags)
    except OSError as error:
        raise CertificateBreachRecoveryError("recovery_object_root_unsafe") from error
    try:
        details = os.fstat(directory)
        if not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o022:
            raise CertificateBreachRecoveryError("recovery_object_root_unsafe")
        try:
            descriptor = os.open(
                digest,
                os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=directory,
            )
        except OSError as error:
            raise CertificateBreachRecoveryError("recovery_committed_object_missing") from error
        try:
            data = _read_descriptor(
                descriptor,
                maximum_bytes=maximum_bytes,
                unsafe_reason="recovery_object_path_unsafe",
                changed_reason="recovery_object_changed",
            )
        finally:
            os.close(descriptor)
    finally:
        os.close(directory)
    if hashlib.sha256(data).hexdigest() != digest:
        raise CertificateBreachRecoveryError("recovery_object_digest_mismatch")
    return data


async def run_installed_recovery(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Reconcile one published UMI certificate-breach incident without scoring"
    )
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--incident-bundle", type=Path, required=True)
    parser.add_argument("--recovered-objects", type=Path, required=True)
    parser.add_argument("--reveal-pulse", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        config = load_live_validator_config(args.config)
        policy = load_live_policy(config)
        validation = validate_live_startup(config, policy)
        proof = SubprocessStorageProofVerifier(
            binary_path=config.storage_proof_verifier_binary,
            expected_sha256=validation.storage_proof_verifier_sha256,
        )
        bundle_verifier = build_production_calibration_bundle_verifier(
            policy=policy,
            target_triple=config.target_triple,
            finality_verifier_binary=config.finality_verifier_binary,
            finality_chain_spec=config.finality_chain_spec_path,
            storage_proof_verifier=proof,
        )
        verified = await verify_incident_bundle(
            args.incident_bundle,
            ports=bundle_verifier.ports,
        )
        pulse_bytes = _read_explicit_file(args.reveal_pulse, MAX_RECOVERED_OBJECT_BYTES)

        async def decrypt(sealed: SealedResponse, supplied: DrandPulse) -> bytes:
            return await TLERevealDecryptAdapter(policy)(sealed, supplied)

        report = await reconcile_certificate_breach(
            policy=policy,
            paths=LiveValidatorPaths.below(config.state_root),
            incident_root=args.incident_bundle,
            verified_incident=verified,
            recovered_objects_root=args.recovered_objects,
            reveal_pulse_bytes=pulse_bytes,
            decrypt=decrypt,
        )
        print(canonical_json_bytes(report).decode("utf-8"))
        return 0
    except (
        BundlePortCompositionError,
        CertificateBreachRecoveryError,
        LiveValidatorError,
        SubstrateProofVerifierError,
        ValueError,
        OSError,
    ) as error:
        reason = getattr(error, "reason_code", "certificate_breach_recovery_failed")
        print(
            canonical_json_bytes(
                {
                    "status": "blocked",
                    "reason_code": reason,
                    "scoring_performed": False,
                    "weight_submission_capability": False,
                }
            ).decode("utf-8"),
            file=os.sys.stderr,
        )
        return 2


def _read_explicit_file(path: Path, maximum: int) -> bytes:
    if not path.is_absolute():
        raise CertificateBreachRecoveryError("recovery_input_path_unsafe")
    try:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError as error:
        raise CertificateBreachRecoveryError("recovery_input_path_unsafe") from error
    try:
        return _read_descriptor(
            descriptor,
            maximum_bytes=maximum,
            unsafe_reason="recovery_input_path_unsafe",
            changed_reason="recovery_input_changed",
        )
    finally:
        os.close(descriptor)


def _read_descriptor(
    descriptor: int,
    *,
    maximum_bytes: int,
    unsafe_reason: str,
    changed_reason: str,
) -> bytes:
    details = os.fstat(descriptor)
    if (
        not stat.S_ISREG(details.st_mode)
        or details.st_size <= 0
        or details.st_size > maximum_bytes
        or details.st_mode & 0o022
    ):
        raise CertificateBreachRecoveryError(unsafe_reason)
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum_bytes - total + 1))
        if not chunk:
            break
        total += len(chunk)
        if total > maximum_bytes:
            raise CertificateBreachRecoveryError(unsafe_reason)
        chunks.append(chunk)
    if total != details.st_size:
        raise CertificateBreachRecoveryError(changed_reason)
    return b"".join(chunks)


def main() -> None:
    raise SystemExit(asyncio.run(run_installed_recovery()))


__all__ = [
    "CERTIFICATE_BREACH_RECONCILIATION_SCHEMA",
    "CertificateBreachRecoveryError",
    "reconcile_certificate_breach",
    "run_installed_recovery",
]
