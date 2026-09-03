"""Proof- and bundle-backed readiness for the next scheduled window.

The plan source may advance only after the prior window's public terminal bundle
has independently replayed, its reveal receipt reproduces the durable protocol
state head, and the exact audit-release block is present in the owned finalized
header store.  This adapter is read-only.  In particular, an early incident that
has not yet advanced spent state returns ``None`` instead of silently treating an
incident bundle as a retirement transition.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, runtime_checkable

from .calibration_bundle import (
    CALIBRATION_BUNDLE_SCHEMA,
    MAX_CALIBRATION_BUNDLE_BYTES,
    MAX_CALIBRATION_MANIFEST_BYTES,
    CalibrationBundleManifest,
    CalibrationVerificationPorts,
    verify_calibration_bundle,
)
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import PROTOCOL_VERSION, canonical_json_bytes
from .validator_adapters import stage_result_from_receipt
from .validator_incident_bundle import (
    INCIDENT_BUNDLE_SCHEMA,
    IncidentBundleManifest,
    verify_incident_bundle,
)
from .validator_journal import ValidatorStageJournal
from .validator_plans import VerifiedFinalizedBlock, VerifiedPriorWindowCheckpoint
from .validator_protocol_state import ValidatorProtocolStateStore
from .validator_reveal_effect import ResolvedRevealStage, resolve_reveal_stage_record
from .validator_state import (
    STAGE_ORDER,
    TerminalDecision,
    TerminalOutcome,
    WindowRecord,
    WindowStage,
)

READINESS_EVIDENCE_SCHEMA = "umi-validator-prior-window-readiness/1"


class ReadinessEvidenceError(RuntimeError):
    """Stable fail-closed error while proving a prior window is settled."""

    def __init__(self, reason_code: str) -> None:
        self.reason_code = reason_code
        super().__init__(reason_code)


@dataclass(frozen=True, slots=True)
class VerifiedPublishedBundle:
    """Small exact binding returned only after full bundle replay."""

    manifest_sha256: str
    window_id: str
    window_index: int
    scoring_policy_hash: str
    terminal_classification: str
    highest_stage: str
    audit_release_block: int
    audit_release_block_hash: str
    reason_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        for name in ("manifest_sha256", "window_id", "scoring_policy_hash"):
            value = getattr(self, name)
            if not isinstance(value, str) or len(value) != 64:
                raise ValueError(f"{name} must be lowercase SHA-256 hexadecimal")
            try:
                if bytes.fromhex(value).hex() != value:
                    raise ValueError
            except ValueError as error:
                raise ValueError(f"{name} must be lowercase SHA-256 hexadecimal") from error
        if not isinstance(self.window_index, int) or isinstance(self.window_index, bool):
            raise TypeError("window_index must be an integer")
        if self.window_index < 0:
            raise ValueError("window_index must be nonnegative")
        if self.highest_stage not in {stage.value for stage in STAGE_ORDER}:
            raise ValueError("highest_stage is not a protocol stage")
        if self.terminal_classification not in {
            "calibration_no_weight",
            "skipped",
            "void",
            "failed",
        }:
            raise ValueError("terminal classification is unsupported")
        if (
            not isinstance(self.audit_release_block, int)
            or isinstance(self.audit_release_block, bool)
            or self.audit_release_block <= 0
        ):
            raise ValueError("audit release block must be a positive integer")
        if (
            not isinstance(self.audit_release_block_hash, str)
            or not self.audit_release_block_hash.startswith("0x")
            or len(self.audit_release_block_hash) != 66
        ):
            raise ValueError("audit release block hash is invalid")
        if self.reason_codes != tuple(sorted(set(self.reason_codes))):
            raise ValueError("reason codes must be unique and sorted")


@runtime_checkable
class PublishedBundleVerifier(Protocol):
    async def verify(self, root: Path) -> VerifiedPublishedBundle: ...


@runtime_checkable
class ReadinessFinalityPort(Protocol):
    @property
    def chain_observation(self): ...

    @property
    def finality_verifier_sha256(self) -> str: ...

    async def verified_block_at(self, height: int) -> VerifiedFinalizedBlock | None: ...


@dataclass(frozen=True, slots=True)
class ReplayPublishedBundleVerifier:
    """Dispatch a public bundle to the full calibration or incident verifier."""

    ports: CalibrationVerificationPorts

    def __post_init__(self) -> None:
        if not isinstance(self.ports, CalibrationVerificationPorts):
            raise TypeError("ports must be CalibrationVerificationPorts")

    async def verify(self, root: Path) -> VerifiedPublishedBundle:
        manifest_bytes, schema = await asyncio.to_thread(_read_manifest_discriminator, root)
        if schema == CALIBRATION_BUNDLE_SCHEMA:
            verified = await verify_calibration_bundle(
                root,
                ports=self.ports,
                maximum_bundle_bytes=MAX_CALIBRATION_BUNDLE_BYTES,
            )
            manifest = verified.manifest
        elif schema == INCIDENT_BUNDLE_SCHEMA:
            verified = await verify_incident_bundle(
                root,
                ports=self.ports,
                maximum_bundle_bytes=MAX_CALIBRATION_BUNDLE_BYTES,
            )
            manifest = verified.manifest
        else:  # pragma: no cover - discriminator narrows this branch
            raise ReadinessEvidenceError("published_bundle_schema_unsupported")
        if canonical_json_bytes(manifest) != manifest_bytes:
            raise ReadinessEvidenceError("published_bundle_manifest_changed_during_replay")
        return _bundle_binding(manifest, manifest_bytes)


class ProofBackedPriorWindowReadiness:
    """Return a checkpoint only for a fully replayed and state-advanced window."""

    def __init__(
        self,
        *,
        policy: ScoringPolicy,
        protocol_state: ValidatorProtocolStateStore,
        journal: ValidatorStageJournal,
        bundle_root: str | Path,
        incident_bundle_root: str | Path | None = None,
        bundle_verifier: PublishedBundleVerifier,
        finality: ReadinessFinalityPort,
    ) -> None:
        if not isinstance(policy, ScoringPolicy) or policy.translation_weights_active:
            raise ValueError("prior readiness requires an inactive scoring policy")
        if policy.implementation_pins.pin_profile != "live_shadow_calibration":
            raise ValueError("prior readiness requires a live-shadow policy")
        if not isinstance(protocol_state, ValidatorProtocolStateStore):
            raise TypeError("protocol_state must be ValidatorProtocolStateStore")
        if not isinstance(journal, ValidatorStageJournal):
            raise TypeError("journal must be ValidatorStageJournal")
        if not callable(getattr(bundle_verifier, "verify", None)):
            raise TypeError("bundle_verifier must implement verify")
        if not callable(getattr(finality, "verified_block_at", None)):
            raise TypeError("finality must implement verified_block_at")
        pins = policy.implementation_pins
        if (
            pins.live_chain is None
            or pins.finality_verifier is None
            or getattr(finality, "chain_observation", None) != pins.live_chain
            or getattr(finality, "finality_verifier_sha256", None)
            not in pins.finality_verifier.release_sha256_by_target.values()
        ):
            raise ValueError("readiness finality port disagrees with policy pins")
        self.policy = policy
        self.policy_hash = scoring_policy_hash(policy)
        self.protocol_state = protocol_state
        self.journal = journal
        self.bundle_root = Path(bundle_root)
        self.incident_bundle_root = (
            None if incident_bundle_root is None else Path(incident_bundle_root)
        )
        if self.incident_bundle_root == self.bundle_root:
            self.incident_bundle_root = None
        self.bundle_verifier = bundle_verifier
        self.finality = finality

    async def verified_reveal_and_spent(
        self,
        previous: WindowRecord,
    ) -> VerifiedPriorWindowCheckpoint | None:
        if not isinstance(previous, WindowRecord):
            raise TypeError("previous must be a WindowRecord")
        if previous.is_active or previous.terminal_outcome is None:
            raise ReadinessEvidenceError("prior_window_not_terminal")
        if previous.plan.scoring_policy_hash != self.policy_hash:
            raise ReadinessEvidenceError("prior_window_policy_mismatch")
        if previous.terminal_outcome is TerminalOutcome.APPLIED:
            raise ReadinessEvidenceError("active_weight_outcome_under_inactive_policy")
        candidate_paths = [self.bundle_root / previous.plan.window_id]
        if self.incident_bundle_root is not None:
            candidate_paths.append(self.incident_bundle_root / previous.plan.window_id)
        existing_paths = [path for path in candidate_paths if path.exists()]
        if not existing_paths:
            return None
        if len(existing_paths) != 1:
            raise ReadinessEvidenceError("prior_bundle_namespace_conflict")
        bundle_path = existing_paths[0]
        try:
            binding = await self.bundle_verifier.verify(bundle_path)
        except FileNotFoundError:
            return None
        except Exception as error:
            raise ReadinessEvidenceError("prior_bundle_replay_failed") from error
        if not isinstance(binding, VerifiedPublishedBundle):
            raise ReadinessEvidenceError("prior_bundle_verifier_result_invalid")
        _bind_bundle_to_window(binding, previous, self.policy_hash)

        records = await asyncio.to_thread(self.journal.load_window, previous.plan.window_id)
        if not records:
            raise ReadinessEvidenceError("prior_stage_receipts_missing")
        terminal_record = records[-1]
        if (
            terminal_record.receipt.stage != previous.stage.value
            or terminal_record.evidence_sha256 != previous.terminal_evidence_sha256
        ):
            raise ReadinessEvidenceError("prior_terminal_receipt_mismatch")
        result = stage_result_from_receipt(terminal_record)
        if not isinstance(result, TerminalDecision):
            raise ReadinessEvidenceError("prior_terminal_receipt_not_terminal")
        if (
            result.outcome is not previous.terminal_outcome
            or result.reason_code != previous.terminal_reason_code
            or result.audit_release_block != previous.audit_release_block
        ):
            raise ReadinessEvidenceError("prior_terminal_decision_mismatch")

        state = await asyncio.to_thread(self.protocol_state.audit)
        expected_index = previous.plan.window_index
        expected_id = bytes.fromhex(previous.plan.window_id)
        if state.last_window_index < expected_index - 1:
            raise ReadinessEvidenceError("protocol_state_history_gap")
        if state.last_window_index == expected_index - 1:
            # A pre-reveal terminal incident may be public before its retirement
            # settlement is complete.  Never invent an empty transition here.
            return None
        if state.last_window_index != expected_index or state.last_window_id != expected_id:
            raise ReadinessEvidenceError("protocol_state_advanced_beyond_prior_window")

        reveal_index = STAGE_ORDER.index(WindowStage.REVEAL_AND_SCORE)
        if len(records) <= reveal_index:
            raise ReadinessEvidenceError("state_advanced_without_reveal_receipt")
        reveal_record = records[reveal_index]
        try:
            resolved = await asyncio.to_thread(
                resolve_reveal_stage_record,
                reveal_record,
                self.journal,
            )
        except Exception as error:
            raise ReadinessEvidenceError("prior_reveal_replay_failed") from error
        _bind_resolved_reveal(resolved, previous, state, self.policy)

        release_height = previous.audit_release_block
        if release_height is None:
            raise ReadinessEvidenceError("prior_audit_release_missing")
        try:
            block = await self.finality.verified_block_at(release_height)
        except Exception as error:
            raise ReadinessEvidenceError("prior_release_finality_failed") from error
        if block is None:
            return None
        _bind_release_block(block, binding, self.policy, self.policy_hash)

        evidence = canonical_json_bytes(
            {
                "schema": READINESS_EVIDENCE_SCHEMA,
                "protocol": PROTOCOL_VERSION,
                "window_id": previous.plan.window_id,
                "window_index": previous.plan.window_index,
                "reveal_round": previous.plan.reveal_round,
                "scoring_policy_hash": self.policy_hash,
                "terminal_outcome": previous.terminal_outcome.value,
                "terminal_stage": previous.stage.value,
                "terminal_stage_evidence_sha256": terminal_record.evidence_sha256,
                "reveal_stage_evidence_sha256": reveal_record.evidence_sha256,
                "bundle_manifest_sha256": binding.manifest_sha256,
                "audit_release_block": block.height,
                "audit_release_block_hash": block.block_hash,
                "audit_release_state_root": block.state_root,
                "finality_verifier_sha256": block.finality_verifier_sha256,
                "finality_evidence_sha256": block.finality_evidence_sha256,
                "protocol_state_digest": state.state_digest.hex(),
                "spent_root": state.spent_registry.root.hex(),
                "spent_last_reveal_round": state.spent_registry.last_reveal_round,
            }
        )
        return VerifiedPriorWindowCheckpoint(
            window_id=previous.plan.window_id,
            window_index=previous.plan.window_index,
            reveal_round=previous.plan.reveal_round,
            spent_root=state.spent_registry.root.hex(),
            checkpoint_block_height=block.height,
            checkpoint_block_hash=block.block_hash,
            checkpoint_state_root=block.state_root,
            evidence=evidence,
            evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        )


def _bundle_binding(
    manifest: CalibrationBundleManifest | IncidentBundleManifest,
    manifest_bytes: bytes,
) -> VerifiedPublishedBundle:
    return VerifiedPublishedBundle(
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        window_id=manifest.window_id,
        window_index=manifest.window_index,
        scoring_policy_hash=manifest.scoring_policy_hash,
        terminal_classification=manifest.terminal_classification,
        highest_stage=manifest.highest_stage,
        audit_release_block=manifest.audit_release_block,
        audit_release_block_hash=manifest.audit_release_block_hash,
        reason_codes=tuple(manifest.reason_codes),
    )


def _bind_bundle_to_window(
    bundle: VerifiedPublishedBundle,
    previous: WindowRecord,
    policy_hash: str,
) -> None:
    if (
        bundle.window_id != previous.plan.window_id
        or bundle.window_index != previous.plan.window_index
        or bundle.scoring_policy_hash != policy_hash
        or bundle.highest_stage != previous.stage.value
        or bundle.audit_release_block != previous.audit_release_block
        or bundle.terminal_classification != previous.terminal_outcome.value
    ):
        raise ReadinessEvidenceError("prior_bundle_window_mismatch")
    reason = previous.terminal_reason_code
    if reason is None:
        if bundle.reason_codes:
            raise ReadinessEvidenceError("successful_prior_bundle_has_reason")
    elif reason not in bundle.reason_codes:
        raise ReadinessEvidenceError("prior_bundle_reason_mismatch")


def _bind_resolved_reveal(
    resolved: object,
    previous: WindowRecord,
    state: object,
    policy: ScoringPolicy,
) -> None:
    if not isinstance(resolved, ResolvedRevealStage):
        raise ReadinessEvidenceError("prior_reveal_resolver_result_invalid")
    if (
        resolved.policy != policy
        or resolved.result.window_id != previous.plan.window_id
        or resolved.result.window_index != previous.plan.window_index
        or resolved.result.scoring_policy_hash != previous.plan.scoring_policy_hash
        or resolved.resulting_protocol_state_digest != state.state_digest.hex()
    ):
        raise ReadinessEvidenceError("prior_reveal_state_mismatch")
    transition = resolved.protocol_transition_result
    spent = transition.get("spent")
    if (
        not isinstance(spent, dict)
        or spent.get("resulting_root") != state.spent_registry.root.hex()
        or state.spent_registry.last_reveal_round != previous.plan.reveal_round
    ):
        raise ReadinessEvidenceError("prior_spent_transition_mismatch")


def _bind_release_block(
    block: object,
    bundle: VerifiedPublishedBundle,
    policy: ScoringPolicy,
    policy_hash: str,
) -> None:
    pins = policy.implementation_pins
    if not isinstance(block, VerifiedFinalizedBlock):
        raise ReadinessEvidenceError("prior_release_block_invalid")
    if (
        block.height != bundle.audit_release_block
        or block.block_hash != bundle.audit_release_block_hash
        or block.scoring_policy_hash != policy_hash
        or block.chain_observation != pins.live_chain
        or pins.finality_verifier is None
        or block.finality_verifier_sha256
        not in pins.finality_verifier.release_sha256_by_target.values()
    ):
        raise ReadinessEvidenceError("prior_release_block_mismatch")


def _read_manifest_discriminator(root: Path) -> tuple[bytes, str]:
    if not isinstance(root, Path) or not root.exists() or root.is_symlink() or not root.is_dir():
        raise FileNotFoundError("published bundle root is unavailable")
    path = root / "manifest.json"
    if path.is_symlink():
        raise ReadinessEvidenceError("published_bundle_manifest_unsafe")
    before = path.stat()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
        or before.st_size > MAX_CALIBRATION_MANIFEST_BYTES
    ):
        raise ReadinessEvidenceError("published_bundle_manifest_unsafe")
    data = path.read_bytes()
    after = path.stat()
    if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ) or len(data) != before.st_size:
        raise ReadinessEvidenceError("published_bundle_manifest_changed")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ReadinessEvidenceError("published_bundle_manifest_invalid") from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != data:
        raise ReadinessEvidenceError("published_bundle_manifest_noncanonical")
    schema = value.get("schema")
    if schema not in {CALIBRATION_BUNDLE_SCHEMA, INCIDENT_BUNDLE_SCHEMA}:
        raise ReadinessEvidenceError("published_bundle_schema_unsupported")
    return data, schema


__all__ = [
    "READINESS_EVIDENCE_SCHEMA",
    "ProofBackedPriorWindowReadiness",
    "PublishedBundleVerifier",
    "ReadinessEvidenceError",
    "ReadinessFinalityPort",
    "ReplayPublishedBundleVerifier",
    "VerifiedPublishedBundle",
]
