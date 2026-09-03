"""Proof-backed authority for publisher availability qualification.

The installed availability operator enters through this module. It rebuilds the
announcement validator set from authenticated Substrate storage, replays the
smoldot finality record, and binds the complete spent set to either exact genesis
or a fully replayed prior-window readiness record before any candidate can be
signed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

from .encoding import account_id32
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import canonical_json_bytes
from .publisher_availability import (
    AvailabilityQualificationContext,
    AvailabilityQualificationReceipt,
    AvailabilityQualificationStore,
    AvailabilityWorkflowError,
    LoadedCandidateBundle,
    ValidatedCandidateBundle,
    qualify_candidate_set_component,
    validate_candidate_bundle,
)
from .validator_chain import MultiStorageProofVerifier
from .validator_closing_snapshot import (
    AnnouncementValidatorSnapshot,
    ClosingSnapshotCollectorError,
    replay_announcement_validator_storage,
    validate_replayed_announcement_validator_snapshot,
)
from .validator_pool_replay import (
    PoolStageReplayError,
    verify_snapshot_finality,
)
from .validator_protocol_state import (
    ProtocolStateCorruption,
    ProtocolStateSnapshot,
    decode_protocol_state_snapshot,
)
from .validator_readiness import READINESS_EVIDENCE_SCHEMA

PROTOCOL_STATE_GENESIS_EVIDENCE_SCHEMA = "umi-availability-protocol-state-genesis/1"

_GENESIS_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "protocol",
        "window_id",
        "window_index",
        "scoring_policy_hash",
        "protocol_state_sha256",
        "protocol_state_digest",
        "spent_root",
        "spent_last_reveal_round",
    }
)
_READINESS_EVIDENCE_KEYS = frozenset(
    {
        "schema",
        "protocol",
        "window_id",
        "window_index",
        "reveal_round",
        "scoring_policy_hash",
        "terminal_outcome",
        "terminal_stage",
        "terminal_stage_evidence_sha256",
        "reveal_stage_evidence_sha256",
        "bundle_manifest_sha256",
        "audit_release_block",
        "audit_release_block_hash",
        "audit_release_state_root",
        "finality_verifier_sha256",
        "finality_evidence_sha256",
        "protocol_state_digest",
        "spent_root",
        "spent_last_reveal_round",
    }
)


@dataclass(frozen=True, slots=True)
class VerifiedQualificationObservation:
    """One current finalized head returned by the pinned smoldot observer."""

    block_number: int
    block_hash: str
    finality_evidence_bytes: bytes

    def __post_init__(self) -> None:
        if isinstance(self.block_number, bool) or not isinstance(self.block_number, int):
            raise TypeError("qualification observation block number must be an integer")
        if self.block_number < 0:
            raise ValueError("qualification observation block number must be nonnegative")
        try:
            block_hash = bytes.fromhex(self.block_hash.removeprefix("0x"))
        except (AttributeError, ValueError) as error:
            raise ValueError("qualification observation block hash is invalid") from error
        if len(block_hash) != 32 or self.block_hash != f"0x{block_hash.hex()}":
            raise ValueError("qualification observation block hash is invalid")
        if not isinstance(self.finality_evidence_bytes, bytes) or not self.finality_evidence_bytes:
            raise TypeError("qualification observation evidence must be nonempty exact bytes")
        try:
            value = json.loads(self.finality_evidence_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("qualification observation evidence is invalid JSON") from error
        if canonical_json_bytes(value) != self.finality_evidence_bytes:
            raise ValueError("qualification observation evidence is not canonical JSON")


@dataclass(frozen=True, slots=True)
class ProofBackedQualificationAuthority:
    """Replayed common authority and exact objects retained with one signature."""

    context: AvailabilityQualificationContext
    announcement: AnnouncementValidatorSnapshot
    protocol_state: ProtocolStateSnapshot
    authority_objects: dict[str, bytes]

    def __post_init__(self) -> None:
        if not isinstance(self.context, AvailabilityQualificationContext):
            raise TypeError("qualification authority context has another type")
        if not isinstance(self.announcement, AnnouncementValidatorSnapshot):
            raise TypeError("qualification announcement snapshot has another type")
        if not isinstance(self.protocol_state, ProtocolStateSnapshot):
            raise TypeError("qualification protocol state has another type")
        if len(self.authority_objects) != 5:
            raise ValueError("qualification authority must retain five exact objects")
        for digest, data in self.authority_objects.items():
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError("qualification authority object does not reproduce its digest")


@dataclass(frozen=True, slots=True)
class AuthorizedCandidateQualification:
    """Candidate validation result paired with the authority that produced it."""

    validated: ValidatedCandidateBundle
    authority: ProofBackedQualificationAuthority


def authorize_candidate_qualification(
    *,
    loaded: LoadedCandidateBundle,
    policy: ScoringPolicy,
    validator_hotkey: str,
    announcement_snapshot_bytes: bytes,
    announcement_proof_evidence_bytes: bytes,
    protocol_state_bytes: bytes,
    protocol_state_continuity_evidence_bytes: bytes,
    observation: VerifiedQualificationObservation,
    storage_proof_verifier: MultiStorageProofVerifier,
    finality_verifier: Any,
    finality_verifier_sha256: str,
) -> AuthorizedCandidateQualification:
    """Rebuild all qualification authority, then apply spent checks to candidates."""

    if not isinstance(loaded, LoadedCandidateBundle):
        raise TypeError("qualification candidate bundle has another type")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("qualification policy has another type")
    if policy.translation_weights_active is not False:
        raise AvailabilityWorkflowError("availability_requires_shadow_policy")
    account_id32(validator_hotkey)
    if not callable(storage_proof_verifier) or not callable(finality_verifier):
        raise TypeError("qualification proof verifiers must be callable")
    policy_hash = scoring_policy_hash(policy)

    try:
        replayed = replay_announcement_validator_storage(
            announcement_proof_evidence_bytes,
            verifier=storage_proof_verifier,
        )
        announcement = validate_replayed_announcement_validator_snapshot(
            announcement_snapshot_bytes,
            replayed,
            policy=policy,
        )
        verify_snapshot_finality(
            replayed.evidence,
            label="availability announcement",
            policy=policy,
            finality_verifier=finality_verifier,
            finality_verifier_sha256=finality_verifier_sha256,
        )
    except (ClosingSnapshotCollectorError, PoolStageReplayError) as error:
        raise AvailabilityWorkflowError("qualification_announcement_authority_invalid") from error

    window = loaded.manifest.window
    if (
        announcement.window_id != window.window_id
        or announcement.window_index != window.window_index
        or announcement.scoring_policy_hash != policy_hash
        or announcement.announcement_block != window.announcement_block
    ):
        raise AvailabilityWorkflowError("qualification_announcement_window_mismatch")

    try:
        protocol_state = decode_protocol_state_snapshot(protocol_state_bytes)
    except (ProtocolStateCorruption, TypeError, ValueError) as error:
        raise AvailabilityWorkflowError("qualification_protocol_state_invalid") from error
    if protocol_state.last_window_index != window.window_index - 1:
        raise AvailabilityWorkflowError("qualification_protocol_state_not_reconciled")
    if protocol_state.spent_registry.last_reveal_round >= window.reveal_round:
        raise AvailabilityWorkflowError("qualification_protocol_state_round_invalid")
    _validate_protocol_state_continuity_evidence(
        protocol_state_continuity_evidence_bytes,
        protocol_state_bytes=protocol_state_bytes,
        protocol_state=protocol_state,
        window_id=window.window_id,
        window_index=window.window_index,
        reveal_round=window.reveal_round,
        policy_hash=policy_hash,
    )

    active = [item.validator_hotkey for item in announcement.validators if item.validator_permit]
    active.sort(key=account_id32)
    validator_account = account_id32(validator_hotkey)
    if len(active) < 4 or validator_account not in {account_id32(value) for value in active}:
        raise AvailabilityWorkflowError("qualification_validator_not_active")
    if not (window.announcement_block <= observation.block_number < window.proposal_close_block):
        raise AvailabilityWorkflowError("qualification_outside_proposal_interval")
    if (
        observation.block_number == window.announcement_block
        and observation.block_hash != announcement.announcement_block_hash
    ):
        raise AvailabilityWorkflowError("qualification_observation_hash_mismatch")

    snapshot_sha256 = hashlib.sha256(announcement_snapshot_bytes).hexdigest()
    proof_sha256 = hashlib.sha256(announcement_proof_evidence_bytes).hexdigest()
    state_sha256 = hashlib.sha256(protocol_state_bytes).hexdigest()
    continuity_sha256 = hashlib.sha256(protocol_state_continuity_evidence_bytes).hexdigest()
    observation_sha256 = hashlib.sha256(observation.finality_evidence_bytes).hexdigest()
    context = AvailabilityQualificationContext(
        schema="umi-availability-qualification-context/1",
        protocol="umi-asl/0.1",
        window_id=window.window_id,
        window_index=window.window_index,
        scoring_policy_hash=policy_hash,
        candidate_set_sha256=loaded.sha256,
        announcement_block_hash=announcement.announcement_block_hash,
        announcement_timestamp_ms=announcement.announcement_block_timestamp_ms,
        announcement_finality_evidence_sha256=(
            replayed.evidence.finality.finality_attestation_sha256
        ),
        active_validator_set_evidence_sha256=snapshot_sha256,
        announcement_validator_proof_evidence_sha256=proof_sha256,
        protocol_state_continuity_evidence_sha256=continuity_sha256,
        observed_finalized_block=observation.block_number,
        observed_finalized_block_hash=observation.block_hash,
        observation_finality_evidence_sha256=observation_sha256,
        validator_hotkey=validator_hotkey,
        active_validator_hotkeys=active,
        spent_registry_root=protocol_state.spent_registry.root.hex(),
        spent_registry_evidence_sha256=state_sha256,
        spent_leaves=[item.hex() for item in sorted(protocol_state.spent_registry.leaves)],
    )
    authority = ProofBackedQualificationAuthority(
        context=context,
        announcement=announcement,
        protocol_state=protocol_state,
        authority_objects={
            snapshot_sha256: announcement_snapshot_bytes,
            proof_sha256: announcement_proof_evidence_bytes,
            state_sha256: protocol_state_bytes,
            continuity_sha256: protocol_state_continuity_evidence_bytes,
            observation_sha256: observation.finality_evidence_bytes,
        },
    )
    validated = validate_candidate_bundle(loaded, policy=policy, context=context)
    return AuthorizedCandidateQualification(validated=validated, authority=authority)


def protocol_state_genesis_evidence(
    *,
    protocol_state_bytes: bytes,
    protocol_state: ProtocolStateSnapshot,
    window_id: str,
    policy_hash: str,
) -> bytes:
    """Bind the one permitted genesis state to the first candidate window."""

    _require_exact_protocol_state_genesis(protocol_state)
    return canonical_json_bytes(
        {
            "schema": PROTOCOL_STATE_GENESIS_EVIDENCE_SCHEMA,
            "protocol": "umi-asl/0.1",
            "window_id": window_id,
            "window_index": 0,
            "scoring_policy_hash": policy_hash,
            "protocol_state_sha256": hashlib.sha256(protocol_state_bytes).hexdigest(),
            "protocol_state_digest": protocol_state.state_digest.hex(),
            "spent_root": protocol_state.spent_registry.root.hex(),
            "spent_last_reveal_round": protocol_state.spent_registry.last_reveal_round,
        }
    )


def _validate_protocol_state_continuity_evidence(
    evidence: bytes,
    *,
    protocol_state_bytes: bytes,
    protocol_state: ProtocolStateSnapshot,
    window_id: str,
    window_index: int,
    reveal_round: int,
    policy_hash: str,
) -> None:
    try:
        value = json.loads(evidence)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AvailabilityWorkflowError(
            "qualification_protocol_state_continuity_invalid"
        ) from error
    if not isinstance(value, dict) or canonical_json_bytes(value) != evidence:
        raise AvailabilityWorkflowError("qualification_protocol_state_continuity_invalid")
    if window_index == 0:
        _require_exact_protocol_state_genesis(protocol_state)
        expected = protocol_state_genesis_evidence(
            protocol_state_bytes=protocol_state_bytes,
            protocol_state=protocol_state,
            window_id=window_id,
            policy_hash=policy_hash,
        )
        if set(value) != _GENESIS_EVIDENCE_KEYS or evidence != expected:
            raise AvailabilityWorkflowError("qualification_protocol_state_genesis_mismatch")
        return
    if set(value) != _READINESS_EVIDENCE_KEYS or value.get("schema") != READINESS_EVIDENCE_SCHEMA:
        raise AvailabilityWorkflowError("qualification_protocol_state_continuity_invalid")
    if (
        value.get("protocol") != "umi-asl/0.1"
        or value.get("window_index") != window_index - 1
        or value.get("window_id")
        != (None if protocol_state.last_window_id is None else protocol_state.last_window_id.hex())
        or value.get("scoring_policy_hash") != policy_hash
        or value.get("reveal_round") != protocol_state.spent_registry.last_reveal_round
        or value.get("spent_last_reveal_round") != protocol_state.spent_registry.last_reveal_round
        or value.get("spent_root") != protocol_state.spent_registry.root.hex()
        or value.get("protocol_state_digest") != protocol_state.state_digest.hex()
        or not isinstance(value.get("audit_release_block"), int)
        or isinstance(value.get("audit_release_block"), bool)
        or value["audit_release_block"] <= 0
        or value.get("terminal_stage")
        not in {
            "reveal_and_score",
            "weight_build",
            "commit_and_terminal_state",
        }
        or value.get("terminal_outcome")
        not in {
            "calibration_no_weight",
            "skipped",
            "void",
            "failed",
        }
        or protocol_state.spent_registry.last_reveal_round >= reveal_round
    ):
        raise AvailabilityWorkflowError("qualification_protocol_state_continuity_mismatch")
    for key in (
        "terminal_stage_evidence_sha256",
        "reveal_stage_evidence_sha256",
        "bundle_manifest_sha256",
        "finality_verifier_sha256",
        "finality_evidence_sha256",
    ):
        _require_hex32(value.get(key), reason="qualification_protocol_state_continuity_invalid")
    for key in ("audit_release_block_hash", "audit_release_state_root"):
        raw = value.get(key)
        if not isinstance(raw, str) or not raw.startswith("0x"):
            raise AvailabilityWorkflowError("qualification_protocol_state_continuity_invalid")
        _require_hex32(raw[2:], reason="qualification_protocol_state_continuity_invalid")


def _require_exact_protocol_state_genesis(state: ProtocolStateSnapshot) -> None:
    zero = bytes(32)
    if (
        state.last_window_index != -1
        or state.last_window_id is not None
        or state.spent_registry.root != zero
        or state.spent_registry.leaves
        or state.spent_registry.last_reveal_round != 0
        or state.publisher_faults.root != zero
        or state.publisher_faults.last_window_index != -1
        or state.publisher_faults.strikes
        or state.publisher_faults.cooldown_ends
        or state.rolling_scores.batches
        or state.assigned_observation_counts
        or state.observation_root != zero
    ):
        raise AvailabilityWorkflowError("qualification_protocol_state_not_exact_genesis")


def _require_hex32(value: object, *, reason: str) -> None:
    if not isinstance(value, str) or len(value) != 64:
        raise AvailabilityWorkflowError(reason)
    try:
        if bytes.fromhex(value).hex() != value:
            raise ValueError
    except ValueError as error:
        raise AvailabilityWorkflowError(reason) from error


def sign_authorized_candidate_qualification(
    authorized: AuthorizedCandidateQualification,
    *,
    policy: ScoringPolicy,
    state: AvailabilityQualificationStore,
    wallet: Any,
    before_sign: Any | None = None,
) -> AvailabilityQualificationReceipt:
    """Reserve and sign one already replayed proof-backed qualification."""

    if not isinstance(authorized, AuthorizedCandidateQualification):
        raise TypeError("authorized qualification has another type")
    return qualify_candidate_set_component(
        authorized.validated,
        policy=policy,
        context=authorized.authority.context,
        authority_objects=authorized.authority.authority_objects,
        state=state,
        wallet=wallet,
        before_sign=before_sign,
    )


__all__ = [
    "PROTOCOL_STATE_GENESIS_EVIDENCE_SCHEMA",
    "AuthorizedCandidateQualification",
    "ProofBackedQualificationAuthority",
    "VerifiedQualificationObservation",
    "authorize_candidate_qualification",
    "protocol_state_genesis_evidence",
    "sign_authorized_candidate_qualification",
]
