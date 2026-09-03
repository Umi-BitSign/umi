"""Deterministic spent-content and publisher-fault registry transitions."""

from __future__ import annotations

import hashlib
from collections import Counter
from dataclasses import dataclass
from enum import Enum

from pydantic import ValidationError

from .artifacts import PublicBatchManifest
from .crypto import SealedResponse, TimelockDecryptionError, parse_sealed_response
from .drand import DrandPulse
from .encoding import (
    account_id32,
    binary_merkle_root,
    raw_sha256,
    sha256_domain,
    u16be,
    u32be,
    u64be,
)
from .policy import ScoringPolicy, scoring_policy_hash
from .pool import PoolBatchEntry, batch_commitment
from .protocol import GroundTruthPayload, canonical_json_bytes

ZERO_ROOT = bytes(32)


class PublisherFaultReason(str, Enum):
    """The exhaustive Section 8.6 objective publisher-fault reasons."""

    TIMELOCK_DECRYPTION_FAILED = "timelock_decryption_failed"
    GROUND_TRUTH_SCHEMA_INVALID = "ground_truth_schema_invalid"
    COMMITTED_BINDING_MISMATCH = "committed_binding_mismatch"
    SPENT_SCRIPT_DUPLICATE = "spent_script_duplicate"


class PublisherRevealOutcome(str, Enum):
    """A verified timelock's only two admissible classifier outcomes.

    ``TIMELOCK_DECRYPTION_FAILED`` means the retained, structurally valid
    portable envelope failed cryptographic decryption with the verified pulse.
    It must not be used for a missing mirror, retrieval failure, timeout before
    the pulse, or any other validator-local failure.
    """

    DECRYPTED = "decrypted"
    TIMELOCK_DECRYPTION_FAILED = "timelock_decryption_failed"


def spent_batch_leaf(batch_commitment: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-batch-v1\0",
        raw_sha256(batch_commitment, field="batch commitment"),
    )


def spent_script_leaf(script_hash: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-script-v1\0",
        raw_sha256(script_hash, field="normalized script hash"),
    )


def spent_video_leaf(video_hash: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-video-v1\0",
        raw_sha256(video_hash, field="video hash"),
    )


def spent_frame_leaf(frame_digest: str | bytes) -> bytes:
    return sha256_domain(
        b"umi-spent-frame-v1\0",
        raw_sha256(frame_digest, field="frame digest"),
    )


@dataclass(frozen=True)
class SpentCohortBatch:
    batch_commitment: str | bytes
    video_hashes: tuple[str | bytes, ...]
    frame_digests: tuple[str | bytes, ...]
    revealed_script_hashes: tuple[str | bytes, ...] = ()

    def __post_init__(self) -> None:
        raw_sha256(self.batch_commitment, field="batch commitment")
        if not self.video_hashes or not self.frame_digests:
            raise ValueError("spent batch must carry public video and frame hashes")
        if len(self.video_hashes) != len(self.frame_digests):
            raise ValueError("spent batch video and frame hash counts disagree")
        for value in self.video_hashes:
            raw_sha256(value, field="video hash")
        for value in self.frame_digests:
            raw_sha256(value, field="frame digest")
        for value in self.revealed_script_hashes:
            raw_sha256(value, field="normalized script hash")


@dataclass(frozen=True)
class SpentTransition:
    reveal_round: int
    previous_root: bytes
    delta_leaves: tuple[bytes, ...]
    delta_root: bytes
    resulting_root: bytes
    prior_collisions: tuple[bytes, ...]
    duplicate_video_hashes: tuple[bytes, ...]
    duplicate_frame_digests: tuple[bytes, ...]

    @property
    def has_eligibility_fault(self) -> bool:
        return bool(
            self.prior_collisions or self.duplicate_video_hashes or self.duplicate_frame_digests
        )


@dataclass(frozen=True)
class SpentRegistryState:
    root: bytes = ZERO_ROOT
    leaves: frozenset[bytes] = frozenset()
    last_reveal_round: int = 0

    def __post_init__(self) -> None:
        raw_sha256(self.root, field="spent registry root")
        for leaf in self.leaves:
            raw_sha256(leaf, field="spent registry leaf")
        if self.last_reveal_round < 0:
            raise ValueError("last reveal round must not be negative")

    def apply(
        self,
        reveal_round: int,
        batches: tuple[SpentCohortBatch, ...],
    ) -> tuple[SpentRegistryState, SpentTransition]:
        if reveal_round <= self.last_reveal_round:
            raise ValueError("spent transitions must advance in reveal-round order")
        commitments = [
            raw_sha256(batch.batch_commitment, field="batch commitment") for batch in batches
        ]
        if len(set(commitments)) != len(commitments):
            raise ValueError("spent cohort contains a duplicate batch commitment")

        raw_videos = [
            raw_sha256(value, field="video hash")
            for batch in batches
            for value in batch.video_hashes
        ]
        raw_frames = [
            raw_sha256(value, field="frame digest")
            for batch in batches
            for value in batch.frame_digests
        ]
        duplicate_videos = tuple(
            sorted(value for value, count in Counter(raw_videos).items() if count > 1)
        )
        duplicate_frames = tuple(
            sorted(value for value, count in Counter(raw_frames).items() if count > 1)
        )
        cohort_leaves: set[bytes] = set()
        for batch in batches:
            cohort_leaves.add(spent_batch_leaf(batch.batch_commitment))
            cohort_leaves.update(spent_video_leaf(value) for value in batch.video_hashes)
            cohort_leaves.update(spent_frame_leaf(value) for value in batch.frame_digests)
            cohort_leaves.update(spent_script_leaf(value) for value in batch.revealed_script_hashes)

        collisions = tuple(sorted(cohort_leaves.intersection(self.leaves)))
        delta = tuple(sorted(cohort_leaves.difference(self.leaves)))
        delta_root = binary_merkle_root(
            delta,
            node_domain=b"umi-spent-node-v1\0",
            empty_domain=b"umi-spent-empty-v1\0",
        )
        resulting_root = sha256_domain(
            b"umi-spent-root-v1\0",
            self.root,
            u64be(reveal_round),
            delta_root,
        )
        next_state = SpentRegistryState(
            root=resulting_root,
            leaves=frozenset(self.leaves.union(cohort_leaves)),
            last_reveal_round=reveal_round,
        )
        transition = SpentTransition(
            reveal_round=reveal_round,
            previous_root=self.root,
            delta_leaves=delta,
            delta_root=delta_root,
            resulting_root=resulting_root,
            prior_collisions=collisions,
            duplicate_video_hashes=duplicate_videos,
            duplicate_frame_digests=duplicate_frames,
        )
        return next_state, transition


@dataclass(frozen=True, slots=True)
class PublisherRevealEvidence:
    """Canonical evidence for one attributable anchored-eligible batch.

    Construction is intentionally impossible without the retained pool entry,
    public manifest, portable envelope, and independently verified Quicknet
    pulse. ``anchored_eligibility_evidence_sha256`` binds the finalized anchor,
    registration, ownership, collateral, certificate, and artifact checks made
    by the live collector; this pure registry module does not treat that digest
    as a substitute for verifying those checks.

    A caller must only use ``TIMELOCK_DECRYPTION_FAILED`` after
    :func:`umi.crypto.decrypt_response` raises its narrow
    ``TimelockDecryptionError``. Generic I/O and local-availability failures do
    not produce this evidence type and therefore cannot become strikes here.
    """

    control_group_id: str | bytes
    pool_entry: PoolBatchEntry
    public_manifest: PublicBatchManifest
    sealed_ground_truth: SealedResponse
    reveal_pulse: DrandPulse
    anchored_eligibility_evidence_sha256: str | bytes
    outcome: PublisherRevealOutcome
    decrypted_bytes: bytes | None
    decryption_error: TimelockDecryptionError | None = None
    prior_spent_leaves: frozenset[bytes] = frozenset()

    def __post_init__(self) -> None:
        raw_sha256(self.control_group_id, field="control group ID")
        raw_sha256(
            self.anchored_eligibility_evidence_sha256,
            field="anchored-eligibility evidence digest",
        )
        if not isinstance(self.pool_entry, PoolBatchEntry):
            raise TypeError("pool_entry must be a PoolBatchEntry")
        if not isinstance(self.public_manifest, PublicBatchManifest):
            raise TypeError("public_manifest must be a PublicBatchManifest")
        if not isinstance(self.sealed_ground_truth, SealedResponse):
            raise TypeError("sealed_ground_truth must be a SealedResponse")
        if not isinstance(self.reveal_pulse, DrandPulse):
            raise TypeError("reveal_pulse must be a DrandPulse")
        if not isinstance(self.outcome, PublisherRevealOutcome):
            raise TypeError("outcome must be a PublisherRevealOutcome")
        for leaf in self.prior_spent_leaves:
            raw_sha256(leaf, field="prior spent leaf")

        manifest = self.public_manifest
        entry = self.pool_entry
        canonical_manifest = canonical_json_bytes(manifest)
        if entry.batch_id != manifest.batch_id:
            raise ValueError("pool entry batch ID does not match the public manifest")
        if entry.public_manifest_sha256 != hashlib.sha256(canonical_manifest).hexdigest():
            raise ValueError("pool entry does not commit the canonical public manifest")
        if entry.ciphertext_sha256 != manifest.ciphertext_sha256:
            raise ValueError("pool entry and public manifest ciphertext hashes disagree")
        if entry.reveal_round != manifest.reveal_round:
            raise ValueError("pool entry and public manifest reveal rounds disagree")
        expected_commitment = batch_commitment(
            manifest,
            self.sealed_ground_truth.portable_bytes,
            manifest.reveal_round,
        )
        if entry.batch_commitment != expected_commitment:
            raise ValueError("pool entry batch commitment does not reproduce")
        if self.sealed_ground_truth.sha256_hex != manifest.ciphertext_sha256:
            raise ValueError("retained portable envelope does not match its public commitment")
        if self.sealed_ground_truth.reveal_round != manifest.reveal_round:
            raise ValueError("portable envelope and public manifest reveal rounds disagree")

        # Reparse instead of trusting a manually constructed SealedResponse.
        parsed = parse_sealed_response(
            self.sealed_ground_truth.portable_b64,
            reveal_round=manifest.reveal_round,
            sha256_hex=manifest.ciphertext_sha256,
        )
        if parsed.portable_bytes != self.sealed_ground_truth.portable_bytes:
            raise ValueError("retained portable envelope bytes changed during strict parsing")
        self.reveal_pulse.verify()
        if self.reveal_pulse.round != manifest.reveal_round:
            raise ValueError("verified Quicknet pulse is for a different reveal round")

        if self.outcome is PublisherRevealOutcome.DECRYPTED:
            if not isinstance(self.decrypted_bytes, bytes):
                raise TypeError("a decrypted reveal outcome requires exact plaintext bytes")
            if self.decryption_error is not None:
                raise ValueError("a decrypted reveal outcome must not carry a decryption error")
        else:
            if self.decrypted_bytes is not None:
                raise ValueError("a failed timelock outcome must not carry plaintext bytes")
            if not isinstance(self.decryption_error, TimelockDecryptionError):
                raise TypeError(
                    "a failed timelock outcome requires TimelockDecryptionError evidence"
                )


@dataclass(frozen=True, slots=True)
class PublisherFaultFinding:
    """One evidence-derived leaf input, before the per-group strike collapse."""

    control_group_id: bytes
    publisher_hotkey: bytes
    window_id: bytes
    batch_commitment: bytes
    reason: PublisherFaultReason
    reason_code: int

    def __post_init__(self) -> None:
        raw_sha256(self.control_group_id, field="control group ID")
        account_id32(self.publisher_hotkey)
        raw_sha256(self.window_id, field="window ID")
        raw_sha256(self.batch_commitment, field="batch commitment")
        if not isinstance(self.reason, PublisherFaultReason):
            raise TypeError("publisher fault reason must be canonical")
        u16be(self.reason_code)

    @property
    def leaf(self) -> bytes:
        return publisher_fault_leaf(
            self.control_group_id,
            self.publisher_hotkey,
            self.window_id,
            self.batch_commitment,
            self.reason_code,
        )


def classify_publisher_reveal(
    evidence: PublisherRevealEvidence,
    *,
    policy: ScoringPolicy,
) -> tuple[PublisherFaultFinding, ...]:
    """Classify only the four objective Section 8.6 reveal faults.

    Canary hits, reference-quality or consent disputes, and validator-local
    retrieval failures are deliberately absent from the input and cannot
    produce a finding. The returned findings are sorted by the policy-pinned
    ``u16`` reason code; a later state transition may retain several leaves but
    accrues at most one strike to their control group for this window.
    """

    if not isinstance(evidence, PublisherRevealEvidence):
        raise TypeError("evidence must be PublisherRevealEvidence")
    if not isinstance(policy, ScoringPolicy):
        raise TypeError("policy must be a ScoringPolicy")
    manifest = evidence.public_manifest
    if manifest.scoring_policy_hash != scoring_policy_hash(policy):
        raise ValueError("publisher reveal evidence names a different scoring policy")
    publisher_account = account_id32(manifest.publisher_hotkey)
    publisher_registry = {
        account_id32(entry.publisher_hotkey): entry for entry in policy.publisher_registry
    }
    publisher = publisher_registry.get(publisher_account)
    if publisher is None:
        raise ValueError("publisher reveal evidence names an unregistered publisher")
    if raw_sha256(publisher.control_group_id, field="registered control group ID") != raw_sha256(
        evidence.control_group_id,
        field="control group ID",
    ):
        raise ValueError("publisher reveal evidence has the wrong control-group attribution")
    codebook = _publisher_fault_codebook(
        {
            item.name: item.code
            for item in policy.implementation_pins.rules.publisher_fault_reason_codes
        }
    )
    reasons: set[PublisherFaultReason] = set()

    if evidence.outcome is PublisherRevealOutcome.TIMELOCK_DECRYPTION_FAILED:
        reasons.add(PublisherFaultReason.TIMELOCK_DECRYPTION_FAILED)
    else:
        plaintext = evidence.decrypted_bytes
        if not isinstance(plaintext, bytes):  # Reassert the frozen evidence invariant.
            raise TypeError("decrypted evidence is missing exact plaintext bytes")
        try:
            ground_truth = GroundTruthPayload.model_validate_json(plaintext)
        except (ValidationError, ValueError):
            reasons.add(PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID)
        else:
            if canonical_json_bytes(ground_truth) != plaintext:
                reasons.add(PublisherFaultReason.GROUND_TRUTH_SCHEMA_INVALID)
            else:
                if _ground_truth_binding_mismatch(evidence.public_manifest, ground_truth):
                    reasons.add(PublisherFaultReason.COMMITTED_BINDING_MISMATCH)
                if any(
                    spent_script_leaf(script_hash) in evidence.prior_spent_leaves
                    for item in ground_truth.items
                    for script_hash in item.retirement_script_sha256s
                ):
                    reasons.add(PublisherFaultReason.SPENT_SCRIPT_DUPLICATE)

    findings = [
        PublisherFaultFinding(
            control_group_id=raw_sha256(evidence.control_group_id, field="control group ID"),
            publisher_hotkey=publisher_account,
            window_id=raw_sha256(manifest.window_id, field="window ID"),
            batch_commitment=raw_sha256(
                evidence.pool_entry.batch_commitment,
                field="batch commitment",
            ),
            reason=reason,
            reason_code=codebook[reason],
        )
        for reason in reasons
    ]
    return tuple(sorted(findings, key=lambda finding: finding.reason_code))


def _publisher_fault_codebook(
    values: dict[str, int],
) -> dict[PublisherFaultReason, int]:
    parsed: dict[PublisherFaultReason, int] = {}
    for name, code in values.items():
        try:
            reason = name if isinstance(name, PublisherFaultReason) else PublisherFaultReason(name)
        except (TypeError, ValueError) as error:
            raise ValueError("publisher fault codebook contains a noncanonical reason") from error
        u16be(code)
        if reason in parsed:
            raise ValueError("publisher fault codebook contains a duplicate reason")
        parsed[reason] = code
    if set(parsed) != set(PublisherFaultReason):
        raise ValueError("publisher fault codebook must contain exactly the four canonical reasons")
    if len(set(parsed.values())) != len(parsed):
        raise ValueError("publisher fault reason codes must be unique")
    return parsed


def _ground_truth_binding_mismatch(
    manifest: PublicBatchManifest,
    ground_truth: GroundTruthPayload,
) -> bool:
    if (
        ground_truth.window_id != manifest.window_id
        or ground_truth.batch_id != manifest.batch_id
        or ground_truth.scoring_policy_hash != manifest.scoring_policy_hash
        or ground_truth.tle_profile != manifest.tle_profile
        or ground_truth.response_close_round != manifest.response_close_round
        or ground_truth.reveal_round != manifest.reveal_round
    ):
        return True
    public_items = {item.challenge_id: item for item in manifest.items}
    revealed_items = {item.challenge_id: item for item in ground_truth.items}
    if public_items.keys() != revealed_items.keys():
        return True
    return any(
        revealed.metric != public_items[challenge_id].metric
        or revealed.consent_manifest_sha256 != public_items[challenge_id].consent_manifest_sha256
        for challenge_id, revealed in revealed_items.items()
    )


def publisher_fault_leaf(
    control_group_id: str | bytes,
    publisher_hotkey: str | bytes,
    window_id: str | bytes,
    batch_commitment: str | bytes,
    reason_code: int,
) -> bytes:
    """Reproduce the Section 8.6 leaf for already-classified evidence.

    This low-level function only implements the binary hash formula. Live code
    must obtain its inputs from :func:`classify_publisher_reveal` before applying
    a :class:`PublisherFaultState` transition.
    """

    return sha256_domain(
        b"umi-publisher-fault-leaf-v1\0",
        raw_sha256(control_group_id, field="control group ID"),
        account_id32(publisher_hotkey),
        raw_sha256(window_id, field="window ID"),
        raw_sha256(batch_commitment, field="batch commitment"),
        u16be(reason_code),
    )


@dataclass(frozen=True)
class PublisherFaultTransition:
    window_index: int
    previous_root: bytes
    fault_leaves: tuple[bytes, ...]
    resulting_root: bytes
    struck_groups: tuple[bytes, ...]


@dataclass(frozen=True)
class PublisherFaultState:
    root: bytes = ZERO_ROOT
    strikes: tuple[tuple[bytes, int], ...] = ()
    cooldown_ends: tuple[tuple[bytes, int], ...] = ()
    last_window_index: int = -1

    def __post_init__(self) -> None:
        raw_sha256(self.root, field="publisher fault root")
        if isinstance(self.last_window_index, bool) or not isinstance(self.last_window_index, int):
            raise TypeError("last publisher fault window index must be an integer")
        if self.last_window_index < -1:
            raise ValueError("last publisher fault window index must be at least -1")
        strike_groups = [group for group, _ in self.strikes]
        cooldown_groups = [group for group, _ in self.cooldown_ends]
        if strike_groups != sorted(strike_groups) or len(set(strike_groups)) != len(strike_groups):
            raise ValueError("publisher strikes must be unique and sorted by group")
        if cooldown_groups != sorted(cooldown_groups) or len(set(cooldown_groups)) != len(
            cooldown_groups
        ):
            raise ValueError("publisher cooldowns must be unique and sorted by group")
        for group, count in self.strikes:
            raw_sha256(group, field="control group ID")
            if count not in {1, 2}:
                raise ValueError("publisher strike count must be one or two")
        for group, end in self.cooldown_ends:
            raw_sha256(group, field="control group ID")
            if end < 0:
                raise ValueError("publisher cooldown end must not be negative")
            if group not in strike_groups:
                raise ValueError("publisher cooldown group must have a strike")

    def is_eligible(self, control_group_id: str | bytes, window_index: int) -> bool:
        group = raw_sha256(control_group_id, field="control group ID")
        strikes = dict(self.strikes).get(group, 0)
        if strikes >= 2:
            return False
        return window_index > dict(self.cooldown_ends).get(group, -1)

    def advance_empty_window(
        self,
        window_index: int,
    ) -> tuple[PublisherFaultState, PublisherFaultTransition]:
        """Preserve the existing empty-window API over the general transition."""

        return self._advance(window_index, (), cooldown_windows=None)

    def advance_window(
        self,
        window_index: int,
        findings: tuple[PublisherFaultFinding, ...],
        *,
        cooldown_windows: int,
    ) -> tuple[PublisherFaultState, PublisherFaultTransition]:
        """Apply objective findings and deterministically advance one window.

        Every unique finding contributes its leaf. Several leaves or batches
        from one control group still add exactly one strike in the window.
        """

        return self._advance(window_index, findings, cooldown_windows=cooldown_windows)

    def apply(
        self,
        window_index: int,
        findings: tuple[PublisherFaultFinding, ...],
        *,
        cooldown_windows: int,
    ) -> tuple[PublisherFaultState, PublisherFaultTransition]:
        """Alias matching :class:`SpentRegistryState`'s transition API."""

        return self.advance_window(
            window_index,
            findings,
            cooldown_windows=cooldown_windows,
        )

    def _advance(
        self,
        window_index: int,
        findings: tuple[PublisherFaultFinding, ...],
        *,
        cooldown_windows: int | None,
    ) -> tuple[PublisherFaultState, PublisherFaultTransition]:
        if isinstance(window_index, bool) or not isinstance(window_index, int):
            raise TypeError("publisher fault window index must be an integer")
        if window_index != self.last_window_index + 1:
            raise ValueError("publisher fault transitions must cover every scheduled window")
        if not isinstance(findings, tuple) or any(
            not isinstance(finding, PublisherFaultFinding) for finding in findings
        ):
            raise TypeError("publisher fault findings must be a tuple of canonical findings")
        if findings:
            if isinstance(cooldown_windows, bool) or not isinstance(cooldown_windows, int):
                raise TypeError("publisher fault cooldown must be an integer")
            if cooldown_windows <= 0:
                raise ValueError("publisher fault cooldown must be positive")

        window_ids = {finding.window_id for finding in findings}
        if len(window_ids) > 1:
            raise ValueError("publisher fault findings for one transition disagree on window ID")
        attribution: dict[tuple[bytes, bytes], tuple[bytes, bytes]] = {}
        for finding in findings:
            identity = (finding.window_id, finding.batch_commitment)
            source = (finding.control_group_id, finding.publisher_hotkey)
            prior = attribution.setdefault(identity, source)
            if prior != source:
                raise ValueError("one publisher batch has conflicting fault attribution")

        leaves = tuple(sorted({finding.leaf for finding in findings}))
        struck_groups = tuple(sorted({finding.control_group_id for finding in findings}))
        for group in struck_groups:
            if not self.is_eligible(group, window_index):
                raise ValueError("an ineligible publisher group cannot have an anchored batch")

        strikes = dict(self.strikes)
        cooldowns = dict(self.cooldown_ends)
        for group in struck_groups:
            prior_count = strikes.get(group, 0)
            strikes[group] = min(2, prior_count + 1)
            if prior_count == 0:
                if cooldown_windows is None:  # Findings above make this unreachable.
                    raise RuntimeError("fault transition is missing its cooldown")
                cooldowns[group] = window_index + cooldown_windows

        resulting_root = sha256_domain(
            b"umi-publisher-fault-root-v1\0",
            self.root,
            u64be(window_index),
            u32be(len(leaves)),
            b"".join(leaves),
        )
        next_state = PublisherFaultState(
            root=resulting_root,
            strikes=tuple(sorted(strikes.items())),
            cooldown_ends=tuple(sorted(cooldowns.items())),
            last_window_index=window_index,
        )
        transition = PublisherFaultTransition(
            window_index=window_index,
            previous_root=self.root,
            fault_leaves=leaves,
            resulting_root=resulting_root,
            struck_groups=struck_groups,
        )
        return next_state, transition


__all__ = [
    "PublisherFaultFinding",
    "PublisherFaultReason",
    "PublisherFaultState",
    "PublisherFaultTransition",
    "PublisherRevealEvidence",
    "PublisherRevealOutcome",
    "SpentCohortBatch",
    "SpentRegistryState",
    "SpentTransition",
    "classify_publisher_reveal",
    "publisher_fault_leaf",
    "spent_batch_leaf",
    "spent_frame_leaf",
    "spent_script_leaf",
    "spent_video_leaf",
]
