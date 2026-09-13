"""Signed, replayable publication records for local successor competition state.

These contracts authenticate evaluator statements about a cutoff and a retained
settlement.  They do not prove when either object was observed, prove that no
conflicting statement exists elsewhere, or authorize a weight transaction.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from collections.abc import Sequence
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Any, Literal, TypeVar

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_evidence import (
    IndependentEvaluationEvidence,
    independent_evidence_digest,
    replay_independent_evaluation,
)
from .competition_settlement import (
    CompetitionSettlement,
    EvidenceCutoffSchedule,
    competition_settlement_digest,
)
from .crypto import sign_response_digest, verify_response_signature
from .open_competition import (
    CompetitionPolicy,
    EvaluationRound,
    RegistrationSnapshot,
    Signature,
    SignedSubmission,
    StrictProtocolModel,
    digest,
    identity,
    project_weights,
    validate_admission,
)
from .protocol import Hex32, canonical_json_bytes

_CUTOFF_PUBLICATION_DOMAIN = b"umi-competition-cutoff-publication-v1\0"
_SETTLEMENT_PUBLICATION_DOMAIN = b"umi-competition-settlement-publication-v1\0"
_SIGNED_CUTOFF_DOMAIN = b"umi-signed-competition-cutoff-publication-v1\0"
_SIGNED_SETTLEMENT_DOMAIN = b"umi-signed-competition-settlement-publication-v1\0"
_ROSTER_DOMAIN = b"umi-competition-authenticated-roster-v1\0"
_EVIDENCE_SET_DOMAIN = b"umi-competition-independent-evidence-set-v1\0"
_MAX_REPLAY_BYTES = 512 * 1024**2
_MAX_JOURNAL_BYTES = 64 * 1024**3
_MAX_JOURNAL_RECORDS = 1_000_000
_ModelT = TypeVar("_ModelT", bound=StrictProtocolModel)


class PublicationReplayLimits(StrictProtocolModel):
    """Explicit in-memory validation ceilings, separate from economic policy."""

    maximum_roster_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_BYTES)]
    maximum_evidence_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_BYTES)]
    maximum_certificate_bytes: Annotated[int, Field(ge=1, le=_MAX_REPLAY_BYTES)]


class PublicationJournalCapacity(StrictProtocolModel):
    """Logical append-only certificate capacity, excluding SQLite overhead."""

    maximum_certificates: Annotated[int, Field(ge=1, le=_MAX_JOURNAL_RECORDS)]
    maximum_bytes: Annotated[int, Field(ge=1, le=_MAX_JOURNAL_BYTES)]


class PublicationCapacityError(ValueError):
    """A new certificate could not be retained within the journal capacity."""


class CutoffPublication(StrictProtocolModel):
    schema_: Literal["umi-competition-cutoff-publication/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    runtime_sha256: Hex32
    round: EvaluationRound
    cutoff_schedule: EvidenceCutoffSchedule
    registration_snapshot: RegistrationSnapshot
    authenticated_roster_sha256: Hex32
    finalized_receipt_timing_proven: Literal[False] = False
    global_conflict_absence_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def validate_internal_bindings(self) -> Self:
        if (
            self.round_sha256 != digest(self.round)
            or self.runtime_sha256 != self.round.runtime_sha256
            or self.policy_sha256 != self.round.policy_sha256
        ):
            raise ValueError("cutoff publication round binding mismatch")
        if (
            self.cutoff_schedule.policy_sha256 != self.policy_sha256
            or self.cutoff_schedule.round_sha256 != self.round_sha256
        ):
            raise ValueError("cutoff publication schedule binding mismatch")
        if not (
            self.round.reveal_block
            <= self.cutoff_schedule.evidence_cutoff_block
            <= self.round.valid_through_block
        ):
            raise ValueError("cutoff publication schedule interval is invalid")
        if self.registration_snapshot.block > self.round.submission_close_block:
            raise ValueError("cutoff registration snapshot is from the future")
        return self


class SignedCutoffPublication(StrictProtocolModel):
    publication: CutoffPublication
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class SettlementPublication(StrictProtocolModel):
    schema_: Literal["umi-competition-settlement-publication/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    runtime_sha256: Hex32
    round: EvaluationRound
    settlement_sha256: Hex32
    settlement: CompetitionSettlement
    cutoff_publication_sha256: Hex32
    authenticated_roster_sha256: Hex32
    independent_evidence_set_sha256: Hex32
    projection_sha256: Hex32
    promotion_head_sha256: Hex32
    finalized_receipt_timing_proven: Literal[False] = False
    global_conflict_absence_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def validate_internal_bindings(self) -> Self:
        settlement = self.settlement
        if (
            self.round_sha256 != digest(self.round)
            or self.runtime_sha256 != self.round.runtime_sha256
            or self.policy_sha256 != self.round.policy_sha256
        ):
            raise ValueError("settlement publication round binding mismatch")
        if (
            self.settlement_sha256 != competition_settlement_digest(settlement)
            or settlement.policy_sha256 != self.policy_sha256
            or settlement.round_sha256 != self.round_sha256
            or settlement.roster != self.round.roster
        ):
            raise ValueError("settlement publication record binding mismatch")
        if (
            self.round.suite_sha256 != digest(settlement.suite)
            or settlement.cutoff_schedule.round_sha256 != self.round_sha256
            or settlement.cutoff_schedule.policy_sha256 != self.policy_sha256
        ):
            raise ValueError("settlement publication suite or cutoff binding mismatch")
        if self.projection_sha256 != digest(settlement.projection):
            raise ValueError("settlement publication projection binding mismatch")
        if self.promotion_head_sha256 != digest(settlement.promotion_head):
            raise ValueError("settlement publication promotion-head binding mismatch")
        if not (
            settlement.cutoff_schedule.evidence_cutoff_block
            <= settlement.observed_block
            <= self.round.valid_through_block
        ):
            raise ValueError("settlement publication interval is invalid")
        if any(
            not self.round.reveal_block
            <= result.first_observed_block
            <= settlement.cutoff_schedule.evidence_cutoff_block
            for result in settlement.results
        ):
            raise ValueError("settlement publication evidence interval is invalid")
        return self


class SignedSettlementPublication(StrictProtocolModel):
    publication: SettlementPublication
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


def cutoff_publication_digest(publication: CutoffPublication) -> str:
    publication = _canonical(CutoffPublication, publication)
    return hashlib.sha256(
        _CUTOFF_PUBLICATION_DOMAIN + canonical_json_bytes(publication)
    ).hexdigest()


def settlement_publication_digest(publication: SettlementPublication) -> str:
    publication = _canonical(SettlementPublication, publication)
    return hashlib.sha256(
        _SETTLEMENT_PUBLICATION_DOMAIN + canonical_json_bytes(publication)
    ).hexdigest()


def signed_cutoff_publication_digest(certificate: SignedCutoffPublication) -> str:
    certificate = _canonical(SignedCutoffPublication, certificate)
    return hashlib.sha256(_SIGNED_CUTOFF_DOMAIN + canonical_json_bytes(certificate)).hexdigest()


def signed_settlement_publication_digest(certificate: SignedSettlementPublication) -> str:
    certificate = _canonical(SignedSettlementPublication, certificate)
    return hashlib.sha256(_SIGNED_SETTLEMENT_DOMAIN + canonical_json_bytes(certificate)).hexdigest()


def sign_cutoff_publication(publication: CutoffPublication, wallet: Any) -> Signature:
    publication = _canonical(CutoffPublication, publication)
    return _sign_digest(cutoff_publication_digest(publication), wallet)


def sign_settlement_publication(publication: SettlementPublication, wallet: Any) -> Signature:
    publication = _canonical(SettlementPublication, publication)
    return _sign_digest(settlement_publication_digest(publication), wallet)


def authenticated_roster_digest(
    submissions: Sequence[SignedSubmission],
    *,
    maximum_bytes: int,
) -> str:
    normalized, _ = _canonical_submissions(submissions, maximum_bytes=maximum_bytes)
    return _roster_digest(normalized)


def independent_evidence_set_digest(
    evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
    *,
    maximum_bytes: int,
) -> str:
    normalized, _ = _canonical_evidence(evidence, maximum_bytes=maximum_bytes)
    return _evidence_digest(normalized)


def build_cutoff_publication(
    *,
    round_: EvaluationRound,
    cutoff_schedule: EvidenceCutoffSchedule,
    registration_snapshot: RegistrationSnapshot,
    submissions: Sequence[SignedSubmission],
    policy: CompetitionPolicy,
    limits: PublicationReplayLimits,
) -> CutoffPublication:
    policy = _canonical(CompetitionPolicy, policy)
    round_ = _canonical(EvaluationRound, round_)
    cutoff_schedule = _canonical(EvidenceCutoffSchedule, cutoff_schedule)
    registration_snapshot = _canonical(RegistrationSnapshot, registration_snapshot)
    normalized = _validate_cutoff_material(
        round_=round_,
        cutoff_schedule=cutoff_schedule,
        registration_snapshot=registration_snapshot,
        submissions=submissions,
        policy=policy,
        limits=limits,
    )
    return CutoffPublication(
        schema="umi-competition-cutoff-publication/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        runtime_sha256=round_.runtime_sha256,
        round=round_,
        cutoff_schedule=cutoff_schedule,
        registration_snapshot=registration_snapshot,
        authenticated_roster_sha256=_roster_digest(normalized),
    )


def verify_cutoff_publication(
    certificate: SignedCutoffPublication,
    *,
    policy: CompetitionPolicy,
    submissions: Sequence[SignedSubmission],
    limits: PublicationReplayLimits,
) -> CutoffPublication:
    policy = _canonical(CompetitionPolicy, policy)
    certificate = _bounded_certificate(
        SignedCutoffPublication,
        certificate,
        maximum_bytes=limits.maximum_certificate_bytes,
    )
    publication = certificate.publication
    normalized = _validate_cutoff_material(
        round_=publication.round,
        cutoff_schedule=publication.cutoff_schedule,
        registration_snapshot=publication.registration_snapshot,
        submissions=submissions,
        policy=policy,
        limits=limits,
    )
    if publication.authenticated_roster_sha256 != _roster_digest(normalized):
        raise ValueError("cutoff publication authenticated-roster digest mismatch")
    _verify_publication_quorum(
        cutoff_publication_digest(publication),
        certificate.signatures,
        policy=policy,
        roster=normalized,
        forbidden_hotkeys=(),
    )
    return publication


def build_settlement_publication(
    *,
    cutoff_certificate: SignedCutoffPublication,
    retained_settlement: CompetitionSettlement,
    submissions: Sequence[SignedSubmission],
    evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
    policy: CompetitionPolicy,
    limits: PublicationReplayLimits,
) -> SettlementPublication:
    cutoff = verify_cutoff_publication(
        cutoff_certificate,
        policy=policy,
        submissions=submissions,
        limits=limits,
    )
    settlement = _canonical(CompetitionSettlement, retained_settlement)
    normalized_roster, evidence_digest = _validate_settlement_material(
        round_=cutoff.round,
        settlement=settlement,
        cutoff=cutoff,
        submissions=submissions,
        evidence=evidence,
        policy=_canonical(CompetitionPolicy, policy),
        limits=limits,
    )
    return SettlementPublication(
        schema="umi-competition-settlement-publication/1",
        policy_sha256=cutoff.policy_sha256,
        round_sha256=cutoff.round_sha256,
        runtime_sha256=cutoff.runtime_sha256,
        round=cutoff.round,
        settlement_sha256=competition_settlement_digest(settlement),
        settlement=settlement,
        cutoff_publication_sha256=cutoff_publication_digest(cutoff),
        authenticated_roster_sha256=_roster_digest(normalized_roster),
        independent_evidence_set_sha256=evidence_digest,
        projection_sha256=digest(settlement.projection),
        promotion_head_sha256=digest(settlement.promotion_head),
    )


def verify_settlement_publication(
    certificate: SignedSettlementPublication,
    *,
    cutoff_certificate: SignedCutoffPublication,
    policy: CompetitionPolicy,
    submissions: Sequence[SignedSubmission],
    evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
    retained_settlement: CompetitionSettlement,
    limits: PublicationReplayLimits,
) -> SettlementPublication:
    policy = _canonical(CompetitionPolicy, policy)
    certificate = _bounded_certificate(
        SignedSettlementPublication,
        certificate,
        maximum_bytes=limits.maximum_certificate_bytes,
    )
    publication = certificate.publication
    cutoff = verify_cutoff_publication(
        cutoff_certificate,
        policy=policy,
        submissions=submissions,
        limits=limits,
    )
    if publication.cutoff_publication_sha256 != cutoff_publication_digest(cutoff):
        raise ValueError("settlement publication refers to another cutoff publication")
    if publication.round != cutoff.round or publication.policy_sha256 != cutoff.policy_sha256:
        raise ValueError("settlement and cutoff publications bind different rounds")
    retained = _canonical(CompetitionSettlement, retained_settlement)
    if publication.settlement != retained:
        raise ValueError("settlement publication differs from the retained settlement")
    normalized_roster, evidence_digest = _validate_settlement_material(
        round_=publication.round,
        settlement=publication.settlement,
        cutoff=cutoff,
        submissions=submissions,
        evidence=evidence,
        policy=policy,
        limits=limits,
    )
    if publication.authenticated_roster_sha256 != _roster_digest(normalized_roster):
        raise ValueError("settlement publication authenticated-roster digest mismatch")
    if publication.independent_evidence_set_sha256 != evidence_digest:
        raise ValueError("settlement publication independent-evidence digest mismatch")
    _verify_publication_quorum(
        settlement_publication_digest(publication),
        certificate.signatures,
        policy=policy,
        roster=normalized_roster,
        forbidden_hotkeys=_settlement_recipients(publication),
    )
    return publication


def _settlement_recipients(publication):
    contributor = publication.settlement.promotion_head.contributor_hotkey
    return tuple(
        a.hotkey for a in publication.settlement.projection.allocations if a.raw_weight > 0
    ) + (() if contributor is None else (contributor,))


def settlement_signer_eligible(hotkey, publication, policy, submissions):
    return identity(hotkey) in _publication_groups(
        policy, submissions, _settlement_recipients(publication)
    )


def verify_settlement_endorsement(signature, publication, policy, submissions):
    """Validate one eligible signature, without claiming publication quorum."""
    if not settlement_signer_eligible(signature.hotkey, publication, policy, submissions):
        raise ValueError("unauthorized or self-interested settlement signer")
    if not verify_response_signature(
        settlement_publication_digest(publication),
        hotkey_ss58=signature.hotkey,
        scheme=signature.scheme,
        signature=signature.signature,
    ):
        raise ValueError("invalid settlement endorsement")


def _validate_cutoff_material(
    *,
    round_: EvaluationRound,
    cutoff_schedule: EvidenceCutoffSchedule,
    registration_snapshot: RegistrationSnapshot,
    submissions: Sequence[SignedSubmission],
    policy: CompetitionPolicy,
    limits: PublicationReplayLimits,
) -> tuple[SignedSubmission, ...]:
    if (
        round_.policy_sha256 != digest(policy)
        or round_.runtime_sha256 != policy.evaluation_runtime_sha256
        or cutoff_schedule.policy_sha256 != digest(policy)
        or cutoff_schedule.round_sha256 != digest(round_)
    ):
        raise ValueError("cutoff publication policy, round or runtime mismatch")
    if not (
        policy.valid_from_block
        <= round_.submission_close_block
        < round_.evaluation_close_block
        < round_.reveal_block
        <= cutoff_schedule.evidence_cutoff_block
        <= round_.valid_through_block
        <= policy.valid_through_block
    ):
        raise ValueError("cutoff publication interval is outside policy")
    if not (
        policy.valid_from_block <= registration_snapshot.block <= round_.submission_close_block
    ):
        raise ValueError("cutoff registration snapshot interval is invalid")
    normalized, _ = _canonical_submissions(
        submissions,
        maximum_bytes=limits.maximum_roster_bytes,
    )
    submission_ids = tuple(digest(item.submission) for item in normalized)
    if submission_ids != round_.roster:
        raise ValueError("cutoff publication requires the exact complete round roster")
    slots: set[tuple[str, str]] = set()
    for signed in normalized:
        submission = signed.submission
        slot = (identity(submission.hotkey), submission.track)
        if slot in slots:
            raise ValueError("cutoff publication has duplicate hotkey and track")
        slots.add(slot)
        validate_admission(
            signed,
            policy,
            registration_snapshot,
            round_.submission_close_block,
        )
        if submission.valid_through_block < round_.evaluation_close_block:
            raise ValueError("roster submission expires before evaluation close")
    return normalized


def _validate_settlement_material(
    *,
    round_: EvaluationRound,
    settlement: CompetitionSettlement,
    cutoff: CutoffPublication,
    submissions: Sequence[SignedSubmission],
    evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
    policy: CompetitionPolicy,
    limits: PublicationReplayLimits,
) -> tuple[tuple[SignedSubmission, ...], str]:
    normalized_roster = _validate_cutoff_material(
        round_=round_,
        cutoff_schedule=cutoff.cutoff_schedule,
        registration_snapshot=cutoff.registration_snapshot,
        submissions=submissions,
        policy=policy,
        limits=limits,
    )
    if (
        settlement.policy_sha256 != digest(policy)
        or settlement.round_sha256 != digest(round_)
        or settlement.cutoff_schedule != cutoff.cutoff_schedule
        or settlement.roster != round_.roster
        or round_.suite_sha256 != digest(settlement.suite)
    ):
        raise ValueError("retained settlement policy, round, cutoff or suite mismatch")
    if not (
        settlement.cutoff_schedule.evidence_cutoff_block
        <= settlement.observed_block
        <= round_.valid_through_block
    ):
        raise ValueError("retained settlement observation is outside the round")

    normalized_evidence, _ = _canonical_evidence(
        evidence,
        maximum_bytes=limits.maximum_evidence_bytes,
    )
    if tuple(digest(item[0].submission) for item in normalized_evidence) != round_.roster:
        raise ValueError("settlement evidence must cover the complete roster in order")
    if tuple(item[0] for item in normalized_evidence) != normalized_roster:
        raise ValueError("settlement evidence uses a different signed roster")

    replayed = []
    for binding, (signed, independent) in zip(
        settlement.results,
        normalized_evidence,
        strict=True,
    ):
        evidence_id = independent_evidence_digest(independent)
        if (
            binding.submission_sha256 != digest(signed.submission)
            or binding.result_sha256 != digest(independent.attested_result.result)
            or binding.independent_evidence_sha256 != evidence_id
            or not round_.reveal_block
            <= binding.first_observed_block
            <= settlement.cutoff_schedule.evidence_cutoff_block
        ):
            raise ValueError("settlement result or retained-evidence binding mismatch")
        replay_independent_evaluation(
            independent,
            signed,
            round_,
            settlement.suite,
            policy,
            current_block=settlement.observed_block,
        )
        replayed.append((signed, independent.attested_result))

    expected_projection = project_weights(
        policy=policy,
        round_=round_,
        suite=settlement.suite,
        evaluations=tuple(replayed),
        snapshot=settlement.registration_snapshot,
        current_block=settlement.observed_block,
        promoted_model_sha256=settlement.promotion_head.model_sha256,
        promoted_hotkey=settlement.promotion_head.contributor_hotkey,
    )
    if settlement.projection != expected_projection:
        raise ValueError("settlement projection does not match deterministic replay")
    return normalized_roster, _evidence_digest(normalized_evidence)


def _publication_groups(policy, roster, forbidden_hotkeys):
    groups = {
        identity(evaluator.hotkey): evaluator.control_group for evaluator in policy.evaluators
    }
    forbidden_keys = {identity(item.submission.hotkey) for item in roster}
    forbidden_keys.update(identity(hotkey) for hotkey in forbidden_hotkeys)
    forbidden_groups = {groups[key] for key in forbidden_keys if key in groups}
    return {
        k: g for k, g in groups.items() if k not in forbidden_keys and g not in forbidden_groups
    }


def _verify_publication_quorum(
    statement_digest: str,
    signatures: Sequence[Signature],
    *,
    policy: CompetitionPolicy,
    roster: Sequence[SignedSubmission],
    forbidden_hotkeys: Sequence[str],
) -> None:
    groups = _publication_groups(policy, roster, forbidden_hotkeys)
    seen_keys: set[str] = set()
    seen_groups: set[str] = set()
    for signature in signatures:
        key = identity(signature.hotkey)
        group = groups.get(key)
        if group is None or key in seen_keys or group in seen_groups:
            raise ValueError("unauthorized, self-interested or duplicate publication signer")
        if not verify_response_signature(
            statement_digest,
            hotkey_ss58=signature.hotkey,
            scheme=signature.scheme,
            signature=signature.signature,
        ):
            raise ValueError("invalid publication signature")
        seen_keys.add(key)
        seen_groups.add(group)
    if len(seen_groups) < policy.required_evaluator_groups:
        raise ValueError("insufficient independent publication signatures")


def _canonical_submissions(
    submissions: Sequence[SignedSubmission],
    *,
    maximum_bytes: int,
) -> tuple[tuple[SignedSubmission, ...], int]:
    _positive_bound(maximum_bytes, "maximum roster bytes", maximum=_MAX_REPLAY_BYTES)
    if not 1 <= len(submissions) <= 512:
        raise ValueError("authenticated roster count is outside bounds")
    normalized: list[SignedSubmission] = []
    total = 0
    for item in submissions:
        body = canonical_json_bytes(item)
        total += len(body)
        if total > maximum_bytes:
            raise ValueError("authenticated roster exceeds its byte limit")
        normalized.append(SignedSubmission.model_validate_json(body, strict=True))
    normalized.sort(key=lambda item: digest(item.submission))
    return tuple(normalized), total


def _canonical_evidence(
    evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
    *,
    maximum_bytes: int,
) -> tuple[tuple[tuple[SignedSubmission, IndependentEvaluationEvidence], ...], int]:
    _positive_bound(maximum_bytes, "maximum evidence bytes", maximum=_MAX_REPLAY_BYTES)
    if not 1 <= len(evidence) <= 512:
        raise ValueError("independent evidence count is outside bounds")
    normalized: list[tuple[SignedSubmission, IndependentEvaluationEvidence]] = []
    total = 0
    for signed, independent in evidence:
        signed_body = canonical_json_bytes(signed)
        evidence_body = canonical_json_bytes(independent)
        total += len(signed_body) + len(evidence_body)
        if total > maximum_bytes:
            raise ValueError("independent evidence exceeds its byte limit")
        normalized.append(
            (
                SignedSubmission.model_validate_json(signed_body, strict=True),
                IndependentEvaluationEvidence.model_validate_json(evidence_body, strict=True),
            )
        )
    normalized.sort(key=lambda item: digest(item[0].submission))
    return tuple(normalized), total


def _roster_digest(submissions: Sequence[SignedSubmission]) -> str:
    hasher = hashlib.sha256(_ROSTER_DOMAIN)
    hasher.update(len(submissions).to_bytes(4, "big"))
    for signed in submissions:
        body = canonical_json_bytes(signed)
        hasher.update(len(body).to_bytes(8, "big"))
        hasher.update(body)
    return hasher.hexdigest()


def _evidence_digest(
    evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
) -> str:
    hasher = hashlib.sha256(_EVIDENCE_SET_DOMAIN)
    hasher.update(len(evidence).to_bytes(4, "big"))
    for signed, independent in evidence:
        for body in (canonical_json_bytes(signed), canonical_json_bytes(independent)):
            hasher.update(len(body).to_bytes(8, "big"))
            hasher.update(body)
    return hasher.hexdigest()


def _sign_digest(statement_digest: str, wallet: Any) -> Signature:
    import bittensor as bt

    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme, signature = sign_response_digest(wallet, statement_digest)
    return Signature(hotkey=signer.ss58_address, scheme=scheme, signature=signature)


def _bounded_certificate(
    model_type: type[_ModelT],
    value: _ModelT,
    *,
    maximum_bytes: int,
) -> _ModelT:
    _positive_bound(maximum_bytes, "maximum certificate bytes", maximum=_MAX_REPLAY_BYTES)
    body = canonical_json_bytes(value)
    if len(body) > maximum_bytes:
        raise ValueError("publication certificate exceeds its byte limit")
    return model_type.model_validate_json(body, strict=True)


def _canonical(model_type: type[_ModelT], value: _ModelT) -> _ModelT:
    return model_type.model_validate_json(canonical_json_bytes(value), strict=True)


def _positive_bound(value: int, label: str, *, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= maximum:
        raise ValueError(f"{label} must be an integer in [1, {maximum}]")


class PublicationJournal:
    """Private append-only certificate journal with persistent conflict holds."""

    def __init__(
        self,
        directory: Path,
        policy: CompetitionPolicy,
        *,
        capacity: PublicationJournalCapacity,
    ) -> None:
        if not directory.is_absolute() or directory.is_symlink():
            raise ValueError("publication state directory must be absolute and not a symlink")
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        if directory.stat().st_mode & 0o077:
            raise ValueError("publication state directory must be private")
        self.directory = directory
        self.path = directory / "competition-publication.sqlite3"
        if self.path.is_symlink():
            raise ValueError("publication database cannot be a symlink")
        self.policy = _canonical(CompetitionPolicy, policy)
        self.capacity = _canonical(PublicationJournalCapacity, capacity)
        with self._connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY, value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS certificates (
                    digest TEXT PRIMARY KEY,
                    kind TEXT NOT NULL CHECK(kind IN ('cutoff', 'settlement')),
                    round TEXT NOT NULL,
                    round_sequence INTEGER NOT NULL CHECK(round_sequence>=1),
                    publication TEXT NOT NULL,
                    body BLOB NOT NULL
                );
                CREATE INDEX IF NOT EXISTS certificate_round
                    ON certificates (round, kind, digest);
                CREATE INDEX IF NOT EXISTS certificate_round_sequence
                    ON certificates (round_sequence, round);
                CREATE TABLE IF NOT EXISTS round_bindings (
                    round_sequence INTEGER PRIMARY KEY CHECK(round_sequence>=1),
                    round TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS round_sequence_conflicts (
                    round_sequence INTEGER NOT NULL CHECK(round_sequence>=1),
                    first_round TEXT NOT NULL,
                    other_round TEXT NOT NULL,
                    PRIMARY KEY(round_sequence, other_round)
                );
                CREATE TABLE IF NOT EXISTS publication_heads (
                    kind TEXT NOT NULL,
                    round TEXT NOT NULL,
                    publication TEXT NOT NULL,
                    PRIMARY KEY(kind, round)
                );
                CREATE TABLE IF NOT EXISTS publication_conflicts (
                    kind TEXT NOT NULL,
                    round TEXT NOT NULL,
                    first_publication TEXT NOT NULL,
                    other_publication TEXT NOT NULL,
                    PRIMARY KEY(kind, round, other_publication)
                );
                CREATE TABLE IF NOT EXISTS publication_usage (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    records INTEGER NOT NULL CHECK(records>=0),
                    payload_bytes INTEGER NOT NULL CHECK(payload_bytes>=0)
                );
            """)
            connection.execute("BEGIN IMMEDIATE")
            try:
                bound = connection.execute(
                    "SELECT value FROM metadata WHERE key='policy'"
                ).fetchone()
                policy_id = digest(self.policy)
                if bound is None:
                    connection.execute("INSERT INTO metadata VALUES ('policy', ?)", (policy_id,))
                elif bound[0] != policy_id:
                    raise ValueError("publication journal belongs to another policy")
                usage = connection.execute(
                    "SELECT COUNT(*), COALESCE(SUM(length(CAST(body AS BLOB))), 0) "
                    "FROM certificates"
                ).fetchone()
                connection.execute(
                    "INSERT INTO publication_usage VALUES (1, ?, ?) "
                    "ON CONFLICT(singleton) DO UPDATE SET records=excluded.records, "
                    "payload_bytes=excluded.payload_bytes",
                    usage,
                )
                if (
                    usage[0] > self.capacity.maximum_certificates
                    or usage[1] > self.capacity.maximum_bytes
                ):
                    connection.execute(
                        "INSERT OR REPLACE INTO metadata VALUES "
                        "('publication_halted', 'capacity_exhausted')"
                    )
                self._hydrate_conflicts(connection)
                if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                    raise ValueError("publication journal integrity check failed")
                connection.commit()
            except BaseException:
                connection.rollback()
                raise
        os.chmod(self.path, 0o600)

    @contextmanager
    def _connection(self):
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    @staticmethod
    def _hydrate_conflicts(connection: sqlite3.Connection) -> None:
        # A valid journal can never retain more than the protocol-wide maximum.
        # Keep recovery bounded by that ceiling even if SQLite was modified
        # outside this class.  The configured capacity may legitimately be
        # lowered on restart, in which case initialization records a durable
        # capacity hold instead of making the old journal unreadable.
        measured = connection.execute(
            "SELECT COUNT(*), COALESCE(SUM(length(CAST(body AS BLOB))), 0) FROM certificates"
        ).fetchone()
        if measured[0] > _MAX_JOURNAL_RECORDS or measured[1] > _MAX_JOURNAL_BYTES:
            raise ValueError("publication journal recovery bound exceeded")
        usage = connection.execute(
            "SELECT records, payload_bytes FROM publication_usage WHERE singleton=1"
        ).fetchone()
        if usage != measured:
            raise ValueError("publication usage ledger is corrupt")

        for table in (
            "publication_heads",
            "publication_conflicts",
            "round_bindings",
            "round_sequence_conflicts",
        ):
            rows = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            if rows > _MAX_JOURNAL_RECORDS:
                raise ValueError("publication journal recovery bound exceeded")

        # Heads and bindings are derived indexes.  Preserve a retained choice
        # when it exists; if the index was deleted, recover its old choice from
        # a consistent conflict row or choose the canonical minimum.
        connection.execute(
            "INSERT OR IGNORE INTO publication_heads (kind, round, publication) "
            "SELECT c.kind, c.round, COALESCE(("
            "SELECT MIN(pc.first_publication) FROM publication_conflicts pc "
            "WHERE pc.kind=c.kind AND pc.round=c.round "
            "HAVING COUNT(DISTINCT pc.first_publication)=1"
            "), MIN(c.publication)) FROM certificates c GROUP BY c.kind, c.round"
        )
        connection.execute(
            "INSERT OR IGNORE INTO round_bindings (round_sequence, round) "
            "SELECT c.round_sequence, COALESCE(("
            "SELECT MIN(rc.first_round) FROM round_sequence_conflicts rc "
            "WHERE rc.round_sequence=c.round_sequence "
            "HAVING COUNT(DISTINCT rc.first_round)=1"
            "), MIN(c.round)) FROM certificates c GROUP BY c.round_sequence"
        )

        bad_head = connection.execute(
            "SELECT h.kind, h.round FROM publication_heads h "
            "LEFT JOIN certificates c ON c.kind=h.kind AND c.round=h.round "
            "AND c.publication=h.publication WHERE c.digest IS NULL LIMIT 1"
        ).fetchone()
        if bad_head is not None:
            raise ValueError("publication head lacks its certificate")
        bad_round_binding = connection.execute(
            "SELECT b.round_sequence, b.round FROM round_bindings b "
            "LEFT JOIN certificates c ON c.round_sequence=b.round_sequence "
            "AND c.round=b.round WHERE c.digest IS NULL LIMIT 1"
        ).fetchone()
        if bad_round_binding is not None:
            raise ValueError("round-sequence binding lacks its certificate")

        bad_conflict = connection.execute(
            "SELECT pc.kind, pc.round FROM publication_conflicts pc "
            "LEFT JOIN publication_heads h ON h.kind=pc.kind AND h.round=pc.round "
            "WHERE h.publication IS NULL OR pc.first_publication<>h.publication "
            "OR pc.other_publication=h.publication OR NOT EXISTS ("
            "SELECT 1 FROM certificates c WHERE c.kind=pc.kind AND c.round=pc.round "
            "AND c.publication=pc.other_publication) LIMIT 1"
        ).fetchone()
        if bad_conflict is not None:
            raise ValueError("publication conflict lacks its retained certificates")
        bad_round_conflict = connection.execute(
            "SELECT rc.round_sequence FROM round_sequence_conflicts rc "
            "LEFT JOIN round_bindings b ON b.round_sequence=rc.round_sequence "
            "WHERE b.round IS NULL OR rc.first_round<>b.round OR rc.other_round=b.round "
            "OR NOT EXISTS (SELECT 1 FROM certificates c "
            "WHERE c.round_sequence=rc.round_sequence AND c.round=rc.other_round) LIMIT 1"
        ).fetchone()
        if bad_round_conflict is not None:
            raise ValueError("round conflict lacks its retained certificates")

        # Recreate every missing edge, not just one MIN/MAX pair.  Therefore a
        # partially deleted summary cannot conceal a retained equivocation.
        connection.execute(
            "INSERT OR IGNORE INTO publication_conflicts "
            "(kind, round, first_publication, other_publication) "
            "SELECT h.kind, h.round, h.publication, c.publication "
            "FROM publication_heads h JOIN ("
            "SELECT DISTINCT kind, round, publication FROM certificates"
            ") c ON c.kind=h.kind AND c.round=h.round "
            "WHERE c.publication<>h.publication"
        )
        connection.execute(
            "INSERT OR IGNORE INTO round_sequence_conflicts "
            "(round_sequence, first_round, other_round) "
            "SELECT b.round_sequence, b.round, c.round FROM round_bindings b JOIN ("
            "SELECT DISTINCT round_sequence, round FROM certificates"
            ") c ON c.round_sequence=b.round_sequence WHERE c.round<>b.round"
        )

    def record_cutoff(
        self,
        certificate: SignedCutoffPublication,
        *,
        submissions: Sequence[SignedSubmission],
        limits: PublicationReplayLimits,
    ) -> dict:
        publication = verify_cutoff_publication(
            certificate,
            policy=self.policy,
            submissions=submissions,
            limits=limits,
        )
        return self._record(
            kind="cutoff",
            round_sha256=publication.round_sha256,
            round_sequence=publication.round.sequence,
            publication_sha256=cutoff_publication_digest(publication),
            certificate_sha256=signed_cutoff_publication_digest(certificate),
            body=canonical_json_bytes(_canonical(SignedCutoffPublication, certificate)),
            required_cutoff_publication_sha256=None,
        )

    def record_settlement(
        self,
        certificate: SignedSettlementPublication,
        *,
        cutoff_certificate: SignedCutoffPublication,
        submissions: Sequence[SignedSubmission],
        evidence: Sequence[tuple[SignedSubmission, IndependentEvaluationEvidence]],
        retained_settlement: CompetitionSettlement,
        limits: PublicationReplayLimits,
    ) -> dict:
        publication = verify_settlement_publication(
            certificate,
            cutoff_certificate=cutoff_certificate,
            policy=self.policy,
            submissions=submissions,
            evidence=evidence,
            retained_settlement=retained_settlement,
            limits=limits,
        )
        return self._record(
            kind="settlement",
            round_sha256=publication.round_sha256,
            round_sequence=publication.round.sequence,
            publication_sha256=settlement_publication_digest(publication),
            certificate_sha256=signed_settlement_publication_digest(certificate),
            body=canonical_json_bytes(_canonical(SignedSettlementPublication, certificate)),
            required_cutoff_publication_sha256=publication.cutoff_publication_sha256,
        )

    def _record(
        self,
        *,
        kind: Literal["cutoff", "settlement"],
        round_sha256: str,
        round_sequence: int,
        publication_sha256: str,
        certificate_sha256: str,
        body: bytes,
        required_cutoff_publication_sha256: str | None,
    ) -> dict:
        exhausted = False
        with self._transaction() as connection:
            self._hydrate_conflicts(connection)
            prior = connection.execute(
                "SELECT kind, round, round_sequence, publication, body "
                "FROM certificates WHERE digest=?",
                (certificate_sha256,),
            ).fetchone()
            if prior is not None:
                if prior != (
                    kind,
                    round_sha256,
                    round_sequence,
                    publication_sha256,
                    body,
                ):
                    raise ValueError("stored publication certificate is corrupt")
            else:
                if required_cutoff_publication_sha256 is not None:
                    cutoff = connection.execute(
                        "SELECT digest, body FROM certificates "
                        "WHERE kind='cutoff' AND round=? AND publication=? "
                        "ORDER BY digest LIMIT 1",
                        (round_sha256, required_cutoff_publication_sha256),
                    ).fetchone()
                    if cutoff is None:
                        raise ValueError("settlement cutoff publication is not retained")
                    parsed = SignedCutoffPublication.model_validate_json(cutoff[1], strict=True)
                    if (
                        signed_cutoff_publication_digest(parsed) != cutoff[0]
                        or cutoff_publication_digest(parsed.publication)
                        != required_cutoff_publication_sha256
                    ):
                        raise ValueError("retained cutoff certificate is corrupt")
                halted = connection.execute(
                    "SELECT value FROM metadata WHERE key='publication_halted'"
                ).fetchone()
                usage = connection.execute(
                    "SELECT records, payload_bytes FROM publication_usage WHERE singleton=1"
                ).fetchone()
                if usage is None:
                    raise ValueError("publication usage ledger is unavailable")
                next_records = usage[0] + 1
                next_bytes = usage[1] + len(body)
                if (
                    halted is not None
                    or next_records > self.capacity.maximum_certificates
                    or next_bytes > self.capacity.maximum_bytes
                ):
                    connection.execute(
                        "INSERT OR REPLACE INTO metadata VALUES "
                        "('publication_halted', 'capacity_exhausted')"
                    )
                    exhausted = True
                else:
                    connection.execute(
                        "INSERT INTO certificates VALUES (?, ?, ?, ?, ?, ?)",
                        (
                            certificate_sha256,
                            kind,
                            round_sha256,
                            round_sequence,
                            publication_sha256,
                            body,
                        ),
                    )
                    connection.execute(
                        "UPDATE publication_usage SET records=?, payload_bytes=? WHERE singleton=1",
                        (next_records, next_bytes),
                    )
                    head = connection.execute(
                        "SELECT publication FROM publication_heads WHERE kind=? AND round=?",
                        (kind, round_sha256),
                    ).fetchone()
                    if head is None:
                        connection.execute(
                            "INSERT INTO publication_heads VALUES (?, ?, ?)",
                            (kind, round_sha256, publication_sha256),
                        )
                    elif head[0] != publication_sha256:
                        connection.execute(
                            "INSERT OR IGNORE INTO publication_conflicts VALUES (?, ?, ?, ?)",
                            (kind, round_sha256, head[0], publication_sha256),
                        )
                    round_head = connection.execute(
                        "SELECT round FROM round_bindings WHERE round_sequence=?",
                        (round_sequence,),
                    ).fetchone()
                    if round_head is None:
                        connection.execute(
                            "INSERT INTO round_bindings VALUES (?, ?)",
                            (round_sequence, round_sha256),
                        )
                    elif round_head[0] != round_sha256:
                        connection.execute(
                            "INSERT OR IGNORE INTO round_sequence_conflicts VALUES (?, ?, ?)",
                            (round_sequence, round_head[0], round_sha256),
                        )
        if exhausted:
            raise PublicationCapacityError("publication journal capacity is exhausted")
        return self.round_status(round_sha256)

    def round_status(self, round_sha256: str, *, offset: int = 0, limit: int = 100) -> dict:
        _require_hex32(round_sha256, "round digest")
        if not 0 <= offset <= 10_000_000 or not 1 <= limit <= 100:
            raise ValueError("invalid publication page")
        with self._transaction() as connection:
            self._hydrate_conflicts(connection)
            rows = connection.execute(
                "SELECT digest, kind, round_sequence, publication, body FROM certificates "
                "WHERE round=? ORDER BY kind, digest LIMIT ? OFFSET ?",
                (round_sha256, limit, offset),
            ).fetchall()
            conflicts = connection.execute(
                "SELECT kind, first_publication, other_publication "
                "FROM publication_conflicts WHERE round=? ORDER BY kind, other_publication",
                (round_sha256,),
            ).fetchall()
            round_conflicts = connection.execute(
                "SELECT round_sequence, first_round, other_round "
                "FROM round_sequence_conflicts WHERE first_round=? OR other_round=? "
                "ORDER BY round_sequence, first_round, other_round",
                (round_sha256, round_sha256),
            ).fetchall()
            halted = connection.execute(
                "SELECT value FROM metadata WHERE key='publication_halted'"
            ).fetchone()
            usage = connection.execute(
                "SELECT records, payload_bytes FROM publication_usage WHERE singleton=1"
            ).fetchone()
        certificates = []
        for certificate_id, kind, round_sequence, publication_id, body in rows:
            if kind == "cutoff":
                parsed = SignedCutoffPublication.model_validate_json(body, strict=True)
                actual_certificate = signed_cutoff_publication_digest(parsed)
                actual_publication = cutoff_publication_digest(parsed.publication)
            else:
                parsed = SignedSettlementPublication.model_validate_json(body, strict=True)
                actual_certificate = signed_settlement_publication_digest(parsed)
                actual_publication = settlement_publication_digest(parsed.publication)
            if certificate_id != actual_certificate or publication_id != actual_publication:
                raise ValueError("stored publication certificate is corrupt")
            if parsed.publication.round.sequence != round_sequence:
                raise ValueError("stored publication round sequence is corrupt")
            certificates.append(
                {
                    "kind": kind,
                    "certificate_sha256": certificate_id,
                    "publication_sha256": publication_id,
                }
            )
        return {
            "schema": "umi-competition-publication-journal-status/1",
            "policy_sha256": digest(self.policy),
            "round_sha256": round_sha256,
            "certificates": certificates,
            "conflicts": [
                {
                    "kind": kind,
                    "first_publication_sha256": first,
                    "other_publication_sha256": other,
                }
                for kind, first, other in conflicts
            ],
            "round_sequence_conflicts": [
                {
                    "round_sequence": sequence,
                    "first_round_sha256": first,
                    "other_round_sha256": other,
                }
                for sequence, first, other in round_conflicts
            ],
            "held": halted is not None or bool(conflicts) or bool(round_conflicts),
            "halt_reason": None if halted is None else halted[0],
            "usage": {
                "certificates": usage[0],
                "maximum_certificates": self.capacity.maximum_certificates,
                "payload_bytes": usage[1],
                "maximum_payload_bytes": self.capacity.maximum_bytes,
            },
            "offset": offset,
            "limit": limit,
            "finalized_receipt_timing_proven": False,
            "global_conflict_absence_proven": False,
            "chain_submission_authorized": False,
        }


def _require_hex32(value: str, label: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"invalid {label}")


__all__ = [
    "CutoffPublication",
    "PublicationCapacityError",
    "PublicationJournal",
    "PublicationJournalCapacity",
    "PublicationReplayLimits",
    "SettlementPublication",
    "SignedCutoffPublication",
    "SignedSettlementPublication",
    "authenticated_roster_digest",
    "build_cutoff_publication",
    "build_settlement_publication",
    "cutoff_publication_digest",
    "independent_evidence_set_digest",
    "settlement_publication_digest",
    "settlement_signer_eligible",
    "sign_cutoff_publication",
    "sign_settlement_publication",
    "signed_cutoff_publication_digest",
    "signed_settlement_publication_digest",
    "verify_cutoff_publication",
    "verify_settlement_endorsement",
    "verify_settlement_publication",
]
