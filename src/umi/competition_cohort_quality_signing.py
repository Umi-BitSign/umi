"""Retained quality votes, independent certificates and complete cohort manifests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_endpoint_archive import JournalEndpointObjects, read_endpoint_object
from .competition_cohort_execution_journal import CohortExecutionJournal
from .competition_cohort_quality import ClosedParticipantQuality, ClosedQualityReview
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_request_terminal import SignedRequestTerminal
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class SignedClosedQualityVote(StrictProtocolModel):
    result: ClosedParticipantQuality
    signature: Signature


class CertifiedClosedQuality(StrictProtocolModel):
    result: ClosedParticipantQuality
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class QualityCertificateRef(StrictProtocolModel):
    submission_sha256: Hex32
    certificate_sha256: Hex32


class CohortQualityManifest(StrictProtocolModel):
    schema_: Literal["umi-cohort-quality-manifest/1", "umi-cohort-quality-manifest/2"] = Field(
        alias="schema"
    )
    request_closure_sha256: Hex32
    participants: Annotated[tuple[QualityCertificateRef, ...], Field(min_length=1, max_length=512)]
    skipped_participants: Annotated[tuple[Hex32, ...], Field(max_length=512)] = ()
    service_credit_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.schema_ == "umi-cohort-quality-manifest/1" and not self.skipped_participants:
            value.pop("skipped_participants", None)
        return value

    @model_validator(mode="after")
    def selected_version(self):
        if self.schema_ == "umi-cohort-quality-manifest/1" and self.skipped_participants:
            raise ValueError("legacy quality manifest cannot skip a participant")
        if len(set(self.skipped_participants)) != len(self.skipped_participants):
            raise ValueError("quality manifest repeats a skipped disposition")
        return self


class PendingQualityCertificates(ValueError):
    def __init__(self, submissions: tuple[str, ...]):
        self.submissions = submissions
        super().__init__(f"quality certification has {len(submissions)} pending participants")


def _own_terminal(
    owner: CohortExecutionJournal, slot: str, result: ClosedParticipantQuality
) -> None:
    assignment = owner.assignment(slot)
    raw = owner.journal.get("request_terminal", slot)
    if raw is None:
        raise FileNotFoundError("quality signer has no retained execution terminal")
    signed = SignedRequestTerminal.model_validate_json(canonical_json_bytes(raw))
    verify_signature(signed.terminal, signed.signature)
    who = identity(owner.config.signer)
    own = next((r for r in result.runs if identity(r.evaluator_hotkey) == who), None)
    if (
        own is None
        or own.terminal_sha256 != digest(signed)
        or identity(signed.signature.hotkey) != who
        or signed.terminal.assignment_sha256 != digest(assignment)
        or result.policy_sha256 != digest(owner.policy)
        or result.submission_sha256 != digest(assignment.certificate.order.submission.submission)
        or result.order_sha256 != digest(assignment.certificate)
        or result.round_sha256 != digest(assignment.certificate.order.round)
    ):
        raise ValueError("quality vote does not retain the signer's exact owned terminal")


def retained_quality_vote(
    owner: CohortExecutionJournal, slot: str
) -> SignedClosedQualityVote | None:
    """Recover an archived signature without peers or a new authority decision.

    This returns evidence only. A current consumer still replays the certificate
    against its owned history and original sources before using it.
    """
    raw = owner.journal.get("closed_quality_vote", slot)
    if raw is None:
        return None
    vote = SignedClosedQualityVote.model_validate_json(canonical_json_bytes(raw))
    intent = owner.journal.get("closed_quality_intent", slot)
    if intent is None or canonical_json_bytes(intent) != canonical_json_bytes(vote.result):
        raise ValueError("quality vote differs from its retained signing intent")
    _own_terminal(owner, slot, vote.result)
    if identity(vote.signature.hotkey) != identity(owner.config.signer):
        raise ValueError("quality vote signer differs from its owner")
    verify_signature(vote.result, vote.signature)
    return vote


async def sign_closed_quality(
    owner: CohortExecutionJournal,
    slot: str,
    review: ClosedQualityReview,
    sign: Callable[[ClosedParticipantQuality], Awaitable[Signature]],
) -> SignedClosedQualityVote:
    """Owner-serialized port: replay, commit intent, sign, commit before reply."""
    assignment = await run_owned_thread(owner.assignment, slot)
    result = await run_owned_thread(
        review.outcome, digest(assignment.certificate.order.submission.submission)
    )
    await run_owned_thread(_own_terminal, owner, slot, result)
    await run_owned_thread(owner.journal.put, "closed_quality_intent", slot, result)
    vote = await run_owned_thread(retained_quality_vote, owner, slot)
    if vote is None:
        signature = await wait_for_owned(sign(result), timeout=owner.config.signing_timeout_seconds)
        if identity(signature.hotkey) != identity(owner.config.signer):
            raise ValueError("quality vote signer differs from its owner")
        verify_signature(result, signature)
        vote = SignedClosedQualityVote(result=result, signature=signature)
        await run_owned_thread(owner.journal.put, "closed_quality_vote", slot, vote)
    await run_owned_thread(JournalEndpointObjects(owner.journal).put, vote)
    return vote


def verify_quality_certificate(
    certificate: CertifiedClosedQuality, review: ClosedQualityReview
) -> ClosedParticipantQuality:
    certificate = CertifiedClosedQuality.model_validate_json(canonical_json_bytes(certificate))
    expected = review.outcome(certificate.result.submission_sha256)
    if certificate.result != expected:
        raise ValueError("quality certificate differs from complete retained observations")
    if tuple(identity(s.hotkey) for s in certificate.signatures) != tuple(
        identity(r.evaluator_hotkey) for r in expected.runs
    ):
        raise ValueError("quality certificate requires exactly all assigned evaluators")
    verify_recovery_quorum(expected, certificate.signatures, review.policy)
    if identity(expected.hotkey) in {identity(s.hotkey) for s in certificate.signatures}:
        raise ValueError("a submitting hotkey cannot certify its own quality")
    return expected


def collect_quality_certificate(
    journal: RoundJournal,
    review: ClosedQualityReview,
    submission_sha256: str,
    votes: Iterable[SignedClosedQualityVote],
) -> CertifiedClosedQuality | None:
    """Persist partial independent votes; retry with no new votes after restart."""
    result = review.outcome(submission_sha256)
    slot = digest(result)
    wanted = tuple(identity(r.evaluator_hotkey) for r in result.runs)
    journal.put("closed_quality_collect_intent", slot, result)
    for supplied in votes:
        vote = SignedClosedQualityVote.model_validate_json(canonical_json_bytes(supplied))
        key = identity(vote.signature.hotkey)
        if vote.result != result or key not in wanted:
            raise ValueError("quality collection received another result or evaluator")
        verify_signature(result, vote.signature)
        vote_key = digest({"slot": slot, "evaluator": key})
        prior = journal.get("closed_quality_peer", vote_key)
        if prior is None:
            journal.put("closed_quality_peer", vote_key, vote)
        else:
            old = SignedClosedQualityVote.model_validate_json(canonical_json_bytes(prior))
            if old.result != result or identity(old.signature.hotkey) != key:
                raise ValueError("retained quality peer vote changed its binding")
            verify_signature(result, old.signature)
    signatures = []
    for key in wanted:
        raw = journal.get("closed_quality_peer", digest({"slot": slot, "evaluator": key}))
        if raw is None:
            return None
        vote = SignedClosedQualityVote.model_validate_json(canonical_json_bytes(raw))
        if vote.result != result or identity(vote.signature.hotkey) != key:
            raise ValueError("retained quality peer vote changed its binding")
        signatures.append(vote.signature)
    certificate = CertifiedClosedQuality(result=result, signatures=tuple(signatures))
    verify_quality_certificate(certificate, review)
    journal.put("closed_quality_certificate", slot, certificate)
    JournalEndpointObjects(journal).put(certificate)
    return certificate


def review_quality_manifest(
    manifest: CohortQualityManifest, review: ClosedQualityReview
) -> tuple[ClosedParticipantQuality, ...]:
    manifest = CohortQualityManifest.model_validate_json(canonical_json_bytes(manifest))
    tail = review.closure.schema_ == "umi-cohort-request-closure/3"
    if tail != (
        manifest.schema_ == "umi-cohort-quality-manifest/2"
    ) or manifest.skipped_participants != tuple(digest(p) for p in review.closure.skipped):
        raise ValueError("quality manifest differs from certified unperformed dispositions")
    if manifest.request_closure_sha256 != review.request_closure_sha256 or tuple(
        p.submission_sha256 for p in manifest.participants
    ) != tuple(p.submission_sha256 for p in review.closure.participants):
        raise ValueError("quality manifest must cover the exact certified roster")
    results = []
    for member in manifest.participants:
        certificate = CertifiedClosedQuality.model_validate_json(
            read_endpoint_object(review.objects, member.certificate_sha256)
        )
        if certificate.result.submission_sha256 != member.submission_sha256:
            raise ValueError("quality certificate belongs to another participant")
        results.append(verify_quality_certificate(certificate, review))
    return tuple(results)


def build_quality_manifest(
    review: ClosedQualityReview,
    certificates: Callable[[str], CertifiedClosedQuality | None],
) -> CohortQualityManifest:
    """Certificates must already be independently retrievable by content digest."""
    pending, refs = [], []
    for member in review.closure.participants:
        key = member.submission_sha256
        certificate = certificates(key)
        if certificate is None:
            pending.append(key)
        else:
            refs.append(
                QualityCertificateRef(submission_sha256=key, certificate_sha256=digest(certificate))
            )
    if pending:
        raise PendingQualityCertificates(tuple(pending))
    manifest = CohortQualityManifest(
        schema="umi-cohort-quality-manifest/2"
        if review.closure.schema_ == "umi-cohort-request-closure/3"
        else "umi-cohort-quality-manifest/1",
        request_closure_sha256=review.request_closure_sha256,
        participants=tuple(refs),
        skipped_participants=tuple(digest(p) for p in review.closure.skipped),
    )
    review_quality_manifest(manifest, review)
    return manifest
