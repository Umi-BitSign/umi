"""Retained independent service-allocation votes using the round journal."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Iterable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_service_allocation import ServiceAllocation, allocate_service_quality
from .competition_cohort_service_quality import replay_closed_service_quality
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex


class ServiceAllocationStatement(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-allocation-statement/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    allocation: ServiceAllocation


class ServiceAllocationVote(StrictProtocolModel):
    statement: ServiceAllocationStatement
    signature: Signature


class CertifiedServiceAllocation(StrictProtocolModel):
    schema_: Literal["umi-cohort-certified-service-allocation/1"] = Field(alias="schema")
    statement: ServiceAllocationStatement
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ServiceAllocationReview:
    """Replay one complete allocation from independently selected sources.

    The host owns source authentication and supplies current authority on each
    signing/replay attempt. This object contains a reviewed value, not a proof
    capability; portable certificates must be replayed by their consumers.
    """

    def __init__(
        self,
        closure,
        roster,
        objects,
        policy,
        history,
        transport,
        terms,
        reveal,
        *,
        expected_catalogs,
        expected_seals,
        expected_terms_sha256,
        decision_source,
        intake_records,
        pulses,
        expected_tip_sha256,
        current_block,
    ):
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        quality = replay_closed_service_quality(
            closure,
            roster,
            objects,
            self.policy,
            history,
            transport,
            terms,
            reveal,
            expected_catalogs=expected_catalogs,
            expected_seals=expected_seals,
            expected_terms_sha256=expected_terms_sha256,
            decision_source=decision_source,
            intake_records=intake_records,
            pulses=pulses,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        allocation = allocate_service_quality(quality, terms)
        self.statement = ServiceAllocationStatement(
            schema="umi-cohort-service-allocation-statement/1",
            policy_sha256=digest(self.policy),
            round_sha256=digest(roster.round),
            allocation=allocation,
        )
        self.slot = digest(
            ["umi-service-allocation-slot/1", digest(self.policy), digest(roster.round)]
        )
        self.groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        self.recipients = {identity(w.recipient_hotkey) for w in quality.work}

    def check_vote(self, vote: ServiceAllocationVote) -> None:
        key = identity(vote.signature.hotkey)
        if vote.statement != self.statement or key not in self.groups or key in self.recipients:
            raise ValueError(
                "allocation vote differs from independent review or signer eligibility"
            )
        verify_signature(vote.statement, vote.signature)


def _vote_key(slot: str, hotkey: str) -> str:
    return digest([slot, identity(hotkey)])


def retained_service_allocation_vote(
    journal: RoundJournal, slot: str, hotkey: str
) -> ServiceAllocationVote | None:
    """Recover historical evidence without requiring another key operation."""
    key = _vote_key(slot, hotkey)
    value = journal.get("service_allocation_vote", key)
    if value is None:
        return None
    vote = ServiceAllocationVote.model_validate_json(canonical_json_bytes(value))
    intent = journal.get("service_allocation_intent", slot)
    if intent is None or canonical_json_bytes(intent) != canonical_json_bytes(vote.statement):
        raise ValueError("allocation vote differs from its retained intent")
    if identity(vote.signature.hotkey) != identity(hotkey):
        raise ValueError("retained allocation vote belongs to another signer")
    verify_signature(vote.statement, vote.signature)
    return vote


async def sign_service_allocation(
    journal: RoundJournal,
    review: ServiceAllocationReview,
    hotkey: str,
    sign: Callable[[ServiceAllocationStatement], Awaitable[Signature]],
    *,
    signing_timeout_seconds: float = 30,
) -> ServiceAllocationVote:
    """Serialize intent, signature and retention; retries never change allocation."""
    if identity(hotkey) not in review.groups or identity(hotkey) in review.recipients:
        raise ValueError("ineligible service allocation signer")
    raw = canonical_json_bytes(review.statement)
    key, slot = _vote_key(review.slot, hotkey), review.slot
    with journal.locked():
        journal.reserve_records(
            "service-allocation-sign:" + key,
            (
                RecordReservation("service_allocation_intent", slot, len(raw), sha256_hex(raw)),
                RecordReservation("service_allocation_vote", key, len(raw) + 4096),
            ),
        )
        journal.put("service_allocation_intent", slot, review.statement)
        prior = retained_service_allocation_vote(journal, slot, hotkey)
        if prior is not None:
            review.check_vote(prior)
            return prior

        async def sign_and_retain():
            signature = await sign(review.statement)
            vote = ServiceAllocationVote(statement=review.statement, signature=signature)
            if identity(signature.hotkey) != identity(hotkey):
                raise ValueError("allocation signature differs from selected signer")
            review.check_vote(vote)
            journal.put("service_allocation_vote", key, vote)
            return vote

        return await wait_for_owned(sign_and_retain(), timeout=signing_timeout_seconds)


def verify_service_allocation_certificate(
    certificate: CertifiedServiceAllocation, review: ServiceAllocationReview
) -> ServiceAllocation:
    certificate = CertifiedServiceAllocation.model_validate_json(canonical_json_bytes(certificate))
    if certificate.statement != review.statement:
        raise ValueError("service certificate differs from replayed allocation")
    for signature in certificate.signatures:
        review.check_vote(
            ServiceAllocationVote(statement=certificate.statement, signature=signature)
        )
    verify_recovery_quorum(certificate.statement, certificate.signatures, review.policy)
    return certificate.statement.allocation


def collect_service_allocation(
    journal: RoundJournal, review: ServiceAllocationReview, votes: Iterable[ServiceAllocationVote]
) -> CertifiedServiceAllocation | None:
    """Persist partial votes; recover the first complete certificate unchanged."""
    slot, body = review.slot, review.statement
    raw = canonical_json_bytes(body)
    wanted = sorted(review.groups)
    with journal.locked():
        journal.reserve_records(
            "service-allocation-collect:" + slot,
            (
                RecordReservation("service_allocation_intent", slot, len(raw), sha256_hex(raw)),
                RecordReservation("service_allocation_certificate", slot, len(raw) + 32768),
                *(
                    RecordReservation(
                        "service_allocation_peer", digest([slot, key]), len(raw) + 4096
                    )
                    for key in wanted
                ),
            ),
        )
        journal.put("service_allocation_intent", slot, body)
        for supplied in votes:
            vote = ServiceAllocationVote.model_validate_json(canonical_json_bytes(supplied))
            review.check_vote(vote)
            key = _vote_key(slot, vote.signature.hotkey)
            prior = journal.get("service_allocation_peer", key)
            if prior is None:
                journal.put("service_allocation_peer", key, vote)
            else:
                review.check_vote(
                    ServiceAllocationVote.model_validate_json(canonical_json_bytes(prior))
                )
        old = journal.get("service_allocation_certificate", slot)
        if old is not None:
            certificate = CertifiedServiceAllocation.model_validate_json(canonical_json_bytes(old))
            verify_service_allocation_certificate(certificate, review)
            return certificate
        signatures, groups = [], set()
        for key in wanted:
            value = journal.get("service_allocation_peer", digest([slot, key]))
            if value is None:
                continue
            vote = ServiceAllocationVote.model_validate_json(canonical_json_bytes(value))
            review.check_vote(vote)
            if review.groups[key] not in groups:
                signatures.append(vote.signature)
                groups.add(review.groups[key])
        if len(groups) < review.policy.required_evaluator_groups:
            return None
        certificate = CertifiedServiceAllocation(
            schema="umi-cohort-certified-service-allocation/1",
            statement=body,
            signatures=tuple(signatures),
        )
        verify_service_allocation_certificate(certificate, review)
        journal.put("service_allocation_certificate", slot, certificate)
        return certificate
