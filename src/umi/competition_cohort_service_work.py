"""Opt-in paid-work inventory and miner claims, separate from benchmark quotas.

Admission binds an obligation; it does not establish execution, earned credit,
publication time or reward authority. Hosts authenticate current history and
registration proof sources before invoking these reviewers.
"""

from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_evaluation import (
    RecoverableEvaluationRound,
    verify_recoverable_round_participant,
)
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_order_signer import CohortOrderHistory, CohortOrderParticipant
from .competition_cohort_recovery import Block, verify_recovery_quorum
from .competition_execution import ExecutionBoundary
from .open_competition import (
    CompetitionPolicy,
    Hotkey,
    RegistrationSnapshot,
    Signature,
    SignedSubmission,
    Stratum,
    digest,
    identity,
    verify_signature,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_CATALOG_BYTES = 8 * 1024**2
MAX_CLAIM_BYTES = 4096


class ServiceWorkItem(StrictProtocolModel):
    case_id: Hex32
    video_sha256: Hex32
    reference_sha256: Hex32
    stratum: Stratum
    units: Literal[1] = 1


class ServiceWorkCatalog(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-work-catalog/1"] = Field(alias="schema")
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    round_sha256: Hex32
    service_terms_sha256: Hex32
    issued_at_block: Block
    work: Annotated[tuple[ServiceWorkItem, ...], Field(min_length=1, max_length=8192)]
    selection_rule: Literal["global_fifo_no_identity_quota"]
    credit_rule: Literal["verified_terminal_work_only"]
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def ordered(self):
        keys = tuple(w.case_id for w in self.work)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("service work cases must be unique and ordered")
        if len({w.video_sha256 for w in self.work}) != len(self.work):
            raise ValueError("repeating an input does not create another paid work item")
        return self


class SignedServiceWorkCatalog(StrictProtocolModel):
    catalog: ServiceWorkCatalog
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ServiceWorkClaim(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-work-claim/1"] = Field(alias="schema")
    catalog_sha256: Hex32
    hotkey: Hotkey
    submission_sha256: Hex32
    nonce: Hex32


class SignedServiceWorkClaim(StrictProtocolModel):
    claim: ServiceWorkClaim
    signature: Signature


class ServiceWorkAdmission(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-work-admission/1"] = Field(alias="schema")
    catalog_sha256: Hex32
    claim: SignedServiceWorkClaim
    ordinal: Annotated[int, Field(ge=1, le=8192)]
    predecessor_sha256: Hex32 | None
    work_sha256: Hex32
    submission: SignedSubmission
    participant: CohortOrderParticipant
    history_sha256: Hex32
    registration: RegistrationSnapshot
    observation: ExecutionBoundary
    service_credit_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


def service_work_key(catalog: ServiceWorkCatalog, ordinal: int) -> str:
    if type(ordinal) is not int or not 1 <= ordinal <= len(catalog.work):
        raise ValueError("service work ordinal is outside the committed catalog")
    return digest(
        {
            "schema": "umi-cohort-service-work-key/1",
            "catalog": digest(catalog),
            "ordinal": ordinal,
            "work": digest(catalog.work[ordinal - 1]),
        }
    )


def service_claim_key(claim: ServiceWorkClaim) -> str:
    return digest(
        {
            "schema": "umi-cohort-service-claim-key/1",
            "catalog": claim.catalog_sha256,
            "recipient": identity(claim.hotkey),
            "nonce": claim.nonce,
        }
    )


def verify_service_claim(value: SignedServiceWorkClaim) -> SignedServiceWorkClaim:
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_CLAIM_BYTES:
        raise ValueError("service claim exceeds its ingress bound")
    value = SignedServiceWorkClaim.model_validate_json(raw)
    if identity(value.signature.hotkey) != identity(value.claim.hotkey):
        raise ValueError("service claim signature belongs to another recipient")
    verify_signature(value.claim, value.signature)
    return value


def review_service_catalog(
    signed: SignedServiceWorkCatalog,
    round_: RecoverableEvaluationRound,
    policy: CompetitionPolicy,
    source: CohortOrderHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> ServiceWorkCatalog:
    raw = canonical_json_bytes(signed)
    if len(raw) > MAX_CATALOG_BYTES:
        raise ValueError("service catalog exceeds its byte bound")
    signed = SignedServiceWorkCatalog.model_validate_json(raw)
    round_ = RecoverableEvaluationRound.model_validate_json(canonical_json_bytes(round_))
    source = CohortOrderHistory.model_validate_json(canonical_json_bytes(source))
    view = verify_cohort_history(
        source.history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    inputs = source.inputs()
    state, _, _ = replay_cohort_decisions(source.history, policy, inputs.__getitem__)
    preparation = view.closure("preparation")
    body = signed.catalog
    if (
        state != view.state
        or state.phase != "requests"
        or body.policy_sha256 != digest(policy)
        or body.cohort_sha256 != state.cohort_sha256
        or body.authority_sha256 != state.authority_sha256
        or body.round_sha256 != digest(round_)
        or round_.cohort_sha256 != state.cohort_sha256
        or round_.policy_sha256 != digest(policy)
        or inputs[preparation.evidence_sha256].progress.progress.phase_result_sha256
        != digest(round_)
        or not preparation.observed_at_block <= body.issued_at_block <= current_block
        or any(w.stratum not in policy.stratum_weights for w in body.work)
    ):
        raise ValueError("service catalog requires exact preparation and an open request phase")
    verify_recovery_quorum(body, signed.signatures, policy)
    return body


def review_service_admission(
    value: ServiceWorkAdmission,
    signed: SignedServiceWorkCatalog,
    round_: RecoverableEvaluationRound,
    source: CohortOrderHistory,
    policy: CompetitionPolicy,
    *,
    previous: ServiceWorkAdmission | None,
) -> ServiceWorkAdmission:
    """Replay original admission evidence; no current execution authority is returned.

    Original registration captures and the owner journal must be independently
    authenticated. An unsigned admission's ordinal is not a publication proof.
    """
    value = ServiceWorkAdmission.model_validate_json(canonical_json_bytes(value))
    catalog = review_service_catalog(
        signed,
        round_,
        policy,
        source,
        expected_tip_sha256=history_tip(source.history),
        current_block=value.observation.block,
    )
    claim = verify_service_claim(value.claim).claim
    verify_recoverable_round_participant(
        value.submission,
        round_,
        policy,
        value.participant.consent,
        value.participant.admission,
        value.participant.admission_snapshot,
        source.history,
        expected_tip_sha256=history_tip(source.history),
        current_block=value.observation.block,
    )
    ordinal = 1 if previous is None else previous.ordinal + 1
    predecessor = None if previous is None else digest(previous)
    who = identity(claim.hotkey)
    if (
        value.catalog_sha256 != digest(catalog)
        or claim.catalog_sha256 != digest(catalog)
        or value.history_sha256 != digest(source)
        or value.ordinal != ordinal
        or value.predecessor_sha256 != predecessor
        or (previous is not None and previous.catalog_sha256 != value.catalog_sha256)
        or value.work_sha256 != service_work_key(catalog, ordinal)
        or claim.submission_sha256 != digest(value.submission.submission)
        or who != identity(value.submission.submission.hotkey)
        or value.submission.submission.track != "endpoint"
        or value.observation.snapshot_sha256 != digest(value.registration)
        or value.observation.block != value.registration.block
        or value.observation.block_hash != value.registration.block_hash
        or value.registration.network != policy.network
        or value.registration.netuid != policy.netuid
        or who not in {identity(r.hotkey) for r in value.registration.registrations}
        or (previous is not None and value.observation.block < previous.observation.block)
    ):
        raise ValueError("service admission changed its claim, work, order or registration binding")
    if who in {identity(s.hotkey) for s in signed.signatures}:
        raise ValueError("service recipient cannot authorize its own work catalog")
    return value
