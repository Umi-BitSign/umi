"""Explicit evaluator-authorized neutral disposition for lost coordinator outcomes.

The signatures attest local unavailability, not miner behavior or proof of a
negative. This contract requires a successor verifier and cannot create a score,
complete a transport claim, change a deadline, or authorize a chain submission.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_authorization import SignedEndpointAuthorization, validate_publication_suite
from .competition_dispatch_replay import _replay_validated_dispatch_bytes
from .competition_endpoint_execution import (
    MAX_PAIRED_BYTES,
    EndpointDispatchEvidence,
    _assignments,
)
from .competition_execution import EndpointIncumbentEvidence, ExecutionBoundary
from .competition_scheduling import assignment_key
from .open_competition import Hotkey, Signature, digest, identity, verify_signature
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes, request_digest


class UnavailableDispatchClaim(StrictProtocolModel):
    assignment_key: Hex32
    evaluator_hotkey: Hotkey
    claim_sha256: Hex32
    claim_block: Annotated[int, Field(ge=0, le=2**53 - 1)]
    claim_unix_ms: Annotated[int, Field(ge=0, le=2**53 - 1)]
    request_sha256: Hex32
    deadline_block: Annotated[int, Field(ge=0, le=2**53 - 1)]


class DispatchRepairAmendment(StrictProtocolModel):
    schema_: Literal["umi-coordinator-outcome-repair/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    order_sha256: Hex32
    publication_sha256: Hex32
    submission_sha256: Hex32
    predecessor_release_identity_sha256: Hex32
    successor_release_identity_sha256: Hex32
    audit_sha256: Hex32
    observed: ExecutionBoundary
    unavailable: Annotated[
        tuple[UnavailableDispatchClaim, ...], Field(min_length=1, max_length=2048)
    ]
    reason: Literal["coordinator_outcome_unavailable"]
    miner_fault: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def exact_scope(self):
        keys = tuple(c.assignment_key for c in self.unavailable)
        if keys != tuple(sorted(set(keys))):
            raise ValueError("repair claims must be sorted and unique")
        if self.predecessor_release_identity_sha256 == self.successor_release_identity_sha256:
            raise ValueError("repair requires an explicit successor verifier release")
        return self


class SignedDispatchRepair(StrictProtocolModel):
    amendment: DispatchRepairAmendment
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class EndpointUnavailableEvidence(StrictProtocolModel):
    schema_: Literal["umi-endpoint-unavailable-evidence/1"] = Field(alias="schema")
    incumbent: EndpointIncumbentEvidence
    publication: SignedEndpointAuthorization
    legacy_policy: ScoringPolicy
    dispatches: Annotated[tuple[EndpointDispatchEvidence, ...], Field(max_length=2048)]
    repair: SignedDispatchRepair
    chain_submission_authorized: Literal[False] = False


def verify_dispatch_repair(signed, *, signed_order, policy, legacy, current_block):
    from .competition_evaluator import validate_order

    signed = SignedDispatchRepair.model_validate_json(canonical_json_bytes(signed))
    order = validate_order(signed_order, policy, legacy).order
    body = signed.amendment
    _verify_amendment_body(body, order, policy, current_block)
    keys = []
    for signature in signed.signatures:
        verify_signature(body, signature)
        keys.append(identity(signature.hotkey))
    if sorted(keys) != sorted(identity(k) for k in order.evaluators):
        raise ValueError("repair requires exactly all assigned evaluator signatures")
    return signed


def _verify_amendment_body(body, order, policy, current_block):
    body = DispatchRepairAmendment.model_validate_json(canonical_json_bytes(body))
    if order.publication is None or (
        body.policy_sha256 != digest(policy)
        or body.round_sha256 != digest(order.round)
        or body.order_sha256 != digest(order)
        or body.publication_sha256 != digest(order.publication.publication)
        or body.submission_sha256 != digest(order.submission.submission)
    ):
        raise ValueError("repair changes the original order, publication, policy or round")
    if type(current_block) is not int or not (
        order.round.submission_close_block
        <= body.observed.block
        <= order.round.public_schedule.evidence_cutoff_block
        and body.observed.block <= current_block <= order.round.valid_through_block
    ):
        raise ValueError("repair authorization is premature, late or expired")
    assignments = {
        assignment_key(order.publication, a): a
        for a in order.publication.publication.assignments
        if a.submission_sha256 == body.submission_sha256
        and identity(a.evaluator_hotkey) in {identity(k) for k in order.evaluators}
    }
    for claim in body.unavailable:
        a = assignments.get(claim.assignment_key)
        if a is None or (
            identity(claim.evaluator_hotkey) != identity(a.evaluator_hotkey)
            or claim.request_sha256 != request_digest(a.request)
            or claim.deadline_block != a.request.deadline_block
            or not a.request.issued_block <= claim.claim_block <= a.request.deadline_block
            or not a.request.deadline_block < body.observed.block
        ):
            raise ValueError("repair claim differs from its original assignment or deadline")


def retained_claim(journal, key, *, allow_retired=False, signed_observation=None):
    """Read the immutable claim without expiring work or advancing a clock."""
    with closing(sqlite3.connect(journal.path.as_uri() + "?mode=ro", uri=True)) as db:
        db.execute("PRAGMA query_only=ON")
        db.execute("BEGIN")
        rows = db.execute(
            "SELECT kind,observed_height,observed_ms,body,length(evidence) FROM events "
            "WHERE assignment_id=? ORDER BY ordinal LIMIT 4",
            (key,),
        ).fetchall()
        kinds = [r[0] for r in rows]
        if signed_observation is not None and kinds == ["published", "dispatched", "completed"]:
            # A previously signed local observation records absence at its
            # creation. A later completion remains additional history and must
            # not prevent that observation from reaching its quorum. New repair
            # signing and new unavailable observation assembly never use this.
            from .competition_observations import SignedExecutionAnnouncement

            observed = SignedExecutionAnnouncement.model_validate_json(
                canonical_json_bytes(signed_observation)
            )
            verify_signature(observed.announcement, observed.signature)
            evidence = observed.announcement.evidence
            valid = isinstance(evidence, EndpointUnavailableEvidence) and any(
                c.assignment_key == key
                and identity(c.evaluator_hotkey) == identity(observed.signature.hotkey)
                and identity(c.evaluator_hotkey) == identity(observed.announcement.evaluator_hotkey)
                for c in evidence.repair.amendment.unavailable
            )
        elif allow_retired and kinds == ["published", "dispatched", "completed"]:
            # Authenticate the already retained void before accepting subsequent
            # transcript recovery as additional history. Signing a new repair
            # never enables this path and still requires an uncertain claim.
            from .competition_scheduling_retirement import retired_claims

            valid = key in retired_claims(journal, db)
        else:
            valid = kinds == ["published", "dispatched"]
        if not valid or rows[1][4] not in (0, None):
            raise ValueError("repair requires an original uncertain claim without a completion")
        _, block, ms, raw, _ = rows[1]
        body = json.loads(raw)
        if canonical_json_bytes(body) != raw or set(body) != {
            "claim_id",
            "issuance_height",
            "request_sha256",
        }:
            raise ValueError("repair claim bytes are not canonical")
        return hashlib.sha256(raw).hexdigest(), block, ms, body["request_sha256"]


def validate_local_repair(signed, *, journal, evaluator_hotkey, signed_observation=None, **context):
    """Check local absence before signing/using a separately authorized repair.

    Operators must also retain the bounded retention-search audit named by the
    amendment. A journal alone cannot establish absence from every other store.
    """
    signed = verify_dispatch_repair(signed, **context)
    if signed_observation is not None:
        from .competition_observations import SignedExecutionAnnouncement

        signed_observation = SignedExecutionAnnouncement.model_validate_json(
            canonical_json_bytes(signed_observation)
        )
        observed = signed_observation.announcement
        verify_signature(observed, signed_observation.signature)
        if (
            not isinstance(observed.evidence, EndpointUnavailableEvidence)
            or observed.evidence.repair.amendment != signed.amendment
            or observed.order_sha256 != signed.amendment.order_sha256
            or identity(observed.evaluator_hotkey) != identity(evaluator_hotkey)
            or identity(signed_observation.signature.hotkey) != identity(evaluator_hotkey)
        ):
            raise ValueError("repair observation differs from its original scope")
    own = [
        c
        for c in signed.amendment.unavailable
        if identity(c.evaluator_hotkey) == identity(evaluator_hotkey)
    ]
    for claim in own:
        expected = (
            claim.claim_sha256,
            claim.claim_block,
            claim.claim_unix_ms,
            claim.request_sha256,
        )
        if (
            retained_claim(
                journal,
                claim.assignment_key,
                allow_retired=True,
                signed_observation=signed_observation,
            )
            != expected
        ):
            raise ValueError("repair does not retain the exact original local claim")
    return signed


def unavailable_observations(evidence, suite, policy, *, current_block):
    raw = canonical_json_bytes(evidence)
    if len(raw) > MAX_PAIRED_BYTES:
        raise ValueError("unavailable endpoint evidence exceeds its byte bound")
    evidence = EndpointUnavailableEvidence.model_validate_json(raw)
    job = evidence.incumbent.job
    if (
        type(current_block) is not int
        or not job.round.reveal_block <= current_block <= job.round.valid_through_block
    ):
        raise ValueError("unavailable endpoint review is premature or expired")
    assignments = _assignments(
        evidence.incumbent, evidence.publication, policy, evidence.legacy_policy
    )
    validate_publication_suite(evidence.publication, suite, policy)
    body = evidence.repair.amendment
    if (
        body.round_sha256 != digest(job.round)
        or body.policy_sha256 != digest(policy)
        or body.publication_sha256 != digest(evidence.publication.publication)
        or body.submission_sha256 != digest(job.submission.submission)
    ):
        raise ValueError("unavailable evidence differs from its repair")
    missing = {
        c.assignment_key
        for c in body.unavailable
        if identity(c.evaluator_hotkey) == identity(job.evaluator_hotkey)
    }
    assigned = {assignment_key(evidence.publication, a) for a in assignments}
    if not missing or not missing <= assigned:
        raise ValueError("unavailable evidence must retain its own affected assignments")
    expected = [a for a in assignments if assignment_key(evidence.publication, a) not in missing]
    if len(expected) != len(evidence.dispatches):
        raise ValueError("repair omits an unaffected dispatch")
    outputs = []
    for a, dispatch in zip(expected, evidence.dispatches, strict=True):
        key = assignment_key(evidence.publication, a)
        if key != dispatch.assignment_key:
            raise ValueError("repair changes retained dispatch ordering")
        raw = bytes.fromhex(dispatch.transcript_hex)
        document = json.loads(raw)
        if not isinstance(document, dict):
            raise ValueError("dispatch transcript must be an object")
        origin_block = document.get("origin_block")
        if type(origin_block) is not int or not (
            a.request.issued_block <= origin_block < a.request.deadline_block
        ):
            raise ValueError("dispatch origin observation is outside the assigned interval")
        replay = _replay_validated_dispatch_bytes(
            raw,
            key,
            publication=evidence.publication,
            policy=policy,
            legacy_policy=evidence.legacy_policy,
            suite=suite,
            reveal_pulse=None
            if dispatch.reveal_pulse is None
            else dispatch.reveal_pulse.verified(),
        )
        outputs.append(replay.output)
    # Deliberately no synthetic output for an unknown response. Only void review
    # accepts this view; ordinary score replay rejects this evidence schema.
    return dict(
        job=job,
        candidate=tuple(outputs),
        incumbent=tuple(s.execution.output for s in evidence.incumbent.steps),
        coordinator_outcome_unavailable=True,
        evidence_sha256=digest(evidence),
    )


def assemble_unavailable_observations(
    *, incumbent, journal, signed_order, repair, suite, pulses, current_block
):
    repair = validate_local_repair(
        repair,
        journal=journal,
        evaluator_hotkey=incumbent.job.evaluator_hotkey,
        signed_order=signed_order,
        policy=journal.policy,
        legacy=journal.legacy_policy,
        current_block=current_block,
    )
    publication = signed_order.order.publication
    assignments = _assignments(incumbent, publication, journal.policy, journal.legacy_policy)
    missing = {c.assignment_key for c in repair.amendment.unavailable}
    dispatches = []
    for a in assignments:
        key = assignment_key(publication, a)
        if key not in missing:
            dispatches.append(
                EndpointDispatchEvidence(
                    assignment_key=key,
                    transcript_hex=journal.outcome(key).hex(),
                    reveal_pulse=pulses.get(a.request.reveal_round),
                )
            )
    result = EndpointUnavailableEvidence(
        schema="umi-endpoint-unavailable-evidence/1",
        incumbent=incumbent,
        publication=publication,
        legacy_policy=journal.legacy_policy,
        dispatches=tuple(dispatches),
        repair=repair,
    )
    unavailable_observations(result, suite, journal.policy, current_block=current_block)
    return result


def sign_dispatch_repair(
    amendment, *, signed_order, policy, legacy, journal, evaluator_hotkey, capture, wallet
):
    """Sign only after an owned fresh capture and exact local claim inspection.

    The caller retains the signed audit named in audit_sha256 and publishes only
    after gathering every assigned evaluator's signature. No wallet is opened.
    """
    import bittensor as bt

    from .competition_evaluator import validate_order
    from .competition_execution import execution_boundary
    from .open_competition import sign_object

    amendment = DispatchRepairAmendment.model_validate_json(canonical_json_bytes(amendment))
    order = validate_order(signed_order, policy, legacy).order
    observed = execution_boundary(capture)
    _verify_amendment_body(amendment, order, policy, observed.block)
    if observed.block > order.round.public_schedule.evidence_cutoff_block:
        raise ValueError("repair signing cutoff elapsed")
    if identity(evaluator_hotkey) not in {identity(k) for k in order.evaluators}:
        raise ValueError("repair signer is not assigned to the order")
    if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
        evaluator_hotkey
    ):
        raise ValueError("repair wallet does not hold the assigned evaluator key")
    for claim in amendment.unavailable:
        if identity(claim.evaluator_hotkey) == identity(evaluator_hotkey) and retained_claim(
            journal, claim.assignment_key
        ) != (claim.claim_sha256, claim.claim_block, claim.claim_unix_ms, claim.request_sha256):
            raise ValueError("repair does not retain the exact original local claim")
    return sign_object(amendment, wallet)


def validate_local_repair_observation(
    observation, *, journal, signed_order, policy, legacy, current_block, evaluator_hotkey
):
    if isinstance(observation.announcement.evidence, EndpointUnavailableEvidence):
        validate_local_repair(
            observation.announcement.evidence.repair,
            journal=journal,
            signed_order=signed_order,
            policy=policy,
            legacy=legacy,
            current_block=current_block,
            evaluator_hotkey=evaluator_hotkey,
            signed_observation=observation,
        )
