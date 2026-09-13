"""Pair retained endpoint transport with actual, pre-reveal incumbent execution.

These are private evaluator observations. Signatures authenticate the miner's
bytes and publication, but do not prove elapsed time or independent operation.
No function here signs results, changes policy, or submits weights.
"""

from __future__ import annotations

import hashlib
import json
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_authorization import (
    SignedEndpointAuthorization,
    validate_publication,
    validate_publication_suite,
)
from .competition_dispatch_replay import _replay_validated_dispatch_bytes
from .competition_execution import (
    EndpointIncumbentEvidence,
    EndpointIncumbentJob,
    ExecutionCase,
    validate_execution,
    validate_incumbent_job,
)
from .competition_scheduling import assignment_key
from .drand import DrandPulse
from .open_competition import EvaluationSuite, _quality, digest, identity
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_PAIRED_BYTES = 64 * 1024**2


class RetainedRevealPulse(StrictProtocolModel):
    round: Annotated[int, Field(ge=1, le=2**64 - 1)]
    randomness: Hex32
    signature: Annotated[str, Field(pattern=r"^[0-9a-f]{96}$")]

    def verified(self):
        pulse = DrandPulse(**self.model_dump())
        pulse.verify()
        return pulse


class EndpointDispatchEvidence(StrictProtocolModel):
    assignment_key: Hex32
    transcript_hex: Annotated[str, Field(min_length=2, max_length=2 * 1024**2)]
    reveal_pulse: RetainedRevealPulse | None

    @model_validator(mode="after")
    def canonical_hex(self):
        if bytes.fromhex(self.transcript_hex).hex() != self.transcript_hex:
            raise ValueError("endpoint transcript must be canonical lowercase hex")
        return self


class EndpointPairedEvidence(StrictProtocolModel):
    schema_: Literal["umi-endpoint-paired-evidence/1"] = Field(alias="schema")
    incumbent: EndpointIncumbentEvidence
    publication: SignedEndpointAuthorization
    legacy_policy: ScoringPolicy
    dispatches: Annotated[
        tuple[EndpointDispatchEvidence, ...], Field(min_length=3, max_length=2048)
    ]
    chain_submission_authorized: Literal[False] = False


def prepare_incumbent_job(
    *, publication, submission_sha256, incumbent, runtime, evaluator_hotkey, policy, legacy_policy
):
    """Derive the reference-free local job from the authenticated assignment list."""
    publication = validate_publication(publication, policy, legacy_policy)
    body = publication.publication
    submissions = [s for s in body.submissions if digest(s.submission) == submission_sha256]
    if len(submissions) != 1:
        raise ValueError("endpoint submission is absent from the signed publication")
    job = validate_incumbent_job(
        EndpointIncumbentJob(
            schema="umi-endpoint-incumbent-job/1",
            round=body.round,
            submission=submissions[0],
            incumbent=incumbent,
            runtime=runtime,
            evaluator_hotkey=evaluator_hotkey,
            cases=tuple(
                ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
                for c in body.cases
            ),
        ),
        policy,
    )
    assigned = {
        a.case_sha256
        for a in body.assignments
        if a.submission_sha256 == submission_sha256
        and identity(a.evaluator_hotkey) == identity(evaluator_hotkey)
    }
    if assigned != {digest(c) for c in body.cases}:
        raise ValueError("endpoint evaluator does not have all paired assignments")
    return job


def _assignments(incumbent, publication, policy, legacy_policy):
    validate_execution(incumbent, policy)
    publication = validate_publication(publication, policy, legacy_policy)
    job, body = incumbent.job, publication.publication
    if job.round != body.round or job.submission not in body.submissions:
        raise ValueError("endpoint baseline and publication assignments differ")
    if job.cases != tuple(
        ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
        for c in body.cases
    ):
        raise ValueError("endpoint baseline must cover the complete published case list")
    cases = {digest(c): c for c in body.cases}
    assigned = {
        cases[a.case_sha256].case_id: a
        for a in body.assignments
        if a.submission_sha256 == digest(job.submission.submission)
        and identity(a.evaluator_hotkey) == identity(job.evaluator_hotkey)
    }
    if set(assigned) != {c.case_id for c in job.cases}:
        raise ValueError("endpoint evaluator does not have all paired assignments")
    return tuple(assigned[c.case_id] for c in job.cases)


def assemble_endpoint_evidence(
    *, incumbent, journal, publication_sha256, suite, pulses, current_block
):
    """Export completed local journal bytes and bind them to retained baseline runs.

    Uncertain/missing work is never converted to a miner failure. This function
    does no network work and never reruns a model or requests another response.
    """
    incumbent = EndpointIncumbentEvidence.model_validate_json(canonical_json_bytes(incumbent))
    publication = journal.publication(publication_sha256)
    assignments = _assignments(incumbent, publication, journal.policy, journal.legacy_policy)
    dispatches = []
    retained_bytes = len(canonical_json_bytes(incumbent)) + len(canonical_json_bytes(publication))
    for assignment in assignments:
        key = assignment_key(publication, assignment)
        status = journal.status(key)
        if status["state"] != "completed":
            raise ValueError("endpoint assignment is incomplete; no evaluation can be assembled")
        raw = journal.outcome(key)
        if hashlib.sha256(raw).hexdigest() != status["outcome_evidence_sha256"]:
            raise ValueError("endpoint outcome differs from its retained journal hash")
        retained_bytes += len(raw) * 2
        if retained_bytes > MAX_PAIRED_BYTES:
            raise ValueError("paired endpoint evidence exceeds its byte bound")
        dispatches.append(
            EndpointDispatchEvidence(
                assignment_key=key,
                transcript_hex=raw.hex(),
                reveal_pulse=pulses.get(assignment.request.reveal_round),
            )
        )
    evidence = EndpointPairedEvidence(
        schema="umi-endpoint-paired-evidence/1",
        incumbent=incumbent,
        publication=publication,
        legacy_policy=journal.legacy_policy,
        dispatches=tuple(dispatches),
    )
    endpoint_evaluation_view(evidence, suite, journal.policy, current_block=current_block)
    return evidence


def endpoint_evaluation_view(evidence, suite, policy, *, current_block):
    """Replay both roles before proposing or accepting a shared result."""
    raw = canonical_json_bytes(evidence)
    if len(raw) > MAX_PAIRED_BYTES:
        raise ValueError("paired endpoint evidence exceeds its byte bound")
    evidence = EndpointPairedEvidence.model_validate_json(raw)
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    job = evidence.incumbent.job
    if type(current_block) is not int or not (
        job.round.reveal_block <= current_block <= job.round.valid_through_block
    ):
        raise ValueError("paired endpoint scoring is premature or expired")
    assignments = _assignments(
        evidence.incumbent, evidence.publication, policy, evidence.legacy_policy
    )
    validate_publication_suite(evidence.publication, suite, policy)
    if len(evidence.dispatches) != len(assignments):
        raise ValueError("paired endpoint evidence has incomplete dispatch coverage")
    outputs = []
    starts, finishes = (
        [evidence.incumbent.steps[0].started.block],
        [evidence.incumbent.steps[-1].finished.block],
    )
    for assignment, dispatch in zip(assignments, evidence.dispatches, strict=True):
        key = assignment_key(evidence.publication, assignment)
        if dispatch.assignment_key != key:
            raise ValueError("paired endpoint dispatch order or assignment changed")
        raw = bytes.fromhex(dispatch.transcript_hex)
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
        document = json.loads(raw)
        origin_block = document["origin_block"]
        if type(origin_block) is not int or not (
            assignment.request.issued_block <= origin_block < assignment.request.deadline_block
        ):
            raise ValueError("dispatch origin observation is outside the assigned interval")
        # These are conservative assigned bounds, not fabricated finish-block
        # attestations. The individual baseline steps retain owned boundaries.
        starts.append(assignment.request.issued_block)
        finishes.append(assignment.request.deadline_block)
        outputs.append(replay.output)
    candidate = tuple(outputs)
    incumbent = tuple(s.execution.output for s in evidence.incumbent.steps)
    _quality(candidate, suite, policy)
    _quality(incumbent, suite, policy, incumbent=True)
    return {
        "job": job,
        "candidate": candidate,
        "incumbent": incumbent,
        "started_block": min(starts),
        "finished_block": max(finishes),
        "evidence_sha256": digest(evidence),
    }
