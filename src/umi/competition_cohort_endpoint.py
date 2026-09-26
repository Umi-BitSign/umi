"""Recoverable endpoint observations, using exact signed requests and responses.

Orders here describe one bounded attempt for each immutable case obligation.
This replay consumer does not authorize live delivery or reissue: the durable
dispatcher must retain attempt history, fence retries and certify its terminal
selection before settlement. Timing/origin boundaries reference separately
retained native proofs; evaluator-reported receipt times are not chain proofs.
"""

from __future__ import annotations

import hashlib
from collections import Counter, defaultdict
from typing import Annotated, Literal
from urllib.parse import urlsplit

from pydantic import Field

from .anchors import VerifiedAuthEvidence
from .competition_authorization import validate_transport_cohort
from .competition_cohort_evaluation import verify_recoverable_round_participant
from .competition_cohort_execution import (
    RecoverableExecutionEvidence,
    RecoverableExecutionJob,
    RecoverableExecutionObservation,
    recoverable_execution_observations,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
)
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_endpoint import EndpointReplayBinding, replay_authenticated_endpoint_outcome
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_execution import ExecutionBoundary
from .config import Limits
from .open_competition import (
    CompetitionPolicy,
    EvaluationSuite,
    RegistrationSnapshot,
    Signature,
    digest,
    has_case_coverage,
    identity,
)
from .policy import ScoringPolicy, scoring_policy_hash
from .protocol import (
    Hex32,
    StrictProtocolModel,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
)
from .validator import PreparedRequestAttempt, QueryOutcome

MAX_ENDPOINT_EVIDENCE_BYTES = 64 * 1024**2
WireHex = Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})*$", max_length=128 * 1024)]
Timestamp = Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]{0,19})$")]


class RecoverableEndpointOrder(StrictProtocolModel):
    schema_: Literal["umi-recoverable-endpoint-order/1"] = Field(alias="schema")
    job: RecoverableExecutionJob
    transport_policy_sha256: Hex32
    attempt_number: Annotated[int, Field(ge=1, le=2**53 - 1)]
    requests: Annotated[tuple[TranslationRequest, ...], Field(min_length=3, max_length=2048)]
    chain_submission_authorized: Literal[False] = False


class SignedRecoverableEndpointOrder(StrictProtocolModel):
    order: RecoverableEndpointOrder
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class RecoverableEndpointTranscript(StrictProtocolModel):
    case_id: Hex32
    request_hex: WireHex
    auth_headers: Annotated[tuple[tuple[str, str], ...], Field(min_length=1, max_length=8)]
    origin: ExecutionBoundary
    started_at_unix_ns: Timestamp
    finished_at_unix_ns: Timestamp
    received_at_unix_ns: Timestamp | None
    envelope_hex: WireHex | None
    response_signature: Annotated[str, Field(max_length=130)] | None
    received_body_prefix_hex: WireHex | None
    received_bytes_sha256: Hex32 | None
    failure_code: Annotated[str, Field(max_length=128)] | None
    reveal_pulse: RetainedRevealPulse | None


class RecoverableEndpointPairedEvidence(StrictProtocolModel):
    schema_: Literal["umi-recoverable-endpoint-paired-evidence/1"] = Field(alias="schema")
    incumbent: RecoverableExecutionEvidence
    order: SignedRecoverableEndpointOrder
    transport_policy: ScoringPolicy
    transcripts: Annotated[
        tuple[RecoverableEndpointTranscript, ...], Field(min_length=3, max_length=2048)
    ]
    chain_submission_authorized: Literal[False] = False


def endpoint_obligation_sha256(job: RecoverableExecutionJob, case_id: str) -> str:
    """The work identity survives reissue with another bounded request window."""
    job = RecoverableExecutionJob.model_validate_json(canonical_json_bytes(job))
    if case_id not in {c.case_id for c in job.cases}:
        raise ValueError("endpoint obligation case is not assigned")
    return hashlib.sha256(
        b"umi-recoverable-endpoint-obligation-v1\0"
        + canonical_json_bytes(
            [
                job.round.policy_sha256,
                digest(job.round),
                digest(job.submission.submission),
                identity(job.evaluator_hotkey),
                case_id,
            ]
        )
    ).hexdigest()


def endpoint_attempt_wire_ids(
    job: RecoverableExecutionJob, attempt_number: int, case_id: str
) -> tuple[str, str]:
    if type(attempt_number) is not int or not 1 <= attempt_number <= 2**53 - 1:
        raise ValueError("invalid endpoint attempt number")
    obligation = endpoint_obligation_sha256(job, case_id)
    batch = hashlib.sha256(
        b"umi-recoverable-endpoint-batch-v1\0" + canonical_json_bytes([digest(job), attempt_number])
    ).digest()[:16]
    challenge = hashlib.sha256(
        b"umi-recoverable-endpoint-attempt-v1\0"
        + canonical_json_bytes([obligation, attempt_number])
    ).digest()[:16]
    return base64url_encode(batch), base64url_encode(challenge)


def verify_recoverable_endpoint_order(
    signed: SignedRecoverableEndpointOrder,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> SignedRecoverableEndpointOrder:
    """Authenticate historical assignments after certified request closure.

    The signatures bind an attempt; they do not prove its original publication
    time or that it was the only attempt. Those are durable-dispatcher gates.
    """
    signed = validate_recoverable_endpoint_transport(signed, policy, transport)
    job = signed.order.job
    view = verify_recoverable_round_participant(
        job.submission,
        job.round,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    preparation = view.closure("preparation")
    requests = view.closure("requests")
    view.closure("reference_reveal")
    if job.preparation_closure_sha256 != digest(preparation):
        raise ValueError("recoverable endpoint order scope or signer differs")
    for request in signed.order.requests:
        if (
            not preparation.observed_at_block
            < request.issued_block
            < request.deadline_block
            <= requests.observed_at_block
        ):
            raise ValueError("recoverable endpoint assignment or request interval differs")
    return signed


def validate_recoverable_endpoint_transport(
    signed: SignedRecoverableEndpointOrder,
    policy: CompetitionPolicy,
    transport: ScoringPolicy,
) -> SignedRecoverableEndpointOrder:
    """Verify bounded signed request scope; confer no live delivery authority."""
    raw = canonical_json_bytes(signed)
    if len(raw) > 16 * 1024**2:
        raise ValueError("recoverable endpoint order exceeds its byte bound")
    signed = SignedRecoverableEndpointOrder.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
    body, job = signed.order, signed.order.job
    validate_transport_cohort(policy, transport)
    verify_recovery_quorum(body, signed.signatures, policy)
    evaluator, miner = identity(job.evaluator_hotkey), identity(job.submission.submission.hotkey)
    if (
        job.mode != "endpoint_incumbent"
        or evaluator == miner
        or evaluator not in {identity(e.hotkey) for e in policy.evaluators}
        or evaluator not in {identity(v.validator_hotkey) for v in transport.validator_registry}
        or any(identity(s.hotkey) == miner for s in signed.signatures)
        or body.transport_policy_sha256 != scoring_policy_hash(transport)
        or body.transport_policy_sha256 == digest(policy)
        or len(body.requests) != len(job.cases)
        or not has_case_coverage(job.cases, policy)
    ):
        raise ValueError("recoverable endpoint order scope or signer differs")
    validate_endpoint_request_pairs(
        job, tuple(zip(job.cases, body.requests, strict=True)), body.attempt_number, transport
    )
    return signed


def validate_endpoint_request_pairs(job, pairs, attempt_number, transport):
    """Enforce native request bindings and window quotas for selected cases."""
    limits = Limits.from_policy(transport)
    counts: Counter[int] = Counter()
    videos: dict[int, set[str]] = defaultdict(set)
    for case, request in pairs:
        expected_ids = endpoint_attempt_wire_ids(job, attempt_number, case.case_id)
        if (
            (request.batch_id, request.challenge_id) != expected_ids
            or request.video.sha256 != case.video_sha256
            or request.task.stratum != case.stratum
            or request.scoring_policy_hash != scoring_policy_hash(transport)
            or not request.issued_block < request.deadline_block
            or request.issued_block < transport.activation_block
            or request.video.size_bytes > limits.maximum_clip_size_bytes
            or len(canonical_json_bytes(request)) > limits.maximum_request_body_bytes
        ):
            raise ValueError("recoverable endpoint assignment or request interval differs")
        url = urlsplit(request.video.url)
        if (
            url.scheme != "https"
            or not url.hostname
            or url.username is not None
            or url.password is not None
            or url.fragment
            or len(request.video.url) > 4096
            or any(ord(c) < 33 for c in request.video.url)
        ):
            raise ValueError("endpoint video URL is not bounded HTTPS")
        window = (
            request.issued_block - transport.activation_block
        ) // transport.clock.window_stride_blocks
        counts[window] += 1
        videos[window].add(request.video.sha256)
    if (
        any(n > limits.maximum_assignments_per_validator_window for n in counts.values())
        or any(n > limits.maximum_total_assignments_per_window for n in counts.values())
        or any(len(v) > limits.maximum_unique_videos_per_validator_window for v in videos.values())
    ):
        raise ValueError("endpoint attempt exceeds transport quotas")


def recoverable_endpoint_observations(
    evidence: RecoverableEndpointPairedEvidence,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    consent: SignedCohortParticipationConsent,
    admission: AttestedCohortParticipantAdmission,
    admission_snapshot: RegistrationSnapshot,
    history: CohortRecoveryHistory,
    *,
    expected_tip_sha256: str,
    current_block: int,
) -> RecoverableExecutionObservation:
    raw = canonical_json_bytes(evidence)
    if len(raw) > MAX_ENDPOINT_EVIDENCE_BYTES:
        raise ValueError("recoverable endpoint evidence exceeds its byte bound")
    evidence = RecoverableEndpointPairedEvidence.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    order = verify_recoverable_endpoint_order(
        evidence.order,
        policy,
        evidence.transport_policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    ).order
    if order.job != evidence.incumbent.job or len(evidence.transcripts) != len(order.job.cases):
        raise ValueError("endpoint observations do not match the complete assigned job")
    baseline = recoverable_execution_observations(
        evidence.incumbent,
        suite,
        policy,
        consent,
        admission,
        admission_snapshot,
        history,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    job = order.job
    limits = Limits.from_policy(evidence.transport_policy)
    outputs = []
    for case, request, transcript in zip(
        job.cases, order.requests, evidence.transcripts, strict=True
    ):
        request_bytes = bytes.fromhex(transcript.request_hex)
        if (
            transcript.case_id != case.case_id
            or request_bytes != canonical_json_bytes(request)
            or not request.issued_block <= transcript.origin.block < request.deadline_block
            or transcript.origin.evidence_sha256 == "0" * 64
            or len({name.lower() for name, _ in transcript.auth_headers})
            != len(transcript.auth_headers)
        ):
            raise ValueError("endpoint transcript changed its request, origin or case")
        headers = dict(transcript.auth_headers)
        auth = VerifiedAuthEvidence.from_headers(
            headers,
            request=request,
            expected_validator_hotkey=job.evaluator_hotkey,
            expected_miner_hotkey=job.submission.submission.hotkey,
        )
        prepared = PreparedRequestAttempt(
            request,
            request_bytes,
            job.evaluator_hotkey,
            job.submission.submission.hotkey,
            transcript.auth_headers,
            auth,
        )
        outcome = QueryOutcome(
            request=request,
            auth_headers=headers,
            received_at_unix_ns=transcript.received_at_unix_ns,
            envelope_bytes=None
            if transcript.envelope_hex is None
            else bytes.fromhex(transcript.envelope_hex),
            response_signature=transcript.response_signature,
            envelope=None,
            sealed_response=None,
            received_body_prefix=None
            if transcript.received_body_prefix_hex is None
            else bytes.fromhex(transcript.received_body_prefix_hex),
            received_bytes_sha256=transcript.received_bytes_sha256,
            failure_code=transcript.failure_code,
        )
        result = replay_authenticated_endpoint_outcome(
            EndpointReplayBinding(
                prepared,
                policy,
                job.submission,
                digest(job.round),
                job.round.suite_sha256,
                case.case_id,
                order.transport_policy_sha256,
                limits,
            ),
            outcome,
            suite=suite,
            reveal_pulse=None
            if transcript.reveal_pulse is None
            else transcript.reveal_pulse.verified(),
            started_at_unix_ns=transcript.started_at_unix_ns,
            finished_at_unix_ns=transcript.finished_at_unix_ns,
            recoverable=True,
        )
        outputs.append(result.output)
    # The request bounds are conservative assignment bounds, not fabricated
    # finality attestations of network completion or response receipt.
    return RecoverableExecutionObservation(
        job=job,
        candidate=tuple(outputs),
        incumbent=baseline.incumbent,
        started_block=min(baseline.started_block, *(r.issued_block for r in order.requests)),
        finished_block=max(baseline.finished_block, *(r.deadline_block for r in order.requests)),
        requests_closed_at_block=baseline.requests_closed_at_block,
        evidence_sha256=digest(evidence),
    )
