"""No-weight replay bridge for existing authenticated endpoint transcripts.

This module cannot send requests or authorize a miner to accept successor work.
The existing miner requires its real ScoringPolicy hash, authorized validator
registry, and proof-backed MinerWindowAuthority schedule. CompetitionPolicy has
no replacement for that contract or its block-to-Quicknet deadline mapping.
Supplying a transport-policy hash here asserts neither miner authorization nor
chain-announced serving origin. A miner release and an authenticated mapping of
successor rounds to admitted transport assignments are required before live use.

Preparation retains a reference-free case binding. Replay checks membership in
the committed suite after reveal, authenticates raw request/response bytes, and
decrypts with a verified retained Quicknet pulse without network access. Reported
receipt times measure evaluator-observed round-trip time, not miner inference
time or independently proven pre-reveal delivery.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass

from .anchors import VerifiedAuthEvidence
from .config import Limits
from .drand import DrandPulse
from .open_competition import (
    CaseOutput,
    CompetitionPolicy,
    EvaluationRound,
    EvaluationSuite,
    SignedSubmission,
    digest,
    identity,
)
from .protocol import (
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
    normalized_grapheme_count,
    normalized_token_count,
)
from .validator import (
    ComponentResponseError,
    PreparedRequestAttempt,
    QueryOutcome,
    validate_response_envelope,
    validate_response_plaintext,
)
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

_HEX32 = re.compile(r"[0-9a-f]{64}\Z")
_TIMESTAMP = re.compile(r"(?:0|[1-9][0-9]{0,19})\Z")


@dataclass(frozen=True, slots=True)
class EndpointPreparedCase:
    """Rehearsal input only; possession conveys no transmission authority."""

    prepared: PreparedRequestAttempt
    policy: CompetitionPolicy
    round_: EvaluationRound
    signed: SignedSubmission
    case_id: str
    transport_policy_sha256: str
    limits: Limits


@dataclass(frozen=True, slots=True)
class EndpointReplay:
    output: CaseOutput
    reason_code: str | None
    evidence_bytes: bytes

    @property
    def evidence_sha256(self) -> str:
        return hashlib.sha256(self.evidence_bytes).hexdigest()


def prepare_endpoint_case(
    prepared: PreparedRequestAttempt,
    *,
    policy: CompetitionPolicy,
    round_: EvaluationRound,
    signed: SignedSubmission,
    case_id: str,
    expected_transport_policy_sha256: str,
    limits: Limits,
) -> EndpointPreparedCase:
    """Validate an already signed legacy request without signing or sending it.

    The explicit transport hash is kept distinct from the competition hash. It
    identifies the supplied transcript's policy; it does not prove authorization.
    The case/video mapping is checked against the committed suite during replay.
    """
    if not isinstance(prepared, PreparedRequestAttempt) or not isinstance(limits, Limits):
        raise TypeError("prepared request and explicit transport limits are required")
    # Reparse recursively: model_copy/model_construct must not bypass validation.
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    round_ = EvaluationRound.model_validate_json(canonical_json_bytes(round_))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    limits = Limits(**asdict(limits))
    for name, maximum in (
        ("maximum_request_body_bytes", 64 * 1024),
        ("maximum_response_body_bytes", 64 * 1024),
        ("maximum_response_plaintext_bytes", 40 * 1024),
        ("maximum_http_header_bytes", 16 * 1024),
        ("maximum_clip_size_bytes", 16 * 1024 * 1024),
    ):
        if getattr(limits, name) > maximum:
            raise ValueError("endpoint rehearsal exceeds bounded transport limits")
    if not isinstance(prepared.request_bytes, bytes):
        raise TypeError("request must retain exact bytes")
    if len(prepared.request_bytes) > limits.maximum_request_body_bytes:
        raise ValueError("request exceeds transport byte limit")
    if (
        not isinstance(prepared.auth_headers, tuple)
        or not 1 <= len(prepared.auth_headers) <= 8
        or any(
            not isinstance(header, tuple)
            or len(header) != 2
            or any(not isinstance(part, str) for part in header)
            for header in prepared.auth_headers
        )
    ):
        raise ValueError("authentication headers must be a bounded tuple of text pairs")
    if sum(len(k.encode()) + len(v.encode()) + 4 for k, v in prepared.auth_headers) > (
        limits.maximum_http_header_bytes
    ):
        raise ValueError("authentication headers exceed transport byte limit")
    request = TranslationRequest.model_validate_json(prepared.request_bytes)
    if prepared.request_bytes != canonical_json_bytes(request):
        raise ValueError("request bytes are not canonical")
    if canonical_json_bytes(prepared.request) != prepared.request_bytes:
        raise ValueError("prepared request does not match retained bytes")
    auth = VerifiedAuthEvidence.from_headers(
        dict(prepared.auth_headers),
        request=request,
        expected_validator_hotkey=prepared.validator_hotkey,
        expected_miner_hotkey=prepared.miner_hotkey,
    )
    prepared = PreparedRequestAttempt(
        request=request,
        request_bytes=prepared.request_bytes,
        validator_hotkey=prepared.validator_hotkey,
        miner_hotkey=prepared.miner_hotkey,
        auth_headers=prepared.auth_headers,
        auth_evidence=auth,
    )
    if (
        not isinstance(case_id, str)
        or not _HEX32.fullmatch(case_id)
        or not isinstance(expected_transport_policy_sha256, str)
        or not _HEX32.fullmatch(expected_transport_policy_sha256)
    ):
        raise ValueError("case and transport policy digests must be lowercase SHA-256")
    policy_sha = digest(policy)
    sub = signed.submission
    if (
        expected_transport_policy_sha256 == policy_sha
        or request.scoring_policy_hash != expected_transport_policy_sha256
    ):
        raise ValueError("request must keep its distinct legacy transport policy hash")
    if (
        round_.policy_sha256 != policy_sha
        or sub.policy_sha256 != policy_sha
        or round_.runtime_sha256 != policy.evaluation_runtime_sha256
        or digest(sub) not in round_.roster
        or sub.track != "endpoint"
        or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
    ):
        raise ValueError("endpoint policy, round, roster or submission binding mismatch")
    if not (
        policy.valid_from_block
        <= sub.valid_from_block
        <= round_.submission_close_block
        < request.issued_block
        < request.deadline_block
        <= round_.evaluation_close_block
        < round_.reveal_block
        <= round_.valid_through_block
        <= policy.valid_through_block
        and round_.evaluation_close_block <= sub.valid_through_block <= policy.valid_through_block
        and sub.valid_through_block - sub.valid_from_block
        <= policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("endpoint request is outside its historical evaluation interval")
    if (
        identity(prepared.miner_hotkey) != identity(sub.hotkey)
        or identity(prepared.validator_hotkey) == identity(sub.hotkey)
        or identity(prepared.validator_hotkey)
        not in {identity(e.hotkey) for e in policy.evaluators}
    ):
        raise ValueError("endpoint request has an unauthorized evaluator or different miner")
    if request.video.size_bytes > limits.maximum_clip_size_bytes:
        raise ValueError("request video exceeds transport byte limit")
    return EndpointPreparedCase(
        prepared, policy, round_, signed, case_id, expected_transport_policy_sha256, limits
    )


def _timestamp(value: str, label: str) -> int:
    if not isinstance(value, str) or not _TIMESTAMP.fullmatch(value) or int(value) > 2**64 - 1:
        raise ValueError(f"{label} must be canonical unsigned nanoseconds")
    return int(value)


def replay_endpoint_outcome(
    prepared_case: EndpointPreparedCase,
    outcome: QueryOutcome,
    *,
    suite: EvaluationSuite,
    reveal_pulse: DrandPulse | None,
    started_at_unix_ns: str,
    finished_at_unix_ns: str,
) -> EndpointReplay:
    """Replay one transcript, retaining its exact bytes and no-weight scope.

    Missing or unauthenticated transport evidence is an infrastructure failure.
    Authenticated miner errors, malformed sealed content, and revision mismatch
    are miner failures. Timing remains an evaluator claim in the evidence.
    """
    if not isinstance(prepared_case, EndpointPreparedCase) or not isinstance(outcome, QueryOutcome):
        raise TypeError("prepared endpoint case and query outcome are required")
    item = prepare_endpoint_case(
        prepared_case.prepared,
        policy=prepared_case.policy,
        round_=prepared_case.round_,
        signed=prepared_case.signed,
        case_id=prepared_case.case_id,
        expected_transport_policy_sha256=prepared_case.transport_policy_sha256,
        limits=prepared_case.limits,
    )
    request = item.prepared.request
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    if suite.policy_sha256 != digest(item.policy) or digest(suite) != item.round_.suite_sha256:
        raise ValueError("revealed suite does not match the committed round")
    cases = [case for case in suite.cases if case.case_id == item.case_id]
    if (
        len(cases) != 1
        or cases[0].video_sha256 != request.video.sha256
        or cases[0].stratum != request.task.stratum
    ):
        raise ValueError("request case/video/stratum does not match the revealed suite")
    if canonical_json_bytes(
        outcome.request
    ) != item.prepared.request_bytes or outcome.auth_headers != dict(item.prepared.auth_headers):
        raise ValueError("outcome changed the authenticated request")
    started = _timestamp(started_at_unix_ns, "start time")
    finished = _timestamp(finished_at_unix_ns, "finish time")
    elapsed_ms = (finished - started + 999_999) // 1_000_000
    if not 0 <= finished - started <= 86_400_000 * 1_000_000:
        raise ValueError("endpoint elapsed time is negative or exceeds one day")
    nonce = item.prepared.auth_evidence.auth_record.nonce_int
    if not (
        -int(item.limits.btauth_allowed_skew_seconds * 1_000_000_000)
        <= started - nonce
        <= int(item.limits.btauth_max_age_seconds * 1_000_000_000)
    ):
        raise ValueError("request authentication was stale at reported start time")
    received = None
    if outcome.received_at_unix_ns is not None:
        received = _timestamp(outcome.received_at_unix_ns, "receipt time")
        if not started <= received <= finished:
            raise ValueError("receipt time is outside the reported exchange")
    for value, maximum in (
        (outcome.envelope_bytes, item.limits.maximum_response_body_bytes),
        (outcome.received_body_prefix, item.limits.maximum_response_body_bytes),
        (outcome.plaintext_bytes, item.limits.maximum_response_plaintext_bytes),
    ):
        if value is not None and (not isinstance(value, bytes) or len(value) > maximum):
            raise ValueError("retained response exceeds its byte limit")
    retained = (
        outcome.envelope_bytes
        if outcome.envelope_bytes is not None
        else outcome.received_body_prefix
    )
    if outcome.received_bytes_sha256 != (
        None if retained is None else hashlib.sha256(retained).hexdigest()
    ):
        raise ValueError("received byte digest does not match retained response bytes")
    if outcome.envelope_bytes is not None and outcome.received_body_prefix not in {
        None,
        outcome.envelope_bytes,
    }:
        raise ValueError("retained prefix differs from the complete response")
    if outcome.failure_code is not None and (
        not isinstance(outcome.failure_code, str) or len(outcome.failure_code.encode()) > 128
    ):
        raise ValueError("transport failure code is not bounded text")
    if outcome.response_signature is not None and (
        not isinstance(outcome.response_signature, str) or len(outcome.response_signature) > 130
    ):
        raise ValueError("response signature is not bounded text")

    pulse_record = None
    if reveal_pulse is not None:
        if not isinstance(reveal_pulse, DrandPulse) or reveal_pulse.round != request.reveal_round:
            raise ValueError("reveal pulse does not match request timelock round")
        reveal_pulse.verify()
        pulse_record = asdict(reveal_pulse)
    status, hypothesis, reason = "infrastructure_failure", "", "unauthenticated_transport"
    revealed = None
    if outcome.envelope_bytes is not None and outcome.response_signature is not None:
        try:
            envelope, sealed = validate_response_envelope(
                outcome.envelope_bytes,
                outcome.response_signature,
                request=request,
                validator_hotkey=item.prepared.validator_hotkey,
                miner_hotkey=item.prepared.miner_hotkey,
            )
        except ComponentResponseError as error:
            if outcome.plaintext_bytes is not None:
                raise ValueError("plaintext has no authenticated envelope") from error
            reason = error.code
        else:
            if reveal_pulse is None or received is None:
                raise ValueError("signed response requires retained receipt time and reveal pulse")
            import bittensor_core

            decrypt = getattr(bittensor_core, "decrypt_with_signature", None)
            if not callable(decrypt):
                raise RuntimeError("offline timelock decryption primitive is unavailable")
            try:
                revealed = decrypt(sealed.portable_bytes, reveal_pulse.signature)
            except Exception as error:
                if outcome.plaintext_bytes is not None:
                    raise ValueError(
                        "retained plaintext belongs to an undecryptable response"
                    ) from error
                status, reason = "miner_failure", "undecryptable"
            else:
                if not isinstance(revealed, bytes):
                    raise RuntimeError("offline timelock decryption returned non-bytes")
                if len(revealed) > item.limits.maximum_response_plaintext_bytes:
                    raise ValueError("decrypted plaintext exceeds retained evidence byte limit")
                if outcome.plaintext_bytes is not None and outcome.plaintext_bytes != revealed:
                    raise ValueError("retained plaintext does not match its timelock")
                try:
                    plaintext = validate_response_plaintext(
                        revealed, envelope=envelope, request=request
                    )
                except ComponentResponseError as error:
                    status, reason = "miner_failure", error.code
                else:
                    if plaintext.status != "ok":
                        status, reason = "miner_failure", "signed_miner_error"
                    elif plaintext.model_revision != item.signed.submission.model_revision:
                        status, reason = "miner_failure", "model_revision_mismatch"
                    elif (
                        len(plaintext.hypothesis.encode())
                        > min(
                            item.policy.maximum_output_bytes,
                            item.limits.maximum_hypothesis_utf8_bytes,
                        )
                        or normalized_token_count(plaintext.hypothesis)
                        > item.limits.maximum_hypothesis_tokens
                        or normalized_grapheme_count(plaintext.hypothesis)
                        > item.limits.maximum_hypothesis_graphemes
                    ):
                        status, reason = "miner_failure", "output_limit"
                    else:
                        status, hypothesis, reason = "ok", plaintext.hypothesis, None
            close_ns = (
                QUICKNET_GENESIS_MS + (request.response_close_round - 1) * QUICKNET_PERIOD_MS
            ) * 1_000_000
            if received >= close_ns:
                status, hypothesis, reason = "infrastructure_failure", "", "reported_late_delivery"
    elif outcome.plaintext_bytes is not None:
        raise ValueError("plaintext has no authenticated envelope")

    output = CaseOutput(
        case_id=item.case_id, status=status, hypothesis=hypothesis, elapsed_ms=elapsed_ms
    )
    evidence = {
        "schema": "umi-competition-endpoint-replay/1",
        "profile": "legacy-transport-rehearsal/1",
        "no_weight": True,
        "miner_authorization_verified": False,
        "pre_reveal_delivery_proven": False,
        "timing_class": "evaluator_reported_round_trip",
        "policy_sha256": digest(item.policy),
        "round_sha256": digest(item.round_),
        "submission_sha256": digest(item.signed.submission),
        "suite_sha256": digest(suite),
        "case_id": item.case_id,
        "endpoint_url": item.signed.submission.endpoint_url,
        "transport_policy_sha256": item.transport_policy_sha256,
        "limits": asdict(item.limits),
        "request_bytes": base64url_encode(item.prepared.request_bytes),
        "auth_headers": dict(item.prepared.auth_headers),
        "started_at_unix_ns": started_at_unix_ns,
        "finished_at_unix_ns": finished_at_unix_ns,
        "received_at_unix_ns": outcome.received_at_unix_ns,
        "envelope_bytes": None
        if outcome.envelope_bytes is None
        else base64url_encode(outcome.envelope_bytes),
        "response_signature": outcome.response_signature,
        "received_body_prefix": None
        if outcome.received_body_prefix is None
        else base64url_encode(outcome.received_body_prefix),
        "received_bytes_sha256": outcome.received_bytes_sha256,
        "reported_failure_code": outcome.failure_code,
        "plaintext_bytes": None if revealed is None else base64url_encode(revealed),
        "reveal_pulse": pulse_record,
        "output": output.model_dump(mode="json", by_alias=True),
        "reason_code": reason,
    }
    return EndpointReplay(output, reason, canonical_json_bytes(evidence))
