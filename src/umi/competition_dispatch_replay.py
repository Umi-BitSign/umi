"""Replay retained dispatcher bytes without sending or re-signing a request."""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict

from .anchors import VerifiedAuthEvidence
from .competition_endpoint import prepare_endpoint_case, replay_endpoint_outcome
from .competition_scheduling import assignment_key
from .config import Limits
from .open_competition import digest
from .policy import scoring_policy_hash
from .protocol import canonical_json_bytes
from .validator import PreparedRequestAttempt, QueryOutcome

_FIELDS = frozenset(
    {
        "schema",
        "assignment_key",
        "publication_sha256",
        "case_id",
        "origin_evidence_sha256",
        "origin_block",
        "request_hex",
        "auth_headers",
        "limits",
        "started_at_unix_ns",
        "finished_at_unix_ns",
        "received_at_unix_ns",
        "envelope_hex",
        "response_signature",
        "received_body_prefix_hex",
        "received_bytes_sha256",
        "failure_code",
        "no_weight",
        "evidence_verified",
        "chain_submission_authorized",
    }
)


def _bytes(value, maximum):
    if value is None:
        return None
    if not isinstance(value, str) or len(value) > maximum * 2:
        raise ValueError("dispatch transcript bytes exceed their bound")
    raw = bytes.fromhex(value)
    if raw.hex() != value:
        raise ValueError("dispatch transcript hex must be canonical")
    return raw


def replay_dispatch_transcript(journal, key, *, suite, reveal_pulse):
    """Authenticate retained transport and revealed references; produce no weights.

    The origin digest identifies separately retained local storage-proof evidence.
    This function does not certify it, publication timing, or evaluator independence.
    """
    status = journal.status(key)
    raw = journal.outcome(key)
    if (
        status["state"] != "completed"
        or hashlib.sha256(raw).hexdigest() != status["outcome_evidence_sha256"]
    ):
        raise ValueError("dispatch outcome differs from completed journal evidence")
    return replay_dispatch_bytes(
        raw,
        key,
        publication=journal.publication(status["publication_sha256"]),
        policy=journal.policy,
        legacy_policy=journal.legacy_policy,
        suite=suite,
        reveal_pulse=reveal_pulse,
    )


def replay_dispatch_bytes(raw, key, *, publication, policy, legacy_policy, suite, reveal_pulse):
    """Replay exported private evidence; journal completion/timing remain host claims."""
    from .competition_authorization import validate_publication

    publication = validate_publication(publication, policy, legacy_policy)
    return _replay_validated_dispatch_bytes(
        raw,
        key,
        publication=publication,
        policy=policy,
        legacy_policy=legacy_policy,
        suite=suite,
        reveal_pulse=reveal_pulse,
    )


def _replay_validated_dispatch_bytes(
    raw,
    key,
    *,
    publication,
    policy,
    legacy_policy,
    suite,
    reveal_pulse,
):
    """Internal batch path after the complete publication's quorum was checked."""
    if not isinstance(raw, bytes) or len(raw) > 1024**2:
        raise ValueError("dispatch transcript exceeds the paired-evidence bound")
    document = json.loads(raw)
    if (
        not isinstance(document, dict)
        or set(document) != _FIELDS
        or canonical_json_bytes(document) != raw
    ):
        raise ValueError("dispatch transcript must use the exact canonical schema")
    if (
        document["schema"] != "umi-endpoint-dispatch-transcript/1"
        or document["assignment_key"] != key
        or document["publication_sha256"] != digest(publication.publication)
        or document["no_weight"] is not True
        or document["evidence_verified"] is not False
        or document["chain_submission_authorized"] is not False
    ):
        raise ValueError("dispatch transcript scope or assignment binding changed")
    origin_digest = document["origin_evidence_sha256"]
    if (
        not isinstance(origin_digest, str)
        or len(origin_digest) != 64
        or any(c not in "0123456789abcdef" for c in origin_digest)
        or origin_digest == "0" * 64
    ):
        raise ValueError("dispatch transcript has no bounded origin-evidence reference")
    body = publication.publication
    assignment = next(a for a in body.assignments if assignment_key(publication, a) == key)
    signed = next(
        s for s in body.submissions if digest(s.submission) == assignment.submission_sha256
    )
    case = next(c for c in body.cases if digest(c) == assignment.case_sha256)
    limits = Limits.from_policy(legacy_policy)
    if document["limits"] != asdict(limits) or document["case_id"] != case.case_id:
        raise ValueError("dispatch transcript limits or case changed")
    request_bytes = _bytes(document["request_hex"], limits.maximum_request_body_bytes)
    if request_bytes != canonical_json_bytes(assignment.request):
        raise ValueError("dispatch transcript changed its signed request")
    headers = document["auth_headers"]
    if (
        not isinstance(headers, dict)
        or not 1 <= len(headers) <= 8
        or any(not isinstance(k, str) or not isinstance(v, str) for k, v in headers.items())
    ):
        raise ValueError("dispatch authentication must be bounded text pairs")
    auth = VerifiedAuthEvidence.from_headers(
        headers,
        request=assignment.request,
        expected_validator_hotkey=assignment.evaluator_hotkey,
        expected_miner_hotkey=signed.submission.hotkey,
    )
    prepared = PreparedRequestAttempt(
        assignment.request,
        request_bytes,
        assignment.evaluator_hotkey,
        signed.submission.hotkey,
        tuple(sorted(headers.items())),
        auth,
    )
    prepared_case = prepare_endpoint_case(
        prepared,
        policy=policy,
        round_=body.round,
        signed=signed,
        case_id=case.case_id,
        expected_transport_policy_sha256=scoring_policy_hash(legacy_policy),
        limits=limits,
    )
    outcome = QueryOutcome(
        request=assignment.request,
        auth_headers=headers,
        received_at_unix_ns=document["received_at_unix_ns"],
        envelope_bytes=_bytes(document["envelope_hex"], limits.maximum_response_body_bytes),
        response_signature=document["response_signature"],
        envelope=None,
        sealed_response=None,
        received_body_prefix=_bytes(
            document["received_body_prefix_hex"], limits.maximum_response_body_bytes
        ),
        received_bytes_sha256=document["received_bytes_sha256"],
        failure_code=document["failure_code"],
    )
    return replay_endpoint_outcome(
        prepared_case,
        outcome,
        suite=suite,
        reveal_pulse=reveal_pulse,
        started_at_unix_ns=document["started_at_unix_ns"],
        finished_at_unix_ns=document["finished_at_unix_ns"],
    )
