"""Bounded HTTPS submission of an already signed public competition object."""

from __future__ import annotations

import asyncio
from typing import Annotated, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import Field

from .competition_policy_lineage import submission_policy_admitted
from .open_competition import (
    Block,
    CompetitionPolicy,
    Hex32,
    RegistrationSnapshot,
    SignedSubmission,
    digest,
    validate_admission,
)
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_SUBMISSION_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_BYTES = 64 * 1024


class CompetitionSubmissionError(RuntimeError):
    """Stable public failure; never embeds a server body or local wallet data."""

    def __init__(self, reason_code: str, *, status_code: int | None = None):
        self.reason_code = reason_code
        self.status_code = status_code
        super().__init__(reason_code)


class AdmissionReceipt(StrictProtocolModel):
    schema_: Literal["umi-competition-admission/2"] = Field(alias="schema")
    policy_sha256: Hex32
    submission_sha256: Hex32
    accepted_block: Block
    registration_snapshot_sha256: Hex32
    registration_snapshot: RegistrationSnapshot
    registration_source: Literal["verifier_attested_finality"]
    observed_uid: Annotated[int, Field(ge=0, le=255)]
    status: Literal["accepted_no_weight"]
    chain_submission_authorized: Literal[False]


def validate_intake_origin(origin: str) -> str:
    if (
        not isinstance(origin, str)
        or not 1 <= len(origin) <= 2048
        or any(ord(c) < 33 or ord(c) == 127 for c in origin)
    ):
        raise ValueError("intake must be a credential-free HTTPS origin")
    try:
        parsed = urlsplit(origin)
        port = parsed.port
    except ValueError as error:
        raise ValueError("invalid intake origin") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise ValueError("intake must be a credential-free HTTPS origin")
    return origin.rstrip("/")


async def submit_signed_submission(
    *,
    origin: str,
    policy: CompetitionPolicy,
    signed: SignedSubmission,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AdmissionReceipt:
    """Send only a validated signed body, once, and verify its receipt binding.

    TLS identifies the selected intake server. A receipt is an admission claim,
    not a portable finality proof, quality certificate, or reward entitlement.
    Retrying this function sends the same canonical bytes; it never re-signs or
    renews a submission after an uncertain response.
    """
    origin = validate_intake_origin(origin)
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(signed))
    if not submission_policy_admitted(policy, signed.submission.policy_sha256):
        raise ValueError("submission belongs to another policy")
    body = canonical_json_bytes(signed)
    if len(body) > MAX_SUBMISSION_BYTES:
        raise ValueError("signed submission exceeds intake byte limit")

    raw = await post_intake_document(
        origin=origin, path="/v1/competition/submissions", body=body, transport=transport
    )
    try:
        receipt = AdmissionReceipt.model_validate_json(raw)
    except ValueError as error:
        raise CompetitionSubmissionError("invalid_receipt") from error
    sub = signed.submission
    if (
        receipt.policy_sha256 != digest(policy)
        or receipt.submission_sha256 != digest(sub)
        or receipt.observed_uid >= policy.maximum_uids
        or not sub.valid_from_block <= receipt.accepted_block <= sub.valid_through_block
        or not policy.valid_from_block <= receipt.accepted_block <= policy.valid_through_block
        or digest(receipt.registration_snapshot) != receipt.registration_snapshot_sha256
    ):
        raise CompetitionSubmissionError("receipt_binding_mismatch")
    try:
        observed_uid = validate_admission(
            signed, policy, receipt.registration_snapshot, receipt.accepted_block
        )
    except ValueError as error:
        raise CompetitionSubmissionError("receipt_registration_mismatch") from error
    if observed_uid != receipt.observed_uid:
        raise CompetitionSubmissionError("receipt_registration_mismatch")
    return receipt


async def post_intake_document(
    *,
    origin: str,
    path: str,
    body: bytes,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bytes:
    """Send one bounded document to a fixed intake path; never retry or re-sign."""
    origin = validate_intake_origin(origin)
    if not path.startswith("/v1/competition/") or any(c in path for c in "?#\\"):
        raise ValueError("invalid competition intake path")
    if len(body) > MAX_SUBMISSION_BYTES:
        raise ValueError("signed submission exceeds intake byte limit")

    async def send() -> bytes:
        async with (
            httpx.AsyncClient(
                transport=transport,
                timeout=httpx.Timeout(20, connect=5),
                follow_redirects=False,
                trust_env=False,
            ) as client,
            client.stream(
                "POST",
                origin + path,
                content=body,
                headers={
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "Accept-Encoding": "identity",
                },
            ) as response,
        ):
            if response.status_code != 200:
                raise CompetitionSubmissionError(
                    "intake_rejected_or_unavailable", status_code=response.status_code
                )
            if response.headers.get("content-type", "").split(";", 1)[0].strip() != (
                "application/json"
            ):
                raise CompetitionSubmissionError("invalid_receipt_content_type")
            if response.headers.get("content-encoding", "identity") != "identity":
                raise CompetitionSubmissionError("encoded_receipt_not_allowed")
            chunks = bytearray()
            async for chunk in response.aiter_bytes():
                if len(chunks) + len(chunk) > MAX_RECEIPT_BYTES:
                    raise CompetitionSubmissionError("receipt_byte_limit_exceeded")
                chunks.extend(chunk)
            return bytes(chunks)

    try:
        return await asyncio.wait_for(send(), timeout=25)
    except (httpx.HTTPError, asyncio.TimeoutError) as error:
        raise CompetitionSubmissionError("intake_transport_unavailable") from error
