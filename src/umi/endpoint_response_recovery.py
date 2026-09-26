"""Bounded retrieval of a miner's original sealed response.

Retrieval never calls the inference route. A missing or unavailable archive does
not prove that remote work stopped. Receipt time is the actual retrieval time,
not a substitute for the original response-window evidence.
"""

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from dataclasses import asdict, dataclass
from typing import Annotated, Any, Literal

import bittensor as bt
import httpx
from pydantic import Field

from .auth import REQUEST_BODY_SHA256_HEADER, RequestAuthenticator
from .config import Limits
from .miner import RESPONSE_RECOVERY_PATH, RESPONSE_SIGNATURE_HEADER
from .open_competition import identity
from .protocol import StrictProtocolModel, TranslationRequest, canonical_json_bytes
from .validator import (
    ComponentResponseError,
    OriginResolver,
    _header_size,
    _pinned_public_origin,
    _read_response_body,
    validate_response_envelope,
)


class RecoveredEndpointResponse(StrictProtocolModel):
    schema_: Literal["umi-recovered-endpoint-response/1"] = Field(alias="schema")
    envelope_hex: Annotated[str, Field(pattern=r"^(?:[0-9a-f]{2})+$", max_length=128 * 1024)]
    signature: Annotated[str, Field(pattern=r"^0x[0-9a-f]{128}$")]
    retrieval_started_at_unix_ns: Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]{0,19})$")]
    retrieved_at_unix_ns: Annotated[str, Field(pattern=r"^(?:0|[1-9][0-9]{0,19})$")]


@dataclass(frozen=True)
class EndpointRecoveryOutcome:
    status: Literal["recovered", "pending"]
    reason: str
    http_status: int | None = None
    response: RecoveredEndpointResponse | None = None


def recovery_limits(limits: Limits) -> Limits:
    limits = Limits(**asdict(limits))
    for name, maximum in (
        ("maximum_request_body_bytes", 64 * 1024),
        ("maximum_response_body_bytes", 64 * 1024),
        ("maximum_http_header_bytes", 16 * 1024),
    ):
        if getattr(limits, name) > maximum:
            raise ValueError("response recovery exceeds bounded transport limits")
    return limits


def verify_recovered_response(value, *, request, validator_hotkey, miner_hotkey, limits):
    value = RecoveredEndpointResponse.model_validate_json(canonical_json_bytes(value))
    raw = bytes.fromhex(value.envelope_hex)
    if len(raw) > recovery_limits(limits).maximum_response_body_bytes:
        raise ValueError("recovered response exceeds transport limit")
    if int(value.retrieved_at_unix_ns) < int(value.retrieval_started_at_unix_ns):
        raise ValueError("response retrieval clock regressed")
    validate_response_envelope(
        raw,
        value.signature,
        request=request,
        validator_hotkey=validator_hotkey,
        miner_hotkey=miner_hotkey,
    )
    return value


async def retrieve_endpoint_response(
    request: TranslationRequest,
    *,
    wallet: Any,
    validator_hotkey: str,
    miner_hotkey: str,
    miner_url: str,
    limits: Limits,
    timeout_seconds: float,
    resolver: OriginResolver | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> EndpointRecoveryOutcome:
    """Use fresh route-specific authentication and exact original request bytes."""
    limits = recovery_limits(limits)
    if (
        isinstance(timeout_seconds, bool)
        or not math.isfinite(timeout_seconds)
        or not 0 < timeout_seconds <= 3600
    ):
        raise ValueError("response recovery timeout must be bounded and positive")
    request = TranslationRequest.model_validate_json(canonical_json_bytes(request))
    body = canonical_json_bytes(request)
    if len(body) > limits.maximum_request_body_bytes:
        raise ValueError("recovery request exceeds transport limit")
    if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
        validator_hotkey
    ):
        raise ValueError("recovery signer differs from original evaluator")
    started = str(time.time_ns())

    async def exchange():
        # Even injected transports use the same HTTPS/public-address checks.
        # The production caller supplies the resolver from a current origin proof.
        origin, host, sni = await _pinned_public_origin(miner_url, resolver=resolver)
        headers = bt.http_auth.sign(
            wallet,
            method="POST",
            path=RESPONSE_RECOVERY_PATH,
            body=body,
            receiver_ss58=miner_hotkey,
        )
        caller = RequestAuthenticator.in_memory(miner_hotkey).verify_without_replay(
            headers,
            body,
            method="POST",
            path=RESPONSE_RECOVERY_PATH,
        )
        if identity(caller.hotkey_ss58) != identity(validator_hotkey):
            raise ValueError("recovery authentication differs from original evaluator")
        headers.update(
            {
                "Accept-Encoding": "identity",
                "Content-Type": "application/json",
                "Host": host,
                REQUEST_BODY_SHA256_HEADER: hashlib.sha256(body).hexdigest(),
            }
        )
        async with httpx.AsyncClient(
            base_url=origin,
            timeout=timeout_seconds,
            follow_redirects=False,
            trust_env=False,
            transport=transport,
        ) as client:
            wire = client.build_request(
                "POST", RESPONSE_RECOVERY_PATH, content=body, headers=headers
            )
            wire.extensions["sni_hostname"] = sni
            if _header_size(wire.headers) > limits.maximum_http_header_bytes:
                raise ComponentResponseError("resource_limit", "recovery request header limit")
            response = await client.send(wire, stream=True)
            try:
                if _header_size(response.headers) > limits.maximum_http_header_bytes:
                    raise ComponentResponseError("resource_limit", "recovery response header limit")
                # No error body, redirect target, or capability URL is retained.
                if response.status_code != 200:
                    return response.status_code, None, None, None
                raw = await _read_response_body(
                    response, limits.maximum_response_body_bytes, prefix=bytearray()
                )
                return (
                    response.status_code,
                    raw,
                    response.headers.get(RESPONSE_SIGNATURE_HEADER),
                    str(time.time_ns()),
                )
            finally:
                await response.aclose()

    try:
        status, raw, signature, received = await asyncio.wait_for(exchange(), timeout_seconds)
    except (OSError, httpx.HTTPError, TimeoutError, ComponentResponseError):
        return EndpointRecoveryOutcome("pending", "recovery_transport_unavailable")
    if status != 200:
        return EndpointRecoveryOutcome("pending", "recovery_response_unavailable", status)
    # Local signature and timelock parsing has no network deadline.
    try:
        value = verify_recovered_response(
            RecoveredEndpointResponse(
                schema="umi-recovered-endpoint-response/1",
                envelope_hex=raw.hex(),
                signature=signature,
                retrieval_started_at_unix_ns=started,
                retrieved_at_unix_ns=received,
            ),
            request=request,
            validator_hotkey=validator_hotkey,
            miner_hotkey=miner_hotkey,
            limits=limits,
        )
    except ValueError:
        return EndpointRecoveryOutcome("pending", "recovery_response_invalid", status)
    return EndpointRecoveryOutcome("recovered", "original_response_recovered", status, value)
