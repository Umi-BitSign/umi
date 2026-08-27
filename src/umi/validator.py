"""One-shot UMI component validator with no chain write capability."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from .audit import EvidenceStore
from .auth import verify_historical_auth_record
from .chain import discover_miner
from .component import (
    BUNDLE_SCHEMA,
    MAX_COMPONENT_REQUESTS,
    NOT_REACHED,
    PreparedCase,
    load_case,
    prepare_case,
    score_component_responses,
    validate_case_bindings,
)
from .config import SAFETY_BOUNDARY, Limits
from .crypto import (
    SealedResponse,
    TimelockDecryptionError,
    decrypt_response,
    parse_sealed_response,
    verify_response_signature,
)
from .miner import RESPONSE_SIGNATURE_HEADER, TRANSLATE_PATH
from .protocol import (
    GroundTruthPayload,
    ResponseEnvelope,
    ResponsePlaintext,
    TranslationRequest,
    base64url_decode,
    base64url_encode,
    canonical_json_bytes,
    request_digest,
)
from .scoring import scoring_environment

LOGGER = logging.getLogger("umi.validator")


class ComponentResponseError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class QueryOutcome:
    request: TranslationRequest
    auth_headers: dict[str, str]
    received_at_unix_ns: str | None
    envelope_bytes: bytes | None
    envelope: ResponseEnvelope | None
    response_signature: str | None
    sealed_response: SealedResponse | None
    plaintext_bytes: bytes | None = None
    plaintext: ResponsePlaintext | None = None
    failure_code: str | None = None


def _hotkey_ss58(wallet: Any) -> str:
    import bittensor as bt

    return bt.resolve_signer(wallet, role="hotkey").ss58_address


def _validate_miner_url(miner_url: str) -> str:
    parsed = urlsplit(miner_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("miner URL must be an absolute HTTP(S) origin")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("miner URL must be an origin without a path, query, or fragment")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("miner URL must not contain user information")
    return miner_url.rstrip("/")


def _header_size(headers: httpx.Headers) -> int:
    return sum(
        len(name.encode("ascii")) + len(value.encode("latin-1")) + 4
        for name, value in headers.items()
    )


def _auth_record(headers: httpx.Headers) -> dict[str, str]:
    return {
        name: value
        for name, value in sorted(headers.items(), key=lambda item: item[0].lower())
        if name.lower().startswith("x-bittensor-")
    }


async def _read_response_body(response: httpx.Response, maximum_bytes: int) -> bytes:
    content_length = response.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise ComponentResponseError(
                "outer_invalid", "miner response has an invalid Content-Length"
            ) from error
        if declared < 0 or declared > maximum_bytes:
            raise ComponentResponseError(
                "resource_limit", "miner response exceeds the configured body ceiling"
            )
    body = bytearray()
    async for chunk in response.aiter_bytes():
        if len(body) + len(chunk) > maximum_bytes:
            raise ComponentResponseError(
                "resource_limit", "miner response exceeds the configured body ceiling"
            )
        body.extend(chunk)
    return bytes(body)


def validate_response_envelope(
    raw_body: bytes,
    signature: str,
    *,
    request: TranslationRequest,
    validator_hotkey: str,
    miner_hotkey: str,
) -> tuple[ResponseEnvelope, SealedResponse]:
    try:
        envelope = ResponseEnvelope.model_validate_json(raw_body)
    except ValidationError as error:
        raise ComponentResponseError("outer_invalid", "invalid response envelope") from error
    if canonical_json_bytes(envelope) != raw_body:
        raise ComponentResponseError("outer_invalid", "response envelope is not canonical JSON")

    expected = {
        "window_id": request.window_id,
        "batch_id": request.batch_id,
        "challenge_id": request.challenge_id,
        "request_digest": request_digest(request),
        "issued_block_hash": request.issued_block_hash,
        "validator_hotkey": validator_hotkey,
        "serving_hotkey": miner_hotkey,
        "response_reveal_round": request.reveal_round,
    }
    for field, value in expected.items():
        if getattr(envelope, field) != value:
            raise ComponentResponseError(
                "binding_mismatch", f"response envelope does not bind {field}"
            )
    if not verify_response_signature(
        envelope,
        hotkey_ss58=miner_hotkey,
        scheme=envelope.signature_scheme,
        signature=signature,
    ):
        raise ComponentResponseError("bad_signature", "miner response signature is invalid")
    try:
        sealed = parse_sealed_response(
            envelope.encrypted_response,
            reveal_round=request.reveal_round,
            sha256_hex=envelope.encrypted_response_sha256,
        )
    except ValueError as error:
        raise ComponentResponseError("outer_invalid", "invalid response timelock") from error
    return envelope, sealed


def validate_response_plaintext(
    raw_plaintext: bytes,
    *,
    envelope: ResponseEnvelope,
    request: TranslationRequest,
) -> ResponsePlaintext:
    try:
        plaintext = ResponsePlaintext.model_validate_json(raw_plaintext)
    except ValidationError as error:
        raise ComponentResponseError("plaintext_invalid", "invalid response plaintext") from error
    if canonical_json_bytes(plaintext) != raw_plaintext:
        raise ComponentResponseError(
            "plaintext_invalid", "response plaintext is not canonical JSON"
        )
    expected = {
        "protocol": request.protocol,
        "window_id": request.window_id,
        "batch_id": request.batch_id,
        "challenge_id": request.challenge_id,
        "request_digest": request_digest(request),
        "issued_block_hash": request.issued_block_hash,
        "validator_hotkey": envelope.validator_hotkey,
        "serving_hotkey": envelope.serving_hotkey,
    }
    for field, value in expected.items():
        if getattr(plaintext, field) != value:
            raise ComponentResponseError(
                "plaintext_binding_mismatch", f"response plaintext does not bind {field}"
            )
    if plaintext.received_video_sha256 not in {None, request.video.sha256}:
        raise ComponentResponseError(
            "plaintext_binding_mismatch", "response plaintext binds a different video"
        )
    return plaintext


async def query_miner(
    request: TranslationRequest,
    *,
    wallet: Any,
    miner_url: str,
    miner_hotkey: str,
    limits: Limits,
    timeout_seconds: float,
    transport: httpx.AsyncBaseTransport | None = None,
) -> QueryOutcome:
    if timeout_seconds <= 0:
        raise ValueError("request timeout must be positive")
    validator_hotkey = _hotkey_ss58(wallet)
    body = canonical_json_bytes(request)
    import bittensor as bt

    response_close_ns = _round_time_ns(request.response_close_round)
    response_close_timestamp = response_close_ns / 1_000_000_000
    remaining_response_seconds = response_close_timestamp - time.time()
    if remaining_response_seconds <= 0:
        raise ValueError("component request response window has already closed")

    auth_headers = bt.http_auth.sign(
        wallet,
        method="POST",
        path=TRANSLATE_PATH,
        body=body,
        receiver_ss58=miner_hotkey,
    )
    auth_headers = _auth_record(httpx.Headers(auth_headers))
    raw_body: bytes | None = None
    received_at: str | None = None
    signature: str | None = None

    async def exchange() -> None:
        nonlocal auth_headers, raw_body, received_at, signature
        async with (
            httpx.AsyncClient(
                base_url=_validate_miner_url(miner_url),
                timeout=httpx.Timeout(min(timeout_seconds, remaining_response_seconds)),
                follow_redirects=False,
                transport=transport,
            ) as client,
            client.stream(
                "POST",
                TRANSLATE_PATH,
                content=body,
                headers={"Content-Type": "application/json", **auth_headers},
            ) as response,
        ):
            auth_headers = _auth_record(response.request.headers)
            if _header_size(response.headers) > limits.maximum_http_header_bytes:
                raise ComponentResponseError(
                    "resource_limit", "miner response headers exceed the ceiling"
                )
            if response.status_code != 200:
                raise ComponentResponseError(
                    "http_error", f"miner returned HTTP {response.status_code}"
                )
            raw_body = await _read_response_body(
                response,
                limits.maximum_response_body_bytes,
            )
            received_at = str(time.time_ns())
            signature = response.headers.get(RESPONSE_SIGNATURE_HEADER)
            if signature is None:
                raise ComponentResponseError(
                    "outer_invalid", "miner response signature header is missing"
                )

    try:
        await asyncio.wait_for(
            exchange(),
            timeout=min(timeout_seconds, remaining_response_seconds),
        )
    except ComponentResponseError as error:
        return QueryOutcome(
            request=request,
            auth_headers=auth_headers,
            received_at_unix_ns=received_at,
            envelope_bytes=raw_body,
            envelope=None,
            response_signature=signature,
            sealed_response=None,
            failure_code=error.code,
        )
    except asyncio.TimeoutError:
        failure_code = "late" if time.time() >= response_close_timestamp else "transport_timeout"
        return QueryOutcome(
            request=request,
            auth_headers=auth_headers,
            received_at_unix_ns=received_at,
            envelope_bytes=raw_body,
            envelope=None,
            response_signature=signature,
            sealed_response=None,
            failure_code=failure_code,
        )
    except httpx.HTTPError as error:
        LOGGER.warning("miner transport failed: %s", type(error).__name__)
        return QueryOutcome(
            request=request,
            auth_headers=auth_headers,
            received_at_unix_ns=None,
            envelope_bytes=None,
            envelope=None,
            response_signature=None,
            sealed_response=None,
            failure_code="transport_error",
        )

    try:
        if raw_body is None or received_at is None or signature is None:
            raise RuntimeError("successful response path lost its bounded evidence")
        envelope, sealed = validate_response_envelope(
            raw_body,
            signature,
            request=request,
            validator_hotkey=validator_hotkey,
            miner_hotkey=miner_hotkey,
        )
    except ComponentResponseError as error:
        return QueryOutcome(
            request=request,
            auth_headers=auth_headers,
            received_at_unix_ns=received_at,
            envelope_bytes=raw_body,
            envelope=None,
            response_signature=signature,
            sealed_response=None,
            failure_code=error.code,
        )
    return QueryOutcome(
        request=request,
        auth_headers=auth_headers,
        received_at_unix_ns=received_at,
        envelope_bytes=raw_body,
        envelope=envelope,
        response_signature=signature,
        sealed_response=sealed,
        failure_code=("late" if int(received_at) >= response_close_ns else None),
    )


async def _decrypt(sealed: SealedResponse, *, timeout: float | None) -> bytes:
    return await asyncio.to_thread(
        decrypt_response,
        sealed,
        reveal_round=sealed.reveal_round,
        sha256_hex=sealed.sha256_hex,
        wait=True,
        timeout=timeout,
    )


def _require_empty_output(output: Path) -> None:
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"output path is not an empty directory: {output}")


def _write_run_bundle(
    output: Path,
    prepared: PreparedCase,
    ground_truth_bytes: bytes,
    outcomes: tuple[QueryOutcome, ...],
    scoring: dict[str, Any],
    miner_url: str,
    miner_hotkey: str,
) -> Path:
    store = EvidenceStore(output)
    ground_truth_envelope_ref = store.add_bytes(
        prepared.ground_truth.portable_bytes, "application/octet-stream"
    )
    ground_truth_ref = store.add_bytes(ground_truth_bytes, "application/json")
    outcome_records: list[dict[str, Any]] = []
    for outcome in outcomes:
        request_ref = store.add_json(outcome.request)
        auth_ref = store.add_json(outcome.auth_headers)
        envelope_ref = (
            store.add_bytes(outcome.envelope_bytes, "application/json")
            if outcome.envelope_bytes is not None
            else None
        )
        signature_ref = (
            store.add_json({"signature": outcome.response_signature})
            if outcome.response_signature is not None
            else None
        )
        plaintext_ref = (
            store.add_bytes(
                outcome.plaintext_bytes,
                "application/json" if outcome.plaintext is not None else "application/octet-stream",
            )
            if outcome.plaintext_bytes is not None
            else None
        )
        outcome_records.append(
            {
                "challenge_id": outcome.request.challenge_id,
                "request": request_ref.as_dict(),
                "authentication_record": auth_ref.as_dict(),
                "received_at_unix_ns": outcome.received_at_unix_ns,
                "response_envelope": envelope_ref.as_dict() if envelope_ref else None,
                "response_signature": signature_ref.as_dict() if signature_ref else None,
                "response_plaintext": plaintext_ref.as_dict() if plaintext_ref else None,
                "failure_code": outcome.failure_code,
            }
        )
    scoring_ref = store.add_json(scoring)
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "terminal_code": SAFETY_BOUNDARY.terminal_code,
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "miner_origin": miner_url,
        "miner_hotkey": miner_hotkey,
        "scoring_environment": scoring_environment(),
        "ground_truth_envelope": ground_truth_envelope_ref.as_dict(),
        "ground_truth_plaintext": ground_truth_ref.as_dict(),
        "outcomes": outcome_records,
        "scoring": scoring_ref.as_dict(),
        "not_reached": list(NOT_REACHED),
    }
    return store.write_manifest(manifest)


async def run_component_case(
    case_root: Path,
    output: Path,
    *,
    wallet: Any,
    miner_url: str,
    miner_hotkey: str,
    request_timeout_seconds: float = 30.0,
    reveal_timeout_seconds: float | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> Path:
    """Query one miner, wait for the common reveal, score, and persist evidence."""

    _require_empty_output(output)
    prepared = load_case(case_root)
    limits = Limits()
    queried = await asyncio.gather(
        *(
            query_miner(
                request,
                wallet=wallet,
                miner_url=miner_url,
                miner_hotkey=miner_hotkey,
                limits=limits,
                timeout_seconds=request_timeout_seconds,
                transport=transport,
            )
            for request in prepared.requests
        )
    )
    outcomes = tuple(queried)

    ground_truth_bytes = await _decrypt(prepared.ground_truth, timeout=reveal_timeout_seconds)
    try:
        ground_truth = GroundTruthPayload.model_validate_json(ground_truth_bytes)
    except ValidationError as error:
        raise ValueError("revealed ground truth is invalid") from error
    if canonical_json_bytes(ground_truth) != ground_truth_bytes:
        raise ValueError("revealed ground truth is not canonical JSON")
    validate_case_bindings(prepared.requests, ground_truth)

    revealed_outcomes: list[QueryOutcome] = []
    response_map: dict[str, ResponsePlaintext | None] = {}
    failure_map: dict[str, str | None] = {}
    for outcome in outcomes:
        if outcome.sealed_response is None or outcome.envelope is None:
            revealed = outcome
        else:
            try:
                plaintext_bytes = await _decrypt(
                    outcome.sealed_response, timeout=reveal_timeout_seconds
                )
            except TimelockDecryptionError:
                revealed = replace(
                    outcome,
                    failure_code=outcome.failure_code or "undecryptable",
                )
            else:
                try:
                    plaintext = validate_response_plaintext(
                        plaintext_bytes,
                        envelope=outcome.envelope,
                        request=outcome.request,
                    )
                except ComponentResponseError as error:
                    revealed = replace(
                        outcome,
                        plaintext_bytes=plaintext_bytes,
                        failure_code=outcome.failure_code or error.code,
                    )
                else:
                    revealed = replace(
                        outcome,
                        plaintext_bytes=plaintext_bytes,
                        plaintext=plaintext,
                        failure_code=(
                            outcome.failure_code
                            or (plaintext.error_code if plaintext.status == "error" else None)
                        ),
                    )
        revealed_outcomes.append(revealed)
        response_map[revealed.request.challenge_id] = revealed.plaintext
        failure_map[revealed.request.challenge_id] = revealed.failure_code

    scoring = score_component_responses(
        prepared.requests,
        ground_truth,
        response_map,
        failure_map,
    )
    return _write_run_bundle(
        output,
        prepared,
        ground_truth_bytes,
        tuple(revealed_outcomes),
        scoring,
        _validate_miner_url(miner_url),
        miner_hotkey,
    )


def _read_object(store: EvidenceStore, value: Any) -> bytes:
    if not isinstance(value, dict):
        raise ValueError("bundle object reference is malformed")
    return store.read(value)


def _parse_receipt_time(value: Any) -> int | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.isdecimal() or value != str(int(value)):
        raise ValueError("response receipt time is not canonical integer nanoseconds")
    return int(value)


def _round_time_ns(round_number: int) -> int:
    import bittensor as bt

    return int(bt.timelock.reveal_time(round_number).timestamp()) * 1_000_000_000


def replay_bundle(root: Path) -> dict[str, Any]:
    """Recompute timelocks, signatures, bindings, and scores without a miner/model."""

    store = EvidenceStore(root)
    manifest = store.load_manifest()
    safety = {
        "schema": BUNDLE_SCHEMA,
        "terminal_code": SAFETY_BOUNDARY.terminal_code,
        "netuid": 78,
        "mechanism_id": 0,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
    }
    for field, expected in safety.items():
        if manifest.get(field) != expected:
            raise ValueError(f"bundle safety field is invalid: {field}")
    if manifest.get("scoring_environment") != scoring_environment():
        raise ValueError("bundle scoring environment does not match this replay runtime")

    raw_outcomes = manifest.get("outcomes")
    if not isinstance(raw_outcomes, list) or not raw_outcomes:
        raise ValueError("bundle contains no outcomes")
    if len(raw_outcomes) > MAX_COMPONENT_REQUESTS:
        raise ValueError(f"bundle exceeds the {MAX_COMPONENT_REQUESTS}-outcome ceiling")
    declared_challenges = [
        outcome.get("challenge_id") if isinstance(outcome, dict) else None
        for outcome in raw_outcomes
    ]
    if any(not isinstance(challenge_id, str) for challenge_id in declared_challenges):
        raise ValueError("bundle outcome challenge ID is malformed")
    if len(set(declared_challenges)) != len(declared_challenges):
        raise ValueError("bundle contains a duplicate challenge ID")
    try:
        canonical_declared = sorted(
            declared_challenges,
            key=lambda challenge_id: base64url_decode(str(challenge_id)),
        )
    except ValueError as error:
        raise ValueError("bundle outcome challenge ID is malformed") from error
    if declared_challenges != canonical_declared:
        raise ValueError("bundle outcomes are not canonically ordered by challenge ID")

    requests: list[TranslationRequest] = []
    responses: dict[str, ResponsePlaintext | None] = {}
    failures: dict[str, str | None] = {}
    miner_hotkey = str(manifest["miner_hotkey"])
    validator_hotkey: str | None = None
    seen_challenges: set[str] = set()
    seen_nonces: set[tuple[str, int]] = set()
    for raw_outcome in raw_outcomes:
        if not isinstance(raw_outcome, dict):
            raise ValueError("bundle outcome is malformed")
        request_bytes = _read_object(store, raw_outcome.get("request"))
        request = TranslationRequest.model_validate_json(request_bytes)
        if canonical_json_bytes(request) != request_bytes:
            raise ValueError("stored request is not canonical JSON")
        if raw_outcome.get("challenge_id") != request.challenge_id:
            raise ValueError("bundle outcome does not bind its request challenge ID")
        if request.challenge_id in seen_challenges:
            raise ValueError("bundle contains a duplicate challenge ID")
        seen_challenges.add(request.challenge_id)
        requests.append(request)
        failure_code = raw_outcome.get("failure_code")
        if failure_code is not None and (
            not isinstance(failure_code, str) or not failure_code.strip()
        ):
            raise ValueError("bundle response failure code is malformed")
        failures[request.challenge_id] = failure_code
        received_at = _parse_receipt_time(raw_outcome.get("received_at_unix_ns"))
        auth_record = json.loads(_read_object(store, raw_outcome.get("authentication_record")))
        if not isinstance(auth_record, dict):
            raise ValueError("request authentication record is malformed")
        auth_verification = verify_historical_auth_record(
            auth_record,
            request_bytes,
            method="POST",
            path=TRANSLATE_PATH,
            receiver_ss58=miner_hotkey,
        )
        if validator_hotkey is None:
            validator_hotkey = auth_verification.sender_ss58
        elif validator_hotkey != auth_verification.sender_ss58:
            raise ValueError("bundle combines assignments from different validators")
        nonce_key = (auth_verification.sender_ss58, auth_verification.nonce)
        if nonce_key in seen_nonces:
            raise ValueError("bundle reuses a btauth nonce")
        seen_nonces.add(nonce_key)

        plaintext_ref = raw_outcome.get("response_plaintext")
        envelope_ref = raw_outcome.get("response_envelope")
        signature_ref = raw_outcome.get("response_signature")
        if envelope_ref is None:
            if plaintext_ref is not None or signature_ref is not None:
                raise ValueError("partial response evidence is not replayable")
            if failure_code is None:
                raise ValueError("missing response evidence has no failure code")
            responses[request.challenge_id] = None
            continue
        envelope_bytes = _read_object(store, envelope_ref)
        if signature_ref is None:
            if plaintext_ref is None and failure_code == "outer_invalid":
                responses[request.challenge_id] = None
                continue
            raise ValueError("response envelope lacks its signature evidence")
        signature_record = json.loads(_read_object(store, signature_ref))
        if not isinstance(signature_record, dict) or set(signature_record) != {"signature"}:
            raise ValueError("response signature record is malformed")
        try:
            envelope, sealed = validate_response_envelope(
                envelope_bytes,
                str(signature_record["signature"]),
                request=request,
                validator_hotkey=auth_verification.sender_ss58,
                miner_hotkey=miner_hotkey,
            )
        except (ComponentResponseError, ValidationError) as error:
            code = error.code if isinstance(error, ComponentResponseError) else "outer_invalid"
            if plaintext_ref is not None or failure_code != code:
                raise ValueError("stored response failure does not reproduce") from error
            responses[request.challenge_id] = None
            continue

        if received_at is None:
            raise ValueError("valid response envelope has no receipt time")
        was_late = received_at >= _round_time_ns(request.response_close_round)
        if plaintext_ref is None:
            try:
                decrypt_response(
                    sealed,
                    reveal_round=sealed.reveal_round,
                    sha256_hex=sealed.sha256_hex,
                    wait=False,
                )
            except TimelockDecryptionError as error:
                expected_failure = "late" if was_late else "undecryptable"
                if failure_code != expected_failure:
                    raise ValueError("stored timelock failure does not reproduce") from error
                responses[request.challenge_id] = None
                continue
            raise ValueError("decryptable response is missing its retained plaintext bytes")
        plaintext_bytes = _read_object(store, plaintext_ref)
        try:
            revealed_bytes = decrypt_response(
                sealed,
                reveal_round=sealed.reveal_round,
                sha256_hex=sealed.sha256_hex,
                wait=False,
            )
        except TimelockDecryptionError as error:
            raise ValueError("stored plaintext belongs to an undecryptable response") from error
        if revealed_bytes != plaintext_bytes:
            raise ValueError("stored response plaintext does not match its timelock")
        try:
            plaintext = validate_response_plaintext(
                plaintext_bytes,
                envelope=envelope,
                request=request,
            )
        except ComponentResponseError as error:
            expected_failure = "late" if was_late else error.code
            if failure_code != expected_failure:
                raise ValueError("stored plaintext failure does not reproduce") from error
            responses[request.challenge_id] = None
            continue
        expected_failure = (
            "late" if was_late else (plaintext.error_code if plaintext.status == "error" else None)
        )
        if failure_code != expected_failure:
            raise ValueError("stored response disposition does not reproduce")
        responses[request.challenge_id] = plaintext

    ordered_requests = tuple(requests)
    if tuple(sorted(requests, key=lambda item: base64url_decode(item.challenge_id))) != tuple(
        requests
    ):
        raise ValueError("bundle outcomes are not canonically ordered by challenge ID")
    ground_truth_bytes = _read_object(store, manifest.get("ground_truth_plaintext"))
    ground_truth_envelope_ref = manifest.get("ground_truth_envelope")
    if not isinstance(ground_truth_envelope_ref, dict):
        raise ValueError("ground-truth envelope reference is malformed")
    ground_truth_envelope_bytes = _read_object(store, ground_truth_envelope_ref)
    ground_truth_sealed = parse_sealed_response(
        base64url_encode(ground_truth_envelope_bytes),
        reveal_round=ordered_requests[0].reveal_round,
        sha256_hex=str(ground_truth_envelope_ref["sha256"]),
    )
    revealed_ground_truth = decrypt_response(
        ground_truth_sealed,
        reveal_round=ground_truth_sealed.reveal_round,
        sha256_hex=ground_truth_sealed.sha256_hex,
        wait=False,
    )
    if revealed_ground_truth != ground_truth_bytes:
        raise ValueError("stored ground truth does not match its timelock")
    ground_truth = GroundTruthPayload.model_validate_json(ground_truth_bytes)
    if canonical_json_bytes(ground_truth) != ground_truth_bytes:
        raise ValueError("stored ground truth is not canonical JSON")
    validate_case_bindings(ordered_requests, ground_truth)
    recomputed = score_component_responses(ordered_requests, ground_truth, responses, failures)
    stored_scoring = json.loads(_read_object(store, manifest.get("scoring")))
    if canonical_json_bytes(recomputed) != canonical_json_bytes(stored_scoring):
        raise ValueError("stored scores do not match deterministic replay")
    return recomputed


def score_summary(scoring: dict[str, Any]) -> dict[str, Any]:
    failure_counts: dict[str, int] = {}
    for clip in scoring.get("per_clip", []):
        if not isinstance(clip, dict):
            continue
        failure_code = clip.get("failure_code")
        if isinstance(failure_code, str):
            failure_counts[failure_code] = failure_counts.get(failure_code, 0) + 1
    return {
        "assigned_clip_count": scoring.get("assigned_clip_count"),
        "diagnostic_accuracy": scoring.get("diagnostic_accuracy"),
        "stratum_means": scoring.get("stratum_means"),
        "failure_counts": dict(sorted(failure_counts.items())),
        "weight_eligible": scoring.get("weight_eligible"),
    }


def _stored_scoring(root: Path) -> tuple[dict[str, Any], str]:
    store = EvidenceStore(root)
    manifest = store.load_manifest()
    scoring_ref = manifest.get("scoring")
    scoring = json.loads(_read_object(store, scoring_ref))
    if not isinstance(scoring, dict):
        raise ValueError("stored scoring object is malformed")
    if not isinstance(scoring_ref, dict) or not isinstance(scoring_ref.get("sha256"), str):
        raise ValueError("stored scoring reference is malformed")
    return scoring, scoring_ref["sha256"]


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="UMI no-weight component validator")
    subcommands = parser.add_subparsers(dest="command", required=True)

    prepare = subcommands.add_parser("prepare", help="seal a component challenge case")
    prepare.add_argument("--requests", type=Path, required=True)
    prepare.add_argument("--ground-truth", type=Path, required=True)
    prepare.add_argument("--output", type=Path, required=True)

    run = subcommands.add_parser("run-once", help="query, reveal, score, and bundle")
    run.add_argument("--case", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--wallet-name", required=True)
    run.add_argument("--hotkey", required=True)
    run.add_argument("--wallet-path", default="~/.bittensor/wallets")
    run.add_argument(
        "--miner-url",
        help="explicit component endpoint; otherwise discover the hotkey on SN78",
    )
    run.add_argument("--miner-hotkey", required=True)
    run.add_argument("--network", default="finney")
    run.add_argument("--request-timeout", type=float, default=30.0)
    run.add_argument("--reveal-timeout", type=float)

    replay = subcommands.add_parser("replay", help="recompute a completed bundle")
    replay.add_argument("--bundle", type=Path, required=True)
    return parser


def main() -> None:
    args = _parser().parse_args()
    logging.basicConfig(level=logging.INFO)
    if args.command == "prepare":
        print(prepare_case(args.requests, args.ground_truth, args.output))
        return
    if args.command == "replay":
        scoring = replay_bundle(args.bundle)
        print(
            canonical_json_bytes(
                {
                    "status": "replay_ok",
                    "bundle_manifest": str(args.bundle / "manifest.json"),
                    "summary": score_summary(scoring),
                }
            ).decode("utf-8")
        )
        return

    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)

    async def run_from_args() -> Path:
        miner_url = args.miner_url
        if miner_url is None:
            endpoint = await discover_miner(
                args.miner_hotkey,
                network=args.network,
                netuid=78,
            )
            miner_url = endpoint.origin
        return await run_component_case(
            args.case,
            args.output,
            wallet=wallet,
            miner_url=miner_url,
            miner_hotkey=args.miner_hotkey,
            request_timeout_seconds=args.request_timeout,
            reveal_timeout_seconds=args.reveal_timeout,
        )

    manifest = asyncio.run(run_from_args())
    scoring, scoring_digest = _stored_scoring(manifest.parent)
    print(
        canonical_json_bytes(
            {
                "status": "component_run_complete",
                "bundle_manifest": str(manifest),
                "scoring_object_sha256": scoring_digest,
                "summary": score_summary(scoring),
            }
        ).decode("utf-8")
    )


if __name__ == "__main__":
    main()
