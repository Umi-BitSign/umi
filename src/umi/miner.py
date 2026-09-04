"""UMI miner HTTP service for the initial no-weight component slice."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import os
import re
import stat
import time
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from weakref import WeakValueDictionary

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError

from .auth import REQUEST_BODY_SHA256_HEADER, RequestAuthenticator, wire_request_target
from .backends import Translator, UnixSocketTranslator, load_translator
from .config import SAFETY_BOUNDARY, Limits
from .crypto import seal_response, sign_response_digest, verify_response_signature
from .grandpa_finality_supervisor import DurableGrandpaFinalityPort
from .miner_admission import (
    MinerAdmissionError,
    MinerWindowAdmission,
    MinerWindowAuthority,
    ProofBackedMinerWindowAuthority,
)
from .miner_resources import (
    CachedMinerResponse,
    MinerAssignmentBinding,
    MinerResourceError,
    SQLiteMinerResourceLedger,
)
from .model_scheduler import WindowCoalescingTranslator
from .nonce import NonceStoreAuthorizationError, NonceStoreCapacityError, NonceStoreError
from .policy import ScoringPolicy, scoring_policy_hash, validate_scoring_runtime
from .protocol import (
    PROTOCOL_VERSION,
    RESPONSE_ENVELOPE_SCHEMA,
    RESPONSE_PLAINTEXT_SCHEMA,
    RESPONSE_TLE_PROFILE,
    ResponseEnvelope,
    ResponsePlaintext,
    TranslationRequest,
    canonical_json_bytes,
    normalized_grapheme_count,
    normalized_token_count,
    request_digest,
)
from .video import HttpVideoFetcher, VideoFetcher, VideoFetchError, VideoFetchResult

LOGGER = logging.getLogger("umi.miner")
TRANSLATE_PATH = "/v1/translate"
RESPONSE_SIGNATURE_HEADER = "X-UMI-Signature"


class BodyLimitExceeded(ValueError):
    pass


class EnvelopeLimitExceeded(ValueError):
    pass


class IngressLimitExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class MinerRuntime:
    wallet: Any
    hotkey_ss58: str
    signature_scheme: str
    translator: Translator
    video_fetcher: VideoFetcher
    allowed_validator_hotkeys: frozenset[str]
    authenticator: RequestAuthenticator
    limits: Limits
    scoring_policy_sha256: str
    response_deadline_blocks: int
    resource_ledger: SQLiteMinerResourceLedger
    window_authority: MinerWindowAuthority
    model_revision: str | None = None
    finality_service: DurableGrandpaFinalityPort | None = field(
        default=None,
        repr=False,
        compare=False,
    )
    inference_semaphore: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(1),
        repr=False,
        compare=False,
    )
    work_semaphore: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(1),
        repr=False,
        compare=False,
    )
    preauth_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock,
        repr=False,
        compare=False,
    )
    active_preauth_tokens: set[object] = field(
        default_factory=set,
        repr=False,
        compare=False,
    )
    maximum_preauth_concurrency: int = field(
        init=False,
        repr=False,
        compare=False,
    )
    ingress_lock: asyncio.Lock = field(
        default_factory=asyncio.Lock,
        repr=False,
        compare=False,
    )
    active_ingress_accounts: dict[str, int] = field(
        default_factory=dict,
        repr=False,
        compare=False,
    )
    allowed_validator_accounts: tuple[tuple[str, str], ...] = field(
        init=False,
        repr=False,
        compare=False,
    )
    assignment_locks: WeakValueDictionary[str, asyncio.Lock] = field(
        default_factory=WeakValueDictionary,
        repr=False,
        compare=False,
    )
    validator_work_semaphores: WeakValueDictionary[str, asyncio.Semaphore] = field(
        default_factory=WeakValueDictionary,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        if re.fullmatch(r"[0-9a-f]{64}", self.scoring_policy_sha256) is None:
            raise ValueError("scoring policy hash must be lowercase SHA-256 hexadecimal")
        if (
            self.model_revision is not None
            and re.fullmatch(r"[0-9a-f]{64}", self.model_revision) is None
        ):
            raise ValueError("model revision must be a lowercase SHA-256 hex digest")
        if not isinstance(self.limits, Limits):
            raise TypeError("limits must be Limits")
        if not isinstance(self.resource_ledger, SQLiteMinerResourceLedger):
            raise TypeError("resource ledger must be the durable SQLite implementation")
        if not callable(getattr(self.window_authority, "authorize", None)):
            raise TypeError("window authority must implement request authorization")
        if self.finality_service is not None and not isinstance(
            self.finality_service, DurableGrandpaFinalityPort
        ):
            raise TypeError("finality service must be the durable GRANDPA implementation")
        if not self.allowed_validator_hotkeys:
            raise ValueError("at least one policy validator hotkey is required")
        from .encoding import account_id32

        account_pairs = [(account_id32(value), value) for value in self.allowed_validator_hotkeys]
        accounts = [account for account, _hotkey in account_pairs]
        if len(set(accounts)) != len(accounts):
            raise ValueError("validator allowlist contains duplicate accounts")
        object.__setattr__(
            self,
            "allowed_validator_accounts",
            tuple(sorted((account.hex(), hotkey) for account, hotkey in account_pairs)),
        )
        object.__setattr__(
            self,
            "maximum_preauth_concurrency",
            max(4, 2 * len(account_pairs)),
        )
        if self.limits.maximum_inference_concurrency < len(account_pairs):
            raise ValueError(
                "maximum inference concurrency must reserve one slot per policy validator"
            )
        if self.limits.maximum_inference_concurrency % len(account_pairs) != 0:
            raise ValueError(
                "maximum inference concurrency must be a multiple of the policy validator count"
            )
        if (
            isinstance(self.response_deadline_blocks, bool)
            or not isinstance(self.response_deadline_blocks, int)
            or self.response_deadline_blocks <= 0
        ):
            raise ValueError("response deadline blocks must be a positive integer")
        _preflight_hotkey_signing(
            self.wallet,
            hotkey_ss58=self.hotkey_ss58,
            expected_scheme=self.signature_scheme,
        )


async def _read_bounded_body(request: Request, maximum_bytes: int) -> bytes:
    _validate_declared_content_length(request, maximum_bytes)

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum_bytes:
            raise BodyLimitExceeded("request body exceeds the configured ceiling")
        body.extend(chunk)
    return bytes(body)


def _validate_declared_content_length(request: Request, maximum_bytes: int) -> None:
    content_length = request.headers.get("content-length")
    if content_length is None:
        return
    if not content_length.isdecimal() or content_length != str(int(content_length)):
        raise BodyLimitExceeded("invalid Content-Length")
    if int(content_length) > maximum_bytes:
        raise BodyLimitExceeded("request body exceeds the configured ceiling")


def _header_bytes(request: Request) -> int:
    headers = request.scope.get("headers", ())
    return sum(len(name) + len(value) + 4 for name, value in headers)


def _claimed_policy_validator(
    runtime: MinerRuntime,
    request: Request,
) -> tuple[str, str, dict[str, str], str]:
    """Parse one bounded auth header set without treating it as authenticated."""

    import bittensor as bt

    raw_headers = request.scope.get("headers", ())
    required_headers = (
        bt.http_auth.HEADER_VERSION,
        bt.http_auth.HEADER_HOTKEY,
        bt.http_auth.HEADER_RECEIVER,
        bt.http_auth.HEADER_NONCE,
        bt.http_auth.HEADER_SIGNATURE,
        REQUEST_BODY_SHA256_HEADER,
    )
    values = {
        name: _single_ascii_header(raw_headers, name, required=True) for name in required_headers
    }
    crypto = _single_ascii_header(
        raw_headers,
        bt.http_auth.HEADER_CRYPTO,
        required=False,
    )
    if crypto is not None:
        values[bt.http_auth.HEADER_CRYPTO] = crypto
    claimed = values[bt.http_auth.HEADER_HOTKEY]
    if claimed != claimed.strip():
        raise HTTPException(status_code=401, detail="invalid btauth sender header")
    from .encoding import account_id32

    try:
        account_hex = account_id32(claimed).hex()
    except ValueError as error:
        raise HTTPException(status_code=401, detail="invalid btauth sender header") from error
    canonical_hotkey = dict(runtime.allowed_validator_accounts).get(account_hex)
    if canonical_hotkey is None:
        raise HTTPException(status_code=403, detail="claimed caller is not allowed")
    body_sha256 = values.pop(REQUEST_BODY_SHA256_HEADER)
    return account_hex, canonical_hotkey, values, body_sha256


def _single_ascii_header(
    raw_headers: Any,
    name: str,
    *,
    required: bool,
) -> str | None:
    encoded_name = name.encode("ascii").lower()
    matches = [value for key, value in raw_headers if key.lower() == encoded_name]
    if not matches and not required:
        return None
    if len(matches) != 1 or not matches[0] or len(matches[0]) > 256:
        raise HTTPException(status_code=401, detail=f"invalid or duplicate {name}")
    try:
        return matches[0].decode("ascii")
    except UnicodeDecodeError as error:
        raise HTTPException(status_code=401, detail=f"invalid {name}") from error


@asynccontextmanager
async def _preauth_slot(runtime: MinerRuntime):
    """Bound identity-neutral signature checks before trusting a claimed sender.

    The caller intentionally performs no await inside this scope. This keeps an
    authenticated burst from queueing behind the small untrusted-ingress guard.
    """

    token = object()
    async with runtime.preauth_lock:
        if len(runtime.active_preauth_tokens) >= runtime.maximum_preauth_concurrency:
            raise IngressLimitExceeded("miner_preauth_busy")
        runtime.active_preauth_tokens.add(token)
    try:
        yield
    finally:
        async with runtime.preauth_lock:
            runtime.active_preauth_tokens.discard(token)


@asynccontextmanager
async def _authenticated_ingress_slot(
    runtime: MinerRuntime,
    validator_account_hex: str,
):
    """Admit the policy-bounded request burst without cross-validator starvation."""

    async with runtime.ingress_lock:
        per_validator_limit, total_limit = _authenticated_request_task_limits(runtime)
        active_for_validator = runtime.active_ingress_accounts.get(validator_account_hex, 0)
        if active_for_validator >= per_validator_limit:
            raise IngressLimitExceeded("validator_ingress_busy")
        if sum(runtime.active_ingress_accounts.values()) >= total_limit:
            raise IngressLimitExceeded("miner_ingress_busy")
        runtime.active_ingress_accounts[validator_account_hex] = active_for_validator + 1
    try:
        yield
    finally:
        async with runtime.ingress_lock:
            remaining = runtime.active_ingress_accounts.get(validator_account_hex, 0) - 1
            if remaining <= 0:
                runtime.active_ingress_accounts.pop(validator_account_hex, None)
            else:
                runtime.active_ingress_accounts[validator_account_hex] = remaining


def _authenticated_request_task_limits(runtime: MinerRuntime) -> tuple[int, int]:
    """Return per-validator and global bounds for simultaneous signed attempts."""

    transmissions = runtime.limits.maximum_request_transmissions_per_assignment
    per_validator = runtime.limits.maximum_assignments_per_validator_window * transmissions
    unique_total = min(
        runtime.limits.maximum_total_assignments_per_window,
        (
            runtime.limits.maximum_assignments_per_validator_window
            * len(runtime.allowed_validator_accounts)
        ),
    )
    return per_validator, unique_total * transmissions


def _identity(wallet: Any) -> tuple[str, str]:
    import bittensor as bt

    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme = bt.wallets.format_crypto_type(signer.crypto_type)
    if scheme not in {"sr25519", "ed25519"}:
        raise ValueError(f"unsupported miner hotkey signature scheme: {scheme}")
    return signer.ss58_address, scheme


def _preflight_hotkey_signing(
    wallet: Any,
    *,
    hotkey_ss58: str,
    expected_scheme: str,
) -> None:
    digest = hashlib.sha256(b"umi-miner-startup-signing-v1\0" + hotkey_ss58.encode()).digest()
    try:
        scheme, signature = sign_response_digest(wallet, digest)
    except Exception as error:
        raise RuntimeError("miner hotkey signing preflight failed") from error
    if scheme != expected_scheme or not verify_response_signature(
        digest,
        hotkey_ss58=hotkey_ss58,
        scheme=scheme,
        signature=signature,
    ):
        raise RuntimeError("miner hotkey signing preflight did not verify")


def _plaintext(
    request: TranslationRequest,
    *,
    request_digest_hex: str,
    validator_hotkey: str,
    miner_hotkey: str,
    status: str,
    received_video_sha256: str | None,
    hypothesis: str | None,
    model_revision: str | None,
    error_code: str | None,
) -> ResponsePlaintext:
    return ResponsePlaintext.model_validate(
        {
            "schema": RESPONSE_PLAINTEXT_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": request.window_id,
            "batch_id": request.batch_id,
            "challenge_id": request.challenge_id,
            "request_digest": request_digest_hex,
            "issued_block_hash": request.issued_block_hash,
            "validator_hotkey": validator_hotkey,
            "serving_hotkey": miner_hotkey,
            "status": status,
            "received_video_sha256": received_video_sha256,
            "hypothesis": hypothesis,
            "model_revision": model_revision,
            "error_code": error_code,
        }
    )


def _signed_envelope(
    runtime: MinerRuntime,
    request: TranslationRequest,
    plaintext: ResponsePlaintext,
) -> tuple[bytes, str]:
    sealed = seal_response(canonical_json_bytes(plaintext), reveal_round=request.reveal_round)
    envelope = ResponseEnvelope.model_validate(
        {
            "schema": RESPONSE_ENVELOPE_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window_id": request.window_id,
            "batch_id": request.batch_id,
            "challenge_id": request.challenge_id,
            "request_digest": plaintext.request_digest,
            "issued_block_hash": request.issued_block_hash,
            "validator_hotkey": plaintext.validator_hotkey,
            "serving_hotkey": runtime.hotkey_ss58,
            "response_tle_profile": RESPONSE_TLE_PROFILE,
            "response_reveal_round": sealed.reveal_round,
            "encrypted_response": sealed.portable_b64,
            "encrypted_response_sha256": sealed.sha256_hex,
            "signature_scheme": runtime.signature_scheme,
        }
    )
    scheme, signature = sign_response_digest(runtime.wallet, envelope)
    if scheme != runtime.signature_scheme:
        raise RuntimeError("miner hotkey signature scheme changed during the request")
    body = canonical_json_bytes(envelope)
    if len(body) > runtime.limits.maximum_response_body_bytes:
        raise EnvelopeLimitExceeded("signed response envelope exceeds the configured ceiling")
    return body, signature


def _seconds_until_round(reveal_round: int) -> float:
    import bittensor as bt

    return bt.timelock.reveal_time(reveal_round).timestamp() - time.time()


def _validate_cached_response(
    runtime: MinerRuntime,
    request: TranslationRequest,
    validator_hotkey: str,
    cached: CachedMinerResponse,
) -> None:
    """Re-verify durable response bytes before every retransmission."""

    try:
        envelope = ResponseEnvelope.model_validate_json(cached.body)
    except ValidationError as error:
        raise MinerResourceError("cached_response_invalid") from error
    if canonical_json_bytes(envelope) != cached.body:
        raise MinerResourceError("cached_response_noncanonical")
    expected = (
        envelope.window_id == request.window_id
        and envelope.batch_id == request.batch_id
        and envelope.challenge_id == request.challenge_id
        and envelope.request_digest == request_digest(request)
        and envelope.issued_block_hash == request.issued_block_hash
        and envelope.validator_hotkey == validator_hotkey
        and envelope.serving_hotkey == runtime.hotkey_ss58
        and envelope.response_reveal_round == request.reveal_round
        and envelope.signature_scheme == runtime.signature_scheme
    )
    if not expected or not verify_response_signature(
        envelope,
        hotkey_ss58=runtime.hotkey_ss58,
        scheme=envelope.signature_scheme,
        signature=cached.signature,
    ):
        raise MinerResourceError("cached_response_binding_invalid")


async def _translate(
    runtime: MinerRuntime,
    request: TranslationRequest,
    validator_hotkey: str,
    binding: MinerAssignmentBinding | None = None,
) -> ResponsePlaintext:
    async with (
        _validator_work_semaphore(runtime, validator_hotkey),
        runtime.work_semaphore,
    ):
        return await _translate_bounded(runtime, request, validator_hotkey, binding)


async def _translate_bounded(
    runtime: MinerRuntime,
    request: TranslationRequest,
    validator_hotkey: str,
    binding: MinerAssignmentBinding | None = None,
) -> ResponsePlaintext:
    digest = request_digest(request)
    if binding is None:
        binding = MinerAssignmentBinding.from_request(
            request,
            validator_hotkey=validator_hotkey,
            window_index=0,
        )
        runtime.resource_ledger.record_request(binding, observed_wire_bytes=0)
    video = runtime.resource_ledger.cached_video(binding)
    fetch_wait_deadline = (
        asyncio.get_running_loop().time() + runtime.limits.video_fetch_timeout_seconds
    )
    while video is None:
        try:
            fetch_operation = runtime.resource_ledger.begin_video_fetch(binding)
        except MinerResourceError as error:
            if (
                error.reason_code == "video_fetch_in_progress"
                and asyncio.get_running_loop().time() < fetch_wait_deadline
            ):
                await asyncio.sleep(0.01)
                video = runtime.resource_ledger.cached_video(binding)
                continue
            LOGGER.warning("video fetch resource limit for challenge %s", request.challenge_id)
            return _plaintext(
                request,
                request_digest_hex=digest,
                validator_hotkey=validator_hotkey,
                miner_hotkey=runtime.hotkey_ss58,
                status="error",
                received_video_sha256=None,
                hypothesis=None,
                model_revision=None,
                error_code="video_fetch_failed",
            )
        try:
            receipt_method = getattr(runtime.video_fetcher, "fetch_with_receipt", None)
            if receipt_method is None:
                video = await runtime.video_fetcher.fetch(request.video)
                fetch_result = VideoFetchResult(data=video, wire_bytes=len(video))
            else:
                fetch_result = await receipt_method(request.video)
                if not isinstance(fetch_result, VideoFetchResult):
                    raise TypeError("video fetch receipt has an invalid type")
                video = fetch_result.data
        except VideoFetchError as error:
            runtime.resource_ledger.finish_video_fetch(
                fetch_operation,
                observed_wire_bytes=error.wire_bytes,
                error_code="video_fetch_failed",
            )
            LOGGER.warning("video fetch failed for challenge %s", request.challenge_id)
            return _plaintext(
                request,
                request_digest_hex=digest,
                validator_hotkey=validator_hotkey,
                miner_hotkey=runtime.hotkey_ss58,
                status="error",
                received_video_sha256=None,
                hypothesis=None,
                model_revision=None,
                error_code="video_fetch_failed",
            )
        except asyncio.CancelledError:
            runtime.resource_ledger.abandon_video_fetch(
                fetch_operation,
                error_code="video_fetch_cancelled",
            )
            raise
        except Exception as error:
            runtime.resource_ledger.abandon_video_fetch(
                fetch_operation,
                error_code="video_fetch_internal_error",
            )
            LOGGER.warning(
                "video fetch backend failed for challenge %s: %s",
                request.challenge_id,
                type(error).__name__,
            )
            return _plaintext(
                request,
                request_digest_hex=digest,
                validator_hotkey=validator_hotkey,
                miner_hotkey=runtime.hotkey_ss58,
                status="error",
                received_video_sha256=None,
                hypothesis=None,
                model_revision=None,
                error_code="video_fetch_failed",
            )
        runtime.resource_ledger.finish_video_fetch(
            fetch_operation,
            observed_wire_bytes=fetch_result.wire_bytes,
            error_code=None,
            data=video,
        )

    try:
        async with _inference_slot(runtime):
            hypothesis = await asyncio.wait_for(
                runtime.translator.translate(video, request),
                timeout=runtime.limits.inference_timeout_seconds,
            )
    except Exception as error:
        LOGGER.warning(
            "translation backend failed for challenge %s: %s",
            request.challenge_id,
            type(error).__name__,
        )
        return _plaintext(
            request,
            request_digest_hex=digest,
            validator_hotkey=validator_hotkey,
            miner_hotkey=runtime.hotkey_ss58,
            status="error",
            received_video_sha256=request.video.sha256,
            hypothesis=None,
            model_revision=None,
            error_code="inference_failed",
        )

    if not isinstance(hypothesis, str):
        LOGGER.warning("translation backend returned a non-text result")
        return _plaintext(
            request,
            request_digest_hex=digest,
            validator_hotkey=validator_hotkey,
            miner_hotkey=runtime.hotkey_ss58,
            status="error",
            received_video_sha256=request.video.sha256,
            hypothesis=None,
            model_revision=None,
            error_code="inference_failed",
        )

    try:
        hypothesis_bytes = hypothesis.encode("utf-8")
    except UnicodeEncodeError:
        hypothesis_bytes = b""
    if (
        (not hypothesis_bytes and hypothesis != "")
        or len(hypothesis_bytes) > runtime.limits.maximum_hypothesis_utf8_bytes
        or normalized_token_count(hypothesis) > runtime.limits.maximum_hypothesis_tokens
        or normalized_grapheme_count(hypothesis) > runtime.limits.maximum_hypothesis_graphemes
    ):
        return _plaintext(
            request,
            request_digest_hex=digest,
            validator_hotkey=validator_hotkey,
            miner_hotkey=runtime.hotkey_ss58,
            status="error",
            received_video_sha256=request.video.sha256,
            hypothesis=None,
            model_revision=None,
            error_code="hypothesis_invalid",
        )
    success = _plaintext(
        request,
        request_digest_hex=digest,
        validator_hotkey=validator_hotkey,
        miner_hotkey=runtime.hotkey_ss58,
        status="ok",
        received_video_sha256=request.video.sha256,
        hypothesis=hypothesis,
        model_revision=runtime.model_revision,
        error_code=None,
    )
    if len(canonical_json_bytes(success)) <= runtime.limits.maximum_response_plaintext_bytes:
        return success
    return _plaintext(
        request,
        request_digest_hex=digest,
        validator_hotkey=validator_hotkey,
        miner_hotkey=runtime.hotkey_ss58,
        status="error",
        received_video_sha256=request.video.sha256,
        hypothesis=None,
        model_revision=None,
        error_code="hypothesis_invalid",
    )


def _assignment_lock(runtime: MinerRuntime, assignment_id: str) -> asyncio.Lock:
    lock = runtime.assignment_locks.get(assignment_id)
    if lock is None:
        lock = asyncio.Lock()
        runtime.assignment_locks[assignment_id] = lock
    return lock


def _validator_work_semaphore(
    runtime: MinerRuntime,
    validator_hotkey: str,
) -> asyncio.Semaphore:
    from .encoding import account_id32

    key = account_id32(validator_hotkey).hex()
    semaphore = runtime.validator_work_semaphores.get(key)
    if semaphore is None:
        validator_count = len(runtime.allowed_validator_accounts)
        capacity = runtime.limits.maximum_inference_concurrency // validator_count
        semaphore = asyncio.Semaphore(capacity)
        runtime.validator_work_semaphores[key] = semaphore
    return semaphore


@asynccontextmanager
async def _inference_slot(runtime: MinerRuntime):
    try:
        await asyncio.wait_for(
            runtime.inference_semaphore.acquire(),
            timeout=runtime.limits.inference_admission_timeout_seconds,
        )
    except asyncio.TimeoutError as error:
        raise RuntimeError("model inference capacity was unavailable") from error
    try:
        yield
    finally:
        runtime.inference_semaphore.release()


async def _finish_recorded_request(
    runtime: MinerRuntime,
    challenge: TranslationRequest,
    *,
    validator_hotkey: str,
    binding: MinerAssignmentBinding,
    cached: CachedMinerResponse | None,
) -> Response:
    import bittensor as bt

    current_round = bt.timelock.current_round()
    runtime.resource_ledger.prune_closed_video_cache(current_round)
    if current_round >= challenge.response_close_round:
        raise HTTPException(status_code=422, detail="response window has closed")
    if challenge.reveal_round <= current_round:
        raise HTTPException(
            status_code=422,
            detail="response reveal round is not in the future",
        )

    work_budget = (
        _seconds_until_round(challenge.response_close_round)
        - runtime.limits.response_seal_margin_seconds
    )
    if work_budget <= 0:
        raise HTTPException(status_code=422, detail="insufficient response-window budget")
    if cached is None:
        cached = runtime.resource_ledger.cached_response(binding)
    if cached is not None:
        _validate_cached_response(
            runtime,
            challenge,
            validator_hotkey,
            cached,
        )
        try:
            runtime.resource_ledger.record_response(
                binding,
                body=cached.body,
                signature=cached.signature,
            )
        except MinerResourceError as error:
            raise HTTPException(status_code=429, detail=error.reason_code) from error
        return Response(
            content=cached.body,
            media_type="application/json",
            headers={RESPONSE_SIGNATURE_HEADER: cached.signature},
        )
    try:
        plaintext = await asyncio.wait_for(
            _translate(runtime, challenge, validator_hotkey, binding),
            timeout=work_budget,
        )
    except asyncio.TimeoutError:
        plaintext = _plaintext(
            challenge,
            request_digest_hex=request_digest(challenge),
            validator_hotkey=validator_hotkey,
            miner_hotkey=runtime.hotkey_ss58,
            status="error",
            received_video_sha256=None,
            hypothesis=None,
            model_revision=None,
            error_code="response_deadline_exceeded",
        )

    if _seconds_until_round(challenge.response_close_round) <= 0:
        raise HTTPException(status_code=422, detail="response window closed during work")
    try:
        try:
            response_body, signature = _signed_envelope(runtime, challenge, plaintext)
        except EnvelopeLimitExceeded:
            plaintext = _plaintext(
                challenge,
                request_digest_hex=request_digest(challenge),
                validator_hotkey=validator_hotkey,
                miner_hotkey=runtime.hotkey_ss58,
                status="error",
                received_video_sha256=(
                    challenge.video.sha256 if plaintext.received_video_sha256 is not None else None
                ),
                hypothesis=None,
                model_revision=None,
                error_code="hypothesis_invalid",
            )
            response_body, signature = _signed_envelope(runtime, challenge, plaintext)
    except bt.timelock.TimelockError as error:
        raise HTTPException(
            status_code=422,
            detail="response reveal round elapsed before sealing",
        ) from error
    if _seconds_until_round(challenge.response_close_round) <= 0:
        raise HTTPException(status_code=422, detail="response window closed during sealing")
    try:
        runtime.resource_ledger.record_response(
            binding,
            body=response_body,
            signature=signature,
        )
    except MinerResourceError as error:
        raise HTTPException(status_code=429, detail=error.reason_code) from error
    return Response(
        content=response_body,
        media_type="application/json",
        headers={RESPONSE_SIGNATURE_HEADER: signature},
    )


def create_app(runtime: MinerRuntime) -> FastAPI:
    """Create the miner app without performing any chain mutation."""

    finality_task: asyncio.Task[None] | None = None
    finality_stop: asyncio.Event | None = None

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        nonlocal finality_stop, finality_task
        translator_lifecycle_entered = False
        try:
            translator_lifecycle_entered = True
            await _run_translator_lifecycle(runtime, "startup")
            if runtime.finality_service is not None:
                finality_stop = asyncio.Event()
                finality_task = asyncio.create_task(runtime.finality_service.run(finality_stop))
                await asyncio.sleep(0)
                if finality_task.done():
                    await finality_task
            yield
        finally:
            if finality_stop is not None:
                finality_stop.set()
            if finality_task is not None:
                with suppress(asyncio.CancelledError):
                    await finality_task
            if translator_lifecycle_entered:
                await _run_translator_lifecycle(runtime, "shutdown")

    app = FastAPI(title="UMI component miner", version="0.1.0", lifespan=lifespan)

    @app.get("/healthz")
    async def health() -> dict[str, object]:
        if runtime.finality_service is None:
            finality_status = "component_authority"
        elif finality_task is None:
            finality_status = "not_started"
        elif finality_task.done():
            finality_status = "failed" if finality_task.exception() is not None else "stopped"
        else:
            finality_status = "running"
        return {
            "ok": finality_status not in {"failed", "stopped"},
            "netuid": SAFETY_BOUNDARY.netuid,
            "translation_weights_active": False,
            "protocol_conformance": False,
            "runtime_mode": "inactive_shadow",
            "scoring_policy_sha256": runtime.scoring_policy_sha256,
            "model_revision": runtime.model_revision,
            "window_authority": type(runtime.window_authority).__name__,
            "finality_service": finality_status,
        }

    @app.post(TRANSLATE_PATH)
    async def translate(request: Request) -> Response:
        if _header_bytes(request) > runtime.limits.maximum_http_header_bytes:
            raise HTTPException(status_code=431, detail="request headers exceed the ceiling")
        try:
            _validate_declared_content_length(
                request,
                runtime.limits.maximum_request_body_bytes,
            )
        except BodyLimitExceeded as error:
            raise HTTPException(status_code=413, detail=str(error)) from error
        try:
            (
                validator_account_hex,
                validator_hotkey,
                auth_headers,
                declared_body_sha256,
            ) = _claimed_policy_validator(runtime, request)
            async with _preauth_slot(runtime):
                try:
                    caller = runtime.authenticator.verify_declared_body_digest(
                        auth_headers,
                        declared_body_sha256,
                        method=request.method,
                        path=wire_request_target(request.scope),
                    )
                except Exception as error:
                    import bittensor as bt

                    if isinstance(error, bt.http_auth.AuthError):
                        raise HTTPException(status_code=401, detail=str(error)) from error
                    raise
                from .encoding import account_id32

                if account_id32(caller.hotkey_ss58).hex() != validator_account_hex:
                    raise HTTPException(status_code=401, detail="authenticated caller changed")

            async with _authenticated_ingress_slot(runtime, validator_account_hex):
                try:
                    body = await asyncio.wait_for(
                        _read_bounded_body(
                            request,
                            runtime.limits.maximum_request_body_bytes,
                        ),
                        timeout=runtime.limits.request_body_timeout_seconds,
                    )
                except asyncio.TimeoutError as error:
                    raise HTTPException(
                        status_code=408,
                        detail="request body deadline exceeded",
                    ) from error
                except BodyLimitExceeded as error:
                    raise HTTPException(status_code=413, detail=str(error)) from error
                if hashlib.sha256(body).hexdigest() != declared_body_sha256:
                    raise HTTPException(
                        status_code=401,
                        detail="request body does not match its authenticated digest",
                    )
                try:
                    runtime.authenticator.commit_replay(caller)
                except NonceStoreAuthorizationError as error:
                    raise HTTPException(status_code=403, detail=error.reason_code) from error
                except NonceStoreCapacityError as error:
                    raise HTTPException(status_code=429, detail=error.reason_code) from error
                except NonceStoreError as error:
                    raise HTTPException(status_code=503, detail=error.reason_code) from error
                except Exception as error:
                    import bittensor as bt

                    if isinstance(error, bt.http_auth.AuthError):
                        raise HTTPException(status_code=401, detail=str(error)) from error
                    raise

                try:
                    challenge = TranslationRequest.model_validate_json(body)
                except ValidationError as error:
                    raise HTTPException(status_code=422, detail="invalid UMI request") from error
                canonical_request = canonical_json_bytes(challenge)
                if body != canonical_request:
                    raise HTTPException(
                        status_code=422,
                        detail="request JSON is not RFC 8785 canonical",
                    )
                if challenge.scoring_policy_hash != runtime.scoring_policy_sha256:
                    raise HTTPException(
                        status_code=422,
                        detail="request scoring policy does not match",
                    )
                if challenge.deadline_block != (
                    challenge.issued_block + runtime.response_deadline_blocks
                ):
                    raise HTTPException(
                        status_code=422,
                        detail="request block deadline does not match",
                    )

                try:
                    admission = await runtime.window_authority.authorize(challenge)
                except MinerAdmissionError as error:
                    status = 503 if error.retryable else 422
                    raise HTTPException(status_code=status, detail=error.reason_code) from error
                if (
                    not isinstance(admission, MinerWindowAdmission)
                    or admission.window_id != challenge.window_id
                    or admission.response_close_round != challenge.response_close_round
                    or admission.reveal_round != challenge.reveal_round
                ):
                    raise HTTPException(status_code=503, detail="window_authority_invalid")

                binding = MinerAssignmentBinding.from_request(
                    challenge,
                    validator_hotkey=validator_hotkey,
                    window_index=admission.window_index,
                )
                try:
                    import bittensor as bt

                    cached = runtime.resource_ledger.record_request(
                        binding,
                        observed_wire_bytes=_header_bytes(request) + len(body),
                        current_round=bt.timelock.current_round(),
                    )
                except MinerResourceError as error:
                    raise HTTPException(status_code=429, detail=error.reason_code) from error
        except IngressLimitExceeded as error:
            raise HTTPException(status_code=429, detail=str(error)) from error
        async with _assignment_lock(runtime, binding.assignment_id):
            return await _finish_recorded_request(
                runtime,
                challenge,
                validator_hotkey=validator_hotkey,
                binding=binding,
                cached=cached,
            )

    return app


async def _run_translator_lifecycle(runtime: MinerRuntime, operation: str) -> None:
    hook = getattr(runtime.translator, operation, None)
    if hook is None:
        return
    if not callable(hook):
        raise RuntimeError(f"translator {operation} hook is invalid")
    await asyncio.wait_for(
        hook(),
        timeout=runtime.limits.backend_lifecycle_timeout_seconds,
    )


def build_runtime(args: argparse.Namespace) -> MinerRuntime:
    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
    hotkey_ss58, scheme = _identity(wallet)
    policy = _load_policy(args.policy)
    policy_hash = scoring_policy_hash(policy)
    allowed_validator_hotkeys = frozenset(
        item.validator_hotkey for item in policy.validator_registry
    )
    inference_concurrency = _effective_inference_concurrency(
        args.max_inference_concurrency,
        validator_count=len(allowed_validator_hotkeys),
    )
    if (
        args.model_revision is not None
        and re.fullmatch(r"[0-9a-f]{64}", args.model_revision) is None
    ):
        raise ValueError("model revision must be a lowercase SHA-256 hex digest")
    if args.translator_unix_socket is not None and args.allow_unsafe_sync_translator:
        raise ValueError("the unsafe synchronous opt-in applies only to module translators")
    limits = Limits.from_policy(
        policy,
        inference_timeout_seconds=args.inference_timeout,
        backend_lifecycle_timeout_seconds=args.backend_lifecycle_timeout,
        inference_admission_timeout_seconds=args.inference_admission_timeout,
        maximum_inference_concurrency=inference_concurrency,
        request_body_timeout_seconds=args.request_body_timeout,
    )
    fetcher = HttpVideoFetcher(
        allowed_origins=frozenset(args.video_origin),
        maximum_clip_size_bytes=limits.maximum_clip_size_bytes,
        maximum_http_header_bytes=limits.maximum_http_header_bytes,
        timeout_seconds=limits.video_fetch_timeout_seconds,
    )
    authenticator = RequestAuthenticator.sqlite(
        hotkey_ss58,
        args.nonce_db,
        max_age_seconds=limits.btauth_max_age_seconds,
        allowed_skew_seconds=limits.btauth_allowed_skew_seconds,
        allowed_hotkeys=allowed_validator_hotkeys,
        maximum_nonces_per_hotkey=limits.maximum_nonce_rows_per_validator,
        maximum_total_nonces=limits.maximum_nonce_rows_total,
        maximum_database_bytes=limits.maximum_nonce_database_bytes,
    )
    finality_pin = policy.implementation_pins.finality_verifier
    if finality_pin is None:
        raise ValueError("miner live policy is missing its finality-verifier pin")
    finality = DurableGrandpaFinalityPort.from_policy(
        policy,
        target_triple=args.target_triple,
        binary_path=args.finality_verifier_binary,
        chain_spec_path=args.finality_chain_spec,
        state_path=args.finality_state,
        initial_minimum_finalized_block=max(
            finality_pin.bootstrap_block_number,
            policy.activation_block - 1,
        ),
    )
    translator = _build_translator(
        args,
        limits=limits,
        scoring_policy_sha256=policy_hash,
        validator_count=len(allowed_validator_hotkeys),
    )
    return MinerRuntime(
        wallet=wallet,
        hotkey_ss58=hotkey_ss58,
        signature_scheme=scheme,
        translator=translator,
        video_fetcher=fetcher,
        allowed_validator_hotkeys=allowed_validator_hotkeys,
        authenticator=authenticator,
        limits=limits,
        scoring_policy_sha256=policy_hash,
        response_deadline_blocks=(
            policy.clock.issue_allowance_seconds
            + policy.clock.response_window_seconds
            + policy.clock.target_block_interval_seconds
            - 1
        )
        // policy.clock.target_block_interval_seconds,
        resource_ledger=SQLiteMinerResourceLedger(
            args.assignment_db,
            miner_hotkey=hotkey_ss58,
            scoring_policy_sha256=policy_hash,
            limits=limits,
        ),
        window_authority=ProofBackedMinerWindowAuthority(
            policy=policy,
            finalized_blocks=finality,
        ),
        model_revision=args.model_revision,
        finality_service=finality,
        inference_semaphore=asyncio.Semaphore(limits.maximum_inference_concurrency),
        work_semaphore=asyncio.Semaphore(limits.maximum_inference_concurrency),
    )


def _build_translator(
    args: argparse.Namespace,
    *,
    limits: Limits,
    scoring_policy_sha256: str,
    validator_count: int,
) -> Translator:
    """Construct the configured backend and any explicit semantic-sharing layer."""

    sharing = args.coalesce_window_video_inference
    backend_workers = args.max_backend_workers
    if args.translator_unix_socket is not None:
        if sharing or backend_workers is not None:
            raise ValueError("window-video coalescing is limited to in-process translators")
        return UnixSocketTranslator(
            socket_path=args.translator_unix_socket,
            maximum_request_metadata_bytes=limits.maximum_request_body_bytes,
            maximum_response_bytes=limits.maximum_hypothesis_utf8_bytes,
            expected_model_revision=args.model_revision,
            expected_scoring_policy_sha256=scoring_policy_sha256,
            required_validator_slots=validator_count,
            maximum_inference_seconds=limits.inference_timeout_seconds,
        )

    backend = load_translator(
        args.translator,
        maximum_concurrency=limits.maximum_inference_concurrency,
        allow_synchronous=args.allow_unsafe_sync_translator,
        expected_model_revision=args.model_revision,
    )
    if not sharing:
        if backend_workers is not None:
            raise ValueError("--max-backend-workers requires --coalesce-window-video-inference")
        return backend
    if args.model_revision is None:
        raise ValueError("window-video coalescing requires a bound model revision")
    if backend_workers is None:
        raise ValueError("window-video coalescing requires --max-backend-workers")
    if isinstance(backend_workers, bool) or backend_workers <= 0:
        raise ValueError("maximum backend workers must be a positive integer")
    if backend_workers > limits.maximum_inference_concurrency:
        raise ValueError("maximum backend workers cannot exceed outer inference concurrency")
    return WindowCoalescingTranslator(
        backend,
        model_revision=args.model_revision,
        maximum_workers=backend_workers,
        maximum_window_keys=limits.maximum_unique_videos_per_validator_window,
        maximum_inference_seconds=limits.inference_timeout_seconds,
    )


def _effective_inference_concurrency(
    requested: int | None,
    *,
    validator_count: int,
) -> int:
    """Reserve one independently schedulable inference slot per validator."""

    if isinstance(validator_count, bool) or not isinstance(validator_count, int):
        raise TypeError("validator_count must be an integer")
    if validator_count <= 0:
        raise ValueError("validator_count must be positive")
    if requested is None:
        return validator_count
    if isinstance(requested, bool) or not isinstance(requested, int) or requested <= 0:
        raise ValueError("maximum inference concurrency must be a positive integer")
    if requested < validator_count:
        raise ValueError("maximum inference concurrency must reserve one slot per policy validator")
    if requested % validator_count != 0:
        raise ValueError(
            "maximum inference concurrency must be a multiple of the policy validator count"
        )
    return requested


def _load_policy(path: str | Path) -> ScoringPolicy:
    """Load an exact canonical policy without following a final symlink."""

    resolved = Path(path).expanduser().absolute()
    try:
        parent = resolved.parent.lstat()
    except OSError as error:
        raise RuntimeError("scoring policy parent is unavailable") from error
    if (
        stat.S_ISLNK(parent.st_mode)
        or not stat.S_ISDIR(parent.st_mode)
        or parent.st_uid != os.geteuid()
        or parent.st_mode & 0o022
    ):
        raise RuntimeError("scoring policy parent is unsafe")
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(resolved, flags)
    except OSError as error:
        raise RuntimeError("scoring policy could not be opened safely") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
        ):
            raise RuntimeError("scoring policy file is unsafe")
        if metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
            raise RuntimeError("scoring policy file size is invalid")
        encoded = bytearray()
        while chunk := os.read(descriptor, min(1024 * 1024 + 1 - len(encoded), 64 * 1024)):
            encoded.extend(chunk)
            if len(encoded) > 1024 * 1024:
                raise RuntimeError("scoring policy exceeds the startup ceiling")
        after = os.fstat(descriptor)
        before_identity = (
            metadata.st_dev,
            metadata.st_ino,
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ctime_ns,
        )
        after_identity = (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        )
        if before_identity != after_identity or len(encoded) != metadata.st_size:
            raise RuntimeError("scoring policy changed while it was read")
    finally:
        os.close(descriptor)
    raw = bytes(encoded)
    try:
        policy = ScoringPolicy.model_validate_json(raw)
    except (ValidationError, ValueError) as error:
        raise RuntimeError("scoring policy is invalid") from error
    if canonical_json_bytes(policy) != raw:
        raise RuntimeError("scoring policy is not RFC 8785 canonical")
    validate_scoring_runtime(policy)
    return policy


def _uvicorn_limits(runtime: MinerRuntime) -> dict[str, int]:
    """Bound open request tasks outside the application-level ingress gate."""

    _per_validator_limit, authenticated_limit = _authenticated_request_task_limits(runtime)
    connection_limit = authenticated_limit + runtime.maximum_preauth_concurrency + 4
    return {
        "limit_concurrency": connection_limit,
        "backlog": 2 * connection_limit,
        "timeout_keep_alive": 5,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the UMI inactive-shadow miner")
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    parser.add_argument("--policy", required=True, help="canonical inactive scoring policy")
    parser.add_argument(
        "--target-triple",
        required=True,
        help="target key used by the policy's finality-verifier release map",
    )
    parser.add_argument("--finality-verifier-binary", required=True)
    parser.add_argument("--finality-chain-spec", required=True)
    parser.add_argument("--finality-state", required=True)
    translator = parser.add_mutually_exclusive_group(required=True)
    translator.add_argument("--translator", help="trusted in-process module:callable backend")
    translator.add_argument(
        "--translator-unix-socket",
        help="private mode-0600 Unix socket for an isolated async model sidecar",
    )
    parser.add_argument(
        "--allow-unsafe-sync-translator",
        action="store_true",
        help="allow a synchronous backend whose hung worker thread cannot be terminated",
    )
    parser.add_argument(
        "--video-origin",
        action="append",
        required=True,
        help="exact allowed HTTPS origin; repeat as needed",
    )
    parser.add_argument("--model-revision")
    parser.add_argument("--request-body-timeout", type=float, default=5.0)
    parser.add_argument("--backend-lifecycle-timeout", type=float, default=60.0)
    parser.add_argument("--inference-admission-timeout", type=float, default=10.0)
    parser.add_argument("--inference-timeout", type=float, default=120.0)
    parser.add_argument(
        "--max-inference-concurrency",
        type=int,
        default=None,
        help=(
            "total runnable model slots (default: policy validator count; explicit values "
            "must be a positive multiple of that count)"
        ),
    )
    parser.add_argument(
        "--coalesce-window-video-inference",
        action="store_true",
        help=(
            "explicitly assert that the in-process backend depends only on the signed "
            "window/video/task/model projection and share identical work across validators"
        ),
    )
    parser.add_argument(
        "--max-backend-workers",
        type=int,
        default=None,
        help="unique model jobs allowed when window-video coalescing is enabled",
    )
    parser.add_argument(
        "--nonce-db",
        required=True,
        help="SQLite nonce database owned by this single miner protocol process",
    )
    parser.add_argument(
        "--assignment-db",
        required=True,
        help="durable resource-counter and encrypted-response cache database",
    )
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument("--log-level", default="INFO")
    return parser


def main() -> None:
    args = _parser().parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level.upper()))
    runtime = build_runtime(args)
    import uvicorn

    try:
        uvicorn.run(
            create_app(runtime),
            host=args.listen_host,
            port=args.port,
            **_uvicorn_limits(runtime),
        )
    finally:
        runtime.resource_ledger.close()


if __name__ == "__main__":
    main()
