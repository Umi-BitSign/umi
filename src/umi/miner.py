"""UMI miner HTTP service for the initial no-weight component slice."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import re
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, HTTPException, Request, Response
from pydantic import ValidationError

from .auth import RequestAuthenticator, wire_request_target
from .backends import Translator, load_translator
from .config import SAFETY_BOUNDARY, Limits
from .crypto import seal_response, sign_response_digest, verify_response_signature
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
from .video import HttpVideoFetcher, VideoFetcher, VideoFetchError

LOGGER = logging.getLogger("umi.miner")
TRANSLATE_PATH = "/v1/translate"
RESPONSE_SIGNATURE_HEADER = "X-UMI-Signature"


class BodyLimitExceeded(ValueError):
    pass


class EnvelopeLimitExceeded(ValueError):
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
    model_revision: str | None = None
    inference_semaphore: asyncio.Semaphore = field(
        default_factory=lambda: asyncio.Semaphore(1),
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        _preflight_hotkey_signing(
            self.wallet,
            hotkey_ss58=self.hotkey_ss58,
            expected_scheme=self.signature_scheme,
        )


async def _read_bounded_body(request: Request, maximum_bytes: int) -> bytes:
    content_length = request.headers.get("content-length")
    if content_length is not None:
        try:
            declared = int(content_length)
        except ValueError as error:
            raise BodyLimitExceeded("invalid Content-Length") from error
        if declared < 0 or declared > maximum_bytes:
            raise BodyLimitExceeded("request body exceeds the configured ceiling")

    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > maximum_bytes:
            raise BodyLimitExceeded("request body exceeds the configured ceiling")
        body.extend(chunk)
    return bytes(body)


def _header_bytes(request: Request) -> int:
    headers = request.scope.get("headers", ())
    return sum(len(name) + len(value) + 4 for name, value in headers)


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


async def _translate(
    runtime: MinerRuntime,
    request: TranslationRequest,
    validator_hotkey: str,
) -> ResponsePlaintext:
    digest = request_digest(request)
    try:
        video = await runtime.video_fetcher.fetch(request.video)
    except VideoFetchError:
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

    try:
        async with runtime.inference_semaphore:
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

    try:
        hypothesis_bytes = hypothesis.encode("utf-8")
    except UnicodeEncodeError:
        hypothesis_bytes = b""
    if (
        (not hypothesis_bytes and hypothesis != "")
        or len(hypothesis_bytes) > runtime.limits.maximum_hypothesis_utf8_bytes
        or normalized_token_count(hypothesis) > 128
        or normalized_grapheme_count(hypothesis) > 512
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


def create_app(runtime: MinerRuntime) -> FastAPI:
    """Create the miner app without performing any chain mutation."""

    app = FastAPI(title="UMI component miner", version="0.1.0")

    @app.get("/healthz")
    async def health() -> dict[str, object]:
        return {
            "ok": True,
            "netuid": SAFETY_BOUNDARY.netuid,
            "translation_weights_active": False,
            "protocol_conformance": False,
        }

    @app.post(TRANSLATE_PATH)
    async def translate(request: Request) -> Response:
        if _header_bytes(request) > runtime.limits.maximum_http_header_bytes:
            raise HTTPException(status_code=431, detail="request headers exceed the ceiling")
        try:
            body = await _read_bounded_body(request, runtime.limits.maximum_request_body_bytes)
        except BodyLimitExceeded as error:
            raise HTTPException(status_code=413, detail=str(error)) from error

        try:
            caller = runtime.authenticator.verify(
                request.headers,
                body,
                method=request.method,
                path=wire_request_target(request.scope),
            )
        except Exception as error:
            import bittensor as bt

            if isinstance(error, bt.http_auth.AuthError):
                raise HTTPException(status_code=401, detail=str(error)) from error
            raise
        if caller.hotkey_ss58 not in runtime.allowed_validator_hotkeys:
            raise HTTPException(status_code=403, detail="authenticated caller is not allowed")

        try:
            challenge = TranslationRequest.model_validate_json(body)
        except ValidationError as error:
            raise HTTPException(status_code=422, detail="invalid UMI request") from error
        canonical_request = canonical_json_bytes(challenge)
        if body != canonical_request:
            raise HTTPException(status_code=422, detail="request JSON is not RFC 8785 canonical")

        import bittensor as bt

        current_round = bt.timelock.current_round()
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
        try:
            plaintext = await asyncio.wait_for(
                _translate(runtime, challenge, caller.hotkey_ss58),
                timeout=work_budget,
            )
        except asyncio.TimeoutError:
            plaintext = _plaintext(
                challenge,
                request_digest_hex=request_digest(challenge),
                validator_hotkey=caller.hotkey_ss58,
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
                    validator_hotkey=caller.hotkey_ss58,
                    miner_hotkey=runtime.hotkey_ss58,
                    status="error",
                    received_video_sha256=(
                        challenge.video.sha256
                        if plaintext.received_video_sha256 is not None
                        else None
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
        return Response(
            content=response_body,
            media_type="application/json",
            headers={RESPONSE_SIGNATURE_HEADER: signature},
        )

    return app


def build_runtime(args: argparse.Namespace) -> MinerRuntime:
    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
    hotkey_ss58, scheme = _identity(wallet)
    if (
        args.model_revision is not None
        and re.fullmatch(r"[0-9a-f]{64}", args.model_revision) is None
    ):
        raise ValueError("model revision must be a lowercase SHA-256 hex digest")
    limits = Limits(
        inference_timeout_seconds=args.inference_timeout,
        maximum_inference_concurrency=args.max_inference_concurrency,
    )
    fetcher = HttpVideoFetcher(
        allowed_hosts=frozenset(args.video_host),
        allowed_ports=frozenset(args.video_port or (443,)),
        maximum_clip_size_bytes=limits.maximum_clip_size_bytes,
        maximum_http_header_bytes=limits.maximum_http_header_bytes,
        timeout_seconds=limits.video_fetch_timeout_seconds,
    )
    authenticator = (
        RequestAuthenticator.sqlite(hotkey_ss58, args.nonce_db)
        if args.nonce_db is not None
        else RequestAuthenticator.in_memory(hotkey_ss58)
    )
    return MinerRuntime(
        wallet=wallet,
        hotkey_ss58=hotkey_ss58,
        signature_scheme=scheme,
        translator=load_translator(
            args.translator,
            maximum_concurrency=limits.maximum_inference_concurrency,
        ),
        video_fetcher=fetcher,
        allowed_validator_hotkeys=frozenset(args.validator_hotkey),
        authenticator=authenticator,
        limits=limits,
        model_revision=args.model_revision,
        inference_semaphore=asyncio.Semaphore(limits.maximum_inference_concurrency),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Serve the UMI no-weight component miner")
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    parser.add_argument("--translator", required=True, help="trusted module:callable backend")
    parser.add_argument("--validator-hotkey", action="append", required=True)
    parser.add_argument("--video-host", action="append", required=True)
    parser.add_argument(
        "--video-port",
        action="append",
        type=int,
        help="allowed HTTPS port; repeat as needed (default: 443)",
    )
    parser.add_argument("--model-revision")
    parser.add_argument("--inference-timeout", type=float, default=120.0)
    parser.add_argument("--max-inference-concurrency", type=int, default=1)
    parser.add_argument(
        "--nonce-db",
        help="SQLite nonce database shared by same-host miner processes",
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

    uvicorn.run(create_app(runtime), host=args.listen_host, port=args.port)


if __name__ == "__main__":
    main()
