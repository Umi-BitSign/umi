"""Public HTTP miner for one exact, weight-disabled component-pilot case."""

from __future__ import annotations

import argparse
import ipaddress
import logging
import re
import sys
from collections.abc import Sequence
from pathlib import Path
from urllib.parse import urlsplit

from .auth import RequestAuthenticator
from .backends import UnixSocketTranslator, load_translator
from .component import PreparedCase, load_case
from .config import Limits
from .encoding import account_id32
from .miner import MinerRuntime, _identity, _uvicorn_limits, create_app
from .miner_admission import ExactComponentWindowAuthority
from .miner_resources import SQLiteMinerResourceLedger
from .public_pilot_campaign import load_public_pilot_campaign
from .public_pilot_readiness import (
    parse_public_pilot_readiness_payload_token,
    public_pilot_readiness_marker,
    sign_public_pilot_readiness,
)
from .video import HttpVideoFetcher

_SHA256 = re.compile(r"[0-9a-f]{64}")


def _normalized_https_origin(value: str) -> str:
    """Return one canonical public-pilot video origin."""

    if not isinstance(value, str) or not value:
        raise ValueError("video origin must be nonempty text")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("video origin contains a control character")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError("video origin is invalid") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("video origin must be an HTTPS origin without credentials or a path")
    try:
        hostname = parsed.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError as error:
        raise ValueError("video origin hostname is invalid") from error
    if not hostname:
        raise ValueError("video origin hostname is invalid")
    effective_port = port or 443
    if not 1 <= effective_port <= 65_535:
        raise ValueError("video origin port is invalid")
    authority = f"[{hostname}]" if ":" in hostname else hostname
    if effective_port != 443:
        authority += f":{effective_port}"
    return f"https://{authority}"


def _case_video_origins(prepared: PreparedCase) -> frozenset[str]:
    origins: set[str] = set()
    for request in prepared.requests:
        parsed = urlsplit(str(request.video.url))
        if parsed.hostname is None:  # TranslationRequest validation is stricter; defensive only.
            raise ValueError("component request video URL has no hostname")
        authority = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        effective_port = parsed.port or 443
        if effective_port != 443:
            authority += f":{effective_port}"
        origins.add(_normalized_https_origin(f"https://{authority}"))
    return frozenset(origins)


def _validate_case(prepared: PreparedCase) -> tuple[str, int]:
    """Validate the shared runtime bindings in one already sealed case."""

    if not isinstance(prepared, PreparedCase) or not prepared.requests:
        raise ValueError("public pilot requires a nonempty prepared case")
    shared_fields = (
        "window_id",
        "batch_id",
        "scoring_policy_hash",
        "response_close_round",
        "reveal_round",
    )
    first = prepared.requests[0]
    for request in prepared.requests:
        if any(getattr(request, field) != getattr(first, field) for field in shared_fields):
            raise ValueError("public pilot requests disagree on shared case bindings")
    deadline_intervals = {
        request.deadline_block - request.issued_block for request in prepared.requests
    }
    if len(deadline_intervals) != 1 or next(iter(deadline_intervals)) <= 0:
        raise ValueError("public pilot requests require one positive block deadline interval")
    if _SHA256.fullmatch(first.scoring_policy_hash) is None:
        raise ValueError("public pilot scoring policy hash is invalid")

    import bittensor as bt

    if first.response_close_round <= bt.timelock.current_round():
        raise ValueError("public pilot response window has already closed")
    if first.reveal_round <= first.response_close_round:
        raise ValueError("public pilot reveal round must follow response close")
    return first.scoring_policy_hash, next(iter(deadline_intervals))


def _require_loopback(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError as error:
        raise ValueError("public pilot miner must listen on a literal loopback address") from error
    if not address.is_loopback:
        raise ValueError("public pilot miner must stay behind a loopback TLS proxy")
    return address.compressed


def build_runtime(args: argparse.Namespace) -> MinerRuntime:
    """Build a bounded runtime authorized for one exact prepared case."""

    if _SHA256.fullmatch(args.model_revision) is None:
        raise ValueError("model revision must be a lowercase SHA-256 digest")
    campaign = load_public_pilot_campaign(args.case)
    prepared = load_case(args.case)
    scoring_policy_sha256, response_deadline_blocks = _validate_case(prepared)
    if (
        campaign.response_close_round != prepared.requests[0].response_close_round
        or campaign.reveal_round != prepared.requests[0].reveal_round
    ):
        raise ValueError("public-pilot campaign rounds do not match the loaded case")

    declared_origins = tuple(_normalized_https_origin(value) for value in args.video_origin)
    if len(declared_origins) != len(set(declared_origins)):
        raise ValueError("video origins must not contain duplicates")
    case_origins = _case_video_origins(prepared)
    if frozenset(declared_origins) != case_origins:
        raise ValueError("video origins must exactly match the prepared case")

    import bittensor as bt

    wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
    hotkey_ss58, signature_scheme = _identity(wallet)
    if account_id32(hotkey_ss58) != account_id32(campaign.expected_miner_hotkey):
        raise ValueError("wallet hotkey does not match the campaign's expected miner hotkey")
    if account_id32(hotkey_ss58) == account_id32(campaign.coordinator_hotkey):
        raise ValueError("public pilot validator and miner hotkeys must be distinct")

    limits = Limits(
        request_body_timeout_seconds=args.request_body_timeout,
        video_fetch_timeout_seconds=args.video_fetch_timeout,
        backend_lifecycle_timeout_seconds=args.backend_lifecycle_timeout,
        inference_admission_timeout_seconds=args.inference_admission_timeout,
        inference_timeout_seconds=args.inference_timeout,
        maximum_inference_concurrency=1,
    )
    if args.translator_unix_socket is None:
        translator = load_translator(
            args.translator,
            maximum_concurrency=1,
            allow_synchronous=False,
            expected_model_revision=args.model_revision,
        )
    else:
        translator = UnixSocketTranslator(
            socket_path=args.translator_unix_socket,
            maximum_request_metadata_bytes=limits.maximum_request_body_bytes,
            maximum_response_bytes=limits.maximum_hypothesis_utf8_bytes,
            expected_model_revision=args.model_revision,
            expected_scoring_policy_sha256=scoring_policy_sha256,
            required_validator_slots=1,
            maximum_inference_seconds=limits.inference_timeout_seconds,
        )

    ledger = SQLiteMinerResourceLedger(
        args.assignment_db,
        miner_hotkey=hotkey_ss58,
        scoring_policy_sha256=scoring_policy_sha256,
        limits=limits,
    )
    try:
        return MinerRuntime(
            wallet=wallet,
            hotkey_ss58=hotkey_ss58,
            signature_scheme=signature_scheme,
            translator=translator,
            video_fetcher=HttpVideoFetcher(
                allowed_origins=case_origins,
                maximum_clip_size_bytes=limits.maximum_clip_size_bytes,
                maximum_http_header_bytes=limits.maximum_http_header_bytes,
                timeout_seconds=limits.video_fetch_timeout_seconds,
            ),
            allowed_validator_hotkeys=frozenset({campaign.coordinator_hotkey}),
            authenticator=RequestAuthenticator.sqlite(
                hotkey_ss58,
                args.nonce_db,
                max_age_seconds=limits.btauth_max_age_seconds,
                allowed_skew_seconds=limits.btauth_allowed_skew_seconds,
                allowed_hotkeys=(campaign.coordinator_hotkey,),
                maximum_nonces_per_hotkey=limits.maximum_nonce_rows_per_validator,
                maximum_total_nonces=limits.maximum_nonce_rows_total,
                maximum_database_bytes=limits.maximum_nonce_database_bytes,
            ),
            limits=limits,
            scoring_policy_sha256=scoring_policy_sha256,
            response_deadline_blocks=response_deadline_blocks,
            resource_ledger=ledger,
            window_authority=ExactComponentWindowAuthority(prepared.requests),
            model_revision=args.model_revision,
            runtime_mode="public_component_pilot",
        )
    except BaseException:
        ledger.close()
        raise


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=("Serve one exact UMI component-pilot case on loopback for a public TLS proxy"),
        epilog=(
            "Use 'umi-public-pilot-miner authorize --help' to sign a public-pilot "
            "readiness challenge."
        ),
    )
    parser.add_argument("--case", type=Path, required=True, help="sealed prepared-case directory")
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    translator = parser.add_mutually_exclusive_group(required=True)
    translator.add_argument("--translator", help="trusted async module:callable backend")
    translator.add_argument(
        "--translator-unix-socket",
        help="private mode-0600 Unix socket for an isolated async model sidecar",
    )
    parser.add_argument("--model-revision", required=True)
    parser.add_argument(
        "--video-origin",
        action="append",
        required=True,
        help="exact case HTTPS video origin; repeat for each origin",
    )
    parser.add_argument("--nonce-db", required=True)
    parser.add_argument("--assignment-db", required=True)
    parser.add_argument("--request-body-timeout", type=float, default=5.0)
    parser.add_argument("--video-fetch-timeout", type=float, default=30.0)
    parser.add_argument("--backend-lifecycle-timeout", type=float, default=60.0)
    parser.add_argument("--inference-admission-timeout", type=float, default=10.0)
    parser.add_argument("--inference-timeout", type=float, default=180.0)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8091)
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="INFO",
    )
    return parser


def _authorize_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="umi-public-pilot-miner authorize",
        description="Sign one exact public-pilot readiness challenge with the miner hotkey",
    )
    parser.add_argument(
        "--payload-token",
        required=True,
        help="unpadded base64url RFC8785 challenge payload from the coordinator",
    )
    parser.add_argument("--wallet-name", required=True)
    parser.add_argument("--hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    return parser


def _authorize(argv: Sequence[str]) -> None:
    parser = _authorize_parser()
    args = parser.parse_args(argv)
    try:
        payload = parse_public_pilot_readiness_payload_token(args.payload_token)

        import bittensor as bt

        wallet = bt.Wallet(name=args.wallet_name, hotkey=args.hotkey, path=args.wallet_path)
        proof = sign_public_pilot_readiness(payload, wallet=wallet)
        marker = public_pilot_readiness_marker(proof)
    except (OSError, RuntimeError, TypeError, ValueError) as error:
        parser.exit(2, f"public-pilot readiness authorization failed: {error}\n")
    print(marker, flush=True)


def main(argv: Sequence[str] | None = None) -> None:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments[:1] == ["authorize"]:
        _authorize(arguments[1:])
        return
    parser = _parser()
    args = parser.parse_args(arguments)
    try:
        args.listen_host = _require_loopback(args.listen_host)
        if isinstance(args.port, bool) or not 1 <= args.port <= 65_535:
            raise ValueError("port must be from 1 through 65535")
        runtime = build_runtime(args)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, f"public component-pilot miner failed: {error}\n")

    import uvicorn

    logging.basicConfig(level=getattr(logging, args.log_level))
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
