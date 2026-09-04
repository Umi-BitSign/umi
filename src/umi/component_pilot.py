"""One-shot real-model runner for a no-weight, nonconforming public pilot."""

from __future__ import annotations

import argparse
import asyncio
import re
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .audit import MAX_COMPONENT_MANIFEST_BYTES, _read_bounded_regular_file
from .auth import RequestAuthenticator
from .backends import Translator, load_translator
from .component import load_case, prepare_case
from .config import Limits
from .encoding import account_id32
from .miner import MinerRuntime, _identity, create_app
from .miner_admission import LocalComponentWindowAuthority
from .miner_resources import SQLiteMinerResourceLedger
from .protocol import canonical_json_bytes
from .validator import replay_bundle, run_component_case, score_summary
from .video import HttpVideoFetcher, VideoFetcher

_IN_PROCESS_MINER_ORIGIN = "http://component-pilot.invalid"


def validate_public_pilot_video_url(value: str) -> tuple[str, int]:
    """Validate a credential-free URL that is safe to retain in public evidence."""

    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in value):
        raise ValueError("public pilot video URLs must not contain control characters")
    try:
        parsed = urlsplit(value)
        port = parsed.port or 443
    except ValueError as error:
        raise ValueError("public pilot video URL is invalid") from error
    if parsed.scheme != "https" or parsed.hostname is None:
        raise ValueError("public pilot video URLs must use HTTPS")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("public pilot video URLs must not contain user information")
    # The exact request becomes immutable public evidence. Even an expired
    # presigned query can disclose account identifiers or bearer material.
    if "?" in value or "#" in value or parsed.query or parsed.fragment:
        raise ValueError("public pilot video URLs must not contain a query or fragment")
    return parsed.hostname.lower().rstrip("."), port


async def run_local_component_pilot(
    *,
    requests_path: Path,
    ground_truth_path: Path,
    output: Path,
    validator_wallet: Any,
    miner_wallet: Any,
    translator: Translator,
    video_fetcher: VideoFetcher,
    model_revision: str | None,
    request_timeout_seconds: float,
    reveal_timeout_seconds: float | None,
    inference_timeout_seconds: float,
    backend_lifecycle_timeout_seconds: float,
) -> tuple[Path, dict[str, Any]]:
    """Run one signed component pilot entirely in-process and replay its bundle."""

    request_bytes = _read_bounded_regular_file(requests_path, MAX_COMPONENT_MANIFEST_BYTES)
    ground_truth_bytes = _read_bounded_regular_file(
        ground_truth_path,
        MAX_COMPONENT_MANIFEST_BYTES,
    )
    with tempfile.TemporaryDirectory(prefix="umi-component-pilot-") as temporary:
        temporary_root = Path(temporary)
        request_snapshot = temporary_root / "requests.json"
        truth_snapshot = temporary_root / "ground-truth.json"
        request_snapshot.write_bytes(request_bytes)
        truth_snapshot.write_bytes(ground_truth_bytes)
        case_root = temporary_root / "case"
        prepare_case(request_snapshot, truth_snapshot, case_root)
        prepared = load_case(case_root)

        policy_hashes = {request.scoring_policy_hash for request in prepared.requests}
        deadline_blocks = {
            request.deadline_block - request.issued_block for request in prepared.requests
        }
        if len(policy_hashes) != 1 or len(deadline_blocks) != 1:
            raise ValueError("pilot requests require one policy hash and deadline interval")
        response_deadline_blocks = next(iter(deadline_blocks))
        if response_deadline_blocks <= 0:
            raise ValueError("pilot response deadline interval must be positive")
        scoring_policy_sha256 = next(iter(policy_hashes))

        miner_hotkey, signature_scheme = _identity(miner_wallet)
        validator_hotkey, _ = _identity(validator_wallet)
        if account_id32(validator_hotkey) == account_id32(miner_hotkey):
            raise ValueError("pilot validator and miner hotkeys must be distinct")
        limits = Limits(
            inference_timeout_seconds=inference_timeout_seconds,
            backend_lifecycle_timeout_seconds=backend_lifecycle_timeout_seconds,
        )
        ledger = SQLiteMinerResourceLedger(
            ":memory:",
            miner_hotkey=miner_hotkey,
            scoring_policy_sha256=scoring_policy_sha256,
            limits=limits,
        )
        runtime = MinerRuntime(
            wallet=miner_wallet,
            hotkey_ss58=miner_hotkey,
            signature_scheme=signature_scheme,
            translator=translator,
            video_fetcher=video_fetcher,
            allowed_validator_hotkeys=frozenset({validator_hotkey}),
            authenticator=RequestAuthenticator.in_memory(miner_hotkey),
            limits=limits,
            scoring_policy_sha256=scoring_policy_sha256,
            response_deadline_blocks=response_deadline_blocks,
            resource_ledger=ledger,
            window_authority=LocalComponentWindowAuthority(),
            model_revision=model_revision,
        )
        startup = getattr(translator, "startup", None)
        shutdown = getattr(translator, "shutdown", None)
        try:
            if startup is not None:
                await asyncio.wait_for(startup(), timeout=backend_lifecycle_timeout_seconds)
            manifest = await run_component_case(
                case_root,
                output,
                wallet=validator_wallet,
                miner_url=_IN_PROCESS_MINER_ORIGIN,
                miner_hotkey=miner_hotkey,
                request_timeout_seconds=request_timeout_seconds,
                reveal_timeout_seconds=reveal_timeout_seconds,
                transport=httpx.ASGITransport(app=create_app(runtime)),
            )
            scoring = replay_bundle(output)
            return manifest, scoring
        finally:
            if shutdown is not None:
                await asyncio.wait_for(shutdown(), timeout=backend_lifecycle_timeout_seconds)
            ledger.close()


def _video_origins(requests_path: Path) -> frozenset[str]:
    from .component import _parse_requests

    requests = _parse_requests(
        _read_bounded_regular_file(requests_path, MAX_COMPONENT_MANIFEST_BYTES)
    )
    origins: set[str] = set()
    for request in requests:
        host, port = validate_public_pilot_video_url(str(request.video.url))
        authority = f"[{host}]" if ":" in host else host
        if port != 443:
            authority += f":{port}"
        origins.add(f"https://{authority}")
    return frozenset(origins)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run a signed, replayable component_test_no_weight pilot"
    )
    parser.add_argument("--requests", type=Path, required=True)
    parser.add_argument("--ground-truth", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--validator-wallet-name", required=True)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--miner-wallet-name", required=True)
    parser.add_argument("--miner-hotkey", required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    parser.add_argument("--translator", required=True)
    parser.add_argument("--model-revision")
    parser.add_argument("--allow-unsafe-sync-translator", action="store_true")
    parser.add_argument("--request-timeout", type=float, default=30.0)
    parser.add_argument("--reveal-timeout", type=float)
    parser.add_argument("--video-fetch-timeout", type=float, default=30.0)
    parser.add_argument("--inference-timeout", type=float, default=180.0)
    parser.add_argument("--backend-lifecycle-timeout", type=float, default=60.0)
    return parser


def main() -> None:
    args = _parser().parse_args()
    if (
        args.model_revision is not None
        and re.fullmatch(r"[0-9a-f]{64}", args.model_revision) is None
    ):
        raise SystemExit("--model-revision must be a lowercase SHA-256 digest")
    import bittensor as bt

    wallet_path = str(Path(args.wallet_path).expanduser())
    validator_wallet = bt.Wallet(
        name=args.validator_wallet_name,
        hotkey=args.validator_hotkey,
        path=wallet_path,
    )
    miner_wallet = bt.Wallet(
        name=args.miner_wallet_name,
        hotkey=args.miner_hotkey,
        path=wallet_path,
    )
    translator = load_translator(
        args.translator,
        maximum_concurrency=1,
        allow_synchronous=args.allow_unsafe_sync_translator,
        expected_model_revision=args.model_revision,
    )
    origins = _video_origins(args.requests)
    video_fetcher = HttpVideoFetcher(
        allowed_origins=origins,
        maximum_clip_size_bytes=Limits().maximum_clip_size_bytes,
        maximum_http_header_bytes=Limits().maximum_http_header_bytes,
        timeout_seconds=args.video_fetch_timeout,
    )
    manifest, scoring = asyncio.run(
        run_local_component_pilot(
            requests_path=args.requests,
            ground_truth_path=args.ground_truth,
            output=args.output,
            validator_wallet=validator_wallet,
            miner_wallet=miner_wallet,
            translator=translator,
            video_fetcher=video_fetcher,
            model_revision=args.model_revision,
            request_timeout_seconds=args.request_timeout,
            reveal_timeout_seconds=args.reveal_timeout,
            inference_timeout_seconds=args.inference_timeout,
            backend_lifecycle_timeout_seconds=args.backend_lifecycle_timeout,
        )
    )
    print(
        canonical_json_bytes(
            {
                "bundle_manifest": str(manifest),
                "status": "component_pilot_complete",
                "summary": score_summary(scoring),
            }
        ).decode("utf-8")
    )


if __name__ == "__main__":
    main()
