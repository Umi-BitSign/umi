"""One-command local smoke run for the no-weight UMI component slice."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx

from .auth import RequestAuthenticator
from .backends import Translator
from .component import prepare_case
from .config import Limits
from .miner import MinerRuntime, _identity, create_app
from .miner_admission import LocalComponentWindowAuthority
from .miner_resources import SQLiteMinerResourceLedger
from .protocol import (
    GROUND_TRUTH_SCHEMA,
    GROUND_TRUTH_TLE_PROFILE,
    PROTOCOL_VERSION,
    GroundTruthPayload,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
)
from .validator import replay_bundle, run_component_case, score_summary
from .video import VideoFetcher

_DEMO_VIDEO = b"umi-component-smoke-video-bytes"


@dataclass(frozen=True)
class _DemoFetcher(VideoFetcher):
    async def fetch(self, descriptor: Any) -> bytes:
        if hashlib.sha256(_DEMO_VIDEO).hexdigest() != descriptor.sha256:
            raise ValueError("demo video descriptor does not match its fixture")
        return _DEMO_VIDEO


@dataclass(frozen=True)
class _DemoTranslator(Translator):
    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        if video != _DEMO_VIDEO:
            raise ValueError("demo translator received different video bytes")
        return "hello" if request.task.stratum == "fingerspelling" else "hello world"


def _development_wallet(uri: str) -> Any:
    import bittensor as bt

    hotkey = bt.sp_core.Keypair.create_from_uri(uri, crypto_type=bt.sp_core.CRYPTO_SR25519)
    coldkey = bt.sp_core.Keypair.create_from_uri(
        f"{uri}//cold",
        crypto_type=bt.sp_core.CRYPTO_SR25519,
    )
    return SimpleNamespace(coldkey=coldkey, coldkeypub=coldkey, hotkey=hotkey)


def _demo_inputs(reveal_round: int) -> tuple[tuple[TranslationRequest, ...], GroundTruthPayload]:
    import bittensor as bt

    if reveal_round <= bt.timelock.current_round() + 2:
        raise ValueError("demo reveal round must leave two full response rounds")
    strata = ("fingerspelling", "short_utterance", "continuous")
    requests: list[TranslationRequest] = []
    video_hash = hashlib.sha256(_DEMO_VIDEO).hexdigest()
    for index, stratum in enumerate(strata, start=1):
        requests.append(
            TranslationRequest.model_validate(
                {
                    "protocol": PROTOCOL_VERSION,
                    "window_id": "10" * 32,
                    "batch_id": base64url_encode(b"D" * 16),
                    "challenge_id": base64url_encode(bytes([index]) * 16),
                    "issued_block": 100,
                    "issued_block_hash": "0x" + "30" * 32,
                    "deadline_block": 110,
                    "response_close_round": reveal_round - 2,
                    "reveal_round": reveal_round,
                    "video": {
                        "url": f"https://objects.example/{index:032x}",
                        "sha256": video_hash,
                        "size_bytes": len(_DEMO_VIDEO),
                        "media_type": "video/mp4",
                    },
                    "task": {
                        "source_language": "ase",
                        "target_language": "en",
                        "stratum": stratum,
                    },
                    "scoring_policy_hash": "20" * 32,
                }
            )
        )

    items = []
    for index, request in enumerate(requests, start=1):
        script_hash = f"{index:064x}"
        items.append(
            {
                "challenge_id": request.challenge_id,
                "metric": "cer" if request.task.stratum == "fingerspelling" else "wer",
                "canary": False,
                "references": (
                    ["hello", "h e l l o", "hello"]
                    if request.task.stratum == "fingerspelling"
                    else ["hello world", "hi world", "hello, world"]
                ),
                "canary_evidence": None,
                "normalized_script_sha256": script_hash,
                "retirement_script_sha256s": [script_hash],
                "consent_manifest_sha256": "40" * 32,
            }
        )
    ground_truth = GroundTruthPayload.model_validate(
        {
            "schema": GROUND_TRUTH_SCHEMA,
            "window_id": requests[0].window_id,
            "batch_id": requests[0].batch_id,
            "scoring_policy_hash": requests[0].scoring_policy_hash,
            "tle_profile": GROUND_TRUTH_TLE_PROFILE,
            "response_close_round": reveal_round - 2,
            "reveal_round": reveal_round,
            "items": items,
        }
    )
    return tuple(requests), ground_truth


def _require_empty_output(output: Path) -> None:
    if output.exists() and (not output.is_dir() or any(output.iterdir())):
        raise FileExistsError(f"demo output path is not an empty directory: {output}")
    output.mkdir(parents=True, exist_ok=True)


async def run_demo(output: Path) -> tuple[Path, dict[str, Any]]:
    """Run the complete local component flow and return its manifest and scores."""

    import bittensor as bt

    _require_empty_output(output)
    requests, ground_truth = _demo_inputs(bt.timelock.current_round() + 5)
    inputs = output / "inputs"
    inputs.mkdir()
    requests_path = inputs / "requests.json"
    ground_truth_path = inputs / "ground-truth.json"
    requests_path.write_bytes(
        canonical_json_bytes(
            [request.model_dump(mode="json", by_alias=True) for request in requests]
        )
    )
    ground_truth_path.write_bytes(canonical_json_bytes(ground_truth))

    case_root = output / "case"
    prepare_case(requests_path, ground_truth_path, case_root)
    validator_wallet = _development_wallet("//Alice")
    miner_wallet = _development_wallet("//Bob")
    miner_hotkey, scheme = _identity(miner_wallet)
    limits = Limits(inference_timeout_seconds=5)
    runtime = MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=miner_hotkey,
        signature_scheme=scheme,
        translator=_DemoTranslator(),
        video_fetcher=_DemoFetcher(),
        allowed_validator_hotkeys=frozenset({validator_wallet.hotkey.ss58_address}),
        authenticator=RequestAuthenticator.in_memory(miner_hotkey),
        limits=limits,
        scoring_policy_sha256="20" * 32,
        response_deadline_blocks=10,
        resource_ledger=SQLiteMinerResourceLedger(
            ":memory:",
            miner_hotkey=miner_hotkey,
            scoring_policy_sha256="20" * 32,
            limits=limits,
        ),
        window_authority=LocalComponentWindowAuthority(),
    )
    bundle_root = output / "bundle"
    manifest = await run_component_case(
        case_root,
        bundle_root,
        wallet=validator_wallet,
        miner_url="http://miner.test",
        miner_hotkey=miner_hotkey,
        request_timeout_seconds=5,
        reveal_timeout_seconds=30,
        transport=httpx.ASGITransport(app=create_app(runtime)),
    )
    scoring = replay_bundle(bundle_root)
    return manifest, scoring


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the local UMI no-weight smoke flow")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest, scoring = asyncio.run(run_demo(args.output))
    print(
        canonical_json_bytes(
            {
                "status": "demo_complete",
                "bundle_manifest": str(manifest),
                "summary": score_summary(scoring),
            }
        ).decode("utf-8")
    )


if __name__ == "__main__":
    main()
