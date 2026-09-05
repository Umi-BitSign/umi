"""One-command, local reference-model pilot for one explicitly declared miner.

This module deliberately uses :class:`LocalComponentWindowAuthority`.  It proves
that the supplied miner hotkey signed a response produced by the locally loaded
reference backend; it does not contact or attest the miner's public axon.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .backends import load_translator
from .component_pilot import run_local_component_pilot
from .config import Limits
from .encoding import account_id32
from .miner import _identity
from .protocol import (
    GROUND_TRUTH_SCHEMA,
    GROUND_TRUTH_TLE_PROFILE,
    PROTOCOL_VERSION,
    GroundTruthPayload,
    TranslationRequest,
    base64url_encode,
    canonical_json_bytes,
)
from .scoring import normalize_text
from .validator import replay_bundle_detailed, score_summary
from .video import HttpVideoFetcher
from .window import QUICKNET_PERIOD_MS, ceil_div

KIT_SCHEMA = "umi-external-miner-component-pilot/1"
MODEL_RELEASE_TAG = "umi-s1-public-finetune-v1-r2"
MODEL_RELEASE_COMMIT = "20307ea05684e098ab362fa6bfc174c2aced3b9e"
MODEL_RELEASE_SIGNER_FINGERPRINT = "478B8C18537D7536A8C3982D58B44AF349CF5A4D"
MODEL_RELEASE_ID = "umi-s1-public-finetune-v1-r2"
MODEL_TRANSLATOR = "bitsign_motion.umi_reference_backend:translator"
ASSET_URL = (
    "https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev/component-pilot/media/"
    "7558c4b41aa18a9dc8377b84bda06c1595b4fcdcf5e69dd154d5e210127a29ff.mp4"
)
ASSET_SHA256 = "7558c4b41aa18a9dc8377b84bda06c1595b4fcdcf5e69dd154d5e210127a29ff"
ASSET_SIZE_BYTES = 302_686
ASSET_LICENSE = "CC-BY-3.0"
ASSET_ATTRIBUTION = "Richard Goodrow"
ASSET_SOURCE_URL = "https://commons.wikimedia.org/wiki/File:ASL_BOOK.ogv"
ASSET_REFERENCES = (
    "book b o o k my daughter and i read every day together book",
    "book b o o k my daughter and i read together every day book",
    "book b o o k my daughter and i read daily together book",
)

_GIT_REVISION = re.compile(r"[0-9a-f]{40}")
_SHA256 = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True, slots=True)
class VerifiedPilotSources:
    """Exact source identities checked before the local model is loaded."""

    umi_revision: str
    model_tag: str
    model_revision: str
    model_tag_signer_fingerprint: str
    model_manifest_sha256: str
    model_manifest_umi_revision: str
    base_inference_revision: str


CommandRunner = Callable[[Sequence[str], Path, str], tuple[bytes, bytes]]


def _run_checked(command: Sequence[str], cwd: Path, label: str) -> tuple[bytes, bytes]:
    try:
        result = subprocess.run(
            list(command),
            cwd=cwd,
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise RuntimeError(f"{label} could not start") from error
    if result.returncode != 0:
        raise RuntimeError(f"{label} failed")
    return result.stdout, result.stderr


def _git_text(
    repository: Path,
    arguments: Sequence[str],
    *,
    label: str,
    runner: CommandRunner,
) -> str:
    stdout, _stderr = runner(("git", *arguments), repository, label)
    try:
        return stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as error:
        raise RuntimeError(f"{label} returned non-UTF-8 output") from error


def _require_clean_exact_checkout(
    repository: Path,
    expected_revision: str,
    *,
    label: str,
    runner: CommandRunner,
) -> None:
    observed = _git_text(repository, ("rev-parse", "HEAD"), label=label, runner=runner)
    if observed != expected_revision:
        raise RuntimeError(f"{label} is not at the expected revision")
    status = _git_text(
        repository,
        ("status", "--porcelain=v1", "--untracked-files=all"),
        label=label,
        runner=runner,
    )
    if status:
        raise RuntimeError(f"{label} checkout is not clean")


def _read_model_manifest(model_repository: Path) -> tuple[dict[str, Any], bytes]:
    path = model_repository / "release" / "release-manifest.json"
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as error:
        raise RuntimeError("reference-model release manifest is unavailable") from error
    if not path.is_file() or metadata.st_size <= 0 or metadata.st_size > 1024 * 1024:
        raise RuntimeError("reference-model release manifest has an invalid size or type")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("reference-model release manifest is invalid JSON") from error
    canonical = canonical_json_bytes(value)
    if not isinstance(value, dict) or raw != canonical + b"\n":
        raise RuntimeError("reference-model release manifest is not canonical JSON plus one LF")
    return value, raw


def _verify_pilot_asset(umi_repository: Path) -> None:
    path = umi_repository / "docs" / "pilot-media" / "asl-book.mp4"
    try:
        metadata = path.stat()
        raw = path.read_bytes()
    except OSError as error:
        raise RuntimeError("checked-in ASL BOOK pilot asset is unavailable") from error
    if not path.is_file() or metadata.st_size != ASSET_SIZE_BYTES:
        raise RuntimeError("checked-in ASL BOOK pilot asset has the wrong size or type")
    if hashlib.sha256(raw).hexdigest() != ASSET_SHA256:
        raise RuntimeError("checked-in ASL BOOK pilot asset has the wrong digest")


def _require_loaded_source_checkout(repository: Path, package: str, expected: Path) -> None:
    spec = importlib.util.find_spec(package)
    if spec is None or spec.origin is None:
        raise RuntimeError(f"{package} cannot be imported")
    if Path(spec.origin).resolve() != expected.resolve():
        raise RuntimeError(f"{package} is not loaded from the verified checkout")


def verify_pilot_sources(
    *,
    umi_repository: Path,
    expected_umi_revision: str,
    model_repository: Path,
    runner: CommandRunner = _run_checked,
) -> VerifiedPilotSources:
    """Verify the exact UMI checkout and the signed public S1 release tag."""

    if _GIT_REVISION.fullmatch(expected_umi_revision) is None:
        raise ValueError("expected UMI revision must be a lowercase 40-character Git revision")
    umi_repository = umi_repository.expanduser().resolve(strict=True)
    model_repository = model_repository.expanduser().resolve(strict=True)
    if not umi_repository.is_dir() or not model_repository.is_dir():
        raise ValueError("UMI and reference-model repositories must be directories")

    _require_clean_exact_checkout(
        umi_repository,
        expected_umi_revision,
        label="UMI checkout",
        runner=runner,
    )
    expected_source = umi_repository / "src" / "umi" / Path(__file__).name
    if Path(__file__).resolve() != expected_source.resolve():
        raise RuntimeError("pilot command is not loaded from the verified UMI checkout")
    _verify_pilot_asset(umi_repository)

    signature_stdout, signature_stderr = runner(
        ("git", "verify-tag", "--raw", MODEL_RELEASE_TAG),
        model_repository,
        "reference-model tag signature verification",
    )
    signature_status = (signature_stdout + signature_stderr).decode("utf-8", errors="replace")
    valid_fingerprints = {
        line.split()[2]
        for line in signature_status.splitlines()
        if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) >= 3
    }
    if valid_fingerprints != {MODEL_RELEASE_SIGNER_FINGERPRINT}:
        raise RuntimeError("reference-model tag does not have the pinned signer fingerprint")

    tag_commit = _git_text(
        model_repository,
        ("rev-parse", f"{MODEL_RELEASE_TAG}^{{commit}}"),
        label="reference-model tag resolution",
        runner=runner,
    )
    if tag_commit != MODEL_RELEASE_COMMIT:
        raise RuntimeError("reference-model tag does not resolve to the pinned release commit")
    _require_clean_exact_checkout(
        model_repository,
        MODEL_RELEASE_COMMIT,
        label="reference-model checkout",
        runner=runner,
    )

    manifest, manifest_bytes = _read_model_manifest(model_repository)
    if manifest.get("release_id") != MODEL_RELEASE_ID:
        raise RuntimeError("reference-model release ID differs from the pinned release")
    if manifest.get("status") != "baseline_no_weight":
        raise RuntimeError("reference-model release is not the no-weight baseline")
    base_inference_revision = manifest.get("inference_revision")
    model_manifest_umi_revision = manifest.get("umi_git_revision")
    if (
        not isinstance(base_inference_revision, str)
        or _SHA256.fullmatch(base_inference_revision) is None
    ):
        raise RuntimeError("reference-model base inference revision is invalid")
    if (
        not isinstance(model_manifest_umi_revision, str)
        or _GIT_REVISION.fullmatch(model_manifest_umi_revision) is None
    ):
        raise RuntimeError("reference-model UMI integration revision is invalid")

    runner(
        (
            "git",
            "merge-base",
            "--is-ancestor",
            model_manifest_umi_revision,
            expected_umi_revision,
        ),
        umi_repository,
        "UMI compatibility ancestry verification",
    )
    verifier = model_repository / "tools" / "release_artifacts.py"
    runner(
        (
            sys.executable,
            str(verifier),
            "--verify",
            str(model_repository / "release" / "release-manifest.json"),
            "--artifact-directory",
            str(model_repository / "release"),
            "--repository",
            str(model_repository),
            "--release-git-revision",
            MODEL_RELEASE_COMMIT,
        ),
        model_repository,
        "reference-model artifact and history verification",
    )
    _require_loaded_source_checkout(
        model_repository,
        "bitsign_motion",
        model_repository / "src" / "bitsign_motion" / "__init__.py",
    )
    return VerifiedPilotSources(
        umi_revision=expected_umi_revision,
        model_tag=MODEL_RELEASE_TAG,
        model_revision=MODEL_RELEASE_COMMIT,
        model_tag_signer_fingerprint=MODEL_RELEASE_SIGNER_FINGERPRINT,
        model_manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
        model_manifest_umi_revision=model_manifest_umi_revision,
        base_inference_revision=base_inference_revision,
    )


def _reference_inputs(
    *,
    current_round: int,
    backend_lifecycle_timeout_seconds: float,
    inference_timeout_seconds: float,
    response_buffer_seconds: float,
    reveal_margin_seconds: float,
    entropy: Callable[[int], bytes] = secrets.token_bytes,
) -> tuple[TranslationRequest, GroundTruthPayload]:
    if isinstance(current_round, bool) or not isinstance(current_round, int) or current_round <= 0:
        raise ValueError("current Quicknet round must be a positive integer")
    durations = (
        backend_lifecycle_timeout_seconds,
        inference_timeout_seconds,
        response_buffer_seconds,
        reveal_margin_seconds,
    )
    if any(
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
        for value in durations
    ):
        raise ValueError("pilot timing values must be finite positive numbers")
    period_seconds = QUICKNET_PERIOD_MS // 1000
    response_allowance = ceil_div(
        math.ceil(
            backend_lifecycle_timeout_seconds + inference_timeout_seconds + response_buffer_seconds
        ),
        period_seconds,
    )
    response_close_round = current_round + response_allowance
    reveal_round = response_close_round + ceil_div(math.ceil(reveal_margin_seconds), period_seconds)

    batch_bytes = entropy(16)
    challenge_bytes = entropy(16)
    nonce = entropy(32)
    if len(batch_bytes) != 16 or len(challenge_bytes) != 16 or len(nonce) != 32:
        raise RuntimeError("entropy provider returned an invalid byte count")
    window_id = hashlib.sha256(
        b"umi-external-miner-pilot-window-v1\0"
        + nonce
        + response_close_round.to_bytes(8, "big")
        + reveal_round.to_bytes(8, "big")
    ).hexdigest()
    policy_hash = hashlib.sha256(
        b"umi-external-miner-pilot-policy-v1\0"
        + MODEL_RELEASE_TAG.encode("ascii")
        + bytes.fromhex(ASSET_SHA256)
    ).hexdigest()
    issued_block_hash = (
        "0x" + hashlib.sha256(b"umi-component-nonchain-block-v1\0" + nonce).hexdigest()
    )
    request = TranslationRequest.model_validate(
        {
            "protocol": PROTOCOL_VERSION,
            "window_id": window_id,
            "batch_id": base64url_encode(batch_bytes),
            "challenge_id": base64url_encode(challenge_bytes),
            "issued_block": 0,
            "issued_block_hash": issued_block_hash,
            "deadline_block": 1,
            "response_close_round": response_close_round,
            "reveal_round": reveal_round,
            "video": {
                "url": ASSET_URL,
                "sha256": ASSET_SHA256,
                "size_bytes": ASSET_SIZE_BYTES,
                "media_type": "video/mp4",
            },
            "task": {
                "source_language": "ase",
                "target_language": "en",
                "stratum": "continuous",
            },
            "scoring_policy_hash": policy_hash,
        }
    )
    script_hash = hashlib.sha256(normalize_text(ASSET_REFERENCES[0]).encode("utf-8")).hexdigest()
    attribution_path = (
        Path(__file__).resolve().parents[2] / "docs" / "pilot-media" / "ASL_BOOK_ATTRIBUTION.md"
    )
    attribution_bytes = attribution_path.read_bytes()
    consent_placeholder = hashlib.sha256(
        b"umi-component-no-consent-v1\0" + hashlib.sha256(attribution_bytes).digest()
    ).hexdigest()
    truth = GroundTruthPayload.model_validate(
        {
            "schema": GROUND_TRUTH_SCHEMA,
            "window_id": request.window_id,
            "batch_id": request.batch_id,
            "scoring_policy_hash": request.scoring_policy_hash,
            "tle_profile": GROUND_TRUTH_TLE_PROFILE,
            "response_close_round": response_close_round,
            "reveal_round": reveal_round,
            "items": [
                {
                    "challenge_id": request.challenge_id,
                    "metric": "wer",
                    "canary": False,
                    "references": list(ASSET_REFERENCES),
                    "canary_evidence": None,
                    "normalized_script_sha256": script_hash,
                    "retirement_script_sha256s": [script_hash],
                    "consent_manifest_sha256": consent_placeholder,
                }
            ],
        }
    )
    return request, truth


def _write_exclusive(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        written = 0
        while written < len(value):
            written += os.write(descriptor, value[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _require_successful_model_outcome(
    bundle_root: Path,
    *,
    expected_model_revision: str,
    expected_scoring: dict[str, Any],
) -> dict[str, Any]:
    replay = replay_bundle_detailed(bundle_root)
    if replay.scoring != expected_scoring:
        raise RuntimeError("external pilot replay changed between verification passes")
    if len(replay.outcomes) != 1:
        raise RuntimeError("external pilot did not contain exactly one outcome")
    outcome = replay.outcomes[0]
    response = outcome.response
    if outcome.failure_code is not None or response is None or response.status != "ok":
        raise RuntimeError("external pilot did not produce a successful model response")
    if response.received_video_sha256 != ASSET_SHA256:
        raise RuntimeError("external pilot response did not bind the pinned video bytes")
    if response.model_revision != expected_model_revision:
        raise RuntimeError("external pilot response did not bind the local model revision")
    return replay.scoring


async def run_external_reference_pilot(
    *,
    output: Path,
    umi_repository: Path,
    expected_umi_revision: str,
    model_repository: Path,
    validator_wallet: Any,
    miner_wallet: Any,
    model_revision: str,
    expected_miner_hotkey: str,
    declared_miner_uid: int,
    backend_lifecycle_timeout_seconds: float = 60.0,
    inference_timeout_seconds: float = 180.0,
    response_buffer_seconds: float = 60.0,
    reveal_margin_seconds: float = 30.0,
    request_timeout_seconds: float = 240.0,
    reveal_timeout_seconds: float = 600.0,
    video_fetch_timeout_seconds: float = 30.0,
) -> tuple[Path, Path]:
    """Verify sources, run the local signed pilot, replay it, and publish a receipt."""

    if _SHA256.fullmatch(model_revision) is None:
        raise ValueError("model revision must be a lowercase SHA-256 digest")
    if isinstance(declared_miner_uid, bool) or not isinstance(declared_miner_uid, int):
        raise ValueError("declared miner UID must be an integer")
    if declared_miner_uid < 0:
        raise ValueError("declared miner UID must not be negative")
    output = output.expanduser().resolve(strict=False)
    umi_repository = umi_repository.expanduser().resolve(strict=True)
    model_repository = model_repository.expanduser().resolve(strict=True)
    if output.exists():
        raise FileExistsError("pilot output path already exists")
    if output.is_relative_to(umi_repository) or output.is_relative_to(model_repository):
        raise ValueError("pilot output must be outside both source repositories")

    sources = verify_pilot_sources(
        umi_repository=umi_repository,
        expected_umi_revision=expected_umi_revision,
        model_repository=model_repository,
    )
    if model_revision == sources.base_inference_revision:
        raise ValueError("pilot requires the locally rebound extractor-specific model revision")

    validator_hotkey, _validator_scheme = _identity(validator_wallet)
    miner_hotkey, _miner_scheme = _identity(miner_wallet)
    if miner_hotkey != expected_miner_hotkey:
        raise ValueError("miner wallet hotkey does not match the explicitly expected hotkey")
    if account_id32(validator_hotkey) == account_id32(miner_hotkey):
        raise ValueError("pilot validator and miner hotkeys must be distinct")

    translator = load_translator(
        MODEL_TRANSLATOR,
        maximum_concurrency=1,
        expected_model_revision=model_revision,
    )
    import bittensor as bt

    request, truth = _reference_inputs(
        current_round=bt.timelock.current_round(),
        backend_lifecycle_timeout_seconds=backend_lifecycle_timeout_seconds,
        inference_timeout_seconds=inference_timeout_seconds,
        response_buffer_seconds=response_buffer_seconds,
        reveal_margin_seconds=reveal_margin_seconds,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{output.name}.stage-", dir=output.parent))
    try:
        inputs = stage / ".private-inputs"
        inputs.mkdir(mode=0o700)
        requests_path = inputs / "requests.json"
        truth_path = inputs / "ground-truth.json"
        _write_exclusive(
            requests_path,
            canonical_json_bytes([request.model_dump(mode="json", by_alias=True)]),
        )
        _write_exclusive(truth_path, canonical_json_bytes(truth))
        fetcher = HttpVideoFetcher(
            allowed_origins=frozenset({"https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev"}),
            maximum_clip_size_bytes=Limits().maximum_clip_size_bytes,
            maximum_http_header_bytes=Limits().maximum_http_header_bytes,
            timeout_seconds=video_fetch_timeout_seconds,
        )
        manifest_path, scoring = await run_local_component_pilot(
            requests_path=requests_path,
            ground_truth_path=truth_path,
            output=stage / "bundle",
            validator_wallet=validator_wallet,
            miner_wallet=miner_wallet,
            translator=translator,
            video_fetcher=fetcher,
            model_revision=model_revision,
            request_timeout_seconds=request_timeout_seconds,
            reveal_timeout_seconds=reveal_timeout_seconds,
            inference_timeout_seconds=inference_timeout_seconds,
            backend_lifecycle_timeout_seconds=backend_lifecycle_timeout_seconds,
        )
        scoring = _require_successful_model_outcome(
            stage / "bundle",
            expected_model_revision=model_revision,
            expected_scoring=scoring,
        )
        manifest_bytes = manifest_path.read_bytes()
        receipt = {
            "schema": KIT_SCHEMA,
            "evidence_class": "component_test_no_weight",
            "terminal_code": "component_test_no_weight",
            "translation_weights_active": False,
            "protocol_conformance": False,
            "activation_evidence": False,
            "validator_input_eligible": False,
            "deterministic_replay_verified": True,
            "public_miner_transport_used": False,
            "public_axon_service_proven": False,
            "uid_chain_binding_verified": False,
            "receipt_authenticated_by_miner": False,
            "source_verification_is_operator_asserted": True,
            "model_execution_is_operator_asserted": True,
            "model_revision_is_operator_asserted": True,
            "declared_miner_uid": declared_miner_uid,
            "miner_hotkey": miner_hotkey,
            "validator_hotkey": validator_hotkey,
            "model": {
                "release_id": MODEL_RELEASE_ID,
                "tag": sources.model_tag,
                "tag_commit": sources.model_revision,
                "tag_signer_fingerprint": sources.model_tag_signer_fingerprint,
                "release_manifest_sha256": sources.model_manifest_sha256,
                "base_inference_revision": sources.base_inference_revision,
                "local_inference_revision": model_revision,
            },
            "umi": {
                "revision": sources.umi_revision,
                "model_e2e_revision": sources.model_manifest_umi_revision,
                "model_e2e_revision_is_ancestor": True,
            },
            "asset": {
                "url": ASSET_URL,
                "sha256": ASSET_SHA256,
                "size_bytes": ASSET_SIZE_BYTES,
                "source_url": ASSET_SOURCE_URL,
                "license": ASSET_LICENSE,
                "attribution": ASSET_ATTRIBUTION,
                "fresh": False,
                "umi_specific_consent": False,
                "independent_reference_review": False,
            },
            "component_bindings": {
                "issued_block_is_nonchain_placeholder": True,
                "consent_digest_is_attribution_bound_placeholder": True,
                "response_close_round": request.response_close_round,
                "reveal_round": request.reveal_round,
            },
            "bundle": {
                "relative_path": "bundle",
                "manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                "summary": score_summary(scoring),
            },
        }
        _write_exclusive(stage / "kit-receipt.json", canonical_json_bytes(receipt))
        shutil.rmtree(inputs)
        os.replace(stage, output)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    return output / "bundle" / "manifest.json", output / "kit-receipt.json"


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Run a declared miner's signed S1 component_test_no_weight pilot locally; "
            "this does not test the public axon"
        )
    )
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--umi-repo", type=Path, required=True)
    parser.add_argument("--expected-umi-revision", required=True)
    parser.add_argument("--model-repo", type=Path, required=True)
    parser.add_argument("--wallet-path", default="~/.bittensor/wallets")
    parser.add_argument("--validator-wallet-name", required=True)
    parser.add_argument("--validator-hotkey", required=True)
    parser.add_argument("--miner-wallet-name", required=True)
    parser.add_argument("--miner-hotkey", required=True)
    parser.add_argument("--expected-miner-uid", required=True, type=int)
    parser.add_argument("--expected-miner-hotkey", required=True)
    parser.add_argument("--model-revision", default=os.environ.get("UMI_S1_INFERENCE_REVISION"))
    parser.add_argument("--backend-lifecycle-timeout", type=float, default=60.0)
    parser.add_argument("--inference-timeout", type=float, default=180.0)
    parser.add_argument("--response-buffer", type=float, default=60.0)
    parser.add_argument("--reveal-margin", type=float, default=30.0)
    parser.add_argument("--request-timeout", type=float, default=240.0)
    parser.add_argument("--reveal-timeout", type=float, default=600.0)
    parser.add_argument("--video-fetch-timeout", type=float, default=30.0)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    if args.model_revision is None:
        parser.error("--model-revision or UMI_S1_INFERENCE_REVISION is required")
    import asyncio

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
    try:
        manifest, receipt = asyncio.run(
            run_external_reference_pilot(
                output=args.output,
                umi_repository=args.umi_repo,
                expected_umi_revision=args.expected_umi_revision,
                model_repository=args.model_repo,
                validator_wallet=validator_wallet,
                miner_wallet=miner_wallet,
                model_revision=args.model_revision,
                expected_miner_hotkey=args.expected_miner_hotkey,
                declared_miner_uid=args.expected_miner_uid,
                backend_lifecycle_timeout_seconds=args.backend_lifecycle_timeout,
                inference_timeout_seconds=args.inference_timeout,
                response_buffer_seconds=args.response_buffer,
                reveal_margin_seconds=args.reveal_margin,
                request_timeout_seconds=args.request_timeout,
                reveal_timeout_seconds=args.reveal_timeout,
                video_fetch_timeout_seconds=args.video_fetch_timeout,
            )
        )
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, f"external miner component pilot failed: {error}\n")
    print(
        canonical_json_bytes(
            {
                "status": "component_pilot_complete",
                "evidence_class": "component_test_no_weight",
                "translation_weights_active": False,
                "protocol_conformance": False,
                "activation_evidence": False,
                "public_miner_transport_used": False,
                "public_axon_service_proven": False,
                "bundle_manifest": str(manifest),
                "kit_receipt": str(receipt),
            }
        ).decode("utf-8")
    )


if __name__ == "__main__":
    main()
