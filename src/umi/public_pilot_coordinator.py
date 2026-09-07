"""UMI-operated coordinator for the public SN78 miner endpoint pilot."""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import logging
import math
import os
import shutil
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from .audit import EvidenceStore
from .chain import discover_miner_finalized
from .component import load_case, score_component_responses, validate_case_bindings
from .config import Limits
from .crypto import (
    TimelockDecryptionError,
    sign_response_digest,
    verify_response_signature,
)
from .encoding import account_id32
from .protocol import GroundTruthPayload, ResponsePlaintext, canonical_json_bytes
from .public_pilot_campaign import (
    CAMPAIGN_ID,
    DEFAULT_RESPONSE_WINDOW_SECONDS,
    DEFAULT_REVEAL_MARGIN_SECONDS,
    DEFAULT_SETUP_ALLOWANCE_SECONDS,
    load_public_pilot_campaign,
    prepare_public_pilot_case,
    validate_public_pilot_replay,
)
from .public_pilot_evidence import (
    attach_public_endpoint_pilot,
    verify_public_endpoint_pilot_attachment,
)
from .public_pilot_journal import PublicPilotAttemptJournal, load_attempt_journal
from .validator import (
    ComponentResponseError,
    QueryOutcome,
    _decrypt,
    _write_run_bundle,
    prepare_request_attempt,
    replay_bundle_detailed,
    score_summary,
    send_prepared_request,
    validate_response_plaintext,
)

LOGGER = logging.getLogger("umi.public_pilot_coordinator")
_MINIMUM_RESPONSE_HEADROOM_SECONDS = 300.0
_MINIMUM_POST_REQUEST_HEADROOM_SECONDS = 60.0
_REVEAL_TIMEOUT_GRACE_SECONDS = 120.0
_COORDINATOR_POSSESSION_DOMAIN = b"umi-public-pilot-coordinator-possession-v1\0"


def _wallet_hotkey(wallet: Any) -> str:
    import bittensor as bt

    return bt.resolve_signer(wallet, role="hotkey").ss58_address


def _coordinator_possession_challenge(expected_coordinator_hotkey: str) -> bytes:
    """Bind a fixed-size signing challenge to the announced coordinator account."""

    return hashlib.sha256(
        _COORDINATOR_POSSESSION_DOMAIN + account_id32(expected_coordinator_hotkey)
    ).digest()


def _prove_coordinator_signer(wallet: Any, expected_coordinator_hotkey: str) -> str:
    """Require the selected wallet to hold the announced coordinator private key."""

    try:
        coordinator_hotkey = _wallet_hotkey(wallet)
    except Exception as error:
        raise RuntimeError("coordinator hotkey signer is unavailable") from error
    if account_id32(coordinator_hotkey) != account_id32(expected_coordinator_hotkey):
        raise ValueError("coordinator wallet does not match the expected coordinator hotkey")

    challenge = _coordinator_possession_challenge(expected_coordinator_hotkey)
    try:
        scheme, signature = sign_response_digest(wallet, challenge)
    except Exception as error:
        raise RuntimeError("coordinator hotkey signing preflight failed") from error
    if not verify_response_signature(
        challenge,
        hotkey_ss58=expected_coordinator_hotkey,
        scheme=scheme,
        signature=signature,
    ):
        raise RuntimeError("coordinator hotkey signing preflight did not verify")
    return coordinator_hotkey


def prepare_public_endpoint_pilot_case(
    output: Path,
    *,
    wallet: Any,
    expected_coordinator_hotkey: str,
    expected_miner_uid: int,
    expected_miner_hotkey: str,
    setup_allowance_seconds: float = DEFAULT_SETUP_ALLOWANCE_SECONDS,
    response_window_seconds: float = DEFAULT_RESPONSE_WINDOW_SECONDS,
    reveal_margin_seconds: float = DEFAULT_REVEAL_MARGIN_SECONDS,
) -> Path:
    """Prove coordinator signing custody before creating a timed sealed case."""

    coordinator_hotkey = _prove_coordinator_signer(wallet, expected_coordinator_hotkey)

    import bittensor as bt

    return prepare_public_pilot_case(
        output,
        coordinator_hotkey=coordinator_hotkey,
        expected_miner_uid=expected_miner_uid,
        expected_miner_hotkey=expected_miner_hotkey,
        current_round=bt.timelock.current_round(),
        setup_allowance_seconds=setup_allowance_seconds,
        response_window_seconds=response_window_seconds,
        reveal_margin_seconds=reveal_margin_seconds,
    )


def _require_distinct_output(case_root: Path, output: Path) -> None:
    case = case_root.expanduser().resolve(strict=True)
    destination = output.expanduser().resolve(strict=False)
    if destination == case or destination.is_relative_to(case) or case.is_relative_to(destination):
        raise ValueError("pilot result and sealed case must use separate directory trees")
    if destination.exists():
        raise FileExistsError("public pilot output already exists")
    if _incomplete_root(destination).exists():
        raise FileExistsError("a preserved incomplete public pilot attempt already exists")


def _incomplete_root(destination: Path) -> Path:
    return destination.with_name(f"{destination.name}.incomplete")


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _durable_copy_tree(source: Path, destination: Path) -> None:
    """Copy a verified base component tree before mutating the public candidate."""

    shutil.copytree(source, destination)
    files = tuple(path for path in destination.rglob("*") if path.is_file())
    for path in files:
        descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    directories = sorted(
        (path for path in destination.rglob("*") if path.is_dir()),
        key=lambda path: len(path.parts),
        reverse=True,
    )
    for path in directories:
        _fsync_directory(path)
    _fsync_directory(destination)
    _fsync_directory(destination.parent)


async def _build_base_component_bundle(
    case_root: Path,
    output: Path,
    *,
    outcome: QueryOutcome,
    miner_url: str,
    miner_hotkey: str,
    reveal_timeout_seconds: float,
) -> Path:
    """Finish reveal and scoring from an already journaled one-shot outcome."""

    prepared = load_case(case_root)
    if len(prepared.requests) != 1 or outcome.request != prepared.requests[0]:
        raise ValueError("journaled outcome does not match the fixed public pilot case")
    ground_truth_bytes = await _decrypt(
        prepared.ground_truth,
        timeout=reveal_timeout_seconds,
    )
    try:
        ground_truth = GroundTruthPayload.model_validate_json(ground_truth_bytes)
    except ValidationError as error:
        raise ValueError("revealed ground truth is invalid") from error
    if canonical_json_bytes(ground_truth) != ground_truth_bytes:
        raise ValueError("revealed ground truth is not canonical JSON")
    validate_case_bindings(prepared.requests, ground_truth)
    validate_public_pilot_replay(prepared.requests[0], ground_truth)

    if outcome.sealed_response is None or outcome.envelope is None:
        revealed = outcome
    else:
        try:
            plaintext_bytes = await _decrypt(
                outcome.sealed_response,
                timeout=reveal_timeout_seconds,
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

    response_map: dict[str, ResponsePlaintext | None] = {
        revealed.request.challenge_id: revealed.plaintext
    }
    failure_map = {revealed.request.challenge_id: revealed.failure_code}
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
        (revealed,),
        scoring,
        miner_url,
        miner_hotkey,
    )


def _effective_reveal_timeout(
    reveal_round: int,
    requested_timeout_seconds: float | None,
    *,
    now_seconds: float | None = None,
) -> float:
    import bittensor as bt

    now = time.time() if now_seconds is None else now_seconds
    if not math.isfinite(now) or now < 0:
        raise ValueError("current time must be finite and nonnegative")
    reveal_time = bt.timelock.reveal_time(reveal_round).timestamp()
    minimum = max(
        _REVEAL_TIMEOUT_GRACE_SECONDS,
        reveal_time - now + _REVEAL_TIMEOUT_GRACE_SECONDS,
    )
    if requested_timeout_seconds is None:
        return minimum
    if (
        isinstance(requested_timeout_seconds, bool)
        or not isinstance(requested_timeout_seconds, (int, float))
        or not math.isfinite(requested_timeout_seconds)
        or requested_timeout_seconds <= 0
    ):
        raise ValueError("reveal timeout must be finite and positive")
    if requested_timeout_seconds < minimum:
        raise ValueError("reveal timeout expires before the case reveal plus the safety allowance")
    return float(requested_timeout_seconds)


def _require_response_headroom(
    response_close_round: int,
    *,
    now_seconds: float | None = None,
) -> float:
    """Require the published five-minute operator margin before one-shot contact."""

    import bittensor as bt

    now = time.time() if now_seconds is None else now_seconds
    if not math.isfinite(now) or now < 0:
        raise ValueError("current time must be finite and nonnegative")
    close_time = bt.timelock.reveal_time(response_close_round).timestamp()
    remaining = close_time - now
    if remaining < _MINIMUM_RESPONSE_HEADROOM_SECONDS:
        raise ValueError("fewer than 300 seconds remain before the public pilot response close")
    return remaining


def _validated_request_timeout(value: float, *, response_headroom_seconds: float) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, (int, float))
        or not math.isfinite(value)
        or value <= 0
    ):
        raise ValueError("request timeout must be finite and positive")
    maximum = response_headroom_seconds - _MINIMUM_POST_REQUEST_HEADROOM_SECONDS
    if value > maximum:
        raise ValueError("request timeout must leave at least 60 seconds before the response close")
    return float(value)


async def run_public_endpoint_pilot(
    case_root: Path,
    output: Path,
    *,
    wallet: Any,
    network: str = "finney",
    request_timeout_seconds: float = 240.0,
    reveal_timeout_seconds: float | None = None,
) -> Path:
    """Contact the finalized chain endpoint once and publish its replayable outcome."""

    _require_distinct_output(case_root, output)
    if network != "finney":
        raise ValueError("public endpoint pilots are pinned to the Finney mainnet")
    campaign = load_public_pilot_campaign(case_root)
    coordinator_hotkey = _wallet_hotkey(wallet)
    if account_id32(coordinator_hotkey) != account_id32(campaign.coordinator_hotkey):
        raise ValueError("coordinator wallet does not match the sealed campaign case")
    effective_reveal_timeout = _effective_reveal_timeout(
        campaign.reveal_round,
        reveal_timeout_seconds,
    )

    endpoint = await discover_miner_finalized(
        campaign.expected_miner_hotkey,
        network=network,
        netuid=78,
    )
    if account_id32(endpoint.hotkey) != account_id32(campaign.expected_miner_hotkey):
        raise RuntimeError("finalized chain discovery returned another miner hotkey")
    if endpoint.uid != campaign.expected_miner_uid:
        raise RuntimeError("finalized chain UID does not match the sealed campaign case")
    if endpoint.validator_permit:
        raise RuntimeError("finalized chain identity has a validator permit")
    response_headroom = _require_response_headroom(campaign.response_close_round)
    request_timeout = _validated_request_timeout(
        request_timeout_seconds,
        response_headroom_seconds=response_headroom,
    )

    destination = output.expanduser().resolve(strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    incomplete = _incomplete_root(destination)
    incomplete.mkdir(mode=0o700)
    _fsync_directory(destination.parent)
    journal: PublicPilotAttemptJournal | None = None
    failure_stage: Literal[
        "request_send",
        "reveal_and_scoring",
        "attachment",
        "publication",
    ] = "request_send"
    try:
        prepared_case = load_case(case_root)
        if len(prepared_case.requests) != 1:
            raise ValueError("public endpoint pilot must contain exactly one request")
        prepared_attempt = prepare_request_attempt(
            prepared_case.requests[0],
            wallet=wallet,
            miner_hotkey=endpoint.hotkey,
        )
        _, case_manifest_bytes = EvidenceStore(case_root).load_manifest_with_bytes()
        journal = PublicPilotAttemptJournal.start(
            incomplete / "attempt-journal",
            prepared=prepared_attempt,
            endpoint=endpoint,
            case_manifest_sha256=hashlib.sha256(case_manifest_bytes).hexdigest(),
        )
        outcome = await send_prepared_request(
            prepared_attempt,
            miner_url=endpoint.origin,
            limits=Limits(),
            timeout_seconds=request_timeout,
        )
        journal.record_outcome(outcome, limits=Limits())

        failure_stage = "reveal_and_scoring"
        base_bundle_root = incomplete / "base-component-bundle"
        base_manifest = await _build_base_component_bundle(
            case_root,
            base_bundle_root,
            outcome=outcome,
            miner_url=endpoint.origin,
            miner_hotkey=endpoint.hotkey,
            reveal_timeout_seconds=effective_reveal_timeout,
        )
        replay_bundle_detailed(base_bundle_root)
        journal.record_base_component(base_manifest)

        failure_stage = "attachment"
        bundle_root = incomplete / "public-endpoint-candidate"
        _durable_copy_tree(base_bundle_root, bundle_root)
        attach_public_endpoint_pilot(
            bundle_root,
            wallet=wallet,
            campaign_id=campaign.campaign_id,
            network=endpoint.network,
            genesis_block_hash=endpoint.genesis_block_hash,
            finalized_block_number=endpoint.finalized_block_number,
            finalized_block_hash=endpoint.finalized_block_hash,
            finalized_block_timestamp_ms=endpoint.finalized_block_timestamp_ms,
            expected_miner_uid=endpoint.uid,
            announced_origin=endpoint.origin,
            contacted_origin=endpoint.origin,
        )
        replay = replay_bundle_detailed(bundle_root)
        verified = verify_public_endpoint_pilot_attachment(
            EvidenceStore(bundle_root), replay.manifest, replay
        )
        if verified is None or verified.attestation.campaign_id != CAMPAIGN_ID:
            raise RuntimeError("completed pilot lacks the fixed public-endpoint attestation")

        failure_stage = "publication"
        os.replace(bundle_root, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if journal is None:
            shutil.rmtree(incomplete, ignore_errors=True)
            _fsync_directory(destination.parent)
        else:
            try:
                journal.mark_incomplete(failure_stage)
            except Exception:
                LOGGER.exception("failed to advance preserved attempt journal to incomplete")
        raise
    shutil.rmtree(incomplete, ignore_errors=True)
    _fsync_directory(destination.parent)
    return destination / "manifest.json"


def replay_public_endpoint_pilot(bundle_root: Path) -> dict[str, Any]:
    """Verify the component replay and its signed public-endpoint attachment."""

    root = bundle_root.expanduser().resolve(strict=True)
    replay = replay_bundle_detailed(root)
    verified = verify_public_endpoint_pilot_attachment(EvidenceStore(root), replay.manifest, replay)
    if verified is None:
        raise ValueError("bundle has no signed public-endpoint evidence")
    if verified.attestation.campaign_id != CAMPAIGN_ID:
        raise ValueError("bundle does not belong to the fixed public endpoint campaign")
    _manifest, manifest_bytes = EvidenceStore(root).load_manifest_with_bytes()
    return {
        "status": "public_endpoint_pilot_replay_ok",
        "campaign_id": CAMPAIGN_ID,
        "bundle_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "miner_uid": verified.attestation.expected_miner_uid,
        "miner_hotkey": verified.attestation.miner_hotkey,
        "announced_origin": verified.attestation.announced_origin,
        "network": verified.attestation.chain_observation.network,
        "genesis_block_hash": verified.attestation.chain_observation.genesis_block_hash,
        "finalized_block_number": verified.attestation.chain_observation.block_number,
        "finalized_block_hash": verified.attestation.chain_observation.block_hash,
        "outcome": verified.attestation.outcome_classification,
        "summary": score_summary(replay.scoring),
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "validator_input_eligible": False,
    }


def inspect_public_endpoint_attempt(journal_root: Path) -> dict[str, Any]:
    """Read and verify one incomplete attempt journal without finalizing or rerunning it."""

    verified = load_attempt_journal(journal_root)
    manifest = verified.manifest
    observation = manifest.chain_observation
    return {
        "status": "public_endpoint_attempt_journal_ok",
        "schema": manifest.schema_,
        "journal_manifest_sha256": verified.manifest_sha256,
        "phase": manifest.phase,
        "completed_through": manifest.completed_through,
        "failure_stage": manifest.failure_stage,
        "campaign_id": manifest.campaign_id,
        "attempt_count": manifest.attempt_count,
        "coordinator_hotkey": manifest.coordinator_hotkey,
        "expected_miner_uid": manifest.expected_miner_uid,
        "miner_hotkey": manifest.miner_hotkey,
        "announced_origin": manifest.announced_origin,
        "network": observation.network,
        "genesis_block_hash": observation.genesis_block_hash,
        "finalized_block_number": observation.block_number,
        "finalized_block_hash": observation.block_hash,
        "finalized_block_timestamp_ms": observation.block_timestamp_unix_ms,
        "request_digest": manifest.request_digest,
        "feed_eligible": False,
        "replayable_score": False,
        "translation_weights_active": False,
        "protocol_conformance": False,
        "activation_evidence": False,
        "validator_input_eligible": False,
    }


def _wallet(args: argparse.Namespace) -> Any:
    import bittensor as bt

    return bt.Wallet(
        name=args.wallet_name,
        hotkey=args.hotkey,
        path=str(Path(args.wallet_path).expanduser()),
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Prepare, run, and replay the public SN78 miner endpoint pilot"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    prepare = commands.add_parser("prepare", help="create one sealed miner-bound case")
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--wallet-name", required=True)
    prepare.add_argument("--hotkey", required=True, help="UMI coordinator hotkey name")
    prepare.add_argument("--wallet-path", default="~/.bittensor/wallets")
    prepare.add_argument(
        "--expected-coordinator-hotkey",
        required=True,
        help="public SS58 coordinator hotkey that the selected wallet must sign for",
    )
    prepare.add_argument("--expected-miner-uid", type=int, required=True)
    prepare.add_argument("--expected-miner-hotkey", required=True)
    prepare.add_argument("--setup-allowance", type=float, default=DEFAULT_SETUP_ALLOWANCE_SECONDS)
    prepare.add_argument("--response-window", type=float, default=DEFAULT_RESPONSE_WINDOW_SECONDS)
    prepare.add_argument("--reveal-margin", type=float, default=DEFAULT_REVEAL_MARGIN_SECONDS)

    run = commands.add_parser("run", help="contact the finalized chain endpoint once")
    run.add_argument("--case", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--wallet-name", required=True)
    run.add_argument("--hotkey", required=True, help="UMI coordinator hotkey name")
    run.add_argument("--wallet-path", default="~/.bittensor/wallets")
    run.add_argument("--network", choices=("finney",), default="finney")
    run.add_argument("--request-timeout", type=float, default=240.0)
    run.add_argument(
        "--reveal-timeout",
        type=float,
        default=None,
        help="optional override; must last through the case reveal plus its safety allowance",
    )

    inspect = commands.add_parser("inspect-case", help="verify and print sealed case metadata")
    inspect.add_argument("--case", type=Path, required=True)

    inspect_attempt = commands.add_parser(
        "inspect-attempt",
        help="verify one preserved incomplete attempt without contacting the miner",
    )
    inspect_attempt.add_argument("--journal", type=Path, required=True)

    replay = commands.add_parser("replay", help="verify a completed public endpoint bundle")
    replay.add_argument("--bundle", type=Path, required=True)
    return parser


def main() -> None:
    parser = _parser()
    args = parser.parse_args()
    logging.basicConfig(level=logging.INFO)
    try:
        if args.command == "inspect-case":
            campaign = load_public_pilot_campaign(args.case)
            result = {
                "status": "public_endpoint_pilot_case_ok",
                "campaign_id": campaign.campaign_id,
                "coordinator_hotkey": campaign.coordinator_hotkey,
                "expected_miner_uid": campaign.expected_miner_uid,
                "expected_miner_hotkey": campaign.expected_miner_hotkey,
                "response_close_round": campaign.response_close_round,
                "reveal_round": campaign.reveal_round,
            }
        elif args.command == "inspect-attempt":
            result = inspect_public_endpoint_attempt(args.journal)
        elif args.command == "replay":
            result = replay_public_endpoint_pilot(args.bundle)
        elif args.command == "prepare":
            wallet = _wallet(args)
            manifest = prepare_public_endpoint_pilot_case(
                args.output,
                wallet=wallet,
                expected_coordinator_hotkey=args.expected_coordinator_hotkey,
                expected_miner_uid=args.expected_miner_uid,
                expected_miner_hotkey=args.expected_miner_hotkey,
                setup_allowance_seconds=args.setup_allowance,
                response_window_seconds=args.response_window,
                reveal_margin_seconds=args.reveal_margin,
            )
            campaign = load_public_pilot_campaign(args.output)
            _case_manifest, case_manifest_bytes = EvidenceStore(
                args.output
            ).load_manifest_with_bytes()
            result = {
                "status": "public_endpoint_pilot_case_prepared",
                "manifest": str(manifest),
                "manifest_sha256": hashlib.sha256(case_manifest_bytes).hexdigest(),
                "campaign_id": campaign.campaign_id,
                "coordinator_hotkey": campaign.coordinator_hotkey,
                "expected_miner_uid": campaign.expected_miner_uid,
                "expected_miner_hotkey": campaign.expected_miner_hotkey,
                "response_close_round": campaign.response_close_round,
                "reveal_round": campaign.reveal_round,
            }
        else:
            manifest = asyncio.run(
                run_public_endpoint_pilot(
                    args.case,
                    args.output,
                    wallet=_wallet(args),
                    network=args.network,
                    request_timeout_seconds=args.request_timeout,
                    reveal_timeout_seconds=args.reveal_timeout,
                )
            )
            result = replay_public_endpoint_pilot(manifest.parent)
            result["bundle_manifest"] = str(manifest)
    except (OSError, RuntimeError, ValueError) as error:
        parser.exit(2, f"public endpoint pilot failed: {error}\n")
    print(canonical_json_bytes(result).decode())


if __name__ == "__main__":
    main()
