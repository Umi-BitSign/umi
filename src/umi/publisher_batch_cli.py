"""Installed publisher-side CLI for constructing one sealed launch batch."""

from __future__ import annotations

import argparse
import hashlib
import sys
from collections.abc import Sequence
from pathlib import Path

from .encoding import account_id32
from .policy import ScoringPolicy, validate_rehearsal_runtime
from .protocol import PROTOCOL_VERSION, base64url_decode, canonical_json_bytes
from .publisher_availability import AvailabilityWindow
from .publisher_availability_cli import (
    ASSEMBLY_CONFIG_SCHEMA,
    AvailabilityAssemblyConfig,
)
from .publisher_batch import (
    PublisherBatchError,
    PublisherBatchIdentity,
    PublisherBatchSource,
    PublisherBatchWindow,
    create_publisher_batch_identity,
    derive_publisher_batch_window,
    inspect_publisher_reserve_video,
    load_publisher_batch_release,
    prepare_publisher_batch_from_paths,
    read_canonical_private_publisher_input,
    read_canonical_public_publisher_input,
    validate_publisher_batch_window,
    write_private_publisher_document,
    write_publisher_batch,
    write_publisher_batch_identity,
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create opaque IDs and a sealed UMI publisher batch"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    derive_window = commands.add_parser(
        "derive-window",
        help="derive exact window bytes from a caller-supplied announcement observation",
    )
    derive_window.add_argument("--policy", type=Path, required=True)
    derive_window.add_argument("--window-index", type=int, required=True)
    derive_window.add_argument("--announcement-block-hash", required=True)
    derive_window.add_argument("--announcement-timestamp-ms", type=int, required=True)
    derive_window.add_argument("--output", type=Path)
    derive_window.add_argument("--check", action="store_true")

    initialize = commands.add_parser(
        "initialize",
        help="allocate a private batch identity after the window announcement is finalized",
    )
    initialize.add_argument("--policy", type=Path, required=True)
    initialize.add_argument("--window", type=Path, required=True)
    initialize.add_argument("--publisher-hotkey", required=True)
    initialize.add_argument("--output", type=Path)
    initialize.add_argument("--check", action="store_true")

    build = commands.add_parser(
        "build",
        help="inspect fourteen clips and construct the pool body, manifest, and timelock",
    )
    build.add_argument("--policy", type=Path, required=True)
    build.add_argument("--identity", type=Path, required=True)
    build.add_argument("--source", type=Path, required=True)
    build.add_argument("--output", type=Path)
    build.add_argument("--ffmpeg", default="ffmpeg")
    build.add_argument("--ffprobe", default="ffprobe")
    build.add_argument("--check", action="store_true")

    reserve = commands.add_parser(
        "inspect-reserve-video",
        help="inspect one reserve clip with the policy-pinned media tools",
    )
    reserve.add_argument("--policy", type=Path, required=True)
    reserve.add_argument("--video", type=Path, required=True)
    reserve.add_argument("--expected-video-sha256", required=True)
    reserve.add_argument("--ffmpeg", default="ffmpeg")
    reserve.add_argument("--ffprobe", default="ffprobe")
    reserve.add_argument("--output", type=Path, required=True)

    availability = commands.add_parser(
        "availability-config",
        help="replay one to three batch releases and create exact availability assembly input",
    )
    availability.add_argument("--policy", type=Path, required=True)
    availability.add_argument("--window", type=Path, required=True)
    availability.add_argument(
        "--release-root",
        type=Path,
        required=True,
        action="append",
    )
    availability.add_argument("--output", type=Path)
    availability.add_argument("--check", action="store_true")
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        policy = read_canonical_public_publisher_input(args.policy, ScoringPolicy)
        validate_rehearsal_runtime(policy)
        if args.command != "inspect-reserve-video" and not args.check and args.output is None:
            raise PublisherBatchError("publisher_batch_output_required")
        if args.command == "derive-window":
            return _derive_window(args, policy)
        if args.command == "initialize":
            return _initialize(args, policy)
        if args.command == "build":
            return _build(args, policy)
        if args.command == "inspect-reserve-video":
            return _inspect_reserve_video(args, policy)
        if args.command == "availability-config":
            return _availability_config(args, policy)
        raise RuntimeError("argument parser returned an unknown publisher command")
    except Exception as error:
        if isinstance(error, PublisherBatchError):
            reason = error.reason_code
        elif isinstance(error, FileExistsError):
            reason = "publisher_batch_output_exists"
        else:
            reason = "publisher_batch_failed"
        sys.stderr.buffer.write(
            canonical_json_bytes(
                {
                    "schema": "umi-publisher-batch-cli-error/1",
                    "protocol": PROTOCOL_VERSION,
                    "reason_code": str(reason),
                }
            )
            + b"\n"
        )
        return 2


def _derive_window(args: argparse.Namespace, policy: ScoringPolicy) -> int:
    window = derive_publisher_batch_window(
        policy=policy,
        window_index=args.window_index,
        announcement_block_hash=args.announcement_block_hash,
        announcement_timestamp_ms=args.announcement_timestamp_ms,
    )
    encoded = canonical_json_bytes(window)
    if not args.check:
        if args.output is None:
            raise ValueError("--output is required unless --check is used")
        write_private_publisher_document(window, args.output)
    _emit(
        {
            "schema": "umi-publisher-batch-window-result/1",
            "protocol": PROTOCOL_VERSION,
            "status": "checked" if args.check else "created",
            "window_id": window.window_id,
            "window_sha256": hashlib.sha256(encoded).hexdigest(),
            "announcement_finality_verified": False,
            "state_mutated": not args.check,
            "translation_weights_active": False,
        }
    )
    return 0


def _initialize(args: argparse.Namespace, policy: ScoringPolicy) -> int:
    window = read_canonical_public_publisher_input(args.window, PublisherBatchWindow)
    validate_publisher_batch_window(
        policy=policy,
        window=window,
        publisher_hotkey=args.publisher_hotkey,
    )
    if args.check:
        identity = None
        expected_wer = None
    else:
        if args.output is None:
            raise ValueError("--output is required unless --check is used")
        identity = create_publisher_batch_identity(
            policy=policy,
            window=window,
            publisher_hotkey=args.publisher_hotkey,
        )
        write_publisher_batch_identity(identity, args.output)
        expected_wer = identity.expected_wer_canary_stratum
    _emit(
        {
            "schema": "umi-publisher-batch-initialize-result/1",
            "protocol": PROTOCOL_VERSION,
            "status": "checked" if args.check else "created",
            "window_id": window.window_id,
            "publisher_hotkey": args.publisher_hotkey,
            "wer_canary_stratum": expected_wer,
            "state_mutated": not args.check,
            "translation_weights_active": False,
        }
    )
    return 0


def _build(args: argparse.Namespace, policy: ScoringPolicy) -> int:
    identity = read_canonical_private_publisher_input(args.identity, PublisherBatchIdentity)
    validate_publisher_batch_window(
        policy=policy,
        window=identity.window,
        publisher_hotkey=identity.publisher_hotkey,
    )
    source = read_canonical_private_publisher_input(args.source, PublisherBatchSource)
    prepared = prepare_publisher_batch_from_paths(
        policy=policy,
        identity=identity,
        source=source,
        ffmpeg=args.ffmpeg,
        ffprobe=args.ffprobe,
    )
    if not args.check:
        if args.output is None:
            raise ValueError("--output is required unless --check is used")
        write_publisher_batch(prepared, args.output)
        installed = load_publisher_batch_release(
            args.output,
            policy=policy,
            window=identity.window,
        )
        if installed.release != prepared.release:
            raise PublisherBatchError("publisher_batch_installed_release_mismatch")
    release_bytes = canonical_json_bytes(prepared.release)
    _emit(
        {
            "schema": "umi-publisher-batch-build-result/1",
            "protocol": PROTOCOL_VERSION,
            "status": "checked" if args.check else "created",
            "window_id": prepared.release.window_id,
            "batch_id": prepared.release.batch_id,
            "batch_commitment": prepared.release.batch_commitment,
            "release_sha256": hashlib.sha256(release_bytes).hexdigest(),
            "state_mutated": not args.check,
            "translation_weights_active": False,
        }
    )
    return 0


def _inspect_reserve_video(args: argparse.Namespace, policy: ScoringPolicy) -> int:
    inspection = inspect_publisher_reserve_video(
        policy=policy,
        video_path=args.video,
        expected_video_sha256=args.expected_video_sha256,
        ffmpeg=args.ffmpeg,
        ffprobe=args.ffprobe,
    )
    encoded = canonical_json_bytes(inspection)
    write_private_publisher_document(inspection, args.output)
    _emit(
        {
            "schema": "umi-publisher-reserve-video-inspection-result/1",
            "protocol": PROTOCOL_VERSION,
            "status": "created",
            "receipt_sha256": hashlib.sha256(encoded).hexdigest(),
            "state_mutated": True,
            "translation_weights_active": False,
        }
    )
    return 0


def _availability_config(args: argparse.Namespace, policy: ScoringPolicy) -> int:
    window = read_canonical_public_publisher_input(args.window, PublisherBatchWindow)
    if len(args.release_root) > policy.limits.max_candidate_batches_total:
        raise PublisherBatchError("publisher_batch_release_count_limit")
    loaded = [
        load_publisher_batch_release(root, policy=policy, window=window)
        for root in args.release_root
    ]
    for item in loaded:
        validate_publisher_batch_window(
            policy=policy,
            window=window,
            publisher_hotkey=item.release.publisher_hotkey,
        )
    publisher_accounts = [account_id32(item.release.publisher_hotkey) for item in loaded]
    batch_ids = [base64url_decode(item.release.batch_id) for item in loaded]
    if len(set(publisher_accounts)) != len(publisher_accounts):
        raise PublisherBatchError("publisher_batch_release_publisher_duplicate")
    if len(set(batch_ids)) != len(batch_ids):
        raise PublisherBatchError("publisher_batch_release_batch_duplicate")

    videos = [
        {
            "batch_id": item.release.batch_id,
            "challenge_id": challenge_id,
            "path": str(path),
        }
        for item in loaded
        for challenge_id, path in item.video_paths_by_challenge.items()
    ]
    videos.sort(
        key=lambda item: (
            base64url_decode(item["batch_id"]),
            base64url_decode(item["challenge_id"]),
        )
    )
    envelopes = [
        {
            "batch_id": item.release.batch_id,
            "path": str(item.envelope_path),
        }
        for item in loaded
    ]
    envelopes.sort(key=lambda item: base64url_decode(item["batch_id"]))
    config = AvailabilityAssemblyConfig.model_validate(
        {
            "schema": ASSEMBLY_CONFIG_SCHEMA,
            "protocol": PROTOCOL_VERSION,
            "window": AvailabilityWindow.from_plan(window.to_plan()).model_dump(mode="json"),
            "pool_body_paths": sorted(str(item.pool_body_path) for item in loaded),
            "public_manifest_paths": sorted(str(item.public_manifest_path) for item in loaded),
            "ground_truth_envelopes": envelopes,
            "videos": videos,
        }
    )
    encoded = canonical_json_bytes(config)
    if not args.check:
        if args.output is None:
            raise ValueError("--output is required unless --check is used")
        write_private_publisher_document(config, args.output)
    _emit(
        {
            "schema": "umi-publisher-batch-availability-config-result/1",
            "protocol": PROTOCOL_VERSION,
            "status": "checked" if args.check else "created",
            "window_id": window.window_id,
            "batch_count": len(loaded),
            "assembly_config_sha256": hashlib.sha256(encoded).hexdigest(),
            "state_mutated": not args.check,
            "translation_weights_active": False,
        }
    )
    return 0


def _emit(document: dict[str, object]) -> None:
    sys.stdout.buffer.write(canonical_json_bytes(document) + b"\n")


def main() -> None:
    raise SystemExit(run_cli())


__all__ = ["main", "run_cli"]
