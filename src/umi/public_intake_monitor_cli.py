"""Off-host read-only monitoring and public audit backup for UMI intake."""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from pathlib import Path

from pydantic import ValidationError

from .protocol import canonical_json_bytes
from .public_intake_archive import PublicIntakeArchive, PublicIntakeArchiveError
from .public_intake_http import PublicIntakeHttpError, PublicIntakeHttpSource
from .public_intake_monitor import (
    PublicIntakeMonitorConfig,
    PublicIntakeMonitorError,
    document_sha256,
    severity_exit_code,
    validate_public_capture,
)

_MAXIMUM_CONFIG_BYTES = 1024 * 1024


def _reject_constant(_value: str):
    raise ValueError("non-finite JSON number")


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def load_config(path: Path) -> PublicIntakeMonitorConfig:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0),
    )
    try:
        details = os.fstat(descriptor)
        if (
            not stat.S_ISREG(details.st_mode)
            or details.st_uid not in {0, os.geteuid()}
            or details.st_nlink != 1
            or details.st_mode & 0o022
            or not 1 <= details.st_size <= _MAXIMUM_CONFIG_BYTES
        ):
            raise ValueError("unsafe_monitor_config_file")
        body = bytearray()
        while len(body) <= _MAXIMUM_CONFIG_BYTES:
            chunk = os.read(descriptor, min(65_536, _MAXIMUM_CONFIG_BYTES + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
    finally:
        os.close(descriptor)
    if len(body) > _MAXIMUM_CONFIG_BYTES:
        raise ValueError("unsafe_monitor_config_file")
    value = json.loads(
        body,
        object_pairs_hook=_unique_object,
        parse_constant=_reject_constant,
    )
    return PublicIntakeMonitorConfig.model_validate_json(canonical_json_bytes(value))


def _emit(value, *, error: bool = False) -> None:
    output = sys.stderr.buffer if error else sys.stdout.buffer
    output.write(canonical_json_bytes(value) + b"\n")
    output.flush()


def _poll(config: PublicIntakeMonitorConfig, archive_root: Path) -> int:
    archive = PublicIntakeArchive(archive_root)
    with archive.locked():
        context = archive.poll_context(config)
        previous = context.state
        with PublicIntakeHttpSource(config) as source:
            capture = source.capture()
        captured_at_unix_ms = time.time_ns() // 1_000_000
        try:
            validated = validate_public_capture(
                capture,
                config,
                previous_state=previous,
                now_unix_ms=captured_at_unix_ms,
            )
        except PublicIntakeMonitorError as error:
            rejected, manifest = archive.commit_rejected(
                capture,
                config,
                previous,
                reason=str(error),
                captured_at_unix_ms=captured_at_unix_ms,
                context=context,
            )
            _emit(
                {
                    "schema": "umi-public-intake-monitor-result/1",
                    "status": "rejected",
                    "severity": "unknown",
                    "reason": str(error),
                    "rejected_capture": rejected,
                    "manifest_sha256": document_sha256(manifest),
                    "chain_writes_authorized": False,
                },
                error=True,
            )
            return 3
        snapshot, manifest = archive.commit(capture, validated, config, context=context)
    _emit(
        {
            "schema": "umi-public-intake-monitor-result/1",
            "status": "healthy" if validated.severity == "ok" else "alert",
            "severity": validated.severity,
            "identity_name": validated.identity.name,
            "policy_sha256": validated.status.policy_sha256,
            "deployment_document_sha256": validated.identity.deployment_document_sha256,
            "accepted_submission_count": validated.status.accepted_submission_count,
            "admission_checked_block": validated.status.admission_checked_block,
            "observer_finalized_block": validated.observer_finalized_block,
            "retained_head_sha256": validated.status.retained_submission_head.head_sha256,
            "snapshot": snapshot,
            "manifest_sha256": document_sha256(manifest),
            "issues": [item.model_dump(mode="json", by_alias=True) for item in validated.issues],
            "validator_observations": [
                item.model_dump(mode="json", by_alias=True)
                for item in validated.validator_observations
            ],
            "chain_writes_authorized": False,
        }
    )
    return severity_exit_code(validated.severity)


def _observe(config: PublicIntakeMonitorConfig) -> int:
    with PublicIntakeHttpSource(config) as source:
        result = source.observed_identity()
    _emit(result)
    return 0


def _verify(config: PublicIntakeMonitorConfig, archive_root: Path, snapshot: str) -> int:
    archive = PublicIntakeArchive(archive_root)
    with archive.locked():
        if snapshot == "latest":
            latest = archive.latest()
            if latest is None:
                raise PublicIntakeArchiveError("archive_has_no_snapshot")
            snapshot = latest.snapshot
        manifest = archive.verify_with_config(snapshot, config)
    _emit(
        {
            "schema": "umi-public-intake-monitor-verify-result/1",
            "status": "verified",
            "snapshot": snapshot,
            "manifest_sha256": document_sha256(manifest),
            "accepted_submission_count": manifest.accepted_submission_count,
            "retained_head_sha256": manifest.retained_head_sha256,
            "chain_writes_authorized": False,
        }
    )
    return 0


def _verify_rejected(archive_root: Path, rejected_capture: str) -> int:
    archive = PublicIntakeArchive(archive_root)
    with archive.locked():
        manifest = archive.verify_rejected(rejected_capture)
    _emit(
        {
            "schema": "umi-public-intake-monitor-rejected-verify-result/1",
            "status": "verified_rejection",
            "rejected_capture": rejected_capture,
            "manifest_sha256": document_sha256(manifest),
            "reason": manifest.reason,
            "last_accepted_snapshot": manifest.last_accepted_snapshot,
            "chain_writes_authorized": False,
        }
    )
    return 0


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest="command", required=True)
    poll = subcommands.add_parser("poll", help="validate and atomically archive one public poll")
    poll.add_argument("--config", type=Path, required=True)
    poll.add_argument("--archive-root", type=Path, required=True)
    observe = subcommands.add_parser(
        "observe-identity",
        help="print an untrusted rollover candidate for independent operator review",
    )
    observe.add_argument("--config", type=Path, required=True)
    verify = subcommands.add_parser("verify", help="revalidate one committed archive snapshot")
    verify.add_argument("--config", type=Path, required=True)
    verify.add_argument("--archive-root", type=Path, required=True)
    verify.add_argument("--snapshot", default="latest")
    verify_rejected = subcommands.add_parser(
        "verify-rejected",
        help="authenticate and reproduce one rejected public capture",
    )
    verify_rejected.add_argument("--archive-root", type=Path, required=True)
    verify_rejected.add_argument("--rejected-capture", required=True)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "verify-rejected":
            return _verify_rejected(args.archive_root, args.rejected_capture)
        config = load_config(args.config)
        if args.command == "poll":
            return _poll(config, args.archive_root)
        if args.command == "observe-identity":
            return _observe(config)
        if args.command == "verify":
            return _verify(config, args.archive_root, args.snapshot)
        raise AssertionError("unknown monitor command")
    except (OSError, ValueError, ValidationError) as error:
        reason = (
            str(error)
            if isinstance(
                error,
                (PublicIntakeMonitorError, PublicIntakeHttpError, PublicIntakeArchiveError),
            )
            else "invalid_monitor_configuration_or_input"
        )
        _emit(
            {
                "schema": "umi-public-intake-monitor-error/1",
                "status": "unknown",
                "reason": reason,
                "chain_writes_authorized": False,
            },
            error=True,
        )
        return 3
    except RuntimeError as error:
        reason = (
            str(error)
            if isinstance(error, (PublicIntakeHttpError, PublicIntakeArchiveError))
            else "public_intake_monitor_failed"
        )
        _emit(
            {
                "schema": "umi-public-intake-monitor-error/1",
                "status": "unknown",
                "reason": reason,
                "chain_writes_authorized": False,
            },
            error=True,
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
