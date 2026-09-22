"""Competition host command handlers."""

from __future__ import annotations

import argparse
import asyncio
from pathlib import Path

from ..open_competition import CompetitionPolicy


def fetch_initial_successor_history(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    import hashlib

    from ..competition_delivery import HTTPSSuccessorDirectiveFetcher, write_initial_history
    from ..competition_delivery_config import successor_delivery_client
    from ..competition_host_artifacts import MAX_HOST_MANIFEST_BYTES, parse_signed_host_artifact
    from ..competition_supervisor import (
        MAX_SUCCESSOR_DOCUMENT_BYTES,
        parse_canonical_successor_operator_consent,
        parse_canonical_successor_supervisor_directive_history,
    )
    from ..validator_supervisor import parse_canonical_validator_supervisor_config

    def bounded_bytes(path, maximum=MAX_SUCCESSOR_DOCUMENT_BYTES):
        with Path(path).open("rb") as stream:
            result = stream.read(maximum + 1)
        if len(result) > maximum:
            raise ValueError("initial history input exceeds its byte limit")
        return result

    config = parse_canonical_validator_supervisor_config(bounded_bytes(args.config))
    consent = parse_canonical_successor_operator_consent(bounded_bytes(args.consent))
    host_path = getattr(args, "signed_host_artifact", None)
    client = (
        None
        if host_path is None
        else successor_delivery_client(
            config,
            parse_signed_host_artifact(bounded_bytes(host_path, MAX_HOST_MANIFEST_BYTES)),
            expected_manifest_sha256=consent.approved_host_manifest_sha256,
        )
    )
    payload = asyncio.run(
        HTTPSSuccessorDirectiveFetcher(config, client=client).fetch_initial_history(
            legacy_signed_bytes=bounded_bytes(args.accepted_directive),
            operator_consent=consent,
            finalized_block=args.current_block,
            timeout_seconds=args.timeout_seconds,
        )
    )
    write_initial_history(Path(args.output), payload)
    history = parse_canonical_successor_supervisor_directive_history(payload)
    return {
        "status": "initial_history_staged",
        "history_sha256": hashlib.sha256(payload).hexdigest(),
        "history_size_bytes": len(payload),
        "directive_count": len(history.directives),
        "head_sequence": history.head.directive.sequence,
        "host_upgrade_authorized": False,
        "chain_submission_authorized": False,
    }


def inspect_host_upgrade(args: argparse.Namespace, policy: CompetitionPolicy) -> dict:
    from dataclasses import asdict

    from ..competition_upgrade import inspect_successor_upgrade
    from ..validator_supervisor import MAX_SUPERVISOR_DOCUMENT_BYTES

    with Path(args.accepted_directive).open("rb") as stream:
        raw = stream.read(MAX_SUPERVISOR_DOCUMENT_BYTES + 1)
    if len(raw) > MAX_SUPERVISOR_DOCUMENT_BYTES:
        raise ValueError("accepted directive exceeds its byte limit")
    result = inspect_successor_upgrade(
        config_path=Path(args.config).absolute(),
        accepted_directive_bytes=raw,
        expected_hotkey=args.expected_hotkey,
        expected_platform=args.expected_platform,
        service_uid=args.service_uid,
        staged_directory=None
        if args.staged_directory is None
        else Path(args.staged_directory).absolute(),
    )
    # The inspected installation still binds its original signed policy.
    # Supplying --policy here does not replace that historical binding.
    return asdict(result)
