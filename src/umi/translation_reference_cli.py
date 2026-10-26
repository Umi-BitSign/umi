"""Run the explicitly configured automatic approval/channel owner."""

import argparse
import asyncio
import json
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from .concurrency import run_until_stopped
from .open_competition import digest
from .private_files import read_private_model
from .translation_reference_channel import ReferenceHorizonExpired
from .translation_reference_config import (
    ReferencePublisherConfig,
    build_reference_service,
    selected_inputs,
)

_SAFE_RUNTIME_ERRORS = frozenset(
    {"owned_finality_observer_stopped", "owned_finality_provider_closed"}
)
_SAFE_CAUSE_REASONS = frozenset(
    {"proof_rpc_rate_limited", "proof_rpc_failed", "proof_rpc_error", "validation_failed"}
)


def _redacted_error_chain(error):
    """Retain typed observer failures without printing RPC URLs or exception text."""
    result = []
    seen = set()
    current = error
    while current is not None and len(result) < 4 and id(current) not in seen:
        seen.add(id(current))
        item = {"error_type": type(current).__name__}
        reason = getattr(current, "reason_code", None)
        if isinstance(reason, str) and reason in _SAFE_CAUSE_REASONS:
            item["reason_code"] = reason
        elif (
            isinstance(current, RuntimeError)
            and len(current.args) == 1
            and isinstance(current.args[0], str)
            and current.args[0] in _SAFE_RUNTIME_ERRORS
        ):
            item["reason_code"] = current.args[0]
        result.append(item)
        current = current.__cause__
    return result


def report(value):
    print(
        json.dumps({"observed_at_utc": datetime.now(timezone.utc).isoformat(), **value}), flush=True
    )


async def run(config):
    loop, stop = asyncio.get_running_loop(), asyncio.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stop.set)
    try:
        started = time.monotonic()
        report(
            dict(
                stage="reference_owner_prepare",
                completed=0,
                total=1,
                elapsed_seconds=0,
                eta_seconds=None,
                planning_seconds=[2, 120],
                eta_basis="bounded local configuration/resources; native startup separate",
            )
        )
        service = build_reference_service(config, progress=report)
        report(
            dict(
                stage="reference_owner_prepare",
                completed=1,
                total=1,
                elapsed_seconds=time.monotonic() - started,
                eta_seconds=0,
                eta_basis="local service construction completed; native startup separate",
            )
        )
        await run_until_stopped(service.run(stop), stop)
    finally:
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.remove_signal_handler(sig)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("check", "run"))
    parser.add_argument("--config", required=True, type=Path)
    args = parser.parse_args(argv)
    started = time.monotonic()
    try:
        config = read_private_model(args.config, ReferencePublisherConfig, maximum_bytes=1024**2)
        if args.action == "check":
            selected, chain = selected_inputs(config)
            report(
                dict(
                    status="configuration_valid",
                    config_sha256=digest(config),
                    series_sha256=digest(selected.series),
                    chain_config_sha256=digest(chain),
                    runtime_qualified=False,
                    credentials_opened=False,
                    signer_loaded=False,
                    completed=1,
                    total=1,
                    elapsed_seconds=time.monotonic() - started,
                    eta_seconds=0,
                    eta_basis="local configuration check complete",
                )
            )
        else:
            asyncio.run(run(config))
    except Exception as error:
        # SDK/parser exceptions may include credentials or private paths.
        report(
            dict(
                status="repair_required",
                error_type=type(error).__name__,
                completed=0,
                total=1,
                elapsed_seconds=time.monotonic() - started,
                eta_seconds=None,
                eta_basis="repair required; completion is not forecast",
                recovery="restore_original_inputs_or_supported_configuration_no_reset",
                error_chain=_redacted_error_chain(error),
                **(
                    dict(
                        reason_code="reference_directive_horizon_expired",
                        selected_horizon=error.selected_horizon,
                        current_block=error.current_block,
                    )
                    if isinstance(error, ReferenceHorizonExpired)
                    else {}
                ),
            )
        )
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
