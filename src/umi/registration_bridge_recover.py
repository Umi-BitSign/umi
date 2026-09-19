"""Recover a proven registration-bridge submission without rebroadcasting.

The normal bridge deliberately holds when submission outcome is unknown. This
tool can close that hold only when finalized chain history contains the exact
intended call, signed by the same validator, with a successful dispatch event,
and the current finalized row still shows that call's effect.
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from collections.abc import Sequence
from functools import partial
from pathlib import Path

from .bridge.legacy_recovery import _call_params as _call_params
from .bridge.legacy_recovery import _event_matches as _event_matches
from .bridge.legacy_recovery import persist_recovered_attempt as persist_recovered_attempt
from .bridge.legacy_recovery import prove_applied_attempt as prove_applied_attempt
from .bridge.legacy_recovery import recover_with_client as recover_with_client
from .bridge.policy import _require
from .bridge.state import RegistrationBridgeState
from .concurrency import run_owned_thread
from .encoding import datetime_to_unix_ms as _datetime_ms
from .protocol import canonical_json_bytes
from .registration_bridge import BittensorRegistrationBridgeChain


async def recover_applied_attempt(
    state_dir: Path,
    *,
    execute: bool,
    confirm_attempt_id: str | None,
    confirm_extrinsic_id: str | None,
    chain=None,
):
    chain = chain or BittensorRegistrationBridgeChain()
    try:
        with RegistrationBridgeState(state_dir.resolve()) as state:
            journal = state.load()
            _require(journal is not None, "recovery_journal_missing")
            async with chain.client_factory("finney") as client:
                observation = await chain.observation_with_client(
                    client, validator_hotkey=journal.validator_hotkey
                )
                journal = await run_owned_thread(
                    partial(state.initialize, observation, now=chain.clock())
                )
                writer = next(
                    item
                    for item in observation.participants
                    if item.hotkey == journal.validator_hotkey
                )
                block_info = await client.block_info(block=writer.last_update)
                events = await client.query(("System", "Events"), block=writer.last_update)
                receipt = prove_applied_attempt(journal, observation, block_info, events)
                await chain.verify_finalized_receipt_with_client(
                    client, receipt, observation=observation
                )
            result = {
                "attempt_id": journal.attempt.attempt_id,
                "block_hash": receipt.block_hash,
                "extrinsic_id": receipt.extrinsic_id,
                "reason_code": "exact_successful_attempt_found",
                "status": "recoverable",
                "validator_hotkey": journal.validator_hotkey,
            }
            if not execute:
                return result
            _require(
                confirm_attempt_id == journal.attempt.attempt_id,
                "recovery_attempt_confirmation_mismatch",
            )
            _require(
                confirm_extrinsic_id == receipt.extrinsic_id,
                "recovery_extrinsic_confirmation_mismatch",
            )
            applied = await run_owned_thread(
                partial(
                    persist_recovered_attempt,
                    state,
                    journal,
                    observation,
                    receipt,
                    now_ms=_datetime_ms(chain.clock()),
                )
            )
            _require(applied.phase == "applied", "recovery_transition_mismatch")
            return {
                **result,
                "reason_code": "exact_successful_attempt_recovered",
                "status": "applied",
            }
    finally:
        await chain.aclose()


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/umi-worker"))
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--confirm-attempt-id")
    parser.add_argument("--confirm-extrinsic-id")
    return parser


def run_cli(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    try:
        result = asyncio.run(
            recover_applied_attempt(
                args.state_dir,
                execute=args.execute,
                confirm_attempt_id=args.confirm_attempt_id,
                confirm_extrinsic_id=args.confirm_extrinsic_id,
            )
        )
        print(canonical_json_bytes(result).decode())
        return 0
    except Exception as error:
        print(
            canonical_json_bytes(
                {
                    "reason_code": getattr(error, "reason_code", "bridge_recovery_failed"),
                    "status": "held",
                }
            ).decode()
        )
        return 2


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
