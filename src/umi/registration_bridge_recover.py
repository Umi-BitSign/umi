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
from pathlib import Path

from .bootstrap_weight_operator import BootstrapExtrinsicReference
from .encoding import account_id32
from .protocol import canonical_json_bytes
from .registration_bridge import (
    BittensorRegistrationBridgeChain,
    RegistrationBridgeJournal,
    RegistrationBridgeState,
    _datetime_ms,
    _require,
)


def _event_matches(event, *, index: int, module: str, name: str) -> bool:
    return (
        isinstance(event, dict)
        and event.get("extrinsic_idx") == index
        and event.get("module_id") == module
        and event.get("event_id") == name
    )


def _call_params(call) -> dict:
    _require(isinstance(call, dict), "recovery_call_shape_changed")
    arguments = call.get("call_args")
    _require(isinstance(arguments, list), "recovery_call_shape_changed")
    params = {}
    for argument in arguments:
        _require(
            isinstance(argument, dict)
            and isinstance(argument.get("name"), str)
            and argument["name"] not in params
            and "value" in argument,
            "recovery_call_shape_changed",
        )
        params[argument["name"]] = argument["value"]
    return params


def prove_applied_attempt(journal, observation, block_info, events):
    """Return the unique finalized receipt proving this uncertain attempt."""

    _require(
        isinstance(journal, RegistrationBridgeJournal)
        and journal.phase in {"submitting", "outcome_unknown"}
        and journal.attempt is not None,
        "recovery_attempt_not_uncertain",
    )
    attempt = journal.attempt
    _require(
        observation.validator_hotkey == journal.validator_hotkey,
        "recovery_validator_changed",
    )
    writer = next(
        (item for item in observation.participants if item.hotkey == journal.validator_hotkey),
        None,
    )
    _require(writer is not None, "recovery_validator_not_registered")
    _require(
        observation.validator_row == attempt.expected_row,
        "recovery_expected_row_not_visible",
    )
    _require(
        attempt.preflight_block
        < writer.last_update
        <= attempt.preflight_block + attempt.signed_policy.body.submission_era_period,
        "recovery_last_update_outside_attempt_era",
    )
    _require(
        writer.last_update < attempt.signed_policy.body.submission_limit,
        "recovery_last_update_outside_policy",
    )
    _require(
        getattr(block_info, "number", None) == writer.last_update
        and isinstance(getattr(block_info, "hash", None), str),
        "recovery_block_identity_mismatch",
    )
    expected_params = {
        "netuid": 78,
        "mecid": 0,
        "dests": list(range(256)),
        "weights": [pair[1] for pair in attempt.expected_row],
        "version_key": 4_294_967_296,
    }
    matches = []
    for index, extrinsic in enumerate(getattr(block_info, "extrinsics", ())):
        if not isinstance(extrinsic, dict):
            continue
        call = extrinsic.get("call")
        if not isinstance(call, dict):
            continue
        try:
            same_signer = account_id32(extrinsic.get("address", "")) == account_id32(
                journal.validator_hotkey
            )
        except ValueError:
            same_signer = False
        if not (
            same_signer
            and call.get("call_module") == "SubtensorModule"
            and call.get("call_function") == "set_mechanism_weights"
            and _call_params(call) == expected_params
        ):
            continue
        success = any(
            _event_matches(event, index=index, module="System", name="ExtrinsicSuccess")
            for event in events
        )
        failed = any(
            _event_matches(event, index=index, module="System", name="ExtrinsicFailed")
            for event in events
        )
        weights_set = any(
            _event_matches(event, index=index, module="SubtensorModule", name="WeightsSet")
            and isinstance(event.get("attributes"), (list, tuple))
            and list(event["attributes"]) == [78, writer.uid]
            for event in events
        )
        if success and not failed and weights_set:
            matches.append(index)
    _require(len(matches) == 1, "recovery_exact_successful_call_not_unique")
    index = matches[0]
    return BootstrapExtrinsicReference(
        extrinsic_id=f"{block_info.number}-{index:04d}",
        block_number=block_info.number,
        extrinsic_index=index,
        block_hash=block_info.hash,
    )


def persist_recovered_attempt(state, journal, observation, receipt, *, now_ms: int):
    """Archive the proof-backed receipt and applied transitions atomically."""

    returned = RegistrationBridgeJournal.model_validate(
        journal.model_copy(
            update={
                "phase": "receipt_returned",
                "weight_call": receipt,
                "last_observed_block": observation.block_number,
                "last_observed_block_hash": observation.block_hash,
                "updated_at_unix_ms": now_ms,
            }
        ).model_dump(mode="python", by_alias=True)
    )
    state.store(returned, archive=True)
    applied = returned.model_copy(update={"phase": "applied", "updated_at_unix_ms": now_ms})
    state.store(applied, archive=True)
    return applied


async def recover_with_client(state, journal, observation, client, chain):
    """Prove and persist an uncertain attempt as applied, without submitting."""

    writer = next(
        item for item in observation.participants if item.hotkey == journal.validator_hotkey
    )
    block_info = await client.block_info(block=writer.last_update)
    events = await client.query(("System", "Events"), block=writer.last_update)
    receipt = prove_applied_attempt(journal, observation, block_info, events)
    await chain.verify_finalized_receipt_with_client(client, receipt, observation=observation)
    applied = persist_recovered_attempt(
        state,
        journal,
        observation,
        receipt,
        now_ms=_datetime_ms(chain.clock()),
    )
    return applied, receipt


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
                journal = state.initialize(observation, now=chain.clock())
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
            applied = persist_recovered_attempt(
                state,
                journal,
                observation,
                receipt,
                now_ms=_datetime_ms(chain.clock()),
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
