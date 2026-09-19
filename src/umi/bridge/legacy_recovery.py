"""Legacy-only receipt recovery, shared by the worker and recovery command.

V1 matching and durable journal bytes remain unchanged. V2 journals require the
exact-byte reader and cannot acquire authority through this historical path.
No command parsing, wallet access, signing or broadcast belongs here.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from functools import partial
from typing import Protocol

from ..bootstrap_weight_operator import BootstrapExtrinsicReference
from ..concurrency import run_owned_thread
from ..encoding import account_id32
from ..encoding import datetime_to_unix_ms as _datetime_ms
from .journal import RegistrationBridgeJournal
from .policy import _require
from .selection import RegistrationBridgeObservation
from .submission import BridgeStatePort


class LegacyBlockInfo(Protocol):
    number: int
    hash: str
    extrinsics: Sequence[object]


class LegacyRecoveryClient(Protocol):
    async def block_info(self, *, block: int) -> LegacyBlockInfo: ...
    async def query(self, item: tuple[str, str], *, block: int) -> Sequence[object]: ...


class LegacyRecoveryChain(Protocol):
    def clock(self) -> datetime: ...
    async def verify_finalized_receipt_with_client(
        self,
        client: LegacyRecoveryClient,
        receipt: BootstrapExtrinsicReference,
        *,
        observation: RegistrationBridgeObservation,
    ) -> None: ...


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


def prove_applied_attempt(
    journal: RegistrationBridgeJournal,
    observation: RegistrationBridgeObservation,
    block_info: LegacyBlockInfo,
    events: Sequence[object],
) -> BootstrapExtrinsicReference:
    """Return the unique finalized receipt proving this uncertain attempt."""

    # V2 requires exact signed-byte inclusion, not merely a matching decoded
    # call from the same hotkey. This historical repair cannot supply that proof.
    _require(
        type(journal) is RegistrationBridgeJournal,
        "recovery_version_requires_exact_transaction_proof",
    )
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


def persist_recovered_attempt(
    state: BridgeStatePort,
    journal: RegistrationBridgeJournal,
    observation: RegistrationBridgeObservation,
    receipt: BootstrapExtrinsicReference,
    *,
    now_ms: int,
) -> RegistrationBridgeJournal:
    """Retain receipt and applied through two existing durable publications."""

    _require(
        type(journal) is RegistrationBridgeJournal,
        "recovery_version_requires_exact_transaction_proof",
    )
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


async def recover_with_client(
    state: BridgeStatePort,
    journal: RegistrationBridgeJournal,
    observation: RegistrationBridgeObservation,
    client: LegacyRecoveryClient,
    chain: LegacyRecoveryChain,
) -> tuple[RegistrationBridgeJournal, BootstrapExtrinsicReference]:
    """Prove and persist an uncertain attempt as applied, without submitting."""

    writer = next(
        item for item in observation.participants if item.hotkey == journal.validator_hotkey
    )
    block_info = await client.block_info(block=writer.last_update)
    events = await client.query(("System", "Events"), block=writer.last_update)
    receipt = prove_applied_attempt(journal, observation, block_info, events)
    await chain.verify_finalized_receipt_with_client(client, receipt, observation=observation)
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
    return applied, receipt
