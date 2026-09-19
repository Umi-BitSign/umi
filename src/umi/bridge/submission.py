"""Versioned bridge submission I/O with durable, exact-byte transaction identity.

One invocation may sign and broadcast one new attempt. Recovery never broadcasts
retained bytes. A transport result is only a hint; the owned receipt reader and
separate current-row check determine the recorded result.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from functools import partial
from typing import Protocol

import bittensor as bt

from ..concurrency import await_owned_task, run_owned_thread
from ..encoding import datetime_to_unix_ms
from ..grandpa_finality import FINNEY_GENESIS_HASH
from ..protocol import canonical_json_bytes
from ..signed_extrinsic import encode_mortal_call, exact_signed_extrinsic
from .policy import SignedRegistrationBridgePolicy, _require
from .receipts import VerifiedBridgeReceipt, retain_verified_receipt
from .selection import (
    RegistrationBridgeDecision,
    RegistrationBridgeHealth,
    RegistrationBridgeObservation,
    _validate_row,
    validate_registration_bridge_chain,
    validate_registration_bridge_observation,
)
from .signing import BridgeSigningState
from .transactions import (
    BridgeJournal,
    RegistrationBridgeTransactionJournal,
    evolve_journal,
    new_transaction_journal,
    reconcile_transaction_journal,
    retain_signed_extrinsic,
)


class BridgeStatePort(Protocol):
    def require_unchanged(self) -> None: ...
    def store(self, journal: BridgeJournal, *, archive: bool = False) -> None: ...
    def legacy(self) -> tuple[bytes | None, str | None]: ...


class BridgeChainPort(Protocol):
    def clock(self) -> datetime: ...
    async def observation_with_client(
        self, client: bt.Client, *, validator_hotkey: str
    ) -> RegistrationBridgeObservation: ...
    async def signing_observation_with_client(
        self, client: bt.Client, *, validator_hotkey: str
    ) -> tuple[RegistrationBridgeObservation, BridgeSigningState]: ...
    async def exact_receipt_with_client(
        self, client: bt.Client, journal: RegistrationBridgeTransactionJournal
    ) -> VerifiedBridgeReceipt | None: ...


class BridgeSignerPort(Protocol):
    ss58_address: str
    crypto_type: int

    def sign(self, payload: bytes) -> bytes: ...


def build_registration_bridge_call(decision: RegistrationBridgeDecision, *, call_builder=None):
    _require(decision.action == "submit", "weight_submission_not_due")
    _validate_row(decision.expected_row)
    params = {
        "netuid": 78,
        "mecid": 0,
        "dests": list(range(256)),
        "weights": [pair[1] for pair in decision.expected_row],
        "version_key": 4_294_967_296,
    }
    expected = canonical_json_bytes(params)
    call = (call_builder or bt.calls.SubtensorModule.set_mechanism_weights)(**params)
    _require(
        call.module == "SubtensorModule"
        and call.function == "set_mechanism_weights"
        and canonical_json_bytes(call.params) == expected,
        "weight_call_shape_changed",
    )
    return call


async def persist(
    state: BridgeStatePort, journal: BridgeJournal, *, archive: bool = False
) -> BridgeJournal:
    # Keep the service lock until all directory syncs and publication complete,
    # including repeated caller cancellation and archive/current crash windows.
    await run_owned_thread(partial(state.store, journal, archive=archive))
    return journal


def submission_freshness(
    policy: SignedRegistrationBridgePolicy,
    observation: RegistrationBridgeObservation,
    health: list[RegistrationBridgeHealth],
    *,
    now: datetime,
) -> None:
    now_ms = datetime_to_unix_ms(now)
    reserve_ms = policy.body.submission_timeout_seconds * 1000
    _require(
        now_ms - observation.block_timestamp_ms + reserve_ms
        <= policy.body.maximum_finalized_age_seconds * 1000,
        "submission_finality_headroom_insufficient",
    )
    _require(
        all(
            now_ms - item.checked_at_unix_ms + reserve_ms <= policy.body.health_ttl_seconds * 1000
            for item in health
        ),
        "submission_health_headroom_insufficient",
    )


def validate_active_observation(
    policy: SignedRegistrationBridgePolicy,
    observation: RegistrationBridgeObservation,
    chain: BridgeChainPort,
    revision: str,
    valid_from: int,
    valid_through: int,
) -> None:
    _require(
        valid_from <= observation.block_number <= valid_through, "supervisor_directive_inactive"
    )
    validate_registration_bridge_chain(
        policy, observation, expected_revision=revision, now=chain.clock()
    )


async def recover_transaction(
    journal: RegistrationBridgeTransactionJournal,
    *,
    state: BridgeStatePort,
    chain: BridgeChainPort,
    client: bt.Client,
) -> tuple[RegistrationBridgeTransactionJournal, RegistrationBridgeObservation]:
    """Resolve a version-2 attempt using fresh proofs, without signing or sending.

    A fresh available nonce after mortality closes the retry ambiguity even when
    a historical body is unavailable. An advanced nonce needs the exact receipt.
    Receipt-returned records always reauthenticate inclusion after restart.
    """
    _require(
        type(journal) is RegistrationBridgeTransactionJournal, "bridge_journal_version_invalid"
    )
    hotkey = journal.validator_hotkey
    if journal.phase in {"preparing", "signed", "submitting", "outcome_unknown"}:
        observed, signing = await chain.signing_observation_with_client(
            client, validator_hotkey=hotkey
        )
        state.require_unchanged()
        if (
            observed.block_number >= journal.attempt.era_death
            and signing.nonce == journal.attempt.signing.nonce
        ):
            expired = reconcile_transaction_journal(
                journal, observed, now=chain.clock(), signing_state=signing
            )
            return await persist(state, expired, archive=True), observed
        _require(
            journal.phase in {"submitting", "outcome_unknown"}
            and journal.signed_extrinsic is not None,
            "prior_submission_outcome_unknown",
        )
    proven = await chain.exact_receipt_with_client(client, journal)
    state.require_unchanged()
    _require(proven is not None, "prior_submission_outcome_unknown")
    if journal.phase != "receipt_returned":
        journal = await persist(
            state, retain_verified_receipt(journal, proven, now=chain.clock()), archive=True
        )
    else:
        # Validate the retained receipt against the local proof, but preserve
        # its immutable archived transition instead of republishing it.
        retain_verified_receipt(journal, proven, now=chain.clock())
    observed = await chain.observation_with_client(client, validator_hotkey=hotkey)
    state.require_unchanged()
    return journal, observed


async def submit_transaction(
    policy: SignedRegistrationBridgePolicy,
    *,
    observation: RegistrationBridgeObservation,
    health: list[RegistrationBridgeHealth],
    health_observation: RegistrationBridgeObservation,
    decision: RegistrationBridgeDecision,
    signing_state: BridgeSigningState,
    previous: BridgeJournal,
    signer: BridgeSignerPort,
    state: BridgeStatePort,
    chain: BridgeChainPort,
    client: bt.Client,
    expected_revision: str,
    directive_valid_from: int,
    directive_valid_through: int,
) -> tuple[RegistrationBridgeTransactionJournal, RegistrationBridgeObservation]:
    """Persist preparing -> signed -> submitting, then send only those bytes."""

    def preflight():
        state.require_unchanged()
        _, legacy_digest = state.legacy()
        _require(
            legacy_digest == previous.legacy_journal_sha256, "legacy_journal_changed_before_submit"
        )
        validate_active_observation(
            policy,
            observation,
            chain,
            expected_revision,
            directive_valid_from,
            directive_valid_through,
        )
        checked = validate_registration_bridge_observation(
            policy,
            observation,
            health,
            expected_revision=expected_revision,
            now=chain.clock(),
            health_observation=health_observation,
        )
        _require(checked == decision, "weight_decision_changed_before_submit")
        submission_freshness(policy, observation, health, now=chain.clock())

    preflight()
    journal = new_transaction_journal(
        policy,
        observation,
        decision,
        health,
        signing_state=signing_state,
        previous=previous,
        now=chain.clock(),
        health_observation=health_observation,
    )
    await persist(state, journal, archive=True)
    preflight()
    encoded = await run_owned_thread(
        partial(
            encode_mortal_call,
            build_registration_bridge_call(decision),
            runtime=signing_state.runtime,
            signer=signer,
            validator_hotkey=journal.validator_hotkey,
            nonce=signing_state.nonce,
            mortality_period=policy.body.submission_era_period,
            genesis_hash="0x" + FINNEY_GENESIS_HASH,
        )
    )
    journal = await persist(
        state, retain_signed_extrinsic(journal, encoded, now=chain.clock()), archive=True
    )
    preflight()
    journal = await persist(
        state,
        evolve_journal(
            journal, phase="submitting", updated_at_unix_ms=datetime_to_unix_ms(chain.clock())
        ),
        archive=True,
    )
    try:
        preflight()
        # The SDK's submit_signed path neither composes nor signs. Its transport
        # excludes author submission methods from reconnect replay.
        task = asyncio.create_task(
            asyncio.wait_for(
                client._substrate.submit_signed(
                    exact_signed_extrinsic(encoded),
                    signer,
                    wait_for_inclusion=True,
                    wait_for_finalization=True,
                ),
                timeout=policy.body.submission_timeout_seconds,
            )
        )
        await await_owned_task(task, on_cancel=task.cancel)
        state.require_unchanged()
        proven = await chain.exact_receipt_with_client(client, journal)
        state.require_unchanged()
        _require(proven is not None, "prior_submission_outcome_unknown")
        retained = retain_verified_receipt(journal, proven, now=chain.clock())
    except BaseException:
        if journal.phase == "submitting":
            # store() checks the exact retained snapshot. A failed archive or
            # current write cannot be overwritten with a guessed outcome.
            await persist(
                state,
                evolve_journal(
                    journal,
                    phase="outcome_unknown",
                    updated_at_unix_ms=datetime_to_unix_ms(chain.clock()),
                ),
                archive=True,
            )
        raise
    # Receipt persistence is outside the transport-error handler. Cancellation
    # can finish this write before propagating; a stale local variable must not
    # attempt to replace that completed transition with outcome_unknown.
    journal = await persist(state, retained, archive=True)
    _require(proven.successful, "bridge_weight_submission_failed")
    after = await chain.observation_with_client(client, validator_hotkey=journal.validator_hotkey)
    state.require_unchanged()
    validate_active_observation(
        policy, after, chain, expected_revision, directive_valid_from, directive_valid_through
    )
    applied = reconcile_transaction_journal(journal, after, now=chain.clock())
    await persist(state, applied, archive=True)
    return applied, after
