"""Recheck retained standing transactions at their original finalized snapshot.

The returned receipt query is derived from proved historical state and actual
signed bytes. It grants no current reward authority or permission to retry.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import partial
from typing import Literal

from .competition_chain import _uint
from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    validate_historical_reward_control,
)
from .competition_reward_transactions import (
    PendingStandingWeight,
    StandingWeightJournal,
)
from .competition_weight_archive import WeightStateArchive
from .concurrency import run_owned_thread
from .mortal_receipts import MortalReceiptQuery
from .open_competition import digest
from .runtime_metadata import ExecutedRuntimeContext
from .signed_extrinsic import verify_mortal_call


@dataclass(frozen=True)
class ReviewedStandingTransaction:
    pending: PendingStandingWeight
    query: MortalReceiptQuery | None
    chain_submission_authorized: Literal[False] = False


async def review_standing_transaction(
    provider: HistoricalRewardControlProvider,
    journal: StandingWeightJournal,
    *,
    control_hotkey: str,
) -> ReviewedStandingTransaction | None:
    """Verify original context after restart, without replacing a pending attempt.

    The provider owns finality, runtime selection and proof verifiers. A receipt
    consumer may use the checked query; neither an empty result nor an unsigned
    intent proves that a nonce is free or that another submission is authorized.
    """
    if (
        not isinstance(provider, HistoricalRewardControlProvider)
        or type(journal) is not StandingWeightJournal
    ):
        raise TypeError("standing recovery requires the native provider and journal")
    inputs = await run_owned_thread(journal.recovery_inputs)
    if inputs is None:
        return None
    pending, intent = inputs.pending, inputs.pending.intent
    async with provider._lock:
        control, runtime = await provider._review_control_runtime_locked(
            inputs.control, inputs.metadata
        )
        validate_historical_reward_control(
            control,
            expected_control_hotkey=control_hotkey,
            expected_chain_config_sha256=digest(provider.config),
        )
        if (
            intent.chain_config_sha256 != digest(provider.config)
            or (intent.block, intent.block_hash)
            != (control.snapshot.block_number, control.snapshot.block_hash)
            or intent.decision_sha256 != control.control_sha256
        ):
            raise ValueError("standing intent differs from original control or chain")
        archive = await run_owned_thread(
            WeightStateArchive, inputs.chain, runtime, provider.config, inputs.control
        )
        collector = provider._proofs.with_evidence_rpc(archive)
        values = {}
        for keys in archive.batches:
            batch = await collector.storage_evidence_many(runtime.snapshot, keys)
            values.update((claim.storage_key, claim.value) for claim in batch.claims)
        if isinstance(runtime, ExecutedRuntimeContext):
            code = await provider._runtime_proofs.with_evidence_rpc(archive).storage_evidence(
                runtime.snapshot, b":code"
            )
            if code.value != runtime.code_evidence.value:
                raise ValueError("standing recovery runtime proof differs")

        def decode(pallet, item, params=()):
            key = runtime.storage_key(pallet, item, params)
            if key not in values:
                raise ValueError("standing recovery lacks a required signing claim")
            return runtime.decode_storage(pallet, item, values[key])

        account = decode("System", "Account", (intent.validator_hotkey,))
        uid = _uint(decode("SubtensorModule", "Uids", (78, intent.validator_hotkey)), 255)
        updates = decode("SubtensorModule", "LastUpdate", (78,))
        if not isinstance(updates, (list, tuple)) or not uid < len(updates) <= 256:
            raise ValueError("standing recovery LastUpdate coverage differs")
        if (
            type(account) is not dict
            or "nonce" not in account
            or _uint(account["nonce"], 2**32 - 1) != intent.nonce
            or _uint(updates[uid], intent.block) != intent.prior_last_update
            or _uint(decode("SubtensorModule", "WeightsVersionKey", (78,)), 2**64 - 1)
            != intent.weights_version_key
            or decode("SubtensorModule", "NetworksAdded", (78,)) is not True
        ):
            raise ValueError("standing intent differs from proved original signing state")
        query = None
        if pending.signed is not None:
            await run_owned_thread(
                partial(
                    verify_mortal_call,
                    bytes.fromhex(pending.signed.signed_extrinsic),
                    intent.call(),
                    runtime=runtime,
                    validator_hotkey=intent.validator_hotkey,
                    nonce=intent.nonce,
                    mortality_period=intent.mortality_period,
                    genesis_hash="0x" + provider.config.chain_pin.genesis_block_hash,
                )
            )
            query = MortalReceiptQuery(
                schema="umi-mortal-receipt-query/1",
                birth_block=intent.block,
                birth_hash=intent.block_hash,
                mortality_period=intent.mortality_period,
                signed_extrinsic=pending.signed.signed_extrinsic,
            )
        if await run_owned_thread(journal.recovery_inputs) != inputs:
            raise ValueError("standing attempt changed while its history was being reviewed")
        return ReviewedStandingTransaction(pending, query)
