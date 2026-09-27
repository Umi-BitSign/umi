"""Recheck retained standing transactions at their original finalized snapshot.

The returned receipt query is derived from proved historical state and actual
signed bytes. It grants no current reward authority or permission to retry.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import partial
from typing import Literal

from .competition_chain import _uint
from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    validate_historical_reward_control,
)
from .competition_reward_transactions import (
    MAX_CONTEXT_BYTES,
    PendingStandingWeight,
    StandingWeightJournal,
)
from .concurrency import run_owned_thread
from .mortal_receipts import MortalReceiptQuery
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext
from .signed_extrinsic import verify_mortal_call


class _WeightArchive:
    """Bounded storage answers from one retained snapshot, without RPC fallback."""

    def __init__(self, raw, runtime, config, control_raw):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTEXT_BYTES:
            raise ValueError("standing recovery evidence exceeds its bound")
        body = json.loads(raw)
        required = {
            "schema",
            "config_sha256",
            "block",
            "block_hash",
            "state_root",
            "finality",
            "runtime_metadata_sha256",
            "runtime_version",
            "storage_batches",
            "pending_commitment_absence_proven",
        }
        optional = {"storage_codec_mode", "runtime_execution", "registrations_complete"}
        if (
            type(body) is not dict
            or not required <= set(body) <= required | optional
            or canonical_json_bytes(body) != raw
            or body["schema"] != "umi-competition-weight-state-evidence/1"
            or body["config_sha256"] != digest(config)
            or body["pending_commitment_absence_proven"] is not False
            or ("registrations_complete" in body and body["registrations_complete"] is not True)
        ):
            raise ValueError("standing recovery requires exact native weight evidence")
        ref = runtime.snapshot
        finality = body["finality"]
        control_finality = json.loads(control_raw)["finality"]
        if (
            (body["block"], body["block_hash"], body["state_root"])
            != (ref.block_number, ref.block_hash, ref.state_root)
            or type(body["block"]) is not int
            or body["runtime_metadata_sha256"] != runtime.metadata_sha256
            or body["runtime_version"] != json.loads(runtime.runtime_version_bytes)
            or body.get("storage_codec_mode", "exact_runtime") != runtime.storage_codec_mode
            or type(finality) is not dict
            or any(
                finality.get(k) != control_finality.get(k)
                for k in ("genesis_hash", "evidence_class", "offline_finality_proof", "block")
            )
        ):
            raise ValueError("standing weight evidence differs from owned historical context")
        self.snapshot, self.values, self.proofs = ref, {}, {}
        batches = body["storage_batches"]
        if type(batches) is not list or not 1 <= len(batches) <= 4:
            raise ValueError("standing weight evidence has invalid batch coverage")
        self.batches = []
        for batch in batches:
            if (
                type(batch) is not dict
                or set(batch) != {"state_root", "claims", "proof"}
                or batch["state_root"] != ref.state_root
                or type(batch["claims"]) is not list
                or not 1 <= len(batch["claims"]) <= 256
            ):
                raise ValueError("standing weight evidence has invalid storage batch")
            keys = []
            for claim in batch["claims"]:
                if type(claim) is not dict or set(claim) != {"key", "value"}:
                    raise ValueError("standing recovery claim is malformed")
                key, value = claim["key"], claim["value"]
                _hex(key, 4096)
                if value is not None:
                    _hex(value, MAX_CONTEXT_BYTES, empty=True)
                if key in self.values and self.values[key] != value:
                    raise ValueError("standing recovery repeats a conflicting claim")
                self.values[key] = value
                keys.append(key)
            if keys != sorted(set(keys)) or tuple(keys) in self.proofs:
                raise ValueError("standing recovery repeats or reorders a proof batch")
            self.proofs[tuple(keys)] = batch["proof"]
            self.batches.append(tuple(bytes.fromhex(k[2:]) for k in keys))
        execution = body.get("runtime_execution")
        if isinstance(runtime, ExecutedRuntimeContext):
            if (
                type(execution) is not dict
                or set(execution)
                != {
                    "executor_sha256",
                    "block",
                    "block_hash",
                    "parent_hash",
                    "state_root",
                    "key",
                    "value",
                    "proof",
                }
                or (
                    execution["block"],
                    execution["block_hash"],
                    execution["parent_hash"],
                    execution["state_root"],
                    execution["key"],
                    execution["executor_sha256"],
                )
                != (
                    ref.block_number,
                    ref.block_hash,
                    ref.parent_hash,
                    ref.state_root,
                    "0x3a636f6465",
                    runtime.executor_sha256,
                )
                or execution["value"] != "0x" + runtime.code_evidence.value.hex()
                or execution["key"] in self.values
            ):
                raise ValueError("standing recovery runtime code differs from owned execution")
            self.values[execution["key"]] = execution["value"]
            self.proofs[(execution["key"],)] = execution["proof"]
        elif execution is not None:
            raise ValueError("standing recovery has unexpected runtime execution evidence")
        self.body = body

    async def request(self, method, params):
        if len(params) != 2 or params[-1] != self.snapshot.block_hash:
            raise ValueError("standing recovery cannot read another snapshot")
        if method == "state_getStorageAt" and params[0] in self.values:
            return self.values[params[0]]
        if method == "state_getReadProof" and tuple(params[0]) in self.proofs:
            return {"at": self.snapshot.block_hash, "proof": self.proofs[tuple(params[0])]}
        raise ValueError("standing recovery lacks the requested original storage evidence")


def _hex(value, maximum, *, empty=False):
    if type(value) is not str or not value.startswith("0x") or len(value) > 2 + maximum * 2:
        raise ValueError("standing recovery storage hex is invalid")
    raw = bytes.fromhex(value[2:])
    if "0x" + raw.hex() != value or (not raw and not empty):
        raise ValueError("standing recovery storage hex is noncanonical")
    return raw


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
            _WeightArchive, inputs.chain, runtime, provider.config, inputs.control
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
