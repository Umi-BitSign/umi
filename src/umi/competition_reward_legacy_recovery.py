"""Replay C4 signing evidence and prove that its exact bytes have expired.

This is one input to migration, not permission to start another writer. The
host must still fence the old process and account for its complete retained
transaction inventory. Local outcome flags never establish an expiry.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from functools import partial
from typing import Literal

import bittensor as bt

from .chain_evidence import FinalizedSnapshotRef
from .competition_chain import _uint
from .competition_chain_state import _cache_usage
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_transactions import MAX_CONTEXT_BYTES
from .competition_weight_archive import WeightStateArchive, _hex
from .competition_weights import _WeightAttempt
from .concurrency import run_owned_thread
from .encoding import account_id32
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import collect_executed_runtime
from .signed_extrinsic import verify_mortal_call

_ISSUER = object()


class _RuntimeArchive:
    """Original codec inputs only; never supplies a live or historical RPC fallback."""

    def __init__(self, chain: bytes, metadata: bytes):
        if (
            type(chain) is not bytes
            or not 0 < len(chain) <= MAX_CONTEXT_BYTES
            or type(metadata) is not bytes
            or not 0 < len(metadata) <= 16 * 1024**2
        ):
            raise ValueError("legacy signing evidence exceeds its byte bound")
        body = json.loads(chain)
        if (
            type(body) is not dict
            or canonical_json_bytes(body) != chain
            or body.get("schema") != "umi-competition-weight-state-evidence/1"
            or body.get("runtime_metadata_sha256") != hashlib.sha256(metadata).hexdigest()
        ):
            raise ValueError("legacy signing evidence is not the original native archive")
        finality = body.get("finality")
        if (
            type(finality) is not dict
            or finality.get("evidence_class") != "verifier_attested_finality"
            or finality.get("offline_finality_proof") is not False
            or type(finality.get("block")) is not dict
        ):
            raise ValueError("legacy signing evidence lacks its original finalized header")
        encoded = finality["block"].get("scale_header")
        header = _decode_header(encoded, maximum_bytes=MAXIMUM_HEADER_BYTES)
        self.snapshot = FinalizedSnapshotRef(
            header["number"], header["hash"], header["parent_hash"], header["state_root"]
        )
        if type(body.get("block")) is not int or (
            body["block"],
            body.get("block_hash"),
            body.get("state_root"),
        ) != (self.snapshot.block_number, self.snapshot.block_hash, self.snapshot.state_root):
            raise ValueError("legacy signing archive differs from its header")
        self.body, self.metadata, self.encoded = body, metadata, encoded

    async def request(self, method, params):
        if not params or params[-1] != self.snapshot.block_hash:
            raise ValueError("legacy signing replay requested another snapshot")
        if method == "state_getRuntimeVersion" and len(params) == 1:
            return self.body["runtime_version"]
        if method == "state_getMetadata" and len(params) == 1:
            return "0x" + self.metadata.hex()
        execution = self.body.get("runtime_execution")
        if type(execution) is dict:
            if method == "state_getStorageAt" and tuple(params) == (
                "0x3a636f6465",
                self.snapshot.block_hash,
            ):
                return execution["value"]
            if (
                method == "state_getReadProof"
                and len(params) == 2
                and tuple(params[0]) == ("0x3a636f6465",)
            ):
                return {"at": self.snapshot.block_hash, "proof": execution["proof"]}
        raise ValueError("legacy runtime archive cannot make this RPC request")


@dataclass(frozen=True, slots=True)
class LegacyWeightExpiry:
    """Process-local proof about one exact old transaction; outcome remains unknown."""

    attempt_sha256: str
    chain_config_sha256: str
    validator_hotkey: str
    signed_extrinsic_hash: str
    birth_block: int
    death_block: int
    finalized: FinalizedSnapshotRef
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: LegacyWeightExpiry) -> str:
    return digest(
        {
            "attempt": value.attempt_sha256,
            "config": value.chain_config_sha256,
            "hotkey": value.validator_hotkey,
            "extrinsic": value.signed_extrinsic_hash,
            "birth": value.birth_block,
            "death": value.death_block,
            "finalized": asdict(value.finalized),
        }
    )


def validate_legacy_weight_expiry(
    value: LegacyWeightExpiry, *, attempt: bytes, chain_config_sha256: str, validator_hotkey: str
) -> None:
    """Bind a native result to the exact inventory entry being drained."""
    if (
        type(value) is not LegacyWeightExpiry
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.chain_submission_authorized is not False
        or type(attempt) is not bytes
        or value.attempt_sha256 != hashlib.sha256(attempt).hexdigest()
        or value.chain_config_sha256 != chain_config_sha256
        or account_id32(value.validator_hotkey) != account_id32(validator_hotkey)
        or not value.birth_block < value.death_block <= value.finalized.block_number
    ):
        raise ValueError("legacy transaction expiry lacks matching native provenance")


def _retained_call(runtime, encoded: bytes, version: int):
    decoded = runtime._runtime.decode_extrinsic(encoded, True)
    call = decoded.get("call") if type(decoded) is dict else None
    if (
        type(call) is not dict
        or call.get("call_module") != "SubtensorModule"
        or call.get("call_function") != "set_mechanism_weights"
        or type(call.get("call_args")) is not list
    ):
        raise ValueError("legacy transaction is not a direct mechanism weight call")
    entries = call["call_args"]
    if any(type(v) is not dict or "name" not in v or "value" not in v for v in entries):
        raise ValueError("legacy weight arguments are malformed")
    args = {v["name"]: v["value"] for v in entries}
    if (
        set(args) != {"netuid", "mecid", "dests", "weights", "version_key"}
        or len(entries) != len(args)
        or type(args["dests"]) is not list
        or type(args["weights"]) is not list
        or not 1 <= len(args["dests"]) == len(args["weights"]) <= 256
        or _uint(args["netuid"], 65535) != 78
        or _uint(args["mecid"], 255) != 0
        or _uint(args["version_key"], 2**64 - 1) != version
    ):
        raise ValueError("legacy weight call differs from its subnet or signing version")
    dests = tuple(_uint(v, 255) for v in args["dests"])
    if dests != tuple(sorted(set(dests))):
        raise ValueError("legacy weight destinations are not unique and ordered")
    for weight in args["weights"]:
        _uint(weight, 65535)
    return bt.calls.SubtensorModule.set_mechanism_weights(**args)


async def review_legacy_weight_expiry(
    provider: HistoricalRewardControlProvider,
    *,
    attempt: bytes,
    chain: bytes,
    metadata: bytes,
    validator_hotkey: str,
) -> LegacyWeightExpiry | None:
    """Check original proof/signature and current finality, ignoring outcome flags.

    A still-live signed transaction returns None. Missing signed bytes cannot
    establish a drain: the caller must handle unsigned intentions under the
    original stopped-writer protocol. No journal, service or transaction changes.
    Original proof replay has no aggregate age or elapsed-time cutoff.
    """
    if not isinstance(provider, HistoricalRewardControlProvider):
        raise TypeError("legacy recovery requires the native historical provider")
    if type(attempt) is not bytes or not 0 < len(attempt) <= 256 * 1024:
        raise ValueError("legacy attempt exceeds its byte bound")
    original = _WeightAttempt.model_validate_json(attempt)
    if (
        canonical_json_bytes(original) != attempt
        or account_id32(original.validator_hotkey) != account_id32(validator_hotkey)
        or original.chain_config_sha256 != digest(provider.config)
        or type(chain) is not bytes
        or hashlib.sha256(chain).hexdigest() != original.chain_evidence_sha256
        or original.signed_extrinsic is None
    ):
        raise ValueError("legacy recovery requires the exact retained signing inputs and bytes")
    async with provider._lock:
        if provider._closed:
            raise ValueError("legacy recovery provider is closed")
        _cache_usage(provider._cache_root, provider.config.maximum_cache_bytes)
        inputs = await run_owned_thread(_RuntimeArchive, chain, metadata)
        ref = inputs.snapshot
        if (original.preflight_block, original.preflight_hash) != (
            ref.block_number,
            ref.block_hash,
        ) or inputs.body["finality"].get(
            "genesis_hash"
        ) != "0x" + provider.config.chain_pin.genesis_block_hash:
            raise ValueError("legacy attempt differs from original signing finality")
        timestamp, ceiling = await provider._resolve_control_header(ref, inputs.encoded)
        if provider._runtime_executor is not None:
            execution = inputs.body.get("runtime_execution")
            if (
                type(execution) is not dict
                or execution.get("executor_sha256")
                != provider.config.runtime_metadata_binary_sha256
            ):
                raise ValueError("legacy runtime executor differs from selection")
            runtime = await collect_executed_runtime(
                provider._runtime_proofs.with_evidence_rpc(inputs), provider._runtime_executor, ref
            )
        else:
            if provider._storage_codec is not None:
                raise ValueError("legacy signed bytes require an authenticated signing runtime")
            runtime = await provider._proofs.with_evidence_rpc(inputs).pinned_runtime(
                ref, provider._runtime_pin
            )
        provider._validate_runtime_context(runtime, ref)
        archive = await run_owned_thread(WeightStateArchive, chain, runtime, provider.config)
        collector = provider._proofs.with_evidence_rpc(archive)
        values = {}
        for keys in archive.batches:
            batch = await collector.storage_evidence_many(ref, keys)
            values.update((c.storage_key, c.value) for c in batch.claims)

        def decode(pallet, item, params=()):
            key = runtime.storage_key(pallet, item, params)
            if key not in values:
                raise ValueError("legacy recovery lacks a required original signing claim")
            return runtime.decode_storage(pallet, item, values[key])

        actual_time = _uint(decode("Timestamp", "Now"), 2**53 - 1)
        uid = _uint(decode("SubtensorModule", "Uids", (78, original.validator_hotkey)), 255)
        account = decode("System", "Account", (original.validator_hotkey,))
        updates = decode("SubtensorModule", "LastUpdate", (78,))
        if (
            not 0 < actual_time <= ceiling
            or (timestamp is not None and timestamp != actual_time)
            or type(account) is not dict
            or _uint(account.get("nonce"), 2**32 - 1) != original.nonce
            or not isinstance(updates, (list, tuple))
            or not uid < len(updates) <= 256
            or _uint(updates[uid], ref.block_number) != original.prior_last_update
            or decode("SubtensorModule", "NetworksAdded", (78,)) is not True
        ):
            raise ValueError("legacy attempt differs from proved signing state")
        version = _uint(decode("SubtensorModule", "WeightsVersionKey", (78,)), 2**64 - 1)
        encoded = _hex(original.signed_extrinsic, 64 * 1024)
        call = await run_owned_thread(_retained_call, runtime, encoded, version)
        envelope = await run_owned_thread(
            partial(
                verify_mortal_call,
                encoded,
                call,
                runtime=runtime,
                validator_hotkey=original.validator_hotkey,
                nonce=original.nonce,
                mortality_period=original.era_death - original.preflight_block,
                genesis_hash="0x" + provider.config.chain_pin.genesis_block_hash,
            )
        )
        # Refresh owned finality after potentially slow replay. No local phase
        # or preflight-era claim can bypass verification of the encoded bytes.
        head = await provider._proofs.finalized_snapshot()
        if not isinstance(head, FinalizedSnapshotRef):
            raise ValueError("legacy expiry lacks owned finality")
        provider._check_finality(
            head, await provider._finality.verified_block_at(head.block_number)
        )
        if head.block_number < ref.block_number or (
            head.block_number == ref.block_number and head != ref
        ):
            raise ValueError("legacy expiry finality precedes its signing checkpoint")
        _cache_usage(provider._cache_root, provider.config.maximum_cache_bytes)
        if head.block_number < original.era_death:
            return None
        result = LegacyWeightExpiry(
            hashlib.sha256(attempt).hexdigest(),
            digest(provider.config),
            original.validator_hotkey,
            envelope.extrinsic_hash,
            ref.block_number,
            original.era_death,
            head,
            _issuer=_ISSUER,
        )
        object.__setattr__(result, "_binding", _binding(result))
        return result
