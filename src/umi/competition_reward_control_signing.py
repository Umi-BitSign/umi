"""Original nonce proofs for the reserved standing reward control hotkey.

Current observations can authorize preflight checks. Archived observations
verify old signed bytes only; they never become fresh submission authority.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

from .competition_chain import _uint
from .competition_reward_control import (
    FinalizedRewardControlProvider,
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .concurrency import wait_for_owned
from .open_competition import digest
from .protocol import canonical_json_bytes
from .validator_chain import PinnedRuntimeContext, StorageReadSpec

MAX_NONCE_EVIDENCE_BYTES = 32 * 1024**2
_ISSUER = object()


@dataclass(frozen=True, slots=True)
class RewardControlSigningState:
    control: OwnedRewardControlObservation | OwnedHistoricalRewardControl
    nonce: int
    runtime: PinnedRuntimeContext = field(repr=False)
    nonce_evidence: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: RewardControlSigningState) -> str:
    return digest(
        [
            value.control.evidence_sha256,
            value.nonce,
            hashlib.sha256(value.nonce_evidence).hexdigest(),
            value.runtime.metadata_sha256,
            str(id(value.runtime)),
        ]
    )


def validate_control_signing_state(
    value: RewardControlSigningState,
    *,
    hotkey: str,
    config_sha256: str,
    historical: bool = False,
) -> None:
    if (
        type(value) is not RewardControlSigningState
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.runtime.snapshot != value.control.snapshot
    ):
        raise ValueError("control signing state lacks native proof provenance")
    check = validate_historical_reward_control if historical else validate_owned_reward_control
    check(value.control, expected_control_hotkey=hotkey, expected_chain_config_sha256=config_sha256)


def _nonce(batch, runtime, spec):
    if batch.runtime != runtime or len(batch.reads) != 1 or batch.reads[0].spec != spec:
        raise ValueError("control signing nonce proof has different coverage")
    account = batch.reads[0].decoded_value
    if type(account) is not dict or "nonce" not in account:
        raise ValueError("control signing account lacks a proved nonce")
    return _uint(account["nonce"], 2**32 - 1)


async def collect_control_signing_state(
    provider: FinalizedRewardControlProvider,
    hotkey: str,
) -> RewardControlSigningState:
    if not isinstance(provider, FinalizedRewardControlProvider):
        raise TypeError("control signing requires the native proof provider")
    control = await provider.collect_control(hotkey)

    async def collect():
        async with provider._lock:
            if provider._closed:
                raise ValueError("control signing provider is closed")
            runtime = control.runtime
            spec = StorageReadSpec("System", "Account", (hotkey,))
            batch = await provider._weight_read(runtime, (spec,))
            nonce = _nonce(batch, runtime, spec)
            newest = await provider._finality.verified_finalized_snapshot()
            ref = control.snapshot
            if (
                newest.block_number < ref.block_number
                or (newest.block_number == ref.block_number and newest != ref)
                or newest.block_number - ref.block_number
                > provider.policy.maximum_snapshot_age_blocks
            ):
                raise ValueError("control signing finality rolled back, changed or became stale")
            evidence = canonical_json_bytes(
                {
                    "schema": "umi-reward-control-nonce/1",
                    "control_evidence_sha256": control.evidence_sha256,
                    "key": "0x" + batch.evidence.claims[0].storage_key.hex(),
                    "value": None
                    if batch.evidence.claims[0].value is None
                    else "0x" + batch.evidence.claims[0].value.hex(),
                    "proof": ["0x" + n.hex() for n in batch.evidence.proof],
                }
            )
            if len(evidence) > MAX_NONCE_EVIDENCE_BYTES:
                raise ValueError("control signing nonce evidence exceeds capacity")
            value = RewardControlSigningState(control, nonce, runtime, evidence, _issuer=_ISSUER)
            object.__setattr__(value, "_binding", _binding(value))
            validate_control_signing_state(
                value, hotkey=hotkey, config_sha256=digest(provider.config)
            )
            return value

    return await wait_for_owned(collect(), timeout=provider.config.collection_timeout_seconds)


class _NonceArchive:
    def __init__(self, raw: bytes, control, runtime, hotkey):
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_NONCE_EVIDENCE_BYTES:
            raise ValueError("control nonce archive exceeds capacity")
        self.body = body = json.loads(raw)
        self.snapshot = control.snapshot
        self.key = "0x" + runtime.storage_key("System", "Account", (hotkey,)).hex()
        if (
            type(body) is not dict
            or set(body)
            != {
                "schema",
                "control_evidence_sha256",
                "key",
                "value",
                "proof",
            }
            or canonical_json_bytes(body) != raw
            or body["schema"] != "umi-reward-control-nonce/1"
            or body["control_evidence_sha256"] != control.evidence_sha256
            or body["key"] != self.key
        ):
            raise ValueError("control nonce archive changes its original context")
        self.used = set()

    async def request(self, method, params):
        if len(params) != 2 or params[-1] != self.snapshot.block_hash:
            raise ValueError("control nonce archive requested another block")
        if method == "state_getStorageAt" and params[0] == self.key:
            self.used.add("value")
            return self.body["value"]
        if method == "state_getReadProof" and tuple(params[0]) == (self.key,):
            self.used.add("proof")
            return {"at": self.snapshot.block_hash, "proof": self.body["proof"]}
        raise ValueError("control nonce archive cannot supply this request")


async def review_control_signing_state(
    provider: HistoricalRewardControlProvider,
    *,
    hotkey: str,
    control_evidence: bytes,
    nonce_evidence: bytes,
    metadata: bytes,
) -> RewardControlSigningState:
    """Replay retained proofs without requesting historical state or new metadata."""
    if not isinstance(provider, HistoricalRewardControlProvider):
        raise TypeError("control signing recovery requires the native history provider")
    async with provider._lock:
        if provider._closed:
            raise ValueError("control signing provider is closed")
        control, runtime = await provider._review_control_runtime_locked(control_evidence, metadata)
        validate_historical_reward_control(
            control,
            expected_control_hotkey=hotkey,
            expected_chain_config_sha256=digest(provider.config),
        )
        archive = _NonceArchive(nonce_evidence, control, runtime, hotkey)
        spec = StorageReadSpec("System", "Account", (hotkey,))
        batch = await provider._proofs.with_evidence_rpc(archive).storage_reads(runtime, (spec,))
        if archive.used != {"value", "proof"}:
            raise ValueError("control signing recovery did not consume its complete nonce evidence")
        value = RewardControlSigningState(
            control,
            _nonce(batch, runtime, spec),
            runtime,
            nonce_evidence,
            _issuer=_ISSUER,
        )
        object.__setattr__(value, "_binding", _binding(value))
        validate_control_signing_state(
            value,
            hotkey=hotkey,
            config_sha256=digest(provider.config),
            historical=True,
        )
        return value
