"""Historical eligibility replay from retained bytes and owned finalized ancestry.

Historical results neither impersonate a fresh observation nor credit an interval.
Control history, allocation matching and reward opportunity remain separate.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Literal

from .competition_chain import _hotkey, _uint
from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_eligibility import (
    _MAX_EVIDENCE_BYTES,
    RewardEligibilityRuntime,
    _eligibility_inputs,
    _EligibilitySubject,
    _vector,
)
from .competition_reward_eligibility_math import epoch_eligibility
from .competition_reward_transaction_recovery import _hex, _WeightArchive
from .concurrency import run_owned_thread
from .encoding import account_id32
from .open_competition import Registration, digest
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext

_ISSUER = object()


@dataclass(frozen=True, slots=True)
class OwnedHistoricalRewardEligibility:
    control: OwnedHistoricalRewardControl
    subject: _EligibilitySubject
    timestamp_ms: int
    runtime_profile_sha256: str
    reason: str
    chain_evidence: bytes = field(repr=False)
    eligibility_evidence: bytes = field(repr=False)
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def eligible(self) -> bool:
        return self.reason == "eligible"


def _binding(value: OwnedHistoricalRewardEligibility) -> str:
    state = value.subject
    return digest(
        {
            "control": value.control._binding,
            "block": state.block,
            "uid": state.validator_uid,
            "permit": state.validator_permit,
            "last_update": state.validator_last_update,
            "registered_count": state.registered_uid_count,
            "registrations": [r.model_dump(mode="json") for r in state.registrations],
            "row": state.validator_row,
            "timestamp_ms": value.timestamp_ms,
            "runtime_profile": value.runtime_profile_sha256,
            "reason": value.reason,
            "chain": hashlib.sha256(value.chain_evidence).hexdigest(),
            "eligibility": hashlib.sha256(value.eligibility_evidence).hexdigest(),
        }
    )


def validate_historical_reward_eligibility(
    value: OwnedHistoricalRewardEligibility,
    *,
    expected_control_hotkey: str,
    expected_chain_config_sha256: str,
    expected_runtime_profile_sha256: str,
) -> None:
    if (
        type(value) is not OwnedHistoricalRewardEligibility
        or value._issuer is not _ISSUER
        or type(value.control) is not OwnedHistoricalRewardControl
        or type(value.subject) is not _EligibilitySubject
        or type(value.chain_evidence) is not bytes
        or type(value.eligibility_evidence) is not bytes
        or value.chain_submission_authorized is not False
        or value.runtime_profile_sha256 != expected_runtime_profile_sha256
        or value._binding != _binding(value)
    ):
        raise ValueError("historical eligibility lacks selected native provenance")
    validate_historical_reward_control(
        value.control,
        expected_control_hotkey=expected_control_hotkey,
        expected_chain_config_sha256=expected_chain_config_sha256,
    )


class _EligibilityArchive:
    """Exact bounded eligibility answers, with no external RPC fallback."""

    def __init__(self, raw: bytes, chain: bytes, profile: RewardEligibilityRuntime, runtime):
        if type(raw) is not bytes or not 0 < len(raw) <= _MAX_EVIDENCE_BYTES:
            raise ValueError("eligibility archive exceeds its byte bound")
        body = json.loads(raw)
        if (
            type(body) is not dict
            or set(body)
            != {"schema", "chain_evidence_sha256", "runtime_profile_sha256", "storage_batches"}
            or canonical_json_bytes(body) != raw
            or body["schema"] != "umi-reward-eligibility-evidence/1"
            or body["chain_evidence_sha256"] != hashlib.sha256(chain).hexdigest()
            or body["runtime_profile_sha256"] != digest(profile)
        ):
            raise ValueError("eligibility archive differs from its selected native context")
        batches = body["storage_batches"]
        # At most 256 registered keys and 65,536 additional parent keys.
        if type(batches) is not list or not 1 <= len(batches) <= 389:
            raise ValueError("eligibility archive has invalid proof batch coverage")
        self.snapshot = runtime.snapshot
        self.values, self.proofs = {}, {}
        for batch in batches:
            if (
                type(batch) is not dict
                or set(batch) != {"state_root", "claims", "proof"}
                or batch["state_root"] != self.snapshot.state_root
                or type(batch["claims"]) is not list
                or not 1 <= len(batch["claims"]) <= 512
            ):
                raise ValueError("eligibility archive has invalid storage batch")
            keys = []
            for claim in batch["claims"]:
                if type(claim) is not dict or set(claim) != {"key", "value"}:
                    raise ValueError("eligibility archive claim is malformed")
                key, value = claim["key"], claim["value"]
                _hex(key, 4096)
                if value is not None:
                    _hex(value, _MAX_EVIDENCE_BYTES, empty=True)
                if key in self.values:
                    raise ValueError("eligibility archive repeats a claim")
                self.values[key] = value
                keys.append(key)
            if keys != sorted(set(keys)):
                raise ValueError("eligibility archive reorders a proof batch")
            self.proofs[tuple(keys)] = batch["proof"]
        self.used_keys, self.used_batches = set(), set()

    async def request(self, method, params):
        if len(params) != 2 or params[-1] != self.snapshot.block_hash:
            raise ValueError("eligibility archive cannot read another snapshot")
        if method == "state_getStorageAt" and params[0] in self.values:
            self.used_keys.add(params[0])
            return self.values[params[0]]
        if method == "state_getReadProof" and tuple(params[0]) in self.proofs:
            self.used_batches.add(tuple(params[0]))
            return {"at": self.snapshot.block_hash, "proof": self.proofs[tuple(params[0])]}
        raise ValueError("eligibility archive lacks the requested storage evidence")

    def consumed(self):
        if self.used_keys != set(self.values) or self.used_batches != set(self.proofs):
            raise ValueError("eligibility archive contains unused proof evidence")


def _subject(runtime, values, hotkey):
    def decode(item, *params, pallet="SubtensorModule"):
        key = runtime.storage_key(pallet, item, params)
        if key not in values:
            raise ValueError("historical eligibility lacks required weight state")
        return runtime.decode_storage(pallet, item, values[key])

    n = _uint(decode("SubnetworkN", 78), 256)
    if (
        n == 0
        or decode("NetworksAdded", 78) is not True
        or type(decode("MechanismCountCurrent", 78)) is not int
        or decode("MechanismCountCurrent", 78) != 1
        or decode("CommitRevealWeightsEnabled", 78) is not False
    ):
        raise ValueError("historical eligibility requires a supported complete subnet")
    uid = _uint(decode("Uids", 78, hotkey), n - 1)
    members = tuple(Registration(uid=i, hotkey=_hotkey(decode("Keys", 78, i))) for i in range(n))
    if (
        len({account_id32(r.hotkey) for r in members}) != n
        or account_id32(members[uid].hotkey) != account_id32(hotkey)
        or any(_uint(decode("Uids", 78, r.hotkey), n - 1) != r.uid for r in members)
    ):
        raise ValueError("historical eligibility registration mapping is inconsistent")
    permits, updates = (
        _vector(decode("ValidatorPermit", 78), n),
        _vector(decode("LastUpdate", 78), n),
    )
    if any(type(p) is not bool for p in permits):
        raise ValueError("historical eligibility permits are malformed")
    for update in updates:
        _uint(update, runtime.snapshot.block_number)
    row = decode("Weights", 78, uid)
    if (
        not isinstance(row, (tuple, list))
        or len(row) > n
        or any(not isinstance(r, (tuple, list)) or len(r) != 2 for r in row)
    ):
        raise ValueError("historical eligibility row is malformed")
    subject = _EligibilitySubject(
        runtime.snapshot.block_number,
        uid,
        permits[uid],
        updates[uid],
        n,
        members,
        tuple(tuple(r) for r in row),
    )
    timestamp = _uint(decode("Now", pallet="Timestamp"), 2**53 - 1)
    return subject, timestamp


async def review_reward_eligibility(
    provider: HistoricalRewardControlProvider,
    *,
    control: bytes,
    chain: bytes,
    eligibility: bytes,
    metadata: bytes,
    validator_hotkey: str,
    control_hotkey: str,
    profile: RewardEligibilityRuntime,
    expected_runtime_profile_sha256: str,
    maximum_parent_hotkeys: int = 4096,
) -> OwnedHistoricalRewardEligibility:
    """Replay without a wall-clock expiry or a current-observation capability.

    Individual proof/ancestry operations remain bounded and retryable. The host
    independently selects the original runtime profile and control identity.
    """
    profile = RewardEligibilityRuntime.model_validate_json(canonical_json_bytes(profile))
    if (
        not isinstance(provider, HistoricalRewardControlProvider)
        or digest(profile) != expected_runtime_profile_sha256
        or _uint(maximum_parent_hotkeys, 65536) == 0
    ):
        raise ValueError("historical eligibility requires selected native inputs")
    hotkey = _hotkey(validator_hotkey)
    async with provider._lock:
        observed, runtime = await provider._review_control_runtime_locked(control, metadata)
        validate_historical_reward_control(
            observed,
            expected_control_hotkey=control_hotkey,
            expected_chain_config_sha256=digest(provider.config),
        )
        if (
            type(runtime) is not ExecutedRuntimeContext
            or hashlib.sha256(runtime.code_evidence.value).hexdigest()
            != profile.runtime_code_sha256
        ):
            raise ValueError("historical eligibility requires the proved qualified runtime")
        weights = await run_owned_thread(_WeightArchive, chain, runtime, provider.config, control)
        if weights.body.get("registrations_complete") is not True:
            raise ValueError("historical eligibility requires complete registration evidence")
        collector = provider._proofs.with_evidence_rpc(weights)
        values = {}
        for keys in weights.batches:
            batch = await collector.storage_evidence_many(runtime.snapshot, keys)
            values.update((c.storage_key, c.value) for c in batch.claims)
        code = await provider._runtime_proofs.with_evidence_rpc(weights).storage_evidence(
            runtime.snapshot, b":code"
        )
        if code.value != runtime.code_evidence.value:
            raise ValueError("historical weight runtime proof differs")
        subject, timestamp = await run_owned_thread(_subject, runtime, values, hotkey)
        archive = await run_owned_thread(_EligibilityArchive, eligibility, chain, profile, runtime)
        collector = provider._proofs.with_evidence_rpc(archive)
        state, _ = await _eligibility_inputs(
            subject, runtime, collector.storage_reads, maximum_parent_hotkeys
        )
        archive.consumed()
        result = OwnedHistoricalRewardEligibility(
            observed,
            subject,
            timestamp,
            digest(profile),
            epoch_eligibility(state),
            chain,
            eligibility,
            _issuer=_ISSUER,
        )
        object.__setattr__(result, "_binding", _binding(result))
        validate_historical_reward_eligibility(
            result,
            expected_control_hotkey=control_hotkey,
            expected_chain_config_sha256=digest(provider.config),
            expected_runtime_profile_sha256=digest(profile),
        )
        return result
