"""Current proof-backed eligibility under an independently qualified runtime.

The code-hash profile must be selected by the installed series qualification.
Supplying a hash does not establish a source/build correspondence. Unsupported
code or missing proofs holds collection; a permit or old epoch output is never
substituted. This consumer does not accrue coverage or authorize transactions.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field, model_validator

from .competition_chain import _hotkey, _uint
from .competition_chain_state import (
    OwnedCompetitionChainObservation,
    validate_owned_weight_observation,
)
from .competition_reward_control import FinalizedRewardControlProvider
from .competition_reward_eligibility_math import U64_MAX, EpochEligibilityInputs, epoch_eligibility
from .concurrency import wait_for_owned
from .encoding import account_id32
from .grandpa_finality import FINNEY_GENESIS_HASH
from .open_competition import Registration, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext
from .validator_chain import StorageReadSpec

_ISSUER = object()
_MAX_EVIDENCE_BYTES = 32 * 1024**2
# Exact scoped predicate qualification, independently reviewed; this does not
# claim build or contract-execution equivalence. Retained provenance and limits:
# tests/fixtures/reward-eligibility/runtime{479,481}-qualification.json.
# A signed transition still needs this gate and every endpoint's native proofs.
_QUALIFIED_YUMA_RUNTIMES: frozenset[tuple[str, str]] = frozenset(
    {
        (
            "48225f3199bf317966d0214588bc45fb49c28c3e7bd510293bb4da7d6aea224b",
            "6a972693ae9580541225bd37696ac2fee26b8ae9",
        ),
        (
            "d0ea4955e6b4366d8561038307d5e47572c1ad67664638402c8253cde26a84be",
            "f4786f9087cac84cfab37cbdf1e01c399042653a",
        ),
    }
)


class RewardEligibilityRuntime(StrictProtocolModel):
    """Selected code and reviewed pre-consensus semantics, never a code wildcard.

    /1 preserves historical c004 evidence exactly. /2 supports the reviewed
    f4786f and 6a9726 Yuma paths only: each endpoint must also prove its epoch mode. The
    source revision alone cannot select that mutable subnet state.
    """

    schema_: Literal["umi-reward-eligibility-runtime/1", "umi-reward-eligibility-runtime/2"] = (
        Field(alias="schema")
    )
    genesis_hash: Literal[FINNEY_GENESIS_HASH]
    netuid: Literal[78]
    runtime_code_sha256: Hex32
    epoch_source_revision: Literal[
        "c004cebf360f4088187ee49d851dfb1a1eaaf710",
        "f4786f9087cac84cfab37cbdf1e01c399042653a",
        "6a972693ae9580541225bd37696ac2fee26b8ae9",
    ]

    @model_validator(mode="after")
    def selected_semantics(self):
        original = "c004cebf360f4088187ee49d851dfb1a1eaaf710"
        yuma_sources = {
            "f4786f9087cac84cfab37cbdf1e01c399042653a",
            "6a972693ae9580541225bd37696ac2fee26b8ae9",
        }
        supported = (
            self.epoch_source_revision == original
            if self.schema_ == "umi-reward-eligibility-runtime/1"
            else self.epoch_source_revision in yuma_sources
        )
        if not supported:
            raise ValueError("reward eligibility profile schema and source semantics differ")
        return self

    @property
    def requires_epoch_consensus_proof(self) -> bool:
        return self.schema_ == "umi-reward-eligibility-runtime/2"


class RewardRuntimeCodeMismatch(ValueError):
    """Expose exact proved code drift without logging provider URLs or credentials."""

    reason_code = "reward_eligibility_runtime_code_mismatch"

    def __init__(self, *, expected: str, observed: str):
        self.expected_runtime_code_sha256 = expected
        self.observed_runtime_code_sha256 = observed
        super().__init__("reward eligibility requires the proved qualified runtime code")


def validate_reward_runtime_code(runtime, profile: RewardEligibilityRuntime) -> None:
    if type(runtime) is not ExecutedRuntimeContext:
        raise ValueError("reward eligibility requires an owned executed runtime context")
    observed = hashlib.sha256(runtime.code_evidence.value).hexdigest()
    if observed != profile.runtime_code_sha256:
        raise RewardRuntimeCodeMismatch(expected=profile.runtime_code_sha256, observed=observed)


class UnsupportedRewardEpochConsensus(ValueError):
    """A proved endpoint is outside the selected Yuma eligibility semantics."""

    reason_code = "reward_epoch_consensus_unsupported"


class UnsupportedRewardEligibilityRuntime(ValueError):
    """The requested new profile has no reviewed exact code/source binding."""

    reason_code = "reward_eligibility_runtime_unqualified"


def validate_qualified_reward_runtime(profile: RewardEligibilityRuntime) -> None:
    """Require qualification separately from authorization for new semantics.

    This gate is for newly authorized profiles. Existing /1 native consumers
    retain their original installed qualification and signed selector instead;
    a new adoption cannot use /1 to authorize an arbitrary replacement hash.
    """
    profile = RewardEligibilityRuntime.model_validate_json(canonical_json_bytes(profile))
    if (
        not profile.requires_epoch_consensus_proof
        or (profile.runtime_code_sha256, profile.epoch_source_revision)
        not in _QUALIFIED_YUMA_RUNTIMES
    ):
        raise UnsupportedRewardEligibilityRuntime("reward eligibility lacks a qualified runtime")


@dataclass(frozen=True, slots=True)
class OwnedRewardEligibility:
    chain: OwnedCompetitionChainObservation
    runtime_profile_sha256: str
    reason: str
    evidence: bytes = field(repr=False)
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)

    @property
    def eligible(self) -> bool:
        return self.reason == "eligible"


def _binding(value: OwnedRewardEligibility) -> str:
    return digest(
        {
            "chain": hashlib.sha256(value.chain.evidence).hexdigest(),
            "chain_binding": value.chain._binding,
            "runtime_profile": value.runtime_profile_sha256,
            "reason": value.reason,
            "evidence": hashlib.sha256(value.evidence).hexdigest(),
        }
    )


def validate_reward_eligibility(
    value: OwnedRewardEligibility,
    *,
    expected_runtime_profile_sha256: str,
    expected_chain_config_sha256: str,
) -> None:
    if (
        type(value) is not OwnedRewardEligibility
        or value._issuer is not _ISSUER
        or value._binding != _binding(value)
        or value.runtime_profile_sha256 != expected_runtime_profile_sha256
        or value.chain.chain_config_sha256 != expected_chain_config_sha256
        or not value.chain.registrations_complete
    ):
        raise ValueError("reward eligibility lacks selected native provenance")
    validate_owned_weight_observation(value.chain)


def _spec(name: str, *params) -> StorageReadSpec:
    return StorageReadSpec("SubtensorModule", name, params)


def _links(value) -> tuple[tuple[int, str], ...]:
    if not isinstance(value, (tuple, list)):
        raise ValueError("reward eligibility linkage is malformed")
    result = []
    for entry in value:
        if not isinstance(entry, (tuple, list)) or len(entry) != 2:
            raise ValueError("reward eligibility linkage is malformed")
        result.append((_uint(entry[0], U64_MAX), _hotkey(entry[1])))
    return tuple(result)


def _vector(value, size: int) -> tuple:
    if not isinstance(value, (tuple, list)) or len(value) != size:
        raise ValueError("reward eligibility vector does not cover the registry")
    return tuple(value)


async def collect_reward_eligibility(
    provider: FinalizedRewardControlProvider,
    chain: OwnedCompetitionChainObservation,
    profile: RewardEligibilityRuntime,
    *,
    expected_runtime_profile_sha256: str,
    maximum_parent_hotkeys: int = 4096,
) -> OwnedRewardEligibility:
    """Collect eligibility at the exact complete weight observation's root.

    The parent-key ceiling is a local provisioning limit, not an eligibility rule.
    Exhaustion holds collection and can be retried with more capacity. No snapshot
    is credited merely because it is too large or too slow to verify.
    """
    profile = RewardEligibilityRuntime.model_validate_json(canonical_json_bytes(profile))
    if digest(profile) != expected_runtime_profile_sha256:
        raise ValueError("reward eligibility runtime differs from selected profile")
    if profile.requires_epoch_consensus_proof:
        validate_qualified_reward_runtime(profile)
    _uint(maximum_parent_hotkeys, 65536)
    if maximum_parent_hotkeys == 0 or not isinstance(provider, FinalizedRewardControlProvider):
        raise ValueError("reward eligibility requires a standing provider and parent capacity")
    return await wait_for_owned(
        _collect(provider, chain, profile, maximum_parent_hotkeys),
        timeout=provider.config.collection_timeout_seconds,
    )


@dataclass(frozen=True)
class _EligibilitySubject:
    """Untrusted facts; only native proof consumers may issue observations."""

    block: int
    validator_uid: int
    validator_permit: bool
    validator_last_update: int
    registered_uid_count: int
    registrations: tuple[Registration, ...]
    validator_row: tuple[tuple[int, int], ...]


async def _collect(provider, chain, profile, maximum_parent_hotkeys):
    async with provider._lock:
        if provider._closed or (
            provider._owned and (provider._task is None or provider._task.done())
        ):
            raise ValueError("reward eligibility provider is not running")
        validate_owned_weight_observation(chain)
        if (
            chain.chain_config_sha256 != digest(provider.config)
            or not chain.registrations_complete
            or chain.mechanism_count != 1
            or chain.commit_reveal_enabled
        ):
            raise ValueError("reward eligibility requires complete state and supported mechanism")
        runtime = chain.runtime
        provider._validate_runtime_context(runtime, chain.snapshot)
        validate_reward_runtime_code(runtime, profile)
        block = await provider._finality.verified_block_at(chain.block)
        provider._check_finality(chain.snapshot, block)
        provider._fresh(chain.timestamp_ms)
        subject = _EligibilitySubject(
            chain.block,
            chain.validator_uid,
            chain.validator_permit,
            chain.validator_last_update,
            chain.registered_uid_count,
            chain.registrations,
            chain.validator_row,
        )
        state, batches = await _eligibility_inputs(
            subject, runtime, provider._weight_read, maximum_parent_hotkeys, profile=profile
        )
        reason = epoch_eligibility(state)
        raw = canonical_json_bytes(
            {
                "schema": "umi-reward-eligibility-evidence/1",
                "chain_evidence_sha256": hashlib.sha256(chain.evidence).hexdigest(),
                "runtime_profile_sha256": digest(profile),
                "storage_batches": [
                    {
                        "state_root": b.evidence.verified_state_root,
                        "claims": [
                            {
                                "key": "0x" + c.storage_key.hex(),
                                "value": None if c.value is None else "0x" + c.value.hex(),
                            }
                            for c in b.evidence.claims
                        ],
                        "proof": ["0x" + node.hex() for node in b.evidence.proof],
                    }
                    for b in batches
                ],
            }
        )
        if len(raw) > _MAX_EVIDENCE_BYTES:
            raise ValueError("reward eligibility evidence exceeds its byte bound")
        newest = await provider._finality.verified_finalized_snapshot()
        if (
            newest.block_number < chain.block
            or (newest.block_number == chain.block and newest != chain.snapshot)
            or newest.block_number - chain.block > provider.policy.maximum_snapshot_age_blocks
        ):
            raise ValueError("reward eligibility finality changed or became stale")
        provider._fresh(chain.timestamp_ms)
        result = OwnedRewardEligibility(chain, digest(profile), reason, raw, _issuer=_ISSUER)
        object.__setattr__(result, "_binding", _binding(result))
        validate_reward_eligibility(
            result,
            expected_runtime_profile_sha256=digest(profile),
            expected_chain_config_sha256=digest(provider.config),
        )
        return result


async def _eligibility_inputs(
    chain: _EligibilitySubject,
    runtime: ExecutedRuntimeContext,
    read_batch,
    maximum_parent_hotkeys: int,
    *,
    profile: RewardEligibilityRuntime,
):
    batches = []
    reads = {}
    present = {}

    async def read(specs):
        for start in range(0, len(specs), 512):
            batch = await read_batch(runtime, specs[start : start + 512])
            batches.append(batch)
            reads.update((r.spec, r.decoded_value) for r in batch.reads)
            claims = {c.storage_key: c.value for c in batch.evidence.claims}
            present.update(
                (
                    r.spec,
                    claims[runtime.storage_key(r.spec.pallet, r.spec.item, r.spec.params)]
                    is not None,
                )
                for r in batch.reads
            )

    members = chain.registrations
    if tuple(r.uid for r in members) != tuple(range(chain.registered_uid_count)):
        raise ValueError("reward eligibility registry is incomplete")
    owner_spec = _spec("SubnetOwnerHotkey", 78)
    globals_ = (
        owner_spec,
        _spec("TaoWeight"),
        _spec("StakeThreshold"),
        _spec("Tempo", 78),
        _spec("ActivityCutoffFactorMilli", 78),
        _spec("ValidatorPermit", 78),
        _spec("LastUpdate", 78),
    )
    consensus_spec = _spec("SubnetEpochConsensus", 78)
    await read(
        globals_
        + ((consensus_spec,) if profile.requires_epoch_consensus_proof else ())
        + tuple(
            spec
            for r in members
            for spec in (
                _spec("BlockAtRegistration", 78, r.uid),
                _spec("ParentKeys", r.hotkey, 78),
                _spec("ChildKeys", r.hotkey, 78),
                _spec("TotalHotkeyAlpha", r.hotkey, 78),
                _spec("TotalHotkeyAlpha", r.hotkey, 0),
                _spec("ChildkeyThresholdSuspended", r.hotkey),
            )
        )
    )
    if profile.requires_epoch_consensus_proof and (
        type(reads[consensus_spec]) is not str or reads[consensus_spec] != "Yuma"
    ):
        raise UnsupportedRewardEpochConsensus("reward eligibility requires proved Yuma consensus")
    # The native batch authenticates membership or absence at runtime.snapshot.
    # For ValueQuery absence, decode_storage uses the executed metadata default;
    # never infer Yuma from a missing response, permit, or earlier endpoint.
    parents = tuple(_links(reads[_spec("ParentKeys", r.hotkey, 78)]) for r in members)
    children = tuple(_links(reads[_spec("ChildKeys", r.hotkey, 78)]) for r in members)
    known = {account_id32(r.hotkey): r.hotkey for r in members}
    extra = {}
    for links in parents:
        for _, hotkey in links:
            identity = account_id32(hotkey)
            if identity not in known:
                extra[identity] = hotkey
    if len(extra) > maximum_parent_hotkeys:
        raise ValueError("reward eligibility parent proof capacity exceeded")
    await read(
        tuple(
            spec
            for _, hotkey in sorted(extra.items())
            for spec in (
                _spec("TotalHotkeyAlpha", hotkey, 78),
                _spec("TotalHotkeyAlpha", hotkey, 0),
                _spec("ChildkeyThresholdSuspended", hotkey),
            )
        )
    )
    # try_get in the reviewed epoch distinguishes absence from a decoded
    # ValueQuery default. Preserve that distinction for the owner exception.
    owner_present = present[owner_spec]
    owner = None
    owner_uid = None
    if owner_present:
        owner = _hotkey(reads[owner_spec])
        owner_uid_spec = _spec("Uids", 78, owner)
        await read((owner_uid_spec,))
        if reads[owner_uid_spec] is not None:
            owner_uid = _uint(reads[owner_uid_spec], len(members) - 1)
            if account_id32(members[owner_uid].hotkey) != account_id32(owner):
                raise ValueError("reward eligibility owner mapping is inconsistent")

    def balance(hotkey, netuid):
        # Account encodings are normalized by identity, including parents
        # whose SS58 spelling differs from their registered hotkey.
        name = known.get(account_id32(hotkey), extra.get(account_id32(hotkey), hotkey))
        return _uint(reads[_spec("TotalHotkeyAlpha", name, netuid)], U64_MAX)

    def suspended(hotkey):
        identity = account_id32(hotkey)
        name = known.get(identity, extra.get(identity, hotkey))
        return present[_spec("ChildkeyThresholdSuspended", name)] and (
            owner is None or identity != account_id32(owner)
        )

    updates = _vector(reads[_spec("LastUpdate", 78)], len(members))
    permits = _vector(reads[_spec("ValidatorPermit", 78)], len(members))
    if (
        updates[chain.validator_uid] != chain.validator_last_update
        or permits[chain.validator_uid] is not chain.validator_permit
    ):
        raise ValueError("reward eligibility differs from the weight observation")
    state = EpochEligibilityInputs(
        block=chain.block,
        validator_uid=chain.validator_uid,
        owner_uid=owner_uid,
        last_updates=updates,
        registration_blocks=tuple(reads[_spec("BlockAtRegistration", 78, r.uid)] for r in members),
        permits=permits,
        alpha=tuple(balance(r.hotkey, 78) for r in members),
        tao=tuple(balance(r.hotkey, 0) for r in members),
        parents=tuple(
            tuple((p, balance(k, 78), balance(k, 0)) for p, k in links if not suspended(k))
            for links in parents
        ),
        children=tuple(
            () if suspended(r.hotkey) else tuple(p for p, _ in links)
            for r, links in zip(members, children, strict=True)
        ),
        tao_weight=reads[_spec("TaoWeight")],
        stake_threshold=reads[_spec("StakeThreshold")],
        tempo=reads[_spec("Tempo", 78)],
        activity_factor_milli=reads[_spec("ActivityCutoffFactorMilli", 78)],
        row=chain.validator_row,
    )
    return state, batches
