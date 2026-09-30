"""Capture original historical weight and eligibility proofs for coverage replay.

The selected historical control is authenticated again under owned finality.
This creates no fresh transaction observation and changes no freshness rule.
"""

from __future__ import annotations

import hashlib
import json

from .competition_chain import _hotkey, _uint, model_burn_storage_reads
from .competition_chain_state import _runtime_execution_evidence
from .competition_reward_control_archive import (
    HistoricalRewardControlProvider,
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_eligibility import (
    _MAX_EVIDENCE_BYTES,
    RewardEligibilityRuntime,
    _eligibility_inputs,
    _spec,
)
from .competition_reward_eligibility_archive import (
    OwnedHistoricalRewardEligibility,
    _subject,
    review_reward_eligibility,
)
from .open_competition import digest
from .protocol import canonical_json_bytes
from .runtime_metadata import ExecutedRuntimeContext
from .validator_chain import StorageReadSpec


def _batches(batches):
    return [
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
    ]


async def capture_reward_eligibility(
    provider: HistoricalRewardControlProvider,
    control: OwnedHistoricalRewardControl,
    *,
    validator_hotkey: str,
    control_hotkey: str,
    profile: RewardEligibilityRuntime,
    expected_runtime_profile_sha256: str,
    maximum_parent_hotkeys: int = 4096,
) -> OwnedHistoricalRewardEligibility:
    """Capture a fixed root with bounded RPC/proof operations and no total timer."""
    profile = RewardEligibilityRuntime.model_validate_json(canonical_json_bytes(profile))
    if (
        not isinstance(provider, HistoricalRewardControlProvider)
        or digest(profile) != expected_runtime_profile_sha256
        or _uint(maximum_parent_hotkeys, 65536) == 0
    ):
        raise ValueError("historical capture requires selected native inputs")
    validate_historical_reward_control(
        control,
        expected_control_hotkey=control_hotkey,
        expected_chain_config_sha256=digest(provider.config),
    )
    return await _capture(
        provider,
        control,
        _hotkey(validator_hotkey),
        control_hotkey,
        profile,
        maximum_parent_hotkeys,
    )


async def _capture(provider, control, hotkey, control_hotkey, profile, maximum_parent_hotkeys):
    async with provider._lock:
        observed, runtime = await provider._review_control_runtime_locked(
            control.evidence, control.metadata
        )
        if (
            observed.snapshot != control.snapshot
            or type(runtime) is not ExecutedRuntimeContext
            or hashlib.sha256(runtime.code_evidence.value).hexdigest()
            != profile.runtime_code_sha256
        ):
            raise ValueError("historical capture requires the proved qualified runtime")
        batches, values = [], {}

        async def read(specs):
            batch = await provider._weight_read(runtime, tuple(dict.fromkeys(specs)))
            batches.append(batch)
            values.update((c.storage_key, c.value) for c in batch.evidence.claims)
            return {r.spec: r.decoded_value for r in batch.reads}

        base = await read(
            (
                StorageReadSpec("Timestamp", "Now", ()),
                _spec("NetworksAdded", 78),
                _spec("SubnetworkN", 78),
                _spec("Uids", 78, hotkey),
                _spec("ValidatorPermit", 78),
                _spec("LastUpdate", 78),
                _spec("MechanismCountCurrent", 78),
                _spec("CommitRevealWeightsEnabled", 78),
                *model_burn_storage_reads(provider.policy),
            )
        )
        count = _uint(base[_spec("SubnetworkN", 78)], 256)
        if count == 0:
            raise ValueError("historical capture requires a registered validator")
        uid = _uint(base[_spec("Uids", 78, hotkey)], count - 1)
        members = await read(tuple(_spec("Keys", 78, i) for i in range(count)))
        await read(
            tuple(_spec("Uids", 78, _hotkey(members[_spec("Keys", 78, i)])) for i in range(count))
        )
        await read((_spec("Weights", 78, uid),))
        subject, _ = _subject(runtime, values, hotkey)
        chain = canonical_json_bytes(
            {
                "schema": "umi-competition-weight-state-evidence/1",
                "config_sha256": digest(provider.config),
                "block": runtime.snapshot.block_number,
                "block_hash": runtime.snapshot.block_hash,
                "state_root": runtime.snapshot.state_root,
                "finality": json.loads(control.evidence)["finality"],
                "runtime_metadata_sha256": runtime.metadata_sha256,
                "runtime_version": json.loads(runtime.runtime_version_bytes),
                **(
                    {"storage_codec_mode": runtime.storage_codec_mode}
                    if runtime.storage_codec_mode != "exact_runtime"
                    else {}
                ),
                "runtime_execution": _runtime_execution_evidence(runtime),
                "storage_batches": _batches(batches),
                "registrations_complete": True,
                "pending_commitment_absence_proven": False,
            }
        )
        if len(chain) > _MAX_EVIDENCE_BYTES:
            raise ValueError("historical weight evidence exceeds its byte bound")
        _, eligibility_batches = await _eligibility_inputs(
            subject, runtime, provider._weight_read, maximum_parent_hotkeys
        )
        eligibility = canonical_json_bytes(
            {
                "schema": "umi-reward-eligibility-evidence/1",
                "chain_evidence_sha256": hashlib.sha256(chain).hexdigest(),
                "runtime_profile_sha256": digest(profile),
                "storage_batches": _batches(eligibility_batches),
            }
        )
        if len(eligibility) > _MAX_EVIDENCE_BYTES:
            raise ValueError("historical eligibility evidence exceeds its byte bound")
    # Use the same native consumer as restart/recovery; the producer does not
    # issue its own eligibility capability or bypass proof completeness checks.
    return await review_reward_eligibility(
        provider,
        control=control.evidence,
        metadata=control.metadata,
        chain=chain,
        eligibility=eligibility,
        validator_hotkey=hotkey,
        control_hotkey=control_hotkey,
        profile=profile,
        expected_runtime_profile_sha256=digest(profile),
        maximum_parent_hotkeys=maximum_parent_hotkeys,
    )
