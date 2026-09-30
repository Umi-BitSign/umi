"""Eligibility predicates and native collection with synthetic chain/trie/Wasm ports.

The arithmetic tests exercise boundaries in the reviewed upstream profile. The
code bytes below are a fixture, not a qualified Finney runtime or deployment.
"""

import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from pathlib import Path

import pytest

from umi.competition_reward_control import FinalizedRewardControlProvider
from umi.competition_reward_eligibility import (
    RewardEligibilityRuntime,
    collect_reward_eligibility,
    validate_reward_eligibility,
)
from umi.competition_reward_eligibility_math import (
    U64_MAX,
    EpochEligibilityInputs,
    _inherited,
    epoch_eligibility,
)
from umi.grandpa_finality import FINNEY_GENESIS_HASH
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import RuntimeMetadataExecutor
from umi.validator_chain import FinalizedProofCollector

from .test_competition_chain import _Runtime
from .test_competition_reward_registrations import chain as chain
from .test_competition_reward_registrations import chain_config as chain_config
from .test_competition_reward_registrations import key, set_members
from .test_competition_reward_registrations import registered_case as registered_case
from .test_open_competition import policy as policy


def state(**changes):
    return replace(
        EpochEligibilityInputs(
            block=1000,
            validator_uid=1,
            owner_uid=0,
            last_updates=(950, 950),
            registration_blocks=(1, 1),
            permits=(False, True),
            alpha=(100, 100),
            tao=(0, 0),
            parents=((), ()),
            children=((), ()),
            tao_weight=0,
            stake_threshold=10,
            tempo=100,
            activity_factor_milli=1000,
            row=((0, 65535),),
        ),
        **changes,
    )


@pytest.mark.parametrize(
    ("changes", "reason"),
    [
        ({}, "eligible"),
        ({"last_updates": (950, 900)}, "eligible"),
        ({"last_updates": (950, 899)}, "inactive"),
        ({"activity_factor_milli": 0, "last_updates": (999, 999)}, "eligible"),
        ({"activity_factor_milli": 0, "last_updates": (998, 998)}, "inactive"),
        ({"permits": (False, False)}, "permit_missing"),
        ({"alpha": (100, 9)}, "stake_unavailable"),
        ({"alpha": (100, 10)}, "eligible"),
        ({"alpha": (100, 0), "tao": (0, 10), "tao_weight": U64_MAX}, "eligible"),
        ({"alpha": (100, 0), "tao": (0, 10), "tao_weight": U64_MAX - 1}, "stake_unavailable"),
        ({"alpha": (2**33, 1), "stake_threshold": 0}, "stake_rounds_to_zero"),
        ({"alpha": (100, 0), "parents": ((), ((U64_MAX, 100, 0),))}, "eligible"),
        ({"children": ((), (U64_MAX,))}, "stake_unavailable"),
        ({"children": ((), (U64_MAX, U64_MAX))}, "stake_unavailable"),
        ({"row": ((0, 60000), (1, 5535))}, "weight_masked"),
        ({"row": ((0, 65535), (1, 0))}, "eligible"),
        ({"registration_blocks": (950, 1)}, "weight_masked"),
        ({"registration_blocks": (949, 1)}, "eligible"),
        ({"row": ((0, 0),)}, "no_positive_weights"),
        ({"validator_uid": 0, "alpha": (1, 100)}, "eligible"),
        ({"validator_uid": 0, "alpha": (0, 100)}, "stake_unavailable"),
        ({"validator_uid": 0, "owner_uid": None}, "permit_missing"),
        ({"block": U64_MAX, "last_updates": (U64_MAX, U64_MAX)}, "eligible"),
    ],
)
def test_epoch_boundaries(changes, reason):
    assert epoch_eligibility(state(**changes)) == reason


@pytest.mark.parametrize(
    "changes",
    [
        {"alpha": None},
        {"alpha": (1,)},
        {"permits": (0, 1)},
        {"validator_uid": True},
        {"last_updates": (1001, 999)},
        {"row": ((0, 1), (0, 2))},
        {"row": ((1, 1), (0, 2))},
        {"tao_weight": 2**64},
        {"parents": ((), ((True, 100, 0),))},
        {"alpha": (2**63 - 1, 2**63 - 1)},
    ],
)
def test_malformed_or_unsupported_state_is_not_credited(changes):
    with pytest.raises(ValueError):
        epoch_eligibility(state(**changes))


@pytest.fixture
async def eligibility_case(registered_case, monkeypatch, tmp_path):
    t = await configure_eligibility(registered_case, monkeypatch, tmp_path)
    try:
        yield t
    finally:
        await t.provider.aclose()


async def configure_eligibility(t, monkeypatch, tmp_path):
    """Configure synthetic execution/eligibility ports around a native provider."""
    await t.provider.aclose()
    t.config = t.config.model_copy(
        update={
            "runtime_metadata_binary": str(tmp_path / "executor"),
            "runtime_metadata_binary_sha256": "ab" * 32,
        }
    )
    t.code = b"synthetic qualified epoch runtime"
    original = t.rpc.request

    async def request(method, params):
        if method == "state_getStorageAt" and params[0] == "0x3a636f6465":
            return "0x" + t.code.hex()
        return await original(method, params)

    monkeypatch.setattr(t.rpc, "request", request)
    monkeypatch.setattr("umi.runtime_metadata.bittensor_core.Runtime", _Runtime)

    def read_many(*, state_root, storage_keys, proof, **limits):
        # Synthetic SCALE port uses JSON integers for full u64 proportions;
        # these bytes are storage values, not RFC 8785 protocol objects.
        if state_root != bytes.fromhex(t.finality.ref.state_root[2:]) or proof != (b"proof",):
            raise ValueError("invalid fixture state proof")
        values = []
        for key_bytes in storage_keys:
            pallet, name, params = json.loads(key_bytes)
            value = t.rpc.values.get((pallet, name, tuple(params)))
            values.append((key_bytes, None if value is None else json.dumps(value).encode()))
        return tuple(values)

    monkeypatch.setattr(t.verifier, "read_many", read_many)

    def invoke(self, code):
        assert code == t.code
        metadata = b"metadata"
        return (
            canonical_json_bytes(
                {
                    "schema": "umi-runtime-metadata-execution/1",
                    "runtime_code_sha256": hashlib.sha256(code).hexdigest(),
                    "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                    "metadata_hex": metadata.hex(),
                    "spec_version": 452,
                    "transaction_version": 1,
                    "state_version": 1,
                    "chain_submission_authorized": False,
                }
            )
            + b"\n"
        )

    monkeypatch.setattr(RuntimeMetadataExecutor, "_invoke", invoke)
    t.provider = FinalizedRewardControlProvider(
        t.config, t.policy, finality=t.finality, proofs=t.proofs, now_ms=lambda: t.clock.now
    )
    t.provider._runtime_proofs = FinalizedProofCollector(
        t.rpc,
        finality=t.finality,
        verifier=lambda **kw: kw["proof"] == (b"proof",) and kw["expected_value"] == t.code,
    )
    t.profile = RewardEligibilityRuntime(
        schema="umi-reward-eligibility-runtime/1",
        genesis_hash=FINNEY_GENESIS_HASH,
        netuid=78,
        runtime_code_sha256=hashlib.sha256(t.code).hexdigest(),
        epoch_source_revision="c004cebf360f4088187ee49d851dfb1a1eaaf710",
    )
    t.members = [key(n) for n in ("Burn", "Alice", "Bob", "Eve")]

    def fill(members):
        for uid, hotkey in enumerate(members):
            for item, params, value in [
                ("BlockAtRegistration", (78, uid), 1),
                ("ParentKeys", (hotkey, 78), []),
                ("ChildKeys", (hotkey, 78), []),
                ("TotalHotkeyAlpha", (hotkey, 78), 1000),
                ("TotalHotkeyAlpha", (hotkey, 0), 0),
                ("ChildkeyThresholdSuspended", (hotkey,), None),
            ]:
                t.rpc.values[("SubtensorModule", item, params)] = value

    t.fill = fill
    fill(t.members)
    t.rpc.values.update(
        {
            ("SubtensorModule", "TaoWeight", ()): 0,
            ("SubtensorModule", "StakeThreshold", ()): 100,
            ("SubtensorModule", "Tempo", (78,)): 360,
            ("SubtensorModule", "ActivityCutoffFactorMilli", (78,)): 5000,
        }
    )

    async def capture(**changes):
        chain = await t.provider.collect_registered_weights(t.hotkey)
        return await collect_reward_eligibility(
            t.provider,
            chain,
            t.profile,
            expected_runtime_profile_sha256=digest(t.profile),
            **changes,
        )

    t.capture = capture
    return t


async def test_full_native_state_and_runtime_are_bound_at_one_root(eligibility_case):
    t = eligibility_case
    result = await t.capture()
    validate_reward_eligibility(
        result,
        expected_runtime_profile_sha256=digest(t.profile),
        expected_chain_config_sha256=digest(t.config),
    )
    assert result.eligible
    e = json.loads(result.evidence)
    assert e["chain_evidence_sha256"] == result.chain.evidence_sha256
    assert {b["state_root"] for b in e["storage_batches"]} == {result.chain.snapshot.state_root}
    for altered in [
        replace(result, reason="inactive"),
        replace(result, evidence=b"{}"),
        replace(result, _issuer=None),
        replace(result, chain=replace(result.chain, validator_permit=False)),
    ]:
        with pytest.raises(ValueError):
            validate_reward_eligibility(
                altered,
                expected_runtime_profile_sha256=digest(t.profile),
                expected_chain_config_sha256=digest(t.config),
            )


@pytest.mark.parametrize(
    "suspended,owner,eligible", [(False, False, True), (True, False, False), (True, True, True)]
)
async def test_external_parent_suspension_and_owner_exception(
    eligibility_case, suspended, owner, eligible
):
    t = eligibility_case
    parent = key("Ferdie")
    t.rpc.values[("SubtensorModule", "ParentKeys", (t.hotkey, 78))] = [[U64_MAX, parent]]
    t.rpc.values[("SubtensorModule", "TotalHotkeyAlpha", (t.hotkey, 78))] = 0
    for netuid, amount in [(78, 1000), (0, 0)]:
        t.rpc.values[("SubtensorModule", "TotalHotkeyAlpha", (parent, netuid))] = amount
    t.rpc.values[("SubtensorModule", "ChildkeyThresholdSuspended", (parent,))] = (
        [] if suspended else None
    )
    if owner:
        t.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = parent
    result = await t.capture()
    assert result.eligible is eligible


@pytest.mark.parametrize(
    "suspended,owner,eligible", [(False, False, False), (True, False, True), (True, True, False)]
)
async def test_suspended_outgoing_children_stop_deducting_stake(
    eligibility_case, suspended, owner, eligible
):
    t = eligibility_case
    t.rpc.values[("SubtensorModule", "ChildKeys", (t.hotkey, 78))] = [[U64_MAX, key("Alice")]]
    t.rpc.values[("SubtensorModule", "ChildkeyThresholdSuspended", (t.hotkey,))] = (
        [] if suspended else None
    )
    if owner:
        t.rpc.values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = t.hotkey
    assert (await t.capture()).eligible is eligible


async def test_parent_capacity_holds_then_recovers_without_changing_state(eligibility_case):
    t = eligibility_case
    parents = [key("Ferdie"), key("Charlie")]
    t.rpc.values[("SubtensorModule", "ParentKeys", (t.hotkey, 78))] = [
        [U64_MAX // 2, k] for k in parents
    ]
    for k in parents:
        for item, params, value in [
            ("TotalHotkeyAlpha", (k, 78), 100),
            ("TotalHotkeyAlpha", (k, 0), 0),
            ("ChildkeyThresholdSuspended", (k,), None),
        ]:
            t.rpc.values[("SubtensorModule", item, params)] = value
    with pytest.raises(ValueError, match="capacity"):
        await t.capture(maximum_parent_hotkeys=1)
    assert (await t.capture(maximum_parent_hotkeys=2)).eligible


async def test_missing_proofs_and_unqualified_code_do_not_become_ineligibility(eligibility_case):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    profile = t.profile.model_copy(update={"runtime_code_sha256": "ff" * 32})
    with pytest.raises(ValueError, match="qualified runtime"):
        await collect_reward_eligibility(
            t.provider, chain, profile, expected_runtime_profile_sha256=digest(profile)
        )
    with pytest.raises(ValueError, match="selected profile"):
        await collect_reward_eligibility(
            t.provider, chain, profile, expected_runtime_profile_sha256=digest(t.profile)
        )
    t.rpc.bad_proof = True
    with pytest.raises((ValueError, RuntimeError)):
        await collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
        )
    t.rpc.bad_proof = False
    assert (await t.capture()).eligible


async def test_complete_256_uid_domain_is_collected_in_bounded_proof_batches(eligibility_case):
    t = eligibility_case
    members = t.members + [key(f"coverage-{i}") for i in range(252)]
    set_members(t, members)
    t.fill(members)
    t.rpc.values[("SubtensorModule", "ValidatorPermit", (78,))] = [False, False, False, True] + [
        False
    ] * 252
    t.rpc.values[("SubtensorModule", "LastUpdate", (78,))] = [
        0,
        0,
        0,
        t.finality.ref.block_number - 100,
    ] + [0] * 252
    result = await t.capture()
    e = json.loads(result.evidence)
    assert result.eligible and len(e["storage_batches"]) == 5
    assert all(len(b["claims"]) <= 512 for b in e["storage_batches"])


async def test_cancellation_releases_collection_for_retry(eligibility_case, monkeypatch):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    original = t.provider._weight_read
    entered = asyncio.Event()

    async def stalled(*args):
        entered.set()
        await asyncio.Event().wait()

    with monkeypatch.context() as m:
        m.setattr(t.provider, "_weight_read", stalled)
        task = asyncio.create_task(
            collect_reward_eligibility(
                t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
            )
        )
        await asyncio.wait_for(entered.wait(), 5)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert t.provider._weight_read == original and not t.provider._lock.locked()
    assert (await t.capture()).eligible


@pytest.mark.parametrize("item", ["LastUpdate", "ValidatorPermit"])
@pytest.mark.parametrize("value", [None, [], {}, "bad"])
async def test_malformed_vectors_hold_instead_of_claiming_ineligible(eligibility_case, item, value):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    t.rpc.values[("SubtensorModule", item, (78,))] = value
    with pytest.raises(ValueError, match="vector"):
        await collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
        )


@pytest.mark.parametrize("item", ["LastUpdate", "ValidatorPermit"])
async def test_repeated_values_must_match_the_weight_observation(eligibility_case, item):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    values = list(t.rpc.values[("SubtensorModule", item, (78,))])
    values[chain.validator_uid] = (
        chain.validator_last_update - 1 if item == "LastUpdate" else not chain.validator_permit
    )
    t.rpc.values[("SubtensorModule", item, (78,))] = values
    with pytest.raises(ValueError, match="differs from the weight"):
        await collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
        )


@pytest.mark.parametrize("changed", ["stale", "rollback", "root"])
async def test_changed_finality_holds_then_allows_retry(eligibility_case, monkeypatch, changed):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    newest = replace(
        chain.snapshot,
        **(
            {"block_number": chain.block + t.policy.maximum_snapshot_age_blocks + 1}
            if changed == "stale"
            else {"block_number": chain.block - 1}
            if changed == "rollback"
            else {"state_root": "0x" + "ab" * 32}
        ),
    )

    async def changed_head():
        return newest

    with monkeypatch.context() as m:
        m.setattr(t.finality, "verified_finalized_snapshot", changed_head)
        with pytest.raises(ValueError, match="finality changed or became stale"):
            await collect_reward_eligibility(
                t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
            )
    assert (await t.capture()).eligible


async def test_head_expiry_during_collection_does_not_issue_eligibility(
    eligibility_case, monkeypatch
):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    original = t.provider._weight_read
    before = t.clock.now

    async def delayed(*args):
        value = await original(*args)
        t.clock.now = before + t.config.maximum_head_age_ms + 1
        return value

    with monkeypatch.context() as m:
        m.setattr(t.provider, "_weight_read", delayed)
        with pytest.raises(ValueError, match="stale"):
            await collect_reward_eligibility(
                t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
            )
    t.clock.now = before
    assert (await t.capture()).eligible


async def test_cancelled_native_read_drains_before_close(eligibility_case, monkeypatch):
    t = eligibility_case
    chain = await t.provider.collect_registered_weights(t.hotkey)
    entered, release = threading.Event(), threading.Event()
    original = t.verifier.read_many

    def blocked(**kwargs):
        entered.set()
        assert release.wait(10)
        return original(**kwargs)

    monkeypatch.setattr(t.verifier, "read_many", blocked)
    task = asyncio.create_task(
        collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
        )
    )
    closing = None
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        closing = asyncio.create_task(t.provider.aclose())
        await asyncio.sleep(0.02)
        assert not task.done() and not closing.done() and t.provider._lock.locked()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await closing
    with pytest.raises(ValueError, match="not running"):
        await collect_reward_eligibility(
            t.provider, chain, t.profile, expected_runtime_profile_sha256=digest(t.profile)
        )


_ORACLE = json.loads(
    (Path(__file__).parent / "fixtures" / "reward-eligibility" / "arithmetic.json").read_bytes()
)


@pytest.mark.parametrize("case", _ORACLE["cases"], ids=lambda c: str(c["index"]))
def test_pinned_fixed_point_reference_vectors(case):
    values, expected = case["inputs"], case["expected"]
    n = len(values["alpha"])
    base = EpochEligibilityInputs(
        block=1000,
        validator_uid=0,
        owner_uid=values["owner_uid"],
        last_updates=(999,) * n,
        registration_blocks=(1,) * n,
        permits=(True,) * n,
        alpha=tuple(values["alpha"]),
        tao=tuple(values["tao"]),
        parents=tuple(tuple(tuple(p) for p in row) for row in values["parents"]),
        children=tuple(tuple(row) for row in values["children"]),
        tao_weight=values["tao_weight"],
        stake_threshold=values["stake_threshold"],
        tempo=360,
        activity_factor_milli=5000,
        row=(),
    )
    for uid in range(n):
        for column, name in ((1, "alpha"), (2, "tao")):
            assert (
                _inherited(
                    values[name][uid],
                    tuple((p[0], p[column]) for p in values["parents"][uid]),
                    base.children[uid],
                )
                == expected[name][uid]
            )
        current = replace(base, validator_uid=uid, row=(((uid + 1) % n, 65535),))
        if expected["normalized_bits"] is None:
            with pytest.raises(ValueError, match="stake sum"):
                epoch_eligibility(current)
        else:
            reason = (
                "stake_unavailable"
                if int(expected["filtered_bits"][uid]) == 0
                else "stake_rounds_to_zero"
                if expected["normalized_bits"][uid] == 0
                else "eligible"
            )
            assert epoch_eligibility(current) == reason
