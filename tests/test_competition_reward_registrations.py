"""Current recipient discovery through native readers with synthetic chain ports."""

import json
from dataclasses import replace

import pytest

from umi.competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    validate_owned_weight_observation,
)
from umi.competition_cohort_reward_allocation import project_owned_reward_allocation
from umi.encoding import account_id32
from umi.open_competition import Registration, digest
from umi.validator_chain import ValidatorChainError

from . import test_open_competition as competition_tests
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_reward_allocation import allocation, key
from .test_competition_model_burn import burn_policy

base_policy = competition_tests.policy


@pytest.fixture
def policy(base_policy):
    return burn_policy(base_policy, owner="Burn")


def set_members(item, members):
    values = item.rpc.values
    for spec in list(values):
        if spec[0] == "SubtensorModule" and spec[1] in {"Keys", "Uids"}:
            del values[spec]
    for uid, hotkey in enumerate(members):
        values[("SubtensorModule", "Keys", (78, uid))] = hotkey
        values[("SubtensorModule", "Uids", (78, hotkey))] = uid
    values[("SubtensorModule", "SubnetworkN", (78,))] = len(members)


def advance(item):
    previous = item.finality.ref
    height = previous.block_number + 1
    item.finality.ref = replace(
        previous,
        block_number=height,
        block_hash="0x" + f"{height:064x}",
        parent_hash=previous.block_hash,
        state_root="0x" + f"{height + 1:064x}",
    )
    item.finality.timestamp += 12000
    item.clock.now += 12000
    item.rpc.values[("Timestamp", "Now", ())] = item.finality.timestamp


@pytest.fixture
async def registered_case(chain):
    item = chain
    item.hotkey = key("Eve")
    set_members(item, [key(name) for name in ("Burn", "Alice", "Bob", "Eve")])
    values = {
        "ValidatorPermit": [False, False, False, True],
        "LastUpdate": [0, 0, 0, item.finality.ref.block_number - 100],
        "MechanismCountCurrent": 1,
        "CommitRevealWeightsEnabled": False,
        "WeightsVersionKey": 2**32,
        "MinAllowedWeights": 1,
        "MaxAllowedUids": 256,
        "MaxWeightsLimit": 65535,
        "WeightsSetRateLimit": 10,
        "SubnetOwnerHotkey": key("Burn"),
        "RecycleOrBurn": "Burn",
    }
    item.rpc.values.update({("SubtensorModule", k, (78,)): v for k, v in values.items()})
    item.rpc.values.update(
        {
            ("SubtensorModule", "Weights", (78, 3)): [[0, 19661], [1, 20000], [2, 25874]],
            ("System", "Account", (item.hotkey,)): {"nonce": 10},
            ("Commitments", "CommitmentOf", (78, item.hotkey)): None,
        }
    )
    item.provider = FinalizedCompetitionWeightProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    try:
        yield item
    finally:
        await item.provider.aclose()


def project(item, observation, **changes):
    options = dict(chain_config=item.config)
    options.update(changes)
    return project_owned_reward_allocation(
        allocation(item.policy), observation, item.policy, **options
    )


async def capture(item):
    return await item.provider.collect_registered_weights(item.hotkey)


def row(projection):
    assert sum(projection.weights) == 65535
    assert not projection.chain_submission_authorized
    return dict(zip(projection.uids, projection.weights, strict=True))


async def test_complete_registry_and_validator_state_share_a_proven_root(registered_case):
    item = registered_case
    obs = await capture(item)
    validate_owned_weight_observation(obs)
    assert obs.registrations_complete is True
    assert [(r.uid, r.hotkey) for r in obs.registrations] == [
        (uid, key(name)) for uid, name in enumerate(("Burn", "Alice", "Bob", "Eve"))
    ]
    assert obs.registered_uid_count == 4
    assert (obs.validator_uid, obs.validator_nonce, obs.validator_permit) == (3, 10, True)
    assert obs.validator_row == ((0, 19661), (1, 20000), (2, 25874))
    evidence = json.loads(obs.evidence)
    assert evidence["registrations_complete"] is True
    assert evidence["config_sha256"] == digest(item.config)
    assert len(evidence["storage_batches"]) == len(item.verifier.checked) == 4
    assert {b["state_root"] for b in evidence["storage_batches"]} == {obs.snapshot.state_root}
    keys = [
        json.loads(bytes.fromhex(c["key"][2:]))
        for b in evidence["storage_batches"]
        for c in b["claims"]
    ]
    assert [k[2][1] for k in keys if k[:2] == ["SubtensorModule", "Keys"]] == list(range(4))
    assert row(project(item, obs)) == {0: 19661, 1: 20000, 2: 25874}


async def test_selected_snapshot_survives_head_advancement(registered_case, monkeypatch):
    item = registered_case
    selected = item.finality.ref

    async def latest():
        return replace(selected, block_number=selected.block_number + 1)

    async def forbidden():
        raise AssertionError("selected snapshot must not be replaced by the latest head")

    monkeypatch.setattr(item.finality, "verified_finalized_snapshot", latest)
    monkeypatch.setattr(item.proofs, "finalized_snapshot", forbidden)
    observed = await item.provider.collect_registered_weights(item.hotkey, at=selected)
    assert observed.snapshot == selected
    assert row(project(item, observed)) == {0: 19661, 1: 20000, 2: 25874}


@pytest.mark.parametrize("damage", ["type", "hash", "root", "stale", "unknown", "lag"])
async def test_selected_snapshot_still_requires_current_owned_finality(
    registered_case, monkeypatch, damage
):
    item = registered_case
    selected = item.finality.ref
    if damage == "type":
        selected = {"block_number": selected.block_number}
    elif damage == "hash":
        selected = replace(selected, block_hash="0x" + "ff" * 32)
    elif damage == "root":
        selected = replace(selected, state_root="0x" + "ff" * 32)
    elif damage == "stale":
        item.clock.now += item.config.maximum_head_age_ms + 1
    elif damage == "unknown":

        async def unknown(height):
            raise ValueError("owned block is unavailable")

        monkeypatch.setattr(item.finality, "verified_block_at", unknown)
    else:

        async def latest():
            return replace(
                selected,
                block_number=selected.block_number + item.policy.maximum_snapshot_age_blocks + 1,
            )

        monkeypatch.setattr(item.finality, "verified_finalized_snapshot", latest)
    with pytest.raises(ValueError):
        await item.provider.collect_registered_weights(item.hotkey, at=selected)


async def test_complete_discovery_survives_uid_reuse_and_hotkey_return(registered_case):
    item = registered_case
    before = digest(allocation(item.policy))
    assert row(project(item, await capture(item))) == {0: 19661, 1: 20000, 2: 25874}
    advance(item)
    set_members(item, [key(n) for n in ("Burn", "Charlie", "Bob", "Eve")])
    absent = await capture(item)
    assert row(project(item, absent)) == {0: 39661, 2: 25874}
    assert next(r for r in project(item, absent).recipients if r.hotkey == key("Alice")).uid is None
    advance(item)
    set_members(item, [key(n) for n in ("Burn", "Charlie", "Bob", "Eve", "Alice")])
    assert row(project(item, await capture(item))) == {0: 19661, 2: 25874, 4: 20000}
    assert digest(allocation(item.policy)) == before


@pytest.mark.parametrize("all_recipients", [False, True])
async def test_legacy_selected_mapping_proof_cannot_establish_absence(
    registered_case, all_recipients
):
    item = registered_case
    recipients = (
        tuple(
            Registration(uid=i, hotkey=key(n))
            for i, n in enumerate(("Burn", "Alice", "Bob", "Eve"))
        )
        if all_recipients
        else ()
    )
    obs = await item.provider.collect_weights(item.hotkey, recipients)
    validate_owned_weight_observation(obs)
    assert obs.registrations_complete is False
    assert "registrations_complete" not in json.loads(obs.evidence)
    assert len(json.loads(obs.evidence)["storage_batches"]) == 3
    with pytest.raises(ValueError, match="complete registration proof"):
        project(item, obs)
    with pytest.raises(ValueError, match="owned proof adapter"):
        project(item, replace(obs, registrations_complete=True))


@pytest.mark.parametrize(
    "damage", ["config", "policy", "omission", "evidence", "issuer", "expired"]
)
async def test_projection_requires_selected_fresh_owned_evidence(registered_case, damage):
    item = registered_case
    obs = await capture(item)
    config = item.config
    if damage == "config":
        config = config.model_copy(update={"rpc_url": "wss://different.example.org"})
    elif damage == "policy":
        config = config.model_copy(update={"policy_sha256": "ff" * 32})
    elif damage == "omission":
        obs = replace(obs, registrations=obs.registrations[1:])
    elif damage == "evidence":
        obs = replace(obs, evidence=b"{}")
    elif damage == "issuer":
        obs = replace(obs, _issuer=None)
    else:
        obs = replace(obs, expires_monotonic_ns=0)
    with pytest.raises(ValueError):
        project(item, obs, chain_config=config)


@pytest.mark.parametrize(
    "damage",
    [
        "missing_key",
        "duplicate",
        "inverse",
        "validator",
        "burn",
        "owner",
        "mode",
        "count",
        "proof",
        "stale",
    ],
)
async def test_partial_or_changed_registry_holds_instead_of_burning(registered_case, damage):
    item = registered_case
    values = item.rpc.values
    if damage == "missing_key":
        del values[("SubtensorModule", "Keys", (78, 1))]
    elif damage == "duplicate":
        values[("SubtensorModule", "Keys", (78, 1))] = "0x" + account_id32(key("Bob")).hex()
    elif damage == "inverse":
        values[("SubtensorModule", "Uids", (78, key("Alice")))] = 2
    elif damage == "validator":
        values[("SubtensorModule", "Keys", (78, 3))] = key("Charlie")
    elif damage == "burn":
        values[("SubtensorModule", "Keys", (78, 0))] = key("Charlie")
    elif damage == "owner":
        values[("SubtensorModule", "SubnetOwnerHotkey", (78,))] = key("Charlie")
    elif damage == "mode":
        values[("SubtensorModule", "RecycleOrBurn", (78,))] = "Recycle"
    elif damage == "count":
        values[("SubtensorModule", "SubnetworkN", (78,))] = 257
    elif damage == "proof":
        item.rpc.bad_proof = True
    else:
        item.finality.advance_after_reads = item.policy.maximum_snapshot_age_blocks + 1
    with pytest.raises(ValidatorChainError if damage == "proof" else ValueError):
        await capture(item)


async def test_interrupted_inverse_read_retries_without_partial_result(
    registered_case, monkeypatch
):
    item = registered_case
    request = item.rpc.request
    calls = 0

    async def interrupted(method, params):
        nonlocal calls
        if method == "state_getStorageAt":
            pallet, name, arguments = json.loads(bytes.fromhex(params[0][2:]))
            if (pallet, name, arguments) == ("SubtensorModule", "Uids", [78, key("Alice")]):
                calls += 1
                if calls == 1:
                    raise ConnectionError("fixture interrupted inverse proof")
        return await request(method, params)

    monkeypatch.setattr(item.rpc, "request", interrupted)
    with pytest.raises(ValidatorChainError, match="storage_proof_rpc_failed") as error:
        await capture(item)
    assert isinstance(error.value.__cause__, ConnectionError)
    assert row(project(item, await capture(item))) == {0: 19661, 1: 20000, 2: 25874}


async def test_full_256_uid_domain_is_discovered_with_bounded_batches(registered_case):
    import bittensor as bt

    item = registered_case
    members = [key(n) for n in ("Burn", "Alice", "Bob", "Eve")]
    members.extend(bt.sp_core.ss58_encode(i.to_bytes(32, "big"), 42) for i in range(4, 256))
    set_members(item, members)
    obs = await capture(item)
    assert tuple(r.uid for r in obs.registrations) == tuple(range(256))
    sizes = [len(b["claims"]) for b in json.loads(obs.evidence)["storage_batches"]]
    assert sizes == [17, 256, 256, 1]
    assert row(project(item, obs)) == {0: 19661, 1: 20000, 2: 25874}


async def test_closed_provider_cannot_issue_complete_registry(registered_case):
    item = registered_case
    await item.provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await capture(item)


async def test_projection_rechecks_actual_observation_expiry(registered_case, monkeypatch):
    item = registered_case
    obs = await capture(item)
    monkeypatch.setattr(
        "umi.competition_chain_state.time.monotonic_ns", lambda: obs.expires_monotonic_ns + 1
    )
    with pytest.raises(ValueError, match="owned proof adapter"):
        project(item, obs)
