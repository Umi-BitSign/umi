from __future__ import annotations

import json
from dataclasses import replace

import pytest

from umi.competition_reward_control import (
    FinalizedRewardControlProvider,
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from umi.open_competition import digest
from umi.validator_chain import ValidatorChainError

from .test_competition_chain import _hash
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_weights import executed_weight_case as executed_weight_case
from .test_competition_weights import package_case as package_case
from .test_competition_weights import package_limits as package_limits
from .test_competition_weights import release_identity as release_identity
from .test_competition_weights import replay_limits as replay_limits
from .test_competition_weights import weight_case as weight_case
from .test_competition_weights import worker_capacity as worker_capacity
from .test_open_competition import policy as policy
from .test_open_competition import wallet


def commitment(root="aa" * 32, block=100):
    return {"block": block, "info": {"fields": [{"Sha256": "0x" + root}]}}


@pytest.fixture
async def control(chain):
    item = chain
    item.hotkey = wallet("Ferdie").hotkey.ss58_address
    item.spec = ("Commitments", "CommitmentOf", (78, item.hotkey))
    item.rpc.values[item.spec] = commitment()

    def reopen():
        return FinalizedRewardControlProvider(
            item.config,
            item.policy,
            finality=item.finality,
            proofs=item.proofs,
            now_ms=lambda: item.clock.now,
        )

    item.reopen = reopen
    item.provider = reopen()
    try:
        yield item
    finally:
        await item.provider.aclose()


def validate(item, observed):
    validate_owned_reward_control(
        observed,
        expected_control_hotkey=item.hotkey,
        expected_chain_config_sha256=digest(item.config),
    )


async def test_current_proven_digest_is_discovered_without_a_coordinator(control):
    item = control
    value = await item.provider.collect_control(item.hotkey)
    validate(item, value)
    assert (value.control_sha256, value.committed_at_block) == ("aa" * 32, 100)
    assert len(item.verifier.checked) == 1
    assert len(item.verifier.checked[0]["items"]) == 3
    record = json.loads(value.evidence)
    assert record["control_hotkey"] == item.hotkey
    assert not record["chain_submission_authorized"]
    assert len(record["claims"]) == 3
    assert "rpc_url" not in record and "state_directory" not in record
    assert "chain_getFinalizedHead" not in {m for m, _ in item.rpc.calls}
    assert all(not m.startswith("author_") for m, _ in item.rpc.calls)

    # No renewal or certificate-age limit. The proof is fresh after restart,
    # even when the unchanged commitment is much older than the old leases.
    await item.provider.aclose()
    item.finality.ref = replace(
        item.finality.ref,
        block_number=item.finality.ref.block_number + 1_000_000,
        block_hash=_hash(5),
    )
    item.provider = item.reopen()
    later = await item.provider.collect_control(item.hotkey)
    validate(item, later)
    assert (later.control_sha256, later.committed_at_block) == ("aa" * 32, 100)
    assert later.snapshot.block_number > value.snapshot.block_number

    # A changed digest is discoverable even when the host only retained the old
    # allocation. Only the independent history consumer may authorize it.
    item.rpc.values[item.spec] = commitment("bb" * 32, later.snapshot.block_number)
    changed = await item.provider.collect_control(item.hotkey)
    validate(item, changed)
    assert changed.control_sha256 == "bb" * 32
    assert changed.committed_at_block == later.snapshot.block_number


async def test_proven_absence_does_not_fall_back_to_a_cached_digest(control):
    item = control
    assert (await item.provider.collect_control(item.hotkey)).control_sha256 == "aa" * 32
    del item.rpc.values[item.spec]
    missing = await item.provider.collect_control(item.hotkey)
    validate(item, missing)
    assert missing.control_sha256 is None and missing.committed_at_block is None
    assert not json.loads(missing.evidence)["chain_submission_authorized"]


@pytest.mark.parametrize(
    "value",
    [
        [],
        {},
        {"block": True, "info": {"fields": [{"Sha256": "0x" + "aa" * 32}]}},
        commitment(block=-1),
        commitment(block=2**53 - 1),
        {"block": 10, "info": {"fields": []}},
        {"block": 10, "info": {"fields": [{"Raw": "0xaaaa"}]}},
        {"block": 10, "info": {"fields": [{"Sha256": "0xaaaa"}]}},
        {"block": 10, "info": {"fields": [{"Sha256": "0x" + "aa" * 32}] * 2}},
    ],
)
async def test_unrelated_or_malformed_slot_is_a_hold(control, value):
    control.rpc.values[control.spec] = value
    with pytest.raises((ValueError, RuntimeError)):
        await control.provider.collect_control(control.hotkey)


@pytest.mark.parametrize(
    "mutation",
    ["stale", "future", "genesis", "class", "root", "metadata", "proof", "network", "time"],
)
async def test_invalid_owned_proof_never_becomes_current_control(control, mutation):
    item = control
    if mutation == "stale":
        item.clock.now += item.provider.config.maximum_head_age_ms + 1
    elif mutation == "future":
        item.clock.now -= 31_002
    elif mutation == "genesis":
        item.finality.genesis = _hash(99)
    elif mutation == "class":
        item.finality.evidence_class = "rpc_finalized"
    elif mutation == "root":
        item.rpc.header_root = _hash(99)
    elif mutation == "metadata":
        item.rpc.metadata = b"different"
    elif mutation == "proof":
        item.rpc.bad_proof = True
    elif mutation == "network":
        item.rpc.values[("SubtensorModule", "NetworksAdded", (78,))] = False
    elif mutation == "time":
        item.rpc.values[("Timestamp", "Now", ())] += 1
    with pytest.raises((ValueError, ValidatorChainError)):
        await item.provider.collect_control(item.hotkey)


@pytest.mark.parametrize("advance", [-1, 1000])
async def test_finality_rollback_or_slow_collection_holds(control, advance):
    control.finality.advance_after_reads = advance
    with pytest.raises(ValueError, match="rolled back, changed or became stale"):
        await control.provider.collect_control(control.hotkey)


@pytest.mark.parametrize(
    "field,value",
    [
        ("control_sha256", "bb" * 32),
        ("committed_at_block", 99),
        ("timestamp_ms", 1),
        ("chain_config_sha256", "bb" * 32),
        ("captured_monotonic_ns", 0),
        ("expires_monotonic_ns", 2**63 - 1),
        ("evidence", b"{}"),
        ("_issuer", None),
    ],
)
async def test_observation_cannot_be_edited_into_authority(control, field, value):
    observed = await control.provider.collect_control(control.hotkey)
    with pytest.raises(ValueError, match="selected current proof adapter"):
        validate(control, replace(observed, **{field: value}))


async def test_selected_slot_config_and_expiry_must_match(control, monkeypatch):
    observed = await control.provider.collect_control(control.hotkey)
    with pytest.raises(ValueError):
        validate_owned_reward_control(
            observed,
            expected_control_hotkey=wallet("Alice").hotkey.ss58_address,
            expected_chain_config_sha256=digest(control.config),
        )
    with pytest.raises(ValueError):
        validate_owned_reward_control(
            observed,
            expected_control_hotkey=control.hotkey,
            expected_chain_config_sha256="bb" * 32,
        )
    copied = OwnedRewardControlObservation(
        **{
            name: getattr(observed, name)
            for name in observed.__dataclass_fields__
            if name not in {"_issuer", "_binding"}
        }
    )
    with pytest.raises(ValueError):
        validate(control, copied)
    monkeypatch.setattr(
        "umi.competition_reward_control.time.monotonic_ns",
        lambda: observed.expires_monotonic_ns + 1,
    )
    with pytest.raises(ValueError):
        validate(control, observed)


async def test_transport_failure_is_retryable_and_never_returns_the_previous_value(
    control, monkeypatch
):
    item = control
    await item.provider.collect_control(item.hotkey)
    with monkeypatch.context() as patch:

        async def unavailable(*args):
            raise ConnectionError("fixture provider unavailable")

        patch.setattr(item.rpc, "request", unavailable)
        with pytest.raises(ValidatorChainError, match="finalized_snapshot_rpc_failed"):
            await item.provider.collect_control(item.hotkey)
    assert (await item.provider.collect_control(item.hotkey)).control_sha256 == "aa" * 32
    await item.provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await item.provider.collect_control(item.hotkey)


async def test_collection_cannot_extend_wall_clock_freshness(control, monkeypatch):
    original = control.provider._weight_read

    async def slow_read(*args):
        result = await original(*args)
        control.clock.now += control.provider.config.maximum_head_age_ms + 1
        return result

    monkeypatch.setattr(control.provider, "_weight_read", slow_read)
    with pytest.raises(ValueError, match="stale"):
        await control.provider.collect_control(control.hotkey)


async def test_same_height_finality_fork_is_rejected(control, monkeypatch):
    calls = 0

    async def snapshot():
        nonlocal calls
        calls += 1
        return (
            control.finality.ref
            if calls == 1
            else replace(control.finality.ref, block_hash=_hash(99))
        )

    monkeypatch.setattr(control.finality, "verified_finalized_snapshot", snapshot)
    with pytest.raises(ValueError, match="rolled back, changed or became stale"):
        await control.provider.collect_control(control.hotkey)


async def test_executed_runtime_control_retains_and_binds_code_proof(
    executed_weight_case, chain_config, tmp_path
):
    item = executed_weight_case
    config = item.config.model_copy(
        update={
            "state_directory": str(tmp_path / "control-observer"),
            "minimum_finalized_block": chain_config.minimum_finalized_block,
        }
    )
    provider = FinalizedRewardControlProvider(
        config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    # The shared execution fixture supplies synthetic code, metadata, finality
    # and trie verification. The native runtime/collection binding stays real.
    provider.config = config.model_copy(update={"minimum_finalized_block": 100})
    provider._runtime_proofs = item.provider._runtime_proofs
    item.rpc.values[("Commitments", "CommitmentOf", (78, item.hotkey))] = commitment()
    try:
        observed = await provider.collect_control(item.hotkey)
        selection = dict(
            expected_control_hotkey=item.hotkey,
            expected_chain_config_sha256=digest(provider.config),
        )
        validate_owned_reward_control(observed, **selection)
        evidence = json.loads(observed.evidence)
        assert evidence["storage_codec_mode"] == "executed_runtime/1"
        assert evidence["runtime_execution"]["value"] == "0x" + item.code.hex()
        assert evidence["runtime_execution"]["state_root"] == observed.snapshot.state_root
        changed = replace(observed, runtime=replace(observed.runtime, executor_sha256="b" * 64))
        with pytest.raises(ValueError):
            validate_owned_reward_control(changed, **selection)
    finally:
        await provider.aclose()
        await item.provider.aclose()
