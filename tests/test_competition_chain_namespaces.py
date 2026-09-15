from __future__ import annotations

import json
from pathlib import Path

import pytest

from umi.competition_chain_state import FinalizedCompetitionWeightProvider
from umi.open_competition import digest

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_package import package_case as package_case
from .test_competition_package import package_limits as package_limits
from .test_competition_package import release_identity as release_identity
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_weights import _advance, _run
from .test_competition_weights import weight_case as weight_case
from .test_competition_worker import worker_capacity as worker_capacity
from .test_open_competition import policy as policy


def provider(case, *, config=None, policy=None):
    return FinalizedCompetitionWeightProvider(
        config or case.config,
        policy or case.policy,
        finality=case.finality,
        proofs=case.proofs,
        now_ms=lambda: case.clock.now,
    )


async def test_owned_weight_collector_keeps_its_smaller_proof_limits(chain, monkeypatch):
    item = provider(chain)
    monkeypatch.setattr(
        "umi.competition_chain_state.SubprocessStorageProofVerifier",
        lambda **_: chain.verifier,
    )
    try:
        item._owned = True
        item._configure_weight_collector()
        assert item._proofs._limits.maximum_proof_node_bytes == 2 * 1024**2
        assert item._proofs._limits.maximum_proof_bytes == 8 * 1024**2
    finally:
        item._owned = False
        await item.aclose()


async def test_same_config_reuses_namespace_without_rebinding_public_config(chain):
    first = provider(chain)
    path = first._path
    assert path.parent == Path(chain.config.state_directory) / digest(chain.config)
    assert first.config == chain.config
    before = path.read_bytes()
    await first.aclose()
    second = provider(chain)
    try:
        assert second._path == path and second.config == chain.config
        assert path.read_bytes() == before
    finally:
        await second.aclose()


async def test_new_policy_uses_new_namespace_and_preserves_all_old_files(chain):
    first = provider(chain)
    path = first._path
    before = path.read_bytes()
    await first.aclose()
    changed_policy = chain.policy.model_copy(update={"sequence": chain.policy.sequence + 1})
    config = chain.config.model_copy(update={"policy_sha256": digest(changed_policy)})
    second = provider(chain, config=config, policy=changed_policy)
    try:
        assert second._path != path
        assert second._path.parent.name == digest(config)
        assert path.read_bytes() == before
        assert (Path(config.state_directory) / "registrations.sqlite3").exists()
    finally:
        await second.aclose()


async def test_changed_runtime_pin_gets_separate_namespace(chain):
    first = provider(chain)
    path = first._path
    await first.aclose()
    config = chain.config.model_copy(
        update={
            "chain_pin": chain.config.chain_pin.model_copy(update={"runtime_spec_version": 453})
        }
    )
    second = provider(chain, config=config)
    try:
        assert second._path != path and path.exists()
    finally:
        await second.aclose()


async def test_alternating_initial_and_target_configs_preserves_budgets(chain):
    first = provider(chain)
    original_path = first._path
    budget_path = original_path.parent / "namespace-budget.json"
    original_budget = budget_path.read_bytes()
    await first.aclose()
    policy = chain.policy.model_copy(update={"sequence": chain.policy.sequence + 1})
    target_config = chain.config.model_copy(update={"policy_sha256": digest(policy)})
    second = provider(chain, config=target_config, policy=policy)
    target_path = second._path
    await second.aclose()
    for config, selected_policy, expected_path in (
        (chain.config, chain.policy, original_path),
        (target_config, policy, target_path),
        (chain.config, chain.policy, original_path),
    ):
        reopened = provider(chain, config=config, policy=selected_policy)
        try:
            assert reopened._path == expected_path
            assert reopened.config == config
            assert (
                reopened._namespace_budget <= json.loads(original_budget)["maximum_namespace_bytes"]
            )
        finally:
            await reopened.aclose()
    assert budget_path.read_bytes() == original_budget
    assert target_path.exists()


async def test_reopening_old_config_respects_remaining_aggregate_space(chain):
    config = chain.config.model_copy(update={"maximum_cache_bytes": 1024**2})
    first = provider(chain, config=config)
    original_path = first._path
    await first.aclose()
    policy = chain.policy.model_copy(update={"sequence": chain.policy.sequence + 1})
    target_config = config.model_copy(update={"policy_sha256": digest(policy)})
    second = provider(chain, config=target_config, policy=policy)
    target_path = second._path.parent / "finality.sqlite3"
    await second.aclose()
    # Retained bytes, not a new reservation, consume almost all shared space.
    with target_path.open("r+b") as stream:
        stream.truncate(800 * 1024)
    with pytest.raises(ValueError, match="aggregate capacity"):
        provider(chain, config=config)
    assert original_path.exists() and target_path.stat().st_size == 800 * 1024


async def test_shared_root_lease_prevents_concurrent_budget_allocations(chain):
    first = provider(chain)
    try:
        with pytest.raises(BlockingIOError):
            provider(chain)
    finally:
        await first.aclose()
    replacement = provider(chain)
    await replacement.aclose()


async def test_namespace_count_bound_never_deletes_old_policy(chain, monkeypatch):
    monkeypatch.setattr("umi.competition_chain_state._MAX_CACHE_NAMESPACES", 1)
    first = provider(chain)
    path = first._path
    await first.aclose()
    changed_policy = chain.policy.model_copy(update={"sequence": chain.policy.sequence + 1})
    config = chain.config.model_copy(update={"policy_sha256": digest(changed_policy)})
    with pytest.raises(ValueError, match="namespace count"):
        provider(chain, config=config, policy=changed_policy)
    assert path.exists()


def test_aggregate_budget_rejects_retained_legacy_usage_before_new_namespace(chain):
    config = chain.config.model_copy(update={"maximum_cache_bytes": 1024})
    with pytest.raises(ValueError, match="aggregate byte budget"):
        provider(chain, config=config)
    assert not (Path(config.state_directory) / digest(config)).exists()


@pytest.mark.parametrize("entry", ["namespace", "database", "unknown"])
def test_symlink_and_unknown_cache_entries_are_rejected(chain, tmp_path, entry):
    root = Path(chain.config.state_directory)
    if entry == "namespace":
        (root / digest(chain.config)).symlink_to(tmp_path, target_is_directory=True)
    elif entry == "database":
        (root / "finality.sqlite3").symlink_to(tmp_path / "outside")
    else:
        (root / "unexpected.bin").write_bytes(b"preserve me")
    with pytest.raises((ValueError, OSError)):
        provider(chain)
    assert (root / "registrations.sqlite3").exists()


@pytest.mark.parametrize("different_policy", [False, True])
async def test_corrupt_namespace_budget_is_preserved_and_rejected(chain, different_policy):
    first = provider(chain)
    path = first._path.parent / "namespace-budget.json"
    await first.aclose()
    path.chmod(0o600)
    path.write_text("{}")
    path.chmod(0o400)
    policy = (
        chain.policy.model_copy(update={"sequence": chain.policy.sequence + 1})
        if different_policy
        else chain.policy
    )
    config = chain.config.model_copy(update={"policy_sha256": digest(policy)})
    with pytest.raises(ValueError, match="budget binding"):
        provider(chain, config=config, policy=policy)
    assert path.read_text() == "{}"
    path.chmod(0o600)


async def test_finality_database_limit_fits_reserved_namespace_budget(chain):
    current = provider(chain)
    try:
        budget = json.loads((current._path.parent / "namespace-budget.json").read_bytes())
        limits = current._finality_storage_limits()
        assert limits.maximum_database_bytes < budget["maximum_namespace_bytes"]
        assert budget["maximum_namespace_bytes"] <= chain.config.maximum_cache_bytes
    finally:
        await current.aclose()


async def test_namespace_change_does_not_reset_validator_global_highwater(
    weight_case, chain_config
):
    item = weight_case
    await _run(item)
    await item.provider.aclose()
    old_namespace = item.provider._path
    policy = item.policy.model_copy(update={"sequence": item.policy.sequence + 1})
    config = chain_config.model_copy(update={"policy_sha256": digest(policy)})
    current = provider(item, config=config, policy=policy)
    # Only fixture heights use a smaller floor after validated construction.
    current.config = config.model_copy(update={"minimum_finalized_block": 100})
    item.finality.policy = policy
    assert current._path != old_namespace
    _advance(item, 169)
    item.rpc.values[("SubtensorModule", "LastUpdate", (78,))][54] = 0
    try:
        observation = await current.collect_weights(item.hotkey, item.recipients)
        with pytest.raises(ValueError, match=r"finalized.*(rollback|rolled|back)|high-water"):
            item.worker._load(item.hotkey, "cd" * 32, observation)
    finally:
        await current.aclose()
