from dataclasses import replace

import pytest

from umi.competition_chain import FinalizedRegistrationProvider
from umi.competition_chain_capacity import grow_registration_cache

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_chain import policy as policy
from .test_competition_evaluator_rpc_migration import snapshot


def reopen(chain, config):
    return FinalizedRegistrationProvider(
        config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )


async def test_growth_preserves_proofs_metadata_highwater_and_reopens(chain):
    await chain.provider.collect()
    path = chain.provider._path
    before = snapshot(path)
    larger = chain.config.model_copy(update={"maximum_cache_bytes": 12 * 1024**3})
    await chain.provider.aclose()
    grow_registration_cache(path, chain.config, larger)
    after = snapshot(path)
    assert {k: after[k] for k in before if k != "binding"} == {
        k: v for k, v in before.items() if k != "binding"
    }
    grow_registration_cache(path, chain.config, larger)
    assert snapshot(path) == after
    provider = reopen(chain, larger)
    assert (await provider.collect()).snapshot.block == chain.finality.ref.block_number
    chain.finality.ref = replace(
        chain.finality.ref,
        block_number=chain.finality.ref.block_number + 1,
        block_hash="0x" + "42" * 32,
    )
    await provider.collect()
    assert len(snapshot(path)["captures"]) == len(before["captures"]) + 1
    await provider.aclose()
    with pytest.raises(ValueError, match="another chain configuration"):
        reopen(chain, chain.config)


@pytest.mark.parametrize("change", ["decrease", "rpc", "pin", "directory", "too_large"])
async def test_growth_rejects_unrelated_changes_without_writes(chain, change):
    await chain.provider.collect()
    path = chain.provider._path
    before = snapshot(path)
    update = {"maximum_cache_bytes": 12 * 1024**3}
    if change == "decrease":
        update["maximum_cache_bytes"] = 1024
    if change == "rpc":
        update["rpc_url"] = "wss://other.example"
    if change == "pin":
        update["proof_binary_sha256"] = "fe" * 32
    if change == "directory":
        update["state_directory"] = chain.config.state_directory + "-other"
    if change == "too_large":
        update["maximum_cache_bytes"] = 21 * 1024**3
    with pytest.raises(ValueError):
        grow_registration_cache(path, chain.config, chain.config.model_copy(update=update))
    assert snapshot(path) == before
    await chain.provider.aclose()


async def test_growth_failure_rolls_back_binding_and_receipt(chain):
    await chain.provider.collect()
    path = chain.provider._path
    with chain.provider._connect() as db:
        db.execute(
            "CREATE TRIGGER reject_growth BEFORE UPDATE ON binding "
            "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
        )
    before = snapshot(path)
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError, match="injected failure"):
        grow_registration_cache(
            path,
            chain.config,
            chain.config.model_copy(update={"maximum_cache_bytes": 12 * 1024**3}),
        )
    assert snapshot(path) == before
    await chain.provider.aclose()


async def test_changed_capacity_history_rejected_at_provider_reopen(chain):
    await chain.provider.collect()
    larger = chain.config.model_copy(update={"maximum_cache_bytes": 12 * 1024**3})
    grow_registration_cache(chain.provider._path, chain.config, larger)
    with chain.provider._connect() as db:
        db.execute("UPDATE cache_capacity_changes SET sequence=2")
    with pytest.raises(ValueError, match="capacity history changed"):
        reopen(chain, larger)
    await chain.provider.aclose()
