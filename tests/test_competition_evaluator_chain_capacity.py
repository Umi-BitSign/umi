import pytest

from umi.competition_evaluator import EvaluatorJournal

from .test_competition_evaluator_rpc_migration import chain_config as chain_config
from .test_competition_evaluator_rpc_migration import model_setup as model_setup
from .test_competition_evaluator_rpc_migration import policy as policy
from .test_competition_evaluator_rpc_migration import runtime as runtime
from .test_competition_evaluator_rpc_migration import setup as setup
from .test_competition_evaluator_rpc_migration import snapshot, spec, upgraded


def enlarged(config):
    return config.model_copy(
        update={"chain": config.chain.model_copy(update={"maximum_cache_bytes": 12 * 1024**3})}
    )


def test_growth_after_rpc_migration_preserves_original_binding_and_reservations(setup):
    old = setup.drivers[0].journal
    r = spec(setup)
    receipt = old.reserve_orders("ab" * 32, [r])
    old.admit(setup.order, r.slot)
    old.put(r.slot, "announcement_intent", {"message": "reserved"})
    rpc = EvaluatorJournal(upgraded(old.config))
    before = snapshot(old.path)
    new = EvaluatorJournal(enlarged(rpc.config))
    after = snapshot(old.path)
    assert {k: after[k] for k in before} == before
    assert new.reservation("ab" * 32) == receipt
    assert EvaluatorJournal(new.config).reservation("ab" * 32) == receipt
    assert snapshot(old.path) == after
    with pytest.raises(ValueError):
        EvaluatorJournal(rpc.config)
    assert snapshot(old.path) == after


@pytest.mark.parametrize("change", ["rpc", "directory", "freshness", "decrease"])
def test_capacity_cannot_change_other_bindings_or_roll_back(setup, change):
    old = setup.drivers[0].journal
    config = enlarged(old.config)
    if change == "rpc":
        config = config.model_copy(
            update={"chain": config.chain.model_copy(update={"rpc_url": "wss://other.example"})}
        )
    if change == "directory":
        config = config.model_copy(update={"peer_directory": "/other"})
    if change == "freshness":
        config = config.model_copy(
            update={"chain": config.chain.model_copy(update={"maximum_head_age_ms": 1000})}
        )
    if change == "decrease":
        config = old.config.model_copy(
            update={"chain": old.config.chain.model_copy(update={"maximum_cache_bytes": 1024})}
        )
    before = snapshot(old.path)
    with pytest.raises(ValueError):
        EvaluatorJournal(config)
    assert snapshot(old.path) == before


def many_increases(setup):
    old = setup.drivers[0].journal
    reservation = spec(setup)
    receipt = old.reserve_orders("ab" * 32, [reservation])
    old.admit(setup.order, reservation.slot)
    old.put(reservation.slot, "announcement_intent", {"message": "reserved"})
    current = EvaluatorJournal(upgraded(old.config))
    retained = snapshot(old.path)
    configs = [current.config]
    for _ in range(65):
        config = current.config.model_copy(
            update={
                "chain": current.config.chain.model_copy(
                    update={"maximum_cache_bytes": current.config.chain.maximum_cache_bytes + 1024}
                )
            }
        )
        current = EvaluatorJournal(config)
        configs.append(config)
    return current, retained, receipt, configs


def test_more_than_32_increases_preserve_binding_reservations_and_reopen(setup):
    current, retained, receipt, configs = many_increases(setup)
    after = snapshot(current.path)
    assert len(after["evaluator_chain_capacity_changes"]) == 65
    assert {k: after[k] for k in retained} == retained
    assert EvaluatorJournal(current.config).reservation("ab" * 32) == receipt
    assert snapshot(current.path) == after
    with pytest.raises(ValueError):
        EvaluatorJournal(configs[32])
    assert snapshot(current.path) == after


@pytest.mark.parametrize("corruption", ["sequence", "canonical"])
def test_late_evaluator_history_corruption_rejects_without_writes(setup, corruption):
    import sqlite3

    current, _, _, _ = many_increases(setup)
    with sqlite3.connect(current.path) as db:
        if corruption == "sequence":
            db.execute("UPDATE evaluator_chain_capacity_changes SET sequence=90 WHERE sequence=40")
        else:
            prior = db.execute(
                "SELECT previous FROM evaluator_chain_capacity_changes WHERE sequence=40"
            ).fetchone()[0]
            db.execute(
                "UPDATE evaluator_chain_capacity_changes SET previous=? WHERE sequence=40",
                (prior + b" ",),
            )
    before = snapshot(current.path)
    with pytest.raises(ValueError):
        EvaluatorJournal(current.config)
    assert snapshot(current.path) == before


@pytest.mark.parametrize("change", ["rpc_url", "proof_binary_sha256", "proof_rpc_fallback_urls"])
def test_late_growth_cannot_change_chain_authority_or_transports(setup, change):
    current, _, _, _ = many_increases(setup)
    update = {
        "maximum_cache_bytes": current.config.chain.maximum_cache_bytes + 1024,
        change: ["wss://other1.example", "wss://other2.example"]
        if change == "proof_rpc_fallback_urls"
        else "fe" * 32
        if change == "proof_binary_sha256"
        else "wss://other.example",
    }
    before = snapshot(current.path)
    with pytest.raises(ValueError):
        EvaluatorJournal(
            current.config.model_copy(
                update={"chain": current.config.chain.model_copy(update=update)}
            )
        )
    assert snapshot(current.path) == before


def test_late_evaluator_append_failure_rolls_back_without_losing_reservations(setup):
    import sqlite3

    current, _, receipt, _ = many_increases(setup)
    with sqlite3.connect(current.path) as db:
        db.execute(
            "CREATE TRIGGER reject_late_growth BEFORE INSERT ON evaluator_chain_capacity_changes "
            "BEGIN SELECT RAISE(ABORT, 'injected late failure'); END"
        )
    before = snapshot(current.path)
    config = current.config.model_copy(
        update={
            "chain": current.config.chain.model_copy(
                update={"maximum_cache_bytes": current.config.chain.maximum_cache_bytes + 1024}
            )
        }
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected late failure"):
        EvaluatorJournal(config)
    assert snapshot(current.path) == before
    assert EvaluatorJournal(current.config).reservation("ab" * 32) == receipt
