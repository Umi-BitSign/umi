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
