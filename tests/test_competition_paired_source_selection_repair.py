"""A fresh consumer cannot replace a damaged original source selection."""

import pytest

from umi.competition_cohort_execution_journal import incumbent_scope
from umi.competition_cohort_orders import recoverable_order_job

from .test_competition_cohort_executor import base_policy as base_policy
from .test_competition_cohort_executor import execution as execution
from .test_competition_cohort_executor import legacy_scenario as legacy_scenario
from .test_competition_cohort_executor import policy as policy
from .test_competition_cohort_executor import receipt_scenario as receipt_scenario
from .test_competition_cohort_executor import recovery as recovery
from .test_competition_cohort_executor import relay as relay
from .test_competition_cohort_executor import runtime as runtime
from .test_competition_cohort_executor import scenario as scenario
from .test_competition_cohort_incumbent_reuse import other_assignment
from .test_competition_cohort_paired_incumbent_reuse import finish, paired
from .test_competition_cohort_paired_incumbent_reuse import harness as harness
from .test_competition_cohort_paired_incumbent_reuse import original_harness as original_harness


@pytest.mark.parametrize("damage", ["incumbent_source", "incumbent_source_selection"])
async def test_new_consumer_refuses_damaged_original_selection_without_inference(execution, damage):
    e = execution
    executor = paired(e)
    await finish(e, e.assignment)
    owner = executor.journal
    scope = incumbent_scope(e.job)
    original = {
        kind: owner.journal.get_raw(kind, scope)
        for kind in ("incumbent_source", "incumbent_source_selection")
    }
    assert all(original.values())
    with owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", (damage, scope))

    assignment, _slot, _ = await other_assignment(e)
    untouched = recoverable_order_job(assignment.certificate.order, e.cfg.signer)
    assert owner.head(untouched, 0) is None
    calls = len(e.calls)
    with pytest.raises(ValueError, match="repair"):
        await paired(e).advance(assignment)
    assert len(e.calls) == calls
    assert owner.head(untouched, 0) is None
    for kind, raw in original.items():
        assert owner.journal.get_raw(kind, scope) == (None if kind == damage else raw)
