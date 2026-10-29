"""Role planning reuses the real journal's evidence pass; inference is synthetic."""

from contextlib import asynccontextmanager

import pytest

from umi.competition_cohort_execution import RecoverableSharedIncumbentEvidence
from umi.competition_cohort_execution_journal import execution_step_key
from umi.competition_cohort_orders import recoverable_order_job
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_execution import observe
from .test_competition_cohort_incumbent_reuse import other_assignment
from .test_competition_cohort_paired_incumbent_reuse import base_policy as base_policy
from .test_competition_cohort_paired_incumbent_reuse import execution as execution
from .test_competition_cohort_paired_incumbent_reuse import finish, paired
from .test_competition_cohort_paired_incumbent_reuse import harness as harness
from .test_competition_cohort_paired_incumbent_reuse import legacy_scenario as legacy_scenario
from .test_competition_cohort_paired_incumbent_reuse import original_harness as original_harness
from .test_competition_cohort_paired_incumbent_reuse import policy as policy
from .test_competition_cohort_paired_incumbent_reuse import receipt_scenario as receipt_scenario
from .test_competition_cohort_paired_incumbent_reuse import recovery as recovery
from .test_competition_cohort_paired_incumbent_reuse import relay as relay
from .test_competition_cohort_paired_incumbent_reuse import runtime as runtime
from .test_competition_cohort_paired_incumbent_reuse import scenario as scenario


def role_port(e, scope):
    e.port.execution_scope = scope
    e.port.execution_scope_roles = True
    e.port.prepared_execution_scope = True
    e.port.execution_scope_before_reserve = True


@pytest.mark.parametrize("resume", [False, True])
async def test_consumer_scope_uses_same_validated_reuse_pass(execution, monkeypatch, resume):
    e = execution
    paired(e)
    first = await finish(e, e.assignment)
    original = canonical_json_bytes(first)
    assignment, _slot, scenario = await other_assignment(e)
    if resume:
        e.r.h.block += 1
        assert await paired(e).advance(assignment) is None
    executor = paired(e)
    reads, entered = [], []
    source_evidence = executor.journal._source_evidence

    def counted(*args):
        reads.append(True)
        return source_evidence(*args)

    monkeypatch.setattr(executor.journal, "_source_evidence", counted)

    @asynccontextmanager
    async def scope(job, *, model_roles, before_reserve=None):
        assert before_reserve is None
        assert model_roles == ("candidate",)
        # Fresh reuse already reads the source and validates its retained result;
        # a restarted consumer needs only _completed's existing evidence pass.
        assert len(reads) == (1 if resume else 2)
        entered.append(job)
        yield True

    role_port(e, scope)
    e.r.h.block += 1
    result = await executor.advance_batch(assignment)
    assert isinstance(result, RecoverableSharedIncumbentEvidence)
    assert len(entered) == 1 and len(e.calls) == 3 * len(e.job.cases)
    assert result.incumbent_source == first
    assert canonical_json_bytes(executor.journal.evidence(e.r.slot)) == original
    assert (
        observe(scenario, result).incumbent == observe(e.r.h.batch["scenarios"][0], first).incumbent
    )
    assert canonical_json_bytes(await paired(e).advance_batch(assignment)) == canonical_json_bytes(
        result
    )


@pytest.mark.parametrize("resume", [False, True])
async def test_source_scope_keeps_both_models_before_and_after_restart(execution, resume):
    e = execution
    executor = paired(e)
    if resume:
        await executor.advance(e.assignment)
        executor = paired(e)
    entered = []

    @asynccontextmanager
    async def scope(job, *, model_roles=("candidate", "incumbent"), before_reserve=None):
        if before_reserve is not None:
            model_roles = await before_reserve()
        assert model_roles == ("candidate", "incumbent")
        entered.append(job)
        yield True

    role_port(e, scope)
    e.r.h.block += 1
    result = await executor.advance_batch(e.assignment)
    assert len(entered) == 1 and len(e.calls) == 2 * len(e.job.cases)
    assert canonical_json_bytes(result) == canonical_json_bytes(executor.journal.evidence(e.r.slot))


@pytest.mark.parametrize("damage", ["missing_reuse", "corrupt_reuse", "source_step"])
async def test_damaged_reuse_never_enters_reduced_scope(execution, damage):
    e = execution
    paired(e)
    await finish(e, e.assignment)
    assignment, _slot, _ = await other_assignment(e)
    e.r.h.block += 1
    await paired(e).advance(assignment)
    executor = paired(e)
    job = recoverable_order_job(assignment.certificate.order, e.cfg.signer)
    kind, key = (
        ("step", execution_step_key(e.job, 1))
        if damage == "source_step"
        else ("incumbent_reuse", digest(job))
    )
    with executor.journal.journal.transaction() as db:
        if damage == "corrupt_reuse":
            db.execute("UPDATE records SET body=? WHERE kind=? AND id=?", (b"{}", kind, key))
        else:
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, key))
    calls = len(e.calls)

    @asynccontextmanager
    async def forbidden(*args, **kwargs):
        pytest.fail("damaged retained reuse must fail before model residency")
        yield

    role_port(e, forbidden)
    with pytest.raises(ValueError):
        await executor.advance_batch(assignment)
    assert len(e.calls) == calls
