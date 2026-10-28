"""Successor progress survives an older cohort's slow reconciliation after restart."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker


@pytest.mark.parametrize("successor_pending", [False, True])
@pytest.mark.parametrize("configured_priority", [False, True])
async def test_successor_inventory_has_one_independent_pass(
    tmp_path, monkeypatch, successor_pending, configured_priority
):
    old, successor = "a" * 64, "b" * 64
    events = []

    class Owner:
        intake = SimpleNamespace(
            config=SimpleNamespace(
                cohorts=[
                    SimpleNamespace(cohort_sha256=old),
                    SimpleNamespace(cohort_sha256=successor),
                ]
            )
        )

        def pending_latest_entries(self, cohort, *, limit, offset):
            events.append(("pending", cohort))
            if cohort == successor and successor_pending:
                return [("new", object())][offset : offset + limit]
            return []

        def entries(self, cohort, *, after, limit):
            events.append(("entries", cohort))
            return [("old", object())] if cohort == old else []

    worker = ModelAcceptanceWorker(
        Owner(),
        None,
        tmp_path / "inputs",
        tmp_path / "output",
        priority_cohorts=(successor,) if configured_priority else (),
    )

    async def report(cohort):
        events.append(("report", cohort))
        return True

    async def one(cohort, submission):
        events.append(("work", cohort))

    monkeypatch.setattr(worker, "_report_inventory", report)
    monkeypatch.setattr(worker, "_one", one)
    observed = await worker.report_inventory_once()
    await worker.poll_once()

    assert observed["stage"] == "model_certification_inventory"
    assert observed["status"] == "completed"
    assert observed["completed"] == observed["total"] == 2

    assert events.count(("report", successor)) == 1
    assert events.count(("report", old)) == 1
    assert events.count(("pending", successor)) == 1
    assert events.count(("pending", old)) == 1
    if configured_priority and successor_pending:
        assert ("work", old) not in events
        assert events.index(("report", successor)) < events.index(("work", successor))
        return
    assert events.index(("report", successor)) < events.index(("work", old))
    assert events.index(("report", old)) < events.index(("work", old))
    if successor_pending:
        assert events.index(("work", successor)) < events.index(("work", old))
    else:
        assert ("work", successor) not in events
