"""Successor progress survives an older cohort's slow reconciliation after restart."""

from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker


@pytest.mark.parametrize("successor_pending", [False, True])
async def test_successor_inventory_reported_first_without_duplicate_pass(
    tmp_path, monkeypatch, successor_pending
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

        def pending_latest_entries(self, cohort, *, limit):
            events.append(("pending", cohort))
            return [("new", object())] if cohort == successor and successor_pending else []

        def entries(self, cohort, *, after, limit):
            events.append(("entries", cohort))
            return [("old", object())] if cohort == old else []

    worker = ModelAcceptanceWorker(
        Owner(), None, tmp_path / "inputs", tmp_path / "output", priority_cohorts=(successor,)
    )

    async def report(cohort):
        events.append(("report", cohort))

    async def one(cohort, submission):
        events.append(("work", cohort))

    monkeypatch.setattr(worker, "_report_inventory", report)
    monkeypatch.setattr(worker, "_one", one)
    await worker.poll_once()

    assert events[0] == ("report", successor)
    assert events.count(("report", successor)) == 2
    assert events.count(("report", old)) == 2
    if successor_pending:
        assert events.index(("work", successor)) < events.index(("work", old))
    else:
        assert ("work", successor) not in events
        assert events.index(("work", old)) < events.index(("entries", successor))
