from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker


@pytest.mark.parametrize("urgent", [False, True])
async def test_released_intake_backlog_bounds_held_batches_without_starving_them(urgent, tmp_path):
    released, held = "a" * 64, "b" * 64
    calls, completed = [], []
    bindings = tuple(SimpleNamespace(cohort_sha256=c) for c in (released, held))

    def entries(cohort, *, after="", limit):
        calls.append((cohort, limit))
        start = int(after) + 1 if after else 0
        return tuple((str(n), (cohort, n)) for n in range(start, start + limit))

    def pending(cohort, *, limit, offset):
        if urgent and cohort == released:
            return (("latest", (cohort, "latest")),)[offset : offset + limit]
        return ()

    owner = SimpleNamespace(
        intake=SimpleNamespace(config=SimpleNamespace(cohorts=bindings)),
        entries=entries,
        pending_latest_entries=pending,
    )
    worker = ModelAcceptanceWorker(
        owner, None, tmp_path, tmp_path, batch_size=4, priority_cohorts=(released,)
    )

    async def one(cohort, sub):
        completed.append(sub)

    async def report(_):
        pass

    worker._one, worker._report_inventory = one, report
    await worker.poll_once()
    assert calls == [(released, 4), (held, 1 if urgent else 4)]
    assert (held, 0) in completed
    completed.clear()
    await worker.poll_once()
    assert (held, 1 if urgent else 4) in completed
    if urgent:
        assert completed[0] == (released, "latest")


def test_priority_cannot_select_an_unconfigured_cohort(tmp_path):
    owner = SimpleNamespace(intake=SimpleNamespace(config=SimpleNamespace(cohorts=())))
    with pytest.raises(ValueError, match="distinct configured"):
        ModelAcceptanceWorker(owner, None, tmp_path, tmp_path, priority_cohorts=("a" * 64,))
