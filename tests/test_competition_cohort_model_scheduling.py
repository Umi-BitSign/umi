from types import SimpleNamespace

import pytest

from umi.competition_cohort_model_acceptance_worker import ModelAcceptanceWorker


@pytest.mark.parametrize("urgent", [False, True])
async def test_released_intake_backlog_bounds_held_batches_without_starving_them(urgent, tmp_path):
    released, held = "a" * 64, "b" * 64
    calls, completed = [], []
    remaining = [f"latest-{n}" for n in range(12)]
    bindings = tuple(SimpleNamespace(cohort_sha256=c) for c in (released, held))

    def entries(cohort, *, after="", limit):
        calls.append((cohort, limit))
        start = int(after) + 1 if after else 0
        return tuple((str(n), (cohort, n)) for n in range(start, start + limit))

    def pending(cohort, *, limit, offset):
        if urgent and cohort == released:
            return tuple((key, (cohort, key)) for key in remaining[offset : offset + limit])
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
        if urgent and cohort == released:
            remaining.remove(sub[1])

    async def report(_):
        pass

    worker._one, worker._report_inventory = one, report
    if urgent:
        # Latest pending metadata is already the selected native work: no
        # duplicate export scan. Four foreground attempts must yield one
        # background slot, even while the released backlog remains nonempty.
        for _ in range(10):
            report = await worker.poll_once()
            assert report["entries_exported"] == 1
        assert calls == [(held, 1), (held, 1)]
        assert [cohort for cohort, _ in completed] == ([released] * 4 + [held]) * 2
        assert [sub for sub in completed if sub[0] == held] == [(held, 0), (held, 1)]
        assert [key for cohort, key in completed if cohort == released] == [
            f"latest-{n}" for n in range(8)
        ]
        # Draining the final foreground items restores ordinary full batches
        # and continues the held cohort's retained cursor.
        for _ in range(4):
            await worker.poll_once()
        assert not remaining
        await worker.poll_once()
        assert calls[-2:] == [(released, 4), (held, 4)]
        assert (held, 2) in completed
    else:
        await worker.poll_once()
        assert calls == [(released, 4), (held, 4)]
        assert (held, 0) in completed
        completed.clear()
        await worker.poll_once()
        assert (held, 4) in completed


def test_priority_cannot_select_an_unconfigured_cohort(tmp_path):
    owner = SimpleNamespace(intake=SimpleNamespace(config=SimpleNamespace(cohorts=())))
    with pytest.raises(ValueError, match="distinct configured"):
        ModelAcceptanceWorker(owner, None, tmp_path, tmp_path, priority_cohorts=("a" * 64,))
