from __future__ import annotations

import asyncio
import heapq
import random
from types import SimpleNamespace

import pytest

from umi.competition_dispatch_capacity import (
    DispatchCapacityJob,
    DispatchTimingBudget,
    DispatchTimingLimits,
    capacity_job,
    plan_dispatch_capacity,
    timing_profile_sha256,
)
from umi.competition_scheduling import assignment_key
from umi.open_competition import digest, identity
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_authorization import build_authorization_fixture
from .test_competition_dispatch import authorization as authorization
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_dispatch import feed as feed
from .test_competition_dispatch import ready
from .test_open_competition import policy as policy


@pytest.fixture
def limits():
    return DispatchTimingLimits(
        maximum_concurrency=4,
        page_size=32,
        poll_seconds=5,
        discovery_grace_seconds=10,
        request_timeout_seconds=180,
    )


@pytest.fixture
def budget():
    # Deliberately synthetic unit inputs, not production qualification evidence.
    return DispatchTimingBudget(
        proof_collection_ms=50,
        origin_collection_ms=80,
        publication_ingestion_ms=100,
        local_cycle_ms=2,
        publication_delay_ms=1000,
        block_advance_numerator=1,
        block_advance_denominator_ms=12000,
        finality_headroom_blocks=2,
        measurement_sha256="ab" * 32,
    )


def job(index=1, *, miner=1, **changes):
    return DispatchCapacityJob(
        **{
            "assignment_key": f"{index:064x}",
            "miner_account": f"{miner:064x}",
            "publication_sha256": f"{miner + 1000:064x}",
            "issued_block": 10,
            "deadline_block": 1_000_000,
            "issue_close_ms": 10_000_000,
            "response_close_ms": 20_000_000,
            **changes,
        }
    )


def plan(jobs, limits, budget, **changes):
    return plan_dispatch_capacity(
        jobs,
        limits=limits,
        budget=budget,
        **{"now_ms": 1000, "observed_block": 10, **changes},
    )


def test_empty_inventory_has_no_invented_work(limits, budget):
    result = plan((), limits, budget)
    assert result.assignment_count == result.pending_count == result.publication_count == 0
    assert result.serial_overhead_ms == result.parallel_work_ms == result.scan_cycles == 0
    assert result.last_start_upper_bound_ms == result.last_finish_upper_bound_ms == 1000
    assert result.finish_block_upper_bound == 10
    assert result.profile_sha256 == timing_profile_sha256(limits, budget)
    assert result.conditional_block_advance is True


def test_input_order_does_not_change_the_capacity_bound(limits, budget):
    jobs = tuple(job(i, miner=i % 3) for i in range(1, 12))
    assert plan(jobs, limits, budget) == plan(tuple(reversed(jobs)), limits, budget)


def test_single_miner_is_serial_even_with_more_http_slots(limits, budget):
    jobs = tuple(job(i) for i in range(1, 7))
    ordinary = plan(jobs, limits, budget)
    raised = plan(jobs, limits.model_copy(update={"maximum_concurrency": 128}), budget)
    assert ordinary.maximum_miner_assignments == 6
    assert ordinary.last_finish_upper_bound_ms == raised.last_finish_upper_bound_ms


def test_concurrency_only_helps_when_multiple_miners_can_run(limits, budget):
    jobs = tuple(job(i, miner=i) for i in range(1, 9))
    single = plan(jobs, limits.model_copy(update={"maximum_concurrency": 1}), budget)
    parallel = plan(jobs, limits, budget)
    assert parallel.last_finish_upper_bound_ms < single.last_finish_upper_bound_ms
    assert parallel.serial_overhead_ms == single.serial_overhead_ms


@pytest.mark.parametrize("slots", [3, 4, 128])
def test_one_slot_per_miner_bounds_http_by_longest_chain(limits, budget, slots):
    jobs = tuple(job(i, miner=1 if i <= 6 else i - 5) for i in range(1, 9))
    limits = limits.model_copy(update={"maximum_concurrency": slots})
    result = plan(jobs, limits, budget)
    padded = limits.request_timeout_seconds * 1000 + result.scan_cycles * (
        limits.poll_seconds * 1000 + budget.local_cycle_ms
    )
    assert result.maximum_miner_assignments == 6
    assert result.parallel_work_ms == 6 * padded
    # Spare slots cannot accelerate a miner's serialized work or remove I/O cost.
    saturated = plan(jobs, limits.model_copy(update={"maximum_concurrency": 3}), budget)
    assert result.last_finish_upper_bound_ms == saturated.last_finish_upper_bound_ms


def test_in_flight_miner_counts_at_slot_contention_boundary(limits, budget):
    limits = limits.model_copy(update={"maximum_concurrency": 2})
    jobs = (job(1, miner=1), job(2, miner=2))
    spare = plan(jobs, limits, budget)
    occupied = plan(
        (*jobs, job(3, miner=3, state="in_flight", issue_close_ms=100)), limits, budget
    )
    padded = limits.request_timeout_seconds * 1000 + occupied.scan_cycles * (
        limits.poll_seconds * 1000 + budget.local_cycle_ms
    )
    assert occupied.parallel_work_ms == 2 * padded
    assert occupied.parallel_work_ms > spare.parallel_work_ms
    assert occupied.pending_count == 2


def test_existing_work_consumes_slots_and_time(limits, budget):
    candidate = job(1)
    alone = plan((candidate,), limits, budget)
    existing = job(2, state="in_flight", issue_close_ms=100)
    combined = plan((candidate, existing), limits, budget)
    assert combined.assignment_count == 2 and combined.pending_count == 1
    assert combined.maximum_miner_assignments == 2
    assert combined.last_finish_upper_bound_ms > alone.last_finish_upper_bound_ms
    # Existing in-flight work is not reissued; its elapsed issue window is allowed.
    assert plan((existing,), limits, budget).pending_count == 0


@pytest.mark.parametrize("field,value", [("page_size", 1), ("poll_seconds", 30)])
def test_page_sweep_and_poll_cadence_are_not_free(limits, budget, field, value):
    jobs = tuple(job(i, miner=i) for i in range(1, 9))
    original = plan(jobs, limits, budget)
    slower = plan(jobs, limits.model_copy(update={field: value}), budget)
    assert slower.last_start_upper_bound_ms > original.last_start_upper_bound_ms


def test_serial_proofs_include_header_origin_and_grace_probe_costs(limits, budget):
    jobs = (job(1), job(2), job(3))
    original = plan(jobs, limits, budget)
    header = plan(jobs, limits, budget.model_copy(update={"proof_collection_ms": 51}))
    origin = plan(jobs, limits, budget.model_copy(update={"origin_collection_ms": 81}))
    # One publication, ceil(10 seconds / 5-second polling) + 1 grace probes.
    assert header.serial_overhead_ms - original.serial_overhead_ms == 3 + len(jobs)
    assert origin.serial_overhead_ms - original.serial_overhead_ms == len(jobs)
    assert header.parallel_work_ms == original.parallel_work_ms


def test_restart_inbox_ingestion_and_delivery_delay_are_budgeted(limits, budget):
    original = plan((job(),), limits, budget)
    retained_files = plan((job(),), limits, budget, additional_inbox_publications=3)
    delayed = plan((job(),), limits, budget.model_copy(update={"publication_delay_ms": 2000}))
    assert retained_files.publication_count == 4
    assert retained_files.last_start_upper_bound_ms > original.last_start_upper_bound_ms
    assert delayed.last_start_upper_bound_ms - original.last_start_upper_bound_ms == 1000


def test_discovery_grace_can_serialize_across_publications(limits, budget):
    limits = limits.model_copy(
        update={
            "maximum_concurrency": 1,
            "poll_seconds": 1,
            "discovery_grace_seconds": 60,
            "request_timeout_seconds": 1,
        }
    )
    jobs = tuple(job(i, miner=i) for i in range(1, 11))
    result = plan(jobs, limits, budget)
    # A first-page held job can monopolize the sole slot until its own grace
    # completes; subsequent publications must not receive imaginary overlap.
    assert result.serial_overhead_ms >= 10 * 60_000


def test_issue_window_is_a_strict_start_deadline(limits, budget):
    bound = plan((job(),), limits, budget).last_start_upper_bound_ms
    with pytest.raises(ValueError, match="original issue window"):
        plan((job(issue_close_ms=bound),), limits, budget)
    plan((job(issue_close_ms=bound + 1),), limits, budget)


def test_response_window_must_fit_the_full_timeout(limits, budget):
    bound = plan((job(),), limits, budget).last_finish_upper_bound_ms
    original = job(issue_close_ms=bound - 1, response_close_ms=bound)
    with pytest.raises(ValueError, match="original response window"):
        plan((original,), limits, budget)
    plan((original.model_copy(update={"response_close_ms": bound + 1}),), limits, budget)


def test_block_deadline_uses_explicit_advance_bound_and_headroom(limits, budget):
    original = plan((job(),), limits, budget)
    faster = plan((job(),), limits, budget.model_copy(update={"block_advance_numerator": 2}))
    assert faster.finish_block_upper_bound > original.finish_block_upper_bound
    assert faster.last_finish_upper_bound_ms == original.last_finish_upper_bound_ms
    plan((job(deadline_block=original.finish_block_upper_bound),), limits, budget)
    with pytest.raises(ValueError, match="original block deadline"):
        plan((job(deadline_block=original.finish_block_upper_bound - 1),), limits, budget)


@pytest.mark.parametrize(
    "changes,reason",
    [({"issued_block": 11}, "not yet finalized"), ({"deadline_block": 11}, "block deadline")],
)
def test_finalized_height_is_checked_before_qualification(limits, budget, changes, reason):
    with pytest.raises(ValueError, match=reason):
        plan((job(**changes),), limits, budget)


def test_any_earlier_existing_deadline_prevents_admitting_new_work(limits, budget):
    existing = job(1)
    first_bound = plan((existing,), limits, budget).last_start_upper_bound_ms
    existing = existing.model_copy(update={"issue_close_ms": first_bound + 1})
    plan((existing,), limits, budget)
    with pytest.raises(ValueError, match="original issue window"):
        plan((existing, job(2)), limits, budget)


def test_duplicate_assignment_cannot_hide_as_an_existing_reservation(limits, budget):
    with pytest.raises(ValueError, match="repeats an assignment"):
        plan((job(), job(state="in_flight")), limits, budget)


def test_profile_binds_every_actual_limit_and_qualification_input(limits, budget):
    original = timing_profile_sha256(limits, budget)
    for name in DispatchTimingLimits.model_fields:
        value = getattr(limits, name)
        assert (
            timing_profile_sha256(limits.model_copy(update={name: value + 1}), budget) != original
        )
    for name in DispatchTimingBudget.model_fields:
        value = getattr(budget, name)
        replacement = "cd" * 32 if name == "measurement_sha256" else value + 1
        assert (
            timing_profile_sha256(limits, budget.model_copy(update={name: replacement})) != original
        )


def test_budget_has_no_invented_latency_or_block_velocity_defaults(budget):
    for name in DispatchTimingBudget.model_fields:
        raw = budget.model_dump()
        del raw[name]
        with pytest.raises(ValueError):
            DispatchTimingBudget.model_validate(raw)


@pytest.mark.parametrize(
    "changes",
    [
        {"now_ms": True},
        {"now_ms": -1},
        {"observed_block": False},
        {"additional_inbox_publications": True},
        {"additional_inbox_publications": -1},
    ],
)
def test_clock_and_inventory_inputs_are_strict(limits, budget, changes):
    with pytest.raises(ValueError):
        plan((job(),), limits, budget, **changes)


def test_actual_dispatcher_inbox_bound_is_not_replaced_by_larger_storage_cap(limits, budget):
    with pytest.raises(ValueError, match="publication inbox bound"):
        plan((job(),), limits, budget, additional_inbox_publications=1024)


def test_job_does_not_allow_retry_of_unknown_or_completed_claims():
    for state in ("uncertain", "completed", "expired"):
        with pytest.raises(ValueError):
            job(state=state)


def test_job_builder_matches_existing_assignment_identity_and_signed_clock(policy):
    fixture = build_authorization_fixture(policy)
    signed = fixture.publication
    body = signed.publication
    assignment = body.assignments[0]
    result = capacity_job(body, assignment, fixture.legacy_policy)
    assert result.assignment_key == assignment_key(signed, assignment)
    assert result.publication_sha256 == digest(body)
    assert result.miner_account == identity(body.submissions[0].submission.hotkey)
    assert result.issued_block == assignment.request.issued_block
    assert result.deadline_block == assignment.request.deadline_block
    assert result.issue_close_ms == (
        QUICKNET_GENESIS_MS + (fixture.schedule.issue_close_round - 1) * QUICKNET_PERIOD_MS
    )
    assert result.response_close_ms == (
        QUICKNET_GENESIS_MS + (fixture.schedule.response_close_round - 1) * QUICKNET_PERIOD_MS
    )


def test_job_builder_rejects_foreign_assignment_or_transport(policy):
    fixture = build_authorization_fixture(policy)
    body = fixture.publication.publication
    assignment = body.assignments[0]
    with pytest.raises(ValueError, match="absent"):
        capacity_job(
            body, assignment.model_copy(update={"case_sha256": "ef" * 32}), fixture.legacy_policy
        )
    with pytest.raises(ValueError, match="transport policy mismatch"):
        capacity_job(
            body.model_copy(update={"legacy_policy_sha256": "ef" * 32}),
            assignment,
            fixture.legacy_policy,
        )


def test_dispatch_config_preserves_missing_budget_compatibility(dispatch):
    from umi.competition_dispatch import EndpointDispatchConfig

    raw = dispatch.config.model_dump(by_alias=True, exclude={"timing_budget"})
    assert EndpointDispatchConfig.model_validate(raw).timing_budget is None


@pytest.mark.parametrize("configured", [False, True])
def test_dispatcher_binds_actual_limits_even_without_optional_budget(
    dispatch, budget, monkeypatch, configured
):
    from umi.competition_dispatch import EndpointDispatcher

    config = dispatch.config.model_copy(
        update={
            "maximum_concurrency": 7,
            "page_size": 19,
            "poll_seconds": 3,
            "discovery_grace_seconds": 13,
            "request_timeout_seconds": 117,
            "timing_budget": budget if configured else None,
        }
    )
    calls = []
    monkeypatch.setattr(dispatch.feed.journal, "configure_dispatch", lambda **kw: calls.append(kw))
    EndpointDispatcher(
        config, dispatch.feed.journal, dispatch.provider, dispatch.feed.item.validator_wallet
    )
    assert calls == [
        {
            "evaluator_hotkey": config.evaluator_hotkey,
            "limits": DispatchTimingLimits(
                maximum_concurrency=7,
                page_size=19,
                poll_seconds=3,
                discovery_grace_seconds=13,
                request_timeout_seconds=117,
            ),
            "budget": budget if configured else None,
            "publication_directory": config.publication_directory,
        }
    ]


def test_dispatcher_does_not_ignore_retained_profile_rejection(dispatch, monkeypatch):
    from umi.competition_dispatch import EndpointDispatcher

    def incompatible(**_kw):
        raise ValueError("retained timing profile differs")

    monkeypatch.setattr(dispatch.feed.journal, "configure_dispatch", incompatible)
    with pytest.raises(ValueError, match="retained timing profile differs"):
        EndpointDispatcher(
            dispatch.config,
            dispatch.feed.journal,
            dispatch.provider,
            dispatch.feed.item.validator_wallet,
        )


async def test_each_poll_rechecks_profile_before_reading_inbox(dispatch, monkeypatch):
    def incompatible(**_kw):
        raise ValueError("retained timing profile differs")

    async def forbidden_ingestion():
        pytest.fail("profile mismatch must stop polling before ingestion")

    monkeypatch.setattr(dispatch.feed.journal, "configure_dispatch", incompatible)
    monkeypatch.setattr(dispatch.driver, "ingest_once", forbidden_ingestion)
    with pytest.raises(ValueError, match="retained timing profile differs"):
        await dispatch.driver.poll_once()
    assert not dispatch.driver._tasks


async def test_profile_changed_during_origin_proof_holds_before_claim(dispatch, monkeypatch):
    await ready(dispatch)
    original = dispatch.provider.dispatch_origin

    async def origin_then_profile_change(*args):
        origin = await original(*args)

        def incompatible(**_kw):
            raise ValueError("retained timing profile differs")

        monkeypatch.setattr(dispatch.feed.journal, "configure_dispatch", incompatible)
        return origin

    def forbidden_claim(*args, **kw):
        pytest.fail("profile changed while awaiting proofs: must not claim")

    monkeypatch.setattr(dispatch.provider, "dispatch_origin", origin_then_profile_change)
    monkeypatch.setattr(dispatch.feed.journal, "claim", forbidden_claim)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "published"


async def test_claim_receives_actual_timing_profile_for_atomic_recheck(
    dispatch, budget, monkeypatch
):
    await ready(dispatch)
    dispatch.driver.config = dispatch.config.model_copy(update={"timing_budget": budget})
    actual = DispatchTimingLimits(
        **{name: getattr(dispatch.config, name) for name in DispatchTimingLimits.model_fields}
    )
    seen = []
    monkeypatch.setattr(dispatch.feed.journal, "configure_dispatch", lambda **kw: None)

    def record_claim(key, **kw):
        seen.append((key, kw["expected_dispatch_profile"]))
        return None

    monkeypatch.setattr(dispatch.feed.journal, "claim", record_claim)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert seen == [(dispatch.key, timing_profile_sha256(actual, budget))]


class _DispatchClock:
    """Event-loop driven virtual time; no wall-clock sleeps or HTTP requests."""

    def __init__(self, now_ms):
        self.now_ms = now_ms
        self.waiters = []
        self.sequence = 0

    async def sleep(self, milliseconds):
        future = asyncio.get_running_loop().create_future()
        self.sequence += 1
        heapq.heappush(self.waiters, (self.now_ms + milliseconds, self.sequence, future))
        await future

    async def run(self, task, *, maximum_events=20_000):
        for _ in range(maximum_events):
            # Let released tasks enqueue all work at this instant before advancing.
            for _ in range(12):
                await asyncio.sleep(0)
            if task.done():
                return await task
            assert self.waiters, "fake-clock dispatcher stalled without scheduled work"
            self.now_ms = self.waiters[0][0]
            while self.waiters and self.waiters[0][0] <= self.now_ms:
                _time, _seq, future = heapq.heappop(self.waiters)
                if not future.done():
                    future.set_result(None)
        pytest.fail("fake-clock dispatch did not finish within bounded event count")


async def _exercise_poll_loop(jobs, limits, budget, *, extra_inbox=(), restart_after=None):
    """Run real task retirement, paging and per-miner admission over synthetic I/O.

    The pending-page adapter mirrors the journal's ordering/filtering but does not
    authenticate publications or persist SQLite state. Only a drained restart is
    modeled; interrupted in-flight work is covered by the native lifecycle tests.
    """
    from umi.competition_dispatch import EndpointDispatcher

    clock = _DispatchClock(1000)
    pending, completed = {}, set()
    by_publication = {}
    for item in jobs:
        by_publication.setdefault(item.publication_sha256, []).append(item)
    publication_order = sorted(set(by_publication) | set(extra_inbox))
    starts, finishes, active_miners = {}, {}, set()
    metrics = SimpleNamespace(
        pages=0,
        full_pages=0,
        cursor_wraps=0,
        peak_http=0,
        http=0,
        ingestions=0,
        restarts=0,
    )

    def pending_dispatches(*, evaluator_hotkey, after, limit):
        assert evaluator_hotkey == "synthetic-evaluator"
        rows = [pending[key] for key in sorted(pending) if after is None or key > after]
        page = rows[:limit]
        metrics.pages += 1
        metrics.full_pages += len(page) == limit
        metrics.cursor_wraps += after is not None and len(rows) <= limit
        return {
            "items": [
                {"assignment_key": item.assignment_key, "miner_account": item.miner_account}
                for item in page
            ],
            "next_cursor": page[-1].assignment_key if len(rows) > limit else None,
        }

    def make_driver():
        proof_gate = asyncio.Lock()
        ready_since, ingested = {}, set()

        async def ingest_once():
            if len(ingested) == len(publication_order):
                return "idle"
            publication = publication_order[len(ingested)]
            async with proof_gate:
                await clock.sleep(budget.publication_ingestion_ms)
            ingested.add(publication)
            metrics.ingestions += 1
            # Exact inbox replay must not resurrect claimed or completed work.
            pending.update(
                {
                    item.assignment_key: item
                    for item in by_publication.get(publication, ())
                    if item.assignment_key not in starts
                }
            )
            return "retained"

        async def dispatch_one(key):
            item = pending[key]
            assert item.miner_account not in active_miners
            active_miners.add(item.miner_account)
            try:
                async with proof_gate:
                    await clock.sleep(budget.proof_collection_ms)
                ready_since.setdefault(item.publication_sha256, clock.now_ms)
                grace_close = (
                    ready_since[item.publication_sha256] + limits.discovery_grace_seconds * 1000
                )
                if clock.now_ms < grace_close:
                    return "held"
                async with proof_gate:
                    await clock.sleep(budget.origin_collection_ms)
                assert key not in starts
                assert clock.now_ms < item.issue_close_ms
                del pending[key]
                starts[key] = clock.now_ms
                metrics.http += 1
                metrics.peak_http = max(metrics.peak_http, metrics.http)
                assert metrics.http <= limits.maximum_concurrency
                await clock.sleep(limits.request_timeout_seconds * 1000)
                metrics.http -= 1
                assert clock.now_ms < item.response_close_ms
                finishes[key] = clock.now_ms
                await clock.sleep(budget.local_cycle_ms)
                completed.add(key)
                return "completed"
            finally:
                active_miners.remove(item.miner_account)

        driver = object.__new__(EndpointDispatcher)
        driver.config = SimpleNamespace(
            **limits.model_dump(), evaluator_hotkey="synthetic-evaluator"
        )
        driver.journal = SimpleNamespace(pending_dispatches=pending_dispatches)
        driver._configure_timing = lambda: None
        driver._tasks, driver._cursor = {}, None
        driver._counts = {"completed": 0, "held": 0, "uncertain": 0}
        driver.ingest_once, driver.dispatch_one = ingest_once, dispatch_one
        return driver

    driver = make_driver()

    async def run():
        nonlocal driver
        await clock.sleep(budget.publication_delay_ms)
        while len(completed) < len(jobs) or driver._tasks:
            await clock.sleep(budget.local_cycle_ms)
            await driver.poll_once()
            if (
                restart_after is not None
                and not metrics.restarts
                and len(completed) >= restart_after
            ):
                await driver.drain()
                await driver.aclose()
                assert not active_miners and metrics.http == 0
                driver = make_driver()
                metrics.restarts += 1
            await clock.sleep(limits.poll_seconds * 1000)

    task = asyncio.create_task(run())
    try:
        await clock.run(
            task,
            maximum_events=max(20_000, len(jobs) * 8 + len(publication_order) * 32),
        )
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        await driver.aclose()
    assert not pending and not active_miners and metrics.http == 0
    assert len(completed) == len(starts) == len(finishes) == len(jobs)
    return SimpleNamespace(
        starts=starts,
        finishes=finishes,
        metrics=metrics,
        publication_count=len(publication_order),
    )


@pytest.mark.parametrize("concurrency,page_size,grace,timeout", [(1, 100, 60, 1), (4, 2, 5, 2)])
async def test_capacity_bound_covers_real_poll_loop_with_serial_publication_grace(
    limits,
    budget,
    concurrency,
    page_size,
    grace,
    timeout,
):
    """Synthetic I/O bounds exercise real scheduling, not production throughput."""
    limits = limits.model_copy(
        update={
            "maximum_concurrency": concurrency,
            "page_size": page_size,
            "poll_seconds": 1,
            "discovery_grace_seconds": grace,
            "request_timeout_seconds": timeout,
        }
    )
    jobs = tuple(job(i + 1, miner=i // 3 + 1) for i in range(30))
    result = plan(jobs, limits, budget)
    observed = await _exercise_poll_loop(jobs, limits, budget)
    assert max(observed.starts.values()) <= result.last_start_upper_bound_ms
    assert max(observed.finishes.values()) <= result.last_finish_upper_bound_ms
    if concurrency == 1:
        # First-page grace holds really do monopolize the single dispatch slot.
        assert max(observed.finishes.values()) - 1000 >= observed.publication_count * grace * 1000


@pytest.mark.parametrize("slots", [3, 128])
@pytest.mark.parametrize("ordering", ["grouped", "interleaved", "shuffled"])
async def test_uncontended_bound_covers_real_poll_loop(limits, budget, slots, ordering):
    limits = limits.model_copy(
        update={"maximum_concurrency": slots, "page_size": 2, "poll_seconds": 1}
    )
    entries = [(miner, case) for miner, count in ((1, 6), (2, 4), (3, 1)) for case in range(count)]
    if ordering == "interleaved":
        entries.sort(key=lambda item: (item[1], item[0]))
    elif ordering == "shuffled":
        random.Random(314159).shuffle(entries)
    jobs = tuple(job(index, miner=miner) for index, (miner, _case) in enumerate(entries, 1))
    extra_inbox = tuple(f"{index:064x}" for index in range(1, 4))
    result = plan(jobs, limits, budget, additional_inbox_publications=len(extra_inbox))
    observed = await _exercise_poll_loop(jobs, limits, budget, extra_inbox=extra_inbox)
    assert observed.metrics.full_pages > 0 and observed.metrics.cursor_wraps > 0
    assert 1 < observed.metrics.peak_http <= 3
    assert max(observed.starts.values()) <= result.last_start_upper_bound_ms
    assert max(observed.finishes.values()) <= result.last_finish_upper_bound_ms


@pytest.mark.parametrize(
    "ordering,restart,inbox_pressure",
    [
        ("grouped", False, False),
        ("interleaved", False, False),
        ("shuffled", False, False),
        ("grouped", True, True),
    ],
)
async def test_full_cohort_real_poll_loop_characterizes_conservative_rejection(
    ordering, restart, inbox_pressure, record_testsuite_property
):
    """6,912 synthetic requests are not a signed or hardware-qualified workload.

    Keep the real planner's rejection for the original 5,400-second issue window.
    The clock shows what the polling loop does at explicit 1ms local/1s request
    costs, not what an arbitrary miner, proof source or machine can guarantee.
    """
    limits = DispatchTimingLimits(
        maximum_concurrency=128,
        page_size=100,
        poll_seconds=1,
        discovery_grace_seconds=5,
        request_timeout_seconds=1,
    )
    budget = DispatchTimingBudget(
        proof_collection_ms=1,
        origin_collection_ms=1,
        publication_ingestion_ms=1,
        local_cycle_ms=1,
        publication_delay_ms=0,
        block_advance_numerator=1,
        block_advance_denominator_ms=12000,
        finality_headroom_blocks=0,
        measurement_sha256="cd" * 32,
    )
    entries = [(miner, case) for miner in range(1, 257) for case in range(27)]
    if ordering == "interleaved":
        entries.sort(key=lambda item: (item[1], item[0]))
    elif ordering == "shuffled":
        random.Random(271828).shuffle(entries)
    jobs = tuple(
        job(
            index,
            miner=miner,
            issue_close_ms=1000 + 5_400_000,
            response_close_ms=1000 + 5_700_000,
        )
        for index, (miner, _case) in enumerate(entries, 1)
    )
    # Completed/unrelated inbox publications still cost one ingestion per poll.
    extra_inbox = tuple(f"{index:064x}" for index in range(1, 769)) if inbox_pressure else ()
    with pytest.raises(ValueError, match="cannot fit its original issue window"):
        plan(jobs, limits, budget, additional_inbox_publications=len(extra_inbox))

    observed = await _exercise_poll_loop(
        jobs,
        limits,
        budget,
        extra_inbox=extra_inbox,
        restart_after=len(jobs) // 3 if restart else None,
    )
    assert len(observed.starts) == len(observed.finishes) == 256 * 27
    assert observed.metrics.full_pages > 0 and observed.metrics.cursor_wraps > 0
    assert 1 < observed.metrics.peak_http <= 128
    assert observed.metrics.restarts == int(restart)
    assert max(observed.starts.values()) < 1000 + 5_400_000
    assert max(observed.finishes.values()) < 1000 + 5_700_000
    if inbox_pressure:
        assert observed.publication_count == 1024
        assert observed.metrics.ingestions > observed.publication_count
        assert min(observed.starts.values()) >= 1000 + len(extra_inbox) * 1000
    for name, value in {
        "last_start_elapsed_ms": max(observed.starts.values()) - 1000,
        "last_finish_elapsed_ms": max(observed.finishes.values()) - 1000,
        "poll_count": observed.metrics.pages,
        "peak_http": observed.metrics.peak_http,
        "ingestion_count": observed.metrics.ingestions,
        "restart_count": observed.metrics.restarts,
    }.items():
        record_testsuite_property(f"{ordering}:{restart}:{inbox_pressure}.{name}", value)
