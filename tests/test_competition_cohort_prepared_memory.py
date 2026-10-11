"""Prepared request lifetime under actual tiny admission-policy fixtures."""

import asyncio
import threading
import weakref
from contextlib import contextmanager
from contextvars import ContextVar
from types import SimpleNamespace

import pytest

from tests.test_host_memory_admission import provisioned as provisioned
from tests.test_host_memory_requests import bind
from tests.test_host_memory_requests import stage as stage
from umi import host_memory_request_bounds as bounds
from umi import host_memory_runtime as memory
from umi.competition_cohort_lifecycle import CohortLifecycleService
from umi.competition_cohort_request_preparation import prepared_request_thread
from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver
from umi.host_memory_requests import C5


def observer(native, *, hint=False):
    state = SimpleNamespace(cohort_sha256=C5, phase="requests")
    source = SimpleNamespace(prepare=native, has_fence_hint=lambda _: hint)
    live = LiveRequestPhaseObserver(source, "https://owner.example", client=None)

    async def ready(_):
        return "fixture-nonce", None

    live._fetch_readiness = ready
    live._ready_at = lambda *_: True
    return live, state


def record_graph_release(lease, references, releases):
    original_close = lease.close

    def close():
        # Restore the real method before destruction can revisit this lease.
        del lease.close
        releases.append([ref() is None for ref in references])
        original_close()

    lease.close = close


async def test_one_worker_context_carries_native_tokens_and_selected_policy(stage):
    native_token = ContextVar("native_preparation_test", default=None)
    parent_token = native_token.set("parent")
    threads, leases, budgets = [], [], []
    try:

        @contextmanager
        def native():
            token = native_token.set("worker")
            try:

                def note():
                    threads.append(threading.get_ident())
                    assert native_token.get() == "worker"
                    assert memory.selected_memory() is stage[0]
                    lease = memory._active.get()
                    assert lease is not None and not lease.closed
                    leases.append(lease)
                    budgets.append(bounds._evidence_values.get())

                note()
                yield lambda _: note() or 7
            finally:
                note()
                native_token.reset(token)

        with bind(stage):
            async with (
                memory.memory_operation_context(
                    operation="requests_observe", cohort=C5, phase="requests"
                ),
                prepared_request_thread(native()) as sample,
            ):
                assert native_token.get() == "parent"
                assert await sample(object()) == 7
            assert memory._active.get() is None
            assert bounds._evidence_values.get() is None
        assert len(set(threads)) == 1 and threads[0] != threading.get_ident()
        assert all(lease is leases[0] for lease in leases) and leases[0].closed
        assert all(budget is budgets[0] and budget is not None for budget in budgets)
        assert native_token.get() == "parent"
    finally:
        native_token.reset(parent_token)


@pytest.mark.parametrize("block_at", ["enter", "capture", "sample", "exit"])
async def test_live_preparation_cancellation_holds_grant_until_native_cleanup(stage, block_at):
    loop = asyncio.get_running_loop()
    reached = asyncio.Event()
    release = threading.Event()
    cleaned = threading.Event()
    leases, threads = [], []
    references, releases = [], []

    class Graph:
        pass

    def point(where):
        threads.append(threading.get_ident())
        lease = memory._active.get()
        assert lease is not None and not lease.closed
        assert memory.selected_memory() is stage[0]
        assert bounds._evidence_values.get() is not None
        leases.append(lease)
        if where == block_at:
            loop.call_soon_threadsafe(reached.set)
            assert release.wait(10)

    @contextmanager
    def native(_state):
        graph = Graph()
        references.append(weakref.ref(graph))
        record_graph_release(memory._active.get(), references, releases)
        try:
            point("enter")

            def sample(_capture, **_options):
                assert graph is references[0]()
                point("sample")
                return 7

            yield sample
        finally:
            point("exit")
            cleaned.set()

    live, state = observer(native)

    async def work():
        with bind(stage):
            async with live.prepare(state) as sample:
                if block_at == "capture":
                    reached.set()
                    await asyncio.Event().wait()
                assert await sample(object()) == 7

    pending = asyncio.create_task(work())
    try:
        await asyncio.wait_for(reached.wait(), 10)
        assert leases and not leases[0].closed
        pending.cancel()
        await asyncio.sleep(0)
        pending.cancel()
        await asyncio.sleep(0)
        if block_at != "capture":
            assert not pending.done() and not cleaned.is_set() and not leases[0].closed
            assert (
                stage[0].try_acquire(
                    "transient", operation="requests_observe", cohort=C5, phase="requests"
                )
                is None
            )
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(pending, 10)
        assert cleaned.is_set() and all(lease.closed for lease in leases)
        assert releases == [[True]]
        assert len(set(threads)) == 1
        replacement = stage[0].try_acquire(
            "transient", operation="requests_observe", cohort=C5, phase="requests"
        )
        assert replacement is not None
        replacement.close()
    finally:
        release.set()
        await asyncio.gather(pending, return_exceptions=True)


async def test_fresh_preparation_charges_one_evidence_budget_across_enter_and_sample(stage):
    closed = []
    first = b"[" + b",".join([b"1"] * 70) + b"]"
    second = b"[" + b",".join([b"2"] * 70) + b"]"

    @contextmanager
    def native(_):
        try:
            bounds.check_stage_json(first)

            def sample(_capture, **_options):
                bounds.check_stage_json(second)
                return 7

            yield sample
        finally:
            closed.append(True)

    live, state = observer(native)
    with bind(stage), pytest.raises(ValueError, match="value count"):
        async with live.prepare(state) as sample:
            await sample(object())
    assert closed == [True]
    lease = stage[0].try_acquire(
        "transient", operation="requests_observe", cohort=C5, phase="requests"
    )
    assert lease is not None
    lease.close()


async def test_retained_fence_uses_separate_non_nested_grants(stage):
    seen = []
    live, state = observer(lambda _: pytest.fail("fresh preparation entered"), hint=True)

    def native(label):
        def call(*_args, **_kwargs):
            lease = memory._active.get()
            assert lease is not None and not lease.closed
            seen.append((label, lease))
            return 7

        return call

    live.source.has_fence_hint = native("hint")
    live.source.seal_fenced = native("seal")
    live.source.observe = native("observe")
    with bind(stage):
        async with live.prepare(state) as sample:
            assert memory._active.get() is None
            assert await sample(object()) == 7
    assert [name for name, _ in seen] == ["hint", "seal", "observe"]
    assert len({id(lease) for _, lease in seen}) == 3
    assert all(lease.closed for _, lease in seen)


@pytest.mark.parametrize("field,value", [("cohort_sha256", "0" * 64), ("phase", "preparation")])
async def test_preparation_refuses_scope_before_hint_history_or_driver(stage, field, value):
    live, state = observer(lambda _: pytest.fail("native prepare called"))
    live.source.has_fence_hint = lambda _: pytest.fail("native hint read before scope refusal")
    setattr(state, field, value)
    with bind(stage), pytest.raises(ValueError, match="outside"):
        async with live.prepare(state):
            pytest.fail("unqualified native scope")
    with bind(stage), pytest.raises(ValueError, match="outside"):
        async with CohortLifecycleService._prepare(object(), state):
            pytest.fail("unqualified driver scope")


async def test_disabled_escaped_sampler_releases_enter_result_graph():
    references = []

    class Graph:
        pass

    @contextmanager
    def native():
        graph = Graph()
        references.append(weakref.ref(graph))

        def sample(_):
            assert graph is references[0]()
            return 7

        yield sample

    async with prepared_request_thread(native()) as escaped:
        assert references[0]() is not None
        assert await escaped(object()) == 7
    assert references[0]() is None
    with pytest.raises(RuntimeError, match="no longer available"):
        await escaped(object())


async def test_child_cannot_reenter_parent_preparation_grant(stage):
    with bind(stage):
        async with memory.memory_operation_context(
            operation="requests_observe", cohort=C5, phase="requests"
        ):

            async def nested():
                async with memory.memory_operation_context(
                    operation="requests_sample", cohort=C5, phase="requests"
                ):
                    pytest.fail("inherited lease became reentrant")

            with pytest.raises(RuntimeError, match="nested host"):
                await asyncio.create_task(nested())


@pytest.mark.parametrize("failure_at", ["enter", "capture", "sample", "exit"])
@pytest.mark.parametrize("kind", ["validation", "attributes"])
async def test_native_failure_drops_graph_before_grant_close(stage, failure_at, kind):
    from umi.protocol import StrictProtocolModel

    references, owned, closed, releases = [], [], [], []

    class Graph:
        pass

    class Small(StrictProtocolModel):
        value: int

    def fail(graph):
        if kind == "validation":
            Small.model_validate({"value": graph})
        error = ValueError("native failure", graph)
        error.graph = graph
        raise error

    @contextmanager
    def native(_):
        graph = Graph()
        references.append(weakref.ref(graph))
        lease = memory._active.get()
        owned.append(lease)
        record_graph_release(lease, references, releases)
        try:
            if failure_at == "enter":
                fail(graph)

            def sample(_capture, **_options):
                if failure_at == "sample":
                    fail(graph)
                return 7

            yield sample
            if failure_at == "exit":
                fail(graph)
        finally:
            closed.append(True)

    live, state = observer(native)
    with bind(stage), pytest.raises((ValueError, OSError)) as caught:
        async with live.prepare(state) as sample:
            if failure_at == "capture":
                raise OSError("capture failed")
            await sample(object())
    assert caught.value.__cause__ is None
    assert owned[0].closed
    assert closed == [True]
    assert releases == [[True]]
    assert references[0]() is None
