"""Bound retained settlement lifetimes without repeating native pending work."""

import asyncio
import threading
import weakref
from contextlib import nullcontext
from types import SimpleNamespace

import pytest

from umi import competition_cohort_settlement_service as service
from umi.competition_cohort_settlement_service import CohortSettlementService
from umi.concurrency import run_owned_thread


class Marker:
    pass


def graph(node):
    data = Marker()
    data.objects = lambda _: b"original"
    data.pulses = lambda _: b"pulse"
    owner = SimpleNamespace(external=data.objects, pulses=lambda _: data)
    phases = SimpleNamespace(owner=owner)
    exchange = SimpleNamespace(phases=phases)
    phases.peers = (lambda: exchange,)
    node.data = data
    node.votes = SimpleNamespace(inputs=data, retained_deliveries=())
    node.controller = SimpleNamespace(phases=phases)
    node.phases, node.exchange = phases, exchange
    node.batch_votes = ((data,), (data,))
    return weakref.ref(data)


def blank():
    node = object.__new__(CohortSettlementService)
    # These lifecycle fixtures replace native verification with tiny graph ports.
    # Supply its owner scope explicitly, just as the real constructor does.
    node.verification_reuse = SimpleNamespace(selected=nullcontext)
    node.data = node.votes = node.controller = node.phases = node.exchange = None
    node.batch_votes = ((), ())
    node.retained_result_votes = ()
    node.completed_requests = {("evidence", "progress"): "retained-request"}
    node.journal = object()
    node.signing = object()
    node.reference = False
    node.reviewed_terminal_tip = node.published_tip = None
    node.package_reference = ("retained-original", "retained-digest")
    node.reward_package_reference = None
    node.terminal_certification_sha256 = None
    return node


async def ready(node, *, phase="first_admission", role="coordinator"):
    node.cohort = "cohort"
    node.provider = SimpleNamespace(ensure_observer_running=lambda: None)
    node.config = SimpleNamespace(role=role, exchange_outbox="/unused", maximum_package_bytes=1024)
    history = SimpleNamespace(transitions=())
    state = SimpleNamespace(phase=phase, tip_sha256="tip", observed_at_block=1)
    node.store = SimpleNamespace(
        status=lambda _: (state, None), published_history=lambda _: history
    )

    async def handoff():
        return history

    async def received(value):
        return value

    async def model_artifacts():
        return None

    node._handoff, node._receive_history = handoff, received
    node._ensure_model_artifacts = model_artifacts
    node._certification_prefix = lambda history: "original-certified-prefix"
    return state, history


@pytest.mark.parametrize("retain_exchange", [False, True])
def test_release_breaks_phase_exchange_cycle_and_raw_closures(retain_exchange):
    node = blank()
    retained = node.journal, node.signing, node.package_reference, node.completed_requests
    reference = graph(node)
    node._release_active_inputs(retain_exchange=retain_exchange)
    # No gc.collect(): peer/exchange cycles must be explicitly broken.
    assert reference() is None
    assert node.data is None and node.votes is None and node.controller is None
    assert node.batch_votes == ((), ())
    assert (node.journal, node.signing, node.package_reference, node.completed_requests) == retained
    if retain_exchange:
        assert node.phases is not None and node.exchange is not None
        with pytest.raises(RuntimeError, match="released"):
            node.phases.owner.pulses(1)
        with pytest.raises(RuntimeError, match="released"):
            node.phases.owner.external("object")
    else:
        assert node.phases is None and node.exchange is None


@pytest.mark.parametrize("failure", [False, True])
async def test_phase_rebuild_releases_old_graph_before_loading_and_failed_partial(failure):
    node = blank()
    previous = graph(node)
    created = []

    async def load(history):
        assert previous() is None
        assert node.data is None and node.phases is None
        created.append(graph(node))
        if failure:
            raise OSError("missing original proof")

    node._load_active_inputs = load
    if failure:
        with pytest.raises(OSError, match="missing original proof"):
            await node._start("history")
        assert created[0]() is None
        assert node.phases is None
    else:
        await node._start("history")
        assert created[0]() is node.data
    assert node.package_reference == ("retained-original", "retained-digest")


async def test_failed_start_cancellation_drains_before_releasing_active_inputs():
    node = blank()
    entered, release = threading.Event(), threading.Event()
    references = []

    def worker():
        entered.set()
        assert release.wait(10)
        assert node.data is not None

    async def load(history):
        references.append(graph(node))
        await run_owned_thread(worker)

    node._load_active_inputs = load
    task = asyncio.create_task(node._start("history"))
    assert await asyncio.to_thread(entered.wait, 5)
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done() and references[0]() is not None
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert node.data is None and references[0]() is None


@pytest.mark.parametrize("publication_failure", [False, True])
async def test_terminal_release_follows_durable_history_and_package(
    publication_failure, monkeypatch
):
    node = blank()
    reference = graph(node)
    _, history = await ready(node)
    monkeypatch.setattr(service, "replicate_verified_aggregate", lambda *args, **kwargs: None)
    package_references = []

    def advance(*args, **kwargs):
        package = Marker()
        package_references.append(weakref.ref(package))
        return SimpleNamespace(status="package_published", package=package)

    node.phases.owner.advance = advance
    node.votes = None
    node.source = lambda: SimpleNamespace(
        inputs=SimpleNamespace(history=history), intake=(), quality_votes=(), service_votes=()
    )
    calls = []

    async def publish(value):
        assert (node.data is not None) == (node.published_tip is None)
        assert all(reference() is None for reference in package_references)
        calls.append(value)
        if publication_failure:
            raise OSError("history acknowledgement lost")

    node._publish_history = publish
    node._remember_reward_package = lambda package: asyncio.sleep(0)
    node._check_reward_package = lambda: asyncio.sleep(0)
    if publication_failure:
        with pytest.raises(OSError, match="acknowledgement lost"):
            await node.tick()
        assert reference() is node.data and node.published_tip is None
        publication_failure = False
    assert await node.tick() == "package_published"
    assert reference() is None and node.phases is None
    assert node.published_tip == "tip"
    count = len(calls)
    assert await node.tick() == "package_published"
    assert len(calls) == count + 1


async def test_pending_tick_reuses_native_graph_but_revocation_releases():
    node = blank()
    reference = graph(node)
    state, _ = await ready(node, phase="review", role="reviewer")
    node.votes = None
    reviewed = []

    async def review(*, terminal):
        assert node.data is reference()
        reviewed.append(terminal)

    node._review_requests = review
    assert await node.tick() == "reviewing"
    assert await node.tick() == "reviewing"
    assert reviewed == [False, False] and reference() is not None
    state.phase = "revoked"
    assert await node.tick() == "revoked"
    assert reference() is None


async def test_terminal_reviewer_releases_inventory_and_keeps_authenticated_delivery_ports():
    node = blank()
    reference = graph(node)
    state, _ = await ready(node, role="reviewer")
    node.votes = None
    reviewed = []

    async def review(*, terminal):
        reviewed.append((terminal, node.data is None))
        assert node.phases is not None and node.exchange is not None

    node._review_requests = review
    assert await node.tick() == "reviewing"
    assert reference() is None and node.reviewed_terminal_tip == state.tip_sha256
    assert await node.tick() == "reviewing"
    assert reviewed == [(True, False), (True, True)]
    assert node.package_reference == ("retained-original", "retained-digest")
    # An authenticated extension retaining the certification prefix needs only
    # compact maintenance, even while a later cohort owns native capacity.
    starts = []

    async def load(history):
        starts.append(history)
        graph(node)
        node.votes = None

    node._load_active_inputs = load
    state.tip_sha256 = "later-tip"
    assert await node.tick() == "reviewing"
    assert starts == [] and node.reviewed_terminal_tip == "later-tip"
    assert node.data is None


async def test_run_shutdown_releases_pending_inventory():
    node = blank()
    reference = graph(node)
    stop = asyncio.Event()
    stop.set()
    await node.run(stop)
    assert reference() is None


@pytest.mark.parametrize("retained_vote", [False, True])
async def test_compact_reviewer_only_retransmits_retained_votes(retained_vote):
    node = blank()
    await ready(node, role="reviewer")
    graph(node)
    request = {"request": "original"}
    calls = []
    transitions = tuple(
        SimpleNamespace(transition=SimpleNamespace(phase=phase, operation="close_phase"))
        for phase in service.PHASES
    )
    node.store.published_history = lambda _: SimpleNamespace(transitions=transitions)

    def original(phase, kind):
        if (phase, kind) != ("evidence", "progress"):
            raise FileNotFoundError
        return request

    def vote(body):
        calls.append("retained_vote")
        if not retained_vote:
            raise FileNotFoundError
        return "original-vote"

    async def review(body):
        assert body == request
        calls.append("retry_delivery")

    node.phases.signer = SimpleNamespace(retained_vote=vote)
    node.exchange.request = original
    node.exchange._check = lambda value: calls.append("check")
    node.exchange._body = lambda value: value
    node.exchange.review = review
    node.completed_requests.clear()
    node._release_active_inputs(retain_exchange=True)
    await node._review_requests(terminal=True)
    assert node.data is None
    assert calls == ["check", "retained_vote"] + (["retry_delivery"] if retained_vote else [])
    request["request"] = "changed"
    with pytest.raises(ValueError, match="completed settlement request changed"):
        await node._review_requests(terminal=True)


async def test_compact_reviewer_refuses_open_phase_before_native_work():
    node = blank()
    await ready(node, role="reviewer")
    graph(node)
    node.completed_requests.clear()
    node.exchange.request = lambda *args: {"request": "open"}
    node._release_active_inputs(retain_exchange=True)
    with pytest.raises(ValueError, match="received an open phase"):
        await node._review_requests(terminal=True)


@pytest.mark.parametrize("damage", [None, "missing", "changed"])
def test_retained_result_delivery_recovers_only_exact_journal_original(tmp_path, damage):
    from umi.competition_cohort_settlement_delivery import RetainedResultVoteDelivery
    from umi.open_competition import digest
    from umi.protocol import StrictProtocolModel, canonical_json_bytes

    class Vote(StrictProtocolModel):
        body: str

    original = Vote(body="journal-verified-original")
    selected = original
    destination = tmp_path / "delivery" / "vote.json"
    retained = RetainedResultVoteDelivery(lambda: selected, digest(original), destination)
    retained.publish()
    raw = destination.read_bytes()
    assert raw == canonical_json_bytes(original)
    destination.unlink()
    retained.publish()
    assert destination.read_bytes() == raw
    if damage is not None:
        selected = None if damage == "missing" else Vote(body="different")
        with pytest.raises((FileNotFoundError, ValueError), match="signed original"):
            retained.publish()
        assert destination.read_bytes() == raw


async def test_terminal_reviewer_retries_result_deliveries_before_phase_replies():
    node = blank()
    await ready(node, role="reviewer")
    graph(node)
    calls = []
    node.votes.retained_deliveries = (SimpleNamespace(publish=lambda: calls.append("result")),)
    node._release_active_inputs(retain_exchange=True)
    node.reviewed_terminal_tip = "tip"
    node.terminal_certification_sha256 = "original-certified-prefix"

    async def review(*, terminal):
        assert terminal
        calls.append("phase")

    node._review_requests = review
    assert await node.tick() == "reviewing"
    assert calls == ["result", "phase"] and node.data is None
