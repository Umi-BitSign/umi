"""Certified fixture roster to native outbox, private HTTP and native evaluator inboxes.

The retained preparation and finality sources are fixtures; every order review,
signature, selection and delivery receipt uses the native implementation.
"""

import json
import logging
import threading
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_order_host import CohortOrderHost, OrderHostConfig
from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_request_readiness_host import CombinedRequestReadiness
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.open_competition import digest, identity
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_order_http import base_policy as base_policy
from .test_competition_cohort_order_http import harness as harness
from .test_competition_cohort_order_http import legacy_scenario as legacy_scenario
from .test_competition_cohort_order_http import network as network
from .test_competition_cohort_order_http import policy as policy
from .test_competition_cohort_order_http import receipt_scenario as receipt_scenario
from .test_competition_cohort_order_http import recovery as recovery
from .test_competition_cohort_order_http import relay as relay
from .test_competition_cohort_order_http import runtime as runtime
from .test_competition_cohort_order_http import scenario as scenario


@pytest.fixture
async def owner(network, tmp_path):
    n, r = network, network.r
    cfg = OrderHostConfig(
        schema="umi-cohort-order-host/1",
        queue=r.cfg.model_copy(update={"directory": str(tmp_path / "automatic-orders")}),
    )
    root = tmp_path / "objects"
    files = SettlementEvidenceFiles(root)
    for value in (r.h.batch["suite"], r.h.order.runtime, r.h.order.incumbent):
        files.publish(digest(value), lambda _, value=value: canonical_json_bytes(value))
    peers = tuple(
        SimpleNamespace(
            signer=who, origin="https://" + identity(who) + ".example", timeout_seconds=30
        )
        for who in cfg.queue.reviewers
    )
    o = SimpleNamespace(
        network=n,
        files=files,
        prepared_reads=0,
        fail_after=None,
        shared_queue=tmp_path / "shared-control-group-orders",
    )

    def retained(cohort, *, expected_tip_sha256, current_block):
        o.prepared_reads += 1
        assert cohort == r.cohort
        return SimpleNamespace(roster=r.h.batch["roster"])

    service = SimpleNamespace(
        config=SimpleNamespace(
            orders=cfg,
            admission_owner=SimpleNamespace(reviewers=peers),
            lifecycle=SimpleNamespace(sources=SimpleNamespace(objects_directory=str(root))),
        ),
        intake=SimpleNamespace(
            policy=r.h.batch["policy"], config=SimpleNamespace(cohorts=r.cfg.cohorts)
        ),
        provider=r.h.worker().provider,
        history=r.h.worker().history,
        preparation=SimpleNamespace(retained=retained),
    )
    o.service = service

    class Route(httpx.AsyncBaseTransport):
        async def handle_async_request(self, request):
            who = request.url.host.removesuffix(".example")
            # Forward through the fixture's native authenticated ASGI route.
            return await n.clients[who]._transport.handle_async_request(request)

    async with httpx.AsyncClient(transport=Route()) as client:
        o.host = lambda: CohortOrderHost(service, client, ("private-order-token" * 3,) * len(peers))
        yield o


async def test_redundant_reviewers_in_one_control_group_form_one_group_quorum(owner):
    o = owner
    original = o.service.intake.policy
    shared = original.model_copy(
        update={
            "required_evaluator_groups": 1,
            "evaluators": tuple(
                item.model_copy(update={"control_group": "shared-operator"})
                for item in original.evaluators
            ),
        }
    )
    queue = o.service.config.orders.queue.model_copy(
        update={"directory": str(o.shared_queue), "policy_sha256": digest(shared)}
    )
    o.service.intake.policy = shared
    o.service.provider.policy = shared
    o.service.config.orders = o.service.config.orders.model_copy(update={"queue": queue})
    host = o.host()
    assert host.queue.policy.required_evaluator_groups == 1


async def test_redundant_reviewers_cannot_claim_two_group_quorum(owner):
    o = owner
    original = o.service.intake.policy
    shared = original.model_copy(
        update={
            "required_evaluator_groups": 2,
            "evaluators": tuple(
                item.model_copy(update={"control_group": "shared-operator"})
                for item in original.evaluators
            ),
        }
    )
    queue = o.service.config.orders.queue.model_copy(
        update={"directory": str(o.shared_queue), "policy_sha256": digest(shared)}
    )
    o.service.intake.policy = shared
    o.service.provider.policy = shared
    o.service.config.orders = o.service.config.orders.model_copy(update={"queue": queue})
    with pytest.raises(ValueError, match="cannot form the policy evaluator quorum"):
        o.host()


async def test_complete_roster_selected_and_delivered_without_manual_orders(owner):
    o, r = owner, owner.network.r
    host = o.host()
    count = len(r.h.batch["roster"].participants)
    assert await host.select(r.cohort) == count
    slots = host.queue.pending(r.cohort)
    assert len(slots) == count
    assert host.queue.intent(r.slot).order == r.h.order
    assert b'"references"' not in canonical_json_bytes(host.queue.intent(r.slot))
    report = await host.worker.poll_once()
    assert report["deliveries_acknowledged"] == count * len(r.h.order.evaluators)
    assert report["retry_count"] == 0
    for who in r.h.order.evaluators:
        box = r.inbox(who)
        for slot in slots:
            assert order_slot(box.assignment(slot).certificate.order) == slot
    r.h.fail_collect = True
    calls = len(r.h.calls), len(r.receipt_calls), o.prepared_reads
    resumed = o.host()
    assert await resumed.select(r.cohort) == count
    assert (await resumed.worker.poll_once())["retry_count"] == 0
    assert (len(r.h.calls), len(r.receipt_calls), o.prepared_reads) == calls


async def test_waiting_history_reuses_native_result_after_restart_off_event_loop(
    owner, monkeypatch
):
    from umi import competition_cohort_order_host as native

    o, r = owner, owner.network.r
    initial = r.h.source
    r.h.source = initial.model_copy(
        update={
            "history": initial.history.model_copy(update={"transitions": ()}),
            "decisions": (),
        }
    )
    calls = []
    verify = native.verify_cohort_history
    event_thread = threading.get_ident()

    def counted(*args, **kwargs):
        calls.append(threading.get_ident())
        return verify(*args, **kwargs)

    monkeypatch.setattr(native, "verify_cohort_history", counted)
    host = o.host()
    assert await host.select(r.cohort) == 0
    assert await host.select(r.cohort) == 0
    assert await o.host().select(r.cohort) == 0
    assert len(calls) == 1 and calls[0] != event_thread
    assert o.prepared_reads == 0
    # A receipt cannot stand in for fresh current history or owned finality.
    r.h.fail_collect = True
    with pytest.raises(OSError, match="provider unavailable"):
        await host.select(r.cohort)
    r.h.fail_collect = False
    r.h.block = initial.history.genesis.admitted_at_block - 1
    with pytest.raises(ValueError, match="owned finalized"):
        await host.select(r.cohort)
    assert len(calls) == 1
    r.h.block = 400
    r.h.source = initial
    assert await host.select(r.cohort) == len(r.h.batch["roster"].participants)
    assert len(calls) == 2  # The changed signed history receives its own first review.


@pytest.mark.parametrize("change", ["signature", "policy", "authority", "runtime"])
async def test_order_history_reuse_binds_changed_dependencies(owner, monkeypatch, change):
    from umi import competition_cohort_order_host as native

    o, r = owner, owner.network.r
    host = o.host()
    source = r.h.source
    calls = []
    verify = native.verify_cohort_history

    def counted(*args, **kwargs):
        calls.append(1)
        return verify(*args, **kwargs)

    monkeypatch.setattr(native, "verify_cohort_history", counted)
    host._history_review(r.cohort, source, r.h.block)
    if change == "signature":
        signatures = source.history.genesis_signatures
        changed = signatures[0].model_copy(update={"signature": "00" * 64})
        source = source.model_copy(
            update={
                "history": source.history.model_copy(
                    update={"genesis_signatures": (changed, *signatures[1:])}
                )
            }
        )
    elif change == "policy":
        host.queue.policy = host.queue.policy.model_copy(
            update={"valid_through_block": host.queue.policy.valid_through_block + 1}
        )
    elif change == "authority":
        host.queue.cohorts[r.cohort] = "ff" * 32
    else:
        host.history_verification.runtime = "changed-native-semantics"
    if change == "runtime":
        host._history_review(r.cohort, source, r.h.block)
        assert len(calls) == 2
    else:
        with pytest.raises(ValueError):
            host._history_review(r.cohort, source, r.h.block)
        assert len(calls) == (1 if change == "authority" else 2)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
async def test_order_history_receipt_damage_reports_scoped_repair(
    owner, monkeypatch, caplog, damage
):
    from umi import competition_cohort_order_host as native

    o, r = owner, owner.network.r
    host = o.host()
    original = host._history_review(r.cohort, r.h.source, r.h.block)
    (path,) = host.history_verification.directory.glob("*.json")
    if damage == "missing":
        path.unlink()
    else:
        path.write_bytes(b"{}")
    calls = []
    verify = native.verify_cohort_history

    def counted(*args, **kwargs):
        calls.append(1)
        return verify(*args, **kwargs)

    monkeypatch.setattr(native, "verify_cohort_history", counted)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        resumed = o.host()
        assert resumed._history_review(r.cohort, r.h.source, r.h.block) == original
    assert calls == [1]
    assert '"state":"repair_required"' in caplog.text
    assert '"stage":"order_selection_signed_history"' in caplog.text
    assert o.host()._history_review(r.cohort, r.h.source, r.h.block) == original
    assert calls == [1]


async def test_order_history_owner_scope_does_not_borrow_another_queues_result(owner, monkeypatch):
    from umi import competition_cohort_order_host as native

    o, r = owner, owner.network.r
    first = o.host()
    first._history_review(r.cohort, r.h.source, r.h.block)
    queue = o.service.config.orders.queue.model_copy(update={"directory": str(o.shared_queue)})
    o.service.config.orders = o.service.config.orders.model_copy(update={"queue": queue})
    calls = []
    verify = native.verify_cohort_history

    def counted(*args, **kwargs):
        calls.append(1)
        return verify(*args, **kwargs)

    monkeypatch.setattr(native, "verify_cohort_history", counted)
    second = o.host()
    second._history_review(r.cohort, r.h.source, r.h.block)
    assert calls == [1]
    assert second.history_verification.owner != first.history_verification.owner


async def test_retained_roster_returns_verified_orders_and_rejects_later_tampering(owner):
    o, r = owner, owner.network.r
    host = o.host()
    count = await host.select(r.cohort)
    selected = host.queue.journal.get("order_host_roster", r.cohort)
    expected = tuple(host.queue.intent(slot).order for slot in selected["slots"])
    assert host._retained_orders(r.cohort) == expected
    assert host._retained(r.cohort) == count == len(expected)
    slot = selected["slots"][0]
    original = host.queue.journal.get("intent", slot)
    damaged = json.loads(canonical_json_bytes(original))
    damaged["order"]["round"]["cohort_sha256"] = "ff" * 32
    with host.queue.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='intent' AND id=?",
            (canonical_json_bytes(damaged), slot),
        )
    with pytest.raises(ValueError):
        host._retained_orders(r.cohort)


async def test_readiness_ignores_delivery_noise_but_rejects_changed_selection(owner, monkeypatch):
    o, r = owner, owner.network.r
    host = o.host()
    await host.select(r.cohort)
    # The selection reader uses a real signed roster and native journal. Its
    # surrounding HTTP/finality ports are exercised by the readiness suite.
    reader = CombinedRequestReadiness.__new__(CombinedRequestReadiness)
    reader.orders, reader.selected, reader.selection_stamps = host, {}, {}
    source = SimpleNamespace(cohort=r.cohort, roster=SimpleNamespace(round=r.h.order.round))
    original = reader._orders(source)
    stamp = reader.selection_stamps[r.cohort]
    await host.worker.poll_once()
    # A newly observed history has no effect on the original intent's embedded
    # history. Replaying every order after each append can starve delivery.
    history = host.queue.intent(
        host.queue.journal.get("order_host_roster", r.cohort)["slots"][0]
    ).source
    host.queue.journal.put("order_history", "a1" * 32, history)
    assert reader._selection_stamp(r.cohort) == stamp
    with monkeypatch.context() as context:
        context.setattr(
            host, "_retained_orders", lambda _: pytest.fail("unchanged roster replayed")
        )
        context.setattr(host.queue.journal, "transaction", lambda: pytest.fail("read takes writer"))
        assert reader._orders(source) == original
    selected = host.queue.journal.get("order_host_roster", r.cohort)
    slot = selected["slots"][0]
    damaged = json.loads(canonical_json_bytes(host.queue.journal.get("intent", slot)))
    damaged["order"]["round"]["cohort_sha256"] = "ff" * 32
    with host.queue.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind='intent' AND id=?",
            (canonical_json_bytes(damaged), slot),
        )
    assert reader._selection_stamp(r.cohort) != stamp
    with pytest.raises(ValueError):
        reader._orders(source)


async def test_partial_selection_resumes_originals_after_long_outage(owner, monkeypatch):
    o, r = owner, owner.network.r
    host = o.host()
    select = host.queue.select
    saved = []

    def interrupted(*args):
        if saved:
            raise OSError("disk temporarily full")
        saved.append(select(*args))
        return saved[-1]

    monkeypatch.setattr(host.queue, "select", interrupted)
    with pytest.raises(OSError):
        await host.select(r.cohort)
    original = canonical_json_bytes(host.queue.intent(saved[0]))
    assert host.queue.journal.get("order_host_roster", r.cohort) is None
    r.h.block += 3000
    resumed = o.host()
    count = len(r.h.batch["roster"].participants)
    assert await resumed.select(r.cohort) == count
    assert canonical_json_bytes(resumed.queue.intent(saved[0])) == original
    assert len(resumed.queue.pending(r.cohort)) == count


def test_readiness_keeps_independent_cohort_selections():
    # Authentication of the selected objects uses the native owner tests above.
    # Alternating readiness probes must not replay both immutable rosters.
    reader = CombinedRequestReadiness.__new__(CombinedRequestReadiness)
    reader.selected, reader.selection_stamps = {}, {}
    rounds = {cohort: object() for cohort in ("a", "b")}
    calls = []

    def retained(cohort):
        calls.append(cohort)
        return (SimpleNamespace(round=rounds[cohort]),)

    reader.orders = SimpleNamespace(_retained_orders=retained)
    reader._selection_stamp = lambda cohort: cohort + "-unchanged"
    for cohort in ("a", "b", "a", "b"):
        source = SimpleNamespace(cohort=cohort, roster=SimpleNamespace(round=rounds[cohort]))
        assert reader._orders(source)[0].round is rounds[cohort]
    assert calls == ["a", "b"]


async def test_missing_original_runtime_does_not_select_replacement_or_smaller_roster(owner):
    o, r = owner, owner.network.r
    o.files._path(digest(r.h.order.runtime)).unlink()
    host = o.host()
    with pytest.raises(FileNotFoundError):
        await host.select(r.cohort)
    assert host.queue.pending(r.cohort) == ()
    assert host.queue.journal.get("order_host_roster", r.cohort) is None
    o.files.publish(digest(r.h.order.runtime), lambda _: canonical_json_bytes(r.h.order.runtime))
    assert await host.select(r.cohort) == len(r.h.batch["roster"].participants)


async def test_enabled_host_gets_normal_quorum_on_explicit_sampling_orders(owner):
    o, r = owner, owner.network.r
    o.service.config.orders = o.service.config.orders.model_copy(
        update={"share_paired_incumbent": True}
    )
    host = o.host()
    count = await host.select(r.cohort)
    report = await host.worker.poll_once()
    assert report["retry_count"] == 0
    assert report["deliveries_acknowledged"] == count * len(r.h.order.evaluators)
    for order in host._retained_orders(r.cohort):
        expected = order.submission.submission.track == "model"
        assert (order.incumbent_observation_mode is not None) is expected
        assert order.schema_.endswith("/2" if expected else "/1")
        for who in order.evaluators:
            assigned = r.inbox(who).assignment(order_slot(order))
            assert assigned.certificate.order == order


async def test_enabling_sampling_preserves_partially_selected_original_orders(owner, monkeypatch):
    o, r = owner, owner.network.r
    host = o.host()
    select, saved = host.queue.select, []

    def interrupted(*args):
        if saved:
            raise OSError("disk temporarily full")
        saved.append(select(*args))
        return saved[-1]

    monkeypatch.setattr(host.queue, "select", interrupted)
    with pytest.raises(OSError):
        await host.select(r.cohort)
    original = canonical_json_bytes(host.queue.intent(saved[0]))
    o.service.config.orders = o.service.config.orders.model_copy(
        update={"share_paired_incumbent": True}
    )
    resumed = o.host()
    assert await resumed.select(r.cohort) == len(r.h.batch["roster"].participants)
    assert canonical_json_bytes(resumed.queue.intent(saved[0])) == original
    assert resumed.queue.intent(saved[0]).order.incumbent_observation_mode is None
    for order in resumed._retained_orders(r.cohort):
        if order_slot(order) != saved[0] and order.submission.submission.track == "model":
            assert order.incumbent_observation_mode == "first_reserved_per_scope/1"
