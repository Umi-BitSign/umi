"""Operational capacity changes keep exchange identities and event history."""

import sqlite3
from pathlib import Path

import pytest

from umi.competition_evaluator import EvaluatorJournal, validate_order
from umi.competition_exchange import ExchangeJournal
from umi.competition_scheduling import SchedulingCapacity
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import signed_order
from .test_competition_exchange import chain_config as chain_config
from .test_competition_exchange import finish
from .test_competition_exchange import model_setup as model_setup
from .test_competition_exchange import policy as policy
from .test_competition_exchange import relay as relay
from .test_competition_exchange import runtime as runtime


def snapshot(path):
    with sqlite3.connect(path) as db:
        return tuple(db.iterdump())


def enlarged(config):
    return config.model_copy(update={"maximum_orders": 4096, "maximum_bytes": 8 * 1024**3})


@pytest.mark.asyncio
async def test_capacity_reopen_preserves_complete_exchange_history_and_evaluator_binding(relay):
    await finish(relay)
    try:
        journal = ExchangeJournal(relay.config, relay.policy)
        before = snapshot(journal.path)
        expanded = enlarged(relay.config)
        for _ in range(2):
            reopened = ExchangeJournal(expanded, relay.policy)
            assert snapshot(reopened.path) == before
            assert reopened.object(digest(relay.order.order), "order") == relay.order
            # Retry retains the original event id, author, body and observation.
            with sqlite3.connect(reopened.path) as db:
                event, block = db.execute(
                    "SELECT id,block FROM events WHERE kind='order'"
                ).fetchone()
            assert (
                reopened.append(digest(relay.order.order), "order", None, relay.order, block + 100)
                == event
            )
            assert snapshot(reopened.path) == before
        changed = expanded.model_copy(
            update={
                "reveal_directory": str(
                    Path(relay.config.reveal_directory).parent / "other-reveals"
                )
            }
        )
        with pytest.raises(ValueError, match="configuration changed"):
            ExchangeJournal(changed, relay.policy)
        assert snapshot(journal.path) == before
        for driver in relay.drivers:
            prior = snapshot(driver.journal.path)
            config = driver.config.model_copy(
                update={
                    "scheduling_capacity": SchedulingCapacity(
                        maximum_publications=4096, maximum_bytes=48 * 1024**3
                    )
                }
            )
            EvaluatorJournal(config)
            assert snapshot(driver.journal.path) == prior
    finally:
        for driver in relay.drivers:
            await driver.aclose()


@pytest.mark.parametrize("exhausted", ["orders", "events", "bytes"])
def test_raised_capacity_recovers_append_without_rewriting_retained_event(relay, exhausted):
    config = relay.config.model_copy(update={"maximum_orders": 1})
    journal = ExchangeJournal(config, relay.policy)
    journal.ingest(125)
    suite = relay.suite.model_copy(
        update={
            "cases": tuple(
                c.model_copy(update={"case_id": f"{i + 100:064x}"})
                for i, c in enumerate(relay.suite.cases)
            )
        }
    )
    round_ = relay.job.round.model_copy(update={"sequence": 2, "suite_sha256": digest(suite)})
    order = signed_order(relay.job.model_copy(update={"round": round_}), relay.wallets)
    validate_order(order, relay.policy)
    if exhausted != "orders":
        config = config.model_copy(update={"maximum_orders": 4096})
    if exhausted == "events":
        config = config.model_copy(update={"maximum_events": 1})
    elif exhausted == "bytes":
        config = config.model_copy(update={"maximum_bytes": len(canonical_json_bytes(relay.order))})
    journal = ExchangeJournal(config, relay.policy)
    before = snapshot(journal.path)
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.append(digest(order.order), "order", None, order, 125)
    assert snapshot(journal.path) == before
    expanded = enlarged(config).model_copy(update={"maximum_events": 65536})
    reopened = ExchangeJournal(expanded, relay.policy)
    assert snapshot(reopened.path) == before
    event = reopened.append(digest(order.order), "order", None, order, 125)
    assert event == 2
    after = snapshot(reopened.path)
    restarted = ExchangeJournal(expanded, relay.policy)
    assert snapshot(restarted.path) == after
    assert restarted.object(digest(relay.order.order), "order") == relay.order
    assert restarted.object(digest(order.order), "order") == order
