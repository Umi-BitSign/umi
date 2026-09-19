from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from threading import Barrier

import pytest

from umi import competition_evaluator_capacity as capacity
from umi.competition_evaluator import EvaluatorJournal, order_job, validate_order
from umi.competition_execution import execution_key
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import agree, completed, execute
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_evaluator import model_setup as model_setup
from .test_competition_evaluator import policy as policy
from .test_competition_evaluator import runtime as runtime
from .test_competition_evaluator import setup as setup


def spec(setup, *, artifacts=None):
    return capacity.OrderReservation(
        execution_key(setup.job),
        capacity.order_binding(setup.order.order),
        len(canonical_json_bytes(setup.order)),
        tuple(
            capacity.ArtifactReservation(kind, len(canonical_json_bytes(value)))
            for kind, value in (
                artifacts or {"announcement_intent": {"message": "reserved"}}
            ).items()
        ),
    )


def used(journal):
    with journal.transaction() as db:
        return capacity.usage(db)[0] + sum(
            db.execute(f"SELECT COALESCE(SUM(length(body)),0) FROM {table}").fetchone()[0]
            for table in ("orders", "artifacts")
        )


def limit(journal, *, size=None, count=None):
    journal.config = journal.config.model_copy(
        update={
            **({} if size is None else {"maximum_journal_bytes": size}),
            **({} if count is None else {"maximum_orders": count}),
        }
    )


def test_complete_inventory_pending_until_native_writes_and_exact_retry(setup):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    batch = digest({"batch": 1})
    receipt = journal.reserve_orders(batch, [reservation])
    original_usage = used(journal)
    assert journal.orders() == []
    assert setup.drivers[0].executions.status(reservation.slot) is None
    assert journal.reservation(batch) == receipt
    assert journal.reserve_orders(batch, iter([reservation])) == receipt
    assert used(journal) == original_usage

    limit(journal, size=original_usage, count=1)
    with pytest.raises(ValueError, match="capacity"):
        journal.put("ff" * 32, "unrelated", {"x": 1})
    journal.admit(setup.order, reservation.slot)
    journal.put(reservation.slot, "announcement_intent", {"message": "reserved"})
    assert used(journal) == original_usage
    assert journal.reservation(batch) == receipt
    assert journal.reserve_orders(batch, [reservation]) == receipt
    journal.admit(setup.order, reservation.slot)
    journal.put(reservation.slot, "announcement_intent", {"message": "reserved"})
    assert used(journal) == original_usage


def test_order_count_reserves_slots_without_creating_discoverable_work(setup):
    journal = setup.drivers[0].journal
    limit(journal, count=1)
    reservation = spec(setup)
    journal.reserve_orders("aa" * 32, [reservation])
    with pytest.raises(ValueError, match="order capacity"):
        journal.admit(setup.order, "ff" * 32)
    assert journal.orders() == []
    journal.admit(setup.order, reservation.slot)
    assert len(journal.orders()) == 1


def test_one_byte_short_rolls_back_batch_and_private_migration(setup):
    first, second = (driver.journal for driver in setup.drivers)
    reservation = spec(setup)
    first.reserve_orders("aa" * 32, [reservation])
    # Both configured paths have the same length, so metadata has equal size.
    limit(second, size=used(first) - 1)
    with pytest.raises(ValueError, match="capacity"):
        second.reserve_orders("aa" * 32, [reservation])
    with second.transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
        assert (
            db.execute("SELECT name FROM sqlite_master WHERE name LIKE 'capacity_%'").fetchall()
            == []
        )
    assert second.orders() == []


def test_overlapping_batches_share_credit_but_charge_each_receipt(setup):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    first = journal.reserve_orders("aa" * 32, [reservation])
    before = used(journal)
    second = journal.reserve_orders("bb" * 32, [reservation])
    assert used(journal) - before == len(canonical_json_bytes(second))
    assert journal.reservation("aa" * 32) == first
    assert journal.reservation("bb" * 32) == second


def test_existing_rows_consume_no_pending_credit_and_preserve_first_bytes(setup):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    journal.admit(setup.order, reservation.slot)
    journal.put(reservation.slot, "announcement_intent", {"message": "reserved"})
    before = used(journal)
    receipt = journal.reserve_orders("aa" * 32, [reservation])
    assert used(journal) - before == len(canonical_json_bytes(receipt))
    # Existing admission keeps its first envelope for the identical order body.
    journal.admit(
        setup.order.model_copy(update={"signatures": setup.order.signatures[:1]}), reservation.slot
    )
    assert journal.orders()[0][1] == setup.order
    assert journal.reservation("aa" * 32) == receipt


@pytest.mark.parametrize("change", ["binding", "size", "artifact_size", "batch_spec"])
def test_changed_reservation_rolls_back_without_spending_credit(setup, change):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    receipt = journal.reserve_orders("aa" * 32, [reservation])
    before = used(journal)
    changed = {
        "binding": replace(reservation, order_sha256="cc" * 32),
        "size": replace(reservation, maximum_bytes=reservation.maximum_bytes + 1),
        "artifact_size": replace(
            reservation, artifacts=(capacity.ArtifactReservation("announcement_intent", 200),)
        ),
        "batch_spec": replace(reservation, artifacts=()),
    }[change]
    with pytest.raises(ValueError, match="changed"):
        journal.reserve_orders("aa" * 32 if change == "batch_spec" else "bb" * 32, [changed])
    assert used(journal) == before
    assert journal.reservation("aa" * 32) == receipt


def test_wrong_order_retains_hold_even_before_admission(setup):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    journal.reserve_orders("aa" * 32, [reservation])
    limit(journal, size=used(journal))
    # This is a second quorum-signed order for the same execution slot.
    cases = setup.order.order.cases
    body = setup.order.order.model_copy(
        update={
            "cases": (
                cases[0].model_copy(update={"video_sha256": "ef" * 32}),
                *cases[1:],
            )
        }
    )
    wrong = setup.order.model_copy(
        update={
            "order": body,
            "signatures": tuple(sign_object(body, signer) for signer in setup.wallets),
        }
    )
    validate_order(wrong, setup.policy)
    with pytest.raises(ValueError, match="conflicting signed"):
        journal.admit(wrong, reservation.slot)
    assert journal.orders() == []
    restarted = EvaluatorJournal(journal.config)
    with pytest.raises(ValueError, match="conflicting signed"):
        restarted.admit(setup.order, reservation.slot)
    with pytest.raises(ValueError, match="missing or changed"):
        restarted.reservation("aa" * 32)


def test_oversized_artifact_does_not_consume_credit(setup):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    receipt = journal.reserve_orders("aa" * 32, [reservation])
    journal.admit(setup.order, reservation.slot)
    with pytest.raises(ValueError, match="reserved allowance"):
        journal.put(reservation.slot, "announcement_intent", {"message": "too long for reserved"})
    assert journal.reservation("aa" * 32) == receipt
    journal.put(reservation.slot, "announcement_intent", {"message": "reserved"})


def test_scored_void_conflict_hold_survives_full_capacity(setup):
    journal = setup.drivers[0].journal
    reservation = spec(setup, artifacts={"result_intent": {"x": 1}, "void_intent": {"x": 2}})
    journal.reserve_orders("aa" * 32, [reservation])
    limit(journal, size=used(journal))
    journal.admit(setup.order, reservation.slot)
    journal.put(reservation.slot, "result_intent", {"x": 1})
    with pytest.raises(ValueError, match="conflict held"):
        journal.put(reservation.slot, "void_intent", {"x": 2})
    assert journal.orders()[0][2] is True
    with journal.transaction() as db:
        assert db.execute(
            "SELECT consumed FROM capacity_artifacts WHERE kind='void_intent'"
        ).fetchone() == (0,)


@pytest.mark.parametrize(
    "statement",
    [
        "UPDATE binding SET body=body",
        "INSERT INTO orders VALUES ('legacy', '{}', 0)",
        "INSERT INTO artifacts VALUES ('legacy', 'test', '{}')",
        "DELETE FROM capacity_batches",
    ],
)
def test_preopened_old_writers_cannot_ignore_obligations(setup, statement):
    journal = setup.drivers[0].journal
    with sqlite3.connect(journal.path) as old:
        old.execute("SELECT 1 FROM binding").fetchall()
        receipt = journal.reserve_orders("aa" * 32, [spec(setup)])
        with pytest.raises(sqlite3.OperationalError, match="no such function"):
            old.execute(statement)
    assert journal.reservation("aa" * 32) == receipt


def test_reservation_survives_reopen_and_rejects_smaller_caps(setup):
    journal = setup.drivers[0].journal
    receipt = journal.reserve_orders("aa" * 32, [spec(setup)])
    assert EvaluatorJournal(journal.config).reservation("aa" * 32) == receipt
    with pytest.raises(ValueError, match="capacity"):
        EvaluatorJournal(
            journal.config.model_copy(update={"maximum_journal_bytes": used(journal) - 1})
        )


def test_missing_credit_or_fence_is_not_repaired_silently(setup):
    journal = setup.drivers[0].journal
    journal.reserve_orders("aa" * 32, [spec(setup)])
    with journal.transaction() as db:
        db.execute("DELETE FROM capacity_artifacts")
    with pytest.raises(ValueError, match="consumption mismatch"):
        journal.reservation("aa" * 32)
    with journal.transaction() as db:
        db.execute("DROP TRIGGER capacity_orders_insert")
    with pytest.raises(ValueError, match="fences changed"):
        EvaluatorJournal(journal.config)


@pytest.mark.parametrize(
    "case", ["empty", "duplicate", "overlarge", "negative", "bool", "conflict"]
)
def test_invalid_inventory_never_enables_migration(setup, case):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    specs = {
        "empty": [],
        "duplicate": [reservation, reservation],
        "overlarge": [replace(reservation, maximum_bytes=capacity.MAX_PRIVATE_BYTES + 1)],
        "negative": [replace(reservation, maximum_bytes=-1)],
        "bool": [replace(reservation, maximum_bytes=True)],
        "conflict": [
            replace(reservation, artifacts=(capacity.ArtifactReservation("conflict:x", 100),))
        ],
    }[case]
    with pytest.raises(ValueError):
        journal.reserve_orders("aa" * 32, specs)
    with journal.transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0


@pytest.mark.parametrize(
    "field,value", [("schema", "wrong"), ("generation", 0), ("orders", []), ("unexpected", 1)]
)
def test_receipt_rejects_wrong_schema_or_structure(setup, field, value):
    journal = setup.drivers[0].journal
    receipt = journal.reserve_orders("aa" * 32, [spec(setup)])
    with journal.transaction() as db:
        db.execute(
            "UPDATE capacity_batches SET body=?", (canonical_json_bytes({**receipt, field: value}),)
        )
    with pytest.raises(ValueError):
        journal.reservation("aa" * 32)


def test_receipt_size_bound_applies_to_staging_and_read(setup, monkeypatch):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    # Use an artifact-heavy inventory so its receipt, not the order body, exceeds the limit.
    reservation = replace(
        reservation,
        maximum_bytes=1,
        artifacts=tuple(capacity.ArtifactReservation("artifact_" + str(i), 1) for i in range(100)),
    )
    monkeypatch.setattr(capacity, "MAX_PRIVATE_BYTES", 2048)
    with pytest.raises(ValueError, match="staging"):
        journal.reserve_orders("aa" * 32, [reservation])
    with journal.transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 0
    with pytest.raises(ValueError, match="byte bound"):
        capacity.parse_receipt(b" " * 2049)


def test_concurrent_openers_cannot_reserve_the_same_available_order_slot_twice(setup):
    journal = setup.drivers[0].journal
    limit(journal, count=1)
    others = [EvaluatorJournal(journal.config), EvaluatorJournal(journal.config)]
    barrier = Barrier(2)

    def reserve(index):
        reservation = replace(spec(setup), slot=("aa" if index == 0 else "bb") * 32)
        barrier.wait(timeout=5)
        try:
            others[index].reserve_orders(digest({"batch": index}), [reservation])
            return True
        except ValueError as exc:
            assert "capacity" in str(exc)
            return False

    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(reserve, range(2))) == [False, True]
    with journal.transaction() as db:
        assert capacity.usage(db)[1] == 1
        assert db.execute("SELECT count(*) FROM capacity_batches").fetchone()[0] == 1


@pytest.mark.parametrize("kind", [None, "announcement_intent"])
def test_failure_between_insert_and_consumption_rolls_back_both(setup, monkeypatch, kind):
    journal = setup.drivers[0].journal
    reservation = spec(setup)
    receipt = journal.reserve_orders("aa" * 32, [reservation])
    before = used(journal)

    def failed_consume(*args):
        raise RuntimeError("simulated crash before consumption")

    with monkeypatch.context() as context:
        context.setattr(capacity, "consume", failed_consume)
        with pytest.raises(RuntimeError, match="simulated crash"):
            if kind is None:
                journal.admit(setup.order, reservation.slot)
            else:
                journal.put(reservation.slot, kind, {"message": "reserved"})
    assert used(journal) == before
    assert journal.reservation("aa" * 32) == receipt


async def test_reserved_model_pipeline_preserves_complete_signed_evidence(setup):
    receipts = []
    for driver in setup.drivers:
        job = order_job(setup.order.order, driver.config.evaluator_hotkey, setup.policy)
        kinds = {
            "announcement_intent",
            "announcement",
            "result_intent",
            "run_intent",
            "vote",
            "independent",
            "independent_observation",
            "void_intent",
            "void_vote",
            "void",
            "void_observation",
        }
        kinds.update(
            prefix + identity(evaluator)
            for evaluator in setup.order.order.evaluators
            for prefix in ("peer_execution:", "peer_vote:", "peer_void_vote:")
        )
        # Small fixture only. Production sizing must derive its complete bounds.
        reservation = capacity.OrderReservation(
            execution_key(job),
            capacity.order_binding(setup.order.order),
            len(canonical_json_bytes(setup.order)),
            tuple(capacity.ArtifactReservation(kind, 1024**2) for kind in sorted(kinds)),
        )
        receipts.append(
            (
                driver.journal.reserve_orders("aa" * 32, [reservation]),
                driver.executions.reserve_jobs("aa" * 32, [job]),
            )
        )
    await execute(setup.drivers)
    await agree(setup)
    assert completed(setup.drivers[0]) == completed(setup.drivers[1])
    assert len(completed(setup.drivers[0])) == 1
    for driver, (artifacts, execution) in zip(setup.drivers, receipts, strict=True):
        assert driver.journal.reservation("aa" * 32) == artifacts
        assert driver.executions.reservation("aa" * 32) == execution
        await driver.aclose()
