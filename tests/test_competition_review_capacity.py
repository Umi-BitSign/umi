from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from threading import Barrier

import pytest

from umi.competition_publication import PublicationReplayLimits, build_cutoff_publication
from umi.competition_review_history import EvaluatorReviewStore, ReviewReservation
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import AdmissionCapacity, AdmissionCapacityError
from umi.competition_void import VoidEvaluationEvidence
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_publication import _independent
from .test_competition_review_history import attest, observe
from .test_competition_review_history import setup as reviewed_fixture
from .test_competition_void import attempts as attempts
from .test_competition_void import certify
from .test_open_competition import policy as policy
from .test_open_competition import result_for, snapshot
from .test_open_competition import scenario as scenario

reviewed = reviewed_fixture


def spec(s, signed=None, **changes):
    value = ReviewReservation(
        digest(s.round),
        digest((signed or s.model).submission),
        1_000_000,
        1_000_000,
        1_000_000,
    )
    return replace(value, **changes)


def evidence(s):
    return _independent(s.policy, s.model, s.round, s.suite, s.evaluation)


def record(s, value=None, *, block=150):
    return s.reviews.record_independent_evaluation(
        signed=s.model,
        evidence=value or evidence(s),
        round_=s.round,
        suite=s.suite,
        observed_block=block,
    )


def state(store):
    with sqlite3.connect(store.path) as db:
        tables = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND name NOT LIKE 'sqlite_%' ORDER BY name"
        ).fetchall()
        return {
            "version": db.execute("PRAGMA user_version").fetchone()[0],
            "tables": {name: db.execute(f"SELECT * FROM {name}").fetchall() for (name,) in tables},
            "triggers": db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' ORDER BY name"
            ).fetchall(),
        }


def used(store):
    with store._connection() as db:
        return store._usage(db)


def limit(store, *, records=None, size=None):
    store.admission_capacity = AdmissionCapacity(
        maximum_records=records
        if records is not None
        else store.admission_capacity.maximum_records,
        maximum_bytes=size if size is not None else store.admission_capacity.maximum_bytes,
    )


def test_ordinary_review_remains_legacy_until_explicit_reservation(reviewed):
    s = reviewed
    observe(s)
    record(s)
    assert state(s.reviews)["version"] == 0
    assert s.reviews.reservation("aa" * 32) is None


def test_reservation_requires_previously_reviewed_cutoff_and_roster(reviewed):
    s = reviewed
    before = state(s.reviews)
    with pytest.raises(ValueError):
        s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    assert state(s.reviews) == before
    observe(s)
    before = state(s.reviews)
    with pytest.raises(ValueError, match="absent from the cutoff"):
        s.reviews.reserve_evidence("aa" * 32, [spec(s, submission_sha256="ff" * 32)])
    assert state(s.reviews) == before


def test_full_reservation_is_private_recoverable_and_idempotent(reviewed):
    s = reviewed
    observe(s)
    specs = [spec(s), spec(s, s.endpoint)]
    receipt = s.reviews.reserve_evidence("aa" * 32, iter(specs))
    before = state(s.reviews)
    assert s.reviews.reserve_evidence("aa" * 32, reversed(specs)) == receipt
    assert s.reviews.reservation("aa" * 32) == receipt
    assert state(s.reviews) == before
    assert not before["tables"]["evaluation_results"]
    assert not before["tables"]["independent_evaluation_evidence"]
    assert receipt["generation"] == 2
    assert receipt["journal_path"] == str(s.reviews.path.resolve())
    assert receipt["policy_sha256"] == digest(s.policy)
    assert len(receipt["journal_identity"]) == 64
    restored = EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    assert restored.reservation("aa" * 32) == receipt


@pytest.mark.parametrize("bound", ["bytes", "records"])
def test_one_unit_short_rejects_entire_native_batch(reviewed, monkeypatch, bound):
    s = reviewed
    observe(s)
    before = state(s.reviews)
    capacity = s.reviews._check_capacity

    def undersize(db):
        count, size = s.reviews._usage(db)
        limit(s.reviews, **({"size": size - 1} if bound == "bytes" else {"records": count - 1}))
        return capacity(db)

    monkeypatch.setattr(s.reviews, "_check_capacity", undersize)
    with pytest.raises(AdmissionCapacityError, match="capacity exhausted"):
        s.reviews.reserve_evidence("aa" * 32, [spec(s), spec(s, s.endpoint)])
    assert state(s.reviews) == before


def test_inherited_writer_cannot_spend_another_slots_allowance(reviewed):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s, s.endpoint)])
    limit(s.reviews, size=used(s.reviews)[1])
    before = state(s.reviews)
    with pytest.raises(AdmissionCapacityError, match="capacity exhausted"):
        record(s)
    assert state(s.reviews) == before


def test_native_certificate_and_independent_writes_consume_credit_atomically(reviewed):
    s = reviewed
    observe(s)
    value = evidence(s)
    certificate_size = len(canonical_json_bytes(value.attested_result.result)) + sum(
        len(canonical_json_bytes(sig)) for sig in value.attested_result.signatures
    )
    reservation = spec(
        s,
        maximum_certificate_bytes=certificate_size,
        maximum_independent_bytes=len(canonical_json_bytes(value)),
    )
    receipt = s.reviews.reserve_evidence("aa" * 32, [reservation])
    count, size = used(s.reviews)
    limit(s.reviews, records=count, size=size)
    first = record(s, value)
    assert used(s.reviews)[1] <= size
    with s.reviews._connection() as db:
        assert db.execute(
            "SELECT kind FROM review_capacity_consumptions ORDER BY kind"
        ).fetchall() == [("certificate",), ("independent",)]
        assert db.execute("SELECT COUNT(*) FROM void_evaluation_evidence").fetchone() == (0,)
    assert record(s, value, block=151) == first
    assert s.reviews.reservation("aa" * 32) == receipt
    restored = EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    assert restored.reservation("aa" * 32) == receipt


def test_existing_evidence_is_bound_without_charging_a_second_copy(reviewed):
    s = reviewed
    observe(s)
    value = evidence(s)
    record(s, value)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    before = state(s.reviews)
    with s.reviews._connection() as db:
        assert db.execute("SELECT COUNT(*) FROM review_capacity_consumptions").fetchone() == (2,)
    record(s, value)
    assert state(s.reviews) == before


def test_matching_batches_share_credit_but_retain_each_manifest(reviewed):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    count, size = used(s.reviews)
    s.reviews.reserve_evidence("bb" * 32, [spec(s)])
    other_count, other_size = used(s.reviews)
    assert other_count == count + 1
    assert 0 < other_size - size < 4096


def test_increasing_capacity_preserves_receipt_but_insufficient_capacity_fails(reviewed):
    s = reviewed
    observe(s)
    receipt = s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    limit(
        s.reviews,
        records=s.reviews.admission_capacity.maximum_records + 1,
        size=s.reviews.admission_capacity.maximum_bytes + 1,
    )
    assert s.reviews.reservation("aa" * 32) == receipt
    limit(s.reviews, size=used(s.reviews)[1] - 1)
    with pytest.raises(AdmissionCapacityError):
        s.reviews.reservation("aa" * 32)


def test_changed_native_batch_or_spec_has_no_side_effects(reviewed):
    s = reviewed
    observe(s)
    reservation = spec(s)
    s.reviews.reserve_evidence("aa" * 32, [reservation])
    before = state(s.reviews)
    for batch in ("aa" * 32, "bb" * 32):
        with pytest.raises(ValueError, match="changed"):
            s.reviews.reserve_evidence(batch, [replace(reservation, maximum_void_bytes=999999)])
        assert state(s.reviews) == before


def test_retention_crash_rolls_back_consumption_and_body(reviewed, monkeypatch):
    s = reviewed
    observe(s)
    value = evidence(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    s.reviews.record_evaluation(
        signed=s.model,
        attested=value.attested_result,
        round_=s.round,
        suite=s.suite,
        observed_block=150,
    )
    before = state(s.reviews)
    original = s.reviews._consume_outcomes

    def fail(db):
        original(db)
        raise RuntimeError("simulated interruption")

    monkeypatch.setattr(s.reviews, "_consume_outcomes", fail)
    with pytest.raises(RuntimeError, match="interruption"):
        s.reviews._store_independent_evaluation(
            signed=s.model, evidence=value, round_=s.round, suite=s.suite, observed_block=150
        )
    assert state(s.reviews) == before


def corrupt(store, table, sql, arguments=()):
    with sqlite3.connect(store.path) as db:
        db.create_function("umi_writer_generation", 0, lambda: 2)
        db.create_function("umi_review_writer_generation", 0, lambda: 2)
        triggers = db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND tbl_name=?", (table,)
        ).fetchall()
        for name, _sql in triggers:
            db.execute(f"DROP TRIGGER {name}")
        db.execute(sql, arguments)
        for _name, definition in triggers:
            db.execute(definition)


@pytest.mark.parametrize("damage", ["spec", "consumption", "body"])
def test_retry_never_repairs_missing_or_changed_evidence(reviewed, damage):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    if damage == "spec":
        corrupt(s.reviews, "review_capacity_specs", "DELETE FROM review_capacity_specs")
    else:
        record(s)
        if damage == "consumption":
            corrupt(
                s.reviews,
                "review_capacity_consumptions",
                "DELETE FROM review_capacity_consumptions",
            )
        else:
            corrupt(
                s.reviews,
                "independent_evaluation_evidence",
                "UPDATE independent_evaluation_evidence SET body=X'7b7d'",
            )
    before = state(s.reviews)
    with pytest.raises(ValueError, match=r"missing|changed"):
        s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    assert state(s.reviews) == before


@pytest.mark.parametrize(
    "sql",
    [
        "INSERT INTO round_conflicts VALUES ('old',150)",
        "UPDATE metadata SET value='151' WHERE key='observed_block'",
        "DELETE FROM reviewed_cutoffs",
        "INSERT INTO evaluation_results VALUES ('old','old','old',X'7b7d',150)",
    ],
)
def test_preopened_older_review_writer_is_fenced(reviewed, sql):
    s = reviewed
    observe(s)
    old = sqlite3.connect(s.reviews.path, isolation_level=None)
    old.create_function("umi_writer_generation", 0, lambda: 2)
    try:
        old.execute("SELECT 1 FROM reviewed_cutoffs").fetchone()
        s.reviews.reserve_evidence("aa" * 32, [spec(s)])
        before = state(s.reviews)
        with pytest.raises(sqlite3.OperationalError, match="umi_review_writer_generation"):
            old.execute(sql)
        assert state(s.reviews) == before
    finally:
        old.close()


def test_missing_writer_fence_is_not_recreated(reviewed):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    with sqlite3.connect(s.reviews.path) as db:
        db.execute("DROP TRIGGER review_capacity_metadata_update")
    before = state(s.reviews)
    with pytest.raises(ValueError, match="fence changed"):
        s.reviews.reservation("aa" * 32)
    assert state(s.reviews) == before


def test_reset_generation_marker_blocks_reopen_and_ordinary_writes(reviewed):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    with sqlite3.connect(s.reviews.path) as db:
        db.execute("PRAGMA user_version=0")
    before = state(s.reviews)
    with pytest.raises(ValueError, match="generation marker missing"):
        record(s)
    assert state(s.reviews) == before
    with pytest.raises(ValueError, match="generation marker missing"):
        EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    assert state(s.reviews) == before


def test_identity_extra_fields_cannot_override_receipt(reviewed):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    with sqlite3.connect(s.reviews.path) as db:
        doc = json.loads(db.execute("SELECT body FROM review_capacity_identity").fetchone()[0])
    doc["batch_id"] = "ff" * 32
    corrupt(
        s.reviews,
        "review_capacity_identity",
        "UPDATE review_capacity_identity SET body=?",
        (canonical_json_bytes(doc),),
    )
    before = state(s.reviews)
    with pytest.raises(ValueError, match="binding changed"):
        s.reviews.reservation("aa" * 32)
    assert state(s.reviews) == before


def test_concurrent_openers_share_exact_credit_once(reviewed):
    s = reviewed
    observe(s)
    s.reviews.reserve_evidence("aa" * 32, [spec(s)])
    # A new envelope may use only the small unreserved headroom, not the
    # independently reserved scored/void allowance of the first roster entry.
    maximum = used(s.reviews)[1] + 3_100_000
    stores = [
        EvaluatorReviewStore(
            s.reviews.directory,
            s.policy,
            limits=s.limits,
            admission_capacity=AdmissionCapacity(maximum_bytes=maximum),
        )
        for _ in range(2)
    ]
    barrier = Barrier(2)

    def reserve(index):
        barrier.wait()
        try:
            return stores[index].reserve_evidence(f"{index + 1:064x}", [spec(s, s.endpoint)])
        except AdmissionCapacityError:
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(reserve, range(2)))
    assert all(value is not None for value in results)
    assert used(stores[0])[1] <= maximum
    with stores[0]._connection() as db:
        assert db.execute("SELECT COUNT(*) FROM review_capacity_specs").fetchone() == (2,)


@pytest.fixture
async def void_review(attempts, setup, tmp_path):
    context, observations, signers = attempts
    order = context["signed_order"].order
    value = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/1",
        order=context["signed_order"],
        certificate=certify(context, observations, signers),
        legacy_policy=None,
    )
    limits = PublicationReplayLimits(
        maximum_certificate_bytes=4_000_000,
        maximum_roster_bytes=1_000_000,
        maximum_evidence_bytes=5_000_000,
    )
    store = EvaluatorReviewStore(tmp_path / "void-review", context["policy"], limits=limits)
    store.initialize_baseline(order.incumbent, setup[3])
    cutoff = build_cutoff_publication(
        policy=context["policy"],
        round_=order.round,
        submissions=(order.submission,),
        registration_snapshot=snapshot(120),
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(context["policy"]),
            round_sha256=digest(order.round),
            evidence_cutoff_block=160,
        ),
        limits=limits,
    )
    store.observe_cutoff(
        attest(cutoff), (order.submission,), snapshot=snapshot(120), observed_block=121
    )
    reservation = ReviewReservation(
        digest(order.round),
        digest(order.submission.submission),
        1_000_000,
        1_000_000,
        len(canonical_json_bytes(value)),
    )
    return store, value, context, reservation


async def test_void_body_uses_reserved_credit_and_keeps_first_receipt(void_review):
    store, value, context, reservation = void_review
    receipt = store.reserve_evidence("aa" * 32, [reservation])
    count, size = used(store)
    limit(store, records=count, size=size)
    first = store.record_void_evaluation(evidence=value, suite=context["suite"], observed_block=150)
    assert (
        store.record_void_evaluation(evidence=value, suite=context["suite"], observed_block=151)
        == first
    )
    assert store.reservation("aa" * 32) == receipt
    assert used(store)[1] <= size


async def test_capacity_failure_preserves_new_authenticated_conflict_hold(void_review):
    store, value, context, reservation = void_review
    store.reserve_evidence("aa" * 32, [reservation])
    order = value.order.order
    store.record_evaluation(
        signed=order.submission,
        attested=result_for(order.submission, order.round, context["suite"]),
        round_=order.round,
        suite=context["suite"],
        observed_block=150,
    )
    _count, size = used(store)
    limit(store, size=size - 1)
    with pytest.raises(AdmissionCapacityError):
        store.record_void_evaluation(evidence=value, suite=context["suite"], observed_block=150)
    with store._connection() as db:
        assert db.execute("SELECT round FROM round_conflicts").fetchall() == [
            (reservation.round_sha256,)
        ]
        assert db.execute("SELECT COUNT(*) FROM void_evaluation_evidence").fetchone() == (0,)
        assert db.execute(
            "SELECT kind FROM review_capacity_consumptions ORDER BY kind"
        ).fetchall() == [("certificate",)]


async def test_conflict_recovery_keeps_writer_lock_until_hold_commits(void_review, monkeypatch):
    store, value, context, reservation = void_review
    store.reserve_evidence("aa" * 32, [reservation])
    order = value.order.order
    store.record_evaluation(
        signed=order.submission,
        attested=result_for(order.submission, order.round, context["suite"]),
        round_=order.round,
        suite=context["suite"],
        observed_block=150,
    )
    limit(store, size=used(store)[1] - 1)
    probes = []

    def try_competing_writer():
        other = sqlite3.connect(store.path, timeout=0, isolation_level=None)
        try:
            other.create_function("umi_writer_generation", 0, lambda: 2)
            other.create_function("umi_review_writer_generation", 0, lambda: 2)
            try:
                other.execute("BEGIN IMMEDIATE")
            except sqlite3.OperationalError as error:
                assert "locked" in str(error)
                probes.append("blocked")
            else:
                probes.append("acquired")
                other.execute("UPDATE metadata SET value='151' WHERE key='observed_block'")
                other.commit()
        finally:
            other.close()

    class ProbedConnection:
        def __init__(self, connection):
            self.connection = connection

        def __getattr__(self, name):
            return getattr(self.connection, name)

        def execute(self, sql, *arguments):
            result = self.connection.execute(sql, *arguments)
            if sql.lstrip().upper().startswith("ROLLBACK TO"):
                try_competing_writer()
            return result

        def rollback(self):
            self.connection.rollback()
            try_competing_writer()

    original = store._connection

    @contextmanager
    def probed_connection():
        with original() as connection:
            yield ProbedConnection(connection)

    monkeypatch.setattr(store, "_connection", probed_connection)
    with pytest.raises(AdmissionCapacityError):
        store.record_void_evaluation(evidence=value, suite=context["suite"], observed_block=150)
    assert probes == ["blocked"]
    with original() as db:
        assert db.execute("SELECT round,detected_block FROM round_conflicts").fetchall() == [
            (reservation.round_sha256, 150)
        ]
        assert db.execute("SELECT value FROM metadata WHERE key='observed_block'").fetchone() == (
            "150",
        )
        assert db.execute("SELECT COUNT(*) FROM void_evaluation_evidence").fetchone() == (0,)
        assert db.execute(
            "SELECT kind FROM review_capacity_consumptions ORDER BY kind"
        ).fetchall() == [("certificate",)]
