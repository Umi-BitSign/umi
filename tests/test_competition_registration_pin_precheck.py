"""Cold projection metadata refuses pruning before completed result-body reads."""

import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from umi.competition_registration_pins import (
    TABLES,
    RegistrationPinProjectionPending,
    RegistrationPinRepairRequired,
    RegistrationPins,
)
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_service_queue import (
    admit,
)
from .test_competition_cohort_service_queue import (
    base_policy as base_policy,
)
from .test_competition_cohort_service_queue import (
    harness as harness,
)
from .test_competition_cohort_service_queue import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_service_queue import (
    policy as policy,
)
from .test_competition_cohort_service_queue import (
    queue_case as queue_case,
)
from .test_competition_cohort_service_queue import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_service_queue import (
    recovery as recovery,
)
from .test_competition_cohort_service_queue import (
    runtime as runtime,
)
from .test_competition_cohort_service_queue import (
    scenario as scenario,
)


@pytest.fixture
def metadata():
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE records(kind TEXT,id TEXT,body BLOB,PRIMARY KEY(kind,id))")
    db.execute("CREATE TABLE holds(id TEXT PRIMARY KEY)")
    for sql in TABLES.values():
        db.execute(sql)
    pins = RegistrationPins.__new__(RegistrationPins)
    pins.owner = "fixture-owner"
    pins.marker = {"schema": "fixture", "owner": pins.owner}
    slots = [(str(n), digest(["admission", n])) for n in range(1, 4)]
    keys = []
    for slot, source in slots[:2]:
        key, result = digest([pins.owner, slot]), digest(["result", slot])
        db.execute("INSERT INTO registration_pin_index VALUES (?,?)", (key, result))
        db.execute(
            "INSERT INTO records VALUES ('registration_pin_completed',?,?)",
            (key, canonical_json_bytes(pins.marker)),
        )
        db.execute("INSERT INTO records VALUES ('registration_pin_result',?,?)", (result, b"{}"))
        db.execute("INSERT INTO records VALUES ('service_admission',?,?)", (source, b"{}"))
        db.execute(
            "INSERT INTO registration_pin_sources VALUES ('service_admission',?,0,1)", (source,)
        )
        keys.append((key, result, source))
    yield SimpleNamespace(db=db, pins=pins, slots=slots, keys=keys)
    db.close()


@pytest.mark.parametrize("operation", ["snapshot", "writer"])
def test_native_pin_contention_keeps_cause_and_retries(tmp_path, operation):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    pins = RegistrationPins(journal, {})
    with pins.snapshot() as db:
        value = pins.make(db, [], {}, {})

    def use():
        if operation == "snapshot":
            with pins.snapshot() as db:
                db.execute("SELECT * FROM records").fetchall()
        else:
            pins.remember("fixture", value, lambda _: None)

    holder = sqlite3.connect(journal.path, isolation_level=None)
    try:
        holder.execute("BEGIN EXCLUSIVE")
        with pytest.raises(PrivateStateBusyError) as busy:
            use()
        assert isinstance(busy.value.__cause__, sqlite3.OperationalError)
        assert busy.value.operation == "registration_pin_" + operation
        assert busy.value.resource_sha256 == digest(str(journal.path))
        assert busy.value.errno == getattr(busy.value.__cause__, "sqlite_errorcode", None)
        assert str(journal.path) not in str(busy.value)
    finally:
        holder.rollback()
        holder.close()
    use()


@pytest.mark.parametrize("operation", ["snapshot", "writer"])
def test_native_pin_storage_error_is_not_contention(tmp_path, operation):
    journal = RoundJournal(tmp_path / "journal", {}, maximum_rounds=32)
    pins = RegistrationPins(journal, {})
    with pins.snapshot() as db:
        value = pins.make(db, [], {}, {})
    original = []

    def fail(db):
        try:
            db.execute("SELECT * FROM missing_private_table")
        except sqlite3.OperationalError as error:
            original.append(error)
            raise

    expected = (
        sqlite3.OperationalError if operation == "snapshot" else RegistrationPinRepairRequired
    )
    with pytest.raises(expected) as failure:
        if operation == "snapshot":
            with pins.snapshot() as db:
                fail(db)
        else:
            pins.remember("fixture", value, fail)
    if operation == "snapshot":
        assert failure.value is original[0]
    else:
        assert failure.value.__cause__ is original[0]
        assert "missing_private_table" not in str(failure.value)
        assert str(journal.path) not in str(failure.value)
        pins.remember("fixture", value, lambda _: None)


def test_metadata_presence_is_only_negative_readiness_not_a_verified_pin_set(metadata):
    m = metadata
    assert m.pins.require_complete_metadata(m.db, m.slots[:2]) is None
    with pytest.raises(RegistrationPinProjectionPending) as pending:
        m.pins.require_complete_metadata(m.db, m.slots)
    assert (pending.value.completed, pending.value.total) == (2, 3)
    assert pending.value.reason == "projection_metadata_incomplete"


def test_never_completed_source_hold_keeps_existing_pending_boundary(metadata):
    m = metadata
    m.db.execute("INSERT INTO holds VALUES (?)", (m.slots[2][1],))
    # Existing load() returns None before checking an unprojected original.
    # The metadata check preserves that boundary, refuses pruning, and leaves
    # the original's conflict investigation to the independent projection owner.
    with pytest.raises(RegistrationPinProjectionPending) as pending:
        m.pins.require_complete_metadata(m.db, m.slots)
    assert (pending.value.completed, pending.value.total) == (2, 3)


@pytest.mark.parametrize(
    "damage",
    [
        "index",
        "marker",
        "marker_bytes",
        "result",
        "empty_result",
        "completion_hold",
        "result_hold",
        "source_hold",
        "source_row",
        "source_revision",
    ],
)
def test_damaged_completed_metadata_is_repair_even_beside_never_projected_slot(metadata, damage):
    m = metadata
    key, result, source = m.keys[1]
    if damage == "index":
        m.db.execute("DELETE FROM registration_pin_index WHERE id=?", (key,))
    elif damage in {"marker", "result"}:
        kind, identity = (
            ("registration_pin_completed", key)
            if damage == "marker"
            else ("registration_pin_result", result)
        )
        m.db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, identity))
    elif damage == "marker_bytes":
        # Semantically equal but noncanonical completed metadata still fails.
        m.db.execute(
            "UPDATE records SET body=? WHERE kind='registration_pin_completed' AND id=?",
            (canonical_json_bytes(m.pins.marker) + b" ", key),
        )
    elif damage == "empty_result":
        m.db.execute(
            "UPDATE records SET body=? WHERE kind='registration_pin_result' AND id=?", (b"", result)
        )
    elif damage.endswith("hold"):
        identity = {"completion_hold": key, "result_hold": result, "source_hold": source}[damage]
        m.db.execute("INSERT INTO holds VALUES (?)", (identity,))
    elif damage == "source_row":
        m.db.execute("DELETE FROM registration_pin_sources WHERE id=?", (source,))
    else:
        m.db.execute("UPDATE registration_pin_sources SET revision=-1 WHERE id=?", (source,))
    with pytest.raises(RegistrationPinRepairRequired):
        m.pins.require_complete_metadata(m.db, [m.slots[2], *m.slots[:2]])


def test_metadata_batches_stay_bounded_for_older_sqlite_variable_limit(metadata):
    m = metadata
    slots = m.slots + [(str(n), digest(["admission", n])) for n in range(4, 601)]
    queries = []
    m.db.set_trace_callback(queries.append)
    with pytest.raises(RegistrationPinProjectionPending) as pending:
        m.pins.require_complete_metadata(m.db, slots)
    assert (pending.value.completed, pending.value.total) == (2, 600)
    queries = [q for q in queries if q.startswith("WITH expected")]
    assert len(queries) == 3
    assert all("SELECT body" not in q for q in queries)


def test_incomplete_queue_skips_completed_admission_loads_and_writes(queue_case, monkeypatch):
    c = queue_case
    admit(c)
    admit(c, "Bob", 2)
    assert c.queue.retained_registration_blocks() == frozenset({400})
    admit(c, "Alice", 3)
    pins = c.queue._registration_pins
    load = pins.load
    calls = []

    def catalog_only(db, slot, context):
        calls.append(slot)
        assert slot == "catalog", "cold callback decoded a completed admission projection"
        return load(db, slot, context)

    monkeypatch.setattr(pins, "load", catalog_only)
    forbidden = Mock(side_effect=AssertionError("cold callback performed projection or wrote"))
    monkeypatch.setattr(c.queue, "_raw_admission", forbidden)
    monkeypatch.setattr(c.queue, "_retained_pin_blocks", forbidden)
    monkeypatch.setattr(pins, "remember", forbidden)
    monkeypatch.setattr(pins, "_capacity", forbidden)
    monkeypatch.setattr(c.queue.journal, "transaction", forbidden)
    with pytest.raises(RegistrationPinProjectionPending) as pending:
        c.queue.retained_registration_blocks(complete_only=True)
    assert (pending.value.completed, pending.value.total) == (2, 3)
    assert calls == ["catalog"]
    forbidden.assert_not_called()


def test_partial_metadata_never_prunes_and_background_still_reports_body_corruption(queue_case):
    c = queue_case
    admit(c)
    assert c.queue.retained_registration_blocks() == frozenset({400})
    admit(c, "Bob", 2)
    with c.queue.journal.transaction() as db:
        slot = digest([c.queue._registration_pins.owner, "1"])
        result = db.execute(
            "SELECT result FROM registration_pin_index WHERE id=?", (slot,)
        ).fetchone()[0]
        db.execute(
            "UPDATE records SET body=? WHERE kind='registration_pin_result' AND id=?",
            (b"not-json", result),
        )
    with pytest.raises(RegistrationPinProjectionPending):
        c.queue.retained_registration_blocks(complete_only=True)
    # Fast refusal confers no validity on that body. Its independent owner
    # retains the full canonical/identity check and specific repair reporting.
    with pytest.raises(RegistrationPinRepairRequired):
        c.queue.retained_registration_blocks()
