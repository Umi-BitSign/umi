"""Warmed receipt validation must still detect changed state and policy context."""

import json

import pytest

from umi.protocol import canonical_json_bytes

from .test_competition_scheduling import _publish
from .test_competition_scheduling_reservations import policy as policy
from .test_competition_scheduling_reservations import reserve
from .test_competition_scheduling_reservations import reserved_schedule as reserved_schedule
from .test_competition_scheduling_reservations import schedule as schedule


def receipt(fixture):
    return fixture.journal.reservation(
        "a" * 64,
        evaluator_hotkey=fixture.authorization.publication.publication.assignments[
            0
        ].evaluator_hotkey,
    )


@pytest.mark.parametrize("changed", ["policy", "legacy", "outcome_allowance"])
def test_warm_receipt_rechecks_its_policy_and_capacity_context(reserved_schedule, changed):
    fixture = reserved_schedule
    reserve(fixture)
    assert receipt(fixture) is not None
    if changed == "policy":
        fixture.journal.policy = fixture.journal.policy.model_copy(
            update={"sequence": fixture.journal.policy.sequence + 1}
        )
    elif changed == "legacy":
        fixture.journal.legacy_policy = fixture.journal.legacy_policy.model_copy(
            update={"activation_block": fixture.journal.legacy_policy.activation_block + 1}
        )
    else:
        fixture.journal.maximum_outcome_bytes += 1
    with pytest.raises(ValueError):
        receipt(fixture)


@pytest.mark.parametrize(
    "table,column,change",
    [
        ("reservation_publications", "body", "noncanonical"),
        ("reservation_publications", "allowance", "increase"),
        ("publications", "signed", "different_body"),
        ("publications", "signed", "malformed_signature"),
        ("assignments", "body", "noncanonical"),
    ],
)
def test_warm_receipt_still_checks_every_retained_row(reserved_schedule, table, column, change):
    fixture = reserved_schedule
    reserve(fixture)
    _publish(fixture)
    assert receipt(fixture) is not None
    with fixture.journal._transaction() as db:
        # Recreate the unchanged trigger after simulating on-disk corruption so
        # the test reaches row validation rather than failing the fence check.
        trigger = f"immutable_{table}_update"
        sql = db.execute("SELECT sql FROM sqlite_master WHERE name=?", (trigger,)).fetchone()[0]
        db.execute(f"DROP TRIGGER {trigger}")
        rowid, raw = db.execute(f"SELECT rowid,{column} FROM {table} LIMIT 1").fetchone()
        if change == "increase":
            altered = raw + 1
        elif change == "noncanonical":
            altered = bytes(raw) + b" "
        else:
            value = json.loads(raw)
            if change == "different_body":
                value["publication"]["round"]["sequence"] += 1
            else:
                value["signatures"][0]["signature"] = "0x01"
            altered = canonical_json_bytes(value)
        db.execute(f"UPDATE {table} SET {column}=? WHERE rowid=?", (altered, rowid))
        db.execute(sql)
    with pytest.raises(ValueError):
        receipt(fixture)


def test_warm_receipt_does_not_cache_timing_admission(reserved_schedule, monkeypatch):
    fixture = reserved_schedule
    reserve(fixture)
    assert receipt(fixture) is not None

    def expired(*args, requalify):
        assert requalify is True
        raise ValueError("dispatch timing no longer admits work")

    monkeypatch.setattr(fixture.journal, "_recover_capacity", expired)
    with pytest.raises(ValueError, match="timing no longer"):
        receipt(fixture)
