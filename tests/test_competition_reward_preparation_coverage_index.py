"""Legacy metadata inventory never repeats package/proof verification."""

import sqlite3

import pytest

from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from umi.competition_reward_preparation_coverage_index import (
    PENDING,
    STATE,
    TABLE,
    PreparationCoverageIndex,
)
from umi.competition_reward_transition_anchor import RewardLiveAnchorMissing
from umi.open_competition import digest

from .test_competition_reward_transition_anchor import anchors as anchors


def test_unstarted_and_new_activation_have_no_prior_completion(anchors):
    c = anchors
    index = PreparationCoverageIndex(c.journal)
    assert index.advance(c.activation) == (True, None)
    endpoint = c.endpoint()
    assert index.advance(c.activation) == (True, endpoint.point.key())
    successor = c.activation.model_copy(update={"cohort_sha256": "88" * 32})
    assert index.advance(successor) == (True, None)


def test_missing_live_index_restores_completed_endpoint_hint_once(anchors, monkeypatch):
    c = anchors
    endpoint = c.endpoint()
    with pytest.raises(RewardLiveAnchorMissing):
        c.select()
    index = PreparationCoverageIndex(c.journal)
    assert index.advance(c.activation) == (True, endpoint.point.key())
    fresh = c.reopen()
    original = fresh.journal.get

    def completed_metadata_once(kind, *args, **kwargs):
        assert kind != "coverage_verified"
        return original(kind, *args, **kwargs)

    monkeypatch.setattr(fresh.journal, "get", completed_metadata_once)
    restarted = PreparationCoverageIndex(fresh)
    assert restarted.advance(c.activation) == (True, endpoint.point.key())


def test_inventory_resumes_bounded_pages_and_captures_appends(anchors, caplog):
    c = anchors
    c.endpoint(110)
    earlier = c.endpoint(100)
    index = PreparationCoverageIndex(c.journal)
    with caplog.at_level("INFO", logger="umi.competition.progress"):
        assert index.advance(c.activation, maximum_endpoints=1) == (False, None)
        restarted = PreparationCoverageIndex(c.reopen())
        assert restarted.advance(c.activation, maximum_endpoints=1) == (True, earlier.point.key())
    assert "standing_preparation_completion_inventory" in caplog.text
    assert "retained_completion_metadata_remaining" in caplog.text
    first = c.endpoint(90)
    assert restarted.advance(c.activation, maximum_endpoints=1) == (True, first.point.key())


@pytest.mark.parametrize(
    "damage", ["native_result", "native_marker", "native_index", "lookup", "cursor"]
)
def test_missing_completed_metadata_never_becomes_unstarted(anchors, damage):
    c = anchors
    endpoint = c.endpoint()
    index = PreparationCoverageIndex(c.journal)
    if damage in {"lookup", "cursor"}:
        assert index.advance(c.activation)[0]
    with c.journal.journal.transaction() as db:
        if damage == "native_result":
            db.execute("DELETE FROM records WHERE kind='coverage_verified'")
        elif damage == "native_marker":
            db.execute("DELETE FROM records WHERE kind='coverage_verified_done'")
        elif damage == "native_index":
            db.execute("DELETE FROM coverage_checkpoint_index WHERE id=?", (endpoint.point.key(),))
        elif damage == "lookup":
            db.execute(f"DELETE FROM {TABLE}")
        else:
            db.execute(f"UPDATE {STATE} SET position=position+1")
    with pytest.raises(CoverageCheckpointRepairRequired):
        index.advance(c.activation)


def test_native_repair_change_is_queued_before_absence_can_be_returned(anchors):
    c = anchors
    endpoint = c.endpoint()
    index = PreparationCoverageIndex(c.journal)
    assert index.advance(c.activation) == (True, endpoint.point.key())
    with c.journal.journal.transaction() as db:
        db.execute(
            "UPDATE coverage_checkpoint_index SET result=? WHERE id=?",
            ("99" * 32, endpoint.point.key()),
        )
        assert db.execute(f"SELECT id FROM {PENDING}").fetchall() == [(endpoint.point.key(),)]
    with pytest.raises(CoverageCheckpointRepairRequired):
        index.advance(c.activation)


@pytest.mark.parametrize(
    "change",
    [
        "activation='changed'",
        "id='changed'",
        "position=position+1",
        "block=block+1",
        "result='changed'",
    ],
)
def test_completed_lookup_identity_cannot_be_changed_into_first_preparation(anchors, change):
    c = anchors
    endpoint = c.endpoint()
    index = PreparationCoverageIndex(c.journal)
    assert index.advance(c.activation) == (True, endpoint.point.key())
    with pytest.raises(sqlite3.IntegrityError), c.journal.journal.transaction() as db:
        db.execute(f"UPDATE {TABLE} SET {change}")
    assert index.advance(c.activation) == (True, endpoint.point.key())


def test_same_endpoint_native_dependency_repair_updates_only_result(anchors):
    c = anchors
    endpoint = c.endpoint()
    key = endpoint.point.key()
    index = PreparationCoverageIndex(c.journal)
    assert index.advance(c.activation) == (True, key)
    value = c.journal.checkpoints.load(key) | {"repair": "explicit native metadata repair"}

    def repair(db):
        db.execute("UPDATE coverage_checkpoint_index SET result=? WHERE id=?", (digest(value), key))

    # Emulate only the native result replacement boundary. Its original point
    # and completion ledger identity remain the same throughout this repair.
    c.journal.journal.put_many((("coverage_verified", digest(value), value),), index=repair)
    assert index.advance(c.activation) == (True, key)
    with c.journal.journal.read_transaction() as db:
        assert db.execute(f"SELECT result FROM {TABLE} WHERE id=?", (key,)).fetchone() == (
            digest(value),
        )
