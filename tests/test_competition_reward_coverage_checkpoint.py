"""Private completion accounting; fixtures do not establish native proof authority."""

import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_reward_coverage_checkpoint as module
from umi.competition_reward_coverage_checkpoint import (
    CoverageCheckpointRepairRequired,
    CoverageCheckpoints,
)
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest

from .test_competition_reward_coverage_intervals import point, rule


@pytest.fixture
def checkpoint(tmp_path, monkeypatch):
    monkeypatch.setattr(module, "runtime_identity", lambda: "aa" * 32)
    monkeypatch.setattr(module, "coverage_point", lambda endpoint, _rule: endpoint.point)
    selected = rule()
    journal = RoundJournal(tmp_path / "coverage", selected, maximum_rounds=64)
    owner = CoverageCheckpoints(journal, selected)
    endpoint = SimpleNamespace(
        point=point(),
        prepared=SimpleNamespace(
            activation=SimpleNamespace(package_sha256="11" * 32, cohort_sha256="22" * 32),
            requirement_sha256="33" * 32,
        ),
        eligibility=SimpleNamespace(policy_sha256="44" * 32),
    )
    keys = [("coverage_endpoint", endpoint.point.key()), ("coverage_object", "55" * 32)]
    journal.put_many((kind, key, {"original": True}) for kind, key in keys)
    return SimpleNamespace(
        owner=owner,
        journal=journal,
        rule=selected,
        endpoint=endpoint,
        keys=keys,
        key=endpoint.point.key(),
    )


def legacy(checkpoint):
    """Remove this new schema from an isolated fixture to reproduce old storage."""
    with checkpoint.journal.transaction() as db:
        for name in checkpoint.owner.ledger_triggers:
            db.execute("DROP TRIGGER " + name)
        db.execute("DELETE FROM records WHERE kind='coverage_checkpoint_owner'")
        db.execute("DROP TABLE coverage_completion_ledger")


def remember(checkpoint, **kwargs):
    checkpoint.owner.remember(checkpoint.endpoint, checkpoint.keys, **kwargs)
    return checkpoint.owner.load(checkpoint.key)


def test_completion_survives_restart_without_reading_source_payloads(checkpoint, monkeypatch):
    saved = remember(checkpoint)
    original = checkpoint.journal._record

    def metadata_only(db, kind, key):
        assert kind not in module.KINDS
        return original(db, kind, key)

    monkeypatch.setattr(checkpoint.journal, "_record", metadata_only)
    fresh = CoverageCheckpoints(checkpoint.journal, checkpoint.rule)
    assert fresh.load(checkpoint.key) == saved
    assert fresh.load("99" * 32) is None


@pytest.mark.parametrize("missing", ["marker", "index", "both", "result"])
def test_missing_completed_work_requires_repair(checkpoint, missing):
    value = remember(checkpoint)
    with checkpoint.journal.transaction() as db:
        if missing in {"marker", "both"}:
            db.execute("DELETE FROM records WHERE kind='coverage_verified_done'")
        if missing in {"index", "both"}:
            db.execute("DELETE FROM coverage_checkpoint_index")
        if missing == "result":
            db.execute(
                "DELETE FROM records WHERE kind='coverage_verified' AND id=?", (digest(value),)
            )
    fresh = CoverageCheckpoints(checkpoint.journal, checkpoint.rule)
    with pytest.raises(CoverageCheckpointRepairRequired, match="explicit scoped repair"):
        fresh.load(checkpoint.key)


@pytest.mark.parametrize(
    "statement",
    [
        "DELETE FROM coverage_completion_ledger",
        "UPDATE coverage_completion_ledger SET owner='damaged'",
        "DELETE FROM records WHERE kind='coverage_checkpoint_owner'",
        "UPDATE records SET body='null' WHERE kind='coverage_checkpoint_owner'",
    ],
)
def test_completion_ledger_and_owner_cannot_be_mutated(checkpoint, statement):
    saved = remember(checkpoint)
    with pytest.raises(sqlite3.IntegrityError), checkpoint.journal.transaction() as db:
        db.execute(statement)
    assert checkpoint.owner.load(checkpoint.key) == saved


@pytest.mark.parametrize("damage", ["table", "fence", "entry"])
def test_ledger_damage_cannot_be_adopted_as_legacy_state(checkpoint, damage):
    remember(checkpoint)
    with checkpoint.journal.transaction() as db:
        if damage == "table":
            db.execute("DROP TABLE coverage_completion_ledger")
        elif damage == "fence":
            db.execute("DROP TRIGGER coverage_completion_delete")
        else:
            # Model storage damage bypassing the SQL fence, then restore its
            # exact schema so the endpoint's missing permanent entry is tested.
            db.execute("DROP TRIGGER coverage_completion_delete")
            db.execute("DELETE FROM coverage_completion_ledger")
            db.execute(checkpoint.owner.ledger_triggers["coverage_completion_delete"])
    with pytest.raises(CoverageCheckpointRepairRequired):
        fresh = CoverageCheckpoints(checkpoint.journal, checkpoint.rule)
        fresh.load(checkpoint.key)


def test_source_repair_preserves_prior_results_and_permanent_completion(checkpoint):
    original = remember(checkpoint)
    with checkpoint.journal.transaction() as db:
        db.execute("UPDATE records SET body=body WHERE kind='coverage_object'")
    with pytest.raises(CoverageCheckpointRepairRequired):
        checkpoint.owner.load(checkpoint.key)
    repaired = remember(checkpoint, repair_reason="exact original source restored")
    assert repaired["sources"] != original["sources"]
    assert checkpoint.journal.get("coverage_verified", digest(original)) == original
    assert checkpoint.journal.get("coverage_verified", digest(repaired)) == repaired
    with checkpoint.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM coverage_completion_ledger").fetchone() == (1,)


def test_missing_marker_and_index_can_be_explicitly_repaired(checkpoint):
    original = remember(checkpoint)
    with checkpoint.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='coverage_verified_done'")
        db.execute("DELETE FROM coverage_checkpoint_index")
    repaired = remember(checkpoint, repair_reason="native original explicitly requalified")
    assert repaired["repair"]
    assert checkpoint.journal.get("coverage_verified", digest(original)) == original


def test_interrupted_completion_is_atomic_with_ledger(checkpoint, monkeypatch):
    original = checkpoint.journal.put_many

    def interrupted(records, *, index):
        def fail(db):
            index(db)
            raise OSError("interrupted after completion index")

        original(records, index=fail)

    with monkeypatch.context() as patch:
        patch.setattr(checkpoint.journal, "put_many", interrupted)
        with pytest.raises(OSError, match="interrupted"):
            remember(checkpoint)
    assert checkpoint.owner.load(checkpoint.key) is None
    with checkpoint.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM coverage_completion_ledger").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM coverage_checkpoint_index").fetchone() == (0,)
    assert remember(checkpoint) is not None


def test_legacy_completed_results_migrate_once_without_changing_originals(checkpoint):
    original = remember(checkpoint)
    with checkpoint.journal.transaction() as db:
        db.execute("UPDATE records SET body=body WHERE kind='coverage_object'")
    repaired = remember(checkpoint, repair_reason="original source restored")
    legacy(checkpoint)
    for _ in range(2):
        fresh = CoverageCheckpoints(checkpoint.journal, checkpoint.rule)
        assert fresh.load(checkpoint.key) == repaired
    assert checkpoint.journal.get("coverage_verified", digest(original)) == original
    assert checkpoint.journal.get("coverage_verified", digest(repaired)) == repaired


def test_legacy_orphan_success_requires_repair_instead_of_native_first_pass(checkpoint):
    remember(checkpoint)
    legacy(checkpoint)
    with checkpoint.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='coverage_verified_done'")
        db.execute("DELETE FROM coverage_checkpoint_index")
    with pytest.raises(CoverageCheckpointRepairRequired, match="lost its marker and index"):
        CoverageCheckpoints(checkpoint.journal, checkpoint.rule)
    with checkpoint.journal.read_transaction() as db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='coverage_completion_ledger'"
        ).fetchone()
    assert checkpoint.journal.get("coverage_checkpoint_owner", "owner") is None


def test_unknown_endpoint_does_not_borrow_unrelated_completion(checkpoint):
    remember(checkpoint)
    assert checkpoint.owner.load("98" * 32) is None


def test_owner_change_cannot_reuse_completed_coverage(checkpoint, monkeypatch):
    remember(checkpoint)
    original_identity = checkpoint.owner.identity
    monkeypatch.setattr(
        CoverageCheckpoints, "_identity", lambda self: [*original_identity, [1, 2, 3]]
    )
    with pytest.raises(CoverageCheckpointRepairRequired, match="owner"):
        CoverageCheckpoints(checkpoint.journal, checkpoint.rule)


def test_native_model_dependency_migration_preserves_old_success(checkpoint):
    original = remember(checkpoint)
    assert "model_dependencies" not in original
    checkpoint.endpoint.model_dependencies = {
        "schema": "umi-coverage-model-dependencies/1",
        "mode": "not_selected",
        "context": None,
        "items": [],
    }
    migrated = remember(checkpoint)
    assert migrated["model_dependencies"] == checkpoint.endpoint.model_dependencies
    assert migrated["repair"] == "native model dependency migration"
    assert checkpoint.journal.get("coverage_verified", digest(original)) == original
    assert remember(checkpoint) == migrated
