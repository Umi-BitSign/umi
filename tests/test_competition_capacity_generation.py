from __future__ import annotations

import sqlite3

import pytest

from umi.competition_evaluator import EvaluatorJournal
from umi.competition_execution import ExecutionJournal
from umi.competition_round_journal import RecordReservation, RoundJournal
from umi.competition_scheduling import AssignmentPublicationJournal

from .test_competition_evaluator import chain_config as chain_config
from .test_competition_evaluator import model_setup as model_setup
from .test_competition_evaluator import policy as policy
from .test_competition_evaluator import runtime as runtime
from .test_competition_evaluator import setup as _evaluator_setup
from .test_competition_evaluator_capacity import spec
from .test_competition_scheduling import _publish
from .test_competition_scheduling_reservations import reserve
from .test_competition_scheduling_reservations import reserved_schedule as reserved_schedule
from .test_competition_scheduling_reservations import schedule as schedule
from .test_open_competition import wallet

_BATCH = "ab" * 32
evaluator_setup = _evaluator_setup


def snapshot(path):
    """Observe corruption without opening a journal that could migrate it."""
    with sqlite3.connect(path) as db:
        schema = db.execute(
            "SELECT type,name,tbl_name,sql FROM sqlite_master ORDER BY type,name"
        ).fetchall()
        tables = {}
        for kind, name, _, _ in schema:
            if kind == "table":
                quoted = '"' + name.replace('"', '""') + '"'
                tables[name] = sorted(db.execute(f"SELECT * FROM {quoted}").fetchall(), key=repr)
        return db.execute("PRAGMA user_version").fetchone()[0], schema, tables


def downgrade(path, generation):
    with sqlite3.connect(path) as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 2
        db.execute(f"PRAGMA user_version={generation}")


def assert_rejected_without_mutation(path, *actions):
    before = snapshot(path)
    for action in actions:
        with pytest.raises(ValueError, match="generation marker was downgraded"):
            action()
        assert snapshot(path) == before


def test_evaluator_downgrade_cannot_bypass_pending_artifact_allowances(evaluator_setup):
    journal = evaluator_setup.drivers[0].journal
    reservation = spec(evaluator_setup)
    journal.reserve_orders(_BATCH, (reservation,))
    downgrade(journal.path, 0)

    assert_rejected_without_mutation(
        journal.path,
        lambda: journal.put("ff" * 32, "unrelated", {"value": 1}),
        lambda: journal.admit(evaluator_setup.order, reservation.slot),
        lambda: journal.reservation(_BATCH),
        lambda: journal.reserve_orders(_BATCH, (reservation,)),
        lambda: EvaluatorJournal(journal.config),
    )


def test_round_downgrade_cannot_bypass_pending_record_allowances(tmp_path):
    binding = {"purpose": "generation-downgrade"}
    journal = RoundJournal(tmp_path / "round", binding)
    reservation = RecordReservation("vote", "reserved", 4096)
    journal.reserve_records(_BATCH, (reservation,))
    downgrade(journal.path, 0)

    assert_rejected_without_mutation(
        journal.path,
        lambda: journal.put("vote", "unrelated", {"value": 1}),
        lambda: journal.put("vote", "reserved", {"value": 1}),
        lambda: journal.reservation(_BATCH),
        lambda: journal.reserve_records(_BATCH, (reservation,)),
        lambda: RoundJournal(journal.root, binding),
    )


def test_execution_downgrade_cannot_bypass_pending_job_allowances(model_setup, tmp_path):
    policy, job, *_ = model_setup
    journal = ExecutionJournal(tmp_path / "execution", policy)
    journal.reserve_jobs(_BATCH, (job,))
    unrelated = job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address})
    downgrade(journal.path, 0)

    assert_rejected_without_mutation(
        journal.path,
        lambda: journal.reserve(unrelated),
        lambda: journal.reserve(job),
        lambda: journal.reservation(_BATCH),
        lambda: journal.reserve_jobs(_BATCH, (job,)),
        lambda: ExecutionJournal(journal.path.parent, policy),
    )


@pytest.mark.parametrize("generation", [0, 1])
def test_scheduling_downgrade_cannot_bypass_pending_publication_allowances(
    reserved_schedule, generation
):
    fixture = reserved_schedule
    reserve(fixture, batch_id=_BATCH)
    journal = fixture.journal
    evaluator = fixture.authorization.publication.publication.assignments[0].evaluator_hotkey
    downgrade(journal.path, generation)

    assert_rejected_without_mutation(
        journal.path,
        lambda: _publish(fixture),
        lambda: journal.reservation(_BATCH, evaluator_hotkey=evaluator),
        lambda: reserve(fixture, batch_id=_BATCH),
        lambda: AssignmentPublicationJournal(
            fixture.directory,
            fixture.authorization.policy,
            fixture.authorization.legacy_policy,
        ),
    )
