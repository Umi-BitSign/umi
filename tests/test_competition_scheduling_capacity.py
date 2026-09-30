from __future__ import annotations

import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_commands import evidence, services
from umi.competition_commands.arguments import build_parser
from umi.competition_scheduling import AssignmentPublicationJournal, SchedulingCapacity
from umi.protocol import canonical_json_bytes

from .test_competition_scheduling import _publish
from .test_competition_scheduling import schedule as schedule
from .test_open_competition import policy as policy


def test_scheduling_capacity_preserves_journal_defaults(schedule):
    expected = {
        "maximum_publications": 1024,
        "maximum_assignments": 16384,
        "maximum_bytes": 1024**3,
        "maximum_outcome_bytes": 1024**2,
    }
    assert SchedulingCapacity().model_dump() == expected
    assert {name: getattr(schedule.journal, name) for name in expected} == expected


@pytest.mark.parametrize(
    ("field", "lower", "upper"),
    [
        ("maximum_publications", 1, 65536),
        ("maximum_assignments", 1, 262144),
        ("maximum_bytes", 1024, 64 * 1024**3),
        ("maximum_outcome_bytes", 1, 16 * 1024**2),
    ],
)
def test_capacity_model_and_journal_accept_the_same_integer_bounds(schedule, field, lower, upper):
    for value in (lower, upper):
        assert getattr(SchedulingCapacity(**{field: value}), field) == value
    for value in (lower - 1, upper + 1, True, float(lower), str(lower)):
        with pytest.raises(ValueError):
            SchedulingCapacity(**{field: value})
        with pytest.raises(ValueError, match="invalid scheduling capacity"):
            AssignmentPublicationJournal(
                schedule.directory,
                schedule.authorization.policy,
                schedule.authorization.legacy_policy,
                **{field: value},
            )


def test_unknown_capacity_field_is_rejected():
    with pytest.raises(ValueError):
        SchedulingCapacity.model_validate({"maximum_byte": 2 * 1024**3})


def test_expanded_capacity_reopens_historical_journal_without_rebinding(schedule):
    _publish(schedule)
    with sqlite3.connect(schedule.journal.path) as db:
        metadata = db.execute("SELECT key,value FROM metadata ORDER BY key").fetchall()
        signed = db.execute("SELECT id,signed FROM publications ORDER BY id").fetchall()
    capacity = SchedulingCapacity(
        maximum_publications=2048, maximum_assignments=32768, maximum_bytes=32 * 1024**3
    )
    reopened = AssignmentPublicationJournal(
        schedule.directory,
        schedule.authorization.policy,
        schedule.authorization.legacy_policy,
        **capacity.model_dump(),
    )
    assert reopened.maximum_bytes == 32 * 1024**3
    with sqlite3.connect(reopened.path) as db:
        assert db.execute("SELECT key,value FROM metadata ORDER BY key").fetchall() == metadata
        assert db.execute("SELECT id,signed FROM publications ORDER BY id").fetchall() == signed
        assert db.execute("PRAGMA user_version").fetchone()[0] == 1
    changed = capacity.model_copy(update={"maximum_outcome_bytes": 2 * 1024**2})
    with pytest.raises(ValueError, match="outcome capacity mismatch"):
        AssignmentPublicationJournal(
            schedule.directory,
            schedule.authorization.policy,
            schedule.authorization.legacy_policy,
            **changed.model_dump(),
        )


def _command_args(tmp_path, command, capacity_path):
    arguments = ["--policy", "unused-policy.json", command, "--legacy-policy", "unused-legacy.json"]
    if command == "serve-assignment-feed":
        arguments += ["--state", str(tmp_path / "state"), "--nonce-path", str(tmp_path / "nonce")]
    else:
        for option in (
            "incumbent-execution",
            "dispatch-state",
            "publication-sha256",
            "suite",
            "reveal-pulses",
        ):
            arguments += ["--" + option, str(tmp_path / option)]
        arguments += ["--current-block", "100"]
    if capacity_path is not None:
        arguments += ["--scheduling-capacity", str(capacity_path)]
    return build_parser().parse_args(arguments)


@pytest.mark.parametrize("command", ["serve-assignment-feed", "assemble-endpoint-execution"])
@pytest.mark.parametrize("mode", ["default", "configured", "legacy-namespace"])
def test_command_openers_share_capacity_configuration(tmp_path, monkeypatch, command, mode):
    from umi import competition_endpoint_execution, competition_feed, competition_scheduling

    capacity = (
        SchedulingCapacity(
            maximum_publications=2000,
            maximum_assignments=20000,
            maximum_bytes=3 * 1024**3,
            maximum_outcome_bytes=2 * 1024**2,
        )
        if mode == "configured"
        else SchedulingCapacity()
    )
    capacity_path = tmp_path / "capacity.json" if mode == "configured" else None
    if capacity_path is not None:
        capacity_path.write_bytes(canonical_json_bytes(capacity))
    args = _command_args(tmp_path, command, capacity_path)
    assert args.scheduling_capacity == (str(capacity_path) if capacity_path else None)
    if mode == "legacy-namespace":
        del args.scheduling_capacity
    module = services if command == "serve-assignment-feed" else evidence
    original_load = module.load_json

    def load(path, model):
        if model is SchedulingCapacity:
            return original_load(path, model)
        return SimpleNamespace(pulses=())

    monkeypatch.setattr(module, "load_json", load)
    opened = []
    journal = object()

    def open_journal(directory, policy, legacy, **limits):
        opened.append((directory, limits))
        return journal

    monkeypatch.setattr(competition_scheduling, "AssignmentPublicationJournal", open_journal)
    if command == "serve-assignment-feed":
        import uvicorn

        monkeypatch.setattr(
            competition_feed, "create_assignment_feed", lambda *_args, **_kw: object()
        )
        monkeypatch.setattr(uvicorn, "run", lambda *_args, **_kw: None)
        services.serve_assignment_feed(args, object())
    else:
        monkeypatch.setattr(
            competition_endpoint_execution,
            "assemble_endpoint_evidence",
            lambda **_kw: SimpleNamespace(model_dump=lambda **_options: {}),
        )
        evidence.assemble_endpoint_execution(args, object())
    assert len(opened) == 1
    assert opened[0][1] == capacity.model_dump()


@pytest.mark.parametrize("command", ["serve-assignment-feed", "assemble-endpoint-execution"])
def test_command_rejects_invalid_capacity_before_opening_journal(tmp_path, monkeypatch, command):
    from umi import competition_scheduling

    capacity_path = tmp_path / "capacity.json"
    capacity_path.write_text('{"maximum_bytes":true}')
    args = _command_args(tmp_path, command, capacity_path)
    module = services if command == "serve-assignment-feed" else evidence
    original_load = module.load_json
    monkeypatch.setattr(
        module,
        "load_json",
        lambda path, model: (
            original_load(path, model)
            if model is SchedulingCapacity
            else SimpleNamespace(pulses=())
        ),
    )
    monkeypatch.setattr(
        competition_scheduling,
        "AssignmentPublicationJournal",
        lambda *_args, **_kw: pytest.fail("invalid capacity opened journal"),
    )
    handler = (
        services.serve_assignment_feed
        if module is services
        else evidence.assemble_endpoint_execution
    )
    with pytest.raises(ValueError):
        handler(args, object())
