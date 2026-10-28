import json
import logging
from contextlib import contextmanager

import pytest

from umi.competition_cohort_intake import CohortIntake
from umi.competition_cohort_seal_reuse import IntakeSealRepairRequired

from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at, request_for, seal_and_close
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy


def prepared(intake, scenario):
    intake.retain(request_for(scenario), capture_at(210))
    _, _, seal = seal_and_close(intake, scenario)
    return seal, seal.cohort_sha256, seal.recovery_tip_sha256


def test_creation_restart_and_cache_hit_never_read_original_bodies(
    intake, scenario, monkeypatch, caplog
):
    import umi.competition_cohort_seal_reuse as reuse

    seal, cohort, tip = prepared(intake, scenario)
    caplog.set_level(logging.INFO, logger=reuse.__name__)
    caplog.clear()

    def unexpected(*args, **kwargs):
        raise AssertionError("completed original work repeated")

    monkeypatch.setattr(reuse, "read_participation", unexpected)
    monkeypatch.setattr(reuse, "verify_model_acceptance", unexpected)
    for current in (intake, CohortIntake(intake.config, intake.policy)):
        queries = []
        original = current._exclusive_connection

        @contextmanager
        def observed(original=original, queries=queries):
            with original() as value:
                value[0].set_trace_callback(queries.append)
                yield value

        monkeypatch.setattr(current, "_exclusive_connection", observed)
        result = current.sealed(cohort, tip)
        assert result == seal
        object.__setattr__(result, "selected", ())
        assert current.sealed(cohort, tip) == seal
        assert not [
            q
            for q in queries
            if q.lstrip().upper().startswith("SELECT")
            and "body" in q
            and ("FROM cohort_consents" in q or "FROM cohort_model_acceptances" in q)
        ]
    events = [
        json.loads(record.getMessage().split(" ", 1)[1])
        for record in caplog.records
        if record.name == reuse.__name__
        and record.getMessage().startswith("cohort_intake_seal_reuse ")
    ]
    assert len(events) == 4
    for event in events:
        assert event["cohort_sha256"] == cohort and event["recovery_tip_sha256"] == tip
        assert len(event["dependency_context_sha256"]) == 64
        assert event["status"] == "reused" and event["completed"] == event["total"] == 1
        assert event["elapsed_seconds"] >= 0 and event["eta_seconds"] == 0
        assert event["eta_basis"] == "retained_verified_result"


@pytest.mark.parametrize("damage", ["missing", "bytes", "completion"])
def test_damaged_result_requires_explicit_repair_preserving_other_items(
    intake, scenario, monkeypatch, damage
):
    import umi.competition_cohort_seal_reuse as reuse

    seal, cohort, tip = prepared(intake, scenario)
    with intake._connection() as (db, _):
        if damage == "missing":
            db.execute("DELETE FROM intake_seal_reuse_results WHERE kind='seal'")
        elif damage == "bytes":
            db.execute("UPDATE intake_seal_reuse_results SET body=? WHERE kind='seal'", (b"{}",))
        else:
            db.execute("DELETE FROM intake_seal_reuse_completions WHERE kind='seal'")

    def unexpected(*args, **kwargs):
        raise AssertionError("intact per-record check repeated")

    monkeypatch.setattr(reuse, "read_participation", unexpected)
    with pytest.raises(IntakeSealRepairRequired):
        intake.sealed(cohort, tip)
    assert intake.repair_seal_reuse(cohort, tip, reason="restore exact derived seal") == seal
    assert CohortIntake(intake.config, intake.policy).sealed(cohort, tip) == seal


@pytest.mark.parametrize("damage", ["body", "index", "delete", "add", "rekey"])
def test_original_mutations_invalidate_only_native_result(intake, scenario, damage):
    _, cohort, tip = prepared(intake, scenario)
    with intake._connection() as (db, _):
        if damage == "body":
            db.execute("UPDATE cohort_consents SET body=?", (b"{}",))
        elif damage == "index":
            db.execute("UPDATE cohort_consents SET observed=observed+1")
        elif damage == "delete":
            db.execute("DELETE FROM cohort_consents")
        elif damage == "rekey":
            db.execute("UPDATE cohort_consents SET cohort=?", ("00" * 32,))
        else:
            row = db.execute("SELECT * FROM cohort_consents").fetchone()
            db.execute(
                "INSERT INTO cohort_consents VALUES (?,?,?,?,?,?,?,?)",
                ("00" * 32, *row[1:4], row[4] + 1, *row[5:]),
            )
    with pytest.raises(ValueError):
        CohortIntake(intake.config, intake.policy).sealed(cohort, tip)


@pytest.mark.parametrize("damage", ["source", "trigger", "table", "owner"])
def test_damaged_source_metadata_is_not_a_cache_miss(intake, scenario, monkeypatch, damage):
    import umi.competition_cohort_seal_reuse as reuse

    _, cohort, tip = prepared(intake, scenario)
    with intake._connection() as (db, _):
        if damage == "source":
            db.execute("DELETE FROM intake_seal_reuse_sources WHERE kind='consent'")
        elif damage == "trigger":
            db.execute("DROP TRIGGER intake_seal_reuse_consent_update")
        elif damage == "table":
            db.execute("DROP TABLE intake_seal_reuse_sources")
        else:
            db.execute("DELETE FROM intake_seal_reuse_owner")

    def unexpected(*args, **kwargs):
        raise AssertionError("damaged metadata silently rescanned originals")

    monkeypatch.setattr(reuse, "read_participation", unexpected)
    with pytest.raises(IntakeSealRepairRequired):
        intake.sealed(cohort, tip)


def test_metadata_counts_toward_intake_capacity(intake, scenario):
    from umi.competition_cohort_seal_reuse import retained_metadata_bytes

    prepared(intake, scenario)
    with intake._connection() as (db, _):
        total = intake.retained_bytes(db)
        derived = retained_metadata_bytes(db)
        assert 0 < derived < total
        db.execute("DELETE FROM intake_seal_reuse_results")
        assert intake.retained_bytes(db) < total


def legacy_layout(intake):
    """Restore a pre-feature fixture without changing its original signed rows."""
    import shutil

    with intake._connection() as (db, _):
        for name, kind in db.execute(
            "SELECT name,type FROM sqlite_master WHERE name GLOB 'intake_seal_reuse_*'"
        ).fetchall():
            if kind == "trigger":
                db.execute("DROP TRIGGER " + name)
        for name, kind in db.execute(
            "SELECT name,type FROM sqlite_master WHERE name GLOB 'intake_seal_reuse_*'"
        ).fetchall():
            if kind == "table":
                db.execute("DROP TABLE " + name)
    shutil.rmtree(intake.directory / "seal-reuse")


def test_legacy_first_pass_checkpoints_resume_after_interruption(intake, scenario, monkeypatch):
    import umi.competition_cohort_seal_reuse as reuse

    intake.retain(request_for(scenario), capture_at(210))
    intake.retain(request_for(scenario, sequence=2, block=220), capture_at(220))
    _, _, seal = seal_and_close(intake, scenario)
    legacy_layout(intake)
    project = reuse.project_participation
    calls = []

    def interrupt(key, *args):
        calls.append(key)
        if len(calls) == 2:
            raise InterruptedError("fixture interruption")
        return project(key, *args)

    monkeypatch.setattr(reuse, "project_participation", interrupt)
    with pytest.raises(InterruptedError):
        intake.sealed(seal.cohort_sha256, seal.recovery_tip_sha256)
    with intake._connection() as (db, _):
        assert (
            db.execute(
                "SELECT COUNT(*) FROM intake_seal_reuse_results WHERE kind='participation'"
            ).fetchone()[0]
            == 1
        )
    first = calls[0]

    def resume(key, *args):
        assert key != first, "completed native participation replayed after restart"
        calls.append(key)
        return project(key, *args)

    monkeypatch.setattr(reuse, "project_participation", resume)
    restarted = CohortIntake(intake.config, intake.policy)
    assert restarted.sealed(seal.cohort_sha256, seal.recovery_tip_sha256) == seal
    assert len(calls) == 3


@pytest.mark.parametrize("damage", ["source", "trigger", "owner", "file-owner", "marker"])
def test_source_repair_resumes_supported_layout_and_is_idempotent(
    intake, scenario, monkeypatch, damage
):
    import shutil

    import umi.competition_cohort_seal_reuse as reuse

    seal, cohort, tip = prepared(intake, scenario)
    if damage == "file-owner":
        path = intake.directory / "intake.sqlite3"
        replacement = path.with_suffix(".replacement")
        shutil.copyfile(path, replacement)
        replacement.chmod(0o600)
        replacement.replace(path)
    elif damage == "marker":
        (intake.directory / "seal-reuse/installed.json").unlink()
    else:
        with intake._connection() as (db, _):
            if damage == "source":
                db.execute("DELETE FROM intake_seal_reuse_sources WHERE kind='consent'")
            elif damage == "trigger":
                db.execute("DROP TRIGGER intake_seal_reuse_consent_update")
            else:
                db.execute("DELETE FROM intake_seal_reuse_owner")
    with pytest.raises(IntakeSealRepairRequired):
        intake.sealed(cohort, tip)
    assert intake.repair_seal_reuse(cohort, tip, reason="restored exact intake fixture") == seal

    def unexpected(*args, **kwargs):
        raise AssertionError("completed repair repeated original work")

    monkeypatch.setattr(reuse, "read_participation", unexpected)
    assert intake.repair_seal_reuse(cohort, tip, reason="restored exact intake fixture") == seal
    assert CohortIntake(intake.config, intake.policy).sealed(cohort, tip) == seal


def test_missing_verified_original_seal_is_not_unsealed_intake(intake, scenario):
    _, cohort, tip = prepared(intake, scenario)
    with intake._connection() as (db, _):
        db.execute("DELETE FROM cohort_intake_seals")
    with pytest.raises(IntakeSealRepairRequired, match="original intake seal is missing"):
        intake.sealed(cohort, tip)


def test_direct_seal_transaction_failure_does_not_leave_committed_fence(
    intake, scenario, monkeypatch
):
    import umi.competition_cohort_seal_reuse as reuse
    from umi.competition_cohort_intake import history_tip
    from umi.open_competition import digest

    intake.retain(request_for(scenario), capture_at(210))
    history = scenario["intake_history"]
    cohort, tip = digest(history.plan), history_tip(history)
    original = reuse.IntakeSealReuse.record_created

    def interrupted(self, *args):
        original(self, *args)
        raise InterruptedError("fixture metadata publication interrupted")

    monkeypatch.setattr(reuse.IntakeSealReuse, "record_created", interrupted)
    with pytest.raises(InterruptedError):
        intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    with intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_intake_seals").fetchone()[0] == 0
        assert (
            db.execute(
                "SELECT COUNT(*) FROM intake_seal_reuse_results WHERE kind='participation'"
            ).fetchone()[0]
            == 1
        )
    monkeypatch.setattr(reuse.IntakeSealReuse, "record_created", original)

    def unexpected(*args, **kwargs):
        raise AssertionError("completed participation repeated")

    monkeypatch.setattr(reuse, "read_participation", unexpected)
    assert intake.seal(cohort, capture_at(305), expected_tip_sha256=tip)


def test_loss_of_result_and_completion_does_not_hide_registered_success(intake, scenario):
    seal, cohort, tip = prepared(intake, scenario)
    with intake._connection() as (db, _):
        db.execute("DELETE FROM intake_seal_reuse_results WHERE kind='seal'")
        db.execute("DELETE FROM intake_seal_reuse_completions WHERE kind='seal'")
    with pytest.raises(IntakeSealRepairRequired):
        intake.sealed(cohort, tip)
    assert intake.repair_seal_reuse(cohort, tip, reason="restore missing derived receipt") == seal


def test_historical_context_survives_successor_and_return(intake, scenario, monkeypatch):
    import umi.competition_cohort_seal_reuse as reuse
    from umi.competition_cohort_intake import history_tip
    from umi.open_competition import digest

    from .test_competition_cohort_consumers import transition

    first = request_for(scenario)
    intake.retain(first, capture_at(210))
    history = scenario["intake_history"]
    cohort, tip = digest(history.plan), history_tip(history)
    seal = intake.seal(cohort, capture_at(300), expected_tip_sha256=tip)
    extended = transition(history, scenario["policy"], "extend", 300, extension=20)
    intake.publish(extended, capture_at(310))
    intake.retain(request_for(scenario, sequence=2, block=310), capture_at(310))
    newer = intake.seal(cohort, capture_at(320), expected_tip_sha256=history_tip(extended))
    assert newer != seal
    original = reuse.project_participation
    calls = []

    def observed(key, *args):
        calls.append(key)
        return original(key, *args)

    monkeypatch.setattr(reuse, "project_participation", observed)
    assert intake.sealed(cohort, tip) == seal
    assert calls == []


def test_repair_cli_preserves_selected_service_limits(intake, scenario, tmp_path, monkeypatch):
    import sys
    from types import SimpleNamespace

    import umi.competition_cohort_seal_reuse_cli as cli
    from umi.private_files import publish_private_model

    seal, cohort, tip = prepared(intake, scenario)
    with intake._connection() as (db, _):
        db.execute("DELETE FROM intake_seal_reuse_results WHERE kind='seal'")
    policy_path = tmp_path / "policy.json"
    publish_private_model(policy_path, intake.policy)
    # Reading the full selected config supplies both operational limits and the
    # exact legacy track order; native CohortIntake and repair remain real.
    selected = SimpleNamespace(
        recoverable_intake=intake.config,
        policy_sha256=seal.policy_sha256,
        public_deployment=SimpleNamespace(eligible_tracks=intake.tracks),
        admission_capacity=intake.capacity,
    )
    original = cli.read_private_model

    def read(path, model):
        return selected if path == tmp_path / "selected-owner.json" else original(path, model)

    monkeypatch.setattr(cli, "read_private_model", read)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "repair",
            "--service-config",
            str(tmp_path / "selected-owner.json"),
            "--policy",
            str(policy_path),
            "--cohort",
            cohort,
            "--tip",
            tip,
            "--reason",
            "fixture lost derived receipt",
        ],
    )
    assert cli.main() == 0
    assert intake.sealed(cohort, tip) == seal
