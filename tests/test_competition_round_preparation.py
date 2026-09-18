from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_launch import PublicIntakeDeployment, PublicRoundSchedule
from umi.competition_publication import PublicationReplayLimits, build_cutoff_publication
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore, RoundPreparationCapacity
from umi.competition_store_migration_cli import migrate
from umi.open_competition import EvaluationRound, SignedSubmission, digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import bundle_at, round_for, snapshot, submission, suite_for
from .test_open_competition import policy as policy


@pytest.fixture
def setup(policy, tmp_path):
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    store = CompetitionStore(tmp_path / "state", policy)
    store.initialize_baseline(baseline, archive)
    first, second = submission(policy), submission(policy, name="Bob")
    for signed in (first, second):
        store.admit(signed, snapshot(), 110)
    options = {
        "snapshot": snapshot(120),
        "suite": suite_for(policy),
        "public_schedule": PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=100,
            roster_close_earliest_block=120,
            roster_close_latest_block=125,
            work_signing_close_block=130,
            evaluation_close_block=140,
            protected_reference_reveal_block=150,
            evidence_cutoff_block=160,
            round_valid_through_block=190,
        ),
        "eligible_tracks": ("endpoint", "model"),
        "intake_opened_block": 100,
        "evaluation_close_block": 140,
        "reveal_block": 150,
        "evidence_cutoff_block": 160,
        "valid_through_block": 190,
        "limits": PublicationReplayLimits(
            maximum_roster_bytes=1_000_000,
            maximum_evidence_bytes=1_000_000,
            maximum_certificate_bytes=2_000_000,
        ),
    }
    return SimpleNamespace(
        store=store,
        policy=policy,
        archive=archive,
        baseline=baseline,
        first=first,
        second=second,
        options=options,
    )


def unpack(result):
    p = result["cutoff_publication"]
    return (
        EvaluationRound.model_validate_json(canonical_json_bytes(p["round"])),
        EvidenceCutoffSchedule.model_validate_json(canonical_json_bytes(p["cutoff_schedule"])),
        tuple(
            SignedSubmission.model_validate_json(canonical_json_bytes(s))
            for s in result["submissions"]
        ),
    )


def next_options(setup):
    suite = setup.options["suite"]
    return {
        **setup.options,
        "snapshot": snapshot(121),
        "public_schedule": setup.options["public_schedule"].model_copy(
            update={"roster_close_latest_block": 124}
        ),
        "suite": suite.model_copy(
            update={
                "cases": tuple(
                    c.model_copy(
                        update={"case_id": f"{i + 1000:064x}", "video_sha256": f"{i + 2000:064x}"}
                    )
                    for i, c in enumerate(suite.cases)
                ),
            }
        ),
    }


def assert_empty(store):
    with sqlite3.connect(store.path) as db:
        for table in (
            "round_preparations",
            "rounds",
            "suite_usage",
            "public_schedule_usage",
            "evidence_cutoff_schedules",
        ):
            assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_complete_current_roster_cutoff_and_snapshot_freeze_together(setup):
    replacement = submission(setup.policy, sequence=2)
    setup.store.admit(replacement, snapshot(115), 115)
    model = submission(setup.policy, bundle=setup.baseline)
    setup.store.admit(model, snapshot(116), 116)
    prepared = setup.store.prepare_round(**setup.options)
    round_, cutoff, roster = unpack(prepared)
    assert round_.roster == tuple(
        sorted(digest(s.submission) for s in (replacement, model, setup.second))
    )
    assert round_.incumbent_model_sha256 == digest(setup.baseline)
    assert round_.sequence == 1 and round_.submission_close_block == 120
    assert cutoff.evidence_cutoff_block == 160
    assert not prepared["chain_submission_authorized"]
    assert b"references" not in canonical_json_bytes(prepared)
    publication = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=cutoff,
        submissions=roster,
        registration_snapshot=setup.options["snapshot"],
        policy=setup.policy,
        limits=setup.options["limits"],
    )
    assert publication.model_dump(mode="json", by_alias=True) == prepared["cutoff_publication"]
    assert (
        setup.store.fix_evidence_cutoff(round_, cutoff, observed_block=999)
        == prepared["cutoff_receipt"]
    )
    assert setup.store.close_round(round_, current_block=125) == digest(round_)
    with pytest.raises(ValueError, match="boundary is already closed"):
        setup.store.admit(submission(setup.policy, sequence=3), snapshot(120), 120)
    setup.store.admit(submission(setup.policy, sequence=3), snapshot(121), 121)


def test_state_binds_launch_semantics_not_mutable_deployment_metadata(policy, tmp_path):
    deployment = PublicIntakeDeployment(
        schema="umi-competition-intake-deployment/2",
        repository="https://github.com/Umi-BitSign/umi",
        umi_git_revision="12" * 20,
        umi_source_tree_sha256="34" * 32,
        deployed_at_utc="2026-09-17T12:00:00Z",
        round_schedule=PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=100,
            roster_close_earliest_block=120,
            roster_close_latest_block=125,
            work_signing_close_block=130,
            evaluation_close_block=140,
            protected_reference_reveal_block=150,
            evidence_cutoff_block=160,
            round_valid_through_block=190,
        ),
        eligible_tracks=("endpoint",),
        assignment_delivery_ready=False,
        model_intake_ready=False,
    )
    directory = tmp_path / "launch-bound"
    CompetitionStore(directory, policy, public_launch=deployment.launch_identity())
    later = deployment.model_copy(
        update={
            "umi_git_revision": "56" * 20,
            "umi_source_tree_sha256": "78" * 32,
            "deployed_at_utc": "2026-09-17T13:00:00Z",
            "assignment_delivery_ready": True,
        }
    )
    CompetitionStore(directory, policy, public_launch=later.launch_identity())
    with pytest.raises(ValueError, match="requires its public launch identity"):
        CompetitionStore(directory, policy)
    changed_schedule = deployment.round_schedule.model_copy(
        update={"roster_close_latest_block": 124}
    )
    with pytest.raises(ValueError, match="overlaps or rolls back"):
        CompetitionStore(
            directory,
            policy,
            public_launch=deployment.model_copy(
                update={"round_schedule": changed_schedule}
            ).launch_identity(),
        )
    with pytest.raises(ValueError, match="schedule reuse"):
        CompetitionStore(
            directory,
            policy,
            public_launch=deployment.model_copy(
                update={"eligible_tracks": ("endpoint", "model")}
            ).launch_identity(),
        )


def test_legacy_submission_writer_is_fenced_by_transactional_migration(policy, tmp_path):
    directory = tmp_path / "legacy-writer"
    directory.mkdir(mode=0o700)
    database = directory / "competition.sqlite3"
    old_schema = """
        CREATE TABLE submissions (
            digest TEXT PRIMARY KEY, hotkey TEXT NOT NULL, track TEXT NOT NULL,
            sequence INTEGER NOT NULL, accepted_block INTEGER NOT NULL,
            expires_block INTEGER NOT NULL, body BLOB NOT NULL, receipt BLOB NOT NULL,
            UNIQUE(hotkey, track, sequence)
        )
    """
    with sqlite3.connect(database) as connection:
        connection.execute(old_schema)
    CompetitionStore(directory, policy, migrate_writer_generation=True)
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT value FROM metadata WHERE key='policy'").fetchone() == (
            f"writer-2:{digest(policy)}",
        )
        assert connection.execute("SELECT value FROM metadata WHERE key='policy'").fetchone() != (
            digest(policy),
        )  # The legacy constructor's equality check fails.
        assert [row[1] for row in connection.execute("PRAGMA table_info(submissions)")] == [
            "digest",
            "hotkey",
            "track",
            "sequence",
            "accepted_block",
            "expires_block",
            "body",
            "receipt",
            "writer_generation",
        ]
        with pytest.raises(sqlite3.OperationalError, match="9 columns"):
            connection.execute(
                "INSERT INTO submissions VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("11" * 32, "22" * 32, "endpoint", 1, 1, 2, b"{}", b"{}"),
            )
        with pytest.raises(sqlite3.OperationalError, match="umi_writer_generation"):
            connection.execute("INSERT INTO rounds VALUES (?, ?, ?)", ("33" * 32, 1, b"{}"))


def test_legacy_store_requires_explicit_quiesced_writer_migration(policy, tmp_path):
    directory = tmp_path / "legacy-unmigrated"
    CompetitionStore(directory, policy)
    database = directory / "competition.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.create_function("umi_writer_generation", 0, lambda: 2)
        connection.execute("UPDATE metadata SET value=? WHERE key='policy'", (digest(policy),))
    with pytest.raises(ValueError, match="explicit quiesced migration"):
        CompetitionStore(directory, policy)
    CompetitionStore(directory, policy, migrate_writer_generation=True)


def test_one_shot_writer_migration_requires_explicit_quiesced_backup(policy, tmp_path):
    directory = tmp_path / "legacy-command"
    store = CompetitionStore(directory, policy)
    with store._connection() as connection:
        connection.execute("UPDATE metadata SET value=? WHERE key='policy'", (digest(policy),))
        connection.execute("DELETE FROM metadata WHERE key='retained_submission_head'")
    with pytest.raises(ValueError, match="quiesced store and verified backup"):
        migrate(directory, policy, confirmed=False)
    result = migrate(directory, policy, confirmed=True)
    assert result["status"] == "writer_generation_migrated"
    assert result["retained_submission_head"]["record_count"] == 0


def test_legacy_retained_round_without_exact_schedule_fails_closed(setup):
    prepared = setup.store.prepare_round(**setup.options)
    round_, _schedule, _submissions = unpack(prepared)
    legacy = round_.model_dump(mode="json", by_alias=True)
    legacy["schema"] = "umi-competition-round/1"
    legacy.pop("public_schedule")
    legacy.pop("eligible_tracks")
    with setup.store._connection() as connection:
        connection.execute(
            "UPDATE rounds SET body=? WHERE digest=?",
            (canonical_json_bytes(legacy), digest(round_)),
        )
    with pytest.raises(ValueError, match="legacy retained round lacks an exact public launch"):
        CompetitionStore(setup.store.directory, setup.policy)


def test_legacy_writer_migration_rolls_back_with_failed_store_binding(policy, tmp_path):
    directory = tmp_path / "legacy-writer-rollback"
    directory.mkdir(mode=0o700)
    database = directory / "competition.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE submissions ("
            "digest TEXT PRIMARY KEY, hotkey TEXT NOT NULL, track TEXT NOT NULL, "
            "sequence INTEGER NOT NULL, accepted_block INTEGER NOT NULL, "
            "expires_block INTEGER NOT NULL, body BLOB NOT NULL, receipt BLOB NOT NULL, "
            "UNIQUE(hotkey, track, sequence))"
        )
        connection.execute("CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        connection.execute("INSERT INTO metadata VALUES ('policy', ?)", ("00" * 32,))
    with pytest.raises(ValueError, match="different competition policy"):
        CompetitionStore(directory, policy)
    with sqlite3.connect(database) as connection:
        assert [row[1] for row in connection.execute("PRAGMA table_info(submissions)")] == [
            "digest",
            "hotkey",
            "track",
            "sequence",
            "accepted_block",
            "expires_block",
            "body",
            "receipt",
        ]


def test_retry_after_expiry_returns_identical_original_inputs(setup):
    first = setup.store.prepare_round(**setup.options)
    result = setup.store.prepare_round(**{**setup.options, "snapshot": snapshot(999)})
    assert canonical_json_bytes(result) == canonical_json_bytes(first)
    for name in (
        "evaluation_close_block",
        "reveal_block",
        "evidence_cutoff_block",
        "valid_through_block",
    ):
        with pytest.raises(ValueError, match="public schedule"):
            setup.store.prepare_round(**{**setup.options, name: setup.options[name] + 1})

    with pytest.raises(ValueError, match="frozen intake opening"):
        setup.store.prepare_round(
            **{
                **setup.options,
                "public_schedule": setup.options["public_schedule"].model_copy(
                    update={"intake_opened_block": 101}
                ),
                "intake_opened_block": 101,
            }
        )


def test_round_roster_excludes_pre_open_admission_and_includes_opening_boundary(setup):
    before_open = submission(setup.policy, name="Bob")
    at_open = submission(setup.policy)
    store = CompetitionStore(setup.store.directory.parent / "opening", setup.policy)
    store.initialize_baseline(setup.baseline, setup.archive)
    store.admit(before_open, snapshot(109), 109)
    store.admit(at_open, snapshot(110), 110)
    prepared = store.prepare_round(
        **{
            **setup.options,
            "intake_opened_block": 110,
            "public_schedule": setup.options["public_schedule"].model_copy(
                update={"intake_opened_block": 110}
            ),
        }
    )
    assert unpack(prepared)[0].roster == (digest(at_open.submission),)
    assert len(store.submissions()) == 2


def test_deregistered_hotkey_does_not_block_registered_peer(setup):
    snap = snapshot(120)
    prepared = setup.store.prepare_round(
        **{
            **setup.options,
            "snapshot": snap.model_copy(update={"registrations": snap.registrations[:1]}),
        }
    )
    assert unpack(prepared)[0].roster == (digest(setup.first.submission),)
    assert len(setup.store.submissions()) == 2  # Prior admission evidence remains.


def test_expired_replacement_does_not_revive_older_submission(setup):
    replacement = submission(setup.policy, sequence=2, end=135)
    setup.store.admit(replacement, snapshot(115), 115)
    assert unpack(setup.store.prepare_round(**setup.options))[0].roster == (
        digest(setup.second.submission),
    )


def test_first_new_round_freezes_next_sequence_and_fresh_suite(setup):
    first = setup.store.prepare_round(**setup.options)
    second = setup.store.prepare_round(**next_options(setup))
    a, _, _ = unpack(first)
    b, _, _ = unpack(second)
    assert b.sequence == a.sequence + 1
    assert b.suite_sha256 != a.suite_sha256 and b.submission_close_block == 121


def test_public_schedule_cannot_be_reused_for_another_suite(setup):
    setup.store.prepare_round(**setup.options)
    other = next_options(setup)
    other["public_schedule"] = setup.options["public_schedule"]
    with pytest.raises(ValueError, match="public round schedule was already used"):
        setup.store.prepare_round(**other)


@pytest.mark.parametrize(
    "key,value",
    [
        ("evaluation_close_block", 120),
        ("evaluation_close_block", True),
        ("evaluation_close_block", 2**80),
        ("reveal_block", 140),
        ("evidence_cutoff_block", 149),
        ("evidence_cutoff_block", 191),
        ("valid_through_block", 1001),
    ],
)
def test_invalid_window_leaves_no_partial_freeze(setup, key, value):
    with pytest.raises(ValueError):
        setup.store.prepare_round(**{**setup.options, key: value})
    assert_empty(setup.store)


@pytest.mark.parametrize("mode", ["foreign", "coverage", "stale_head", "no_baseline", "empty"])
def test_invalid_round_inputs_leave_admission_open(setup, mode):
    options = dict(setup.options)
    if mode == "foreign":
        options["suite"] = options["suite"].model_copy(update={"policy_sha256": "ff" * 32})
    elif mode == "coverage":
        suite = options["suite"]
        options["suite"] = suite.model_copy(
            update={
                "cases": tuple(c.model_copy(update={"stratum": "continuous"}) for c in suite.cases),
            }
        )
    elif mode == "stale_head":
        options["snapshot"] = snapshot(109)
    elif mode == "no_baseline":
        setup.store = CompetitionStore(setup.store.directory.parent / "no-baseline", setup.policy)
    else:
        options["evaluation_close_block"] = 950
        options.update(reveal_block=960, evidence_cutoff_block=970, valid_through_block=990)
    with pytest.raises(ValueError):
        setup.store.prepare_round(**options)
    assert_empty(setup.store)


def test_pending_manual_cutoff_is_not_skipped(setup):
    round_ = round_for(
        setup.policy, setup.options["suite"], (setup.first, setup.second), digest(setup.baseline)
    )
    cutoff = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(setup.policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    setup.store.fix_evidence_cutoff(round_, cutoff, observed_block=115)
    with pytest.raises(ValueError, match="previously fixed cutoff"):
        setup.store.prepare_round(**setup.options)
    setup.store.close_round(round_, current_block=120)
    with pytest.raises(ValueError, match="suite was already used"):
        setup.store.prepare_round(**setup.options)
    assert unpack(setup.store.prepare_round(**next_options(setup)))[0].sequence == 2


@pytest.mark.parametrize("mode", ["wire_bytes", "storage_bytes", "records"])
def test_capacity_failure_rolls_back_all_round_records_and_preserves_retry(setup, mode):
    options = setup.options
    if mode == "wire_bytes":
        options = {
            **options,
            "limits": options["limits"].model_copy(update={"maximum_certificate_bytes": 1}),
        }
    elif mode == "storage_bytes":
        setup.store.preparation_capacity = RoundPreparationCapacity(maximum_bytes=1)
    else:
        setup.store.preparation_capacity = RoundPreparationCapacity(maximum_records=1)
        first = setup.store.prepare_round(**options)
        with pytest.raises(ValueError, match="capacity"):
            setup.store.prepare_round(**next_options(setup))
        assert setup.store.prepare_round(**options) == first
        with sqlite3.connect(setup.store.path) as db:
            for table in (
                "rounds",
                "round_preparations",
                "suite_usage",
                "public_schedule_usage",
                "evidence_cutoff_schedules",
            ):
                assert db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 1
        return
    with pytest.raises(ValueError, match=r"bound|capacity"):
        setup.store.prepare_round(**options)
    assert_empty(setup.store)


def test_concurrent_preparation_has_one_frozen_result(setup):
    barrier = Barrier(2)

    def run():
        store = CompetitionStore(setup.store.directory, setup.policy)
        barrier.wait()
        return store.prepare_round(**setup.options)

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run) for _ in range(2)]
        first, second = (f.result(timeout=10) for f in futures)
    assert first == second
    with sqlite3.connect(setup.store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM rounds").fetchone()[0] == 1


def test_admission_racing_freeze_is_included_or_explicitly_deferred(setup):
    barrier = Barrier(2)
    replacement = submission(setup.policy, sequence=2)

    def admit():
        barrier.wait()
        try:
            setup.store.admit(replacement, snapshot(120), 120)
            return True
        except ValueError as error:
            assert "boundary is already closed" in str(error)
            return False

    def prepare():
        barrier.wait()
        return setup.store.prepare_round(**setup.options)

    with ThreadPoolExecutor(max_workers=2) as pool:
        admitted, prepared = pool.submit(admit), pool.submit(prepare)
        included = admitted.result(timeout=10)
        round_, _, _ = unpack(prepared.result(timeout=10))
    assert (digest(replacement.submission) in round_.roster) is included
    assert (digest(setup.first.submission) in round_.roster) is not included


def test_competing_suites_cannot_both_freeze_one_admission_boundary(setup):
    barrier = Barrier(2)
    options = [setup.options, {**next_options(setup), "snapshot": snapshot(120)}]

    def run(config):
        barrier.wait()
        try:
            return setup.store.prepare_round(**config)
        except ValueError as error:
            assert "advance the admission boundary" in str(error)
            return None

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(run, config) for config in options]
        results = [f.result(timeout=10) for f in futures]
    assert sum(r is not None for r in results) == 1
    with sqlite3.connect(setup.store.path) as db:
        assert db.execute("SELECT COUNT(*) FROM rounds").fetchone()[0] == 1


def test_restart_keeps_original_preparation_and_does_not_change_its_roster(setup):
    expected = setup.store.prepare_round(**setup.options)
    restarted = CompetitionStore(setup.store.directory, setup.policy)
    restarted.admit(submission(setup.policy, sequence=2), snapshot(121), 121)
    assert restarted.prepare_round(**setup.options) == expected


@pytest.mark.parametrize(
    "mode",
    [
        "roster",
        "receipt",
        "authority",
        "noncanonical",
        "submissions_null",
        "submissions_object",
        "submissions_scalar",
        "round",
        "schedule",
        "usage",
        "schedule_usage",
    ],
)
def test_corrupt_retained_preparation_is_never_reused(setup, mode):
    setup.store.prepare_round(**setup.options)
    with sqlite3.connect(setup.store.path) as db:
        db.create_function("umi_writer_generation", 0, lambda: 2)
        if mode in {"round", "schedule", "usage", "schedule_usage"}:
            table = {
                "round": "rounds",
                "schedule": "evidence_cutoff_schedules",
                "usage": "suite_usage",
                "schedule_usage": "public_schedule_usage",
            }[mode]
            db.execute(f"DELETE FROM {table}")
        else:
            raw = db.execute("SELECT body FROM round_preparations").fetchone()[0]
            data = json.loads(raw)
            if mode == "roster":
                data["submissions"].pop()
            elif mode == "receipt":
                data["cutoff_receipt"]["fixed_observed_block"] += 1
            elif mode == "authority":
                data["chain_submission_authorized"] = True
            elif mode == "submissions_null":
                data["submissions"] = None
            elif mode == "submissions_object":
                data["submissions"] = {}
            elif mode == "submissions_scalar":
                data["submissions"] = 1
            body = raw + b" " if mode == "noncanonical" else canonical_json_bytes(data)
            db.execute("UPDATE round_preparations SET body=?", (body,))
    with pytest.raises(ValueError):
        setup.store.prepare_round(**setup.options)


def test_close_round_canonically_revalidates_caller_input(setup):
    round_ = round_for(
        setup.policy, setup.options["suite"], (setup.first, setup.second), digest(setup.baseline)
    )
    malformed = round_.model_copy(update={"eligible_tracks": ("model", "endpoint")})
    with pytest.raises(ValueError, match="eligible tracks must be sorted and unique"):
        setup.store.close_round(malformed, current_block=120)
    assert_empty(setup.store)


def test_launch_bound_close_requires_atomic_snapshot_preparation(setup):
    launch = PublicIntakeDeployment(
        schema="umi-competition-intake-deployment/2",
        repository="https://github.com/Umi-BitSign/umi",
        umi_git_revision="12" * 20,
        umi_source_tree_sha256="34" * 32,
        deployed_at_utc="2026-09-17T12:00:00Z",
        round_schedule=setup.options["public_schedule"],
        eligible_tracks=setup.options["eligible_tracks"],
        assignment_delivery_ready=True,
        model_intake_ready=True,
    ).launch_identity()
    store = CompetitionStore(setup.store.directory, setup.policy, public_launch=launch)
    round_ = round_for(
        setup.policy, setup.options["suite"], (setup.first, setup.second), digest(setup.baseline)
    ).model_copy(
        update={
            "public_schedule": setup.options["public_schedule"],
            "valid_through_block": setup.options["valid_through_block"],
        }
    )
    with pytest.raises(ValueError, match="finalized registration snapshot"):
        store.close_round(round_, current_block=120)
    assert_empty(store)
    prepared = store.prepare_round(**setup.options)
    frozen, _, _ = unpack(prepared)
    assert store.close_round(frozen, current_block=120) == digest(frozen)
