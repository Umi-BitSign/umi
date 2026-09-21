from __future__ import annotations

import json
import sqlite3

import pytest
from fastapi.testclient import TestClient

from umi.competition_api import create_app
from umi.competition_launch import PublicLaunchIdentity
from umi.competition_launch_amendment import (
    LaunchAmendment,
    SignedLaunchAmendment,
    verify_launch_amendment,
)
from umi.competition_store import CompetitionStore
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .competition_checkpoint import bind_submission_checkpoint
from .test_competition_round_preparation import setup as setup
from .test_competition_rounds import deployment_for
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, submission, wallet


def continuous(schedule, tracks=("endpoint", "model")):
    return PublicLaunchIdentity(
        schema="umi-competition-public-launch/2",
        round_schedule=schedule,
        eligible_tracks=tracks,
        round_stride_blocks=100,
    )


def signed_amendment(policy, previous, replacement):
    amendment = LaunchAmendment(
        schema="umi-competition-launch-amendment/1",
        policy_sha256=digest(policy),
        previous_launch_sha256=digest(previous),
        replacement=replacement,
        effective_block=111,
        reason="accelerate_first_cohort_continuous_intake",
    )
    return SignedLaunchAmendment(
        amendment=amendment,
        signatures=tuple(sign_object(amendment, wallet(name)) for name in ("Charlie", "Dave")),
    )


def launch_pair(setup):
    replacement = continuous(setup.options["public_schedule"])
    old = replacement.schedule_for_cycle(1).model_copy(update={"intake_opened_block": 100})
    previous = PublicLaunchIdentity(
        schema="umi-competition-public-launch/1",
        round_schedule=old,
        eligible_tracks=replacement.eligible_tracks,
    )
    return previous, replacement


def test_legacy_signed_bytes_remain_unchanged(setup):
    previous, _ = launch_pair(setup)
    body = previous.model_dump(mode="json", by_alias=True)
    assert set(body) == {"schema", "round_schedule", "eligible_tracks"}
    assert canonical_json_bytes(previous) == canonical_json_bytes(body)
    deployment = deployment_for(previous.round_schedule, previous.eligible_tracks)
    assert "round_stride_blocks" not in deployment.model_dump(mode="json", by_alias=True)
    assert deployment.launch_identity() == previous


def test_exact_continuous_schedules_and_guaranteed_cutoffs(setup):
    previous, launch = launch_pair(setup)
    assert not previous.accepts_at(226)
    assert launch.accepts_at(226)
    assert not launch.accepts_at(99)
    for index in range(4):
        schedule = launch.schedule_for_cycle(index)
        assert launch.contains_schedule(schedule)
        assert schedule.intake_opened_block == 100
        assert schedule.roster_close_earliest_block == 120 + index * 100
        assert launch.next_intake_schedule(120 + index * 100) == schedule
        assert launch.next_intake_schedule(121 + index * 100) == launch.schedule_for_cycle(
            index + 1
        )
        assert not launch.contains_schedule(
            schedule.model_copy(
                update={"evidence_cutoff_block": schedule.evidence_cutoff_block + 1}
            )
        )
    for bad in (-1, True, 1.2, 2**53):
        with pytest.raises(ValueError):
            launch.accepts_at(bad)
    with pytest.raises(ValueError):
        launch.schedule_for_cycle(2**53)
    with pytest.raises(ValueError):
        PublicLaunchIdentity.model_validate_json(
            canonical_json_bytes(
                {**launch.model_dump(mode="json", by_alias=True), "round_stride_blocks": 40}
            )
        )


def test_amendment_preserves_receipts_checkpoint_and_stale_writer_fence(setup, tmp_path):
    previous, launch = launch_pair(setup)
    checkpoint = tmp_path / "checkpoint"
    store = bind_submission_checkpoint(setup.store, previous, checkpoint)
    before = store._submission_checkpoint.load()
    with sqlite3.connect(store.path) as db:
        records = db.execute(
            "SELECT digest, body, receipt FROM submissions ORDER BY digest"
        ).fetchall()
    amendment = signed_amendment(setup.policy, previous, launch)
    with pytest.raises(ValueError, match="overlaps"):
        CompetitionStore(
            store.directory,
            setup.policy,
            public_launch=launch,
            submission_head_checkpoint_directory=checkpoint,
        )
    migrated = CompetitionStore(
        store.directory,
        setup.policy,
        public_launch=launch,
        submission_head_checkpoint_directory=checkpoint,
        launch_amendment=amendment,
        amendment_observed_block=112,
        migrate_writer_generation=True,
    )
    after = migrated._submission_checkpoint.load()
    assert after.public_launch_sha256 == digest(launch)
    for key in ("submission_sha256s", "admission_record_sha256s"):
        assert getattr(after, key) == getattr(before, key)
    with sqlite3.connect(store.path) as db:
        assert (
            db.execute("SELECT digest, body, receipt FROM submissions ORDER BY digest").fetchall()
            == records
        )
        assert db.execute("SELECT COUNT(*) FROM public_launch_history").fetchone() == (2,)
        assert db.execute("SELECT body FROM public_launch_amendments").fetchone() == (
            canonical_json_bytes(amendment),
        )
    with pytest.raises(ValueError, match="stale public launch"):
        store.admit(submission(setup.policy, sequence=2), snapshot(113), 113)
    restarted = CompetitionStore(
        store.directory,
        setup.policy,
        public_launch=launch,
        submission_head_checkpoint_directory=checkpoint,
    )
    original_receipt = next(
        json.loads(receipt) for key, _, receipt in records if key == digest(setup.first.submission)
    )
    assert restarted.admit(setup.first, snapshot(113), 113) == original_receipt
    assert (
        restarted.admit(submission(setup.policy, sequence=2), snapshot(126), 126)["accepted_block"]
        == 126
    )


@pytest.mark.parametrize(
    "kind", ["missing_quorum", "wrong_policy", "different_tracks", "different_opening"]
)
def test_amendment_rejects_unauthorized_changes(setup, kind):
    previous, launch = launch_pair(setup)
    signed = signed_amendment(setup.policy, previous, launch)
    if kind == "missing_quorum":
        signed = signed.model_copy(update={"signatures": signed.signatures[:1]})
    elif kind == "wrong_policy":
        signed = signed.model_copy(
            update={"amendment": signed.amendment.model_copy(update={"policy_sha256": "f1" * 32})}
        )
    elif kind == "different_tracks":
        launch = launch.model_copy(update={"eligible_tracks": ("endpoint",)})
    else:
        launch = launch.model_copy(
            update={
                "round_schedule": launch.round_schedule.model_copy(
                    update={"intake_opened_block": 101}
                )
            }
        )
    with pytest.raises(ValueError):
        verify_launch_amendment(signed, previous, launch, setup.policy)


def test_continuous_rosters_freeze_and_later_admissions_enter_next_cycle(setup):
    launch = continuous(setup.options["public_schedule"])
    store = CompetitionStore(setup.store.directory, setup.policy, public_launch=launch)
    first = store.prepare_round(**setup.options)
    replacement = submission(setup.policy, sequence=2)
    store.admit(replacement, snapshot(126), 126)
    assert store.prepare_round(**setup.options) == first
    schedule = launch.schedule_for_cycle(1)
    suite = setup.options["suite"].model_copy(
        update={
            "cases": tuple(
                case.model_copy(
                    update={
                        "case_id": f"{index + 1000:064x}",
                        "video_sha256": f"{index + 2000:064x}",
                    }
                )
                for index, case in enumerate(setup.options["suite"].cases)
            )
        }
    )
    second = store.prepare_round(
        **{
            **setup.options,
            "snapshot": snapshot(220),
            "suite": suite,
            "public_schedule": schedule,
            "evaluation_close_block": 240,
            "reveal_block": 250,
            "evidence_cutoff_block": 260,
            "valid_through_block": 290,
        }
    )
    assert digest(replacement.submission) in second["cutoff_publication"]["round"]["roster"]
    assert digest(replacement.submission) not in first["cutoff_publication"]["round"]["roster"]


def test_api_remains_open_after_first_cohort(setup):
    launch = continuous(setup.options["public_schedule"])
    deployment = deployment_for(launch.round_schedule, launch.eligible_tracks)
    deployment = type(deployment).model_validate_json(
        canonical_json_bytes(
            {
                **deployment.model_dump(mode="json", by_alias=True),
                "schema": "umi-competition-intake-deployment/3",
                "round_stride_blocks": 100,
            }
        )
    )
    store = CompetitionStore(setup.store.directory, setup.policy, public_launch=launch)

    async def provider():
        return snapshot(126)

    with TestClient(create_app(store, provider, public_deployment=deployment)) as client:
        status = client.get("/v1/competition/status").json()
        assert status["admission_accepting_new"] is True
        assert status["next_intake_schedule"]["roster_close_earliest_block"] == 220
        response = client.post(
            "/v1/competition/submissions",
            json=submission(setup.policy, sequence=2).model_dump(mode="json", by_alias=True),
        )
        assert response.status_code == 200, response.text
        assert response.json()["status"] == "accepted_no_weight"


def test_amendment_cannot_retime_a_prepared_round(setup):
    store = setup.store
    prepared = store.prepare_round(**setup.options)
    previous = PublicLaunchIdentity(
        schema="umi-competition-public-launch/1",
        round_schedule=setup.options["public_schedule"],
        eligible_tracks=setup.options["eligible_tracks"],
    )
    store = CompetitionStore(store.directory, setup.policy, public_launch=previous)
    schedule = previous.round_schedule.model_copy(update={"roster_close_earliest_block": 119})
    launch = continuous(schedule)
    amendment = signed_amendment(setup.policy, previous, launch)
    with pytest.raises(ValueError, match="unused first-cohort"):
        CompetitionStore(
            store.directory,
            setup.policy,
            public_launch=launch,
            launch_amendment=amendment,
            amendment_observed_block=112,
            migrate_writer_generation=True,
        )
    assert store.prepared_round(digest(setup.options["suite"]), setup.options["limits"]) == prepared


@pytest.mark.parametrize("observed", [110, 120, True])
def test_amendment_application_requires_current_future_cutoff(setup, observed):
    previous, launch = launch_pair(setup)
    store = CompetitionStore(setup.store.directory, setup.policy, public_launch=previous)
    with pytest.raises(ValueError, match="application window"):
        CompetitionStore(
            store.directory,
            setup.policy,
            public_launch=launch,
            launch_amendment=signed_amendment(setup.policy, previous, launch),
            amendment_observed_block=observed,
            migrate_writer_generation=True,
        )
    assert (
        CompetitionStore(store.directory, setup.policy, public_launch=previous).public_launch
        == previous
    )


def future_amendment(setup, *, previous=None, replacement=None, effective=200):
    previous = previous or continuous(setup.options["public_schedule"])
    if replacement is None:
        schedule = previous.schedule_for_cycle(1)
        replacement = previous.model_copy(
            update={
                "round_stride_blocks": 200,
                "round_schedule": schedule.model_copy(
                    update={
                        "work_signing_close_block": schedule.work_signing_close_block + 20,
                        "evaluation_close_block": schedule.evaluation_close_block + 60,
                        "protected_reference_reveal_block": (
                            schedule.protected_reference_reveal_block + 60
                        ),
                        "evidence_cutoff_block": schedule.evidence_cutoff_block + 60,
                        "round_valid_through_block": schedule.round_valid_through_block + 60,
                    }
                ),
            }
        )
    amendment = LaunchAmendment(
        schema="umi-competition-launch-amendment/2",
        policy_sha256=digest(setup.policy),
        previous_launch_sha256=digest(previous),
        replacement=replacement,
        first_replaced_cycle=1,
        effective_block=effective,
        reason="extend_future_cohort_windows",
    )
    signed = SignedLaunchAmendment(
        amendment=amendment,
        signatures=tuple(sign_object(amendment, wallet(name)) for name in ("Charlie", "Dave")),
    )
    return previous, replacement, signed


def test_future_extension_preserves_prior_preparation_receipts_and_checkpoint(setup, tmp_path):
    previous, replacement, signed = future_amendment(setup)
    checkpoint = tmp_path / "checkpoint"
    store = bind_submission_checkpoint(setup.store, previous, checkpoint)
    prepared = store.prepare_round(**setup.options)
    retained_tables = (
        "submissions",
        "rounds",
        "round_preparations",
        "suite_usage",
        "public_schedule_usage",
        "evidence_cutoff_schedules",
        "promotions",
    )
    with sqlite3.connect(store.path) as db:
        before = {
            name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall()
            for name in retained_tables
        }
    checkpoint_before = store._submission_checkpoint.load()
    migrated = CompetitionStore(
        store.directory,
        setup.policy,
        public_launch=replacement,
        submission_head_checkpoint_directory=checkpoint,
        launch_amendment=signed,
        amendment_observed_block=200,
        migrate_writer_generation=True,
    )
    with sqlite3.connect(store.path) as db:
        assert before == {
            name: db.execute(f"SELECT * FROM {name} ORDER BY 1").fetchall()
            for name in retained_tables
        }
    assert (
        migrated.prepared_round(digest(setup.options["suite"]), setup.options["limits"]) == prepared
    )
    checkpoint_after = migrated._submission_checkpoint.load()
    assert checkpoint_after.submission_sha256s == checkpoint_before.submission_sha256s
    assert checkpoint_after.admission_record_sha256s == checkpoint_before.admission_record_sha256s
    assert checkpoint_after.public_launch_sha256 == digest(replacement)
    with pytest.raises(ValueError, match="stale public launch"):
        store.admit(submission(setup.policy, sequence=2), snapshot(201), 201)
    for retry in (False, True):
        kwargs = (
            dict(
                launch_amendment=signed,
                amendment_observed_block=200,
                migrate_writer_generation=True,
            )
            if retry
            else {}
        )
        reopened = CompetitionStore(
            store.directory,
            setup.policy,
            public_launch=replacement,
            submission_head_checkpoint_directory=checkpoint,
            **kwargs,
        )
        assert reopened.public_launch_amendments() == [
            signed.model_dump(mode="json", by_alias=True)
        ]


@pytest.mark.parametrize("effective", [190, 220])
def test_future_extension_requires_a_gap_after_prior_validity_before_next_roster(setup, effective):
    previous, replacement, signed = future_amendment(setup, effective=effective)
    with pytest.raises(ValueError, match="follow prior cohorts"):
        verify_launch_amendment(signed, previous, replacement, setup.policy)


@pytest.mark.parametrize(
    "change", ["shorter_phase", "earlier_roster", "shorter_cadence", "opening", "tracks", "quorum"]
)
def test_future_extension_rejects_shortening_or_changed_deal(setup, change):
    previous, replacement, signed = future_amendment(setup)
    schedule = replacement.round_schedule
    if change == "shorter_phase":
        replacement = replacement.model_copy(
            update={
                "round_schedule": schedule.model_copy(
                    update={"roster_close_latest_block": schedule.roster_close_earliest_block}
                )
            }
        )
    elif change == "earlier_roster":
        replacement = replacement.model_copy(
            update={
                "round_schedule": schedule.model_copy(update={"roster_close_earliest_block": 219})
            }
        )
    elif change == "shorter_cadence":
        replacement = replacement.model_copy(
            update={"round_stride_blocks": 99, "round_schedule": previous.schedule_for_cycle(1)}
        )
    elif change == "opening":
        replacement = replacement.model_copy(
            update={"round_schedule": schedule.model_copy(update={"intake_opened_block": 101})}
        )
    elif change == "tracks":
        replacement = replacement.model_copy(update={"eligible_tracks": ("endpoint",)})
    if change != "quorum":
        _, _, signed = future_amendment(setup, replacement=replacement)
    else:
        signed = signed.model_copy(update={"signatures": signed.signatures[:1]})
    with pytest.raises(ValueError):
        verify_launch_amendment(signed, previous, replacement, setup.policy)


def test_legacy_amendment_encoding_omits_future_scope(setup):
    previous, replacement = launch_pair(setup)
    signed = signed_amendment(setup.policy, previous, replacement)
    assert "first_replaced_cycle" not in signed.amendment.model_dump(mode="json", by_alias=True)
    verify_launch_amendment(signed, previous, replacement, setup.policy)


def test_future_extension_rejects_already_prepared_next_cohort_atomically(setup):
    previous, replacement, signed = future_amendment(setup)
    store = CompetitionStore(setup.store.directory, setup.policy, public_launch=previous)
    schedule = previous.schedule_for_cycle(1)
    store.prepare_round(
        **{
            **setup.options,
            "snapshot": snapshot(220),
            "public_schedule": schedule,
            "evaluation_close_block": 240,
            "reveal_block": 250,
            "evidence_cutoff_block": 260,
            "valid_through_block": 290,
        }
    )
    with sqlite3.connect(store.path) as db:
        before = tuple(db.iterdump())
    with pytest.raises(ValueError, match="prepared or active cohort"):
        CompetitionStore(
            store.directory,
            setup.policy,
            public_launch=replacement,
            launch_amendment=signed,
            amendment_observed_block=200,
            migrate_writer_generation=True,
        )
    with sqlite3.connect(store.path) as db:
        assert tuple(db.iterdump()) == before


def test_future_extension_cannot_be_applied_after_original_cutoff(setup):
    previous, replacement, _ = future_amendment(setup)
    fields = replacement.round_schedule.model_dump(mode="json", by_alias=True)
    fields = {
        key: value + 80 if key.endswith("_block") and key != "intake_opened_block" else value
        for key, value in fields.items()
    }
    replacement = replacement.model_copy(
        update={"round_schedule": type(replacement.round_schedule).model_validate(fields)}
    )
    _, _, signed = future_amendment(setup, replacement=replacement)
    store = CompetitionStore(setup.store.directory, setup.policy, public_launch=previous)
    with pytest.raises(ValueError, match="original roster application window"):
        CompetitionStore(
            store.directory,
            setup.policy,
            public_launch=replacement,
            launch_amendment=signed,
            amendment_observed_block=220,
            migrate_writer_generation=True,
        )
