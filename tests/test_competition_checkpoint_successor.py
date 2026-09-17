from __future__ import annotations

import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Event, get_ident
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_publication import PublicationReplayLimits
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore
from umi.competition_submission_checkpoint import (
    SubmissionCheckpointError,
    SubmissionHeadCheckpointFile,
)
from umi.open_competition import digest

from .test_competition_round_preparation import unpack
from .test_competition_settlement import (
    _independent,
    _launch,
    _record_all,
    _scenario,
    _settle,
    _successor,
)
from .test_open_competition import (
    bundle_at,
    result_for,
    round_for,
    snapshot,
    submission,
    suite_for,
)
from .test_open_competition import policy as policy


def _checkpointed_settled_scenario(policy, root):
    scenario = _scenario(policy, root)
    current = _launch(scenario.round)
    scenario.store = CompetitionStore(
        scenario.store.directory,
        scenario.policy,
        public_launch=current,
    )
    checkpoint = root / "submission-checkpoint"
    checkpoint.mkdir(mode=0o700)
    submission_ids = tuple(sorted(digest(item.submission) for item in scenario.submissions))
    scenario.store = CompetitionStore(
        scenario.store.directory,
        scenario.policy,
        public_launch=current,
        submission_head_checkpoint_directory=checkpoint,
        initial_checkpoint_submission_sha256s=submission_ids,
        initial_checkpoint_baseline_promotion_sha256=scenario.store.baseline_summary()[
            "promotion_sha256"
        ],
        initialize_submission_checkpoint=True,
    )
    _record_all(scenario)
    _settle(scenario)
    return scenario, current, checkpoint


def _checkpointed_open_scenario(policy, root):
    policy = policy.model_copy(update={"endpoint_reward_bps": 10_000, "model_reward_bps": 0})
    archive = root / "archive"
    baseline = bundle_at(root / "baseline")
    preserve_bundle(baseline, root / "baseline", archive, policy)
    store = CompetitionStore(root / "state", policy)
    store.initialize_baseline(baseline, archive)
    submissions = (submission(policy), submission(policy, name="Bob"))
    for signed in submissions:
        store.admit(signed, snapshot(), 110)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, submissions, digest(baseline))
    current = _launch(round_)
    store = CompetitionStore(store.directory, policy, public_launch=current)
    checkpoint = root / "submission-checkpoint"
    checkpoint.mkdir(mode=0o700)
    store = CompetitionStore(
        store.directory,
        policy,
        public_launch=current,
        submission_head_checkpoint_directory=checkpoint,
        initial_checkpoint_submission_sha256s=tuple(
            sorted(digest(item.submission) for item in submissions)
        ),
        initial_checkpoint_baseline_promotion_sha256=store.baseline_summary()["promotion_sha256"],
        initialize_submission_checkpoint=True,
    )
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    evidence = tuple(
        (
            signed,
            _independent(policy, signed, round_, suite, result_for(signed, round_, suite)),
        )
        for signed in submissions
    )
    return (
        SimpleNamespace(
            policy=policy,
            store=store,
            round=round_,
            suite=suite,
            schedule=schedule,
            submissions=submissions,
            evidence=evidence,
        ),
        current,
        checkpoint,
    )


def _open(scenario, launch, checkpoint):
    return CompetitionStore(
        scenario.store.directory,
        scenario.policy,
        public_launch=launch,
        submission_head_checkpoint_directory=checkpoint,
    )


def test_successor_checkpoint_rejects_database_launch_history_rollback(policy, tmp_path):
    scenario, current, checkpoint = _checkpointed_settled_scenario(policy, tmp_path)
    database = scenario.store.path
    before_successor = tmp_path / "before-successor.sqlite3"
    with sqlite3.connect(database) as source, sqlite3.connect(before_successor) as target:
        source.backup(target)

    successor = _successor(current)
    assert _open(scenario, successor, checkpoint).retained_submission_head()[
        "public_launch_sha256"
    ] == digest(successor)

    with sqlite3.connect(before_successor) as source, sqlite3.connect(database) as target:
        source.backup(target)
    with pytest.raises(SubmissionCheckpointError, match=r"launch|checkpoint"):
        _open(scenario, successor, checkpoint)


def test_successor_checkpoint_recovers_db_first_crash_without_changed_records(
    policy, tmp_path, monkeypatch
):
    scenario, current, checkpoint = _checkpointed_settled_scenario(policy, tmp_path)
    successor = _successor(current)
    original_replace = scenario.store._submission_checkpoint.replace

    def fail_successor_replace(_checkpoint_file, value):
        if value.public_launch_sha256 == digest(successor):
            raise SubmissionCheckpointError("simulated loss before successor checkpoint replace")
        original_replace(value)

    monkeypatch.setattr(
        "umi.competition_submission_checkpoint.SubmissionHeadCheckpointFile.replace",
        fail_successor_replace,
    )
    with pytest.raises(SubmissionCheckpointError, match="simulated loss"):
        _open(scenario, successor, checkpoint)

    monkeypatch.undo()
    recovered = _open(scenario, successor, checkpoint).retained_submission_head()
    assert recovered["public_launch_sha256"] == digest(successor)
    assert recovered["record_count"] == len(scenario.submissions)


def test_successor_rotation_serializes_against_old_launch_admission(policy, tmp_path, monkeypatch):
    scenario, current, checkpoint = _checkpointed_open_scenario(policy, tmp_path)
    successor = _successor(current)
    old_store = scenario.store
    admission_committed = Event()
    continue_admission = Event()
    successor_waiting_for_checkpoint = Event()
    successor_thread = {"ident": None}
    synchronization_calls = 0
    original_synchronize = old_store._synchronize_submission_checkpoint_locked
    original_locked = SubmissionHeadCheckpointFile.locked
    admitted = submission(scenario.policy, name="Alice", sequence=2, start=100, end=900)

    def pause_before_second_synchronization(**kwargs):
        nonlocal synchronization_calls
        synchronization_calls += 1
        if synchronization_calls == 2:
            admission_committed.set()
            assert continue_admission.wait(timeout=10)
        return original_synchronize(**kwargs)

    @contextmanager
    def observe_successor_lock(checkpoint_file):
        if get_ident() == successor_thread["ident"]:
            successor_waiting_for_checkpoint.set()
        with original_locked(checkpoint_file):
            yield

    def open_successor():
        successor_thread["ident"] = get_ident()
        return _open(scenario, successor, checkpoint)

    monkeypatch.setattr(
        old_store,
        "_synchronize_submission_checkpoint_locked",
        pause_before_second_synchronization,
    )
    monkeypatch.setattr(SubmissionHeadCheckpointFile, "locked", observe_successor_lock)
    with ThreadPoolExecutor(max_workers=2) as pool:
        admission_future = pool.submit(old_store.admit, admitted, snapshot(116), 116)
        assert admission_committed.wait(timeout=10)

        prepared = old_store.prepare_round(
            snapshot=snapshot(120),
            suite=scenario.suite,
            public_schedule=current.round_schedule,
            eligible_tracks=current.eligible_tracks,
            intake_opened_block=current.round_schedule.intake_opened_block,
            evaluation_close_block=current.round_schedule.evaluation_close_block,
            reveal_block=current.round_schedule.protected_reference_reveal_block,
            evidence_cutoff_block=current.round_schedule.evidence_cutoff_block,
            valid_through_block=current.round_schedule.round_valid_through_block,
            limits=PublicationReplayLimits(
                maximum_roster_bytes=1_000_000,
                maximum_evidence_bytes=1_000_000,
                maximum_certificate_bytes=2_000_000,
            ),
        )
        scenario.round, scenario.schedule, scenario.submissions = unpack(prepared)
        scenario.evidence = tuple(
            (
                signed,
                _independent(
                    scenario.policy,
                    signed,
                    scenario.round,
                    scenario.suite,
                    result_for(signed, scenario.round, scenario.suite),
                ),
            )
            for signed in scenario.submissions
        )
        old_store.close_round(scenario.round, current_block=125)
        _record_all(scenario)
        _settle(scenario)

        successor_future = pool.submit(open_successor)
        assert successor_waiting_for_checkpoint.wait(timeout=10)
        continue_admission.set()
        admission = admission_future.result(timeout=10)
        advanced = successor_future.result(timeout=10)

    assert admission["submission_sha256"] == digest(admitted.submission)
    head = advanced.retained_submission_head()
    assert head["public_launch_sha256"] == digest(successor)
    assert head["record_count"] == len(scenario.submissions) + 1
