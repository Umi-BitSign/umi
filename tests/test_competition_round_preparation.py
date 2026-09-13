from __future__ import annotations

import json
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_publication import PublicationReplayLimits, build_cutoff_publication
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore, RoundPreparationCapacity
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
        for table in ("round_preparations", "rounds", "suite_usage", "evidence_cutoff_schedules"):
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
        with pytest.raises(ValueError, match="frozen round window"):
            setup.store.prepare_round(**{**setup.options, name: setup.options[name] + 1})


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
    "mode", ["roster", "receipt", "authority", "noncanonical", "round", "schedule", "usage"]
)
def test_corrupt_retained_preparation_is_never_reused(setup, mode):
    setup.store.prepare_round(**setup.options)
    with sqlite3.connect(setup.store.path) as db:
        if mode in {"round", "schedule", "usage"}:
            table = {
                "round": "rounds",
                "schedule": "evidence_cutoff_schedules",
                "usage": "suite_usage",
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
            body = raw + b" " if mode == "noncanonical" else canonical_json_bytes(data)
            db.execute("UPDATE round_preparations SET body=?", (body,))
    with pytest.raises(ValueError):
        setup.store.prepare_round(**setup.options)
