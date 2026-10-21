"""Native retained-store append/restart; inference and source finality are fixtures."""

import json
import logging
import sqlite3

import pytest

from umi import competition_store
from umi.competition_launch import PublicLaunchIdentity, PublicRoundSchedule
from umi.competition_runtime_port import baseline_record_digest
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_baseline_review import (
    base_policy as base_policy,
)
from .test_competition_cohort_baseline_review import (
    certify,
)
from .test_competition_cohort_baseline_review import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_baseline_review import (
    model_case as model_case,
)
from .test_competition_cohort_baseline_review import (
    model_parent_context as model_parent_context,
)
from .test_competition_cohort_baseline_review import (
    policy as policy,
)
from .test_competition_cohort_baseline_review import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_baseline_review import (
    recovery as recovery,
)
from .test_competition_cohort_baseline_review import (
    review_case as review_case,
)
from .test_competition_cohort_baseline_review import (
    runtime as runtime,
)
from .test_open_competition import round_for, snapshot, submission, suite_for

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("model_case", [("best", 2)], indirect=True),
]


@pytest.fixture
def retained_case(review_case, model_case, tmp_path):
    policy, review = review_case
    b, _, _, _, archive = model_case
    original = b["scenarios"][0]["artifacts"][0].job.incumbent
    store = CompetitionStore(tmp_path / "promotion-state", policy)
    baseline = store.initialize_baseline(original, archive)
    previous = store.reviewed_promotion_head(review.candidate.round_sha256, maximum_bytes=1_000_000)
    review = review.model_copy(update={"previous": previous})
    return store, review, baseline, b


def apply(store, review, **options):
    return store.apply_cohort_baseline(certify(review), observed_block=options.get("block", 230))


def test_certified_winner_is_not_blocked_by_unused_continuous_calendar(retained_case):
    store, review, baseline, _ = retained_case
    launch = PublicLaunchIdentity(
        schema="umi-competition-public-launch/2",
        eligible_tracks=("model",),
        round_stride_blocks=200,
        round_schedule=PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=100,
            roster_close_earliest_block=150,
            roster_close_latest_block=151,
            work_signing_close_block=160,
            evaluation_close_block=180,
            protected_reference_reveal_block=190,
            evidence_cutoff_block=200,
            round_valid_through_block=300,
        ),
    )
    store = CompetitionStore(store.directory, store.policy, public_launch=launch)
    record = apply(store, review)
    assert record["previous_promotion_sha256"] == baseline_record_digest(baseline)
    reopened = CompetitionStore(store.directory, store.policy, public_launch=launch)
    assert reopened.baseline() == record
    assert reopened.public_launch == launch
    assert reopened.cohort_baseline_application_status(certify(review)) == "completed"


def test_actual_retained_round_still_blocks_certified_winner(retained_case):
    store, review, baseline, batch = retained_case
    original = batch["scenarios"][0]["artifacts"][0].job.incumbent
    signed = submission(store.policy)
    store.admit(signed, snapshot(), 110)
    round_ = round_for(store.policy, suite_for(store.policy), (signed,), digest(original))
    round_ = round_.model_copy(
        update={
            "valid_through_block": 300,
            "public_schedule": round_.public_schedule.model_copy(
                update={"round_valid_through_block": 300}
            ),
        }
    )
    store.close_round(round_, current_block=round_.submission_close_block)
    before = rows(store)
    with pytest.raises(ValueError, match="during a retained round"):
        apply(store, review)
    assert rows(store) == before and store.baseline() == baseline


def rows(store):
    with store._connection() as connection:
        return {
            table: connection.execute(f"SELECT * FROM {table}").fetchall()
            for table in ("submissions", "promotions", "model_identities")
        }


@pytest.mark.parametrize("model_parent_context", [None, "89" * 32], indirect=True)
def test_native_winner_history_reopens_and_repeats_without_payloads(
    retained_case, monkeypatch, caplog
):
    store, review, baseline, _ = retained_case
    before = rows(store)

    def no_payload(*args, **kwargs):
        raise AssertionError("reviewed winner metadata must not rehash retained model payloads")

    monkeypatch.setattr(competition_store, "verify_preserved_bundle", no_payload)
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    record = apply(store, review)
    assert record["previous_promotion_sha256"] == baseline_record_digest(baseline)
    assert record["model_sha256"] == review.candidate.model_sha256
    assert record["contributor_hotkey"] == review.candidate.contributor_hotkey
    assert rows(store)["submissions"] == before["submissions"]
    assert rows(store)["promotions"][:1] == before["promotions"]
    reopened = CompetitionStore(store.directory, store.policy)
    assert reopened.baseline() == record
    head = reopened.reviewed_promotion_head(review.candidate.round_sha256, maximum_bytes=1_000_000)
    assert head.model_sha256 == digest(review.model)
    old_head = reopened.reviewed_promotion_at(
        review.candidate.round_sha256, baseline_record_digest(baseline), maximum_bytes=1_000_000
    )
    assert old_head == review.previous

    def no_observation():
        raise AssertionError("completed append retry must reuse the original observation")

    assert (
        reopened.apply_cohort_baseline(
            certify(review, ("Dave", "Charlie")), observed_block=no_observation
        )
        == record
    )
    assert rows(reopened)["promotions"] == rows(store)["promotions"]
    with reopened._connection() as connection:
        receipt = json.loads(
            connection.execute(
                "SELECT value FROM metadata WHERE key='cohort_baseline_receipt:1'"
            ).fetchone()[0]
        )
    assert receipt["observed_block"] == 230
    assert receipt["certificate"]["review"]["model"] == review.model.model_dump(
        mode="json", by_alias=True
    )
    events = [
        json.loads(r.message)
        for r in caplog.records
        if r.name == "umi.competition.progress"
        and json.loads(r.message).get("stage") == "cohort_baseline_history_append"
    ]
    assert events[0]["planning_eta_seconds"] == [0.001, 30]
    assert events[-1]["completed_units"] == events[-1]["total_units"] == 1
    assert events[-1]["status"] == "completed"
    assert events[-1]["eta_seconds"] == 0
    assert events[-1]["elapsed_seconds"] >= 0


def test_winner_transition_preserves_retained_signed_submissions_and_anchor(retained_case):
    store, review, baseline, b = retained_case
    for participant in b["roster"].participants:
        store.admit(
            participant.record.request.signed_submission,
            participant.record.snapshot,
            participant.record.snapshot.block,
        )
    required = tuple(
        sorted(
            digest(p.record.request.signed_submission.submission) for p in b["roster"].participants
        )
    )
    store.verify_retained_intake_state(
        baseline_promotion_sha256=baseline_record_digest(baseline),
        required_submission_sha256s=required,
    )
    with store._connection() as connection:
        original_anchor = connection.execute(
            "SELECT value FROM metadata WHERE key='retained_intake_anchor'"
        ).fetchone()[0]
    original_submissions = rows(store)["submissions"]
    record = apply(store, review)
    reopened = CompetitionStore(store.directory, store.policy)
    reopened.verify_retained_intake_state(
        baseline_promotion_sha256=baseline_record_digest(record),
        required_submission_sha256s=required,
    )
    assert rows(reopened)["submissions"] == original_submissions
    with reopened._connection() as connection:
        assert connection.execute(
            "SELECT value FROM metadata WHERE key='cohort_baseline_prior_intake_anchor:1'"
        ).fetchone() == (original_anchor,)


@pytest.mark.parametrize("change", ["before", "after", "boolean", "parent", "quorum"])
def test_refused_transition_is_atomic(retained_case, change):
    store, review, baseline, _ = retained_case
    before = rows(store)
    block = {"before": 219, "after": 251, "boolean": True}.get(change, 230)
    if change == "parent":
        review = review.model_copy(
            update={"previous": review.previous.model_copy(update={"promotion_sha256": "99" * 32})}
        )
    certificate = certify(review, ("Charlie",) if change == "quorum" else ("Charlie", "Dave"))
    with pytest.raises(ValueError):
        store.apply_cohort_baseline(certificate, observed_block=block)
    assert rows(store) == before
    assert store.baseline() == baseline


def test_already_open_old_writer_is_fenced(retained_case):
    store, review, _, _ = retained_case
    old = sqlite3.connect(store.path)
    old.create_function("umi_writer_generation", 0, lambda: 2)
    old.create_function("umi_submission_checkpoint_binding", 0, lambda: None)
    old.create_function("umi_runtime_port_writer", 0, lambda: 1)
    try:
        apply(store, review)
        with pytest.raises(sqlite3.OperationalError, match="umi_cohort_baseline_writer"):
            old.execute("INSERT INTO metadata VALUES ('old-writer-probe','1')")
        old.rollback()
    finally:
        old.close()
    assert (
        CompetitionStore(store.directory, store.policy).baseline()["schema"]
        == "umi-model-baseline/4"
    )


@pytest.mark.parametrize("damage", ["missing_receipt", "changed_receipt", "missing_fence"])
def test_retained_damage_requires_repair_instead_of_silent_reverification(retained_case, damage):
    store, review, _, _ = retained_case
    apply(store, review)
    with store._transaction() as connection:
        if damage == "missing_receipt":
            connection.execute("DELETE FROM metadata WHERE key='cohort_baseline_receipt:1'")
        elif damage == "changed_receipt":
            raw = json.loads(
                connection.execute(
                    "SELECT value FROM metadata WHERE key='cohort_baseline_receipt:1'"
                ).fetchone()[0]
            )
            raw["certificate"]["review"]["candidate"]["rights_evidence_sha256"] = "99" * 32
            connection.execute(
                "UPDATE metadata SET value=? WHERE key='cohort_baseline_receipt:1'",
                (canonical_json_bytes(raw).decode(),),
            )
        else:
            connection.execute("DELETE FROM metadata WHERE key='cohort_baseline_writer'")
    with pytest.raises(ValueError):
        CompetitionStore(store.directory, store.policy)
