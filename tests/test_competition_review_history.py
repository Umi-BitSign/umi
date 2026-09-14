from __future__ import annotations

import pytest

from umi.competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    build_cutoff_publication,
    sign_cutoff_publication,
)
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import AdmissionCapacity, AdmissionCapacityError, CompetitionStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import policy as policy
from .test_open_competition import scenario as scenario
from .test_open_competition import snapshot, wallet
from .test_promotion_agreement import agreed_review, promote


@pytest.fixture
def setup(scenario, tmp_path):
    s = scenario
    s.limits = PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_certificate_bytes=4_000_000,
        maximum_evidence_bytes=5_000_000,
    )
    s.roster = tuple(sorted((s.model, s.endpoint), key=lambda v: digest(v.submission)))
    s.cutoff_snapshot = snapshot(s.round.submission_close_block)
    body = build_cutoff_publication(
        policy=s.policy,
        round_=s.round,
        submissions=s.roster,
        registration_snapshot=s.cutoff_snapshot,
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(s.policy),
            round_sha256=digest(s.round),
            evidence_cutoff_block=s.round.reveal_block + 5,
        ),
        limits=s.limits,
    )
    s.cutoff = attest(body)
    s.reviews = EvaluatorReviewStore(tmp_path / "reviews", s.policy, limits=s.limits)
    s.reviews.initialize_baseline(s.baseline, s.archive)
    return s


def attest(body):
    return SignedCutoffPublication(
        publication=body,
        signatures=tuple(sign_cutoff_publication(body, wallet(n)) for n in ("Charlie", "Dave")),
    )


def observe(s, *, block=None, certificate=None, roster=None, snapshot_=None):
    return s.reviews.observe_cutoff(
        certificate or s.cutoff,
        s.roster if roster is None else roster,
        snapshot=s.cutoff_snapshot if snapshot_ is None else snapshot_,
        observed_block=s.round.submission_close_block + 1 if block is None else block,
    )


def test_receives_history_at_actual_block_without_backdating_admission(setup):
    s = setup
    actual = observe(s)
    assert actual > s.round.submission_close_block
    assert len(s.reviews.submissions()) == 2
    for entry in s.reviews.submissions():
        receipt = entry["receipt"]
        assert receipt["first_observed_block"] == actual
        assert receipt["admission_timing_proven"] is False
        assert "accepted_block" not in receipt
    s.reviews = EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    assert observe(s, block=s.round.valid_through_block) == actual
    reversed_certificate = s.cutoff.model_copy(
        update={"signatures": tuple(reversed(s.cutoff.signatures))}
    )
    assert observe(s, certificate=reversed_certificate) == actual
    with s.reviews._connection() as c:
        assert c.execute("SELECT COUNT(*) FROM reviewed_cutoffs").fetchone() == (1,)


def test_reviewed_history_supports_actual_promotion_and_restart(setup):
    s = setup
    observe(s)
    review = agreed_review(s)
    first = promote(s, s.store, review, 150)
    second = promote(s, s.reviews, review, 153)
    assert first == second
    reopened = EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    assert reopened.baseline() == first
    assert reopened.reviewed_promotion_head(digest(s.round), maximum_bytes=8_000_000).sequence == 1


def test_roles_cannot_be_reinterpreted_or_used_for_new_intake(setup):
    s = setup
    with pytest.raises(ValueError, match="store role"):
        CompetitionStore(s.reviews.directory, s.policy)
    with pytest.raises(ValueError, match="store role"):
        EvaluatorReviewStore(s.store.directory, s.policy, limits=s.limits)
    with pytest.raises(ValueError, match="intake operations"):
        s.reviews.admit(s.model, s.cutoff_snapshot, s.cutoff_snapshot.block)
    with pytest.raises(ValueError, match="intake operations"):
        s.reviews.close_round(s.round, current_block=s.cutoff_snapshot.block)


@pytest.mark.parametrize("bad", ["missing_quorum", "roster", "snapshot", "late", "early"])
def test_invalid_delivery_creates_no_history(setup, bad):
    s = setup
    opts = {}
    if bad == "missing_quorum":
        opts["certificate"] = s.cutoff.model_copy(update={"signatures": s.cutoff.signatures[:1]})
    elif bad == "roster":
        opts["roster"] = s.roster[:1]
    elif bad == "snapshot":
        opts["snapshot_"] = s.cutoff_snapshot.model_copy(update={"registrations": ()})
    elif bad == "late":
        opts["block"] = s.round.evaluation_close_block
    else:
        opts["block"] = s.round.submission_close_block - 1
    with pytest.raises(ValueError):
        observe(s, **opts)
    assert not s.reviews.submissions()
    with s.reviews._connection() as c:
        assert c.execute("SELECT COUNT(*) FROM rounds").fetchone() == (0,)


def test_changed_cutoff_and_capacity_failure_preserve_first_state(setup, tmp_path):
    s = setup
    observe(s)
    changed = s.cutoff.publication.model_copy(
        update={
            "cutoff_schedule": s.cutoff.publication.cutoff_schedule.model_copy(
                update={"evidence_cutoff_block": s.round.reveal_block + 6}
            )
        }
    )
    with pytest.raises(ValueError, match="original decision"):
        observe(s, certificate=attest(changed))
    s.reviews = EvaluatorReviewStore(
        tmp_path / "small-reviews",
        s.policy,
        limits=s.limits,
        admission_capacity=AdmissionCapacity(maximum_records=1),
    )
    s.reviews.initialize_baseline(s.baseline, s.archive)
    with pytest.raises(AdmissionCapacityError):
        observe(s)
    assert not s.reviews.submissions()
    assert s.reviews.admission_capacity_status()["records"] == 0


@pytest.mark.parametrize(
    "bad", ["missing", "oversized", "round", "submission", "observed", "clock"]
)
def test_corrupt_receipt_holds_restart_and_live_signer_reads(setup, bad):
    s = setup
    observe(s)
    with s.reviews._transaction() as c:
        if bad == "missing":
            c.execute("DELETE FROM reviewed_cutoffs")
        elif bad == "oversized":
            c.execute(
                "UPDATE reviewed_cutoffs SET body=?", (b"x" * (s.reviews.maximum_cutoff_bytes + 1),)
            )
        elif bad == "round":
            c.execute("UPDATE rounds SET body=?", (canonical_json_bytes({}),))
        elif bad == "submission":
            c.execute("UPDATE submissions SET body=?", (canonical_json_bytes({}),))
        elif bad == "observed":
            c.execute("UPDATE reviewed_cutoffs SET observed_block=1")
        else:
            c.execute("UPDATE metadata SET value='1' WHERE key='observed_block'")
    with pytest.raises(ValueError):
        EvaluatorReviewStore(s.reviews.directory, s.policy, limits=s.limits)
    with pytest.raises(ValueError):
        s.reviews.reviewed_promotion_head(digest(s.round), maximum_bytes=8_000_000)


def test_cli_initializes_review_baseline_without_importing_admissions(setup, tmp_path):
    from umi.competition_cli import _parser, execute

    s = setup
    paths = {}
    for name, value in (("policy", s.policy), ("manifest", s.baseline), ("limits", s.limits)):
        path = tmp_path / (name + ".json")
        path.write_bytes(canonical_json_bytes(value))
        paths[name] = str(path)
    directory = tmp_path / "cli-review"
    result = execute(
        _parser().parse_args(
            [
                "--policy",
                paths["policy"],
                "initialize-baseline",
                "--state",
                str(directory),
                "--manifest",
                paths["manifest"],
                "--archive",
                str(s.archive),
                "--evaluator-review-limits",
                paths["limits"],
            ]
        )
    )
    assert result["contributor_hotkey"] is None
    store = EvaluatorReviewStore(directory, s.policy, limits=s.limits)
    assert store.baseline() == result and not store.submissions()
