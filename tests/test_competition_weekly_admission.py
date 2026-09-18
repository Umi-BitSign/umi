"""Seven-day intake must not strand opening-day signed submissions."""

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_launch import PublicRoundSchedule
from umi.competition_publication import PublicationReplayLimits, build_cutoff_publication
from umi.competition_store import CompetitionStore
from umi.open_competition import CompetitionPolicy, digest
from umi.protocol import canonical_json_bytes

from .test_competition_round_preparation import unpack
from .test_open_competition import bundle_at, snapshot, submission, suite_for
from .test_open_competition import policy as policy

OPEN = 100
CLOSE = OPEN + 50_400
EVALUATION_CLOSE = CLOSE + 100


def weekly_policy(policy, lifetime):
    body = policy.model_dump(mode="json", by_alias=True)
    body.update(
        valid_through_block=EVALUATION_CLOSE + 100,
        maximum_submission_lifetime_blocks=lifetime,
    )
    return CompetitionPolicy.model_validate_json(canonical_json_bytes(body))


@pytest.mark.parametrize("track", ["endpoint", "model"])
@pytest.mark.parametrize("early_end", [OPEN + 7_200, EVALUATION_CLOSE - 1, EVALUATION_CLOSE])
def test_weekly_roster_requires_validity_through_evaluation(policy, tmp_path, track, early_end):
    policy = weekly_policy(policy, EVALUATION_CLOSE - OPEN)
    baseline = bundle_at(tmp_path / "baseline")
    archive = tmp_path / "archive"
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    store = CompetitionStore(tmp_path / "state", policy)
    store.initialize_baseline(baseline, archive)
    model = baseline if track == "model" else None
    early = submission(policy, bundle=model, start=OPEN, end=early_end)
    late = submission(policy, bundle=model, name="Bob", start=CLOSE - 1, end=EVALUATION_CLOSE)
    store.admit(early, snapshot(OPEN), OPEN)
    store.admit(late, snapshot(CLOSE - 1), CLOSE - 1)
    options = dict(
        snapshot=snapshot(CLOSE),
        suite=suite_for(policy),
        public_schedule=PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=OPEN,
            roster_close_earliest_block=CLOSE,
            roster_close_latest_block=CLOSE,
            work_signing_close_block=CLOSE + 50,
            evaluation_close_block=EVALUATION_CLOSE,
            protected_reference_reveal_block=EVALUATION_CLOSE + 10,
            evidence_cutoff_block=EVALUATION_CLOSE + 20,
            round_valid_through_block=EVALUATION_CLOSE + 50,
        ),
        eligible_tracks=(track,),
        intake_opened_block=OPEN,
        evaluation_close_block=EVALUATION_CLOSE,
        reveal_block=EVALUATION_CLOSE + 10,
        evidence_cutoff_block=EVALUATION_CLOSE + 20,
        valid_through_block=EVALUATION_CLOSE + 50,
        limits=PublicationReplayLimits(
            maximum_roster_bytes=1_000_000,
            maximum_evidence_bytes=1_000_000,
            maximum_certificate_bytes=2_000_000,
        ),
    )
    result = store.prepare_round(**options)
    round_, cutoff, roster = unpack(result)
    expected = [digest(late.submission)]
    if early_end == EVALUATION_CLOSE:
        expected.append(digest(early.submission))
    assert round_.roster == tuple(sorted(expected))
    assert len(store.submissions()) == 2  # Exclusion never erases admission evidence.
    replay = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=cutoff,
        submissions=roster,
        registration_snapshot=options["snapshot"],
        policy=policy,
        limits=options["limits"],
    )
    assert replay.model_dump(mode="json", by_alias=True) == result["cutoff_publication"]


def test_one_day_policy_rejects_week_long_signature_even_with_later_policy_expiry(policy, tmp_path):
    policy = weekly_policy(policy, 7_200)
    store = CompetitionStore(tmp_path / "state", policy)
    signed = submission(policy, start=OPEN, end=EVALUATION_CLOSE)
    with pytest.raises(ValueError, match="submission lifetime is outside the policy"):
        store.admit(signed, snapshot(OPEN), OPEN)
    assert store.submissions() == []
