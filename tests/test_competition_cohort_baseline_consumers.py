"""Independent history consumption; source finality and inference are fixtures."""

import pytest

from umi import competition_store
from umi.competition_publication import PublicationReplayLimits, build_cutoff_publication
from umi.competition_review_history import EvaluatorReviewStore
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_baseline_history import (
    base_policy as base_policy,
)
from .test_competition_cohort_baseline_history import (
    certify,
)
from .test_competition_cohort_baseline_history import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_baseline_history import (
    model_case as model_case,
)
from .test_competition_cohort_baseline_history import (
    model_parent_context as model_parent_context,
)
from .test_competition_cohort_baseline_history import (
    policy as policy,
)
from .test_competition_cohort_baseline_history import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_baseline_history import (
    recovery as recovery,
)
from .test_competition_cohort_baseline_history import (
    retained_case as retained_case,
)
from .test_competition_cohort_baseline_history import (
    review_case as review_case,
)
from .test_competition_cohort_baseline_history import (
    runtime as runtime,
)
from .test_competition_review_history import attest
from .test_competition_two_task_profile import launch_suite
from .test_open_competition import round_for, snapshot

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("model_case", [("best", 2)], indirect=True),
]


@pytest.mark.parametrize("model_parent_context", [None, "89" * 32], indirect=True)
def test_independent_review_history_accepts_winner_without_intake_authority(
    retained_case, model_case, tmp_path, monkeypatch
):
    source, review, _, b = retained_case
    archive = model_case[-1]
    original = b["scenarios"][0]["artifacts"][0].job.incumbent
    limits = PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_evidence_bytes=1_000_000,
        maximum_certificate_bytes=1_000_000,
    )
    peer = EvaluatorReviewStore(tmp_path / "independent-history", source.policy, limits=limits)
    peer.initialize_baseline(original, archive)
    certificate = certify(review)
    signed_bytes = canonical_json_bytes(certificate)

    def no_payload(*args, **kwargs):
        raise AssertionError("reviewed winner history must reuse completed model verification")

    monkeypatch.setattr(competition_store, "verify_preserved_bundle", no_payload)
    expected = source.apply_cohort_baseline(certificate, observed_block=230)
    actual = peer.apply_cohort_baseline(certificate, observed_block=231)
    assert actual == expected
    assert canonical_json_bytes(certificate) == signed_bytes
    assert actual["schema"] == "umi-model-baseline/4"
    assert actual["contributor_hotkey"] == review.candidate.contributor_hotkey

    member = b["roster"].participants[0].record
    signed = member.request.signed_submission
    suite = launch_suite(source.policy)
    future = round_for(source.policy, suite, (signed,), digest(review.model))
    schedule = future.public_schedule.model_copy(
        update={
            name: value + 200
            for name, value in future.public_schedule.model_dump().items()
            if name.endswith("_block")
        }
    )
    future = future.model_copy(
        update={
            "public_schedule": schedule,
            "eligible_tracks": ("model",),
            "submission_close_block": 320,
            "evaluation_close_block": 340,
            "reveal_block": 350,
            "valid_through_block": 400,
        }
    )
    # A promotion receipt must not bypass this role's independent roster proof.
    with pytest.raises(ValueError, match="review cutoff receipt missing"):
        peer.reviewed_promotion_head(digest(future), maximum_bytes=1_000_000)
    registration = snapshot(320)
    cutoff = build_cutoff_publication(
        policy=source.policy,
        round_=future,
        submissions=(signed,),
        registration_snapshot=registration,
        cutoff_schedule=EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(source.policy),
            round_sha256=digest(future),
            evidence_cutoff_block=360,
        ),
        limits=limits,
    )
    peer.observe_cutoff(attest(cutoff), (signed,), snapshot=registration, observed_block=321)
    reopened = EvaluatorReviewStore(peer.directory, source.policy, limits=limits)
    selected = reopened.reviewed_promotion_head(digest(future), maximum_bytes=1_000_000)
    assert selected.model_sha256 == digest(review.model)
    assert selected.sequence == review.previous.sequence + 1
    assert (
        reopened.reviewed_promotion_at(
            digest(future),
            review.previous.promotion_sha256,
            maximum_bytes=1_000_000,
        )
        == review.previous
    )

    def no_observation():
        raise AssertionError("a completed retry must retain its original observation")

    assert reopened.apply_cohort_baseline(certificate, observed_block=no_observation) == expected
    with pytest.raises(ValueError, match="cannot authorize intake operations"):
        reopened.admit(member.request.signed_submission, member.snapshot, member.snapshot.block)
