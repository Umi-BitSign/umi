"""Retained consent replay after an outage, using the native registration archive."""

import json
from contextlib import closing

import pytest

from umi.competition_cohort_admission_review import review_cohort_participation
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_participation import CohortParticipationReceipt
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_intake import request_for
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_historical_registration import archive as archive
from .test_open_competition import policy as policy


@pytest.fixture
def accepted(archive, scenario, tmp_path):
    history = scenario["intake_history"]
    config = CohortIntakeConfig(
        directory=str(tmp_path / "intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=digest(history.plan),
                authority_sha256=digest(history.authority.authority),
            ),
        ),
    )
    intake = CohortIntake(config, scenario["policy"], initialize=True)
    intake.publish(history, archive.capture)
    request = request_for(scenario, block=archive.old.height)
    receipt = CohortParticipationReceipt.model_validate_json(
        canonical_json_bytes(intake.retain(request, archive.capture))
    )
    with intake._connection() as (db, _):
        ((_, raw),) = tuple(intake._records(db, history))
    return config, history, raw, receipt


async def test_restart_rechecks_original_consent_and_membership_after_four_hours(archive, accepted):
    config, history, raw, receipt = accepted
    intake = CohortIntake(config, archive.chain.policy)
    assert archive.old.height in intake.retained_registration_blocks()
    history = transition(
        history, archive.chain.policy, "extend", archive.fresh.height, extension=1200
    )
    result = await review_cohort_participation(
        raw, history, archive.chain.policy, archive.reviewer, expected_tip_sha256=tip(history)
    )
    assert result.admission == receipt.proposed_admission
    assert result.registration.snapshot == archive.capture.snapshot
    assert result.registration.replayed_at.block_number == archive.fresh.height
    assert result.admission.admitted_at_block == archive.old.height
    assert receipt.status == "pending_attestation"
    assert not hasattr(result, "signatures")


async def test_peer_uses_supplied_archive_and_its_own_header(archive, accepted):
    _, history, raw, receipt = accepted
    with closing(archive.reviewer._connect()) as db:
        db.execute("DELETE FROM captures")
        db.execute("DELETE FROM artifacts")
    result = await review_cohort_participation(
        raw,
        history,
        archive.chain.policy,
        archive.reviewer,
        expected_tip_sha256=tip(history),
        registration_archive=(archive.raw, archive.metadata),
    )
    assert result.admission == receipt.proposed_admission
    del archive.blocks[archive.old.height]
    with pytest.raises(FileNotFoundError, match=r"historical.*unavailable"):
        await review_cohort_participation(
            raw,
            history,
            archive.chain.policy,
            archive.reviewer,
            expected_tip_sha256=tip(history),
            registration_archive=(archive.raw, archive.metadata),
        )


@pytest.mark.parametrize(
    "failure",
    [
        "consent",
        "submission",
        "observation",
        "admission",
        "snapshot",
        "tip",
        "revoked",
        "invalidated_by_closure",
    ],
)
async def test_no_review_of_changed_consent_or_inconsistent_history(archive, accepted, failure):
    _, history, raw, _ = accepted
    body = json.loads(raw)
    expected_tip = tip(history)
    if failure == "consent":
        body["request"]["consent"]["consent"]["signed_at_block"] += 1
    elif failure == "submission":
        body["request"]["signed_submission"]["submission"]["sequence"] += 1
    elif failure == "observation":
        body["observation"]["evidence_sha256"] = "00" * 32
    elif failure == "admission":
        body["proposed_admission"]["uid"] = 1
    elif failure == "snapshot":
        body["snapshot"]["registrations"][0]["uid"] = 4
    elif failure == "tip":
        expected_tip = "00" * 32
    elif failure == "revoked":
        history = transition(history, archive.chain.policy, "revoke", archive.fresh.height)
        expected_tip = tip(history)
    elif failure == "invalidated_by_closure":
        history = transition(history, archive.chain.policy, "close_phase", archive.old.height - 1)
        expected_tip = tip(history)
    with pytest.raises(ValueError):
        await review_cohort_participation(
            canonical_json_bytes(body),
            history,
            archive.chain.policy,
            archive.reviewer,
            expected_tip_sha256=expected_tip,
        )
