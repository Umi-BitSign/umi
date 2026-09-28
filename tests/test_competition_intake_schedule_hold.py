"""A setup hold preserves open intake without inventing another cohort."""

from dataclasses import replace

import pytest
from fastapi.testclient import TestClient

from umi.competition_launch import IntakeScheduleHold, PublicIntakeDeployment, PublicRoundSchedule
from umi.open_competition import digest
from umi.policy import umi_source_tree_sha256
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_service import app_for
from .test_competition_service import config as config
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, submission


@pytest.fixture
def public_deployment():
    return PublicIntakeDeployment(
        schema="umi-competition-intake-deployment/3",
        repository="https://github.com/Umi-BitSign/umi",
        umi_git_revision="12" * 20,
        umi_source_tree_sha256=umi_source_tree_sha256(),
        deployed_at_utc="2026-09-25T18:00:00Z",
        round_schedule=PublicRoundSchedule(
            schema="umi-public-round-schedule/1",
            intake_opened_block=105,
            roster_close_earliest_block=130,
            roster_close_latest_block=130,
            work_signing_close_block=140,
            evaluation_close_block=150,
            protected_reference_reveal_block=160,
            evidence_cutoff_block=170,
            round_valid_through_block=180,
        ),
        eligible_tracks=("endpoint",),
        assignment_delivery_ready=False,
        model_intake_ready=False,
        round_stride_blocks=100,
        intake_schedule_hold=IntakeScheduleHold(
            schema="umi-competition-intake-schedule-hold/1", cohort_number=5
        ),
    )


def set_provider_block(provider, block):
    current = snapshot(block=block)
    provider.capture = replace(
        provider.capture,
        snapshot=current,
        provenance={
            **provider.capture.provenance,
            "block": block,
            "block_hash": current.block_hash,
            "snapshot_sha256": digest(current),
        },
    )


def test_hold_survives_elapsed_cycles_restart_and_real_admission(config, policy):
    signed = submission(policy)
    receipt = None
    retained_record = None
    for block in (110, 240, 840):
        app, provider = app_for(config, policy)
        set_provider_block(provider, block)
        with TestClient(app) as client:
            for path in ("status", "readiness"):
                response = client.get("/v1/competition/" + path)
                assert response.status_code == 200, response.text
                data = response.json()
                assert data["admission_accepting_new"] is True
                assert data["continuous_intake"] is True
                assert data["next_intake_schedule"] is None
                assert data["intake_schedule_hold"]["cohort_number"] == 5
                assert data["intake_schedule_hold"]["submission_close_block"] is None
                assert data["evaluation_ready"] is False
                assert data["retained_submission_head"]["public_launch_sha256"] == digest(
                    config.public_deployment.launch_identity()
                )
                assert response.headers["cache-control"] == "no-store"
            if receipt is None:
                response = client.post(
                    "/v1/competition/submissions",
                    content=canonical_json_bytes(signed),
                    headers={"content-type": "application/json"},
                )
                assert response.status_code == 200, response.text
                receipt = response.json()
                assert receipt["status"] == "accepted_no_weight"
            stored = client.get("/v1/competition/submissions/" + digest(signed.submission))
            assert stored.status_code == 200, stored.text
            if retained_record is None:
                retained_record = stored.json()
            assert stored.json() == retained_record
            assert client.get("/v1/competition/status").json()["accepted_submission_count"] == 2
        assert provider.closed


@pytest.mark.parametrize("block,readiness_status", [(104, 200), (1001, 503)])
def test_hold_does_not_override_policy_or_intake_opening(config, policy, block, readiness_status):
    app, provider = app_for(config, policy)
    set_provider_block(provider, block)
    with TestClient(app) as client:
        status = client.get("/v1/competition/status")
        assert status.status_code == 200
        assert status.json()["admission_accepting_new"] is False
        assert status.json()["next_intake_schedule"] is None
        readiness = client.get("/v1/competition/readiness")
        assert readiness.status_code == readiness_status
        if readiness_status == 200:
            assert readiness.json()["admission_accepting_new"] is False
            assert readiness.json()["next_intake_schedule"] is None
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy)),
            headers={"content-type": "application/json"},
        )
        assert response.status_code != 200


def test_hold_preserves_signed_launch_and_legacy_deployment_bytes(public_deployment):
    held = public_deployment
    unheld = PublicIntakeDeployment.model_validate(
        {
            **held.model_dump(by_alias=True),
            "intake_schedule_hold": None,
        }
    )
    assert canonical_json_bytes(held.launch_identity()) == canonical_json_bytes(
        unheld.launch_identity()
    )
    assert "intake_schedule_hold" not in unheld.model_dump(by_alias=True)
    assert held.next_intake_schedule(840) is None
    assert unheld.next_intake_schedule(840).roster_close_earliest_block == 930


@pytest.mark.parametrize(
    "changes",
    [
        {"evaluation_ready": True, "assignment_delivery_ready": True},
        {"schema": "umi-competition-intake-deployment/2", "round_stride_blocks": None},
    ],
)
def test_hold_cannot_claim_evaluation_readiness_or_extend_single_round(public_deployment, changes):
    with pytest.raises(ValueError, match="schedule hold requires"):
        PublicIntakeDeployment.model_validate(
            {
                **public_deployment.model_dump(by_alias=True),
                **changes,
            }
        )
