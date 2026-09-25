"""Check continuous API schedules against the deployment and observed block."""

import copy

import pytest

from umi.competition_launch import PublicIntakeDeployment
from umi.protocol import canonical_json_bytes
from umi.public_intake_monitor import (
    PublicIntakeMonitorError,
    _validate_status_readiness,
    parse_readiness,
    parse_status,
)

from .test_public_intake_monitor import chain_config as chain_config
from .test_public_intake_monitor import intake_scenario as intake_scenario
from .test_public_intake_monitor import policy as policy
from .test_public_intake_monitor import public_deployment as public_deployment
from .test_public_intake_monitor import service_config as service_config


def continuous(scenario, phase="open"):
    capture = copy.deepcopy(scenario.capture)
    doc = dict(
        capture.status["deployment"],
        schema="umi-competition-intake-deployment/3",
        round_stride_blocks=100,
    )
    deployment = PublicIntakeDeployment.model_validate_json(canonical_json_bytes(doc))
    schedule = deployment.round_schedule
    block = schedule.roster_close_latest_block + 1
    if phase == "not_open":
        block = schedule.intake_opened_block - 1
    elif phase == "closed":
        block = scenario.policy.valid_through_block + 1
    accepting = phase == "open"
    next_schedule = (
        deployment.launch_identity()
        .next_intake_schedule(block)
        .model_dump(mode="json", by_alias=True)
        if accepting
        else None
    )
    for status in (capture.status_before, capture.status):
        status.update(
            deployment=doc,
            continuous_intake=True,
            next_intake_schedule=next_schedule,
            admission_checked_block=block,
            admission_accepting_new=accepting,
            admission_phase=phase,
            admission_capacity_available=phase != "capacity_exhausted",
        )
    for readiness in (capture.readiness_before, capture.readiness):
        readiness.update(
            deployment=doc,
            continuous_intake=True,
            next_intake_schedule=next_schedule,
            admission_checked_block=block,
            admission_accepting_new=accepting,
            admission_phase=phase,
            ready_for=(
                "first_round_intake_not_open"
                if phase == "not_open"
                else "first_round_intake_closed"
                if phase == "closed"
                else "continuous_intake"
            ),
        )
        readiness["registration_source"]["block"] = block
    return capture, deployment


def validate(scenario, capture, deployment):
    return _validate_status_readiness(
        capture,
        parse_status(capture.status),
        parse_readiness(capture.readiness),
        scenario.policy,
        deployment,
    )


@pytest.mark.parametrize("phase", ["open", "not_open", "closed", "capacity_exhausted"])
def test_continuous_schedule_and_phase(intake_scenario, phase):
    capture, deployment = continuous(intake_scenario, phase)
    issues = validate(intake_scenario, capture, deployment)
    assert [item.code for item in issues] == (
        ["admission_capacity_exhausted"] if phase == "capacity_exhausted" else []
    )


@pytest.mark.parametrize("fault", ["missing_flag", "wrong_next", "missing_next", "wrong_ready"])
def test_continuous_inconsistency_is_rejected(intake_scenario, fault):
    capture, deployment = continuous(intake_scenario)
    if fault == "missing_flag":
        capture.readiness.pop("continuous_intake")
    elif fault == "wrong_next":
        capture.readiness["next_intake_schedule"] = capture.readiness["round_schedule"]
    elif fault == "missing_next":
        capture.status["next_intake_schedule"] = None
    else:
        capture.readiness["ready_for"] = "first_round_intake"
    with pytest.raises(PublicIntakeMonitorError):
        validate(intake_scenario, capture, deployment)


def test_legacy_launch_cannot_claim_continuous_schedule(intake_scenario):
    capture = copy.deepcopy(intake_scenario.capture)
    capture.status["continuous_intake"] = True
    deployment = PublicIntakeDeployment.model_validate_json(
        canonical_json_bytes(capture.status["deployment"])
    )
    with pytest.raises(PublicIntakeMonitorError, match="continuous_intake_schedule_mismatch"):
        validate(intake_scenario, capture, deployment)


def test_deal_fields_parse_but_unknown_fields_still_fail(intake_scenario):
    capture, _ = continuous(intake_scenario)
    capture.status.update(
        honored_policy_sha256s=[capture.status["policy_sha256"]], deal_sha256="aa" * 32
    )
    parse_status(capture.status)
    capture.status["unreviewed_field"] = True
    with pytest.raises(PublicIntakeMonitorError, match="invalid_competition_status"):
        parse_status(capture.status)


def held_capture(scenario):
    capture, deployment = continuous(scenario)
    hold = {
        "schema": "umi-competition-intake-schedule-hold/1",
        "cohort_number": 5,
    }
    deployment = PublicIntakeDeployment.model_validate(
        {
            **deployment.model_dump(by_alias=True),
            "evaluation_ready": False,
            "intake_schedule_hold": hold,
        }
    )
    for value in (
        capture.status_before,
        capture.status,
        capture.readiness_before,
        capture.readiness,
    ):
        value.update(
            deployment=deployment.model_dump(mode="json", by_alias=True),
            evaluation_ready=False,
            next_intake_schedule=None,
            intake_schedule_hold=deployment.intake_schedule_hold.model_dump(
                mode="json", by_alias=True
            ),
        )
    return capture, deployment


def test_monitor_accepts_deployment_bound_hold_without_cutoff(intake_scenario):
    capture, deployment = held_capture(intake_scenario)
    assert validate(intake_scenario, capture, deployment) == []


@pytest.mark.parametrize("fault", ["missing_hold", "wrong_cohort", "invented_cutoff"])
def test_monitor_rejects_hold_mismatch(intake_scenario, fault):
    capture, deployment = held_capture(intake_scenario)
    if fault == "missing_hold":
        capture.readiness.pop("intake_schedule_hold")
    elif fault == "wrong_cohort":
        capture.status["intake_schedule_hold"]["cohort_number"] = 6
    else:
        capture.status["next_intake_schedule"] = capture.status["round_schedule"]
    with pytest.raises(PublicIntakeMonitorError, match="continuous_intake_schedule_mismatch"):
        validate(intake_scenario, capture, deployment)
