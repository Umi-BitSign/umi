from __future__ import annotations

import copy
import json
import os
import plistlib
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from umi.competition_launch import PublicIntakeDeployment
from umi.competition_submission_checkpoint import build_submission_checkpoint
from umi.observer import create_observer_app
from umi.open_competition import CompetitionPolicy, SignedSubmission, digest, identity
from umi.protocol import canonical_json_bytes
from umi.public_intake_archive import PublicIntakeArchive, PublicIntakeArchiveError
from umi.public_intake_http import PublicIntakeHttpError, PublicIntakeHttpSource
from umi.public_intake_monitor import (
    ExpectedIntakeIdentity,
    PublicIntakeMonitorConfig,
    PublicIntakeMonitorError,
    PublicRouteCapture,
    ReviewedBootstrapCheckpoint,
    SubmissionRecordState,
    _next_state,
    document_sha256,
    validate_public_capture,
)
from umi.public_intake_monitor_cli import _parser, load_config

from .test_competition_chain import chain_config as chain_config
from .test_competition_service import app_for
from .test_competition_service import config as service_config  # noqa: F401
from .test_competition_service import public_deployment as public_deployment
from .test_observer import SequenceCollector, _cache, _participant, _snapshot
from .test_open_competition import policy as policy
from .test_open_competition import submission as make_submission

NOW_MS = 1_800_000_000_000


@dataclass(frozen=True)
class IntakeScenario:
    policy: CompetitionPolicy
    capture: PublicRouteCapture
    config: PublicIntakeMonitorConfig


@pytest.fixture(autouse=True)
def _restore_test_directory_modes(request):
    yield
    root = request.node.funcargs.get("tmp_path")
    if root is None or not root.exists():
        return
    for directory, subdirectories, files in os.walk(root, topdown=False):
        for name in files:
            Path(directory, name).chmod(0o600)
        for name in subdirectories:
            Path(directory, name).chmod(0o700)
        Path(directory).chmod(0o700)


def _participant_page(block: int, *, uid_0_age: int, uid_54_age: int) -> dict[str, Any]:
    rows = tuple(
        _participant(uid, validator=True).model_copy(
            update={
                "last_update_block": str(block - age),
                "last_update_age_blocks": str(age),
            }
        )
        for uid, age in ((0, uid_0_age), (54, uid_54_age))
    )
    snapshot = _snapshot(block_number=block, participants=rows)
    app = create_observer_app(_cache(SequenceCollector([snapshot])))
    with TestClient(app) as client:
        response = client.get("/api/v1/participants?role=all&limit=512")
        assert response.status_code == 200
        body = response.json()
        body["protocol_state"]["chain_identity_matches_expected"] = True
        return body


def _replace_public_head(
    capture: PublicRouteCapture,
    *,
    policy_sha256: str,
    writer_generations: dict[str, int] | None = None,
) -> PublicRouteCapture:
    summaries = capture.submission_pages[0]["items"]
    commitments: dict[str, str] = {}
    for summary in summaries:
        submission_sha = summary["submission_sha256"]
        record = capture.submission_records[submission_sha]
        signed = SignedSubmission.model_validate_json(
            canonical_json_bytes(record["signed_submission"])
        )
        receipt = record["receipt"]
        commitment = {
            "schema": "umi-competition-admission-record-commitment/1",
            "submission_sha256": submission_sha,
            "hotkey": identity(signed.submission.hotkey),
            "track": signed.submission.track,
            "sequence": signed.submission.sequence,
            "accepted_block": summary["accepted_block"],
            "expires_block": signed.submission.valid_through_block,
            "body_sha256": document_sha256(signed),
            "receipt_sha256": document_sha256(receipt),
            "writer_generation": (writer_generations or {}).get(submission_sha, 2),
        }
        commitments[submission_sha] = document_sha256(commitment)
    submission_ids = tuple(sorted(commitments))
    deployment = PublicIntakeDeployment.model_validate_json(
        canonical_json_bytes(capture.status["deployment"])
    )
    checkpoint = build_submission_checkpoint(
        policy_sha256=policy_sha256,
        public_launch_sha256=digest(deployment.launch_identity()),
        submission_sha256s=submission_ids,
        admission_record_sha256s=tuple(commitments[item] for item in submission_ids),
    )
    public_head = {
        "schema": "umi-competition-submission-head/1",
        "policy_sha256": checkpoint.policy_sha256,
        "record_count": checkpoint.record_count,
        "submission_set_sha256": checkpoint.submission_set_sha256,
        "head_sha256": checkpoint.head_sha256,
        "public_launch_sha256": checkpoint.public_launch_sha256,
        "external_checkpoint_sha256": document_sha256(checkpoint),
        "external_checkpoint_durable": True,
    }
    updated = copy.deepcopy(capture)
    for status in (updated.status_before, updated.status):
        status["retained_submission_head"] = copy.deepcopy(public_head)
    for readiness in (updated.readiness_before, updated.readiness):
        readiness["retained_submission_head"] = copy.deepcopy(public_head)
    return updated


@pytest.fixture
def intake_scenario(request, policy) -> IntakeScenario:
    service_config_value = request.getfixturevalue("service_config")
    app, _provider = app_for(service_config_value, policy)
    with TestClient(app) as client:
        status_before = client.get("/v1/competition/status").json()
        readiness_before = client.get("/v1/competition/readiness").json()
        page = client.get("/v1/competition/submissions?offset=0&limit=100").json()
        records = {
            item["submission_sha256"]: client.get(
                f"/v1/competition/submissions/{item['submission_sha256']}"
            ).json()
            for item in page["items"]
        }
        readiness = client.get("/v1/competition/readiness").json()
        status = client.get("/v1/competition/status").json()
    capture = PublicRouteCapture(
        status_before=status_before,
        readiness_before=readiness_before,
        submission_pages=(page,),
        submission_records=records,
        participant_pages=(
            _participant_page(status["admission_checked_block"], uid_0_age=10, uid_54_age=20),
        ),
        readiness=readiness,
        status=status,
    )
    for record in capture.submission_records.values():
        record["receipt"]["registration_source"] = "verifier_attested_finality"
    capture = _replace_public_head(capture, policy_sha256=digest(policy))
    monitor_config = PublicIntakeMonitorConfig(
        schema="umi-public-intake-monitor-config/1",
        competition_origin="https://competition.example",
        observer_origin="https://observer.example",
        expected_identities=(
            ExpectedIntakeIdentity(
                schema="umi-public-intake-monitor-identity/1",
                name="initial",
                policy_sha256=digest(policy),
                deployment_document_sha256=document_sha256(status["deployment"]),
                expected_baseline_promotion_sha256=status["baseline"]["promotion_sha256"],
                not_before_checked_block=status["admission_checked_block"],
                acceptance_not_before_block=status["round_schedule"]["intake_opened_block"],
                minimum_accepted_submission_count=status["accepted_submission_count"],
                required_submission_count=len(
                    readiness["retained_state"]["required_submission_sha256s"]
                ),
                required_submission_set_sha256=document_sha256(
                    sorted(readiness["retained_state"]["required_submission_sha256s"])
                ),
                admission_writer_generation=2,
            ),
        ),
        reviewed_bootstrap=ReviewedBootstrapCheckpoint(
            schema="umi-public-intake-monitor-bootstrap/1",
            identity_name="initial",
            accepted_submission_count=capture.status["accepted_submission_count"],
            retained_head_sha256=capture.status["retained_submission_head"]["head_sha256"],
        ),
    )
    return IntakeScenario(policy=policy, capture=capture, config=monitor_config)


def _replace_participant_ages(
    scenario: IntakeScenario, *, uid_0_age: int, uid_54_age: int
) -> PublicRouteCapture:
    finalized_block = max(scenario.capture.status["admission_checked_block"], uid_0_age, uid_54_age)
    return replace(
        scenario.capture,
        participant_pages=(
            _participant_page(
                finalized_block,
                uid_0_age=uid_0_age,
                uid_54_age=uid_54_age,
            ),
        ),
    )


def _successor_capture(
    scenario: IntakeScenario,
) -> tuple[CompetitionPolicy, PublicRouteCapture, PublicIntakeMonitorConfig]:
    successor = scenario.policy.model_copy(
        update={
            "sequence": scenario.policy.sequence + 1,
            "predecessor_sha256": digest(scenario.policy),
            "contribution_terms_sha256": "ef" * 32,
        }
    )
    policy_sha = digest(successor)
    raw = copy.deepcopy(scenario.capture)
    successor_block = raw.status["admission_checked_block"] + 1
    for status in (raw.status_before, raw.status):
        status["policy_sha256"] = policy_sha
        status["policy"] = successor.model_dump(mode="json", by_alias=True)
        status["admission_checked_block"] = successor_block
    for readiness in (raw.readiness_before, raw.readiness):
        readiness["policy_sha256"] = policy_sha
        readiness["admission_checked_block"] = successor_block
        readiness["registration_source"]["block"] = successor_block
        readiness["registration_source"]["block_hash"] = "0x" + f"{successor_block:064x}"
    raw = _replace_public_head(raw, policy_sha256=policy_sha)
    successor_identity = ExpectedIntakeIdentity(
        schema="umi-public-intake-monitor-identity/1",
        name="successor",
        policy_sha256=policy_sha,
        deployment_document_sha256=document_sha256(raw.status["deployment"]),
        expected_baseline_promotion_sha256=raw.status["baseline"]["promotion_sha256"],
        not_before_checked_block=successor_block,
        acceptance_not_before_block=successor_block,
        minimum_accepted_submission_count=raw.status["accepted_submission_count"],
        required_submission_count=scenario.config.expected_identities[0].required_submission_count,
        required_submission_set_sha256=scenario.config.expected_identities[
            0
        ].required_submission_set_sha256,
        admission_writer_generation=2,
    )
    config = PublicIntakeMonitorConfig.model_validate_json(
        canonical_json_bytes(
            {
                **scenario.config.model_dump(mode="json", by_alias=True),
                "expected_identities": [
                    *[
                        item.model_dump(mode="json", by_alias=True)
                        for item in scenario.config.expected_identities
                    ],
                    successor_identity.model_dump(mode="json", by_alias=True),
                ],
            }
        )
    )
    return successor, raw, config


def _capture_from_intake_client(client: TestClient) -> PublicRouteCapture:
    status_before = client.get("/v1/competition/status").json()
    readiness_before = client.get("/v1/competition/readiness").json()
    page = client.get("/v1/competition/submissions?offset=0&limit=100").json()
    records = {
        item["submission_sha256"]: client.get(
            f"/v1/competition/submissions/{item['submission_sha256']}"
        ).json()
        for item in page["items"]
    }
    readiness = client.get("/v1/competition/readiness").json()
    status = client.get("/v1/competition/status").json()
    capture = PublicRouteCapture(
        status_before=status_before,
        readiness_before=readiness_before,
        submission_pages=(page,),
        submission_records=records,
        participant_pages=(
            _participant_page(status["admission_checked_block"], uid_0_age=10, uid_54_age=20),
        ),
        readiness=readiness,
        status=status,
    )
    for record in capture.submission_records.values():
        record["receipt"]["registration_source"] = "verifier_attested_finality"
    return capture


def _replace_deployment(
    capture: PublicRouteCapture,
    deployment: PublicIntakeDeployment,
    *,
    checked_block: int | None = None,
) -> PublicRouteCapture:
    updated = copy.deepcopy(capture)
    deployment_body = deployment.model_dump(mode="json", by_alias=True)
    schedule_body = deployment.round_schedule.model_dump(mode="json", by_alias=True)
    for status in (updated.status_before, updated.status):
        status["deployment"] = copy.deepcopy(deployment_body)
        status["round_schedule"] = copy.deepcopy(schedule_body)
        status["assignment_delivery_ready"] = deployment.assignment_delivery_ready
        status["model_intake_ready"] = deployment.model_intake_ready
        status["evaluation_ready"] = deployment.evaluation_ready
        if checked_block is not None:
            status["admission_checked_block"] = checked_block
    for readiness in (updated.readiness_before, updated.readiness):
        readiness["deployment"] = copy.deepcopy(deployment_body)
        readiness["round_schedule"] = copy.deepcopy(schedule_body)
        readiness["assignment_delivery_ready"] = deployment.assignment_delivery_ready
        readiness["model_intake_ready"] = deployment.model_intake_ready
        readiness["evaluation_ready"] = deployment.evaluation_ready
        if checked_block is not None:
            readiness["admission_checked_block"] = checked_block
            readiness["registration_source"]["block"] = checked_block
            readiness["registration_source"]["block_hash"] = "0x" + f"{checked_block:064x}"
    if checked_block is not None:
        updated = replace(
            updated,
            participant_pages=(_participant_page(checked_block, uid_0_age=10, uid_54_age=20),),
        )
    return updated


def test_validates_full_public_ledger_and_monotonic_state(intake_scenario) -> None:
    result = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )

    assert result.severity == "ok"
    assert result.next_state.accepted_submission_count == 1
    assert len(result.next_state.submissions) == 1
    assert result.next_state.submissions[0].policy_sha256 == digest(intake_scenario.policy)
    assert result.next_state.policies[0].policy_sha256 == digest(intake_scenario.policy)
    assert [item.uid for item in result.validator_observations] == [0, 54]

    stalled = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=result.next_state,
        now_unix_ms=NOW_MS + 181_000,
    )
    assert stalled.severity == "critical"
    assert [item.code for item in stalled.issues] == ["admission_checked_block_stalled"]


def test_bootstrap_replays_non_anchor_records_before_observation_floor(request, policy) -> None:
    service_config_value = request.getfixturevalue("service_config")
    app, _provider = app_for(service_config_value, policy)
    with TestClient(app) as client:
        signed = make_submission(policy, name="Alice")
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        observed_block = (
            service_config_value.public_deployment.round_schedule.intake_opened_block + 6
        )
        capture = _replace_deployment(
            _capture_from_intake_client(client),
            service_config_value.public_deployment,
            checked_block=observed_block,
        )
    capture = _replace_public_head(capture, policy_sha256=digest(policy))
    required = capture.readiness["retained_state"]["required_submission_sha256s"]
    identity_ = ExpectedIntakeIdentity(
        schema="umi-public-intake-monitor-identity/1",
        name="historical-bootstrap",
        policy_sha256=digest(policy),
        deployment_document_sha256=document_sha256(capture.status["deployment"]),
        expected_baseline_promotion_sha256=capture.status["baseline"]["promotion_sha256"],
        not_before_checked_block=observed_block,
        acceptance_not_before_block=capture.status["round_schedule"]["intake_opened_block"],
        minimum_accepted_submission_count=capture.status["accepted_submission_count"],
        required_submission_count=len(required),
        required_submission_set_sha256=document_sha256(sorted(required)),
        admission_writer_generation=2,
    )
    config = PublicIntakeMonitorConfig(
        schema="umi-public-intake-monitor-config/1",
        competition_origin="https://competition.example",
        observer_origin="https://observer.example",
        expected_identities=(identity_,),
        reviewed_bootstrap=ReviewedBootstrapCheckpoint(
            schema="umi-public-intake-monitor-bootstrap/1",
            identity_name=identity_.name,
            accepted_submission_count=capture.status["accepted_submission_count"],
            retained_head_sha256=capture.status["retained_submission_head"]["head_sha256"],
        ),
    )

    validated = validate_public_capture(
        capture,
        config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    endpoint = next(item for item in validated.next_state.submissions if item.track == "endpoint")
    assert endpoint.accepted_block < identity_.not_before_checked_block
    assert endpoint.accepted_block >= identity_.acceptance_not_before_block


@pytest.mark.parametrize(
    ("age", "severity"),
    ((199, "ok"), (200, "warning"), (240, "investigate"), (300, "critical"), (360, "stale")),
)
def test_validator_age_boundaries(intake_scenario, age: int, severity: str) -> None:
    capture = _replace_participant_ages(intake_scenario, uid_0_age=age, uid_54_age=0)
    result = validate_public_capture(
        capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    assert result.validator_observations[0].severity == severity
    assert result.severity == severity


def test_capacity_exhaustion_requires_consistent_closed_flags(intake_scenario) -> None:
    exhausted = copy.deepcopy(intake_scenario.capture)
    for status in (exhausted.status_before, exhausted.status):
        status["admission_phase"] = "capacity_exhausted"
        status["admission_accepting_new"] = False
        status["admission_capacity_available"] = False
    for readiness in (exhausted.readiness_before, exhausted.readiness):
        readiness["admission_phase"] = "capacity_exhausted"
        readiness["admission_accepting_new"] = False
    validated = validate_public_capture(
        exhausted,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    assert validated.severity == "critical"
    assert [item.code for item in validated.issues] == ["admission_capacity_exhausted"]

    inconsistent = copy.deepcopy(exhausted)
    inconsistent.readiness["admission_phase"] = "open"
    inconsistent.readiness["admission_accepting_new"] = True
    with pytest.raises(PublicIntakeMonitorError, match="admission_phase_or_capacity_mismatch"):
        validate_public_capture(
            inconsistent,
            intake_scenario.config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )


def test_baseline_is_pinned_and_conflict_hold_is_critical(intake_scenario) -> None:
    changed = copy.deepcopy(intake_scenario.capture)
    replacement = "ab" * 32
    for status in (changed.status_before, changed.status):
        status["baseline"]["promotion_sha256"] = replacement
    for readiness in (changed.readiness_before, changed.readiness):
        readiness["retained_state"]["baseline_promotion_sha256"] = replacement
    with pytest.raises(
        PublicIntakeMonitorError,
        match="retained_baseline_differs_from_expected_identity",
    ):
        validate_public_capture(
            changed,
            intake_scenario.config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )

    held = copy.deepcopy(intake_scenario.capture)
    for status in (held.status_before, held.status):
        status["baseline"]["held_for_conflict"] = True
    validated = validate_public_capture(
        held,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    assert validated.severity == "critical"
    assert [item.code for item in validated.issues] == ["baseline_held_for_conflict"]


def test_policy_rollover_is_append_only_and_retains_old_admission_policy(intake_scenario) -> None:
    initial = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    successor, capture, config = _successor_capture(intake_scenario)

    advanced = validate_public_capture(
        capture,
        config,
        previous_state=initial.next_state,
        now_unix_ms=NOW_MS + 1_000,
    )
    assert advanced.identity.name == "successor"
    assert {item.policy_sha256 for item in advanced.next_state.policies} == {
        digest(intake_scenario.policy),
        digest(successor),
    }
    assert {item.policy_sha256 for item in advanced.next_state.submissions} == {
        digest(intake_scenario.policy)
    }

    with pytest.raises(
        PublicIntakeMonitorError, match="public_head_differs_from_reviewed_bootstrap"
    ):
        validate_public_capture(
            capture,
            config,
            previous_state=None,
            now_unix_ms=NOW_MS + 1_000,
        )
    with pytest.raises(PublicIntakeMonitorError, match="public_identity_regressed"):
        validate_public_capture(
            intake_scenario.capture,
            config,
            previous_state=advanced.next_state,
            now_unix_ms=NOW_MS + 2_000,
        )


def test_same_policy_deployment_rollover_uses_activation_and_writer_generation(
    request, policy
) -> None:
    service_config_value = request.getfixturevalue("service_config")
    app, _provider = app_for(service_config_value, policy)
    initial_deployment = service_config_value.public_deployment.model_copy(
        update={
            "eligible_tracks": ("model",),
            "model_intake_ready": True,
        }
    )
    successor_deployment = service_config_value.public_deployment.model_copy(
        update={
            "eligible_tracks": ("endpoint", "model"),
            "model_intake_ready": True,
        }
    )
    with TestClient(app) as client:
        initial_capture = _replace_deployment(
            _capture_from_intake_client(client), initial_deployment
        )
        initial_capture = _replace_public_head(initial_capture, policy_sha256=digest(policy))
        initial_status = initial_capture.status
        initial_readiness = initial_capture.readiness
        required = initial_readiness["retained_state"]["required_submission_sha256s"]
        initial_identity = ExpectedIntakeIdentity(
            schema="umi-public-intake-monitor-identity/1",
            name="model-only",
            policy_sha256=digest(policy),
            deployment_document_sha256=document_sha256(initial_status["deployment"]),
            expected_baseline_promotion_sha256=initial_status["baseline"]["promotion_sha256"],
            not_before_checked_block=initial_status["admission_checked_block"] - 1,
            acceptance_not_before_block=initial_status["round_schedule"]["intake_opened_block"],
            minimum_accepted_submission_count=initial_status["accepted_submission_count"],
            required_submission_count=len(required),
            required_submission_set_sha256=document_sha256(sorted(required)),
            admission_writer_generation=2,
        )
        initial_config = PublicIntakeMonitorConfig(
            schema="umi-public-intake-monitor-config/1",
            competition_origin="https://competition.example",
            observer_origin="https://observer.example",
            expected_identities=(initial_identity,),
            reviewed_bootstrap=ReviewedBootstrapCheckpoint(
                schema="umi-public-intake-monitor-bootstrap/1",
                identity_name=initial_identity.name,
                accepted_submission_count=initial_status["accepted_submission_count"],
                retained_head_sha256=initial_status["retained_submission_head"]["head_sha256"],
            ),
        )
        initial = validate_public_capture(
            initial_capture,
            initial_config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )

        signed = make_submission(policy, name="Alice")
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        endpoint_sha256 = digest(signed.submission)
        successor_capture = _replace_deployment(
            _capture_from_intake_client(client), successor_deployment
        )
        successor_capture = _replace_public_head(
            successor_capture,
            policy_sha256=digest(policy),
            writer_generations={endpoint_sha256: 3},
        )

    activation_block = successor_capture.status["admission_checked_block"]
    successor_identity = ExpectedIntakeIdentity(
        schema="umi-public-intake-monitor-identity/1",
        name="endpoint-enabled",
        policy_sha256=digest(policy),
        deployment_document_sha256=document_sha256(successor_capture.status["deployment"]),
        expected_baseline_promotion_sha256=successor_capture.status["baseline"]["promotion_sha256"],
        not_before_checked_block=activation_block,
        acceptance_not_before_block=activation_block,
        minimum_accepted_submission_count=successor_capture.status["accepted_submission_count"],
        required_submission_count=len(required),
        required_submission_set_sha256=document_sha256(sorted(required)),
        admission_writer_generation=3,
    )
    successor_config = initial_config.model_copy(
        update={"expected_identities": (initial_identity, successor_identity)}
    )
    advanced = validate_public_capture(
        successor_capture,
        successor_config,
        previous_state=initial.next_state,
        now_unix_ms=NOW_MS + 1_000,
    )
    endpoint_state = next(
        item
        for item in advanced.next_state.submissions
        if item.submission_sha256 == endpoint_sha256
    )
    assert endpoint_state.admission_identity_name == successor_identity.name
    assert endpoint_state.admission_writer_generation == 3

    late_activation_block = activation_block + 1
    backdated_capture = _replace_deployment(
        successor_capture,
        successor_deployment,
        checked_block=late_activation_block,
    )
    backdated_identity = successor_identity.model_copy(
        update={
            "not_before_checked_block": late_activation_block,
            "acceptance_not_before_block": late_activation_block,
        }
    )
    backdated_config = initial_config.model_copy(
        update={"expected_identities": (initial_identity, backdated_identity)}
    )
    with pytest.raises(
        PublicIntakeMonitorError, match="new_submission_outside_active_deployment_rules"
    ):
        validate_public_capture(
            backdated_capture,
            backdated_config,
            previous_state=initial.next_state,
            now_unix_ms=NOW_MS + 1_000,
        )


@pytest.mark.parametrize("rollover_kind", ("removed_track", "new_policy"))
def test_rollover_closes_prior_identity_acceptance_interval(
    request, policy, rollover_kind: str
) -> None:
    service_config_value = request.getfixturevalue("service_config")
    app, _provider = app_for(service_config_value, policy)
    with TestClient(app) as client:
        initial_capture = _replace_public_head(
            _capture_from_intake_client(client), policy_sha256=digest(policy)
        )
        initial_status = initial_capture.status
        required = initial_capture.readiness["retained_state"]["required_submission_sha256s"]
        initial_identity = ExpectedIntakeIdentity(
            schema="umi-public-intake-monitor-identity/1",
            name="endpoint-v1",
            policy_sha256=digest(policy),
            deployment_document_sha256=document_sha256(initial_status["deployment"]),
            expected_baseline_promotion_sha256=initial_status["baseline"]["promotion_sha256"],
            not_before_checked_block=initial_status["admission_checked_block"] - 1,
            acceptance_not_before_block=initial_status["round_schedule"]["intake_opened_block"],
            minimum_accepted_submission_count=initial_status["accepted_submission_count"],
            required_submission_count=len(required),
            required_submission_set_sha256=document_sha256(sorted(required)),
            admission_writer_generation=2,
        )
        initial_config = PublicIntakeMonitorConfig(
            schema="umi-public-intake-monitor-config/1",
            competition_origin="https://competition.example",
            observer_origin="https://observer.example",
            expected_identities=(initial_identity,),
            reviewed_bootstrap=ReviewedBootstrapCheckpoint(
                schema="umi-public-intake-monitor-bootstrap/1",
                identity_name=initial_identity.name,
                accepted_submission_count=initial_status["accepted_submission_count"],
                retained_head_sha256=initial_status["retained_submission_head"]["head_sha256"],
            ),
        )
        initial = validate_public_capture(
            initial_capture,
            initial_config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )

        signed = make_submission(policy, name="Alice")
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        rollover_capture = _capture_from_intake_client(client)

    if rollover_kind == "removed_track":
        successor_policy = policy
        successor_deployment = service_config_value.public_deployment.model_copy(
            update={
                "eligible_tracks": ("model",),
                "model_intake_ready": True,
            }
        )
        rollover_capture = _replace_deployment(rollover_capture, successor_deployment)
    else:
        successor_policy = policy.model_copy(
            update={
                "sequence": policy.sequence + 1,
                "predecessor_sha256": digest(policy),
                "contribution_terms_sha256": "cd" * 32,
            }
        )
        successor_deployment = service_config_value.public_deployment
        successor_policy_sha256 = digest(successor_policy)
        for status in (rollover_capture.status_before, rollover_capture.status):
            status["policy_sha256"] = successor_policy_sha256
            status["policy"] = successor_policy.model_dump(mode="json", by_alias=True)
        for readiness in (
            rollover_capture.readiness_before,
            rollover_capture.readiness,
        ):
            readiness["policy_sha256"] = successor_policy_sha256
    rollover_capture = _replace_public_head(
        rollover_capture, policy_sha256=digest(successor_policy)
    )
    activation_block = rollover_capture.status["admission_checked_block"]
    successor_identity = ExpectedIntakeIdentity(
        schema="umi-public-intake-monitor-identity/1",
        name=f"successor-{rollover_kind.replace('_', '-')}",
        policy_sha256=digest(successor_policy),
        deployment_document_sha256=document_sha256(rollover_capture.status["deployment"]),
        expected_baseline_promotion_sha256=rollover_capture.status["baseline"]["promotion_sha256"],
        not_before_checked_block=activation_block,
        acceptance_not_before_block=activation_block,
        minimum_accepted_submission_count=rollover_capture.status["accepted_submission_count"],
        required_submission_count=len(required),
        required_submission_set_sha256=document_sha256(sorted(required)),
        admission_writer_generation=2,
    )
    rollover_config = PublicIntakeMonitorConfig(
        schema="umi-public-intake-monitor-config/1",
        competition_origin=initial_config.competition_origin,
        observer_origin=initial_config.observer_origin,
        expected_identities=(initial_identity, successor_identity),
        reviewed_bootstrap=initial_config.reviewed_bootstrap,
    )
    with pytest.raises(
        PublicIntakeMonitorError, match="new_submission_outside_active_deployment_rules"
    ):
        validate_public_capture(
            rollover_capture,
            rollover_config,
            previous_state=initial.next_state,
            now_unix_ms=NOW_MS + 1_000,
        )


def test_preconfigured_successor_closes_predecessor_acceptance_interval(request, policy) -> None:
    service_config_value = request.getfixturevalue("service_config")
    app, _provider = app_for(service_config_value, policy)
    with TestClient(app) as client:
        initial_capture = _replace_public_head(
            _capture_from_intake_client(client), policy_sha256=digest(policy)
        )
        initial_status = initial_capture.status
        required = initial_capture.readiness["retained_state"]["required_submission_sha256s"]
        initial_identity = ExpectedIntakeIdentity(
            schema="umi-public-intake-monitor-identity/1",
            name="endpoint-v1",
            policy_sha256=digest(policy),
            deployment_document_sha256=document_sha256(initial_status["deployment"]),
            expected_baseline_promotion_sha256=initial_status["baseline"]["promotion_sha256"],
            not_before_checked_block=initial_status["admission_checked_block"] - 1,
            acceptance_not_before_block=initial_status["round_schedule"]["intake_opened_block"],
            minimum_accepted_submission_count=initial_status["accepted_submission_count"],
            required_submission_count=len(required),
            required_submission_set_sha256=document_sha256(sorted(required)),
            admission_writer_generation=2,
        )
        initial_config = PublicIntakeMonitorConfig(
            schema="umi-public-intake-monitor-config/1",
            competition_origin="https://competition.example",
            observer_origin="https://observer.example",
            expected_identities=(initial_identity,),
            reviewed_bootstrap=ReviewedBootstrapCheckpoint(
                schema="umi-public-intake-monitor-bootstrap/1",
                identity_name=initial_identity.name,
                accepted_submission_count=initial_status["accepted_submission_count"],
                retained_head_sha256=initial_status["retained_submission_head"]["head_sha256"],
            ),
        )
        initial = validate_public_capture(
            initial_capture,
            initial_config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )

        signed = make_submission(policy, name="Alice")
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert response.status_code == 200
        predecessor_capture = _replace_public_head(
            _capture_from_intake_client(client), policy_sha256=digest(policy)
        )

    submission_sha256 = digest(signed.submission)
    accepted_block = next(
        item["accepted_block"]
        for item in predecessor_capture.submission_pages[0]["items"]
        if item["submission_sha256"] == submission_sha256
    )
    successor_deployment = service_config_value.public_deployment.model_copy(
        update={"eligible_tracks": ("model",), "model_intake_ready": True}
    )
    successor_identity = ExpectedIntakeIdentity(
        schema="umi-public-intake-monitor-identity/1",
        name="model-v2",
        policy_sha256=digest(policy),
        deployment_document_sha256=document_sha256(successor_deployment),
        expected_baseline_promotion_sha256=predecessor_capture.status["baseline"][
            "promotion_sha256"
        ],
        not_before_checked_block=accepted_block + 1,
        acceptance_not_before_block=accepted_block,
        minimum_accepted_submission_count=predecessor_capture.status["accepted_submission_count"],
        required_submission_count=len(required),
        required_submission_set_sha256=document_sha256(sorted(required)),
        admission_writer_generation=3,
    )
    rollover_config = initial_config.model_copy(
        update={"expected_identities": (initial_identity, successor_identity)}
    )

    with pytest.raises(
        PublicIntakeMonitorError, match="new_submission_outside_active_deployment_rules"
    ):
        validate_public_capture(
            predecessor_capture,
            rollover_config,
            previous_state=initial.next_state,
            now_unix_ms=NOW_MS + 1_000,
        )


def test_record_mutation_and_identity_substitution_fail_closed(intake_scenario) -> None:
    initial = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    changed = copy.deepcopy(intake_scenario.capture)
    record = next(iter(changed.submission_records.values()))
    record["receipt"]["observed_uid"] += 1
    with pytest.raises(PublicIntakeMonitorError, match="submission_record_or_summary_mismatch"):
        validate_public_capture(
            changed,
            intake_scenario.config,
            previous_state=initial.next_state,
            now_unix_ms=NOW_MS + 1_000,
        )

    wrong_config = intake_scenario.config.model_copy(
        update={
            "expected_identities": (
                intake_scenario.config.expected_identities[0].model_copy(
                    update={"deployment_document_sha256": "00" * 32}
                ),
            )
        }
    )
    with pytest.raises(PublicIntakeMonitorError, match="unexpected_policy_or_deployment_identity"):
        validate_public_capture(
            intake_scenario.capture,
            wrong_config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )


def test_bootstrap_head_and_required_set_are_exactly_pinned(intake_scenario) -> None:
    wrong_head = intake_scenario.config.model_copy(
        update={
            "reviewed_bootstrap": intake_scenario.config.reviewed_bootstrap.model_copy(
                update={"retained_head_sha256": "00" * 32}
            )
        }
    )
    with pytest.raises(
        PublicIntakeMonitorError, match="public_head_differs_from_reviewed_bootstrap"
    ):
        validate_public_capture(
            intake_scenario.capture,
            wrong_head,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )

    changed_required = copy.deepcopy(intake_scenario.capture)
    for readiness in (changed_required.readiness_before, changed_required.readiness):
        readiness["retained_state"]["required_submission_sha256s"].append("ff" * 32)
        readiness["retained_state"]["required_submission_sha256s"].sort()
    with pytest.raises(
        PublicIntakeMonitorError,
        match="required_retained_submission_set_differs_from_expected_identity",
    ):
        validate_public_capture(
            changed_required,
            intake_scenario.config,
            previous_state=None,
            now_unix_ms=NOW_MS,
        )


def test_monotonic_state_rejects_a_record_hidden_before_prior_checked_block(
    intake_scenario,
) -> None:
    validated = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    current = validated.next_state.submissions[0]
    retained = SubmissionRecordState(
        submission_sha256="00" * 32,
        policy_sha256=current.policy_sha256,
        hotkey_account_id32="11" * 32,
        track="endpoint",
        sequence=1,
        accepted_block=current.accepted_block,
        admission_identity_name=validated.identity.name,
        admission_writer_generation=validated.identity.admission_writer_generation,
        record_sha256="22" * 32,
    )
    prior = validated.next_state.model_copy(
        update={"accepted_submission_count": 1, "submissions": (retained,)}
    )
    hidden = current.model_copy(
        update={"accepted_block": validated.status.admission_checked_block - 1}
    )
    assert hidden.accepted_block > retained.accepted_block
    records = tuple(sorted((retained, hidden), key=lambda item: item.submission_sha256))
    status = validated.status.model_copy(update={"accepted_submission_count": 2})
    with pytest.raises(
        PublicIntakeMonitorError, match="new_submission_backfilled_before_prior_checked_block"
    ):
        _next_state(
            state=prior,
            now_unix_ms=NOW_MS + 1_000,
            identity_=validated.identity,
            status=status,
            records=records,
            policies=validated.next_state.policies,
            deployments=validated.next_state.deployments,
            identity_index=0,
            config=intake_scenario.config,
        )


def test_archive_is_atomic_complete_content_addressed_and_replayable(
    intake_scenario, tmp_path
) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    validated = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )

    with archive.locked():
        name, manifest = archive.commit(intake_scenario.capture, validated, intake_scenario.config)
    assert manifest.predecessor_snapshot is None
    assert manifest.predecessor_manifest_sha256 is None
    assert archive.latest().snapshot == name
    assert archive.verify_with_config(name, intake_scenario.config) == manifest
    assert manifest.accepted_submission_count == len(
        tuple((root / "snapshots" / name / "submission-records").iterdir())
    )
    state = archive.snapshot_state(name)
    record = state.submissions[0]
    object_path = root / "objects" / f"{record.record_sha256}.json"
    snapshot_path = (
        root / "snapshots" / name / "submission-records" / (f"{record.submission_sha256}.json")
    )
    assert object_path.stat().st_ino == snapshot_path.stat().st_ino
    assert oct(object_path.stat().st_mode & 0o777) == "0o400"
    assert oct((root / "snapshots" / name).stat().st_mode & 0o777) == "0o500"

    second = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=validated.next_state,
        now_unix_ms=NOW_MS + 1_000,
    )
    with archive.locked():
        second_name, second_manifest = archive.commit(
            intake_scenario.capture, second, intake_scenario.config
        )
    assert second_manifest.predecessor_snapshot == name
    assert second_manifest.predecessor_manifest_sha256 == document_sha256(manifest)
    assert archive.verify_with_config(second_name, intake_scenario.config) == second_manifest
    assert second_name != name
    assert (
        object_path.stat().st_ino
        == (root / "snapshots" / second_name / "submission-records" / snapshot_path.name)
        .stat()
        .st_ino
    )
    _successor, _capture, extended_config = _successor_capture(intake_scenario)
    assert archive.verify_with_config(name, extended_config) == manifest


def test_archive_recovers_stale_pointer_and_unsealed_rename(
    intake_scenario, tmp_path, monkeypatch
) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    first = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    with archive.locked():
        first_name, _manifest = archive.commit(
            intake_scenario.capture, first, intake_scenario.config
        )
    old_pointer = (root / "latest.json").read_bytes()
    second = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=first.next_state,
        now_unix_ms=NOW_MS + 1_000,
    )
    with archive.locked():
        second_name, _manifest = archive.commit(
            intake_scenario.capture, second, intake_scenario.config
        )
    (root / "latest.json").write_bytes(old_pointer)
    (root / "latest.json").chmod(0o600)
    assert archive.latest().snapshot == second_name
    assert archive.latest().snapshot != first_name

    crash_root = tmp_path / "crash-audit"
    crash_root.mkdir(mode=0o700)
    crash_archive = PublicIntakeArchive(crash_root)
    real_replace = os.replace

    def crash_after_snapshot_rename(source, destination):
        real_replace(source, destination)
        if Path(source).parent.name == ".staging":
            raise RuntimeError("simulated crash after snapshot rename")

    monkeypatch.setattr("umi.public_intake_archive.os.replace", crash_after_snapshot_rename)
    with pytest.raises(RuntimeError, match="simulated crash"):
        crash_archive.commit(intake_scenario.capture, first, intake_scenario.config)
    monkeypatch.setattr("umi.public_intake_archive.os.replace", real_replace)
    unsealed = next((crash_root / "snapshots").iterdir())
    assert unsealed.stat().st_mode & 0o777 == 0o700
    recovered = crash_archive.latest()
    assert recovered is not None
    assert unsealed.stat().st_mode & 0o777 == 0o500


def test_poll_context_rejects_a_missing_predecessor_snapshot(intake_scenario, tmp_path) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    first = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    with archive.locked():
        first_name, _manifest = archive.commit(
            intake_scenario.capture, first, intake_scenario.config
        )
        second = validate_public_capture(
            intake_scenario.capture,
            intake_scenario.config,
            previous_state=first.next_state,
            now_unix_ms=NOW_MS + 1_000,
        )
        archive.commit(intake_scenario.capture, second, intake_scenario.config)
    (root / "snapshots" / first_name).chmod(0o700)
    os.replace(root / "snapshots" / first_name, root / "detached-predecessor")

    with pytest.raises(PublicIntakeArchiveError, match="archive_directory_unavailable"):
        archive.poll_context(intake_scenario.config)


def test_archive_rejects_tampering_and_unsafe_root(intake_scenario, tmp_path) -> None:
    unsafe = tmp_path / "unsafe"
    unsafe.mkdir(mode=0o755)
    with pytest.raises(PublicIntakeArchiveError, match="archive_directory_not_private"):
        PublicIntakeArchive(unsafe)

    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    validated = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    with archive.locked():
        name, _manifest = archive.commit(intake_scenario.capture, validated, intake_scenario.config)
    status = root / "snapshots" / name / "status.json"
    status.chmod(0o600)
    status.write_bytes(status.read_bytes() + b" ")
    status.chmod(0o400)
    with pytest.raises(PublicIntakeArchiveError, match="archived_file_digest_mismatch"):
        archive.verify_snapshot(name)


def test_archive_atomically_quarantines_rejected_capture_without_advancing_latest(
    intake_scenario, tmp_path
) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    validated = validate_public_capture(
        intake_scenario.capture,
        intake_scenario.config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    rejected_capture = copy.deepcopy(intake_scenario.capture)
    rejected_record = next(iter(rejected_capture.submission_records.values()))
    rejected_record["receipt"]["observed_uid"] += 1
    with archive.locked():
        accepted_name, accepted_manifest = archive.commit(
            intake_scenario.capture, validated, intake_scenario.config
        )
        rejected_name, rejected_manifest = archive.commit_rejected(
            rejected_capture,
            intake_scenario.config,
            validated.next_state,
            reason="submission_record_or_summary_mismatch",
            captured_at_unix_ms=NOW_MS + 1_000,
        )

    assert archive.latest().snapshot == accepted_name
    rejected_root = root / "rejected" / rejected_name
    rejected_root.chmod(0o700)
    with archive.locked():
        pass
    assert archive.verify_rejected(rejected_name) == rejected_manifest
    assert rejected_manifest.last_accepted_snapshot == accepted_name
    assert rejected_manifest.last_accepted_manifest_sha256 == document_sha256(accepted_manifest)
    assert (rejected_root / "previous-monitor-state.json").is_file()
    record = validated.next_state.submissions[0]
    rejected_record_sha256 = document_sha256(
        rejected_capture.submission_records[record.submission_sha256]
    )
    assert (
        rejected_root / "submission-records" / f"{record.submission_sha256}.json"
    ).stat().st_ino == (root / "objects" / f"{rejected_record_sha256}.json").stat().st_ino
    assert oct(rejected_root.stat().st_mode & 0o777) == "0o500"


def test_archive_rejects_edits_to_preconfigured_identity_history(intake_scenario, tmp_path) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    _successor, _capture, extended_config = _successor_capture(intake_scenario)
    validated = validate_public_capture(
        intake_scenario.capture,
        extended_config,
        previous_state=None,
        now_unix_ms=NOW_MS,
    )
    with archive.locked():
        archive.commit(intake_scenario.capture, validated, extended_config)

    altered_successor = extended_config.expected_identities[1].model_copy(
        update={"name": "altered-successor"}
    )
    altered_config = extended_config.model_copy(
        update={
            "expected_identities": (
                extended_config.expected_identities[0],
                altered_successor,
            )
        }
    )
    with pytest.raises(
        PublicIntakeArchiveError,
        match="monitor_config_is_not_an_append_only_extension",
    ):
        archive.ensure_config_extension(altered_config)

    weakened_config = extended_config.model_copy(
        update={"maximum_checked_block_stall_seconds": 3600}
    )
    with pytest.raises(
        PublicIntakeArchiveError,
        match="monitor_config_is_not_an_append_only_extension",
    ):
        archive.ensure_config_extension(weakened_config)


def test_archive_reaps_only_safe_abandoned_staging_directories(tmp_path) -> None:
    root = tmp_path / "audit"
    root.mkdir(mode=0o700)
    archive = PublicIntakeArchive(root)
    abandoned = root / ".staging" / (".snapshot-" + "a" * 32)
    abandoned.mkdir(mode=0o700)
    nested = abandoned / "submission-records"
    nested.mkdir(mode=0o700)
    debris = nested / "capture.json"
    debris.write_bytes(b"{}")
    debris.chmod(0o400)
    nested.chmod(0o500)
    object_temporary = root / "objects" / ("." + "c" * 64 + "." + "d" * 32 + ".tmp")
    object_temporary.write_bytes(b"record")
    object_temporary.chmod(0o400)
    latest_temporary = root / (".latest.json." + "e" * 32 + ".tmp")
    latest_temporary.write_bytes(b"pointer")
    latest_temporary.chmod(0o600)

    with archive.locked():
        assert not abandoned.exists()
        assert not object_temporary.exists()
        assert not latest_temporary.exists()

    outside = tmp_path / "outside"
    outside.mkdir(mode=0o700)
    unsafe = root / ".staging" / (".rejected-" + "b" * 32)
    unsafe.symlink_to(outside, target_is_directory=True)
    with (
        pytest.raises(PublicIntakeArchiveError, match="unsafe_abandoned_staging_entry"),
        archive.locked(),
    ):
        pass
    assert outside.is_dir()


def _mock_source(intake_scenario, handler) -> PublicIntakeHttpSource:
    client = httpx.Client(transport=httpx.MockTransport(handler), follow_redirects=False)
    return PublicIntakeHttpSource(
        intake_scenario.config, client=client, sleeper=lambda _delay: None
    )


def test_http_capture_uses_only_bounded_get_routes_and_fetches_every_record(
    intake_scenario,
) -> None:
    calls: list[tuple[str, str]] = []
    capture = intake_scenario.capture

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.method, request.url.path))
        if request.url.path == "/v1/competition/status":
            value = capture.status
        elif request.url.path == "/v1/competition/readiness":
            value = capture.readiness
        elif request.url.path == "/v1/competition/submissions":
            value = capture.submission_pages[0]
        elif request.url.path.startswith("/v1/competition/submissions/"):
            value = capture.submission_records[request.url.path.rsplit("/", 1)[1]]
        elif request.url.path == "/api/v1/participants":
            value = capture.participant_pages[0]
        else:
            raise AssertionError(request.url)
        return httpx.Response(
            200,
            content=canonical_json_bytes(value),
            headers={"content-type": "application/json"},
        )

    source = _mock_source(intake_scenario, handler)
    observed = source.capture()
    assert observed.submission_records == capture.submission_records
    identity_candidate = source.observed_identity()
    assert identity_candidate["policy"] == capture.status["policy"]
    assert identity_candidate["baseline"] == capture.status["baseline"]
    assert (
        identity_candidate["identity_template_requires_review"][
            "expected_baseline_promotion_sha256"
        ]
        == capture.status["baseline"]["promotion_sha256"]
    )
    assert identity_candidate["required_submission_sha256s"] == sorted(
        capture.readiness["retained_state"]["required_submission_sha256s"]
    )
    assert all(method == "GET" for method, _path in calls)
    assert {path for _method, path in calls} == {
        "/v1/competition/status",
        "/v1/competition/readiness",
        "/v1/competition/submissions",
        "/v1/competition/submissions/" + next(iter(capture.submission_records)),
        "/api/v1/participants",
    }


def test_observed_identity_fences_retained_baseline(intake_scenario) -> None:
    readiness = copy.deepcopy(intake_scenario.capture.readiness)
    readiness["retained_state"]["baseline_promotion_sha256"] = "cd" * 32

    def handler(request: httpx.Request) -> httpx.Response:
        value = (
            readiness
            if request.url.path == "/v1/competition/readiness"
            else intake_scenario.capture.status
        )
        return httpx.Response(
            200,
            content=canonical_json_bytes(value),
            headers={"content-type": "application/json"},
        )

    with pytest.raises(PublicIntakeHttpError, match="public_identity_changed_during_observation"):
        _mock_source(intake_scenario, handler).observed_identity()


def test_http_source_rejects_redirect_and_oversized_response(intake_scenario) -> None:
    def redirect(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://elsewhere.invalid"})

    with pytest.raises(PublicIntakeHttpError, match="public_route_http_302"):
        _mock_source(intake_scenario, redirect).capture()

    def oversized(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=b"{}",
            headers={
                "content-type": "application/json",
                "content-length": str(intake_scenario.config.maximum_response_bytes + 1),
            },
        )

    with pytest.raises(PublicIntakeHttpError, match="public_route_response_too_large"):
        _mock_source(intake_scenario, oversized).capture()


@pytest.mark.parametrize(
    ("item_count", "error_code"),
    (
        (2, "submission_pages_exceed_checkpoint_count"),
        (101, "submission_page_item_count_exceeds_limit"),
    ),
)
def test_http_source_rejects_page_growth_before_record_fanout(
    intake_scenario, item_count: int, error_code: str
) -> None:
    page = copy.deepcopy(intake_scenario.capture.submission_pages[0])
    page["items"] = page["items"] * item_count
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if request.url.path == "/v1/competition/status":
            value = intake_scenario.capture.status
        elif request.url.path == "/v1/competition/readiness":
            value = intake_scenario.capture.readiness
        elif request.url.path == "/v1/competition/submissions":
            value = page
        else:
            raise AssertionError("record fanout started before page bounds were checked")
        return httpx.Response(
            200,
            content=canonical_json_bytes(value),
            headers={"content-type": "application/json"},
        )

    with pytest.raises(PublicIntakeHttpError, match=error_code):
        _mock_source(intake_scenario, handler).capture()
    assert not any(path.startswith("/v1/competition/submissions/") for path in calls)


def test_http_source_enforces_total_budget_count_cap_and_elapsed_deadline(
    intake_scenario,
) -> None:
    bounded_config = PublicIntakeMonitorConfig.model_validate_json(
        canonical_json_bytes(
            {
                **intake_scenario.config.model_dump(mode="json", by_alias=True),
                "maximum_response_bytes": 1024**2,
                "maximum_capture_bytes": 1024**2,
            }
        )
    )
    padded_status = canonical_json_bytes(intake_scenario.capture.status) + b" " * 600_000
    padded_readiness = canonical_json_bytes(intake_scenario.capture.readiness) + b" " * 600_000

    def large_documents(request: httpx.Request) -> httpx.Response:
        body = padded_status if request.url.path.endswith("/status") else padded_readiness
        return httpx.Response(200, content=body, headers={"content-type": "application/json"})

    source = PublicIntakeHttpSource(
        bounded_config,
        client=httpx.Client(transport=httpx.MockTransport(large_documents)),
        sleeper=lambda _delay: None,
    )
    with pytest.raises(PublicIntakeHttpError, match="public_capture_response_budget_exceeded"):
        source.capture()

    too_many = copy.deepcopy(intake_scenario.capture.status)
    too_many["accepted_submission_count"] = 2

    def count_response(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=canonical_json_bytes(too_many),
            headers={"content-type": "application/json"},
        )

    count_source = PublicIntakeHttpSource(
        intake_scenario.config.model_copy(update={"maximum_accepted_submission_count": 1}),
        client=httpx.Client(transport=httpx.MockTransport(count_response)),
        sleeper=lambda _delay: None,
    )
    with pytest.raises(PublicIntakeHttpError, match="accepted_submission_count_exceeds"):
        count_source.capture()

    ticks = iter((0.0, 0.0, 0.0, 0.0, 21.0))

    def clock() -> float:
        return next(ticks, 21.0)

    def valid_status(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            content=canonical_json_bytes(intake_scenario.capture.status),
            headers={"content-type": "application/json"},
        )

    deadline_source = PublicIntakeHttpSource(
        intake_scenario.config,
        client=httpx.Client(transport=httpx.MockTransport(valid_status)),
        sleeper=lambda _delay: None,
        monotonic=clock,
    )
    with pytest.raises(PublicIntakeHttpError, match="elapsed_deadline_exceeded"):
        deadline_source.capture()

    clock_calls = 0

    def late_clock() -> float:
        nonlocal clock_calls
        clock_calls += 1
        return 0.0 if clock_calls == 1 else 12.0

    timeout_extensions: list[dict[str, float]] = []

    def teapot(request: httpx.Request) -> httpx.Response:
        timeout_extensions.append(request.extensions["timeout"])
        return httpx.Response(418)

    timeout_source = PublicIntakeHttpSource(
        intake_scenario.config.model_copy(
            update={
                "maximum_poll_seconds": 30,
                "request_timeout_seconds": 60,
                "request_attempts": 1,
            }
        ),
        client=httpx.Client(transport=httpx.MockTransport(teapot)),
        sleeper=lambda _delay: None,
        monotonic=late_clock,
    )
    with pytest.raises(PublicIntakeHttpError, match="public_route_http_418"):
        timeout_source.capture()
    assert timeout_extensions == [{"connect": 18.0, "read": 18.0, "write": 18.0, "pool": 18.0}]


def test_config_loader_rejects_writable_and_duplicate_key_files(intake_scenario, tmp_path) -> None:
    path = tmp_path / "config.json"
    path.write_bytes(canonical_json_bytes(intake_scenario.config))
    path.chmod(0o600)
    assert load_config(path) == intake_scenario.config

    path.chmod(0o622)
    with pytest.raises(ValueError, match="unsafe_monitor_config_file"):
        load_config(path)

    path.chmod(0o600)
    path.write_text('{"schema":"umi-public-intake-monitor-config/1","schema":"duplicate"}')
    with pytest.raises(ValueError, match="duplicate JSON object key"):
        load_config(path)


def test_monitor_has_no_chain_or_wallet_write_surface() -> None:
    paths = (
        Path("src/umi/public_intake_monitor.py"),
        Path("src/umi/public_intake_http.py"),
        Path("src/umi/public_intake_archive.py"),
        Path("src/umi/public_intake_monitor_cli.py"),
    )
    combined = "\n".join(path.read_text() for path in paths)
    assert "bittensor" not in combined
    assert "import bittensor" not in combined
    assert "from bittensor" not in combined
    assert "client.post(" not in combined
    assert "client.put(" not in combined
    assert "client.delete(" not in combined
    assert "client.patch(" not in combined
    assert "self.client.stream(" in combined
    assert '"GET",' in Path("src/umi/public_intake_http.py").read_text()
    assert json.loads(canonical_json_bytes({"chain_writes_authorized": False})) == {
        "chain_writes_authorized": False
    }


def test_deployment_examples_parse_and_match_cli_contract() -> None:
    root = Path("deploy/public-intake-monitor")
    config = load_config(root / "config.json.example")
    assert config.validator_age_thresholds.model_dump() == {
        "schema_": "umi-validator-age-thresholds/1",
        "warning_blocks": 200,
        "investigate_blocks": 240,
        "critical_blocks": 300,
        "stale_blocks": 360,
    }
    assert config.expected_identities[0].acceptance_not_before_block == 9_085_463
    assert (
        config.expected_identities[0].acceptance_not_before_block
        < config.expected_identities[0].not_before_checked_block
    )
    assert config.expected_identities[0].expected_baseline_promotion_sha256 == (
        "911a2342bcd7bf74d02d896d0a398b1ad800aa0fc26bfda6097baf1ff4388279"
    )

    with (root / "launchd/vision.umi.public-intake-monitor.plist").open("rb") as stream:
        launchd = plistlib.load(stream)
    launchd_arguments = launchd["ProgramArguments"]
    assert launchd_arguments[1] == "poll"
    assert launchd_arguments[-2:] == [
        "--archive-root",
        "/var/db/umi-public-intake-monitor",
    ]
    assert launchd["StartInterval"] == 300

    service = (root / "systemd/umi-public-intake-monitor.service").read_text()
    timer = (root / "systemd/umi-public-intake-monitor.timer").read_text()
    assert "User=umi-intake-audit" in service
    assert "ProtectSystem=strict" in service
    assert "TimeoutStartSec=900" in service
    assert "OnUnitActiveSec=5min" in timer
    assert "--archive-root /var/lib/umi-public-intake-monitor" in service

    rejected = _parser().parse_args(
        [
            "verify-rejected",
            "--archive-root",
            "/var/lib/umi-public-intake-monitor",
            "--rejected-capture",
            "0000000000000000-0000000000000000-0000000000000000",
        ]
    )
    assert rejected.command == "verify-rejected"
