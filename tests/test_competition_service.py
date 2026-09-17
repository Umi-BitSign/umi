from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from umi.competition_api import PublicIntakeDeployment, PublicRoundSchedule
from umi.competition_artifacts import preserve_bundle
from umi.competition_chain import RegistrationCapture
from umi.competition_service import (
    CompetitionServiceConfig,
    RetainedIntakeState,
    create_intake_app,
    serve_intake,
)
from umi.competition_store import AdmissionCapacity, CompetitionStore
from umi.competition_store_migration_cli import migrate
from umi.competition_submission_checkpoint import SubmissionCheckpointError
from umi.open_competition import digest
from umi.policy import umi_source_tree_sha256
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_open_competition import bundle_at, snapshot, submission
from .test_open_competition import policy as policy


@pytest.fixture
def public_deployment():
    return PublicIntakeDeployment(
        schema="umi-competition-intake-deployment/2",
        repository="https://github.com/Umi-BitSign/umi",
        umi_git_revision="12" * 20,
        umi_source_tree_sha256=umi_source_tree_sha256(),
        deployed_at_utc="2026-09-17T12:00:00Z",
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
    )


@pytest.fixture
def config(chain_config, tmp_path, policy, public_deployment):
    state = tmp_path / "intake"
    checkpoint = tmp_path / "intake-checkpoint"
    checkpoint.mkdir(mode=0o700)
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    store = CompetitionStore(state, policy)
    store.initialize_baseline(baseline, archive)
    anchor_model = bundle_at(tmp_path / "anchor-model", marker="anchor-model")
    anchor_submission = submission(policy, bundle=anchor_model, name="Bob")
    anchor_snapshot = snapshot().model_copy(update={"block": 105})
    store.admit(anchor_submission, anchor_snapshot, 105)
    store.verify_retained_intake_state(
        baseline_promotion_sha256=store.baseline_summary()["promotion_sha256"],
        required_submission_sha256s=(digest(anchor_submission.submission),),
    )
    config = CompetitionServiceConfig(
        schema="umi-competition-service-config/2",
        mode="intake_no_weight",
        policy_sha256=digest(policy),
        public_deployment=public_deployment,
        retained_state=RetainedIntakeState(
            schema="umi-competition-retained-intake-state/1",
            baseline_promotion_sha256=store.baseline_summary()["promotion_sha256"],
            required_submission_sha256s=(digest(anchor_submission.submission),),
        ),
        state_directory=str(state),
        submission_head_checkpoint_directory=str(checkpoint),
        chain=chain_config,
    )
    migrate(state, policy, confirmed=True, service_config=config)
    return config


class Provider:
    def __init__(self, _config, _policy):
        self.started = False
        self.closed = False
        self.start_error = None
        self.error = None
        snap = snapshot()
        self.capture = RegistrationCapture(
            snapshot=snap,
            provenance={
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "genesis_block_hash": "0x" + "11" * 32,
                "block": snap.block,
                "block_hash": snap.block_hash,
                "state_root": "0x" + "22" * 32,
                "timestamp_ms": time.time_ns() // 1_000_000,
                "snapshot_sha256": digest(snap),
                "evidence_sha256": "33" * 32,
                "metadata_sha256": "44" * 32,
                "finality_evidence_sha256": "55" * 32,
                "finality_verifier_sha256": "66" * 32,
                "storage_proof_verifier_sha256": "77" * 32,
                "chain_submission_authorized": False,
                "private_path": "/PRIVATE/STATE",
                "rpc_url": "wss://PRIVATE.example",
            },
        )

    async def start(self):
        self.started = True
        if self.start_error:
            raise self.start_error

    async def collect(self):
        assert self.started and not self.closed
        if self.error:
            raise self.error
        return self.capture

    async def __call__(self):
        return (await self.collect()).snapshot

    async def aclose(self):
        self.closed = True


def app_for(config, policy):
    provider = Provider(config.chain, policy)
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)
    assert not provider.started
    return app, provider


def checkpoint_store(config, policy):
    return CompetitionStore(
        Path(config.state_directory),
        policy,
        admission_capacity=config.admission_capacity,
        public_launch=config.public_deployment.launch_identity(),
        submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
    )


def successor_launch(launch, offset):
    schedule = launch.round_schedule
    schedule = schedule.model_copy(
        update={
            field: getattr(schedule, field) + offset
            for field in (
                "intake_opened_block",
                "roster_close_earliest_block",
                "roster_close_latest_block",
                "work_signing_close_block",
                "evaluation_close_block",
                "protected_reference_reveal_block",
                "evidence_cutoff_block",
                "round_valid_through_block",
            )
        }
    )
    return launch.model_copy(update={"round_schedule": schedule})


def commit_public_launch_before_checkpoint(store, launch):
    """Reproduce the durable DB half of a launch-transition crash window."""

    with store._transaction() as connection:
        history = store._public_launch_history(connection)
        connection.execute(
            "INSERT INTO public_launch_history VALUES (?, ?, ?, ?)",
            (
                history[-1][0] + 1,
                digest(launch),
                digest(launch.round_schedule),
                canonical_json_bytes(launch),
            ),
        )
        connection.execute(
            "UPDATE metadata SET value=? WHERE key='public_launch_identity'",
            (digest(launch),),
        )


def test_lifecycle_readiness_and_real_admission(config, policy):
    app, provider = app_for(config, policy)
    with TestClient(app) as client:
        response = client.get("/v1/competition/readiness")
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        data = response.json()
        assert data["schema"] == "umi-competition-readiness/2"
        assert data["ready_for"] == "first_round_intake"
        assert data["deployment"]["umi_git_revision"] == "12" * 20
        assert data["round_schedule"]["evaluation_close_block"] == 150
        assert data["retained_state"] == config.retained_state.model_dump(
            mode="json", by_alias=True
        )
        assert data["retained_submission_head"]["record_count"] == 1
        assert len(data["retained_submission_head"]["head_sha256"]) == 64
        assert data["retained_submission_head"]["external_checkpoint_durable"] is True
        assert data["retained_submission_head"]["public_launch_sha256"] == digest(
            config.public_deployment.launch_identity()
        )
        assert not data["assignment_delivery_ready"]
        assert not data["model_intake_ready"]
        assert data["admission_accepting_new"]
        assert data["admission_phase"] == "open"
        assert data["admission_checked_block"] == 110
        assert not data["evaluation_ready"]
        assert not data["rewards_active"]
        assert not data["chain_submission_authorized"]
        assert data["registration_count"] == 2
        assert "PRIVATE" not in response.text
        signed = submission(policy)
        receipt = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert receipt.status_code == 200
        assert receipt.json()["registration_snapshot_sha256"] == digest(snapshot())
        assert receipt.json()["status"] == "accepted_no_weight"
        assert receipt.json()["registration_source"] == "verifier_attested_finality"
        status = client.get("/v1/competition/status").json()
        assert status["schema"] == "umi-competition-status/2"
        assert status["mode"] == "intake_no_weight"
        assert status["accepted_submission_count"] == 2
        assert status["retained_submission_head"]["record_count"] == 2
        assert len(status["retained_submission_head"]["head_sha256"]) == 64
        assert status["retained_submission_head"]["external_checkpoint_durable"] is True
        assert status["deployment"]["umi_git_revision"] == "12" * 20
        assert status["round_schedule"]["roster_close_earliest_block"] == 130
        assert status["admission_accepting_new"]
        assert status["admission_capacity_available"]
        assert status["admission_phase"] == "open"
        assert status["admission_checked_block"] == 110
        assert not status["assignment_delivery_ready"]
        assert not status["model_intake_ready"]
        assert not status["evaluation_ready"]
        assert not status["rewards_active"]
    assert provider.closed


def test_same_launch_checkpoint_restart_is_exact(config, policy):
    first = checkpoint_store(config, policy).retained_submission_head()
    second = checkpoint_store(config, policy).retained_submission_head()
    assert second == first
    assert second["public_launch_sha256"] == digest(config.public_deployment.launch_identity())


def test_db_first_launch_transition_recovers_the_exact_checkpoint(config, policy):
    current = config.public_deployment.launch_identity()
    successor = successor_launch(current, 100)
    store = checkpoint_store(config, policy)
    before = store.retained_submission_head()
    commit_public_launch_before_checkpoint(store, successor)

    recovered = CompetitionStore(
        Path(config.state_directory),
        policy,
        public_launch=successor,
        submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
    ).retained_submission_head()
    assert recovered["public_launch_sha256"] == digest(successor)
    assert recovered["record_count"] == before["record_count"]
    assert recovered["submission_set_sha256"] == before["submission_set_sha256"]


def test_database_rollback_after_checkpoint_launch_advance_is_rejected(config, policy, tmp_path):
    current = config.public_deployment.launch_identity()
    successor = successor_launch(current, 100)
    store = checkpoint_store(config, policy)
    database = store.path
    backup = tmp_path / "pre-successor.sqlite3"
    with sqlite3.connect(database) as source, sqlite3.connect(backup) as target:
        source.backup(target)
    commit_public_launch_before_checkpoint(store, successor)
    advanced = CompetitionStore(
        Path(config.state_directory),
        policy,
        public_launch=successor,
        submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
    )
    assert advanced.retained_submission_head()["public_launch_sha256"] == digest(successor)

    with sqlite3.connect(backup) as source, sqlite3.connect(database) as target:
        source.backup(target)
    with pytest.raises(SubmissionCheckpointError, match="immediate predecessor"):
        checkpoint_store(config, policy)


def test_checkpoint_from_older_than_immediate_launch_is_rejected(config, policy):
    first = config.public_deployment.launch_identity()
    second = successor_launch(first, 100)
    third = successor_launch(second, 100)
    store = checkpoint_store(config, policy)
    checkpoint = Path(config.submission_head_checkpoint_directory) / "submission-head.json"
    first_checkpoint = checkpoint.read_bytes()
    commit_public_launch_before_checkpoint(store, second)
    store = CompetitionStore(
        Path(config.state_directory),
        policy,
        public_launch=second,
        submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
    )
    commit_public_launch_before_checkpoint(store, third)
    checkpoint.write_bytes(first_checkpoint)
    checkpoint.chmod(0o600)

    with pytest.raises(SubmissionCheckpointError, match="immediate predecessor"):
        CompetitionStore(
            Path(config.state_directory),
            policy,
            public_launch=third,
            submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
        )


def test_live_intake_rejects_unpublished_model_runtime(config, policy, tmp_path):
    app, _provider = app_for(config, policy)
    model = submission(policy, bundle=bundle_at(tmp_path / "candidate"))
    with TestClient(app) as client:
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(model),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 409
    assert response.json() == {"detail": "model contribution intake is not open"}


def test_model_intake_gate_preserves_exact_historical_retry(config, policy, tmp_path):
    # Reproduce the model admission retained before this endpoint-only launch.
    model = submission(
        policy,
        bundle=bundle_at(tmp_path / "anchor-copy", marker="anchor-model"),
        name="Bob",
    )
    saved = checkpoint_store(config, policy).submission_by_digest(digest(model.submission))[
        "receipt"
    ]
    app, _provider = app_for(config, policy)
    with TestClient(app) as client:
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(model),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 200, response.json()
    assert response.json() == saved


def test_latest_roster_close_rejects_new_admission_but_preserves_retry(config, policy):
    saved_submission = submission(policy)
    saved = checkpoint_store(config, policy).admit(saved_submission, snapshot(), 110)
    app, provider = app_for(config, policy)
    closed = snapshot().model_copy(update={"block": 131})
    provider.capture = replace(
        provider.capture,
        snapshot=closed,
        provenance={
            **provider.capture.provenance,
            "block": closed.block,
            "snapshot_sha256": digest(closed),
        },
    )
    new_submission = submission(policy, sequence=2)
    with TestClient(app) as client:
        readiness = client.get("/v1/competition/readiness")
        assert readiness.status_code == 200
        assert readiness.json()["ready_for"] == "first_round_intake_closed"
        assert not readiness.json()["admission_accepting_new"]
        assert readiness.json()["admission_phase"] == "closed"
        assert readiness.json()["admission_checked_block"] == 131

        status = client.get("/v1/competition/status")
        assert status.status_code == 200
        assert not status.json()["admission_accepting_new"]
        assert status.json()["admission_phase"] == "closed"
        assert status.json()["admission_checked_block"] == 131

        rejected = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(new_submission),
            headers={"content-type": "application/json"},
        )
        assert rejected.status_code == 409
        assert rejected.json() == {"detail": "first-round endpoint intake is closed"}

        retry = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(saved_submission),
            headers={"content-type": "application/json"},
        )
        assert retry.status_code == 200
        assert retry.json() == saved


def test_latest_roster_close_block_remains_inclusive(config, policy):
    app, provider = app_for(config, policy)
    boundary = snapshot().model_copy(update={"block": 130})
    provider.capture = replace(
        provider.capture,
        snapshot=boundary,
        provenance={
            **provider.capture.provenance,
            "block": boundary.block,
            "snapshot_sha256": digest(boundary),
        },
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy)),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 200
    assert response.json()["status"] == "accepted_no_weight"


def test_status_reports_capacity_exhaustion(config, policy):
    limited = config.model_copy(update={"admission_capacity": AdmissionCapacity(maximum_records=2)})
    checkpoint_store(limited, policy).admit(submission(policy), snapshot(), 110)
    app, _provider = app_for(limited, policy)
    with TestClient(app) as client:
        readiness = client.get("/v1/competition/readiness")
        status = client.get("/v1/competition/status")
    assert readiness.status_code == 503
    assert status.status_code == 200
    assert not status.json()["admission_accepting_new"]
    assert status.json()["admission_phase"] == "capacity_exhausted"


def test_preopen_block_rejects_new_admission(config, policy):
    app, provider = app_for(config, policy)
    preopen = snapshot().model_copy(update={"block": 104})
    provider.capture = replace(
        provider.capture,
        snapshot=preopen,
        provenance={
            **provider.capture.provenance,
            "block": preopen.block,
            "snapshot_sha256": digest(preopen),
        },
    )
    with TestClient(app) as client:
        readiness = client.get("/v1/competition/readiness")
        assert readiness.status_code == 200
        assert readiness.json()["ready_for"] == "first_round_intake_not_open"
        assert not readiness.json()["admission_accepting_new"]
        assert readiness.json()["admission_phase"] == "not_open"

        status = client.get("/v1/competition/status")
        assert status.status_code == 200
        assert not status.json()["admission_accepting_new"]
        assert status.json()["admission_phase"] == "not_open"

        rejected = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy)),
            headers={"content-type": "application/json"},
        )
        assert rejected.status_code == 409
        assert rejected.json() == {"detail": "first-round endpoint intake is not open"}


def test_intake_opened_block_is_inclusive(config, policy):
    app, provider = app_for(config, policy)
    opened = snapshot().model_copy(update={"block": 105})
    provider.capture = replace(
        provider.capture,
        snapshot=opened,
        provenance={
            **provider.capture.provenance,
            "block": opened.block,
            "snapshot_sha256": digest(opened),
        },
    )
    with TestClient(app) as client:
        response = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy)),
            headers={"content-type": "application/json"},
        )
    assert response.status_code == 200, response.json()
    assert response.json()["status"] == "accepted_no_weight"


def test_startup_failure_closes_provider(config, policy):
    app, provider = app_for(config, policy)
    provider.start_error = RuntimeError("observer startup failed")
    with pytest.raises(RuntimeError, match="startup"), TestClient(app):
        pytest.fail("startup failure must not serve intake")
    assert provider.closed


def test_deployment_manifest_must_match_running_source(config, policy):
    mismatched = config.model_copy(
        update={
            "public_deployment": config.public_deployment.model_copy(
                update={"umi_source_tree_sha256": "13" * 32}
            )
        }
    )
    with pytest.raises(ValueError, match="does not match the running UMI source tree"):
        create_intake_app(mismatched, policy)


def test_service_refuses_a_new_or_mistyped_ledger_path(config, policy, tmp_path):
    changed = config.model_copy(update={"state_directory": str(tmp_path / "wrong-ledger")})
    with pytest.raises(ValueError, match="pre-existing durable ledger"):
        create_intake_app(changed, policy, provider_factory=Provider)


def test_service_refuses_another_baseline(config, policy):
    changed = config.model_copy(
        update={
            "retained_state": config.retained_state.model_copy(
                update={"baseline_promotion_sha256": "13" * 32}
            )
        }
    )
    with pytest.raises(ValueError, match="another baseline"):
        create_intake_app(changed, policy, provider_factory=Provider)


def test_service_requires_every_anchored_submission(config, policy):
    changed = config.model_copy(
        update={
            "retained_state": config.retained_state.model_copy(
                update={"required_submission_sha256s": ("13" * 32,)}
            )
        }
    )
    with pytest.raises(ValueError, match="missing required submissions"):
        create_intake_app(changed, policy, provider_factory=Provider)


@pytest.mark.parametrize(
    "statement,parameters",
    [
        ("UPDATE submissions SET body=?", (b"{}",)),
        ("UPDATE submissions SET receipt=?", (b"{}",)),
        ("UPDATE submissions SET hotkey=?", ("00" * 32,)),
    ],
)
def test_service_replays_every_retained_submission_row(config, policy, statement, parameters):
    store = checkpoint_store(config, policy)
    with store._connection() as connection:
        connection.execute(statement, parameters)
    with pytest.raises(RuntimeError, match="checkpoint is ahead of or differs"):
        create_intake_app(config, policy, provider_factory=Provider)


def test_service_replays_retained_baseline_body(config, policy):
    store = checkpoint_store(config, policy)
    with store._connection() as connection:
        connection.execute("UPDATE promotions SET body=?", (b"{}",))
    with pytest.raises(ValueError, match=r"promotion history|retained baseline"):
        create_intake_app(config, policy, provider_factory=Provider)


def test_service_rejects_retained_baseline_that_is_not_current_head(config, policy):
    store = checkpoint_store(config, policy)
    with store._connection() as connection:
        connection.execute(
            "INSERT INTO promotions VALUES (?, ?, ?, ?, ?)",
            (2, "23" * 32, "24" * 32, None, b"{}"),
        )
    with pytest.raises(ValueError, match="current promotion head"):
        store.verify_retained_intake_state(
            baseline_promotion_sha256=config.retained_state.baseline_promotion_sha256,
            required_submission_sha256s=config.retained_state.required_submission_sha256s,
        )


def test_service_rejects_post_anchor_submission_deletion(config, policy):
    store = checkpoint_store(config, policy)
    later = submission(policy, sequence=2, name="Bob")
    later_snapshot = snapshot().model_copy(update={"block": 110})
    store.admit(later, later_snapshot, 110)
    with store._connection() as connection:
        connection.execute("DELETE FROM submissions WHERE digest=?", (digest(later.submission),))
    with pytest.raises(ValueError, match="retained submission head"):
        create_intake_app(config, policy, provider_factory=Provider)


def test_service_does_not_recreate_a_deleted_submission_head(config, policy):
    store = checkpoint_store(config, policy)
    with store._connection() as connection:
        connection.execute("DELETE FROM metadata WHERE key='retained_submission_head'")
    with pytest.raises(ValueError, match="retained submission head is missing"):
        create_intake_app(config, policy, provider_factory=Provider)


def test_service_never_bootstraps_a_missing_external_checkpoint(config, policy):
    checkpoint = Path(config.submission_head_checkpoint_directory) / "submission-head.json"
    checkpoint.unlink()
    with pytest.raises(SubmissionCheckpointError, match="checkpoint is missing"):
        create_intake_app(config, policy, provider_factory=Provider)
    assert not checkpoint.exists()


def test_checkpoint_requirement_survives_initialization_crash(config, policy):
    state = Path(config.state_directory)
    store = checkpoint_store(config, policy)
    checkpoint = Path(config.submission_head_checkpoint_directory) / "submission-head.json"
    checkpoint.unlink()
    with store._connection() as connection:
        connection.execute("DELETE FROM metadata WHERE key='submission_head_checkpoint_binding'")

    with pytest.raises(ValueError, match="requires its configured submission checkpoint"):
        CompetitionStore(
            state,
            policy,
            public_launch=config.public_deployment.launch_identity(),
        )
    with pytest.raises(SubmissionCheckpointError, match="checkpoint is missing"):
        checkpoint_store(config, policy)

    result = migrate(state, policy, confirmed=True, service_config=config)
    assert result["retained_submission_head"]["external_checkpoint_durable"] is True


def test_restoring_older_whole_sqlite_after_acknowledged_admission_fails_startup(
    config, policy, tmp_path
):
    database = Path(config.state_directory) / "competition.sqlite3"
    old_database = tmp_path / "old-competition.sqlite3"
    with sqlite3.connect(database) as source, sqlite3.connect(old_database) as target:
        source.backup(target)

    accepted = submission(policy)
    checkpoint_store(config, policy).admit(
        accepted,
        snapshot(),
        110,
        registration_source="verifier_attested_finality",
    )
    assert checkpoint_store(config, policy).retained_submission_head()["record_count"] == 2

    with sqlite3.connect(old_database) as source, sqlite3.connect(database) as target:
        source.backup(target)
    with pytest.raises(SubmissionCheckpointError, match="ahead of or differs"):
        create_intake_app(config, policy, provider_factory=Provider)


@pytest.mark.parametrize("checkpoint_was_replaced", [False, True])
def test_checkpoint_crash_window_never_loses_an_acknowledged_receipt(
    config, policy, monkeypatch, checkpoint_was_replaced
):
    app, provider = app_for(config, policy)
    store = app.state.competition_store
    checkpoint_file = store._submission_checkpoint
    original_replace = checkpoint_file.replace
    failed = False

    def crash_during_replace(checkpoint):
        nonlocal failed
        if checkpoint.record_count == 2 and not failed:
            failed = True
            if checkpoint_was_replaced:
                original_replace(checkpoint)
            raise SubmissionCheckpointError("simulated process loss around checkpoint replace")
        original_replace(checkpoint)

    monkeypatch.setattr(checkpoint_file, "replace", crash_during_replace)
    signed = submission(policy)
    with TestClient(app) as client:
        first = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert first.status_code == 503
        with sqlite3.connect(Path(config.state_directory) / "competition.sqlite3") as connection:
            saved = json.loads(
                connection.execute(
                    "SELECT receipt FROM submissions WHERE digest=?",
                    (digest(signed.submission),),
                ).fetchone()[0]
            )

        if not checkpoint_was_replaced:
            failed = False
            listing = client.get("/v1/competition/submissions")
            assert listing.status_code == 503
            failed = False
            exact = client.get(f"/v1/competition/submissions/{digest(signed.submission)}")
            assert exact.status_code == 503

        # The exact historical path does not collect finality. It first repairs
        # an old checkpoint, or verifies the replacement that reached disk.
        monkeypatch.setattr(checkpoint_file, "replace", original_replace)
        provider.error = RuntimeError("finality is unavailable")
        retry = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert retry.status_code == 200
        assert retry.json() == saved
        head = client.get("/v1/competition/status").json()["retained_submission_head"]
        assert head["record_count"] == 2
        assert head["external_checkpoint_durable"] is True


def test_retained_submission_anchor_is_canonical(config):
    raw = config.retained_state.model_dump(mode="json", by_alias=True)
    raw["required_submission_sha256s"] = ["22" * 32, "11" * 32]
    with pytest.raises(ValueError, match="sorted and unique"):
        RetainedIntakeState.model_validate_json(canonical_json_bytes(raw))


@pytest.mark.parametrize(
    "eligible_tracks,model_intake_ready",
    [
        (("model", "endpoint"), True),
        (("endpoint", "endpoint"), False),
        (("endpoint", "model"), False),
        (("endpoint",), True),
    ],
)
def test_deployment_manifest_requires_canonical_consistent_tracks(
    public_deployment, eligible_tracks, model_intake_ready
):
    with pytest.raises(ValueError):
        PublicIntakeDeployment.model_validate(
            {
                **public_deployment.model_dump(mode="json", by_alias=True),
                "eligible_tracks": eligible_tracks,
                "model_intake_ready": model_intake_ready,
            }
        )


def test_intake_state_allows_new_deployment_metadata_for_same_launch(config, policy):
    create_intake_app(config, policy, provider_factory=Provider)
    changed = config.model_copy(
        update={
            "public_deployment": config.public_deployment.model_copy(
                update={"deployed_at_utc": "2026-09-17T12:00:01Z"}
            )
        }
    )
    create_intake_app(changed, policy, provider_factory=Provider)


def test_intake_state_rejects_a_different_public_launch(config, policy):
    create_intake_app(config, policy, provider_factory=Provider)
    changed = config.model_copy(
        update={
            "public_deployment": config.public_deployment.model_copy(
                update={
                    "round_schedule": config.public_deployment.round_schedule.model_copy(
                        update={"intake_opened_block": 104}
                    )
                }
            )
        }
    )
    with pytest.raises(ValueError, match=r"checkpoint|overlaps or rolls back"):
        create_intake_app(changed, policy, provider_factory=Provider)


def test_status_fails_closed_when_registration_state_is_unavailable(config, policy):
    app, provider = app_for(config, policy)
    provider.capture.provenance["timestamp_ms"] = (
        time.time_ns() // 1_000_000 - config.chain.maximum_head_age_ms - 1
    )
    with TestClient(app) as client:
        response = client.get("/v1/competition/status")
    assert response.status_code == 200
    assert not response.json()["admission_accepting_new"]
    assert response.json()["admission_phase"] == "unverified"
    assert response.json()["admission_checked_block"] is None
    assert "PRIVATE" not in response.text


@pytest.mark.parametrize("route", ["readiness", "submissions"])
def test_failed_proofs_never_accept_and_hide_private_details(config, policy, route):
    app, provider = app_for(config, policy)
    provider.error = RuntimeError("PRIVATE RPC OR PATH")
    with TestClient(app) as client:
        if route == "readiness":
            reply = client.get("/v1/competition/readiness")
        else:
            reply = client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(submission(policy)),
                headers={"content-type": "application/json"},
            )
        assert reply.status_code == 503
        assert "PRIVATE" not in reply.text


@pytest.mark.parametrize(
    "change",
    [
        {"snapshot_sha256": "00" * 32},
        {"block": 111},
        {"block_hash": "0x" + "00" * 32},
        {"offline_finality_proof": True},
        {"chain_submission_authorized": True},
        {"evidence_class": "rpc_finalized_label"},
        {"schema": "other"},
    ],
)
def test_readiness_rejects_bad_provenance(config, policy, change):
    app, provider = app_for(config, policy)
    provider.capture.provenance.update(change)
    with TestClient(app) as client:
        assert client.get("/v1/competition/readiness").status_code == 503


def test_readiness_requires_complete_provenance(config, policy):
    app, provider = app_for(config, policy)
    del provider.capture.provenance["evidence_sha256"]
    with TestClient(app) as client:
        assert client.get("/v1/competition/readiness").status_code == 503


def test_expired_policy_holds_readiness_and_admission(config, policy):
    app, provider = app_for(config, policy)
    provider.capture = replace(provider.capture, snapshot=snapshot(block=1001))
    with TestClient(app) as client:
        assert client.get("/v1/competition/readiness").status_code == 503
        assert (
            client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(submission(policy)),
                headers={"content-type": "application/json"},
            ).status_code
            == 503
        )


@pytest.mark.parametrize(
    "change",
    [
        {"host": "0.0.0.0"},
        {"state_directory": "/"},
        {"state_directory": "relative"},
        {"wallet_name": "forbidden"},
        {"mode": "live_weights"},
        {"port": 80},
        {"policy_sha256": "00" * 32},
    ],
)
def test_config_rejects_unsafe_or_unbound_fields(config, change):
    raw = config.model_dump(mode="json", by_alias=True)
    raw.update(change)
    with pytest.raises(ValueError):
        CompetitionServiceConfig.model_validate_json(canonical_json_bytes(raw))


@pytest.mark.parametrize("relative", [".", "inside", ".."])
def test_config_disallows_overlapping_state(config, relative):
    from pathlib import Path

    raw = config.model_dump(mode="json", by_alias=True)
    raw["state_directory"] = str((Path(config.chain.state_directory) / relative).resolve())
    with pytest.raises(ValueError, match="overlap"):
        CompetitionServiceConfig.model_validate_json(canonical_json_bytes(raw))


def test_config_proof_deadline_fits_request_timeout(config):
    raw = config.model_dump(mode="json", by_alias=True)
    raw["chain"]["collection_timeout_seconds"] = 16
    with pytest.raises(ValueError, match="15 seconds"):
        CompetitionServiceConfig.model_validate_json(canonical_json_bytes(raw))


def test_startup_rejects_round_longer_than_submission_lifetime(config, policy):
    short_policy = policy.model_copy(update={"maximum_submission_lifetime_blocks": 40})
    policy_sha256 = digest(short_policy)
    changed = config.model_copy(
        update={
            "policy_sha256": policy_sha256,
            "chain": config.chain.model_copy(update={"policy_sha256": policy_sha256}),
        }
    )
    with pytest.raises(ValueError, match="maximum submission lifetime"):
        create_intake_app(changed, short_policy, provider_factory=Provider)


def test_startup_rejects_signing_window_older_than_snapshot_limit(config, policy):
    schedule = config.public_deployment.round_schedule.model_copy(
        update={"roster_close_earliest_block": 129}
    )
    changed = config.model_copy(
        update={
            "public_deployment": config.public_deployment.model_copy(
                update={"round_schedule": schedule}
            )
        }
    )
    with pytest.raises(ValueError, match="outlive its registration snapshot"):
        create_intake_app(changed, policy, provider_factory=Provider)


def test_serve_intake_uses_one_loopback_worker_without_proxy_trust(config, policy, monkeypatch):
    calls = []
    app = object()
    monkeypatch.setattr("umi.competition_service.create_intake_app", lambda *_: app)
    monkeypatch.setattr(
        "umi.competition_service_supervision.serve_with_finality_supervision",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    serve_intake(config, policy)
    assert calls == [
        (
            (app,),
            {
                "host": "127.0.0.1",
                "port": 8098,
                "workers": 1,
                "proxy_headers": False,
                "access_log": False,
                "backlog": 128,
            },
        )
    ]


async def test_client_verified_service_retries_without_personal_credentials(config, policy):
    from umi.competition_client import submit_signed_submission

    app, provider = app_for(config, policy)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        signed = submission(policy)
        first = await submit_signed_submission(
            origin="https://intake.example", policy=policy, signed=signed, transport=transport
        )
        second = await submit_signed_submission(
            origin="https://intake.example", policy=policy, signed=signed, transport=transport
        )
        assert first == second
    assert provider.closed


def test_authenticated_historical_retry_survives_proof_outage(config, policy):
    app, provider = app_for(config, policy)
    signed = submission(policy)
    with TestClient(app) as client:
        original = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert original.status_code == 200
        provider.error = RuntimeError("PRIVATE PROOF FAILURE")
        retry = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert retry.status_code == 200
        assert retry.json() == original.json()
        # Public reads may use the last verified capture only for its bounded
        # cache lifetime. They do not trigger another failing proof collection.
        assert client.get("/v1/competition/readiness").status_code == 200
        new_request = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy, name="Bob")),
            headers={"content-type": "application/json"},
        )
        assert new_request.status_code == 503
        bad_signature = signed.model_copy(
            update={
                "signature": signed.signature.model_copy(update={"signature": "0x" + "00" * 64}),
            }
        )
        assert (
            client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(bad_signature),
                headers={"content-type": "application/json"},
            ).status_code
            == 422
        )
