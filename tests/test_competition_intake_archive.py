from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from umi.competition_api import create_app
from umi.competition_artifacts import preserve_bundle
from umi.competition_client import AdmissionReceipt
from umi.competition_intake_archive import (
    IntakeArchiveConfig,
    IntakeArchiveManifest,
    export_intake_archive,
    load_intake_archive,
)
from umi.competition_service import CompetitionServiceConfig, RetainedIntakeState, create_intake_app
from umi.competition_store import CompetitionStore, HistoricalIntakeArchiveBinding
from umi.open_competition import CompetitionPolicy, digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_competition_policy_transition import accepted_predecessor, deployment, policies
from .test_open_competition import bundle_at


@pytest.fixture
def policy():
    return policies()[0]


def archived_v1(tmp_path: Path):
    prior, successor = policies()
    public_deployment = deployment()
    signed, receipt = accepted_predecessor(prior)
    store = CompetitionStore(
        tmp_path / "v1-state",
        prior,
        public_launch=public_deployment.launch_identity(),
    )
    baseline_source = tmp_path / "v1-baseline-source"
    baseline_archive = tmp_path / "v1-baseline-archive"
    baseline = bundle_at(baseline_source).model_copy(update={"license_id": "MIT"})
    preserve_bundle(baseline, baseline_source, baseline_archive, prior)
    store.initialize_baseline(baseline, baseline_archive)
    saved = AdmissionReceipt.model_validate_json(
        canonical_json_bytes(
            store.admit(
                signed,
                receipt.registration_snapshot,
                receipt.accepted_block,
                registration_source="verifier_attested_finality",
            )
        )
    )
    checkpoint = tmp_path / "v1-checkpoint"
    checkpoint.mkdir(mode=0o700)
    store = CompetitionStore(
        store.directory,
        prior,
        public_launch=public_deployment.launch_identity(),
        migrate_writer_generation=True,
        submission_head_checkpoint_directory=checkpoint,
        initial_checkpoint_submission_sha256s=(digest(signed.submission),),
        initial_checkpoint_baseline_promotion_sha256=store.baseline_summary()["promotion_sha256"],
        initialize_submission_checkpoint=True,
    )
    destination = tmp_path / "v1-archive"
    result = export_intake_archive(store, destination, confirmed_quiesced=True)
    config = IntakeArchiveConfig(
        schema="umi-competition-intake-archive-config/1",
        directory=str(destination),
        manifest_sha256=result["manifest_sha256"],
    )
    return prior, successor, public_deployment, signed, saved, config


def test_archive_is_policy_qualified_and_does_not_enter_current_log(tmp_path: Path):
    prior, successor, public_deployment, signed, saved, config = archived_v1(tmp_path)
    archive = load_intake_archive(config)
    assert archive.manifest.source_checkpoint_sha256 is not None
    current = CompetitionStore(
        tmp_path / "v2-state",
        successor,
        public_launch=public_deployment.launch_identity(),
        historical_intake_archive_bindings=(
            HistoricalIntakeArchiveBinding(
                schema="umi-historical-intake-archive-binding/1",
                policy_sha256=digest(prior),
                manifest_sha256=archive.manifest_sha256,
            ),
        ),
    )

    async def snapshot():
        return saved.registration_snapshot

    app = create_app(
        current,
        snapshot,
        public_deployment=public_deployment,
        historical_archives=(archive,),
    )
    submission_sha256 = digest(signed.submission)
    policy_sha256 = digest(prior)
    with TestClient(app) as client:
        status = client.get("/v1/competition/status")
        current_log = client.get("/v1/competition/submissions")
        current_exact = client.get(f"/v1/competition/submissions/{submission_sha256}")
        archived_manifest = client.get(f"/v1/competition/archives/{policy_sha256}/manifest")
        archived_log = client.get(f"/v1/competition/archives/{policy_sha256}/submissions")
        archived_exact = client.get(
            f"/v1/competition/archives/{policy_sha256}/submissions/{submission_sha256}"
        )

    assert status.status_code == 200
    assert status.json()["historical_intake_archives"] == [archive.summary()]
    assert current_log.json()["items"] == []
    assert current_exact.status_code == 404
    assert archived_manifest.status_code == 200
    assert hashlib.sha256(archived_manifest.content).hexdigest() == archive.manifest_sha256
    assert archived_manifest.content == canonical_json_bytes(archive.manifest)
    assert archived_log.json()["items"][0]["submission_sha256"] == submission_sha256
    assert archived_exact.status_code == 200
    reference = archive.manifest.records[0]
    assert hashlib.sha256(archived_exact.content).hexdigest() == reference.record_sha256
    assert archived_exact.json()["signed_submission"] == json.loads(canonical_json_bytes(signed))
    assert archived_exact.json()["receipt"] == saved.model_dump(mode="json", by_alias=True)


def test_archive_manifest_binding_is_restart_stable(tmp_path: Path):
    prior, successor, public_deployment, _signed, _saved, config = archived_v1(tmp_path)
    archive = load_intake_archive(config)
    state = tmp_path / "v2-state"
    binding = HistoricalIntakeArchiveBinding(
        schema="umi-historical-intake-archive-binding/1",
        policy_sha256=digest(prior),
        manifest_sha256=archive.manifest_sha256,
    )
    CompetitionStore(
        state,
        successor,
        public_launch=public_deployment.launch_identity(),
        historical_intake_archive_bindings=(binding,),
    )

    CompetitionStore(
        state,
        successor,
        public_launch=public_deployment.launch_identity(),
        historical_intake_archive_bindings=(binding,),
    )
    with pytest.raises(ValueError, match="bound historical intake archives"):
        CompetitionStore(
            state,
            successor,
            public_launch=public_deployment.launch_identity(),
            historical_intake_archive_bindings=(
                binding.model_copy(update={"manifest_sha256": "ff" * 32}),
            ),
        )


def test_public_archive_requires_the_ledger_bound_manifest(tmp_path: Path):
    _prior, successor, public_deployment, _signed, saved, config = archived_v1(tmp_path)
    archive = load_intake_archive(config)
    current = CompetitionStore(
        tmp_path / "v2-state",
        successor,
        public_launch=public_deployment.launch_identity(),
    )

    async def snapshot():
        return saved.registration_snapshot

    with pytest.raises(ValueError, match="ledger-bound archive manifests"):
        create_app(
            current,
            snapshot,
            public_deployment=public_deployment,
            historical_archives=(archive,),
        )


def test_archive_export_requires_confirmation_and_loader_rejects_record_mutation(tmp_path: Path):
    prior, _successor = policies()
    public_deployment = deployment()
    signed, receipt = accepted_predecessor(prior)
    store = CompetitionStore(
        tmp_path / "state",
        prior,
        public_launch=public_deployment.launch_identity(),
    )
    store.admit(
        signed,
        receipt.registration_snapshot,
        receipt.accepted_block,
        registration_source="verifier_attested_finality",
    )
    with pytest.raises(ValueError, match="stopped intake"):
        export_intake_archive(store, tmp_path / "archive", confirmed_quiesced=False)

    _prior, _successor, _deployment, signed, _saved, config = archived_v1(tmp_path / "durable")
    destination = Path(config.directory)
    record = destination / "records" / f"{digest(signed.submission)}.json"
    record.write_bytes(record.read_bytes() + b" ")
    with pytest.raises(ValueError, match="pinned digest"):
        load_intake_archive(config)


def test_archive_loader_recomputes_the_claimed_external_checkpoint(tmp_path: Path):
    _prior, _successor, _deployment, _signed, _saved, config = archived_v1(tmp_path)
    manifest_path = Path(config.directory) / "manifest.json"
    manifest = IntakeArchiveManifest.model_validate_json(manifest_path.read_bytes()).model_copy(
        update={"source_head_sha256": "ff" * 32}
    )
    payload = canonical_json_bytes(manifest)
    manifest_path.write_bytes(payload)
    changed = config.model_copy(update={"manifest_sha256": hashlib.sha256(payload).hexdigest()})

    with pytest.raises(ValueError, match="differs from its durable checkpoint"):
        load_intake_archive(changed)


def test_published_staged_policy_cannot_start_without_its_v1_archive(chain_config, tmp_path: Path):
    policy = CompetitionPolicy.model_validate_json(
        (Path(__file__).parents[1] / "docs/competition/FIRST_ROUND_STAGED_POLICY.json").read_bytes()
    )
    public_deployment = deployment()
    chain = chain_config.model_copy(update={"policy_sha256": digest(policy)})
    config = CompetitionServiceConfig(
        schema="umi-competition-service-config/2",
        mode="intake_no_weight",
        policy_sha256=digest(policy),
        public_deployment=public_deployment,
        retained_state=RetainedIntakeState(
            schema="umi-competition-retained-intake-state/1",
            baseline_promotion_sha256="11" * 32,
            required_submission_sha256s=(),
        ),
        state_directory=str(tmp_path / "v2-state"),
        submission_head_checkpoint_directory=str(tmp_path / "v2-checkpoint"),
        chain=chain,
    )

    with pytest.raises(ValueError, match="requires its pinned predecessor archive"):
        create_intake_app(config, policy)
