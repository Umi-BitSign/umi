"""Synthetic successor direct object delivery through native certification.

The provider, finality, inference and scratch filesystem are explicit fixture
ports. These cases do not select or rewrite any production cohort plan.
"""

import asyncio
import hashlib
import inspect
import json
from collections import Counter
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_direct_model_review as review_module
from umi import competition_cohort_service_host as service_module
from umi.competition_artifacts import preserve_bundle, verify_preserved_bundle
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_direct_model_owner import DirectModelUploadOwner
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelMaterialization,
    DirectModelReviewSourceConfig,
    DirectModelSettlementVerifier,
)
from umi.competition_cohort_direct_model_upload import preserved_model_object_key
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_execution_journal import case_role_model
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_intake_records import read_participation
from umi.competition_cohort_model_client import submit_cohort_model
from umi.competition_cohort_model_review import ModelArtifactReviewer, ModelReviewConfig
from umi.competition_cohort_model_review_http import ModelReviewPeer, model_review_routes
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_cohort_sandbox import DirectCohortCpuSandbox
from umi.competition_cohort_service_host import DirectModelUploadHostConfig
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_execution import execution_boundary
from umi.open_competition import ModelBundle, digest, identity, sign_object, verify_signature
from umi.private_files import ensure_private_directory
from umi.protocol import canonical_json_bytes

from .cohort_native_direct_provider_fixture import NativeMultipart
from .test_competition_cohort_native_pipeline import (
    base_policy as base_policy,
)
from .test_competition_cohort_native_pipeline import (
    chain_config as chain_config,
)
from .test_competition_cohort_native_pipeline import (
    host as host,
)
from .test_competition_cohort_native_pipeline import (
    intake as intake,
)
from .test_competition_cohort_native_pipeline import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_native_pipeline import (
    lifecycle as lifecycle,
)
from .test_competition_cohort_native_pipeline import (
    lifecycle_before_intake as lifecycle_before_intake,
)
from .test_competition_cohort_native_pipeline import (
    model_request,
    precommit_model_inventory,
    run_pipeline,
)
from .test_competition_cohort_native_pipeline import (
    policy as native_policy,  # noqa: F401
)
from .test_competition_cohort_native_pipeline import (
    recovery as recovery,
)
from .test_competition_cohort_native_pipeline import (
    runtime as runtime,
)
from .test_competition_cohort_native_pipeline import (
    scenario as single_scenario,  # noqa: F401
)
from .test_competition_cohort_recovery import signatures as quorum_signatures
from .test_competition_cohort_standing_phases import standing
from .test_open_competition import bundle_at, wallet


def direct_inventory(h):
    precommit_model_inventory(h)
    source = Path(h.intake.config.directory).parent / "model-submission"
    data = b"INERT MULTIPART WEIGHTS\n" + bytes(5 * 1024**2)
    (source / "weights.txt").write_bytes(data)
    h.model = h.model.model_copy(
        update={
            "files": tuple(
                record.model_copy(
                    update={"size_bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                )
                if record.role == "weights"
                else record
                for record in h.model.files
            )
        }
    )


pytestmark = pytest.mark.parametrize("lifecycle_before_intake", [direct_inventory], indirect=True)


@pytest.fixture
def policy(native_policy):  # noqa: F811
    return native_policy.model_copy(update={"maximum_bundle_bytes": 16 * 1024**2})


@pytest.fixture
def scenario(single_scenario, policy, request):  # noqa: F811
    model_only = getattr(request, "param", {}).get("model_only", False)
    old = single_scenario["intake_history"]
    plan = old.plan.model_copy(
        update={
            "schema_": "umi-recoverable-cohort-plan/4",
            "sequence": 6 if model_only else 7,
            "eligible_tracks": ("model",) if model_only else ("endpoint", "model"),
            "service_pool_bps": 0 if model_only else 5000,
            "request_tail_rule": "original_request_12h_with_completed_miner/1",
            "model_delivery": ModelDeliveryProfile(
                schema="umi-model-delivery-profile/1",
                mechanism="direct_r2_multipart_v1",
                part_size_bytes=5 * 1024**2,
                maximum_concurrent_parts=2,
                capability_ttl_seconds=900,
            ),
        }
    )
    authority, genesis, _ = standing(
        plan,
        policy,
        model_rewards=True,
        model_rule=(
            "baseline_or_better_geometric_bands_first_complete/1"
            if model_only
            else "baseline_or_better_quality_bucket_best_score_first_complete/1"
        ),
        model_quality_bucket_width_bps=None if model_only else 500,
        model_reward_parameters=(
            {
                "schema": "umi-geometric-reward-parameters/2",
                "band_width_bps": 250,
                "band_decay_bps": 7500,
                "within_band_decay_bps": 7500,
                "score_duplicate_tolerance_bps": 1,
            }
            if model_only
            else None
        ),
    )
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=quorum_signatures(genesis),
        transitions=(),
    )
    consent = single_scenario["consent"].consent.model_copy(
        update={
            "authority_sha256": digest(authority.authority),
            "cohort_sha256": digest(plan),
        }
    )
    return dict(
        single_scenario,
        intake_history=history,
        consent=single_scenario["consent"].model_copy(
            update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))},
        ),
    )


class NativeDirect:
    def __init__(self, root, policy, monkeypatch):
        self.root, self.policy = root, policy
        self.provider = NativeMultipart(lose_first_complete_reply=True)
        self.reviewers, self.artifacts, self.readers, self.reservations = {}, {}, {}, []
        self.candidate_invocations = Counter()
        self.candidate_jobs = {}
        self.candidate_trace = []
        self.standing = StandingModelReviewPolicy(
            schema="umi-standing-model-artifact-review-policy/1",
            competition_policy_sha256=digest(policy),
            contribution_terms_sha256=policy.contribution_terms_sha256,
            standing_approval_record_sha256="ab" * 32,
            approved_by="operator@example.test",
            approved_at_utc="2026-10-02T12:00:00Z",
            complete_declared_bundle_rights_approved=True,
            licenses_and_notices_reviewed=True,
            public_redistribution_and_evaluation_approved=True,
        )
        monkeypatch.setattr(
            service_module,
            "load_r2_credentials",
            lambda _: SimpleNamespace(
                endpoint=self.provider.signer.endpoint,
                credentials=self.provider.signer.credentials,
            ),
        )
        monkeypatch.setattr(service_module, "R2MultipartClient", lambda *a, **kw: self.provider)
        monkeypatch.setattr(service_module, "load_named_hotkey", lambda *a: wallet("Charlie"))
        self.protected = root / "protected"
        ensure_private_directory(self.protected)
        # This only tests the native policy checks, not dedicated disk provisioning.
        monkeypatch.setattr(
            review_module, "_filesystem_device", lambda p: 1 if p == self.protected else 2
        )
        monkeypatch.setattr(
            review_module,
            "_filesystem_usage",
            lambda p: SimpleNamespace(total=80 * 1024**3, free=70 * 1024**3),
        )

    def owner_config(self, o):
        return dict(
            schema="umi-cohort-service-admission-host/9",
            model_uploads=None,
            direct_model_uploads=DirectModelUploadHostConfig(
                schema="umi-direct-model-upload-host/1",
                directory=str(self.root / "uploads"),
                owner_hotkey=wallet("Charlie").hotkey.ss58_address,
                owner_key_file=o.config.admission_owner.owner_key_file,
                r2_credentials_file=str(self.root / "owner-credentials"),
                r2_bucket="umi-model-artifacts",
                standing_review_policy=self.standing,
            ),
        )

    async def accept_model(self, o, scenario):
        h = o.h
        baseline_sha = h.owner.promotion.baseline()["model_sha256"]
        baseline = ModelBundle.model_validate_json(
            (
                Path(h.intake.config.directory).parent / "archive" / baseline_sha / "manifest.json"
            ).read_bytes()
        )
        SettlementEvidenceFiles(Path(o.config.lifecycle.sources.objects_directory)).publish(
            baseline_sha, lambda _: canonical_json_bytes(baseline)
        )
        requests = [
            read_participation(raw).request
            for _, raw in h.intake.export_records(
                h.cohort, maximum_bytes=1024**2, maximum_records=8
            )
        ]
        h.block += 5
        submitted = model_request(scenario, h.model, sequence=3, block=h.block)
        requests.append(submitted)
        owner = o.service.direct_uploads.owners[h.cohort]
        # Constructor catalog iteration must not overwrite the captured key.
        probe = await owner.sign(h.history.plan)
        assert probe.hotkey == o.config.admission_owner.owner_hotkey
        verify_signature(h.history.plan, probe)

        def application(owner):
            app = FastAPI()
            app.include_router(
                cohort_routes(
                    h.intake,
                    o.service.capture,
                    maximum_body_bytes=4 * 1024**2,
                    models=o.service.payloads,
                )
            )
            app.include_router(direct_model_upload_routes(owner))
            return app

        async def deliver(request, app):
            events = []
            operation = submit_cohort_model(
                origin="https://intake.example",
                policy=h.intake.policy,
                request=request,
                source=Path(h.intake.config.directory).parent / "model-submission",
                wallet=wallet("Alice"),
                transport=httpx.ASGITransport(app),
                object_transport=self.provider.transport,
                retry_seconds=0.01,
                report=events.append,
            )
            try:
                return await asyncio.wait_for(operation, 120)
            except asyncio.TimeoutError as error:
                raise AssertionError(events[-10:]) from error

        async def poll():
            while True:
                await o.service.direct_uploads.poll_once()
                await asyncio.sleep(0.005)

        task = asyncio.create_task(poll())
        try:
            app = application(owner)
            for request in requests:
                receipt = await deliver(request, app)
                assert receipt.status == "pending_attestation"
                artifact = owner.review_artifact(request)
                assert artifact.reservation.payload.upload_sha256 == digest(request)
                assert artifact.reservation.payload.total_parts == 2
                self.reservations.append(artifact)
            uploads_before = len(self.provider.create_calls)
            mutations_before = (
                len(self.provider.put_calls),
                len(self.provider.complete_calls),
                len(self.provider.copy_calls),
                self.provider.bytes_uploaded,
            )
            reopened = DirectModelUploadOwner(
                owner.config,
                self.provider,
                authorize=owner.authorize,
                sign=owner.sign,
                policy=h.intake.policy,
            )
            o.service.direct_uploads.owners[h.cohort] = reopened
            assert await deliver(submitted, application(reopened)) == receipt
            assert reopened.review_artifact(submitted) == self.reservations[-1]
            assert len(self.provider.create_calls) == uploads_before
            assert mutations_before == (
                len(self.provider.put_calls),
                len(self.provider.complete_calls),
                len(self.provider.copy_calls),
                self.provider.bytes_uploaded,
            )
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
        capture = h.capture(h.block)
        h.queue.attach_evidence(
            h.cohort,
            digest(submitted.consent.consent),
            *await h.provider.retained_archive(execution_boundary(capture)),
        )
        for worker in h.admissions:
            await worker.poll_once()
        assert len({digest(r.reservation) for r in self.reservations}) == 3
        return h.model, submitted

    def review_config(self, role):
        return DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/2",
            r2_credentials_file=str(self.root / (role + "-credentials")),
            r2_bucket="umi-model-artifacts",
            standing_review_policy=self.standing,
            materialization_protected_roots=(str(self.protected),),
            materialization_free_space_reserve_bytes=64 * 1024**2,
        )

    def artifact_reader(self, role):
        reader = self.readers.setdefault(role, self.provider.reader(role))
        return DirectModelArtifactReviewer(
            self.review_config(role),
            self.policy,
            wallet("Charlie").hotkey.ss58_address,
            multipart=reader,
            verification_root=self.root / (role + "-byte-verification"),
        )

    def configure_model_reviews(self, o, client, signatures):
        peers = []
        for name in ("Charlie", "Dave"):
            selected = self.root / name
            artifact = self.artifacts[name] = self.artifact_reader(name + "-review-and-benchmark")

            async def sign(body, name=name):
                signatures[(name, digest(body))] += 1
                return sign_object(body, wallet(name))

            reviewer = self.reviewers[name] = ModelArtifactReviewer(
                ModelReviewConfig(
                    schema="umi-cohort-model-review-config/1",
                    directory=str(selected / "journal"),
                    approvals_directory=str(selected / "approvals"),
                    archive_directory=str(selected / "archive"),
                    policy_sha256=digest(self.policy),
                    signer=wallet(name).hotkey.ss58_address,
                    cohorts=o.h.intake.config.cohorts,
                ),
                self.policy,
                o.service.capture,
                o.service.history,
                sign,
                direct_review=artifact.review,
            )
            o.apps[name.lower() + ".example"].include_router(
                model_review_routes(reviewer, token="v" * 32)
            )
            peers.append(
                ModelReviewPeer(
                    client,
                    f"https://{name.lower()}.example",
                    policy=self.policy,
                    cohorts=o.h.intake.config.cohorts,
                    signer=wallet(name).hotkey.ss58_address,
                    token="v" * 32,
                    timeout_seconds=10,
                )
            )
        o.service.models.reviewers = tuple(peers)

    def benchmark_options(self, name):
        return dict(model_reviewer=self.reviewers[name], direct_artifacts=self.artifacts[name])

    def inference(self, monkeypatch, invoke):
        async def fake_inference(sandbox, job, attempt, archive):
            sandbox._path(attempt)
            case, role, model = case_role_model(job, attempt.step_index)
            if role == "candidate":
                # A direct candidate must reach this inference port only through
                # the native materialization path, even after evaluator restart.
                assert archive == sandbox.cache / "archive"
                request = sandbox.request(job)
                if inspect.isawaitable(request):
                    request = await request
                assert request.direct_artifact is not None
                payload = request.direct_artifact.reservation.payload
                assert model == request.record.request.signed_submission.submission.model_bundle
                assert digest(model) == payload.model_sha256
                verify_preserved_bundle(model, archive, self.policy)
                marker = DirectModelMaterialization.model_validate_json(
                    (archive / "materialization.json").read_bytes()
                )
                source_key = preserved_model_object_key(
                    job.round.cohort_sha256, payload.model_sha256, payload.payload_sha256
                )
                assert marker == DirectModelMaterialization(
                    schema="umi-direct-model-materialization/2",
                    review_request_sha256=digest(request),
                    source_object_key_sha256=hashlib.sha256(source_key.encode()).hexdigest(),
                    model_sha256=digest(model),
                    payload_sha256=payload.payload_sha256,
                    total_bytes=payload.total_bytes,
                )
                names = {
                    identity(wallet(name).hotkey.ss58_address): name for name in ("Charlie", "Dave")
                }
                name = names[identity(job.evaluator_hotkey)]
                assert self.candidate_jobs.setdefault(name, job) == job
                assert not any(
                    trace["evaluator"] == name and trace["step_index"] == attempt.step_index
                    for trace in self.candidate_trace
                )
                self.candidate_invocations[name] += 1
                self.candidate_trace.append(
                    {
                        "evaluator": name,
                        "job_sha256": digest(job),
                        "case_id": case.case_id,
                        "step_index": attempt.step_index,
                        "archive": str(archive),
                        "materialization": marker.model_dump(mode="json", by_alias=True),
                    }
                )
            else:
                assert role == "incumbent" and archive == sandbox.archive
            return await invoke(job, attempt)

        monkeypatch.setattr(DirectCohortCpuSandbox, "_invoke", fake_inference)

    def settlement_options(self, name, base):
        return dict(
            direct_model_review=self.review_config(name + "-settlement"),
            request_export_directory=str(base / "request-export"),
        )

    def settlement_baseline(self, promotion, base, policy):
        source = base / "baseline-source"
        if not source.exists():
            baseline = bundle_at(source)
            preserve_bundle(baseline, source, base / "baseline-archive", policy)
            promotion.initialize_baseline(baseline, base / "baseline-archive")
            preserve_bundle(
                baseline, source, promotion.directory / "model-reward-artifacts", policy
            )

    def settlement_verifier(self, name, base, promotion):
        return DirectModelSettlementVerifier(
            self.artifact_reader(name + "-settlement"),
            promotion.directory / "model-reward-artifacts",
            base / "artifact-receipts",
        )


async def test_native_direct_multipart_paid_work_and_certification_recover(
    host,
    scenario,
    runtime,
    tmp_path,
    monkeypatch,
    chain_config,
):
    await _assert_native_direct_recovery(
        host, scenario, runtime, tmp_path, monkeypatch, chain_config, mixed=True
    )


@pytest.mark.parametrize("scenario", [{"model_only": True}], indirect=True)
async def test_native_direct_model_only_certification_and_rewards_recover(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config
):
    await _assert_native_direct_recovery(
        host, scenario, runtime, tmp_path, monkeypatch, chain_config, mixed=False
    )


async def _assert_native_direct_recovery(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config, *, mixed
):
    direct = NativeDirect(tmp_path / "direct", host.h.intake.policy, monkeypatch)
    settled = await run_pipeline(
        host,
        scenario,
        runtime,
        tmp_path,
        monkeypatch,
        chain_config,
        interrupt=True,
        mixed=mixed,
        direct=direct,
    )
    assert settled.package.inputs.history.plan == scenario["intake_history"].plan
    if not mixed:
        assert settled.package.inputs.history.plan.eligible_tracks == ("model",)
        assert settled.package.inputs.history.plan.service_pool_bps == 0
        assert settled.package.allocation.schema_ == "umi-cohort-reward-allocation/5"
        assert settled.package.allocation.recipients
    assert set(direct.candidate_jobs) == {"Charlie", "Dave"}
    assert set(direct.candidate_invocations) == {"Charlie", "Dave"}
    for name, job in direct.candidate_jobs.items():
        assert job.mode == "paired_model" and len(job.cases) > 0
        assert direct.candidate_invocations[name] == len(job.cases)
        assert {
            trace["case_id"] for trace in direct.candidate_trace if trace["evaluator"] == name
        } == {case.case_id for case in job.cases}
    assert direct.provider.lost_complete_replies == 1
    assert len(direct.provider.put_calls) == 6
    payload = direct.reservations[-1].reservation.payload
    canonical_key = preserved_model_object_key(
        host.h.cohort, payload.model_sha256, payload.payload_sha256
    )
    body = b"".join(
        (tmp_path / "model-submission" / r.path).read_bytes() for r in host.h.model.files
    )
    assert direct.provider.objects[canonical_key] == body
    assert hashlib.sha256(body).hexdigest() == payload.payload_sha256
    assert direct.provider.bytes_uploaded == 3 * len(body)
    assert direct.provider.bytes_copied == len(body)
    certificate = next(
        a
        for a in settled.package.allocation.model_award.acceptances
        if a.acceptance.direct_artifact == direct.reservations[-1]
    )
    for name in ("Charlie", "Dave"):
        assert not (
            tmp_path
            / "native-settlement"
            / name
            / "promotion"
            / "model-reward-artifacts"
            / digest(host.h.model)
        ).exists()
        assert direct.readers[name + "-review-and-benchmark"].read_calls
        assert direct.readers[name + "-settlement"].read_calls
        receipts = list(
            (tmp_path / "native-settlement" / name / "artifact-receipts").rglob("*.json")
        )
        assert len(receipts) == 1
        receipt = json.loads(receipts[0].read_bytes())
        assert receipt["acceptance_sha256"] == digest(certificate)
        assert receipt["payload_sha256"] == payload.payload_sha256
        assert receipt["total_bytes"] == len(body)
    assert (tmp_path / "native-rewards" / "result.json").is_file()
    (tmp_path / "direct-result.json").write_text(
        json.dumps(
            {
                "cohort_sha256": host.h.cohort,
                "eligible_tracks": settled.package.inputs.history.plan.eligible_tracks,
                "service_pool_bps": settled.package.inputs.history.plan.service_pool_bps,
                "package_sha256": digest(settled.package),
                "reservations": [
                    r.model_dump(mode="json", by_alias=True) for r in direct.reservations
                ],
                "provider": "in-memory multipart emulator",
                "provider_counts": dict(direct.provider.counts),
                "bytes_uploaded": direct.provider.bytes_uploaded,
                "bytes_copied": direct.provider.bytes_copied,
                "lost_complete_replies": direct.provider.lost_complete_replies,
                "reader_operations": direct.provider.reader_operations,
                "provider_operations": direct.provider.operations,
                "direct_candidate_invocations": dict(direct.candidate_invocations),
                "expected_candidate_invocations": {
                    name: len(job.cases) for name, job in direct.candidate_jobs.items()
                },
                "direct_candidate_trace": direct.candidate_trace,
                "finality": "synthetic",
                "inference": "fixture",
                "scratch_filesystem": "mocked policy ports; installed disk not qualified",
                "production_c6_plan_changed": False,
            },
            indent=2,
        )
        + "\n"
    )
