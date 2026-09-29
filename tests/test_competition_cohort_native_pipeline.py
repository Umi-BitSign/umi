"""Public model delivery through artifact review and certified reward publication.

Finality, readiness, reviewed rights documents and sandbox inference are fixtures.
No prepared round, order, execution receipt, score or settlement vote is supplied.
The mixed cohort also claims paid service work and serves endpoint benchmarks.
Neither case qualifies installed rewards or production chain effects.
"""

import asyncio
import hashlib
from collections import Counter
from contextlib import AsyncExitStack
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_admission_host as admission_module
from umi import competition_cohort_benchmark_host as benchmark_module
from umi import competition_cohort_dispatch_host as dispatch_module
from umi.competition_artifacts import preserve_bundle, verify_preserved_bundle
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_benchmark_host import BenchmarkHost, BenchmarkHostConfig
from umi.competition_cohort_clip_delivery import ClipDeliveryConfig
from umi.competition_cohort_dispatch_host import ServiceDispatchConfig
from umi.competition_cohort_execution_journal import CohortExecutionConfig
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_intake import (
    CohortIntake,
    CohortIntakeBinding,
    CohortIntakeConfig,
    history_tip,
)
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_cohort_model_acceptance_store import PendingModelArtifacts
from umi.competition_cohort_model_client import submit_cohort_model
from umi.competition_cohort_model_review import ModelArtifactReviewer, ModelReviewConfig
from umi.competition_cohort_model_review_http import ModelReviewPeer, model_review_routes
from umi.competition_cohort_model_upload import ModelUploadConfig
from umi.competition_cohort_model_upload_http import model_upload_routes
from umi.competition_cohort_order_host import OrderHostConfig
from umi.competition_cohort_order_inbox import CohortOrderInboxConfig
from umi.competition_cohort_order_queue import CohortOrderQueueConfig
from umi.competition_cohort_order_signer import CohortOrderSignerConfig
from umi.competition_cohort_orders import recoverable_order_job
from umi.competition_cohort_participation import (
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_phase_vote_http import phase_vote_routes
from umi.competition_cohort_progress_signer import CohortProgressSigner, CohortProgressSignerConfig
from umi.competition_cohort_request_closure import PendingRequestClosure, build_request_closure
from umi.competition_cohort_request_files import RequestCompletionFiles
from umi.competition_cohort_request_readiness import LiveRequestPhaseObserver
from umi.competition_cohort_request_review import RequestProgressReviewer
from umi.competition_cohort_service_host import ServiceAdmissionHost, ServiceAdmissionHostConfig
from umi.competition_cohort_service_quality import ServiceReference, ServiceTerms
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, identity, sign_object
from umi.policy import scoring_policy_hash
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .cohort_native_service_fixture import (
    SERVICE_SHA,
    NativeService,
    admit_endpoint,
    media,
    transport_policy,
)
from .cohort_native_settlement_fixture import run_settlement
from .test_competition_cohort_executor import output
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_lifecycle_host import host as host
from .test_competition_cohort_lifecycle_host import legacy_scenario as legacy_scenario
from .test_competition_cohort_lifecycle_host import lifecycle as lifecycle
from .test_competition_cohort_lifecycle_host import (
    lifecycle_before_intake as lifecycle_before_intake,
)
from .test_competition_cohort_lifecycle_host import precommit_service_inventory
from .test_competition_cohort_lifecycle_host import recovery as recovery
from .test_competition_cohort_recovery import signatures as quorum_signatures
from .test_competition_cohort_standing_phases import standing
from .test_competition_runner import runtime as runtime
from .test_competition_service import chain_config as chain_config
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as base_policy  # noqa: F401


def model_request(scenario, model, *, sequence, block):
    signed = submission(scenario["policy"], bundle=model, sequence=sequence)
    body = scenario["consent"].consent.model_copy(
        update={"submission_sha256": digest(signed.submission), "signed_at_block": block}
    )
    return CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=body, signature=sign_object(body, wallet("Alice"))
        ),
    )


def precommit_model_inventory(h):
    h.transport = transport_policy()
    h.terms = ServiceTerms(
        schema="umi-cohort-service-terms/1",
        policy_sha256=digest(h.intake.policy),
        transport_policy_sha256=scoring_policy_hash(h.transport),
        service_pool_bps=5000,
        stratum_weights={"fingerspelling": 3, "continuous": 10},
    )
    h.reference = ServiceReference(
        schema="umi-cohort-service-reference/1",
        case_id="91" * 32,
        video_sha256=SERVICE_SHA,
        stratum="fingerspelling",
        salt="41" * 32,
        reference="hello",
    )
    precommit_service_inventory(
        h,
        service_terms_sha256=digest(h.terms),
        service_reference_sha256=digest(h.reference),
        service_video_sha256=SERVICE_SHA,
    )
    h.model = bundle_at(Path(h.intake.config.directory).parent / "model-submission")
    h.request_for = lambda scenario, **kwargs: model_request(scenario, h.model, **kwargs)


pytestmark = pytest.mark.parametrize(
    "lifecycle_before_intake", [precommit_model_inventory], indirect=True
)


@pytest.fixture
def scenario(legacy_scenario, policy):
    old = legacy_scenario["intake_history"]
    suite = legacy_scenario["suite"].model_copy(
        update={
            "cases": tuple(
                c.model_copy(update={"video_sha256": hashlib.sha256(media(c)).hexdigest()})
                for c in legacy_scenario["suite"].cases
            )
        }
    )
    plan = old.plan.model_copy(update={"suite_sha256": digest(suite)})
    authority, genesis, _ = standing(plan, policy, model_rewards=True)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=quorum_signatures(genesis),
        transitions=(),
    )
    consent = legacy_scenario["consent"].consent.model_copy(
        update={"authority_sha256": digest(authority.authority), "cohort_sha256": digest(plan)}
    )
    return dict(
        legacy_scenario,
        intake_history=history,
        suite=suite,
        consent=SignedCohortParticipationConsent(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )


@pytest.fixture
def policy(base_policy, runtime):  # noqa: F811
    return base_policy.model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "endpoint_reward_bps": 5000,
            "model_reward_bps": 5000,
        }
    )


@pytest.fixture
def intake(tmp_path, scenario):
    history = scenario["intake_history"]
    config = CohortIntakeConfig(
        directory=str(tmp_path / "cohort-intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=digest(history.plan),
                authority_sha256=digest(history.authority.authority),
            ),
        ),
    )
    service = CohortIntake(
        config, scenario["policy"], eligible_tracks=("endpoint", "model"), initialize=True
    )
    service.publish(history, capture_at(210))
    return service


async def accept_model(o, scenario):
    # A newer explicitly signed model submission supersedes the two model
    # submissions retained by the lifecycle fixture, before intake closes.
    h = o.h
    h.block += 5
    request = model_request(scenario, h.model, sequence=3, block=h.block)
    public = FastAPI()
    public.include_router(
        cohort_routes(
            h.intake, o.service.capture, maximum_body_bytes=4 * 1024**2, models=o.service.uploads
        )
    )
    public.include_router(model_upload_routes(o.service.uploads, o.service.capture))
    stop = asyncio.Event()
    polling = asyncio.create_task(o.service._poll(stop))
    try:
        receipt = await asyncio.wait_for(
            submit_cohort_model(
                origin="https://intake.example",
                policy=h.intake.policy,
                request=request,
                source=Path(h.intake.config.directory).parent / "model-submission",
                wallet=wallet("Alice"),
                retry_seconds=0.01,
                transport=httpx.ASGITransport(public),
            ),
            20,
        )
    finally:
        stop.set()
        await asyncio.wait_for(polling, 10)
    assert receipt.status == "pending_attestation"
    assert verify_preserved_bundle(
        h.model, o.service.models.owner.archive, h.intake.policy
    ) == digest(h.model)
    capture = h.capture(h.block)
    h.queue.attach_evidence(
        h.cohort,
        digest(request.consent.consent),
        *await h.provider.retained_archive(execution_boundary(capture)),
    )
    for worker in h.admissions:
        await worker.poll_once()
    return h.model, request


def configure_owner(o, orders, chain_config, root, monkeypatch):
    dispatch = ServiceDispatchConfig(
        schema="umi-cohort-service-dispatch-config/1",
        origins=chain_config.model_copy(
            update={
                "proof_rpc_fallback_urls": ("wss://backup-one.example", "wss://backup-two.example")
            }
        ),
        clips=ClipDeliveryConfig(
            schema="umi-cohort-clip-delivery-config/1",
            directory=str(root / "clips"),
            videos_directory=str(root / "videos"),
            origin="https://clips.example",
            upload_token_file=str(root / "clip-token"),
        ),
        poll_seconds=1,
    )
    config = ServiceAdmissionHostConfig.model_validate(
        {
            **o.config.model_dump(by_alias=True),
            "schema": "umi-cohort-service-admission-host/7",
            "orders": orders,
            "dispatch": dispatch,
            "model_review_peers": o.config.admission_owner.reviewers,
            "model_uploads": ModelUploadConfig(
                directory=str(root / "uploads"), maximum_reserved_bytes=1024**2
            ),
            "poll_seconds": 1,
        }
    )
    previous = o.service
    # Construct the actual service through its validating startup boundary.
    o.service = ServiceAdmissionHost(
        config,
        o.h.intake,
        o.h.owner.promotion,
        previous.capture,
        o.h.provider.retained_archive,
        provider=o.h.provider,
    )
    o.config = config
    catalog = o.h.precommitted[0]
    publish_private_model(
        Path(config.inputs_directory) / "catalogs" / (digest(catalog.catalog) + ".json"), catalog
    )
    publish_private_model(
        Path(config.lifecycle.sources.transport_directory)
        / (scoring_policy_hash(o.h.transport) + ".json"),
        o.h.transport,
    )
    SettlementEvidenceFiles(Path(config.lifecycle.sources.objects_directory)).publish(
        digest(o.h.terms), lambda _: canonical_json_bytes(o.h.terms)
    )
    SettlementEvidenceFiles(Path(config.lifecycle.sources.objects_directory)).publish(
        digest(o.h.reference), lambda _: canonical_json_bytes(o.h.reference)
    )
    o.open = lambda: admission_module.admission_owner_app(
        config.admission_owner, o.service.preparation, o.h.provider, service_host=o.service
    )
    old_token = admission_module._token
    monkeypatch.setattr(
        admission_module,
        "_token",
        lambda path: "a" * 64 if path == dispatch.clips.upload_token_file else old_token(path),
    )

    class Origins:
        # Retain real dispatch startup and its policy/provider checks. Only the
        # external finality process is replaced; this cohort has no endpoints.
        def __init__(self, config, policy):
            self.config, self.policy = config, policy

        async def start(self):
            pass

        async def aclose(self):
            pass

    monkeypatch.setattr(dispatch_module, "CohortEndpointFinalityProvider", Origins)


def configure_model_reviews(o, root, client, signatures):
    inputs = ModelArtifactReviewInputs(
        model_sha256=digest(o.h.model),
        rights_evidence={"fixture": "inert bundle with retained license and provenance"},
        reconstruction_evidence={"fixture": "independently preserved inert baseline bundle"},
    )
    publish_private_model(
        Path(o.config.inputs_directory) / "model-reviews" / (inputs.model_sha256 + ".json"), inputs
    )
    peers = []
    for name in ("Charlie", "Dave"):
        selected = root / name
        archive = selected / "artifacts"
        preserve_bundle(
            o.h.model,
            Path(o.h.intake.config.directory).parent / "model-submission",
            archive,
            o.h.intake.policy,
        )
        publish_private_model(selected / "approvals" / (inputs.model_sha256 + ".json"), inputs)

        async def sign(body, name=name):
            signatures[(name, digest(body))] += 1
            return sign_object(body, wallet(name))

        reviewer = ModelArtifactReviewer(
            ModelReviewConfig(
                schema="umi-cohort-model-review-config/1",
                directory=str(selected / "journal"),
                approvals_directory=str(selected / "approvals"),
                archive_directory=str(archive),
                policy_sha256=digest(o.h.intake.policy),
                signer=wallet(name).hotkey.ss58_address,
                cohorts=o.h.intake.config.cohorts,
            ),
            o.h.intake.policy,
            o.service.capture,
            o.service.history,
            sign,
        )
        o.apps[name.lower() + ".example"].include_router(
            model_review_routes(reviewer, token="v" * 32)
        )
        peers.append(
            ModelReviewPeer(
                client,
                f"https://{name.lower()}.example",
                policy=o.h.intake.policy,
                cohorts=o.h.intake.config.cohorts,
                signer=wallet(name).hotkey.ss58_address,
                token="v" * 32,
                timeout_seconds=10,
            )
        )
    o.service.models.reviewers = tuple(peers)


async def certify_requests(o, app, root, monkeypatch, signatures):
    """Use native request observation, review and handoff with synthetic readiness.

    Fence the original catalog, preserve completed benchmark and service work,
    and certify the whole request closure before revealing references.
    """
    h = o.h
    assert (await o.service.poll_once())["catalogs_installed"] == 1
    node = await app.state.lifecycle.node(h.cohort)
    await node._driver("requests")
    source = app.state.lifecycle.requests[h.cohort]

    async def ready(self, state, capture):
        return h.ready

    monkeypatch.setattr(LiveRequestPhaseObserver, "_ready", ready)
    for name in ("Charlie", "Dave"):
        config = CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(root / name),
            policy_sha256=digest(h.intake.policy),
            signer=wallet(name).hotkey.ss58_address,
            cohorts=h.intake.config.cohorts,
        )

        async def sign(body, name=name):
            signatures[(name, digest(body))] += 1
            return sign_object(body, wallet(name))

        reviewer = RequestProgressReviewer(source, h.provider, h.provider.retained_archive)
        signer = CohortProgressSigner(config, reviewer, sign)
        o.apps[name.lower() + ".example"].include_router(
            phase_vote_routes(signer, phase="requests", token="v" * 32)
        )
    for _ in range(100):
        h.block += 5
        await node.tick()
        if node.controller.store.status(h.cohort)[0].phase == "reference_reveal":
            break
    assert node.controller.store.status(h.cohort)[0].phase == "reference_reveal", node.last_report
    assert Path(o.config.lifecycle.settlement_history_directory, h.cohort + ".json").is_file()
    history = h.intake.history(h.cohort)
    assert history.transitions[-1].transition.phase == "requests"
    assert history.transitions[-1].transition.operation == "close_phase"


def evaluator_config(o, name, root):
    common = dict(
        policy_sha256=digest(o.h.intake.policy),
        signer=wallet(name).hotkey.ss58_address,
        cohorts=o.h.intake.config.cohorts,
    )
    return SimpleNamespace(
        policy=o.h.intake.policy,
        series=o.config.series,
        owner_hotkey=o.config.admission_owner.owner_hotkey,
        owner_origin="https://owner.example",
        review_timeout_seconds=30,
        benchmark=BenchmarkHostConfig(
            schema="umi-cohort-benchmark-host/1",
            directory=str(root / "host"),
            orders=CohortOrderSignerConfig(
                schema="umi-cohort-order-signer-config/1",
                directory=str(root / "orders"),
                **common,
            ),
            inbox=CohortOrderInboxConfig(
                schema="umi-cohort-order-inbox-config/1",
                directory=str(root / "inbox"),
                **common,
            ),
            execution=CohortExecutionConfig(
                schema="umi-cohort-execution-config/1",
                directory=str(root / "execution"),
                **common,
            ),
            archive_directory=str(root / "models"),
            videos_directory=str(root / "videos"),
            workspace_directory=str(root / "scratch"),
            request_export_directory=str(root / "exports"),
            poll_seconds=1,
        ),
    )


def deliver_exports(nodes, target):
    """Transport original immutable files; never read another owner's database."""
    for node in nodes.values():
        for original in Path(node.config.request_export_directory).rglob("*.json"):
            destination = target / original.relative_to(node.config.request_export_directory)
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if destination.exists():
                assert destination.read_bytes() == original.read_bytes()
            else:
                destination.write_bytes(original.read_bytes())
                destination.chmod(0o600)


@pytest.mark.parametrize(
    "interrupt,mixed",
    [(False, False), (True, False), (False, True), (True, True)],
    ids=["normal", "outage-restart", "mixed-service-model", "mixed-outage-lost-reply"],
)
async def test_accepted_model_reaches_native_reward_package(
    host, scenario, runtime, tmp_path, monkeypatch, chain_config, interrupt, mixed
):
    o, h = host, host.h
    orders = OrderHostConfig(
        schema="umi-cohort-order-host/1",
        queue=CohortOrderQueueConfig(
            schema="umi-cohort-order-queue-config/1",
            directory=str(tmp_path / "owner-orders"),
            policy_sha256=digest(h.intake.policy),
            cohorts=h.intake.config.cohorts,
            reviewers=tuple(
                sorted((p.signer for p in o.config.admission_owner.reviewers), key=identity)
            ),
        ),
        poll_seconds=1,
    )
    configure_owner(o, orders, chain_config, tmp_path / "native-owner", monkeypatch)
    model, submitted = await accept_model(o, scenario)
    inputs = SettlementEvidenceFiles(Path(o.config.lifecycle.sources.objects_directory))
    for value in (scenario["suite"], runtime, model):
        inputs.publish(digest(value), lambda _, value=value: canonical_json_bytes(value))
    inference, signatures = Counter(), Counter()
    service = (
        NativeService(
            o, scenario, tmp_path / "native-service", monkeypatch, signatures, lose_reply=interrupt
        )
        if mixed
        else None
    )
    if service:
        endpoint_request = await admit_endpoint(o, scenario)

    async def invoke(job, attempt):
        inference[(identity(job.evaluator_hotkey), digest(job), attempt.step_index)] += 1
        return output(job, attempt)

    async def reconcile(job, attempt):
        raise AssertionError("completed inference must not be discarded")

    monkeypatch.setattr(
        benchmark_module,
        "CohortCpuSandbox",
        lambda *a, **kw: SimpleNamespace(invoke=invoke, reconcile=reconcile),
    )
    configs = {n: evaluator_config(o, n, tmp_path / n) for n in ("Charlie", "Dave")}
    async with httpx.AsyncClient() as client, AsyncExitStack() as stack:
        configure_model_reviews(o, tmp_path / "artifact-review", client, signatures)

        # Independent artifact acceptance is required even for a baseline copy.
        o.outages.add("dave.example")
        assert (await o.service.models.poll_once())["entries_pending"] == 3
        with pytest.raises(PendingModelArtifacts):
            o.service.models.owner.retained(
                h.cohort, digest(submitted.signed_submission.submission)
            )
        assert len(signatures) == 3
        o.outages.clear()
        async with o.open() as app:
            lifecycle = await app.state.lifecycle.node(h.cohort)
            for _ in range(15):
                h.block += 5
                await lifecycle.tick()
            assert lifecycle.controller.store.status(h.cohort)[0].phase == "intake"
        original_votes = dict(signatures)
        o.outages.clear()
        o.outages.add("charlie.example")
        assert (await o.service.models.poll_once())["entries_exported"] == 3
        assert all(signatures[k] == count for k, count in original_votes.items())
        accepted_artifact = o.service.models.owner.retained(
            h.cohort, digest(submitted.signed_submission.submission)
        )
        assert len(accepted_artifact.certificate.signatures) == 2
        o.outages.clear()

        def evaluator(name):
            async def sign(body):
                signatures[(name, digest(body))] += 1
                return sign_object(body, wallet(name))

            return BenchmarkHost(configs[name], h.provider, client, "e" * 32, "v" * 32, sign)

        nodes = {name: evaluator(name) for name in configs}
        for name, node in nodes.items():
            o.apps[name.lower() + ".example"].include_router(node.routes)
        async with o.open() as app:
            o.apps["owner.example"] = app
            lifecycle = await app.state.lifecycle.node(h.cohort)
            for _ in range(100):
                if lifecycle.controller.store.status(h.cohort)[0].phase != "intake":
                    break
                h.block += 5
                await lifecycle.tick()
            assert lifecycle.controller.store.status(h.cohort)[0].phase == "preparation"
            assert (await lifecycle.tick())["status"] == "waiting_request_rest"
            h.timestamp = 2_030_000
            await lifecycle.tick()
            assert lifecycle.controller.store.status(h.cohort)[0].phase == "requests"
            source = await o.service.history(h.cohort)
            prepared = o.service.preparation.retained(
                h.cohort, expected_tip_sha256=history_tip(source.history), current_block=h.block
            )
            assert prepared.roster.intake_seal.record_count == 3 + mixed
            assert len(prepared.roster.participants) == 1 + mixed
            assert submitted in [p.record.request for p in prepared.roster.participants]
            assert await app.state.orders.select(h.cohort) == 1 + mixed
            slots = app.state.orders.queue.pending(h.cohort)
            report = await app.state.orders.worker.poll_once()
            assert report["deliveries_acknowledged"] == 2 * (1 + mixed), report
            slot = next(
                s
                for s in slots
                if nodes["Charlie"]
                .inbox.assignment(s)
                .certificate.order.submission.submission.track
                == "model"
            )
            assignments = {name: n.inbox.assignment(slot) for name, n in nodes.items()}
            frozen_order = canonical_json_bytes(assignments["Charlie"].certificate)
            for node in nodes.values():
                assert (await node.worker.poll_once())["retry_count"] == 1 + mixed
                assert node.execution.journal.get("assignment", slot) is None
            assert not inference
            h.block += 1
            for node in nodes.values():
                report = await node.worker.poll_once()
                assert report["retry_count"] == 0, str(report)
            first_steps = {
                name: canonical_json_bytes(
                    node.execution.step(
                        recoverable_order_job(
                            assignments[name].certificate.order, node.config.orders.signer
                        ),
                        0,
                    )
                )
                for name, node in nodes.items()
            }

        if interrupt:
            # Ten hours at nominal block cadence, with no owner or renewer.
            h.block += 3000
            o.outages.add("owner.example")
            for name in nodes:
                nodes[name] = evaluator(name)
                assert (await nodes[name].worker.poll_once())["retry_count"] == 1 + mixed
            assert sum(inference.values()) == 2 * (1 + mixed)
            o.outages.clear()

        async with o.open() as app:
            o.apps["owner.example"] = app
            selected_signatures = sum(signatures.values())
            assert await app.state.orders.select(h.cohort) == 1 + mixed
            assert (await app.state.orders.worker.poll_once())["retry_count"] == 0
            assert sum(signatures.values()) == selected_signatures
            for name, node in nodes.items():
                assignment = node.inbox.assignment(slot)
                assert canonical_json_bytes(assignment.certificate) == frozen_order
                job = recoverable_order_job(assignment.certificate.order, node.config.orders.signer)
                assert canonical_json_bytes(node.execution.step(job, 0)) == first_steps[name]

            if service:
                service.window()
                service.reviewers(nodes, client)
                await service.miner(stack)
                catalog_key = await service.claim(endpoint_request, client)
                service_worker = await app.state.dispatch.worker(catalog_key)

            # The actual recurring host owns the remaining execution and export
            # work. This loop advances only the synthetic chain, never a stage.
            certificates = {
                name: [node.inbox.assignment(s).certificate for s in slots]
                for name, node in nodes.items()
            }
            service_reports = []
            stop = asyncio.Event()
            tasks = [asyncio.create_task(node.run(stop)) for node in nodes.values()]
            if service:
                tasks.append(
                    asyncio.create_task(
                        service_worker.run(stop, poll_seconds=0.1, report=service_reports.append)
                    )
                )
            try:

                async def complete():
                    while True:
                        for task in tasks:
                            if task.done():
                                task.result()
                                raise AssertionError("evaluator exited before completion")
                        if all(
                            node.files.terminal(certificate, node.config.orders.signer) is not None
                            for name, node in nodes.items()
                            for certificate in certificates[name]
                        ) and (
                            not service
                            or (service_reports and service_reports[-1].get("work_complete") == 1)
                        ):
                            return
                        if (
                            service
                            and service_reports
                            and service_reports[-1].get("work_complete") == 1
                            and all(
                                n.last_reports.get("endpoints", {}).get("assignments_complete") == 1
                                for n in nodes.values()
                            )
                        ):
                            h.block = max(h.block, service.window_end)
                        if not service:
                            h.block += 1
                        await asyncio.sleep(0.1)

                try:
                    await asyncio.wait_for(complete(), 180 if mixed else 60)
                except TimeoutError as error:
                    raise AssertionError(
                        {
                            "evaluators": {name: n.last_reports for name, n in nodes.items()},
                            "service": service_reports[-1:],
                        }
                    ) from error
            finally:
                stop.set()
                await asyncio.wait_for(asyncio.gather(*tasks), 30)
            assert all(not node.tasks for node in nodes.values())
            assert all(node.execution.evidence(slot) is not None for node in nodes.values())

            delivered = Path(o.config.lifecycle.request_completion_directory)
            files = RequestCompletionFiles(delivered)

            def close():
                return build_request_closure(
                    prepared.roster,
                    files.orders(prepared.roster),
                    files.terminal,
                    files.objects,
                    h.intake.policy,
                    source.history,
                    execution_boundary(h.capture(h.block)),
                    decision_source=source.inputs().__getitem__,
                    intake_records=h.intake.export_records(
                        h.cohort, maximum_bytes=1024**2, maximum_records=8
                    ),
                    expected_tip_sha256=history_tip(source.history),
                    current_block=h.block,
                )

            with pytest.raises(PendingRequestClosure):
                close()
            deliver_exports({"Charlie": nodes["Charlie"]}, delivered)
            with pytest.raises(PendingRequestClosure):
                close()
            deliver_exports({"Dave": nodes["Dave"]}, delivered)
            closure = close()
            assert len(closure.participants) == 1 + mixed
            assert all(len(p.evaluators) == 2 for p in closure.participants)
            assert max(inference.values()) == max(signatures.values()) == 1
            assert sum(inference.values()) == 12 + 6 * mixed
            if service:
                assert len(service.calls) == 7 and max(service.calls.values()) == 1
                assert service.lost_replies == int(interrupt)
                service.reveal()
            await certify_requests(o, app, tmp_path / "request-review", monkeypatch, signatures)
            assert max(signatures.values()) == 1
            await run_settlement(
                o, nodes, tmp_path / "native-settlement", signatures, interrupt, mixed=mixed
            )
            assert max(inference.values()) == max(signatures.values()) == 1
            # Reopened workers can recover all completed originals offline.
            h.offline = True
            o.outages.add("owner.example")
            counts = dict(inference), dict(signatures)
            for name in nodes:
                node = evaluator(name)
                assert (await node.worker.poll_once())["jobs_complete"] == 1 + mixed
                with pytest.raises(OSError):
                    await node.exporter.poll_once()
                # Already published immutable exports remain readable even when
                # finality prevents this worker from creating another terminal.
                assert (
                    node.files.terminal(assignments[name].certificate, node.config.orders.signer)
                    is not None
                )
            assert (dict(inference), dict(signatures)) == counts
