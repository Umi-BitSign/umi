"""Run admission votes and private owner exports beside the public intake.

The intake keeps the original records and proofs. Remote reviewers keep their
own keys and finality verification; this host publishes their native quorum
certificates. No subprocess, journal deletion or operator retry is needed.
"""

from __future__ import annotations

import asyncio
import logging
import os
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal

import httpx
import uvicorn
from fastapi import FastAPI
from pydantic import Field, model_serializer, model_validator

from .competition_cohort_admission_http import (
    AdmissionHistoryExporter,
    AdmissionVotePeer,
    admission_history_routes,
)
from .competition_cohort_admission_worker import CohortAdmissionWorker
from .competition_cohort_capacity import (
    LEGACY_AGGREGATE_REPLAY_BYTES,
    AggregateEvidenceCapacity,
    request_evidence_bytes,
)
from .competition_cohort_dispatch_host import start_service_dispatch
from .competition_cohort_history_http import CohortHistoryExporter, cohort_history_routes
from .competition_cohort_intake_export import IntakeReviewExporter
from .competition_cohort_intake_review import NativeIntakeProgressSource
from .competition_cohort_intake_review_http import intake_review_routes
from .competition_cohort_lifecycle_host import LifecycleHost
from .competition_cohort_model_delivery_api import model_delivery_adoption_owner_routes
from .competition_cohort_model_delivery_preflight import model_delivery_preflight_routes
from .competition_cohort_model_delivery_reservation import model_delivery_reservation_routes
from .competition_cohort_model_execution_source import model_execution_source_routes
from .competition_cohort_order_host import CohortOrderHost
from .competition_cohort_preparation_export import PreparationReviewExporter
from .competition_cohort_preparation_phase import NativePreparationProgressSource
from .competition_cohort_preparation_review_http import preparation_review_routes
from .competition_cohort_producer_epoch import producer_epoch_client
from .competition_cohort_request_probe import tasks_running
from .competition_cohort_request_readiness_host import CombinedRequestReadiness
from .competition_cohort_request_review_http import request_review_routes
from .competition_cohort_request_rule_api import request_tail_adoption_owner_routes
from .competition_cohort_request_rule_reservation import request_tail_reservation_routes
from .competition_cohort_review_boot import _token
from .competition_cohort_review_budget import PhaseReviewBudget, checked_budget
from .competition_cohort_review_http import CohortReviewPeerConfig
from .competition_cohort_service_export import service_work_routes
from .competition_cohort_suite_adoption_api import evaluation_suite_adoption_owner_routes
from .competition_cohort_suite_adoption_reservation import evaluation_suite_reservation_routes
from .competition_cohort_window_http import LocalWindowClient, window_routes
from .competition_cohort_window_owner import CohortWindowOwner, WindowOwnerConfig
from .competition_cohort_window_store import CohortMinerWindowStore
from .competition_reward_boot import _disjoint
from .competition_reward_service import _stop_task
from .competition_service_supervision import drain_server_requests
from .concurrency import await_owned_task, run_owned_thread
from .config import Limits
from .host_memory_runtime import (
    HostMemoryAdmissionSelection,
    RequestsStageASGIBinding,
    memory_runtime,
    requests_stage_policy,
    selected_memory,
)
from .named_hotkey import load_named_hotkey
from .open_competition import Hotkey, digest, identity, sign_object
from .policy import scoring_policy_hash
from .private_files import Directory, ensure_private_directory, lock_private_file
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)

# Inbound control calls may be cancelled on stop; owned native writes still drain.
OWNER_REQUEST_DRAIN_SECONDS = 120


class AdmissionOwnerConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-admission-owner/1"] = Field(alias="schema")
    directory: Directory
    owner_hotkey: Hotkey
    owner_key_file: Directory
    export_token_file: Directory
    reviewers: Annotated[tuple[CohortReviewPeerConfig, ...], Field(min_length=1, max_length=64)]
    listen_host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    listen_port: Annotated[int, Field(ge=1024, le=65535)]
    batch_size: Annotated[int, Field(ge=1, le=256)] = 16
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    maximum_sample_gap_blocks: Annotated[int, Field(ge=1, le=300)] = 10
    maximum_export_bytes: Annotated[int, Field(ge=1024, le=512 * 1024**2)] = 64 * 1024**2
    maximum_aggregate_evidence_bytes: AggregateEvidenceCapacity | None = None
    phase_review_budget: PhaseReviewBudget | None = None
    windows: WindowOwnerConfig | None = None

    host_memory_admission: HostMemoryAdmissionSelection | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        value = handler(self)
        if self.host_memory_admission is None:
            value.pop("host_memory_admission", None)
        if self.phase_review_budget is None:
            value.pop("phase_review_budget", None)
        if self.maximum_aggregate_evidence_bytes is None:
            value.pop("maximum_aggregate_evidence_bytes", None)
        if self.windows is None:
            value.pop("windows", None)
        return value

    @property
    def request_evidence_bytes(self) -> int:
        return request_evidence_bytes(
            self.maximum_aggregate_evidence_bytes, self.maximum_export_bytes
        )

    @property
    def request_replay_bytes(self) -> int:
        return request_evidence_bytes(
            self.maximum_aggregate_evidence_bytes, LEGACY_AGGREGATE_REPLAY_BYTES
        )

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.directory,
                self.owner_key_file,
                self.export_token_file,
                *((self.windows.directory,) if self.windows else ()),
                *(p.token_file for p in self.reviewers),
            )
        )

    @model_validator(mode="after")
    def unique(self):
        keys = tuple(identity(p.signer) for p in self.reviewers)
        if len(keys) != len(set(keys)):
            raise ValueError("admission owner repeats a reviewer")
        _disjoint(self.stores())
        return self

    def check_policy(self, policy):
        checked_budget(
            self.phase_review_budget,
            policy,
            self.request_evidence_bytes,
            reviewers=len(self.reviewers),
        )
        for peer in self.reviewers:
            checked_budget(peer.phase_review_budget, policy, self.request_evidence_bytes)
        groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
        keys = {identity(p.signer) for p in self.reviewers}
        if (
            identity(self.owner_hotkey) not in groups
            or not keys <= groups.keys()
            or len({groups[k] for k in keys}) < policy.required_evaluator_groups
        ):
            raise ValueError("admission owner reviewers cannot form the selected policy quorum")


@asynccontextmanager
async def admission_owner_app(
    config: AdmissionOwnerConfig, preparation, provider, *, service_host=None
):
    """Hold the key, process lease and HTTP clients until every caller drains."""
    c = AdmissionOwnerConfig.model_validate_json(canonical_json_bytes(config))
    queue, intake = preparation.queue, preparation.queue.intake
    c.check_policy(intake.policy)
    if provider.policy != intake.policy:
        raise ValueError("admission owner finality differs from intake")
    root = Path(c.directory)
    ensure_private_directory(root)
    lease = lock_private_file(root / "service.lock")
    async with AsyncExitStack() as resources:
        resources.callback(os.close, lease)
        resources.enter_context(
            memory_runtime(
                c.host_memory_admission,
                role="intake",
                protocol_policy_sha256=digest(intake.policy),
                series_sha256=None if service_host is None else digest(service_host.config.series),
                authority_sha256=None
                if service_host is None
                else digest(service_host.config.series.recovery.authority),
                maximum_aggregate_bytes=max(
                    c.maximum_export_bytes, c.request_evidence_bytes, c.request_replay_bytes
                ),
            )
        )
        token = _token(c.export_token_file)
        credentials = tuple(_token(p.token_file) for p in c.reviewers)
        if token in credentials:
            raise ValueError("owner exports and reviewer votes require separate credentials")
        key = await run_owned_thread(load_named_hotkey, Path(c.owner_key_file), c.owner_hotkey)

        async def sign(body):
            return await run_owned_thread(sign_object, body, key)

        client = await resources.enter_async_context(
            httpx.AsyncClient(
                trust_env=False,
                follow_redirects=False,
                limits=httpx.Limits(
                    max_connections=len(c.reviewers), max_keepalive_connections=len(c.reviewers)
                ),
            )
        )
        if service_host is not None and (
            service_host.preparation is not preparation or service_host.provider is not provider
        ):
            raise ValueError("phase control requires the same owned admission and finality")
        capture = provider.collect if service_host is None else service_host.capture
        workers = tuple(
            CohortAdmissionWorker(
                queue,
                AdmissionVotePeer(
                    client,
                    peer.origin,
                    policy=intake.policy,
                    cohorts=intake.config.cohorts,
                    signer=peer.signer,
                    token=credential,
                    timeout_seconds=peer.timeout_seconds,
                ),
                provider=provider,
                capture=capture,
                batch_size=c.batch_size,
            )
            for peer, credential in zip(c.reviewers, credentials, strict=True)
        )
        lifecycle = None
        if service_host is not None and service_host.config.lifecycle is not None:
            epoch_client = await resources.enter_async_context(producer_epoch_client())
            lifecycle = await run_owned_thread(
                LifecycleHost,
                service_host,
                resources,
                client,
                credentials,
                sign,
                epoch_client,
            )
        review_timeout_seconds = min(peer.timeout_seconds for peer in c.reviewers)
        phase_export_timeout_seconds = (
            c.phase_review_budget.export_seconds
            if c.phase_review_budget is not None
            else review_timeout_seconds
        )
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        if service_host is not None and service_host.uploads is not None:
            app.include_router(
                model_delivery_preflight_routes(
                    intake,
                    service_host.uploads,
                    token=token,
                    maximum_bytes=c.maximum_export_bytes,
                    timeout_seconds=phase_export_timeout_seconds,
                )
            )
        if requests_stage_policy() is not None:
            app.add_middleware(
                RequestsStageASGIBinding, controller=selected_memory(), private_role="intake"
            )
        operator_tokens = []
        if lifecycle is not None and lifecycle.config.request_tail_operator_token_file is not None:
            operator_token = _token(lifecycle.config.request_tail_operator_token_file)
            if operator_token in (token, *credentials):
                raise ValueError("request-rule control requires a separate operator credential")
            app.include_router(request_tail_adoption_owner_routes(lifecycle, token=operator_token))
            operator_tokens.append(operator_token)
        if (
            lifecycle is not None
            and lifecycle.config.model_delivery_operator_token_file is not None
        ):
            model_operator_token = _token(lifecycle.config.model_delivery_operator_token_file)
            if model_operator_token in (token, *credentials):
                raise ValueError("model delivery control requires a separate operator credential")
            app.include_router(
                model_delivery_adoption_owner_routes(lifecycle, token=model_operator_token)
            )
            operator_tokens.append(model_operator_token)
        if (
            lifecycle is not None
            and lifecycle.config.evaluation_suite_operator_token_file is not None
        ):
            suite_token = _token(lifecycle.config.evaluation_suite_operator_token_file)
            if suite_token in (token, *credentials, *operator_tokens):
                raise ValueError("suite adoption requires a separate operator credential")
            app.include_router(evaluation_suite_adoption_owner_routes(lifecycle, token=suite_token))
        app.include_router(
            admission_history_routes(
                AdmissionHistoryExporter(queue, c.owner_hotkey, sign),
                token=token,
            )
        )
        app.state.history_exporter = CohortHistoryExporter(
            intake,
            c.owner_hotkey,
            sign,
            timeout_seconds=(
                2400 if c.phase_review_budget is None else phase_export_timeout_seconds
            ),
        )
        app.include_router(cohort_history_routes(app.state.history_exporter, token=token))
        if service_host is not None and getattr(service_host, "models", None) is not None:
            app.include_router(
                model_execution_source_routes(
                    service_host.models.owner,
                    app.state.history_exporter.read,
                    token=token,
                    timeout_seconds=phase_export_timeout_seconds,
                )
            )
        if lifecycle is not None:
            app.include_router(request_tail_reservation_routes(lifecycle, token=token))
            app.include_router(model_delivery_reservation_routes(lifecycle, token=token))
            app.include_router(evaluation_suite_reservation_routes(lifecycle, token=token))
        app.state.intake_review_exporter = IntakeReviewExporter(
            NativeIntakeProgressSource(
                intake, maximum_sample_gap_blocks=c.maximum_sample_gap_blocks
            ),
            c.owner_hotkey,
            sign,
            publish_archive=None if lifecycle is None else lifecycle.proofs.publish,
            maximum_bytes=c.maximum_export_bytes,
            timeout_seconds=phase_export_timeout_seconds,
        )
        app.include_router(intake_review_routes(app.state.intake_review_exporter, token=token))
        app.include_router(
            preparation_review_routes(
                PreparationReviewExporter(
                    NativePreparationProgressSource(preparation),
                    c.owner_hotkey,
                    sign,
                    maximum_bytes=c.maximum_export_bytes,
                    timeout_seconds=phase_export_timeout_seconds,
                ),
                token=token,
            )
        )
        app.state.admission_workers = workers
        app.state.admission_reports = {}
        app.state.finality_provider = provider
        app.state.lifecycle = lifecycle
        app.state.dispatch = None
        app.state.orders = None
        app.state.request_readiness = None
        app.state.windows = None
        if c.windows is not None:

            def open_windows():
                store = CohortMinerWindowStore(
                    Path(c.windows.directory),
                    cohorts=tuple(binding.cohort_sha256 for binding in intake.config.cohorts),
                    evaluators=tuple(e.hotkey for e in intake.policy.evaluators),
                    transports={
                        scoring_policy_hash(p): Limits.from_policy(p) for p in c.windows.transports
                    },
                    bootstrap_sources=c.windows.bootstrap_sources,
                )
                return CohortWindowOwner(
                    store,
                    intake.policy,
                    c.windows.transports,
                    {
                        binding.cohort_sha256: binding.authority_sha256
                        for binding in intake.config.cohorts
                    },
                )

            owner = await run_owned_thread(open_windows)
            app.state.windows = LocalWindowClient(owner, timeout_seconds=review_timeout_seconds)
            app.include_router(window_routes(app.state.windows, token=token))
        if app.state.lifecycle is not None:
            app.include_router(request_review_routes(app.state.lifecycle, token=token))
            if service_host.config.dispatch is not None:
                clip_token = _token(service_host.config.dispatch.clips.upload_token_file)
                if clip_token in (token, *credentials):
                    raise ValueError("clip upload requires a separate credential")
                app.state.dispatch = await start_service_dispatch(
                    service_host,
                    app.state.lifecycle,
                    resources,
                    client,
                    credentials,
                    key,
                    sign,
                    clip_token,
                    windows=app.state.windows,
                )
                app.include_router(service_work_routes(app.state.dispatch, token=token))
            if service_host.config.orders is not None:
                app.state.orders = CohortOrderHost(service_host, client, credentials)
                if app.state.dispatch is not None:
                    # Readiness cannot queue behind the phase vote that is
                    # currently awaiting the public readiness response.
                    probes = await resources.enter_async_context(
                        httpx.AsyncClient(
                            trust_env=False,
                            follow_redirects=False,
                            limits=httpx.Limits(max_connections=len(c.reviewers)),
                        )
                    )
                    app.state.request_readiness = CombinedRequestReadiness(
                        service_host,
                        app.state.lifecycle,
                        app.state.dispatch,
                        app.state.orders,
                        probes,
                        credentials,
                        lambda: False,
                    )
        yield app


class _Server(uvicorn.Server):
    @contextmanager
    def capture_signals(self):
        # The enclosing intake service owns process signals and finality.
        yield


async def run_admission_owner(
    config: AdmissionOwnerConfig, preparation, provider, stop, *, service_host=None
):
    async with admission_owner_app(config, preparation, provider, service_host=service_host) as app:
        server = _Server(
            uvicorn.Config(
                app,
                host=config.listen_host,
                port=config.listen_port,
                access_log=False,
                log_config=None,
                timeout_graceful_shutdown=OWNER_REQUEST_DRAIN_SECONDS,
            )
        )

        async def poll(worker):
            # Each reviewer has its own loop. A slow peer cannot starve another
            # peer or stall the public intake's readiness/cache worker.
            with preparation.queue.intake.readiness_wakes.subscribe("admissions") as wake:
                await poll_reviewer(worker, wake)

        async def poll_reviewer(worker, wake):
            while not stop.is_set():
                wake.begin()
                provider.ensure_observer_running()
                report = await worker.poll_once()
                retrying = bool(report["retry_count"])
                wake.finish(retrying=retrying)
                report["readiness_wake"] = wake.snapshot()
                app.state.admission_reports[identity(worker.votes.signer)] = report
                logger.info(
                    "cohort_admission_votes reviewer=%s status=%s votes=%s retries=%s "
                    "readiness_wake=%s",
                    worker.votes.signer,
                    report["status"],
                    report["votes_published"],
                    report["retry_count"],
                    canonical_json_bytes(report["readiness_wake"]).decode("ascii"),
                )
                await wake.wait(stop, config.poll_seconds, retrying=retrying)

        serving = asyncio.create_task(server.serve())
        workers = []
        stopping = asyncio.create_task(stop.wait())
        try:
            while not server.started and not serving.done() and not stop.is_set():
                await asyncio.wait((serving, stopping), timeout=0.05)
            if not stop.is_set() and server.started:
                if service_host is not None:
                    service_host.history_exporter = app.state.history_exporter
                workers = (
                    []
                    if requests_stage_policy() is not None
                    else [asyncio.create_task(poll(w)) for w in app.state.admission_workers]
                )
                if app.state.lifecycle is not None:
                    workers.append(asyncio.create_task(app.state.lifecycle.run(stop)))
                if app.state.dispatch is not None and requests_stage_policy() is None:
                    workers.append(asyncio.create_task(app.state.dispatch.run(stop)))
                if app.state.orders is not None and requests_stage_policy() is None:
                    workers.append(asyncio.create_task(app.state.orders.run(stop)))
                if app.state.request_readiness is not None:
                    app.state.request_readiness.running = lambda: (
                        not stop.is_set() and tasks_running((serving, *workers))
                    )
                    service_host.request_readiness = app.state.request_readiness
                logger.info("cohort_admission_owner_ready config_sha256=%s", digest(config))
            await asyncio.wait((serving, stopping, *workers), return_when=asyncio.FIRST_COMPLETED)
            for task in (serving, *workers):
                if task.done():
                    task.result()
                    if not stop.is_set():
                        raise RuntimeError("admission owner task exited before shutdown")
        finally:
            if service_host is not None:
                service_host.request_readiness = None
                service_host.history_exporter = None
            server.should_exit = True

            async def drain_workers():
                for task in workers:
                    task.cancel()
                for task in workers:
                    # Consume all task failures, including multiple failures in
                    # the same pass, before releasing client or key ownership.
                    with suppress(asyncio.CancelledError, Exception):
                        await await_owned_task(task)

            try:
                # Stop outgoing votes while keeping the export key available to
                # existing inbound requests. Native writes drain on cancellation.
                await await_owned_task(asyncio.create_task(drain_workers()))
            finally:
                try:
                    await await_owned_task(serving)
                finally:
                    try:
                        await drain_server_requests(server)
                    finally:
                        await _stop_task(stopping)
