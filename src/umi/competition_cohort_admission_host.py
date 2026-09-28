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
from pydantic import Field, model_validator

from .competition_cohort_admission_http import (
    AdmissionHistoryExporter,
    AdmissionVotePeer,
    admission_history_routes,
)
from .competition_cohort_admission_worker import CohortAdmissionWorker
from .competition_cohort_dispatch_host import start_service_dispatch
from .competition_cohort_history_http import CohortHistoryExporter, cohort_history_routes
from .competition_cohort_intake_export import IntakeReviewExporter
from .competition_cohort_intake_review import NativeIntakeProgressSource
from .competition_cohort_intake_review_http import intake_review_routes
from .competition_cohort_lifecycle_host import LifecycleHost
from .competition_cohort_order_host import CohortOrderHost
from .competition_cohort_preparation_export import PreparationReviewExporter
from .competition_cohort_preparation_phase import NativePreparationProgressSource
from .competition_cohort_preparation_review_http import preparation_review_routes
from .competition_cohort_request_review_http import request_review_routes
from .competition_cohort_review_boot import _token
from .competition_cohort_review_http import CohortReviewPeerConfig
from .competition_cohort_service_export import service_work_routes
from .competition_reward_boot import _disjoint
from .competition_reward_service import _stop_task
from .concurrency import await_owned_task, run_owned_thread
from .named_hotkey import load_named_hotkey
from .open_competition import Hotkey, digest, identity, sign_object
from .private_files import Directory, ensure_private_directory, lock_private_file
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


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

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.directory,
                self.owner_key_file,
                self.export_token_file,
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
                batch_size=c.batch_size,
            )
            for peer, credential in zip(c.reviewers, credentials, strict=True)
        )
        app = FastAPI(openapi_url=None, docs_url=None, redoc_url=None)
        app.include_router(
            admission_history_routes(
                AdmissionHistoryExporter(queue, c.owner_hotkey, sign),
                token=token,
            )
        )
        app.include_router(
            cohort_history_routes(CohortHistoryExporter(intake, c.owner_hotkey, sign), token=token)
        )
        app.include_router(
            intake_review_routes(
                IntakeReviewExporter(
                    NativeIntakeProgressSource(
                        intake, maximum_sample_gap_blocks=c.maximum_sample_gap_blocks
                    ),
                    c.owner_hotkey,
                    sign,
                    maximum_bytes=c.maximum_export_bytes,
                ),
                token=token,
            )
        )
        app.include_router(
            preparation_review_routes(
                PreparationReviewExporter(
                    NativePreparationProgressSource(preparation),
                    c.owner_hotkey,
                    sign,
                    maximum_bytes=c.maximum_export_bytes,
                ),
                token=token,
            )
        )
        app.state.admission_workers = workers
        app.state.admission_reports = {}
        app.state.finality_provider = provider
        app.state.lifecycle = None
        app.state.dispatch = None
        app.state.orders = None
        if service_host is not None:
            if service_host.preparation is not preparation or service_host.provider is not provider:
                raise ValueError("phase control requires the same owned admission and finality")
            app.state.lifecycle = LifecycleHost(service_host, resources, client, credentials, sign)
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
                )
                app.include_router(service_work_routes(app.state.dispatch, token=token))
            if service_host.config.orders is not None:
                app.state.orders = CohortOrderHost(service_host, client, credentials)
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
                timeout_graceful_shutdown=None,
            )
        )

        async def poll(worker):
            # Each reviewer has its own loop. A slow peer cannot starve another
            # peer or stall the public intake's readiness/cache worker.
            while not stop.is_set():
                provider.ensure_observer_running()
                report = await worker.poll_once()
                app.state.admission_reports[identity(worker.votes.signer)] = report
                logger.info(
                    "cohort_admission_votes reviewer=%s status=%s votes=%s retries=%s",
                    worker.votes.signer,
                    report["status"],
                    report["votes_published"],
                    report["retry_count"],
                )
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=config.poll_seconds)

        serving = asyncio.create_task(server.serve())
        workers = []
        stopping = asyncio.create_task(stop.wait())
        try:
            while not server.started and not serving.done() and not stop.is_set():
                await asyncio.wait((serving, stopping), timeout=0.05)
            if not stop.is_set() and server.started:
                workers = [asyncio.create_task(poll(w)) for w in app.state.admission_workers]
                if app.state.lifecycle is not None:
                    workers.append(asyncio.create_task(app.state.lifecycle.run(stop)))
                if app.state.dispatch is not None:
                    workers.append(asyncio.create_task(app.state.dispatch.run(stop)))
                if app.state.orders is not None:
                    workers.append(asyncio.create_task(app.state.orders.run(stop)))
                logger.info("cohort_admission_owner_ready config_sha256=%s", digest(config))
            await asyncio.wait((serving, stopping, *workers), return_when=asyncio.FIRST_COMPLETED)
            for task in (serving, *workers):
                if task.done():
                    task.result()
                    if not stop.is_set():
                        raise RuntimeError("admission owner task exited before shutdown")
        finally:
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
                    await _stop_task(stopping)
