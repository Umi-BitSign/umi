"""Run accepted service work inside the admission owner's lifetime."""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Awaitable, Callable
from contextlib import suppress
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

import httpx
from pydantic import Field, model_serializer

from .competition_chain import CompetitionChainConfig
from .competition_cohort_clip_delivery import ClipDeliveryConfig, CohortClipDelivery
from .competition_cohort_origin import CohortEndpointFinalityProvider
from .competition_cohort_request_window import capture_cohort_attempt_window, capture_request_window
from .competition_cohort_service_authority import ServiceWorkAuthority
from .competition_cohort_service_export import ServiceWorkExporter, ServiceWorkLookup
from .competition_cohort_service_peers import ServiceWorkPeerReviews
from .competition_cohort_service_requests import ServiceWorkRequests
from .competition_cohort_service_transport import ServiceWorkTransport
from .competition_cohort_service_vote_http import ServiceVotePeer
from .competition_cohort_service_work import MAX_SERVICE_REQUEST_BYTES, ServiceWorkAssignment
from .competition_cohort_service_worker import _RETRY, ServiceRequestInputs, ServiceWorkWorker
from .competition_reward_service import _close_provider
from .competition_transport_finality import CompetitionTransportFinality
from .concurrency import run_owned_thread
from .open_competition import Hotkey, Signature, digest, identity
from .private_state_wait import run_private_state_operation
from .protocol import StrictProtocolModel, Video, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_cohort_lifecycle_host import LifecycleHost
    from .competition_cohort_service_host import ServiceAdmissionHost

logger = logging.getLogger(__name__)


class ServiceDispatchConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-dispatch-config/1"] = Field(alias="schema")
    request_window_version: Literal[1, 2] = 1
    request_window_miner_hotkeys: Annotated[tuple[Hotkey, ...], Field(max_length=4096)] | None = (
        None
    )
    origins: CompetitionChainConfig
    clips: ClipDeliveryConfig
    batch_size: Annotated[int, Field(ge=1, le=256)] = 16
    concurrency: Annotated[int, Field(ge=1, le=32)] = 4
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    operation_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400

    @model_serializer(mode="wrap")
    def preserve_legacy_window_config(self, handler):
        value = handler(self)
        if self.request_window_version == 1:
            value.pop("request_window_version", None)
        if self.request_window_miner_hotkeys is None:
            value.pop("request_window_miner_hotkeys", None)
        return value

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.origins.state_directory,
                self.clips.directory,
                self.clips.videos_directory,
                self.clips.upload_token_file,
            )
        )


class ServiceDispatchHost:
    def __init__(
        self,
        service: ServiceAdmissionHost,
        lifecycle: LifecycleHost,
        origins: CohortEndpointFinalityProvider,
        client: httpx.AsyncClient,
        credentials: tuple[str, ...],
        key,
        sign: Callable[[object], Awaitable[Signature]],
        clips: Callable[[str], Awaitable[Video]],
    ):
        self.service, self.lifecycle, self.origins = service, lifecycle, origins
        self.config = ServiceDispatchConfig.model_validate_json(
            canonical_json_bytes(service.config.dispatch)
        )
        self.client, self.credentials = client, credentials
        self.key, self.sign, self.clips = key, sign, clips
        if origins.policy != service.intake.policy:
            raise ValueError("service dispatch origin policy differs from its admission")
        self.workers, self.last_reports, self.tasks = {}, {}, {}
        self.maximum_bytes = MAX_SERVICE_REQUEST_BYTES
        # The private exporter can replay retained request evidence before it
        # returns one assignment. Keep that replay inside the same generous
        # operation budget as the worker that consumes it.
        self.timeout_seconds = self.config.operation_timeout_seconds

    async def respond(self, request: ServiceWorkLookup) -> bytes:
        # The request can select only an already configured queue. Native
        # exporter validation binds the claim to its original accepted record.
        key = request.claim.claim.catalog_sha256
        queue = self.service.queues.get(key)
        if queue is None:
            raise ValueError("service lookup catalog is outside selected manifest")
        return await ServiceWorkExporter(
            queue, self.service.config.admission_owner.owner_hotkey, self.sign
        ).respond(request)

    async def worker(self, key: str) -> ServiceWorkWorker:
        if key in self.workers:
            return self.workers[key]
        cohort = self.service.cohorts[key]
        source = await run_owned_thread(self.lifecycle._request_source, cohort)
        queue = self.service.queues[key]
        requests = ServiceWorkRequests(queue, source.transport)
        finality = getattr(self.service, "finality", self.service.provider)
        authority = ServiceWorkAuthority(
            queue,
            finality,
            self.service.history,
            self.origins,
            timeout_seconds=self.config.operation_timeout_seconds,
        )
        blocks = CompetitionTransportFinality(finality, source.transport)

        async def inputs(assignment: ServiceWorkAssignment) -> ServiceRequestInputs:
            # Verify live authority before publishing private media. Capturing
            # the request window comes last, after a potentially slow upload.
            await authority.observe(assignment)
            item = assignment.catalog.catalog.work[assignment.admission.ordinal - 1]
            video = await self.clips(item.video_sha256)
            permitted = self.config.request_window_miner_hotkeys
            miner = identity(assignment.admission.submission.submission.hotkey)
            if self.config.request_window_version == 2 and (
                permitted is None or miner in {identity(key) for key in permitted}
            ):
                latest = await run_private_state_operation(
                    requests.latest,
                    assignment.admission.claim,
                    transport.evaluator,
                    timeout=self.config.operation_timeout_seconds,
                )
                number = 1 if latest is None else latest.attempt_number + 1
                height = await blocks.finalized_head_height()
                window = await capture_cohort_attempt_window(
                    source.transport, blocks, height, assignment, number
                )
            else:
                height = await blocks.finalized_head_height()
                window = await capture_request_window(source.transport, blocks, height)
            return ServiceRequestInputs(video=video, window=window)

        peers = ServiceWorkPeerReviews(
            requests,
            tuple(
                ServiceVotePeer(
                    self.client,
                    peer.origin,
                    policy=queue.policy,
                    cohorts=self.service.intake.config.cohorts,
                    signer=peer.signer,
                    token=token,
                    timeout_seconds=peer.timeout_seconds,
                )
                for peer, token in zip(
                    self.service.config.admission_owner.reviewers, self.credentials, strict=True
                )
            ),
        )
        transport = ServiceWorkTransport(
            requests,
            self.key,
            blocks,
            authority.origin,
            timeout_seconds=self.config.operation_timeout_seconds,
        )
        worker = await run_owned_thread(
            lambda: ServiceWorkWorker(
                transport,
                inputs,
                authority.observe,
                peers.reviewers,
                peers.retry,
                self.sign,
                batch_size=self.config.batch_size,
                concurrency=self.config.concurrency,
            )
        )
        self.workers[key] = worker
        return worker

    async def _run_queue(self, key: str, stop: asyncio.Event) -> None:
        # Future catalogs can arrive at any time; retry them without holding up
        # another cohort or making absence into a terminal result.
        while not stop.is_set():
            try:
                worker = await self.worker(key)
            except _RETRY as error:
                report = {
                    "status": "cohort_dispatch_waiting_inputs",
                    "error_type": type(error).__name__,
                }
                if self.last_reports.get(key) != report:
                    logger.info(
                        "cohort_dispatch_waiting_inputs catalog=%s error_type=%s",
                        key,
                        report["error_type"],
                    )
                self.last_reports[key] = report
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)
                continue

            def report(value):
                self.last_reports[key] = value
                logger.info(
                    "cohort_service_dispatch catalog=%s report=%s",
                    key,
                    json.dumps(value, sort_keys=True, separators=(",", ":")),
                )

            await worker.run(stop, poll_seconds=self.config.poll_seconds, report=report)
            return

    async def run(self, stop: asyncio.Event) -> None:
        self.tasks = {
            key: asyncio.create_task(self._run_queue(key, stop)) for key in self.service.queues
        }
        try:
            done, _ = await asyncio.wait(self.tasks.values(), return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            if not stop.is_set():
                raise RuntimeError("service dispatch worker exited before shutdown")
        finally:
            await ServiceWorkWorker._stop_tasks(tuple(self.tasks.values()))


async def start_service_dispatch(
    service, lifecycle, resources, client, credentials, key, sign, token
):
    config = service.config.dispatch
    if (
        config.origins.policy_sha256 != digest(service.intake.policy)
        or len(config.origins.proof_rpc_fallback_urls) != 2
    ):
        raise ValueError("service dispatch needs the selected policy and two backup RPCs")
    origins = CohortEndpointFinalityProvider(config.origins, service.intake.policy)
    resources.push_async_callback(_close_provider, origins)
    await origins.start()
    return ServiceDispatchHost(
        service,
        lifecycle,
        origins,
        client,
        credentials,
        key,
        sign,
        CohortClipDelivery(config.clips, client, token),
    )
