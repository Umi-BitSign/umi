"""Configured native phase factories owned by the admission service.

All cohort decisions use remote native reviewers. The owner publishes original
request evidence and hands certified closure to settlement. Missing dispatch
readiness or delivered originals hold progress and preserve the same cohort.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, field_validator

from .competition_client import validate_intake_origin
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_intake import CohortIntakePublisher
from .competition_cohort_intake_phase import CohortIntakePhaseObserver
from .competition_cohort_lifecycle import CohortLifecycleService, CohortPhaseDriver
from .competition_cohort_phase_vote_http import PhaseVotePeer
from .competition_cohort_preparation import PreparedCohortRound
from .competition_cohort_preparation_phase import NativePreparationProgressSource
from .competition_cohort_preparation_publisher import CohortPreparationPublisher
from .competition_cohort_progress_signer import CertifiedPhaseObserver
from .competition_cohort_readiness import LiveIntakePhaseObserver
from .competition_cohort_request_export import RequestReviewExporter
from .competition_cohort_request_files import RequestCompletionFiles
from .competition_cohort_request_inventory import RequestInventoryCutoff
from .competition_cohort_request_phase import NativeRequestProgressSource
from .competition_cohort_request_publication import CohortRequestSettlementPublisher
from .competition_cohort_request_readiness import LiveRequestPhaseObserver
from .competition_cohort_request_start import RequestStartConfig, SeriesRequestStart
from .competition_cohort_service_quality import ServiceTerms
from .competition_cohort_settlement_boot import settlement_store
from .competition_cohort_settlement_config import SettlementOriginalSources
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_cohort_settlement_proofs import SettlementRegistrationFiles
from .competition_execution import execution_boundary
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread
from .open_competition import digest
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import Directory, publish_private_model, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_cohort_service_host import ServiceAdmissionHost

logger = logging.getLogger(__name__)


class LifecycleHostConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-lifecycle-host/1"] = Field(alias="schema")
    directory: Directory
    request_start: RequestStartConfig
    request_completion_directory: Directory
    settlement_history_directory: Directory
    proof_export_directory: Directory
    sources: SettlementOriginalSources
    public_origin: str
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    sample_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    maximum_state_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)] = 1024**3

    _origin = field_validator("public_origin")(validate_intake_origin)

    def stores(self):
        # Intake and catalog paths are selected by the enclosing admission host.
        return tuple(
            Path(p)
            for p in (
                self.directory,
                self.request_start.directory,
                self.request_completion_directory,
                self.settlement_history_directory,
                self.proof_export_directory,
                self.sources.round_directory,
                self.sources.objects_directory,
                self.sources.transport_directory,
                self.sources.pulses_directory,
            )
        )


class LifecycleHost:
    def __init__(self, service: ServiceAdmissionHost, resources, client, credentials, sign):
        self.service, self.resources, self.client = service, resources, client
        self.config = LifecycleHostConfig.model_validate_json(
            canonical_json_bytes(service.config.lifecycle)
        )
        c, owner = self.config, service.config.admission_owner
        if owner is None or service.provider is None:
            raise ValueError("cohort lifecycle requires the owned admission runtime")
        if (
            c.sources.intake != service.intake.config
            or c.sources.eligible_tracks != service.intake.tracks
        ):
            raise ValueError("cohort lifecycle originals differ from its owned intake")
        if Path(c.sources.catalogs_directory) != Path(service.config.inputs_directory) / "catalogs":
            raise ValueError("cohort lifecycle catalogs differ from service admission")
        self.provider = getattr(service, "finality", service.provider)
        self.policy = service.intake.policy
        self.credentials, self.sign = credentials, sign
        self.root = Path(c.directory) / digest(service.config.series)
        self.gate = SeriesRequestStart(
            c.request_start, service.config.series, self.provider, service.history
        )
        self.files = RequestCompletionFiles(Path(c.request_completion_directory))
        self.proofs = SettlementRegistrationFiles(
            self.provider, inbox=self.root / "proof-inbox", outbox=Path(c.proof_export_directory)
        )
        self.stores, self.nodes, self.requests = {}, {}, {}
        self.last_reports = {}
        self.request_opening_clocks = {}
        # A request export can replay every retained service observation and
        # object in a cohort. Use the same operational budget as the configured
        # reviewers instead of cancelling that replay after a fixed 30 seconds.
        self.maximum_bytes = owner.maximum_export_bytes
        self.timeout_seconds = min(peer.timeout_seconds for peer in owner.reviewers)

    def _peers(self, phase):
        owner = self.service.config.admission_owner
        return tuple(
            PhaseVotePeer(
                self.client,
                peer.origin,
                policy=self.policy,
                cohorts=self.service.intake.config.cohorts,
                signer=peer.signer,
                phase=phase,
                token=credential,
                timeout_seconds=peer.timeout_seconds,
            )
            for peer, credential in zip(owner.reviewers, self.credentials, strict=True)
        )

    async def decision(self, cohort, key):
        # All control SQLite connections belong to this event loop.
        return self.stores[cohort].source(cohort, key, CohortDecisionInput)

    async def _intake(self):
        phase = CohortIntakePhaseObserver(
            self.service.intake,
            maximum_sample_gap_blocks=self.service.config.admission_owner.maximum_sample_gap_blocks,
        )
        live = LiveIntakePhaseObserver(
            phase,
            self.config.public_origin,
            timeout_seconds=self.timeout_seconds,
        )
        return CohortPhaseDriver(
            CertifiedPhaseObserver(live, self._peers("intake"), self.policy),
            sample_service=live.sample_service,
        )

    async def _preparation(self):
        source = NativePreparationProgressSource(self.service.preparation)
        publisher = CohortPreparationPublisher(
            self.service.preparation, self.provider, Path(self.config.sources.round_directory)
        )
        return CohortPhaseDriver(
            CertifiedPhaseObserver(source.sample, self._peers("preparation"), self.policy),
            publisher.publish_history,
        )

    def _request_source(self, cohort):
        c = self.config
        prepared = read_private_model(
            Path(c.sources.round_directory) / (cohort + ".json"),
            PreparedCohortRound,
            maximum_bytes=self.maximum_bytes,
        )
        if prepared.roster.round.cohort_sha256 != cohort:
            raise ValueError("request owner prepared round changed its cohort")
        requirement = next(
            r for r in self.service.config.manifest.cohorts if r.cohort_sha256 == cohort
        )
        queues = tuple(self.service.queues[k] for k in requirement.catalog_sha256s)
        # Queues must already be installed by their native admission owner.
        installed = tuple(q._catalog() for q in queues)
        if any(round_ != prepared.roster.round for _, round_ in installed):
            raise ValueError("request owner queue differs from the prepared round")
        catalogs = tuple(catalog for catalog, _ in installed)
        objects = SettlementEvidenceFiles(Path(c.sources.objects_directory))
        terms = ServiceTerms.model_validate_json(objects(requirement.terms_sha256))
        transport = read_private_model(
            Path(c.sources.transport_directory) / (terms.transport_policy_sha256 + ".json"),
            ScoringPolicy,
            maximum_bytes=8 * 1024**2,
        )
        if scoring_policy_hash(transport) != terms.transport_policy_sha256:
            raise ValueError("request owner transport differs from selected service terms")
        journal = RoundJournal(
            self.root / cohort / "requests",
            {
                "schema": "umi-cohort-request-owner/1",
                "series": digest(self.service.config.series),
                "cohort": cohort,
            },
            maximum_rounds=65536,
            maximum_bytes=c.maximum_state_bytes,
        )

        def publish_inventory_cutoff(tail):
            publish_private_model(
                Path(c.settlement_history_directory) / (cohort + "-inventory-cutoff.json"),
                RequestInventoryCutoff(
                    schema="umi-private-request-inventory-cutoff/1",
                    cohort_sha256=cohort,
                    policy_sha256=digest(self.service.intake.policy),
                    observation=tail.observation,
                ),
                maximum_bytes=16384,
            )

        return NativeRequestProgressSource(
            self.service.intake,
            journal,
            roster=prepared.roster,
            catalogs=catalogs,
            queues=queues,
            transport=transport,
            orders=partial(self.files.orders, prepared.roster),
            terminals=self.files.terminal,
            objects=self.files.objects,
            partial_source=partial(self.files.partial, prepared.roster),
            inventory_source=partial(self.files.inventories, prepared.roster),
            publish_inventory_cutoff=publish_inventory_cutoff,
            maximum_sample_gap_blocks=self.service.config.admission_owner.maximum_sample_gap_blocks,
        )

    async def _request_opening_clock(self, source, state):
        observation = await run_owned_thread(source.request_opening, state)
        key = digest(observation)
        if key not in self.request_opening_clocks:
            raw, metadata = await self.provider.retained_archive(observation)
            reviewed = await self.provider.review_archive(observation, raw, metadata)
            if reviewed.original != observation or type(reviewed.timestamp_ms) is not int:
                raise ValueError("request opening lacks its native timestamp proof")
            await self.proofs.publish(observation)
            self.request_opening_clocks[key] = reviewed
        return self.request_opening_clocks[key]

    async def _requests(self, cohort):
        if cohort not in self.requests:
            self.requests[cohort] = await run_owned_thread(self._request_source, cohort)
        source = self.requests[cohort]
        live = LiveRequestPhaseObserver(
            source,
            self.config.public_origin,
            client=self.client,
            timeout_seconds=self.timeout_seconds,
            opening_clock=partial(self._request_opening_clock, source),
        )
        publisher = CohortRequestSettlementPublisher(
            source,
            self.provider.collect,
            self.decision,
            self.proofs.publish,
            sources=self.config.sources,
            history_directory=Path(self.config.settlement_history_directory),
        )
        return CohortPhaseDriver(
            CertifiedPhaseObserver(live, self._peers("requests"), self.policy),
            publisher,
            live.sample_service,
        )

    async def respond(self, request):
        source = self.requests.get(request.progress.cohort_sha256)
        if source is None:
            raise FileNotFoundError("native request owner has not started")
        return await RequestReviewExporter(
            source,
            self.service.config.admission_owner.owner_hotkey,
            self.sign,
            maximum_bytes=self.maximum_bytes,
            timeout_seconds=self.timeout_seconds,
        ).respond(request)

    async def node(self, cohort):
        if cohort in self.nodes:
            return self.nodes[cohort]
        original = await self.service.history(cohort)
        plan = next(p for p in self.service.config.series.cohorts if digest(p) == cohort)
        if (
            original.history.plan != plan
            or original.history.authority != self.service.config.series.recovery
        ):
            raise ValueError("cohort lifecycle admission differs from selected series")
        replay_cohort_decisions(original.history, self.policy, original.inputs().__getitem__)
        if cohort not in self.stores:
            self.stores[cohort] = self.resources.enter_context(
                settlement_store(self.root / cohort / "control", self.config.maximum_state_bytes)
            )
        store = self.stores[cohort]
        if not store.has_published_history(cohort):
            capture = await self.provider.collect()
            store.publish_history(
                original.history, self.policy, current_block=execution_boundary(capture).block
            )
        current = store.published_history(cohort)
        shared = min(len(current.transitions), len(original.history.transitions))
        if (
            current.genesis != original.history.genesis
            or current.genesis_signatures != original.history.genesis_signatures
            or current.transitions[:shared] != original.history.transitions[:shared]
        ):
            raise ValueError("cohort lifecycle cannot replace its original control history")
        # Missing sources after a lost import acknowledgement are repaired.
        for decision in original.decisions:
            store.retain_source(cohort, decision)
        node = CohortLifecycleService(
            store,
            cohort,
            self.policy,
            current.genesis_signatures,
            self.provider,
            CohortIntakePublisher(self.service.intake, self.provider.collect, self.decision),
            {
                "intake": self._intake,
                "preparation": self._preparation,
                "requests": partial(self._requests, cohort),
            },
            request_start=self.gate,
        )
        self.nodes[cohort] = node
        return node

    async def run(self, stop):
        async def cohort_loop(cohort):
            while not stop.is_set():
                try:
                    node = await self.node(cohort)
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    result = {
                        "status": "cohort_lifecycle_start_retry",
                        "error_type": type(error).__name__,
                    }
                    self.last_reports[cohort] = result
                    logger.info(
                        "cohort_lifecycle_start cohort=%s error_type=%s",
                        cohort,
                        type(error).__name__,
                    )
                else:
                    self.last_reports[cohort] = await node.run(
                        stop,
                        poll_seconds=self.config.poll_seconds,
                        sample_seconds=self.config.sample_seconds,
                        report=lambda r: self.last_reports.__setitem__(cohort, r),
                    )
                    # Settlement owns subsequent phases; keep exports and the
                    # control journal open until the enclosing service stops.
                    await stop.wait()
                    return
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)

        tasks = [
            asyncio.create_task(cohort_loop(digest(p))) for p in self.service.config.series.cohorts
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
