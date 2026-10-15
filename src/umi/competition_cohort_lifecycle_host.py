"""Configured native phase factories owned by the admission service.

All cohort decisions use remote native reviewers. The owner publishes original
request evidence and hands certified closure to settlement. Missing dispatch
readiness or delivered originals hold progress and preserve the same cohort.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
import time
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import TYPE_CHECKING, Annotated, Literal

from pydantic import Field, field_validator, model_serializer, model_validator

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
from .competition_cohort_reference_preflight import preflight_service_references
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
from .concurrency import run_owned_thread, wait_for_owned
from .host_memory_request_bounds import bounded_stage_declarations, check_stage_json, stage_count
from .host_memory_runtime import authorize_memory, requests_stage_policy
from .open_competition import digest
from .policy import ScoringPolicy, scoring_policy_hash
from .private_files import Directory, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

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
    request_tail_operator_token_file: Directory | None = None
    automatic_progression_hold_cohorts: tuple[Hex32, ...] = ()

    @model_serializer(mode="wrap")
    def preserve_legacy(self, handler):
        value = handler(self)
        if self.request_tail_operator_token_file is None:
            value.pop("request_tail_operator_token_file", None)
        if not self.automatic_progression_hold_cohorts:
            value.pop("automatic_progression_hold_cohorts", None)
        return value

    @model_validator(mode="after")
    def known_hold_cohorts(self):
        holds = self.automatic_progression_hold_cohorts
        allowed = {entry.cohort_sha256 for entry in self.sources.intake.cohorts}
        if len(holds) != len(set(holds)) or not set(holds) <= allowed:
            raise ValueError("automatic progression holds must name distinct configured cohorts")
        return self

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
        self.files = RequestCompletionFiles(
            Path(c.request_completion_directory), maximum_bytes=owner.request_replay_bytes
        )
        self.proofs = SettlementRegistrationFiles(
            self.provider, inbox=self.root / "proof-inbox", outbox=Path(c.proof_export_directory)
        )
        self.stores, self.nodes, self.requests = {}, {}, {}
        self.last_reports = {}
        self.request_opening_clocks = {}
        # A request export can replay every retained service observation and
        # object in a cohort. Use the same operational budget as the configured
        # reviewers instead of cancelling that replay after a fixed 30 seconds.
        self.declaration_bytes = owner.maximum_export_bytes
        self.maximum_bytes = owner.request_evidence_bytes
        self.request_replay_bytes = owner.request_replay_bytes
        self.readiness_timeout_seconds = min(peer.timeout_seconds for peer in owner.reviewers)
        self.timeout_seconds = (
            owner.phase_review_budget.export_seconds
            if owner.phase_review_budget is not None
            else self.readiness_timeout_seconds
        )

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
                budget=peer.phase_review_budget,
            )
            for peer, credential in zip(owner.reviewers, self.credentials, strict=True)
        )

    async def decision(self, cohort, key):
        # All control SQLite connections belong to this event loop.
        return self.stores[cohort].source(cohort, key, CohortDecisionInput)

    async def _publication_block(self):
        budget = self.service.config.admission_owner.phase_review_budget
        block = await wait_for_owned(
            self.provider.current_finalized_block(), timeout=budget.authority_seconds
        )
        if type(block) is not int or not 0 <= block <= 2**53 - 1:
            raise ValueError("lifecycle publication owned block is invalid")
        return block

    async def _intake(self):
        authorize_memory(None, None, "intake")
        phase = CohortIntakePhaseObserver(
            self.service.intake,
            maximum_sample_gap_blocks=self.service.config.admission_owner.maximum_sample_gap_blocks,
        )
        live = LiveIntakePhaseObserver(
            phase,
            self.config.public_origin,
            timeout_seconds=self.readiness_timeout_seconds,
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

    @bounded_stage_declarations
    def _request_source(self, cohort):
        authorize_memory("requests_source", cohort, "requests")
        c = self.config
        prepared = read_private_model(
            Path(c.sources.round_directory) / (cohort + ".json"),
            PreparedCohortRound,
            maximum_bytes=self.declaration_bytes,
        )
        if prepared.roster.round.cohort_sha256 != cohort:
            raise ValueError("request owner prepared round changed its cohort")
        stage = requests_stage_policy()
        if stage is not None and digest(prepared.roster.round) != stage.preparation_result_sha256:
            raise ValueError("prepared round differs from qualified requests stage")
        stage_count("maximum_participants", len(prepared.roster.round.participants))
        requirement = next(
            r for r in self.service.config.manifest.cohorts if r.cohort_sha256 == cohort
        )
        stage_count("maximum_catalogs", len(requirement.catalog_sha256s))
        queues = tuple(self.service.queues[k] for k in requirement.catalog_sha256s)
        # Queues must already be installed by their native admission owner.
        installed = tuple(q._catalog() for q in queues)
        if any(round_ != prepared.roster.round for _, round_ in installed):
            raise ValueError("request owner queue differs from the prepared round")
        catalogs = tuple(catalog for catalog, _ in installed)
        objects = SettlementEvidenceFiles(Path(c.sources.objects_directory))
        terms_raw = objects(requirement.terms_sha256)
        check_stage_json(terms_raw, kind="declaration")
        terms = ServiceTerms.model_validate_json(terms_raw)
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
            maximum_observation_bytes=self.request_replay_bytes,
            maximum_replay_bytes=self.request_replay_bytes,
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
            timeout_seconds=self.readiness_timeout_seconds,
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
            live.prepare,
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
        authorize_memory("requests_lifecycle", cohort, "requests")
        if cohort in self.nodes:
            return self.nodes[cohort]
        original = await self.service.history(cohort)
        plan = next(p for p in self.service.config.series.cohorts if digest(p) == cohort)
        if (
            original.history.plan != plan
            or original.history.authority != self.service.config.series.recovery
        ):
            raise ValueError("cohort lifecycle admission differs from selected series")
        original_state, _, _ = replay_cohort_decisions(
            original.history, self.policy, original.inputs().__getitem__
        )
        stage = requests_stage_policy()
        if stage is not None and original_state.phase in {"intake", "preparation", "revoked"}:
            raise ValueError("requests stage requires the existing active request authority")
        if cohort not in self.stores:
            self.stores[cohort] = self.resources.enter_context(
                settlement_store(self.root / cohort / "control", self.config.maximum_state_bytes)
            )
        store = self.stores[cohort]
        owned_publication = (
            self._publication_block
            if plan.sequence > 5
            and self.service.config.admission_owner.phase_review_budget is not None
            else None
        )
        if not store.has_published_history(cohort):
            current_block = (
                await owned_publication()
                if owned_publication is not None
                else execution_boundary(await self.provider.collect()).block
            )
            store.publish_history(original.history, self.policy, current_block=current_block)
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

        adoption_compatible = plan.sequence > 5 and plan.schema_ != "umi-recoverable-cohort-plan/4"

        async def reconcile_request_tail_adoption():
            # Intake gates receipts first. Resume exact bytes after a crash
            # between that native reservation and control-journal acknowledgement.
            pending = await run_owned_thread(
                self.service.intake.pending_request_tail_adoption, cohort
            )
            if pending is not None:
                store.reserve_exact(pending)

        if adoption_compatible:
            await reconcile_request_tail_adoption()

        async def preflight_before_tick():
            if adoption_compatible:
                await reconcile_request_tail_adoption()
            state, _ = node.controller.store.status(cohort)
            if state.phase not in {"intake", "preparation"}:
                return
            # The control journal belongs to the event-loop thread. Snapshot
            # verified selections here; only independent private files go to a
            # worker, which must never acquire this live SQLite connection.
            history, state, _, _ = node.controller._history()
            await run_owned_thread(
                partial(
                    preflight_service_references,
                    self.config.sources,
                    history,
                    self.service.config.manifest.requirement(cohort),
                    self.policy,
                    phase=state.phase,
                )
            )

        node = CohortLifecycleService(
            store,
            cohort,
            self.policy,
            current.genesis_signatures,
            self.provider,
            CohortIntakePublisher(
                self.service.intake,
                self.provider.collect,
                self.decision,
                current_block=owned_publication,
            ),
            {
                "intake": self._intake,
                "preparation": self._preparation,
                "requests": partial(self._requests, cohort),
            },
            request_start=self.gate,
            before_tick=preflight_before_tick,
        )
        self.nodes[cohort] = node
        return node

    async def run(self, stop):
        async def cohort_loop(cohort):
            if cohort in self.config.automatic_progression_hold_cohorts:
                # Do not construct a controller, publish history, sample, seal,
                # sign or resume a retained intent while this local hold is set.
                # HTTP admission and other cohorts retain their own workers.
                started = time.monotonic()
                while not stop.is_set():
                    result = {
                        "status": "automatic_progression_held",
                        "cohort_sha256": cohort,
                        "completed": 0,
                        "total": 1,
                        "percent": 0.0,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "eta_seconds": None,
                        "eta_basis": "awaiting_qualified_release_and_explicit_hold_removal",
                        "signed_state_changed": False,
                    }
                    self.last_reports[cohort] = result
                    logger.info("cohort_lifecycle_hold %s", canonical_json_bytes(result).decode())
                    with suppress(asyncio.TimeoutError):
                        await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)
                return
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

        stage = requests_stage_policy()
        tasks = [
            asyncio.create_task(cohort_loop(digest(p)))
            for p in self.service.config.series.cohorts
            if stage is None or digest(p) == stage.cohort_sha256
        ]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
