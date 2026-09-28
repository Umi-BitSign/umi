"""Install selected service queues from the intake owner's certified preparation.

The public intake host owns these stores and its finality provider. Missing
future inputs hold their catalog while other catalogs and exact retries remain
available. No catalog, roster, key or executable is selected by an HTTP client.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import suppress
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_cohort_recovery import verify_recovery_authority
from .competition_cohort_service_api import ServiceWorkAdmissionAPI, prepared_service_roster
from .competition_cohort_service_queue import ServiceWorkQueue, ServiceWorkQueueConfig
from .competition_cohort_service_work import MAX_CATALOG_BYTES, SignedServiceWorkCatalog
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import RewardManifest, verify_reward_manifest
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import Directory, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class ServiceAdmissionHostConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-service-admission-host/1"] = Field(alias="schema")
    series: StandingRewardSeries
    manifest: RewardManifest
    queue_directory: Directory
    inputs_directory: Directory
    maximum_claims_per_catalog: Annotated[int, Field(ge=1, le=8192)] = 1024
    maximum_queue_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5

    def stores(self):
        return (Path(self.queue_directory), Path(self.inputs_directory))


class ServiceAdmissionHost:
    def __init__(
        self,
        config: ServiceAdmissionHostConfig,
        intake: CohortIntake,
        promotion: CompetitionStore,
        capture: Callable[[], Awaitable[RegistrationCapture]],
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
    ):
        self.config = ServiceAdmissionHostConfig.model_validate_json(canonical_json_bytes(config))
        c, policy = self.config, intake.policy
        verify_reward_manifest(canonical_json_bytes(c.manifest), c.series, policy)
        verify_recovery_authority(c.series.recovery, policy)
        expected = {digest(p): digest(c.series.recovery.authority) for p in c.series.cohorts}
        if intake.bindings != expected:
            raise ValueError("service admission series differs from owned intake")
        self.intake, self.capture = intake, capture
        self.preparation = CohortPreparation(CohortAdmissionQueue(intake), promotion)
        self.queues, self.cohorts = {}, {}
        root = Path(c.queue_directory) / digest(c.series)
        for requirement in c.manifest.cohorts:
            for key in requirement.catalog_sha256s:
                if key in self.queues:
                    raise ValueError("service admission manifest repeats a catalog")
                self.cohorts[key] = requirement.cohort_sha256
                self.queues[key] = ServiceWorkQueue(
                    ServiceWorkQueueConfig(
                        schema="umi-cohort-service-work-queue-config/1",
                        directory=str(root / key),
                        policy_sha256=digest(policy),
                        catalog_sha256=key,
                        service_terms_sha256=requirement.terms_sha256,
                        maximum_claims=c.maximum_claims_per_catalog,
                        maximum_bytes=c.maximum_queue_bytes,
                    ),
                    policy,
                )
        self.api = ServiceWorkAdmissionAPI(
            self.queues,
            capture,
            self.history,
            prepared_service_roster(self.preparation),
            archive,
            intake=intake,
        )

    def _history(self, cohort: str) -> CohortOrderHistory:
        self.intake._allowed(cohort)
        with self.intake._connection() as (_, store):
            history = store.published_history(cohort)
            keys = sorted(
                {
                    t.transition.evidence_sha256
                    for t in history.transitions
                    if t.transition.operation != "revoke"
                }
            )
            return CohortOrderHistory(
                history=history,
                decisions=tuple(store.source(cohort, key, CohortDecisionInput) for key in keys),
            )

    async def history(self, cohort: str) -> CohortOrderHistory:
        return await run_owned_thread(self._history, cohort)

    def _install(self, key, catalog, source, capture):
        cohort = self.cohorts[key]
        prepared = self.preparation.retained(
            cohort,
            expected_tip_sha256=history_tip(source.history),
            current_block=execution_boundary(capture).block,
        )
        with self.intake._connection() as (_, store):
            if store.published_history(cohort) != source.history:
                raise OSError("service installation history changed")
            self.queues[key].install(
                catalog,
                prepared.roster.round,
                source,
                capture,
                expected_tip_sha256=history_tip(source.history),
            )

    async def poll_once(self) -> dict:
        ready = pending = 0
        last_error = ""
        for key, queue in self.queues.items():
            try:
                # Original queue selection recovers without input files or RPC.
                try:
                    await run_owned_thread(queue._catalog)
                except FileNotFoundError:
                    # Only a never-installed queue may select a prepared round.
                    if (
                        await run_owned_thread(queue.journal.get, "service_catalog", key)
                        is not None
                    ):
                        raise
                    catalog = await run_owned_thread(
                        partial(
                            read_private_model,
                            Path(self.config.inputs_directory) / "catalogs" / (key + ".json"),
                            SignedServiceWorkCatalog,
                            maximum_bytes=MAX_CATALOG_BYTES,
                        )
                    )
                    if catalog.catalog.cohort_sha256 != self.cohorts[key]:
                        raise ValueError("service catalog changes selected cohort") from None
                    source = await self.history(self.cohorts[key])
                    state, _, _ = replay_cohort_decisions(
                        source.history, self.intake.policy, source.inputs().__getitem__
                    )
                    if state.phase != "requests":
                        pending += 1
                        continue
                    capture = await self.capture()
                    await run_owned_thread(self._install, key, catalog, source, capture)
                ready += 1
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                pending += 1
                last_error = type(error).__name__
        return {
            "status": "service_admission_inputs_pending"
            if pending
            else "service_admission_installed",
            "catalogs_installed": ready,
            "catalogs_pending": pending,
            "last_error_type": last_error,
            "dispatch_authorized": False,
            "chain_submission_authorized": False,
        }

    def retained_registration_blocks(self) -> frozenset[int]:
        blocks = set()
        for queue in self.queues.values():
            after = 0
            while True:
                page = queue.entries(after_ordinal=after, limit=256)
                if not page:
                    break
                blocks.update(a.observation.block for a in page)
                after = page[-1].ordinal
        return frozenset(blocks)

    async def run(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            report = await self.poll_once()
            logger.info("cohort_service_admission %s", canonical_json_bytes(report).decode("ascii"))
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)
