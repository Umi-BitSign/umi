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

import httpx
from pydantic import Field, model_serializer, model_validator

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_host import AdmissionOwnerConfig, run_admission_owner
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_model_acceptance_store import CohortModelAcceptances
from .competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from .competition_cohort_model_review_http import ModelReviewPeer, ModelReviewPeerConfig
from .competition_cohort_model_upload import CohortModelUploads, ModelUploadConfig
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_cohort_recovery import ModelRewardCohortAuthority, verify_recovery_authority
from .competition_cohort_service_api import ServiceWorkAdmissionAPI, prepared_service_roster
from .competition_cohort_service_queue import ServiceWorkQueue, ServiceWorkQueueConfig
from .competition_cohort_service_work import MAX_CATALOG_BYTES, SignedServiceWorkCatalog
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_host_activation import _read_root_control_path
from .competition_reward_decisions import StandingRewardSeries
from .competition_reward_manifest import RewardManifest, verify_reward_manifest
from .competition_reward_service import _stop_task
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import Directory, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class ServiceAdmissionHostConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-cohort-service-admission-host/1",
        "umi-cohort-service-admission-host/2",
        "umi-cohort-service-admission-host/3",
        "umi-cohort-service-admission-host/4",
    ] = Field(alias="schema")
    series: StandingRewardSeries
    manifest: RewardManifest
    queue_directory: Directory
    inputs_directory: Directory
    maximum_claims_per_catalog: Annotated[int, Field(ge=1, le=8192)] = 1024
    maximum_queue_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    model_review_peers: Annotated[tuple[ModelReviewPeerConfig, ...], Field(max_length=64)] = ()
    model_uploads: ModelUploadConfig | None = None
    admission_owner: AdmissionOwnerConfig | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        if not self.model_review_peers:
            value.pop("model_review_peers", None)
        if self.model_uploads is None:
            value.pop("model_uploads", None)
        if self.admission_owner is None:
            value.pop("admission_owner", None)
        return value

    @model_validator(mode="after")
    def peers(self):
        if self.schema_ != "umi-cohort-service-admission-host/4" and (
            (self.schema_ != "umi-cohort-service-admission-host/1") != bool(self.model_review_peers)
        ):
            raise ValueError("model peers require service admission host version two")
        if self.schema_ != "umi-cohort-service-admission-host/4" and (
            (self.schema_ == "umi-cohort-service-admission-host/3")
            != (self.model_uploads is not None)
        ):
            raise ValueError("model delivery requires service admission host version three")
        if self.model_uploads is not None and not self.model_review_peers:
            raise ValueError("model delivery requires configured reviewers")
        if (self.schema_ == "umi-cohort-service-admission-host/4") != (
            self.admission_owner is not None
        ):
            raise ValueError("automatic admission requires service admission host version four")
        if len({identity(p.signer) for p in self.model_review_peers}) != len(
            self.model_review_peers
        ):
            raise ValueError("model reviewer configuration repeats a signer")
        return self

    def stores(self):
        # The same private reviewer serves admission and model votes. Reuse its
        # credential file, but never alias a credential to a mutable state root
        # or to an unrelated reviewer identity/origin.
        tokens = {}
        for peer in (
            *self.model_review_peers,
            *(self.admission_owner.reviewers if self.admission_owner else ()),
        ):
            path, binding = Path(peer.token_file), (identity(peer.signer), peer.origin)
            if path in tokens and tokens[path] != binding:
                raise ValueError("reviewer credential path has conflicting identities or origins")
            tokens[path] = binding
        return (
            Path(self.queue_directory),
            Path(self.inputs_directory),
            *tokens,
            *((Path(self.model_uploads.directory),) if self.model_uploads else ()),
            *(
                (
                    Path(self.admission_owner.directory),
                    Path(self.admission_owner.owner_key_file),
                    Path(self.admission_owner.export_token_file),
                )
                if self.admission_owner
                else ()
            ),
        )


class ServiceAdmissionHost:
    def __init__(
        self,
        config: ServiceAdmissionHostConfig,
        intake: CohortIntake,
        promotion: CompetitionStore,
        capture: Callable[[], Awaitable[RegistrationCapture]],
        archive: Callable[[ExecutionBoundary], Awaitable[tuple[bytes, bytes]]],
        *,
        provider=None,
    ):
        self.config = ServiceAdmissionHostConfig.model_validate_json(canonical_json_bytes(config))
        c, policy = self.config, intake.policy
        verify_reward_manifest(canonical_json_bytes(c.manifest), c.series, policy)
        verify_recovery_authority(c.series.recovery, policy)
        expected = {digest(p): digest(c.series.recovery.authority) for p in c.series.cohorts}
        if intake.bindings != expected:
            raise ValueError("service admission series differs from owned intake")
        self.intake, self.capture = intake, capture
        self.provider = provider
        if c.admission_owner is not None:
            c.admission_owner.check_policy(policy)
            if provider is None or provider.policy != policy:
                raise ValueError("automatic admission requires the owned finality provider")
        self.preparation = CohortPreparation(CohortAdmissionQueue(intake), promotion)
        self.models = (
            ModelAcceptanceWorker(
                CohortModelAcceptances(intake, promotion.directory / "model-reward-artifacts"),
                capture,
                Path(c.inputs_directory),
                promotion.directory,
            )
            if isinstance(c.series.recovery.authority, ModelRewardCohortAuthority)
            else None
        )
        if c.model_uploads and self.models is None:
            raise ValueError("model delivery requires model reward authority")
        self.uploads = (
            CohortModelUploads(c.model_uploads, intake, self.models.owner.archive)
            if c.model_uploads
            else None
        )
        if c.model_review_peers:
            groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
            if self.models is None or any(
                identity(p.signer) not in groups for p in c.model_review_peers
            ):
                raise ValueError("model reviewer is outside model authority or policy")
            if (
                len({groups[identity(p.signer)] for p in c.model_review_peers})
                < policy.required_evaluator_groups
            ):
                raise ValueError("configured model reviewers cannot form independent quorum")
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
        uploads = None if self.uploads is None else await run_owned_thread(self.uploads.poll_once)
        models = None if self.models is None else await self.models.poll_once()
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
            "model_acceptance": models,
            "model_delivery": uploads,
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
        async with httpx.AsyncClient(
            trust_env=False,
            follow_redirects=False,
            limits=httpx.Limits(max_connections=2, max_keepalive_connections=2),
        ) as client:
            if self.models is not None and self.config.model_review_peers:
                peers = []
                for p in self.config.model_review_peers:
                    token = (
                        _read_root_control_path(Path(p.token_file), 257, modes={0o400, 0o440})
                        .decode("ascii")
                        .removesuffix("\n")
                    )
                    peers.append(
                        ModelReviewPeer(
                            client,
                            p.origin,
                            policy=self.intake.policy,
                            cohorts=self.intake.config.cohorts,
                            signer=p.signer,
                            token=token,
                            timeout_seconds=p.timeout_seconds,
                        )
                    )
                self.models.reviewers = tuple(peers)
            if self.config.admission_owner is None:
                await self._poll(stop)
                return
            owner = asyncio.create_task(
                run_admission_owner(
                    self.config.admission_owner,
                    self.preparation,
                    self.provider,
                    stop,
                )
            )
            polling = asyncio.create_task(self._poll(stop))
            try:
                await asyncio.wait((owner, polling), return_when=asyncio.FIRST_COMPLETED)
                for task in (owner, polling):
                    if task.done():
                        task.result()
                        if not stop.is_set():
                            raise RuntimeError("service admission worker exited before shutdown")
            finally:
                try:
                    await _stop_task(owner)
                finally:
                    await _stop_task(polling)

    async def _poll(self, stop: asyncio.Event) -> None:
        while not stop.is_set():
            report = await self.poll_once()
            logger.info("cohort_service_admission %s", canonical_json_bytes(report).decode("ascii"))
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)
