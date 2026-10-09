"""Install selected service queues from the intake owner's certified preparation.

The public intake host owns these stores and its finality provider. Missing
future inputs hold their catalog while other catalogs and exact retries remain
available. No catalog, roster, key or executable is selected by an HTTP client.
"""

from __future__ import annotations

import asyncio
import logging
import os
import sqlite3
from collections.abc import Awaitable, Callable
from contextlib import AsyncExitStack, suppress
from functools import partial
from pathlib import Path
from typing import Annotated, Literal

import httpx
from pydantic import Field, model_serializer, model_validator

from .competition_chain import RegistrationCapture
from .competition_cohort_admission_host import AdmissionOwnerConfig, run_admission_owner
from .competition_cohort_admission_queue import CohortAdmissionQueue
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
    DirectModelUploadOwners,
)
from .competition_cohort_dispatch_host import ServiceDispatchConfig
from .competition_cohort_intake import CohortIntake, history_tip
from .competition_cohort_lifecycle_host import LifecycleHostConfig
from .competition_cohort_model_acceptance_store import CohortModelAcceptances
from .competition_cohort_model_acceptance_worker import ModelAcceptanceWorker
from .competition_cohort_model_review_http import ModelReviewPeer, ModelReviewPeerConfig
from .competition_cohort_model_static_review import StandingModelReviewPolicy
from .competition_cohort_model_upload import (
    CohortModelUploads,
    ModelUploadConfig,
    authorize_model_delivery,
)
from .competition_cohort_order_host import OrderHostConfig
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_cohort_recovery import (
    ModelRewardCohortAuthority,
    cohort_model_delivery,
    verify_recovery_authority,
)
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
from .named_hotkey import load_named_hotkey
from .open_competition import Hotkey, digest, identity, sign_object
from .private_files import Directory, lock_private_file, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes
from .r2_multipart import R2MultipartClient
from .r2_sigv4 import R2SigV4, load_r2_credentials

logger = logging.getLogger(__name__)


class _SharedFreshFinality:
    """Delegate historical reads while coalescing every fresh capture."""

    def __init__(self, provider, capture, policy, capture_at_least=None):
        if provider is None or not callable(capture):
            raise ValueError("shared service finality is unavailable")
        self._provider, self._capture = provider, capture
        self.policy = policy
        self._capture_at_least = capture_at_least

    async def collect(self):
        return await self._capture()

    async def collect_at_least(self, block):
        # Production uses the shared cache's minimum-height collection. Custom
        # providers without that callback retain their fresh native collection.
        capture = await (
            self._provider.collect()
            if self._capture_at_least is None
            else self._capture_at_least(block)
        )
        if execution_boundary(capture).block < block:
            raise OSError("owned registration head precedes required origin")
        return capture

    def __getattr__(self, name):
        return getattr(self._provider, name)


class DirectModelUploadHostConfig(StrictProtocolModel):
    """One durable direct-R2 issuer that adapts to each signed cohort plan."""

    schema_: Literal["umi-direct-model-upload-host/1"] = Field(alias="schema")
    directory: Directory
    owner_hotkey: Hotkey
    owner_key_file: Directory
    r2_credentials_file: Directory
    r2_bucket: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")]
    standing_review_policy: StandingModelReviewPolicy
    maximum_uploads_per_cohort: Annotated[int, Field(ge=1, le=4096)] = 1024
    maximum_attempts_per_upload: Annotated[int, Field(ge=2, le=64)] = 16
    maximum_metadata_bytes_per_cohort: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)] = 1024**3
    attempt_lease_seconds: Annotated[int, Field(ge=30, le=900)] = 120
    verification_batch_size: Annotated[int, Field(ge=1, le=16)] = 2
    rejected_object_retention_seconds: Annotated[int, Field(ge=300, le=30 * 24 * 60 * 60)] = (
        7 * 24 * 60 * 60
    )
    cleanup_batch_size: Annotated[int, Field(ge=1, le=16)] = 2
    r2_timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60

    def stores(self) -> tuple[Path, ...]:
        return tuple(
            Path(value) for value in (self.directory, self.owner_key_file, self.r2_credentials_file)
        )


class CohortModelPayloadRouter:
    """Route each immutable cohort to its signed payload mechanism."""

    def __init__(self, plans, *, legacy=None, direct=None):
        self.legacy, self.direct = legacy, direct
        self.mechanisms = {}
        for plan in plans:
            if plan.eligible_tracks is not None and "model" not in plan.eligible_tracks:
                continue
            self.mechanisms[digest(plan)] = cohort_model_delivery(plan).mechanism
        if not self.mechanisms:
            raise ValueError("model payload routing requires a model-enabled cohort")
        required = set(self.mechanisms.values())
        if ("coordinator_chunked_v1" in required) != (legacy is not None):
            raise ValueError("legacy model payload routing differs from the signed series")
        if ("direct_r2_multipart_v1" in required) != (direct is not None):
            raise ValueError("direct model payload routing differs from the signed series")

    @property
    def maximum_concurrent_uploads(self) -> int:
        # Only the legacy PUT route streams payload bytes through this process.
        # Direct-only series still construct the common API middleware, where a
        # single unused slot keeps the router interface complete.
        return 1 if self.legacy is None else self.legacy.config.maximum_concurrent_uploads

    def _mechanism(self, request):
        cohort = request.consent.consent.cohort_sha256
        try:
            return self.mechanisms[cohort]
        except KeyError as error:
            raise ValueError("model payload request is outside the signed series") from error

    def require_payload(self, request):
        mechanism = self._mechanism(request)
        selected = self.direct if mechanism == "direct_r2_multipart_v1" else self.legacy
        selected.require_payload(request)

    def review_artifact(self, request):
        if self._mechanism(request) != "direct_r2_multipart_v1":
            return None
        return self.direct.review_artifact(request)

    def delivery_route(self, cohort: str) -> dict[str, str]:
        mechanism = self.mechanisms.get(cohort)
        if mechanism == "direct_r2_multipart_v1":
            return {
                "direct_model_upload_url": (
                    f"/v1/competition/cohorts/{cohort}/direct-model-uploads"
                )
            }
        if mechanism == "coordinator_chunked_v1":
            return {"model_upload_url": f"/v1/competition/cohorts/{cohort}/model-uploads"}
        return {}


class ServiceAdmissionHostConfig(StrictProtocolModel):
    schema_: Literal[
        "umi-cohort-service-admission-host/1",
        "umi-cohort-service-admission-host/2",
        "umi-cohort-service-admission-host/3",
        "umi-cohort-service-admission-host/4",
        "umi-cohort-service-admission-host/5",
        "umi-cohort-service-admission-host/6",
        "umi-cohort-service-admission-host/7",
        "umi-cohort-service-admission-host/8",
        "umi-cohort-service-admission-host/9",
    ] = Field(alias="schema")
    series: StandingRewardSeries
    manifest: RewardManifest
    queue_directory: Directory
    inputs_directory: Directory
    maximum_claims_per_catalog: Annotated[int, Field(ge=1, le=8192)] = 1024
    maximum_queue_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    admission_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 2400
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    model_review_peers: Annotated[tuple[ModelReviewPeerConfig, ...], Field(max_length=64)] = ()
    model_uploads: ModelUploadConfig | None = None
    direct_model_uploads: DirectModelUploadHostConfig | None = None
    admission_owner: AdmissionOwnerConfig | None = None
    lifecycle: LifecycleHostConfig | None = None
    dispatch: ServiceDispatchConfig | None = None
    orders: OrderHostConfig | None = None

    @model_serializer(mode="wrap")
    def serialize(self, handler):
        value = handler(self)
        # Older host configs did not carry this local operational budget. Keep
        # their canonical bytes stable while new deployments set it explicitly.
        if "admission_timeout_seconds" not in self.model_fields_set:
            value.pop("admission_timeout_seconds", None)
        if not self.model_review_peers:
            value.pop("model_review_peers", None)
        if self.model_uploads is None:
            value.pop("model_uploads", None)
        if self.direct_model_uploads is None:
            value.pop("direct_model_uploads", None)
        if self.admission_owner is None:
            value.pop("admission_owner", None)
        if self.lifecycle is None:
            value.pop("lifecycle", None)
        if self.dispatch is None:
            value.pop("dispatch", None)
        if self.orders is None:
            value.pop("orders", None)
        return value

    @model_validator(mode="after")
    def peers(self):
        if self.schema_ not in {
            "umi-cohort-service-admission-host/4",
            "umi-cohort-service-admission-host/5",
            "umi-cohort-service-admission-host/6",
            "umi-cohort-service-admission-host/7",
            "umi-cohort-service-admission-host/8",
            "umi-cohort-service-admission-host/9",
        } and (
            (self.schema_ != "umi-cohort-service-admission-host/1") != bool(self.model_review_peers)
        ):
            raise ValueError("model peers require service admission host version two")
        if self.schema_ not in {
            "umi-cohort-service-admission-host/4",
            "umi-cohort-service-admission-host/5",
            "umi-cohort-service-admission-host/6",
            "umi-cohort-service-admission-host/7",
            "umi-cohort-service-admission-host/8",
            "umi-cohort-service-admission-host/9",
        } and (
            (self.schema_ == "umi-cohort-service-admission-host/3")
            != (self.model_uploads is not None)
        ):
            raise ValueError("model delivery requires service admission host version three")
        if (self.model_uploads is not None or self.direct_model_uploads is not None) and not (
            self.model_review_peers
        ):
            raise ValueError("model delivery requires configured reviewers")
        if (self.schema_ == "umi-cohort-service-admission-host/9") != (
            self.direct_model_uploads is not None
        ):
            raise ValueError("direct R2 model delivery requires service host version nine")
        if (
            self.schema_
            in {
                "umi-cohort-service-admission-host/4",
                "umi-cohort-service-admission-host/5",
                "umi-cohort-service-admission-host/6",
                "umi-cohort-service-admission-host/7",
                "umi-cohort-service-admission-host/8",
                "umi-cohort-service-admission-host/9",
            }
        ) != (self.admission_owner is not None):
            raise ValueError("automatic admission requires service admission host version four")
        if (
            self.schema_
            in {
                "umi-cohort-service-admission-host/5",
                "umi-cohort-service-admission-host/6",
                "umi-cohort-service-admission-host/7",
                "umi-cohort-service-admission-host/8",
                "umi-cohort-service-admission-host/9",
            }
        ) != (self.lifecycle is not None):
            raise ValueError("automatic phase control requires service admission host version five")
        if (
            self.schema_
            in {
                "umi-cohort-service-admission-host/6",
                "umi-cohort-service-admission-host/7",
                "umi-cohort-service-admission-host/8",
                "umi-cohort-service-admission-host/9",
            }
        ) != (self.dispatch is not None):
            raise ValueError(
                "automatic service dispatch requires service admission host version six"
            )
        if (
            self.schema_
            in {
                "umi-cohort-service-admission-host/7",
                "umi-cohort-service-admission-host/8",
                "umi-cohort-service-admission-host/9",
            }
        ) != (self.orders is not None):
            raise ValueError(
                "automatic benchmark orders require service admission host version seven"
            )
        if self.schema_ == "umi-cohort-service-admission-host/8" and (
            self.model_uploads is None or self.model_uploads.admission_reviews_directory is None
        ):
            raise ValueError("version eight model intake requires pre-admission artifact reviews")
        if self.direct_model_uploads is not None and (
            self.admission_owner is None
            or identity(self.direct_model_uploads.owner_hotkey)
            != identity(self.admission_owner.owner_hotkey)
            or Path(self.direct_model_uploads.owner_key_file)
            != Path(self.admission_owner.owner_key_file)
        ):
            raise ValueError("direct model delivery must reuse the admission owner's signer")
        if self.direct_model_uploads is not None:
            mechanisms = {
                cohort_model_delivery(plan).mechanism
                for plan in self.series.cohorts
                if plan.eligible_tracks is None or "model" in plan.eligible_tracks
            }
            if "direct_r2_multipart_v1" not in mechanisms or (
                "coordinator_chunked_v1" in mechanisms
            ) != (self.model_uploads is not None):
                raise ValueError("configured model delivery differs from the signed series")
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
        values = (
            Path(self.queue_directory),
            Path(self.inputs_directory),
            *tokens,
            *(self.lifecycle.stores() if self.lifecycle else ()),
            *(self.dispatch.stores() if self.dispatch else ()),
            *((Path(self.orders.queue.directory),) if self.orders else ()),
            *((Path(self.model_uploads.directory),) if self.model_uploads else ()),
            *(self.direct_model_uploads.stores() if self.direct_model_uploads else ()),
            *(
                (Path(self.model_uploads.admission_reviews_directory),)
                if self.model_uploads is not None
                and self.model_uploads.admission_reviews_directory is not None
                else ()
            ),
            *(
                (
                    Path(self.admission_owner.directory),
                    Path(self.admission_owner.owner_key_file),
                    Path(self.admission_owner.export_token_file),
                    *(
                        (Path(self.admission_owner.windows.directory),)
                        if self.admission_owner.windows
                        else ()
                    ),
                )
                if self.admission_owner
                else ()
            ),
        )
        return tuple(dict.fromkeys(values))


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
        capture_at_least: Callable[[int], Awaitable[RegistrationCapture]] | None = None,
    ):
        self.config = ServiceAdmissionHostConfig.model_validate_json(canonical_json_bytes(config))
        c, policy = self.config, intake.policy
        verify_reward_manifest(canonical_json_bytes(c.manifest), c.series, policy)
        verify_recovery_authority(c.series.recovery, policy)
        expected = {digest(p): digest(c.series.recovery.authority) for p in c.series.cohorts}
        if intake.bindings != expected:
            raise ValueError("service admission series differs from owned intake")
        self.intake, self.capture = intake, capture
        self.runtime_tasks, self.request_readiness = (), None
        self.history_exporter = None
        self.provider = provider
        self.finality = (
            None
            if provider is None
            else _SharedFreshFinality(provider, capture, policy, capture_at_least)
        )
        if c.admission_owner is not None:
            c.admission_owner.check_policy(policy)
            if provider is None or provider.policy != policy:
                raise ValueError("automatic admission requires the owned finality provider")
        self.preparation = CohortPreparation(CohortAdmissionQueue(intake), promotion)
        self.payloads = None
        self.direct_uploads = None
        model_authority = isinstance(c.series.recovery.authority, ModelRewardCohortAuthority)
        if (c.model_uploads or c.direct_model_uploads) and not model_authority:
            raise ValueError("model delivery requires model reward authority")
        if c.direct_model_uploads is not None:
            direct = c.direct_model_uploads
            loaded = load_r2_credentials(Path(direct.r2_credentials_file))
            signer = R2SigV4(loaded.endpoint, direct.r2_bucket, loaded.credentials)
            multipart = R2MultipartClient(signer, timeout_seconds=direct.r2_timeout_seconds)
            key = load_named_hotkey(Path(direct.owner_key_file), direct.owner_hotkey)

            async def authorize(request):
                observed = await capture()
                await run_owned_thread(authorize_model_delivery, intake, request, observed)

            async def sign(body):
                return await run_owned_thread(sign_object, body, key)

            owners = {}
            for plan in c.series.cohorts:
                if plan.eligible_tracks is not None and "model" not in plan.eligible_tracks:
                    continue
                delivery = cohort_model_delivery(plan)
                if delivery.mechanism != "direct_r2_multipart_v1":
                    continue
                cohort = digest(plan)
                owners[cohort] = DirectModelUploadOwner(
                    DirectModelUploadOwnerConfig(
                        schema="umi-direct-model-upload-owner-config/1",
                        directory=str(Path(direct.directory) / cohort),
                        cohort_sha256=cohort,
                        owner_hotkey=direct.owner_hotkey,
                        delivery=delivery,
                        maximum_uploads=direct.maximum_uploads_per_cohort,
                        maximum_attempts_per_upload=direct.maximum_attempts_per_upload,
                        maximum_metadata_bytes=direct.maximum_metadata_bytes_per_cohort,
                        attempt_lease_seconds=direct.attempt_lease_seconds,
                        verification_batch_size=direct.verification_batch_size,
                        rejected_object_retention_seconds=(
                            direct.rejected_object_retention_seconds
                        ),
                        cleanup_batch_size=direct.cleanup_batch_size,
                        admission_reviews_directory=str(Path(c.inputs_directory) / "model-reviews"),
                        standing_review_policy=direct.standing_review_policy,
                    ),
                    multipart,
                    authorize=authorize,
                    sign=sign,
                    policy=policy,
                )
            self.direct_uploads = DirectModelUploadOwners(owners)
        self.models = (
            ModelAcceptanceWorker(
                CohortModelAcceptances(
                    intake,
                    promotion.directory / "model-reward-artifacts",
                    verify_request=(
                        None
                        if c.model_uploads is None and self.direct_uploads is None
                        else lambda request: self.payloads.require_payload(request)
                    ),
                    review_artifact=(
                        None
                        if self.direct_uploads is None
                        else lambda request: self.payloads.review_artifact(request)
                    ),
                ),
                capture,
                Path(c.inputs_directory),
                promotion.directory,
                promote=(None if self.direct_uploads is None else self.direct_uploads.promote),
            )
            if model_authority
            else None
        )
        self.uploads = (
            CohortModelUploads(c.model_uploads, intake, self.models.owner.archive)
            if c.model_uploads
            else None
        )
        if self.uploads is not None or self.direct_uploads is not None:
            self.payloads = CohortModelPayloadRouter(
                c.series.cohorts, legacy=self.uploads, direct=self.direct_uploads
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
            timeout_seconds=c.admission_timeout_seconds,
        )

    def _history(self, cohort: str) -> CohortOrderHistory:
        self.intake._allowed(cohort)
        with self.intake._connection(prefer_history=True) as (_, store):
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

    def _install(self, key, catalog, source, current_block):
        cohort = self.cohorts[key]
        prepared = self.preparation.retained(
            cohort,
            expected_tip_sha256=history_tip(source.history),
            current_block=current_block,
        )
        with self.intake._connection() as (_, store):
            if store.published_history(cohort) != source.history:
                raise OSError("service installation history changed")
            self.queues[key].install_at_block(
                catalog,
                prepared.roster.round,
                source,
                current_block,
                expected_tip_sha256=history_tip(source.history),
            )

    async def _poll_legacy_uploads(self):
        return await run_owned_thread(self.uploads.poll_once)

    async def _poll_direct_uploads(self):
        return await self.direct_uploads.poll_once()

    async def _poll_models(self):
        return await self.models.poll_once()

    async def poll_once(self) -> dict:
        """One complete reconciliation for callers requesting a bounded cycle."""
        legacy = None if self.uploads is None else await self._poll_legacy_uploads()
        direct = None if self.direct_uploads is None else await self._poll_direct_uploads()
        if legacy is not None and direct is not None:
            uploads = {"status": "model_payloads_polled", "legacy": legacy, "direct": direct}
        else:
            uploads = legacy if direct is None else direct
        models = None if self.models is None else await self._poll_models()
        return {
            **await self._poll_catalogs(),
            "model_acceptance": models,
            "model_delivery": uploads,
        }

    async def _poll_catalogs(self) -> dict:
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
                    current_block = (
                        execution_boundary(await self.capture()).block
                        if self.provider is None
                        else await self.provider.current_finalized_block()
                    )
                    await run_owned_thread(self._install, key, catalog, source, current_block)
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
            blocks.update(queue.retained_registration_blocks())
        return frozenset(blocks)

    async def run(self, stop: asyncio.Event) -> None:
        lease = (
            None
            if self.config.direct_model_uploads is None
            else lock_private_file(
                Path(self.config.direct_model_uploads.directory) / "service.lock"
            )
        )
        try:
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
                        service_host=self,
                    )
                )
                polling = asyncio.create_task(self._poll(stop))
                self.runtime_tasks = (owner, polling)
                try:
                    await asyncio.wait((owner, polling), return_when=asyncio.FIRST_COMPLETED)
                    for task in (owner, polling):
                        if task.done():
                            task.result()
                            if not stop.is_set():
                                raise RuntimeError(
                                    "service admission worker exited before shutdown"
                                )
                finally:
                    self.request_readiness, self.runtime_tasks = None, ()
                    try:
                        await _stop_task(owner)
                    finally:
                        await _stop_task(polling)
        finally:
            if lease is not None:
                os.close(lease)

    async def _poll(self, stop: asyncio.Event) -> None:
        # Each store has one serial reconciliation owner. Slow model reviews or
        # direct-R2 verification cannot postpone legacy upload finalization or
        # catalog installation. Cancel/drain every owner before closing clients,
        # releasing the direct-upload lease, or returning to service shutdown.
        callbacks = [("catalogs", self._poll_catalogs)]
        if self.uploads is not None:
            callbacks.append(("legacy_uploads", self._poll_legacy_uploads))
        if self.direct_uploads is not None:
            callbacks.append(("direct_uploads", self._poll_direct_uploads))
        if self.models is not None:
            callbacks.append(("models", self._poll_models))
        async with AsyncExitStack() as owners:
            tasks = []
            for component, callback in callbacks:
                task = asyncio.create_task(self._poll_component(stop, component, callback))
                tasks.append(task)
                owners.push_async_callback(_stop_task, task)
            await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in tasks:
                if task.done():
                    task.result()
                    if not stop.is_set():
                        raise RuntimeError("service reconciliation exited before shutdown")

    async def _poll_component(self, stop, component, callback):
        while not stop.is_set():
            report = {**await callback(), "component": component}
            logger.info("cohort_service_admission %s", canonical_json_bytes(report).decode("ascii"))
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=self.config.poll_seconds)
