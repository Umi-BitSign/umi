"""Wallet-free successor intake behind an operator-managed HTTPS proxy.

This service accepts signed submissions using the owned-finality registration
provider. It has no scoring scheduler, signing wallet or weight-submit path.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated, Literal

from fastapi import FastAPI, HTTPException
from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_api import CompetitionApiLimits, PublicIntakeDeployment, create_app
from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_finality_cache import VerifiedRegistrationCache
from .competition_intake_archive import IntakeArchiveConfig, load_intake_archive
from .competition_store import (
    AdmissionCapacity,
    CompetitionStore,
    HistoricalIntakeArchiveBinding,
)
from .open_competition import CompetitionPolicy, Hex32, RegistrationSnapshot, digest
from .policy import umi_source_tree_sha256
from .protocol import StrictProtocolModel, canonical_json_bytes

_FIRST_STAGED_POLICY_SHA256 = "eae2a709bd54468d7ea42c370867be77144115ec709c22e976320828a0e90e56"


class RetainedIntakeState(StrictProtocolModel):
    """Minimum durable ledger state an intake deployment must preserve."""

    schema_: Literal["umi-competition-retained-intake-state/1"] = Field(alias="schema")
    baseline_promotion_sha256: Hex32
    required_submission_sha256s: Annotated[tuple[Hex32, ...], Field(max_length=65_536)]

    @model_validator(mode="after")
    def canonical_submission_digests(self) -> Self:
        if tuple(sorted(set(self.required_submission_sha256s))) != (
            self.required_submission_sha256s
        ):
            raise ValueError("required retained submission digests must be sorted and unique")
        return self


class CompetitionServiceConfig(StrictProtocolModel):
    schema_: Literal["umi-competition-service-config/2"] = Field(alias="schema")
    mode: Literal["intake_no_weight"]
    policy_sha256: Hex32
    public_deployment: PublicIntakeDeployment
    retained_state: RetainedIntakeState
    state_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    submission_head_checkpoint_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    chain: CompetitionChainConfig
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: Annotated[int, Field(ge=1024, le=65535)] = 8098
    admission_capacity: AdmissionCapacity = Field(default_factory=AdmissionCapacity)
    api_limits: CompetitionApiLimits = Field(default_factory=CompetitionApiLimits)
    historical_archives: Annotated[tuple[IntakeArchiveConfig, ...], Field(max_length=8)] = ()

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.chain.policy_sha256 != self.policy_sha256:
            raise ValueError("intake and chain configuration bind different policies")
        if self.chain.collection_timeout_seconds > 15:
            raise ValueError("intake proof collection must finish within 15 seconds")
        if self.admission_capacity.maximum_records > 65_536:
            raise ValueError("intake admission capacity exceeds checkpoint capacity")
        state = Path(self.state_directory)
        checkpoint = Path(self.submission_head_checkpoint_directory)
        chain_state = Path(self.chain.state_directory)
        if not state.is_absolute() or state == Path(state.anchor):
            raise ValueError("intake needs a dedicated absolute state directory")
        if not checkpoint.is_absolute() or checkpoint == Path(checkpoint.anchor):
            raise ValueError("intake needs a dedicated absolute submission checkpoint directory")
        # Keep SQLite, its independent rollback anchor, and the finality cache in
        # separate operator-managed directory trees and backup failure domains.
        roots = (state.resolve(), checkpoint.resolve(), chain_state.resolve())
        if any(
            left == right or left in right.parents or right in left.parents
            for index, left in enumerate(roots)
            for right in roots[index + 1 :]
        ):
            raise ValueError("intake, checkpoint, and finality state directories must not overlap")
        archive_roots = tuple(Path(item.directory).resolve() for item in self.historical_archives)
        if (
            len(set(archive_roots)) != len(archive_roots)
            or any(
                archive == root or archive in root.parents or root in archive.parents
                for archive in archive_roots
                for root in roots
            )
            or any(
                left in right.parents or right in left.parents
                for index, left in enumerate(archive_roots)
                for right in archive_roots[index + 1 :]
            )
        ):
            raise ValueError("historical archives need distinct read-only directory trees")
        return self


def create_intake_app(
    config: CompetitionServiceConfig,
    policy: CompetitionPolicy,
    *,
    provider_factory=None,
) -> FastAPI:
    """Create intake without starting it or contacting the chain at import time.

    The factory injection is for in-process tests; no CLI/config option accepts
    an arbitrary provider, fixture snapshot, wallet or Python import path.
    """
    config = CompetitionServiceConfig.model_validate_json(canonical_json_bytes(config))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if digest(policy) != config.policy_sha256:
        raise ValueError("service configuration does not bind the supplied policy")
    if digest(policy) == _FIRST_STAGED_POLICY_SHA256 and len(config.historical_archives) != 1:
        raise ValueError("the first staged policy requires its pinned predecessor archive")
    if config.public_deployment.umi_source_tree_sha256 != umi_source_tree_sha256():
        raise ValueError("public deployment does not match the running UMI source tree")
    schedule = config.public_deployment.round_schedule
    if not (
        policy.valid_from_block
        <= schedule.intake_opened_block
        <= schedule.round_valid_through_block
        <= policy.valid_through_block
    ):
        raise ValueError("public round schedule is outside the policy interval")
    if (
        schedule.evaluation_close_block - schedule.intake_opened_block
        > policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("public round exceeds the maximum submission lifetime")
    if (
        schedule.work_signing_close_block - schedule.roster_close_earliest_block
        > policy.maximum_snapshot_age_blocks
    ):
        raise ValueError("public round signing can outlive its registration snapshot")
    historical_archives = tuple(load_intake_archive(item) for item in config.historical_archives)
    if historical_archives:
        if len(historical_archives) != 1:
            raise ValueError("the first staged transition requires one predecessor archive")
        predecessor = historical_archives[0]
        predecessor_summary = predecessor.summary()
        if policy.predecessor_sha256 != predecessor_summary["policy_sha256"] or predecessor_summary[
            "public_launch_sha256"
        ] != digest(config.public_deployment.launch_identity()):
            raise ValueError(
                "historical archive is not the durable immediate predecessor for this launch"
            )
    archive_bindings = tuple(
        HistoricalIntakeArchiveBinding(
            schema="umi-historical-intake-archive-binding/1",
            policy_sha256=digest(archive.manifest.policy),
            manifest_sha256=archive.manifest_sha256,
        )
        for archive in historical_archives
    )
    database = Path(config.state_directory) / "competition.sqlite3"
    if not database.is_file() or database.is_symlink():
        raise ValueError("intake deployment requires its pre-existing durable ledger")
    store = CompetitionStore(
        Path(config.state_directory),
        policy,
        admission_capacity=config.admission_capacity,
        public_launch=config.public_deployment.launch_identity(),
        submission_head_checkpoint_directory=Path(config.submission_head_checkpoint_directory),
        historical_intake_archive_bindings=archive_bindings,
    )
    store.verify_retained_intake_state(
        baseline_promotion_sha256=config.retained_state.baseline_promotion_sha256,
        required_submission_sha256s=config.retained_state.required_submission_sha256s,
    )
    provider = (
        FinalizedRegistrationProvider(
            config.chain, policy, retained_capture_blocks=store.retained_registration_blocks
        )
        if provider_factory is None
        else provider_factory(config.chain, policy)
    )
    finality_cache = VerifiedRegistrationCache(
        provider,
        policy,
        maximum_cache_age_seconds=config.chain.maximum_head_age_ms / 1000,
        maximum_head_age_ms=config.chain.maximum_head_age_ms,
        maximum_future_skew_ms=config.chain.maximum_future_skew_ms,
        public_wait_seconds=config.chain.collection_timeout_seconds + 1,
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            await provider.start()
            await finality_cache.start()
            yield
        finally:
            await finality_cache.aclose()
            await provider.aclose()

    async def current_snapshot() -> RegistrationSnapshot:
        return (await finality_cache.collect_fresh()).snapshot

    async def cached_snapshot() -> RegistrationSnapshot:
        return (await finality_cache.cached()).snapshot

    app = create_app(
        store,
        current_snapshot,
        status_snapshot_provider=cached_snapshot,
        lifespan=lifespan,
        registration_source="verifier_attested_finality",
        limits=config.api_limits,
        public_deployment=config.public_deployment,
        historical_archives=historical_archives,
    )
    app.state.finality_providers = (provider,)
    app.state.registration_snapshot_cache = finality_cache
    app.state.historical_intake_archives = historical_archives

    @app.get("/v1/competition/readiness")
    async def readiness():
        try:
            durable = await asyncio.to_thread(store.durable_admission_status)
            admission = durable["admission_capacity"]
            submission_head = durable["retained_submission_head"]
            capture = await finality_cache.cached()
            snapshot, provenance = capture.snapshot, capture.provenance
            schedule_not_open = snapshot.block < schedule.intake_opened_block
            schedule_closed = not schedule_not_open and (
                not config.public_deployment.launch_identity().accepts_at(snapshot.block)
                or snapshot.block > policy.valid_through_block
            )
            if not admission["accepting_new"] and not schedule_not_open and not schedule_closed:
                raise ValueError("admission capacity is exhausted")
        except Exception as error:
            # Provider errors can include filesystem/RPC details; keep them private.
            raise HTTPException(503, "verified registration unavailable; retry later") from error
        result = {
            "schema": "umi-competition-readiness/2",
            "mode": "intake_no_weight",
            "ready_for": (
                "first_round_intake_not_open"
                if schedule_not_open
                else "first_round_intake_closed"
                if schedule_closed
                else "continuous_intake"
                if config.public_deployment.round_stride_blocks is not None
                else "first_round_intake"
            ),
            "policy_sha256": digest(policy),
            "deployment": config.public_deployment.model_dump(mode="json", by_alias=True),
            "round_schedule": schedule.model_dump(mode="json", by_alias=True),
            "retained_state": config.retained_state.model_dump(mode="json", by_alias=True),
            "retained_submission_head": submission_head,
            "assignment_delivery_ready": config.public_deployment.assignment_delivery_ready,
            "model_intake_ready": config.public_deployment.model_intake_ready,
            "admission_accepting_new": (
                not schedule_not_open and not schedule_closed and admission["accepting_new"]
            ),
            "admission_phase": (
                "not_open"
                if schedule_not_open
                else "closed"
                if schedule_closed
                else "open"
                if admission["accepting_new"]
                else "capacity_exhausted"
            ),
            "admission_checked_block": snapshot.block,
            "registration_count": len(snapshot.registrations),
            "registration_source": provenance,
            "evaluation_ready": config.public_deployment.evaluation_ready,
            "rewards_active": False,
            "chain_submission_authorized": False,
        }
        if config.public_deployment.round_stride_blocks is not None:
            result["continuous_intake"] = True
            result["next_intake_schedule"] = (
                config.public_deployment.launch_identity()
                .next_intake_schedule(snapshot.block)
                .model_dump(mode="json", by_alias=True)
                if result["admission_accepting_new"]
                else None
            )
        return result

    return app


def serve_intake(config: CompetitionServiceConfig, policy: CompetitionPolicy) -> None:
    from .competition_service_supervision import serve_with_finality_supervision

    config = CompetitionServiceConfig.model_validate_json(canonical_json_bytes(config))
    app = create_intake_app(config, policy)
    # Terminate TLS at a reviewed reverse proxy. Never trust forwarded headers or
    # accept a request-selected source of finality. One process owns this cache.
    serve_with_finality_supervision(
        app,
        host=config.host,
        port=config.port,
        workers=1,
        proxy_headers=False,
        access_log=False,
        backlog=config.api_limits.socket_backlog,
    )
