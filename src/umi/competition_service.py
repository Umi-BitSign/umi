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

from .competition_api import CompetitionApiLimits, create_app
from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_store import AdmissionCapacity, CompetitionStore
from .open_competition import CompetitionPolicy, Hex32, RegistrationSnapshot, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class CompetitionServiceConfig(StrictProtocolModel):
    schema_: Literal["umi-competition-service-config/1"] = Field(alias="schema")
    mode: Literal["intake_no_weight"]
    policy_sha256: Hex32
    state_directory: Annotated[str, Field(min_length=1, max_length=4096)]
    chain: CompetitionChainConfig
    host: Literal["127.0.0.1", "::1"] = "127.0.0.1"
    port: Annotated[int, Field(ge=1024, le=65535)] = 8098
    admission_capacity: AdmissionCapacity = Field(default_factory=AdmissionCapacity)
    api_limits: CompetitionApiLimits = Field(default_factory=CompetitionApiLimits)

    @model_validator(mode="after")
    def validate_bindings(self) -> Self:
        if self.chain.policy_sha256 != self.policy_sha256:
            raise ValueError("intake and chain configuration bind different policies")
        if self.chain.collection_timeout_seconds > 15:
            raise ValueError("intake proof collection must finish within 15 seconds")
        state = Path(self.state_directory)
        chain_state = Path(self.chain.state_directory)
        if not state.is_absolute() or state == Path(state.anchor):
            raise ValueError("intake needs a dedicated absolute state directory")
        # Keep SQLite ownership and lifecycle separate from the finality cache.
        state, chain_state = state.resolve(), chain_state.resolve()
        if state == chain_state or state in chain_state.parents or chain_state in state.parents:
            raise ValueError("intake and finality state directories must not overlap")
        return self


_PROVENANCE_FIELDS = frozenset(
    {
        "schema",
        "evidence_class",
        "offline_finality_proof",
        "genesis_block_hash",
        "block",
        "block_hash",
        "state_root",
        "timestamp_ms",
        "snapshot_sha256",
        "evidence_sha256",
        "metadata_sha256",
        "finality_evidence_sha256",
        "finality_verifier_sha256",
        "storage_proof_verifier_sha256",
        "chain_submission_authorized",
    }
)


def create_intake_app(
    config: CompetitionServiceConfig,
    policy: CompetitionPolicy,
    *,
    provider_factory=FinalizedRegistrationProvider,
) -> FastAPI:
    """Create intake without starting it or contacting the chain at import time.

    The factory injection is for in-process tests; no CLI/config option accepts
    an arbitrary provider, fixture snapshot, wallet or Python import path.
    """
    config = CompetitionServiceConfig.model_validate_json(canonical_json_bytes(config))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if digest(policy) != config.policy_sha256:
        raise ValueError("service configuration does not bind the supplied policy")
    store = CompetitionStore(
        Path(config.state_directory),
        policy,
        admission_capacity=config.admission_capacity,
    )
    provider = provider_factory(config.chain, policy)
    collection_capacity = asyncio.Semaphore(
        config.api_limits.maximum_concurrent_registration_collections
    )

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        try:
            await provider.start()
            yield
        finally:
            await provider.aclose()

    async def collect_registration():
        acquired = False
        try:
            try:
                await asyncio.wait_for(
                    collection_capacity.acquire(),
                    timeout=config.api_limits.capacity_wait_seconds,
                )
                acquired = True
            except asyncio.TimeoutError as error:
                raise ValueError("registration collection capacity reached") from error
            return await provider.collect()
        finally:
            if acquired:
                collection_capacity.release()

    async def current_snapshot() -> RegistrationSnapshot:
        snapshot = (await collect_registration()).snapshot
        snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(snapshot))
        if not policy.valid_from_block <= snapshot.block <= policy.valid_through_block:
            raise ValueError("intake policy is not current")
        return snapshot

    app = create_app(
        store,
        current_snapshot,
        lifespan=lifespan,
        registration_source="verifier_attested_finality",
        limits=config.api_limits,
    )
    app.state.finality_providers = (provider,)

    @app.get("/v1/competition/readiness")
    async def readiness():
        try:
            admission = await asyncio.to_thread(store.admission_capacity_status)
            if not admission["accepting_new"]:
                raise ValueError("admission capacity is exhausted")
            capture = await asyncio.wait_for(collect_registration(), timeout=20)
            snapshot = RegistrationSnapshot.model_validate_json(
                canonical_json_bytes(capture.snapshot)
            )
            if not policy.valid_from_block <= snapshot.block <= policy.valid_through_block:
                raise ValueError("intake policy is not current")
            provenance = {k: v for k, v in capture.provenance.items() if k in _PROVENANCE_FIELDS}
            if (
                set(provenance) != _PROVENANCE_FIELDS
                or provenance.get("schema") != "umi-competition-registration-provenance/1"
                or provenance.get("snapshot_sha256") != digest(snapshot)
                or provenance.get("block") != snapshot.block
                or provenance.get("block_hash") != snapshot.block_hash
                or provenance.get("evidence_class") != "verifier_attested_finality"
                or provenance.get("offline_finality_proof") is not False
                or provenance.get("chain_submission_authorized") is not False
                or len(canonical_json_bytes(provenance)) > 16 * 1024
            ):
                raise ValueError("registration provenance mismatch")
        except Exception as error:
            # Provider errors can include filesystem/RPC details; keep them private.
            raise HTTPException(503, "verified registration unavailable; retry later") from error
        return {
            "schema": "umi-competition-readiness/1",
            "mode": "intake_no_weight",
            "ready_for": "signed_submission_rehearsal",
            "policy_sha256": digest(policy),
            "registration_count": len(snapshot.registrations),
            "registration_source": provenance,
            "evaluation_ready": False,
            "rewards_active": False,
            "chain_submission_authorized": False,
        }

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
        limit_concurrency=config.api_limits.maximum_http_connections,
        backlog=config.api_limits.socket_backlog,
    )
