"""Measure the configured request service before crediting available time."""

import asyncio
import secrets
from functools import partial
from typing import Annotated, Literal

import httpx
from pydantic import Field

from .competition_client import validate_intake_origin
from .competition_execution import ExecutionBoundary, execution_boundary
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel


class RequestReadiness(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-readiness/1"] = Field(alias="schema")
    nonce: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    policy_sha256: Hex32
    cohort_sha256: Hex32
    recovery_tip_sha256: Hex32
    catalog_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=64)]
    observation: ExecutionBoundary
    ready: bool
    chain_submission_authorized: Literal[False] = False


class LiveRequestPhaseObserver:
    def __init__(
        self,
        source,
        origin: str,
        *,
        client: httpx.AsyncClient,
        timeout_seconds=2400,
        opening_clock=None,
    ):
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 3600:
            raise ValueError("request readiness timeout must be bounded")
        self.source, self.origin = source, validate_intake_origin(origin)
        self.client, self.timeout = client, timeout_seconds
        self.opening_clock = opening_clock

    async def _ready(self, state, capture):
        nonce = secrets.token_hex(16)

        async def fetch():
            async with self.client.stream(
                "GET",
                self.origin + f"/v1/competition/cohorts/{state.cohort_sha256}/requests/readiness",
                params={"nonce": nonce},
                headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"},
                timeout=httpx.Timeout(self.timeout, connect=min(5, self.timeout)),
                follow_redirects=False,
            ) as response:
                if (
                    response.status_code != 200
                    or response.headers.get("content-encoding", "identity") != "identity"
                    or response.headers.get("content-type", "").split(";", 1)[0].strip()
                    != "application/json"
                ):
                    return None
                data = bytearray()
                async for part in response.aiter_bytes():
                    if len(data) + len(part) > 16 * 1024:
                        return None
                    data.extend(part)
                return RequestReadiness.model_validate_json(bytes(data))

        try:
            result = await asyncio.wait_for(fetch(), timeout=self.timeout)
            local = execution_boundary(capture)
            return result is not None and (
                result.ready
                and result.nonce == nonce
                and result.policy_sha256 == digest(self.source.intake.policy)
                and result.cohort_sha256 == state.cohort_sha256
                and result.recovery_tip_sha256 == state.tip_sha256
                and result.catalog_sha256s == tuple(digest(c.catalog) for c in self.source.catalogs)
                and abs(result.observation.block - local.block) <= self.source.gap
                and (
                    result.observation.block != local.block
                    or (result.observation.block_hash, result.observation.state_root)
                    == (local.block_hash, local.state_root)
                )
            )
        except (httpx.HTTPError, OSError, ValueError, asyncio.TimeoutError):
            return False

    async def __call__(self, state, capture):
        serving = await self._ready(state, capture)
        options = {}
        if self.opening_clock is not None:
            options["opened"] = await self.opening_clock(state)
        return await run_owned_thread(
            partial(self.source.observe, state, capture, serving=serving, **options)
        )

    async def sample_service(self, state, capture):
        serving = await self._ready(state, capture)
        return await run_owned_thread(
            partial(self.source.sample_service, state, capture, serving=serving)
        )
