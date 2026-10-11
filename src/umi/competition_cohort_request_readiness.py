"""Measure the configured request service before crediting available time."""

import asyncio
import secrets
from contextlib import asynccontextmanager
from functools import partial
from typing import Annotated, Literal

import httpx
from pydantic import Field

from .competition_client import validate_intake_origin
from .competition_cohort_request_preparation import prepared_request_thread
from .competition_execution import ExecutionBoundary, execution_boundary
from .host_memory_runtime import authorize_memory, memory_operation_context, run_memory_thread
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

    async def _fetch_readiness(self, state):
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
            return nonce, result
        except (httpx.HTTPError, OSError, ValueError, asyncio.TimeoutError):
            return nonce, None

    def _ready_at(self, state, capture, nonce, result):
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

    async def _ready(self, state, capture):
        return self._ready_at(state, capture, *await self._fetch_readiness(state))

    @asynccontextmanager
    async def prepare(self, state):
        authorize_memory("requests_observe", state.cohort_sha256, state.phase, lane="transient")
        if await run_memory_thread(
            self.source.has_fence_hint,
            state,
            operation="requests_seal_fenced",
            cohort=state.cohort_sha256,
            phase=state.phase,
        ):
            # Preserve the retained-fence path: one coordinator capture, then
            # full native fence authentication/sealing before network probes.
            # The presence hint never authorizes a cutoff or a phase advance.
            active, used = True, False

            async def sample(capture):
                nonlocal used
                if not active or used:
                    raise RuntimeError("prepared request observation is no longer available")
                used = True
                return await self(state, capture)

            try:
                yield sample
            finally:
                active = False
            return
        readiness = await self._fetch_readiness(state)
        options = {}
        opening_failure = None
        if self.opening_clock is not None:
            try:
                options["opened"] = await self.opening_clock(state)
            except Exception as error:
                # A retained fence can finish without a new opening proof.
                # Keep this error local to the attempt and select no new cutoff.
                opening_failure = error
        async with (
            memory_operation_context(
                operation="requests_observe", cohort=state.cohort_sha256, phase=state.phase
            ),
            prepared_request_thread(self.source.prepare(state)) as native,
        ):

            async def sample(capture):
                if opening_failure is not None:
                    await native(capture, serving=False, seal_only=True)
                    raise opening_failure
                serving = self._ready_at(state, capture, *readiness)
                return await native(capture, serving=serving, **options)

            yield sample

    async def __call__(self, state, capture):
        # An existing admission fence is already authoritative. Finish its
        # native queue seal on the unchanged coordinator capture before network
        # readiness or original-clock retrieval can delay that observation.
        await run_memory_thread(
            self.source.seal_fenced,
            state,
            capture,
            operation="requests_seal_fenced",
            cohort=state.cohort_sha256,
            phase=state.phase,
        )
        serving = await self._ready(state, capture)
        options = {}
        if self.opening_clock is not None:
            options["opened"] = await self.opening_clock(state)
        return await run_memory_thread(
            partial(self.source.observe, state, capture, serving=serving, **options),
            operation="requests_observe",
            cohort=state.cohort_sha256,
            phase=state.phase,
        )

    async def sample_service(self, state, capture):
        serving = await self._ready(state, capture)
        return await run_memory_thread(
            partial(self.source.sample_service, state, capture, serving=serving),
            operation="requests_sample",
            cohort=state.cohort_sha256,
            phase=state.phase,
        )
