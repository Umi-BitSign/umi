"""Live intake readiness for service sampling, without certification authority.

The configured HTTPS origin is an operational trust boundary. A fresh response
reports the serving process's current intake state; it is neither a portable
finality proof nor evidence that an entire interval was available. The native
phase observer retains the resulting sample and compensates unknown intervals.
Independent progress review and quorum certification remain separate.
"""

from __future__ import annotations

import asyncio
import secrets
from functools import partial
from typing import Annotated, Literal

import httpx
from pydantic import Field, model_validator

from .competition_chain import RegistrationCapture
from .competition_client import validate_intake_origin
from .competition_cohort_availability import CohortAvailabilityObservation
from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_intake import CohortIntake, cohort_intake_bytes, history_tip
from .competition_cohort_intake_phase import CohortIntakePhaseObserver, NativeIntakeProgress
from .competition_cohort_recovery import CohortRecoveryState
from .competition_execution import ExecutionBoundary, execution_boundary
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel

Nonce = Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]


class CohortIntakeReadiness(StrictProtocolModel):
    schema_: Literal["umi-cohort-intake-readiness/1"] = Field(alias="schema")
    nonce: Nonce
    policy_sha256: Hex32
    cohort_sha256: Hex32
    authority_sha256: Hex32
    recovery_tip_sha256: Hex32
    observation: ExecutionBoundary
    reason_code: Literal[
        "accepting",
        "before_start",
        "phase_closed",
        "fenced",
        "capacity_exhausted",
        "archive_unavailable",
    ]
    ready: bool
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def readiness(self):
        if self.ready != (self.reason_code == "accepting"):
            raise ValueError("intake readiness reason and flag differ")
        return self


def intake_readiness(
    intake: CohortIntake,
    cohort: str,
    capture: RegistrationCapture,
    *,
    nonce: str,
    archive_available: bool,
) -> CohortIntakeReadiness:
    """Inspect the native admission state under its publication/admission lock."""
    intake._allowed(cohort)
    observation = execution_boundary(capture)
    if type(archive_available) is not bool:
        raise ValueError("archive availability must be a boolean")
    with intake._connection() as (db, store):
        history = store.published_history(cohort)
        state, _, _ = replay_cohort_decisions(
            history,
            intake.policy,
            lambda key: store.source(cohort, key, CohortDecisionInput),
        )
        if observation.block < state.observed_at_block:
            raise ValueError("intake finality predates its published history")
        if state.phase != "intake":
            reason = "phase_closed"
        elif observation.block < state.not_before_block:
            reason = "before_start"
        elif intake._seal(db, history, history_tip(history)) is not None:
            reason = "fenced"
        elif (
            db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone()[0]
            >= intake.capacity.maximum_records
            or cohort_intake_bytes(db) >= intake.capacity.maximum_bytes
        ):
            reason = "capacity_exhausted"
        elif not archive_available:
            reason = "archive_unavailable"
        else:
            reason = "accepting"
        return CohortIntakeReadiness(
            schema="umi-cohort-intake-readiness/1",
            nonce=nonce,
            policy_sha256=digest(intake.policy),
            cohort_sha256=cohort,
            authority_sha256=state.authority_sha256,
            recovery_tip_sha256=state.tip_sha256,
            observation=observation,
            reason_code=reason,
            ready=reason == "accepting",
        )


class LiveIntakePhaseObserver:
    """Probe the serving API before giving the native observer a service sample.

    The enclosing service owns finality, process exclusion and this observer's
    lifetime. Returned progress is unsigned and must undergo independent review.
    Transient transport or response failures count as unavailable service; a
    changed native history still requires retrying the current generation.
    """

    def __init__(
        self,
        phase: CohortIntakePhaseObserver,
        origin: str,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        timeout_seconds: float = 2400,
    ):
        self.phase, self.origin = phase, validate_intake_origin(origin)
        if type(timeout_seconds) not in (int, float) or not 0 < timeout_seconds <= 3600:
            raise ValueError("readiness request timeout must be positive and at most one hour")
        self.transport, self.timeout = transport, timeout_seconds

    async def _ready(self, state: CohortRecoveryState, capture: RegistrationCapture) -> bool:
        nonce = secrets.token_hex(16)
        path = f"/v1/competition/cohorts/{state.cohort_sha256}/readiness"

        async def fetch():
            async with (
                httpx.AsyncClient(
                    transport=self.transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=httpx.Timeout(self.timeout, connect=min(5, self.timeout)),
                ) as client,
                client.stream(
                    "GET",
                    self.origin + path,
                    params={"nonce": nonce},
                    headers={"Accept-Encoding": "identity", "Cache-Control": "no-cache"},
                ) as response,
            ):
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
                return CohortIntakeReadiness.model_validate_json(bytes(data))

        try:
            result = await asyncio.wait_for(fetch(), timeout=self.timeout)
            if result is None:
                return False
            local = execution_boundary(capture)
            return (
                result.ready
                and result.nonce == nonce
                and result.policy_sha256 == digest(self.phase.intake.policy)
                and result.cohort_sha256 == state.cohort_sha256
                and result.authority_sha256 == state.authority_sha256
                and result.recovery_tip_sha256 == state.tip_sha256
                and abs(result.observation.block - local.block) <= self.phase.gap
                and (
                    result.observation.block != local.block
                    or (result.observation.block_hash, result.observation.state_root)
                    == (local.block_hash, local.state_root)
                )
            )
        except (httpx.HTTPError, OSError, ValueError, asyncio.TimeoutError):
            return False

    async def __call__(
        self, state: CohortRecoveryState, capture: RegistrationCapture
    ) -> NativeIntakeProgress:
        if state.phase != "intake":
            raise ValueError("live intake observer cannot observe another phase")
        serving = await self._ready(state, capture)
        return await run_owned_thread(
            partial(
                self.phase.observe,
                state.cohort_sha256,
                capture,
                serving=serving,
                expected_tip_sha256=state.tip_sha256,
            )
        )

    async def sample_service(
        self, state: CohortRecoveryState, capture: RegistrationCapture
    ) -> CohortAvailabilityObservation | None:
        serving = await self._ready(state, capture)
        return await run_owned_thread(
            partial(self.phase.sample_service, state, capture, serving=serving)
        )
