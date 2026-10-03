"""Persist the minimum rest before opening the next cohort's request phase.

Targets do not prove closure. The owner first replays the preceding certificate,
then samples fresh verified chain time. Outages preserve that first observation;
they never expire the cohort or shorten the rest. This is a launch gate, not
reward authority. The first cohort uses the deployment's approved start floor.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_coordinator import replay_cohort_decisions
from .competition_cohort_order_signer import CohortOrderHistory
from .competition_cohort_recovery import (
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    verify_recovery_authority,
)
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_reward_decisions import StandingRewardSeries
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

REST_MS = 5 * 60 * 60 * 1000
Timestamp = Annotated[int, Field(ge=1, le=2**53 - 1)]


class RequestStartConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-start-config/1", "umi-cohort-request-start-config/2"] = (
        Field(alias="schema")
    )
    directory: Directory
    first_cohort_not_before_unix_ms: Timestamp
    predecessor_plan: RecoverableCohortPlan | None = None
    predecessor_recovery: SignedCohortRecoveryAuthority | None = None

    @model_serializer(mode="wrap")
    def preserve_initial_series_bytes(self, handler):
        value = handler(self)
        if self.predecessor_plan is None:
            value.pop("predecessor_plan", None)
        if self.predecessor_recovery is None:
            value.pop("predecessor_recovery", None)
        return value

    @model_validator(mode="after")
    def successor_inputs(self):
        successor = self.schema_ == "umi-cohort-request-start-config/2"
        if successor != (self.predecessor_plan is not None) or successor != (
            self.predecessor_recovery is not None
        ):
            raise ValueError("successor request start requires its complete predecessor inputs")
        return self


class RequestRestObservation(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-rest-observation/1"] = Field(alias="schema")
    predecessor_closure_sha256: Hex32
    observed: ExecutionBoundary
    chain_timestamp_ms: Timestamp
    not_before_unix_ms: Timestamp


class SeriesRequestStart:
    def __init__(
        self,
        config: RequestStartConfig,
        series: StandingRewardSeries,
        provider: HistoricalRegistrationProvider,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
    ):
        self.config = RequestStartConfig.model_validate_json(canonical_json_bytes(config))
        self.series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
        if digest(provider.policy) != series.policy_sha256:
            raise ValueError("request start policy differs from its series")
        verify_recovery_authority(series.recovery, provider.policy)
        successor = series.predecessor is not None
        if successor != (self.config.schema_ == "umi-cohort-request-start-config/2"):
            raise ValueError("request start configuration differs from its series boundary")
        if successor:
            predecessor = series.predecessor
            plan, recovery = self.config.predecessor_plan, self.config.predecessor_recovery
            assert predecessor is not None and plan is not None and recovery is not None
            verify_recovery_authority(recovery, provider.policy)
            if (
                digest(plan) != predecessor.cohort_sha256
                or plan.sequence != predecessor.cohort_sequence
                or plan.policy_sha256 != predecessor.policy_sha256
                or digest(recovery) != predecessor.recovery_sha256
                or predecessor.cohort_sha256 not in recovery.authority.cohort_sha256s
            ):
                raise ValueError(
                    "request start predecessor differs from its signed series boundary"
                )
        self.provider, self.history = provider, history
        self.cohorts = tuple(digest(p) for p in series.cohorts)
        self.head_age = provider.config.maximum_head_age_ms
        self.future_skew = provider.config.maximum_future_skew_ms
        self.journal = RoundJournal(
            Path(config.directory),
            {
                "schema": "umi-cohort-request-start-owner/1",
                "series": digest(series),
                "first_cohort_not_before_unix_ms": config.first_cohort_not_before_unix_ms,
                "minimum_rest_ms": REST_MS,
                "maximum_head_age_ms": self.head_age,
                "maximum_future_skew_ms": self.future_skew,
            },
            maximum_rounds=len(self.cohorts),
        )
        self.serial = asyncio.Lock()

    def _closure(self, source: CohortOrderHistory, plan, authority):
        source = CohortOrderHistory.model_validate_json(canonical_json_bytes(source))
        h = source.history
        if h.plan != plan or h.authority != authority:
            raise ValueError("rest predecessor differs from the selected series")
        try:
            state, _, _ = replay_cohort_decisions(
                h, self.provider.policy, source.inputs().__getitem__
            )
        except KeyError:
            raise ValueError("rest predecessor lacks its original decision evidence") from None
        if state.phase == "revoked":
            raise ValueError("rest predecessor authority is revoked")
        return next(
            (
                s.transition
                for s in h.transitions
                if s.transition.phase == "requests" and s.transition.operation == "close_phase"
            ),
            None,
        )

    async def check(self, cohort: str) -> dict:
        async with self.serial:
            return await self._check(cohort)

    async def _check(self, cohort: str) -> dict:
        if cohort not in self.cohorts:
            raise ValueError("request start is outside its selected series")
        index = self.cohorts.index(cohort)
        report = {
            "cohort_sha256": cohort,
            "ready": False,
            "chain_submission_authorized": False,
        }
        closure = None
        predecessor_cohort = None
        predecessor_plan = None
        predecessor_recovery = None
        if index:
            predecessor_cohort = self.cohorts[index - 1]
            predecessor_plan = self.series.cohorts[index - 1]
            predecessor_recovery = self.series.recovery
        elif self.series.predecessor is not None:
            predecessor_cohort = self.series.predecessor.cohort_sha256
            predecessor_plan = self.config.predecessor_plan
            predecessor_recovery = self.config.predecessor_recovery
        if predecessor_cohort is not None:
            assert predecessor_plan is not None and predecessor_recovery is not None
            try:
                source = await self.history(predecessor_cohort)
            except FileNotFoundError:
                return dict(report, status="waiting_predecessor_requests")
            closure = await run_owned_thread(
                self._closure, source, predecessor_plan, predecessor_recovery
            )
            if closure is None:
                return dict(report, status="waiting_predecessor_requests")
        # Capture after observing certification, never from its potentially old
        # signing intent. Freshness/proof verification belongs to this provider.
        capture = await self.provider.collect()
        observed = execution_boundary(capture)
        timestamp = capture.provenance.get("timestamp_ms")
        if type(timestamp) is not int or not 0 < timestamp < 2**53:
            raise ValueError("request start needs the verified chain timestamp")
        floor = self.config.first_cohort_not_before_unix_ms
        if closure is not None:
            if observed.block < closure.observed_at_block:
                raise ValueError("request start observation precedes certified closure")
            latest = await self.history(predecessor_cohort)
            if (
                await run_owned_thread(
                    self._closure, latest, predecessor_plan, predecessor_recovery
                )
                != closure
            ):
                raise OSError("request start predecessor changed during observation")
            old = await run_owned_thread(self.journal.get, "request_rest", cohort)
            if old is None:
                # Add the admitted maximum head age so a lagging finalized head
                # cannot backdate certification. Subtract future skew below.
                saved = RequestRestObservation(
                    schema="umi-cohort-request-rest-observation/1",
                    predecessor_closure_sha256=digest(closure),
                    observed=observed,
                    chain_timestamp_ms=timestamp,
                    not_before_unix_ms=timestamp + self.head_age + REST_MS,
                )
                await run_owned_thread(self.journal.put, "request_rest", cohort, saved)
            else:
                saved = RequestRestObservation.model_validate(old)
            if (
                saved.predecessor_closure_sha256 != digest(closure)
                or saved.not_before_unix_ms != saved.chain_timestamp_ms + self.head_age + REST_MS
                or observed.block < saved.observed.block
                or timestamp < saved.chain_timestamp_ms
                or (observed.block == saved.observed.block and observed != saved.observed)
            ):
                raise ValueError("request rest changed or its observation regressed")
            floor = max(floor, saved.not_before_unix_ms)
        ready = timestamp - self.future_skew >= floor
        return dict(
            report,
            status="request_start_ready" if ready else "waiting_request_rest",
            ready=ready,
            not_before_unix_ms=floor,
            observed_at_block=observed.block,
            chain_timestamp_ms=timestamp,
        )
