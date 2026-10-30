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
    cohort_evaluation_suite,
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
_REVIEWED_HEAD_AGE_MS = (120_000, 300_000)
Timestamp = Annotated[int, Field(ge=1, le=2**53 - 1)]


def _compatible_head_ages(value: int) -> tuple[int, ...]:
    return _REVIEWED_HEAD_AGE_MS if value in _REVIEWED_HEAD_AGE_MS else (value,)


class CohortCutoverObservation(StrictProtocolModel):
    schema_: Literal["umi-cohort-cutover-observation/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    cutover_unix_ms: Timestamp
    observed: ExecutionBoundary | None = None
    source_sha256: Hex32 | None = None


class OperatorRequestStart(StrictProtocolModel):
    """Explicit local start decision; never backdates cutover or phase evidence."""

    schema_: Literal[
        "umi-cohort-operator-request-start/1", "umi-cohort-operator-request-start/2"
    ] = Field(alias="schema")
    cohort_sha256: Hex32
    authorized_history_tip_sha256: Hex32
    suite_sha256: Hex32
    baseline_model_sha256: Hex32
    evaluation_runtime_sha256: Hex32
    runtime_adoption_sha256: Hex32 | None
    cpu_efficiency_adoption_sha256: Hex32 | None = None
    not_before_unix_ms: Timestamp
    source_sha256: Hex32

    @model_serializer(mode="wrap")
    def preserve_original_start(self, handler):
        value = handler(self)
        if value.get("cpu_efficiency_adoption_sha256") is None:
            value.pop("cpu_efficiency_adoption_sha256", None)
        return value

    @model_validator(mode="after")
    def versioned_efficiency_selection(self):
        if (self.schema_ == "umi-cohort-operator-request-start/2") != (
            self.cpu_efficiency_adoption_sha256 is not None
        ):
            raise ValueError("CPU efficiency request start requires its versioned binding")
        return self


class RequestStartConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-start-config/1", "umi-cohort-request-start-config/2"] = (
        Field(alias="schema")
    )
    directory: Directory
    first_cohort_not_before_unix_ms: Timestamp
    predecessor_plan: RecoverableCohortPlan | None = None
    predecessor_recovery: SignedCohortRecoveryAuthority | None = None
    rest_clock: Literal["predecessor_certification", "cohort_cutover"] = "predecessor_certification"
    cutover_overrides: Annotated[tuple[CohortCutoverObservation, ...], Field(max_length=512)] = ()
    operator_start_overrides: Annotated[
        tuple[OperatorRequestStart, ...], Field(max_length=512)
    ] = ()

    @model_serializer(mode="wrap")
    def preserve_initial_series_bytes(self, handler):
        value = handler(self)
        if self.predecessor_plan is None:
            value.pop("predecessor_plan", None)
        if self.predecessor_recovery is None:
            value.pop("predecessor_recovery", None)
        if self.rest_clock == "predecessor_certification":
            value.pop("rest_clock", None)
        if not self.cutover_overrides:
            value.pop("cutover_overrides", None)
        if not self.operator_start_overrides:
            value.pop("operator_start_overrides", None)
        return value

    @model_validator(mode="after")
    def successor_inputs(self):
        successor = self.schema_ == "umi-cohort-request-start-config/2"
        if successor != (self.predecessor_plan is not None) or successor != (
            self.predecessor_recovery is not None
        ):
            raise ValueError("successor request start requires its complete predecessor inputs")
        keys = [v.cohort_sha256 for v in self.cutover_overrides]
        if keys != sorted(set(keys)) or (keys and self.rest_clock != "cohort_cutover"):
            raise ValueError(
                "cutover overrides need the selected cutover clock and unique ordering"
            )
        if any(v.source_sha256 is None for v in self.cutover_overrides):
            raise ValueError("an explicit historical cutover needs its retained source identity")
        keys = [v.cohort_sha256 for v in self.operator_start_overrides]
        if keys != sorted(set(keys)):
            raise ValueError("operator start overrides require unique cohort ordering")
        return self


class RequestRestObservation(StrictProtocolModel):
    schema_: Literal["umi-cohort-request-rest-observation/1"] = Field(alias="schema")
    predecessor_closure_sha256: Hex32
    observed: ExecutionBoundary
    chain_timestamp_ms: Timestamp
    not_before_unix_ms: Timestamp


class OperatorRequestStartObservation(StrictProtocolModel):
    schema_: Literal["umi-cohort-operator-request-start-observation/1"] = Field(alias="schema")
    selection: OperatorRequestStart
    observed: ExecutionBoundary
    chain_timestamp_ms: Timestamp


class SeriesRequestStart:
    def __init__(
        self,
        config: RequestStartConfig,
        series: StandingRewardSeries,
        provider: HistoricalRegistrationProvider,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        *,
        operator_selection=None,
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
        self.operator_selection = operator_selection
        self.cohorts = tuple(digest(p) for p in series.cohorts)
        self.head_age = provider.config.maximum_head_age_ms
        self.future_skew = provider.config.maximum_future_skew_ms
        binding = {
            "schema": "umi-cohort-request-start-owner/1",
            "series": digest(series),
            "first_cohort_not_before_unix_ms": config.first_cohort_not_before_unix_ms,
            "minimum_rest_ms": REST_MS,
            "maximum_head_age_ms": self.head_age,
            "maximum_future_skew_ms": self.future_skew,
        }
        compatible = tuple(
            dict(binding, maximum_head_age_ms=value)
            for value in _compatible_head_ages(self.head_age)
            if value != self.head_age
        )
        self.journal = RoundJournal(
            Path(config.directory),
            binding,
            maximum_rounds=len(self.cohorts),
            compatible_bindings=compatible,
        )
        if any(v.cohort_sha256 not in self.cohorts for v in self.config.cutover_overrides):
            raise ValueError("configured cutover is outside the selected series")
        if any(v.cohort_sha256 not in self.cohorts for v in self.config.operator_start_overrides):
            raise ValueError("operator request start is outside the selected series")
        self.cutover_journal = (
            RoundJournal(
                Path(config.directory) / "cutovers-v1",
                {
                    "schema": "umi-cohort-cutover-clock-owner/1",
                    "series": digest(series),
                    "minimum_rest_ms": REST_MS,
                },
                maximum_rounds=len(self.cohorts),
            )
            if self.config.rest_clock == "cohort_cutover"
            else None
        )
        self.serial = asyncio.Lock()

    async def observe_cutover(self, cohort: str):
        """Record release during intake, before artifact/roster work can delay it."""
        if self.cutover_journal is None:
            return
        async with self.serial:
            return await self._observe_cutover(cohort)

    async def _observe_cutover(self, cohort):
        if cohort not in self.cohorts or self.cutover_journal is None:
            raise ValueError("cutover observation is outside the selected series/rule")
        configured = next(
            (v for v in self.config.cutover_overrides if v.cohort_sha256 == cohort), None
        )
        old = await run_owned_thread(self.cutover_journal.get, "cutover", cohort)
        if old is not None:
            saved = CohortCutoverObservation.model_validate(old)
            if configured is not None and saved != configured:
                raise ValueError("configured cutover conflicts with its retained observation")
            return saved
        if configured is None:
            capture = await self.provider.collect()
            timestamp = capture.provenance.get("timestamp_ms")
            configured = CohortCutoverObservation(
                schema="umi-cohort-cutover-observation/1",
                cohort_sha256=cohort,
                cutover_unix_ms=timestamp,
                observed=execution_boundary(capture),
            )
        await run_owned_thread(self.cutover_journal.put, "cutover", cohort, configured)
        return configured

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

    async def _operator_start(self, selected, observed, timestamp):
        source = await self.history(selected.cohort_sha256)
        history = source.history
        plan = next(p for p in self.series.cohorts if digest(p) == selected.cohort_sha256)
        if history.plan != plan or history.authority != self.series.recovery:
            raise ValueError("operator request start differs from its selected series")
        state, _, _ = replay_cohort_decisions(
            history, self.provider.policy, source.inputs().__getitem__
        )
        tips = (digest(history.genesis), *(digest(s.transition) for s in history.transitions))
        if (
            selected.authorized_history_tip_sha256 not in tips
            or state.phase in {"complete", "revoked"}
            or cohort_evaluation_suite(plan, state.evaluation_suite_adoption)
            != selected.suite_sha256
        ):
            raise ValueError("operator request start history or suite binding changed")
        index = tips.index(selected.authorized_history_tip_sha256)
        if any(s.transition.operation != "close_phase" for s in history.transitions[index:]):
            raise ValueError("operator request start selection changed after authorization")
        if self.operator_selection is None:
            raise ValueError("operator request start requires its native selection reader")
        actual = await self.operator_selection(selected.cohort_sha256, observed.block)
        expected = {
            key: getattr(selected, key)
            for key in (
                "baseline_model_sha256",
                "evaluation_runtime_sha256",
                "runtime_adoption_sha256",
            )
        }
        if selected.cpu_efficiency_adoption_sha256 is not None:
            expected["cpu_efficiency_adoption_sha256"] = selected.cpu_efficiency_adoption_sha256
        if actual != expected:
            raise ValueError("operator request start baseline or runtime selection changed")
        old = await run_owned_thread(
            self.journal.get, "operator_request_start", selected.cohort_sha256
        )
        if old is None:
            saved = OperatorRequestStartObservation(
                schema="umi-cohort-operator-request-start-observation/1",
                selection=selected,
                observed=observed,
                chain_timestamp_ms=timestamp,
            )
            await run_owned_thread(
                self.journal.put, "operator_request_start", selected.cohort_sha256, saved
            )
        else:
            saved = OperatorRequestStartObservation.model_validate(old)
        if (
            saved.selection != selected
            or observed.block < saved.observed.block
            or timestamp < saved.chain_timestamp_ms
            or (observed.block == saved.observed.block and observed != saved.observed)
        ):
            raise ValueError("operator request start changed or its observation regressed")
        return saved

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
        cutover = None
        operator = next(
            (v for v in self.config.operator_start_overrides if v.cohort_sha256 == cohort), None
        )
        operator_observation = None
        if operator is not None:
            operator_observation = await self._operator_start(operator, observed, timestamp)
            floor = max(floor, operator.not_before_unix_ms)
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
            if operator is not None:
                # Preserve all existing rest/cutover receipts. This is an
                # explicit future start floor, not a fictitious earlier cutover.
                pass
            elif self.cutover_journal is not None:
                saved_cutover = await run_owned_thread(self.cutover_journal.get, "cutover", cohort)
                if saved_cutover is None and not any(
                    v.cohort_sha256 == cohort for v in self.config.cutover_overrides
                ):
                    return dict(report, status="waiting_cutover_observation")
                cutover = await self._observe_cutover(cohort)
                if cutover.cutover_unix_ms > timestamp + self.future_skew:
                    raise ValueError("cohort cutover is ahead of verified chain time")
                floor = max(floor, cutover.cutover_unix_ms + self.head_age + REST_MS)
            else:
                floor = max(
                    floor, await self._legacy_rest_floor(cohort, closure, observed, timestamp)
                )
        ready = timestamp - self.future_skew >= floor
        remaining = max(0, (floor + self.future_skew - timestamp) / 1000)
        total = (
            max(0, (floor + self.future_skew - operator_observation.chain_timestamp_ms) / 1000)
            if operator_observation is not None
            else (REST_MS + self.head_age + self.future_skew) / 1000
            if closure
            else remaining
        )
        completed = max(0, total - remaining)
        return dict(
            report,
            status="request_start_ready" if ready else "waiting_request_rest",
            ready=ready,
            not_before_unix_ms=floor,
            observed_at_block=observed.block,
            chain_timestamp_ms=timestamp,
            rest_clock=self.config.rest_clock,
            cutover_unix_ms=None if cutover is None else cutover.cutover_unix_ms,
            **(
                {
                    "operator_start_source_sha256": operator.source_sha256,
                    "operator_start_not_before_unix_ms": operator.not_before_unix_ms,
                }
                if operator is not None
                else {}
            ),
            stage="request_start_ready" if ready else "waiting_request_rest",
            completed=completed,
            total=total,
            unit="seconds",
            percent=100 * completed / total if total else 100,
            elapsed_seconds=completed,
            eta_seconds=remaining,
            eta_basis="verified_chain_time_until_request_start_floor",
            eta_scope="request_rest_wait_only; preparation, evaluation and activation separate",
            eta_assumptions="verified chain time continues advancing; no additional owner retry",
            stalled_or_retrying=False,
        )

    async def _legacy_rest_floor(self, cohort, closure, observed, timestamp):
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
            or saved.not_before_unix_ms
            not in {
                saved.chain_timestamp_ms + age + REST_MS
                for age in _compatible_head_ages(self.head_age)
            }
            or observed.block < saved.observed.block
            or timestamp < saved.chain_timestamp_ms
            or (observed.block == saved.observed.block and observed != saved.observed)
        ):
            raise ValueError("request rest changed or its observation regressed")
        return saved.not_before_unix_ms
