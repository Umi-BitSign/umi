"""Run native intake, preparation and requests through the durable controller.

The host supplies phase factories, owner publication, finality and process locks.
Factories construct configured native workers; publications never select code,
signers or runtime settings. Settlement takes over after request handoff.
"""

from __future__ import annotations

import asyncio
import logging
import sqlite3
from collections.abc import Awaitable, Callable, Mapping
from contextlib import suppress
from dataclasses import dataclass

from .competition_chain import RegistrationCapture
from .competition_cohort_availability import CohortAvailabilityObservation
from .competition_cohort_coordinator import (
    CohortDecisionInput,
    CohortRecoveryCoordinator,
    HistoryPublisher,
    RecoveryFinality,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_progress_signer import CertifiedPhaseObserver
from .competition_cohort_recovery import CohortRecoveryState, Phase, StandingCohortRecoveryAuthority
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_cohort_request_start import SeriesRequestStart
from .competition_execution import execution_boundary
from .open_competition import CompetitionPolicy, Signature
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)
PHASES = ("intake", "preparation", "requests")
ServiceSampler = Callable[
    [CohortRecoveryState, RegistrationCapture], Awaitable[CohortAvailabilityObservation | None]
]


@dataclass(frozen=True)
class CohortPhaseDriver:
    observer: CertifiedPhaseObserver
    publish_closed: HistoryPublisher | None = None
    sample_service: ServiceSampler | None = None


class CohortLifecycleService:
    def __init__(
        self,
        store: CohortRecoveryStore,
        cohort: str,
        policy: CompetitionPolicy,
        genesis_signatures: tuple[Signature, ...],
        provider: RecoveryFinality,
        publish_history: HistoryPublisher,
        phases: Mapping[Phase, Callable[[], Awaitable[CohortPhaseDriver]]],
        *,
        request_start: SeriesRequestStart | None = None,
    ):
        if set(phases) != set(PHASES):
            raise ValueError("cohort lifecycle requires intake, preparation and request runtimes")
        self.cohort, self.policy, self.factories = cohort, policy, dict(phases)
        if request_start is not None and (
            request_start.provider is not provider or cohort not in request_start.cohorts
        ):
            raise ValueError("request start gate differs from its lifecycle owner")
        self.request_start = request_start
        self.publish_history = publish_history
        self.drivers: dict[Phase, CohortPhaseDriver] = {}
        self.last_report = None
        self.last_sampling_report = None
        self.last_progress = None
        self.expected_round_sha256 = None
        self.phase, self.stage = "intake", "starting"
        self.serial = asyncio.Lock()
        self.controller = CohortRecoveryCoordinator(
            store,
            cohort,
            policy,
            genesis_signatures,
            provider,
            None,
            self._certify,
            self._publish,
            sample_progress=self._sample,
            attest_progress=self._attest,
        )
        history, state, _, _ = self.controller._history()
        self.plan_sequence = history.plan.sequence
        self.phase = state.phase
        self.sequence = state.sequence
        self.target_block = next(
            (item.target_block for item in state.targets if item.phase == state.phase), None
        )
        for transition in reversed(history.transitions):
            if transition.transition.phase != "preparation":
                continue
            evidence = self.controller.store.source(
                self.cohort, transition.transition.evidence_sha256, CohortDecisionInput
            )
            self.expected_round_sha256 = evidence.progress.progress.phase_result_sha256
            break
        if not isinstance(history.authority.authority, StandingCohortRecoveryAuthority):
            raise ValueError("automatic cohort lifecycle requires standing authority")
        if request_start is not None and (
            history.plan != request_start.series.cohorts[request_start.cohorts.index(cohort)]
            or history.authority != request_start.series.recovery
        ):
            raise ValueError("request start authority differs from its lifecycle owner")

    def _remember_state(self, state: CohortRecoveryState) -> None:
        if (self.phase, self.sequence) != (state.phase, state.sequence):
            self.last_progress = None
        self.phase, self.sequence = state.phase, state.sequence
        self.target_block = next(
            (item.target_block for item in state.targets if item.phase == state.phase), None
        )

    def _log_lifecycle(self, status: str, *, error_type: str | None = None) -> None:
        progress = self.last_progress
        report = {
            "schema": "umi-cohort-lifecycle-observation/1",
            "cohort_sha256": self.cohort,
            "plan_sequence": self.plan_sequence,
            "phase": self.phase,
            "sequence": self.sequence,
            "target_block": self.target_block,
            "stage": self.stage,
            "status": status,
            "progress_completion": None if progress is None else progress.completion,
            "progress_observed_at_block": (
                None if progress is None else progress.observed_at_block
            ),
            "unavailable_blocks": None if progress is None else progress.unavailable_blocks,
            "expected_round_sha256": self.expected_round_sha256,
            "error_type": error_type,
        }
        logger.info("%s", canonical_json_bytes(report).decode())

    async def _driver(self, phase: Phase) -> CohortPhaseDriver:
        if phase not in PHASES:
            raise ValueError("phase belongs to the settlement runtime")
        if phase not in self.drivers:
            self.stage = "phase_start"
            driver = await self.factories[phase]()
            if not isinstance(driver, CohortPhaseDriver) or driver.observer.policy != self.policy:
                raise ValueError("cohort phase runtime has another policy")
            if phase in {"preparation", "requests"} and driver.publish_closed is None:
                raise ValueError("cohort phase runtime requires its original result publication")
            if phase in {"intake", "requests"} and driver.sample_service is None:
                raise ValueError("timed cohort phase requires independent service sampling")
            self.drivers[phase] = driver
        return self.drivers[phase]

    async def _sample(self, state, capture):
        self._remember_state(state)
        driver = await self._driver(state.phase)
        self.stage = "progress_sampling"
        progress = await driver.observer.sample(state, capture)
        if (
            progress.phase != state.phase
            or progress.cohort_sha256 != self.cohort
            or progress.recovery_tip_sha256 != state.tip_sha256
        ):
            raise ValueError("phase runtime returned progress for another cohort state")
        self.last_progress = progress
        if progress.phase == "preparation" and progress.completion == "complete":
            self.expected_round_sha256 = progress.phase_result_sha256
        self._log_lifecycle("phase_progress_sampled")
        return progress

    async def _attest(self, progress):
        driver = await self._driver(progress.phase)
        self.stage = "progress_review"
        self.last_progress = progress
        self._log_lifecycle("phase_progress_review_started")
        result = await driver.observer.attest(progress)
        self._log_lifecycle("phase_progress_review_completed")
        return result

    async def _certify(self, transition, evidence):
        if transition.phase != evidence.progress.progress.phase:
            raise ValueError("phase decision differs from its reserved progress")
        driver = await self._driver(transition.phase)
        self.stage = "decision_certification"
        self._log_lifecycle("phase_decision_review_started")
        result = await driver.observer.certify(transition, evidence)
        self._log_lifecycle("phase_decision_review_completed")
        return result

    async def _publish(self, history: CohortRecoveryHistory) -> None:
        # Publish authority first. A result publisher sees the same selected
        # history as admission and rejects revocation or a conflicting change.
        self._remember_state(self.controller.store.status(self.cohort)[0])
        self.stage = "history_publication"
        self._log_lifecycle("history_publication_started")
        await self.publish_history(history)
        if any(t.transition.operation == "revoke" for t in history.transitions):
            return
        for signed in history.transitions:
            transition = signed.transition
            phase = transition.phase
            if phase not in {"preparation", "requests"} or transition.operation != "close_phase":
                continue
            driver = await self._driver(phase)
            if driver.publish_closed is not None:
                self.stage = "result_publication"
                self._log_lifecycle("result_publication_started")
                await driver.publish_closed(history)
            # Replaying publication also repairs a missing derived file. A
            # memory-only acknowledgement must not prevent that recovery.

    async def tick(self) -> dict:
        async with self.serial:
            history, state, _, _ = self.controller._history()
            self._remember_state(state)
            if state.phase == "preparation" and self.request_start is not None:
                self.stage = "request_start"
                readiness = await self.request_start.check(self.cohort)
                if not readiness["ready"]:
                    self.last_report = dict(
                        self.controller._report(state, readiness["status"]),
                        request_start=readiness,
                    )
                    return self.last_report
            if state.phase in PHASES:
                result = await self.controller.tick()
                _, state, _, _ = self.controller._history()
                self._remember_state(state)
            else:
                await self._publish(history)
                result = self.controller._report(state, state.phase)
            if state.phase not in (*PHASES, "revoked"):
                result = self.controller._report(state, "settlement_handoff_published")
            self.last_report = result
            return result

    async def sample_service(self) -> dict:
        """Use the phase owner's epoch and journal, independently of voting.

        Factories are created only by the controller, after prior publications.
        A concurrent phase change is rejected by the native sampler. An outage
        records no guessed interval; the next native receipt accounts for it.
        """
        async with self.controller.sampling_lock:
            return await self._sample_service()

    async def _sample_service(self) -> dict:
        state, _ = self.controller.store.status(self.cohort)
        driver = self.drivers.get(state.phase)
        if state.phase not in {"intake", "requests"} or driver is None:
            return self.controller._report(state, "service_sampling_idle")
        capture = await self.controller.provider.collect()
        receipt = await driver.sample_service(state, capture)
        if receipt is None:
            return self.controller._report(state, "service_sampling_fenced")
        if not isinstance(receipt, CohortAvailabilityObservation) or (
            receipt.phase != state.phase
            or receipt.cohort_sha256 != self.cohort
            or receipt.recovery_tip_sha256 != state.tip_sha256
            or receipt.observation != execution_boundary(capture)
        ):
            raise ValueError("service sample belongs to another phase or finalized observation")
        return dict(
            self.controller._report(state, "service_sample_retained"),
            observed_at_block=receipt.observation.block,
            serving=receipt.serving,
            unavailable_blocks=receipt.unavailable_blocks,
        )

    async def run(
        self,
        stop: asyncio.Event,
        *,
        poll_seconds=5,
        sample_seconds=5,
        report=None,
        sample_report=None,
    ) -> dict:
        if type(poll_seconds) not in (int, float) or not 0 < poll_seconds <= 60:
            raise ValueError("cohort lifecycle polling requires a bounded interval")
        if type(sample_seconds) not in (int, float) or not 0 < sample_seconds <= 60:
            raise ValueError("cohort sampling requires a bounded interval")

        async def sampling():
            while not stop.is_set():
                try:
                    result = await self.sample_service()
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    result = {
                        "status": "service_sampling_retry",
                        "cohort_sha256": self.cohort,
                        "error_type": type(error).__name__,
                        "chain_submission_authorized": False,
                    }
                    logger.info(
                        "cohort_service_sampling cohort=%s error_type=%s",
                        self.cohort,
                        type(error).__name__,
                    )
                self.last_sampling_report = result
                if sample_report is not None:
                    sample_report(result)
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=sample_seconds)

        async def loop():
            while not stop.is_set():
                try:
                    result = await self.tick()
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    result = {
                        "status": "cohort_lifecycle_retry",
                        "cohort_sha256": self.cohort,
                        "error_type": type(error).__name__,
                        "phase": self.phase,
                        "stage": self.stage,
                        "chain_submission_authorized": False,
                    }
                self.last_report = result
                logger.info(
                    "cohort_lifecycle cohort=%s phase=%s stage=%s status=%s",
                    self.cohort,
                    self.phase,
                    self.stage,
                    result["status"],
                )
                self._log_lifecycle(result["status"], error_type=result.get("error_type"))
                if report is not None:
                    report(result)
                if result["status"] in {"settlement_handoff_published", "revoked"}:
                    return result
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            return {
                "status": "stopped",
                "cohort_sha256": self.cohort,
                "chain_submission_authorized": False,
            }

        task = asyncio.create_task(loop())
        samples = asyncio.create_task(sampling())
        stopping = asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait(
                (task, samples, stopping), return_when=asyncio.FIRST_COMPLETED
            )
            if samples in done:
                samples.result()  # Unexpected sampler failure must stop its owning host.
            if task in done:
                return task.result()
            return {
                "status": "stopped",
                "cohort_sha256": self.cohort,
                "chain_submission_authorized": False,
            }
        finally:
            task.cancel()
            samples.cancel()
            stopping.cancel()
            await asyncio.gather(task, samples, stopping, return_exceptions=True)
