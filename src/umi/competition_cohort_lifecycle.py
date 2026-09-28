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

from .competition_cohort_coordinator import (
    CohortRecoveryCoordinator,
    HistoryPublisher,
    RecoveryFinality,
)
from .competition_cohort_history import CohortRecoveryHistory
from .competition_cohort_progress_signer import CertifiedPhaseObserver
from .competition_cohort_recovery import Phase, StandingCohortRecoveryAuthority
from .competition_cohort_recovery_store import CohortRecoveryStore
from .open_competition import CompetitionPolicy, Signature

logger = logging.getLogger(__name__)
PHASES = ("intake", "preparation", "requests")


@dataclass(frozen=True)
class CohortPhaseDriver:
    observer: CertifiedPhaseObserver
    publish_closed: HistoryPublisher | None = None


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
    ):
        if set(phases) != set(PHASES):
            raise ValueError("cohort lifecycle requires intake, preparation and request runtimes")
        self.cohort, self.policy, self.factories = cohort, policy, dict(phases)
        self.publish_history = publish_history
        self.drivers: dict[Phase, CohortPhaseDriver] = {}
        self.last_report = None
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
        history, _, _, _ = self.controller._history()
        if not isinstance(history.authority.authority, StandingCohortRecoveryAuthority):
            raise ValueError("automatic cohort lifecycle requires standing authority")

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
            self.drivers[phase] = driver
        return self.drivers[phase]

    async def _sample(self, state, capture):
        driver = await self._driver(state.phase)
        self.stage = "progress_sampling"
        progress = await driver.observer.sample(state, capture)
        if (
            progress.phase != state.phase
            or progress.cohort_sha256 != self.cohort
            or progress.recovery_tip_sha256 != state.tip_sha256
        ):
            raise ValueError("phase runtime returned progress for another cohort state")
        return progress

    async def _attest(self, progress):
        driver = await self._driver(progress.phase)
        self.stage = "progress_review"
        return await driver.observer.attest(progress)

    async def _certify(self, transition, evidence):
        if transition.phase != evidence.progress.progress.phase:
            raise ValueError("phase decision differs from its reserved progress")
        driver = await self._driver(transition.phase)
        self.stage = "decision_certification"
        return await driver.observer.certify(transition, evidence)

    async def _publish(self, history: CohortRecoveryHistory) -> None:
        # Publish authority first. A result publisher sees the same selected
        # history as admission and rejects revocation or a conflicting change.
        self.phase = self.controller.store.status(self.cohort)[0].phase
        self.stage = "history_publication"
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
                await driver.publish_closed(history)
            # Replaying publication also repairs a missing derived file. A
            # memory-only acknowledgement must not prevent that recovery.

    async def tick(self) -> dict:
        async with self.serial:
            history, state, _, _ = self.controller._history()
            self.phase = state.phase
            if state.phase in PHASES:
                result = await self.controller.tick()
                _, state, _, _ = self.controller._history()
            else:
                await self._publish(history)
                result = self.controller._report(state, state.phase)
            if state.phase not in (*PHASES, "revoked"):
                result = self.controller._report(state, "settlement_handoff_published")
            self.last_report = result
            return result

    async def run(self, stop: asyncio.Event, *, poll_seconds=5, report=None) -> dict:
        if type(poll_seconds) not in (int, float) or not 0 < poll_seconds <= 60:
            raise ValueError("cohort lifecycle polling requires a bounded interval")

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
                if report is not None:
                    report(result)
                if result["status"] in {"settlement_handoff_published", "revoked"}:
                    return result
                with suppress(TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
            return {
                "status": "stopped",
                "cohort_sha256": self.cohort,
                "chain_submission_authorized": False,
            }

        task, stopping = asyncio.create_task(loop()), asyncio.create_task(stop.wait())
        try:
            done, _ = await asyncio.wait((task, stopping), return_when=asyncio.FIRST_COMPLETED)
            if task in done:
                return task.result()
            return {
                "status": "stopped",
                "cohort_sha256": self.cohort,
                "chain_submission_authorized": False,
            }
        finally:
            task.cancel()
            stopping.cancel()
            await asyncio.gather(task, stopping, return_exceptions=True)
