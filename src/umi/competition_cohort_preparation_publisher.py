"""Publish prepared rounds from the admission service's owned stores."""

from __future__ import annotations

import logging
import sqlite3
from functools import partial
from pathlib import Path
from typing import Annotated

from pydantic import Field

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_execution import execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .concurrency import run_owned_thread
from .open_competition import digest
from .private_files import Directory, publish_private_model
from .protocol import StrictProtocolModel

logger = logging.getLogger(__name__)


class CohortPreparationPublicationConfig(StrictProtocolModel):
    promotion_directory: Directory
    output_directory: Directory
    maximum_bytes: Annotated[int, Field(ge=1, le=256 * 1024**2)] = 64 * 1024**2
    maximum_promotion_bytes: Annotated[int, Field(ge=1, le=16 * 1024**2)] = 16 * 1024**2


class CohortPreparationPublisher:
    def __init__(
        self,
        owner: CohortPreparation,
        provider: HistoricalRegistrationProvider,
        output: Path,
    ):
        if owner.queue.policy != provider.policy:
            raise ValueError("preparation publisher finality uses another policy")
        self.owner, self.provider, self.output = owner, provider, output

    async def poll_once(self) -> dict:
        self.provider.ensure_observer_running()
        published = pending = revoked = 0
        for cohort in self.owner.queue.intake.bindings:
            try:
                history = await run_owned_thread(self.owner.queue.intake.history, cohort)
                capture = await self.provider.collect()
                tip = history_tip(history)
                view = verify_cohort_history(
                    history,
                    self.owner.queue.policy,
                    expected_tip_sha256=tip,
                    current_block=execution_boundary(capture).block,
                )
                if view.state.phase == "intake":
                    continue
                if view.state.phase == "revoked":
                    revoked += 1
                    continue
                await self._publish(cohort, capture, tip)
                published += 1
            except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                pending += 1
                logger.info(
                    "cohort_preparation_pending cohort=%s error_type=%s",
                    cohort,
                    type(error).__name__,
                )
        return {
            "status": "preparation_retry" if pending else "preparation_current",
            "rounds_published": published,
            "retry_count": pending,
            "revoked_cohorts": revoked,
            "chain_submission_authorized": False,
        }

    async def publish_history(self, history) -> None:
        """Lifecycle handoff: publish the exact retained prepared round."""
        cohort = digest(history.plan)
        self.provider.ensure_observer_running()
        current = await run_owned_thread(self.owner.queue.intake.history, cohort)
        if current != history:
            raise OSError("preparation publication history changed")
        current_block = await self.provider.current_finalized_block()
        view = verify_cohort_history(
            history,
            self.owner.queue.policy,
            expected_tip_sha256=history_tip(history),
            current_block=current_block,
        )
        if view.state.phase in {"intake", "revoked"}:
            raise ValueError("preparation publication requires active prepared authority")
        prepared = await run_owned_thread(
            partial(
                self.owner.retained,
                cohort,
                expected_tip_sha256=history_tip(history),
                current_block=current_block,
            )
        )
        await self._publish_prepared(cohort, prepared)

    async def _publish(self, cohort, capture, tip):
        prepared = await run_owned_thread(
            partial(self.owner.prepare, cohort, capture, expected_tip_sha256=tip)
        )
        await self._publish_prepared(cohort, prepared)

    async def _publish_prepared(self, cohort, prepared):
        await run_owned_thread(
            partial(
                publish_private_model,
                self.output / (cohort + ".json"),
                prepared,
                maximum_bytes=self.owner.maximum_bytes,
            )
        )
