"""Publish prepared rounds from the admission service's owned stores."""

from __future__ import annotations

import logging
import sqlite3
from functools import partial
from pathlib import Path
from typing import Annotated

from pydantic import Field, model_serializer

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_preparation_owner import CohortPreparation
from .competition_cohort_preparation_publication import PreparedRoundFiles
from .competition_cohort_settlement_delivery import SettlementEvidenceFiles
from .competition_execution import execution_boundary
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_work_progress import await_progress
from .concurrency import run_owned_thread
from .host_memory_runtime import authorize_memory, memory_operation, requests_stage_policy
from .open_competition import digest
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class CohortPreparationPublicationConfig(StrictProtocolModel):
    promotion_directory: Directory
    output_directory: Directory
    objects_directory: Directory | None = None
    maximum_bytes: Annotated[int, Field(ge=1, le=256 * 1024**2)] = 64 * 1024**2
    maximum_promotion_bytes: Annotated[int, Field(ge=1, le=16 * 1024**2)] = 16 * 1024**2

    @model_serializer(mode="wrap")
    def preserve_legacy_config(self, handler):
        value = handler(self)
        if self.objects_directory is None:
            value.pop("objects_directory", None)
        return value


class CohortPreparationPublisher:
    def __init__(
        self,
        owner: CohortPreparation,
        provider: HistoricalRegistrationProvider,
        output: Path,
        *,
        objects: SettlementEvidenceFiles | None = None,
    ):
        if owner.queue.policy != provider.policy:
            raise ValueError("preparation publisher finality uses another policy")
        self.owner, self.provider, self.output = owner, provider, output
        self.objects = objects
        self.files = PreparedRoundFiles(output, maximum_bytes=owner.maximum_bytes)

    async def poll_once(self) -> dict:
        authorize_memory(None, None, None)
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

    @memory_operation(
        operation="preparation_republish",
        requests_stage_only=True,
        scope=lambda self, history: (digest(history.plan), "preparation"),
    )
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
                self.owner.retained_publication,
                cohort,
                expected_tip_sha256=history_tip(history),
                current_block=current_block,
            )
        )
        stage = requests_stage_policy()
        if stage is not None and prepared.round_sha256 != stage.preparation_result_sha256:
            raise ValueError("retained preparation differs from qualified requests stage")
        await self._publish_prepared(cohort, prepared)

    async def _publish(self, cohort, capture, tip):
        authorize_memory(None, cohort, "preparation")
        prepared = await run_owned_thread(
            partial(self.owner.prepare_publication, cohort, capture, expected_tip_sha256=tip)
        )
        stage = requests_stage_policy()
        if stage is not None and prepared.round_sha256 != stage.preparation_result_sha256:
            raise ValueError("retained preparation differs from qualified requests stage")
        await self._publish_prepared(cohort, prepared)

    async def _publish_prepared(self, cohort, prepared):
        if self.objects is not None:
            await await_progress(
                run_owned_thread(self._publish_incumbent, prepared),
                stage="preparation_incumbent_declaration",
                cohort=cohort,
            )
        await run_owned_thread(
            partial(
                self.files.publish, cohort, prepared,
            )
        )

    def _publish_incumbent(self, prepared):
        """Restore only missing metadata from the retained certified baseline.

        The native prepared round selects the immutable identity. Existing
        objects already authenticate that identity; their payloads and baseline
        certificate need no repeated verification. Damaged objects remain errors.
        """
        model = prepared.incumbent_model_sha256
        try:
            self.objects(model)
            return
        except FileNotFoundError:
            pass
        review = self.owner.promotion.certified_cohort_baseline_reference(
            prepared.cohort_sha256,
            prepared.sequence,
            model,
            maximum_bytes=self.owner.maximum_promotion_bytes,
        )
        if review is None:
            # Older baselines use their configured setup inputs. This additive
            # handoff must not create a new preparation gate for those layouts;
            # benchmark construction still requires the original declaration.
            return
        self.objects.publish(model, lambda key: canonical_json_bytes(review.model))
