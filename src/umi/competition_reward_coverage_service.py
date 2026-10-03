"""Installed coverage collection and native recovery of completion evidence.

Discovery and completion records are hints. Original control history, package,
eligibility and interval proofs establish every claim after a process restart.
No coordinator renewal, elapsed-time deadline or serialized verification flag
can finish or discard this work.
"""

from __future__ import annotations

import asyncio
import logging
import math
from contextlib import suppress
from typing import Annotated, Literal

from pydantic import Field

from .competition_evidence_codec import checked_size
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_coverage_collector import RewardCoverageCollector
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_source import CoverageHistoryPending, NativeRewardCoverageSource
from .competition_reward_decisions import RewardActivation, SignedRewardControlDecision
from .competition_reward_eligibility import RewardEligibilityRuntime
from .competition_reward_files import StandingRewardFiles
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_opportunity import VerifiedRewardOpportunity, opportunity_rule
from .competition_reward_opportunity_review import review_opportunity_certificate
from .competition_reward_preparation import StandingRewardPreparation
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)
Block = Annotated[int, Field(ge=1, le=2**53 - 1)]


class CoverageWork(StrictProtocolModel):
    schema_: Literal["umi-reward-coverage-work/1"] = Field(alias="schema")
    activation: RewardActivation
    observed_block: Block
    first_block: Block


class CoverageCompletion(StrictProtocolModel):
    schema_: Literal["umi-reward-coverage-completion/1"] = Field(alias="schema")
    certificate_sha256: Hex32


class StandingRewardCoverageService:
    def __init__(
        self,
        *,
        provider: HistoricalRewardControlProvider,
        journal: RewardCoverageJournal,
        history: RewardControlHistoryReader,
        preparation: StandingRewardPreparation,
        files: StandingRewardFiles,
        profile: RewardEligibilityRuntime,
        maximum_history_blocks: int = 64,
    ):
        checked_size(maximum_history_blocks, 4096)
        reader = preparation.reader
        if (
            journal.rule != opportunity_rule(preparation.manifest, reader.series, reader.policy)
            or journal.rule.runtime_profile_sha256 != digest(profile)
            or history.hotkey != reader.series.control_hotkey
            or history.config_sha256 != digest(provider.config)
            or digest(provider.policy) != digest(reader.policy)
        ):
            raise ValueError("coverage service differs from approved standing context")
        self.provider, self.journal, self.history = provider, journal, history
        self.preparation, self.files, self.profile = preparation, files, profile
        self.maximum_history_blocks = maximum_history_blocks
        self._target = None
        self._active = None
        self._collector = None
        self._completed: dict[str, VerifiedRewardOpportunity] = {}
        self._opportunities: dict[str, VerifiedRewardOpportunity] = {}
        self._lock = asyncio.Lock()

    async def _selection(self, height):
        try:
            prefix = await self.history.verified_prefix(height)
        except ValueError:
            progress = await self.history.advance(
                self.provider, through_block=height, maximum_blocks=self.maximum_history_blocks
            )
            if progress.history is None:
                raise CoverageHistoryPending from None
            prefix = progress.history
        control = await self.history.review_control(self.provider, height)
        if control.control_sha256 is None:
            return None
        reviewed = await run_owned_thread(
            self.preparation.reader.review_history, control, self.files.decision, prefix
        )
        return reviewed.effective_selection

    async def _discover(self):
        if self._target is None:
            control = await self.provider.collect_control(self.history.hotkey)
            self._target = control.snapshot.block_number
        if self._target < self.history.first_block:
            self._target = None
            return
        selection = await self._selection(self._target)
        if selection is not None:
            key = selection.activation.cohort_sha256
            retained = await run_owned_thread(self.journal.journal.get, "coverage_work", key)
            work = (
                CoverageWork.model_validate(retained)
                if retained is not None
                else CoverageWork(
                    schema="umi-reward-coverage-work/1",
                    activation=selection.activation,
                    observed_block=self._target,
                    first_block=selection.effective_at_block,
                )
            )
            if (
                work.activation != selection.activation
                or work.first_block != selection.effective_at_block
            ):
                raise ValueError("retained coverage work changes the effective activation")
            await run_owned_thread(self.journal.journal.put, "coverage_work", key, work)
        # Preserve a fixed target across bounded catch-up passes. Only after
        # completing it may discovery ask for a newer head.
        self._target = None

    async def _source(self, activation):
        package = await run_owned_thread(self.files.package, activation.package_sha256)
        return NativeRewardCoverageSource(
            provider=self.provider,
            journal=self.journal,
            history=self.history,
            preparation=self.preparation,
            package=package,
            decisions=self.files.decision,
            profile=self.profile,
            maximum_history_blocks=self.maximum_history_blocks,
        )

    def _content(self, kind, sha, fallback):
        retained = self.journal.journal.get(kind, sha)
        return fallback(sha) if retained is None else canonical_json_bytes(retained)

    def _witness(self, sha):
        return self._content("opportunity_witness", sha, self.files.witness)

    async def _review(self, sha, activation, source):
        raw = await run_owned_thread(
            self._content, "opportunity_certificate", sha, self.files.certificate
        )
        reader = self.preparation.reader
        return await review_opportunity_certificate(
            raw,
            expected_sha256=sha,
            journal=self.journal,
            witness_source=self._witness,
            review_endpoint=source.replay,
            manifest=self.preparation.manifest,
            series=reader.series,
            policy=reader.policy,
            activation=activation,
            maximum_witness_bytes=self.files.maximum_witness_bytes,
        )

    async def _collect(self):
        keys = await run_owned_thread(self.journal.journal.keys, "coverage_work")
        ordered = tuple(digest(c) for c in self.preparation.reader.series.cohorts)
        if not set(keys) <= set(ordered):
            raise ValueError("coverage work is outside the selected series")
        pending = [key for key in ordered if key in keys and key not in self._completed]
        if not pending:
            return
        # Keep one package/source in memory and its replay cursor across passes.
        # Capture the newest allocation first while its current state is easily
        # available, then finish retained predecessors. Recreating collectors
        # every pass would repeatedly replay the same first page after restart.
        key = pending[-1]
        if self._active != key:
            work = CoverageWork.model_validate(
                await run_owned_thread(self.journal.journal.get, "coverage_work", key)
            )
            selection = await self._selection(work.observed_block)
            if (
                selection is None
                or work.activation.cohort_sha256 != key
                or selection.activation != work.activation
                or selection.effective_at_block != work.first_block
            ):
                raise ValueError("coverage work lacks original effective control")
            source = await self._source(work.activation)
            reader = self.preparation.reader
            self._collector = RewardCoverageCollector(
                self.journal,
                source,
                manifest=self.preparation.manifest,
                series=reader.series,
                policy=reader.policy,
                activation=work.activation,
                first_block=work.first_block,
                maximum_witness_bytes=self.files.maximum_witness_bytes,
            )
            self._active = key
        collector = self._collector
        retained = await run_owned_thread(self.journal.journal.get, "coverage_completion", key)
        if retained is None:
            progress = await collector.step()
            logger.info(
                "coverage_pending cohort_sha256=%s credited_ms=%s errors=%s",
                key,
                dict(progress.credited_ms),
                progress.errors,
            )
            if progress.certificate is None:
                return
            completion = CoverageCompletion(
                schema="umi-reward-coverage-completion/1",
                certificate_sha256=digest(progress.certificate),
            )
            # Persist the chosen identity before any public discovery/export.
            # A lost acknowledgement reads it on retry instead of replacing it.
            await run_owned_thread(self.journal.journal.put, "coverage_completion", key, completion)
        else:
            completion = CoverageCompletion.model_validate(retained)
        verified = await self._review(
            completion.certificate_sha256, collector.terms["activation"], collector.source
        )
        await run_owned_thread(self.files.retain_completion, verified.certificate, self._witness)
        self._completed[key] = verified
        self._active, self._collector = None, None
        logger.info(
            "coverage_complete cohort_sha256=%s certificate_sha256=%s",
            key,
            completion.certificate_sha256,
        )

    async def step(self):
        async with self._lock:
            # Owned work can finish from retained evidence even while discovery
            # or the coordinator is unavailable. Failures are independent.
            for name, operation in (("collection", self._collect), ("discovery", self._discover)):
                try:
                    await operation()
                except Exception as error:
                    logger.warning("coverage_retry phase=%s reason=%s", name, type(error).__name__)

    async def opportunity(self, activation: RewardActivation) -> VerifiedRewardOpportunity:
        async with self._lock:
            key = digest(activation)
            if key in self._opportunities:
                return self._opportunities[key]
            reader = self.preparation.reader
            index = tuple(digest(c) for c in reader.series.cohorts).index(activation.cohort_sha256)
            if index == 0:
                raise ValueError("initial opportunity requires the native legacy handoff")
            prior = SignedRewardControlDecision.model_validate_json(
                canonical_json_bytes(
                    await run_owned_thread(
                        reader.journal.get, "reward_control_decision", f"{index:04d}"
                    )
                )
            ).decision
            if prior.activation is None:
                raise ValueError("standing predecessor activation is unavailable")
            verified = self._completed.get(prior.activation.cohort_sha256)
            if (
                verified is None
                or digest(verified.certificate) != activation.prior_opportunity_sha256
            ):
                verified = await self._review(
                    activation.prior_opportunity_sha256,
                    prior.activation,
                    await self._source(prior.activation),
                )
            self._opportunities[key] = verified
            return verified

    async def completed_opportunity(
        self, activation: RewardActivation
    ) -> VerifiedRewardOpportunity:
        """Replay one selected activation's own completed coverage.

        A successor series uses this path for its predecessor boundary. The
        completion may be discovered after an arbitrarily long outage; absence
        remains pending and never becomes inferred credit.
        """
        async with self._lock:
            reader = self.preparation.reader
            cohorts = tuple(digest(c) for c in reader.series.cohorts)
            try:
                index = cohorts.index(activation.cohort_sha256)
            except ValueError:
                raise ValueError("completed opportunity is outside the selected series") from None
            selected = SignedRewardControlDecision.model_validate_json(
                canonical_json_bytes(
                    await run_owned_thread(
                        reader.journal.get,
                        "reward_control_decision",
                        f"{index + 1:04d}",
                    )
                )
            ).decision
            if selected.kind != "activate" or selected.activation != activation:
                raise ValueError("completed opportunity differs from signed reward selection")
            verified = self._completed.get(activation.cohort_sha256)
            if verified is None:
                retained = await run_owned_thread(
                    self.journal.journal.get,
                    "coverage_completion",
                    activation.cohort_sha256,
                )
                if retained is None:
                    raise ValueError("predecessor reward opportunity is incomplete")
                completion = CoverageCompletion.model_validate(retained)
                verified = await self._review(
                    completion.certificate_sha256,
                    activation,
                    await self._source(activation),
                )
                self._completed[activation.cohort_sha256] = verified
            return verified

    async def run(self, stop: asyncio.Event, *, poll_seconds: float):
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("coverage poll interval is outside its host bound")
        while not stop.is_set():
            self.provider.ensure_observer_running()
            await self.step()
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
