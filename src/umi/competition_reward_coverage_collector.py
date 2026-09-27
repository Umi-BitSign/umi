"""Automatic coverage capture, restart replay and completion content retention.

A failed proof contributes nothing. Collection continues while an activation is
pending; neither failures nor elapsed wall time expire its reward opportunity.
This produces certificate content, not payment confirmation or signing authority.
"""

from __future__ import annotations

import asyncio
import logging
import math
from contextlib import suppress
from dataclasses import dataclass
from typing import Protocol

from .competition_chain import _uint
from .competition_evidence_codec import checked_size
from .competition_reward_coverage import OwnedRewardCoverageEndpoint
from .competition_reward_coverage_intervals import coverage_point
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_source import CoverageHistoryPending
from .competition_reward_decisions import RewardActivation, StandingRewardSeries
from .competition_reward_manifest import StandingRewardOpportunityManifest
from .competition_reward_opportunity import RewardOpportunityCertificate, opportunity_rule
from .competition_reward_opportunity_review import prepare_opportunity_certificate
from .open_competition import CompetitionPolicy, digest, identity
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


class CoverageSource(Protocol):
    async def finalized_height(self) -> int: ...
    async def capture(self, validator_hotkey: str, height: int) -> OwnedRewardCoverageEndpoint: ...
    async def replay(self, key: str) -> OwnedRewardCoverageEndpoint: ...


@dataclass(frozen=True)
class CoverageProgress:
    credited_ms: tuple[tuple[str, int], ...]
    errors: tuple[tuple[str, str], ...]
    certificate: RewardOpportunityCertificate | None


class RewardCoverageCollector:
    def __init__(
        self,
        journal: RewardCoverageJournal,
        source: CoverageSource,
        *,
        manifest: StandingRewardOpportunityManifest,
        series: StandingRewardSeries,
        policy: CompetitionPolicy,
        activation: RewardActivation,
        first_block: int,
        maximum_replay_intervals: int = 8,
        maximum_endpoints_per_validator: int = 4,
        capture_window_blocks: int = 128,
    ):
        if journal.rule != opportunity_rule(manifest, series, policy):
            raise ValueError("coverage collector differs from approved opportunity terms")
        _uint(first_block, 2**53 - 1)
        if first_block == 0 or activation.cohort_sha256 not in {digest(c) for c in series.cohorts}:
            raise ValueError("coverage collector requires a selected cohort and start block")
        checked_size(maximum_replay_intervals, 4096)
        checked_size(maximum_endpoints_per_validator, 4096)
        checked_size(capture_window_blocks, 65536)
        self.journal, self.source = journal, source
        self.terms = dict(manifest=manifest, series=series, policy=policy, activation=activation)
        self.activation = digest(activation)
        self.validators, self.minimum_ms = (
            series.validators,
            manifest.opportunity.minimum_validator_ms,
        )
        self.first_block = first_block
        self.maximum_replay_intervals = maximum_replay_intervals
        self.maximum_endpoints = maximum_endpoints_per_validator
        self.capture_window = capture_window_blocks
        self._cursor = None
        self._replayed: set[str] = set()
        self._next: dict[str, int] = {}
        self._left: dict[str, OwnedRewardCoverageEndpoint] = {}
        self._certificate = None
        self._lock = asyncio.Lock()

    async def _totals(self):
        return tuple(
            [
                (
                    k,
                    await self.journal.verified_ms(
                        activation_sha256=self.activation, validator_hotkey=k
                    ),
                )
                for k in self.validators
            ]
        )

    async def _complete(self, totals):
        if self._certificate is None and all(n >= self.minimum_ms for _, n in totals):
            self._certificate = await prepare_opportunity_certificate(self.journal, **self.terms)
        return self._certificate

    async def step(self) -> CoverageProgress:
        async with self._lock:
            return await self._step()

    async def _step(self):
        errors = []
        if self._certificate is not None:
            return CoverageProgress(await self._totals(), (), self._certificate)
        # Cycling, rather than a terminal retry count, revisits unavailable old
        # evidence. New coverage collection still runs after each bounded page.
        keys = await self.journal.interval_keys(
            after=self._cursor, limit=self.maximum_replay_intervals
        )
        for key in keys:
            self._cursor = key
            if key in self._replayed:
                continue
            try:
                interval = await self.journal.retained_interval(key)
                if interval.activation_sha256 != self.activation:
                    continue
                left, right = (
                    await self.source.replay(interval.left),
                    await self.source.replay(interval.right),
                )
                verified = await self.journal.credit(left, right)
                if verified != interval:
                    raise ValueError("retained coverage differs from native replay")
                self._replayed.add(key)
            except Exception as error:
                errors.append(("replay", type(error).__name__))
        if len(keys) < self.maximum_replay_intervals:
            self._cursor = None
        totals = await self._totals()
        if await self._complete(totals) is not None:
            return CoverageProgress(totals, tuple(errors), self._certificate)
        try:
            head = await self.source.finalized_height()
            _uint(head, 2**53 - 1)
        except Exception as error:
            return CoverageProgress(totals, tuple([*errors, ("head", type(error).__name__)]), None)
        floor = max(self.first_block, head - self.capture_window + 1)
        for hotkey, total in totals:
            if total >= self.minimum_ms:
                continue
            height = max(self._next.get(hotkey, floor), floor)
            for _ in range(self.maximum_endpoints):
                if height > head:
                    break
                try:
                    endpoint = await self.source.capture(hotkey, height)
                    point = coverage_point(endpoint, self.journal.rule)
                    if (
                        point.block != height
                        or point.validator_account_id != identity(hotkey)
                        or point.activation_sha256 != self.activation
                    ):
                        raise ValueError("captured endpoint differs from selected coverage")
                    await self.journal.retain_endpoint(endpoint)
                    left = self._left.get(hotkey)
                    if (
                        left is not None
                        and coverage_point(left, self.journal.rule).block == height - 1
                    ):
                        interval = await self.journal.credit(left, endpoint)
                        if interval is not None:
                            self._replayed.add(interval.key())
                    self._left[hotkey] = endpoint
                except CoverageHistoryPending:
                    errors.append((hotkey, "history_pending"))
                    break
                except Exception as error:
                    # Retry this block and keep its preceding native endpoint.
                    # Slow history/proofs and lost durable acknowledgements must
                    # not advance the cursor. If the head moves beyond the
                    # capture window, fresh opportunity can replace unavailable
                    # history; the adjacency check still forbids bridging gaps.
                    errors.append((hotkey, type(error).__name__))
                    break
                height += 1
                self._next[hotkey] = height
                if (
                    await self.journal.verified_ms(
                        activation_sha256=self.activation, validator_hotkey=hotkey
                    )
                    >= self.minimum_ms
                ):
                    break
        totals = await self._totals()
        await self._complete(totals)
        return CoverageProgress(totals, tuple(errors), self._certificate)

    async def run(
        self, stop: asyncio.Event, *, poll_seconds: float = 12
    ) -> RewardOpportunityCertificate | None:
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("coverage poll interval is outside its host bound")
        while not stop.is_set():
            try:
                progress = await self.step()
                logger.info(
                    canonical_json_bytes(
                        {
                            "status": "coverage_complete"
                            if progress.certificate
                            else "coverage_pending",
                            "activation_sha256": self.activation,
                            "credited_ms": dict(progress.credited_ms),
                            "errors": progress.errors,
                            "certificate_sha256": None
                            if progress.certificate is None
                            else digest(progress.certificate),
                        }
                    ).decode()
                )
                if progress.certificate is not None:
                    return progress.certificate
            except Exception as error:
                logger.warning("coverage_retry reason=%s", type(error).__name__)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
        return None
