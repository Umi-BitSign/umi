"""Automatic coverage capture, restart replay and completion content retention.

A failed proof contributes nothing. Collection continues while an activation is
pending; neither failures nor elapsed wall time expire its reward opportunity.
This produces certificate content, not payment confirmation or signing authority.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .competition_chain import _uint
from .competition_evidence_codec import checked_size
from .competition_reward_coverage_intervals import (
    CoverageEndpoint,
    OwnedRetainedCoverageEndpoint,
    coverage_point,
)
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_source import CoverageHistoryPending
from .competition_reward_decisions import RewardActivation, StandingRewardSeries
from .competition_reward_manifest import StandingRewardOpportunityManifest
from .competition_reward_opportunity import RewardOpportunityCertificate, opportunity_rule
from .competition_reward_opportunity_review import (
    DEFAULT_WITNESS_BYTES,
    prepare_opportunity_certificate,
)
from .competition_transport_verification import TransferProgress
from .open_competition import CompetitionPolicy, digest, identity
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


def _log_retry(error, *, phase, operation, hotkey=None, block=None):
    # Exception text and full tracebacks can include RPC URLs or credentials.
    # Report only source coordinates inside this installed package, never locals.
    origin = {}
    trace = error.__traceback__
    package = Path(__file__).parent
    while trace is not None:
        code = trace.tb_frame.f_code
        source = Path(code.co_filename)
        if source.parent == package:
            origin = {"module": source.stem, "function": code.co_name, "line": trace.tb_lineno}
        trace = trace.tb_next
    logger.info(
        "coverage_retry %s",
        {
            "phase": phase,
            "operation": operation,
            "validator_hotkey": hotkey,
            "block": block,
            "error_type": type(error).__name__,
            "origin": origin,
        },
    )


class CoverageSource(Protocol):
    async def finalized_height(self) -> int: ...
    async def capture(self, validator_hotkey: str, height: int) -> CoverageEndpoint: ...
    async def replay(self, key: str) -> CoverageEndpoint: ...


@dataclass(frozen=True)
class CoverageProgress:
    credited_ms: tuple[tuple[str, int], ...]
    errors: tuple[tuple[str, str], ...]
    certificate: RewardOpportunityCertificate | None
    immediate: bool = False


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
        maximum_backfill_endpoints_per_validator: int = 4,
        # Capture recent points even when a slow endpoint cannot fill a long
        # historical page. Retained intervals have their own replay cursor;
        # this window neither deletes them nor credits gaps between captures.
        capture_window_blocks: int = 4,
        maximum_witness_bytes: int = DEFAULT_WITNESS_BYTES,
    ):
        if journal.rule != opportunity_rule(manifest, series, policy):
            raise ValueError("coverage collector differs from approved opportunity terms")
        _uint(first_block, 2**53 - 1)
        if first_block == 0 or activation.cohort_sha256 not in {digest(c) for c in series.cohorts}:
            raise ValueError("coverage collector requires a selected cohort and start block")
        checked_size(maximum_replay_intervals, 4096)
        checked_size(maximum_endpoints_per_validator, 4096)
        _uint(maximum_backfill_endpoints_per_validator, 4096)
        checked_size(capture_window_blocks, 65536)
        checked_size(maximum_witness_bytes, MAX_CONFIGURED_PRIVATE_BYTES)
        self.maximum_witness_bytes = maximum_witness_bytes
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
        self.maximum_backfill = maximum_backfill_endpoints_per_validator
        self.capture_window = capture_window_blocks
        self._cursor = None
        self._replayed: set[str] = set()
        self._next: dict[str, int] = {}
        self._left: dict[str, CoverageEndpoint] = {}
        self._backfill_next: dict[str, int] = {}
        self._backfill_left: dict[str, CoverageEndpoint] = {}
        self._started = time.monotonic()
        self._initial_head = None
        self._backfill_native: dict[str, int] = {}
        self._backfill_restored: dict[str, int] = {}
        self._gap_samples = 0
        self._gap_frontiers: dict[str, tuple[int, float]] = {}
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
            self._certificate = await prepare_opportunity_certificate(
                self.journal, **self.terms, maximum_witness_bytes=self.maximum_witness_bytes
            )
        return self._certificate

    async def step(self) -> CoverageProgress:
        async with self._lock:
            return await self._step()

    async def _capture_page(self, hotkey, height, through, limit, nexts, lefts, errors, phase):
        count = min(limit, max(0, through - height + 1))
        if count == 0:
            return 0
        done = 0
        with TransferProgress(
            "coverage_" + phase,
            count,
            unit="endpoints",
            planning_unit_seconds=(1, 300),
        ) as progress:
            for _ in range(count):
                operation = "capture"
                try:
                    endpoint = await self.source.capture(hotkey, height)
                    operation = "validate_point"
                    point = coverage_point(endpoint, self.journal.rule)
                    if (
                        point.block != height
                        or point.validator_account_id != identity(hotkey)
                        or point.activation_sha256 != self.activation
                    ):
                        raise ValueError("captured endpoint differs from selected coverage")
                    operation = "retain_endpoint"
                    await self.journal.retain_endpoint(endpoint)
                    left = lefts.get(hotkey)
                    if left is not None and (
                        coverage_point(left, self.journal.rule).block == height - 1
                    ):
                        operation = "credit_interval"
                        interval = await self.journal.credit(left, endpoint)
                        if interval is not None:
                            self._replayed.add(interval.key())
                    lefts[hotkey] = endpoint
                except CoverageHistoryPending:
                    errors.append((hotkey, "history_pending"))
                    progress.emit("retrying", reason="history_pending")
                    break
                except Exception as error:
                    # Preserve both lane cursors and their preceding endpoints
                    # until retention and adjacent credit are acknowledged.
                    errors.append((hotkey, type(error).__name__))
                    _log_retry(error, phase=phase, operation=operation, hotkey=hotkey, block=height)
                    progress.emit("retrying", reason=type(error).__name__)
                    break
                height += 1
                nexts[hotkey] = height
                done += 1
                restored = type(endpoint) is OwnedRetainedCoverageEndpoint
                progress.advance(1, restored=restored)
                if phase == "backfill":
                    counts = self._backfill_restored if restored else self._backfill_native
                    counts[hotkey] = counts.get(hotkey, 0) + 1
                if (
                    await self.journal.verified_ms(
                        activation_sha256=self.activation, validator_hotkey=hotkey
                    )
                    >= self.minimum_ms
                ):
                    # The approved opportunity can finish before this page.
                    progress.total = done
                    break
        return done

    def _report_backfill(self, floor, head, totals, errors):
        now = time.monotonic()
        elapsed = max(0.0, now - self._started)
        self._gap_samples += 1
        target = (
            floor if self.maximum_backfill and floor > self.first_block else self.first_block - 1
        )
        for hotkey, credited in totals:
            next_block = self._backfill_next.get(hotkey, self.first_block)
            pending = max(0, target - next_block + 1) if credited < self.minimum_ms else 0
            completed = max(0, next_block - self.first_block)
            net_rate = (completed - (head - self._initial_head)) / elapsed if elapsed else 0
            enough = self._gap_samples >= 2 and completed >= 2
            failed = any(who in {hotkey, "replay", "head"} for who, _ in errors)
            previous, changed = self._gap_frontiers.get(hotkey, (self.first_block, self._started))
            if previous != next_block:
                changed = now
            self._gap_frontiers[hotkey] = (next_block, changed)
            stalled = bool(pending and now - changed >= 60)
            eta, planning = None, None
            if not self.maximum_backfill:
                state, basis = "disabled", "explicit_historical_capture_disabled"
            elif not pending:
                state, basis, eta = "completed", "completed_opportunity_or_gap_scope", 0
            elif failed:
                state, basis = "retrying", "withdrawn_retrying"
            elif stalled:
                state, basis = "stalled", "withdrawn_stalled_frontier"
            elif not enough:
                state = "running"
                basis = "planning_assumption_1_to_300_seconds_per_endpoint_excludes_growth"
                planning = [pending, 300 * pending]
            elif net_rate <= 0:
                state, basis = "running", "not_converging_with_observed_chain_growth"
            else:
                state, basis = "running", "measured_frontier_rate_minus_observed_chain_growth"
                eta = pending / net_rate
            logger.info(
                "coverage_backfill_progress %s",
                {
                    "activation_sha256": self.activation,
                    "validator_hotkey": hotkey,
                    "state": state,
                    "backfill_enabled": bool(self.maximum_backfill),
                    "stalled": stalled,
                    "first_block": self.first_block,
                    "next_block": next_block,
                    "target_block": target,
                    "completed_endpoints": completed,
                    "pending_endpoints": pending,
                    "percent": 100 * completed / (completed + pending)
                    if completed + pending
                    else 100.0,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": eta,
                    "planning_eta_seconds": planning,
                    "eta_basis": basis,
                    "eta_scope": "historical_gap_frontier_in_current_collector_run",
                    "rate_window_scope": (
                        "since_collector_creation_excludes_prior_owner_restoration"
                    ),
                    "credited_ms": credited,
                    "minimum_ms": self.minimum_ms,
                    "reward_opportunity_percent": 100
                    * min(credited, self.minimum_ms)
                    / self.minimum_ms,
                    "backfill_native_endpoints": self._backfill_native.get(hotkey, 0),
                    "backfill_restored_endpoints": self._backfill_restored.get(hotkey, 0),
                    "sample_count": self._gap_samples,
                    "successor_activation_eta_seconds": None,
                    "successor_activation_eta_basis": (
                        "requires_remaining_opportunity_and_successor_runtime_capacity_qualification"
                    ),
                },
            )

    async def _step(self):
        errors = []
        replayed = 0
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
                replayed += 1
            except Exception as error:
                errors.append(("replay", type(error).__name__))
                _log_retry(error, phase="replay", operation="restore_and_credit_interval")
        if len(keys) < self.maximum_replay_intervals:
            self._cursor = None
        totals = await self._totals()
        if await self._complete(totals) is not None:
            return CoverageProgress(totals, tuple(errors), self._certificate)
        try:
            head = await self.source.finalized_height()
            _uint(head, 2**53 - 1)
        except Exception as error:
            _log_retry(error, phase="head", operation="finalized_height")
            return CoverageProgress(totals, tuple([*errors, ("head", type(error).__name__)]), None)
        floor = max(self.first_block, head - self.capture_window + 1)
        if self._initial_head is None:
            self._initial_head = head
        # Fresh checks always run before the bounded historical lane, for every
        # validator. Advancing the recent floor does not discard the old lane.
        for hotkey, total in totals:
            if total >= self.minimum_ms:
                continue
            height = max(self._next.get(hotkey, floor), floor)
            await self._capture_page(
                hotkey,
                height,
                head,
                self.maximum_endpoints,
                self._next,
                self._left,
                errors,
                "fresh_capture",
            )
        backfilled = 0
        totals = await self._totals()
        if self.maximum_backfill and floor > self.first_block:
            for hotkey, total in totals:
                if total >= self.minimum_ms:
                    continue
                backfilled += await self._capture_page(
                    hotkey,
                    self._backfill_next.get(hotkey, self.first_block),
                    floor,
                    self.maximum_backfill,
                    self._backfill_next,
                    self._backfill_left,
                    errors,
                    "backfill",
                )
        totals = await self._totals()
        await self._complete(totals)
        self._report_backfill(floor, head, totals, errors)
        pending_gap = self.maximum_backfill and any(
            total < self.minimum_ms and self._backfill_next.get(k, self.first_block) <= floor
            for k, total in totals
        )
        immediate = not errors and (
            (backfilled > 0 and pending_gap)
            or (replayed > 0 and len(keys) == self.maximum_replay_intervals)
        )
        return CoverageProgress(totals, tuple(errors), self._certificate, bool(immediate))

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
                if progress.immediate:
                    await asyncio.sleep(0)
                    continue
            except Exception as error:
                logger.warning("coverage_retry reason=%s", type(error).__name__)
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
        return None
