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
from typing import Protocol

from .competition_chain import _uint
from .competition_evidence_codec import checked_size
from .competition_progress import _failure_details
from .competition_reward_coverage_intervals import (
    CoverageEndpoint,
    OwnedRetainedCoverageEndpoint,
    coverage_point,
)
from .competition_reward_coverage_journal import RewardCoverageJournal
from .competition_reward_coverage_source import CoverageHistoryPending
from .competition_reward_decisions import RewardActivation, StandingRewardSeries
from .competition_reward_eligibility import RewardRuntimeCodeMismatch
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
    details = _failure_details(error)
    runtime_code = None
    cause, seen = error, set()
    while cause is not None and id(cause) not in seen and len(seen) < 6:
        seen.add(id(cause))
        if isinstance(cause, RewardRuntimeCodeMismatch):
            runtime_code = {
                "expected_sha256": cause.expected_runtime_code_sha256,
                "observed_sha256": cause.observed_runtime_code_sha256,
            }
            if not all(
                type(value) is str
                and len(value) == 64
                and all(char in "0123456789abcdef" for char in value)
                for value in runtime_code.values()
            ):
                runtime_code = None
            break
        cause = cause.__cause__ or (None if cause.__suppress_context__ else cause.__context__)
    origin = next(
        (cause["source_frames"][-1] for cause in reversed(details) if cause["source_frames"]), {}
    )
    logger.info(
        "coverage_retry %s",
        {
            "phase": phase,
            "operation": operation,
            "validator_hotkey": hotkey,
            "block": block,
            "error_type": type(error).__name__,
            "reason_codes": [detail["reason_code"] for detail in details],
            "runtime_code": runtime_code,
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
    retained_page: bool = False


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
        # This collector is the journal's sole live credit writer. Captures
        # below add their freshly credited intervals to _replayed; a restarted
        # collector scans retained evidence again before claiming any credit.
        self._retained_inventory_drained = False
        self._retained_scan_failed = False
        self._retained_scan_started: float | None = None
        self._retained_scanned = 0
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
        self._owner_counts = {}
        self._credit_start = None
        self._credit_observations = 0
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

    def _report_credit(self, phase, before, after, started, *, retrying):
        # These are actual native credited-total deltas, not endpoint counts or
        # an assumption that every capture is eligible. Saved replay is finite
        # and must not be mixed into the fresh lane's sustained-rate forecast.
        previous = dict(before)
        if phase == "retained_interval_replay":
            self._credit_observations += 1
        logger.info(
            "coverage_credit_progress %s",
            {
                "phase": phase,
                "credited_delta_ms": {k: n - previous[k] for k, n in after},
                "credited_total_ms": dict(after),
                "elapsed_seconds": max(0.0, time.monotonic() - started),
                "status": "retrying" if retrying else "completed",
                "eta_seconds": None if retrying else 0,
                "eta_basis": "withdrawn_retrying" if retrying else "completed_credit_phase",
                "eta_scope": "this_pass_and_phase_only_not_remaining_opportunity",
                "certification_authority": False,
                "opportunities": [
                    dict(validator_hotkey=k, **self._credit_forecast(k, n, retrying=retrying))
                    for k, n in after
                ],
            },
        )

    def _credit_forecast(self, hotkey, credited, *, retrying=False, stalled=False):
        elapsed = max(0.0, time.monotonic() - self._started)
        remaining = max(0, self.minimum_ms - credited)
        baseline = (self._credit_start or {}).get(hotkey, credited)
        delta = max(0, credited - baseline)
        rate = delta / elapsed if elapsed else 0
        measured = (
            not retrying
            and not stalled
            and self._credit_observations >= 2
            and elapsed >= 60
            and delta >= 12000
            and rate > 0
        )
        return dict(
            credited_ms=credited,
            minimum_ms=self.minimum_ms,
            remaining_credit_ms=remaining,
            minimum_remaining_full_intervals=math.ceil(
                remaining / self.journal.rule.maximum_interval_ms
            ),
            opportunity_eta_seconds=0 if not remaining else remaining / rate if measured else None,
            opportunity_eta_scope="remaining_native_credit_restore_and_capture_excludes_activation",
            opportunity_eta_basis="completed_opportunity"
            if not remaining
            else (
                "measured_process_credit_rate_including_waits_assumes_remaining_mix"
                if measured
                else "withdrawn_retry_stall_or_insufficient_credit_samples"
            ),
            credit_rate_ms_per_second=rate if measured else None,
            reward_opportunity_percent=100 * min(credited, self.minimum_ms) / self.minimum_ms,
        )

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
                    if operation == "credit_interval":
                        # A lost acknowledgement can leave an interval durable
                        # without this collector knowing its native credit. Reopen
                        # the retained scan so a later pass can recover it even
                        # if the live endpoint source remains unavailable.
                        self._retained_inventory_drained = False
                        self._retained_scan_failed = False
                        self._retained_scan_started = None
                        self._retained_scanned = 0
                        self._cursor = None
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
                    **self._owner_counts,
                    "replay_page_limit": self.maximum_replay_intervals,
                    "replay_cursor": self._cursor,
                    "replayed_intervals_this_collector": len(self._replayed),
                    **self._credit_forecast(hotkey, credited, retrying=failed, stalled=stalled),
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
        restored_credits = 0
        if self._certificate is not None:
            return CoverageProgress(await self._totals(), (), self._certificate)
        before_replay = await self._totals()
        if self._credit_start is None:
            self._credit_start = dict(before_replay)
        phase_started = time.monotonic()
        already_drained = self._retained_inventory_drained
        if not already_drained and self._retained_scan_started is None:
            self._retained_scan_started = phase_started
        # Retry an incomplete first scan from the start. Once all retained
        # intervals have been checked, new intervals from this owner are already
        # natively credited by _capture_page and need no second inventory pass.
        keys = (
            ()
            if already_drained
            else await self.journal.interval_keys(
                after=self._cursor, limit=self.maximum_replay_intervals
            )
        )
        self._owner_counts = await self.journal.diagnostic_counts()
        if not already_drained:
            logger.info(
                "coverage_native_credit_restore %s",
                dict(
                    **self._owner_counts,
                    status="running",
                    replay_cursor=self._cursor,
                    selected_intervals=len(keys),
                    credited_ms=dict(before_replay),
                    minimum_ms=self.minimum_ms,
                    eta_seconds=None,
                    eta_basis="counted_owner_inventory_not_yet_activation_scoped_credit",
                ),
            )
        for key in keys:
            self._cursor = key
            if key in self._replayed:
                continue
            try:
                interval = await self.journal.retained_interval(key)
                if interval.activation_sha256 != self.activation:
                    continue
                restore_credit = getattr(self.source, "restore_credit", None)
                restored_credit = None if restore_credit is None else await restore_credit(key)
                if restored_credit is not None:
                    from .competition_reward_coverage_credits import validate_native_credit

                    native_interval, _ = validate_native_credit(restored_credit, self.journal)
                    if native_interval != interval:
                        raise ValueError("native credit differs from original interval")
                    self._replayed.add(key)
                    replayed += 1
                    restored_credits += 1
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
                self._retained_scan_failed = True
                _log_retry(error, phase="replay", operation="restore_and_credit_interval")
        if not already_drained:
            self._retained_scanned += len(keys)
        scan_failed = self._retained_scan_failed
        totals = await self._totals()
        if not already_drained and len(keys) < self.maximum_replay_intervals:
            self._cursor = None
            if not self._retained_scan_failed:
                self._retained_inventory_drained = True
                logger.info(
                    "coverage_native_credit_restore %s",
                    dict(
                        **self._owner_counts,
                        status="completed",
                        selected_intervals=len(keys),
                        credited_ms=dict(totals),
                        minimum_ms=self.minimum_ms,
                        eta_seconds=0,
                        eta_basis="completed_retained_inventory_scope_not_activation",
                    ),
                )
            else:
                # A failed item on an earlier full page must be revisited even
                # if the final page in this pass had no errors. Successful
                # native credits in _replayed remain reusable.
                self._retained_scan_failed = False
        if not already_drained:
            total = self._owner_counts["retained_intervals"]
            scanned = min(self._retained_scanned, total)
            remaining = max(0, total - scanned)
            elapsed = max(0.0, time.monotonic() - self._retained_scan_started)
            enough = scanned >= 8 and elapsed >= 1
            measured_eta = (
                remaining * elapsed / scanned
                if enough and not scan_failed and not self._retained_inventory_drained
                else None
            )
            planning_eta = (
                [remaining, 600 * remaining]
                if remaining and not enough and not scan_failed
                else None
            )
            logger.info(
                "coverage_retained_inventory_progress %s",
                {
                    "state": "completed"
                    if self._retained_inventory_drained
                    else "retrying"
                    if scan_failed
                    else "running",
                    "completed_intervals": scanned,
                    "total_intervals": total,
                    "percent": 100 * scanned / total if total else 100.0,
                    "elapsed_seconds": elapsed,
                    "eta_seconds": 0 if self._retained_inventory_drained else measured_eta,
                    "planning_eta_seconds": planning_eta,
                    "eta_basis": "completed_retained_inventory_scope"
                    if self._retained_inventory_drained
                    else "withdrawn_retrying"
                    if scan_failed
                    else "measured_current_scan_intervals_per_elapsed_second"
                    if enough
                    else "planning_1_to_600_seconds_per_interval_excludes_external_waits",
                    "eta_scope": (
                        "retained_inventory_current_attempt_not_native_credit_or_activation"
                    ),
                    "stalled_or_retrying": scan_failed,
                },
            )
            if scan_failed and self._cursor is None:
                self._retained_scan_started = None
                self._retained_scanned = 0
        if not already_drained:
            self._report_credit(
                "retained_interval_replay",
                before_replay,
                totals,
                phase_started,
                retrying=bool(errors),
            )
        if await self._complete(totals) is not None:
            return CoverageProgress(totals, tuple(errors), self._certificate)
        if len(keys) == self.maximum_replay_intervals and not errors:
            # Both first-adoption native endpoint replay and durable credit
            # restoration finish a bounded retained page before moving-head
            # work. The outer owner yields between pages and minimum completion
            # above stops the drain without requiring the full historical gap.
            self._owner_counts = await self.journal.diagnostic_counts()
            logger.info(
                "coverage_native_credit_restore %s",
                dict(
                    **self._owner_counts,
                    restored_intervals=restored_credits,
                    replayed_intervals=replayed,
                    replay_cursor=self._cursor,
                    credited_ms=dict(totals),
                    minimum_ms=self.minimum_ms,
                    eta_seconds=None,
                    eta_basis="bounded_native_credit_page_remaining_count_not_activation",
                ),
            )
            return CoverageProgress(totals, (), None, True, retained_page=True)
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
        before_fresh, phase_started, prior_errors = totals, time.monotonic(), len(errors)
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
        self._report_credit(
            "recent_block_capture",
            before_fresh,
            totals,
            phase_started,
            retrying=len(errors) > prior_errors,
        )
        before_backfill, phase_started, prior_errors = totals, time.monotonic(), len(errors)
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
        self._report_credit(
            "historical_gap_capture",
            before_backfill,
            totals,
            phase_started,
            retrying=len(errors) > prior_errors,
        )
        await self._complete(totals)
        self._owner_counts = await self.journal.diagnostic_counts()
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
