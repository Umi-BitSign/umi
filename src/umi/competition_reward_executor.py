"""Recurring standing weights with durable recovery and one local writer.

The installed host supplies approved series inputs and holds the native legacy
handoff for this executor's lifetime. Content callbacks supply data, never
authority. A recovered attempt is reconciled, not retransmitted or re-signed.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
import time
from collections.abc import Awaitable, Callable, Iterator
from contextlib import ExitStack, contextmanager, suppress
from dataclasses import dataclass
from functools import partial

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_decisions import (
    DecisionSource,
    RewardActivation,
    activation_requires_revision,
    effective_activation_decision,
    original_activation_decision,
    retained_reward_decisions,
)
from .competition_reward_handoff_models import (
    StandingRewardHandoffPlan,
    VerifiedLegacyRewardHandoff,
    validate_legacy_handoff,
)
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_host import (
    BoundStandingRewardHost,
    VerifiedStandingRewardHandoff,
    validate_standing_reward_handoff,
)
from .competition_reward_manifest import StandingRewardOpportunityManifest
from .competition_reward_opportunity import (
    VerifiedRewardOpportunity,
    verify_signed_early_release,
)
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_reward_transaction_outcome import resolve_standing_transaction
from .competition_reward_transactions import (
    PendingStandingWeight,
    StandingWeightJournal,
    standing_weight_call,
)
from .competition_weight_timing import WeightRateLimitWait
from .competition_weights import BittensorCompetitionWeightTransport
from .concurrency import run_owned_thread, wait_for_owned
from .host_memory_runtime import memory_operation
from .open_competition import digest, identity
from .private_files import lock_private_file
from .protocol import canonical_json_bytes
from .r2_evidence import R2EvidenceHTTPError
from .signed_extrinsic import encode_mortal_call

logger = logging.getLogger(__name__)


class StandingHistoryPending(Exception):
    """A bounded history pass saved progress and needs another iteration."""


@dataclass(frozen=True)
class StandingExecutionProgress:
    status: str
    intent_sha256: str | None = None
    extrinsic_hash: str | None = None


class StandingRewardExecutor:
    def __init__(
        self,
        *,
        preparation: StandingRewardPreparation,
        provider: HistoricalRewardControlProvider,
        history: RewardControlHistoryReader,
        journal: StandingWeightJournal,
        first: PreparedStandingReward,
        handoff: VerifiedLegacyRewardHandoff | VerifiedStandingRewardHandoff,
        host: BoundStandingRewardHost,
        packages: Callable[[str], CohortRewardPackage],
        decisions: DecisionSource,
        opportunity: Callable[[RewardActivation], Awaitable[VerifiedRewardOpportunity]],
        signer,
        mortality_period: int,
        maximum_history_blocks: int = 64,
        submission_timeout_seconds: float = 120,
    ):
        if (
            type(preparation) is not StandingRewardPreparation
            or not isinstance(provider, HistoricalRewardControlProvider)
            or type(history) is not RewardControlHistoryReader
            or type(journal) is not StandingWeightJournal
            or type(host) is not BoundStandingRewardHost
            or not isinstance(preparation.manifest, StandingRewardOpportunityManifest)
        ):
            raise TypeError("standing execution requires native preparation and proof owners")
        reader = preparation.reader
        config_sha = digest(provider.config)
        if (
            reader.chain_config_sha256 != config_sha
            or digest(provider.policy) != digest(reader.policy)
            or history.config_sha256 != config_sha
            or identity(history.hotkey) != identity(reader.series.control_hotkey)
            or journal.binding["series_sha256"] != preparation.series_sha256
            or journal.binding["chain_config_sha256"] != config_sha
            or journal.binding["validator_account"] != identity(host._approval.validator_hotkey)
            or len(provider.config.proof_rpc_fallback_urls) != 2
        ):
            raise ValueError("standing execution inputs differ from approved context")
        if (
            type(mortality_period) is not int
            or not 4
            <= mortality_period
            <= min(4096, reader.series.maximum_transaction_lifetime_blocks)
            or mortality_period & (mortality_period - 1)
            or type(maximum_history_blocks) is not int
            or not 1 <= maximum_history_blocks <= 4096
            or not math.isfinite(submission_timeout_seconds)
            or not 0 < submission_timeout_seconds <= 3600
        ):
            raise ValueError("standing execution operation bounds are invalid")
        self.preparation, self.provider, self.history = preparation, provider, history
        self.journal, self.first, self.handoff = journal, first, handoff
        self.host = host
        self.packages, self.decisions, self.opportunity = packages, decisions, opportunity
        self.hotkey, self.signer = host._approval.validator_hotkey, signer
        self.prior = (
            handoff.opportunity if type(handoff) is VerifiedStandingRewardHandoff else handoff
        )
        self.period, self.maximum_history_blocks = mortality_period, maximum_history_blocks
        self.timeout = submission_timeout_seconds
        self.transport = BittensorCompetitionWeightTransport(
            endpoint=provider.config.rpc_url,
            fallback_endpoints=tuple(provider.config.proof_rpc_fallback_urls),
        )
        self._prepared = {digest(first.activation): first}
        self._lock = asyncio.Lock()
        self._descriptor = None
        self._series_descriptor = None
        self._writer_path = host.writer_path
        self._series_writer_path = journal.journal.root / "standing-writer.lock"
        self._fence(handoff.through_block, require_writer=False)

    def _fence(self, block: int, *, require_writer: bool = True) -> None:
        self.host.recheck(
            journal=self.journal,
            preparation=self.preparation,
            first=self.first,
            handoff=self.handoff,
        )
        self.preparation._authority()
        self.preparation._check_prepared(self.first)
        if type(self.handoff) is not VerifiedStandingRewardHandoff:
            validate_legacy_handoff(
                self.handoff,
                series=self.preparation.reader.series,
                activation=self.first.activation,
                validator_hotkey=self.hotkey,
                block=block,
            )
        else:
            series = self.preparation.reader.series
            plan = StandingRewardHandoffPlan(
                schema="umi-standing-reward-handoff-plan/1",
                series_sha256=self.preparation.series_sha256,
                cohort_sha256=digest(series.cohorts[0]),
                predecessor=series.predecessor,
            )
            validate_standing_reward_handoff(
                self.handoff,
                plan=plan,
                activation=self.first.activation,
                block=block,
            )
        if require_writer:
            if self._descriptor is None or self._series_descriptor is None:
                raise ValueError("standing executor does not own its writer lock")
            for descriptor, path in (
                (self._descriptor, self._writer_path),
                (self._series_descriptor, self._series_writer_path),
            ):
                held, named = os.fstat(descriptor), path.lstat()
                if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or held.st_nlink != 1:
                    raise ValueError("standing executor writer lock changed")

    @contextmanager
    def hold_writer(self) -> Iterator[None]:
        """Exclude another executor even within the same predecessor handoff scope."""
        if self._descriptor is not None or self._series_descriptor is not None:
            raise ValueError("standing executor already owns its writer lock")
        with ExitStack() as locks:
            descriptor = lock_private_file(self._writer_path)
            locks.callback(os.close, descriptor)
            series_descriptor = lock_private_file(self._series_writer_path)
            locks.callback(os.close, series_descriptor)
            self._descriptor, self._series_descriptor = descriptor, series_descriptor
            try:
                self._fence(self.handoff.through_block)
                yield
            finally:
                self._descriptor = self._series_descriptor = None

    async def _selection(self):
        control = await self.provider.collect_control(self.history.hotkey)
        height = control.snapshot.block_number
        try:
            history = await self.history.verified_prefix(height)
        except ValueError:
            progress = await self.history.advance(
                self.provider, through_block=height, maximum_blocks=self.maximum_history_blocks
            )
            if progress.history is None:
                raise StandingHistoryPending from None
            history = progress.history
        current = await run_owned_thread(
            self.preparation._selected, control, history, self.decisions
        )
        return control, history, current

    async def _context(self, prepared, prior):
        control, history, _ = await self._selection()
        chain = await self.provider.collect_registered_weights(self.hotkey, at=control.snapshot)
        # Export only the native proof owner's observation. Submission success
        # is not a finalized update, and retries must not invent progress.
        logger.info(
            canonical_json_bytes(
                {
                    "schema": "umi-standing-chain-observation/1",
                    "block_number": chain.block,
                    "weight_update_block": chain.validator_last_update,
                }
            ).decode()
        )
        self._fence(chain.block)
        options = dict(
            control=control,
            history=history,
            source=self.decisions,
            chain=chain,
            chain_config=self.provider.config,
            prior_opportunity=prior,
        )
        projection = await self.preparation.project(prepared, **options)
        return options, projection

    async def step(self) -> StandingExecutionProgress:
        async with self._lock:
            self._fence(self.handoff.through_block)
            await run_owned_thread(self.preparation.reader.refresh_reward_adoptions)
            return await self._step()

    @memory_operation
    async def _prepare_package(self, activation, control, history):
        package = await run_owned_thread(self.packages, activation.package_sha256)
        return await self.preparation.prepare(
            package, control=control, history=history, source=self.decisions
        )

    async def _step(self):
        previous = await run_owned_thread(self.journal.pending)
        ended = None
        if previous is not None:
            ended = await resolve_standing_transaction(
                self.provider, self.journal, control_hotkey=self.history.hotkey
            )
            if ended is None:
                return StandingExecutionProgress("transaction_pending", digest(previous.intent))
        control, history, current = await self._selection()
        if current.selection.state != "selected":
            return StandingExecutionProgress("selection_pending")
        if activation_requires_revision(self.preparation.reader, current.selection):
            return StandingExecutionProgress("reward_revision_pending")
        activation = current.selection.activation
        key = digest(activation)
        prepared = self._prepared.get(key)
        if prepared is None:
            prepared = await self._prepare_package(activation, control, history)
            self._prepared[key] = prepared
        first_cohort = prepared.activation == self.first.activation or (
            type(prepared.activation) is RewardActivation
            and type(self.first.activation) is RewardActivation
            and prepared.activation.cohort_sha256 == self.first.activation.cohort_sha256
        )
        early = False
        if not first_cohort:
            reader = self.preparation.reader
            cohorts = tuple(digest(c) for c in reader.series.cohorts)
            index = cohorts.index(prepared.activation.cohort_sha256)
            prefix = await run_owned_thread(retained_reward_decisions, reader)
            original = original_activation_decision(prefix, prepared.activation.cohort_sha256)
            predecessor = effective_activation_decision(
                prefix,
                cohorts[index - 1],
                through_sequence=None if original is None else original.sequence - 1,
            )
            if predecessor is not None:
                early = verify_signed_early_release(
                    reader.reward_adoptions,
                    series=reader.series,
                    policy=reader.policy,
                    manifest=self.preparation.manifest,
                    predecessor=predecessor,
                    successor=prepared.activation,
                    current_block=control.snapshot.block_number,
                )
        prior = (
            getattr(self, "prior", self.handoff)
            if first_cohort
            else None
            if early
            else await self.opportunity(prepared.activation)
        )
        # Slow immutable replay above has no aggregate timeout. Refresh proofs
        # after it instead of throwing its result away and starting over.
        options, projection = await self._context(prepared, prior)
        self._fence(options["chain"].block)
        pending = await self.preparation.reserve_transaction(
            prepared, self.journal, mortality_period=self.period, previous=ended, **options
        )
        if previous is not None and pending.intent == previous.intent:
            raise ValueError("standing executor cannot retransmit a recovered reservation")
        if pending.signed is not None:
            raise ValueError("standing executor cannot replace an existing signature")
        self._fence(options["chain"].block)
        if activation_requires_revision(self.preparation.reader, projection.current.selection):
            raise ValueError("selected reward parameters require a native activation revision")
        chain = options["chain"]
        encoded = await run_owned_thread(
            partial(
                encode_mortal_call,
                pending.intent.call(),
                runtime=chain.runtime,
                signer=self.signer,
                validator_hotkey=self.hotkey,
                nonce=pending.intent.nonce,
                mortality_period=self.period,
                genesis_hash=chain.genesis_hash,
            )
        )
        pending = await self.preparation.retain_signed_transaction(
            prepared, self.journal, encoded, mortality_period=self.period, **options
        )
        fresh, projection = await self._context(prepared, prior)
        _check_transmission(pending, original=chain, fresh=fresh["chain"], projection=projection)
        if await run_owned_thread(self.journal.pending) != pending:
            raise ValueError("standing attempt changed before transmission")
        # Finish host/journal I/O before the final monotonic freshness check.
        # Slow local inspection must not leave an expired proof ready to send.
        self._fence(fresh["chain"].block)
        projection = await self.preparation.project(prepared, **fresh)
        if activation_requires_revision(self.preparation.reader, projection.current.selection):
            raise ValueError("selected reward parameters require a native activation revision")
        _check_transmission(pending, original=chain, fresh=fresh["chain"], projection=projection)
        logger.info("standing_transmission intent_sha256=%s", digest(pending.intent))
        await wait_for_owned(self.transport.submit(encoded, self.signer), timeout=self.timeout)
        # SDK success is not independently proved inclusion, weights or credit.
        # The next iteration always resolves the retained exact transaction.
        return StandingExecutionProgress(
            "submitted_unconfirmed", digest(pending.intent), pending.signed.extrinsic_hash
        )

    async def run(self, stop: asyncio.Event, *, poll_seconds: float = 12) -> None:
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("standing poll interval is outside its host bound")
        weight_wait = None
        with self.hold_writer():
            while not stop.is_set():
                # A dead observer needs a new owner from service startup. A
                # stale but running observer remains an ordinary retry below.
                self.provider.ensure_observer_running()
                delay = poll_seconds
                try:
                    result = await self.step()
                    weight_wait = None
                    logger.info(
                        canonical_json_bytes(
                            {
                                "status": result.status,
                                "intent_sha256": result.intent_sha256,
                                "extrinsic_hash": result.extrinsic_hash,
                            }
                        ).decode()
                    )
                except WeightRateLimitWait as error:
                    # This is scheduling only. Every later attempt recollects
                    # native state and rechecks every signing predicate. Never
                    # cache permission to submit or sleep to a guessed deadline.
                    delay = max(poll_seconds, min(60.0, poll_seconds * 5))
                    now = time.monotonic()
                    if weight_wait is None or weight_wait["target"] != error.next_eligible_block:
                        weight_wait = {
                            "target": error.next_eligible_block,
                            "first": error.observed_block,
                            "last": error.observed_block,
                            "started": now,
                            "changed": now,
                        }
                    if error.observed_block > weight_wait["last"]:
                        weight_wait.update(last=error.observed_block, changed=now)
                    remaining = max(0, error.next_eligible_block - error.observed_block)
                    completed = max(0, error.observed_block - weight_wait["first"])
                    total = max(1, error.next_eligible_block - weight_wait["first"])
                    stalled = now - weight_wait["changed"] >= 60
                    logger.info(
                        canonical_json_bytes(
                            {
                                "schema": "umi-standing-weight-rate-wait/1",
                                "stage": "standing_weight_rate_limit",
                                "status": "stalled" if stalled else "waiting",
                                "reason_code": error.reason_code,
                                "observed_block": error.observed_block,
                                "next_eligible_block": error.next_eligible_block,
                                "remaining_blocks": remaining,
                                "completed_blocks": completed,
                                "total_blocks": total,
                                "percent": 100 * min(completed, total) / total,
                                "elapsed_seconds": now - weight_wait["started"],
                                "eta_seconds": None,
                                "planning_eta_seconds": None
                                if stalled
                                else [remaining * 6, remaining * 24],
                                "eta_basis": "withdrawn_stalled"
                                if stalled
                                else "planning_assumption_6_to_24_seconds_per_block_not_a_deadline",
                                "eta_scope": "current_rate_limit_only_not_rewards_or_opportunity",
                                "retry_after_seconds": delay,
                                "stalled": stalled,
                                "retrying": True,
                            }
                        ).decode()
                    )
                except Exception as error:
                    weight_wait = None
                    # Error text can contain RPC credentials or response data.
                    if isinstance(error, R2EvidenceHTTPError):
                        logger.warning(
                            "standing_retry reason=%s r2_http_status=%d",
                            type(error).__name__,
                            error.status_code,
                        )
                    else:
                        logger.warning("standing_retry reason=%s", type(error).__name__)
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=delay)


def _check_transmission(pending: PendingStandingWeight, *, original, fresh, projection) -> None:
    """Fresh native projection must still permit the original exact call."""
    intent = pending.intent
    row = dict(zip(projection.projection.uids, projection.projection.weights, strict=True))
    if (
        pending.signed is None
        or not intent.block <= fresh.block < intent.block + intent.mortality_period
        or (fresh.block == intent.block and fresh.block_hash != intent.block_hash)
        or fresh.validator_nonce != intent.nonce
        or identity(fresh.validator_hotkey) != identity(intent.validator_hotkey)
        or fresh.chain_config_sha256 != intent.chain_config_sha256
        or fresh.validator_last_update != intent.prior_last_update
        or fresh.weights_version_key != intent.weights_version_key
        or fresh.registered_uid_count != len(intent.destinations)
        or tuple(row.get(uid, 0) for uid in intent.destinations) != intent.weights
        or projection.current.selection.decision_sha256 != intent.decision_sha256
        or digest(projection.prepared.activation) != intent.activation_sha256
        or fresh.runtime.metadata_bytes != original.runtime.metadata_bytes
        or fresh.runtime.runtime_version_bytes != original.runtime.runtime_version_bytes
        or fresh.genesis_hash != original.genesis_hash
    ):
        raise ValueError("standing transaction no longer matches current selection and chain")
    # This rechecks current permit, rate limits and runtime call constraints.
    from_call, current_call = intent.call(), standing_weight_call(projection.projection, fresh)
    if (from_call.module, from_call.function, from_call.params) != (
        current_call.module,
        current_call.function,
        current_call.params,
    ):
        raise ValueError("standing transaction call changed before transmission")
