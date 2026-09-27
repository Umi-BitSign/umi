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
from collections.abc import Awaitable, Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import partial

from .competition_cohort_reward_package import CohortRewardPackage
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_decisions import DecisionSource, RewardActivation
from .competition_reward_handoff_models import VerifiedLegacyRewardHandoff, validate_legacy_handoff
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_manifest import StandingRewardOpportunityManifest
from .competition_reward_opportunity import VerifiedRewardOpportunity
from .competition_reward_preparation import PreparedStandingReward, StandingRewardPreparation
from .competition_reward_transaction_outcome import resolve_standing_transaction
from .competition_reward_transactions import (
    PendingStandingWeight,
    StandingWeightJournal,
    standing_weight_call,
)
from .competition_weights import BittensorCompetitionWeightTransport
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .private_files import lock_private_file
from .protocol import canonical_json_bytes
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
        handoff: VerifiedLegacyRewardHandoff,
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
            or journal.binding["validator_account"] != identity(handoff.intent.validator_hotkey)
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
        self.packages, self.decisions, self.opportunity = packages, decisions, opportunity
        self.hotkey, self.signer = handoff.intent.validator_hotkey, signer
        self.period, self.maximum_history_blocks = mortality_period, maximum_history_blocks
        self.timeout = submission_timeout_seconds
        self.transport = BittensorCompetitionWeightTransport(
            endpoint=provider.config.rpc_url,
            fallback_endpoints=tuple(provider.config.proof_rpc_fallback_urls),
        )
        self._prepared = {digest(first.activation): first}
        self._lock = asyncio.Lock()
        self._descriptor = None
        self._writer_path = journal.journal.root / "standing-writer.lock"
        self._fence(handoff.through_block, require_writer=False)

    def _fence(self, block: int, *, require_writer: bool = True) -> None:
        self.preparation._authority()
        self.preparation._check_prepared(self.first)
        validate_legacy_handoff(
            self.handoff,
            series=self.preparation.reader.series,
            activation=self.first.activation,
            validator_hotkey=self.hotkey,
            block=block,
        )
        if require_writer:
            if self._descriptor is None:
                raise ValueError("standing executor does not own its writer lock")
            held, named = os.fstat(self._descriptor), self._writer_path.lstat()
            if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or held.st_nlink != 1:
                raise ValueError("standing executor writer lock changed")

    @contextmanager
    def hold_writer(self) -> Iterator[None]:
        """Exclude another executor even within the same legacy handoff scope."""
        if self._descriptor is not None:
            raise ValueError("standing executor already owns its writer lock")
        descriptor = lock_private_file(self._writer_path)
        self._descriptor = descriptor
        try:
            self._fence(self.handoff.through_block)
            yield
        finally:
            self._descriptor = None
            os.close(descriptor)

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
            return await self._step()

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
        activation = current.selection.activation
        key = digest(activation)
        prepared = self._prepared.get(key)
        if prepared is None:
            package = await run_owned_thread(self.packages, activation.package_sha256)
            prepared = await self.preparation.prepare(
                package, control=control, history=history, source=self.decisions
            )
            self._prepared[key] = prepared
        prior = (
            self.handoff
            if prepared.activation == self.first.activation
            else await self.opportunity(prepared.activation)
        )
        # Slow immutable replay above has no aggregate timeout. Refresh proofs
        # after it instead of throwing its result away and starting over.
        options, _ = await self._context(prepared, prior)
        self._fence(options["chain"].block)
        pending = await self.preparation.reserve_transaction(
            prepared, self.journal, mortality_period=self.period, previous=ended, **options
        )
        if previous is not None and pending.intent == previous.intent:
            raise ValueError("standing executor cannot retransmit a recovered reservation")
        if pending.signed is not None:
            raise ValueError("standing executor cannot replace an existing signature")
        self._fence(options["chain"].block)
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
        # Recheck monotonic proof freshness after the journal read. No signing,
        # storage or unbounded replay follows this last authorization check.
        projection = await self.preparation.project(prepared, **fresh)
        _check_transmission(pending, original=chain, fresh=fresh["chain"], projection=projection)
        self._fence(fresh["chain"].block)
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
        with self.hold_writer():
            while not stop.is_set():
                try:
                    result = await self.step()
                    logger.info(
                        canonical_json_bytes(
                            {
                                "status": result.status,
                                "intent_sha256": result.intent_sha256,
                                "extrinsic_hash": result.extrinsic_hash,
                            }
                        ).decode()
                    )
                except Exception as error:
                    # Error text can contain RPC credentials or response data.
                    logger.warning("standing_retry reason=%s", type(error).__name__)
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_seconds)


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
