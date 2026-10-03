"""Recoverable publication of certified standing reward control decisions.

The caller supplies a complete quorum-certified prefix and retained delivery
files. This core does not provision a wallet, install a service, or establish
remote artifact availability. The installed host must qualify those boundaries
and keep this reserved hotkey exclusive across host migrations.
"""

from __future__ import annotations

import asyncio
import logging
import math
import os
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from functools import partial

from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_journal import (
    PendingControlTransaction,
    RewardControlTransactionJournal,
    check_control_transaction,
    verify_control_transaction_bytes,
)
from .competition_reward_control_signing import (
    RewardControlSigningState,
    collect_control_signing_state,
    review_control_signing_state,
    validate_control_signing_state,
)
from .competition_reward_decisions import (
    SignedRewardControlDecision,
    StandingRewardControlReader,
    verify_reward_decisions,
)
from .competition_reward_files import StandingRewardFiles
from .competition_reward_history import RewardControlHistoryReader, validate_control_history
from .competition_weights import BittensorCompetitionWeightTransport
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .private_files import lock_private_file
from .protocol import canonical_json_bytes
from .signed_extrinsic import encode_mortal_call

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ControlPublicationProgress:
    status: str
    decision_sha256: str
    intent_sha256: str | None = None
    extrinsic_hash: str | None = None


class _HistoryPending(Exception):
    pass


class StandingControlPublisher:
    def __init__(
        self,
        *,
        reader: StandingRewardControlReader,
        provider: HistoricalRewardControlProvider,
        history: RewardControlHistoryReader,
        journal: RewardControlTransactionJournal,
        files: StandingRewardFiles,
        signer,
        mortality_period: int,
        maximum_history_blocks: int = 64,
        submission_timeout_seconds: float = 120,
    ):
        if (
            type(reader) is not StandingRewardControlReader
            or not isinstance(provider, HistoricalRewardControlProvider)
            or type(history) is not RewardControlHistoryReader
            or type(journal) is not RewardControlTransactionJournal
            or type(files) is not StandingRewardFiles
        ):
            raise TypeError("control publication requires native proof and journal owners")
        series, config = reader.series, digest(provider.config)
        if (
            reader.chain_config_sha256 != config
            or reader.admission_chain_config_sha256 != config
            or digest(reader.policy) != digest(provider.policy)
            or history.config_sha256 != config
            or journal.config_sha256 != config
            or history.first_block != series.recovery.authority.issued_at_block
            or identity(history.hotkey) != identity(series.control_hotkey)
            or digest(journal.series) != digest(series)
            or identity(signer.ss58_address) != identity(series.control_hotkey)
            or len(provider.config.proof_rpc_fallback_urls) != 2
        ):
            raise ValueError("control publication inputs differ from approved context")
        if (
            type(mortality_period) is not int
            or not 4 <= mortality_period <= min(4096, series.maximum_transaction_lifetime_blocks)
            or mortality_period & (mortality_period - 1)
            or type(maximum_history_blocks) is not int
            or not 1 <= maximum_history_blocks <= 4096
            or not math.isfinite(submission_timeout_seconds)
            or not 0 < submission_timeout_seconds <= 3600
        ):
            raise ValueError("control publication operation bounds are invalid")
        self.reader, self.provider, self.history = reader, provider, history
        self.journal, self.files, self.signer = journal, files, signer
        self.series, self.hotkey, self.config_sha256 = series, series.control_hotkey, config
        self.period, self.maximum_history_blocks = mortality_period, maximum_history_blocks
        self.timeout = submission_timeout_seconds
        self.transport = BittensorCompetitionWeightTransport(
            endpoint=provider.config.rpc_url,
            fallback_endpoints=tuple(provider.config.proof_rpc_fallback_urls),
        )
        self._lock = asyncio.Lock()
        self._descriptor = None
        self._writer_path = journal.journal.root / "control-writer.lock"

    def _writer(self):
        if self._descriptor is None:
            raise ValueError("control publisher does not own its writer lock")
        held, named = os.fstat(self._descriptor), self._writer_path.lstat()
        if (held.st_dev, held.st_ino) != (named.st_dev, named.st_ino) or held.st_nlink != 1:
            raise ValueError("control publisher writer lock changed")

    @contextmanager
    def hold_writer(self) -> Iterator[None]:
        if self._descriptor is not None:
            raise ValueError("control publisher already owns its writer lock")
        self._descriptor = lock_private_file(self._writer_path)
        try:
            self._writer()
            yield
        finally:
            descriptor, self._descriptor = self._descriptor, None
            os.close(descriptor)

    def _delivered(self, prefix):
        """Check local readback, not independent remote availability or replay."""
        for item in prefix:
            saved = SignedRewardControlDecision.model_validate_json(
                self.files.decision(digest(item.decision))
            )
            if saved != item:
                raise ValueError("control decision lacks its exact retained delivery")
            activation = item.decision.activation
            if activation is not None:
                package = self.files.package(activation.package_sha256)
                if digest(package.allocation) != activation.allocation_sha256:
                    raise ValueError("delivered package differs from control allocation")

    async def _observed(self, prefix):
        state = await collect_control_signing_state(self.provider, self.hotkey)
        control, height = state.control, state.control.snapshot.block_number
        try:
            history = await self.history.verified_prefix(height)
        except ValueError:
            progress = await self.history.advance(
                self.provider,
                through_block=height,
                maximum_blocks=self.maximum_history_blocks,
            )
            if progress.history is None:
                raise _HistoryPending from None
            history = progress.history
        validate_control_history(
            history,
            first_block=self.series.recovery.authority.issued_at_block,
            tip=control.snapshot,
            control_hotkey=self.hotkey,
            chain_config_sha256=self.config_sha256,
        )
        predecessor = (
            None if self.series.predecessor is None else self.series.predecessor.decision_sha256
        )
        if control.control_sha256 == predecessor:
            if history.writes or history.unresolved_blocks:
                raise ValueError("reserved control slot has prior or unresolved successor writes")
            selected = -1
        else:
            if control.control_sha256 is None:
                raise ValueError("current control is outside the proposed certified prefix")
            selected = next(
                (
                    i
                    for i, item in enumerate(prefix)
                    if digest(item.decision) == control.control_sha256
                ),
                None,
            )
            if selected is None:
                raise ValueError("current control is outside the proposed certified prefix")
            await run_owned_thread(
                self.reader.select_history,
                control,
                self.files.decision,
                history,
            )
        validate_control_signing_state(state, hotkey=self.hotkey, config_sha256=self.config_sha256)
        return state, selected

    async def _recover(self, pending, prefix):
        intent = pending.intent
        sequence = intent.decision.decision.sequence
        if sequence >= len(prefix) or intent.decision.decision != prefix[sequence].decision:
            raise ValueError("pending control transaction conflicts with selected prefix")
        # Quorum and original proofs are checked even after the era expired.
        verify_reward_decisions(
            self.series, self.reader.policy, (*prefix[:sequence], intent.decision)
        )
        original = await review_control_signing_state(
            self.provider,
            hotkey=self.hotkey,
            control_evidence=self.journal.object(intent.control_evidence_sha256),
            nonce_evidence=self.journal.object(intent.nonce_evidence_sha256),
            metadata=self.journal.object(intent.metadata_sha256),
        )
        check_control_transaction(intent, original, self.series)
        if pending.signed is not None:
            await run_owned_thread(
                verify_control_transaction_bytes,
                intent,
                bytes.fromhex(pending.signed.encoded),
                original,
                self.series,
            )

    async def step(self, decisions: tuple[SignedRewardControlDecision, ...]):
        # Drain cancellation through signing/persistence/submit cleanup before
        # releasing either process or task ownership. RPC operations are bounded.
        async with self._lock:
            self._writer()
            return await await_owned_task(asyncio.create_task(self._step(decisions)))

    async def _step(self, decisions):
        prefix = verify_reward_decisions(self.series, self.reader.policy, decisions)
        wanted = digest(prefix[-1].decision)
        await run_owned_thread(self._delivered, prefix)
        pending = await run_owned_thread(self.journal.pending)
        if pending is not None:
            await self._recover(pending, prefix)
        try:
            state, selected = await self._observed(prefix)
        except _HistoryPending:
            return ControlPublicationProgress("history_pending", wanted)
        if pending is not None:
            intent = pending.intent
            if state.nonce < intent.nonce or state.control.snapshot.block_number < intent.block:
                raise ValueError("control transaction recovery rolled back its signing context")
            if (
                state.nonce == intent.nonce
                and state.control.snapshot.block_number < intent.block + intent.mortality_period
            ):
                return ControlPublicationProgress("transaction_pending", wanted, digest(intent))
        if selected == len(prefix) - 1:
            return ControlPublicationProgress("control_finalized", wanted)
        if selected != len(prefix) - 2:
            raise ValueError(
                "control publication must anchor each predecessor before its successor"
            )
        candidate = prefix[-1]
        # Initial authority must be admitted before intake opens. Standing
        # successors have no cohort expiry; transaction eras remain bounded.
        if candidate.decision.kind == "admit_series" and (
            state.control.snapshot.block_number + self.period - 1
            > self.reader.policy.valid_through_block
        ):
            raise ValueError("initial control transaction exceeds admission validity")
        pending = await run_owned_thread(
            partial(
                self.journal.reserve,
                candidate,
                state,
                mortality_period=self.period,
            )
        )
        encoded = await run_owned_thread(
            partial(
                encode_mortal_call,
                pending.intent.call(),
                runtime=state.runtime,
                signer=self.signer,
                validator_hotkey=self.hotkey,
                nonce=pending.intent.nonce,
                mortality_period=pending.intent.mortality_period,
                genesis_hash="0x" + self.series.genesis_hash,
            )
        )
        pending = await run_owned_thread(self.journal.retain_signed, pending.intent, encoded, state)
        try:
            fresh, current = await self._observed(prefix)
        except _HistoryPending:
            return ControlPublicationProgress("history_pending", wanted, digest(pending.intent))
        if current != selected:
            raise ValueError("control predecessor changed before transmission")
        check_control_transmission(
            pending, original=state, fresh=fresh, config=self.config_sha256, hotkey=self.hotkey
        )
        if await run_owned_thread(self.journal.pending) != pending:
            raise ValueError("control transaction changed before transmission")
        self._writer()
        validate_control_signing_state(fresh, hotkey=self.hotkey, config_sha256=self.config_sha256)
        logger.info(
            "control_transmission sequence=%s intent_sha256=%s",
            candidate.decision.sequence,
            digest(pending.intent),
        )
        await wait_for_owned(self.transport.submit(encoded, self.signer), timeout=self.timeout)
        return ControlPublicationProgress(
            "submitted_unconfirmed",
            wanted,
            digest(pending.intent),
            pending.signed.extrinsic_hash,
        )

    async def run(
        self,
        stop: asyncio.Event,
        decisions: Callable[[], tuple[SignedRewardControlDecision, ...]],
        *,
        poll_seconds: float = 12,
    ) -> None:
        """Retry bounded steps without extending or discarding cohort authority."""
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("control poll interval is outside its host bound")
        with self.hold_writer():
            while not stop.is_set():
                self.provider.ensure_observer_running()
                try:
                    prefix = await run_owned_thread(decisions)
                    result = await self.step(prefix)
                    logger.info(
                        canonical_json_bytes(
                            {
                                "status": result.status,
                                "decision_sha256": result.decision_sha256,
                                "intent_sha256": result.intent_sha256,
                                "extrinsic_hash": result.extrinsic_hash,
                            }
                        ).decode()
                    )
                except Exception as error:
                    # Remote errors can contain credentials or protected data.
                    logger.warning("control_retry reason=%s", type(error).__name__)
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_seconds)


def check_control_transmission(
    pending: PendingControlTransaction,
    *,
    original: RewardControlSigningState,
    fresh: RewardControlSigningState,
    config: str,
    hotkey: str,
) -> None:
    validate_control_signing_state(fresh, hotkey=hotkey, config_sha256=config)
    intent, ref = pending.intent, fresh.control.snapshot
    if (
        pending.signed is None
        or not intent.block <= ref.block_number < intent.block + intent.mortality_period
        or (ref.block_number == intent.block and ref.block_hash != intent.block_hash)
        or fresh.nonce != intent.nonce
        or fresh.control.control_sha256 != intent.decision.decision.predecessor_sha256
        or fresh.runtime.metadata_bytes != original.runtime.metadata_bytes
        or fresh.runtime.runtime_version_bytes != original.runtime.runtime_version_bytes
    ):
        raise ValueError("control transaction no longer matches the current predecessor and nonce")
