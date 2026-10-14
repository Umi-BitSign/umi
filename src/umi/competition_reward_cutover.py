"""Native no-signing reconciliation of stopped coordinator economic state.

Every result is diagnostic. Native ordinary startup must recheck fresh control,
writer ownership and transactions before it can sign or publish anything.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import asdict
from typing import TYPE_CHECKING

from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_journal import (
    RewardControlTransactionJournal,
    check_control_transaction,
    verify_control_transaction_bytes,
)
from .competition_reward_control_signing import (
    collect_control_signing_state,
    review_control_signing_state,
    validate_control_signing_state,
)
from .competition_reward_cutover_ownership import RewardCutoverLease
from .competition_reward_decisions import (
    SignedRewardControlDecision,
    StandingRewardControlReader,
    verify_reward_decisions,
)
from .competition_reward_files import StandingRewardFiles
from .competition_reward_history import RewardControlHistoryReader, validate_control_history
from .competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from .competition_reward_signing import RewardDecisionJournal
from .competition_round_journal import RoundJournal
from .concurrency import run_owned_thread
from .finalized_ancestry import MAXIMUM_HEADER_BYTES
from .grandpa_finality import _decode_header
from .historical_header_recovery import (
    HistoricalHeaderRecoveryPending,
    HistoricalHeaderRecoveryProgress,
)
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from .competition_reward_coordinator_boot import RewardCoordinatorConfig


def retained_decisions(journal: RewardDecisionJournal):
    """Verify every retained local intent, certificate and vote without changing it."""
    with journal.journal.locked():
        keys = journal.journal.keys("reward_certificate")
        if keys != [f"{i:04d}" for i in range(len(keys))]:
            raise ValueError("cutover certificate slots are not contiguous")
        prefix = journal.prefix(len(keys))
        intents, votes = [], set()
        for key in journal.journal.keys("reward_intent"):
            if not key.isascii() or not key.isdecimal() or key != f"{int(key):04d}":
                raise ValueError("cutover intent slot is invalid")
            intent = journal.load(int(key))
            if intent is None:
                raise ValueError("cutover lost a retained intent")
            if (
                intent.decision.sequence < len(prefix)
                and intent.decision != prefix[intent.decision.sequence].decision
            ):
                raise ValueError("cutover intent conflicts with its retained certificate")
            intents.append(intent)
            for account, evaluator in journal.reviewers.items():
                if journal.vote(intent.decision.sequence, evaluator.hotkey) is not None:
                    votes.add(journal._vote_key(key, account))
        if set(journal.journal.keys("reward_vote")) != votes:
            raise ValueError("cutover has an orphan or unauthorized retained vote")
        return prefix, tuple(intents)


def _pending_status(pending, state, history):
    if pending is None:
        return "absent"
    intent = pending.intent
    height = state.control.snapshot.block_number
    if state.nonce < intent.nonce or height < intent.block:
        raise ValueError("cutover control transaction context rolled back")
    if state.nonce == intent.nonce and height < intent.block + intent.mortality_period:
        return "live_original_attempt"
    if any(w.decision_sha256 == digest(intent.decision.decision) for w in history.writes):
        return "decision_present_in_verified_ordered_history"
    return "era_or_nonce_fenced_outcome_unknown"


def _decision(cohort, prefix, intents, chain_prefix, pending_state):
    finalized = [
        s.decision
        for s in chain_prefix
        if s.decision.activation is not None and s.decision.activation.cohort_sha256 == cohort
    ]
    reserved = [
        b
        for b in (*[s.decision for s in prefix], *[i.decision for i in intents])
        if b.activation is not None and b.activation.cohort_sha256 == cohort
    ]
    if chain_prefix and chain_prefix[-1].decision.kind == "revoke":
        action = "series_revoked_preserve_state"
    elif pending_state == "live_original_attempt":
        action = "wait_for_original_pending_control"
    elif finalized:
        action = "existing_activation_requires_native_revision_or_live_lock_review"
    elif reserved:
        action = "preserve_reserved_activation_before_native_revision"
    else:
        action = "first_activation_may_select_adoption_on_next_native_review"
    return (
        action,
        tuple(dict.fromkeys(digest(b) for b in reserved)),
        tuple(dict.fromkeys(digest(b) for b in finalized)),
    )


class NativeRewardCutoverReview:
    def __init__(
        self,
        *,
        config: RewardCoordinatorConfig,
        lease: RewardCutoverLease,
        provider: HistoricalRewardControlProvider,
        history: RewardControlHistoryReader,
        reader: StandingRewardControlReader,
        decisions: RewardDecisionJournal,
        transactions: RewardControlTransactionJournal,
        files: StandingRewardFiles,
        operation: str,
    ):
        if (
            type(lease) is not RewardCutoverLease
            or not isinstance(provider, HistoricalRewardControlProvider)
            or type(history) is not RewardControlHistoryReader
            or type(reader) is not StandingRewardControlReader
            or type(decisions) is not RewardDecisionJournal
            or type(transactions) is not RewardControlTransactionJournal
            or type(files) is not StandingRewardFiles
        ):
            raise TypeError("cutover requires genuine native owners")
        lease.recheck(config)
        root, chain = lease.root, digest(config.chain)
        if (
            digest(provider.config) != chain
            or digest(provider.policy) != digest(config.policy)
            or history.journal.root != root / "history"
            or reader.journal.root != root / "control"
            or decisions.journal.root != root / "decisions"
            or transactions.journal.root != root / "transactions"
            or history.config_sha256 != chain
            or history.first_block != config.series.recovery.authority.issued_at_block
            or identity(history.hotkey) != identity(config.series.control_hotkey)
            or reader.chain_config_sha256 != chain
            or reader.admission_chain_config_sha256 != chain
            or decisions.chain_config_sha256 != chain
            or transactions.config_sha256 != chain
            or digest(reader.series) != digest(config.series)
            or digest(reader.policy) != digest(config.policy)
            or digest(decisions.series) != digest(config.series)
            or digest(decisions.policy) != digest(config.policy)
            or decisions.signer != identity(config.signer_hotkey)
            or digest(transactions.series) != digest(config.series)
            or str(files.root) != config.files_directory
            or reader.reward_adoptions != config.reward_adoptions
            or decisions.reward_adoptions != config.reward_adoptions
        ):
            raise ValueError("cutover changes selected native state bindings")
        if (
            not operation
            or len(operation) > 128
            or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in operation)
        ):
            raise ValueError("cutover needs a bounded explicit operation name")
        self.config, self.lease, self.provider = config, lease, provider
        self.history, self.reader = history, reader
        self.decisions, self.transactions, self.files = decisions, transactions, files
        self.operation = operation
        self._recovery_started = time.monotonic()
        self.targets = RoundJournal(
            root / "cutover-reconciliation" / operation,
            {
                "schema": "umi-standing-reward-cutover-target/1",
                "config": digest(config),
                "series": digest(config.series),
                "chain": chain,
            },
            maximum_bytes=config.service.maximum_journal_bytes,
        )

    def _target(self, cohort, state=None):
        with self.targets.locked():
            key = digest(["cutover-target", cohort])
            values = self.targets.keys(key)
            selected = None
            for position, name in enumerate(values):
                if name != f"{position:08d}":
                    raise HistoryCheckpointRepairRequired("cutover target lineage is damaged")
                value = self.targets.get(key, name)
                if (
                    type(value) is not dict
                    or set(value) != {"height", "block_hash"}
                    or type(value["height"]) is not int
                    or value["height"] < self.history.first_block
                    or type(value["block_hash"]) is not str
                    or len(value["block_hash"]) != 66
                    or not value["block_hash"].startswith("0x")
                    or any(c not in "0123456789abcdef" for c in value["block_hash"][2:])
                    or (selected is not None and value["height"] <= selected["height"])
                ):
                    raise HistoryCheckpointRepairRequired("cutover target binding is damaged")
                selected = value
            if state is None:
                return selected
            ref = state.control.snapshot
            value = {"height": ref.block_number, "block_hash": ref.block_hash}
            if selected is not None:
                if value["height"] < selected["height"] or (
                    value["height"] == selected["height"] and value != selected
                ):
                    raise ValueError("cutover target finality changed or rolled back")
                if value == selected:
                    return selected
            self.targets.put(key, f"{len(values):08d}", value)
            return value

    async def _recover(self, pending, prefix):
        if pending is None:
            return
        intent = pending.intent
        sequence = intent.decision.decision.sequence
        if sequence >= len(prefix) or intent.decision.decision != prefix[sequence].decision:
            raise ValueError("cutover pending transaction conflicts with certified prefix")
        verify_reward_decisions(
            self.config.series,
            self.config.policy,
            (*prefix[:sequence], intent.decision),
            reward_adoptions=self.config.reward_adoptions,
        )
        original = await review_control_signing_state(
            self.provider,
            hotkey=self.config.series.control_hotkey,
            control_evidence=self.transactions.object(intent.control_evidence_sha256),
            nonce_evidence=self.transactions.object(intent.nonce_evidence_sha256),
            metadata=self.transactions.object(intent.metadata_sha256),
        )
        check_control_transaction(intent, original, self.config.series)
        if pending.signed is not None:
            await run_owned_thread(
                verify_control_transaction_bytes,
                intent,
                bytes.fromhex(pending.signed.encoded),
                original,
                self.config.series,
            )

    async def _advance_target(self, height: int):
        # advance() bounds ordered applications, including cheap restored
        # checkpoints. A one-step CLI must drain that durable prefix before
        # returning, or every restart would restore the same first batch and
        # never reach new work. Keep native application and finality checks;
        # never assign the reader's cursor or manufacture an owned history.
        previous = None
        while True:
            before = (
                self.history.progress.native_completed
                if self.history.progress.target == height
                else 0
            )
            result = await self.history.advance(
                self.provider,
                through_block=height,
                maximum_blocks=self.config.service.maximum_history_blocks,
            )
            if result.history is not None or self.history.progress.native_completed > before:
                return result
            if previous is not None and result.next_block <= previous:
                raise ValueError("cutover checkpoint restoration stopped advancing")
            previous = result.next_block

    async def step(self, cohort: str):
        if cohort not in {digest(c) for c in self.config.series.cohorts}:
            raise ValueError("cutover cohort is outside the selected series")
        started, completed = time.monotonic(), 0

        def report(state, **fields):
            elapsed = time.monotonic() - started
            logger.info(
                json.dumps(
                    {
                        "stage": "stopped_reward_cutover_reconciliation",
                        "state": state,
                        "completed_items": completed,
                        "total_items": 5,
                        "percent": completed * 20,
                        "elapsed_seconds": elapsed,
                        "eta_seconds": 0 if state == "completed" else None,
                        "planning_eta_seconds": [1, 300]
                        if state == "running" and elapsed <= 300
                        else None,
                        "eta_basis": "bounded batch; native history reports measured tail ETA",
                        "eta_scope": "reconciliation_not_reward_activation",
                        "retrying": state == "retrying",
                        "stalled": state == "stalled",
                        **fields,
                    }
                )
            )

        loop, timer = asyncio.get_running_loop(), None
        last_progress, changed_at = None, started

        def heartbeat():
            nonlocal timer, last_progress, changed_at
            latest = self.history.progress.latest or {}
            current = (
                completed,
                latest.get("applied_blocks"),
                latest.get("verified_blocks"),
                latest.get("replicated_blocks"),
            )
            if current != last_progress:
                last_progress, changed_at = current, time.monotonic()
            report("stalled" if time.monotonic() - changed_at > 300 else "running")
            timer = loop.call_later(30, heartbeat)

        timer = loop.call_later(30, heartbeat)
        report("running")
        try:
            self.lease.recheck(self.config)
            prefix, intents = await run_owned_thread(retained_decisions, self.decisions)
            completed = 1
            report("running")
            pending = await run_owned_thread(self.transactions.pending)
            await self._recover(pending, prefix)
            completed = 2
            report("running")
            target = await run_owned_thread(self._target, cohort)
            state = None
            if target is None:
                state = await collect_control_signing_state(
                    self.provider, self.config.series.control_hotkey
                )
                target = await run_owned_thread(self._target, cohort, state)
            completed = 3
            report("running", target_block=target["height"])
            progress = await self._advance_target(target["height"])
            if progress.history is None:
                report("pending", target_block=target["height"], next_block=progress.next_block)
                return self._pending_result(target, progress.next_block)
            if progress.history.tip.block_hash != target["block_hash"]:
                raise ValueError("cutover completed history changed selected finalized target")
            # A persisted target fixes slow first-pass work. It never supplies
            # fresh signing-state authority after restart. Catch the final tail
            # to a genuinely current snapshot with one further bounded batch.
            state = await collect_control_signing_state(
                self.provider, self.config.series.control_hotkey
            )
            fresh = await run_owned_thread(self._target, cohort, state)
            if fresh != target:
                progress = await self._advance_target(fresh["height"])
                if progress.history is None:
                    report("pending", target_block=fresh["height"], next_block=progress.next_block)
                    return self._pending_result(fresh, progress.next_block)
            history = progress.history
            validate_control_history(
                history,
                first_block=self.config.series.recovery.authority.issued_at_block,
                tip=state.control.snapshot,
                control_hotkey=self.config.series.control_hotkey,
                chain_config_sha256=digest(self.config.chain),
            )
            if history.unresolved_blocks:
                raise ValueError("cutover has unresolved ordered control writes")
            if time.monotonic_ns() > state.control.expires_monotonic_ns:
                report("retrying", reason="fresh_control_expired_during_history_tail")
                return {
                    **self._pending_result(fresh, progress.next_block),
                    "status": "refresh_required",
                }
            completed = 4
            report("running")
            selection, chain_prefix = await run_owned_thread(
                self._select_history, state, history, prefix
            )
            status = _pending_status(pending, state, history)
            action, reserved, finalized = _decision(cohort, prefix, intents, chain_prefix, status)
            # All mutable owners and the fresh proof must still be the exact
            # ones just reviewed when the diagnostic decision leaves this call.
            if await run_owned_thread(retained_decisions, self.decisions) != (prefix, intents):
                raise ValueError("cutover local decisions changed during review")
            if await run_owned_thread(self.transactions.pending) != pending:
                raise ValueError("cutover pending transaction changed during review")
            if time.monotonic_ns() > state.control.expires_monotonic_ns:
                report("retrying", reason="fresh_control_expired_during_decision_review")
                return {
                    **self._pending_result(fresh, progress.next_block),
                    "status": "refresh_required",
                }
            validate_control_signing_state(
                state,
                hotkey=self.config.series.control_hotkey,
                config_sha256=digest(self.config.chain),
            )
            self.lease.recheck(self.config)
            completed = 5
            report("completed")
            return {
                "schema": "umi-standing-reward-cutover-review/1",
                "status": "reconciled",
                "cohort_sha256": cohort,
                "series_sha256": digest(self.config.series),
                "cutover_decision": action,
                "pending_control_status": status,
                "pending_control_sha256": None if pending is None else digest(pending.intent),
                "pending_signed_bytes_retained": pending is not None and pending.signed is not None,
                "reserved_activation_decisions": reserved,
                "finalized_activation_decisions": finalized,
                "local_certified_decisions": len(prefix),
                "local_retained_intents": len(intents),
                "finalized_control_decisions": len(chain_prefix),
                "control_selection": None if selection is None else asdict(selection.selection),
                "effective_selection": None
                if selection is None or selection.effective_selection is None
                else asdict(selection.effective_selection),
                "initial_selection": None
                if selection is None or selection.initial_selection is None
                else asdict(selection.initial_selection),
                "history_first_block": history.first_block,
                "history_through_block": history.tip.block_number,
                "history_evidence_sha256": history.evidence_sha256,
                "control_evidence_sha256": state.control.evidence_sha256,
                "signed_delay_blocks": self.config.series.maximum_proof_lag_blocks
                + self.config.series.maximum_transaction_lifetime_blocks,
                "publication_authorized": False,
                "writer_reconciliation_required": True,
                "live_reward_row_checked": False,
                "native_startup_recheck_required": True,
            }
        except HistoricalHeaderRecoveryPending as error:
            self.lease.recheck(self.config)
            continued = isinstance(error, HistoricalHeaderRecoveryProgress)
            details = self._recovery_progress()
            if not continued:
                details.update(
                    recovery_eta_seconds=None,
                    recovery_eta_basis="capacity_repair_pending_no_completion_estimate",
                )
            report("pending" if continued else "retrying", **details)
            return {
                "schema": "umi-standing-reward-cutover-review/1",
                "status": "historical_recovery_progress"
                if continued
                else "historical_recovery_pending",
                "cutover_decision": "keep_stopped_and_resume_same_operation",
                "publication_authorized": False,
                "capacity_repair_required": not continued,
                "native_startup_recheck_required": True,
                **details,
            }
        except asyncio.CancelledError:
            report("interrupted")
            raise
        except Exception as error:
            report("repair_required", error_type=type(error).__name__)
            raise
        finally:
            if timer is not None:
                timer.cancel()

    def _recovery_progress(self):
        """Expose the native cursor as telemetry, never as verified authority."""
        recovery = self.provider._historical_headers
        elapsed = time.monotonic() - self._recovery_started
        base = {
            "recovery_elapsed_seconds": elapsed,
            "recovery_eta_seconds": None,
            "recovery_eta_basis": "waiting_for_native_ancestry_cursor",
            "recovery_eta_scope": "historical_header_recovery_only",
        }
        if not recovery.progress or recovery._anchor is None:
            return base
        (_, target), raw = next(reversed(recovery.progress.items()))
        anchor = _decode_header(recovery._anchor[1], maximum_bytes=MAXIMUM_HEADER_BYTES)["number"]
        current = _decode_header(raw, maximum_bytes=MAXIMUM_HEADER_BYTES)["number"]
        completed, total = anchor - current, anchor - target
        rate = completed / elapsed if elapsed and completed else None
        return {
            **base,
            "recovery_completed_headers": completed,
            "recovery_total_headers": total,
            "recovery_percent": 100 * completed / total if total else 100,
            "recovery_eta_seconds": (total - completed) / rate if rate else None,
            "recovery_eta_basis": "measured_native_ancestry_headers_per_second"
            if rate
            else "waiting_for_native_ancestry_samples",
        }

    def _pending_result(self, target, next_block):
        self.lease.recheck(self.config)
        return {
            "schema": "umi-standing-reward-cutover-review/1",
            "status": "history_pending",
            "cutover_decision": "keep_stopped_and_resume_same_operation",
            "target_block": target["height"],
            "next_block": next_block,
            "publication_authorized": False,
            "native_startup_recheck_required": True,
        }

    def _select_history(self, state, history, local_prefix):
        if state.control.control_sha256 is None:
            if history.writes or self.reader.journal.keys("reward_control_decision"):
                raise ValueError("empty control slot conflicts with retained or ordered history")
            return None, ()
        local = {digest(s.decision): s for s in local_prefix}

        def source(key):
            if key in local:
                return canonical_json_bytes(local[key])
            return self.files.decision(key)

        selection = self.reader.select_history(state.control, source, history)
        with self.reader.journal.locked():
            values = tuple(
                SignedRewardControlDecision.model_validate_json(
                    canonical_json_bytes(
                        self.reader.journal.get("reward_control_decision", f"{i:04d}")
                    )
                )
                for i in range(selection.selection.sequence + 1)
            )
        values = verify_reward_decisions(
            self.config.series,
            self.config.policy,
            values,
            reward_adoptions=self.config.reward_adoptions,
        )
        for old, new in zip(local_prefix, values, strict=False):
            if old.decision != new.decision:
                raise ValueError("finalized control differs from immutable local certificate")
        return selection, values
