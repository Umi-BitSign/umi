"""Resolve standing weight attempts without renewing a coordinator lease.

Expiry is enough to fence the original bytes; it is not evidence that they
failed or never landed. Fresh reward selection, recipient/nonce proofs and the
single writer must still authorize every subsequent transmission.
"""

import logging
import time
from dataclasses import asdict

from .chain_evidence import FinalizedSnapshotRef
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_transaction_recovery import review_standing_transaction
from .competition_reward_transactions import (
    StandingTransactionEnd,
    StandingWeightJournal,
    _issue_standing_end,
)
from .concurrency import run_owned_thread
from .mortal_receipts import MortalReceiptReader, VerifiedMortalReceipt
from .open_competition import digest
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


async def resolve_standing_transaction(
    provider: HistoricalRewardControlProvider,
    journal: StandingWeightJournal,
    *,
    control_hotkey: str,
) -> StandingTransactionEnd | None:
    """Recheck original proofs, then prove inclusion or finality past mortality.

    Return None for no attempt or an unresolved live attempt. No journal is
    changed. A later atomic reservation must still match this exact attempt.
    Expired attempts do not depend on historical block bodies or event RPCs.
    """
    started = time.monotonic()
    reviewed = await review_standing_transaction(provider, journal, control_hotkey=control_hotkey)
    if reviewed is None:
        return None
    pending = reviewed.pending
    intent = pending.intent
    death = intent.block + intent.mortality_period
    async with provider._lock:
        if provider._closed:
            raise ValueError("standing outcome provider is closed")
        head = await provider._proofs.finalized_snapshot()
        if not isinstance(head, FinalizedSnapshotRef):
            raise ValueError("standing outcome lacks owned finality")
        block = await provider._finality.verified_block_at(head.block_number)
        provider._check_finality(head, block)
        if head.block_number < intent.block or (
            head.block_number == intent.block and head.block_hash != intent.block_hash
        ):
            raise ValueError("standing outcome finality precedes original signing context")
        if head.block_number >= death:
            result = _issue_standing_end(pending, head, "expired_outcome_unknown")
        elif reviewed.query is None or head.block_number == intent.block:
            result = None
        else:
            # Use the shared native reader under the provider's ownership lock.
            # It verifies exact bytes, body root, executed parent runtime and
            # proved child dispatch events. A missing result remains unknown.
            receipt = await MortalReceiptReader.find(provider._bridge_reader(), reviewed.query)
            if receipt is None:
                result = None
            else:
                if (
                    type(receipt) is not VerifiedMortalReceipt
                    or receipt.signed_extrinsic_hash != pending.signed.extrinsic_hash
                    or type(receipt.successful) is not bool
                    or not intent.block < receipt.receipt.block_number < death
                    or receipt.receipt.block_number > receipt.owned_head.block_number
                ):
                    raise ValueError("standing receipt differs from the retained attempt")
                result = _issue_standing_end(
                    pending,
                    receipt.owned_head,
                    "dispatch_succeeded" if receipt.successful else "dispatch_failed",
                    digest(
                        {
                            "receipt": receipt.receipt.model_dump(mode="json", by_alias=True),
                            "successful": receipt.successful,
                            "signed_extrinsic_hash": receipt.signed_extrinsic_hash,
                            "owned_head": asdict(receipt.owned_head),
                        }
                    ),
                )
        if await run_owned_thread(journal.pending) != pending:
            raise ValueError("standing attempt changed while resolving its outcome")
        remaining = max(0, death - head.block_number)
        completed = min(intent.mortality_period, max(0, head.block_number - intent.block))
        logger.info(
            canonical_json_bytes(
                {
                    "schema": "umi-standing-transaction-resolution-progress/1",
                    "stage": "standing_transaction_resolution",
                    "status": "waiting" if result is None else "completed",
                    "reason_code": (
                        "unsigned_attempt_waiting_for_expiry"
                        if result is None and pending.signed is None
                        else "signed_attempt_waiting_for_receipt_or_expiry"
                        if result is None
                        else result.reason
                    ),
                    "intent_sha256": digest(intent),
                    "signed": pending.signed is not None,
                    "birth_block": intent.block,
                    "finalized_block": head.block_number,
                    "expiry_block": death,
                    "completed_blocks": completed,
                    "total_blocks": intent.mortality_period,
                    "remaining_blocks": remaining,
                    "percent": (
                        100 if result is not None else 100 * completed / intent.mortality_period
                    ),
                    "elapsed_seconds": time.monotonic() - started,
                    "eta_seconds": 0 if result is not None else None,
                    "planning_eta_seconds": (
                        None if result is not None else [6 * remaining, 24 * remaining]
                    ),
                    "eta_basis": (
                        "resolved_by_native_evidence"
                        if result is not None
                        else "planning_6_to_24_seconds_per_block_excludes_recovery_retries"
                    ),
                    "eta_scope": "current_attempt_mortality_only_not_reward_activation",
                    "stalled_or_retrying": False,
                }
            ).decode()
        )
        return result
