"""Pure binding and continuity checks for newly collected bridge outcomes."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from .bridge.receipts import VerifiedBridgeExpiry, VerifiedBridgeReceipt, _check_receipt
from .bridge.transactions import RegistrationBridgeTransactionJournal, parse_bridge_journal
from .competition_bridge_recovery import BridgeHistoryAudit
from .competition_recovery_models import BridgeRecoveryOutcome, CompetitionRecoveryError
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_chain_state import OwnedCompetitionChainObservation


def summarize_bridge_outcome(
    path: str,
    journal: RegistrationBridgeTransactionJournal,
    result: VerifiedBridgeReceipt | VerifiedBridgeExpiry,
) -> BridgeRecoveryOutcome:
    """Check the reader result before retaining its compact, non-authoritative report."""
    if type(journal) is not RegistrationBridgeTransactionJournal:
        raise CompetitionRecoveryError("bridge outcome requires a version-2 journal")
    journal = parse_bridge_journal(canonical_json_bytes(journal))
    if type(result) is VerifiedBridgeReceipt:
        _check_receipt(journal, result)
        if journal.phase not in {
            "submitting",
            "outcome_unknown",
            "receipt_returned",
            "applied",
            "failed",
        }:
            raise CompetitionRecoveryError("receipt conflicts with the retained bridge phase")
        disposition = "applied" if result.successful else "failed"
        block, block_hash = result.receipt.block_number, result.receipt.block_hash
        index, nonce = result.receipt.extrinsic_index, None
    elif type(result) is VerifiedBridgeExpiry:
        if journal.phase not in {
            "preparing",
            "signed",
            "submitting",
            "outcome_unknown",
            "expired_nonce_available",
        }:
            raise CompetitionRecoveryError("expiry cannot replace a retained dispatch receipt")
        block, block_hash = result.snapshot.block_number, result.snapshot.block_hash
        if block < journal.attempt.era_death or result.nonce != journal.attempt.signing.nonce:
            raise CompetitionRecoveryError("expiry does not prove original nonce availability")
        retained = journal.expiry_observation
        if retained is not None and (
            block != retained.block_number
            or block_hash != retained.block_hash
            or result.snapshot.state_root != retained.state_root
        ):
            raise CompetitionRecoveryError("expiry differs from the retained snapshot")
        disposition, index, nonce = "expired_nonce_available", None, result.nonce
    else:
        raise CompetitionRecoveryError("bridge recovery requires a verified reader result")
    return BridgeRecoveryOutcome(
        path=path,
        attempt_id=journal.attempt.attempt_id,
        journal_sha256=hashlib.sha256(canonical_json_bytes(journal)).hexdigest(),
        disposition=disposition,
        resolution_block=block,
        resolution_block_hash=block_hash,
        extrinsic_index=index,
        nonce=nonce,
        verified_head_block=result.owned_head.block_number,
        verified_head_hash=result.owned_head.block_hash,
    )


def bridge_outcomes_match_current_state(
    audit: BridgeHistoryAudit,
    outcomes: tuple[BridgeRecoveryOutcome, ...],
    observation: OwnedCompetitionChainObservation,
) -> bool:
    """Caller must authenticate collection authority before calling this calculation."""
    records = dict(audit.attempts)
    expected = {p for p, j in records.items() if type(j) is RegistrationBridgeTransactionJournal}
    by_path = {item.path: item for item in outcomes}
    if len(by_path) != len(outcomes) or set(by_path) != expected:
        raise CompetitionRecoveryError("bridge outcome set does not cover the stopped history")
    for path, item in by_path.items():
        journal = records[path]
        if (
            item.attempt_id != journal.attempt.attempt_id
            or item.journal_sha256 != hashlib.sha256(canonical_json_bytes(journal)).hexdigest()
        ):
            raise CompetitionRecoveryError("bridge outcome refers to different journal bytes")
        if (
            observation.block < max(journal.last_observed_block, item.verified_head_block)
            or (
                observation.block == item.verified_head_block
                and observation.block_hash != item.verified_head_hash
            )
            or (
                observation.block == journal.last_observed_block
                and observation.block_hash != journal.last_observed_block_hash
            )
        ):
            return False
    if set(audit.holds) - {"registration_bridge_transaction_proof_required"}:
        return False
    last_update, row = None, None
    for path, journal in audit.attempts:
        attempt = journal.attempt
        if last_update is not None and attempt.prior_last_update != last_update:
            return False
        item = by_path.get(path)
        if item is not None and item.disposition == "applied":
            last_update, row = item.resolution_block, attempt.expected_row
        elif item is None and journal.weight_call is not None:
            last_update, row = journal.weight_call.block_number, attempt.expected_row
        else:
            last_update = attempt.prior_last_update
    writers = [
        p for p in audit.current.attempt.roster if p.hotkey == audit.current.validator_hotkey
    ]
    return (
        len(writers) == 1
        and writers[0].uid == observation.validator_uid
        and observation.validator_last_update == last_update
        and (row is None or observation.validator_row == tuple(tuple(pair) for pair in row))
    )


def retained_outcomes_agree(
    retained: list[BridgeRecoveryOutcome],
    fresh: tuple[BridgeRecoveryOutcome, ...],
) -> None:
    """Recollection must preserve disposition; an expiry observation may advance."""
    if [x.path for x in retained] != [x.path for x in fresh]:
        raise CompetitionRecoveryError("recollected bridge outcome set changed")
    for old, new in zip(retained, fresh, strict=True):
        if any(
            getattr(old, k) != getattr(new, k)
            for k in (
                "path",
                "attempt_id",
                "journal_sha256",
                "disposition",
                "extrinsic_index",
                "nonce",
            )
        ):
            raise CompetitionRecoveryError("recollected bridge disposition changed")
        if new.disposition != "expired_nonce_available":
            if (old.resolution_block, old.resolution_block_hash) != (
                new.resolution_block,
                new.resolution_block_hash,
            ):
                raise CompetitionRecoveryError("recollected bridge receipt changed")
        elif new.resolution_block < old.resolution_block or (
            new.resolution_block == old.resolution_block
            and new.resolution_block_hash != old.resolution_block_hash
        ):
            raise CompetitionRecoveryError("recollected expiry rolled back or changed")
