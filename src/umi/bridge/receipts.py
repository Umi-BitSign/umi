"""Read exact bridge transaction outcomes from owned finalized history.

The reader never submits or changes a journal. It hashes backwards from an
owned head, verifies the body root, and decodes proven child events with the
parent's proven runtime. A missing result is uncertainty, not proof of absence.
Completed ancestry/body work survives a timeout in this process. Only one
attempt's eight-block era is retained; a long outage does not grow the cache.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass
from datetime import datetime

from ..chain_evidence import FinalizedSnapshotRef
from ..concurrency import await_owned_task
from ..encoding import datetime_to_unix_ms
from ..mortal_receipts import MortalReceiptError, MortalReceiptQuery, MortalReceiptReader
from ..mortal_receipts import VerifiedMortalReceipt as VerifiedBridgeReceipt
from ..protocol import canonical_json_bytes
from ..runtime_metadata import collect_executed_runtime
from .policy import RegistrationBridgeError, _require
from .transactions import RegistrationBridgeTransactionJournal, evolve_journal, parse_bridge_journal


@dataclass(frozen=True)
class VerifiedBridgeExpiry:
    """Proven nonce availability after mortality, not historical non-inclusion."""

    snapshot: FinalizedSnapshotRef
    nonce: int
    owned_head: FinalizedSnapshotRef


def _check_receipt(journal: RegistrationBridgeTransactionJournal, proven: VerifiedBridgeReceipt):
    _require(
        type(proven) is VerifiedBridgeReceipt
        and proven.signed_extrinsic_hash == journal.signed_extrinsic_hash,
        "bridge_receipt_attempt_mismatch",
    )
    receipt, anchor = proven.receipt, proven.owned_head
    _require(
        journal.attempt.preflight_block < receipt.block_number < journal.attempt.era_death
        and receipt.block_number <= anchor.block_number
        and type(proven.successful) is bool,
        "bridge_receipt_position_invalid",
    )
    _require(
        (journal.weight_call is None or (proven.successful and journal.weight_call == receipt))
        and (
            journal.failed_call is None
            or (not proven.successful and journal.failed_call == receipt)
        ),
        "bridge_receipt_conflict",
    )


def retain_verified_receipt(journal, proven: VerifiedBridgeReceipt, *, now: datetime):
    """Build one transition from a local reader result, never an RPC receipt.

    Receipt inclusion settles transaction uncertainty. A successful call still
    needs the separate current-row check before the journal becomes applied.
    """
    journal = parse_bridge_journal(canonical_json_bytes(journal))
    _require(
        type(journal) is RegistrationBridgeTransactionJournal
        and journal.phase in {"submitting", "outcome_unknown", "receipt_returned"},
        "bridge_receipt_attempt_mismatch",
    )
    _check_receipt(journal, proven)
    receipt, anchor = proven.receipt, proven.owned_head
    updates = dict(updated_at_unix_ms=datetime_to_unix_ms(now))
    if anchor.block_number >= journal.last_observed_block:
        _require(
            anchor.block_number != journal.last_observed_block
            or anchor.block_hash == journal.last_observed_block_hash,
            "bridge_receipt_finality_equivocation",
        )
        updates.update(
            last_observed_block=anchor.block_number, last_observed_block_hash=anchor.block_hash
        )
    if proven.successful:
        updates.update(phase="receipt_returned", weight_call=receipt)
    else:
        updates.update(phase="failed", failed_call=receipt)
    return evolve_journal(journal, **updates)


class BridgeReceiptReader(MortalReceiptReader):
    """Bridge journal adapter; original eight-block and expiry rules are retained."""

    async def expiry(self, journal: RegistrationBridgeTransactionJournal) -> VerifiedBridgeExpiry:
        """Authenticate the retained expiry snapshot, or use the owned head.

        Historical attempts need their original expiry snapshot because later
        transactions may have consumed the same nonce. This never treats the
        journal's recorded nonce or state root as proof.
        """
        journal = parse_bridge_journal(canonical_json_bytes(journal))
        _require(
            type(journal) is RegistrationBridgeTransactionJournal
            and journal.phase
            in {"preparing", "signed", "submitting", "outcome_unknown", "expired_nonce_available"},
            "bridge_expiry_attempt_invalid",
        )
        task = asyncio.create_task(asyncio.wait_for(self._expiry(journal), self._timeout))
        try:
            return await await_owned_task(task, on_cancel=task.cancel)
        except MortalReceiptError as error:
            raise RegistrationBridgeError(
                error.reason_code.replace("mortal_", "bridge_", 1)
            ) from error

    async def _expiry(self, journal):
        async with self._lock:
            retained = journal.expiry_observation
            target = retained.block_number if retained is not None else None
            identity = ("expiry", hashlib.sha256(canonical_json_bytes(journal)).hexdigest())
            if identity != self._identity:
                earlier = (
                    target is not None
                    and self._cursor is not None
                    and target <= self._cursor.snapshot.block_number
                )
                if not earlier:
                    self._anchor = self._cursor = None
                self._identity = identity
                self._found = self._expiry_result = None
                self._era.clear()
                self._checked.clear()
            if self._cursor is None:
                owned = await self._finality.read_finalized_identity()
                anchor = await self._header(owned.block_hash, owned.number)
                self._anchor = self._cursor = anchor
            if target is None:
                target = self._anchor.snapshot.block_number
            ready = journal.attempt.era_death <= target <= self._anchor.snapshot.block_number
            if not ready:
                self._anchor = self._cursor = None
            _require(
                ready,
                "bridge_expiry_not_finalized",
            )
            if self._expiry_result is None:
                while self._cursor.snapshot.block_number > target:
                    self._cursor = await self._header(
                        self._cursor.snapshot.parent_hash, self._cursor.snapshot.block_number - 1
                    )
                ref = self._cursor.snapshot
                _require(
                    retained is None
                    or (
                        ref.block_hash == retained.block_hash
                        and ref.state_root == retained.state_root
                    ),
                    "bridge_expiry_ancestry_mismatch",
                )
                runtime = await collect_executed_runtime(self._code_proofs, self._executor, ref)
                key = runtime.storage_key("System", "Account", (journal.validator_hotkey,))
                evidence = await self._proofs.storage_evidence(ref, key)
                value = runtime.decode_storage("System", "Account", evidence.value)
                nonce = value.get("nonce") if isinstance(value, dict) else None
                _require(
                    type(nonce) is int
                    and 0 <= nonce < 2**32
                    and nonce == journal.attempt.signing.nonce,
                    "bridge_expiry_nonce_unavailable",
                )
                self._expiry_result = VerifiedBridgeExpiry(ref, nonce, self._anchor.snapshot)
            birth = journal.attempt.preflight_block
            while self._cursor.snapshot.block_number > birth:
                self._cursor = await self._header(
                    self._cursor.snapshot.parent_hash, self._cursor.snapshot.block_number - 1
                )
            _require(
                self._cursor.snapshot.block_hash == journal.attempt.preflight_block_hash,
                "bridge_expiry_preflight_ancestry_mismatch",
            )
            return self._expiry_result

    async def find(
        self, journal: RegistrationBridgeTransactionJournal
    ) -> VerifiedBridgeReceipt | None:
        journal = parse_bridge_journal(canonical_json_bytes(journal))
        _require(
            type(journal) is RegistrationBridgeTransactionJournal
            and journal.phase
            in {"submitting", "outcome_unknown", "receipt_returned", "applied", "failed"}
            and journal.signed_extrinsic is not None,
            "bridge_receipt_signed_attempt_required",
        )
        query = MortalReceiptQuery(
            schema="umi-mortal-receipt-query/1",
            birth_block=journal.attempt.preflight_block,
            birth_hash=journal.attempt.preflight_block_hash,
            mortality_period=journal.attempt.era_death - journal.attempt.preflight_block,
            signed_extrinsic=journal.signed_extrinsic,
        )
        _require(query.mortality_period == 8, "bridge_receipt_era_unsupported")
        try:
            proven = await super().find(query)
        except MortalReceiptError as error:
            raise RegistrationBridgeError(
                error.reason_code.replace("mortal_", "bridge_", 1)
            ) from error
        if proven is not None:
            _check_receipt(journal, proven)
        return proven
