"""Immutable follower attempts with atomic, restart-safe nonce fencing.

These local records retain an already checked intent and exact signed bytes.
They are not portable chain proofs. A fresh native observation fences mortality
before another attempt; no restart re-broadcasts a retained transaction. Receipt
and old-layout reconciliation belong to the worker's separate native boundary.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, model_validator

from .bridge.signing import BridgeSigningState, signing_state_digest
from .competition_round_journal import RecordReservation, RoundJournal
from .encoding import account_id32, datetime_to_unix_ms
from .open_competition import Hotkey, digest, identity
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES, exact_signed_extrinsic
from .translation_reference_policy import TranslationReferencePolicy, reference_policy_sha256
from .translation_reference_state import TranslationReferenceError, TranslationReferenceState, _row

_INTENT = "reference_weight_intent"
_SIGNED = "reference_weight_signed"
_END = "reference_weight_end"
_MAX_RECORD_BYTES = 2 * MAX_SIGNED_EXTRINSIC_BYTES + 4096
_LOG = logging.getLogger(__name__)


class ReferenceWeightIntent(StrictProtocolModel):
    schema_: Literal["umi-reference-weight-intent/1"] = Field(alias="schema")
    policy_sha256: Hex32
    validator_hotkey: Hotkey
    reference_hotkey: Hotkey
    block: Annotated[int, Field(ge=1, le=2**53 - 9)]
    block_hash: BlockHash
    state_root: BlockHash
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    mortality_period: Literal[8]
    reference_last_update: Annotated[int, Field(ge=1, le=2**53 - 1)]
    prior_last_update: Annotated[int, Field(ge=0, le=2**53 - 1)]
    row: Annotated[tuple[tuple[int, int], ...], Field(min_length=256, max_length=256)]
    signing_inputs_sha256: Hex32
    previous_intent_sha256: Hex32 | None
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self):
        if self.prior_last_update > self.block or self.reference_last_update > self.block:
            raise ValueError("reference intent contains future state")
        _row(self.row)
        if account_id32(self.validator_hotkey) == account_id32(self.reference_hotkey):
            raise ValueError("reference writer cannot follow itself")
        return self

    def call(self):
        return bt.calls.SubtensorModule.set_mechanism_weights(
            netuid=78,
            mecid=0,
            dests=[uid for uid, _ in self.row],
            weights=[weight for _, weight in self.row],
            version_key=4_294_967_296,
        )


class SignedReferenceWeight(StrictProtocolModel):
    intent_sha256: Hex32
    encoded: Annotated[
        str,
        Field(
            min_length=2, max_length=2 * MAX_SIGNED_EXTRINSIC_BYTES, pattern=r"^(?:[0-9a-f]{2})+$"
        ),
    ]
    extrinsic_hash: BlockHash

    @model_validator(mode="after")
    def bytes_match(self):
        if (
            exact_signed_extrinsic(bytes.fromhex(self.encoded)).extrinsic_hash
            != self.extrinsic_hash
        ):
            raise ValueError("reference signed bytes differ from their hash")
        return self


class ReferenceWeightEnd(StrictProtocolModel):
    intent_sha256: Hex32
    reason: Literal["expired_outcome_unknown"]
    observed_block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    observed_block_hash: BlockHash
    next_nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    original_success_or_failure_claimed: Literal[False] = False


@dataclass(frozen=True, slots=True)
class PendingReferenceWeight:
    intent: ReferenceWeightIntent
    signed: SignedReferenceWeight | None
    end: ReferenceWeightEnd | None


def reference_weight_intent(
    state: TranslationReferenceState,
    policy: TranslationReferencePolicy,
    *,
    now: datetime,
    previous_intent_sha256: str | None,
):
    decision = state.decision(policy, now=now)
    if decision.action != "submit":
        raise TranslationReferenceError("reference_submission_not_due")
    if (
        datetime_to_unix_ms(now)
        - state.signing.timestamp_ms
        + policy.submission_timeout_seconds * 1000
        > policy.maximum_finalized_age_seconds * 1000
    ):
        raise TranslationReferenceError("reference_submission_freshness_headroom_insufficient")
    ref = state.signing.runtime.snapshot
    return ReferenceWeightIntent(
        schema="umi-reference-weight-intent/1",
        policy_sha256=reference_policy_sha256(policy),
        validator_hotkey=state.signing.validator_hotkey,
        reference_hotkey=policy.reference_hotkey,
        block=ref.block_number,
        block_hash=ref.block_hash,
        state_root=ref.state_root,
        nonce=state.signing.nonce,
        mortality_period=policy.submission_era_period,
        reference_last_update=decision.reference_last_update,
        prior_last_update=decision.writer_last_update,
        row=decision.row,
        signing_inputs_sha256=signing_state_digest(state.signing),
        previous_intent_sha256=previous_intent_sha256,
    )


class ReferenceWeightJournal:
    """Shared atomic journal with one counted head; no repeated history scans.

    The head is an index, never authority. Missing/damaged indexes are explicit
    repair failures. The native record counters bind its number of immutable
    intents; a stale index cannot silently reset a pending transaction. All
    archives and signed bytes remain in place across capacity increases.
    """

    def __init__(
        self,
        root: Path,
        *,
        validator_hotkey: str,
        maximum_bytes: int,
        repair_head_index: bool = False,
        progress=None,
    ):
        if type(repair_head_index) is not bool:
            raise TypeError("reference index repair selection must be boolean")
        self.hotkey = validator_hotkey
        self._progress = progress
        self.journal = RoundJournal(
            root,
            {"schema": "umi-reference-weight-journal/1", "hotkey": identity(validator_hotkey)},
            maximum_rounds=65536,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=_MAX_RECORD_BYTES,
        )
        with self.journal.transaction() as db:
            exists = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='reference_head'"
            ).fetchone()
            if not exists:
                retained = db.execute(
                    "SELECT 1 FROM records WHERE kind IN (?,?,?) LIMIT 1", (_INTENT, _SIGNED, _END)
                ).fetchone()
                if retained and not repair_head_index:
                    raise ValueError("reference head index repair required")
                if not retained:
                    self._create_head(db, None, 0)
            if repair_head_index:
                self._repair_head(db)
            self._pending(db)

    @staticmethod
    def _create_head(db, key, number):
        db.execute(
            "CREATE TABLE reference_head (id INTEGER PRIMARY KEY CHECK(id=1), "
            "intent TEXT, number INTEGER NOT NULL CHECK(number>=0))"
        )
        db.execute("INSERT INTO reference_head VALUES (1,?,?)", (key, number))

    def _repair_head(self, db):
        """Reconstruct derived metadata only, atomically, with bounded row memory.

        Every immutable intent/signature/end is checked. Branches, missing
        predecessors, unresolved predecessor effects and orphan bytes refuse
        repair. No original record, lock or accepted outcome is changed.
        """
        started, completed = time.monotonic(), 0
        total = self._intent_count(db)

        def emit(state):
            elapsed = time.monotonic() - started
            event = {
                "stage": "reference_head_index_repair",
                "state": state,
                "completed": completed,
                "total": total,
                "percent": 100 * completed / total if total else 100,
                "elapsed_seconds": elapsed,
                "eta_seconds": 0
                if state == "completed"
                else (
                    (total - completed) * elapsed / completed
                    if completed and state != "repair_refused"
                    else None
                ),
                "planning_seconds": [1, 300]
                if not completed and state != "repair_refused"
                else None,
                "eta_basis": "compact retained records checked in this repair",
                "stalled": state == "repair_refused",
                "retrying": state == "repair_refused",
            }
            _LOG.info("reference_journal_progress %s", event)
            if self._progress is not None:
                self._progress(event)

        emit("running")
        try:
            db.execute(
                "CREATE TEMP TABLE reference_repair (key TEXT PRIMARY KEY, parent TEXT, "
                "block INTEGER, hash TEXT, nonce INTEGER, end_block INTEGER, "
                "end_hash TEXT, end_nonce INTEGER)"
            )
            cursor = db.execute("SELECT id FROM records WHERE kind=? ORDER BY id", (_INTENT,))
            for (key,) in cursor:
                value = self._attempt(db, key)
                intent, end = value.intent, value.end
                db.execute(
                    "INSERT INTO reference_repair VALUES (?,?,?,?,?,?,?,?)",
                    (
                        key,
                        intent.previous_intent_sha256,
                        intent.block,
                        intent.block_hash,
                        intent.nonce,
                        None if end is None else end.observed_block,
                        None if end is None else end.observed_block_hash,
                        None if end is None else end.next_nonce,
                    ),
                )
                completed += 1
                if completed == total or completed % 64 == 0:
                    emit("running")
            if completed != total:
                raise ValueError("reference index repair count changed")
            if db.execute(
                "SELECT 1 FROM records r LEFT JOIN reference_repair p ON r.id=p.key "
                "WHERE r.kind IN (?,?) AND p.key IS NULL LIMIT 1",
                (_SIGNED, _END),
            ).fetchone():
                raise ValueError("reference index repair found orphan transaction bytes")
            roots = db.execute("SELECT key FROM reference_repair WHERE parent IS NULL").fetchall()
            leaves = db.execute(
                "SELECT p.key FROM reference_repair p "
                "LEFT JOIN reference_repair c ON c.parent=p.key "
                "WHERE c.key IS NULL"
            ).fetchall()
            if total and (len(roots) != 1 or len(leaves) != 1):
                raise ValueError("reference index repair found a branched lineage")
            if db.execute(
                "SELECT 1 FROM reference_repair c LEFT JOIN reference_repair p ON c.parent=p.key "
                "WHERE c.parent IS NOT NULL AND (p.key IS NULL OR p.end_block IS NULL "
                "OR c.block<=p.block OR c.block<p.end_block OR c.nonce<p.end_nonce "
                "OR (c.block=p.end_block AND c.hash!=p.end_hash)) LIMIT 1"
            ).fetchone():
                raise ValueError("reference index repair cannot reconcile predecessor effects")
            key = leaves[0][0] if leaves else None
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='reference_head'"
            ).fetchone():
                # Keep the common journal's native capability-fence triggers.
                # Recreating a same-named table would discard those predicates.
                db.execute("DELETE FROM reference_head")
                db.execute("INSERT INTO reference_head VALUES (1,?,?)", (key, total))
            else:
                self._create_head(db, key, total)
            db.execute("DROP TABLE reference_repair")
            emit("completed")
        except BaseException:
            emit("repair_refused")
            raise

    def _intent_count(self, db):
        # Native reservation adoption replaces v1's derived capacity tables.
        # Use the owning journal's corresponding counted metadata in each format.
        capacity = (
            self.journal._capacity
            if self.journal._version(db) == 2
            else self.journal._record_capacity
        )
        return capacity(db)[2].get(_INTENT, 0)

    def _pending(self, db):
        head = db.execute("SELECT intent,number FROM reference_head WHERE id=1").fetchall()
        number = self._intent_count(db)
        if len(head) != 1 or type(head[0][1]) is not int or head[0][1] != number:
            raise ValueError("reference head index repair required")
        key = head[0][0]
        if number == 0:
            if (
                key is not None
                or db.execute(
                    "SELECT 1 FROM records WHERE kind IN (?,?) LIMIT 1", (_SIGNED, _END)
                ).fetchone()
            ):
                raise ValueError("reference head index repair required")
            return None
        if key is None:
            raise ValueError("reference head index repair required")
        return self._attempt(db, key)

    def _attempt(self, db, key):
        raw = self.journal.get(_INTENT, key, db=db)
        if raw is None:
            raise ValueError("reference head intent repair required")
        intent = ReferenceWeightIntent.model_validate_json(canonical_json_bytes(raw))
        if digest(intent) != key or account_id32(intent.validator_hotkey) != account_id32(
            self.hotkey
        ):
            raise ValueError("reference intent identity damaged")
        raw_signed, raw_end = (
            self.journal.get(_SIGNED, key, db=db),
            self.journal.get(_END, key, db=db),
        )
        signed = None if raw_signed is None else SignedReferenceWeight.model_validate(raw_signed)
        end = None if raw_end is None else ReferenceWeightEnd.model_validate(raw_end)
        if signed is not None and signed.intent_sha256 != key:
            raise ValueError("reference signature belongs to another intent")
        if end is not None and (
            end.intent_sha256 != key
            or end.observed_block < intent.block + intent.mortality_period
            or end.next_nonce < intent.nonce
        ):
            raise ValueError("reference end does not fence the original attempt")
        return PendingReferenceWeight(intent, signed, end)

    def pending(self):
        with self.journal.read_transaction() as db:
            return self._pending(db)

    def reserve(self, intent: ReferenceWeightIntent):
        intent = ReferenceWeightIntent.model_validate_json(canonical_json_bytes(intent))
        if account_id32(intent.validator_hotkey) != account_id32(self.hotkey):
            raise ValueError("reference journal belongs to another validator")
        key = digest(intent)
        specs = [
            RecordReservation(
                _INTENT,
                key,
                len(canonical_json_bytes(intent)),
                sha256_hex(canonical_json_bytes(intent)),
            ),
            RecordReservation(_SIGNED, key, _MAX_RECORD_BYTES),
            RecordReservation(_END, key, 4096),
        ]
        with self.journal.locked():
            old = self.pending()
            if old is not None and old.intent == intent:
                return old
            if old is None:
                if intent.previous_intent_sha256 is not None:
                    raise ValueError("reference initial intent has a predecessor")
            elif (
                old.end is None
                or intent.previous_intent_sha256 != digest(old.intent)
                or intent.block < old.end.observed_block
                or intent.block <= old.intent.block
                or intent.nonce < old.end.next_nonce
                or (
                    intent.block == old.end.observed_block
                    and intent.block_hash != old.end.observed_block_hash
                )
            ):
                raise ValueError("reference prior attempt requires native reconciliation")

            def index(db):
                self.journal.reserve_records("reference-weight:" + key, specs, db=db)
                count = self._intent_count(db)
                db.execute("UPDATE reference_head SET intent=?,number=? WHERE id=1", (key, count))

            self.journal.put_many([(_INTENT, key, intent)], index=index)
            return self.pending()

    def retain_signed(self, intent: ReferenceWeightIntent, encoded: bytes):
        envelope = exact_signed_extrinsic(encoded)
        with self.journal.locked():
            old = self.pending()
            if old is None or old.intent != intent or old.end is not None:
                raise ValueError("reference signature lacks its live original intent")
            value = SignedReferenceWeight(
                intent_sha256=digest(intent),
                encoded=encoded.hex(),
                extrinsic_hash=envelope.extrinsic_hash,
            )
            self.journal.put(_SIGNED, digest(intent), value)
            return self.pending()

    def fence_expired(self, signing: BridgeSigningState, *, now: datetime):
        # Fresh current proof and the same single signer are required; the end
        # makes no assertion that the original transaction succeeded or failed.
        if type(signing) is not BridgeSigningState:
            raise ValueError("reference expiry requires native signing state")
        signing = BridgeSigningState(signing.validator_hotkey, signing.runtime, signing.batch)
        if not 0 <= datetime_to_unix_ms(now) - signing.timestamp_ms <= 120_000:
            raise ValueError("reference expiry snapshot is stale")
        with self.journal.locked():
            old = self.pending()
            if old is None:
                return None
            ref = signing.runtime.snapshot
            if account_id32(signing.validator_hotkey) != account_id32(self.hotkey):
                raise ValueError("reference expiry belongs to another signer")
            if ref.block_number < old.intent.block + old.intent.mortality_period:
                raise ValueError("reference prior mortal era has not ended")
            if signing.nonce < old.intent.nonce:
                raise ValueError("reference nonce moved backwards")
            if old.end is None:
                end = ReferenceWeightEnd(
                    intent_sha256=digest(old.intent),
                    reason="expired_outcome_unknown",
                    observed_block=ref.block_number,
                    observed_block_hash=ref.block_hash,
                    next_nonce=signing.nonce,
                )
                self.journal.put(_END, digest(old.intent), end)
            return self.pending()
