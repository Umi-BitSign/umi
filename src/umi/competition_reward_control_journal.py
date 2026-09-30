"""Exact control transactions and original proofs, with one retained attempt lineage."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .chain_evidence import build_sha256_commitment_call
from .competition_reward_control_signing import (
    RewardControlSigningState,
    validate_control_signing_state,
)
from .competition_reward_decisions import SignedRewardControlDecision, StandingRewardSeries
from .competition_round_journal import RecordReservation, RoundJournal
from .open_competition import digest, identity
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES, exact_signed_extrinsic, verify_mortal_call

MAX_OBJECT_BYTES = 32 * 1024**2


class RewardControlTransaction(StrictProtocolModel):
    schema_: Literal["umi-reward-control-transaction/1"] = Field(alias="schema")
    series_sha256: Hex32
    decision: SignedRewardControlDecision
    previous_attempt_sha256: Hex32 | None
    block: Annotated[int, Field(ge=1, le=2**53 - 1)]
    block_hash: BlockHash
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    mortality_period: Annotated[int, Field(ge=4, le=4096)]
    control_evidence_sha256: Hex32
    nonce_evidence_sha256: Hex32
    metadata_sha256: Hex32

    @model_validator(mode="after")
    def bounds(self):
        if (
            self.mortality_period & (self.mortality_period - 1)
            or self.block + self.mortality_period > 2**53 - 1
            or self.decision.decision.series_sha256 != self.series_sha256
            or self.decision.decision.observed_at_block > self.block
        ):
            raise ValueError("control transaction changes decision or mortality bounds")
        return self

    def call(self):
        return build_sha256_commitment_call(digest(self.decision.decision))


class SignedControlTransaction(StrictProtocolModel):
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
            raise ValueError("control transaction bytes differ from their hash")
        return self


@dataclass(frozen=True)
class PendingControlTransaction:
    intent: RewardControlTransaction
    signed: SignedControlTransaction | None


class RewardControlTransactionJournal:
    """Methods run under the publisher's process mutex; no wallet or RPC access.

    Every attempted call and signature remains immutable. A later attempt is
    admitted only after fresh proof fences the old era or consumes its nonce.
    Neither condition asserts whether that original call succeeded.
    """

    def __init__(
        self,
        root: Path,
        series: StandingRewardSeries,
        *,
        config_sha256: str,
        maximum_bytes: int,
    ):
        self.series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
        self.config_sha256 = config_sha256
        if (
            type(config_sha256) is not str
            or len(config_sha256) != 64
            or any(c not in "0123456789abcdef" for c in config_sha256)
        ):
            raise ValueError("control journal chain configuration is invalid")
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-reward-control-transaction-journal/1",
                "series": digest(self.series),
                "hotkey": identity(self.series.control_hotkey),
                "chain_config": config_sha256,
            },
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=2 * MAX_OBJECT_BYTES + 1024,
        )

    def _intent(self, raw) -> RewardControlTransaction:
        intent = RewardControlTransaction.model_validate_json(canonical_json_bytes(raw))
        if intent.series_sha256 != digest(self.series) or (
            intent.mortality_period > self.series.maximum_transaction_lifetime_blocks
        ):
            raise ValueError("control transaction differs from its approved series")
        return intent

    def pending(self) -> PendingControlTransaction | None:
        intents = {}
        for key in self.journal.keys("control_intent"):
            intent = self._intent(self.journal.get("control_intent", key))
            if digest(intent) != key:
                raise ValueError("control transaction identity changed")
            intents[key] = intent
        children, roots = {}, []
        for key, intent in intents.items():
            parent = intent.previous_attempt_sha256
            if parent is None:
                roots.append(key)
            elif (
                parent not in intents or parent in children or intent.block <= intents[parent].block
            ):
                raise ValueError("control journal has conflicting or unordered attempts")
            else:
                old = intents[parent]
                if intent.nonce < old.nonce or (
                    intent.block < old.block + old.mortality_period and intent.nonce == old.nonce
                ):
                    raise ValueError("control journal successor lacks an era or nonce fence")
                children[parent] = key
        signed_keys = self.journal.keys("control_signed")
        if any(key not in intents for key in signed_keys):
            raise ValueError("control signature lost its original intent")
        if not intents:
            return None
        if len(roots) != 1:
            raise ValueError("control journal has multiple unresolved roots")
        key, seen = roots[0], set()
        while key in children and key not in seen:
            seen.add(key)
            key = children[key]
        if key in seen or len(seen) + 1 != len(intents):
            raise ValueError("control journal lineage is incomplete")
        intent = intents[key]
        raw = self.journal.get("control_signed", key)
        signed = (
            None
            if raw is None
            else SignedControlTransaction.model_validate_json(canonical_json_bytes(raw))
        )
        if signed is not None and signed.intent_sha256 != key:
            raise ValueError("control signature changed its intent")
        for sha in (
            intent.control_evidence_sha256,
            intent.nonce_evidence_sha256,
            intent.metadata_sha256,
        ):
            self.object(sha)
        return PendingControlTransaction(intent, signed)

    def object(self, sha: str) -> bytes:
        value = self.journal.get("control_object", sha)
        if type(value) is not dict or set(value) != {"hex"} or type(value["hex"]) is not str:
            raise ValueError("control transaction lost its recovery evidence")
        if not 0 < len(value["hex"]) <= 2 * MAX_OBJECT_BYTES:
            raise ValueError("control recovery evidence exceeds its bound")
        raw = bytes.fromhex(value["hex"])
        if raw.hex() != value["hex"] or sha256_hex(raw) != sha:
            raise ValueError("control recovery evidence is corrupt")
        return raw

    def reserve(
        self,
        decision: SignedRewardControlDecision,
        state: RewardControlSigningState,
        *,
        mortality_period: int,
    ) -> PendingControlTransaction:
        validate_control_signing_state(
            state,
            hotkey=self.series.control_hotkey,
            config_sha256=self.config_sha256,
        )
        prior = self.pending()
        if prior is not None and (
            prior.intent.decision == decision
            and prior.intent.mortality_period == mortality_period
            and prior.intent.block_hash == state.control.snapshot.block_hash
        ):
            check_control_transaction(prior.intent, state, self.series)
            return prior
        if prior is not None and (
            state.nonce < prior.intent.nonce
            or state.control.snapshot.block_number <= prior.intent.block
            or (
                state.control.snapshot.block_number
                < prior.intent.block + prior.intent.mortality_period
                and state.nonce <= prior.intent.nonce
            )
        ):
            raise ValueError("prior control transaction remains live")
        raws = (state.control.evidence, state.nonce_evidence, state.runtime.metadata_bytes)
        intent = self._intent(
            RewardControlTransaction(
                schema="umi-reward-control-transaction/1",
                series_sha256=digest(self.series),
                decision=decision,
                previous_attempt_sha256=None if prior is None else digest(prior.intent),
                block=state.control.snapshot.block_number,
                block_hash=state.control.snapshot.block_hash,
                nonce=state.nonce,
                mortality_period=mortality_period,
                control_evidence_sha256=sha256_hex(raws[0]),
                nonce_evidence_sha256=sha256_hex(raws[1]),
                metadata_sha256=sha256_hex(raws[2]),
            )
        )
        check_control_transaction(intent, state, self.series)
        key = digest(intent)
        records = [("control_intent", key, intent)]
        for raw in raws:
            if type(raw) is not bytes or not 0 < len(raw) <= MAX_OBJECT_BYTES:
                raise ValueError("control transaction evidence exceeds capacity")
            records.append(("control_object", sha256_hex(raw), {"hex": raw.hex()}))
        specs = [
            RecordReservation(
                kind,
                name,
                len(canonical_json_bytes(value)),
                sha256_hex(canonical_json_bytes(value)),
            )
            for kind, name, value in records
        ]
        specs.append(
            RecordReservation("control_signed", key, 2 * MAX_SIGNED_EXTRINSIC_BYTES + 1024)
        )
        self.journal.put_many(
            records,
            index=lambda db: self.journal.reserve_records(
                key,
                specs,
                db=db,
            ),
        )
        return self.pending()

    def retain_signed(
        self,
        intent: RewardControlTransaction,
        encoded: bytes,
        state: RewardControlSigningState,
    ) -> PendingControlTransaction:
        validate_control_signing_state(
            state,
            hotkey=self.series.control_hotkey,
            config_sha256=self.config_sha256,
        )
        check_control_transaction(intent, state, self.series)
        verify_control_transaction_bytes(intent, encoded, state, self.series)
        pending = self.pending()
        if pending is None or pending.intent != intent:
            raise ValueError("control signature lacks its retained intent")
        value = SignedControlTransaction(
            intent_sha256=digest(intent),
            encoded=encoded.hex(),
            extrinsic_hash=exact_signed_extrinsic(encoded).extrinsic_hash,
        )
        if pending.signed is not None and pending.signed != value:
            raise ValueError("control signature cannot replace original bytes")
        self.journal.put("control_signed", digest(intent), value)
        return self.pending()


def check_control_transaction(intent, state, series):
    if (
        intent.series_sha256 != digest(series)
        or (intent.block, intent.block_hash, intent.nonce)
        != (
            state.control.snapshot.block_number,
            state.control.snapshot.block_hash,
            state.nonce,
        )
        or intent.control_evidence_sha256 != state.control.evidence_sha256
        or intent.nonce_evidence_sha256 != hashlib.sha256(state.nonce_evidence).hexdigest()
        or intent.metadata_sha256 != state.runtime.metadata_sha256
        or state.control.control_sha256 != intent.decision.decision.predecessor_sha256
    ):
        raise ValueError("control transaction differs from its original signing context")


def verify_control_transaction_bytes(intent, encoded, state, series):
    check_control_transaction(intent, state, series)
    return verify_mortal_call(
        encoded,
        intent.call(),
        runtime=state.runtime,
        validator_hotkey=series.control_hotkey,
        nonce=intent.nonce,
        mortality_period=intent.mortality_period,
        genesis_hash="0x" + series.genesis_hash,
    )
