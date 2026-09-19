"""Versioned bridge transaction records and stopped expiry reconciliation.

The journal records compact commitments to proof inputs verified by the reader.
Those commitments do not let a historical record manufacture a new proof. A
resolution requires a fresh reader result, and exact bytes are retained before
any broadcast. Version 1 keeps its original schema and recovery semantics.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, ClassVar, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from ..encoding import account_id32, datetime_to_unix_ms
from ..protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from ..signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES, exact_signed_extrinsic
from .journal import (
    RegistrationBridgeAttempt,
    RegistrationBridgeJournal,
    _new_attempt,
    reconcile_registration_bridge_journal,
)
from .policy import PositiveInt, SignedRegistrationBridgePolicy, _canonical_object, _require
from .selection import (
    RegistrationBridgeDecision,
    RegistrationBridgeHealth,
    RegistrationBridgeObservation,
)
from .signing import BridgeSigningState, signing_state_digest

TRANSACTION_JOURNAL_SCHEMA = "umi-registration-bridge-journal/2"


class BridgeSigningRecord(StrictProtocolModel):
    """Local record of a proof-backed read, not a replayable proof authority."""

    validator_hotkey: str
    block_number: PositiveInt
    block_hash: BlockHash
    state_root: BlockHash
    timestamp_ms: PositiveInt
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    runtime_metadata_sha256: Hex32
    runtime_code_sha256: Hex32
    runtime_executor_sha256: Hex32
    proof_inputs_sha256: Hex32

    @model_validator(mode="after")
    def account(self) -> Self:
        account_id32(self.validator_hotkey)
        return self

    @classmethod
    def from_state(cls, state: BridgeSigningState) -> Self:
        _require(type(state) is BridgeSigningState, "bridge_signing_state_required")
        state = BridgeSigningState(state.validator_hotkey, state.runtime, state.batch)
        runtime, ref = state.runtime, state.runtime.snapshot
        return cls(
            validator_hotkey=state.validator_hotkey,
            block_number=ref.block_number,
            block_hash=ref.block_hash,
            state_root=ref.state_root,
            timestamp_ms=state.timestamp_ms,
            nonce=state.nonce,
            runtime_metadata_sha256=runtime.metadata_sha256,
            runtime_code_sha256=hashlib.sha256(runtime.code_evidence.value).hexdigest(),
            runtime_executor_sha256=runtime.executor_sha256,
            proof_inputs_sha256=signing_state_digest(state),
        )


class RegistrationBridgeSigningAttempt(RegistrationBridgeAttempt):
    _identity_domain: ClassVar[bytes] = b"umi-registration-bridge-attempt-v2\0"
    signing: BridgeSigningRecord
    health_observation: RegistrationBridgeObservation | None = None

    @model_validator(mode="after")
    def signing_bindings(self) -> Self:
        if (
            self.signing.validator_hotkey != self.validator_hotkey
            or self.signing.block_number != self.preflight_block
            or self.signing.block_hash != self.preflight_block_hash
            or self.prior_last_update > self.preflight_block
        ):
            raise ValueError("bridge signing record differs from the intended snapshot")
        if self.health_observation is not None and (
            self.health_observation.validator_hotkey != self.validator_hotkey
            or self.health_observation.block_number >= self.preflight_block
        ):
            raise ValueError("bridge probe snapshot does not precede the same writer's submission")
        return self

    @property
    def era_death(self) -> int:
        return self.preflight_block + self.signed_policy.body.submission_era_period


class RegistrationBridgeTransactionJournal(RegistrationBridgeJournal):
    schema_: Literal[TRANSACTION_JOURNAL_SCHEMA] = Field(alias="schema")
    phase: Literal[
        "preparing",
        "signed",
        "submitting",
        "outcome_unknown",
        "receipt_returned",
        "applied",
        "expired_nonce_available",
    ]
    attempt: RegistrationBridgeSigningAttempt
    signed_extrinsic: (
        Annotated[
            str,
            Field(
                min_length=2,
                max_length=2 * MAX_SIGNED_EXTRINSIC_BYTES,
                pattern=r"^(?:[0-9a-f]{2})+$",
            ),
        ]
        | None
    )
    signed_extrinsic_hash: BlockHash | None
    expiry_observation: BridgeSigningRecord | None

    @model_validator(mode="after")
    def transaction_bindings(self) -> Self:
        if (
            self.last_observed_block == self.attempt.preflight_block
            and self.last_observed_block_hash != self.attempt.preflight_block_hash
        ):
            raise ValueError("bridge journal differs from its preflight identity")
        encoded = self.signed_extrinsic
        if (encoded is None) != (self.signed_extrinsic_hash is None):
            raise ValueError("bridge signed bytes and hash must be retained together")
        if encoded is not None:
            envelope = exact_signed_extrinsic(bytes.fromhex(encoded))
            if envelope.extrinsic_hash != self.signed_extrinsic_hash:
                raise ValueError("bridge signed extrinsic hash mismatch")
        if self.phase == "preparing" and encoded is not None:
            raise ValueError("preparing bridge attempt cannot already contain signed bytes")
        if (
            self.phase in {"signed", "submitting", "receipt_returned", "applied"}
            and encoded is None
        ):
            raise ValueError("bridge phase requires retained signed bytes")
        if self.weight_call is not None and self.weight_call.block_number >= self.attempt.era_death:
            raise ValueError("bridge receipt is outside the retained mortal era")
        if (self.phase == "expired_nonce_available") != (self.expiry_observation is not None):
            raise ValueError("bridge expiry observation missing or unexpected")
        if self.expiry_observation is not None:
            observed = self.expiry_observation
            if (
                observed.validator_hotkey != self.validator_hotkey
                or not self.attempt.era_death <= observed.block_number <= self.last_observed_block
                or observed.nonce != self.attempt.signing.nonce
                or (
                    observed.block_number == self.last_observed_block
                    and observed.block_hash != self.last_observed_block_hash
                )
            ):
                raise ValueError("bridge expiry observation does not resolve this attempt")
        return self


BridgeJournal = RegistrationBridgeJournal | RegistrationBridgeTransactionJournal


def parse_bridge_journal(raw: bytes) -> BridgeJournal:
    value = _canonical_object(raw)
    model = (
        RegistrationBridgeTransactionJournal
        if value.get("schema") == TRANSACTION_JOURNAL_SCHEMA
        else RegistrationBridgeJournal
    )
    journal = model.model_validate_json(raw)
    _require(canonical_json_bytes(journal) == raw, "journal_noncanonical")
    return journal


def evolve_journal(journal: BridgeJournal, **updates: object) -> BridgeJournal:
    _require(
        type(journal) in (RegistrationBridgeJournal, RegistrationBridgeTransactionJournal),
        "bridge_journal_version_invalid",
    )
    return type(journal).model_validate(
        journal.model_copy(update=updates).model_dump(mode="python", by_alias=True)
    )


def _observation_follows(
    journal: BridgeJournal, observation: RegistrationBridgeObservation
) -> None:
    _require(journal.validator_hotkey == observation.validator_hotkey, "journal_validator_changed")
    _require(observation.block_number >= journal.last_observed_block, "journal_finality_rollback")
    _require(
        observation.block_number != journal.last_observed_block
        or observation.block_hash == journal.last_observed_block_hash,
        "journal_finality_equivocation",
    )


def _signing_record(
    state: BridgeSigningState, observation: RegistrationBridgeObservation, *, now: datetime
) -> BridgeSigningRecord:
    record = BridgeSigningRecord.from_state(state)
    _require(
        record.validator_hotkey == observation.validator_hotkey
        and (record.block_number, record.block_hash, record.timestamp_ms)
        == (observation.block_number, observation.block_hash, observation.block_timestamp_ms),
        "bridge_signing_observation_changed",
    )
    _require(
        0 <= datetime_to_unix_ms(now) - record.timestamp_ms <= 120_000,
        "bridge_signing_snapshot_stale",
    )
    return record


def new_transaction_journal(
    policy: SignedRegistrationBridgePolicy,
    observation: RegistrationBridgeObservation,
    decision: RegistrationBridgeDecision,
    health: list[RegistrationBridgeHealth],
    *,
    signing_state: BridgeSigningState,
    previous: BridgeJournal,
    now: datetime,
    health_observation: RegistrationBridgeObservation | None = None,
) -> RegistrationBridgeTransactionJournal:
    previous = parse_bridge_journal(canonical_json_bytes(previous))
    _require(
        previous.phase in {"idle", "applied", "expired_nonce_available"},
        "prior_submission_outcome_unknown",
    )
    _observation_follows(previous, observation)
    _require(
        previous.attempt is None or previous.attempt.preflight_block < observation.block_number,
        "bridge_attempt_preflight_not_advanced",
    )
    _require(decision.action == "submit", "weight_submission_not_due")
    signing = _signing_record(signing_state, observation, now=now)
    intent = _new_attempt(
        policy, observation, decision, health, health_observation=health_observation
    )
    immutable = intent.model_dump(mode="json", by_alias=True, exclude={"attempt_id"})
    immutable.setdefault("health_observation", None)
    immutable["signing"] = signing.model_dump(mode="json")
    immutable["attempt_id"] = hashlib.sha256(
        RegistrationBridgeSigningAttempt._identity_domain + canonical_json_bytes(immutable)
    ).hexdigest()
    return RegistrationBridgeTransactionJournal(
        schema=TRANSACTION_JOURNAL_SCHEMA,
        validator_hotkey=observation.validator_hotkey,
        legacy_journal_sha256=previous.legacy_journal_sha256,
        phase="preparing",
        attempt=RegistrationBridgeSigningAttempt.model_validate(immutable),
        weight_call=None,
        last_observed_block=observation.block_number,
        last_observed_block_hash=observation.block_hash,
        updated_at_unix_ms=datetime_to_unix_ms(now),
        signed_extrinsic=None,
        signed_extrinsic_hash=None,
        expiry_observation=None,
    )


def retain_signed_extrinsic(
    journal: RegistrationBridgeTransactionJournal, encoded: bytes, *, now: datetime
) -> RegistrationBridgeTransactionJournal:
    _require(
        type(journal) is RegistrationBridgeTransactionJournal, "bridge_journal_version_invalid"
    )
    _require(journal.phase == "preparing", "bridge_attempt_already_signed")
    envelope = exact_signed_extrinsic(encoded)
    return evolve_journal(
        journal,
        phase="signed",
        signed_extrinsic=encoded.hex(),
        signed_extrinsic_hash=envelope.extrinsic_hash,
        updated_at_unix_ms=datetime_to_unix_ms(now),
    )


def reconcile_transaction_journal(
    journal: BridgeJournal,
    observation: RegistrationBridgeObservation,
    *,
    now: datetime,
    signing_state: BridgeSigningState | None = None,
) -> BridgeJournal:
    journal = parse_bridge_journal(canonical_json_bytes(journal))
    if type(journal) is RegistrationBridgeJournal:
        return reconcile_registration_bridge_journal(journal, observation, now=now)
    _require(
        type(journal) is RegistrationBridgeTransactionJournal, "bridge_journal_version_invalid"
    )
    _observation_follows(journal, observation)
    updates = dict(
        last_observed_block=observation.block_number,
        last_observed_block_hash=observation.block_hash,
        updated_at_unix_ms=datetime_to_unix_ms(now),
    )
    if journal.phase in {"preparing", "signed", "submitting", "outcome_unknown"}:
        _require(type(signing_state) is BridgeSigningState, "prior_submission_outcome_unknown")
        observed = _signing_record(signing_state, observation, now=now)
        _require(
            observed.block_number >= journal.attempt.era_death
            and observed.nonce == journal.attempt.signing.nonce,
            "prior_submission_outcome_unknown",
        )
        # Old bytes cannot land after their mortal era. This records present
        # nonce availability, not a claim that no historical effect occurred.
        updates.update(phase="expired_nonce_available", expiry_observation=observed)
    elif journal.phase == "receipt_returned":
        receipt = journal.weight_call
        writer = next(p for p in observation.participants if p.hotkey == journal.validator_hotkey)
        _require(
            observation.block_number >= receipt.block_number
            and writer.last_update == receipt.block_number
            and observation.validator_row == journal.attempt.expected_row,
            "retained_finalized_receipt_effect_not_visible",
        )
        _require(
            observation.block_number != receipt.block_number
            or observation.block_hash == receipt.block_hash,
            "retained_receipt_hash_mismatch",
        )
        updates["phase"] = "applied"
    return evolve_journal(journal, **updates)
