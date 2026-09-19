"""Pure legacy bridge attempt identities and journal transitions.

Persisted version-1 bytes and hashes remain unchanged. Historical unknown
attempts stay held unless the existing finalized-receipt recovery proves them.
Filesystem ownership and network operations live outside this module.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from ..bootstrap_weight_operator import BootstrapExtrinsicReference
from ..encoding import account_id32
from ..encoding import datetime_to_unix_ms as _datetime_ms
from ..protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes
from .policy import (
    PositiveInt,
    RegistrationBridgeError,
    SignedRegistrationBridgePolicy,
    UInt,
    _require,
    registration_bridge_policy_sha256,
    verify_registration_bridge_policy,
)
from .selection import (
    RegistrationBridgeHealth,
    RegistrationBridgeObservation,
    RegistrationBridgeParticipant,
    _validate_row,
    registration_bridge_roster_sha256,
)

REGISTRATION_BRIDGE_JOURNAL_SCHEMA = "umi-registration-bridge-journal/1"


class RegistrationBridgeAttempt(StrictProtocolModel):
    attempt_id: Hex32
    signed_policy: SignedRegistrationBridgePolicy
    policy_sha256: Hex32
    validator_hotkey: str
    preflight_block: PositiveInt
    preflight_block_hash: BlockHash
    prior_last_update: UInt
    roster: Annotated[list[RegistrationBridgeParticipant], Field(min_length=256, max_length=256)]
    owner_associated_hotkeys: Annotated[list[str], Field(min_length=1, max_length=4096)]
    roster_sha256: Hex32
    expected_row: Annotated[list[list[int]], Field(min_length=256, max_length=256)]
    health: Annotated[list[RegistrationBridgeHealth], Field(max_length=255)]

    @model_validator(mode="after")
    def identity(self) -> Self:
        account_id32(self.validator_hotkey)
        _validate_row(self.expected_row)
        if self.policy_sha256 != registration_bridge_policy_sha256(self.signed_policy):
            raise ValueError("bridge attempt policy identity mismatch")
        verify_registration_bridge_policy(
            self.signed_policy,
            expected_revision=self.signed_policy.body.umi_git_revision,
            current_block=self.preflight_block,
        )
        immutable = self.model_dump(mode="json", by_alias=True, exclude={"attempt_id"})
        if (
            self.attempt_id
            != hashlib.sha256(
                b"umi-registration-bridge-attempt-v1\0" + canonical_json_bytes(immutable)
            ).hexdigest()
        ):
            raise ValueError("bridge attempt identity mismatch")
        return self


class RegistrationBridgeChurnAttempt(RegistrationBridgeAttempt):
    """Retain the original probe snapshot alongside the final submission roster.

    Historical attempts keep their exact bytes and hash. Only a changed roster
    needs this additional evidence; receipts are never relabeled as fresh probes.
    """

    health_observation: RegistrationBridgeObservation

    @model_validator(mode="after")
    def probe_snapshot(self) -> Self:
        if (
            self.health_observation.validator_hotkey != self.validator_hotkey
            or self.health_observation.block_number >= self.preflight_block
        ):
            raise ValueError("bridge probe snapshot does not precede the same writer's submission")
        return self


class RegistrationBridgeJournal(StrictProtocolModel):
    schema_: Literal[REGISTRATION_BRIDGE_JOURNAL_SCHEMA] = Field(alias="schema")
    validator_hotkey: str
    legacy_journal_sha256: Hex32 | None
    phase: Literal["idle", "submitting", "outcome_unknown", "receipt_returned", "applied"]
    attempt: RegistrationBridgeChurnAttempt | RegistrationBridgeAttempt | None
    weight_call: BootstrapExtrinsicReference | None
    last_observed_block: PositiveInt
    last_observed_block_hash: BlockHash
    updated_at_unix_ms: PositiveInt

    @model_validator(mode="after")
    def bindings(self) -> Self:
        account_id32(self.validator_hotkey)
        if (self.phase == "idle") != (self.attempt is None):
            raise ValueError("bridge journal attempt missing or unexpected")
        if (self.phase in {"receipt_returned", "applied"}) != (self.weight_call is not None):
            raise ValueError("bridge journal finalized receipt missing or unexpected")
        if self.attempt is not None:
            if self.validator_hotkey != self.attempt.validator_hotkey:
                raise ValueError("bridge journal validator mismatch")
            if self.last_observed_block < self.attempt.preflight_block:
                raise ValueError("bridge journal finality rollback")
            if self.weight_call is not None and not (
                self.attempt.preflight_block
                < self.weight_call.block_number
                < self.attempt.signed_policy.body.submission_limit
            ):
                raise ValueError("bridge receipt outside attempted interval")
        return self


def reconcile_registration_bridge_journal(
    journal: RegistrationBridgeJournal, observation: RegistrationBridgeObservation, *, now: datetime
) -> RegistrationBridgeJournal:
    _require(journal.validator_hotkey == observation.validator_hotkey, "journal_validator_changed")
    _require(observation.block_number >= journal.last_observed_block, "journal_finality_rollback")
    _require(
        observation.block_number != journal.last_observed_block
        or observation.block_hash == journal.last_observed_block_hash,
        "journal_finality_equivocation",
    )
    updates = {
        "last_observed_block": observation.block_number,
        "last_observed_block_hash": observation.block_hash,
        "updated_at_unix_ms": _datetime_ms(now),
    }
    if journal.phase in {"submitting", "outcome_unknown"}:
        # Equality proves an effect, not that this exact uncertain attempt is
        # drained. Without signed transaction identity/nonce/era we never retry.
        raise RegistrationBridgeError("prior_submission_outcome_unknown")
    if journal.phase == "receipt_returned":
        receipt, attempt = journal.weight_call, journal.attempt
        writer = next(p for p in observation.participants if p.hotkey == journal.validator_hotkey)
        _require(
            observation.block_number >= receipt.block_number
            and writer.last_update == receipt.block_number
            and observation.validator_row == attempt.expected_row,
            "retained_finalized_receipt_effect_not_visible",
        )
        if observation.block_number == receipt.block_number:
            _require(observation.block_hash == receipt.block_hash, "retained_receipt_hash_mismatch")
        updates["phase"] = "applied"
    return RegistrationBridgeJournal.model_validate(
        journal.model_copy(update=updates).model_dump(mode="python", by_alias=True)
    )


def _new_attempt(policy, observation, decision, health, *, health_observation=None):
    body = {
        "signed_policy": policy.model_dump(mode="json", by_alias=True),
        "policy_sha256": registration_bridge_policy_sha256(policy),
        "validator_hotkey": observation.validator_hotkey,
        "preflight_block": observation.block_number,
        "preflight_block_hash": observation.block_hash,
        "prior_last_update": decision.validator_last_update,
        "roster": [p.model_dump(mode="json") for p in observation.participants],
        "owner_associated_hotkeys": observation.owner_associated_hotkeys,
        "roster_sha256": decision.roster_sha256,
        "expected_row": decision.expected_row,
        "health": [h.model_dump(mode="json") for h in health],
    }
    attempt_type = RegistrationBridgeAttempt
    if health_observation is not None and (
        registration_bridge_roster_sha256(health_observation) != decision.roster_sha256
    ):
        body["health_observation"] = health_observation.model_dump(mode="json")
        attempt_type = RegistrationBridgeChurnAttempt
    body["attempt_id"] = hashlib.sha256(
        b"umi-registration-bridge-attempt-v1\0" + canonical_json_bytes(body)
    ).hexdigest()
    return attempt_type.model_validate(body)
