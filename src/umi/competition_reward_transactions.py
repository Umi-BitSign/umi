"""Private standing transaction intents and exact signed bytes.

These records preserve recovery inputs. They grant no signing, submission or
retry authority. An unresolved intent excludes a different attempt, including
after restart; native reconciliation must be integrated before release.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

import bittensor as bt
from pydantic import Field, model_validator

from .competition_chain_state import OwnedCompetitionChainObservation
from .competition_cohort_reward_allocation import CohortRewardProjection
from .competition_round_journal import RecordReservation, RoundJournal
from .open_competition import Hotkey, digest, identity
from .protocol import BlockHash, Hex32, StrictProtocolModel, canonical_json_bytes, sha256_hex
from .signed_extrinsic import MAX_SIGNED_EXTRINSIC_BYTES, exact_signed_extrinsic

Block = Annotated[int, Field(ge=1, le=2**53 - 1)]
MAX_CONTEXT_BYTES = 32 * 1024**2
MAX_INTENT_BYTES = 128 * 1024
MAX_SIGNED_RECORD_BYTES = 2 * MAX_SIGNED_EXTRINSIC_BYTES + 1024


def standing_weight_call(
    projection: CohortRewardProjection, chain: OwnedCompetitionChainObservation
):
    """Check current direct-call constraints and include every registered UID.

    The caller must validate native ownership, current standing selection and
    the allocation first. These checks establish call feasibility only.
    """
    count = chain.registered_uid_count
    if (
        chain.validator_permit is not True
        or chain.mechanism_count != 1
        or chain.commit_reveal_enabled is not False
        or not 1 <= count <= chain.max_allowed_uids <= 256
        or chain.validator_last_update + chain.weights_rate_limit > chain.block
    ):
        raise ValueError("standing transaction is held by current validator or chain constraints")
    pairs = tuple(zip(projection.uids, projection.weights, strict=True))
    if (
        tuple(uid for uid, _ in pairs) != tuple(sorted({uid for uid, _ in pairs}))
        or any(
            type(uid) is not int
            or not 0 <= uid < count
            or type(w) is not int
            or not 0 <= w <= 65535
            for uid, w in pairs
        )
        or sum(w for _, w in pairs) != 65535
    ):
        raise ValueError("standing transaction requires a conserved registered reward row")
    selected = dict(pairs)
    weights = tuple(selected.get(uid, 0) for uid in range(count))
    if (
        len(weights) < min(chain.min_allowed_weights, count)
        or max(weights) * 65535 > sum(weights) * chain.max_weights_limit
    ):
        raise ValueError("standing reward row does not satisfy finalized weight limits")
    return bt.calls.SubtensorModule.set_mechanism_weights(
        netuid=78,
        mecid=0,
        dests=list(range(count)),
        weights=list(weights),
        version_key=chain.weights_version_key,
    )


class StandingWeightIntent(StrictProtocolModel):
    schema_: Literal["umi-standing-weight-intent/1"] = Field(alias="schema")
    series_sha256: Hex32
    decision_sha256: Hex32
    activation_sha256: Hex32
    chain_config_sha256: Hex32
    validator_hotkey: Hotkey
    block: Block
    block_hash: BlockHash
    prior_last_update: Annotated[int, Field(ge=0, le=2**53 - 1)]
    nonce: Annotated[int, Field(ge=0, le=2**32 - 1)]
    mortality_period: Annotated[int, Field(ge=4, le=4096)]
    weights_version_key: Annotated[int, Field(ge=0, le=2**64 - 1)]
    projection: CohortRewardProjection
    destinations: Annotated[tuple[int, ...], Field(min_length=1, max_length=256)]
    weights: Annotated[tuple[int, ...], Field(min_length=1, max_length=256)]
    chain_evidence_sha256: Hex32
    control_evidence_sha256: Hex32
    metadata_sha256: Hex32
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bindings(self):
        if (
            self.prior_last_update > self.block
            or self.mortality_period & (self.mortality_period - 1)
            or self.block + self.mortality_period > 2**53 - 1
            or self.destinations != tuple(range(len(self.weights)))
            or any(type(w) is not int or not 0 <= w <= 65535 for w in self.weights)
            or sum(self.weights) != 65535
        ):
            raise ValueError("standing intent has invalid call or mortality bounds")
        sparse = tuple(zip(self.projection.uids, self.projection.weights, strict=True))
        if (
            any(type(uid) is not int or not 0 <= uid < len(self.weights) for uid, _ in sparse)
            or tuple(uid for uid, _ in sparse) != tuple(sorted({uid for uid, _ in sparse}))
            or any(type(weight) is not int or not 0 <= weight <= 65535 for _, weight in sparse)
            or tuple((uid, w) for uid, w in sparse if w)
            != tuple((uid, w) for uid, w in enumerate(self.weights) if w)
        ):
            raise ValueError("standing intent call differs from its reward projection")
        return self

    def call(self):
        return bt.calls.SubtensorModule.set_mechanism_weights(
            netuid=78,
            mecid=0,
            dests=list(self.destinations),
            weights=list(self.weights),
            version_key=self.weights_version_key,
        )


class StandingSignedWeight(StrictProtocolModel):
    intent_sha256: Hex32
    signed_extrinsic: Annotated[
        str,
        Field(
            min_length=2, max_length=2 * MAX_SIGNED_EXTRINSIC_BYTES, pattern=r"^(?:[0-9a-f]{2})+$"
        ),
    ]
    extrinsic_hash: BlockHash

    @model_validator(mode="after")
    def hash_matches(self):
        if (
            exact_signed_extrinsic(bytes.fromhex(self.signed_extrinsic)).extrinsic_hash
            != self.extrinsic_hash
        ):
            raise ValueError("standing signed bytes differ from their hash")
        return self


@dataclass(frozen=True)
class PendingStandingWeight:
    intent: StandingWeightIntent
    signed: StandingSignedWeight | None
    chain_submission_authorized: Literal[False] = False


class StandingWeightJournal:
    """Reuse the common journal's locking, atomic writes and capacity reservations.

    The selected series and hotkey bind this directory. Capacity may increase
    on reopen without changing the intent. Both unsigned and signed records
    remain pending until an independent native reconciliation consumer exists.
    No reset or retirement port is exposed by this storage component.
    """

    def __init__(
        self,
        root: Path,
        *,
        series_sha256: str,
        validator_hotkey: str,
        chain_config_sha256: str,
        maximum_bytes: int,
    ):
        self.binding = {
            "schema": "umi-standing-weight-journal/1",
            "series_sha256": series_sha256,
            "validator_account": identity(validator_hotkey),
            "chain_config_sha256": chain_config_sha256,
        }
        for value in (series_sha256, chain_config_sha256):
            if (
                type(value) is not str
                or len(value) != 64
                or any(c not in "0123456789abcdef" for c in value)
            ):
                raise ValueError("standing journal digest is invalid")
        self.journal = RoundJournal(
            root,
            self.binding,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=2 * MAX_CONTEXT_BYTES + 1024,
        )

    def _intent(self, value):
        if type(value) is not StandingWeightIntent:
            raise TypeError("standing intent requires its native record type")
        value = StandingWeightIntent.model_validate(value.model_dump(mode="python", by_alias=True))
        if (
            value.series_sha256 != self.binding["series_sha256"]
            or value.chain_config_sha256 != self.binding["chain_config_sha256"]
            or identity(value.validator_hotkey) != self.binding["validator_account"]
            or len(canonical_json_bytes(value)) > MAX_INTENT_BYTES
        ):
            raise ValueError("standing intent differs from the selected journal")
        return value

    def _pending(self):
        keys = self.journal.keys("standing_weight_intent")
        if len(keys) > 1:
            raise ValueError("standing journal has multiple unresolved attempts")
        signed_keys = self.journal.keys("standing_weight_signed")
        if any(key not in keys for key in signed_keys):
            raise ValueError("standing signed bytes lost their intent")
        if not keys:
            return None
        value = self.journal.get("standing_weight_intent", keys[0])
        intent = self._intent(StandingWeightIntent.model_validate_json(canonical_json_bytes(value)))
        if digest(intent) != keys[0]:
            raise ValueError("standing intent identity changed")
        for key in {
            intent.chain_evidence_sha256,
            intent.control_evidence_sha256,
            intent.metadata_sha256,
        }:
            self._object(key)
        value = self.journal.get("standing_weight_signed", keys[0])
        signed = None if value is None else StandingSignedWeight.model_validate(value)
        if signed is not None and signed.intent_sha256 != keys[0]:
            raise ValueError("standing signed bytes belong to another intent")
        return PendingStandingWeight(intent, signed)

    def pending(self) -> PendingStandingWeight | None:
        with self.journal.locked():
            return self._pending()

    def _object(self, key) -> bytes:
        value = self.journal.get("standing_weight_object", key)
        if not isinstance(value, dict) or set(value) != {"hex"} or type(value["hex"]) is not str:
            raise ValueError("standing transaction context is unavailable")
        text = value["hex"]
        if not 0 < len(text) <= 2 * MAX_CONTEXT_BYTES:
            raise ValueError("standing transaction context exceeds its bound")
        raw = bytes.fromhex(text)
        if raw.hex() != text or hashlib.sha256(raw).hexdigest() != key:
            raise ValueError("standing transaction context is corrupt")
        return raw

    def reserve(
        self, intent: StandingWeightIntent, *, chain: bytes, control: bytes, metadata: bytes
    ) -> PendingStandingWeight:
        """Commit exact recovery inputs and signature allowance before signing."""
        intent = self._intent(intent)
        key = digest(intent)
        objects = {}
        for raw, expected in (
            (chain, intent.chain_evidence_sha256),
            (control, intent.control_evidence_sha256),
            (metadata, intent.metadata_sha256),
        ):
            if type(raw) is not bytes or not 0 < len(raw) <= MAX_CONTEXT_BYTES:
                raise ValueError("standing transaction context exceeds its bound")
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("standing transaction context differs from its intent")
            objects[expected] = {"hex": raw.hex()}
        records = [("standing_weight_intent", key, intent)]
        records.extend(
            ("standing_weight_object", name, body) for name, body in sorted(objects.items())
        )
        specs = [
            RecordReservation(
                kind, name, len(canonical_json_bytes(body)), sha256_hex(canonical_json_bytes(body))
            )
            for kind, name, body in records
        ]
        specs.append(RecordReservation("standing_weight_signed", key, MAX_SIGNED_RECORD_BYTES))
        with self.journal.locked():
            old = self._pending()
            if old is not None and old.intent != intent:
                raise ValueError("another standing transaction requires native reconciliation")
            self.journal.reserve_records("standing-weight:" + key, specs)
            self.journal.put_many(records)
            return self._pending()

    def retain_signed(self, intent: StandingWeightIntent, encoded: bytes) -> PendingStandingWeight:
        """Store already checked bytes; this storage call cannot authorize them."""
        intent = self._intent(intent)
        envelope = exact_signed_extrinsic(encoded)
        key = digest(intent)
        value = StandingSignedWeight(
            intent_sha256=key,
            signed_extrinsic=encoded.hex(),
            extrinsic_hash=envelope.extrinsic_hash,
        )
        with self.journal.locked():
            old = self._pending()
            if old is None or old.intent != intent:
                raise ValueError("standing signature lacks its reserved original intent")
            if old.signed is not None:
                if old.signed != value:
                    raise ValueError("standing signature cannot replace retained bytes")
                return old
            self.journal.put("standing_weight_signed", key, value)
            return self._pending()
