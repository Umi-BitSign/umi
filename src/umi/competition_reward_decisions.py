"""Authenticated standing reward decisions selected by current native proofs.

This consumer retains signed history across outages. Its output identifies the
evidence required for admission; it grants no transaction authority. Native
package replay, prior opportunity, series admission and legacy handoff proofs
remain mandatory at the execution boundary.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_recovery import (
    Block,
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    StandingCohortRecoveryAuthority,
    verify_recovery_authority,
    verify_recovery_quorum,
)
from .competition_reward_control import (
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from .competition_round_journal import RoundJournal
from .grandpa_finality import FINNEY_GENESIS_HASH
from .open_competition import CompetitionPolicy, Hotkey, Signature, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_DECISION_BYTES = 128 * 1024
MAX_DECISIONS = 514
DecisionSource = Callable[[str], bytes]


class StandingRewardSeries(StrictProtocolModel):
    """Selected by the host's approved configuration, never by a remote object."""

    schema_: Literal["umi-standing-reward-series/1"] = Field(alias="schema")
    genesis_hash: Literal[FINNEY_GENESIS_HASH]
    netuid: Literal[78]
    policy_sha256: Hex32
    policy_epoch: Annotated[int, Field(ge=1, le=2**32 - 1)]
    manifest_sha256: Hex32
    control_hotkey: Hotkey
    recovery: SignedCohortRecoveryAuthority
    cohorts: Annotated[tuple[RecoverableCohortPlan, ...], Field(min_length=1, max_length=512)]
    validators: Annotated[tuple[Hotkey, ...], Field(min_length=1, max_length=256)]
    maximum_proof_lag_blocks: Annotated[int, Field(ge=1, le=7200)]
    maximum_transaction_lifetime_blocks: Annotated[int, Field(ge=1, le=65536)]
    lifetime: Literal["until_superseded_or_revoked"]

    @model_validator(mode="after")
    def ordered(self):
        numbers = [p.sequence for p in self.cohorts]
        keys = [identity(k) for k in self.validators]
        if (
            numbers != list(range(numbers[0], numbers[0] + len(numbers)))
            or len({digest(p) for p in self.cohorts}) != len(self.cohorts)
            or keys != sorted(set(keys))
            or not isinstance(self.recovery.authority, StandingCohortRecoveryAuthority)
            or tuple(sorted(digest(p) for p in self.cohorts))
            != self.recovery.authority.cohort_sha256s
            or any(p.policy_sha256 != self.policy_sha256 for p in self.cohorts)
            or self.recovery.authority.policy_sha256 != self.policy_sha256
        ):
            raise ValueError("standing series must bind ordered cohorts and standing authority")
        return self


class RewardActivation(StrictProtocolModel):
    cohort_sha256: Hex32
    allocation_sha256: Hex32
    package_sha256: Hex32
    recovery_tip_sha256: Hex32
    # The first activation names qualified legacy handoff evidence. Later
    # activations name the preceding cohort's certified reward opportunity.
    prior_opportunity_sha256: Hex32


class RewardControlDecision(StrictProtocolModel):
    schema_: Literal["umi-reward-control-decision/1"] = Field(alias="schema")
    series_sha256: Hex32
    sequence: Annotated[int, Field(ge=0, le=MAX_DECISIONS - 1)]
    predecessor_sha256: Hex32 | None
    kind: Literal["admit_series", "activate", "revoke"]
    observed_at_block: Block
    activation: RewardActivation | None

    @model_validator(mode="after")
    def shape(self):
        if (
            (self.sequence == 0) != (self.kind == "admit_series")
            or (self.sequence == 0) != (self.predecessor_sha256 is None)
            or (self.kind == "activate") != (self.activation is not None)
        ):
            raise ValueError("reward decision fields do not match its transition")
        return self


class SignedRewardControlDecision(StrictProtocolModel):
    decision: RewardControlDecision
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


@dataclass(frozen=True)
class StandingRewardSelection:
    """Derived selection only; all referenced native evidence still needs replay."""

    series_sha256: str
    decision_sha256: str
    sequence: int
    state: Literal["admitted", "draining", "selected", "revoked"]
    committed_at_block: int
    effective_at_block: int | None
    activation: RewardActivation | None
    chain_submission_authorized: Literal[False] = False


def verify_reward_decisions(
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    decisions: tuple[SignedRewardControlDecision, ...],
) -> tuple[SignedRewardControlDecision, ...]:
    """Verify the complete signed prefix without inferring past chain effects."""
    series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if series.policy_sha256 != digest(policy):
        raise ValueError("standing series policy differs from selected policy")
    authority = verify_recovery_authority(series.recovery, policy)
    if not 1 <= len(decisions) <= len(series.cohorts) + 2:
        raise ValueError("reward history is empty or exceeds the admitted series")
    selected, previous, activated = [], None, 0
    for index, raw in enumerate(decisions):
        item = SignedRewardControlDecision.model_validate_json(canonical_json_bytes(raw))
        body = item.decision
        if (
            body.series_sha256 != digest(series)
            or body.sequence != index
            or body.predecessor_sha256 != (digest(previous) if previous else None)
            or (previous is not None and body.observed_at_block < previous.observed_at_block)
            or (previous is not None and previous.kind == "revoke")
        ):
            raise ValueError("reward history changed authority, order, parent or a revoked series")
        verify_recovery_quorum(body, item.signatures, policy)
        if index == 0:
            if (
                not authority.issued_at_block
                <= body.observed_at_block
                <= policy.valid_through_block
            ):
                raise ValueError("series genesis was not signed under timely recovery authority")
        elif body.kind == "activate":
            if activated >= len(series.cohorts) or body.activation.cohort_sha256 != digest(
                series.cohorts[activated]
            ):
                raise ValueError("reward history skipped, repeated or reordered an admitted cohort")
            activated += 1
        previous = body
        selected.append(item)
    return tuple(selected)


class StandingRewardControlReader:
    """One owner retains decisions; every selection needs a fresh owned proof."""

    def __init__(
        self,
        root: Path,
        series: StandingRewardSeries,
        policy: CompetitionPolicy,
        *,
        expected_series_sha256: str,
        expected_chain_config_sha256: str,
        maximum_bytes: int,
    ):
        self.series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if digest(self.series) != expected_series_sha256:
            raise ValueError("standing series differs from independently selected authority")
        self.series_sha256 = expected_series_sha256
        # Strict digest validation also rejects accidental configuration paths.
        self.chain_config_sha256 = expected_chain_config_sha256
        if (
            type(expected_chain_config_sha256) is not str
            or len(expected_chain_config_sha256) != 64
            or any(c not in "0123456789abcdef" for c in expected_chain_config_sha256)
        ):
            raise ValueError("standing reader chain configuration digest is invalid")
        if self.series.policy_sha256 != digest(self.policy):
            raise ValueError("standing reader policy differs from its series")
        verify_recovery_authority(self.series.recovery, self.policy)
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-standing-reward-reader/1",
                "series_sha256": self.series_sha256,
            },
            maximum_rounds=MAX_DECISIONS,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=MAX_DECISION_BYTES,
        )

    def _proof(self, observation: OwnedRewardControlObservation) -> None:
        validate_owned_reward_control(
            observation,
            expected_control_hotkey=self.series.control_hotkey,
            expected_chain_config_sha256=self.chain_config_sha256,
        )

    def select(
        self, observation: OwnedRewardControlObservation, source: DecisionSource
    ) -> StandingRewardSelection:
        self._proof(observation)
        if observation.control_sha256 is None:
            raise ValueError("standing control commitment is absent")
        with self.journal.locked():
            keys = self.journal.keys("reward_control_decision")
            if len(keys) > len(self.series.cohorts) + 2:
                raise ValueError("retained reward history exceeds the admitted series")
            retained = {}
            for index, key in enumerate(keys):
                if key != f"{index:04d}":
                    raise ValueError("retained reward history is not a contiguous prefix")
                item = SignedRewardControlDecision.model_validate_json(
                    canonical_json_bytes(self.journal.get("reward_control_decision", key))
                )
                if item.decision.sequence != index:
                    raise ValueError("retained reward decision is in a different sequence slot")
                retained[digest(item.decision)] = item

            reversed_chain, key = [], observation.control_sha256
            while key is not None:
                if len(reversed_chain) >= len(self.series.cohorts) + 2:
                    raise ValueError("current reward history exceeds the admitted series")
                item = retained.get(key)
                if item is None:
                    raw = source(key)
                    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_DECISION_BYTES:
                        raise ValueError("reward decision source exceeds its byte bound")
                    item = SignedRewardControlDecision.model_validate_json(raw)
                    if canonical_json_bytes(item) != raw:
                        raise ValueError("reward decision source is not canonical")
                if digest(item.decision) != key:
                    raise ValueError("reward decision source differs from the proven identity")
                reversed_chain.append(item)
                key = item.decision.predecessor_sha256
            decisions = verify_reward_decisions(
                self.series, self.policy, tuple(reversed(reversed_chain))
            )
            if len(decisions) < len(keys) or any(
                digest(decisions[i].decision) not in retained for i in range(len(keys))
            ):
                raise ValueError("current reward control conflicts with retained history")
            tip = decisions[-1].decision
            if (
                not tip.observed_at_block
                <= observation.committed_at_block
                <= observation.snapshot.block_number
            ):
                raise ValueError(
                    "reward decision predates its signed observation or is ahead of finality"
                )
            if (
                tip.kind == "admit_series"
                and observation.committed_at_block > self.policy.valid_through_block
            ):
                raise ValueError("series genesis was committed after its admission window")
            self._proof(observation)

            def record_head(db):
                old = db.execute("SELECT block FROM highwater LIMIT 2").fetchall()
                if old and (len(old) != 1 or old[0][0] > observation.snapshot.block_number):
                    raise ValueError("standing control finalized head regressed")
                db.execute("DELETE FROM highwater")
                db.execute("INSERT INTO highwater VALUES (?)", (observation.snapshot.block_number,))

            # Persist a complete authenticated prefix before returning a selection.
            # A failed acknowledgement retries the same immutable records.
            self.journal.put_many(
                tuple(
                    ("reward_control_decision", f"{i:04d}", item)
                    for i, item in enumerate(decisions)
                    if i >= len(keys)
                ),
                index=record_head,
            )
            self._proof(observation)
            effective = (
                observation.committed_at_block
                + self.series.maximum_proof_lag_blocks
                + self.series.maximum_transaction_lifetime_blocks
                if tip.kind == "activate"
                else None
            )
            state = (
                "admitted"
                if tip.kind == "admit_series"
                else "revoked"
                if tip.kind == "revoke"
                else "draining"
                if observation.snapshot.block_number < effective
                else "selected"
            )
            return StandingRewardSelection(
                self.series_sha256,
                digest(tip),
                tip.sequence,
                state,
                observation.committed_at_block,
                effective,
                tip.activation,
            )
