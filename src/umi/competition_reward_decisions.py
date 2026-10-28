"""Authenticated standing reward decisions selected by current native proofs.

This consumer retains signed history across outages. Its output identifies the
evidence required for admission; it grants no transaction authority. Native
package replay, prior opportunity, series admission and legacy handoff proofs
remain mandatory at the execution boundary.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_cohort_recovery import (
    Block,
    RecoverableCohortPlan,
    SignedCohortRecoveryAuthority,
    StandingCohortRecoveryAuthority,
    verify_recovery_authority,
    verify_recovery_quorum,
)
from .competition_reward_adoption import (
    MAX_REWARD_DECISIONS,
    RewardAdoptionSelection,
    initial_reward_boundary,
    verify_adoption_selection,
    verify_reward_adoption,
)
from .competition_reward_adoption_consumer import RewardAdoptionConsumer
from .competition_reward_adoption_feed import RewardAdoptionFeed
from .competition_reward_control import (
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from .competition_reward_control_archive import (
    MAX_CONTROL_ARCHIVE_BYTES,
    MAX_CONTROL_METADATA_BYTES,
    HistoricalRewardControlProvider,
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_history import OwnedRewardControlHistory, validate_control_history
from .competition_reward_timing import activation_effective_block
from .competition_round_journal import RoundJournal
from .grandpa_finality import FINNEY_GENESIS_HASH
from .open_competition import CompetitionPolicy, Hotkey, Signature, digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_DECISION_BYTES = 128 * 1024
MAX_ADMISSION_BYTES = MAX_CONTROL_ARCHIVE_BYTES + 2 * MAX_CONTROL_METADATA_BYTES + 1024
MAX_DECISIONS = MAX_REWARD_DECISIONS
DecisionSource = Callable[[str], bytes]


class StandingRewardSeriesPredecessor(StrictProtocolModel):
    """Exact prior standing selection replaced by a successor series."""

    schema_: Literal["umi-standing-reward-series-predecessor/1"] = Field(alias="schema")
    series_sha256: Hex32
    policy_sha256: Hex32
    manifest_sha256: Hex32
    recovery_sha256: Hex32
    cohort_sha256: Hex32
    cohort_sequence: Annotated[int, Field(ge=1, le=2**32 - 2)]
    control_hotkey: Hotkey
    decision_sha256: Hex32
    activation_sha256: Hex32
    decision_committed_at_block: Block


class StandingRewardSeries(StrictProtocolModel):
    """Selected by the host's approved configuration, never by a remote object."""

    schema_: Literal["umi-standing-reward-series/1", "umi-standing-reward-series/2"] = Field(
        alias="schema"
    )
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
    predecessor: StandingRewardSeriesPredecessor | None = None

    @model_serializer(mode="wrap")
    def preserve_initial_series_bytes(self, handler):
        value = handler(self)
        if self.predecessor is None:
            value.pop("predecessor", None)
        return value

    @model_validator(mode="after")
    def ordered(self):
        numbers = [p.sequence for p in self.cohorts]
        keys = [identity(k) for k in self.validators]
        successor = self.schema_ == "umi-standing-reward-series/2"
        if (
            numbers != list(range(numbers[0], numbers[0] + len(numbers)))
            or len({digest(p) for p in self.cohorts}) != len(self.cohorts)
            or keys != sorted(set(keys))
            or not isinstance(self.recovery.authority, StandingCohortRecoveryAuthority)
            or tuple(sorted(digest(p) for p in self.cohorts))
            != self.recovery.authority.cohort_sha256s
            or any(p.policy_sha256 != self.policy_sha256 for p in self.cohorts)
            or self.recovery.authority.policy_sha256 != self.policy_sha256
            or successor != (self.predecessor is not None)
        ):
            raise ValueError("standing series must bind ordered cohorts and standing authority")
        if self.predecessor is not None and (
            self.predecessor.policy_sha256 != self.policy_sha256
            or identity(self.predecessor.control_hotkey) != identity(self.control_hotkey)
            or numbers[0] != self.predecessor.cohort_sequence + 1
            or self.recovery.authority.issued_at_block
            < self.predecessor.decision_committed_at_block
        ):
            raise ValueError("successor series differs from its signed predecessor boundary")
        return self


class RewardActivation(StrictProtocolModel):
    cohort_sha256: Hex32
    allocation_sha256: Hex32
    package_sha256: Hex32
    recovery_tip_sha256: Hex32
    # The first activation names qualified legacy handoff evidence. Later
    # activations name the preceding cohort's certified reward opportunity.
    prior_opportunity_sha256: Hex32
    reward_adoption_sha256: Hex32 | None = None
    effective_allocation_sha256: Hex32 | None = None

    @model_serializer(mode="wrap")
    def preserve_original_activation(self, handler):
        value = handler(self)
        if self.reward_adoption_sha256 is None:
            value.pop("reward_adoption_sha256", None)
            value.pop("effective_allocation_sha256", None)
        return value

    @model_validator(mode="after")
    def adopted_pair(self):
        if (self.reward_adoption_sha256 is None) != (self.effective_allocation_sha256 is None):
            raise ValueError("effective rewards require their exact authenticated adoption")
        return self


class RewardControlDecision(StrictProtocolModel):
    schema_: Literal[
        "umi-reward-control-decision/1",
        "umi-reward-control-decision/2",
        "umi-reward-control-decision/3",
        "umi-reward-control-decision/4",
    ] = Field(alias="schema")
    series_sha256: Hex32
    sequence: Annotated[int, Field(ge=0, le=MAX_DECISIONS - 1)]
    predecessor_sha256: Hex32 | None
    kind: Literal[
        "admit_series",
        "activate",
        "revoke",
        "suspend_activation",
        "revise_activation",
        "resume_activation",
    ]
    observed_at_block: Block
    activation: RewardActivation | None
    revision_clearance_sha256: Hex32 | None = None
    admission_adoption_sha256: Hex32 | None = None
    admission_predecessor_committed_at_block: Block | None = None

    @model_serializer(mode="wrap")
    def preserve_original_decision(self, handler):
        value = handler(self)
        if self.revision_clearance_sha256 is None:
            value.pop("revision_clearance_sha256", None)
        if self.admission_adoption_sha256 is None:
            value.pop("admission_adoption_sha256", None)
        if self.admission_predecessor_committed_at_block is None:
            value.pop("admission_predecessor_committed_at_block", None)
        return value

    @model_validator(mode="after")
    def shape(self):
        bootstrap = self.schema_ == "umi-reward-control-decision/4"
        successor = self.schema_ == "umi-reward-control-decision/2" or bootstrap
        if (
            (self.sequence == 0) != (self.kind == "admit_series")
            or bootstrap != (self.admission_adoption_sha256 is not None)
            or bootstrap != (self.admission_predecessor_committed_at_block is not None)
            or (bootstrap and self.sequence != 0)
            or (self.sequence == 0 and successor != (self.predecessor_sha256 is not None))
            or (self.sequence != 0 and self.predecessor_sha256 is None)
            or (
                self.kind
                in {"activate", "suspend_activation", "revise_activation", "resume_activation"}
            )
            != (self.activation is not None)
            or (self.kind == "revise_activation") != (self.revision_clearance_sha256 is not None)
            or (
                self.schema_ != "umi-reward-control-decision/3"
                and (
                    self.kind in {"suspend_activation", "revise_activation", "resume_activation"}
                    or (
                        self.activation is not None
                        and self.activation.reward_adoption_sha256 is not None
                    )
                )
            )
            or (self.sequence == 0 and self.schema_ == "umi-reward-control-decision/3")
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
    state: Literal["admitted", "draining", "selected", "revoked", "suspended"]
    committed_at_block: int
    effective_at_block: int | None
    activation: RewardActivation | None
    chain_submission_authorized: Literal[False] = False


@dataclass(frozen=True)
class AdmittedStandingRewardSelection:
    """Current selection plus independently proved original series admission.

    Reward-package, opportunity, registration and transaction checks still
    belong to execution. A historical proof never substitutes for current control.
    """

    selection: StandingRewardSelection
    admission: OwnedHistoricalRewardControl
    chain_submission_authorized: Literal[False] = False


@dataclass(frozen=True)
class HistoryVerifiedStandingRewardSelection:
    """Selection checked against every control write since authority issuance.

    This includes admission and overwritten decisions. Execution still needs
    native package, opportunity, recipient and transaction verification.
    """

    selection: StandingRewardSelection
    history: OwnedRewardControlHistory
    # The preceding activation remains effective during a successor's drain.
    # This is a control-history fact, not permission to sign the old allocation
    # or proof of validator eligibility, elapsed opportunity or reward credits.
    effective_selection: StandingRewardSelection | None
    chain_submission_authorized: Literal[False] = False
    initial_selection: StandingRewardSelection | None = None
    activation_transitions: tuple[StandingRewardSelection, ...] = ()


@dataclass(frozen=True)
class HistoricalStandingRewardSelection:
    """Control selection at a past finalized root, never current authority."""

    observation: OwnedHistoricalRewardControl
    selection: StandingRewardSelection
    history: OwnedRewardControlHistory
    effective_selection: StandingRewardSelection | None
    chain_submission_authorized: Literal[False] = False
    initial_selection: StandingRewardSelection | None = None
    activation_transitions: tuple[StandingRewardSelection, ...] = ()


def verify_reward_decisions(
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    decisions: tuple[SignedRewardControlDecision, ...],
    *,
    reward_adoptions: RewardAdoptionSelection | None = None,
) -> tuple[SignedRewardControlDecision, ...]:
    """Verify the complete signed prefix without inferring past chain effects."""
    series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if series.policy_sha256 != digest(policy):
        raise ValueError("standing series policy differs from selected policy")
    verify_recovery_authority(series.recovery, policy)
    reward_adoptions = verify_adoption_selection(reward_adoptions, series, policy)
    if not 1 <= len(decisions) <= reward_decision_capacity(series, reward_adoptions):
        raise ValueError("reward history is empty or exceeds the admitted series")
    selected, previous, activated = [], None, 0
    for index, raw in enumerate(decisions):
        item = SignedRewardControlDecision.model_validate_json(canonical_json_bytes(raw))
        body = item.decision
        _decision_body(
            series,
            policy,
            index,
            previous,
            activated,
            body,
            preceding=tuple(selected),
            reward_adoptions=reward_adoptions,
        )
        verify_recovery_quorum(body, item.signatures, policy)
        selected.append(item)
        previous = body
        activated += body.kind == "activate"
    return tuple(selected)


def _decision_body(
    series, policy, index, previous, activated, body, *, preceding=(), reward_adoptions=None
):
    predecessor, committed, adoption_sha = initial_reward_boundary(series, reward_adoptions)
    expected_schema = (
        "umi-reward-control-decision/4"
        if index == 0 and adoption_sha is not None
        else "umi-reward-control-decision/1"
        if series.predecessor is None
        else "umi-reward-control-decision/2"
    )
    if (
        (
            body.schema_ != expected_schema
            and not (
                body.schema_ == "umi-reward-control-decision/3"
                and reward_adoptions is not None
                and body.sequence > 0
            )
        )
        or body.series_sha256 != digest(series)
        or body.sequence != index
        or body.predecessor_sha256 != (digest(previous) if previous else predecessor)
        or body.admission_adoption_sha256 != (adoption_sha if index == 0 else None)
        or body.admission_predecessor_committed_at_block
        != (committed if index == 0 and adoption_sha is not None else None)
        or (previous is not None and body.observed_at_block < previous.observed_at_block)
        or (previous is not None and previous.kind == "revoke")
        or body.sequence >= reward_decision_capacity(series, reward_adoptions)
    ):
        raise ValueError("reward history changed authority, order, parent or a revoked series")
    if previous is None:
        if not (
            max(
                series.recovery.authority.issued_at_block,
                committed,
            )
            <= body.observed_at_block
            <= policy.valid_through_block
        ):
            raise ValueError("series genesis was not signed under timely recovery authority")
        if adoption_sha is not None:
            verify_reward_adoption(
                reward_adoptions,
                adoption_sha,
                series=series,
                policy=policy,
                current_block=body.observed_at_block,
            )
    elif body.kind == "activate" and (
        activated >= len(series.cohorts)
        or body.activation.cohort_sha256 != digest(series.cohorts[activated])
    ):
        raise ValueError("reward history skipped, repeated or reordered an admitted cohort")
    if body.activation is not None and body.activation.reward_adoption_sha256 is not None:
        verify_reward_adoption(
            reward_adoptions,
            body.activation.reward_adoption_sha256,
            series=series,
            policy=policy,
            activation=body.activation,
            current_block=body.observed_at_block,
        )
    if (
        previous is not None
        and previous.kind == "suspend_activation"
        and body.kind not in {"revise_activation", "resume_activation", "revoke"}
    ):
        raise ValueError("suspended rewards require revision, explicit resume or revocation")
    if body.kind in {"suspend_activation", "revise_activation", "resume_activation"}:
        original = effective_activation_decision(preceding)
        if original is None or original.activation is None:
            raise ValueError("reward revision has no preceding effective activation")
        old, new = original.activation, body.activation
        if body.kind == "suspend_activation":
            if previous.kind == "suspend_activation" or new != old:
                raise ValueError("reward suspension changes the preceding activation")
        elif previous.kind != "suspend_activation":
            raise ValueError("reward revision requires a finalized writer suspension")
        elif body.kind == "resume_activation":
            if new != old:
                raise ValueError("reward resume cannot change the suspended allocation")
        else:
            fixed = (
                "cohort_sha256",
                "allocation_sha256",
                "package_sha256",
                "recovery_tip_sha256",
                "prior_opportunity_sha256",
            )
            if any(getattr(old, k) != getattr(new, k) for k in fixed) or (
                new.reward_adoption_sha256 is None
                or new.reward_adoption_sha256 == old.reward_adoption_sha256
            ):
                raise ValueError("reward revision changes original evidence or repeats economics")
            adopted = reward_adoptions.get(new.reward_adoption_sha256).adoption
            if old.reward_adoption_sha256 is not None and adopted.revision <= (
                reward_adoptions.get(old.reward_adoption_sha256).adoption.revision
            ):
                raise ValueError("reward revision rolls back its signed adoption lineage")
    return body


def verify_reward_decision_proposal(
    series: StandingRewardSeries,
    policy: CompetitionPolicy,
    preceding: tuple[SignedRewardControlDecision, ...],
    decision: RewardControlDecision,
    *,
    reward_adoptions: RewardAdoptionSelection | None = None,
) -> RewardControlDecision:
    """Check unsigned ordering; native evidence review must precede signing."""
    series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if series.policy_sha256 != digest(policy):
        raise ValueError("standing series policy differs from selected policy")
    verify_recovery_authority(series.recovery, policy)
    reward_adoptions = verify_adoption_selection(reward_adoptions, series, policy)
    prefix = (
        verify_reward_decisions(series, policy, preceding, reward_adoptions=reward_adoptions)
        if preceding
        else ()
    )
    body = RewardControlDecision.model_validate_json(canonical_json_bytes(decision))
    return _decision_body(
        series,
        policy,
        len(prefix),
        prefix[-1].decision if prefix else None,
        sum(v.decision.kind == "activate" for v in prefix),
        body,
        preceding=prefix,
        reward_adoptions=reward_adoptions,
    )


def reward_decision_capacity(series, reward_adoptions=None):
    return (
        len(series.cohorts) + 2 if reward_adoptions is None else reward_adoptions.maximum_decisions
    )


def effective_activation_decision(prefix, cohort=None, *, through_sequence=None):
    """Latest economics selection; suspend leaves the previous historical row effective."""
    for signed in reversed(prefix):
        body = signed.decision
        if through_sequence is not None and body.sequence > through_sequence:
            continue
        if body.kind in {"activate", "revise_activation", "resume_activation"} and (
            cohort is None or body.activation.cohort_sha256 == cohort
        ):
            return body
    return None


def original_activation_decision(prefix, cohort):
    return next(
        (
            v.decision
            for v in prefix
            if v.decision.kind == "activate" and v.decision.activation.cohort_sha256 == cohort
        ),
        None,
    )


def retained_reward_decisions(reader):
    with reader.journal.locked():
        values = tuple(
            SignedRewardControlDecision.model_validate_json(
                canonical_json_bytes(reader.journal.get("reward_control_decision", key))
            )
            for key in reader.journal.keys("reward_control_decision")
        )
    return (
        verify_reward_decisions(
            reader.series, reader.policy, values, reward_adoptions=reader.reward_adoptions
        )
        if values
        else ()
    )


def activation_requires_revision(reader, selection):
    """Fence stale economics after a newer explicit selection reaches this writer.

    A signed native-reviewed resume is the sole exception: it attests that the
    preceding row won the live-chain race and its economics are permanently
    locked. Ordinary old activate/revise decisions cannot use that exception.
    """
    selected = reader.reward_adoptions
    if selected is None or selection.activation is None:
        return False
    latest = selected.latest(selection.activation.cohort_sha256)
    if latest is None or digest(latest.adoption) == selection.activation.reward_adoption_sha256:
        return False
    prefix = retained_reward_decisions(reader)
    current = next(
        (v.decision for v in prefix if digest(v.decision) == selection.decision_sha256), None
    )
    return current is None or current.kind != "resume_activation"


class StandingRewardControlReader(RewardAdoptionConsumer):
    """Retain decisions with distinct current-selection and historical-review paths."""

    def __init__(
        self,
        root: Path,
        series: StandingRewardSeries,
        policy: CompetitionPolicy,
        *,
        expected_series_sha256: str,
        expected_chain_config_sha256: str,
        maximum_bytes: int,
        expected_admission_chain_config_sha256: str | None = None,
        reward_adoptions: RewardAdoptionSelection | None = None,
        reward_adoption_feed: RewardAdoptionFeed | None = None,
    ):
        self.series = StandingRewardSeries.model_validate_json(canonical_json_bytes(series))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if digest(self.series) != expected_series_sha256:
            raise ValueError("standing series differs from independently selected authority")
        self.series_sha256 = expected_series_sha256
        # Strict digest validation also rejects accidental configuration paths.
        self.chain_config_sha256 = expected_chain_config_sha256
        self.admission_chain_config_sha256 = (
            expected_chain_config_sha256
            if expected_admission_chain_config_sha256 is None
            else expected_admission_chain_config_sha256
        )
        for config_sha256 in (self.chain_config_sha256, self.admission_chain_config_sha256):
            if (
                type(config_sha256) is not str
                or len(config_sha256) != 64
                or any(c not in "0123456789abcdef" for c in config_sha256)
            ):
                raise ValueError("standing reader chain configuration digest is invalid")
        if self.series.policy_sha256 != digest(self.policy):
            raise ValueError("standing reader policy differs from its series")
        verify_recovery_authority(self.series.recovery, self.policy)
        self._configure_reward_adoptions(
            reward_adoptions, series=self.series, policy=self.policy, feed=reward_adoption_feed
        )
        self.journal = RoundJournal(
            root,
            {
                "schema": "umi-standing-reward-reader/1",
                "series_sha256": self.series_sha256,
            },
            maximum_rounds=MAX_DECISIONS + 1,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=MAX_ADMISSION_BYTES,
        )

    def _proof(self, observation: OwnedRewardControlObservation) -> None:
        validate_owned_reward_control(
            observation,
            expected_control_hotkey=self.series.control_hotkey,
            expected_chain_config_sha256=self.chain_config_sha256,
        )

    def _historical_proof(self, observation: OwnedHistoricalRewardControl) -> None:
        validate_historical_reward_control(
            observation,
            expected_control_hotkey=self.series.control_hotkey,
            expected_chain_config_sha256=self.admission_chain_config_sha256,
        )

    def select(
        self, observation: OwnedRewardControlObservation, source: DecisionSource
    ) -> StandingRewardSelection:
        selection, _, _, _ = self._select(observation, source, admission=None)
        return selection

    def select_admitted(
        self,
        observation: OwnedRewardControlObservation,
        source: DecisionSource,
        admission: OwnedHistoricalRewardControl,
    ) -> AdmittedStandingRewardSelection:
        """Accept late recovery only with native evidence of timely chain admission.

        Replay the historical archive before collecting the current observation.
        The immutable admission can be reused in-process; restart replays its
        retained bytes. No coordinator renewal or certificate-age bound applies.
        A migration may independently select the original decoder configuration
        for admission replay while current control uses the new configuration.
        """
        validate_historical_reward_control(
            admission,
            expected_control_hotkey=self.series.control_hotkey,
            expected_chain_config_sha256=self.admission_chain_config_sha256,
        )
        selection, _, _, _ = self._select(observation, source, admission=admission)
        return AdmittedStandingRewardSelection(selection, admission)

    def select_history(
        self,
        observation: OwnedRewardControlObservation,
        source: DecisionSource,
        history: OwnedRewardControlHistory,
    ) -> HistoryVerifiedStandingRewardSelection:
        """Recover from an outage without skipping overwritten control writes.

        Scan from the approved authority's issuance block, including that block,
        through the fresh observation's exact snapshot. A later slot timestamp
        cannot choose a shorter history. The reserved control key must publish
        only this series' ordered decisions throughout that interval.
        """
        selection, effective, initial, transitions = self._select(
            observation, source, admission=None, history=history
        )
        return HistoryVerifiedStandingRewardSelection(
            selection,
            history,
            effective,
            initial_selection=initial,
            activation_transitions=transitions,
        )

    def review_history(
        self,
        observation: OwnedHistoricalRewardControl,
        source: DecisionSource,
        history: OwnedRewardControlHistory,
    ) -> HistoricalStandingRewardSelection:
        """Recover a past selection without rolling back the current checkpoint.

        Require every control write from authority issuance to the exact archived
        root. A retained newer signed prefix must agree with the reviewed prefix.
        Newly recovered decisions may be retained, but historical review never
        advances or rewinds the current finalized highwater mark.
        """
        selection, effective, initial, transitions = self._select(
            observation, source, admission=None, history=history, historical=True
        )
        return HistoricalStandingRewardSelection(
            observation,
            selection,
            history,
            effective,
            initial_selection=initial,
            activation_transitions=transitions,
        )

    def _history_committed_blocks(
        self,
        history: OwnedRewardControlHistory,
        observation: OwnedRewardControlObservation | OwnedHistoricalRewardControl,
        decisions: tuple[SignedRewardControlDecision, ...],
    ) -> tuple[int, ...]:
        validate_control_history(
            history,
            first_block=self.series.recovery.authority.issued_at_block,
            tip=observation.snapshot,
            control_hotkey=self.series.control_hotkey,
            chain_config_sha256=self.admission_chain_config_sha256,
        )
        if history.unresolved_blocks or not history.writes:
            raise ValueError("standing history has unresolved effects or lacks chain admission")
        sequence = -1
        committed_blocks = []
        for write in history.writes:
            if sequence >= 0 and write.decision_sha256 == digest(decisions[sequence].decision):
                # Retransmitting the same decision does not restart its drain.
                continue
            sequence += 1
            if sequence >= len(decisions):
                raise ValueError("standing history conflicts with the selected decision prefix")
            body = decisions[sequence].decision
            if write.decision_sha256 != digest(body) or write.block_number < body.observed_at_block:
                raise ValueError("standing history changed, skipped or backdated a decision")
            if sequence == 0 and write.block_number > self.policy.valid_through_block:
                raise ValueError("standing series lacks timely original chain admission")
            committed_blocks.append(write.block_number)
        last = history.writes[-1]
        if sequence != len(decisions) - 1 or (
            last.decision_sha256,
            last.block_number,
        ) != (observation.control_sha256, observation.committed_at_block):
            raise ValueError("standing history does not reach the current control commitment")
        return tuple(committed_blocks)

    def _selection_at(
        self, decision: RewardControlDecision, committed_at_block: int, current_block: int
    ) -> StandingRewardSelection:
        effective = activation_effective_block(
            self.series, decision, committed_at_block, self.reward_adoptions
        )
        state = (
            "admitted"
            if decision.kind == "admit_series"
            else "revoked"
            if decision.kind == "revoke"
            else "suspended"
            if decision.kind == "suspend_activation"
            else "draining"
            if current_block < effective
            else "selected"
        )
        return StandingRewardSelection(
            self.series_sha256,
            digest(decision),
            decision.sequence,
            state,
            committed_at_block,
            effective,
            decision.activation,
        )

    async def replay_admission(
        self, provider: HistoricalRewardControlProvider
    ) -> OwnedHistoricalRewardControl:
        """Recover the original proof from this reader's private durable journal.

        The caller supplies the independently approved historical provider.
        Retained bytes must pass native replay on every process restart.
        """
        record = self.journal.get("reward_series_admission", "original")
        if (
            not isinstance(record, dict)
            or set(record) != {"evidence", "metadata_hex"}
            or type(record["metadata_hex"]) is not str
            or not 0 < len(record["metadata_hex"]) <= 2 * MAX_CONTROL_METADATA_BYTES
        ):
            raise ValueError("retained reward admission has an invalid envelope")
        proof = await provider.review_control(
            canonical_json_bytes(record["evidence"]), bytes.fromhex(record["metadata_hex"])
        )
        validate_historical_reward_control(
            proof,
            expected_control_hotkey=self.series.control_hotkey,
            expected_chain_config_sha256=self.admission_chain_config_sha256,
        )
        return proof

    def _select(
        self,
        observation: OwnedRewardControlObservation | OwnedHistoricalRewardControl,
        source: DecisionSource,
        *,
        admission: OwnedHistoricalRewardControl | None,
        history: OwnedRewardControlHistory | None = None,
        historical: bool = False,
    ) -> tuple[
        StandingRewardSelection,
        StandingRewardSelection | None,
        StandingRewardSelection | None,
        tuple[StandingRewardSelection, ...],
    ]:
        if historical and (history is None or admission is not None):
            raise ValueError("historical selection requires complete control history")
        self.refresh_reward_adoptions()
        proof = self._historical_proof if historical else self._proof
        proof(observation)
        if observation.control_sha256 is None:
            raise ValueError("standing control commitment is absent")
        with self.journal.locked():
            keys = self.journal.keys("reward_control_decision")
            if len(keys) > reward_decision_capacity(self.series, self.reward_adoptions):
                raise ValueError("retained reward history exceeds the admitted series")
            retained = {}
            for index, key in enumerate(keys):
                if key != f"{index:04d}":
                    raise ValueError("retained reward history is not a contiguous prefix")
                raw = canonical_json_bytes(self.journal.get("reward_control_decision", key))
                if not 0 < len(raw) <= MAX_DECISION_BYTES:
                    raise ValueError("retained reward decision exceeds its byte bound")
                item = SignedRewardControlDecision.model_validate_json(raw)
                if item.decision.sequence != index:
                    raise ValueError("retained reward decision is in a different sequence slot")
                retained[digest(item.decision)] = item

            boundary, _, _ = initial_reward_boundary(self.series, self.reward_adoptions)
            reversed_chain, key = [], observation.control_sha256
            while key != boundary:
                if key is None:
                    raise ValueError(
                        "current reward history does not reach its predecessor boundary"
                    )
                if len(reversed_chain) >= reward_decision_capacity(
                    self.series, self.reward_adoptions
                ):
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
                self.series,
                self.policy,
                tuple(reversed(reversed_chain)),
                reward_adoptions=self.reward_adoptions,
            )
            committed_blocks = (
                None
                if history is None
                else self._history_committed_blocks(history, observation, decisions)
            )
            if admission is not None:
                genesis = decisions[0].decision
                if (
                    admission.control_sha256 != digest(genesis)
                    or admission.committed_at_block is None
                    or not genesis.observed_at_block
                    <= admission.committed_at_block
                    <= self.policy.valid_through_block
                    or admission.snapshot.block_number > observation.snapshot.block_number
                ):
                    raise ValueError("standing series lacks timely original chain admission")
            if (not historical and len(decisions) < len(keys)) or any(
                digest(decisions[i].decision) not in retained
                for i in range(min(len(keys), len(decisions)))
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
                and admission is None
                and history is None
            ):
                raise ValueError("series genesis was committed after its admission window")
            proof(observation)

            def record_head(db):
                old = db.execute("SELECT block FROM highwater LIMIT 2").fetchall()
                if old and (len(old) != 1 or old[0][0] > observation.snapshot.block_number):
                    raise ValueError("standing control finalized head regressed")
                db.execute("DELETE FROM highwater")
                db.execute("INSERT INTO highwater VALUES (?)", (observation.snapshot.block_number,))

            # Persist a complete authenticated prefix before returning a selection.
            # A failed acknowledgement retries the same immutable records.
            records = tuple(
                ("reward_control_decision", f"{i:04d}", item)
                for i, item in enumerate(decisions)
                if i >= len(keys)
            )
            # A later finalized header/proof can prove the same timely genesis.
            # Preserve the first archive instead of conflict-holding it merely
            # because that equivalent proof has different bytes.
            if (
                admission is not None
                and self.journal.get("reward_series_admission", "original") is None
            ):
                records += (
                    (
                        "reward_series_admission",
                        "original",
                        {
                            "evidence": json.loads(admission.evidence),
                            "metadata_hex": admission.metadata.hex(),
                        },
                    ),
                )
            if not historical or records:
                self.journal.put_many(records, index=None if historical else record_head)
            proof(observation)
            selection = self._selection_at(
                tip,
                observation.committed_at_block
                if committed_blocks is None
                else committed_blocks[-1],
                observation.snapshot.block_number,
            )
            effective = None
            transitions = []
            if committed_blocks is not None:
                selections = tuple(
                    self._selection_at(item.decision, block, observation.snapshot.block_number)
                    for item, block in zip(decisions, committed_blocks, strict=True)
                )
                for index, prior in enumerate(selections):
                    invalidated_before_effect = prior.effective_at_block is not None and any(
                        committed_blocks[later] <= prior.effective_at_block
                        and (
                            decisions[later].decision.kind == "revoke"
                            or (
                                selections[later].activation is not None
                                and selections[later].activation != prior.activation
                                and selections[later].effective_at_block is not None
                                and selections[later].effective_at_block <= prior.effective_at_block
                            )
                        )
                        for later in range(index + 1, len(selections))
                    )
                    if (
                        prior.activation is not None
                        and prior.effective_at_block is not None
                        and not invalidated_before_effect
                    ):
                        transitions.append(prior)
                    if tip.kind != "revoke" and prior.state == "selected":
                        effective = prior
            # Preserve the first activation as a historical fact, even when a
            # successor or revocation is current. Boot needs it to reopen the
            # original C4 handoff; it is never current submission authority.
            initial = None
            if (
                committed_blocks is not None
                and len(decisions) > 1
                and decisions[1].decision.kind == "activate"
            ):
                initial = self._selection_at(
                    decisions[1].decision, committed_blocks[1], observation.snapshot.block_number
                )
            return selection, effective, initial, tuple(transitions)
