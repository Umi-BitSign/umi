"""Native pre-live revision clearance after a finalized writer suspension.

Every designated writer is checked at every finalized block where this cohort
could have been live. Retained native coverage endpoints survive interruptions;
their compact completed verdicts are restored by their original owner. A signed
adoption, current row, or remote success flag cannot establish absence of an
earlier live row. Suspension drains all old proof/transaction lifetimes before
clearance; a live row winning that race permanently locks the original economics.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from pydantic import Field

from .competition_cohort_recovery import Block
from .competition_reward_coverage_intervals import coverage_point
from .competition_reward_coverage_service import StandingRewardCoverageService
from .competition_reward_decisions import (
    effective_activation_decision,
    original_activation_decision,
)
from .competition_reward_revision_journal import RevisionProgressJournal
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()


class RewardRevisionPending(Exception):
    """Finalized drain or bounded native coverage review is incomplete."""


class RewardEconomicsLocked(ValueError):
    """A native finalized endpoint proves the cohort's rewards already became live."""


def _row_state(endpoint):
    row_matches = getattr(endpoint, "row_matches", None)
    eligibility = getattr(endpoint, "eligibility", None)
    last_update = (
        eligibility.subject.validator_last_update
        if eligibility is not None
        else getattr(endpoint, "validator_last_update", None)
    )
    if type(row_matches) is not bool or type(last_update) is not int:
        raise ValueError("reward revision requires explicit native coverage row-state repair")
    return row_matches, last_update


class RewardRevisionClearance(StrictProtocolModel):
    schema_: Literal["umi-standing-reward-revision-clearance/1"] = Field(alias="schema")
    series_sha256: Hex32
    cohort_sha256: Hex32
    original_activation_sha256: Hex32
    suspended_activation_sha256: Hex32
    suspension_decision_sha256: Hex32
    suspension_committed_at_block: Block
    first_block: Block
    through_block: Block
    drained_at_block: Block
    validator_accounts: tuple[Hex32, ...]
    reviewed_endpoints: int
    endpoint_facts_sha256: Hex32


@dataclass(frozen=True, slots=True)
class OwnedRewardRevisionClearance:
    clearance: RewardRevisionClearance
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


@dataclass(frozen=True, slots=True)
class OwnedRewardLiveLock:
    series_sha256: str
    cohort_sha256: str
    activation_sha256: str
    endpoint_sha256: str
    block: int
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _live_binding(value):
    return digest(
        [
            value.series_sha256,
            value.cohort_sha256,
            value.activation_sha256,
            value.endpoint_sha256,
            value.block,
        ]
    )


def validate_live_lock(value, *, decision, series):
    if (
        type(value) is not OwnedRewardLiveLock
        or value._issuer is not _ISSUER
        or value._binding != _live_binding(value)
        or value.series_sha256 != digest(series)
        or value.cohort_sha256 != decision.activation.cohort_sha256
        or value.activation_sha256 != digest(decision.activation)
        or value.block > decision.observed_at_block
    ):
        raise ValueError("reward resume requires its original native finalized live lock")
    return value


def validate_revision_clearance(value, *, decision, prefix, series, history=None):
    if (
        type(value) is not OwnedRewardRevisionClearance
        or value._issuer is not _ISSUER
        or value._binding != digest(value.clearance)
    ):
        raise ValueError("reward revision lacks native finalized clearance")
    facts = value.clearance
    old = effective_activation_decision(prefix)
    original = original_activation_decision(prefix, decision.activation.cohort_sha256)
    delay = series.maximum_proof_lag_blocks + series.maximum_transaction_lifetime_blocks
    writes = (
        {}
        if history is None
        else {w.decision_sha256: w.block_number for w in reversed(history.writes)}
    )
    if (
        facts.series_sha256 != digest(series)
        or facts.cohort_sha256 != decision.activation.cohort_sha256
        or facts.suspended_activation_sha256 != digest(old.activation)
        or facts.original_activation_sha256 != digest(original.activation)
        or facts.suspension_decision_sha256 != decision.predecessor_sha256
        or prefix[-1].decision.kind != "suspend_activation"
        or not writes
        or facts.suspension_committed_at_block != writes.get(decision.predecessor_sha256)
        or facts.first_block != writes.get(digest(original), -delay) + delay
        or facts.drained_at_block != facts.suspension_committed_at_block + delay
        or facts.through_block != decision.observed_at_block
        or facts.drained_at_block > facts.through_block
        or facts.validator_accounts != tuple(identity(k) for k in series.validators)
        or facts.reviewed_endpoints
        != max(0, facts.through_block - facts.first_block + 1) * len(series.validators)
        or digest(facts) != decision.revision_clearance_sha256
    ):
        raise ValueError("reward revision clearance changes its original fenced selection")
    return facts


class NativeRewardRevisionReviewer:
    """One owner reuses existing native coverage receipts, never guessed verdicts."""

    def __init__(self, *, coverage: StandingRewardCoverageService, maximum_endpoints: int = 64):
        if (
            type(coverage) is not StandingRewardCoverageService
            or not 1 <= maximum_endpoints <= 4096
        ):
            raise ValueError("reward revision requires a bounded native coverage owner")
        self.coverage = coverage
        self.maximum_endpoints = maximum_endpoints
        self.journal = RevisionProgressJournal(coverage.journal.journal)
        self._source_owner = None
        self._source_activation = None

    async def _source(self, activation):
        key = digest(activation)
        if self._source_activation != key:
            self._source_owner = await self.coverage._source(activation)
            self._source_activation = key
        return self._source_owner

    async def target(self, suspension, control):
        """Retain the first drained finalized audit target across bounded restarts."""
        series = self.coverage.preparation.reader.series
        if suspension.kind != "suspend_activation" or control.control_sha256 != digest(suspension):
            raise ValueError("reward revision target lacks its exact committed suspension")
        committed, through = control.committed_at_block, control.snapshot.block_number
        self._drain(committed, through)
        record = await run_owned_thread(
            self.journal.retain_first,
            "reward_revision_target",
            digest(suspension),
            {"series": digest(series), "through_block": through, "committed_at_block": committed},
        )
        if (
            record["series"] != digest(series)
            or record["through_block"] > through
            or record["committed_at_block"] != committed
        ):
            raise ValueError("reward revision target changes its original finalized boundary")
        self._drain(record["committed_at_block"], record["through_block"])
        return record["through_block"]

    def _drain(self, committed, through):
        series = self.coverage.preparation.reader.series
        delay = series.maximum_proof_lag_blocks + series.maximum_transaction_lifetime_blocks
        drained = committed + delay
        if through < drained:
            with TransferProgress(
                "reward_revision_transaction_drain",
                delay,
                unit="finalized_blocks",
                planning_unit_seconds=(6, 24),
            ) as progress:
                progress.advance(max(0, through - committed), restored=True)
                progress.emit("running", reason="planning_finalized_block_cadence_6_to_24_seconds")
            raise RewardRevisionPending("reward revision waits for finalized transaction drain")
        return drained

    async def _existing_endpoint(self, source, hotkey, block):
        """Recover a completed coverage receipt after interrupted index publication."""
        c = self.coverage
        history = await c.history.verified_prefix(block)
        if history.tip.block_number != block:
            raise ValueError(
                "reward revision endpoint discovery changes its native finalized block"
            )
        key = digest(
            {
                "series": digest(c.preparation.reader.series),
                "validator": identity(hotkey),
                "block_hash": history.tip.block_hash,
            }
        )
        completed = await run_owned_thread(c.journal.checkpoints.load, key)
        return None if completed is None else await source.replay(key)

    async def locked(self, activation):
        return await self.live_lock(activation) is not None

    async def live_lock(self, activation):
        """A permanent hold is restored from its actual native endpoint, never a bool."""
        record = await run_owned_thread(
            self.journal.get, "reward_economics_live_lock", activation.cohort_sha256
        )
        if record is None:
            return None
        source = await self._source(activation)
        endpoint = await source.replay(record["endpoint"])
        point = coverage_point(endpoint, self.coverage.journal.rule)
        row_matches, updated = _row_state(endpoint)
        if (
            point.key() != record["endpoint"]
            or not row_matches
            or updated < record["first_block"]
            or point.activation_sha256 != record["activation"]
        ):
            raise ValueError("reward economics live lock lost its original native evidence")
        value = OwnedRewardLiveLock(
            digest(self.coverage.preparation.reader.series),
            activation.cohort_sha256,
            record["activation"],
            point.key(),
            point.block,
            _issuer=_ISSUER,
        )
        object.__setattr__(value, "_binding", _live_binding(value))
        return value

    async def review(self, *, prefix, control, history):
        c = self.coverage
        reader = c.preparation.reader
        series = reader.series
        if not prefix or prefix[-1].decision.kind != "suspend_activation":
            raise ValueError("reward revision review requires its committed suspension")
        suspension = prefix[-1].decision
        objects = {digest(v.decision): canonical_json_bytes(v) for v in prefix}
        selected = await run_owned_thread(
            reader.review_history, control, objects.__getitem__, history
        )
        if selected.selection.decision_sha256 != digest(suspension):
            raise ValueError("reward revision suspension is not the current finalized control")
        committed = selected.selection.committed_at_block
        through = control.snapshot.block_number
        drained = self._drain(committed, through)
        old = effective_activation_decision(prefix)
        original = original_activation_decision(prefix, old.activation.cohort_sha256)
        if await self.locked(old.activation):
            raise RewardEconomicsLocked("reward economics already have retained live-chain proof")
        original_write = next(
            w.block_number for w in history.writes if w.decision_sha256 == digest(original)
        )
        # This is the original activation's START fence, independently of the
        # later suspension's END fence. StandingRewardControlReader._selection_at
        # returns "draining" before this block; StandingRewardPreparation._project
        # requires current.selection.state == "selected" and effective_selection
        # == current.selection. Every supported StandingRewardExecutor uses that
        # check for reservation and again before submission. An older coincident
        # row is not a C5 activation. No supported C5 writer can authorize an
        # original C5 transaction before this exact first-effective boundary.
        first = (
            original_write
            + series.maximum_proof_lag_blocks
            + series.maximum_transaction_lifetime_blocks
        )
        accounts = tuple(identity(k) for k in series.validators)
        binding = digest([digest(suspension), first, through, accounts])
        done, fresh = 0, 0
        facts = digest(["umi-reward-revision-endpoints/1", binding])
        total = max(0, through - first + 1) * len(accounts)
        writes = {w.decision_sha256: w.block_number for w in reversed(history.writes)}
        economics = tuple(
            (
                v.decision.activation,
                writes[digest(v.decision)]
                + series.maximum_proof_lag_blocks
                + series.maximum_transaction_lifetime_blocks,
            )
            for v in prefix
            if v.decision.kind in {"activate", "revise_activation", "resume_activation"}
            and v.decision.activation.cohort_sha256 == old.activation.cohort_sha256
        )
        with TransferProgress(
            "reward_revision_live_history",
            total,
            unit="endpoints",
            planning_unit_seconds=(0.01, 30),
        ) as progress:
            for index in range(total):
                block = first + index // len(accounts)
                hotkey = series.validators[index % len(accounts)]
                historical = next(
                    activation
                    for activation, effective in reversed(economics)
                    if effective <= block
                )
                source = await self._source(historical)
                key = digest([digest(series), digest(historical), block, identity(hotkey)])
                retained = await run_owned_thread(self.journal.get, "reward_revision_endpoint", key)
                completed = await run_owned_thread(
                    self.journal.get, "reward_revision_endpoint_done", key
                )
                if (retained is None) != (completed is None) or retained != completed:
                    raise ValueError(
                        "reward revision endpoint index needs original metadata repair"
                    )
                restored = retained is not None
                if retained is None:
                    endpoint = await self._existing_endpoint(source, hotkey, block)
                    restored = endpoint is not None
                    if endpoint is None:
                        if fresh >= self.maximum_endpoints:
                            break
                        endpoint = await source.capture(hotkey, block)
                        fresh += 1
                    endpoint_key = await c.journal.retain_endpoint(endpoint)
                    await run_owned_thread(
                        self.journal.put_many,
                        (
                            ("reward_revision_endpoint", key, {"endpoint": endpoint_key}),
                            ("reward_revision_endpoint_done", key, {"endpoint": endpoint_key}),
                        ),
                    )
                else:
                    endpoint = await source.replay(retained["endpoint"])
                point = coverage_point(endpoint, c.journal.rule)
                if (
                    point.block != block
                    or point.validator_account_id != identity(hotkey)
                    or point.activation_sha256 != digest(historical)
                ):
                    raise ValueError("reward revision endpoint changes its exact block or writer")
                if getattr(endpoint, "row_matches", None) is None:
                    with TransferProgress(
                        "reward_revision_row_state_repair",
                        1,
                        unit="endpoints",
                        planning_unit_seconds=(0.01, 30),
                    ) as repair:
                        endpoint = await source.repair(
                            point.key(), reason="reward_revision_row_state_upgrade"
                        )
                        repair.advance(1)
                    point = coverage_point(endpoint, c.journal.rule)
                row_matches, updated = _row_state(endpoint)
                if row_matches and updated >= first:
                    await run_owned_thread(
                        self.journal.retain_first,
                        "reward_economics_live_lock",
                        old.activation.cohort_sha256,
                        {
                            "endpoint": point.key(),
                            "activation": point.activation_sha256,
                            "first_block": first,
                        },
                    )
                    raise RewardEconomicsLocked(
                        "native finalized rewards lock the existing economics"
                    )
                facts = digest([facts, digest(point), row_matches, updated])
                done = index + 1
                progress.advance(1, restored=restored)
        if done != total:
            raise RewardRevisionPending("reward revision retained bounded native coverage progress")
        body = RewardRevisionClearance(
            schema="umi-standing-reward-revision-clearance/1",
            series_sha256=digest(series),
            cohort_sha256=old.activation.cohort_sha256,
            original_activation_sha256=digest(original.activation),
            suspended_activation_sha256=digest(old.activation),
            suspension_decision_sha256=digest(suspension),
            suspension_committed_at_block=committed,
            first_block=first,
            through_block=through,
            drained_at_block=drained,
            validator_accounts=accounts,
            reviewed_endpoints=total,
            endpoint_facts_sha256=facts,
        )
        return OwnedRewardRevisionClearance(body, _issuer=_ISSUER, _binding=digest(body))
