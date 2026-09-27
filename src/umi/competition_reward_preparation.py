"""Native package replay followed by independently refreshed standing selection.

Slow replay produces immutable evidence, not a live transaction permission.
Current control, complete registration and the handoff fence are checked again
when projecting it. Prior opportunity, legacy handoff and transaction recovery
still belong to the execution consumer.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from functools import partial
from typing import Annotated, Literal

from pydantic import Field

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import OwnedCompetitionChainObservation
from .competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    CohortRewardProjection,
    project_owned_reward_allocation,
)
from .competition_cohort_reward_package import (
    DEFAULT_PACKAGE_BYTES,
    CohortRewardPackage,
    replay_reward_package,
)
from .competition_reward_control import (
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from .competition_reward_decisions import (
    DecisionSource,
    HistoryVerifiedStandingRewardSelection,
    RewardActivation,
    StandingRewardControlReader,
)
from .competition_reward_history import OwnedRewardControlHistory
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .open_competition import digest, identity
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes


class RewardReplayRequirement(StrictProtocolModel):
    """Independent host selections; never inferred from the package itself."""

    cohort_sha256: Hex32
    terms_sha256: Hex32
    catalog_sha256s: Annotated[tuple[Hex32, ...], Field(min_length=1, max_length=64)]


@dataclass(frozen=True, slots=True)
class PreparedStandingReward:
    series_sha256: str
    activation: RewardActivation
    requirement_sha256: str
    allocation: CohortRewardAllocation
    reviewed_at_block: int
    chain_submission_authorized: Literal[False] = False
    _owner: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def _binding(value: PreparedStandingReward) -> str:
    return digest(
        {
            "series": value.series_sha256,
            "activation": digest(value.activation),
            "requirement": value.requirement_sha256,
            "allocation": digest(value.allocation),
            "reviewed_at_block": value.reviewed_at_block,
            "chain_submission_authorized": value.chain_submission_authorized,
        }
    )


@dataclass(frozen=True, slots=True)
class PreparedStandingProjection:
    prepared: PreparedStandingReward
    current: HistoryVerifiedStandingRewardSelection
    chain: OwnedCompetitionChainObservation
    projection: CohortRewardProjection
    chain_submission_authorized: Literal[False] = False


class StandingRewardPreparation:
    """Reuse completed native replay while every projection checks fresh proofs.

    The caller retains private packages and promotion assets with the existing
    stores. Restart reconstructs native reviews from those bytes; a serialized
    success flag cannot populate this process-local cache. At most one selected
    immutable package per admitted cohort is retained here.
    """

    def __init__(
        self,
        reader: StandingRewardControlReader,
        promotion_store: CompetitionStore,
        requirements: tuple[RewardReplayRequirement, ...],
        *,
        maximum_promotion_bytes: int,
        maximum_package_bytes: int = DEFAULT_PACKAGE_BYTES,
    ):
        requirements = tuple(
            RewardReplayRequirement.model_validate_json(canonical_json_bytes(r))
            for r in requirements
        )
        keys = [r.cohort_sha256 for r in requirements]
        if len(set(keys)) != len(keys) or set(keys) != {digest(p) for p in reader.series.cohorts}:
            raise ValueError("reward replay requirements must cover exactly the selected series")
        for bound in (maximum_promotion_bytes, maximum_package_bytes):
            if type(bound) is not int or not 1024 <= bound <= MAX_CONFIGURED_PRIVATE_BYTES:
                raise ValueError("reward preparation byte bound is invalid")
        if digest(promotion_store.policy) != digest(reader.policy):
            raise ValueError("reward preparation promotion store belongs to another policy")
        self.reader, self.promotion_store = reader, promotion_store
        self.requirements = {r.cohort_sha256: r for r in requirements}
        self.series_sha256, self.policy_sha256 = digest(reader.series), digest(reader.policy)
        self.maximum_promotion_bytes = maximum_promotion_bytes
        self.maximum_package_bytes = maximum_package_bytes
        self._lock = asyncio.Lock()
        self._owner = object()
        self._prepared: dict[str, PreparedStandingReward] = {}

    def _selected(
        self,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> HistoryVerifiedStandingRewardSelection:
        if (
            digest(self.reader.series) != self.series_sha256
            or digest(self.reader.policy) != self.policy_sha256
            or digest(self.promotion_store.policy) != self.policy_sha256
        ):
            raise ValueError("reward preparation authority changed")
        current = self.reader.select_history(control, source, history)
        if current.selection.state not in {"draining", "selected"}:
            raise ValueError("standing control has no active reward package")
        return current

    async def prepare(
        self,
        package: CohortRewardPackage,
        *,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> PreparedStandingReward:
        async with self._lock:
            return await run_owned_thread(partial(self._prepare, package, control, history, source))

    def _prepare(
        self,
        package: CohortRewardPackage,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> PreparedStandingReward:
        selected = self._selected(control, history, source).selection
        activation = selected.activation
        assert activation is not None
        requirement = self.requirements[activation.cohort_sha256]
        raw = canonical_json_bytes(package)
        if len(raw) > self.maximum_package_bytes:
            raise ValueError("reward package exceeds its byte bound")
        package = CohortRewardPackage.model_validate_json(raw)
        if (
            digest(package) != activation.package_sha256
            or digest(package.allocation) != activation.allocation_sha256
            or digest(package.inputs.history.plan) != activation.cohort_sha256
            or digest(package.inputs.history.authority.authority)
            != digest(self.reader.series.recovery.authority)
        ):
            raise ValueError("reward package differs from current standing activation")
        retained = self._prepared.get(activation.cohort_sha256)
        if retained is not None:
            self._check_prepared(retained)
            if retained.activation != activation:
                raise ValueError("standing activation changed an already prepared cohort")
            return retained
        allocation = replay_reward_package(
            package,
            self.reader.policy,
            self.promotion_store,
            package.inputs.history,
            expected_package_sha256=activation.package_sha256,
            expected_cohort_sha256=activation.cohort_sha256,
            expected_tip_sha256=activation.recovery_tip_sha256,
            current_block=control.snapshot.block_number,
            expected_terms_sha256=requirement.terms_sha256,
            expected_catalog_sha256s=requirement.catalog_sha256s,
            maximum_promotion_bytes=self.maximum_promotion_bytes,
            maximum_bytes=self.maximum_package_bytes,
        )
        prepared = PreparedStandingReward(
            self.series_sha256,
            activation,
            digest(requirement),
            allocation,
            control.snapshot.block_number,
            _owner=self._owner,
        )
        object.__setattr__(prepared, "_binding", _binding(prepared))
        # Retain completion inside the owned thread, even if its waiter was
        # cancelled. Proof expiry during replay never discards immutable work.
        self._prepared[activation.cohort_sha256] = prepared
        return prepared

    def _check_prepared(self, prepared: PreparedStandingReward) -> None:
        if (
            type(prepared) is not PreparedStandingReward
            or prepared._owner is not self._owner
            or prepared._binding != _binding(prepared)
            or prepared.series_sha256 != self.series_sha256
            or prepared.requirement_sha256
            != digest(self.requirements[prepared.activation.cohort_sha256])
        ):
            raise ValueError("reward preparation was not issued by this native replay owner")

    async def project(
        self,
        prepared: PreparedStandingReward,
        *,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
    ) -> PreparedStandingProjection:
        async with self._lock:
            return await run_owned_thread(
                partial(self._project, prepared, control, history, source, chain, chain_config)
            )

    def _project(
        self,
        prepared: PreparedStandingReward,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
    ) -> PreparedStandingProjection:
        self._check_prepared(prepared)
        current = self._selected(control, history, source)
        if (
            current.selection.state != "selected"
            or current.selection.activation != prepared.activation
            or chain.snapshot != control.snapshot
            or chain.block < prepared.reviewed_at_block
            or chain.chain_config_sha256 != self.reader.chain_config_sha256
            or identity(chain.validator_hotkey)
            not in {identity(k) for k in self.reader.series.validators}
        ):
            raise ValueError("prepared rewards lack current standing selection and validator state")
        projection = project_owned_reward_allocation(
            prepared.allocation, chain, self.reader.policy, chain_config=chain_config
        )
        # Projection checks the chain observation again after its calculation.
        # Keep the independently collected current-control proof fresh as well.
        validate_owned_reward_control(
            control,
            expected_control_hotkey=self.reader.series.control_hotkey,
            expected_chain_config_sha256=self.reader.chain_config_sha256,
        )
        return PreparedStandingProjection(prepared, current, chain, projection)
