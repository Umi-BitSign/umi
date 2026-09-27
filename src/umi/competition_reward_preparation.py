"""Native package replay followed by independently refreshed standing selection.

Slow replay produces immutable evidence, not a live transaction permission.
Current control, complete registration and the handoff fence are checked again
when projecting it. Prior opportunity, legacy handoff and transaction recovery
still belong to the execution consumer.
"""

from __future__ import annotations

import asyncio
import hashlib
from dataclasses import dataclass, field
from functools import partial
from typing import Literal

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
from .competition_reward_manifest import StandingRewardManifest, retain_reward_manifest
from .competition_reward_transactions import (
    PendingStandingWeight,
    StandingTransactionEnd,
    StandingWeightIntent,
    StandingWeightJournal,
    standing_weight_call,
)
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .mortal_receipts import MortalReceiptQuery
from .open_competition import digest, identity
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES
from .protocol import canonical_json_bytes
from .signed_extrinsic import verify_mortal_call


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
        manifest: StandingRewardManifest | None = None,
        *,
        maximum_promotion_bytes: int,
        maximum_package_bytes: int = DEFAULT_PACKAGE_BYTES,
    ):
        for bound in (maximum_promotion_bytes, maximum_package_bytes):
            if type(bound) is not int or not 1024 <= bound <= MAX_CONFIGURED_PRIVATE_BYTES:
                raise ValueError("reward preparation byte bound is invalid")
        if digest(promotion_store.policy) != digest(reader.policy):
            raise ValueError("reward preparation promotion store belongs to another policy")
        self.reader, self.promotion_store = reader, promotion_store
        self.manifest = retain_reward_manifest(reader, manifest)
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
            or digest(self.manifest) != self.reader.series.manifest_sha256
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
        requirement = self.manifest.requirement(activation.cohort_sha256)
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
            != digest(self.manifest.requirement(prepared.activation.cohort_sha256))
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

    async def verify_transaction_bytes(
        self,
        prepared: PreparedStandingReward,
        encoded: bytes,
        *,
        mortality_period: int,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
    ) -> MortalReceiptQuery:
        """Bind encoded bytes to a freshly checked allocation and signing context.

        The returned receipt query supplies checked search bounds only. Prior
        opportunity, legacy handoff, exclusive writer ownership and durable
        transaction reconciliation still gate submission. This method never
        signs, sends or treats matching bytes as reward authority.
        """
        async with self._lock:
            return await run_owned_thread(
                partial(
                    self._verify_transaction_bytes,
                    prepared,
                    encoded,
                    mortality_period,
                    control,
                    history,
                    source,
                    chain,
                    chain_config,
                )
            )

    def _verify_transaction_bytes(
        self, prepared, encoded, period, control, history, source, chain, chain_config
    ):
        current = self._project(prepared, control, history, source, chain, chain_config)
        if (
            type(period) is not int
            or not 4 <= period <= self.reader.series.maximum_transaction_lifetime_blocks
        ):
            raise ValueError("transaction mortality exceeds the standing series bound")
        row = current.projection
        call = standing_weight_call(row, chain)
        envelope = verify_mortal_call(
            encoded,
            call,
            runtime=chain.runtime,
            validator_hotkey=chain.validator_hotkey,
            nonce=chain.validator_nonce,
            mortality_period=period,
            genesis_hash=chain.genesis_hash,
        )
        # Native decode/crypto may itself be slow. Recheck both proof lifetimes
        # and current selection after it, without changing the retained bytes.
        refreshed = self._project(prepared, control, history, source, chain, chain_config)
        if refreshed.projection != row or refreshed.current != current.current:
            raise ValueError("standing selection changed while checking transaction bytes")
        return MortalReceiptQuery(
            schema="umi-mortal-receipt-query/1",
            birth_block=chain.block,
            birth_hash=chain.block_hash,
            mortality_period=period,
            signed_extrinsic=envelope.data.hex(),
        )

    def _transaction_intent(self, current, control, chain, period):
        if (
            type(period) is not int
            or not 4 <= period <= self.reader.series.maximum_transaction_lifetime_blocks
        ):
            raise ValueError("transaction mortality exceeds the standing series bound")
        call = standing_weight_call(current.projection, chain)
        return StandingWeightIntent(
            schema="umi-standing-weight-intent/1",
            series_sha256=self.series_sha256,
            decision_sha256=current.current.selection.decision_sha256,
            activation_sha256=digest(current.prepared.activation),
            chain_config_sha256=chain.chain_config_sha256,
            validator_hotkey=chain.validator_hotkey,
            block=chain.block,
            block_hash=chain.block_hash,
            prior_last_update=chain.validator_last_update,
            nonce=chain.validator_nonce,
            mortality_period=period,
            weights_version_key=chain.weights_version_key,
            projection=current.projection,
            destinations=tuple(call.params["dests"]),
            weights=tuple(call.params["weights"]),
            chain_evidence_sha256=chain.evidence_sha256,
            control_evidence_sha256=hashlib.sha256(control.evidence).hexdigest(),
            metadata_sha256=chain.runtime.metadata_sha256,
        )

    async def reserve_transaction(
        self,
        prepared: PreparedStandingReward,
        journal: StandingWeightJournal,
        *,
        mortality_period: int,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
        previous: StandingTransactionEnd | None = None,
    ) -> PendingStandingWeight:
        """Retain an unsigned intent and recovery inputs before any signing.

        This method does not grant signing authority. The future execution owner
        must also verify opportunity, migration fencing and the selected manifest.
        """
        async with self._lock:

            def retain():
                current = self._project(prepared, control, history, source, chain, chain_config)
                intent = self._transaction_intent(current, control, chain, mortality_period)
                result = journal.reserve(
                    intent,
                    chain=chain.evidence,
                    control=control.evidence,
                    metadata=chain.runtime.metadata_bytes,
                    previous=previous,
                )
                # A slow commit may expire the preflight. Its durable intent
                # remains available for recovery; never start another attempt.
                self._project(prepared, control, history, source, chain, chain_config)
                return result

            return await run_owned_thread(retain)

    async def retain_signed_transaction(
        self,
        prepared: PreparedStandingReward,
        journal: StandingWeightJournal,
        encoded: bytes,
        *,
        mortality_period: int,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
    ) -> PendingStandingWeight:
        """Verify actual bytes and commit them against their original reservation.

        A successful return is a recoverable local record, never a broadcast or
        permission to submit. Every transmission still needs fresh native gates.
        """
        async with self._lock:

            def retain():
                current = self._project(prepared, control, history, source, chain, chain_config)
                intent = self._transaction_intent(current, control, chain, mortality_period)
                self._verify_transaction_bytes(
                    prepared,
                    encoded,
                    mortality_period,
                    control,
                    history,
                    source,
                    chain,
                    chain_config,
                )
                return journal.retain_signed(intent, encoded)

            return await run_owned_thread(retain)
