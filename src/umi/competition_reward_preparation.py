"""Native package replay followed by independently refreshed standing selection.

Slow replay produces immutable evidence, not a live transaction permission.
Current control, complete registration and the handoff fence are checked again
when projecting it. The opportunity manifest gates successor handoff on native prior coverage.
Legacy handoff and transaction recovery belong to the execution consumer.
"""

from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import partial
from typing import Literal

from .competition_chain import CompetitionChainConfig
from .competition_chain_state import OwnedCompetitionChainObservation
from .competition_cohort_baseline import (
    CohortBaselineCandidate,
    select_cohort_baseline_candidate,
)
from .competition_cohort_baseline_review import CohortBaselineReview, validate_baseline_review
from .competition_cohort_capacity import check_aggregate_evidence_bytes
from .competition_cohort_direct_model_review import DirectModelSettlementVerifier
from .competition_cohort_reward_allocation import (
    CohortRewardAllocation,
    CohortRewardProjection,
    derive_effective_reward_allocation,
    project_owned_reward_allocation,
)
from .competition_cohort_reward_package import (
    DEFAULT_PACKAGE_BYTES,
    CohortRewardPackage,
    _replay_detached_reward_package,
    _validated_reward_snapshot,
)
from .competition_reward_adoption import verify_reward_adoption
from .competition_reward_control import (
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from .competition_reward_control_archive import OwnedHistoricalRewardControl
from .competition_reward_decisions import (
    DecisionSource,
    HistoryVerifiedStandingRewardSelection,
    RewardActivation,
    StandingRewardControlReader,
    activation_requires_revision,
)
from .competition_reward_history import OwnedRewardControlHistory
from .competition_reward_manifest import (
    RewardManifest,
    StandingRewardOpportunityManifest,
    retain_reward_manifest,
)
from .competition_reward_opportunity import require_previous_opportunity
from .competition_reward_transactions import (
    PendingStandingWeight,
    StandingTransactionEnd,
    StandingWeightIntent,
    StandingWeightJournal,
    standing_weight_call,
)
from .competition_reward_transport_qualification import PackageTransportQualifications
from .competition_settlement import PromotionHeadBinding
from .competition_store import CompetitionStore
from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import VerificationReuse, verification_owner_operation
from .competition_verification_snapshot import verified_package_digest
from .concurrency import run_owned_thread
from .mortal_receipts import MortalReceiptQuery
from .open_competition import ModelBundle, digest, identity
from .private_files import MAX_CONFIGURED_PRIVATE_BYTES
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
    success flag cannot populate this process-local cache. One compact result per
    authenticated activation revision is retained here. Original package
    verification remains reusable when only authenticated reward parameters change.
    """

    def __init__(
        self,
        reader: StandingRewardControlReader,
        promotion_store: CompetitionStore,
        manifest: RewardManifest | None = None,
        *,
        maximum_promotion_bytes: int,
        maximum_package_bytes: int = DEFAULT_PACKAGE_BYTES,
        model_artifacts: DirectModelSettlementVerifier | None = None,
        allocation_sink: Callable[[CohortRewardAllocation], None] | None = None,
    ):
        check_aggregate_evidence_bytes(maximum_package_bytes)
        if (
            type(maximum_promotion_bytes) is not int
            or not 1024 <= maximum_promotion_bytes <= MAX_CONFIGURED_PRIVATE_BYTES
        ):
            raise ValueError("reward preparation byte bound is invalid")
        if digest(promotion_store.policy) != digest(reader.policy):
            raise ValueError("reward preparation promotion store belongs to another policy")
        self.reader, self.promotion_store = reader, promotion_store
        self.manifest = retain_reward_manifest(reader, manifest)
        self.series_sha256, self.policy_sha256 = digest(reader.series), digest(reader.policy)
        self.maximum_promotion_bytes = maximum_promotion_bytes
        self.maximum_package_bytes = maximum_package_bytes
        self.model_artifacts = model_artifacts
        if allocation_sink is not None and not callable(allocation_sink):
            raise TypeError("reward allocation export requires an explicit owner sink")
        self.allocation_sink = allocation_sink
        self.verification_reuse = VerificationReuse(
            promotion_store.directory / "verification" / self.series_sha256 / "native",
            owner={
                "series": self.series_sha256,
                "policy": self.policy_sha256,
                "reader": reader.chain_config_sha256,
            },
        )
        self._lock = asyncio.Lock()
        self._owner = object()
        self._prepared: dict[str, PreparedStandingReward] = {}
        self._baseline_models: dict[str, dict[str, ModelBundle]] = {}
        self._transport_qualifications = None

    @property
    def transport_qualifications(self):
        self._authority()
        if self._transport_qualifications is None:
            self._transport_qualifications = PackageTransportQualifications(self)
        return self._transport_qualifications

    def _authority(self) -> None:
        if (
            digest(self.reader.series) != self.series_sha256
            or digest(self.reader.policy) != self.policy_sha256
            or digest(self.promotion_store.policy) != self.policy_sha256
            or digest(self.manifest) != self.reader.series.manifest_sha256
        ):
            raise ValueError("reward preparation authority changed")

    def _selected(
        self,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> HistoryVerifiedStandingRewardSelection:
        self._authority()
        current = self.reader.select_history(control, source, history)
        if current.selection.state not in {"draining", "selected"}:
            raise ValueError("standing control has no active reward package")
        return current

    @verification_owner_operation
    async def prepare(
        self,
        package: CohortRewardPackage,
        *,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> PreparedStandingReward:
        async with self._lock:
            await self._ensure_model_artifacts(package)
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
        return self._prepare_allocation(package, activation, control.snapshot.block_number)

    @verification_owner_operation
    async def prepare_historical(
        self,
        package: CohortRewardPackage,
        *,
        control: OwnedHistoricalRewardControl,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> PreparedStandingReward:
        """Replay the package effective at a past root for coverage reconstruction.

        This may be the preceding cohort during a successor's drain. It does not
        project a row, credit an interval or grant authority to submit today.
        """
        async with self._lock:
            await self._ensure_model_artifacts(package)
            return await run_owned_thread(
                partial(self._prepare_historical, package, control, history, source)
            )

    def _prepare_historical(self, package, control, history, source):
        self._authority()
        selected = self.reader.review_history(control, source, history).effective_selection
        if selected is None or selected.state != "selected" or selected.activation is None:
            raise ValueError("historical control has no effective reward package")
        return self._prepare_allocation(package, selected.activation, control.snapshot.block_number)

    @verification_owner_operation
    async def prepare_initial(
        self,
        package: CohortRewardPackage,
        *,
        control: OwnedHistoricalRewardControl,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
    ) -> PreparedStandingReward:
        """Recover the first activation for the original installation handoff.

        A later cohort or revocation may be current. This replays the initial
        package from complete native history without selecting it for weights.
        Projection still requires fresh control and the current activation.
        """
        async with self._lock:
            await self._ensure_model_artifacts(package)
            return await run_owned_thread(
                partial(self._prepare_initial, package, control, history, source)
            )

    def _prepare_initial(self, package, control, history, source):
        self._authority()
        initial = self.reader.review_history(control, source, history).initial_selection
        if (
            initial is None
            or initial.sequence != 1
            or initial.activation is None
            or initial.activation.cohort_sha256 != digest(self.reader.series.cohorts[0])
        ):
            raise ValueError("standing history has no initial activation")
        return self._prepare_allocation(package, initial.activation, control.snapshot.block_number)

    def _prepare_allocation(
        self, package: CohortRewardPackage, activation: RewardActivation, block: int
    ) -> PreparedStandingReward:
        requirement = self.manifest.requirement(activation.cohort_sha256)
        package = _validated_reward_snapshot(package, self.maximum_package_bytes)
        if (
            verified_package_digest(package) != activation.package_sha256
            or digest(package.allocation) != activation.allocation_sha256
            or digest(package.inputs.history.plan) != activation.cohort_sha256
            or digest(package.inputs.history.authority.authority)
            != digest(self.reader.series.recovery.authority)
        ):
            raise ValueError("reward package differs from current standing activation")
        self.transport_qualifications.qualify(
            package,
            package_sha256=activation.package_sha256,
            cohort_sha256=activation.cohort_sha256,
        )
        adoption = (
            None
            if activation.reward_adoption_sha256 is None
            else verify_reward_adoption(
                getattr(self.reader, "reward_adoptions", None),
                activation.reward_adoption_sha256,
                series=self.reader.series,
                policy=self.reader.policy,
                activation=activation,
                package=package,
                current_block=block,
            )
        )
        retained = self._prepared.get(digest(activation))
        if retained is not None:
            self._check_prepared(retained)
            if retained.activation != activation:
                raise ValueError("standing activation changed its retained revision")
            # Replay at an earlier root must recheck that the original cohort
            # certification and artifacts were valid by that block. A later
            # successful review cannot backdate their validity.
            if block >= retained.reviewed_at_block:
                self._export_allocations(package.allocation, retained.allocation)
                return retained
        allocation = _replay_detached_reward_package(
            package,
            self.reader.policy,
            self.promotion_store,
            package.inputs.history,
            expected_package_sha256=activation.package_sha256,
            expected_cohort_sha256=activation.cohort_sha256,
            expected_tip_sha256=activation.recovery_tip_sha256,
            current_block=block,
            expected_terms_sha256=requirement.terms_sha256,
            expected_catalog_sha256s=requirement.catalog_sha256s,
            maximum_promotion_bytes=self.maximum_promotion_bytes,
            maximum_bytes=self.maximum_package_bytes,
            verify_model_artifact=(
                None if self.model_artifacts is None else self.model_artifacts.verify_candidate
            ),
        )
        if adoption is not None:
            with TransferProgress(
                "reward_effective_allocation",
                1,
                unit="allocations",
                planning_unit_seconds=(0.001, 1),
            ) as progress:
                allocation = derive_effective_reward_allocation(package, adoption.parameters)
                if digest(allocation) != activation.effective_allocation_sha256:
                    raise ValueError("effective reward allocation differs from signed adoption")
                progress.advance(1)
        prepared = PreparedStandingReward(
            self.series_sha256,
            activation,
            digest(requirement),
            allocation,
            block,
            _owner=self._owner,
        )
        object.__setattr__(prepared, "_binding", _binding(prepared))
        if allocation.model_award is not None:
            self._baseline_models[digest(activation)] = {
                digest(sub): sub.model_bundle
                for participant in package.inputs.roster.participants
                if (sub := participant.record.request.signed_submission.submission).track == "model"
                and sub.model_bundle is not None
            }
        # Retain completion inside the owned thread, even if its waiter was
        # cancelled. Proof expiry during replay never discards immutable work.
        self._prepared[digest(activation)] = prepared
        self._export_allocations(package.allocation, prepared.allocation)
        return prepared

    def _export_allocations(self, original, effective):
        if self.allocation_sink is None:
            return
        allocations = (
            (original,) if digest(original) == digest(effective) else (original, effective)
        )
        with TransferProgress(
            "reward_allocation_export",
            len(allocations),
            unit="allocations",
            planning_unit_seconds=(0.001, 1),
        ) as progress:
            for allocation in allocations:
                self.allocation_sink(allocation)
                progress.advance(1)

    async def _ensure_model_artifacts(self, package: CohortRewardPackage) -> None:
        award = package.allocation.model_award
        if self.model_artifacts is None or award is None:
            return
        completed = {a.acceptance.submission_sha256 for a in award.acceptances}
        participants = tuple(
            participant
            for participant in package.inputs.roster.participants
            if participant.record.request.signed_submission.submission.track == "model"
            and digest(participant.record.request.signed_submission.submission) in completed
        )
        await self.model_artifacts.ensure_all(participants, award.acceptances)

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
        if prepared.activation.reward_adoption_sha256 is not None:
            verify_reward_adoption(
                getattr(self.reader, "reward_adoptions", None),
                prepared.activation.reward_adoption_sha256,
                series=self.reader.series,
                policy=self.reader.policy,
                activation=prepared.activation,
                current_block=prepared.reviewed_at_block,
            )
        expected = (
            prepared.activation.effective_allocation_sha256 or prepared.activation.allocation_sha256
        )
        if digest(prepared.allocation) != expected:
            raise ValueError("prepared rewards changed their effective allocation")

    def baseline_candidate(
        self, prepared: PreparedStandingReward
    ) -> CohortBaselineCandidate | None:
        """Select from this owner's replayed award without reloading its payload.

        This does not append promotion history or authorize a signature. A
        separately reviewed preserving promotion must bind the candidate to the
        activation/package and the actual current promotion head.
        """
        self._authority()
        self._check_prepared(prepared)
        award = prepared.allocation.model_award
        if award is None:
            raise ValueError("a promotion-attribution allocation has no cohort model award")
        with TransferProgress(
            "cohort_baseline_candidate_selection",
            1,
            unit="awards",
            planning_unit_seconds=(0.001, 10),
        ) as progress:
            candidate = select_cohort_baseline_candidate(award)
            progress.advance(1)
        return candidate

    def baseline_review(
        self,
        prepared: PreparedStandingReward,
        *,
        target_cohort_sha256: str,
        previous: PromotionHeadBinding,
        not_before_block: int,
        valid_through_block: int,
    ) -> CohortBaselineReview:
        """Build review metadata solely from this owner's completed native replay.

        The caller independently reads the actual promotion head. Its consuming
        append must recheck that head and the original retained preparation; this
        method grants neither signature authority nor permission to alter it.
        The successor's own paired evaluation determines meet-or-exceed status.
        """
        with TransferProgress(
            "cohort_baseline_review_preparation",
            1,
            unit="reviews",
            planning_unit_seconds=(0.001, 10),
        ) as progress:
            candidate = self.baseline_candidate(prepared)
            if candidate is None:
                raise ValueError("no eligible public model can become a successor baseline")
            plans = {digest(p): p for p in self.reader.series.cohorts}
            source = plans.get(prepared.activation.cohort_sha256)
            target = plans.get(target_cohort_sha256)
            model = self._baseline_models.get(digest(prepared.activation), {}).get(
                candidate.submission_sha256
            )
            if (
                source is None
                or target is None
                or model is None
                or digest(model) != candidate.model_sha256
            ):
                raise ValueError("baseline review requires retained source and selected successor")
            if not_before_block < prepared.reviewed_at_block:
                raise ValueError("baseline review cannot backdate its native source observation")
            result = validate_baseline_review(
                CohortBaselineReview(
                    schema="umi-cohort-baseline-review/1",
                    policy_sha256=self.policy_sha256,
                    series_sha256=self.series_sha256,
                    source_cohort_sha256=digest(source),
                    source_sequence=source.sequence,
                    activation_sha256=digest(prepared.activation),
                    package_sha256=prepared.activation.package_sha256,
                    allocation_sha256=digest(prepared.allocation),
                    target_cohort_sha256=digest(target),
                    target_sequence=target.sequence,
                    previous=previous,
                    candidate=candidate,
                    model=model,
                    not_before_block=not_before_block,
                    valid_through_block=valid_through_block,
                ),
                self.reader.policy,
            )
            progress.advance(1)
            return result

    async def project(
        self,
        prepared: PreparedStandingReward,
        *,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
        prior_opportunity: object | None = None,
    ) -> PreparedStandingProjection:
        async with self._lock:
            return await run_owned_thread(
                partial(
                    self._project,
                    prepared,
                    control,
                    history,
                    source,
                    chain,
                    chain_config,
                    prior_opportunity,
                )
            )

    def _project(
        self,
        prepared: PreparedStandingReward,
        control: OwnedRewardControlObservation,
        history: OwnedRewardControlHistory,
        source: DecisionSource,
        chain: OwnedCompetitionChainObservation,
        chain_config: CompetitionChainConfig,
        prior_opportunity: object | None = None,
    ) -> PreparedStandingProjection:
        self._check_prepared(prepared)
        current = self._selected(control, history, source)
        if (
            current.selection.state != "selected"
            or current.effective_selection != current.selection
            or current.selection.activation != prepared.activation
            or chain.snapshot != control.snapshot
            or chain.block < prepared.reviewed_at_block
            or chain.chain_config_sha256 != self.reader.chain_config_sha256
            or identity(chain.validator_hotkey)
            not in {identity(k) for k in self.reader.series.validators}
        ):
            raise ValueError("prepared rewards lack current standing selection and validator state")
        if activation_requires_revision(self.reader, current.selection):
            raise ValueError("selected reward parameters require a native activation revision")
        if isinstance(self.manifest, StandingRewardOpportunityManifest):
            require_previous_opportunity(
                prior_opportunity,
                reader=self.reader,
                manifest=self.manifest,
                selection=current.selection,
                validator_hotkey=chain.validator_hotkey,
                current_block=chain.block,
            )
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
        prior_opportunity: object | None = None,
    ) -> MortalReceiptQuery:
        """Bind encoded bytes to a freshly checked allocation and signing context.

        The returned receipt query supplies checked search bounds only. Legacy
        handoff, exclusive writer ownership and durable
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
                    prior_opportunity,
                )
            )

    def _verify_transaction_bytes(
        self,
        prepared,
        encoded,
        period,
        control,
        history,
        source,
        chain,
        chain_config,
        prior_opportunity,
    ):
        current = self._project(
            prepared, control, history, source, chain, chain_config, prior_opportunity
        )
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
        refreshed = self._project(
            prepared, control, history, source, chain, chain_config, prior_opportunity
        )
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
        prior_opportunity: object | None = None,
        previous: StandingTransactionEnd | None = None,
    ) -> PendingStandingWeight:
        """Retain an unsigned intent and recovery inputs before any signing.

        This method does not grant signing authority. The execution owner
        must also verify legacy migration fencing and exclusive writer ownership.
        """
        async with self._lock:

            def retain():
                current = self._project(
                    prepared, control, history, source, chain, chain_config, prior_opportunity
                )
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
                self._project(
                    prepared, control, history, source, chain, chain_config, prior_opportunity
                )
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
        prior_opportunity: object | None = None,
    ) -> PendingStandingWeight:
        """Verify actual bytes and commit them against their original reservation.

        A successful return is a recoverable local record, never a broadcast or
        permission to submit. Every transmission still needs fresh native gates.
        """
        async with self._lock:

            def retain():
                current = self._project(
                    prepared, control, history, source, chain, chain_config, prior_opportunity
                )
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
                    prior_opportunity,
                )
                return journal.retain_signed(intent, encoded)

            return await run_owned_thread(retain)
