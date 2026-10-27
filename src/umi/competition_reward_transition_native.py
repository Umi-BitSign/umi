"""Native package and predecessor review before an adoption receives signatures.

This owner shares the ordinary reward reviewer's retained semantic results.
An adoption review grants neither publication nor chain transaction authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from functools import partial
from typing import Literal

from pydantic import Field

from .competition_cohort_intake import history_tip
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_reward_package import replay_reward_package
from .competition_reward_adoption import (
    RewardAutomaticRelease,
    RewardModelAdoption,
    derive_adopted_reward_allocation,
    prepare_initial_reward_adoption,
)
from .competition_reward_control import (
    OwnedRewardControlObservation,
    validate_owned_reward_control,
)
from .competition_reward_control_archive import (
    OwnedHistoricalRewardControl,
    validate_historical_reward_control,
)
from .competition_reward_coordinator import StandingRewardDecisionReviewer
from .competition_reward_decisions import SignedRewardControlDecision
from .competition_reward_opportunity import (
    opportunity_rule,
    prepare_early_release_revision,
    prepare_initial_early_release_adoption,
)
from .competition_reward_transition_review import predecessor_live_age_from_owned_control
from .competition_verification_reuse import verification_owner_operation
from .competition_verification_snapshot import VerifiedPackageSnapshot, verified_package_digest
from .competition_work_progress import WorkProgress
from .concurrency import run_owned_thread
from .host_memory_runtime import memory_operation
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()


class RewardAdoptionReviewIntent(StrictProtocolModel):
    schema_: Literal["umi-reward-adoption-review-intent/1"] = Field(alias="schema")
    proposal: RewardModelAdoption
    predecessor_decision_sha256: Hex32
    manifest_sha256: Hex32
    control_evidence_sha256: Hex32
    control_metadata_sha256: Hex32
    chain_config_sha256: Hex32


@dataclass(frozen=True, slots=True)
class ReviewedRewardAdoption:
    intent: RewardAdoptionReviewIntent
    chain_submission_authorized: Literal[False] = False
    _issuer: object = field(default=None, repr=False, compare=False)
    _binding: str = field(default="", repr=False, compare=False)


def validate_reward_adoption_review(value: ReviewedRewardAdoption) -> RewardAdoptionReviewIntent:
    if (
        type(value) is not ReviewedRewardAdoption
        or value._issuer is not _ISSUER
        or value._binding != digest(value.intent)
        or value.chain_submission_authorized is not False
    ):
        raise ValueError("reward adoption lacks native pre-signing review")
    return value.intent


class NativeRewardTransitionReviewer:
    def __init__(self, reviewer: StandingRewardDecisionReviewer):
        if type(reviewer) is not StandingRewardDecisionReviewer:
            raise TypeError("reward transition requires the existing native decision reviewer")
        self.reviewer = reviewer
        self.verification_reuse = reviewer.verification_reuse

    def _control(self, observation, predecessor, *, current=False):
        reader = self.reviewer.reader
        expected = dict(
            expected_control_hotkey=reader.series.control_hotkey,
            expected_chain_config_sha256=reader.chain_config_sha256,
        )
        if not current and type(observation) is OwnedHistoricalRewardControl:
            validate_historical_reward_control(observation, **expected)
        else:
            validate_owned_reward_control(observation, **expected)
        if (
            predecessor.series_sha256 != digest(reader.series)
            or predecessor.kind
            not in {"admit_series", "activate", "revise_activation", "resume_activation"}
            or observation.control_sha256 != digest(predecessor)
            or observation.committed_at_block is None
            or observation.committed_at_block < predecessor.observed_at_block
        ):
            raise ValueError("reward transition predecessor is no longer selected")

    def _proposal(self, package, proposal, predecessor, observation, live_endpoint):
        p = self.reviewer
        self._control(observation, predecessor)
        if proposal.issued_at_block != observation.snapshot.block_number:
            raise ValueError("reward adoption differs from its pinned finalized issuance")
        release = proposal.early_release
        age = None
        if isinstance(release, RewardAutomaticRelease):
            age = predecessor_live_age_from_owned_control(
                series=p.reader.series,
                predecessor=predecessor,
                live_endpoint=live_endpoint,
                observation=observation,
                chain_config_sha256=p.reader.chain_config_sha256,
                rule=opportunity_rule(p.manifest, p.reader.series, p.reader.policy),
            )
            if age != release.live_age:
                raise ValueError("automatic reward adoption changes its pinned native live age")
        elif live_endpoint is not None:
            raise ValueError("operator release does not select an automatic live-age endpoint")
        shared = dict(
            series=p.reader.series,
            policy=p.reader.policy,
            issued_at_block=proposal.issued_at_block,
        )
        if release is None:
            expected = prepare_initial_reward_adoption(
                package,
                **shared,
                parameters=proposal.parameters,
                previous=p.reader.reward_adoptions,
            )
        elif proposal.revision == 1:
            expected = prepare_initial_early_release_adoption(
                package,
                **shared,
                selection=p.reader.reward_adoptions,
                manifest=p.manifest,
                predecessor=predecessor,
                parameters=proposal.parameters,
                reason=release.reason,
                live_age=age,
            )
        else:
            expected = prepare_early_release_revision(
                p.reader.reward_adoptions,
                **shared,
                manifest=p.manifest,
                predecessor=predecessor,
                successor_cohort_sha256=proposal.cohort_sha256,
                reason=release.reason,
                live_age=age,
            )
        if proposal != expected:
            raise ValueError("reward adoption differs from its native exact-package proposal")
        if (
            verified_package_digest(package) != proposal.package_sha256
            or digest(package.allocation) != proposal.allocation_sha256
            or digest(package.service) != proposal.service_certificate_sha256
            or digest(package.benchmark) != proposal.quality_manifest_sha256
            or digest(package.inputs.history.plan) != proposal.cohort_sha256
            or digest(package.inputs.history.authority.authority) != proposal.authority_sha256
            or package.policy_sha256 != proposal.policy_sha256
        ):
            raise ValueError("reward adoption changes the original retained package")

    @memory_operation
    async def _package(self, package, proposal):
        p = self.reviewer
        if p.model_artifacts is not None and package.allocation.model_award is not None:
            completed = {
                item.acceptance.submission_sha256
                for item in package.allocation.model_award.acceptances
            }
            participants = tuple(
                item
                for item in package.inputs.roster.participants
                if item.record.request.signed_submission.submission.track == "model"
                and digest(item.record.request.signed_submission.submission) in completed
            )
            await p.model_artifacts.ensure_all(
                participants, package.allocation.model_award.acceptances
            )
        requirement = p.manifest.requirement(proposal.cohort_sha256)
        allocation = await run_owned_thread(
            partial(
                replay_reward_package,
                package,
                p.reader.policy,
                p.store,
                package.inputs.history,
                expected_package_sha256=proposal.package_sha256,
                expected_cohort_sha256=proposal.cohort_sha256,
                expected_tip_sha256=history_tip(package.inputs.history),
                current_block=proposal.issued_at_block,
                expected_terms_sha256=requirement.terms_sha256,
                expected_catalog_sha256s=requirement.catalog_sha256s,
                maximum_promotion_bytes=p.maximum_promotion_bytes,
                maximum_bytes=p.files.maximum_package_bytes,
                verify_model_artifact=None
                if p.model_artifacts is None
                else p.model_artifacts.verify_candidate,
            )
        )
        if digest(allocation) != proposal.allocation_sha256:
            raise ValueError("reward adoption differs from its native replay allocation")
        # The initial proposal builder already derives and checks these exact
        # economics. Revision builders preserve signed predecessors instead.
        if proposal.revision > 1:
            effective = await run_owned_thread(
                derive_adopted_reward_allocation, package, proposal, p.reader.policy
            )
            if digest(effective) != proposal.effective_allocation_sha256:
                raise ValueError("reward adoption differs from deterministic effective allocation")

    @verification_owner_operation
    async def review(
        self,
        *,
        package: VerifiedPackageSnapshot,
        proposal: RewardModelAdoption,
        predecessor: SignedRewardControlDecision,
        observation: OwnedHistoricalRewardControl | OwnedRewardControlObservation,
        current_observation: OwnedRewardControlObservation | None = None,
        live_endpoint=None,
    ) -> ReviewedRewardAdoption:
        if type(package) is not VerifiedPackageSnapshot:
            raise TypeError("reward transition requires an already retained verified package")
        proposal = RewardModelAdoption.model_validate_json(canonical_json_bytes(proposal))
        signed_predecessor = SignedRewardControlDecision.model_validate_json(
            canonical_json_bytes(predecessor)
        )
        predecessor = signed_predecessor.decision
        verify_recovery_quorum(
            predecessor, signed_predecessor.signatures, self.reviewer.reader.policy
        )
        current = observation if current_observation is None else current_observation
        if type(current) is not OwnedRewardControlObservation:
            raise ValueError("pinned historical review also requires fresh current control")
        if current is not observation:
            self._control(current, predecessor, current=True)
        with WorkProgress(
            "reward_adoption_native_review",
            3,
            unit="stages",
            cohort=proposal.cohort_sha256,
            estimate=False,
            planning_range_seconds=(1, 120),
            planning_basis=(
                "retained package review; native substage counts govern cold or repaired inputs"
            ),
        ) as progress:
            await run_owned_thread(
                self._proposal, package, proposal, predecessor, observation, live_endpoint
            )
            progress.advance()
            await self._package(package, proposal)
            progress.advance()
            # Semantic receipts are durable before this current freshness fence.
            # A new current observation can retry the same pinned proposal without
            # invalidating any completed unchanged native package verification.
            self._control(current, predecessor, current=True)
            if current.snapshot.block_number < proposal.issued_at_block:
                raise ValueError("current control precedes pinned adoption issuance")
            intent = RewardAdoptionReviewIntent(
                schema="umi-reward-adoption-review-intent/1",
                proposal=proposal,
                predecessor_decision_sha256=digest(predecessor),
                manifest_sha256=digest(self.reviewer.manifest),
                control_evidence_sha256=observation.evidence_sha256,
                control_metadata_sha256=(
                    observation.metadata_sha256
                    if type(observation) is OwnedHistoricalRewardControl
                    else observation.runtime.metadata_sha256
                ),
                chain_config_sha256=self.reviewer.reader.chain_config_sha256,
            )
            result = ReviewedRewardAdoption(intent, _issuer=_ISSUER, _binding=digest(intent))
            progress.advance()
            return result
