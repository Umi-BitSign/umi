"""Recurring operator-or-timeout adoption using the existing reward owners.

Package discovery precedes the economics gate. A native-reviewed original is
retained before signing, so a restart resumes the same issuance and quorum.
Explicit lifecycle/settlement holds always take precedence over either trigger.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_geometric_rewards import cohort_reward_parameters
from .competition_reward_adoption import RewardAutomaticRelease, RewardModelAdoption
from .competition_reward_control import OwnedRewardControlObservation
from .competition_reward_decisions import SignedRewardControlDecision
from .competition_reward_opportunity import (
    opportunity_rule,
    prepare_early_release_revision,
    prepare_initial_early_release_adoption,
)
from .competition_reward_signing import RewardQuorumPending
from .competition_reward_transition_anchor import RewardLiveAnchorMissing
from .competition_reward_transition_native import NativeRewardTransitionReviewer
from .competition_reward_transition_review import predecessor_live_age_from_owned_control
from .competition_round_journal import RoundJournal
from .competition_verification_snapshot import verified_package_digest
from .competition_work_progress import WorkProgress
from .concurrency import run_owned_thread
from .host_memory_runtime import run_memory_thread
from .open_competition import digest, identity
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_ORIGINAL_BYTES = 128 * 1024**2


class RewardTransitionOriginal(StrictProtocolModel):
    schema_: Literal["umi-reward-transition-original/1"] = Field(alias="schema")
    proposal: RewardModelAdoption
    predecessor: SignedRewardControlDecision
    control_evidence_hex: str
    control_metadata_hex: str


@dataclass(frozen=True)
class RewardTransitionProgress:
    status: str
    observation: OwnedRewardControlObservation | None = None
    remaining_seconds: float | None = None


class StandingRewardTransitionProducer:
    def __init__(
        self,
        *,
        root: Path,
        reviewer,
        signer,
        exchange,
        coverage,
        offers,
        controls,
        feed,
        maximum_bytes,
    ):
        if type(reviewer) is not NativeRewardTransitionReviewer:
            raise TypeError("reward producer requires the existing native reviewer")
        self.reviewer, self.signer, self.exchange = reviewer, signer, exchange
        self.coverage, self.offers, self.controls, self.feed = coverage, offers, controls, feed
        native = reviewer.reviewer
        if (
            coverage.provider is not native.provider
            or offers.files is not native.files
            or feed is None
            or feed.series != native.reader.series
            or signer.journal.series != feed.series
            or signer.journal.chain_config_sha256 != native.reader.chain_config_sha256
        ):
            raise ValueError("reward producer owners differ from the selected native context")
        self.originals = RoundJournal(
            root,
            {
                "schema": "umi-reward-transition-original-owner/1",
                "series": digest(feed.series),
                "policy": digest(feed.policy),
                "chain": signer.journal.chain_config_sha256,
            },
            maximum_rounds=4096,
            maximum_bytes=maximum_bytes,
            maximum_record_bytes=MAX_ORIGINAL_BYTES,
        )
        self._live = {}
        self._original = None
        self._reviewed = None

    async def _endpoint(self, predecessor, key=None):
        activation = predecessor.activation
        cache = (digest(activation), key)
        if cache in self._live:
            return self._live[cache]
        if key is None:
            key = await run_owned_thread(
                lambda: self.coverage.journal.first_live_anchor(
                    activation,
                    validators=self.feed.series.validators,
                    chain_config_sha256=self.signer.journal.chain_config_sha256,
                    not_before_block=predecessor.observed_at_block,
                )
            )
        source = await self.coverage._source(activation)
        endpoint = await source.replay(key)
        # Only the current predecessor and chosen exact endpoint stay resident.
        self._live = {cache: endpoint, (digest(activation), key): endpoint}
        return endpoint

    def _saved(self, slot):
        if self._original is not None and self.signer.journal.slot(self._original.proposal) == slot:
            return self._original
        raw = self.originals.get("transition_original", slot)
        if raw is None:
            if self.signer.journal.load(slot) is not None:
                raise ValueError("signed adoption needs repair of its retained original evidence")
            return None
        result = RewardTransitionOriginal.model_validate_json(canonical_json_bytes(raw))
        if self.signer.journal.slot(result.proposal) != slot:
            raise ValueError("retained transition original changed its revision")
        self._original = result
        return result

    async def step(self, cohort, prefix):
        native = self.reviewer.reviewer
        reader, series = native.reader, native.reader.series
        # This references the same authoritative controls as intake/settlement.
        # An approved release and an elapsed clock cannot remove an explicit hold.
        if await run_owned_thread(self.controls.held, cohort):
            return RewardTransitionProgress("progression_held")
        index = tuple(digest(plan) for plan in series.cohorts).index(cohort)
        if index == 0:
            # Initial series handoff retains its separately signed boundary.
            return RewardTransitionProgress("selected")
        selected = reader.reward_adoptions
        latest = None if selected is None else selected.latest(cohort)
        if latest is not None and latest.adoption.early_release is not None:
            return RewardTransitionProgress("selected")
        package = await run_memory_thread(self.offers.completed_package, cohort, prefix)
        if package is None:
            return RewardTransitionProgress("allocation_pending")
        preceding = prefix[-1]
        predecessor = preceding.decision
        if (
            predecessor.kind not in {"activate", "revise_activation", "resume_activation"}
            or predecessor.activation is None
            or predecessor.activation.cohort_sha256 != digest(series.cohorts[index - 1])
        ):
            raise ValueError("reward transition requires the active immediately preceding cohort")
        package_sha = verified_package_digest(package)
        approval = await run_owned_thread(
            self.controls.approval, cohort, digest(predecessor), package_sha
        )
        revision = 1 if latest is None else latest.adoption.revision + 1
        slot = f"{cohort}-{revision:06d}"
        saved = await run_owned_thread(self._saved, slot)
        current = await native.provider.collect_control(series.control_hotkey)
        live = None
        if saved is None:
            age = None
            if approval is None:
                try:
                    live = await self._endpoint(predecessor)
                except RewardLiveAnchorMissing:
                    return RewardTransitionProgress("first_live_anchor_pending", current)
                age = predecessor_live_age_from_owned_control(
                    series=series,
                    predecessor=predecessor,
                    live_endpoint=live,
                    observation=current,
                    chain_config_sha256=reader.chain_config_sha256,
                    rule=opportunity_rule(native.manifest, series, reader.policy),
                )
                if not age.ready:
                    return RewardTransitionProgress(
                        "operator_or_timeout_pending", current, age.remaining_ms / 1000
                    )
            reason = (
                "Automatic release after 24 hours of finalized predecessor live time"
                if approval is None
                else approval.approval.reason
            )
            common = dict(
                series=series,
                policy=reader.policy,
                manifest=native.manifest,
                predecessor=predecessor,
                issued_at_block=current.snapshot.block_number,
                reason=reason,
                live_age=age,
            )
            if latest is None:
                proposal = await run_memory_thread(
                    lambda: prepare_initial_early_release_adoption(
                        package,
                        selection=selected,
                        parameters=cohort_reward_parameters(series.cohorts[index].sequence),
                        **common,
                    )
                )
            else:
                if latest.adoption.package_sha256 != package_sha:
                    raise ValueError("selected adoption and completed successor package differ")
                proposal = prepare_early_release_revision(
                    selected, successor_cohort_sha256=cohort, **common
                )
            observation = current
            saved = RewardTransitionOriginal(
                schema="umi-reward-transition-original/1",
                proposal=proposal,
                predecessor=preceding,
                control_evidence_hex=current.evidence.hex(),
                control_metadata_hex=current.runtime.metadata_bytes.hex(),
            )
        else:
            proposal = saved.proposal
            if saved.predecessor != preceding or proposal.package_sha256 != package_sha:
                raise ValueError("retained transition changed its exact predecessor or package")
            if isinstance(proposal.early_release, RewardAutomaticRelease):
                # Once reserved, a later operator request does not change the
                # selected trigger, issuance, exact evidence or quorum slot.
                approval = None
            if proposal.early_release.schema_ == "umi-reward-early-release/1" and approval is None:
                raise ValueError("operator-approved transition lost its exact approval")
            if approval is not None and proposal.early_release.reason != approval.approval.reason:
                raise ValueError("operator-approved transition changed its retained reason")
            observation = None
        with WorkProgress(
            "reward_transition_producer",
            4,
            unit="stages",
            cohort=cohort,
            estimate=False,
            planning_range_seconds=(0, 300),
            planning_basis=(
                "native retained review, configured signatures and replicated quorum; "
                "missing delivery remains pending"
            ),
        ) as progress:
            review = self._reviewed
            if review is None or review.intent.proposal != proposal:
                if observation is None:
                    observation = await native.provider.review_control(
                        bytes.fromhex(saved.control_evidence_hex),
                        bytes.fromhex(saved.control_metadata_hex),
                    )
                age = getattr(proposal.early_release, "live_age", None)
                if age is not None and live is None:
                    live = await self._endpoint(predecessor, age.live_endpoint_sha256)
                review = await self.reviewer.review(
                    package=package,
                    proposal=proposal,
                    predecessor=preceding,
                    observation=observation,
                    current_observation=current,
                    live_endpoint=live,
                )
                await run_owned_thread(self.originals.put, "transition_original", slot, saved)
                self._original, self._reviewed = saved, review
            else:
                # Original package semantics remain reusable; current authority
                # must still match before any new signatures or publication.
                self.reviewer._control(current, predecessor, current=True)
            progress.advance()
            if await run_owned_thread(self.controls.held, cohort):
                return RewardTransitionProgress("progression_held", current)
            await self.signer.attest(review)
            progress.advance()
            request = await run_owned_thread(
                lambda: self.exchange.publish_request(
                    proposal,
                    predecessor=preceding,
                    control_evidence=bytes.fromhex(saved.control_evidence_hex),
                    control_metadata=bytes.fromhex(saved.control_metadata_hex),
                    operator_approval=approval,
                )
            )
            peer_reviewed = False
            for evaluator in reader.policy.evaluators:
                if identity(evaluator.hotkey) == self.signer.journal.signer:
                    continue
                vote = await run_owned_thread(self.signer.journal.vote, slot, evaluator.hotkey)
                if vote is None:
                    try:
                        vote = await self.exchange.vote_port(evaluator.hotkey)(request)
                    except FileNotFoundError:
                        continue
                    if identity(vote.hotkey) != identity(evaluator.hotkey):
                        raise ValueError("reward transition peer vote changed its evaluator")
                    await self.signer.collect(slot, vote)
                peer_reviewed = True
            # A one-group policy can have several native reviewers. Its local
            # signature still meets the historical certificate quorum, but a
            # new producer publication must retain a distinct configured peer's
            # review. Reuse that durable vote after interruption or delivery loss.
            if not peer_reviewed:
                progress.emit("waiting")
                return RewardTransitionProgress("adoption_quorum_pending", current)
            try:
                await self.signer.certify(slot)
            except RewardQuorumPending:
                progress.emit("waiting")
                return RewardTransitionProgress("adoption_quorum_pending", current)
            progress.advance()
            # The current observation must still be within its native validity
            # interval after signing/delivery. Expiry retries the same intent.
            self.reviewer._control(current, predecessor, current=True)
            if await run_owned_thread(self.controls.held, cohort):
                return RewardTransitionProgress("progression_held", current)
            await self.signer.publish(slot, self.feed)
            progress.advance()
            return RewardTransitionProgress("selected", current)
