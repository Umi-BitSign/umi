"""Recurring reward proposals, native review, independent votes and publication.

Offers and remote signatures are input data. Every local vote follows native
review of the original observation. The installed host owns provider lifetimes,
wallets, sole-writer migration and independent remote delivery qualification.
"""

from __future__ import annotations

import asyncio
import logging
import math
from collections.abc import Awaitable, Callable, Sequence
from contextlib import suppress
from dataclasses import dataclass
from functools import partial

from .competition_cohort_direct_model_review import DirectModelSettlementVerifier
from .competition_progress import _failure_details
from .competition_reward_adoption import initial_reward_boundary
from .competition_reward_control_archive import HistoricalRewardControlProvider
from .competition_reward_control_publisher import StandingControlPublisher
from .competition_reward_decision_review import ReviewedRewardDecision, review_reward_decision
from .competition_reward_decisions import (
    RewardActivation,
    RewardControlDecision,
    SignedRewardControlDecision,
    StandingRewardControlReader,
    effective_activation_decision,
    verify_reward_decision_proposal,
)
from .competition_reward_files import StandingRewardFiles
from .competition_reward_handoff_models import (
    RewardHandoffPlan,
    StandingRewardHandoffPlan,
    verify_handoff_plan,
)
from .competition_reward_history import RewardControlHistoryReader
from .competition_reward_manifest import StandingRewardOpportunityManifest, verify_reward_manifest
from .competition_reward_opportunity import VerifiedRewardOpportunity
from .competition_reward_revision import (
    NativeRewardRevisionReviewer,
    RewardEconomicsLocked,
    RewardRevisionPending,
)
from .competition_reward_series_handoff import StandingRewardPredecessorOpportunity
from .competition_reward_signing import RewardDecisionSigner, RewardQuorumPending
from .competition_store import CompetitionStore
from .competition_verification_reuse import VerificationReuse, verification_owner_operation
from .concurrency import await_owned_task, run_owned_thread, wait_for_owned
from .historical_header_recovery import HistoricalHeaderRecoveryProgress
from .host_memory_runtime import memory_operation, run_memory_thread
from .open_competition import Signature, digest
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)
Prefix = tuple[SignedRewardControlDecision, ...]
VotePort = Callable[[RewardControlDecision, Prefix], Awaitable[Signature]]


class RewardReviewPending(Exception):
    """A bounded original-history pass made durable progress."""


@dataclass(frozen=True)
class RewardCoordinationProgress:
    status: str
    sequence: int
    decision_sha256: str | None = None


class StandingRewardDecisionReviewer:
    def __init__(
        self,
        *,
        reader: StandingRewardControlReader,
        provider: HistoricalRewardControlProvider,
        history: RewardControlHistoryReader,
        files: StandingRewardFiles,
        manifest: StandingRewardOpportunityManifest,
        promotion_store: CompetitionStore,
        handoff: RewardHandoffPlan,
        opportunity: Callable[[RewardActivation], Awaitable[VerifiedRewardOpportunity]],
        maximum_promotion_bytes: int,
        maximum_history_blocks: int = 64,
        model_artifacts: DirectModelSettlementVerifier | None = None,
        predecessor: StandingRewardPredecessorOpportunity | None = None,
        revision_reviewer: NativeRewardRevisionReviewer | None = None,
    ):
        if (
            type(reader) is not StandingRewardControlReader
            or not isinstance(provider, HistoricalRewardControlProvider)
            or type(history) is not RewardControlHistoryReader
            or type(files) is not StandingRewardFiles
        ):
            raise TypeError("reward review requires native proof owners")
        if (
            reader.chain_config_sha256 != digest(provider.config)
            or reader.admission_chain_config_sha256 != digest(provider.config)
            or digest(reader.policy) != digest(provider.policy)
            or history.config_sha256 != digest(provider.config)
            or history.hotkey != reader.series.control_hotkey
            or history.first_block != reader.series.recovery.authority.issued_at_block
            or type(maximum_history_blocks) is not int
            or not 1 <= maximum_history_blocks <= 4096
        ):
            raise ValueError("reward review owners differ from the approved context")
        self.manifest = verify_reward_manifest(
            canonical_json_bytes(manifest), reader.series, reader.policy
        )
        if not isinstance(self.manifest, StandingRewardOpportunityManifest):
            raise ValueError("coordinator requires approved reward opportunity terms")
        if (
            type(maximum_promotion_bytes) is not int
            or not 1024 <= maximum_promotion_bytes <= 16 * 1024**3
        ):
            raise ValueError("reward review requires explicit model replay capacity")
        handoff = verify_handoff_plan(handoff, reader.series)
        standing = type(handoff) is StandingRewardHandoffPlan
        if standing != (predecessor is not None):
            raise ValueError("reward review requires its selected predecessor owner")
        self.reader, self.provider, self.history, self.files = reader, provider, history, files
        self.store, self.handoff, self.predecessor = promotion_store, handoff, predecessor
        self.maximum_history_blocks = maximum_history_blocks
        self.opportunity, self.maximum_promotion_bytes = opportunity, maximum_promotion_bytes
        self.model_artifacts = model_artifacts
        if (
            revision_reviewer is not None
            and type(revision_reviewer) is not NativeRewardRevisionReviewer
        ):
            raise TypeError("reward revisions require the native coverage reviewer")
        self.revision_reviewer = revision_reviewer
        self.verification_reuse = VerificationReuse(
            promotion_store.directory / "verification" / digest(reader.series) / "native",
            owner={
                "series": digest(reader.series),
                "policy": digest(reader.policy),
                "reader": reader.chain_config_sha256,
            },
        )

    @verification_owner_operation
    async def review(self, body: RewardControlDecision, prefix: Prefix) -> ReviewedRewardDecision:
        p = self
        body = verify_reward_decision_proposal(
            p.reader.series,
            p.reader.policy,
            prefix,
            body,
            reward_adoptions=p.reader.reward_adoptions,
        )
        height = body.observed_at_block
        try:
            history = await p.history.verified_prefix(height)
        except ValueError:
            progress = await p.history.advance(
                p.provider, through_block=height, maximum_blocks=p.maximum_history_blocks
            )
            if progress.history is None:
                raise RewardReviewPending from None
            history = progress.history
        control = await p.history.review_control(p.provider, height)
        opportunity = None
        revision_clearance = None
        live_lock = None
        if body.kind in {"revise_activation", "resume_activation"}:
            if p.revision_reviewer is None:
                raise ValueError("reward revision lacks a native all-writer live-history owner")
            try:
                if body.kind == "resume_activation":
                    live_lock = await p.revision_reviewer.live_lock(body.activation)
                if live_lock is None:
                    try:
                        revision_clearance = await p.revision_reviewer.review(
                            prefix=prefix, control=control, history=history
                        )
                    except RewardEconomicsLocked:
                        if body.kind != "resume_activation":
                            raise
                        live_lock = await p.revision_reviewer.live_lock(body.activation)
            except RewardRevisionPending:
                raise RewardReviewPending from None
        if body.activation is not None:
            index = tuple(digest(c) for c in p.reader.series.cohorts).index(
                body.activation.cohort_sha256
            )
            if index == 0 and type(p.handoff) is StandingRewardHandoffPlan:
                opportunity = await p.predecessor.review(
                    body.activation, observed_at_block=body.observed_at_block
                )
            elif index > 0:
                # A peer can first join at a later cohort. Recover its selected
                # predecessor before the opportunity reader looks it up locally.
                objects = {digest(item.decision): canonical_json_bytes(item) for item in prefix}
                selected = await run_owned_thread(
                    p.reader.review_history, control, objects.__getitem__, history
                )
                if selected.selection.decision_sha256 != body.predecessor_sha256:
                    raise ValueError("reward opportunity does not extend the proved predecessor")
                opportunity = await self.opportunity(body.activation)
        return await self._review_package(
            body, prefix, control, history, opportunity, revision_clearance, live_lock
        )

    @memory_operation
    async def _review_package(
        self, body, prefix, control, history, opportunity, revision_clearance=None, live_lock=None
    ):
        p = self
        package = None
        if body.activation is not None:
            package = await run_owned_thread(
                p.files.verified_package, body.activation.package_sha256
            )
            if p.model_artifacts is not None and package.allocation.model_award is not None:
                completed = {
                    a.acceptance.submission_sha256
                    for a in package.allocation.model_award.acceptances
                }
                participants = tuple(
                    participant
                    for participant in package.inputs.roster.participants
                    if participant.record.request.signed_submission.submission.track == "model"
                    and digest(participant.record.request.signed_submission.submission) in completed
                )
                await p.model_artifacts.ensure_all(
                    participants, package.allocation.model_award.acceptances
                )
        return await run_owned_thread(
            partial(
                review_reward_decision,
                p.reader,
                self.manifest,
                prefix,
                body,
                control=control,
                history=history,
                package=package,
                promotion_store=self.store,
                approved_handoff=self.handoff,
                previous_opportunity=opportunity,
                maximum_promotion_bytes=self.maximum_promotion_bytes,
                maximum_package_bytes=p.files.maximum_package_bytes,
                verify_model_artifact=(
                    None if p.model_artifacts is None else p.model_artifacts.verify_candidate
                ),
                revision_clearance=revision_clearance,
                live_lock=live_lock,
            )
        )


class StandingRewardCoordinator:
    """One ordered series; offers may arrive late and votes may resume after outages."""

    def __init__(
        self,
        *,
        reviewer: StandingRewardDecisionReviewer,
        publisher: StandingControlPublisher,
        signer: RewardDecisionSigner,
        readback: StandingRewardFiles,
        offers: Callable[[str, Prefix], RewardActivation | None],
        voters: Sequence[VotePort],
        vote_timeout_seconds: float = 300,
    ):
        if (
            type(reviewer) is not StandingRewardDecisionReviewer
            or type(signer) is not RewardDecisionSigner
            or type(publisher) is not StandingControlPublisher
        ):
            raise TypeError("reward coordinator requires native review and signing owners")
        p, j = publisher, signer.journal
        if (
            reviewer.reader is not p.reader
            or reviewer.provider is not p.provider
            or reviewer.history is not p.history
            or reviewer.files is not p.files
            or digest(j.series) != digest(p.series)
            or digest(j.policy) != digest(p.reader.policy)
            or j.chain_config_sha256 != p.config_sha256
            or type(readback) is not StandingRewardFiles
            or readback.root.resolve() == p.files.root.resolve()
        ):
            raise ValueError("coordinator review, signing or independent readback binding differs")
        if not math.isfinite(vote_timeout_seconds) or not 0 < vote_timeout_seconds <= 3600:
            raise ValueError("one remote vote operation must have a bounded timeout")
        self.reviewer, self.signer, self.readback = reviewer, signer, readback
        self.publisher, self.offers, self.voters = p, offers, tuple(voters)
        self.vote_timeout = vote_timeout_seconds
        self.serial = asyncio.Lock()
        self._reviewed: ReviewedRewardDecision | None = None
        self._unreviewed: RewardControlDecision | None = None
        self._revision_target = None
        self.phase, self.sequence = "starting", 0

    def _prefix(self) -> Prefix:
        j = self.signer.journal
        with j.journal.locked():
            return j.prefix(len(j.journal.keys("reward_certificate")))

    def _pending(self, sequence: int) -> RewardControlDecision | None:
        j = self.signer.journal
        with j.journal.locked():
            intent = j.load(sequence)
            return None if intent is None else intent.decision

    def _readback(self, prefix: Prefix) -> None:
        """Verify separate delivery bytes; host setup must prove their remote origin."""
        for item in prefix:
            sha = digest(item.decision)
            if self.readback.decision(sha) != self.publisher.files.decision(sha):
                raise ValueError("independent decision readback differs from original delivery")
            admission = item.decision.admission_adoption_sha256
            if admission is not None and (
                self.readback.adoption(admission) != self.publisher.files.adoption(admission)
            ):
                raise ValueError("independent admission readback changes its signed adoption")
            activation = item.decision.activation
            if activation is not None:
                package = self.readback.verified_package(activation.package_sha256)
                if digest(package.allocation) != activation.allocation_sha256:
                    raise ValueError("independent package readback changes its allocation")
                if activation.reward_adoption_sha256 is not None and (
                    self.readback.adoption(activation.reward_adoption_sha256)
                    != self.publisher.files.adoption(activation.reward_adoption_sha256)
                ):
                    raise ValueError("independent adoption readback changes its signed selection")
                del package  # Release before the next prefix item is decoded.

    async def _revision_proposal(self, prefix):
        reader = self.reviewer.reader
        selected = reader.reward_adoptions
        old = effective_activation_decision(prefix)
        if selected is None or old is None:
            return None
        latest = selected.latest(old.activation.cohort_sha256)
        suspension = prefix[-1].decision.kind == "suspend_activation"
        if not suspension and (
            latest is None or digest(latest.adoption) == old.activation.reward_adoption_sha256
        ):
            return None
        owner = getattr(self.reviewer, "revision_reviewer", None)
        if owner is None:
            raise ValueError("reward revision requires its installed native coverage owner")
        locked = await owner.locked(old.activation)
        if not suspension:
            if locked:
                return None
            control = await self.reviewer.provider.collect_control(reader.series.control_hotkey)
            return "suspend_activation", old.activation, None, control.snapshot.block_number
        if locked:
            control = await self.reviewer.provider.collect_control(reader.series.control_hotkey)
            return "resume_activation", old.activation, None, control.snapshot.block_number
        if latest is None or digest(latest.adoption) == old.activation.reward_adoption_sha256:
            raise ValueError("suspended revision lost its selected successor adoption")
        if self._revision_target is None:
            control = await self.reviewer.provider.collect_control(reader.series.control_hotkey)
            self._revision_target = await owner.target(prefix[-1].decision, control)
        height = self._revision_target
        try:
            history = await self.reviewer.history.verified_prefix(height)
        except ValueError:
            progress = await self.reviewer.history.advance(
                self.reviewer.provider,
                through_block=height,
                maximum_blocks=self.reviewer.maximum_history_blocks,
            )
            if progress.history is None:
                raise RewardRevisionPending("reward revision history is catching up") from None
            history = progress.history
        control = await self.reviewer.history.review_control(self.reviewer.provider, height)
        try:
            clearance = await owner.review(prefix=prefix, control=control, history=history)
        except RewardEconomicsLocked:
            self._revision_target = None
            return "resume_activation", old.activation, None, height
        activation = old.activation.model_copy(
            update={
                "reward_adoption_sha256": digest(latest.adoption),
                "effective_allocation_sha256": latest.adoption.effective_allocation_sha256,
            }
        )
        return "revise_activation", activation, digest(clearance.clearance), height

    async def step(self) -> RewardCoordinationProgress:
        async with self.serial:
            self.publisher._writer()
            return await await_owned_task(asyncio.create_task(self._step()))

    async def _step(self) -> RewardCoordinationProgress:
        p = self.publisher
        self.phase = "load_prefix"
        prefix = await run_owned_thread(self._prefix)
        sequence = self.sequence = len(prefix)
        if prefix:
            self.phase = "deliver_inputs"
            await self.signer.publish(sequence - 1, p.files, p.files.package)
            self.phase = "readback_inputs"
            try:
                await run_memory_thread(self._readback, prefix)
            except FileNotFoundError:
                return RewardCoordinationProgress(
                    "delivery_pending", sequence - 1, digest(prefix[-1].decision)
                )
            self.phase = "publish_control"
            effect = await p.step(prefix)
            if effect.status != "control_finalized":
                return RewardCoordinationProgress(
                    effect.status, sequence - 1, effect.decision_sha256
                )
            if prefix[-1].decision.kind == "revoke":
                return RewardCoordinationProgress("revoked", sequence - 1, effect.decision_sha256)
        self.phase = "select_decision"
        body = await run_owned_thread(self._pending, sequence)
        boundary, committed, admission_adoption_sha = initial_reward_boundary(
            p.series, p.reader.reward_adoptions
        )
        predecessor = boundary if not prefix else digest(prefix[-1].decision)
        candidate = self._unreviewed
        if body is None and candidate is not None:
            if candidate.sequence == sequence and candidate.predecessor_sha256 == predecessor:
                body = candidate
            else:
                self._unreviewed = None
        if body is None:
            activation = None
            try:
                revision = await self._revision_proposal(prefix)
            except RewardRevisionPending:
                return RewardCoordinationProgress("revision_review_pending", sequence)
            activated = sum(v.decision.kind == "activate" for v in prefix)
            if revision is None and activated == len(p.series.cohorts):
                return RewardCoordinationProgress(
                    "series_control_published", sequence - 1, digest(prefix[-1].decision)
                )
            if sequence and revision is None:
                cohort = digest(p.series.cohorts[activated])
                activation = await run_memory_thread(self.offers, cohort, prefix)
                if activation is None:
                    return RewardCoordinationProgress("allocation_pending", sequence)
                activation = RewardActivation.model_validate_json(canonical_json_bytes(activation))
                if activation.cohort_sha256 != cohort:
                    raise ValueError("reward offer skips the next admitted cohort")
            if revision is None:
                observation = await p.provider.collect_control(p.hotkey)
                kind = "admit_series" if sequence == 0 else "activate"
                height, clearance = observation.snapshot.block_number, None
            else:
                kind, activation, clearance, height = revision
            body = RewardControlDecision(
                schema=(
                    "umi-reward-control-decision/4"
                    if sequence == 0 and admission_adoption_sha is not None
                    else "umi-reward-control-decision/3"
                    if revision is not None
                    or (activation is not None and activation.reward_adoption_sha256 is not None)
                    else "umi-reward-control-decision/1"
                    if p.series.predecessor is None
                    else "umi-reward-control-decision/2"
                ),
                series_sha256=digest(p.series),
                sequence=sequence,
                predecessor_sha256=predecessor,
                kind=kind,
                observed_at_block=height,
                activation=activation,
                revision_clearance_sha256=clearance,
                admission_adoption_sha256=admission_adoption_sha if sequence == 0 else None,
                admission_predecessor_committed_at_block=committed
                if sequence == 0 and admission_adoption_sha is not None
                else None,
            )
            # Bounded history recovery must finish a fixed target even if the
            # chain grows faster than a slow host can replay it. This is only
            # an in-process candidate; it grants no durable signing reservation.
            self._unreviewed = body
        review = self._reviewed
        if review is None or review.intent.decision != body or review.preceding != prefix:
            self.phase = "native_review"
            logger.info(
                "reward_review_started sequence=%d decision_sha256=%s", sequence, digest(body)
            )
            try:
                review = await self.reviewer.review(body, prefix)
            except RewardReviewPending:
                return RewardCoordinationProgress("review_pending", sequence, digest(body))
            except (ValueError, KeyError):
                # Invalid input must not pin a sequence before native review.
                self._unreviewed = None
                raise
            # Immutable original evidence can be reused while waiting for votes.
            # A process restart reconstructs it through the native archives.
            self._reviewed = review
        self._unreviewed = None
        self._revision_target = None
        # Only a successfully reviewed body becomes an immutable intent.
        # Bad offers cannot pin this sequence, and no signature precedes retention.
        self.phase = "sign_decision"
        await self.signer.attest(review)
        self.phase = "collect_quorum"
        for voter in (None, *self.voters):
            if voter is not None:
                try:
                    vote = await wait_for_owned(voter(body, prefix), timeout=self.vote_timeout)
                    await self.signer.collect(sequence, vote)
                except Exception as error:
                    logger.warning("reward_vote_retry reason=%s", type(error).__name__)
                    continue
            try:
                await self.signer.certify(sequence)
                break
            except RewardQuorumPending:
                continue
        else:
            return RewardCoordinationProgress("quorum_pending", sequence, digest(body))
        self.phase = "deliver_inputs"
        await self.signer.publish(sequence, p.files, p.files.package)
        return RewardCoordinationProgress("certified_delivery_pending", sequence, digest(body))

    async def run(self, stop: asyncio.Event, *, poll_seconds: float = 12) -> None:
        if not math.isfinite(poll_seconds) or not 0 < poll_seconds <= 3600:
            raise ValueError("reward coordinator poll interval is invalid")
        with self.publisher.hold_writer():
            while not stop.is_set():
                self.publisher.provider.ensure_observer_running()
                try:
                    result = await self.step()
                    logger.info(
                        canonical_json_bytes(
                            {
                                "status": result.status,
                                "sequence": result.sequence,
                                "decision_sha256": result.decision_sha256,
                            }
                        ).decode()
                    )
                except HistoricalHeaderRecoveryProgress:
                    logger.info(
                        "reward_coordinator_header_progress phase=%s sequence=%d",
                        self.phase,
                        self.sequence,
                    )
                    # The bounded pass retained progress. Yield to other tasks,
                    # then resume its fixed target without a failure backoff.
                    await asyncio.sleep(0)
                    continue
                except Exception as error:
                    logger.warning(
                        "reward_coordinator_retry phase=%s sequence=%d reason=%s details=%s",
                        self.phase,
                        self.sequence,
                        type(error).__name__,
                        canonical_json_bytes(_failure_details(error)).decode(),
                    )
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=poll_seconds)
