"""Recoverable native settlement from retained execution and evaluator votes.

The enclosing cohort service selects current history/finality and delivers
original votes. This owner derives phase results and the portable package; no
operator supplies completion flags, scores, allocations or an activation file.
Independent phase signers and current standing-control review remain required.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from .competition_cohort_coordinator import CohortPhaseProgress, replay_cohort_decisions
from .competition_cohort_endpoint_archive import EndpointObjectSource, JournalEndpointObjects
from .competition_cohort_history import RecoveryHistoryView, verify_cohort_history
from .competition_cohort_quality import ClosedQualityReview
from .competition_cohort_quality_signing import (
    SignedClosedQualityVote,
    build_quality_manifest,
    collect_quality_certificate,
)
from .competition_cohort_recovery import Phase, RecoverableCohortPlan, SignedCohortRecoveryAuthority
from .competition_cohort_reward_allocation import retain_reward_allocation
from .competition_cohort_reward_certification import reward_certification_progress
from .competition_cohort_reward_package import (
    DEFAULT_PACKAGE_BYTES,
    CohortRewardPackage,
    DecisionSource,
    PulseSource,
    RewardReplayInputs,
    prepare_reward_package,
    publish_reward_package,
)
from .competition_cohort_service_certification import (
    ServiceAllocationReview,
    ServiceAllocationVote,
    collect_service_allocation,
)
from .competition_reward_manifest import RewardReplayRequirement
from .competition_round_journal import RoundJournal
from .competition_store import CompetitionStore
from .open_competition import CompetitionPolicy, digest
from .private_files import private_path
from .protocol import StrictProtocolModel, canonical_json_bytes


@dataclass(frozen=True)
class NativeSettlementResult:
    """Local progress only; neither a certificate nor chain permission."""

    status: str
    progress: CohortPhaseProgress | None = None
    package: CohortRewardPackage | None = None


class CohortSettlement:
    """One service-owned cohort, retried from immutable journals after a restart.

    Call under the enclosing service's sole-writer lock. Sources must retain
    their original objects independently of this journal and output directory.
    Missing votes return pending; missing/corrupt evidence raises and must retry
    without treating unavailable evidence as a miner failure.
    """

    def __init__(
        self,
        *,
        plan: RecoverableCohortPlan,
        authority: SignedCohortRecoveryAuthority,
        requirement: RewardReplayRequirement,
        policy: CompetitionPolicy,
        journal: RoundJournal,
        promotion_store: CompetitionStore,
        objects: EndpointObjectSource,
        decisions: DecisionSource,
        pulses: PulseSource,
        output_directory: Path,
        maximum_promotion_bytes: int,
        maximum_package_bytes: int = DEFAULT_PACKAGE_BYTES,
    ):
        self.plan = RecoverableCohortPlan.model_validate_json(canonical_json_bytes(plan))
        self.authority = SignedCohortRecoveryAuthority.model_validate_json(
            canonical_json_bytes(authority)
        )
        self.requirement = RewardReplayRequirement.model_validate_json(
            canonical_json_bytes(requirement)
        )
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if (
            requirement.cohort_sha256 != digest(self.plan)
            or self.plan.policy_sha256 != digest(self.policy)
            or digest(promotion_store.policy) != digest(self.policy)
        ):
            raise ValueError("settlement owner differs from its approved cohort")
        self.journal, self.promotion_store = journal, promotion_store
        self.archive, self.external = JournalEndpointObjects(journal), objects
        self.decisions, self.pulses = decisions, pulses
        self.output = Path(private_path(str(output_directory))) / (digest(self.plan) + ".json")
        self.promotion_bytes, self.package_bytes = maximum_promotion_bytes, maximum_package_bytes

    def _object(self, key: str) -> bytes:
        try:
            return self.archive(key)
        except FileNotFoundError:
            return self.external(key)

    def _closed(self, view: RecoveryHistoryView, phase: Phase, result: StrictProtocolModel) -> None:
        closed = view.closure(phase)
        progress = self.decisions(closed.evidence_sha256).progress.progress
        if progress.phase_result_sha256 != digest(result) or progress.evidence_sha256 != digest(
            result
        ):
            raise ValueError("settlement result differs from its certified phase")

    def advance(
        self,
        inputs: RewardReplayInputs,
        intake_records: Iterable[tuple[str, bytes]],
        *,
        expected_tip_sha256: str,
        current_block: int,
        quality_votes: Iterable[SignedClosedQualityVote] = (),
        service_votes: Iterable[ServiceAllocationVote] = (),
    ) -> NativeSettlementResult:
        inputs = RewardReplayInputs.model_validate_json(canonical_json_bytes(inputs))
        history, requirement = inputs.history, self.requirement
        if (
            history.plan != self.plan
            or history.authority != self.authority
            or digest(inputs.terms) != requirement.terms_sha256
            or tuple(digest(c.catalog) for c in inputs.catalogs) != requirement.catalog_sha256s
        ):
            raise ValueError("settlement evidence differs from approved inputs")
        view = verify_cohort_history(
            history,
            self.policy,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        replay_cohort_decisions(history, self.policy, self.decisions)
        phase = view.state.phase
        if phase not in {"evidence", "review", "certification", "first_admission", "complete"}:
            raise ValueError("settlement requires an active cohort after reference reveal")
        records = tuple(intake_records)
        common = dict(
            expected_catalogs=inputs.catalogs,
            expected_seals=inputs.seals,
            decision_source=self.decisions,
            pulses=self.pulses,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        benchmark_review = ClosedQualityReview(
            inputs.closure,
            inputs.roster,
            self._object,
            inputs.suite,
            self.policy,
            history,
            transport=inputs.transport,
            intake_records=iter(records),
            **common,
        )
        by_submission = {p.submission_sha256: [] for p in benchmark_review.closure.participants}
        for count, supplied in enumerate(quality_votes, 1):
            if count > len(by_submission) * len(self.policy.evaluators):
                raise ValueError("quality vote batch exceeds the cohort's evaluator slots")
            vote = SignedClosedQualityVote.model_validate_json(canonical_json_bytes(supplied))
            if vote.result.submission_sha256 not in by_submission:
                raise ValueError("quality vote belongs to another cohort participant")
            by_submission[vote.result.submission_sha256].append(vote)
        certificates = {
            key: collect_quality_certificate(self.journal, benchmark_review, key, votes)
            for key, votes in by_submission.items()
        }
        if any(c is None for c in certificates.values()):
            return NativeSettlementResult("waiting_quality_votes")
        benchmark = build_quality_manifest(benchmark_review, certificates.get)
        self.archive.put(benchmark)
        if phase == "evidence":
            return self._progress(view, current_block, benchmark)
        self._closed(view, "evidence", benchmark)

        service_review = ServiceAllocationReview(
            inputs.closure,
            inputs.roster,
            self._object,
            self.policy,
            history,
            inputs.transport,
            inputs.terms,
            inputs.reveal,
            expected_terms_sha256=requirement.terms_sha256,
            intake_records=iter(records),
            **common,
        )
        service = collect_service_allocation(self.journal, service_review, service_votes)
        if service is None:
            return NativeSettlementResult("waiting_service_votes")
        self.archive.put(service)
        if phase == "review":
            return self._progress(view, current_block, service)
        self._closed(view, "review", service)
        allocation = retain_reward_allocation(
            self.journal,
            self.promotion_store,
            service,
            service_review,
            benchmark,
            benchmark_review,
            maximum_promotion_bytes=self.promotion_bytes,
        )
        self.archive.put(allocation)
        if phase == "certification":
            progress = reward_certification_progress(
                self.journal,
                self.promotion_store,
                service,
                service_review,
                benchmark,
                benchmark_review,
                history,
                self.decisions,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
                maximum_promotion_bytes=self.promotion_bytes,
            )
            return NativeSettlementResult("phase_ready", progress=progress)
        self._closed(view, "certification", allocation)
        # Stable package bytes after late recovery or later phase advances.
        # Check current authority above, but package the first certified prefix.
        closed = view.closure("certification")
        end = next(i + 1 for i, t in enumerate(history.transitions) if t.transition == closed)
        prefix = history.model_copy(update={"transitions": history.transitions[:end]})
        package = prepare_reward_package(
            inputs.model_copy(update={"history": prefix}),
            allocation,
            service,
            benchmark,
            self.policy,
            self.promotion_store,
            self._object,
            self.decisions,
            iter(records),
            self.pulses,
            expected_tip_sha256=digest(closed),
            current_block=current_block,
            expected_terms_sha256=requirement.terms_sha256,
            expected_catalog_sha256s=requirement.catalog_sha256s,
            maximum_promotion_bytes=self.promotion_bytes,
            maximum_bytes=self.package_bytes,
        )
        publish_reward_package(self.output, package, maximum_bytes=self.package_bytes)
        return NativeSettlementResult("package_published", package=package)

    def _progress(
        self, view: RecoveryHistoryView, block: int, result: StrictProtocolModel
    ) -> NativeSettlementResult:
        return NativeSettlementResult(
            "phase_ready",
            progress=CohortPhaseProgress(
                schema="umi-cohort-phase-progress/1",
                cohort_sha256=digest(self.plan),
                recovery_tip_sha256=view.state.tip_sha256,
                phase=view.state.phase,
                observed_at_block=block,
                unavailable_blocks=0,
                completion="complete",
                phase_result_sha256=digest(result),
                evidence_sha256=digest(result),
            ),
        )
