"""Aggregate exact retained observations selected by certified request closure.

Endpoint content and measured local execution remain distinct. A benchmark
score supplies no paid work entitlement, promotion or chain authority.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from fractions import Fraction
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_coordinator import CohortDecisionInput
from .competition_cohort_endpoint_archive import (
    EndpointObjectSource,
    EndpointReplayArchive,
    read_endpoint_object,
)
from .competition_cohort_endpoint_quality import replay_endpoint_archive_quality
from .competition_cohort_execution import replay_execution_steps
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_request_closure import (
    CohortRequestClosure,
    verify_certified_request_closure,
)
from .competition_cohort_request_terminal import RequestExecutionArchive, SignedRequestTerminal
from .competition_cohort_roster import RecoverableRosterEvidence
from .competition_cohort_service_closure import (
    CohortServiceRequestClosure,
    verify_certified_service_request_closure,
)
from .competition_cohort_service_seal import ServiceWorkSeal
from .competition_cohort_service_work import SignedServiceWorkCatalog
from .competition_endpoint_execution import RetainedRevealPulse
from .competition_execution import ExecutionStep
from .open_competition import (
    CaseOutput,
    CompetitionPolicy,
    EvaluationSuite,
    Hotkey,
    Stratum,
    Track,
    aggregate_quality,
    digest,
    quality_from_hypotheses,
    validate_suite_profile,
)
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

QualityReason = Literal["infrastructure_failure", "incumbent_failure", "observation_disagreement"]


class ExactQuality(StrictProtocolModel):
    numerator: Annotated[str, Field(pattern=r"^[0-9]+$", max_length=4096)]
    denominator: Annotated[str, Field(pattern=r"^[1-9][0-9]*$", max_length=4096)]


class StratumQuality(StrictProtocolModel):
    stratum: Stratum
    quality: ExactQuality


class QualityTotals(StrictProtocolModel):
    strata: Annotated[tuple[StratumQuality, ...], Field(min_length=1, max_length=3)]
    aggregate: ExactQuality


class ClosedEvaluatorQuality(StrictProtocolModel):
    evaluator_hotkey: Hotkey
    terminal_sha256: Hex32
    candidate_observations_sha256: Hex32
    incumbent_observations_sha256: Hex32
    candidate_basis: Literal["endpoint_content_only", "measured_model_execution"]
    reason: Literal["infrastructure_failure", "incumbent_failure"] | None
    candidate: QualityTotals | None
    incumbent: QualityTotals | None


class ClosedParticipantQuality(StrictProtocolModel):
    schema_: Literal["umi-cohort-closed-quality/1"] = Field(alias="schema")
    policy_sha256: Hex32
    round_sha256: Hex32
    suite_sha256: Hex32
    request_closure_sha256: Hex32
    submission_sha256: Hex32
    order_sha256: Hex32
    hotkey: Hotkey
    track: Track
    runs: Annotated[tuple[ClosedEvaluatorQuality, ...], Field(min_length=1, max_length=64)]
    reason: QualityReason | None
    candidate: QualityTotals | None
    incumbent: QualityTotals | None
    service_credit_authorized: Literal[False] = False
    promotion_authorized: Literal[False] = False
    chain_submission_authorized: Literal[False] = False


@dataclass(frozen=True)
class QualityObservation:
    case_id: str
    status: str
    hypothesis: str
    # None means endpoint content only; it must never be cast to elapsed_ms=0.
    resource_eligible: bool | None


def measured_observation(output: CaseOutput, policy: CompetitionPolicy) -> QualityObservation:
    return QualityObservation(
        output.case_id,
        output.status,
        output.hypothesis,
        output.status == "ok"
        and output.elapsed_ms <= policy.maximum_inference_ms
        and len(output.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes,
    )


def observations_sha256(observations: tuple[QualityObservation, ...]) -> str:
    return digest(
        {
            "schema": "umi-cohort-quality-observations/1",
            "cases": [
                {
                    "case_id": o.case_id,
                    "status": o.status,
                    "hypothesis": o.hypothesis,
                    "resource_eligible": o.resource_eligible,
                }
                for o in observations
            ],
        }
    )


def exact_quality(value: Fraction) -> ExactQuality:
    if not 0 <= value <= 1:
        raise ValueError("quality lies outside the normalized interval")
    return ExactQuality(numerator=str(value.numerator), denominator=str(value.denominator))


def quality_totals(
    observations: tuple[QualityObservation, ...],
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    incumbent: bool = False,
) -> QualityTotals:
    if any(o.status == "infrastructure_failure" for o in observations):
        raise ValueError("infrastructure observations have no quality total")
    hypotheses = tuple(
        (
            o.case_id,
            o.hypothesis if o.status == "ok" and o.resource_eligible is not False else None,
        )
        for o in observations
    )
    values = quality_from_hypotheses(hypotheses, suite, policy, incumbent=incumbent)
    return QualityTotals(
        strata=tuple(
            StratumQuality(stratum=k, quality=exact_quality(values[k])) for k in sorted(values)
        ),
        aggregate=exact_quality(aggregate_quality(values, policy)),
    )


class ClosedQualityReview:
    """One authenticated immutable closure, replayed once for a batch of outcomes.

    Construct from owned current authority and independently authenticated proof
    sources. This container is not a transferable proof capability. Sources
    remain content-addressed; missing objects or reveal pulses interrupt review.
    """

    def __init__(
        self,
        closure: CohortRequestClosure | CohortServiceRequestClosure,
        roster: RecoverableRosterEvidence,
        objects: EndpointObjectSource,
        suite: EvaluationSuite,
        policy: CompetitionPolicy,
        history: CohortRecoveryHistory,
        *,
        decision_source: Callable[[str], CohortDecisionInput],
        intake_records: Iterable[tuple[str, bytes]],
        pulses: Callable[[int], RetainedRevealPulse],
        expected_tip_sha256: str,
        current_block: int,
        transport: ScoringPolicy | None = None,
        expected_catalogs: tuple[SignedServiceWorkCatalog, ...] = (),
        expected_seals: tuple[ServiceWorkSeal, ...] = (),
    ):
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
        self.roster = RecoverableRosterEvidence.model_validate_json(canonical_json_bytes(roster))
        self.history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
        if isinstance(closure, CohortServiceRequestClosure):
            if transport is None or not expected_catalogs or not expected_seals:
                raise ValueError("combined quality review requires selected service sources")
            verified = verify_certified_service_request_closure(
                closure,
                self.roster,
                objects,
                self.policy,
                self.history,
                transport,
                expected_catalogs=expected_catalogs,
                expected_seals=expected_seals,
                decision_source=decision_source,
                intake_records=intake_records,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
            self.closure = CohortRequestClosure.model_validate_json(
                read_endpoint_object(objects, verified.benchmark_closure_sha256)
            )
        else:
            verified = self.closure = verify_certified_request_closure(
                closure,
                self.roster,
                objects,
                self.policy,
                self.history,
                decision_source=decision_source,
                intake_records=intake_records,
                expected_tip_sha256=expected_tip_sha256,
                current_block=current_block,
            )
        # For version 2 the benchmark is a subset of the certified closure.
        # Votes bind the complete service-plus-benchmark decision, not its subset.
        self.request_closure_sha256 = digest(verified)
        validate_suite_profile(self.suite, self.policy)
        if self.roster.round.suite_sha256 != digest(
            self.suite
        ) or self.suite.policy_sha256 != digest(self.policy):
            raise ValueError("quality suite differs from the prepared cohort")
        view = verify_cohort_history(
            self.history,
            self.policy,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        self.opened_at = view.closure("preparation").observed_at_block
        self.closed_at = view.closure("requests").observed_at_block
        if not self.closed_at < view.closure("reference_reveal").observed_at_block <= current_block:
            raise ValueError("quality review requires certified reference reveal")
        self.objects, self.pulses = objects, pulses
        self.expected_tip_sha256, self.current_block = expected_tip_sha256, current_block
        self._outcomes: dict[str, ClosedParticipantQuality] = {}

    def outcome(self, submission_sha256: str) -> ClosedParticipantQuality:
        if submission_sha256 in self._outcomes:
            return self._outcomes[submission_sha256]
        member = next(
            (p for p in self.closure.participants if p.submission_sha256 == submission_sha256), None
        )
        if member is None:
            raise ValueError("quality review requested an unselected participant")
        runs = []
        submission = None
        for ref in member.evaluators:
            signed = SignedRequestTerminal.model_validate_json(
                read_endpoint_object(self.objects, ref.terminal_sha256)
            )
            terminal = signed.terminal
            assignment = CohortExecutionAssignment.model_validate_json(
                read_endpoint_object(self.objects, terminal.assignment_sha256)
            )
            order = assignment.certificate.order
            job = recoverable_order_job(order, ref.evaluator_hotkey)
            if [(c.case_id, c.video_sha256, c.stratum) for c in self.suite.cases] != [
                (c.case_id, c.video_sha256, c.stratum) for c in job.cases
            ]:
                raise ValueError("quality case catalog differs from the revealed suite")
            submission = order.submission.submission
            archive = RequestExecutionArchive.model_validate_json(
                read_endpoint_object(self.objects, terminal.execution_archive_sha256)
            )
            outputs = replay_execution_steps(
                job,
                (
                    ExecutionStep.model_validate_json(read_endpoint_object(self.objects, key))
                    for key in archive.steps
                ),
                self.policy,
                started_after=self.opened_at,
                finished_by=self.closed_at,
            )
            incumbent = tuple(measured_observation(o, self.policy) for o in outputs["incumbent"])
            if terminal.endpoint_archive_sha256 is None:
                basis = "measured_model_execution"
                candidate = tuple(
                    measured_observation(o, self.policy) for o in outputs["candidate"]
                )
            else:
                basis = "endpoint_content_only"
                endpoint = EndpointReplayArchive.model_validate_json(
                    read_endpoint_object(self.objects, terminal.endpoint_archive_sha256)
                )
                quality = replay_endpoint_archive_quality(
                    endpoint,
                    self.objects,
                    self.suite,
                    self.policy,
                    self.history,
                    pulses=self.pulses,
                    expected_tip_sha256=self.expected_tip_sha256,
                    current_block=self.current_block,
                )
                candidate = tuple(
                    QualityObservation(c.case_id, c.status, c.hypothesis, None)
                    for c in quality.cases
                )
            reason = None
            if any(o.status == "infrastructure_failure" for o in (*candidate, *incumbent)):
                reason = "infrastructure_failure"
            elif any(o.resource_eligible is not True for o in incumbent):
                reason = "incumbent_failure"
            runs.append(
                ClosedEvaluatorQuality(
                    evaluator_hotkey=ref.evaluator_hotkey,
                    terminal_sha256=ref.terminal_sha256,
                    candidate_observations_sha256=observations_sha256(candidate),
                    incumbent_observations_sha256=observations_sha256(incumbent),
                    candidate_basis=basis,
                    reason=reason,
                    candidate=quality_totals(candidate, self.suite, self.policy)
                    if reason is None
                    else None,
                    incumbent=quality_totals(incumbent, self.suite, self.policy, incumbent=True)
                    if reason is None
                    else None,
                )
            )
        reason = next(
            (
                r
                for r in ("infrastructure_failure", "incumbent_failure")
                if any(run.reason == r for run in runs)
            ),
            None,
        )
        first = runs[0]
        if reason is None and any(
            (
                r.candidate_observations_sha256,
                r.incumbent_observations_sha256,
                r.candidate_basis,
                r.candidate,
                r.incumbent,
            )
            != (
                first.candidate_observations_sha256,
                first.incumbent_observations_sha256,
                first.candidate_basis,
                first.candidate,
                first.incumbent,
            )
            for r in runs[1:]
        ):
            reason = "observation_disagreement"
        result = ClosedParticipantQuality(
            schema="umi-cohort-closed-quality/1",
            policy_sha256=digest(self.policy),
            round_sha256=digest(self.roster.round),
            suite_sha256=digest(self.suite),
            request_closure_sha256=self.request_closure_sha256,
            submission_sha256=submission_sha256,
            order_sha256=member.order_sha256,
            hotkey=submission.hotkey,
            track=submission.track,
            runs=tuple(runs),
            reason=reason,
            candidate=first.candidate if reason is None else None,
            incumbent=first.incumbent if reason is None else None,
        )
        self._outcomes[submission_sha256] = result
        return result
