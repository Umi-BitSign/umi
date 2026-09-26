"""Replay the full accepted roster before considering cohort settlement.

Original intake records and decision inputs come from the caller's retained
evidence sources. No missing member is inferred to be a zero or a void. This
consumer does not select retries, close scheduler obligations or grant rewards.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_coordinator import CohortDecisionInput, replay_cohort_decisions
from .competition_cohort_disposition import (
    RecoverableOrderedOutcome,
    RecoverableOutcomeDecision,
    RecoverableReviewContext,
    replay_recoverable_ordered_outcome,
)
from .competition_cohort_evaluation import (
    RecoverableEvaluationRound,
    verify_recoverable_round_participant,
)
from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_intake_records import (
    RetainedCohortParticipation,
    read_participation,
    replay_participation,
)
from .competition_cohort_intake_seal import (
    CohortIntakeSeal,
    build_intake_seal,
    verify_intake_closure,
)
from .competition_cohort_participation import AttestedCohortParticipantAdmission
from .open_competition import CompetitionPolicy, EvaluationSuite, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class IncompleteRecoverableCohort(ValueError):
    """Accepted members still lack an outcome; retain their pending work."""

    def __init__(self, missing_submissions: tuple[str, ...]):
        self.missing_submissions = missing_submissions
        super().__init__(
            f"recoverable cohort still has {len(missing_submissions)} pending outcomes"
        )


class RecoverableRosterParticipant(StrictProtocolModel):
    record: RetainedCohortParticipation
    admission: AttestedCohortParticipantAdmission


class RecoverableRosterEvidence(StrictProtocolModel):
    schema_: Literal["umi-recoverable-roster-evidence/1"] = Field(alias="schema")
    round: RecoverableEvaluationRound
    intake_seal: CohortIntakeSeal
    participants: Annotated[
        tuple[RecoverableRosterParticipant, ...], Field(min_length=1, max_length=512)
    ]
    chain_submission_authorized: Literal[False] = False


def verify_recoverable_roster(
    roster: RecoverableRosterEvidence,
    policy: CompetitionPolicy,
    suite: EvaluationSuite,
    history: CohortRecoveryHistory,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> dict[str, RecoverableReviewContext]:
    """Authenticate exact intake membership, preparation and every admission.

    Sources may stream arbitrarily old retained records. Their absence or an
    I/O failure prevents review; it never supplies a smaller replacement roster.
    Native proof authenticity and complete ingress retention remain owner duties.
    """
    roster = RecoverableRosterEvidence.model_validate_json(canonical_json_bytes(roster))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    if view.state.phase == "revoked":
        raise ValueError("cohort recovery has been revoked")
    decisions: dict[str, CohortDecisionInput] = {}

    def decision(key: str) -> CohortDecisionInput:
        if key not in decisions:
            item = CohortDecisionInput.model_validate_json(
                canonical_json_bytes(decision_source(key))
            )
            if digest(item) != key:
                raise ValueError("retained cohort decision differs from its requested identity")
            decisions[key] = item
        return decisions[key]

    # Replays outage compensation as well as signatures. A signed closure alone
    # does not establish that the original participant window was satisfied.
    state, _, _ = replay_cohort_decisions(history, policy, decision)
    if state != view.state:
        raise ValueError("cohort decision replay differs from the selected history")
    intake = view.closure("intake")
    preparation = view.closure("preparation")
    index = next(i for i, s in enumerate(history.transitions) if s.transition == intake)
    prefix = history.model_copy(update={"transitions": history.transitions[:index]})
    seal = roster.intake_seal
    expected = build_intake_seal(
        prefix,
        policy,
        seal.observation,
        seal.snapshot,
        intake_records,
        expected_tip_sha256=intake.predecessor_sha256,
    )
    if seal != expected:
        raise ValueError("recoverable roster seal differs from the complete original intake")
    verify_intake_closure(seal, intake, decision(intake.evidence_sha256), policy)
    if (
        decision(preparation.evidence_sha256).progress.progress.phase_result_sha256
        != digest(roster.round)
        or roster.round.suite_sha256 != digest(suite)
        or suite.policy_sha256 != digest(policy)
    ):
        raise ValueError("recoverable round differs from certified preparation or suite")
    selected = {s.submission_sha256: s for s in seal.selected}
    members = tuple(
        digest(p.record.request.signed_submission.submission) for p in roster.participants
    )
    if members != tuple(sorted(selected)):
        raise ValueError("recoverable participants do not cover exactly the sealed intake")
    if members != tuple(p.submission_sha256 for p in roster.round.participants):
        raise ValueError("recoverable round omits or adds sealed participants")
    contexts = {}
    for key, participant in zip(members, roster.participants, strict=True):
        record = read_participation(canonical_json_bytes(participant.record))
        admitted = replay_participation(record, history, policy)
        selection = selected[key]
        if (
            digest(record) != selection.record_sha256
            or admitted.consent_sha256 != selection.consent_sha256
            or admitted != participant.admission.admission
        ):
            raise ValueError("selected participant differs from the retained admission")
        context = RecoverableReviewContext(
            policy=policy,
            suite=suite,
            consent=record.request.consent,
            admission=participant.admission,
            admission_snapshot=record.snapshot,
            history=history,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        verify_recoverable_round_participant(
            record.request.signed_submission,
            roster.round,
            policy,
            context.consent,
            context.admission,
            context.admission_snapshot,
            history,
            expected_tip_sha256=expected_tip_sha256,
            current_block=current_block,
        )
        contexts[key] = context
    return contexts


def replay_recoverable_roster_outcomes(
    roster: RecoverableRosterEvidence,
    outcomes: Iterable[RecoverableOrderedOutcome],
    policy: CompetitionPolicy,
    suite: EvaluationSuite,
    history: CohortRecoveryHistory,
    *,
    decision_source: Callable[[str], CohortDecisionInput],
    intake_records: Iterable[tuple[str, bytes]],
    expected_tip_sha256: str,
    current_block: int,
) -> tuple[RecoverableOutcomeDecision, ...]:
    """Review exactly one complete ordered outcome for each selected participant.

    The owning scheduler must still prove selected orders and retry history before
    using these benchmark decisions in a settlement. They are not service credit.
    """
    contexts = verify_recoverable_roster(
        roster,
        policy,
        suite,
        history,
        decision_source=decision_source,
        intake_records=intake_records,
        expected_tip_sha256=expected_tip_sha256,
        current_block=current_block,
    )
    reviewed = {}
    for outcome in outcomes:
        key = digest(outcome.order.order.submission.submission)
        if key not in contexts or key in reviewed:
            raise ValueError("unexpected or duplicate recoverable participant outcome")
        if outcome.order.order.round != roster.round:
            raise ValueError("outcome belongs to another prepared round")
        reviewed[key] = replay_recoverable_ordered_outcome(outcome, contexts[key])
    missing = tuple(sorted(contexts.keys() - reviewed.keys()))
    if missing:
        raise IncompleteRecoverableCohort(missing)
    return tuple(reviewed[key] for key in sorted(reviewed))
