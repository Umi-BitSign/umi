"""Resolve request cutoff policy from the original plan and signed history."""

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import (
    CohortRecoveryState,
    CohortRecoveryTransition,
    CohortRequestTailAdoption,
    RequestTailRule,
    cohort_request_tail_rule,
    propose_recovery_transition,
)
from .competition_execution import ExecutionBoundary
from .open_competition import CompetitionPolicy, digest
from .protocol import canonical_json_bytes


def _verified_state(
    history: CohortRecoveryHistory, policy: CompetitionPolicy
) -> CohortRecoveryState:
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    last = history.transitions[-1].transition if history.transitions else history.genesis
    return verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=digest(last),
        current_block=(last.observed_at_block if history.transitions else last.admitted_at_block),
    ).state


def authenticated_request_tail_rule(
    history: CohortRecoveryHistory, policy: CompetitionPolicy
) -> RequestTailRule:
    """Signatures authenticate this prefix; caller still owns current-tip selection."""
    state = _verified_state(history, policy)
    return state.request_tail_rule or cohort_request_tail_rule(history.plan)


def prepare_request_tail_adoption(
    history: CohortRecoveryHistory, policy: CompetitionPolicy, observation: ExecutionBoundary
) -> CohortRecoveryTransition:
    """Build unsigned exact bytes; caller must reserve and obtain the policy quorum.

    No wallet, storage or finality is opened here. The caller must supply its
    native verified observation and reconcile the current tip before reservation.
    Adoption is only supported before the original request opening exists.
    """
    state = _verified_state(history, policy)
    observation = ExecutionBoundary.model_validate_json(canonical_json_bytes(observation))
    adoption = CohortRequestTailAdoption(
        schema="umi-cohort-request-tail-adoption/1",
        original_plan=history.plan,
        rule="original_request_12h_with_completed_miner/1",
    )
    return propose_recovery_transition(
        state,
        history.authority.authority,
        operation="adopt_request_tail_rule",
        observed_at_block=observation.block,
        evidence_sha256=digest(adoption),
        request_tail_adoption=adoption,
    )
