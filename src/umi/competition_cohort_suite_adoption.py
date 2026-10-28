"""Authenticated pre-preparation suite selection under the original cohort.

The append-only amendment keeps the original plan, clocks and participant
admissions. Native owners still select current history/finality, reserve the
original predecessor and verify private suite/provenance delivery before signing.
A caller-supplied selection digest is never evidence of those native conditions.
"""

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_recovery import (
    CohortEvaluationSuiteAdoption,
    cohort_evaluation_suite,
    propose_recovery_transition,
)
from .open_competition import digest
from .protocol import canonical_json_bytes


def selected_evaluation_suite(plan, state) -> str:
    if state.cohort_sha256 != digest(plan):
        raise ValueError("evaluation suite state belongs to another original cohort")
    return cohort_evaluation_suite(plan, state.evaluation_suite_adoption)


def authenticated_evaluation_suite(
    history, policy, *, expected_tip_sha256: str, current_block: int
) -> str:
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    return selected_evaluation_suite(history.plan, view.state)


def prepare_evaluation_suite_adoption(
    history,
    policy,
    *,
    expected_tip_sha256: str,
    current_block: int,
    suite_sha256: str,
    selection_manifest_sha256: str,
):
    """Prepare exact unsigned bytes; no signer, RPC, payload read or owner write."""
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    view = verify_cohort_history(
        history, policy, expected_tip_sha256=expected_tip_sha256, current_block=current_block
    )
    adoption = CohortEvaluationSuiteAdoption(
        schema="umi-cohort-evaluation-suite-adoption/1",
        original_plan=history.plan,
        previous_suite_sha256=selected_evaluation_suite(history.plan, view.state),
        suite_sha256=suite_sha256,
        selection_manifest_sha256=selection_manifest_sha256,
    )
    return propose_recovery_transition(
        view.state,
        history.authority.authority,
        operation="adopt_evaluation_suite",
        observed_at_block=current_block,
        evidence_sha256=digest(adoption),
        evaluation_suite_adoption=adoption,
    )
