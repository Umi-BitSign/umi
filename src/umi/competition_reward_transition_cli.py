"""Record an exact operator release without stopping the recurring owner."""

from .competition_reward_operator_signing import sign_operator_approval
from .competition_reward_timing import IMMEDIATE_ACTIVATION_RULE
from .competition_reward_transition_controls import (
    RewardTransitionApproval,
    RewardTransitionControlReader,
    approval_path,
    publish_reward_transition_approval,
)
from .open_competition import digest


def approve_successor(config, *, predecessor, cohort, package, reason):
    if config.role != "coordinator" or config.reward_transition is None:
        raise ValueError("successor approval requires a configured transition coordinator")
    if not reason.strip():
        raise ValueError("successor approval requires a nonempty operator reason")
    controls = RewardTransitionControlReader(
        config.reward_transition, series=config.series, policy=config.policy
    )
    # Do not create a request that appears to override Sam's explicit hold.
    if controls.held(cohort):
        raise ValueError("successor progression is explicitly held in admission or settlement")
    saved = controls.approval(cohort, predecessor, package)
    if saved is not None:
        # Existing approvals keep their original signed timing semantics. An
        # exact retry must not silently upgrade an already reserved release.
        if saved.approval.reason != reason:
            raise ValueError("successor approval already retains a different exact request")
        body = saved.approval
        path = approval_path(config.reward_transition, cohort, package)
    else:
        body = RewardTransitionApproval(
            schema="umi-reward-transition-approval/2",
            series_sha256=digest(config.series),
            predecessor_decision_sha256=predecessor,
            successor_cohort_sha256=cohort,
            successor_package_sha256=package,
            reason=reason,
            activation_rule=IMMEDIATE_ACTIVATION_RULE,
        )
        signed = sign_operator_approval(config, body)
        if controls.held(cohort):
            raise ValueError("successor progression became explicitly held during approval")
        path = publish_reward_transition_approval(
            config.reward_transition, signed, series=config.series
        )
    return {
        "status": "operator_approval_recorded",
        "series_sha256": digest(config.series),
        "cohort_sha256": cohort,
        "package_sha256": package,
        "predecessor_decision_sha256": predecessor,
        "approval_path": str(path),
        "chain_submission_authorized": False,
        "activation_rule": body.activation_rule,
        "next": "recurring_native_review_independent_quorum_and_signed_delivery",
    }
