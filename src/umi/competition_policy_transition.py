"""Pure validation and preparation for an explicit competition-policy transition."""

from __future__ import annotations

from .competition_client import AdmissionReceipt
from .competition_launch import PublicIntakeDeployment
from .open_competition import (
    BURN_POLICY_SCHEMA,
    DEPENDENCE_POLICY_SCHEMA,
    CompetitionPolicy,
    SignedSubmission,
    Submission,
    digest,
    validate_admission,
)
from .protocol import canonical_json_bytes

_TRANSITION_FIELDS = {
    "schema",
    "sequence",
    "predecessor_sha256",
    "contribution_terms_sha256",
    "minimum_continuous_observed_margin_bps",
    "continuous_dependence_lower_bound_floor_bps",
    "minimum_continuous_dependence_pairs",
    "continuous_dependence_duration_bins",
    "maximum_counterfactual_duration_delta_ms",
    "continuous_dependence_bootstrap_replicates",
    "continuous_dependence_confidence_bps",
    "positive_control_model_sha256",
    "minimum_positive_control_dependence_bps",
}


def _unchanged_policy_body(policy: CompetitionPolicy) -> dict:
    body = policy.model_dump(mode="json", by_alias=True)
    for field in _TRANSITION_FIELDS:
        body.pop(field, None)
    return body


def prepare_endpoint_policy_transition(
    *,
    prior_policy: CompetitionPolicy,
    successor_policy: CompetitionPolicy,
    prior_submission: SignedSubmission,
    prior_receipt: AdmissionReceipt,
    deployment: PublicIntakeDeployment,
    current_block: int,
) -> Submission:
    """Build the unsigned successor submission after checking retained v1 evidence.

    The old signed object and receipt remain unchanged. The caller must sign the
    returned object with the same registered hotkey and submit it to an intake
    that advertises the successor policy digest.
    """

    prior_policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(prior_policy))
    successor_policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(successor_policy))
    prior_submission = SignedSubmission.model_validate_json(canonical_json_bytes(prior_submission))
    prior_receipt = AdmissionReceipt.model_validate_json(canonical_json_bytes(prior_receipt))
    deployment = PublicIntakeDeployment.model_validate_json(canonical_json_bytes(deployment))
    if type(current_block) is not int:
        raise ValueError("current block must be an integer")

    prior_policy_sha256 = digest(prior_policy)
    successor_policy_sha256 = digest(successor_policy)
    if (
        prior_policy.schema_ != BURN_POLICY_SCHEMA
        or successor_policy.schema_ != DEPENDENCE_POLICY_SCHEMA
        or successor_policy.minimum_continuous_observed_margin_bps is None
        or successor_policy.continuous_dependence_lower_bound_floor_bps is None
        or successor_policy.minimum_continuous_dependence_pairs is None
        or successor_policy.continuous_dependence_duration_bins is None
        or successor_policy.maximum_counterfactual_duration_delta_ms is None
        or successor_policy.continuous_dependence_bootstrap_replicates is None
        or successor_policy.continuous_dependence_confidence_bps is None
        or successor_policy.positive_control_model_sha256 is None
        or successor_policy.minimum_positive_control_dependence_bps is None
        or successor_policy.sequence != prior_policy.sequence + 1
        or successor_policy.predecessor_sha256 != prior_policy_sha256
        or successor_policy.contribution_terms_sha256 == prior_policy.contribution_terms_sha256
        or _unchanged_policy_body(successor_policy) != _unchanged_policy_body(prior_policy)
    ):
        raise ValueError("successor changes more than sequence, predecessor, and terms")

    old = prior_submission.submission
    if old.track != "endpoint" or old.model_bundle is not None or old.endpoint_url is None:
        raise ValueError("only an accepted endpoint submission can use this transition")
    if (
        old.policy_sha256 != prior_policy_sha256
        or old.accepted_terms_sha256 != prior_policy.contribution_terms_sha256
        or prior_receipt.policy_sha256 != prior_policy_sha256
        or prior_receipt.submission_sha256 != digest(old)
        or prior_receipt.registration_snapshot_sha256 != digest(prior_receipt.registration_snapshot)
        or prior_receipt.registration_source != "verifier_attested_finality"
    ):
        raise ValueError("prior submission or receipt does not bind the predecessor policy")
    try:
        observed_uid = validate_admission(
            prior_submission,
            prior_policy,
            prior_receipt.registration_snapshot,
            prior_receipt.accepted_block,
        )
    except ValueError as error:
        raise ValueError("prior admission receipt cannot be replayed") from error
    if observed_uid != prior_receipt.observed_uid:
        raise ValueError("prior admission receipt names another UID")

    schedule = deployment.round_schedule
    if (
        deployment.repository != "https://github.com/Umi-BitSign/umi"
        or deployment.eligible_tracks != ("endpoint",)
        or old.valid_from_block < schedule.intake_opened_block
        or prior_receipt.accepted_block < schedule.intake_opened_block
        or prior_receipt.accepted_block > min(current_block, schedule.roster_close_latest_block)
        or old.valid_through_block < schedule.evaluation_close_block
    ):
        raise ValueError("predecessor admission is outside the endpoint launch")
    if not (
        schedule.intake_opened_block
        <= current_block
        <= schedule.roster_close_earliest_block
        < schedule.evaluation_close_block
    ):
        raise ValueError("successor acceptance is no longer guaranteed for this round")
    if not (
        successor_policy.valid_from_block
        <= current_block
        < schedule.evaluation_close_block
        <= successor_policy.valid_through_block
        and schedule.evaluation_close_block - current_block
        <= successor_policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("successor submission lifetime is outside the policy")

    return Submission(
        schema="umi-competition-submission/1",
        network=successor_policy.network,
        netuid=successor_policy.netuid,
        policy_sha256=successor_policy_sha256,
        hotkey=old.hotkey,
        track="endpoint",
        sequence=old.sequence + 1,
        valid_from_block=current_block,
        valid_through_block=schedule.evaluation_close_block,
        model_revision=old.model_revision,
        endpoint_url=old.endpoint_url,
        model_bundle=None,
        accepted_terms_sha256=successor_policy.contribution_terms_sha256,
    )


__all__ = ("prepare_endpoint_policy_transition",)
