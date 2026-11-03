"""Authenticated review changes preserve the original upload journal owner."""

from functools import lru_cache

from .competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    verify_standing_review_policy,
)
from .competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    verify_recovery_authority,
)
from .competition_model_license import verify_model_license_selection
from .competition_model_training_rights import validate_model_training_terms
from .open_competition import CompetitionPolicy, SignedModelLicenseTermsAdoption, digest
from .protocol import StrictProtocolModel, canonical_json_bytes


class DirectModelReviewPolicyContinuation(StrictProtocolModel):
    """Retain original ownership while selecting signed prospective rights."""

    predecessor: StandingModelReviewPolicy
    license_adoption: SignedModelLicenseTermsAdoption


@lru_cache(maxsize=32)
def _verified_continuation(raw, current_raw, policy_raw, authority_raw):
    continuation = DirectModelReviewPolicyContinuation.model_validate_json(raw)
    current = StandingModelReviewPolicy.model_validate_json(current_raw)
    policy = CompetitionPolicy.model_validate_json(policy_raw)
    signed_authority = SignedCohortRecoveryAuthority.model_validate_json(authority_raw)
    authority = verify_recovery_authority(signed_authority, policy)
    adoption = verify_model_license_selection(
        continuation.license_adoption, policy=policy, authority=authority
    )
    validate_model_training_terms(
        rights_policy_sha256=adoption.training_rights_policy_sha256,
        supplemental_terms_sha256=adoption.noncommercial_terms_sha256,
    )
    predecessor = continuation.predecessor
    verify_standing_review_policy(predecessor, policy)
    verify_standing_review_policy(current, policy)
    if (
        current.training_rights_policy_sha256 != adoption.training_rights_policy_sha256
        or predecessor.training_rights_policy_sha256 == current.training_rights_policy_sha256
        or canonical_json_bytes(
            current.model_copy(
                update={"training_rights_policy_sha256": predecessor.training_rights_policy_sha256}
            )
        )
        != canonical_json_bytes(predecessor)
    ):
        raise ValueError("direct review continuation changes more than its signed rights selection")
    return predecessor, adoption


def direct_model_review_policies(continuation, current, *, policy, authority, plan):
    """Return effective review and immutable journal policies for this cohort.

    Only the journal's original standing-policy field is preserved. The owner
    still binds every storage, provider, cohort and hotkey field exactly. Signed
    metadata authentication is reused across cohorts and repeated constructors;
    neither this selection nor its journal open reads model payloads.
    """
    predecessor, adoption = _verified_continuation(
        canonical_json_bytes(continuation),
        canonical_json_bytes(current),
        canonical_json_bytes(policy),
        canonical_json_bytes(authority),
    )
    # A series can retain C6 alongside C7+. Its completed reviews keep the
    # original semantics even when later cohorts select newer rights.
    if plan.sequence < adoption.first_cohort_sequence:
        return predecessor, predecessor
    if digest(plan) not in adoption.cohort_sha256s:
        raise ValueError("direct review continuation belongs to another cohort")
    return current, predecessor
