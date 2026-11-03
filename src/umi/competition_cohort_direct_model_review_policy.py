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


class ModelReviewPolicyHistoryEntry(StrictProtocolModel):
    """Retain the authority that authenticated an earlier review selector."""

    authority: SignedCohortRecoveryAuthority
    continuation: DirectModelReviewPolicyContinuation


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


def model_review_policy_history(entries, current, *, policy, series):
    """Authenticate rendering identities without relaxing current rights checks."""
    if not entries:
        return {}, ()
    policies, selected, first = {}, None, None
    for entry in entries:
        historical = current.model_copy(
            update={
                "training_rights_policy_sha256": (
                    entry.continuation.license_adoption.adoption.training_rights_policy_sha256
                )
            }
        )
        predecessor, adoption = _verified_continuation(
            canonical_json_bytes(entry.continuation),
            canonical_json_bytes(historical),
            canonical_json_bytes(policy),
            canonical_json_bytes(entry.authority),
        )
        for value in (historical, predecessor):
            policies[digest(value)] = value
        if first is None or adoption.issued_at_block < first[0]:
            first = adoption.issued_at_block, predecessor
        if historical == current and entry.authority == series.recovery:
            if selected is not None and selected != entry.continuation:
                raise ValueError("review policy history has conflicting current selectors")
            selected = entry.continuation
    if selected is None:
        raise ValueError("review policy history lacks the current authenticated selector")
    effective = {}
    for plan in series.cohorts:
        effective[digest(plan)], _ = direct_model_review_policies(
            selected, current, policy=policy, authority=series.recovery, plan=plan
        )
        if plan.sequence < selected.license_adoption.adoption.first_cohort_sequence:
            effective[digest(plan)] = first[1]
    return effective, tuple(policies.values())


def retained_review_inputs(inputs, acceptance, policies):
    """Reproduce the original proposal after its current rights review passes.

    Only the authenticated historical policy identity changes in the rendered
    metadata. Original documents, decisions and manifest stay exact. Both
    acceptance digests must match; no historical identity grants NC consent.
    """

    def matches(value):
        return (
            value.model_sha256 == acceptance.model_sha256
            and digest(value.rights_evidence) == acceptance.rights_evidence_sha256
            and digest(value.reconstruction_evidence) == acceptance.reconstruction_evidence_sha256
        )

    if matches(inputs):
        return inputs
    if not policies:
        return inputs
    original_policy = inputs.rights_evidence["decision"]["review_policy_sha256"]
    for standing in policies:
        historical_policy = digest(standing)
        if historical_policy == original_policy:
            continue
        candidate = inputs.model_copy(
            update={
                "rights_evidence": dict(
                    inputs.rights_evidence,
                    decision=dict(
                        inputs.rights_evidence["decision"],
                        review_policy_sha256=historical_policy,
                    ),
                ),
                "reconstruction_evidence": dict(
                    inputs.reconstruction_evidence, review_policy_sha256=historical_policy
                ),
            }
        )
        if matches(candidate):
            return candidate
    raise ValueError("model proposal differs from its authenticated review policy history")
