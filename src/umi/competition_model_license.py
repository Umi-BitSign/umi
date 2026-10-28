"""Additive authenticated per-model contribution terms for C7 and successors.

The signed bundle retains its exact opt-in authorization through upload,
restoration, execution and replay. Original permissive manifests, policies and
consents are unchanged. A license declaration alone grants no new permission.
"""

from functools import lru_cache

from .competition_cohort_recovery import verify_recovery_authority, verify_recovery_quorum
from .open_competition import (
    CompetitionPolicy,
    ModelBundle,
    ModelLicenseTermsAdoption,
    SignedModelLicenseTermsAdoption,
    digest,
)
from .protocol import canonical_json_bytes


@lru_cache(maxsize=128)
def _verified_adoption(raw, raw_policy):
    """Reuse metadata-only authentication keyed by every signed input byte."""
    signed = SignedModelLicenseTermsAdoption.model_validate_json(raw)
    policy = CompetitionPolicy.model_validate_json(raw_policy)
    body = signed.adoption
    if (
        body.policy_sha256 != digest(policy)
        or body.original_terms_sha256 != policy.contribution_terms_sha256
    ):
        raise ValueError("model license adoption differs from its original signed policy")
    verify_recovery_quorum(body, signed.signatures, policy)
    return body


def verify_model_license_adoption(bundle, policy):
    """Authenticate the embedded opt-in without authorizing cohort admission."""
    bundle = ModelBundle.model_validate_json(canonical_json_bytes(bundle))
    if bundle.license_adoption is None:
        raise ValueError("model lacks its signed noncommercial license adoption")
    body = _verified_adoption(
        canonical_json_bytes(bundle.license_adoption), canonical_json_bytes(policy)
    )
    if bundle.license_id != body.license_id:
        raise ValueError("model license differs from its signed terms adoption")
    return body


def model_contribution_terms(bundle, policy):
    """Resolve terms for an exact artifact; this does not authorize new intake."""
    if bundle is None or bundle.license_adoption is None:
        return policy.contribution_terms_sha256
    return verify_model_license_adoption(bundle, policy).noncommercial_terms_sha256


def verify_cohort_model_terms(submission, consent, history, policy, *, current_block):
    """Require exact cohort authorization and fresh opt-in for an NC model.

    Callers separately authenticate the owned history and miner signature. This
    scope check is shared by admission, retained replay and signing preflight.
    """
    bundle = submission.model_bundle
    if submission.accepted_terms_sha256 != model_contribution_terms(bundle, policy):
        raise ValueError("submission has not accepted its exact model contribution terms")
    if bundle is None or bundle.license_adoption is None:
        return None
    body = verify_model_license_adoption(bundle, policy)
    authority, plan = history.authority.authority, history.plan
    if (
        submission.track != "model"
        or submission.policy_sha256 != digest(policy)
        or authority.policy_sha256 != digest(policy)
        or body.authority_sha256 != digest(authority)
        or body.cohort_sha256s != authority.cohort_sha256s
        or digest(plan) not in body.cohort_sha256s
        or plan.sequence < body.first_cohort_sequence
        or consent.cohort_sha256 != digest(plan)
        or consent.authority_sha256 != digest(authority)
        or consent.submission_sha256 != digest(submission)
        or not authority.issued_at_block
        <= body.issued_at_block
        <= consent.signed_at_block
        <= current_block
    ):
        raise ValueError("model license adoption lacks exact cohort scope or fresh miner consent")
    return body


def verify_model_license_selection(signed, *, policy, authority):
    """Check a published optional route before miners build their manifests."""
    body = _verified_adoption(canonical_json_bytes(signed), canonical_json_bytes(policy))
    if (
        body.authority_sha256 != digest(authority)
        or body.cohort_sha256s != authority.cohort_sha256s
        or authority.policy_sha256 != digest(policy)
        or body.issued_at_block < authority.issued_at_block
    ):
        raise ValueError("published model license adoption differs from configured authority")
    return body


def prepare_model_license_adoption(
    *,
    policy,
    authority,
    noncommercial_terms_sha256,
    training_rights_policy_sha256,
    operator_decision_sha256,
    issued_at_block,
    reason,
):
    """Build the same explicit C7+ opt-in for each new authenticated authority.

    This deterministic preparation does not sign, publish or enable a route.
    Future-cohort orchestration must collect its usual configured quorum before
    exposing the returned proposal as a signed selection.
    """
    verify_recovery_authority(authority, policy)
    original = authority.authority
    if issued_at_block < original.issued_at_block:
        raise ValueError("model license adoption predates its authority")
    return ModelLicenseTermsAdoption(
        schema="umi-model-license-terms-adoption/1",
        policy_sha256=digest(policy),
        authority_sha256=digest(original),
        cohort_sha256s=original.cohort_sha256s,
        first_cohort_sequence=7,
        original_terms_sha256=policy.contribution_terms_sha256,
        noncommercial_terms_sha256=noncommercial_terms_sha256,
        training_rights_policy_sha256=training_rights_policy_sha256,
        operator_decision_sha256=operator_decision_sha256,
        license_id="CC-BY-NC-SA-4.0",
        issued_at_block=issued_at_block,
        reason=reason,
    )
