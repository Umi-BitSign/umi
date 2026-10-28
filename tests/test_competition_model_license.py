"""Conditional terms preserve old signatures and survive native intake replay."""

from unittest.mock import patch

import pytest

from umi import competition_model_license as licensing
from umi.competition_artifacts import preserve_bundle, verify_preserved_bundle
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipationConsent,
    SignedCohortParticipationConsent,
    admit_recovery_participant,
    verify_participant_admission,
)
from umi.competition_cohort_recovery import (
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.open_competition import (
    ModelBundle,
    SignedModelLicenseTermsAdoption,
    SignedSubmission,
    digest,
    model_content_digest,
    sign_object,
    validate_admission,
    validate_bundle_policy,
)
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_open_competition import bundle_at, snapshot, submission, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def nc_case(policy, recovery, tmp_path):
    plan, authority, _ = recovery
    plan = plan.model_copy(update={"sequence": 7})
    a = authority.authority.model_copy(update={"cohort_sha256s": (digest(plan),)})
    authority = SignedCohortRecoveryAuthority(authority=a, signatures=signatures(a))
    genesis, _ = admit_recoverable_cohort(plan, authority, policy, admitted_at_block=160)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    adoption = licensing.prepare_model_license_adoption(
        policy=policy,
        authority=authority,
        noncommercial_terms_sha256="bc" * 32,
        training_rights_policy_sha256="bd" * 32,
        operator_decision_sha256="be" * 32,
        issued_at_block=190,
        reason="Permit declared noncommercial training under exact additional model terms",
    )
    signed_adoption = SignedModelLicenseTermsAdoption(
        adoption=adoption, signatures=signatures(adoption)
    )
    source = tmp_path / "model"
    original = bundle_at(source)
    bundle = ModelBundle.model_validate_json(
        canonical_json_bytes(
            original.model_copy(
                update={
                    "schema_": "umi-model-bundle/2",
                    "license_id": "CC-BY-NC-SA-4.0",
                    "license_adoption": signed_adoption,
                }
            )
        )
    )
    sub = submission(policy, bundle=bundle).submission.model_copy(
        update={"accepted_terms_sha256": adoption.noncommercial_terms_sha256}
    )
    signed = SignedSubmission(submission=sub, signature=sign_object(sub, wallet("Alice")))
    body = CohortParticipationConsent(
        schema="umi-cohort-participation-consent/1",
        cohort_sha256=digest(plan),
        authority_sha256=digest(a),
        submission_sha256=digest(sub),
        hotkey=sub.hotkey,
        signed_at_block=200,
        lifetime="until_cohort_completed_or_revoked",
        timing_rule="quorum_recovery_history/1",
        original_submission_expiry_does_not_end_participation=True,
    )
    consent = SignedCohortParticipationConsent(
        consent=body, signature=sign_object(body, wallet("Alice"))
    )
    return dict(
        original=original,
        bundle=bundle,
        source=source,
        signed=signed,
        consent=consent,
        history=history,
        adoption=signed_adoption,
    )


def admit(case, policy):
    return admit_recovery_participant(
        case["signed"],
        case["consent"],
        case["history"],
        policy,
        snapshot(210),
        expected_tip_sha256=tip(case["history"]),
        current_block=210,
    )


def resign_submission(case, **updates):
    sub = case["signed"].submission.model_copy(update=updates)
    signed = SignedSubmission(submission=sub, signature=sign_object(sub, wallet("Alice")))
    body = case["consent"].consent.model_copy(update={"submission_sha256": digest(sub)})
    consent = SignedCohortParticipationConsent(
        consent=body, signature=sign_object(body, wallet("Alice"))
    )
    return dict(case, signed=signed, consent=consent)


def test_original_manifest_and_signatures_are_byte_identical(nc_case, policy):
    original = nc_case["original"]
    raw = canonical_json_bytes(original)
    assert b"license_adoption" not in raw
    assert raw == canonical_json_bytes(ModelBundle.model_validate_json(raw))
    signed = submission(policy, bundle=original)
    before = canonical_json_bytes(signed)
    assert validate_admission(signed, policy, snapshot(210), 210) == 6
    assert licensing.model_contribution_terms(original, policy) == policy.contribution_terms_sha256
    validate_bundle_policy(nc_case["bundle"], policy)
    assert canonical_json_bytes(signed) == before
    assert canonical_json_bytes(policy).find(b"CC-BY-NC-SA") == -1


def test_nc_admission_restarts_and_replays_after_closure(nc_case, policy):
    first = admit(nc_case, policy)
    cert = AttestedCohortParticipantAdmission(admission=first, signatures=signatures(first))
    history = transition(nc_case["history"], policy, "close_phase", 300)
    recovered = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    signed = SignedSubmission.model_validate_json(canonical_json_bytes(nc_case["signed"]))
    consent = SignedCohortParticipationConsent.model_validate_json(
        canonical_json_bytes(nc_case["consent"])
    )
    replayed = verify_participant_admission(
        cert,
        signed,
        consent,
        recovered,
        policy,
        snapshot(210),
        expected_tip_sha256=tip(recovered),
        current_block=310,
    )
    assert replayed == first
    assert canonical_json_bytes(recovered.plan) == canonical_json_bytes(nc_case["history"].plan)
    assert canonical_json_bytes(recovered.authority) == canonical_json_bytes(
        nc_case["history"].authority
    )


def test_new_terms_cannot_reuse_original_terms_or_original_consent(nc_case, policy):
    wrong = resign_submission(nc_case, accepted_terms_sha256=policy.contribution_terms_sha256)
    with pytest.raises(ValueError, match="exact model contribution terms"):
        admit(wrong, policy)
    old_sub = submission(policy, bundle=nc_case["original"])
    old_body = nc_case["consent"].consent.model_copy(
        update={"submission_sha256": digest(old_sub.submission)}
    )
    old_consent = SignedCohortParticipationConsent(
        consent=old_body, signature=sign_object(old_body, wallet("Alice"))
    )
    with pytest.raises(ValueError, match="scope or fresh miner consent"):
        admit(dict(nc_case, consent=old_consent), policy)


@pytest.mark.parametrize(
    "field,value",
    [
        ("authority_sha256", "cd" * 32),
        ("cohort_sha256s", ("ce" * 32,)),
        ("first_cohort_sequence", 8),
        ("issued_at_block", 201),
    ],
)
def test_even_signed_adoption_cannot_escape_cohort_scope(nc_case, policy, field, value):
    body = nc_case["adoption"].adoption.model_copy(update={field: value})
    adoption = SignedModelLicenseTermsAdoption(adoption=body, signatures=signatures(body))
    bundle = nc_case["bundle"].model_copy(update={"license_adoption": adoption})
    changed = resign_submission(nc_case, model_bundle=bundle, model_revision=digest(bundle))
    with pytest.raises(ValueError, match="scope or fresh miner consent"):
        admit(changed, policy)


def test_miner_self_authorization_and_tampered_quorum_are_rejected(nc_case, policy):
    adoption = nc_case["adoption"]
    for bad in (
        adoption.model_copy(update={"signatures": signatures(adoption.adoption, ("Alice",))}),
        adoption.model_copy(
            update={
                "adoption": adoption.adoption.model_copy(
                    update={"noncommercial_terms_sha256": "aa" * 32}
                )
            }
        ),
    ):
        with pytest.raises(ValueError):
            validate_bundle_policy(
                nc_case["bundle"].model_copy(update={"license_adoption": bad}), policy
            )


def test_generic_admission_still_needs_its_original_terms(nc_case, policy):
    with pytest.raises(ValueError, match="current terms"):
        validate_admission(nc_case["signed"], policy, snapshot(210), 210)


def test_archive_restore_reuses_manifest_without_license_relabel(nc_case, policy, tmp_path):
    archive = tmp_path / "archive"
    model = preserve_bundle(nc_case["bundle"], nc_case["source"], archive, policy)
    assert verify_preserved_bundle(nc_case["bundle"], archive, policy) == digest(nc_case["bundle"])
    assert model.exists()
    assert model_content_digest(nc_case["original"]) == model_content_digest(nc_case["bundle"])
    assert digest(nc_case["original"]) != digest(nc_case["bundle"])


def test_authentication_cache_reuses_exact_signed_metadata_only(nc_case, policy):
    licensing._verified_adoption.cache_clear()
    with patch.object(
        licensing, "verify_recovery_quorum", wraps=licensing.verify_recovery_quorum
    ) as verify:
        validate_bundle_policy(nc_case["bundle"], policy)
        licensing.model_contribution_terms(nc_case["bundle"], policy)
        admit(nc_case, policy)
        assert verify.call_count == 1


def test_schema_one_cannot_hide_noncommercial_adoption(nc_case, policy):
    with pytest.raises(ValueError, match="bundle version two"):
        validate_bundle_policy(
            nc_case["bundle"].model_copy(update={"schema_": "umi-model-bundle/1"}), policy
        )
