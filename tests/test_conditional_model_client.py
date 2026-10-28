"""NC opt-in travels through supported signing, delivery and public readers."""

import argparse
from pathlib import Path

import bittensor as bt
import pytest

from umi.competition_cohort_intake_records import RetainedCohortParticipation
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelArtifactAcceptance,
)
from umi.competition_cohort_model_client import _fingerprint, submit_cohort_model
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipationRequest,
)
from umi.competition_cohort_public_results import PublicModelInventory, project_models
from umi.competition_cohort_recovery import (
    ModelRewardCohortAuthority,
    SignedCohortRecoveryAuthority,
)
from umi.competition_cohort_roster import RecoverableRosterParticipant
from umi.competition_commands import cohorts, submissions
from umi.competition_execution import execution_boundary
from umi.competition_model_source_verification import verify_model_source
from umi.open_competition import SignedSubmission, digest, model_content_digest
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_recovery as recovery_fixtures
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_public_download_client import Fixture
from .test_competition_cohort_recovery import signatures
from .test_competition_model_license import admit, resign_submission
from .test_competition_model_license import nc_case as nc_case
from .test_open_competition import policy as policy
from .test_open_competition import wallet

base_recovery = recovery_fixtures.recovery


@pytest.fixture
def recovery(base_recovery):
    plan, signed, state = base_recovery
    old = signed.authority
    authority = ModelRewardCohortAuthority(
        schema="umi-cohort-recovery-authority/3",
        policy_sha256=old.policy_sha256,
        cohort_sha256s=old.cohort_sha256s,
        issued_at_block=old.issued_at_block,
        lifetime=old.lifetime,
        closure_rule=old.closure_rule,
        timing_rule="targets_without_extension_signatures",
        model_reward_rule="baseline_or_better_best_score_first_complete/1",
    )
    return (
        plan,
        SignedCohortRecoveryAuthority(authority=authority, signatures=signatures(authority)),
        state,
    )


def signing_args(case, tmp_path):
    files = {}
    for key, obj in (
        ("submission", case["signed"]),
        ("consent", case["consent"].consent),
        ("history", case["history"]),
    ):
        path = tmp_path / (key + ".json")
        path.write_bytes(canonical_json_bytes(obj))
        files[key] = str(path)
    return argparse.Namespace(
        **files,
        current_block=210,
        expected_tip_sha256=digest(case["history"].genesis),
        wallet_name="miner",
        hotkey_name="hotkey",
        wallet_path="unused",
    )


def test_nc_signing_preserves_fresh_request_and_refuses_old_consent(
    nc_case, policy, tmp_path, monkeypatch
):
    used = []
    monkeypatch.setattr(bt, "Wallet", lambda **kwargs: used.append(kwargs) or wallet("Alice"))
    args = signing_args(nc_case, tmp_path)
    request = CohortParticipationRequest.model_validate_json(
        canonical_json_bytes(cohorts.sign_consent(args, policy))
    )
    assert request.signed_submission == nc_case["signed"]
    assert request.consent.consent == nc_case["consent"].consent
    old = resign_submission(nc_case, accepted_terms_sha256=policy.contribution_terms_sha256)
    args = signing_args(old, tmp_path)
    with pytest.raises(ValueError, match="exact model contribution terms"):
        cohorts.sign_consent(args, policy)
    assert len(used) == 1


def test_nc_submission_signer_checks_terms_before_hotkey(nc_case, policy, tmp_path, monkeypatch):
    used = []
    monkeypatch.setattr(bt, "Wallet", lambda **kwargs: used.append(kwargs) or wallet("Alice"))
    args = signing_args(nc_case, tmp_path)
    Path(args.submission).write_bytes(canonical_json_bytes(nc_case["signed"].submission))
    result = SignedSubmission.model_validate_json(
        canonical_json_bytes(submissions.sign_submission(args, policy))
    )
    assert result.submission == nc_case["signed"].submission
    wrong = result.submission.model_copy(
        update={"accepted_terms_sha256": policy.contribution_terms_sha256}
    )
    Path(args.submission).write_bytes(canonical_json_bytes(wrong))
    with pytest.raises(ValueError, match="exact model contribution terms"):
        submissions.sign_submission(args, policy)
    assert len(used) == 1


def test_nc_source_checkpoint_reuse_preserves_files_and_manifest(
    nc_case, policy, tmp_path, monkeypatch
):
    from umi import competition_model_source_verification as source_module

    monkeypatch.setenv("UMI_MODEL_VERIFICATION_DIRECTORY", str(tmp_path / "verification"))
    source, bundle = nc_case["source"], nc_case["bundle"]
    first = verify_model_source(source, bundle, policy, _fingerprint)
    monkeypatch.setattr(
        source_module, "_copy_verified", lambda *_: pytest.fail("unchanged file was rehashed")
    )
    assert verify_model_source(source, bundle, policy, _fingerprint) == first


async def test_nc_wrong_terms_refuse_before_source_or_network(nc_case, policy, monkeypatch):
    from umi import competition_cohort_model_client as client

    case = resign_submission(nc_case, accepted_terms_sha256=policy.contribution_terms_sha256)
    request = CohortParticipationRequest(signed_submission=case["signed"], consent=case["consent"])
    monkeypatch.setattr(
        client, "_verify_source_owned", lambda *_: pytest.fail("invalid terms read source")
    )
    with pytest.raises(ValueError, match="exact model contribution terms"):
        await submit_cohort_model(
            origin="https://intake.example",
            policy=policy,
            request=request,
            source=case["source"],
            wallet=wallet("Alice"),
        )


def inventory(case, policy):
    proposed = admit(case, policy)
    request = CohortParticipationRequest(signed_submission=case["signed"], consent=case["consent"])
    capture = capture_at(210)
    record = RetainedCohortParticipation(
        schema="umi-retained-cohort-participation/1",
        request=request,
        proposed_admission=proposed,
        snapshot=capture.snapshot,
        observation=execution_boundary(capture),
    )
    cert = AttestedCohortParticipantAdmission(admission=proposed, signatures=signatures(proposed))
    sub = case["signed"].submission
    acceptance = ModelArtifactAcceptance(
        schema="umi-cohort-model-artifact-acceptance/1",
        policy_sha256=digest(policy),
        cohort_sha256=digest(case["history"].plan),
        authority_sha256=digest(case["history"].authority.authority),
        submission_sha256=digest(sub),
        model_sha256=digest(sub.model_bundle),
        content_sha256=model_content_digest(sub.model_bundle),
        recipient_hotkey=sub.hotkey,
        rights_evidence_sha256="da" * 32,
        reconstruction_evidence_sha256="db" * 32,
        accepted_at_block=220,
        accepted_ordinal=1,
        rights_and_reconstruction_passed=True,
    )
    return PublicModelInventory(
        schema="umi-native-public-model-inventory/1",
        scope="all_admitted_model_submissions",
        policy=policy,
        history=case["history"],
        participants=(RecoverableRosterParticipant(record=record, admission=cert),),
        acceptances=(
            CertifiedModelArtifactAcceptance(
                acceptance=acceptance, signatures=signatures(acceptance)
            ),
        ),
    )


def test_nc_public_catalog_requires_reviewed_terms_and_certificate(nc_case, policy, monkeypatch):
    from umi import competition_cohort_public_results as module

    source = inventory(nc_case, policy)
    catalog, bundles = project_models(source)
    assert catalog.items[0].release == "terms_review_required" and not bundles
    monkeypatch.setattr(
        module, "PUBLIC_RELEASE_TERMS", {nc_case["signed"].submission.accepted_terms_sha256}
    )
    catalog, bundles = project_models(source)
    row = catalog.items[0]
    assert row.release == "public_release_authorized"
    assert row.license_id == "CC-BY-NC-SA-4.0"
    assert row.accepted_terms_sha256 == nc_case["adoption"].adoption.noncommercial_terms_sha256
    assert bundles[row.model_sha256] == nc_case["bundle"]
    pending, bundles = project_models(source.model_copy(update={"acceptances": ()}))
    assert pending.items[0].release == "artifact_acceptance_pending" and not bundles


@pytest.mark.parametrize("kind", ["preserved_chunks", "concatenated_payload"])
def test_public_download_preserves_nc_manifest_and_completed_verification(nc_case, kind, tmp_path):
    fixture = Fixture(kind)
    try:
        fixture.bundle = nc_case["bundle"]
        fixture.model = digest(fixture.bundle)
        fixture.contents = {
            entry.path: (nc_case["source"] / entry.path).read_bytes()
            for entry in fixture.bundle.files
        }
        fixture.payload = b"".join(fixture.contents.values())
        target = fixture.download(tmp_path / "download")
        fixture.assert_model(target)
        assert (target / "manifest.json").read_bytes() == canonical_json_bytes(nc_case["bundle"])
        calls = fixture.downloads.copy()
        assert fixture.download(tmp_path / "download") == target
        assert fixture.downloads == calls
    finally:
        fixture.close()
