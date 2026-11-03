"""Prospective rights changes preserve retained direct-upload ownership."""

import hashlib
from types import SimpleNamespace

import pytest

from umi.competition_cohort_direct_model_attempts import (
    DirectModelAttemptRepairRequired,
    DirectModelUploadIntent,
)
from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
)
from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
)
from umi.competition_cohort_direct_model_review_policy import (
    DirectModelReviewPolicyContinuation,
    ModelReviewPolicyHistoryEntry,
    direct_model_review_policies,
)
from umi.competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review_from_documents,
    review_hold_key,
)
from umi.competition_cohort_recovery import ModelDeliveryProfile, SignedCohortRecoveryAuthority
from umi.competition_model_license import prepare_model_license_adoption
from umi.competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256,
    LEGACY_NC_CONTRIBUTION_TERMS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
)
from umi.open_competition import BundleFile, ModelBundle, SignedModelLicenseTermsAdoption, digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_model_training_rights import documents, source, stem_source
from .test_open_competition import bundle_at, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def selection(policy, recovery):
    old_plan, authority, _ = recovery
    plan = old_plan.model_copy(update={"sequence": 8})
    old_plan = old_plan.model_copy(update={"sequence": 6})
    body = authority.authority.model_copy(
        update={"cohort_sha256s": tuple(sorted((digest(plan), digest(old_plan))))}
    )
    authority = SignedCohortRecoveryAuthority(authority=body, signatures=signatures(body))
    adoption = prepare_model_license_adoption(
        policy=policy,
        authority=authority,
        noncommercial_terms_sha256=NC_CONTRIBUTION_TERMS_SHA256,
        training_rights_policy_sha256=CONDITIONAL_TRAINING_RIGHTS_SHA256,
        operator_decision_sha256="bc" * 32,
        issued_at_block=190,
        reason="Select the approved source rights while preserving upload ownership",
    )
    signed = SignedModelLicenseTermsAdoption(adoption=adoption, signatures=signatures(adoption))
    previous = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(policy),
        contribution_terms_sha256=policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-01T00:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    current = previous.model_copy(
        update={"training_rights_policy_sha256": CONDITIONAL_TRAINING_RIGHTS_SHA256}
    )
    continuation = DirectModelReviewPolicyContinuation(
        predecessor=previous, license_adoption=signed
    )
    return SimpleNamespace(
        plan=plan,
        old_plan=old_plan,
        authority=authority,
        previous=previous,
        current=current,
        continuation=continuation,
        policy=policy,
    )


def resolve(value, **changes):
    args = dict(policy=value.policy, authority=value.authority, plan=value.plan)
    args.update(changes)
    return direct_model_review_policies(value.continuation, value.current, **args)


def owner(value, root, *, continued=False, plan=None, **changes):
    plan = plan or value.plan
    config = DirectModelUploadOwnerConfig(
        schema="umi-direct-model-upload-owner-config/1",
        directory=str(root / "uploads"),
        cohort_sha256=digest(plan),
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=5 * 1024**2,
            maximum_concurrent_parts=2,
            capability_ttl_seconds=900,
        ),
        maximum_uploads=8,
        admission_reviews_directory=str(root / "reviews"),
        standing_review_policy=value.current if continued else value.previous,
    )
    config = config.model_copy(update=changes)
    multipart = SimpleNamespace(
        signer=SimpleNamespace(endpoint="https://r2.example", bucket="test")
    )
    return DirectModelUploadOwner(
        config,
        multipart,
        authorize=lambda _: None,
        sign=lambda _: None,
        policy=value.policy,
        review_policy_continuation=value.continuation if continued else None,
        review_policy_authority=value.authority if continued else None,
        review_policy_plan=plan if continued else None,
    )


def snapshot(journal):
    with journal.read_transaction() as db:
        tables = (
            "binding",
            "records",
            "round_generation_direct_upload_attempts",
            "direct_upload_attempt_heads",
            "round_record_capacity",
            "round_record_capacity_kinds",
        )
        return {
            table: db.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall() for table in tables
        }


def test_continuation_reopens_original_journal_without_rebuilding_or_changing_records(
    selection,
    tmp_path,
    monkeypatch,
):
    first = owner(selection, tmp_path)
    upload = "aa" * 32
    first.journal.retain_request(upload, {"signed": "request"}, {"signed": "payload"})
    attempt = DirectModelUploadIntent(
        schema="umi-direct-model-upload-intent/1",
        cohort_sha256=digest(selection.plan),
        upload_sha256=upload,
        payload_declaration_sha256="bb" * 32,
        attempt_id="cc" * 32,
        generation=1,
        object_key="retained/model/1",
        created_at_unix_ms=1000,
        retry_after_unix_ms=2000,
    )
    first.journal.retain_attempt(attempt)
    first.journal.advance_poll_cursor("dd" * 32)
    before = snapshot(first.journal)
    # Reopening must use persisted capacity and attempt indexes. Original
    # model records and byte-verification verdicts do not need reading.
    monkeypatch.setattr(
        first.journal.__class__, "get_raw", lambda *a, **kw: pytest.fail("record reread")
    )
    for _ in range(2):
        current = owner(selection, tmp_path, continued=True)
        assert snapshot(current.journal) == before
        assert current.journal.poll_cursor() == "dd" * 32
        assert current.config.standing_review_policy == selection.current
    assert review_hold_key(upload, selection.current) != review_hold_key(upload, selection.previous)


def test_unsigned_policy_change_still_refuses_existing_journal(selection, tmp_path):
    first = owner(selection, tmp_path)
    before = snapshot(first.journal)
    with pytest.raises(DirectModelAttemptRepairRequired, match="owner needs repair"):
        owner(selection, tmp_path, standing_review_policy=selection.current)
    assert snapshot(first.journal) == before


def test_continuation_preserves_older_cohort_review_semantics(selection, tmp_path):
    first = owner(selection, tmp_path, plan=selection.old_plan)
    before = snapshot(first.journal)
    continued = owner(selection, tmp_path, continued=True, plan=selection.old_plan)
    assert continued.config.standing_review_policy == selection.previous
    assert snapshot(continued.journal) == before


def test_historical_cohort_need_not_appear_in_prospective_adoption(selection):
    authority = selection.authority.authority.model_copy(
        update={"cohort_sha256s": (digest(selection.plan),)}
    )
    selection.authority = SignedCohortRecoveryAuthority(
        authority=authority, signatures=signatures(authority)
    )
    body = selection.continuation.license_adoption.adoption.model_copy(
        update={"authority_sha256": digest(authority), "cohort_sha256s": authority.cohort_sha256s}
    )
    selection.continuation = selection.continuation.model_copy(
        update={
            "license_adoption": SignedModelLicenseTermsAdoption(
                adoption=body, signatures=signatures(body)
            )
        }
    )
    assert resolve(selection, plan=selection.old_plan) == (selection.previous, selection.previous)


@pytest.mark.parametrize(
    "field,value",
    [
        ("approved_by", "other@example.test"),
        ("maximum_document_bytes", 1024),
        ("training_rights_policy_sha256", None),
    ],
)
def test_continuation_refuses_other_policy_changes(selection, field, value):
    selection.current = selection.current.model_copy(update={field: value})
    with pytest.raises(ValueError, match="signed rights selection"):
        resolve(selection)


def test_continuation_rejects_tampered_adoption_wrong_authority_and_wrong_cohort(selection):
    original = selection.continuation
    bad = original.license_adoption.model_copy(
        update={
            "adoption": original.license_adoption.adoption.model_copy(
                update={"reason": "tampered reason"}
            ),
        }
    )
    selection.continuation = original.model_copy(update={"license_adoption": bad})
    with pytest.raises(ValueError):
        resolve(selection)
    selection.continuation = original
    other = selection.authority.authority.model_copy(update={"issued_at_block": 151})
    signed = SignedCohortRecoveryAuthority(authority=other, signatures=signatures(other))
    with pytest.raises(ValueError, match="configured authority"):
        resolve(selection, authority=signed)
    with pytest.raises(ValueError, match="another cohort"):
        resolve(selection, plan=selection.plan.model_copy(update={"sequence": 9}))


def reviewed_bundle(tmp_path, raw, adoption=None):
    original = bundle_at(tmp_path / "model")
    records = [record for record in original.files if record.role not in {"license", "provenance"}]
    records.extend(
        BundleFile(
            path=path,
            role="license" if path in {"NOTICE", "LICENSE-WEIGHTS"} else "provenance",
            sha256=hashlib.sha256(body).hexdigest(),
            size_bytes=len(body),
        )
        for path, body in raw.items()
    )
    changes = {"files": tuple(sorted(records, key=lambda r: r.path))}
    if adoption is not None:
        changes.update(
            schema_="umi-model-bundle/2", license_id="CC-BY-NC-SA-4.0", license_adoption=adoption
        )
    return ModelBundle.model_validate_json(
        canonical_json_bytes(original.model_copy(update=changes))
    )


def test_v2_bundle_uses_exact_signed_rights_with_old_and_continued_policy(selection, tmp_path):
    raw = documents([stem_source()])
    bundle = reviewed_bundle(tmp_path, raw, selection.continuation.license_adoption)
    for standing in (selection.previous, resolve(selection)[0]):
        review = build_standing_model_review_from_documents(bundle, selection.policy, standing, raw)
        decision = review.rights_evidence["decision"]
        assert decision["training_rights_policy_sha256"] == CONDITIONAL_TRAINING_RIGHTS_SHA256
        assert decision["contribution_terms_sha256"] == NC_CONTRIBUTION_TERMS_SHA256


def test_continued_policy_rejects_unadopted_stem_relabelled_permissive(selection, tmp_path):
    raw = documents([source(name="ASL STEM Wiki", license_id="MIT")])
    bundle = reviewed_bundle(tmp_path, raw)
    with pytest.raises(StaticModelReviewHeld, match="requires_authenticated_nc_route"):
        build_standing_model_review_from_documents(
            bundle, selection.policy, resolve(selection)[0], raw
        )


def historical_reviewer(selection, tmp_path, *, entries=None):
    if entries is None:
        entries = (
            ModelReviewPolicyHistoryEntry(
                authority=selection.authority, continuation=selection.continuation
            ),
        )
    return DirectModelArtifactReviewer(
        DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/2",
            r2_credentials_file=str(tmp_path / "unused-credentials"),
            r2_bucket="model-tests",
            standing_review_policy=selection.current,
            review_policy_history=entries,
            materialization_protected_roots=(str(tmp_path / "protected"),),
        ),
        selection.policy,
        None,
        multipart=SimpleNamespace(),
        series=SimpleNamespace(
            recovery=selection.authority, cohorts=(selection.old_plan, selection.plan)
        ),
    )


def expected_review(inputs, cohort):
    return SimpleNamespace(
        model_sha256=inputs.model_sha256,
        cohort_sha256=cohort,
        rights_evidence_sha256=digest(inputs.rights_evidence),
        reconstruction_evidence_sha256=digest(inputs.reconstruction_evidence),
    )


@pytest.mark.parametrize("noncommercial", [False, True])
def test_saved_proposal_reconstructs_exact_evidence_after_current_review(
    selection, tmp_path, monkeypatch, noncommercial
):
    if noncommercial:
        raw = documents([stem_source()])
        bundle = reviewed_bundle(tmp_path, raw, selection.continuation.license_adoption)
    else:
        bundle = bundle_at(tmp_path / "model")
        raw = {
            record.path: (tmp_path / "model" / record.path).read_bytes()
            for record in bundle.files
            if record.role in {"license", "provenance"}
        }
    original = build_standing_model_review_from_documents(
        bundle, selection.policy, selection.previous, raw
    )
    before = canonical_json_bytes(original)
    reviewer = historical_reviewer(selection, tmp_path)
    monkeypatch.setattr(
        "umi.competition_cohort_direct_model_review.verify_remote_model",
        lambda *a, **kw: pytest.fail("model payload reverified"),
    )
    result = reviewer.inputs_for_acceptance(
        original, expected_review(original, digest(selection.plan))
    )
    assert canonical_json_bytes(result) == before == canonical_json_bytes(original)
    assert reviewer.review_policies[digest(selection.old_plan)] == selection.previous
    assert reviewer.review_policies[digest(selection.plan)] == selection.current
    if noncommercial:
        assert result.rights_evidence["decision"]["training_rights_policy_sha256"] == (
            CONDITIONAL_TRAINING_RIGHTS_SHA256
        )


def test_saved_policy_identity_cannot_exempt_current_nc_requirements(selection, tmp_path):
    raw = documents([stem_source()])
    bundle = reviewed_bundle(tmp_path, raw)
    # A retained or caller-proposed old rendering cannot confer source rights.
    from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs

    old = ModelArtifactReviewInputs(
        model_sha256=digest(bundle),
        rights_evidence={
            "decision": {"review_policy_sha256": digest(selection.previous)},
            "original_documents": [
                dict(path=path, text=data.decode()) for path, data in raw.items()
            ],
        },
        reconstruction_evidence={
            "original_manifest": bundle.model_dump(mode="json", by_alias=True)
        },
    )
    reviewer = historical_reviewer(selection, tmp_path)
    with pytest.raises(StaticModelReviewHeld, match="requires_authenticated_nc_route"):
        reviewer.inputs_for_acceptance(old, expected_review(old, digest(selection.plan)))


def test_unknown_historical_policy_and_changed_documents_cannot_match_saved_proposal(
    selection, tmp_path
):
    bundle = bundle_at(tmp_path / "model")
    raw = {
        record.path: (tmp_path / "model" / record.path).read_bytes()
        for record in bundle.files
        if record.role in {"license", "provenance"}
    }
    original = build_standing_model_review_from_documents(
        bundle, selection.policy, selection.previous, raw
    )
    reviewer = historical_reviewer(selection, tmp_path)
    unknown = original.model_copy(
        update={
            "rights_evidence": dict(
                original.rights_evidence,
                decision=dict(original.rights_evidence["decision"], review_policy_sha256="ef" * 32),
            ),
            "reconstruction_evidence": dict(
                original.reconstruction_evidence, review_policy_sha256="ef" * 32
            ),
        }
    )
    with pytest.raises(ValueError, match="authenticated review policy history"):
        reviewer.inputs_for_acceptance(original, expected_review(unknown, digest(selection.plan)))
    changed = original.model_copy(
        update={
            "rights_evidence": dict(
                original.rights_evidence,
                original_documents=[
                    dict(item, text=item["text"] + "changed")
                    for item in original.rights_evidence["original_documents"]
                ],
            )
        }
    )
    with pytest.raises(ValueError, match="document differs"):
        reviewer.inputs_for_acceptance(changed, expected_review(original, digest(selection.plan)))


def test_review_history_refuses_tampered_authority_and_reuses_current_review(
    selection, tmp_path, monkeypatch
):
    bad = selection.continuation.license_adoption.model_copy(
        update={
            "adoption": selection.continuation.license_adoption.adoption.model_copy(
                update={"reason": "changed"}
            )
        }
    )
    entry = ModelReviewPolicyHistoryEntry(
        authority=selection.authority,
        continuation=selection.continuation.model_copy(update={"license_adoption": bad}),
    )
    with pytest.raises(ValueError):
        historical_reviewer(selection, tmp_path, entries=(entry,))
    reviewer = historical_reviewer(selection, tmp_path)
    bundle = bundle_at(tmp_path / "model")
    raw = {
        record.path: (tmp_path / "model" / record.path).read_bytes()
        for record in bundle.files
        if record.role in {"license", "provenance"}
    }
    current = build_standing_model_review_from_documents(
        bundle, selection.policy, selection.current, raw
    )
    monkeypatch.setattr(
        "umi.competition_cohort_direct_model_review.build_standing_model_review_from_documents",
        lambda *a, **kw: pytest.fail("unchanged rights review repeated"),
    )
    assert (
        reviewer.inputs_for_acceptance(current, expected_review(current, digest(selection.plan)))
        is current
    )


def test_multiple_rights_updates_retain_old_proposals_and_original_cohort_semantics(
    selection, tmp_path
):
    old_authority = selection.authority
    previous = selection.previous.model_copy(
        update={"training_rights_policy_sha256": LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256}
    )
    body = prepare_model_license_adoption(
        policy=selection.policy,
        authority=old_authority,
        noncommercial_terms_sha256=LEGACY_NC_CONTRIBUTION_TERMS_SHA256,
        training_rights_policy_sha256=LEGACY_CONDITIONAL_TRAINING_RIGHTS_SHA256,
        operator_decision_sha256="cd" * 32,
        issued_at_block=180,
        reason="Earlier authenticated source review selector",
    )
    old = ModelReviewPolicyHistoryEntry(
        authority=old_authority,
        continuation=DirectModelReviewPolicyContinuation(
            predecessor=selection.previous,
            license_adoption=SignedModelLicenseTermsAdoption(
                adoption=body, signatures=signatures(body)
            ),
        ),
    )
    # A later authority must retain the actual old authority with its selector.
    authority = old_authority.authority.model_copy(update={"issued_at_block": 151})
    selection.authority = SignedCohortRecoveryAuthority(
        authority=authority, signatures=signatures(authority)
    )
    current_adoption = selection.continuation.license_adoption.adoption.model_copy(
        update={"authority_sha256": digest(authority)}
    )
    newest = ModelReviewPolicyHistoryEntry(
        authority=selection.authority,
        continuation=DirectModelReviewPolicyContinuation(
            predecessor=previous,
            license_adoption=SignedModelLicenseTermsAdoption(
                adoption=current_adoption, signatures=signatures(current_adoption)
            ),
        ),
    )
    reviewer = historical_reviewer(selection, tmp_path, entries=(old, newest))
    bundle = bundle_at(tmp_path / "model")
    raw = {
        record.path: (tmp_path / "model" / record.path).read_bytes()
        for record in bundle.files
        if record.role in {"license", "provenance"}
    }
    original = build_standing_model_review_from_documents(bundle, selection.policy, previous, raw)
    assert (
        reviewer.inputs_for_acceptance(original, expected_review(original, digest(selection.plan)))
        == original
    )
    assert reviewer.review_policies[digest(selection.old_plan)] == selection.previous
