"""NC and permissive entries use distinct, retained review/consent paths."""

import hashlib
import json

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review,
    build_standing_model_review_from_documents,
)
from umi.competition_model_training_rights import (
    CONDITIONAL_TRAINING_RIGHTS_SHA256,
    NC_CONTRIBUTION_TERMS_SHA256,
    ResearchRightsWarranty,
)
from umi.open_competition import BundleFile, SignedModelLicenseTermsAdoption, digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_model_license import nc_case as nc_case
from .test_open_competition import policy as policy


@pytest.fixture
def reviewed(nc_case, policy):
    provenance = {
        "schema": "umi-model-training-provenance/1",
        "model_license_id": "CC-BY-NC-SA-4.0",
        "sources": [
            {
                "name": "How2Sign",
                "version": "CVPR2021",
                "canonical_url": "https://how2sign.github.io/",
                "license_id": "CC-BY-NC-4.0",
                "download_route": "publisher release",
                "acquired_on": "2026-10-01",
                "archives": [{"name": "training.tar", "sha256": "aa" * 32}],
                "uses": ["training"],
                "accepted_access_terms": [],
                "additional_dataset_contract": False,
                "split": "train",
                "responsible_use_requests": ["Do not redistribute source recordings."],
                "destruction_required": False,
            }
        ],
        "rights_warranty": {key: True for key in ResearchRightsWarranty.model_fields},
    }
    documents = {
        "PROVENANCE.json": json.dumps(provenance).encode(),
        "NOTICE": b"How2Sign consortium, CVPR 2021. Do not redistribute source recordings.",
        "LICENSE-WEIGHTS": b"CC-BY-NC-SA-4.0",
        "MODEL_CARD.md": (
            b"Public noncommercial research model. Declared training sources in PROVENANCE.json."
        ),
    }
    bundle = nc_case["bundle"]
    records = list(bundle.files)
    for path, data in documents.items():
        (nc_case["source"] / path).write_bytes(data)
        records.append(
            BundleFile(
                path=path,
                role="license" if path in ("NOTICE", "LICENSE-WEIGHTS") else "provenance",
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
            )
        )
    body = bundle.license_adoption.adoption.model_copy(
        update={
            "noncommercial_terms_sha256": NC_CONTRIBUTION_TERMS_SHA256,
            "training_rights_policy_sha256": CONDITIONAL_TRAINING_RIGHTS_SHA256,
        }
    )
    bundle = bundle.model_copy(
        update={
            "files": tuple(sorted(records, key=lambda record: record.path)),
            "license_adoption": SignedModelLicenseTermsAdoption(
                adoption=body, signatures=signatures(body)
            ),
        }
    )
    documents = {
        record.path: (nc_case["source"] / record.path).read_bytes()
        for record in bundle.files
        if record.role in ("license", "provenance")
    }
    standing = StandingModelReviewPolicy(
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
    return bundle, standing, documents, nc_case["source"]


def review(sample, policy):
    bundle, standing, documents, _ = sample
    return build_standing_model_review_from_documents(bundle, policy, standing, documents)


def test_nc_static_review_local_and_R2_document_views_match(reviewed, policy, tmp_path):
    bundle, standing, _documents, source = reviewed
    archive = tmp_path / "archive"
    preserve_bundle(bundle, source, archive, policy)
    local = build_standing_model_review(bundle, archive, policy, standing)
    remote = review(reviewed, policy)
    assert canonical_json_bytes(local) == canonical_json_bytes(remote)
    assert remote.rights_evidence["schema"] == "umi-standing-model-rights-review/2"
    decision = remote.rights_evidence["decision"]
    assert decision["contribution_terms_sha256"] == NC_CONTRIBUTION_TERMS_SHA256
    assert decision["original_contribution_terms_sha256"] == policy.contribution_terms_sha256
    assert decision["license_adoption_sha256"] == digest(bundle.license_adoption.adoption)
    assert (
        decision["declared_training_rights_review"]["actual_training_independently_audited"]
        is False
    )


def test_new_nc_declaration_cannot_be_reviewed_as_permissive(reviewed, policy):
    bundle, standing, documents, source = reviewed
    permissive = bundle.model_copy(
        update={
            "schema_": "umi-model-bundle/1",
            "license_adoption": None,
            "license_id": "CC-BY-SA-4.0",
        }
    )
    with pytest.raises(StaticModelReviewHeld, match="authenticated_nc_route"):
        review((permissive, standing, documents, source), policy)


@pytest.mark.parametrize(
    "field,value,reason",
    [
        ("noncommercial_terms_sha256", "cc" * 32, "conditional_model_terms_not_supported"),
        (
            "training_rights_policy_sha256",
            "dd" * 32,
            "conditional_training_rights_policy_not_supported",
        ),
    ],
)
def test_signed_route_cannot_claim_unimplemented_rights_semantics(
    reviewed, policy, field, value, reason
):
    bundle, standing, documents, source = reviewed
    body = bundle.license_adoption.adoption.model_copy(update={field: value})
    changed = bundle.model_copy(
        update={
            "license_adoption": SignedModelLicenseTermsAdoption(
                adoption=body, signatures=signatures(body)
            ),
        }
    )
    with pytest.raises(StaticModelReviewHeld, match=reason):
        review((changed, standing, documents, source), policy)


def test_missing_nc_notice_holds_only_the_new_model_review(reviewed, policy):
    bundle, standing, documents, source = reviewed
    changed = bundle.model_copy(
        update={
            "files": tuple(record for record in bundle.files if record.path != "NOTICE"),
        }
    )
    without = {key: value for key, value in documents.items() if key != "NOTICE"}
    with pytest.raises(StaticModelReviewHeld, match="nc_required_document_missing:NOTICE"):
        review((changed, standing, without, source), policy)


def test_legacy_prose_review_keeps_exact_original_rights_record(nc_case, policy, reviewed):
    original = nc_case["original"]
    documents = {
        record.path: (nc_case["source"] / record.path).read_bytes()
        for record in original.files
        if record.role in ("license", "provenance")
    }
    before = review((original, reviewed[1], documents, nc_case["source"]), policy)
    review(reviewed, policy)
    after = review((original, reviewed[1], documents, nc_case["source"]), policy)
    assert canonical_json_bytes(before) == canonical_json_bytes(after)
    assert before.rights_evidence["schema"] == "umi-standing-model-rights-review/1"
    assert (
        before.rights_evidence["decision"]["contribution_terms_sha256"]
        == policy.contribution_terms_sha256
    )
    assert "declared_training_rights_review" not in before.rights_evidence["decision"]
