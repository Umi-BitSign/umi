"""Empty supporting files preserve rights evidence and historic review reuse."""

import hashlib

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
    build_standing_model_review,
    build_standing_model_review_from_documents,
    obsolete_empty_document_hold,
)
from umi.open_competition import BundleFile, digest
from umi.protocol import canonical_json_bytes

from .test_open_competition import bundle_at
from .test_open_competition import policy as policy


@pytest.fixture
def sample(tmp_path, policy):
    source = tmp_path / "source"
    bundle = bundle_at(source)
    empty = BundleFile(
        path="zz-empty.txt", role="provenance", sha256=hashlib.sha256(b"").hexdigest(), size_bytes=0
    )
    (source / empty.path).write_bytes(b"")
    bundle = bundle.model_copy(update={"files": (*bundle.files, empty)})
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
    documents = {
        r.path: (source / r.path).read_bytes()
        for r in bundle.files
        if r.role in {"license", "provenance"}
    }
    return bundle, standing, documents, source


def test_empty_supporting_document_has_same_exact_local_and_remote_review(sample, policy, tmp_path):
    bundle, standing, documents, source = sample
    archive = tmp_path / "archive"
    preserve_bundle(bundle, source, archive, policy)
    local = build_standing_model_review(bundle, archive, policy, standing)
    remote = build_standing_model_review_from_documents(bundle, policy, standing, documents)
    assert canonical_json_bytes(local) == canonical_json_bytes(remote)
    assert local.rights_evidence["original_documents"][-1]["text"] == ""
    assert local.model_sha256 == digest(bundle)


@pytest.mark.parametrize("role", ["license", "provenance"])
def test_empty_files_cannot_replace_substantive_rights_evidence(sample, policy, role):
    bundle, standing, documents, _ = sample
    files = []
    for record in bundle.files:
        if record.role == role:
            record = record.model_copy(
                update={"size_bytes": 0, "sha256": hashlib.sha256(b"").hexdigest()}
            )
            documents[record.path] = b""
        files.append(record)
    bundle = bundle.model_copy(update={"files": tuple(files)})
    with pytest.raises(StaticModelReviewHeld, match="declared_" + role + "_document_missing"):
        build_standing_model_review_from_documents(bundle, policy, standing, documents)


def test_empty_document_digest_and_exact_presence_remain_required(sample, policy):
    bundle, standing, documents, _ = sample
    documents["zz-empty.txt"] = b"changed"
    with pytest.raises(ValueError, match="differs from its manifest"):
        build_standing_model_review_from_documents(bundle, policy, standing, documents)
    del documents["zz-empty.txt"]
    with pytest.raises(ValueError, match="differ from the model manifest"):
        build_standing_model_review_from_documents(bundle, policy, standing, documents)


def test_only_obsolete_lower_bound_holds_are_reconsidered(sample):
    bundle, standing, _, _ = sample
    assert obsolete_empty_document_hold(bundle, standing, "review_document_size_outside_policy")
    assert not obsolete_empty_document_hold(bundle, standing, "review_document_not_utf8")
    assert not obsolete_empty_document_hold(
        bundle,
        standing.model_copy(update={"maximum_document_bytes": 1}),
        "review_document_size_outside_policy",
    )
