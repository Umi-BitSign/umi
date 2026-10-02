"""Independent R2 review verifies exact bytes without a persistent model archive."""

from __future__ import annotations

import hashlib
import shutil
from types import SimpleNamespace

import pytest

from umi.competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelReviewSourceConfig,
)
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
    direct_model_object_key,
)
from umi.competition_cohort_model_static_review import (
    StandingModelReviewPolicy,
    StaticModelReviewHeld,
)
from umi.open_competition import digest, sign_object
from umi.protocol import sha256_hex

from .test_competition_cohort_model_acceptance import base_policy as base_policy
from .test_competition_cohort_model_acceptance import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_acceptance import policy as policy
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_acceptance import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_acceptance import recovery as recovery
from .test_competition_cohort_model_acceptance import runtime as runtime
from .test_competition_cohort_model_review import reviews as reviews
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


class ReadOnlyObject:
    def __init__(self, key: str, payload: bytes):
        self.key, self.payload = key, payload
        self.etag = "read-only-object"
        self.replace_on_read = False

    async def head(self, key, *, at=None):
        assert key == self.key
        return SimpleNamespace(size_bytes=len(self.payload), etag=self.etag)

    async def read_range(self, key, *, offset, size_bytes, at=None):
        assert key == self.key
        result = self.payload[offset : offset + size_bytes]
        if self.replace_on_read:
            self.etag = "replacement-object"
            self.replace_on_read = False
        return result


@pytest.mark.asyncio
async def test_reviewer_independently_verifies_owner_bound_r2_object(reviews):
    request = reviews.request
    submission = request.record.request.signed_submission.submission
    bundle = submission.model_bundle
    assert bundle is not None
    model_root = reviews.owner.archive / digest(bundle) / "model"
    body = b"".join((model_root / record.path).read_bytes() for record in bundle.files)
    attempt_id = "a1" * 32
    upload_sha256 = digest(request.record.request)
    object_key = direct_model_object_key(
        request.acceptance.cohort_sha256, upload_sha256, attempt_id
    )
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=upload_sha256,
        model_sha256=digest(bundle),
        payload_sha256=hashlib.sha256(body).hexdigest(),
        total_bytes=len(body),
        file_count=len(bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=request.acceptance.cohort_sha256,
        hotkey=submission.hotkey,
        payload=payload,
        attempt_id=attempt_id,
        generation=1,
        object_key_sha256=sha256_hex(object_key.encode()),
        provider_upload_id_sha256="b2" * 32,
        created_at_unix_ms=1_800_000_000_000,
    )
    direct_request = request.model_copy(
        update={
            "schema_": "umi-cohort-model-review-request/2",
            "direct_artifact": SignedDirectModelUploadReservation(
                schema="umi-signed-direct-model-upload-reservation/1",
                reservation=reservation,
                signature=sign_object(reservation, wallet("Charlie")),
            ),
        }
    )
    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(reviews.owner.intake.policy),
        contribution_terms_sha256=reviews.owner.intake.policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-02T12:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    source = ReadOnlyObject(object_key, body)
    verifier = DirectModelArtifactReviewer(
        DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/1",
            r2_credentials_file=str(reviews.root / "unused-read-credentials"),
            r2_bucket="umi-model-artifacts",
            standing_review_policy=standing,
            materialization_free_space_reserve_bytes=64 * 1024**2,
        ),
        reviews.owner.intake.policy,
        wallet("Charlie").hotkey.ss58_address,
        multipart=source,
    )

    result = await verifier.review(direct_request)

    assert result.model_sha256 == digest(bundle)
    documents = result.rights_evidence["original_documents"]
    assert {entry["role"] for entry in documents} == {"license", "provenance"}
    assert not (reviews.root / "unused-read-credentials").exists()
    assert (
        min(
            record.size_bytes for record in bundle.files if record.role in {"license", "provenance"}
        )
        > 1
    )
    held_verifier = DirectModelArtifactReviewer(
        DirectModelReviewSourceConfig(
            schema="umi-direct-model-review-source/1",
            r2_credentials_file=str(reviews.root / "unused-read-credentials"),
            r2_bucket="umi-model-artifacts",
            standing_review_policy=standing.model_copy(
                update={"maximum_document_bytes": 1, "maximum_total_document_bytes": 1}
            ),
            materialization_free_space_reserve_bytes=64 * 1024**2,
        ),
        reviews.owner.intake.policy,
        wallet("Charlie").hotkey.ss58_address,
        multipart=source,
    )
    with pytest.raises(StaticModelReviewHeld, match="review_document_size_outside_policy"):
        await held_verifier.review(direct_request)
    source.replace_on_read = True
    with pytest.raises(ValueError, match="changed while reading"):
        await verifier.review(direct_request)
    source.etag = "read-only-object"
    materialized = reviews.root / "materialized"
    await verifier.materialize(direct_request, materialized)
    assert (materialized / digest(bundle) / "manifest.json").is_file()
    assert (materialized / "materialization.json").is_file()
    assert await verifier.materialized(direct_request, materialized)
    assert sum(
        (materialized / digest(bundle) / "model" / record.path).stat().st_size
        for record in bundle.files
    ) == len(body)
    changed = next(record for record in bundle.files if record.size_bytes)
    changed_path = materialized / digest(bundle) / "model" / changed.path
    changed_path.chmod(0o600)
    original = changed_path.read_bytes()
    changed_path.write_bytes(bytes((original[0] ^ 1,)) + original[1:])
    changed_path.chmod(0o400)
    assert not await verifier.materialized(direct_request, materialized)
    shutil.rmtree(materialized)
    (materialized / digest(bundle) / "model").mkdir(parents=True)
    assert not await verifier.materialized(direct_request, materialized)
    shutil.rmtree(materialized)
    verifier.multipart.payload = body[:-1] + bytes((body[-1] ^ 1,))
    with pytest.raises(ValueError, match="differs"):
        await verifier.materialize(direct_request, materialized)
    assert not materialized.exists()
    verifier.multipart.payload = body
    source.replace_on_read = True
    replaced = reviews.root / "replacement-race"
    with pytest.raises(ValueError, match="changed during materialization"):
        await verifier.materialize(direct_request, replaced)
    assert not replaced.exists()
    source.etag = "read-only-object"

    acceptance = direct_request.acceptance.model_copy(
        update={
            "rights_evidence_sha256": digest(result.rights_evidence),
            "reconstruction_evidence_sha256": digest(result.reconstruction_evidence),
        }
    )
    direct_request = direct_request.model_copy(update={"acceptance": acceptance})
    reviewer = reviews.create("Charlie")
    reviewer.direct_review = verifier.review
    (reviews.root / "Charlie/approvals").rename(reviews.root / "Charlie/approvals-offline")
    reviews.owner.archive.rename(reviews.owner.archive.with_name("archive-offline"))

    vote = await reviewer.attest(direct_request)

    assert vote.acceptance == acceptance
