"""Native R2 materialization, canonical preservation and downstream receipt reuse."""

import hashlib
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
    preserved_model_object_key,
)
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_reference_preparation import SettlementReferencePreparation, _Source
from umi.competition_model_cache_space import BootDiskModelCacheConfig
from umi.open_competition import digest, sign_object
from umi.protocol import sha256_hex

from .test_competition_cohort_direct_model_review import ReadOnlyObject
from .test_competition_cohort_direct_model_review import base_policy as base_policy
from .test_competition_cohort_direct_model_review import legacy_scenario as legacy_scenario
from .test_competition_cohort_direct_model_review import policy as policy
from .test_competition_cohort_direct_model_review import prepared as prepared
from .test_competition_cohort_direct_model_review import receipt_scenario as receipt_scenario
from .test_competition_cohort_direct_model_review import recovery as recovery
from .test_competition_cohort_direct_model_review import reviews as reviews
from .test_competition_cohort_direct_model_review import runtime as runtime
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


async def test_native_remote_reference_restores_and_reuses_without_a_second_payload_read(
    reviews, tmp_path, monkeypatch
):
    request = reviews.request
    policy = reviews.owner.intake.policy
    sub = request.record.request.signed_submission.submission
    bundle = sub.model_bundle
    model_root = reviews.owner.archive / digest(bundle) / "model"
    raw = b"".join((model_root / record.path).read_bytes() for record in bundle.files)
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(request.record.request),
        model_sha256=digest(bundle),
        payload_sha256=hashlib.sha256(raw).hexdigest(),
        total_bytes=len(raw),
        file_count=len(bundle.files),
        part_size_bytes=5 * 1024**2,
        total_parts=1,
    )
    key = direct_model_object_key(
        request.acceptance.cohort_sha256, payload.upload_sha256, "a1" * 32
    )
    reservation = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=request.acceptance.cohort_sha256,
        hotkey=sub.hotkey,
        payload=payload,
        attempt_id="a1" * 32,
        generation=1,
        object_key_sha256=sha256_hex(key.encode()),
        provider_upload_id_sha256="b2" * 32,
        created_at_unix_ms=1800000000000,
    )
    artifact = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=reservation,
        signature=sign_object(reservation, wallet("Charlie")),
    )
    request = request.model_copy(
        update={
            "schema_": "umi-cohort-model-review-request/2",
            "direct_artifact": artifact,
            "acceptance": request.acceptance.model_copy(
                update={
                    "schema_": "umi-cohort-model-artifact-acceptance/2",
                    "direct_artifact": artifact,
                }
            ),
        }
    )
    archive, cache, protected = (tmp_path / name for name in ("canonical", "cache", "protected"))
    for directory in (archive, cache, protected):
        directory.mkdir(mode=0o700)
    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(policy),
        contribution_terms_sha256=policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-02T12:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    source = ReadOnlyObject(
        preserved_model_object_key(
            request.acceptance.cohort_sha256, digest(bundle), payload.payload_sha256
        ),
        raw,
    )
    config = DirectModelReviewSourceConfig(
        schema="umi-direct-model-review-source/2",
        r2_credentials_file=str(tmp_path / "unused-credentials"),
        r2_bucket=source.signer.bucket,
        standing_review_policy=standing,
        materialization_protected_roots=(str(protected),),
        maximum_materialized_bytes=1024**2,
        materialization_free_space_reserve_bytes=64 * 1024**2,
        materialization_boot_disk_cache=BootDiskModelCacheConfig(
            schema="umi-boot-disk-model-cache/1",
            directory=str(cache),
            maximum_allocated_bytes=4 * 1024**2,
        ),
        reference_preservation_directory=str(archive),
        reference_working_set_reclamation=True,
    )
    artifacts = DirectModelArtifactReviewer(
        config, policy, None, multipart=source, verification_root=tmp_path / "durable-byte-results"
    )
    worker = SettlementReferencePreparation(
        artifacts, archive, SimpleNamespace(directory=tmp_path), maximum_bytes=1024**2
    )
    worker._source = lambda _: _Source(bundle, request)
    await worker.ensure(None)
    reads = source.ranges_read
    assert reads > 0
    assert (archive / digest(bundle) / "manifest.json").is_file()
    assert not worker._slot(_Source(bundle, request)).exists()

    from umi import competition_artifacts as native

    def never_reread(*a, **k):
        raise AssertionError("verified reference payload read twice")

    monkeypatch.setattr(native, "_copy_verified", never_reread)
    await worker.ensure(None)
    assert source.ranges_read == reads
    assert native.verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    worker.close()
    assert not (archive / digest(bundle)).exists()
    assert (tmp_path / "durable-byte-results").is_dir()
