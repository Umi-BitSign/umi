"""A public direct download requires completed, exact native R2 preservation."""

import hashlib
import os
import sqlite3

import pytest

from umi.competition_cohort_direct_model_owner import DirectModelPromotion
from umi.competition_cohort_direct_model_upload import (
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
)
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelArtifactAcceptance,
)
from umi.competition_cohort_public_promotion import PublicPromotionJournal
from umi.open_competition import digest, model_content_digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_public_results import public_case as public_case
from .test_open_competition import wallet


@pytest.fixture
def promoted(public_case, tmp_path):
    _, catalog, download, _ = public_case
    body = DirectModelUploadReservation(
        schema="umi-direct-model-upload-reservation/1",
        cohort_sha256=catalog.cohort_sha256,
        hotkey=catalog.items[0].hotkey,
        payload=download.payload,
        attempt_id="cd" * 32,
        generation=1,
        object_key_sha256="ef" * 32,
        provider_upload_id_sha256="01" * 32,
        created_at_unix_ms=1,
    )
    signed = SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=body,
        signature=sign_object(body, wallet("Bob")),
    )
    acceptance = ModelArtifactAcceptance(
        schema="umi-cohort-model-artifact-acceptance/2",
        policy_sha256=catalog.policy_sha256,
        cohort_sha256=catalog.cohort_sha256,
        authority_sha256="ab" * 32,
        submission_sha256=catalog.items[0].submission_sha256,
        model_sha256=download.model_sha256,
        content_sha256=model_content_digest(download.bundle),
        recipient_hotkey=catalog.items[0].hotkey,
        rights_evidence_sha256="23" * 32,
        reconstruction_evidence_sha256="45" * 32,
        accepted_at_block=3,
        accepted_ordinal=1,
        rights_and_reconstruction_passed=True,
        direct_artifact=signed,
    )
    certificate = CertifiedModelArtifactAcceptance(
        acceptance=acceptance, signatures=(sign_object(acceptance, wallet("Bob")),)
    )
    receipt = DirectModelPromotion(
        schema="umi-direct-model-promotion/1",
        acceptance_sha256=digest(acceptance),
        reservation_sha256=digest(body),
        source_object_key_sha256=body.object_key_sha256,
        preserved_object_key_sha256=hashlib.sha256(download.payload_key().encode()).hexdigest(),
        model_sha256=download.model_sha256,
        payload_sha256=download.payload.payload_sha256,
        total_bytes=download.payload.total_bytes,
        provider_etag="retained",
        promoted_at_unix_ms=4,
    )
    path = tmp_path / "promotions.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE binding(body BLOB)")
        db.execute("INSERT INTO binding VALUES (?)", (b"{}",))
        db.execute("CREATE TABLE records(kind TEXT,id TEXT,body BLOB, PRIMARY KEY(kind,id))")
        db.execute(
            "INSERT INTO records VALUES (?,?,?)",
            ("direct-promotion", digest(acceptance), canonical_json_bytes(receipt)),
        )
    path.chmod(0o600)
    source = PublicPromotionJournal(
        path=str(path), owner_uid=os.getuid(), binding_sha256=hashlib.sha256(b"{}").hexdigest()
    )
    return source, certificate, receipt, path


def test_native_promoted_body_identity_and_read_only_restart(promoted):
    source, certificate, _, path = promoted
    before = path.read_bytes()
    for _ in range(2):
        assert source.completed((certificate,)) == {digest(certificate)}
    assert path.read_bytes() == before
    with sqlite3.connect(path) as db:
        db.execute("DELETE FROM records")
    assert source.completed((certificate,)) == set()


@pytest.mark.parametrize(
    "field",
    [
        "acceptance_sha256",
        "reservation_sha256",
        "source_object_key_sha256",
        "preserved_object_key_sha256",
        "model_sha256",
        "payload_sha256",
    ],
)
def test_changed_promotion_requires_repair(promoted, field):
    source, certificate, receipt, path = promoted
    with sqlite3.connect(path) as db:
        db.execute(
            "UPDATE records SET body=?",
            (canonical_json_bytes(receipt.model_copy(update={field: "77" * 32})),),
        )
    with pytest.raises(ValueError, match="differs"):
        source.completed((certificate,))
