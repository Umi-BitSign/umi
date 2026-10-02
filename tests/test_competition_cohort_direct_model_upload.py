from __future__ import annotations

import pytest
from pydantic import ValidationError

from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadCompletion,
    DirectModelUploadPart,
    DirectModelUploadPartCapability,
    SignedDirectModelPayload,
)
from umi.open_competition import sign_object
from umi.r2_limits import R2_MAXIMUM_MULTIPART_BYTES, R2_MAXIMUM_PART_BYTES

from .test_open_competition import wallet


def payload(**changes):
    values = {
        "schema": "umi-direct-model-payload/1",
        "upload_sha256": "11" * 32,
        "model_sha256": "22" * 32,
        "payload_sha256": "33" * 32,
        "total_bytes": 130 * 1024**2,
        "file_count": 451,
        "part_size_bytes": 64 * 1024**2,
        "total_parts": 3,
    }
    return DirectModelPayload.model_validate(values | changes)


def test_direct_payload_binds_exact_part_geometry():
    assert payload().total_parts == 3
    with pytest.raises(ValidationError, match="part geometry differs"):
        payload(total_parts=2)


def test_direct_payload_stays_inside_r2_provider_limits():
    with pytest.raises(ValidationError):
        payload(total_bytes=R2_MAXIMUM_MULTIPART_BYTES + 1)
    with pytest.raises(ValidationError):
        payload(part_size_bytes=R2_MAXIMUM_PART_BYTES + 1)


def test_signed_payload_verifies_its_exact_bytes():
    body = payload()
    signed = SignedDirectModelPayload(
        schema="umi-signed-direct-model-payload/1",
        payload=body,
        signature=sign_object(body, wallet("Alice")),
    )
    assert signed.payload == body
    with pytest.raises(ValidationError, match="invalid competition signature"):
        SignedDirectModelPayload.model_validate(
            signed.model_dump(by_alias=True)
            | {"payload": body.model_copy(update={"total_bytes": body.total_bytes + 1})}
        )


def test_part_capability_requires_https_and_drops_fragments():
    values = {
        "schema": "umi-direct-model-upload-part-capability/1",
        "reservation_sha256": "44" * 32,
        "generation": 1,
        "part_number": 1,
        "size_bytes": 64 * 1024**2,
        "expires_at_unix_ms": 1_800_000_000_000,
    }
    assert (
        DirectModelUploadPartCapability.model_validate(
            values
            | {
                "url": "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/"
                "bucket/key?X-Amz-Signature=x"
            }
        ).part_number
        == 1
    )
    for url in (
        "http://example.invalid/object",
        "https://example.invalid/object?X-Amz-Signature=x",
    ):
        with pytest.raises(ValidationError, match="R2 HTTPS URL"):
            DirectModelUploadPartCapability.model_validate(values | {"url": url})


def test_completion_requires_every_ordered_part_and_normalizes_etags():
    completion = DirectModelUploadCompletion(
        schema="umi-direct-model-upload-completion/1",
        reservation_sha256="55" * 32,
        generation=2,
        parts=(
            DirectModelUploadPart(
                part_number=1, size_bytes=64 * 1024**2, etag='"' + "A1" * 16 + '"'
            ),
            DirectModelUploadPart(part_number=2, size_bytes=1, etag="b2" * 16),
        ),
    )
    assert completion.parts[0].etag == "a1" * 16
    with pytest.raises(ValidationError, match="complete and ordered"):
        DirectModelUploadCompletion.model_validate(
            completion.model_dump(by_alias=True) | {"parts": completion.parts[1:]}
        )


@pytest.mark.parametrize("etag", ["short", "g" * 32, '"' + "a" * 32])
def test_part_rejects_non_provider_etags(etag):
    with pytest.raises(ValidationError):
        DirectModelUploadPart(part_number=1, size_bytes=1, etag=etag)
