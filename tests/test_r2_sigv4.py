from __future__ import annotations

from datetime import datetime, timezone
from urllib.parse import parse_qs, urlsplit

import pytest

from umi.r2_sigv4 import R2Credentials, R2SigV4, load_r2_credentials


def signer():
    return R2SigV4(
        endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
        bucket="umi-model-artifacts",
        credentials=R2Credentials(
            access_key_id="0123456789ABCDEF",
            secret_access_key="secret-access-key-value",
        ),
    )


def test_load_private_cloudflare_credential_export(tmp_path):
    path = tmp_path / "r2.env"
    path.write_text(
        "TOKEN_VALUE=unused-account-token\n"
        "ACCESS_KEY_ID=0123456789ABCDEF\n"
        "SECRET_ACCESS_KEY=secret-access-key-value\n"
        "DEFAULT_ENDPOINT=https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com\n"
    )
    path.chmod(0o600)
    loaded = load_r2_credentials(path)
    assert loaded.endpoint.endswith(".r2.cloudflarestorage.com")
    assert loaded.credentials.access_key_id == "0123456789ABCDEF"


def test_rejects_linked_or_public_credential_export(tmp_path):
    path = tmp_path / "r2.env"
    path.write_text("not-enough")
    path.chmod(0o644)
    with pytest.raises(ValueError):
        load_r2_credentials(path)
    path.chmod(0o600)
    link = tmp_path / "linked.env"
    link.symlink_to(path)
    with pytest.raises(OSError):
        load_r2_credentials(link)


def test_upload_part_url_is_deterministic_and_query_bound():
    at = datetime(2026, 10, 2, 20, 0, tzinfo=timezone.utc)
    first = signer().upload_part_url(
        "incoming/v2/aa/bb/cc/payload",
        upload_id="upload+/identity=",
        part_number=7,
        expires_seconds=3600,
        at=at,
    )
    assert first == signer().upload_part_url(
        "incoming/v2/aa/bb/cc/payload",
        upload_id="upload+/identity=",
        part_number=7,
        expires_seconds=3600,
        at=at,
    )
    parsed = urlsplit(first)
    query = parse_qs(parsed.query)
    assert parsed.path == "/umi-model-artifacts/incoming/v2/aa/bb/cc/payload"
    assert query["partNumber"] == ["7"]
    assert query["uploadId"] == ["upload+/identity="]
    assert query["X-Amz-Expires"] == ["3600"]
    assert len(query["X-Amz-Signature"][0]) == 64
    assert "secret-access-key-value" not in first
    changed = signer().upload_part_url(
        "incoming/v2/aa/bb/cc/payload",
        upload_id="upload+/identity=",
        part_number=8,
        expires_seconds=3600,
        at=at,
    )
    assert parse_qs(urlsplit(changed).query)["X-Amz-Signature"] != query["X-Amz-Signature"]


def test_credentials_do_not_print_secret():
    credentials = signer().credentials
    assert credentials.access_key_id in repr(credentials)
    assert credentials.secret_access_key not in repr(credentials)


def test_authorized_headers_bind_method_query_and_body_without_exposing_secret():
    at = datetime(2026, 10, 2, 20, 0, tzinfo=timezone.utc)
    values = {
        "method": "POST",
        "key": "incoming/v2/aa/payload",
        "query": (("uploadId", "provider-id"),),
        "body": b"<CompleteMultipartUpload/>",
        "at": at,
    }
    headers = signer().authorized_headers(**values)
    assert headers["X-Amz-Date"] == "20261002T200000Z"
    assert headers["X-Amz-Content-SHA256"] == (
        "0c96b0e6e570d37f36e885054140c744ad23a4d62704c396b8b43da729921caf"
    )
    assert "Credential=0123456789ABCDEF/20261002/auto/s3/aws4_request" in headers["Authorization"]
    assert "secret-access-key-value" not in str(headers)
    changed = signer().authorized_headers(**(values | {"body": b"changed"}))
    assert changed["Authorization"] != headers["Authorization"]


@pytest.mark.parametrize(
    "change",
    [
        {"endpoint": "http://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"},
        {"endpoint": "https://example.com"},
        {"endpoint": "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com/x"},
        {"bucket": "../other"},
    ],
)
def test_signer_rejects_non_r2_scope(change):
    values = {
        "endpoint": signer().endpoint,
        "bucket": signer().bucket,
        "credentials": signer().credentials,
    }
    with pytest.raises(ValueError):
        R2SigV4(**(values | change))


def test_presign_rejects_unbounded_capabilities():
    with pytest.raises(ValueError, match="expiry differs"):
        signer().presign("PUT", "incoming/object", expires_seconds=7 * 24 * 60 * 60 + 1)
    with pytest.raises(ValueError, match="method differs"):
        signer().presign("POST", "incoming/object", expires_seconds=60)
    with pytest.raises(ValueError, match="object key differs"):
        signer().presign("PUT", "../accepted/object", expires_seconds=60)
