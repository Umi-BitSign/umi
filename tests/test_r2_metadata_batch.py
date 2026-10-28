"""A metadata batch changes transport, never source identity or byte rules."""

import hashlib
import hmac
import json

import httpx
import pytest

from umi.r2_metadata_batch import (
    HEAD_BATCH_PATH,
    KEY_PURPOSE,
    R2MetadataBatchUnavailable,
    derived_metadata_key,
)
from umi.r2_multipart import R2MultipartClient
from umi.r2_sigv4 import R2Credentials, R2SigV4, load_r2_credentials

ENDPOINT = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com"
ORIGIN = "https://artifacts.example"
ACCESS = "A" * 20
SECRET = "S" * 40


def signer(origin=ORIGIN):
    return R2SigV4(ENDPOINT, "umi-model-artifacts", R2Credentials(ACCESS, SECRET, origin))


def response(request, objects=None, **changes):
    body = json.loads(request.content)
    value = dict(
        schema="umi-r2-head-batch-response/1",
        nonce=body["nonce"],
        endpoint=body["endpoint"],
        bucket=body["bucket"],
        objects=objects
        if objects is not None
        else [dict(key=k, status=200, size_bytes=5, etag="etag") for k in body["keys"]],
    )
    value.update(changes)
    return value


async def test_purpose_key_signature_source_binding_and_fresh_nonce():
    requests = []

    def handle(request):
        requests.append(request)
        assert request.url == ORIGIN + HEAD_BATCH_PATH
        key = hmac.digest(SECRET.encode(), KEY_PURPOSE, "sha256")
        signed = b"POST\n" + HEAD_BATCH_PATH.encode() + b"\n" + request.content
        assert (
            request.headers["authorization"]
            == "UMI-R2-Metadata/1 "
            + ACCESS
            + ":"
            + hmac.new(key, signed, hashlib.sha256).hexdigest()
        )
        assert SECRET.encode() not in request.content
        return httpx.Response(200, json=response(request))

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(handle))
    assert client.head_batch_limit == 32
    async with client.connection_scope():
        a = await client.head_batch(("one", "two"))
        b = await client.head_batch(("one", "two"))
    assert a == b and a["one"].size_bytes == 5
    assert json.loads(requests[0].content)["nonce"] != json.loads(requests[1].content)["nonce"]
    assert derived_metadata_key(SECRET) == hmac.digest(SECRET.encode(), KEY_PURPOSE, "sha256")


@pytest.mark.parametrize(
    "change",
    [
        {"nonce": "0" * 32},
        {"endpoint": "https://other.example"},
        {"bucket": "other-bucket"},
        {"extra": True},
        {"objects": []},
        {"objects": [{"key": "different", "status": 404}]},
        {"objects": [{"key": "one", "status": 200, "size_bytes": True, "etag": "e"}]},
        {"objects": [{"key": "one", "status": 200, "size_bytes": -1, "etag": "e"}]},
        {"objects": [{"key": "one", "status": 200, "size_bytes": 1, "etag": ""}]},
        {"objects": [{"key": "one", "status": 200.0, "size_bytes": 1, "etag": "e"}]},
        {"objects": [{"key": "one", "status": 404, "extra": 1}]},
    ],
)
async def test_malformed_or_foreign_batch_does_not_supply_a_head(change):
    def handle(request):
        return httpx.Response(200, json=response(request, **change))

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(handle))
    with pytest.raises(R2MetadataBatchUnavailable, match="transport unavailable"):
        await client.head_batch(("one",))


async def test_missing_and_individually_unavailable_objects_remain_distinct():
    def handle(request):
        return httpx.Response(
            200,
            json=response(
                request,
                objects=[dict(key="missing", status=404), dict(key="unavailable", status=503)],
            ),
        )

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(handle))
    assert await client.head_batch(("missing", "unavailable")) == {
        "missing": None,
        "unavailable": 503,
    }


@pytest.mark.parametrize("failure", ["status", "type", "oversized", "transport"])
async def test_transport_failure_is_redacted_and_bounded(failure):
    def handle(request):
        if failure == "transport":
            raise httpx.ConnectError("private diagnostic", request=request)
        if failure == "status":
            return httpx.Response(429)
        if failure == "type":
            return httpx.Response(200, text="not JSON")
        return httpx.Response(
            200, content=b"x" * (65536 + 1), headers={"content-type": "application/json"}
        )

    client = R2MultipartClient(signer(), transport=httpx.MockTransport(handle))
    with pytest.raises(R2MetadataBatchUnavailable) as raised:
        await client.head_batch(("one",))
    assert "private diagnostic" not in str(raised.value)
    assert raised.value.http_status == (429 if failure == "status" else None)


@pytest.mark.parametrize(
    "keys", [(), ("one", "one"), ("one", []), ("x" * 1025,), tuple(str(i) for i in range(33))]
)
async def test_key_bounds_refuse_before_network(keys):
    def forbidden(request):
        raise AssertionError("invalid batch contacted provider")

    with pytest.raises(ValueError):
        await R2MultipartClient(signer(), transport=httpx.MockTransport(forbidden)).head_batch(keys)


@pytest.mark.parametrize(
    "origin",
    [
        "http://local",
        "https://host/path",
        "https://host/",
        "https://user:secret@host",
        "https://host?q=1",
        "https://host#x",
        "https://host:443",
        False,
    ],
)
def test_noncanonical_origin_refuses(origin):
    with pytest.raises(ValueError):
        signer(origin)


def test_historical_credential_export_is_unchanged_and_new_copy_opts_in(tmp_path):
    original = (
        f"TOKEN_VALUE=private\nACCESS_KEY_ID={ACCESS}\nSECRET_ACCESS_KEY={SECRET}\nDEFAULT_ENDPOINT={ENDPOINT}\n"
    ).encode()
    old = tmp_path / "old.env"
    old.write_bytes(original)
    old.chmod(0o600)
    assert load_r2_credentials(old).credentials.metadata_batch_origin is None
    new = tmp_path / "new.env"
    new.write_bytes(original + f"METADATA_BATCH_ORIGIN={ORIGIN}\n".encode())
    new.chmod(0o600)
    assert load_r2_credentials(new).credentials.metadata_batch_origin == ORIGIN
    assert old.read_bytes() == original
