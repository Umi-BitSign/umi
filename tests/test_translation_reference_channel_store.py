"""Real SigV4 client and conditional headers against a bounded synthetic R2 port."""

import hashlib
import json

import httpx
import pytest

from umi.r2_evidence import R2EvidenceClient
from umi.r2_sigv4 import R2Credentials, R2SigV4
from umi.translation_reference_channel import ChannelObject, ReferenceChannelConflict
from umi.translation_reference_channel_store import R2ReferenceChannelStore


@pytest.fixture
def store():
    objects, requests = {}, []
    prefix = "validator-supervisor/channels/" + "a1" * 32 + "/linux-amd64/after/"

    def handle(request):
        requests.append(request)
        assert request.url.scheme == "https" and request.headers["authorization"].startswith(
            "AWS4-HMAC-SHA256 "
        )
        assert (
            "if-match" in request.headers.get("authorization", "")
            if "if-match" in request.headers
            else True
        )
        key = request.url.path.removeprefix("/test-bucket/")
        current = objects.get(key)
        if request.method in {"GET", "HEAD"}:
            if current is None:
                return httpx.Response(404)
            raw, etag, metadata = current
            return httpx.Response(
                200,
                content=raw if request.method == "GET" else b"",
                headers={"ETag": etag, "Content-Length": str(len(raw)), **metadata},
            )
        assert request.method == "PUT"
        assert (
            request.headers["x-amz-content-sha256"] == hashlib.sha256(request.content).hexdigest()
        )
        if (request.headers.get("if-none-match") == "*" and current is not None) or (
            "if-match" in request.headers
            and (current is None or request.headers["if-match"] != current[1])
        ):
            return httpx.Response(412)
        etag = '"' + hashlib.md5(request.content, usedforsecurity=False).hexdigest() + '"'
        objects[key] = (
            request.content,
            etag,
            {k: v for k, v in request.headers.items() if k.startswith("x-amz-meta-")},
        )
        return httpx.Response(200, headers={"ETag": etag})

    signer = R2SigV4(
        "https://" + "a" * 32 + ".r2.cloudflarestorage.com",
        "test-bucket",
        R2Credentials("b" * 32, "synthetic-private-key"),
    )
    client = R2EvidenceClient(signer, transport=httpx.MockTransport(handle))
    return R2ReferenceChannelStore(client, channel_prefix=prefix), prefix, objects, requests


def test_conditional_create_update_stale_writer_and_readback(store):
    client, prefix, _objects, requests = store
    key = prefix + "0/initial.json"
    assert client.read(key) is None
    first = b'{"head":1}'
    client.compare_and_swap(key, None, first)
    prior = client.read(key)
    assert prior.payload == first
    second = b'{"head":2}'
    client.compare_and_swap(key, prior, second)
    assert client.read(key).payload == second
    with pytest.raises(ReferenceChannelConflict):
        client.compare_and_swap(key, prior, b"old writer")
    with pytest.raises(ReferenceChannelConflict):
        client.compare_and_swap(key, None, b"cannot replace")
    assert client.read(key).payload == second
    writes = [r for r in requests if r.method == "PUT"]
    assert writes[0].headers["if-none-match"] == "*"
    assert writes[1].headers["if-match"] == prior.etag
    assert writes[1].headers["cache-control"].startswith("no-store")


def test_immutable_approval_exact_retry_does_not_overwrite_original(store):
    client, _, objects, requests = store
    key = "validator-supervisor/translation-reference-policies/" + "c1" * 32 + ".json"
    raw = b'{"signed":"policy"}'
    client.publish_approval(key, raw)
    client.publish_approval(key, raw)
    assert sum(r.method == "PUT" for r in requests) == 1
    with pytest.raises(ValueError, match="immutable"):
        client.publish_approval(key, b"changed policy signature")
    assert objects[key][0] == raw


@pytest.mark.parametrize(
    "suffix", ["../elsewhere", "00/initial.json", "1/initial.json", "0/different.json"]
)
def test_other_namespaces_and_noncanonical_cursors_refuse_before_io(store, suffix):
    client, prefix, _, requests = store
    with pytest.raises(ValueError):
        client.compare_and_swap(prefix + suffix, None, b"{}")
    assert not requests


def test_control_read_rejects_missing_or_unsafe_generation_and_oversize_response(store):
    client, prefix, objects, _ = store
    key = prefix + "0/initial.json"
    objects[key] = (b"{}", 'W/"weak-generation"', {})
    with pytest.raises(ValueError, match="generation"):
        client.read(key)
    objects[key] = (b"0" * (1024**2 + 1), '"generation"', {})
    with pytest.raises(ValueError, match="byte bound"):
        client.read(key)
    with pytest.raises(ValueError, match="generation"):
        client.compare_and_swap(key, ChannelObject(b"{}", '"bad\nheader"'), b"{}")


def test_unsigned_control_bytes_still_need_channel_schema_and_authority_checks(store):
    client, prefix, _, _ = store
    # Conditional storage is transport, not proof of a signed directive.
    key = prefix + "0/initial.json"
    raw = json.dumps({"not": "a signed channel page"}).encode()
    client.compare_and_swap(key, None, raw)
    assert client.read(key).payload == raw
