"""Bounded authenticated gateway through the actual R2 channel-store consumer."""

import hashlib

import httpx
import pytest

from umi.translation_reference_channel import ReferenceChannelConflict
from umi.translation_reference_channel_store import R2ReferenceChannelStore
from umi.translation_reference_gateway import (
    REFERENCE_GATEWAY_ORIGIN,
    R2ReferenceGatewayClient,
)
from umi.validator_supervisor import COMMON_SUPERVISOR_CHANNELS


def test_gateway_client_channel_and_immutable_retry_consumer():
    objects, requests = {}, []
    token = "c" * 64

    def handler(request):
        requests.append(request)
        assert str(request.url).startswith(REFERENCE_GATEWAY_ORIGIN + "/")
        assert request.headers["Authorization"] == "Bearer " + token
        key = request.url.path[1:]
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
        if (current is not None and request.headers.get("If-None-Match") == "*") or (
            "If-Match" in request.headers
            and (current is None or current[1] != request.headers["If-Match"])
        ):
            return httpx.Response(412)
        etag = '"' + hashlib.md5(request.content, usedforsecurity=False).hexdigest() + '"'
        objects[key] = (
            request.content,
            etag,
            {k: v for k, v in request.headers.items() if k.startswith("x-amz-meta-")},
        )
        return httpx.Response(200)

    client = R2ReferenceGatewayClient(
        REFERENCE_GATEWAY_ORIGIN, token, transport=httpx.MockTransport(handler)
    )
    prefix = (
        "validator-supervisor/channels/"
        + COMMON_SUPERVISOR_CHANNELS["linux/amd64"]
        + "/linux-amd64/after/"
    )
    store = R2ReferenceChannelStore(client, channel_prefix=prefix)
    key = prefix + "0/initial.json"
    assert store.read(key) is None
    store.compare_and_swap(key, None, b"original")
    old = store.read(key)
    store.compare_and_swap(key, old, b"current")
    with pytest.raises(ReferenceChannelConflict):
        store.compare_and_swap(key, old, b"stale")
    assert store.read(key).payload == b"current"
    approval = "validator-supervisor/translation-reference-policies/" + "e" * 64 + ".json"
    store.publish_approval(approval, b"signed approval")
    store.publish_approval(approval, b"signed approval")
    with pytest.raises(ValueError, match="immutable"):
        store.publish_approval(approval, b"changed")
    assert sum(r.method == "PUT" and r.url.path[1:] == approval for r in requests) == 1


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(302, headers={"Location": "https://other.example/"}),
        httpx.Response(200, content=b"overflow"),
        httpx.Response(200, headers={"Content-Encoding": "gzip"}),
    ],
)
def test_no_redirect_encoded_or_oversized_response_can_escape_its_bound(response):
    calls = []

    def handler(request):
        calls.append(request)
        return response

    client = R2ReferenceGatewayClient(
        REFERENCE_GATEWAY_ORIGIN, "a" * 64, transport=httpx.MockTransport(handler)
    )
    key = "validator-supervisor/translation-reference-policies/" + "a" * 64 + ".json"
    with pytest.raises((OSError, ValueError)):
        client._exchange("GET", key, maximum=1)
    assert len(calls) == 1


def test_other_origin_namespace_delete_or_auth_override_refuse_before_network():
    with pytest.raises(ValueError):
        R2ReferenceGatewayClient("https://untrusted.example", "a" * 64)

    def forbidden(request):
        pytest.fail("invalid gateway request reached transport")

    client = R2ReferenceGatewayClient(
        REFERENCE_GATEWAY_ORIGIN, "a" * 64, transport=httpx.MockTransport(forbidden)
    )
    with pytest.raises(ValueError):
        client._exchange("GET", "models/private")
    key = "validator-supervisor/translation-reference-policies/" + "a" * 64 + ".json"
    with pytest.raises(ValueError):
        client._exchange("DELETE", key)
    with pytest.raises(ValueError):
        client._exchange("GET", key, headers={"authorization": "override"})
