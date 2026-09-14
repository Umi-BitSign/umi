from __future__ import annotations

import gzip
import hashlib
import json

import httpx
import pytest

from umi import drand
from umi.drand import (
    QUICKNET_CHAIN_HASH,
    QUICKNET_PUBLIC_KEY,
    DrandPulse,
    DrandVerificationError,
    QuicknetClient,
    QuicknetInfo,
    verify_quicknet_signature,
)

ROUND = 1_000_000
SIGNATURE = (
    "83ad29e4c409f9470fc2ef02f90214df49e02b441a1a241a82d622d9f608ef9"
    "8fd8b11a029f1bee9d9e83b45088abe72"
)
RANDOMNESS = "b22aad4794f7451896f7a371aa46106fd84d919f3f569acd5b2fddf1d1440af3"


class StaticStream(httpx.AsyncByteStream):
    def __init__(self, body: bytes) -> None:
        self.body = body

    async def __aiter__(self):
        yield self.body

    async def aclose(self) -> None:
        return None


def json_response(record: dict, *, headers: dict[str, str] | None = None) -> httpx.Response:
    return httpx.Response(
        200,
        headers={"Content-Type": "application/json", **(headers or {})},
        stream=StaticStream(json.dumps(record).encode()),
    )


def info_record() -> dict:
    return {
        "public_key": QUICKNET_PUBLIC_KEY,
        "period": 3,
        "genesis_time": 1692803367,
        "hash": QUICKNET_CHAIN_HASH,
        "groupHash": "f477d5c89f21a17c863a7f937c6a6d15859414d2be09cd448d4279af331c5d3e",
        "schemeID": "bls-unchained-g1-rfc9380",
        "metadata": {"beaconID": "quicknet"},
    }


def pulse_record() -> dict:
    return {"round": ROUND, "randomness": RANDOMNESS, "signature": SIGNATURE}


def test_pinned_quicknet_vector_verifies_independently() -> None:
    pulse = DrandPulse.from_json(pulse_record(), expected_round=ROUND)

    assert verify_quicknet_signature(ROUND, bytes.fromhex(SIGNATURE))
    assert hashlib.sha256(pulse.signature_bytes).hexdigest() == RANDOMNESS
    assert len(bytes.fromhex(pulse.evidence_digest)) == 32


def test_tampered_round_signature_randomness_and_info_fail_closed() -> None:
    assert not verify_quicknet_signature(ROUND + 1, bytes.fromhex(SIGNATURE))
    assert not verify_quicknet_signature(ROUND, bytes.fromhex(SIGNATURE[:-2] + "00"))

    wrong_randomness = pulse_record()
    wrong_randomness["randomness"] = "00" * 32
    with pytest.raises(DrandVerificationError, match="SHA-256"):
        DrandPulse.from_json(wrong_randomness, expected_round=ROUND)

    wrong_info = info_record()
    wrong_info["public_key"] = "00" * 96
    with pytest.raises(DrandVerificationError, match="does not match"):
        QuicknetInfo.from_json(wrong_info)


@pytest.fixture
def empty_bls_cache():
    drand._verify_quicknet_signature_cached.cache_clear()
    yield drand._verify_quicknet_signature_cached
    drand._verify_quicknet_signature_cached.cache_clear()


def test_repeated_pulse_reuses_only_exact_bls_verification(empty_bls_cache, monkeypatch):
    calls = []
    original = drand.pairing

    def pairing(*args, **kwargs):
        calls.append(1)
        return original(*args, **kwargs)

    monkeypatch.setattr(drand, "pairing", pairing)
    pulse = DrandPulse.from_json(pulse_record(), expected_round=ROUND)
    assert len(calls) == 2
    pulse.verify()
    assert verify_quicknet_signature(ROUND, bytes.fromhex(SIGNATURE))
    assert len(calls) == 2 and empty_bls_cache.cache_info().hits == 2
    with pytest.raises(DrandVerificationError, match="different round"):
        DrandPulse.from_json(pulse_record(), expected_round=ROUND + 1)
    with pytest.raises(DrandVerificationError, match="SHA-256"):
        DrandPulse(ROUND, "00" * 32, SIGNATURE).verify()
    assert not verify_quicknet_signature(ROUND + 1, bytes.fromhex(SIGNATURE))
    assert not verify_quicknet_signature(ROUND, bytes.fromhex(SIGNATURE[:-2] + "00"))
    assert empty_bls_cache.cache_info().misses == 3


@pytest.mark.parametrize(
    ("constant", "value", "valid"),
    [
        ("QUICKNET_PUBLIC_KEY", "00" * 96, False),
        ("QUICKNET_DST", b"a-different-signature-domain", False),
        ("QUICKNET_CHAIN_HASH", "00" * 32, True),
    ],
)
def test_bls_cache_key_includes_complete_trust_tuple(
    empty_bls_cache, monkeypatch, constant, value, valid
):
    signature = bytes.fromhex(SIGNATURE)
    assert verify_quicknet_signature(ROUND, signature)
    monkeypatch.setattr(drand, constant, value)
    # A different chain label alone leaves the mathematical equation unchanged,
    # but must still miss the cache. Chain pin validation is a separate check.
    assert verify_quicknet_signature(ROUND, signature) is valid
    assert empty_bls_cache.cache_info().misses == 2
    assert empty_bls_cache.cache_info().hits == 0


@pytest.mark.parametrize("number", [True, float(ROUND), 0, -1, 2**64, [], None])
def test_round_type_and_bounds_are_checked_before_bls_cache(empty_bls_cache, number):
    assert not verify_quicknet_signature(number, bytes.fromhex(SIGNATURE))
    assert empty_bls_cache.cache_info().misses == 0


@pytest.mark.parametrize("signature", [None, [], bytearray(48), b"", b"a" * 49])
def test_signature_shape_is_checked_before_bls_cache(empty_bls_cache, signature):
    assert not verify_quicknet_signature(ROUND, signature)
    assert empty_bls_cache.cache_info().misses == 0


def test_bls_verification_cache_is_bounded(empty_bls_cache, monkeypatch):
    def malformed_point(_):
        raise ValueError("synthetic malformed point")

    monkeypatch.setattr(drand, "decompress_G1", malformed_point)
    signature = bytes.fromhex(SIGNATURE)
    for number in range(1, 300):
        assert not verify_quicknet_signature(number, signature)
    assert empty_bls_cache.cache_info().maxsize == 256
    assert empty_bls_cache.cache_info().currsize == 256


@pytest.mark.asyncio
async def test_client_checks_info_round_body_ceiling_and_signature() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/info"):
            return json_response(info_record())
        return json_response(pulse_record())

    client = QuicknetClient(transport=httpx.MockTransport(handler))
    pulse = await client.fetch(ROUND)
    assert pulse.round == ROUND

    oversized = QuicknetClient(
        maximum_body_bytes=8,
        transport=httpx.MockTransport(handler),
    )
    with pytest.raises(DrandVerificationError, match="byte ceiling"):
        await oversized.fetch(ROUND)

    def bloated_headers(request: httpx.Request) -> httpx.Response:
        record = info_record() if request.url.path.endswith("/info") else pulse_record()
        return json_response(record, headers={"X-Bloat": "a" * 128})

    header_bounded = QuicknetClient(
        maximum_header_bytes=64,
        transport=httpx.MockTransport(bloated_headers),
    )
    with pytest.raises(DrandVerificationError, match="headers exceed"):
        await header_bounded.fetch(ROUND)


@pytest.mark.asyncio
async def test_client_rejects_unpublished_round_before_network() -> None:
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(500)

    client = QuicknetClient(transport=httpx.MockTransport(handler))
    with pytest.raises(DrandVerificationError, match="not published"):
        await client.fetch(10**12)
    assert not called


@pytest.mark.asyncio
async def test_client_rejects_encoded_body_before_decompression_or_body_read() -> None:
    encoded = gzip.compress(b"x" * (8 * 1024 * 1024))
    assert len(encoded) < 64 * 1024

    class EncodedStream(httpx.AsyncByteStream):
        iterated = False

        async def __aiter__(self):
            self.iterated = True
            yield encoded

        async def aclose(self) -> None:
            return None

    stream = EncodedStream()

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["accept-encoding"] == "identity"
        if request.url.path.endswith("/info"):
            return httpx.Response(
                200,
                headers={
                    "Content-Encoding": "gzip",
                    "Content-Length": str(len(encoded)),
                },
                stream=stream,
            )
        return json_response(pulse_record())

    client = QuicknetClient(transport=httpx.MockTransport(handler))
    with pytest.raises(DrandVerificationError, match="Content-Encoding"):
        await client.fetch(ROUND)
    assert not stream.iterated
