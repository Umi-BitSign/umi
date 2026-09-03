"""Pinned Quicknet retrieval and independent RFC 9380 BLS verification."""

from __future__ import annotations

import asyncio
import hashlib
import re
from dataclasses import dataclass
from typing import Any

import httpx
from py_ecc.bls.hash_to_curve import hash_to_G1
from py_ecc.bls.point_compression import decompress_G1, decompress_G2
from py_ecc.optimized_bls12_381 import G2, Z1, Z2, curve_order, eq, multiply, pairing

from .encoding import sha256_domain, u64be
from .protocol import canonical_json_bytes
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

QUICKNET_CHAIN_HASH = "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971"
QUICKNET_PUBLIC_KEY = (
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183"
    "c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4"
    "bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a"
)
QUICKNET_SCHEME_ID = "bls-unchained-g1-rfc9380"
QUICKNET_BEACON_ID = "quicknet"
QUICKNET_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"
QUICKNET_API = f"https://api.drand.sh/{QUICKNET_CHAIN_HASH}"

_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")
_HEX_G1_RE = re.compile(r"^[0-9a-f]{96}$")


class DrandVerificationError(RuntimeError):
    """A Quicknet tuple, round, randomness value, or BLS signature is invalid."""


@dataclass(frozen=True)
class QuicknetInfo:
    public_key: str
    period: int
    genesis_time: int
    chain_hash: str
    group_hash: str
    scheme_id: str
    beacon_id: str

    @classmethod
    def from_json(cls, value: Any) -> QuicknetInfo:
        if not isinstance(value, dict):
            raise DrandVerificationError("Quicknet info must be a JSON object")
        metadata = value.get("metadata")
        if not isinstance(metadata, dict):
            raise DrandVerificationError("Quicknet info is missing metadata")
        try:
            info = cls(
                public_key=str(value["public_key"]),
                period=int(value["period"]),
                genesis_time=int(value["genesis_time"]),
                chain_hash=str(value["hash"]),
                group_hash=str(value["groupHash"]),
                scheme_id=str(value["schemeID"]),
                beacon_id=str(metadata["beaconID"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise DrandVerificationError("Quicknet info has invalid fields") from error
        info.require_pinned()
        return info

    def require_pinned(self) -> None:
        expected = (
            QUICKNET_PUBLIC_KEY,
            QUICKNET_PERIOD_MS // 1000,
            QUICKNET_GENESIS_MS // 1000,
            QUICKNET_CHAIN_HASH,
            QUICKNET_SCHEME_ID,
            QUICKNET_BEACON_ID,
        )
        actual = (
            self.public_key,
            self.period,
            self.genesis_time,
            self.chain_hash,
            self.scheme_id,
            self.beacon_id,
        )
        if actual != expected:
            raise DrandVerificationError("remote drand information does not match Quicknet")
        if _HEX_32_RE.fullmatch(self.group_hash) is None:
            raise DrandVerificationError("Quicknet group hash is malformed")


@dataclass(frozen=True)
class DrandPulse:
    round: int
    randomness: str
    signature: str

    @classmethod
    def from_json(cls, value: Any, *, expected_round: int) -> DrandPulse:
        if not isinstance(value, dict) or set(value) != {"round", "randomness", "signature"}:
            raise DrandVerificationError("drand pulse has an unexpected JSON shape")
        try:
            pulse = cls(
                round=int(value["round"]),
                randomness=str(value["randomness"]),
                signature=str(value["signature"]),
            )
        except (TypeError, ValueError) as error:
            raise DrandVerificationError("drand pulse fields are malformed") from error
        if pulse.round != expected_round:
            raise DrandVerificationError("drand pulse is for a different round")
        pulse.verify()
        return pulse

    def verify(self) -> None:
        if isinstance(self.round, bool) or not isinstance(self.round, int) or self.round <= 0:
            raise DrandVerificationError("drand round must be a positive integer")
        if _HEX_32_RE.fullmatch(self.randomness) is None:
            raise DrandVerificationError("drand randomness must be 32 lowercase hex bytes")
        if _HEX_G1_RE.fullmatch(self.signature) is None:
            raise DrandVerificationError("Quicknet signature must be 48 lowercase hex bytes")
        signature_bytes = bytes.fromhex(self.signature)
        if hashlib.sha256(signature_bytes).hexdigest() != self.randomness:
            raise DrandVerificationError("drand randomness is not SHA-256 of the signature")
        if not verify_quicknet_signature(self.round, signature_bytes):
            raise DrandVerificationError("Quicknet BLS signature does not verify")

    @property
    def signature_bytes(self) -> bytes:
        return bytes.fromhex(self.signature)

    @property
    def evidence_digest(self) -> str:
        return sha256_domain(
            b"umi-drand-pulse-v1\0",
            canonical_json_bytes(
                {
                    "chain_hash": QUICKNET_CHAIN_HASH,
                    "pulse": {
                        "randomness": self.randomness,
                        "round": self.round,
                        "signature": self.signature,
                    },
                }
            ),
        ).hex()


def verify_quicknet_signature(round_number: int, signature: bytes) -> bool:
    """Verify Quicknet's G1 signature over SHA256(U64BE(round))."""

    if isinstance(round_number, bool) or not isinstance(round_number, int) or round_number <= 0:
        return False
    if not isinstance(signature, bytes) or len(signature) != 48:
        return False
    public_key = bytes.fromhex(QUICKNET_PUBLIC_KEY)
    try:
        signature_point = decompress_G1(int.from_bytes(signature, "big"))
        public_key_point = decompress_G2(
            (
                int.from_bytes(public_key[:48], "big"),
                int.from_bytes(public_key[48:], "big"),
            )
        )
        if not eq(multiply(signature_point, curve_order), Z1):
            return False
        if not eq(multiply(public_key_point, curve_order), Z2):
            return False
        message = hashlib.sha256(u64be(round_number)).digest()
        message_point = hash_to_G1(message, QUICKNET_DST, hashlib.sha256)
        return pairing(G2, signature_point) == pairing(public_key_point, message_point)
    except (TypeError, ValueError, OverflowError):
        return False


@dataclass(frozen=True)
class QuicknetClient:
    base_url: str = QUICKNET_API
    timeout_seconds: float = 15.0
    maximum_body_bytes: int = 64 * 1024
    maximum_header_bytes: int = 16 * 1024
    transport: httpx.AsyncBaseTransport | None = None

    def __post_init__(self) -> None:
        if self.base_url.rstrip("/") != QUICKNET_API:
            raise ValueError("Quicknet client must use the policy-pinned chain-hash endpoint")
        if (
            self.timeout_seconds <= 0
            or self.maximum_body_bytes <= 0
            or self.maximum_header_bytes <= 0
        ):
            raise ValueError("Quicknet client limits must be positive")

    async def fetch(self, round_number: int, *, require_published: bool = True) -> DrandPulse:
        if round_number <= 0:
            raise ValueError("drand round must be positive")
        if require_published:
            import bittensor as bt

            if round_number > bt.timelock.current_round():
                raise DrandVerificationError("requested Quicknet round is not published")
        async with httpx.AsyncClient(
            timeout=self.timeout_seconds,
            follow_redirects=False,
            transport=self.transport,
            trust_env=False,
            headers={"Accept-Encoding": "identity"},
        ) as client:
            info_record, pulse_record = await asyncio.gather(
                self._get_json(client, "/info"),
                self._get_json(client, f"/public/{round_number}"),
            )
        QuicknetInfo.from_json(info_record)
        return DrandPulse.from_json(pulse_record, expected_round=round_number)

    async def _get_json(self, client: httpx.AsyncClient, path: str) -> Any:
        try:
            async with client.stream("GET", self.base_url.rstrip("/") + path) as response:
                if response.status_code != 200:
                    raise DrandVerificationError(
                        f"Quicknet endpoint returned HTTP {response.status_code}"
                    )
                if _raw_header_size(response.headers) > self.maximum_header_bytes:
                    raise DrandVerificationError(
                        "Quicknet response headers exceed the byte ceiling"
                    )
                content_encoding = response.headers.get("content-encoding")
                if content_encoding is not None and content_encoding.strip().lower() != "identity":
                    raise DrandVerificationError(
                        "Quicknet response Content-Encoding must be identity"
                    )
                body = bytearray()
                async for chunk in response.aiter_raw():
                    if len(body) + len(chunk) > self.maximum_body_bytes:
                        raise DrandVerificationError("Quicknet response exceeds its byte ceiling")
                    body.extend(chunk)
        except httpx.HTTPError as error:
            raise DrandVerificationError("Quicknet retrieval failed") from error
        try:
            import json

            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise DrandVerificationError("Quicknet response is not valid JSON") from error


def _raw_header_size(headers: httpx.Headers) -> int:
    return sum(len(name) + len(value) + 4 for name, value in headers.raw)


__all__ = [
    "QUICKNET_API",
    "QUICKNET_BEACON_ID",
    "QUICKNET_CHAIN_HASH",
    "QUICKNET_DST",
    "QUICKNET_PUBLIC_KEY",
    "QUICKNET_SCHEME_ID",
    "DrandPulse",
    "DrandVerificationError",
    "QuicknetClient",
    "QuicknetInfo",
    "verify_quicknet_signature",
]
