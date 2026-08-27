"""Bittensor v11 adapters for sealed and hotkey-signed UMI responses.

``bittensor`` is imported only when an operation needs it.  This keeps the
protocol models and deterministic scoring code importable in environments
that do not have the chain SDK installed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
from dataclasses import dataclass
from typing import Any

from py_ecc.bls.point_compression import compress_G2, decompress_G2
from py_ecc.optimized_bls12_381 import Z2, curve_order, eq, multiply

_BASE64URL_RE = re.compile(r"[A-Za-z0-9_-]+\Z")
_DIGEST_HEX_RE = re.compile(r"[0-9a-f]{64}\Z")
_SIGNATURE_RE = re.compile(r"0x[0-9a-f]{128}\Z")
_MAX_U64 = (1 << 64) - 1
_AES_GCM_MARKER = b"AES_GCM_"


class TimelockDecryptionError(RuntimeError):
    """A structurally valid portable timelock could not be opened."""


@dataclass(frozen=True, slots=True)
class SealedResponse:
    """One canonical portable timelock envelope and its redundant anchors."""

    portable_bytes: bytes
    portable_b64: str
    reveal_round: int
    sha256_hex: str

    def __post_init__(self) -> None:
        _require_reveal_round(self.reveal_round)
        if not isinstance(self.portable_bytes, bytes) or not self.portable_bytes:
            raise ValueError("portable_bytes must be non-empty bytes")
        decoded = _stdlib_b64url_decode(self.portable_b64)
        if decoded != self.portable_bytes:
            raise ValueError("portable_b64 does not encode portable_bytes")
        _require_sha256_hex(self.sha256_hex)
        actual_hash = hashlib.sha256(self.portable_bytes).hexdigest()
        if not hmac.compare_digest(actual_hash, self.sha256_hex):
            raise ValueError("sha256_hex does not match portable_bytes")


def seal_response(plaintext: bytes, *, reveal_round: int) -> SealedResponse:
    """Timelock ``plaintext`` to exactly ``reveal_round``.

    The returned bytes are the portable form emitted by Bittensor 11.1.0,
    represented on the wire as strict, unpadded base64url.
    """

    if not isinstance(plaintext, bytes):
        raise TypeError("plaintext must be bytes")
    expected_round = _require_reveal_round(reveal_round)
    bt = _bittensor()
    sealed = bt.timelock.encrypt(plaintext, reveal_round=expected_round)
    portable = bytes(sealed)
    _validate_portable_layout(portable, expected_round)
    parsed = bt.timelock.Timelocked.parse(portable)
    if parsed.reveal_round != expected_round or sealed.reveal_round != expected_round:
        raise ValueError("Bittensor timelock returned a different reveal round")
    return _sealed_record(portable, parsed.reveal_round)


def parse_sealed_response(
    portable_b64: str,
    *,
    reveal_round: int,
    sha256_hex: str | None = None,
) -> SealedResponse:
    """Strictly decode and parse a portable response timelock.

    ``reveal_round`` is always explicit so the caller checks the request round
    against the independently embedded timelock round.  When supplied,
    ``sha256_hex`` is the response envelope's committed ciphertext hash.
    """

    expected_round = _require_reveal_round(reveal_round)
    portable = _decode_portable(portable_b64)
    actual_hash = hashlib.sha256(portable).hexdigest()
    if sha256_hex is not None:
        _require_sha256_hex(sha256_hex)
        if not hmac.compare_digest(actual_hash, sha256_hex):
            raise ValueError("portable timelock SHA-256 does not match")
    _validate_portable_layout(portable, expected_round)

    bt = _bittensor()
    try:
        parsed = bt.timelock.Timelocked.parse(portable)
    except Exception as error:
        raise ValueError("invalid Bittensor portable timelock") from error
    if parsed.reveal_round != expected_round:
        raise ValueError("embedded timelock round does not match reveal_round")
    return SealedResponse(
        portable_bytes=portable,
        portable_b64=portable_b64,
        reveal_round=parsed.reveal_round,
        sha256_hex=actual_hash,
    )


def decrypt_response(
    sealed: SealedResponse | str,
    *,
    reveal_round: int,
    sha256_hex: str | None = None,
    wait: bool = False,
    timeout: float | None = None,
) -> bytes:
    """Validate all public anchors, then decrypt through Bittensor timelock."""

    if isinstance(sealed, SealedResponse):
        if sealed.reveal_round != reveal_round:
            raise ValueError("sealed response round does not match reveal_round")
        if sha256_hex is not None and not hmac.compare_digest(sealed.sha256_hex, sha256_hex):
            raise ValueError("sealed response SHA-256 does not match")
        record = parse_sealed_response(
            sealed.portable_b64,
            reveal_round=reveal_round,
            sha256_hex=sha256_hex or sealed.sha256_hex,
        )
    elif isinstance(sealed, str):
        record = parse_sealed_response(
            sealed,
            reveal_round=reveal_round,
            sha256_hex=sha256_hex,
        )
    else:
        raise TypeError("sealed must be a SealedResponse or base64url string")

    bt = _bittensor()
    parsed = bt.timelock.Timelocked.parse(record.portable_bytes)
    try:
        return bytes(bt.timelock.decrypt(parsed, wait=wait, timeout=timeout))
    except bt.timelock.TimelockError as error:
        raise TimelockDecryptionError(str(error)) from error


def sign_response_digest(wallet: Any, response_or_digest: Any) -> tuple[str, str]:
    """Sign the raw 32-byte UMI response digest with ``wallet``'s hotkey."""

    digest = _coerce_response_digest(response_or_digest)
    bt = _bittensor()
    signer = bt.resolve_signer(wallet, role="hotkey")
    scheme = _scheme_for_crypto_type(bt, signer.crypto_type)
    signature = signer.sign(digest)
    if not isinstance(signature, (bytes, bytearray)):
        raise TypeError(
            "response signing requires a synchronous signer; "
            f"sign() returned {type(signature).__name__}"
        )
    signature_bytes = bytes(signature)
    if len(signature_bytes) != 64:
        raise ValueError("Bittensor hotkey signature must be exactly 64 bytes")
    return scheme, "0x" + signature_bytes.hex()


def verify_response_signature(
    response_or_digest: Any,
    *,
    hotkey_ss58: str,
    scheme: str,
    signature: str,
) -> bool:
    """Verify only the explicitly declared signature scheme.

    Malformed inputs fail closed.  In particular, this function never retries
    verification with the other Bittensor signature scheme.
    """

    try:
        digest = _coerce_response_digest(response_or_digest)
        if not isinstance(hotkey_ss58, str) or not hotkey_ss58:
            return False
        if not isinstance(signature, str) or _SIGNATURE_RE.fullmatch(signature) is None:
            return False
        bt = _bittensor()
        crypto_type = _crypto_type_for_scheme(bt, scheme)
        signature_bytes = bytes.fromhex(signature[2:])
        return bool(
            bt.sp_core.verify(
                digest,
                signature_bytes,
                hotkey_ss58,
                crypto_type,
            )
        )
    except (TypeError, ValueError, RuntimeError):
        return False


def _bittensor():
    try:
        import bittensor as bt
    except ModuleNotFoundError as error:
        if error.name == "bittensor":
            raise RuntimeError(
                "Bittensor operations require the pinned bittensor==11.1.0 dependency"
            ) from error
        raise
    return bt


def _sealed_record(portable: bytes, reveal_round: int) -> SealedResponse:
    return SealedResponse(
        portable_bytes=portable,
        portable_b64=_encode_portable(portable),
        reveal_round=reveal_round,
        sha256_hex=hashlib.sha256(portable).hexdigest(),
    )


def _decode_scale_compact_length(data: bytes) -> tuple[int, int]:
    if not data:
        raise ValueError("portable timelock is missing its SCALE vector length")
    mode = data[0] & 0b11
    if mode == 0:
        return data[0] >> 2, 1
    if mode == 1:
        if len(data) < 2:
            raise ValueError("portable timelock has a truncated SCALE vector length")
        value = int.from_bytes(data[:2], "little") >> 2
        if value < 1 << 6:
            raise ValueError("portable timelock uses a non-canonical SCALE vector length")
        return value, 2
    if mode == 2:
        if len(data) < 4:
            raise ValueError("portable timelock has a truncated SCALE vector length")
        value = int.from_bytes(data[:4], "little") >> 2
        if value < 1 << 14:
            raise ValueError("portable timelock uses a non-canonical SCALE vector length")
        return value, 4
    raise ValueError("portable timelock SCALE vector length is too large")


def _validate_portable_layout(portable: bytes, expected_round: int) -> None:
    """Strictly decode the portable ``UserData`` and compressed ciphertext framing."""

    encrypted_length, prefix_length = _decode_scale_compact_length(portable)
    expected_total = prefix_length + encrypted_length + 8
    if len(portable) != expected_total:
        raise ValueError("portable timelock has trailing or truncated SCALE bytes")
    embedded_round = int.from_bytes(portable[-8:], "little")
    if embedded_round != expected_round:
        raise ValueError("embedded timelock round does not match reveal_round")

    encrypted = portable[prefix_length:-8]
    if len(encrypted) < 244:
        raise ValueError("portable timelock ciphertext is shorter than its canonical framing")
    _validate_tiny_bls381_group(encrypted[:96])

    cursor = 96

    def read_u64(label: str) -> int:
        nonlocal cursor
        if cursor + 8 > len(encrypted):
            raise ValueError(f"portable timelock has a truncated {label}")
        value = int.from_bytes(encrypted[cursor : cursor + 8], "little")
        cursor += 8
        return value

    def consume(length: int, label: str) -> bytes:
        nonlocal cursor
        if length < 0 or cursor + length > len(encrypted):
            raise ValueError(f"portable timelock has a truncated {label}")
        value = encrypted[cursor : cursor + length]
        cursor += length
        return value

    if read_u64("first compressed-field length") != 32:
        raise ValueError("portable timelock has an invalid first compressed field")
    consume(32, "first compressed field")
    if read_u64("second compressed-field length") != 32:
        raise ValueError("portable timelock has an invalid second compressed field")
    consume(32, "second compressed field")

    symmetric_length = read_u64("symmetric-ciphertext length")
    symmetric_end = cursor + symmetric_length
    if symmetric_end > len(encrypted):
        raise ValueError("portable timelock has a truncated symmetric ciphertext")
    ciphertext_length = read_u64("authenticated-ciphertext length")
    if ciphertext_length < 16:
        raise ValueError("portable timelock authenticated ciphertext is too short")
    consume(ciphertext_length, "authenticated ciphertext")
    if read_u64("nonce length") != 12:
        raise ValueError("portable timelock has an invalid nonce length")
    consume(12, "nonce")
    if cursor != symmetric_end:
        raise ValueError("portable timelock symmetric ciphertext has trailing bytes")
    if read_u64("cipher marker length") != len(_AES_GCM_MARKER):
        raise ValueError("portable timelock has an invalid cipher marker length")
    if consume(len(_AES_GCM_MARKER), "cipher marker") != _AES_GCM_MARKER:
        raise ValueError("portable timelock has an unsupported cipher marker")
    if cursor != len(encrypted):
        raise ValueError("portable timelock ciphertext has trailing bytes")


def _validate_tiny_bls381_group(encoded: bytes) -> None:
    """Validate canonical compressed G2 encoding, curve membership, and subgroup."""

    if len(encoded) != 96:
        raise ValueError("portable timelock compressed group data has the wrong length")
    compressed = (
        int.from_bytes(encoded[:48], "big"),
        int.from_bytes(encoded[48:], "big"),
    )
    try:
        point = decompress_G2(compressed)
        if eq(point, Z2):
            raise ValueError("point at infinity is not a valid timelock ciphertext element")
        if not eq(multiply(point, curve_order), Z2):
            raise ValueError("timelock ciphertext element is outside the prime-order subgroup")
        if compress_G2(point) != compressed:
            raise ValueError("timelock ciphertext element is not canonically compressed")
    except (TypeError, ValueError, OverflowError) as error:
        raise ValueError("portable timelock compressed group data is invalid") from error


def _encode_portable(portable: bytes) -> str:
    from .protocol import base64url_encode

    encoded = base64url_encode(portable)
    if not isinstance(encoded, str):
        raise TypeError("b64url_encode must return str")
    if _stdlib_b64url_decode(encoded) != portable:
        raise ValueError("b64url_encode did not return a canonical encoding")
    return encoded


def _decode_portable(encoded: str) -> bytes:
    # Check canonical spelling independently of the protocol helper so a
    # permissive decoder cannot admit padding, alternate alphabets, or aliases.
    canonical = _stdlib_b64url_decode(encoded)
    from .protocol import base64url_decode, base64url_encode

    decoded = base64url_decode(encoded)
    if not isinstance(decoded, bytes):
        raise TypeError("b64url_decode must return bytes")
    if decoded != canonical or base64url_encode(decoded) != encoded:
        raise ValueError("portable timelock is not canonical unpadded base64url")
    return decoded


def _stdlib_b64url_decode(encoded: str) -> bytes:
    if not isinstance(encoded, str) or not encoded:
        raise ValueError("portable timelock must be a non-empty base64url string")
    if "=" in encoded or _BASE64URL_RE.fullmatch(encoded) is None:
        raise ValueError("portable timelock must use unpadded base64url")
    padding = "=" * (-len(encoded) % 4)
    try:
        decoded = base64.b64decode(encoded + padding, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as error:
        raise ValueError("portable timelock is not valid base64url") from error
    canonical = base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii")
    if canonical != encoded:
        raise ValueError("portable timelock is not canonical unpadded base64url")
    return decoded


def _require_reveal_round(value: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= _MAX_U64:
        raise ValueError("reveal_round must be a positive u64")
    return value


def _require_sha256_hex(value: str) -> str:
    if not isinstance(value, str) or _DIGEST_HEX_RE.fullmatch(value) is None:
        raise ValueError("SHA-256 must be 64 lowercase hexadecimal characters")
    return value


def _coerce_response_digest(response_or_digest: Any) -> bytes:
    if isinstance(response_or_digest, (bytes, bytearray, memoryview)):
        digest = bytes(response_or_digest)
    elif isinstance(response_or_digest, str):
        text = response_or_digest.removeprefix("0x")
        _require_sha256_hex(text)
        digest = bytes.fromhex(text)
    else:
        from .protocol import response_digest

        digest = _coerce_response_digest(response_digest(response_or_digest))
    if len(digest) != 32:
        raise ValueError("response digest must be exactly 32 bytes")
    return digest


def _scheme_for_crypto_type(bt: Any, crypto_type: int) -> str:
    if crypto_type == bt.sp_core.CRYPTO_SR25519:
        return "sr25519"
    if crypto_type == bt.sp_core.CRYPTO_ED25519:
        return "ed25519"
    raise ValueError(f"unsupported Bittensor hotkey crypto type {crypto_type}")


def _crypto_type_for_scheme(bt: Any, scheme: str) -> int:
    if scheme == "sr25519":
        return bt.sp_core.CRYPTO_SR25519
    if scheme == "ed25519":
        return bt.sp_core.CRYPTO_ED25519
    raise ValueError("signature scheme must be exactly 'sr25519' or 'ed25519'")


__all__ = [
    "SealedResponse",
    "TimelockDecryptionError",
    "decrypt_response",
    "parse_sealed_response",
    "seal_response",
    "sign_response_digest",
    "verify_response_signature",
]
