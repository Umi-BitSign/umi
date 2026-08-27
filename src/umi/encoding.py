"""Binary encodings and domain-separated hashes used by UMI state machines."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable

_HEX_32_RE = re.compile(r"^[0-9a-f]{64}$")


def u16be(value: int) -> bytes:
    return _unsigned(value, 2, "u16")


def u32be(value: int) -> bytes:
    return _unsigned(value, 4, "u32")


def u64be(value: int) -> bytes:
    return _unsigned(value, 8, "u64")


def _unsigned(value: int, width: int, label: str) -> bytes:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{label} value must be an integer")
    if not 0 <= value < 1 << (width * 8):
        raise ValueError(f"{label} value is out of range")
    return value.to_bytes(width, "big")


def raw_sha256(value: str | bytes, *, field: str = "SHA-256") -> bytes:
    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError(f"{field} must be exactly 32 bytes")
        return value
    if not isinstance(value, str) or _HEX_32_RE.fullmatch(value) is None:
        raise ValueError(f"{field} must be 64 lowercase hexadecimal characters")
    return bytes.fromhex(value)


def account_id32(value: str | bytes) -> bytes:
    """Decode an SS58 address or validate an already-decoded AccountId32."""

    if isinstance(value, bytes):
        if len(value) != 32:
            raise ValueError("AccountId32 must contain exactly 32 bytes")
        return value
    if not isinstance(value, str) or not value:
        raise ValueError("account must be a non-empty SS58 address or 32 bytes")
    import bittensor as bt

    try:
        decoded = bytes(bt.sp_core.ss58_decode(value))
    except (TypeError, ValueError) as error:
        raise ValueError("account is not a valid SS58 address") from error
    if len(decoded) != 32:
        raise ValueError("account does not decode to AccountId32")
    return decoded


def sha256_domain(domain: bytes, *parts: bytes) -> bytes:
    if not isinstance(domain, bytes) or not domain.endswith(b"\0"):
        raise ValueError("hash domain must be bytes ending in NUL")
    if any(not isinstance(part, bytes) for part in parts):
        raise TypeError("hash inputs must be bytes")
    return hashlib.sha256(domain + b"".join(parts)).digest()


def sorted_unique_hashes(
    values: Iterable[str | bytes], *, field: str = "hash"
) -> tuple[bytes, ...]:
    raw = tuple(raw_sha256(value, field=field) for value in values)
    if len(set(raw)) != len(raw):
        raise ValueError(f"{field} values must be unique")
    return tuple(sorted(raw))


def binary_merkle_root(
    leaves: Iterable[str | bytes],
    *,
    node_domain: bytes,
    empty_domain: bytes,
) -> bytes:
    """Return the binary Merkle root with final-node duplication at odd widths."""

    level = list(sorted_unique_hashes(leaves, field="Merkle leaf"))
    if not level:
        return sha256_domain(empty_domain)
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [
            sha256_domain(node_domain, level[index], level[index + 1])
            for index in range(0, len(level), 2)
        ]
    return level[0]


__all__ = [
    "account_id32",
    "binary_merkle_root",
    "raw_sha256",
    "sha256_domain",
    "sorted_unique_hashes",
    "u16be",
    "u32be",
    "u64be",
]
