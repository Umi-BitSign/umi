"""Bittensor v11 ``btauth/1`` adapters for UMI's HTTP transport."""

from __future__ import annotations

import hashlib
import re
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

REQUEST_BODY_SHA256_HEADER = "X-UMI-Body-SHA256"
_HEX_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class _NonMutatingNonceStore:
    """Let ``btauth`` verify freshness/signatures without consuming a nonce."""

    retention = float("inf")

    @staticmethod
    def check_and_store(_hotkey_ss58: str, _nonce_ns: int) -> bool:
        return True


_NON_MUTATING_NONCE_STORE = _NonMutatingNonceStore()


class HotkeyAuth(httpx.Auth):
    """Sign each httpx request attempt for one receiving miner hotkey."""

    requires_request_body = True

    def __init__(self, wallet: Any, receiver_ss58: str) -> None:
        self.wallet = wallet
        self.receiver_ss58 = receiver_ss58

    def auth_flow(self, request: httpx.Request):
        import bittensor as bt

        request.headers.update(
            bt.http_auth.sign(
                self.wallet,
                method=request.method,
                path=request.url.raw_path.decode("ascii"),
                body=request.content,
                receiver_ss58=self.receiver_ss58,
            )
        )
        request.headers[REQUEST_BODY_SHA256_HEADER] = hashlib.sha256(request.content).hexdigest()
        yield request


@dataclass(frozen=True)
class HistoricalAuthVerification:
    sender_ss58: str
    receiver_ss58: str
    nonce: int
    scheme: str


@dataclass(frozen=True)
class RequestAuthenticator:
    """Verify raw request bytes against a caller-supplied replay store."""

    self_hotkey_ss58: str
    nonce_store: Any
    max_age_seconds: float = 10.0
    allowed_skew_seconds: float = 2.0

    @classmethod
    def in_memory(
        cls,
        self_hotkey_ss58: str,
        *,
        max_age_seconds: float = 10.0,
        allowed_skew_seconds: float = 2.0,
    ) -> RequestAuthenticator:
        import bittensor as bt

        retention = max(60.0, max_age_seconds + allowed_skew_seconds)
        return cls(
            self_hotkey_ss58=self_hotkey_ss58,
            nonce_store=bt.http_auth.InMemoryNonceStore(retention=retention),
            max_age_seconds=max_age_seconds,
            allowed_skew_seconds=allowed_skew_seconds,
        )

    @classmethod
    def sqlite(
        cls,
        self_hotkey_ss58: str,
        path: str | Path,
        *,
        max_age_seconds: float = 10.0,
        allowed_skew_seconds: float = 2.0,
        allowed_hotkeys: Iterable[str] | None = None,
        maximum_nonces_per_hotkey: int = 1_024,
        maximum_total_nonces: int = 16_384,
        maximum_database_bytes: int = 8 * 1024 * 1024,
    ) -> RequestAuthenticator:
        from .nonce import SQLiteNonceStore

        retention = max(60.0, max_age_seconds + allowed_skew_seconds)
        return cls(
            self_hotkey_ss58=self_hotkey_ss58,
            nonce_store=SQLiteNonceStore(
                path,
                retention_seconds=retention,
                allowed_hotkeys=allowed_hotkeys,
                maximum_nonces_per_hotkey=maximum_nonces_per_hotkey,
                maximum_total_nonces=maximum_total_nonces,
                maximum_database_bytes=maximum_database_bytes,
            ),
            max_age_seconds=max_age_seconds,
            allowed_skew_seconds=allowed_skew_seconds,
        )

    def verify(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        method: str,
        path: str,
    ) -> Any:
        caller = self.verify_without_replay(
            headers,
            body,
            method=method,
            path=path,
        )
        self.commit_replay(caller)
        return caller

    def verify_without_replay(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        method: str,
        path: str,
    ) -> Any:
        """Verify header shape, freshness, receiver, and signature without mutation."""

        import bittensor as bt

        return bt.http_auth.verify(
            headers,
            body,
            method=method,
            path=path,
            self_hotkey_ss58=self.self_hotkey_ss58,
            max_age=self.max_age_seconds,
            allowed_skew=self.allowed_skew_seconds,
            nonce_store=_NON_MUTATING_NONCE_STORE,
        )

    def verify_declared_body_digest(
        self,
        headers: Mapping[str, str],
        body_sha256: str,
        *,
        method: str,
        path: str,
    ) -> Any:
        """Authenticate the digest line of a btauth payload before reading its body."""

        import bittensor as bt

        if _HEX_SHA256_RE.fullmatch(body_sha256) is None:
            raise bt.http_auth.MalformedAuth(
                f"{REQUEST_BODY_SHA256_HEADER} must be lowercase SHA-256 hexadecimal"
            )
        lowered = {name.lower(): value for name, value in headers.items()}

        def required(name: str) -> str:
            value = lowered.get(name.lower())
            if value is None:
                raise bt.http_auth.MalformedAuth(f"missing {name}")
            return value

        if required(bt.http_auth.HEADER_VERSION) != bt.http_auth.VERSION:
            raise bt.http_auth.MalformedAuth(f"unsupported {bt.http_auth.HEADER_VERSION}")
        sender = required(bt.http_auth.HEADER_HOTKEY)
        receiver = required(bt.http_auth.HEADER_RECEIVER)
        if receiver != self.self_hotkey_ss58:
            raise bt.http_auth.WrongReceiver("request was signed for a different receiving hotkey")
        raw_nonce = required(bt.http_auth.HEADER_NONCE)
        if not raw_nonce.isdecimal() or raw_nonce != str(int(raw_nonce)):
            raise bt.http_auth.MalformedAuth(
                f"{bt.http_auth.HEADER_NONCE} is not a canonical decimal integer"
            )
        nonce = int(raw_nonce)
        now = time.time_ns()
        if now - nonce > self.max_age_seconds * 1e9:
            raise bt.http_auth.StaleRequest(
                f"nonce is older than the {self.max_age_seconds:g}s freshness window"
            )
        if nonce - now > self.allowed_skew_seconds * 1e9:
            raise bt.http_auth.StaleRequest(
                f"nonce is more than {self.allowed_skew_seconds:g}s in the future"
            )
        try:
            crypto_type = bt.wallets.parse_crypto_type(
                lowered.get(bt.http_auth.HEADER_CRYPTO.lower(), "sr25519")
            )
            scheme = bt.wallets.format_crypto_type(crypto_type)
        except ValueError as error:
            raise bt.http_auth.MalformedAuth(f"unsupported {bt.http_auth.HEADER_CRYPTO}") from error
        raw_signature = required(bt.http_auth.HEADER_SIGNATURE)
        if not re.fullmatch(r"0x[0-9a-f]{128}", raw_signature):
            raise bt.http_auth.MalformedAuth(f"{bt.http_auth.HEADER_SIGNATURE} is not canonical")
        signature = bytes.fromhex(raw_signature[2:])
        payload = "\n".join(
            (
                bt.http_auth.PROTOCOL,
                scheme,
                method.upper(),
                path,
                body_sha256,
                str(nonce),
                sender,
                receiver,
            )
        ).encode()
        try:
            verified = bt.sp_core.verify(payload, signature, sender, crypto_type)
        except ValueError as error:
            raise bt.http_auth.MalformedAuth(
                "invalid hotkey address or signature encoding"
            ) from error
        if not verified:
            raise bt.http_auth.BadSignature(
                "signature does not verify against the claimed body digest"
            )
        return bt.http_auth.Caller(
            hotkey_ss58=sender,
            nonce_ns=nonce,
            crypto_type=crypto_type,
        )

    def commit_replay(self, caller: Any) -> None:
        """Atomically consume a nonce after authenticated admission succeeds."""

        import bittensor as bt

        hotkey = getattr(caller, "hotkey_ss58", None)
        nonce = getattr(caller, "nonce_ns", None)
        if not isinstance(hotkey, str) or isinstance(nonce, bool) or not isinstance(nonce, int):
            raise TypeError("authenticated caller has an invalid replay binding")
        retention = getattr(self.nonce_store, "retention", None)
        required = self.max_age_seconds + self.allowed_skew_seconds
        if retention is not None and retention < required:
            raise ValueError(
                f"nonce store retains entries for {retention:g}s but the freshness window is "
                f"{required:g}s"
            )
        if not self.nonce_store.check_and_store(hotkey, nonce):
            raise bt.http_auth.ReplayedRequest("this nonce was already accepted from this hotkey")


def wire_request_target(scope: Mapping[str, Any]) -> str:
    """Recover the percent-encoded path and query from an ASGI scope."""

    raw_path = scope.get("raw_path")
    if not isinstance(raw_path, bytes):
        raise ValueError("ASGI scope does not contain raw_path bytes")
    target = raw_path.decode("ascii")
    query = scope.get("query_string", b"")
    if not isinstance(query, bytes):
        raise ValueError("ASGI query_string is not bytes")
    if query:
        target += "?" + query.decode("ascii")
    return target


def verify_historical_auth_record(
    headers: Mapping[str, str],
    body: bytes,
    *,
    method: str,
    path: str,
    receiver_ss58: str,
) -> HistoricalAuthVerification:
    """Verify a stored ``btauth/1`` signature without applying wall-clock freshness.

    Freshness and replay protection are enforced by the live miner.  An offline
    replay must instead verify the original signature while retaining its
    historical nonce as evidence.
    """

    import bittensor as bt

    lowered = {name.lower(): value for name, value in headers.items()}

    def required(name: str) -> str:
        value = lowered.get(name.lower())
        if value is None:
            raise ValueError(f"historical auth record is missing {name}")
        return value

    if required(bt.http_auth.HEADER_VERSION) != bt.http_auth.VERSION:
        raise ValueError("historical auth record has an unsupported version")
    sender = required(bt.http_auth.HEADER_HOTKEY)
    receiver = required(bt.http_auth.HEADER_RECEIVER)
    if receiver != receiver_ss58:
        raise ValueError("historical auth record binds a different receiver")
    raw_nonce = required(bt.http_auth.HEADER_NONCE)
    if not raw_nonce.isdecimal() or raw_nonce != str(int(raw_nonce)):
        raise ValueError("historical auth nonce is not a decimal integer")
    nonce = int(raw_nonce)
    scheme = lowered.get(bt.http_auth.HEADER_CRYPTO.lower(), "sr25519")
    try:
        crypto_type = bt.wallets.parse_crypto_type(scheme)
    except ValueError as error:
        raise ValueError("historical auth record has an unsupported scheme") from error
    signature_text = required(bt.http_auth.HEADER_SIGNATURE)
    if not signature_text.startswith("0x"):
        raise ValueError("historical auth signature is not 0x-prefixed")
    try:
        signature = bytes.fromhex(signature_text[2:])
    except ValueError as error:
        raise ValueError("historical auth signature is not hexadecimal") from error
    if len(signature) != 64:
        raise ValueError("historical auth signature is not 64 bytes")
    payload = bt.http_auth.build_payload(
        scheme=bt.wallets.format_crypto_type(crypto_type),
        method=method,
        path=path,
        body=body,
        nonce_ns=nonce,
        sender_ss58=sender,
        receiver_ss58=receiver,
    )
    try:
        verified = bt.sp_core.verify(payload, signature, sender, crypto_type)
    except ValueError as error:
        raise ValueError("historical auth record is malformed") from error
    if not verified:
        raise ValueError("historical auth signature is invalid")
    return HistoricalAuthVerification(
        sender_ss58=sender,
        receiver_ss58=receiver,
        nonce=nonce,
        scheme=bt.wallets.format_crypto_type(crypto_type),
    )
