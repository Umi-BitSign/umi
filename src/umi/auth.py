"""Bittensor v11 ``btauth/1`` adapters for UMI's HTTP transport."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import httpx


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
        yield request


@dataclass(frozen=True)
class HistoricalAuthVerification:
    sender_ss58: str
    receiver_ss58: str
    nonce: int
    scheme: str


@dataclass(frozen=True)
class RequestAuthenticator:
    """Verify raw request bytes and keep replay state process-local."""

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

    def verify(
        self,
        headers: Mapping[str, str],
        body: bytes,
        *,
        method: str,
        path: str,
    ) -> Any:
        import bittensor as bt

        return bt.http_auth.verify(
            headers,
            body,
            method=method,
            path=path,
            self_hotkey_ss58=self.self_hotkey_ss58,
            max_age=self.max_age_seconds,
            allowed_skew=self.allowed_skew_seconds,
            nonce_store=self.nonce_store,
        )


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
