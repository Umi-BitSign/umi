from __future__ import annotations

from types import SimpleNamespace

import pytest

bt = pytest.importorskip("bittensor")

from umi.crypto import (  # noqa: E402
    SealedResponse,
    TimelockDecryptionError,
    decrypt_response,
    parse_sealed_response,
    seal_response,
    sign_response_digest,
    verify_response_signature,
)
from umi.protocol import ResponseEnvelope, base64url_encode, sha256_hex  # noqa: E402


def _dev_wallet(hotkey_uri: str, crypto_type: int):
    hotkey = bt.sp_core.Keypair.create_from_uri(hotkey_uri, crypto_type=crypto_type)
    coldkey = bt.sp_core.Keypair.create_from_uri("//Charlie", crypto_type=crypto_type)
    return SimpleNamespace(coldkey=coldkey, coldkeypub=coldkey, hotkey=hotkey)


@pytest.mark.parametrize(
    ("crypto_type", "expected_scheme"),
    [
        (bt.sp_core.CRYPTO_SR25519, "sr25519"),
        (bt.sp_core.CRYPTO_ED25519, "ed25519"),
    ],
)
def test_sign_and_verify_real_dev_hotkeys(crypto_type: int, expected_scheme: str) -> None:
    wallet = _dev_wallet("//Alice", crypto_type)
    digest = bytes(range(32))

    scheme, signature = sign_response_digest(wallet, digest)

    assert scheme == expected_scheme
    assert signature.startswith("0x")
    assert len(signature) == 130
    assert signature == signature.lower()
    assert bt.sp_core.verify(
        digest,
        bytes.fromhex(signature[2:]),
        wallet.hotkey.ss58_address,
        crypto_type,
    )
    assert verify_response_signature(
        digest,
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme=scheme,
        signature=signature,
    )
    # The adapter must select the wallet hotkey rather than its coldkey.
    assert not verify_response_signature(
        digest,
        hotkey_ss58=wallet.coldkey.ss58_address,
        scheme=scheme,
        signature=signature,
    )


@pytest.mark.parametrize(
    ("crypto_type", "scheme", "wrong_scheme"),
    [
        (bt.sp_core.CRYPTO_SR25519, "sr25519", "ed25519"),
        (bt.sp_core.CRYPTO_ED25519, "ed25519", "sr25519"),
    ],
)
def test_verification_fails_closed_for_wrong_key_digest_scheme_and_tamper(
    crypto_type: int,
    scheme: str,
    wrong_scheme: str,
) -> None:
    wallet = _dev_wallet("//Alice", crypto_type)
    wrong_key = bt.sp_core.Keypair.create_from_uri("//Bob", crypto_type=crypto_type)
    digest = hashlib_digest(b"response")
    actual_scheme, signature = sign_response_digest(wallet, digest)
    assert actual_scheme == scheme

    assert not verify_response_signature(
        digest,
        hotkey_ss58=wrong_key.ss58_address,
        scheme=scheme,
        signature=signature,
    )
    assert not verify_response_signature(
        hashlib_digest(b"different response"),
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme=scheme,
        signature=signature,
    )
    assert not verify_response_signature(
        digest,
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme=wrong_scheme,
        signature=signature,
    )

    replacement = "0" if signature[-1] != "0" else "1"
    assert not verify_response_signature(
        digest,
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme=scheme,
        signature=signature[:-1] + replacement,
    )
    assert not verify_response_signature(
        digest,
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme="SR25519",
        signature=signature,
    )
    assert not verify_response_signature(
        digest,
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme=scheme,
        signature=signature.upper(),
    )


def test_seal_and_parse_roundtrip_uses_strict_unpadded_base64url() -> None:
    reveal_round = bt.timelock.current_round() + 100

    sealed = seal_response(b'"canonical plaintext"', reveal_round=reveal_round)

    assert isinstance(sealed, SealedResponse)
    assert sealed.reveal_round == reveal_round
    assert "=" not in sealed.portable_b64
    assert sealed.sha256_hex == hashlib_digest(sealed.portable_bytes).hex()
    parsed = parse_sealed_response(
        sealed.portable_b64,
        reveal_round=reveal_round,
        sha256_hex=sealed.sha256_hex,
    )
    assert parsed == sealed

    with pytest.raises(ValueError, match="unpadded base64url"):
        parse_sealed_response(sealed.portable_b64 + "=", reveal_round=reveal_round)
    with pytest.raises(ValueError, match="SHA-256"):
        parse_sealed_response(
            sealed.portable_b64,
            reveal_round=reveal_round,
            sha256_hex="00" * 32,
        )
    tampered = bytearray(sealed.portable_bytes)
    tampered[0] ^= 1
    with pytest.raises(ValueError, match="SHA-256"):
        parse_sealed_response(
            base64url_encode(bytes(tampered)),
            reveal_round=reveal_round,
            sha256_hex=sealed.sha256_hex,
        )
    with pytest.raises(ValueError, match="embedded timelock round"):
        parse_sealed_response(sealed.portable_b64, reveal_round=reveal_round + 1)


def test_sealed_record_rejects_tampered_redundant_fields() -> None:
    reveal_round = bt.timelock.current_round() + 100
    sealed = seal_response(b"answer", reveal_round=reveal_round)

    with pytest.raises(ValueError, match="portable_b64"):
        SealedResponse(
            portable_bytes=sealed.portable_bytes + b"x",
            portable_b64=sealed.portable_b64,
            reveal_round=sealed.reveal_round,
            sha256_hex=sealed.sha256_hex,
        )
    with pytest.raises(ValueError, match="sha256_hex"):
        SealedResponse(
            portable_bytes=sealed.portable_bytes,
            portable_b64=sealed.portable_b64,
            reveal_round=sealed.reveal_round,
            sha256_hex="00" * 32,
        )


def test_parser_rejects_trailer_only_fake_timelock() -> None:
    reveal_round = bt.timelock.current_round() + 100
    fabricated = b"AES_GCM_" + reveal_round.to_bytes(8, "little")

    with pytest.raises(ValueError, match=r"SCALE|shorter"):
        parse_sealed_response(
            base64url_encode(fabricated),
            reveal_round=reveal_round,
        )


def test_decrypt_revalidates_record_before_calling_bittensor(monkeypatch) -> None:
    reveal_round = bt.timelock.current_round() + 100
    sealed = seal_response(b"answer", reveal_round=reveal_round)
    seen = {}

    def fake_decrypt(parsed, *, wait, timeout):
        seen["parsed"] = parsed
        seen["wait"] = wait
        seen["timeout"] = timeout
        return b"answer"

    monkeypatch.setattr(bt.timelock, "decrypt", fake_decrypt)
    assert (
        decrypt_response(
            sealed,
            reveal_round=reveal_round,
            sha256_hex=sealed.sha256_hex,
            wait=True,
            timeout=7.5,
        )
        == b"answer"
    )
    assert seen["parsed"].reveal_round == reveal_round
    assert seen["wait"] is True
    assert seen["timeout"] == 7.5

    with pytest.raises(ValueError, match="round"):
        decrypt_response(sealed, reveal_round=reveal_round + 1)
    with pytest.raises(ValueError, match="SHA-256"):
        decrypt_response(sealed, reveal_round=reveal_round, sha256_hex="00" * 32)


def test_decrypt_wraps_the_pinned_sdk_error(monkeypatch) -> None:
    reveal_round = bt.timelock.current_round() + 100
    sealed = seal_response(b"answer", reveal_round=reveal_round)

    def fail_decrypt(*_args, **_kwargs):
        raise bt.timelock.TimelockError("corrupt ciphertext")

    monkeypatch.setattr(bt.timelock, "decrypt", fail_decrypt)
    with pytest.raises(TimelockDecryptionError, match="corrupt ciphertext"):
        decrypt_response(sealed, reveal_round=reveal_round)


def test_digest_must_be_raw_32_bytes_or_canonical_hex() -> None:
    wallet = _dev_wallet("//Alice", bt.sp_core.CRYPTO_SR25519)
    digest = hashlib_digest(b"response")

    assert sign_response_digest(wallet, digest.hex())[0] == "sr25519"
    with pytest.raises(ValueError, match="32 bytes"):
        sign_response_digest(wallet, b"short")


def test_response_model_digest_is_converted_to_raw_bytes_before_signing() -> None:
    wallet = _dev_wallet("//Alice", bt.sp_core.CRYPTO_SR25519)
    portable = b"portable"
    envelope = ResponseEnvelope.model_validate(
        {
            "schema": "umi-response-envelope/1",
            "protocol": "umi-asl/0.1",
            "window_id": "00" * 32,
            "batch_id": base64url_encode(bytes(range(16))),
            "challenge_id": base64url_encode(bytes(range(16, 32))),
            "request_digest": "11" * 32,
            "issued_block_hash": "0x" + "22" * 32,
            "validator_hotkey": "validator",
            "serving_hotkey": wallet.hotkey.ss58_address,
            "response_tle_profile": "umi-response-tle/1",
            "response_reveal_round": 12345678,
            "encrypted_response": base64url_encode(portable),
            "encrypted_response_sha256": sha256_hex(portable),
            "signature_scheme": "sr25519",
        }
    )

    scheme, signature = sign_response_digest(wallet, envelope)

    assert verify_response_signature(
        envelope,
        hotkey_ss58=wallet.hotkey.ss58_address,
        scheme=scheme,
        signature=signature,
    )


def hashlib_digest(value: bytes) -> bytes:
    import hashlib

    return hashlib.sha256(value).digest()
