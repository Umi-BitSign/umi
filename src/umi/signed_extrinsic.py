"""Mortal call encoding and exact-byte SDK envelopes, without retry authority.

Callers authenticate the runtime, nonce, finalized snapshot and authorized call
before signing. They must durably retain the returned bytes before broadcasting.
This module never reads a wallet, queries a nonce, chooses a new head, persists
an attempt or submits it. Storage-only codecs cannot be used for signing.
"""

from __future__ import annotations

import hashlib
import re
from typing import Any

from bittensor._transport.contract import SignedExtrinsic

from .encoding import account_id32
from .validator_chain import PinnedRuntimeContext

MAX_SIGNED_EXTRINSIC_BYTES = 64 * 1024
_BLOCK_HASH = re.compile(r"^0x[0-9a-f]{64}$")


def exact_signed_extrinsic(encoded: bytes) -> SignedExtrinsic:
    """Wrap retained immutable bytes without composition, signing or lookup."""
    if type(encoded) is not bytes or not 0 < len(encoded) <= MAX_SIGNED_EXTRINSIC_BYTES:
        raise ValueError("signed extrinsic must be immutable bytes within its fixed bound")
    return SignedExtrinsic(
        data=encoded,
        extrinsic_hash="0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest(),
    )


def encode_mortal_call(
    call: Any,
    *,
    runtime: PinnedRuntimeContext,
    signer: Any,
    validator_hotkey: str,
    nonce: int,
    mortality_period: int,
    genesis_hash: str,
) -> bytes:
    """Sign once using only the caller's already-authenticated state.

    Powers of two through 4096 avoid era-phase quantization: the runtime's
    snapshot is exactly the mortal era's birth block and signing checkpoint.
    Accepting an executed codec here does not authorize its executor; that pin
    remains part of the caller's signed policy and proof validation.
    """
    if not isinstance(runtime, PinnedRuntimeContext) or runtime.storage_codec_mode not in {
        "exact_runtime",
        "executed_runtime/1",
    }:
        raise ValueError("transaction encoding requires an authenticated signing runtime")
    if type(nonce) is not int or not 0 <= nonce < 2**32:
        raise ValueError("transaction nonce must be a proven unsigned 32-bit integer")
    if (
        type(mortality_period) is not int
        or not 4 <= mortality_period <= 4096
        or mortality_period & (mortality_period - 1)
    ):
        raise ValueError("transaction mortality must be a power of two from 4 through 4096")
    if not isinstance(genesis_hash, str) or not _BLOCK_HASH.fullmatch(genesis_hash):
        raise ValueError("transaction genesis hash is invalid")
    signer_account = account_id32(signer.ss58_address)
    if signer_account != account_id32(validator_hotkey):
        raise ValueError("hotkey signer differs from finalized validator")
    crypto_type = signer.crypto_type
    if crypto_type not in (0, 1) or type(crypto_type) is bool:
        raise ValueError("transaction signing only accepts ed25519 or sr25519 hotkeys")
    codec = runtime._runtime
    call_bytes = bytes(codec.compose_call(call.module, call.function, call.params))
    era = {"period": mortality_period, "current": runtime.snapshot.block_number}
    payload = bytes(
        codec.signature_payload(
            call_bytes,
            era=era,
            nonce=nonce,
            tip=0,
            tip_asset_id=None,
            genesis_hash=bytes.fromhex(genesis_hash[2:]),
            era_block_hash=bytes.fromhex(runtime.snapshot.block_hash[2:]),
            metadata_hash=None,
        )
    )
    signature = signer.sign(payload)
    if not isinstance(signature, bytes) or len(signature) != 64:
        raise ValueError("hotkey returned an invalid signature")
    encoded, returned_hash = codec.encode_signed_extrinsic(
        call_bytes,
        public_key=signer_account,
        signature=signature,
        signature_version=crypto_type,
        era=era,
        nonce=nonce,
        tip=0,
        tip_asset_id=None,
        metadata_hash_enabled=False,
    )
    encoded = bytes(encoded)
    envelope = exact_signed_extrinsic(encoded)
    if bytes(returned_hash).hex() != envelope.extrinsic_hash[2:]:
        raise ValueError("runtime returned an inconsistent signed extrinsic hash")
    return encoded
