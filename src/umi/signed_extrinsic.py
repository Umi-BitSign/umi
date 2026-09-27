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

import bittensor as bt
from bittensor._transport.contract import SignedExtrinsic

from .encoding import account_id32
from .validator_chain import PinnedRuntimeContext

MAX_SIGNED_EXTRINSIC_BYTES = 64 * 1024
_BLOCK_HASH = re.compile(r"^0x[0-9a-f]{64}$")


def _validate_context(runtime, nonce, mortality_period, genesis_hash):
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
    _validate_context(runtime, nonce, mortality_period, genesis_hash)
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


def verify_mortal_call(
    encoded: bytes,
    call: Any,
    *,
    runtime: PinnedRuntimeContext,
    validator_hotkey: str,
    nonce: int,
    mortality_period: int,
    genesis_hash: str,
) -> SignedExtrinsic:
    """Verify retained bytes against the original authenticated signing context.

    This checks the actual encoded era, nonce, call, signer and signature, not
    journal claims about them. It can run after arbitrary delay with the
    original runtime and checkpoint. Current authority, finality and unused
    nonce still require independent proofs before any submission or retry.
    """
    _validate_context(runtime, nonce, mortality_period, genesis_hash)
    envelope = exact_signed_extrinsic(encoded)
    codec = runtime._runtime
    decoded = codec.decode_extrinsic(encoded, True)
    if not isinstance(decoded, dict):
        raise ValueError("signed transaction decode is incomplete")
    era = decoded.get("era")
    if (
        not isinstance(era, tuple)
        or len(era) != 2
        or any(type(n) is not int for n in era)
        or era != (mortality_period, runtime.snapshot.block_number % mortality_period)
        or type(decoded.get("nonce")) is not int
        or decoded["nonce"] != nonce
        or decoded.get("extrinsic_hash") != envelope.extrinsic_hash
        or account_id32(decoded.get("address")) != account_id32(validator_hotkey)
    ):
        raise ValueError("signed transaction differs from its nonce, era or signer")
    signatures = decoded.get("signature")
    schemes = {"Ed25519": 0, "Sr25519": 1}
    if not isinstance(signatures, dict) or len(signatures) != 1:
        raise ValueError("signed transaction signature is malformed")
    scheme, raw = next(iter(signatures.items()))
    if (
        scheme not in schemes
        or not isinstance(raw, str)
        or re.fullmatch(r"0x[0-9a-f]{128}", raw) is None
    ):
        raise ValueError("signed transaction signature scheme or bytes are invalid")
    signature = bytes.fromhex(raw[2:])
    call_bytes = bytes(codec.compose_call(call.module, call.function, call.params))
    selected_era = {"period": mortality_period, "current": runtime.snapshot.block_number}
    # Exact reassembly rejects another call, nonzero tips, metadata-hash mode,
    # altered framing and extension fields, including fields not inspected above.
    rebuilt, returned_hash = codec.encode_signed_extrinsic(
        call_bytes,
        public_key=account_id32(validator_hotkey),
        signature=signature,
        signature_version=schemes[scheme],
        era=selected_era,
        nonce=nonce,
        tip=0,
        tip_asset_id=None,
        metadata_hash_enabled=False,
    )
    if bytes(rebuilt) != encoded or bytes(returned_hash).hex() != envelope.extrinsic_hash[2:]:
        raise ValueError("signed transaction differs from the exact intended call and extensions")
    payload = bytes(
        codec.signature_payload(
            call_bytes,
            era=selected_era,
            nonce=nonce,
            tip=0,
            tip_asset_id=None,
            genesis_hash=bytes.fromhex(genesis_hash[2:]),
            era_block_hash=bytes.fromhex(runtime.snapshot.block_hash[2:]),
            metadata_hash=None,
        )
    )
    if not bt.sp_core.verify(payload, signature, validator_hotkey, schemes[scheme]):
        raise ValueError("signed transaction does not verify against its original checkpoint")
    return envelope


def encode_verified_mortal_call(
    call, *, runtime, signer, validator_hotkey, nonce, mortality_period, genesis_hash
) -> bytes:
    """Encode once, then verify the actual bytes before returning them for retention."""
    context = dict(
        runtime=runtime,
        validator_hotkey=validator_hotkey,
        nonce=nonce,
        mortality_period=mortality_period,
        genesis_hash=genesis_hash,
    )
    encoded = encode_mortal_call(call, signer=signer, **context)
    verify_mortal_call(encoded, call, **context)
    return encoded
