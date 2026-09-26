"""Replay the content of an authenticated timelock, separately from timing."""

from __future__ import annotations

from dataclasses import dataclass

import bittensor_core

from .config import Limits
from .drand import DrandPulse
from .protocol import (
    ResponseEnvelope,
    TranslationRequest,
    normalized_grapheme_count,
    normalized_token_count,
)
from .validator import ComponentResponseError, validate_response_plaintext


@dataclass(frozen=True)
class EndpointContent:
    status: str
    hypothesis: str
    reason_code: str | None
    plaintext_bytes: bytes | None


def decrypt_endpoint_content(
    *,
    request: TranslationRequest,
    envelope: ResponseEnvelope,
    sealed_bytes: bytes,
    pulse: DrandPulse,
    model_revision: str,
    maximum_output_bytes: int,
    limits: Limits,
    retained_plaintext: bytes | None = None,
    resource_errors_pending: bool = False,
) -> EndpointContent:
    """Caller authenticates the envelope and selected work before decryption.

    This function establishes no elapsed time, pre-reveal commitment, phase
    closure or reward eligibility. Missing crypto support remains an error.
    """
    if not isinstance(pulse, DrandPulse) or pulse.round != request.reveal_round:
        raise ValueError("reveal pulse does not match request timelock round")
    pulse.verify()
    decrypt = getattr(bittensor_core, "decrypt_with_signature", None)
    if not callable(decrypt):
        raise RuntimeError("offline timelock decryption primitive is unavailable")
    try:
        raw = decrypt(sealed_bytes, pulse.signature)
    except Exception as error:
        if resource_errors_pending and isinstance(error, (OSError, MemoryError)):
            raise
        if retained_plaintext is not None:
            raise ValueError("retained plaintext belongs to an undecryptable response") from error
        return EndpointContent("miner_failure", "", "undecryptable", None)
    if not isinstance(raw, bytes):
        raise RuntimeError("offline timelock decryption returned non-bytes")
    if len(raw) > limits.maximum_response_plaintext_bytes:
        raise ValueError("decrypted plaintext exceeds retained evidence byte limit")
    if retained_plaintext is not None and retained_plaintext != raw:
        raise ValueError("retained plaintext does not match its timelock")
    try:
        plain = validate_response_plaintext(raw, envelope=envelope, request=request)
    except ComponentResponseError as error:
        return EndpointContent("miner_failure", "", error.code, raw)
    if plain.status != "ok":
        return EndpointContent("miner_failure", "", "signed_miner_error", raw)
    if plain.model_revision != model_revision:
        return EndpointContent("miner_failure", "", "model_revision_mismatch", raw)
    if (
        len(plain.hypothesis.encode())
        > min(maximum_output_bytes, limits.maximum_hypothesis_utf8_bytes)
        or normalized_token_count(plain.hypothesis) > limits.maximum_hypothesis_tokens
        or normalized_grapheme_count(plain.hypothesis) > limits.maximum_hypothesis_graphemes
    ):
        return EndpointContent("miner_failure", "", "output_limit", raw)
    return EndpointContent("ok", plain.hypothesis, None, raw)
