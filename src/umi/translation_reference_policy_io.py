"""Read the immutable approval selected by an authenticated directive."""

from __future__ import annotations

from .translation_reference_policy import (
    MAX_REFERENCE_POLICY_BYTES,
    ApprovedTranslationReferencePolicy,
    verify_reference_policy,
)
from .translation_reference_state import TranslationReferenceError
from .validator_supervisor_adapters import PinnedHTTPSClient

REFERENCE_POLICY_ORIGIN = "https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev"
REFERENCE_POLICY_PREFIX = "/validator-supervisor/translation-reference-policies/"


async def fetch_approved_reference_policy(
    policy_sha256: str, *, expected_authority_hotkey: str, http=None
) -> ApprovedTranslationReferencePolicy:
    """The caller's authenticated local authority supplies both expectations."""
    if (
        type(policy_sha256) is not str
        or len(policy_sha256) != 64
        or any(c not in "0123456789abcdef" for c in policy_sha256)
    ):
        raise ValueError("reference policy identity must be a canonical digest")
    payload = await (http or PinnedHTTPSClient()).fetch_bytes(
        f"{REFERENCE_POLICY_ORIGIN}{REFERENCE_POLICY_PREFIX}{policy_sha256}.json",
        maximum_bytes=MAX_REFERENCE_POLICY_BYTES,
    )
    policy = verify_reference_policy(
        payload,
        expected_policy_sha256=policy_sha256,
        expected_authority_hotkey=expected_authority_hotkey,
    )
    if type(policy) is not ApprovedTranslationReferencePolicy:
        raise TranslationReferenceError("reference_authority_approved_row_required")
    return policy
