"""Preserve original object bytes across private replay wrappers.

Ordinary objects retain their native canonical encoding and domain-separated
identity. Retained service catalogs also commit materializer reference files by
the plain SHA256 of their compact, sorted, ASCII-escaped JSON. Only that strict
reference schema may use the historical identity. Its decoder remains necessary
while signed catalogs and their settlement/reward replay packages retain it.
"""

from __future__ import annotations

import hashlib
import json

from pydantic import JsonValue

from .competition_cohort_service_reference import ServiceReference
from .open_competition import digest
from .protocol import canonical_json_bytes


def _materialized_reference_bytes(value: JsonValue) -> bytes:
    if not isinstance(value, dict) or value.get("schema") != "umi-cohort-service-reference/1":
        raise ValueError("endpoint archive object differs from its bounded identity")
    reference = ServiceReference.model_validate(value)
    return json.dumps(
        reference.model_dump(mode="json", by_alias=True),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def endpoint_object_bytes(value: JsonValue, sha256: str) -> bytes:
    """Reconstruct an extracted object's bytes without rekeying its commitment.

    Generic typed objects keep their existing serialization cost and behavior;
    callers authenticate all returned bytes with ``read_endpoint_object``. A
    reference can require the materializer encoding even after a canonical
    wrapper has decoded its ASCII escapes. Select that encoding only when its
    exact original hash matches, leaving native typed references unchanged.
    """
    raw = canonical_json_bytes(value)
    if (
        isinstance(value, dict)
        and value.get("schema") == "umi-cohort-service-reference/1"
        and digest(value) != sha256
    ):
        raw = _materialized_reference_bytes(value)
        if hashlib.sha256(raw).hexdigest() != sha256:
            raise ValueError("service reference differs from its committed identity")
    return raw


def validate_endpoint_object_bytes(raw: bytes, sha256: str) -> None:
    """Authenticate already bounded input, preserving exact original bytes."""
    value = json.loads(raw)
    if canonical_json_bytes(value) == raw and digest(value) == sha256:
        return
    original = _materialized_reference_bytes(value)
    if original != raw or hashlib.sha256(original).hexdigest() != sha256:
        raise ValueError("endpoint archive object differs from its bounded identity")
