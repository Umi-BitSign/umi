"""Exact wire parity and bounded work for the owned canonical exporter."""

import hashlib
import json
import tracemalloc

import pytest
from pydantic import Field

from umi import competition_cohort_request_wire as wire
from umi.competition_cohort_aggregate_model import AggregateProtocolModel
from umi.competition_cohort_reward_package import ReplayObjectCollector, RewardPackageObject
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes


class Metadata(AggregateProtocolModel):
    schema_: str = Field(alias="schema")
    objects: tuple[RewardPackageObject, ...]
    services: tuple[str, ...]
    records: tuple[str, ...]


def originals(count=3, size=32):
    values = [{"é": [i, 1e-7, -0.0, "x" * size], "𐀀": True} for i in range(count)]
    source = {digest(value): canonical_json_bytes(value) for value in values}
    collector = ReplayObjectCollector(source.__getitem__, 64 * 1024**2)
    for key in source:
        collector(key)
    metadata = Metadata(schema="test/1", objects=(), services=("é",), records=("𐀀",))
    return metadata, collector, source


def expected_response(metadata, source):
    return {
        "schema": "umi-request-review-response/1",
        "challenge": "ab" * 32,
        "evidence": {
            **metadata.model_dump(mode="json", by_alias=True),
            "objects": [
                {"sha256": key, "value": json.loads(raw)} for key, raw in sorted(source.items())
            ],
        },
    }


def test_wire_copies_authenticated_originals_once_and_counts_bytes(monkeypatch):
    metadata, collector, source = originals()
    response = expected_response(metadata, source)
    signature = {"signature": "synthetic", "scheme": "test"}
    expected = canonical_json_bytes({"response": response, "signature": signature})
    expected_digest = digest(response)
    events = []
    meter = wire.TransferProgress
    monkeypatch.setattr(
        wire, "TransferProgress", lambda *a, **k: meter(*a, report=events.append, **k)
    )

    def no_reparse(*args, **kwargs):
        pytest.fail("trusted canonical originals must not be parsed again")

    monkeypatch.setattr(json, "loads", no_reparse)
    prepared = wire.prepare_request_response("ab" * 32, metadata, collector, len(expected))
    assert prepared.sha256 == expected_digest
    assert prepared.finish(signature) == expected
    assert not collector._values
    assert len(collector.values) == len(source)
    assert events[-1]["status"] == "completed"
    assert events[-1]["completed_bytes"] == sum(map(len, source.values()))
    assert events[-1]["completed_operations"] == len(source)
    assert events[-1]["eta_seconds"] == 0
    assert events[0]["planning_eta_seconds"] is not None


def test_signature_suffix_stays_inside_original_byte_limit():
    metadata, collector, source = originals()
    response = expected_response(metadata, source)
    signature = {"signature": "long" * 100}
    maximum = len(canonical_json_bytes({"response": response, "signature": signature})) - 1
    prepared = wire.prepare_request_response("ab" * 32, metadata, collector, maximum)
    with pytest.raises(OSError, match="capacity"):
        prepared.finish(signature)


def test_wire_bound_interrupts_assembly_without_changing_originals():
    metadata, collector, source = originals(size=1024)
    with pytest.raises(OSError, match="capacity"):
        wire.prepare_request_response("ab" * 32, metadata, collector, 1024)
    assert len(source) == 3 and all(source.values())


def test_assembly_keeps_one_output_buffer_and_no_expanded_object_graph():
    metadata, collector, _source = originals(count=16, size=256 * 1024)
    tracemalloc.start()
    try:
        prepared = wire.prepare_request_response("ab" * 32, metadata, collector, 16 * 1024**2)
        raw = prepared.finish({"signature": "synthetic"})
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < len(raw) * 1.5 + 256 * 1024
    response_bytes = raw[len(b'{"response":') : raw.rindex(b',"signature":')]
    assert (
        prepared.sha256 == hashlib.sha256(b"umi-open-competition-v1\0" + response_bytes).hexdigest()
    )


def test_prepared_digest_signing_keeps_original_object_signature_domain():
    from umi.open_competition import (
        sign_competition_digest,
        verify_competition_digest,
        verify_signature,
    )

    from .test_open_competition import wallet

    value = {"challenge": "ab" * 32, "value": "é𐀀"}
    expected = digest(value)
    signature = sign_competition_digest(expected, wallet("Charlie"))
    verify_signature(value, signature)
    verify_competition_digest(expected, signature)
    with pytest.raises(ValueError, match="invalid competition signature"):
        verify_competition_digest("cd" * 32, signature)
    with pytest.raises(ValueError, match="invalid prepared"):
        verify_competition_digest("not a digest", signature)


def test_owned_wire_still_enforces_the_original_object_key_schema():
    metadata, collector, _source = originals()
    collector._sizes["invalid key"] = 1
    with pytest.raises(ValueError, match="canonical digest"):
        wire.prepare_request_response("ab" * 32, metadata, collector, 1024**2)
