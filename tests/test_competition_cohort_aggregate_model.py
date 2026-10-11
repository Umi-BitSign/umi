import hashlib
import math

import pytest
import rfc8785
from pydantic import Field, JsonValue, model_serializer

from umi.canonical_stream import canonical_json_sha256, canonical_json_size
from umi.competition_cohort_aggregate_model import AggregateProtocolModel
from umi.open_competition import digest
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Aggregate(AggregateProtocolModel):
    schema_: str = Field(alias="schema")
    objects: tuple[JsonValue, ...]
    optional: str | None = None

    @model_serializer(mode="wrap")
    def omit_default(self, handler):
        body = handler(self)
        if self.optional is None:
            body.pop("optional")
        return body


@pytest.mark.parametrize("optional", [None, "present"])
def test_streamed_aggregate_domain_size_and_hash_preserve_exact_bytes(optional):
    value = Aggregate(
        schema="test/1",
        objects=({"𐀀": ["é", -0.0, 1e-7, 2**53 - 1], "\ue000": {"a": True}},),
        optional=optional,
    )
    raw = canonical_json_bytes(value)
    assert canonical_json_size(value) == len(raw)
    assert (
        canonical_json_sha256(value, b"prefix\0") == hashlib.sha256(b"prefix\0" + raw).hexdigest()
    )
    assert digest(value) == hashlib.sha256(b"umi-open-competition-v1\0" + raw).hexdigest()
    assert Aggregate.model_validate_json(raw) == value


@pytest.mark.parametrize("bad", [2**53, -(2**53), math.nan, math.inf, -math.inf, "\ud800"])
def test_aggregate_rejects_the_same_invalid_protocol_domain(bad):
    class Ordinary(StrictProtocolModel):
        objects: tuple[JsonValue, ...]

    class Streamed(AggregateProtocolModel):
        objects: tuple[JsonValue, ...]

    with pytest.raises(ValueError):
        Ordinary(objects=({"nested": bad},))
    with pytest.raises(ValueError):
        Streamed(objects=({"nested": bad},))


def test_domain_and_digest_do_not_allocate_serialized_output(monkeypatch):
    def buffered_output(*_args, **_kwargs):
        raise AssertionError("aggregate domain/hash must not allocate canonical output")

    monkeypatch.setattr(rfc8785, "dumps", buffered_output)
    value = Aggregate(schema="test/1", objects=({"nested": [1, 2, 3]},))
    assert canonical_json_size(value) > 0
    assert len(digest(value)) == 64


def test_mutated_nested_values_are_never_reused_as_authority():
    value = Aggregate(schema="test/1", objects=({"nested": [1, 2, 3]},))
    original = digest(value)
    value.objects[0]["nested"].append(4)
    assert digest(value) != original
    value.objects[0]["nested"].append(2**53)
    with pytest.raises(rfc8785.CanonicalizationError):
        digest(value)
