"""Exact Pydantic parity and bounded traversal for aggregate evidence."""

import hashlib
import math
import tracemalloc
from typing import Annotated

import pytest
import rfc8785
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    PlainSerializer,
    field_serializer,
    field_validator,
)
from pydantic_core import core_schema

from umi.canonical_aggregate import _parts
from umi.canonical_reuse import canonical_json_reuse
from umi.canonical_stream import canonical_json_matches, canonical_json_sha256, canonical_json_size
from umi.competition_cohort_aggregate_files import publish_aggregate_model, read_aggregate_model
from umi.competition_cohort_aggregate_model import AggregateProtocolModel
from umi.open_competition import digest
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Object(StrictProtocolModel):
    value: JsonValue


class Inventory(AggregateProtocolModel):
    schema_: str = Field(default="inventory/1", alias="schema")
    objects: Annotated[tuple[Object, ...], Field(max_length=65536)]
    optional: str | None = None


class Response(AggregateProtocolModel):
    evidence: Inventory
    challenge: str = "challenge"


class SignedResponse(AggregateProtocolModel):
    response: Response
    signature: str = "signature"


def assert_parity(value):
    expected = rfc8785.dumps(value.model_dump(mode="json", by_alias=True))
    assert canonical_json_bytes(value) == expected
    assert canonical_json_size(value) == len(expected)
    assert canonical_json_matches(value, expected)
    assert not canonical_json_matches(value, expected + b" ")
    assert not canonical_json_matches(value, expected[:-1])
    assert (
        canonical_json_sha256(value, b"test\0") == hashlib.sha256(b"test\0" + expected).hexdigest()
    )
    assert digest(value) == hashlib.sha256(b"umi-open-competition-v1\0" + expected).hexdigest()
    return expected


@pytest.mark.parametrize("count", [0, 1, 17])
def test_inventory_and_nested_envelopes_match_original_pydantic_bytes(count):
    value = Inventory(
        objects=tuple(
            Object(value={"𐀀": ["é", -0.0, 1e-7, 2**53 - 1], "\ue000": True}) for _ in range(count)
        )
    )
    for model in (
        value,
        Response(evidence=value),
        SignedResponse(response=Response(evidence=value)),
    ):
        assert _parts(model)
        assert_parity(model)


def test_every_aggregate_path_excludes_inventory_from_whole_model_dump(monkeypatch, tmp_path):
    original = BaseModel.model_dump
    calls = []

    def guarded(self, *args, **kwargs):
        if isinstance(self, AggregateProtocolModel):
            name = (
                "objects"
                if isinstance(self, Inventory)
                else "evidence"
                if isinstance(self, Response)
                else "response"
            )
            assert name in kwargs.get("exclude", set()), "whole aggregate graph was dumped"
            calls.append((type(self).__name__, name))
        return original(self, *args, **kwargs)

    monkeypatch.setattr(BaseModel, "model_dump", guarded)
    value = SignedResponse(
        response=Response(evidence=Inventory(objects=(Object(value={"a": [1, 2]}),)))
    )
    raw = canonical_json_bytes(value)
    assert canonical_json_size(value) == len(raw)
    assert canonical_json_matches(value, raw)
    assert len(digest(value)) == 64
    assert SignedResponse.model_validate_json(raw) == value
    path = tmp_path / "outbox" / "aggregate.json"
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    inode = path.stat().st_ino
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    assert path.stat().st_ino == inode
    assert read_aggregate_model(path, SignedResponse, maximum_bytes=1024**3) == value
    assert {name for name, _ in calls} == {"Inventory", "Response", "SignedResponse"}


def test_typed_item_projection_preserves_aliases_serializers_and_subclass_exclusion():
    class SerializedObject(Object):
        field: str = Field(default="a", serialization_alias="renamed")
        hidden: str = Field(default="secret", exclude=True)

        @field_serializer("field")
        def serialize(self, value):
            return value.upper()

    class ExtendedObject(SerializedObject):
        extra: str = "must not be serialized through base annotation"

    class Typed(AggregateProtocolModel):
        objects: tuple[SerializedObject, ...] = Field(serialization_alias="𐀀")
        before: str = Field(default="x", serialization_alias="\ue000")

    model = Typed(objects=(ExtendedObject(value=[1, 2]),))
    raw = assert_parity(model)
    assert b"secret" not in raw and b"extra" not in raw
    assert b'"renamed":"A"' in raw
    assert _parts(model)


def test_aggregate_custom_field_serializer_uses_ordinary_projection():
    class Custom(Inventory):
        @field_serializer("objects")
        def serialize(self, value):
            return {"count": len(value)}

    value = Custom(objects=(Object(value=1),))
    assert not _parts(value)
    assert b'"objects":{"count":1}' in assert_parity(value)


def test_annotated_container_serializer_is_never_bypassed():
    class Custom(AggregateProtocolModel):
        objects: Annotated[tuple[Object, ...], PlainSerializer(lambda value: {"count": len(value)})]

    value = Custom(objects=(Object(value=1),))
    assert not _parts(value)
    assert b'"objects":{"count":1}' in assert_parity(value)


def test_excluded_inventory_and_alias_collision_keep_pydantic_semantics():
    class Excluded(Inventory):
        objects: tuple[Object, ...] = Field(exclude=True)

    class Collision(Inventory):
        another: str = Field(default="replacement", serialization_alias="objects")

    for value in (Excluded(objects=(Object(value=1),)), Collision(objects=(Object(value=1),))):
        assert not _parts(value)
        assert_parity(value)


def test_envelope_subclass_projection_keeps_annotated_schema():
    class ExtendedInventory(Inventory):
        extra: str = "not on the signed base schema"

    value = Response(evidence=ExtendedInventory(objects=(Object(value=1),)))
    assert not _parts(value)
    assert b"extra" not in assert_parity(value)


@pytest.mark.parametrize("bad", [2**53, -(2**53), math.nan, math.inf, -math.inf, "\ud800"])
def test_mutation_and_constructed_values_still_validate_full_canonical_domain(bad):
    value = Inventory(objects=(Object(value={"nested": [1]}),))
    value.objects[0].value["nested"].append(bad)
    for encode in (
        canonical_json_bytes,
        canonical_json_size,
        digest,
        lambda v: canonical_json_matches(v, b"mismatch"),
    ):
        with pytest.raises((ValueError, UnicodeError)):
            encode(value)
    with pytest.raises((ValueError, UnicodeError)):
        canonical_json_bytes(
            Inventory.model_construct(objects=(Object.model_construct(value=bad),))
        )


def test_exact_retry_preserves_schema_validation_and_normalization_rejection(tmp_path):
    class Normalized(Inventory):
        label: str

        @field_validator("label")
        @classmethod
        def normalized(cls, value):
            return value.strip()

    path = tmp_path / "outbox" / "aggregate.json"
    value = Normalized.model_construct(objects=(Object(value=1),), label=" padded ")
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    inode, original = path.stat().st_ino, path.read_bytes()
    with pytest.raises(ValueError, match="stable canonical bytes"):
        publish_aggregate_model(path, value, maximum_bytes=1024**3)
    assert (path.stat().st_ino, path.read_bytes()) == (inode, original)
    path2 = tmp_path / "outbox" / "invalid.json"
    invalid = Inventory.model_construct(objects=(Object.model_construct(value={"bad": object()}),))
    with pytest.raises((ValueError, TypeError)):
        publish_aggregate_model(path2, invalid, maximum_bytes=1024**3)
    assert not path2.exists()


def test_streaming_does_not_retain_all_dumped_objects():
    # The ordinary projection copies each nested list: > 1.5 MiB for this input.
    # A streaming count must retain only one item, plus bounded adapter metadata.
    value = Inventory(
        objects=tuple(Object(value={"numbers": list(range(2000))}) for _ in range(128))
    )
    canonical_json_size(value)
    tracemalloc.start()
    try:
        canonical_json_size(value)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 512 * 1024


def test_empty_serialization_alias_is_preserved():
    class EmptyAlias(Inventory):
        objects: tuple[Object, ...] = Field(serialization_alias="")

    value = EmptyAlias(objects=(Object(value=1),))
    assert _parts(value)
    assert b'"":[' in assert_parity(value)


def test_constructed_wrong_inventory_item_is_rejected_on_exact_retry(tmp_path):
    path = tmp_path / "outbox" / "invalid.json"
    value = Inventory.model_construct(objects=(123,))
    with pytest.warns(UserWarning):
        publish_aggregate_model(path, value, maximum_bytes=1024**3)
    inode = path.stat().st_ino
    with pytest.warns(UserWarning), pytest.raises(ValueError):
        publish_aggregate_model(path, value, maximum_bytes=1024**3)
    assert path.stat().st_ino == inode


def test_custom_core_serializer_keeps_ordinary_model_projection():
    class Custom(Inventory):
        @classmethod
        def __get_pydantic_core_schema__(cls, source, handler):
            schema = handler(source)
            schema["serialization"] = core_schema.plain_serializer_function_ser_schema(
                lambda value: {"count": len(value.objects)}
            )
            return schema

    value = Custom(objects=(Object(value=1),))
    assert not _parts(value)
    assert assert_parity(value) == b'{"count":1}'


def test_extra_fields_cannot_override_streamed_aliases_differently():
    class Extensible(Inventory):
        model_config = ConfigDict(extra="allow")
        objects: tuple[Object, ...] = Field(serialization_alias="inventory")

    value = Extensible(objects=(Object(value=1),), inventory="extra replaces alias")
    assert not _parts(value)
    assert b'"inventory":"extra replaces alias"' in assert_parity(value)


def test_canonical_reuse_scope_does_not_snapshot_or_reuse_aggregate_graph(monkeypatch):
    import umi.canonical_reuse as reuse

    value = Inventory(objects=(Object(value={"items": [1]}),))
    raw = canonical_json_bytes(value)

    def forbidden_snapshot(_value):
        pytest.fail("aggregate graph must not enter the ordinary serialization cache")

    monkeypatch.setattr(reuse, "_snapshot", forbidden_snapshot)
    with canonical_json_reuse():
        assert canonical_json_bytes(value) == raw
        value.objects[0].value["items"].append(2)
        assert canonical_json_bytes(value) != raw


def test_constructed_list_container_preserves_pydantic_fallback_projection():
    class ExtendedObject(Object):
        extra: str = "preserved by Pydantic for the invalid list container"

    value = Inventory.model_construct(objects=[ExtendedObject(value=1)])
    assert not _parts(value)
    with pytest.warns(UserWarning):
        raw = assert_parity(value)
    assert b"extra" in raw


def test_item_core_hook_with_parent_field_context_uses_parent_projection():
    class ContextObject(Object):
        @classmethod
        def __get_pydantic_core_schema__(cls, source, handler):
            schema = dict(handler(source))
            name = handler.field_name
            schema["serialization"] = core_schema.plain_serializer_function_ser_schema(
                lambda value: {"field": name, "value": value.value}
            )
            return schema

    class Custom(Inventory):
        objects: tuple[ContextObject, ...]

    value = Custom(objects=(ContextObject(value=1),))
    assert not _parts(value)
    assert b'"field":"objects"' in assert_parity(value)


def test_envelope_core_hook_with_parent_field_context_uses_parent_projection():
    class ContextInventory(Inventory):
        @classmethod
        def __get_pydantic_core_schema__(cls, source, handler):
            schema = dict(handler(source))
            name = handler.field_name
            schema["serialization"] = core_schema.plain_serializer_function_ser_schema(
                lambda value: {"field": name, "count": len(value.objects)}
            )
            return schema

    class Custom(Response):
        evidence: ContextInventory

    value = Custom(evidence=ContextInventory(objects=(Object(value=1),)))
    assert not _parts(value)
    assert b'"field":"evidence"' in assert_parity(value)


def test_envelope_model_dump_override_does_not_change_parent_projection():
    class OverriddenInventory(Inventory):
        def model_dump(self, *args, **kwargs):
            return {"changed": True}

    class Custom(Response):
        evidence: OverriddenInventory

    value = Custom(evidence=OverriddenInventory(objects=(Object(value=1),)))
    assert not _parts(value)
    assert b"changed" not in assert_parity(value)
