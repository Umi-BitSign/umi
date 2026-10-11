"""Stream plain aggregate inventories without copying their entire JSON graph.

Only AggregateProtocolModel opts in. Custom aggregate serialization keeps the
ordinary Pydantic path. Pydantic still serializes metadata and each typed object;
this module changes neither their JSON projection nor RFC 8785 scalar encoding.
"""

from typing import Any, Protocol, get_args, get_origin

import rfc8785
from annotated_types import MaxLen, MinLen
from pydantic import BaseModel, JsonValue, TypeAdapter


class AggregateStreamModel:
    """Internal marker for cohort aggregates eligible for bounded traversal."""


class _Sink(Protocol):
    def write(self, chunk: bytes) -> int: ...


def _alias(name, field):
    return name if field.serialization_alias is None else field.serialization_alias


def _default_schema(cls) -> bool:
    return (
        getattr(cls.__get_pydantic_core_schema__, "__func__", None)
        is BaseModel.__get_pydantic_core_schema__.__func__
    )


def _independent_item(annotation) -> bool:
    # Custom hooks can build a different serializer for handler.field_name in
    # the containing model than in a standalone adapter. Keep that projection.
    return annotation is JsonValue or (
        isinstance(annotation, type)
        and issubclass(annotation, BaseModel)
        and _default_schema(annotation)
    )


def _parts(value: BaseModel) -> dict[str, tuple[Any, TypeAdapter | None]]:
    """Conservatively split only plain inventories and aggregate envelopes.

    Model/field serializers may inspect the complete parent or exclusion context.
    Never bypass them. Conflicting aliases, excluded fields, unusual annotations
    and custom JSON configurations retain the ordinary serializer path.
    """
    cls = type(value)
    decorators = cls.__pydantic_decorators__
    if (
        decorators.model_serializers
        or decorators.field_serializers
        or cls.model_computed_fields
        or cls.model_dump is not BaseModel.model_dump
        or not _default_schema(cls)
        or cls.model_config.get("extra") != "forbid"
        or cls.model_config.get("json_encoders")
        or any(key.startswith("ser_json_") for key in cls.model_config)
    ):
        return {}
    aliases = [_alias(name, field) for name, field in cls.model_fields.items()]
    if len(aliases) != len(set(aliases)):
        return {}
    parts = {}
    for name in ("objects", "evidence", "response"):
        field = cls.model_fields.get(name)
        if (
            field is None
            or name not in value.__dict__
            or field.exclude
            or field.exclude_if is not None
            or any(not isinstance(m, (MinLen, MaxLen)) for m in field.metadata)
        ):
            continue
        item = getattr(value, name)
        annotation = field.annotation
        if name == "objects":
            args = get_args(annotation)
            if (
                get_origin(annotation) is tuple
                and len(args) == 2
                and args[1] is Ellipsis
                and type(item) is tuple
                and _independent_item(args[0])
            ):
                parts[name] = (item, TypeAdapter(args[0]))
        elif (
            type(item) is annotation
            and isinstance(item, AggregateStreamModel)
            and _default_schema(annotation)
            and annotation.model_dump is BaseModel.model_dump
        ):
            parts[name] = (item, None)
    return parts


def dump_aggregate(value: BaseModel, sink: _Sink) -> None:
    """Write exact canonical bytes, retaining at most one dumped inventory item."""
    parts = _parts(value)
    if not parts:
        rfc8785.dump(value.model_dump(mode="json", by_alias=True), sink)
        return
    metadata = value.model_dump(mode="json", by_alias=True, exclude=set(parts))
    fields = type(value).model_fields
    streamed = {_alias(name, fields[name]): part for name, part in parts.items()}
    sink.write(b"{")
    # RFC 8785 sorts property names by UTF-16 code units, including non-BMP keys.
    for index, key in enumerate(
        sorted(metadata.keys() | streamed.keys(), key=lambda k: k.encode("utf-16be"))
    ):
        if index:
            sink.write(b",")
        rfc8785.dump(key, sink)
        sink.write(b":")
        if key not in streamed:
            rfc8785.dump(metadata[key], sink)
            continue
        item, adapter = streamed[key]
        if adapter is None:
            dump_aggregate(item, sink)
            continue
        sink.write(b"[")
        for position, member in enumerate(item):
            if position:
                sink.write(b",")
            rfc8785.dump(adapter.dump_python(member, mode="json", by_alias=True), sink)
        sink.write(b"]")
    sink.write(b"}")
