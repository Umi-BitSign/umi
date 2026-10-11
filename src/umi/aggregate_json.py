"""Bound JSON parser intermediates for plain cohort evidence inventories.

Each opted-in item is validated from its original JSON slice. The original
aggregate JSON validator then validates the unchanged metadata, typed inventory,
field constraints and aggregate invariants. No caller-owned object is reused.
Unsupported schemas and validation options keep Pydantic's ordinary path.
"""

import io
import json
from contextlib import suppress
from typing import Any, get_args, get_origin

from annotated_types import MaxLen, MinLen
from pydantic import AfterValidator, BaseModel, ValidationError
from pydantic_core import SchemaValidator, core_schema

from .canonical_aggregate import AggregateStreamModel, _default_schema
from .json_spans import UnsplitJSON, string_end, value_end, whitespace


class DetachedInventoryItem:
    """Explicit opt-in for the plain, idempotently validated evidence item."""


_ALLOWED_VALIDATORS = {
    ("umi.protocol", "StrictProtocolModel.validate_canonical_json_domain"),
    (
        "umi.competition_cohort_aggregate_model",
        "AggregateProtocolModel.validate_canonical_json_domain",
    ),
    ("umi.competition_cohort_reward_package", "CohortRewardPackage.unique_order"),
    ("umi.competition_cohort_settlement_inputs", "SettlementInputPackage.inventory"),
}


def _plain_validators(model: type[BaseModel]) -> bool:
    decorators = model.__pydantic_decorators__
    return not (
        decorators.field_validators
        or decorators.field_serializers
        or decorators.model_serializers
        or model.model_computed_fields
        or model.__pydantic_custom_init__
        or not _default_schema(model)
        or any(
            (v.func.__module__, v.func.__qualname__) not in _ALLOWED_VALIDATORS
            for v in decorators.model_validators.values()
        )
    )


def _opaque_schema_hook(value) -> bool:
    # The native hash/domain constraints use Pydantic's standard after wrapper,
    # which cannot introduce another model into the compiled schema graph.
    return type(value) is not AfterValidator and hasattr(value, "__get_pydantic_core_schema__")


def _needs_original_parser(annotation, seen=None) -> bool:
    seen = set() if seen is None else seen
    try:
        if annotation in seen:
            return False
        seen.add(annotation)
    except TypeError:
        # Exotic Annotated metadata can be unhashable. Keep it on the ordinary
        # path instead of failing eligibility before its validator can run.
        return True
    if isinstance(annotation, type) and issubclass(annotation, BaseModel):
        if issubclass(annotation, AggregateStreamModel) or not _default_schema(annotation):
            return True
        return any(
            _needs_original_parser(f.annotation, seen)
            or any(_opaque_schema_hook(m) for m in f.metadata)
            for f in annotation.model_fields.values()
        )
    if _opaque_schema_hook(annotation):
        return True
    return any(_needs_original_parser(a, seen) for a in get_args(annotation))


def _layout(model: type[BaseModel], seen=None) -> dict[str, type[BaseModel]] | None:
    seen = set() if seen is None else seen
    if model in seen or not issubclass(model, AggregateStreamModel) or not _plain_validators(model):
        return None
    if model.model_config != {"extra": "forbid", "strict": True, "frozen": True}:
        return None
    seen = seen | {model}
    parts = {}
    for name, field in model.model_fields.items():
        # Another field's alias must never observe an internal placeholder.
        if any(
            alias is not None
            and (
                not isinstance(alias, str)
                or (alias in ("objects", "evidence", "response") and alias != name)
            )
            for alias in (field.alias, field.validation_alias)
        ):
            return None
        annotation = field.annotation
        if name == "objects":
            args = get_args(annotation)
            if not (
                get_origin(annotation) is tuple
                and len(args) == 2
                and args[1] is Ellipsis
                and isinstance(args[0], type)
                and DetachedInventoryItem in args[0].__bases__
                and _plain_validators(args[0])
                and getattr(args[0].model_validate_json, "__func__", None)
                is BaseModel.model_validate_json.__func__
                and all(isinstance(m, (MinLen, MaxLen)) for m in field.metadata)
                and field.is_required()
                and field.alias in (None, name)
                and field.validation_alias in (None, name)
            ):
                return None
            parts[name] = args[0]
        elif (
            name in ("evidence", "response")
            and isinstance(annotation, type)
            and issubclass(annotation, AggregateStreamModel)
        ):
            if (
                field.metadata
                or not field.is_required()
                or field.alias not in (None, name)
                or field.validation_alias not in (None, name)
                or not _layout(annotation, seen)
            ):
                return None
            parts[name] = annotation
        elif _needs_original_parser(annotation) or any(
            _opaque_schema_hook(m) for m in field.metadata
        ):
            # Every aggregate validator invocation must correspond to an
            # explicitly traversed envelope; no unvisited marker can be consumed.
            return None
    return parts or None


class _Inventories:
    def __init__(self):
        self.pending: dict[int, tuple[type[BaseModel], tuple[BaseModel, ...]]] = {}
        self.sequence = 0

    def retain(self, model, items) -> int:
        self.sequence += 1
        self.pending[self.sequence] = (model, tuple(items))
        return self.sequence

    def restore(self, model, marker):
        if type(marker) is not int:
            raise ValueError("invalid private inventory placeholder")
        entry = self.pending.pop(marker, None)
        if entry is None or entry[0] is not model:
            raise ValueError("detached inventory does not match its aggregate schema")
        return entry[1]


def _bound_validator(model, inventories):
    inventory_models = {model for model, _ in inventories.pending.values()}

    def copy(schema):
        if isinstance(schema, list):
            return [copy(value) for value in schema]
        if not isinstance(schema, dict):
            return schema
        result = {
            key: value if key in ("metadata", "default", "config") else copy(value)
            for key, value in schema.items()
        }
        if result.get("type") == "model" and result.get("cls") in inventory_models:
            cls = result["cls"]
            fields = result["schema"]
            if fields.get("type") != "model-fields":
                raise UnsplitJSON
            field = fields["fields"]["objects"]
            # The original tuple schema, item schema, length constraints and
            # aggregate validators remain intact. Only this private parser can
            # replace its own scalar placeholders with detached typed objects.
            field["schema"] = core_schema.no_info_before_validator_function(
                lambda marker, cls=cls: inventories.restore(cls, marker), field["schema"]
            )
        return result

    return SchemaValidator(copy(model.__pydantic_core_schema__))


def _array(raw, start, item_model, depth):
    if start >= len(raw) or raw[start] != 91:
        raise UnsplitJSON
    position = whitespace(raw, start + 1)
    items = []
    if position < len(raw) and raw[position] == 93:
        return items, position + 1
    while True:
        end = value_end(raw, position, depth + 1)
        items.append(item_model.model_validate_json(raw[position:end]))
        position = whitespace(raw, end)
        if position >= len(raw):
            raise UnsplitJSON
        if raw[position] == 93:
            return items, position + 1
        if raw[position] != 44:
            raise UnsplitJSON
        position = whitespace(raw, position + 1)
        if position >= len(raw) or raw[position] == 93:
            raise UnsplitJSON


def _model(raw, start, model, inventories, depth=0):
    start = whitespace(raw, start)
    if depth > 128 or start >= len(raw) or raw[start] != 123:
        raise UnsplitJSON
    parts = _layout(model)
    if not parts:
        raise UnsplitJSON
    output = io.BytesIO()
    output.write(b"{")
    cursor, position, seen = start + 1, whitespace(raw, start + 1), set()
    if position < len(raw) and raw[position] == 125:
        return raw[start : position + 1], position + 1
    while True:
        key_end = string_end(raw, position)
        key = json.loads(raw[position:key_end])
        if key in seen:
            raise UnsplitJSON
        seen.add(key)
        position = whitespace(raw, key_end)
        if position >= len(raw) or raw[position] != 58:
            raise UnsplitJSON
        position = whitespace(raw, position + 1)
        output.write(raw[cursor:position])
        if key == "objects" and key in parts:
            items, end = _array(raw, position, parts[key], depth + 1)
            output.write(str(inventories.retain(model, items)).encode("ascii"))
            del items
        elif key in parts:
            metadata, end = _model(raw, position, parts[key], inventories, depth + 1)
            output.write(metadata)
        else:
            end = value_end(raw, position, depth + 1)
            output.write(raw[position:end])
        cursor = end
        position = whitespace(raw, end)
        if position >= len(raw):
            raise UnsplitJSON
        if raw[position] == 125:
            output.write(raw[cursor : position + 1])
            return output.getvalue(), position + 1
        if raw[position] != 44:
            raise UnsplitJSON
        position = whitespace(raw, position + 1)
        if position >= len(raw) or raw[position] == 125:
            raise UnsplitJSON


def _prepare(raw, model):
    inventories = _Inventories()
    metadata, end = _model(raw, 0, model, inventories)
    if whitespace(raw, end) != len(raw):
        raise UnsplitJSON
    return metadata, inventories


def validate_aggregate_json(model, raw, ordinary, **options: Any):
    """Keep raw bytes and one final graph; bound parser intermediates per item."""
    if (
        type(raw) is not bytes
        or any(value is not None for value in options.values())
        or not _layout(model)
    ):
        return ordinary(raw, **options)
    prepared = None
    with suppress(UnsplitJSON, json.JSONDecodeError, UnicodeError, ValidationError):
        prepared = _prepare(raw, model)
    # Leave the exception scope before fallback so no partial inventory remains
    # retained by its traceback alongside the ordinary parser's complete graph.
    if prepared is None:
        return ordinary(raw, **options)
    metadata, inventories = prepared
    value = _bound_validator(model, inventories).validate_json(metadata, **options)
    if inventories.pending:
        raise ValueError("detached inventory was not consumed by aggregate validation")
    return value
