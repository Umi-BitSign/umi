"""Split parsing must preserve full JSON-mode validation and detached snapshots."""

import copy
import json
import random
from typing import Annotated, Any

import pytest
from pydantic import (
    AfterValidator,
    AliasChoices,
    AliasPath,
    BaseModel,
    BeforeValidator,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

import umi.aggregate_json as decoding
from umi.competition_cohort_aggregate_files import publish_aggregate_model, read_aggregate_model
from umi.competition_cohort_aggregate_model import AggregateProtocolModel
from umi.competition_cohort_request_export import (
    RequestReviewExport,
    RequestReviewResponse,
    SignedRequestReviewResponse,
)
from umi.competition_cohort_reward_package import CohortRewardPackage, RewardPackageObject
from umi.competition_cohort_settlement_inputs import SettlementInputPackage
from umi.protocol import canonical_json_bytes


class Inventory(AggregateProtocolModel):
    objects: Annotated[tuple[RewardPackageObject, ...], Field(max_length=128)]
    label: str = "metadata"


class Envelope(AggregateProtocolModel):
    evidence: Inventory
    challenge: str = "challenge"


class Signed(AggregateProtocolModel):
    response: Envelope
    signature: str = "signature"


def ordinary(model, raw, **options):
    return BaseModel.model_validate_json.__func__(model, raw, **options)


def item(value):
    return RewardPackageObject(sha256="0" * 64, value=value)


def assert_parse_parity(model, raw, **options):
    try:
        expected = ordinary(model, raw, **options)
    except ValueError:
        with pytest.raises(ValueError):
            model.model_validate_json(raw, **options)
        return None
    actual = model.model_validate_json(raw, **options)
    assert canonical_json_bytes(actual) == canonical_json_bytes(expected)
    return actual


@pytest.mark.parametrize("count", [0, 1, 7])
def test_inventory_and_nested_envelopes_preserve_original_json_projection(count):
    value = Inventory(objects=tuple(item({"x": ["é𐀀", '\\"{[]}\\\\', 1e-7]}) for _ in range(count)))
    for model in (value, Envelope(evidence=value), Signed(response=Envelope(evidence=value))):
        assert decoding._layout(type(model))
        parsed = assert_parse_parity(type(model), canonical_json_bytes(model))
        assert parsed == model


def test_native_aggregate_schemas_remain_supported():
    for model in (
        CohortRewardPackage,
        SettlementInputPackage,
        RequestReviewExport,
        RequestReviewResponse,
        SignedRequestReviewResponse,
    ):
        assert decoding._layout(model), model.__name__


def test_parser_receives_each_original_object_and_small_metadata_only(monkeypatch):
    value = Signed(
        response=Envelope(
            evidence=Inventory(objects=tuple(item({"values": list(range(80))}) for _ in range(64)))
        )
    )
    raw = canonical_json_bytes(value)
    original, calls = BaseModel.model_validate_json.__func__, []

    def guarded(cls, data, **options):
        calls.append((cls, len(data)))
        if cls is Signed:
            assert len(data) < 256, "monolithic inventory JSON was sent to the parser"
        return original(cls, data, **options)

    builder = decoding._bound_validator
    metadata_sizes = []

    def guarded_builder(model, inventories):
        validator = builder(model, inventories)

        class Guard:
            def validate_json(self, data, **options):
                metadata_sizes.append(len(data))
                assert len(data) < 256
                return validator.validate_json(data, **options)

        return Guard()

    monkeypatch.setattr(BaseModel, "model_validate_json", classmethod(guarded))
    monkeypatch.setattr(decoding, "_bound_validator", guarded_builder)
    decoded = Signed.model_validate_json(raw)
    assert decoded == value
    assert len(metadata_sizes) == 1
    assert len([c for c in calls if c[0] is RewardPackageObject]) == 64
    assert max(size for _, size in calls) < len(raw) / 32


def test_decoded_inventory_is_detached_from_caller_graph():
    value = Inventory(objects=(item({"nested": [1]}),))
    parsed = Inventory.model_validate_json(canonical_json_bytes(value))
    value.objects[0].value["nested"].append(2)
    assert parsed.objects[0].value == {"nested": [1]}
    parsed.objects[0].value["nested"].append(3)
    assert value.objects[0].value == {"nested": [1, 2]}


def test_full_field_constraints_are_not_replaced_with_empty_inventory():
    class Bounded(Inventory):
        objects: Annotated[tuple[RewardPackageObject, ...], Field(min_length=1, max_length=2)]

    for count in (0, 1, 2, 3):
        raw = canonical_json_bytes(Inventory(objects=tuple(item(i) for i in range(count))))
        assert_parse_parity(Bounded, raw)


@pytest.mark.parametrize(
    "raw",
    [
        b'{"objects":1}',
        b'{"objects":true}',
        b'{"objects":null}',
        b'{"objects":{"marker":1}}',
        b'{"objects":[] ,}',
        b'{"objects":[,]}',
        b'{"objects":[true]}',
        b'{"objects":[{}]}',
        b'{"objects":[]} trailing',
        b'{"objects":[],"label":1}',
        b'{"objects":[],"extra":true}',
        b'{"objects":[],"objects":1}',
        b'{"objects":1,"objects":[]}',
        b'{"objects":[{}],"objects":[]}',
        b'{"objects":[],"label":"a","label":"b"}',
        b' { "label" : "x", "objects" : [ ] }\n',
        b'{"objects":[],"label":"unterminated}',
        b'{"objects":[],"\xff":1}',
        rb'{"objects":[],"label":"\ud800"}',
    ],
)
def test_malformed_noncanonical_duplicates_and_marker_spoofs_keep_validation(raw):
    assert_parse_parity(Inventory, raw)


def test_invalid_nested_domain_and_sha_still_fail():
    for value in (2**53, float("nan"), "\ud800"):
        raw = json.dumps({"objects": [{"sha256": "0" * 64, "value": value}]}).encode()
        assert_parse_parity(Inventory, raw)
    assert_parse_parity(Inventory, b'{"objects":[{"sha256":"wrong","value":1}]}')


def test_deep_json_retains_native_recursion_boundary():
    for depth in (125, 130, 198, 202):
        raw = (
            b'{"objects":[{"sha256":"'
            + b"0" * 64
            + b'","value":'
            + b"[" * depth
            + b"0"
            + b"]" * depth
            + b"}]}"
        )
        assert_parse_parity(Inventory, raw)


def test_custom_before_and_after_validators_use_ordinary_input_semantics():
    class Before(Inventory):
        @model_validator(mode="before")
        @classmethod
        def check_raw_items(cls, data):
            assert isinstance(data["objects"], list)
            return data

    class FieldBefore(Inventory):
        @field_validator("objects", mode="before")
        @classmethod
        def check_raw_items(cls, data):
            assert isinstance(data, list)
            return data

    class After(Inventory):
        @model_validator(mode="after")
        def check_context(self, info):
            assert info.context is None
            return self

    raw = canonical_json_bytes(Inventory(objects=(item(1),)))
    for model in (Before, FieldBefore, After):
        assert decoding._layout(model) is None
        assert_parse_parity(model, raw)


def test_nested_metadata_observes_original_validation_context():
    class Metadata(BaseModel):
        value: str

        @field_validator("value")
        @classmethod
        def context(cls, value, info):
            assert info.context is None
            return value

    class WithMetadata(Inventory):
        metadata: Metadata

    assert decoding._layout(WithMetadata)
    value = WithMetadata(objects=(item(1),), metadata=Metadata(value="v"))
    assert_parse_parity(WithMetadata, canonical_json_bytes(value))


def test_unvisited_nested_aggregate_cannot_consume_inventory_marker():
    class More(Inventory):
        hidden: tuple[Inventory, ...]

    assert decoding._layout(More) is None
    raw = b'{"objects":[],"hidden":[{"objects":1}]}'
    assert_parse_parity(More, raw)


@pytest.mark.parametrize(
    "options",
    [
        {"strict": True},
        {"strict": False},
        {"extra": "ignore"},
        {"context": {}},
        {"by_alias": True},
        {"by_name": True},
    ],
)
def test_explicit_validation_options_use_the_original_parser(options, monkeypatch):
    raw = canonical_json_bytes(Inventory(objects=(item(1),)))
    monkeypatch.setattr(
        decoding, "_prepare", lambda *_: pytest.fail("custom options must use ordinary parser")
    )
    assert_parse_parity(Inventory, raw, **options)


def test_exact_private_retry_and_reopen_preserve_inode_and_validation(tmp_path):
    path = tmp_path / "outbox" / "inventory.json"
    value = Inventory(objects=(item({"nested": [1]}),))
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    inode, raw = path.stat().st_ino, path.read_bytes()
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    assert (path.stat().st_ino, path.read_bytes()) == (inode, raw)
    reopened = read_aggregate_model(path, Inventory, maximum_bytes=1024**3)
    assert reopened == value and reopened.objects[0] is not value.objects[0]
    value.objects[0].value["nested"].append(2)
    with pytest.raises(ValueError, match="different bytes"):
        publish_aggregate_model(path, value, maximum_bytes=1024**3)
    assert path.read_bytes() == raw


def test_constructed_invalid_item_still_fails_exact_retry(tmp_path):
    path = tmp_path / "outbox" / "invalid.json"
    value = Inventory.model_construct(
        objects=(RewardPackageObject.model_construct(sha256="invalid", value=1),)
    )
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    inode = path.stat().st_ino
    with pytest.raises(ValidationError):
        publish_aggregate_model(path, value, maximum_bytes=1024**3)
    assert path.stat().st_ino == inode


def test_seeded_nested_objects_preserve_parser_and_canonical_bytes():
    rng = random.Random(8785)

    def value(depth=0):
        choices = [None, True, False, rng.randrange(-1000, 1000), rng.random(), '\\"[]{}é𐀀\\\\']
        if depth < 4:
            choices.extend(
                [
                    [value(depth + 1) for _ in range(rng.randrange(3))],
                    {str(i): value(depth + 1) for i in range(rng.randrange(3))},
                ]
            )
        return rng.choice(choices)

    for _ in range(80):
        body = Inventory(objects=tuple(item(value()) for _ in range(rng.randrange(5))))
        assert_parse_parity(Inventory, canonical_json_bytes(body))


def test_operation_parser_never_mutates_or_caches_global_schema():
    original_schema = copy.deepcopy(Inventory.__pydantic_core_schema__)
    original_validator = Inventory.__pydantic_validator__
    first = Inventory.model_validate_json(canonical_json_bytes(Inventory(objects=(item(1),))))
    second = Inventory.model_validate_json(canonical_json_bytes(Inventory(objects=(item(2),))))
    assert first.objects[0].value == 1 and second.objects[0].value == 2
    assert Inventory.__pydantic_core_schema__ == original_schema
    assert Inventory.__pydantic_validator__ is original_validator
    with pytest.raises(ValueError):
        Inventory.model_validate_json(b'{"objects":1}')
    with pytest.raises(ValueError):
        ordinary(Inventory, b'{"objects":1}')


def test_unknown_item_subclasses_keep_the_original_validation_path():
    class CustomItem(RewardPackageObject):
        extra: str = "extra"

    class Custom(Inventory):
        objects: tuple[CustomItem, ...]

    assert decoding._layout(Custom) is None
    value = Custom(objects=(CustomItem(sha256="0" * 64, value=1),))
    assert_parse_parity(Custom, canonical_json_bytes(value))


@pytest.mark.parametrize(
    "alias", ["objects", AliasChoices("objects", "hidden"), AliasPath("objects")]
)
def test_other_field_alias_cannot_observe_private_inventory_marker(alias):
    class Aliased(Inventory):
        hidden: int = Field(validation_alias=alias)

    assert decoding._layout(Aliased) is None
    assert_parse_parity(Aliased, b'{"objects":[]}')


def test_non_inventory_metadata_alias_retains_json_projection():
    class MetadataAlias(Inventory):
        schema_: str = Field(alias="schema")

    assert decoding._layout(MetadataAlias)
    assert_parse_parity(MetadataAlias, b'{"objects":[],"schema":"metadata-v1"}')


def test_metadata_after_validator_remains_present_and_sees_validated_inventory():
    def check(value, info):
        assert info.data["objects"] == ()
        if value != "valid":
            raise ValueError("invalid metadata")
        return value

    class MetadataConstraint(Inventory):
        metadata: Annotated[str, AfterValidator(check)]

    assert decoding._layout(MetadataConstraint)
    assert_parse_parity(MetadataConstraint, b'{"objects":[],"metadata":"valid"}')
    assert_parse_parity(MetadataConstraint, b'{"objects":[],"metadata":"invalid"}')


def test_envelope_field_metadata_keeps_original_json_before_semantics():
    class Wrapped(AggregateProtocolModel):
        evidence: Annotated[Inventory, BeforeValidator(lambda value: value)]

    assert decoding._layout(Wrapped) is None
    assert_parse_parity(Wrapped, b'{"evidence":{"objects":[]}}')


def test_custom_init_receives_original_inventory_input():
    class CustomInit(Inventory):
        def __init__(self, **data):
            data["objects"] = tuple(data["objects"])
            super().__init__(**data)

    class Nested(AggregateProtocolModel):
        evidence: CustomInit

    assert decoding._layout(CustomInit) is None
    assert decoding._layout(Nested) is None
    assert_parse_parity(CustomInit, b'{"objects":[]}')
    assert_parse_parity(Nested, b'{"evidence":{"objects":[]}}')


def test_defaulted_inventories_and_envelopes_keep_original_default_semantics():
    class Defaulted(Inventory):
        objects: tuple[RewardPackageObject, ...] = ()

    class DefaultEnvelope(AggregateProtocolModel):
        evidence: Inventory = Field(default_factory=lambda: Inventory(objects=()))

    for model in (Defaulted, DefaultEnvelope):
        assert decoding._layout(model) is None
        assert_parse_parity(model, b"{}")
    assert_parse_parity(Defaulted, b'{"objects":[]}')
    assert_parse_parity(DefaultEnvelope, b'{"evidence":{"objects":[]}}')


def test_schema_copy_does_not_interpret_arbitrary_metadata_as_core_schema():
    class WithMetadata(Envelope):
        label: str = Field(default="x", json_schema_extra={"type": "model", "cls": Inventory})

    assert_parse_parity(WithMetadata, b'{"evidence":{"objects":[]}}')


def test_unhashable_nested_annotation_metadata_keeps_ordinary_parser():
    class Unhashable(Inventory):
        other: tuple[Annotated[str, {"x": 1}], ...]

    assert decoding._layout(Unhashable) is None
    assert_parse_parity(Unhashable, b'{"objects":[],"other":["x"]}')


def test_custom_metadata_schema_cannot_hide_an_aggregate_invocation():
    class Hidden:
        @classmethod
        def __get_pydantic_core_schema__(cls, source, handler):
            return handler(Inventory)

    class WithCustomType(Envelope):
        hidden: Hidden

    class WithAnnotated(Envelope):
        hidden: Annotated[Any, Hidden]

    class Metadata(BaseModel):
        hidden: Hidden

    class WithNestedMetadata(Envelope):
        metadata: Metadata

    raw = b'{"evidence":{"objects":[]},"hidden":{"objects":[]}}'
    for model in (WithCustomType, WithAnnotated):
        assert decoding._layout(model) is None
        assert_parse_parity(model, raw)
    assert decoding._layout(WithNestedMetadata) is None
    assert_parse_parity(
        WithNestedMetadata,
        b'{"evidence":{"objects":[]},"metadata":{"hidden":{"objects":[]}}}',
    )


def test_nonstandard_opted_in_item_parser_uses_original_aggregate_validation():
    from umi.protocol import StrictProtocolModel

    class Item(StrictProtocolModel, decoding.DetachedInventoryItem):
        value: int

        @staticmethod
        def model_validate_json(raw, **options):
            return BaseModel.model_validate_json.__func__(Item, raw, **options)

    class Container(AggregateProtocolModel):
        objects: tuple[Item, ...]

    assert decoding._layout(Container) is None
    assert_parse_parity(Container, b'{"objects":[{"value":1}]}')
