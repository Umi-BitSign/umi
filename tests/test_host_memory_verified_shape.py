"""Retained native shape accounting without reading unchanged evidence payloads."""

import hashlib
import json

import pytest

from umi import host_memory_request_bounds as bounds
from umi.host_memory_requests import RequestStageBounds


@pytest.fixture
def selected_bounds(monkeypatch):
    selected = RequestStageBounds(
        maximum_records=2,
        maximum_objects=3,
        maximum_services=2,
        maximum_orders=2,
        maximum_inventory_entries=2,
        maximum_participants=2,
        maximum_catalogs=2,
        maximum_input_bytes=1024 * 1024,
        maximum_object_bytes=16384,
        maximum_declaration_bytes=65536,
        maximum_json_values=128,
        maximum_json_depth=8,
    )
    monkeypatch.setattr(bounds, "stage_bounds", lambda: selected)
    return selected


def descriptor(raw):
    return {
        "byte_sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        "values": bounds.check_stage_json(raw, kind="object"),
        "bounds_sha256": bounds.stage_shape_identity(),
        "maximum_bytes": 16 * 1024**2,
    }


def accounting():
    aggregate = bounds._evidence_values.get()
    return aggregate["remaining"], dict(aggregate["seen"])


@pytest.mark.parametrize("ordinary_first", [False, True])
def test_ordinary_and_retained_reads_charge_identical_bytes_once(selected_bounds, ordinary_first):
    raw = json.dumps(list(range(80))).encode()
    retained = descriptor(raw)
    with bounds.stage_evidence_budget():
        if ordinary_first:
            assert bounds.check_stage_json(raw, kind="object") == retained["values"]
        else:
            assert bounds.replay_stage_json_shape(**retained)
        charged = accounting()
        for _ in range(3):
            assert bounds.replay_stage_json_shape(**retained)
            assert bounds.check_stage_json(raw, kind="object") == retained["values"]
        assert accounting() == charged
        assert charged[0] == selected_bounds.maximum_json_values - retained["values"]
        assert len(charged[1]) == 1


def test_remaining_aggregate_rejection_matches_native_without_charging(selected_bounds):
    first = descriptor(json.dumps(list(range(80))).encode())
    second_raw = json.dumps(list(range(81))).encode()
    second = descriptor(second_raw)
    with bounds.stage_evidence_budget():
        assert bounds.replay_stage_json_shape(**first)
        before = accounting()
        with pytest.raises(ValueError, match="qualified value count"):
            bounds.replay_stage_json_shape(**second)
        assert accounting() == before
        with pytest.raises(ValueError, match="qualified value count"):
            bounds.check_stage_json(second_raw, kind="object")
        assert accounting() == before


def test_current_object_budget_still_applies_to_repeated_descriptor(selected_bounds):
    retained = descriptor(b'{"value":"original"}')
    with bounds.stage_evidence_budget():
        assert bounds.replay_stage_json_shape(**retained)
        before = accounting()
        with (
            bounds.stage_object_budget(retained["size"] - 1),
            pytest.raises(ValueError, match="qualified byte bound"),
        ):
            bounds.replay_stage_json_shape(**retained)
        assert accounting() == before
        with bounds.stage_object_budget(retained["size"]):
            assert bounds.replay_stage_json_shape(**retained)


@pytest.mark.parametrize("field", list(RequestStageBounds.model_fields))
def test_every_bound_change_misses_without_accounting(selected_bounds, monkeypatch, field):
    retained = descriptor(b'{"value":1}')
    changed = selected_bounds.model_copy(update={field: getattr(selected_bounds, field) + 1})
    with bounds.stage_evidence_budget():
        before = accounting()
        monkeypatch.setattr(bounds, "stage_bounds", lambda: changed)
        assert bounds.replay_stage_json_shape(**retained) is False
        assert accounting() == before
        monkeypatch.setattr(bounds, "stage_bounds", lambda: selected_bounds)
        assert bounds.replay_stage_json_shape(**retained)


def test_no_bound_and_selected_bound_are_distinct_contexts(selected_bounds, monkeypatch):
    original = descriptor(b'"original"')
    monkeypatch.setattr(bounds, "stage_bounds", lambda: None)
    unbounded = descriptor(b'"original"')
    assert unbounded["values"] is None
    assert bounds.replay_stage_json_shape(**unbounded)
    assert bounds.replay_stage_json_shape(**original) is False
    monkeypatch.setattr(bounds, "stage_bounds", lambda: selected_bounds)
    with bounds.stage_evidence_budget():
        before = accounting()
        assert bounds.replay_stage_json_shape(**unbounded) is False
        assert accounting() == before


def test_reuse_needs_no_source_bytes_tokenization_or_payload_hash(selected_bounds, monkeypatch):
    raw = b'{"unchanged":[1,2,3]}'
    retained = json.loads(json.dumps(descriptor(raw)))
    native_sha = hashlib.sha256

    def forbid_payload_hash(data=b"", *args, **kwargs):
        assert data != raw, "warm accounting rehashed its unchanged payload"
        return native_sha(data, *args, **kwargs)

    def forbid_tokens(*args, **kwargs):
        pytest.fail("warm accounting parsed its unchanged payload")

    monkeypatch.setattr(bounds.hashlib, "sha256", forbid_payload_hash)
    monkeypatch.setattr(bounds, "_tokens", forbid_tokens)
    with bounds.stage_evidence_budget():
        assert bounds.replay_stage_json_shape(**retained)
        assert accounting()[0] == selected_bounds.maximum_json_values - retained["values"]


@pytest.mark.parametrize(
    "change",
    [
        {"byte_sha256": "g" * 64},
        {"byte_sha256": "a" * 63},
        {"byte_sha256": b"a" * 64},
        {"size": 0},
        {"size": True},
        {"maximum_bytes": 0},
        {"maximum_bytes": True},
        {"values": 0},
        {"values": True},
        {"values": None},
        {"values": 129},
        {"kind": "unselected"},
    ],
)
def test_invalid_descriptor_refuses_without_charging(selected_bounds, change):
    retained = descriptor(b'{"value":1}') | change
    with bounds.stage_evidence_budget():
        before = accounting()
        with pytest.raises(ValueError, match="retained JSON shape"):
            bounds.replay_stage_json_shape(**retained)
        assert accounting() == before


def test_conflicting_retained_count_cannot_alias_an_ordinary_read(selected_bounds):
    raw = b'{"value":1}'
    retained = descriptor(raw)
    with bounds.stage_evidence_budget():
        bounds.check_stage_json(raw, kind="object")
        before = accounting()
        with pytest.raises(ValueError, match="changed its verified value count"):
            bounds.replay_stage_json_shape(**(retained | {"values": retained["values"] + 1}))
        assert accounting() == before


def test_explicit_capacity_applies_without_selected_bounds(monkeypatch):
    monkeypatch.setattr(bounds, "stage_bounds", lambda: None)
    retained = descriptor(b'"original"')
    with pytest.raises(ValueError, match="qualified byte bound"):
        bounds.replay_stage_json_shape(**(retained | {"maximum_bytes": retained["size"] - 1}))
    assert bounds.replay_stage_json_shape(**(retained | {"maximum_bytes": retained["size"]}))


def test_nested_budget_and_new_operation_charge_exactly_once(selected_bounds):
    retained = descriptor(b'{"value":1}')
    for _ in range(2):
        with bounds.stage_evidence_budget():
            assert bounds.replay_stage_json_shape(**retained)
            before = accounting()
            with bounds.stage_evidence_budget():
                assert bounds.replay_stage_json_shape(**retained)
                assert accounting() == before
            assert before[0] == selected_bounds.maximum_json_values - retained["values"]


def test_shape_reuse_checks_but_does_not_consume_declaration_bytes(selected_bounds):
    retained = descriptor(b'{"value":1}') | {"kind": "declaration"}
    token = bounds._declarations.set([retained["size"]])
    try:
        assert bounds.replay_stage_json_shape(**retained)
        assert bounds._declarations.get() == [retained["size"]]
        bounds._declarations.get()[0] -= 1
        with pytest.raises(ValueError, match="qualified byte bound"):
            bounds.replay_stage_json_shape(**retained)
        assert bounds._declarations.get() == [retained["size"] - 1]
    finally:
        bounds._declarations.reset(token)
