from __future__ import annotations

import random
from concurrent.futures import ThreadPoolExecutor
from contextvars import copy_context
from typing import Any

import pytest
import rfc8785
from pydantic import ValidationError, model_validator

from umi import canonical_reuse as reuse
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Nested(StrictProtocolModel):
    value: dict[str, Any]


def test_nested_mutation_uses_new_content_and_rechecks_domain():
    with reuse.canonical_json_reuse():
        model = Nested(value={"items": [{"number": 1}]})
        before = canonical_json_bytes(model)
        model.value["items"][0]["number"] = 2
        assert canonical_json_bytes(model) != before
        assert canonical_json_bytes(model) == rfc8785.dumps(model.model_dump(mode="json"))
        model.value["items"][0]["number"] = 2**53
        with pytest.raises(rfc8785.IntegerDomainError):
            canonical_json_bytes(model)
        with pytest.raises(ValidationError, match="RFC 8785"):
            Nested(value=model.value)


def test_mutation_during_key_encoding_cannot_poison_the_cached_bytes(monkeypatch):
    source = {"items": [{"number": 1}]}
    original = reuse.json.dumps

    def mutate_after_encoding(*args, **kwargs):
        result = original(*args, **kwargs)
        source["items"][0]["number"] = 2
        return result

    monkeypatch.setattr(reuse.json, "dumps", mutate_after_encoding)
    with reuse.canonical_json_reuse():
        assert canonical_json_bytes(source) == b'{"items":[{"number":1}]}'
        assert canonical_json_bytes(source) == b'{"items":[{"number":2}]}'
        assert canonical_json_bytes({"items": [{"number": 1}]}) == b'{"items":[{"number":1}]}'


@pytest.mark.parametrize(
    ("valid", "invalid"),
    [
        ({"1": "x"}, {1: "x"}),
        ({"true": "x"}, {True: "x"}),
        ({"null": "x"}, {None: "x"}),
        ({"value": "😀"}, {"value": "\ud83d\ude00"}),
        ({"😀": "x"}, {"\ud83d\ude00": "x"}),
        ({"value": "NaN"}, {"value": float("nan")}),
        ({"value": "Infinity"}, {"value": float("inf")}),
        ({"value": "-Infinity"}, {"value": float("-inf")}),
        ({"value": 2**53 - 1}, {"value": 2**53}),
        ({"value": -(2**53) + 1}, {"value": -(2**53)}),
    ],
)
def test_invalid_content_cannot_alias_a_successful_cache_entry(valid, invalid):
    with pytest.raises((ValueError, rfc8785.CanonicalizationError)) as original:
        rfc8785.dumps(invalid)
    with reuse.canonical_json_reuse():
        assert canonical_json_bytes(valid) == rfc8785.dumps(valid)
        for _ in range(2):
            with pytest.raises(type(original.value)):
                canonical_json_bytes(invalid)


def test_semantic_validator_runs_again_after_identical_content_hits():
    allowed = True
    checks = []

    class Checked(StrictProtocolModel):
        value: int

        @model_validator(mode="after")
        def current_authority(self):
            checks.append(allowed)
            if not allowed:
                raise ValueError("authority changed")
            return self

    with reuse.canonical_json_reuse():
        Checked.model_validate_json(b'{"value":1}')
        Checked.model_validate_json(b'{"value":1}')
        allowed = False
        with pytest.raises(ValidationError, match="authority changed"):
            Checked.model_validate_json(b'{"value":1}')
    assert checks == [True, True, False]


def test_reuses_only_canonical_bytes_and_releases_them_at_operation_end(monkeypatch):
    calls = []
    original = reuse.rfc8785.dumps

    def counted(value):
        calls.append(value)
        return original(value)

    monkeypatch.setattr(reuse.rfc8785, "dumps", counted)
    with reuse.canonical_json_reuse():
        cache = reuse._ACTIVE.get()
        assert canonical_json_bytes({"value": 1}) == b'{"value":1}'
        with reuse.canonical_json_reuse():
            assert canonical_json_bytes({"value": 1}) == b'{"value":1}'
        inherited = copy_context()
        assert len(calls) == 1
    assert cache.closed and not cache.entries and cache.size == 0
    inherited.run(canonical_json_bytes, {"value": 1})
    assert len(calls) == 2
    assert reuse._ACTIVE.get() is None


@pytest.mark.parametrize(("budget", "entries"), [(0, 0), (1, 1), (80, 2)])
def test_cache_budgets_evict_or_bypass_without_rejecting_inputs(budget, entries):
    with reuse.canonical_json_reuse(maximum_bytes=budget, maximum_entries=entries):
        cache = reuse._ACTIVE.get()
        for value in [{"n": n} for n in range(20)] + [{"large": "x" * 10000}]:
            assert canonical_json_bytes(value) == rfc8785.dumps(value)
            assert cache.size <= budget and len(cache.entries) <= entries


def test_exception_closes_cache_and_context():
    with pytest.raises(RuntimeError), reuse.canonical_json_reuse():
        canonical_json_bytes({"value": 1})
        cache = reuse._ACTIVE.get()
        raise RuntimeError("abort")
    assert cache.closed and not cache.entries and reuse._ACTIVE.get() is None


def test_copied_thread_contexts_are_bounded_and_independent_operations_are_isolated():
    with reuse.canonical_json_reuse(maximum_bytes=500, maximum_entries=8):
        cache = reuse._ACTIVE.get()
        contexts = [copy_context() for _ in range(32)]
        with ThreadPoolExecutor(max_workers=4) as pool:
            outputs = list(pool.map(lambda ctx: ctx.run(canonical_json_bytes, {"n": 1}), contexts))
            assert pool.submit(reuse._ACTIVE.get).result() is None
        assert outputs == [b'{"n":1}'] * 32
        assert cache.size <= 500 and len(cache.entries) == 1


def test_generated_nested_values_match_original_rfc_bytes():
    rng = random.Random(917)
    atoms = [None, True, False, 0, -0.0, 1.0, 1e-7, 1e21, 2**53 - 1, "", "😀", "\n", "é"]

    def value(depth):
        if depth == 0 or rng.random() < 0.4:
            return rng.choice(atoms)
        if rng.random() < 0.5:
            return [value(depth - 1) for _ in range(rng.randrange(4))]
        return {k: value(depth - 1) for k in rng.sample(["a", "z", "😀", "\ue000"], 3)}

    with reuse.canonical_json_reuse(maximum_bytes=8192, maximum_entries=32):
        for _ in range(500):
            item = value(4)
            expected = rfc8785.dumps(item)
            assert canonical_json_bytes(item) == canonical_json_bytes(item) == expected
