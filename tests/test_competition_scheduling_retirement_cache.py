"""Bounded immutable fact reuse; no journal writes or production replay."""

import hashlib
import threading
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import pytest

from umi.competition_scheduling_retirement_cache import RetirementValidationCache


@dataclass(frozen=True, slots=True)
class Claim:
    key: str
    evaluator: str
    publication: str
    body: str
    deadline: int
    claim: tuple[str, int, int, str]


@dataclass(frozen=True)
class DictFact:
    contents: object


@dataclass(frozen=True, slots=True)
class SlotFact:
    contents: object


def sha(index):
    return hashlib.sha256(str(index).encode()).hexdigest()


def facts(index):
    claims = tuple(
        Claim(
            sha((index, n)),
            sha("evaluator"),
            sha(index),
            sha(("body", index, n)),
            9120000 + n,
            (sha(("claim", index, n)), 9119900, 1790053000000, sha(n)),
        )
        for n in range(3)
    )
    return sha(("order", index)), sha(("decision", index)), claims


def measured(key, value):
    cache = RetirementValidationCache()
    assert cache.put(key, value)
    return cache.retained_bytes


def test_hundred_retirement_publication_pairs_do_not_replay_on_repeated_scans():
    cache = RetirementValidationCache()
    replay_calls = []
    pairs = [(kind, sha(n)) for n in range(150) for kind in ("retirement", "publication")]
    for _ in range(4):
        for kind, key in pairs:
            value = cache.get((kind, key))
            if value is None:
                replay_calls.append((kind, key))
                value = facts(key) if kind == "retirement" else (key, sha(key))
                assert cache.put((kind, key), value)
            assert value == (facts(key) if kind == "retirement" else (key, sha(key)))
    assert len(replay_calls) == len(pairs) == len(cache) == 300
    assert 0 < cache.retained_bytes < cache.maximum_bytes == 32 * 1024**2


def test_get_promotes_lru_and_eviction_is_by_bytes():
    value = b"x" * 1024
    weight = measured("a", value)
    cache = RetirementValidationCache(maximum_bytes=weight * 2)
    assert cache.put("a", value) and cache.put("b", value)
    assert cache.get("a") == value
    assert cache.put("c", value)
    assert cache.get("b") is None
    assert cache.get("a") == value and cache.get("c") == value
    assert len(cache) == 2 and cache.retained_bytes == weight * 2


def test_replacement_updates_weight_and_recency_without_double_charging():
    small, large = b"x" * 512, b"x" * 1024
    cache = RetirementValidationCache(maximum_bytes=2 * measured("a", small))
    assert cache.put("a", small) and cache.put("b", small)
    assert cache.put("a", small)
    assert cache.retained_bytes == 2 * measured("a", small)
    assert cache.put("a", large)
    assert cache.get("b") is None
    assert cache.get("a") == large
    assert len(cache) == 1 and cache.retained_bytes == measured("a", large)


def test_oversized_input_skips_without_flushing_other_entries():
    cache = RetirementValidationCache(maximum_bytes=4096)
    assert cache.put("a", ("small",)) and cache.put("b", ("keep",))
    before = cache.retained_bytes
    assert not cache.put("oversized", b"x" * 8192)
    assert cache.retained_bytes == before and len(cache) == 2
    assert not cache.put("a", b"x" * 8192)
    assert cache.get("a") is None
    assert cache.get("b") == ("keep",)
    assert cache.retained_bytes == measured("b", ("keep",))


@pytest.mark.parametrize("wrapper", [DictFact, SlotFact])
def test_nested_dataclass_payload_and_key_bytes_are_charged(wrapper):
    cache = RetirementValidationCache(maximum_bytes=4096)
    assert not cache.put("nested", wrapper((wrapper(b"x" * 8192),)))
    assert not cache.put(("retirement", "k" * 8192), ("small",))
    assert len(cache) == 0 and cache.retained_bytes == 0
    assert measured("key", wrapper(b"x" * 2048)) > measured("key", wrapper(b"x")) + 2000


def test_inherited_slots_and_dict_storage_are_counted():
    @dataclass(frozen=True, slots=True)
    class Base:
        first: bytes

    @dataclass(frozen=True, slots=True)
    class Child(Base):
        second: bytes

    cache = RetirementValidationCache(maximum_bytes=4096)
    assert not cache.put("key", Child(b"x" * 8192, b"small"))
    assert measured("key", DictFact(b"small")) > measured("key", SlotFact(b"small"))


def test_shared_members_count_once_within_entry_but_not_across_entries():
    first = bytes(bytearray(b"x" * 2048))
    second = bytes(bytearray(first))
    assert first == second and first is not second
    shared = measured("key", (first, first))
    separate = measured("key", (first, second))
    assert separate > shared + 2048
    cache = RetirementValidationCache()
    assert cache.put("one", (first, first)) and cache.put("two", (first, first))
    assert cache.retained_bytes == measured("one", (first, first)) + measured("two", (first, first))


@pytest.mark.parametrize(
    "value", [[], {"key": "value"}, ([],), DictFact([]), SlotFact({}), object()]
)
def test_mutable_or_unknown_facts_are_not_cached(value):
    cache = RetirementValidationCache()
    assert not cache.put("key", value)
    assert cache.get("key") is None and len(cache) == 0


def test_nonfrozen_dataclass_is_not_cached():
    @dataclass
    class Mutable:
        value: str

    assert not RetirementValidationCache().put("key", Mutable("mutable"))


def test_mutable_key_is_a_miss_and_cannot_be_put():
    cache = RetirementValidationCache()
    assert not cache.put(["key"], ("facts",))
    assert cache.get(["key"]) is None and cache.retained_bytes == 0


def test_cache_is_per_instance_and_key_namespaces_do_not_alias():
    a, b = RetirementValidationCache(), RetirementValidationCache()
    assert a.put(("retirement", "digest"), ("retirement facts",))
    assert a.put(("publication", "digest"), ("publication facts",))
    assert b.put(("retirement", "digest"), ("another fixed journal context",))
    assert a.get(("retirement", "digest")) == ("retirement facts",)
    assert a.get(("publication", "digest")) == ("publication facts",)
    assert b.get(("retirement", "digest")) == ("another fixed journal context",)
    assert b.get(("publication", "digest")) is None


@pytest.mark.parametrize("budget", [-1, True, 1.5, "32MiB", None])
def test_invalid_budgets_rejected(budget):
    with pytest.raises(ValueError, match="nonnegative integer"):
        RetirementValidationCache(maximum_bytes=budget)


def test_zero_budget_disables_reuse_without_rejecting_facts():
    cache = RetirementValidationCache(maximum_bytes=0)
    assert not cache.put(("retirement", sha(0)), facts(0))
    assert cache.get(("retirement", sha(0))) is None
    assert len(cache) == cache.retained_bytes == 0


def test_concurrent_replacements_evictions_and_reads_keep_exact_accounting():
    cache = RetirementValidationCache(maximum_bytes=24 * 1024)
    barrier = threading.Barrier(8)
    keys = [("retirement", n) for n in range(40)]

    def update(worker):
        barrier.wait(timeout=5)
        for n in range(250):
            key = keys[(n + worker) % len(keys)]
            value = (worker, n, b"x" * (128 + n % 8 * 128))
            assert cache.put(key, value)
            result = cache.get(key)
            assert result is None or (type(result) is tuple and len(result) == 3)
            assert 0 <= cache.retained_bytes <= cache.maximum_bytes
            if n % 17 == 0:
                assert not cache.put(key, b"oversize" * 4096)

    with ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(update, range(8)))
    retained = [(key, cache.get(key)) for key in keys]
    retained = [(key, value) for key, value in retained if value is not None]
    assert len(retained) == len(cache)
    assert sum(measured(key, value) for key, value in retained) == cache.retained_bytes
    assert cache.retained_bytes <= cache.maximum_bytes
