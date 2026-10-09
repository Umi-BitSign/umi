"""Encoding reuse preserves byte identity, bounds, failure and publication checks."""

from concurrent.futures import ThreadPoolExecutor

import pytest

from umi import competition_evidence_reuse as module
from umi.competition_evidence_codec import decode_evidence, encode_evidence
from umi.competition_evidence_reuse import EvidenceEncodingReuse


@pytest.fixture
def encoded_calls(monkeypatch):
    calls = []

    def counted(raw, *, kind):
        calls.append((kind, raw))
        return encode_evidence(raw, kind=kind)

    monkeypatch.setattr(module, "encode_evidence", counted)
    return calls


def test_exact_content_and_domain_reuse_owns_its_mutable_outputs(encoded_calls):
    cache = EvidenceEncodingReuse()
    raw = b'{"proof":"' + b"ab" * 1024 + b'"}'
    expected = encode_evidence(raw, kind="proof")
    first = cache.encode(raw, kind="proof")
    first.objects.clear()
    second = cache.encode(bytes(bytearray(raw)), kind="proof")
    assert second == expected
    assert (
        decode_evidence(
            second.recipe,
            sha256=second.sha256,
            expanded_bytes=len(raw),
            kind="proof",
            resolve=lambda sha, size: second.objects[sha],
        )
        == raw
    )
    second.objects.clear()
    assert cache.encode(raw, kind="proof") == expected
    assert len(encoded_calls) == 1
    assert cache.encode(raw, kind="metadata") == encode_evidence(raw, kind="metadata")
    assert cache.encode(raw + b" ", kind="proof") == encode_evidence(raw + b" ", kind="proof")
    assert len(encoded_calls) == 3


@pytest.mark.parametrize("raw,kind", [(b"", "proof"), (b"valid", "unknown"), ("text", "proof")])
def test_failed_inputs_never_enter_cache(encoded_calls, raw, kind):
    cache = EvidenceEncodingReuse()
    for _ in range(2):
        with pytest.raises(ValueError):
            cache.encode(raw, kind=kind)
    assert len(encoded_calls) == 2
    assert not cache._entries and cache._size == 0


def test_kind_size_limit_still_applies_after_other_domain_warmup():
    from umi.competition_evidence_codec import MAX_METADATA_BYTES

    raw = b"x" * (MAX_METADATA_BYTES + 1)
    cache = EvidenceEncodingReuse()
    assert cache.encode(raw, kind="proof") == encode_evidence(raw, kind="proof")
    with pytest.raises(ValueError, match="size"):
        cache.encode(raw, kind="metadata")


@pytest.mark.parametrize("budget", [0, 1, 200])
def test_capacity_bypass_does_not_change_supported_inputs(encoded_calls, budget):
    cache = EvidenceEncodingReuse(maximum_bytes=budget)
    raw = b"a" * 128
    for _ in range(2):
        assert cache.encode(raw, kind="proof") == encode_evidence(raw, kind="proof")
    assert len(encoded_calls) == 2
    assert not cache._entries and cache._size == 0


def test_lru_eviction_retains_bounded_entries_and_bytes(encoded_calls):
    cache = EvidenceEncodingReuse(maximum_bytes=1024, maximum_entries=2)
    for raw in (b"a", b"b", b"a", b"c", b"a", b"b"):
        assert cache.encode(raw, kind="proof") == encode_evidence(raw, kind="proof")
        assert len(cache._entries) <= 2 and cache._size <= 1024
    assert [raw for _, raw in encoded_calls] == [b"a", b"b", b"c", b"b"]


def test_concurrent_use_returns_independent_maps_and_skips_inherited_lock(monkeypatch):
    cache = EvidenceEncodingReuse()
    with ThreadPoolExecutor(max_workers=8) as workers:
        values = list(workers.map(lambda _: cache.encode(b"original", kind="proof"), range(32)))
    assert all(value == values[0] for value in values)
    assert len({id(value.objects) for value in values}) == len(values)
    assert len(cache._entries) == 1
    monkeypatch.setattr(module.os, "getpid", lambda: cache._pid + 1)
    with cache._lock:
        assert cache.encode(b"original", kind="proof") == encode_evidence(b"original", kind="proof")


def test_warm_encoding_does_not_skip_archive_repair_or_conflicts(tmp_path):
    from umi.competition_reward_proof_archive import RewardProofArchive

    archive = RewardProofArchive(tmp_path / "archive")
    fields = {"evidence": b"original"}
    archive.write("history", "aa" * 32, context={"block": 1}, fields=fields)
    original_objects = {path: path.read_bytes() for path in (archive.root / "objects").iterdir()}
    for path in original_objects:
        path.unlink()
    archive.write("history", "aa" * 32, context={"block": 1}, fields=fields)
    assert {path: path.read_bytes() for path in original_objects} == original_objects
    with pytest.raises(ValueError):
        archive.write("history", "aa" * 32, context={"block": 2}, fields=fields)
    assert archive.read("history", "aa" * 32, bounds={"evidence": 128}) == ({"block": 1}, fields)
