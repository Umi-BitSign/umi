"""Aggregate budgets do not widen individual objects or ordinary private files."""

import pytest

from umi.competition_cohort_aggregate_files import publish_aggregate_model, read_aggregate_model
from umi.competition_cohort_capacity import (
    MAX_AGGREGATE_EVIDENCE_BYTES,
    check_aggregate_evidence_bytes,
    request_evidence_bytes,
)
from umi.competition_cohort_endpoint_archive import MAX_ARCHIVE_OBJECT_BYTES
from umi.competition_cohort_reward_package import ReplayObjectCollector
from umi.open_competition import digest
from umi.private_files import MAX_CONFIGURED_PRIVATE_BYTES, publish_private_model
from umi.protocol import StrictProtocolModel, canonical_json_bytes


class Aggregate(StrictProtocolModel):
    payload: str


@pytest.mark.parametrize("bound", [True, 0, 1023, MAX_AGGREGATE_EVIDENCE_BYTES + 1])
def test_invalid_aggregate_capacity_refuses_before_io(tmp_path, bound):
    path = tmp_path / "output" / "record.json"
    with pytest.raises(ValueError, match="aggregate evidence capacity"):
        publish_aggregate_model(path, Aggregate(payload="original"), maximum_bytes=bound)
    with pytest.raises(ValueError, match="aggregate evidence capacity"):
        ReplayObjectCollector(lambda _: pytest.fail("source must not be opened"), bound)
    assert not path.parent.exists()


def test_explicit_aggregate_budget_preserves_object_and_private_file_limits(tmp_path):
    assert MAX_CONFIGURED_PRIVATE_BYTES == 512 * 1024**2
    assert MAX_ARCHIVE_OBJECT_BYTES == 16 * 1024**2
    assert request_evidence_bytes(None, 64 * 1024**2) == 64 * 1024**2
    assert request_evidence_bytes(1024**3, 64 * 1024**2) == 1024**3
    path = tmp_path / "aggregate" / "package.json"
    value = Aggregate(payload="original")
    with pytest.raises(ValueError, match="private file byte bound"):
        publish_private_model(path, value, maximum_bytes=1024**3)
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    original, inode = path.read_bytes(), path.stat().st_ino
    assert read_aggregate_model(path, Aggregate, maximum_bytes=1024**3) == value
    publish_aggregate_model(path, value, maximum_bytes=1024**3)
    with pytest.raises(ValueError, match="different bytes"):
        publish_aggregate_model(path, Aggregate(payload="changed"), maximum_bytes=1024**3)
    assert path.read_bytes() == original and path.stat().st_ino == inode


def test_exact_aggregate_file_bound_and_envelope_overhead(tmp_path):
    value = Aggregate(payload="v" * 1024)
    exact = len(canonical_json_bytes(value))
    path = tmp_path / "aggregate" / "package.json"
    with pytest.raises(ValueError, match="output exceeds"):
        publish_aggregate_model(path, value, maximum_bytes=1024)
    assert not path.parent.exists()
    publish_aggregate_model(path, value, maximum_bytes=exact)
    assert read_aggregate_model(path, Aggregate, maximum_bytes=exact) == value
    with pytest.raises(ValueError, match="input exceeds"):
        read_aggregate_model(path, Aggregate, maximum_bytes=exact - 1)


def test_collector_counts_unique_canonical_objects_and_rejects_hash_conflicts():
    first, second = {"value": "a" * 1024}, {"value": "b" * 1024}
    raw, key = canonical_json_bytes(first), digest(first)
    calls = []

    def source(selected):
        calls.append(selected)
        return raw if selected == key else canonical_json_bytes(second)

    collector = ReplayObjectCollector(source, len(raw))
    assert collector(key) == collector(key) == raw
    assert collector.used == len(raw) and calls == [key]
    with pytest.raises(ValueError, match="evidence exceeds its bound"):
        collector(digest(second))
    assert collector.used == len(raw) and tuple(collector.values) == (key,)
    changed = ReplayObjectCollector(lambda _: canonical_json_bytes(second), 1024**3)
    with pytest.raises(ValueError, match="bounded identity"):
        changed(key)
    assert changed.used == 0 and not changed.values
    assert check_aggregate_evidence_bytes(1024**3) == 1024**3
