"""Bounded receipt snapshots retain fresh repair fences without payload work."""

from contextlib import contextmanager

import pytest

from .test_competition_readonly_proof_receipts import consumer
from .test_competition_remote_proof_store import EvidenceServer, store


@pytest.mark.parametrize("independent", [False, True])
def test_batch_opens_each_owner_once_and_reopens_for_later_batch(
    tmp_path, monkeypatch, independent
):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    refs = [producer.put_bytes(str(n).encode()) for n in range(12)]
    reader = consumer(tmp_path / "reader", producer, server) if independent else producer
    journals = [reader.journal, *([reader.receipt_source] if independent else [])]
    snapshots = []
    for journal in journals:
        original = journal.read_transaction

        @contextmanager
        def counted(original=original):
            with original() as db:
                assert db.in_transaction and db.execute("PRAGMA query_only").fetchone() == (1,)
                snapshots.append(db)
                yield db

        monkeypatch.setattr(journal, "read_transaction", counted)
    server.calls.clear()
    for _ in range(2):
        with reader.reference_snapshot() as validate:
            assert [validate(ref).key for ref in refs] == [ref["key"] for ref in refs]
    assert len(snapshots) == 2 * len(journals)
    assert len({id(db) for db in snapshots}) == len(snapshots)
    assert server.calls == []


def test_snapshot_cannot_escape_or_exceed_its_bound(tmp_path):
    server = EvidenceServer()
    reader = store(tmp_path / "reader", server)
    ref = reader.put_bytes(b"original")
    with reader.reference_snapshot() as validate:
        for _ in range(256):
            validate(ref)
        with pytest.raises(ValueError, match="exhausted"):
            validate(ref)
    with pytest.raises(ValueError, match="closed"):
        validate(ref)


@pytest.mark.parametrize("damage_owner", ["producer", "consumer"])
def test_next_batch_observes_independent_damage_and_restart(tmp_path, damage_owner):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    ref = producer.put_bytes(b"original")
    reader = consumer(tmp_path / "reader", producer, server)
    with reader.reference_snapshot() as validate:
        parsed = validate(ref)
    (producer if damage_owner == "producer" else reader)._hold(parsed)
    server.calls.clear()
    for observed in (reader, consumer(tmp_path / "reader", producer, server)):
        with (
            observed.reference_snapshot() as validate,
            pytest.raises(ValueError, match="explicit original-generation repair"),
        ):
            validate(ref)
    assert server.calls == []


def test_new_batch_refuses_damaged_receipt_owner_schema(tmp_path):
    import sqlite3

    from umi.competition_remote_proof_store import _completion_triggers

    server = EvidenceServer()
    reader = store(tmp_path / "reader", server)
    ref = reader.put_bytes(b"original")
    with reader.reference_snapshot() as validate:
        validate(ref)
    # This is an isolated fixture, never a production journal.
    with sqlite3.connect(reader.journal.path) as db:
        db.execute("DROP TRIGGER " + next(iter(_completion_triggers())))
    server.calls.clear()
    with pytest.raises(ValueError, match="ledger damaged"), reader.reference_snapshot():
        pass
    assert server.calls == []


def test_coverage_batch_reuses_receipt_schema_without_reading_source_payloads(
    tmp_path, monkeypatch
):
    from .test_competition_reward_coverage_sources import fresh

    journal, server, records, interval = fresh(tmp_path)
    journal._commit_records([*records, interval])
    remote = journal.remote_store
    original = remote.journal.read_transaction
    reads = []

    @contextmanager
    def counted():
        with original() as db:
            reads.append(db)
            yield db

    monkeypatch.setattr(remote.journal, "read_transaction", counted)
    get_raw = journal.journal.get_raw

    def metadata_only(kind, key, **kwargs):
        assert kind != "coverage_object"
        return get_raw(kind, key, **kwargs)

    monkeypatch.setattr(journal.journal, "get_raw", metadata_only)
    server.calls.clear()
    with journal.journal.read_transaction() as db:
        assert journal.checkpoints.sources([r[:2] for r in records], db) == sorted(
            [kind, key, 0] for kind, key, _value in records
        )
    assert len(reads) == 1
    assert server.calls == []
