"""Native observers reuse live receipt metadata without owning the producer."""

import hashlib

import pytest

from umi.competition_remote_proof_store import RemoteProofStore

from .test_competition_remote_proof_store import EvidenceServer, config, store


def consumer(root, producer, server):
    return RemoteProofStore(
        root,
        config(root.parent, read_only=True),
        client=server.client(),
        receipt_source_directory=producer.journal.root,
    )


def test_observer_reads_original_metadata_and_new_receipts_without_network_or_copy(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"original source")
    before = producer.journal.path.read_bytes()
    server.calls.clear()
    observer = consumer(tmp_path / "observer", producer, server)
    assert observer.receipt_source.read_only and observer.receipt_source.existing_only
    assert observer.validate_reference(reference).content_sha256 == hashlib.sha256(
        b"original source"
    ).hexdigest()
    assert producer.journal.path.read_bytes() == before
    assert server.calls == []
    with observer.journal.read_transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM records").fetchone() == (0,)
    second = producer.put_bytes(b"newly completed source")
    server.calls.clear()
    assert observer.validate_reference(second).key == second["key"]
    assert server.calls == []
    assert observer.read_bytes(reference, maximum=1024) == b"original source"
    observer.evict_cache()
    server.calls.clear()
    restarted = consumer(tmp_path / "observer", producer, server)
    assert restarted.validate_reference(reference).key == reference["key"]
    assert server.calls == []


@pytest.mark.parametrize("wrong", ["writable", "same_root", "wrong_namespace", "missing_source"])
def test_unqualified_source_refuses_without_mutating_producer(tmp_path, wrong):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    producer.put_bytes(b"original source")
    original = producer.journal.path.read_bytes()
    selected = config(tmp_path, read_only=wrong != "writable")
    source = producer.journal.root
    root = tmp_path / "observer"
    if wrong == "same_root":
        root = source
    elif wrong == "wrong_namespace":
        selected = selected.model_copy(update={"prefix": "different"})
    elif wrong == "missing_source":
        source = tmp_path / "missing-producer"
    server.calls.clear()
    with pytest.raises(ValueError):
        RemoteProofStore(root, selected, client=server.client(), receipt_source_directory=source)
    assert producer.journal.path.read_bytes() == original
    assert server.calls == []
    assert not (tmp_path / "missing-producer").exists()


def test_missing_producer_receipt_never_falls_back_to_remote_import(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"source", path="frames/history/original")
    observer = consumer(tmp_path / "observer", producer, server)
    key = hashlib.sha256(reference["key"].encode()).hexdigest()
    with producer.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,))
    server.calls.clear()
    with pytest.raises(ValueError, match="missing or damaged"):
        observer.validate_reference(reference)
    with pytest.raises(ValueError, match="missing or damaged"):
        observer.read_path("frames/history/original", maximum=1024)
    with pytest.raises(ValueError, match="missing; explicit repair"):
        observer.read_path("frames/history/not-completed", maximum=1024)
    assert server.calls == []


def test_consumer_damage_and_producer_hold_have_independent_explicit_repairs(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"source")
    observer = consumer(tmp_path / "observer", producer, server)
    original = producer.journal.path.read_bytes()
    server.corrupt_get = True
    with pytest.raises(ValueError):
        observer.read_bytes(reference, maximum=1024)
    assert producer.journal.path.read_bytes() == original
    observer = consumer(tmp_path / "observer", producer, server)
    server.corrupt_get = False
    server.calls.clear()
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        observer.validate_reference(reference)
    assert server.calls == []
    producer._hold(producer.validate_reference(reference))
    server.calls.clear()
    with pytest.raises(ValueError, match="producer proof receipt"):
        observer.repair_reference(reference)
    assert server.calls == []
    producer.repair_reference(reference)
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        observer.validate_reference(reference)
    original = producer.journal.path.read_bytes()
    observer.repair_reference(reference)
    assert producer.journal.path.read_bytes() == original
    assert observer.read_bytes(reference, maximum=1024) == b"source"


def test_producer_source_cannot_be_written_through_native_receipt_view(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"source")
    observer = consumer(tmp_path / "observer", producer, server)
    original = producer.journal.path.read_bytes()
    with pytest.raises(ValueError, match="read-only"), observer.receipt_source.transaction():
        pytest.fail("readonly source must refuse before entering a writer transaction")
    with pytest.raises(ValueError, match="cannot adopt"):
        observer._remember(producer.validate_reference(reference))
    assert producer.journal.path.read_bytes() == original
