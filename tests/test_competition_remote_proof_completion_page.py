"""Bounded original-receipt enumeration for imported object retirement."""

import copy
import hashlib

import pytest

from umi.competition_remote_proof_store import (
    ProofArchiveR2Config,
    ProofArchiveStores,
    RemoteProofStore,
)
from umi.protocol import canonical_json_bytes

from .test_competition_readonly_proof_receipts import consumer
from .test_competition_remote_proof_store import (
    EvidenceServer,
    config,
    retained_local_config,
    store,
)


def _pages(remote, cursor=None, maximum_records=2):
    references = []
    for _ in range(64):
        page = remote.completion_page(cursor, maximum_records=maximum_records)
        assert page["scanned_records"] <= maximum_records
        references.extend(page["references"])
        cursor = page["cursor"]
        if page["caught_up"]:
            return references, cursor
    pytest.fail("bounded receipt cursor did not complete its fixture")


def test_page_restarts_and_sees_lower_hash_appends_without_remote_or_payload_work(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    values = sorted(
        [b"first object", b"second object"],
        key=lambda raw: hashlib.sha256(
            ("proofs/objects/" + hashlib.sha256(raw).hexdigest()).encode()
        ).hexdigest(),
        reverse=True,
    )
    first = producer.put_bytes(values[0])
    observer = consumer(tmp_path / "observer", producer, server)
    server.calls.clear()
    references, cursor = _pages(observer, maximum_records=1)
    assert references == [first]
    assert cursor["completed_seen"] == 1
    assert server.calls == []
    second = producer.put_bytes(values[1])
    assert (
        hashlib.sha256(second["key"].encode()).hexdigest()
        < hashlib.sha256(first["key"].encode()).hexdigest()
    )
    observer = consumer(tmp_path / "observer", producer, server)
    server.calls.clear()
    references, cursor = _pages(observer, cursor, maximum_records=1)
    assert references == [second]
    assert cursor["completed_seen"] == 2
    assert server.calls == []
    idle = observer.completion_page(cursor, maximum_records=1)
    assert idle["references"] == [] and idle["scanned_records"] == 0
    assert idle["caught_up"]


def test_page_bounds_unrelated_metadata_and_resumes_without_redecoding_receipts(
    tmp_path, monkeypatch
):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    producer.journal.put_many(("unrelated", str(index), {"index": index}) for index in range(9))
    expected = producer.put_bytes(b"completed after metadata")
    observer = consumer(tmp_path / "observer", producer, server)
    seen = []
    get_raw = observer.receipt_source.get_raw

    def counted(kind, key, **kwargs):
        if kind == "remote_proof_completion":
            seen.append(key)
        return get_raw(kind, key, **kwargs)

    monkeypatch.setattr(observer.receipt_source, "get_raw", counted)
    server.calls.clear()
    page = observer.completion_page(maximum_records=2)
    assert page["references"] == []
    assert page["scanned_records"] == 2 and not page["caught_up"]
    references, cursor = _pages(observer, page["cursor"], maximum_records=2)
    assert references == [expected] and len(seen) == 1
    assert observer.completion_page(cursor)["scanned_records"] == 0
    assert len(seen) == 1 and server.calls == []


def test_caught_up_cursor_never_anchors_to_a_mutable_tail(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    first = producer.put_bytes(b"first")
    producer.journal.put("temporary", "tail", {"temporary": True})
    references, cursor = _pages(producer)
    assert references == [first]
    assert cursor["scan_rowid"] == cursor["last_completion_rowid"]
    with producer.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='temporary'")
    second = producer.put_bytes(b"second")
    server.calls.clear()
    references, cursor = _pages(producer, cursor)
    assert references == [second] and cursor["completed_seen"] == 2
    assert server.calls == []


def test_concurrent_appends_do_not_repeat_an_unfinished_metadata_gap(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    first = producer.put_bytes(b"first")
    _, cursor = _pages(producer)
    producer.journal.put_many(("gap", str(index), {"index": index}) for index in range(9))
    second = producer.put_bytes(b"second")
    references, positions = [], []
    for index in range(6):
        producer.put_bytes(("append-" + str(index)).encode())
        page = producer.completion_page(cursor, maximum_records=2)
        assert not page["caught_up"]
        references.extend(page["references"])
        cursor = page["cursor"]
        positions.append(cursor["scan_rowid"])
    assert positions == sorted(set(positions))
    assert first not in references and second in references


@pytest.mark.parametrize("held_owner", ["producer", "consumer"])
def test_page_observes_both_damage_ledgers(tmp_path, held_owner):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"source")
    observer = consumer(tmp_path / "observer", producer, server)
    selected = producer if held_owner == "producer" else observer
    selected._hold(observer.validate_reference(reference))
    server.calls.clear()
    with pytest.raises(ValueError, match="explicit original-generation repair"):
        _pages(observer)
    assert server.calls == []


def test_page_missing_original_receipt_requires_repair_without_remote_reimport(tmp_path):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"source")
    key = hashlib.sha256(reference["key"].encode()).hexdigest()
    with producer.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,))
    server.calls.clear()
    with pytest.raises(ValueError, match="receipt is missing or damaged"):
        _pages(consumer(tmp_path / "observer", producer, server))
    assert server.calls == []


@pytest.mark.parametrize("changed", ["inode", "schema", "anchor", "count"])
def test_cursor_damage_is_explicit_and_does_not_restart_from_zero(tmp_path, changed):
    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    producer.put_bytes(b"source")
    _, original = _pages(producer)
    cursor = copy.deepcopy(original)
    if changed == "inode":
        cursor["owner"]["journal_inode"] = "0"
    elif changed == "schema":
        cursor["owner"]["schema_version"] += 1
    elif changed == "anchor":
        cursor["last_completion_id"] = "00" * 32
    else:
        cursor["observed_completed"] += 1
    server.calls.clear()
    with pytest.raises(ValueError, match=r"changed|regressed"):
        producer.completion_page(cursor)
    assert server.calls == []


@pytest.mark.parametrize("maximum_records", [0, 257, True, 1.5])
def test_page_rejects_unbounded_or_noninteger_limits(tmp_path, maximum_records):
    producer = store(tmp_path / "producer", EvidenceServer())
    with pytest.raises(ValueError, match=r"1\.\.256"):
        producer.completion_page(maximum_records=maximum_records)


def test_original_configs_keep_their_signed_bytes(tmp_path):
    selected = config(tmp_path)
    raw = canonical_json_bytes(selected)
    assert b"receipt_source_directory" not in raw
    assert b"imported_object_release_batch_files" not in raw
    assert b"imported_object_release_maximum_metadata_bytes" not in raw
    assert canonical_json_bytes(ProofArchiveR2Config.model_validate_json(raw)) == raw


@pytest.mark.parametrize("size", [1024**2, 32 * 1024**2, 1024**3])
def test_retirement_metadata_allowance_is_independent_and_roundtrips(tmp_path, size):
    original = config(tmp_path).model_dump(mode="json", by_alias=True)
    selected = ProofArchiveR2Config.model_validate(
        original | {"imported_object_release_maximum_metadata_bytes": size}
    )
    raw = canonical_json_bytes(selected)
    assert selected.imported_object_release_maximum_metadata_bytes == size
    assert selected.maximum_index_bytes == original["maximum_index_bytes"]
    assert canonical_json_bytes(ProofArchiveR2Config.model_validate_json(raw)) == raw


@pytest.mark.parametrize("size", [1024**2 - 1, 1024**3 + 1, True])
def test_retirement_metadata_allowance_refuses_out_of_bounds(tmp_path, size):
    with pytest.raises(ValueError):
        ProofArchiveR2Config.model_validate(
            config(tmp_path).model_dump(mode="json", by_alias=True)
            | {"imported_object_release_maximum_metadata_bytes": size}
        )


@pytest.mark.parametrize(
    "change",
    [
        {"read_only": True},
        {"legacy_read_through": False},
        {"archive_release_consumer_abi": None},
        {"imported_object_release_batch_files": 257},
    ],
)
def test_import_retirement_requires_bounded_writable_owner_and_lease(tmp_path, change):
    value = retained_local_config(tmp_path).model_dump(mode="json", by_alias=True) | {
        "imported_object_release_batch_files": 16,
        "archive_release_consumer_abi": "umi-proof-read-release-lease/1",
    }
    assert ProofArchiveR2Config.model_validate(value).imported_object_release_batch_files == 16
    with pytest.raises(ValueError):
        ProofArchiveR2Config.model_validate(value | change)


def test_selected_original_fallback_is_wired_without_inventory_or_new_receipts(
    tmp_path, monkeypatch
):
    from umi import competition_proof_archive_selection as selection

    server = EvidenceServer()
    producer = store(tmp_path / "producer", server)
    reference = producer.put_bytes(b"original source")
    selected = ProofArchiveR2Config.model_validate(
        retained_local_config(tmp_path).model_dump(mode="json", by_alias=True)
        | {"read_only": True, "receipt_source_directory": str(producer.journal.root)}
    )
    opened = []

    def remote(root, configuration, **kwargs):
        opened.append(kwargs)
        return RemoteProofStore(root, configuration, client=server.client(), **kwargs)

    monkeypatch.setattr(selection, "RemoteProofStore", remote)
    server.calls.clear()
    archive = selection.selected_proof_archive(tmp_path / "imports", selected)
    assert opened == [{"receipt_source_directory": producer.journal.root}]
    assert archive.remote.receipt_source.read_only
    assert _pages(archive.remote)[0] == [reference]
    assert server.calls == []
    exported = ProofArchiveR2Config.model_validate(
        retained_local_config(tmp_path).model_dump(mode="json", by_alias=True)
        | {
            "imported_object_release_batch_files": 16,
            "archive_release_consumer_abi": "umi-proof-read-release-lease/1",
        }
    )
    ProofArchiveStores(schema="umi-proof-archive-stores/1", imported=selected, exported=exported)
    with pytest.raises(ValueError, match="selected original fallback"):
        ProofArchiveStores(schema="umi-proof-archive-stores/1", exported=exported)


@pytest.mark.parametrize("change", [{"read_only": False}, {"legacy_read_through": False}])
def test_configured_receipt_source_requires_readonly_legacy_selection(tmp_path, change):
    value = retained_local_config(tmp_path).model_dump(mode="json", by_alias=True) | {
        "read_only": True,
        "receipt_source_directory": str(tmp_path / "original"),
    }
    with pytest.raises(ValueError, match="read-only retained-local"):
        ProofArchiveR2Config.model_validate(value | change)


def test_configured_receipt_source_cannot_be_overridden_by_constructor(tmp_path):
    selected = ProofArchiveR2Config.model_validate(
        retained_local_config(tmp_path).model_dump(mode="json", by_alias=True)
        | {"read_only": True, "receipt_source_directory": str(tmp_path / "selected")}
    )
    with pytest.raises(ValueError, match="differs from selected transport"):
        RemoteProofStore(
            tmp_path / "consumer",
            selected,
            client=EvidenceServer().client(),
            receipt_source_directory=tmp_path / "different",
        )
    assert not (tmp_path / "consumer").exists()
