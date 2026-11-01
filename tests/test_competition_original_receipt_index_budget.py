"""Local metadata ceilings preserve original receipts and durable damage holds."""

import hashlib
import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event
from types import SimpleNamespace

import pytest

from umi.competition_remote_proof_store import (
    ProofArchiveR2Config,
    RemoteProofStore,
    original_receipt_index_capacity,
)
from umi.competition_round_journal import RoundJournal
from umi.protocol import canonical_json_bytes
from umi.sqlite_contention import is_sqlite_full

from .test_competition_remote_proof_store import EvidenceServer, config


def identity(path):
    hasher = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024**2), b""):
            hasher.update(chunk)
    info = path.stat()
    return info.st_ino, info.st_size, hasher.hexdigest()


def prepare(tmp_path, *, maximum_index_bytes=128 * 1024**2):
    server = EvidenceServer()
    producer = RemoteProofStore(tmp_path / "producer", config(tmp_path), client=server.client())
    references = [producer.put_bytes(raw) for raw in (b"one", b"two")]
    selected = config(tmp_path, read_only=True).model_dump(mode="json", by_alias=True)
    selected.update(
        schema="umi-r2-proof-archive/2",
        legacy_read_through=True,
        maximum_index_bytes=maximum_index_bytes,
        imported_object_release_maximum_metadata_bytes=1024**2,
    )
    selected = ProofArchiveR2Config.model_validate(selected)

    def open_reader(*, original=True):
        return RemoteProofStore(
            tmp_path / "reader",
            selected,
            client=server.client(),
            receipt_source_directory=producer.journal.root if original else None,
        )

    return server, producer, selected, references, open_reader


def test_selected_local_physical_policy_preserves_config_and_producer(tmp_path):
    server, producer, selected, references, open_reader = prepare(tmp_path)
    raw = canonical_json_bytes(selected)
    before = identity(producer.journal.path)
    reader = open_reader()
    capacity = original_receipt_index_capacity(1024**2)
    assert capacity["maximum_database_bytes"] == 20 * 1024**2
    assert capacity["additional_disk_bytes"] == (
        2 * capacity["maximum_database_bytes"]
        + capacity["rollback_bytes"]
        + capacity["allocation_overhead_bytes"]
    )
    assert reader.journal.maximum_bytes == selected.maximum_index_bytes
    assert (
        reader.journal.physical_budget.maximum_database_bytes == capacity["maximum_database_bytes"]
    )
    assert producer.journal.physical_budget is None
    assert reader.receipt_source.read_only and reader.receipt_source.physical_budget is None
    assert canonical_json_bytes(selected) == raw
    server.calls.clear()
    reader.validate_reference(references[0])
    assert server.calls == []
    assert identity(producer.journal.path) == before


def test_real_page_ceiling_rolls_back_and_preserves_logical_allowance(tmp_path):
    _, _, _, _, open_reader = prepare(tmp_path)
    reader = open_reader()
    before = identity(reader.journal.path)
    ceiling = reader.journal.physical_budget.maximum_database_bytes
    with pytest.raises(sqlite3.OperationalError, match="full"), reader.journal.transaction() as db:
        assert db.execute("PRAGMA max_page_count").fetchone()[0] * 4096 == ceiling
        db.execute("CREATE TABLE physical_probe(body BLOB)")
        db.execute("INSERT INTO physical_probe VALUES(zeroblob(?))", (ceiling,))
    assert identity(reader.journal.path) == before
    assert open_reader().journal.maximum_bytes == 128 * 1024**2


def test_legacy_original_consumer_adoption_retains_holds_inode_and_restart(tmp_path):
    server, producer, _, references, open_reader = prepare(tmp_path)
    legacy = open_reader(original=False)
    assert legacy.journal.physical_budget is None
    legacy._hold(
        legacy._reference(references[0]["key"], producer.client.head(references[0]["key"]))
    )
    inode = legacy.journal.path.stat().st_ino
    producer_before = identity(producer.journal.path)
    server.calls.clear()
    reader = open_reader()
    assert reader.journal.path.stat().st_ino == inode
    with pytest.raises(ValueError, match=r"explicit.*repair"):
        reader.validate_reference(references[0])
    after = identity(reader.journal.path)
    reopened = open_reader()
    assert identity(reopened.journal.path) == after
    assert identity(producer.journal.path) == producer_before
    assert server.calls == []


@pytest.mark.parametrize(
    "damage", ["oversized", "wal", "missing_lock", "old_schema", "pre_completion"]
)
def test_incompatible_retained_consumer_refuses_before_mutation(tmp_path, damage):
    _, _, _, _, open_reader = prepare(tmp_path)
    if damage == "pre_completion":
        source = open_reader()
        # A distinct pristine fixture demonstrates a real pre-completion v0
        # journal rather than just corrupting a current completion marker.
        binding = source.binding
        root = tmp_path / "old-completion"
        old_journal = RoundJournal(
            root,
            binding,
            maximum_rounds=65536,
            maximum_bytes=128 * 1024**2,
            maximum_record_bytes=65536,
        )
        before = identity(old_journal.path)
        from umi.competition_remote_proof_store import _OriginalReceiptIndex

        with pytest.raises(ValueError, match="explicit migration"):
            _OriginalReceiptIndex(
                root,
                binding,
                maximum_rounds=65536,
                maximum_bytes=128 * 1024**2,
                maximum_record_bytes=65536,
                metadata_capacity=original_receipt_index_capacity(1024**2),
            )
        assert identity(old_journal.path) == before
        return
    old = open_reader(original=False)
    if damage == "oversized":
        with old.journal.path.open("r+b") as stream:
            stream.truncate(
                original_receipt_index_capacity(1024**2)["maximum_database_bytes"] + 4096
            )
    elif damage == "wal":
        db = sqlite3.connect(old.journal.path)
        try:
            assert db.execute("PRAGMA journal_mode=WAL").fetchone() == ("wal",)
        finally:
            db.close()
    elif damage == "missing_lock":
        old.journal.lock_path.unlink()
    else:
        with old.journal.transaction() as db:
            db.execute("DROP INDEX records_capacity_lengths")
    before = identity(old.journal.path)
    files = sorted(path.name for path in old.journal.root.iterdir())
    with pytest.raises(ValueError):
        open_reader()
    assert identity(old.journal.path) == before
    assert sorted(path.name for path in old.journal.root.iterdir()) == files


def test_free_space_refusal_precedes_new_index_or_retained_write(tmp_path, monkeypatch):
    _, _, _, _, open_reader = prepare(tmp_path)
    with monkeypatch.context() as patch:
        patch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_bavail=1, f_frsize=1))
        with pytest.raises(ValueError, match="reserve unavailable"):
            open_reader()
        assert not (tmp_path / "reader").exists()
    reader = open_reader()
    before = identity(reader.journal.path)
    monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_bavail=1, f_frsize=1))
    with pytest.raises(ValueError, match="reserve unavailable"):
        open_reader()
    assert identity(reader.journal.path) == before


def test_logical_damage_capacity_exhaustion_also_latches_without_losing_failure(tmp_path):
    server, _, _, references, open_reader = prepare(tmp_path, maximum_index_bytes=1024**2)
    reader = open_reader()
    for number in range(32):
        with reader.journal.read_transaction() as db:
            _, used, _ = reader.journal._record_capacity(db)
        remaining = reader.journal.maximum_bytes - used
        if remaining < 171:
            break
        body_length = min(63000, remaining - 170)
        reader.journal.put("retained", str(number), {"body": "x" * (body_length - 11)})
    else:
        raise AssertionError("fixture did not approach logical capacity")
    server.corrupt_get = True
    with pytest.raises(ValueError, match="metadata exhausted"):
        reader.read_bytes(references[0], maximum=3)
    server.corrupt_get = False
    with pytest.raises(ValueError, match="metadata exhausted"):
        open_reader().validate_reference(references[0])


def test_emergency_slot_writes_at_real_physical_saturation_and_reopens(tmp_path):
    _, producer, _, references, open_reader = prepare(tmp_path)
    reader = open_reader()
    source_before = identity(producer.journal.path)
    with reader.journal.transaction() as db:
        db.execute("CREATE TABLE physical_fill(body BLOB)")
    for _ in range(512):
        try:
            with reader.journal.transaction() as db:
                db.execute("INSERT INTO physical_fill VALUES(zeroblob(65536))")
        except sqlite3.OperationalError as error:
            assert is_sqlite_full(error)
            break
    else:
        raise AssertionError("fixture did not fill the real physical page envelope")
    value = dict(
        schema="umi-r2-proof-damage/1",
        reference_sha256="f" * 64,
        reason="remote_proof_missing_changed_or_corrupt",
    )
    for number in range(2048):
        key = hashlib.sha256(str(number).encode()).hexdigest()
        try:
            reader.journal.put("remote_proof_damage", key, value)
        except sqlite3.OperationalError as error:
            assert is_sqlite_full(error)
            # Retry the exact failed insertion through the native latch path.
            # This emergency update now runs at actual SQLITE_FULL, not a mock.
            with pytest.raises(ValueError, match="metadata exhausted"):
                reader.journal.put_damage(key, value)
            break
    else:
        raise AssertionError("fixture did not exhaust damage-row insertion space")
    assert (
        reader.journal.path.stat().st_size <= reader.journal.physical_budget.maximum_database_bytes
    )
    with pytest.raises(ValueError, match="metadata exhausted"):
        open_reader().validate_reference(references[0])
    assert identity(producer.journal.path) == source_before


def test_interrupted_local_metadata_transaction_recovers_in_place(tmp_path):
    _, producer, _, references, open_reader = prepare(tmp_path)
    reader = open_reader()
    before, source_before = identity(reader.journal.path), identity(producer.journal.path)
    program = """
import os,sys
from pathlib import Path
sys.path.insert(0,sys.argv[3])
from umi.competition_remote_proof_store import _OriginalReceiptIndex,original_receipt_index_capacity
import json
j=_OriginalReceiptIndex(Path(sys.argv[1]),json.loads(sys.argv[2]),maximum_rounds=65536,
 maximum_bytes=128*1024**2,maximum_record_bytes=65536,
 metadata_capacity=original_receipt_index_capacity(1024**2))
with j.transaction() as db:
 db.execute("INSERT INTO records VALUES ('temporary','interrupted',?)",(b'{}',))
 os._exit(72)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            program,
            str(reader.journal.root),
            canonical_json_bytes(reader.binding).decode(),
            str(Path(__file__).resolve().parents[1] / "src"),
        ],
        check=False,
    )
    assert result.returncode == 72
    reopened = open_reader()
    assert reopened.journal.get("temporary", "interrupted") is None
    assert identity(reopened.journal.path) == before
    assert identity(producer.journal.path) == source_before
    reopened.validate_reference(references[0])


def test_saturated_damage_latch_covers_concurrent_failures_and_survives_repairs_restart(
    tmp_path, monkeypatch
):
    server, producer, _, references, open_reader = prepare(tmp_path)
    first, second = open_reader(), open_reader()
    original_source = identity(producer.journal.path)
    entered, release = [Event(), Event()], Event()

    def delayed_failure(index):
        def fail(key):
            entered[index].set()
            assert release.wait(5)
            return None

        return fail

    def full(*args, **kwargs):
        error = sqlite3.OperationalError("database or disk is full")
        error.sqlite_errorcode = getattr(sqlite3, "SQLITE_FULL", 13)
        raise error

    for index, reader in enumerate((first, second)):
        monkeypatch.setattr(reader.client, "head", delayed_failure(index))
        monkeypatch.setattr(reader.journal, "put", full)
    server.calls.clear()
    with ThreadPoolExecutor(max_workers=2) as pool:
        pending = [
            pool.submit(reader.read_bytes, reference, maximum=3)
            for reader, reference in zip((first, second), references, strict=True)
        ]
        try:
            assert all(event.wait(5) for event in entered)
            assert server.calls == []
        finally:
            release.set()
        for task in pending:
            with pytest.raises(ValueError, match="metadata exhausted"):
                task.result(timeout=5)
    reopened = open_reader()
    with pytest.raises(ValueError, match="metadata exhausted"):
        reopened.read_bytes(references[1], maximum=3)
    assert server.calls == []
    fault = reopened.journal.get(reopened.journal._capacity_kind, "owner")
    # Individual repair cannot erase an importer-wide latch, even when the
    # first failed object has been restored. Other concurrent failures may not
    # have obtained individual damage slots before saturation.
    for reference in references:
        reopened.repair_reference(reference)
    after_repairs = open_reader()
    with pytest.raises(ValueError, match="metadata exhausted"):
        after_repairs.read_bytes(references[0], maximum=3)
    assert after_repairs.journal.get(after_repairs.journal._capacity_kind, "owner") == fault
    assert identity(producer.journal.path) == original_source
