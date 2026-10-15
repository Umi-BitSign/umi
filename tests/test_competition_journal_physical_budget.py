"""Real SQLite rollback/page limits and retained-reader opening qualification."""

import hashlib
import os
import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_journal_physical_budget import ArchivePhysicalBudget, JournalPhysicalBudget
from umi.competition_round_journal import RoundJournal


def journal(tmp_path, **kwargs):
    return RoundJournal(
        tmp_path / "journal",
        {"fixture": "physical-budget"},
        maximum_bytes=64 * 1024**2,
        maximum_record_bytes=32 * 1024**2,
        **kwargs,
    )


def file_identity(path):
    stat = path.stat()
    return (stat.st_ino, stat.st_size, hashlib.sha256(path.read_bytes()).hexdigest())


def test_existing_source_constructor_and_repeat_do_not_change_database(tmp_path):
    old = journal(tmp_path)
    old.put("proof", "unchanged", {"body": "source"})
    before = file_identity(old.path)
    reader = journal(tmp_path, existing_only=True, read_only=True)
    assert reader.get("proof", "unchanged") == {"body": "source"}
    assert file_identity(old.path) == before
    with pytest.raises(ValueError, match="read-only"):
        reader.put("proof", "another", {"body": "new"})
    assert file_identity(old.path) == before
    assert not old.path.with_name(old.path.name + "-journal").exists()


def test_existing_source_refuses_migration_without_changing_retained_bytes(tmp_path):
    old = journal(tmp_path)
    with old.transaction() as db:
        db.execute("DROP INDEX records_capacity_lengths")
    before = file_identity(old.path)
    with pytest.raises(ValueError, match="explicit migration"):
        journal(tmp_path, existing_only=True, read_only=True)
    assert file_identity(old.path) == before


def test_page_ceiling_rolls_back_full_transaction_and_retry_remains_usable(tmp_path):
    old = journal(tmp_path)
    old.put("proof", "original", {"body": "retained"})
    before = file_identity(old.path)
    limited = journal(
        tmp_path,
        existing_only=True,
        physical_budget=JournalPhysicalBudget(old.path.stat().st_size + 4096, 0, 1024**2),
    )
    with pytest.raises(sqlite3.OperationalError, match="full"):
        limited.put_many(
            (
                ("proof", "small-first", {"body": "first"}),
                ("proof", "too-large", {"body": "x" * 1024**2}),
            )
        )
    assert file_identity(old.path) == before
    assert limited.get("proof", "small-first") is None
    assert limited.get("proof", "original") == {"body": "retained"}
    limited.physical_budget = JournalPhysicalBudget(
        old.path.stat().st_size + 2 * 1024**2, 0, 1024**2
    )
    limited.put("proof", "retry", {"body": "x" * 10000})
    assert limited.get("proof", "retry")["body"] == "x" * 10000


def test_rollback_configuration_cannot_be_relaxed_inside_transaction(tmp_path):
    old = journal(tmp_path)
    limited = journal(
        tmp_path,
        existing_only=True,
        physical_budget=JournalPhysicalBudget(old.path.stat().st_size + 1024**2, 0, 1024**2),
    )
    for sql in (
        "PRAGMA cache_spill=ON",
        "PRAGMA max_page_count=99999999",
        "PRAGMA journal_mode=WAL",
        "SAVEPOINT growth",
        "ATTACH ':memory:' AS other",
    ):
        with pytest.raises(sqlite3.DatabaseError, match="authorized"), limited.transaction() as db:
            db.execute(sql)
    limited.put("proof", "after-refusals", {"body": "retained"})


def test_separate_floor_checked_before_target_write(tmp_path, monkeypatch):
    old = journal(tmp_path)
    before = file_identity(old.path)
    limited = journal(
        tmp_path,
        existing_only=True,
        physical_budget=JournalPhysicalBudget(old.path.stat().st_size + 1024**2, 500, 1024**2),
    )
    monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_bavail=499, f_frsize=1))
    with pytest.raises(ValueError, match="reserve unavailable"):
        limited.put("proof", "refused", {"body": "no"})
    assert file_identity(old.path) == before


def test_archive_file_and_free_space_refuse_before_publication(tmp_path, monkeypatch):
    from umi.competition_reward_proof_archive import RewardProofArchive

    archive = RewardProofArchive(
        tmp_path / "archive", physical_budget=ArchivePhysicalBudget(1024, 1000, 100)
    )
    with pytest.raises(ValueError, match="file ceiling"):
        archive._retain_bytes(b"a" * 1024)
    assert not archive.root.exists()
    monkeypatch.setattr(os, "statvfs", lambda path: SimpleNamespace(f_bavail=1001, f_frsize=1))
    with pytest.raises(ValueError, match="reserve unavailable"):
        archive._retain_bytes(b"a")
    assert not archive.root.exists()


def test_interrupted_uncommitted_target_recovers_and_repeats(tmp_path):
    import subprocess
    import sys

    old = journal(tmp_path)
    old.put("proof", "original", {"body": "retained"})
    before = file_identity(old.path)
    program = """
import os,sys
from pathlib import Path
from umi.competition_round_journal import RoundJournal
from umi.competition_journal_physical_budget import JournalPhysicalBudget
root=Path(sys.argv[1])
path=root/'rounds.sqlite3'
j=RoundJournal(root, {'fixture':'physical-budget'}, maximum_bytes=64*1024**2,
               maximum_record_bytes=32*1024**2, existing_only=True,
               physical_budget=JournalPhysicalBudget(path.stat().st_size+2*1024**2,0,1024**2))
with j.transaction() as db:
 db.execute("INSERT INTO records VALUES ('proof','interrupted',?)",(b'{"body":"interrupted"}',))
 os._exit(72)
"""
    result = subprocess.run([sys.executable, "-B", "-c", program, str(old.root)], check=False)
    assert result.returncode == 72
    assert old.path.with_name(old.path.name + "-journal").exists()
    restored = journal(
        tmp_path,
        existing_only=True,
        physical_budget=JournalPhysicalBudget(old.path.stat().st_size + 2 * 1024**2, 0, 1024**2),
    )
    assert restored.get("proof", "interrupted") is None
    assert file_identity(old.path) == before
    restored.put("proof", "after-recovery", {"body": "complete"})
    assert restored.get("proof", "after-recovery") == {"body": "complete"}


def test_actual_hot_commit_interruption_restores_original_bytes(tmp_path):
    import subprocess
    import sys
    import time

    old = journal(tmp_path)
    old.put("proof", "original-large", {"body": "x" * (16 * 1024**2)})
    before = file_identity(old.path)
    sidecar = old.path.with_name(old.path.name + "-journal")
    program = """
import os,sys
from pathlib import Path
from umi.competition_round_journal import RoundJournal
from umi.competition_journal_physical_budget import JournalPhysicalBudget
root=Path(sys.argv[1]);path=root/'rounds.sqlite3'
j=RoundJournal(root,{'fixture':'physical-budget'},maximum_bytes=64*1024**2,
 maximum_record_bytes=32*1024**2,existing_only=True,
 physical_budget=JournalPhysicalBudget(path.stat().st_size+2*1024**2,0,1024**2))
with j.transaction() as db:
 raw=b'{"body":"'+b'y'*(16*1024**2)+b'"}'
 db.execute("UPDATE records SET body=? WHERE id='original-large'",(raw,))
 print('commit-ready',flush=True)
 sys.stdin.readline()
"""
    child = subprocess.Popen(
        [sys.executable, "-B", "-c", program, str(old.root)],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert child.stdout.readline().strip() == "commit-ready"
        child.stdin.write("commit\n")
        child.stdin.flush()
        observed_hot = False
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and child.poll() is None:
            try:
                with sidecar.open("rb") as stream:
                    header = stream.read(8)
            except FileNotFoundError:
                continue
            if header == bytes.fromhex("d9d505f920a163d7"):
                observed_hot = True
                child.kill()
                child.wait(timeout=10)
                break
        assert observed_hot, "fixture must observe a real SQLite hot journal before interruption"
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=10)
        child.stdin.close()
        child.stdout.close()
    restored = journal(
        tmp_path,
        existing_only=True,
        physical_budget=JournalPhysicalBudget(old.path.stat().st_size + 2 * 1024**2, 0, 1024**2),
    )
    assert file_identity(old.path) == before
    assert restored.get("proof", "original-large")["body"] == "x" * (16 * 1024**2)
    assert not sidecar.exists()


@pytest.mark.parametrize("case", ["original_pages", "page_address", "checksum", "second_segment"])
def test_recovery_refuses_oversized_or_damaged_hot_geometry_before_open(tmp_path, case):
    import struct

    path = tmp_path / "geometry.sqlite3"
    db = sqlite3.connect(path)
    db.execute("PRAGMA page_size=512")
    db.execute("CREATE TABLE t (x)")
    db.commit()
    db.close()
    path.chmod(0o600)
    original = file_identity(path)
    body = bytearray(path.read_bytes()[:512])
    pages = 10000 if case == "original_pages" else 2
    body[28:32] = struct.pack(">I", pages)
    page = 129 if case == "page_address" else 1
    nonce = 12345
    checksum = (nonce + sum(body[offset] for offset in range(512 - 200, 0, -200))) & 0xFFFFFFFF
    if case == "checksum":
        checksum ^= 1
    header = bytes.fromhex("d9d505f920a163d7") + struct.pack(">IIIII", 1, nonce, pages, 512, 512)
    raw = header.ljust(512, b"\0") + struct.pack(">I", page) + body + struct.pack(">I", checksum)
    if case == "second_segment":
        raw += header.ljust(512, b"\0")
    sidecar = path.with_name(path.name + "-journal")
    sidecar.write_bytes(raw)
    sidecar.chmod(0o600)
    with pytest.raises(ValueError, match=r"(geometry|address|checksum)"):
        JournalPhysicalBudget(65536, 0, 4096).recover(path)
    assert file_identity(path) == original
    assert sidecar.read_bytes() == raw
