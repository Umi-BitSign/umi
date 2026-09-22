from __future__ import annotations

import fcntl
import hashlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_evidence_copy import _LEGACY
from umi.competition_evidence_prepare import prepare_legacy_candidate
from umi.competition_evidence_store import EvidenceStore, observation_reservation
from umi.competition_evidence_worker import EvidenceWorkerProfile, bind_worker_profile
from umi.protocol import canonical_json_bytes

from .test_competition_evidence_store import proof


@pytest.fixture
def preparation(tmp_path):
    root = tmp_path / "legacy"
    root.mkdir(mode=0o700)
    path = root / "competition-weights.sqlite3"
    path.touch(mode=0o600)
    (root / "competition-weights.lock").touch(mode=0o600)
    raw = proof(runtime=os.urandom(8192))
    identity = hashlib.sha256(raw).hexdigest()
    binding = [("legacy-owner", 2048, 16 * 1024**3)]
    with sqlite3.connect(path) as db:
        for table, definition in _LEGACY.items():
            db.execute(f"CREATE TABLE {table} {definition}")
        db.executemany("INSERT INTO binding VALUES (?,?,?)", binding)
        db.execute("INSERT INTO evidence VALUES (?,?)", (identity, raw))
        db.execute("INSERT INTO held_policies VALUES (?)", ("a" * 64,))
        db.execute("INSERT INTO highwater VALUES (1,123,?)", ("0x" + "b" * 64,))
        db.execute(
            "INSERT INTO continuity_highwater VALUES (?,?,?,?,?)",
            ("a" * 64, "c" * 64, 4, "d" * 64, "e" * 64),
        )
    options = dict(
        expected_source_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
        expected_binding_sha256=hashlib.sha256(canonical_json_bytes(binding)).hexdigest(),
        profile=EvidenceWorkerProfile(observation_reservation(19), 16),
        maximum_database_bytes=16 * 1024**2,
        minimum_free_bytes=1024**2,
    )
    return SimpleNamespace(
        root=root,
        path=path,
        candidate=tmp_path / "candidate",
        options=options,
        raw=raw,
        identity=identity,
    )


def prepare(item, **changes):
    return prepare_legacy_candidate(item.root, item.candidate, **(item.options | changes))


def test_prepared_copy_has_exact_history_private_files_and_unsigned_receipt(preparation):
    item = preparation
    before = item.path.read_bytes()
    receipt = prepare(item)
    assert item.path.read_bytes() == before
    assert not receipt["activation_authorized"] and not receipt["root_sealed"]
    assert not receipt["source_selection_changed"]
    assert receipt == json.loads((item.candidate / "evidence-preparation.json").read_bytes())
    path = item.candidate / item.path.name
    assert hashlib.sha256(path.read_bytes()).hexdigest() == receipt["candidate_database_sha256"]
    assert path.stat().st_size <= item.options["maximum_database_bytes"]
    assert item.candidate.stat().st_mode & 0o777 == 0o700
    assert all(p.stat().st_mode & 0o777 == 0o600 for p in item.candidate.iterdir())
    with sqlite3.connect(path) as db:
        db.execute("BEGIN")
        bind_worker_profile(db, item.options["profile"])
        store = EvidenceStore(
            db,
            owner_binding_sha256=item.options["expected_binding_sha256"],
            limits=item.options["profile"].limits,
        )
        assert store.get(item.identity) == item.raw
        store.audit()
        with sqlite3.connect(item.path) as source:
            for table in _LEGACY:
                if table != "evidence":
                    assert (
                        db.execute(f"SELECT * FROM {table}").fetchall()
                        == source.execute(f"SELECT * FROM {table}").fetchall()
                    )
    with pytest.raises(FileExistsError):
        prepare(item)
    assert item.path.read_bytes() == before


@pytest.mark.parametrize(
    "changed",
    [
        {"expected_source_sha256": "f" * 64},
        {"expected_binding_sha256": "f" * 64},
        {"minimum_free_bytes": 1024**4},
        {"maximum_database_bytes": 4096},
    ],
)
def test_preparation_bound_failure_preserves_source(preparation, changed):
    item = preparation
    before = item.path.read_bytes()
    with pytest.raises((ValueError, sqlite3.DatabaseError)):
        prepare(item, **changed)
    assert item.path.read_bytes() == before
    assert not (item.candidate / "evidence-preparation.json").exists()


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_refuses_source_sidecars(preparation, suffix):
    item = preparation
    item.path.with_name(item.path.name + suffix).touch(mode=0o600)
    with pytest.raises(ValueError, match="sidecars"):
        prepare(item)
    assert not item.candidate.exists()


def test_refuses_source_lock_and_links(preparation):
    item = preparation
    with (item.root / "competition-weights.lock").open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            prepare(item)
    os.link(item.path, item.root / "linked.sqlite3")
    with pytest.raises(ValueError, match="private"):
        prepare(item)
    assert not item.candidate.exists()


def test_refuses_overlapping_roots(preparation):
    item = preparation
    for candidate in (item.root, item.root / "child", item.root.parent):
        with pytest.raises(ValueError, match="disjoint"):
            prepare_legacy_candidate(item.root, candidate, **item.options)


def test_source_rewrite_or_lock_replacement_blocks_receipt(preparation, monkeypatch):
    import umi.competition_evidence_prepare as module

    item = preparation
    original = module.copy_legacy_weight_journal
    before = item.path.read_bytes()

    def rewrite(*args, **kwargs):
        result = original(*args, **kwargs)
        info = item.path.stat()
        item.path.write_bytes(before)
        os.utime(item.path, ns=(info.st_atime_ns, info.st_mtime_ns))
        return result

    monkeypatch.setattr(module, "copy_legacy_weight_journal", rewrite)
    with pytest.raises(ValueError, match="source history"):
        prepare(item)
    assert item.path.read_bytes() == before
    assert not (item.candidate / "evidence-preparation.json").exists()


@pytest.mark.parametrize("stage", ["uncommitted", "committed", "receipt"])
def test_kill_leaves_original_recoverable_and_never_selects_candidate(preparation, stage):
    item = preparation
    before = item.path.read_bytes()
    script = """
import os, signal, sys
from pathlib import Path
import umi.competition_evidence_prepare as module
from umi.competition_evidence_worker import EvidenceWorkerProfile
from umi.competition_evidence_store import observation_reservation
stage, source, target, source_hash, owner = sys.argv[1:]
if stage == "uncommitted":
    original = module.copy_legacy_weight_journal
    def stop(*args, **kwargs):
        original(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)
    module.copy_legacy_weight_journal = stop
else:
    original = module._write_receipt
    def stop(*args, **kwargs):
        if stage == "receipt": original(*args, **kwargs)
        os.kill(os.getpid(), signal.SIGKILL)
    module._write_receipt = stop
module.prepare_legacy_candidate(Path(source),Path(target),expected_source_sha256=source_hash,
 expected_binding_sha256=owner, profile=EvidenceWorkerProfile(observation_reservation(19),16),
 maximum_database_bytes=16*1024**2,minimum_free_bytes=1024**2)
"""
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            script,
            stage,
            str(item.root),
            str(item.candidate),
            item.options["expected_source_sha256"],
            item.options["expected_binding_sha256"],
        ],
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == -signal.SIGKILL, result.stderr.decode()
    assert item.path.read_bytes() == before
    with sqlite3.connect(item.candidate / item.path.name) as db:
        assert db.execute("PRAGMA quick_check").fetchall() == [("ok",)]
        tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        assert bool(tables) is (stage != "uncommitted")
    receipt = item.candidate / "evidence-preparation.json"
    assert receipt.exists() is (stage == "receipt")
    if receipt.exists():
        assert not json.loads(receipt.read_bytes())["activation_authorized"]
    with pytest.raises(FileExistsError):
        prepare(item)
    item.candidate = item.candidate.with_name("retry-candidate")
    assert not prepare(item)["activation_authorized"]
    assert item.path.read_bytes() == before


def test_candidate_profile_binds_recovery_allowance(preparation):
    item = preparation
    prepare(item)
    with sqlite3.connect(item.candidate / item.path.name) as db:
        db.execute("BEGIN")
        with pytest.raises(ValueError, match="profile changed"):
            bind_worker_profile(db, replace(item.options["profile"], recovery_observations=15))
