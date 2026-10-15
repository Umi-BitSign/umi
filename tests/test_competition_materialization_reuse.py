from __future__ import annotations

import hashlib
import json
import logging
import os
import subprocess
import sys
from pathlib import Path

import pytest

from umi import competition_materialization as material
from umi import competition_materialization_reuse as reuse_module
from umi.competition_package_reuse import package_verification_session


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "sealed"
    root.mkdir()
    for name in ("one", "two"):
        (root / name).write_bytes(name.encode() * 1024)
        (root / name).chmod(0o400)
    root.chmod(0o555)
    limits = material.SuccessorCurrentMaterializationLimits(
        maximum_stages=2,
        maximum_cache_bytes=100_000,
        maximum_tree_entries=16,
        maximum_tree_depth=2,
    )
    yield root, limits, tmp_path / "verification"
    root.chmod(0o700)


def _reads(monkeypatch, root):
    original = os.read
    inodes = {item.stat().st_ino for item in root.iterdir()}
    reads = []

    def read(fd, size):
        if os.fstat(fd).st_ino in inodes:
            reads.append(os.fstat(fd).st_ino)
        return original(fd, size)

    monkeypatch.setattr(os, "read", read)
    return reads


def test_unchanged_tree_uses_durable_results_without_payload_reads(tree, monkeypatch):
    root, limits, directory = tree
    reads = _reads(monkeypatch, root)
    with package_verification_session(directory=directory):
        first = material._tree(root, limits, sealed=True)
        assert reads
        reads.clear()
        assert material._tree(root, limits, sealed=True) == first
        assert reads == []
    with package_verification_session(directory=directory):
        assert material._tree(root, limits, sealed=True) == first
        assert reads == []


def test_restart_reuses_file_hashes_in_a_new_process(tree):
    root, limits, directory = tree
    with package_verification_session(directory=directory):
        material._tree(root, limits, sealed=True)
    script = """
import json, os, sys
from pathlib import Path
from umi import competition_materialization as m
from umi.competition_package_reuse import package_verification_session
root, directory, limits = sys.argv[1:]
root = Path(root)
inodes = {item.stat().st_ino for item in root.iterdir()}
original = os.read
def read(fd, size):
    assert os.fstat(fd).st_ino not in inodes, "restart reread sealed payload"
    return original(fd, size)
os.read = read
with package_verification_session(directory=Path(directory)):
    m._tree(root, m.SuccessorCurrentMaterializationLimits.model_validate_json(limits), sealed=True)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(root), str(directory), limits.model_dump_json()],
        env={**os.environ, "PYTHONPATH": str(Path(material.__file__).resolve().parents[1])},
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize("mutation", ["content", "replace", "permissions", "symlink", "hardlink"])
def test_changed_file_never_borrows_old_digest(tree, monkeypatch, mutation):
    root, limits, directory = tree
    target = root / "one"
    with package_verification_session(directory=directory):
        original = material._tree(root, limits, sealed=True)
    before = target.stat()
    root.chmod(0o755)
    if mutation in {"content", "replace"}:
        if mutation == "replace":
            target.unlink()
        else:
            target.chmod(0o600)
        target.write_bytes(b"x" * before.st_size)
        target.chmod(0o400)
        os.utime(target, ns=(before.st_atime_ns, before.st_mtime_ns))
    elif mutation == "permissions":
        target.chmod(0o600)
    elif mutation == "symlink":
        target.unlink()
        target.symlink_to(root / "two")
    else:
        (root.parent / "hardlink").hardlink_to(target)
    root.chmod(0o555)
    with package_verification_session(directory=directory):
        if mutation in {"content", "replace"}:
            reads = _reads(monkeypatch, root)
            updated = material._tree(root, limits, sealed=True)
            assert updated[1]["/one"][1] == hashlib.sha256(target.read_bytes()).hexdigest()
            assert updated != original
            assert set(reads) == {target.stat().st_ino}
        else:
            with pytest.raises(material.SuccessorMaterializationError):
                material._tree(root, limits, sealed=True)


def test_hit_still_checks_full_inventory_and_current_bounds(tree):
    root, limits, directory = tree
    with package_verification_session(directory=directory):
        material._tree(root, limits, sealed=True)
        with pytest.raises(material.SuccessorMaterializationError, match="byte bound"):
            material._tree(
                root, limits.model_copy(update={"maximum_cache_bytes": 1024}), sealed=True
            )
        root.chmod(0o755)
        (root / "extra").write_bytes(b"new")
        (root / "extra").chmod(0o400)
        root.chmod(0o555)
        result = material._tree(root, limits, sealed=True)
        assert "/extra" in result[1]


def test_mutation_while_using_a_hit_is_rejected(tree, monkeypatch):
    root, limits, directory = tree
    with package_verification_session(directory=directory) as reuse:
        material._tree(root, limits, sealed=True)
        digest = reuse.materialization.digest

        def changed(path, identity, read):
            result = digest(path, identity, read)
            path.chmod(0o600)
            path.write_bytes(b"x" * path.stat().st_size)
            path.chmod(0o400)
            return result

        monkeypatch.setattr(reuse.materialization, "digest", changed)
        with pytest.raises(material.SuccessorMaterializationError, match="changed"):
            material._tree(root, limits, sealed=True)


@pytest.mark.parametrize("damage", ["missing", "corrupt"])
def test_missing_completed_or_damaged_receipt_repairs_only_one_file(
    tree, monkeypatch, caplog, damage
):
    root, limits, directory = tree
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    with package_verification_session(directory=directory):
        expected = material._tree(root, limits, sealed=True)
    receipt = next((directory / "sealed-file-digests").glob("*.json"))
    if damage == "missing":
        receipt.unlink()
    else:
        receipt.write_bytes(b"{}")
    reads = _reads(monkeypatch, root)
    with package_verification_session(directory=directory):
        assert material._tree(root, limits, sealed=True) == expected
    assert len(set(reads)) == 1
    events = [json.loads(record.message) for record in caplog.records]
    assert any(event.get("state") == "repair_required" for event in events)
    assert any(
        event.get("stage") == "materialization_file_hash" and event["state"] == "completed"
        for event in events
    )


def test_digest_cache_is_bounded_and_semantics_change_recomputes(tree, monkeypatch):
    root, limits, directory = tree
    monkeypatch.setattr(reuse_module, "_MAXIMUM_DIGESTS", 1)
    with package_verification_session(directory=directory) as reuse:
        material._tree(root, limits, sealed=True)
        assert len(reuse.materialization._digests) == 1
    monkeypatch.setattr(reuse_module, "_SEMANTICS", "changed-digest-semantics")
    reads = _reads(monkeypatch, root)
    with package_verification_session(directory=directory):
        material._tree(root, limits, sealed=True)
    assert len(set(reads)) == 2


def test_interrupted_pass_keeps_completed_files_and_reports_progress(tree, monkeypatch, caplog):
    root, limits, directory = tree
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    original = os.read
    inodes = {item.stat().st_ino for item in root.iterdir()}
    first = []

    def interrupted(stream, count):
        inode = os.fstat(stream).st_ino
        if inode in inodes:
            if not first:
                first.append(inode)
            elif inode != first[0]:
                raise OSError("interrupted disk read")
        return original(stream, count)

    monkeypatch.setattr(os, "read", interrupted)
    with package_verification_session(directory=directory), pytest.raises(OSError):
        material._tree(root, limits, sealed=True)
    monkeypatch.setattr(os, "read", original)
    reads = _reads(monkeypatch, root)
    with package_verification_session(directory=directory):
        material._tree(root, limits, sealed=True)
    assert len(set(reads)) == 1 and first[0] not in reads
    events = [json.loads(record.message) for record in caplog.records]
    assert any(event["state"] == "interrupted" for event in events)


def test_short_reads_preserve_counted_hash_progress(tree, monkeypatch, caplog):
    root, limits, _ = tree
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    original = os.read
    monkeypatch.setattr(os, "read", lambda fd, count: original(fd, min(count, 37)))
    material._tree(root, limits, sealed=True)
    events = [json.loads(record.message) for record in caplog.records]
    assert all(event["state"] != "accounting_mismatch" for event in events)
    assert sum(event["state"] == "completed" for event in events) == 2
