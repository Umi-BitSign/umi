"""Retained preflight IO must remain read only and expose explicit repair."""

import fcntl
import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from umi import competition_miner_transition_io as io
from umi.competition_verification_reuse import metadata_completion
from umi.protocol import canonical_json_bytes


def private_file(path, body=b"retained"):
    path.write_bytes(body)
    path.chmod(0o600)
    return path


def database(root, mode="DELETE"):
    root.mkdir(mode=0o700)
    path = root / "state.sqlite3"
    db = sqlite3.connect(path)
    assert db.execute("PRAGMA journal_mode=" + mode).fetchone()[0].lower() == mode.lower()
    db.execute("CREATE TABLE retained (body BLOB NOT NULL)")
    db.execute("INSERT INTO retained VALUES (?)", (b"signed-original",))
    db.commit()
    db.close()
    path.chmod(0o600)
    return path, private_file(Path(str(path) + ".lock"), b"")


def inventory(root):
    return {
        str(p.relative_to(root)): (io.file_identity(p), hashlib.sha256(p.read_bytes()).hexdigest())
        for p in root.iterdir()
        if p.is_file()
    }


@pytest.mark.parametrize("mode", ["DELETE", "WAL"])
def test_stopped_database_reads_without_mutation_or_new_sidecars(tmp_path, mode):
    path, lock = database(tmp_path / "owner", mode)
    assert path.read_bytes()[18:20] == (b"\x02\x02" if mode == "WAL" else b"\x01\x01")
    before = inventory(path.parent)
    for _ in range(2):
        with io.stopped_snapshots(((path, lock),), maximum_value_bytes=1024) as (snapshot,):
            assert snapshot.execute("SELECT body FROM retained").fetchone()[0] == b"signed-original"
            with pytest.raises(sqlite3.OperationalError, match="readonly"):
                snapshot.execute("UPDATE retained SET body=X'00'")
        assert inventory(path.parent) == before


def test_held_lifetime_owner_lock_refuses_without_mutation(tmp_path):
    path, lock = database(tmp_path / "owner")
    before = inventory(path.parent)
    with lock.open("rb") as held:
        fcntl.flock(held, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            pytest.raises(io.TransitionPreflightRefused, match="owner_active"),
            io.stopped_snapshots(((path, lock),), maximum_value_bytes=1024),
        ):
            pytest.fail("active owner was inspected")
    assert inventory(path.parent) == before


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_retained_recovery_sidecar_refuses_even_when_empty(tmp_path, suffix):
    path, lock = database(tmp_path / "owner")
    sidecar = private_file(Path(str(path) + suffix), b"")
    before = inventory(path.parent)
    with (
        pytest.raises(io.TransitionPreflightRefused, match="database_recovery_required"),
        io.stopped_snapshots(((path, lock),), maximum_value_bytes=1024),
    ):
        pytest.fail("recovery-required database was inspected")
    assert sidecar.exists() and inventory(path.parent) == before


def test_live_wal_sidecars_refuse_without_touching_writer(tmp_path):
    path, lock = database(tmp_path / "owner", "WAL")
    writer = sqlite3.connect(path)
    try:
        writer.execute("INSERT INTO retained VALUES (?)", (b"second-signed-original",))
        writer.commit()
        assert Path(str(path) + "-wal").exists()
        with (
            pytest.raises(io.TransitionPreflightRefused, match="database_recovery_required"),
            io.stopped_snapshots(((path, lock),), maximum_value_bytes=1024),
        ):
            pytest.fail("live WAL owner was inspected")
        assert writer.execute("SELECT COUNT(*) FROM retained").fetchone()[0] == 2
    finally:
        writer.close()


def test_database_changed_during_snapshot_is_not_accepted(tmp_path):
    path, lock = database(tmp_path / "owner")
    with (
        pytest.raises(io.TransitionPreflightRefused, match="changed"),
        io.stopped_snapshots(((path, lock),), maximum_value_bytes=1024) as (snapshot,),
    ):
        assert snapshot.execute("SELECT body FROM retained").fetchone()[0] == b"signed-original"
        replacement = private_file(path.with_name("replacement"), path.read_bytes())
        os.replace(replacement, path)


def test_sidecar_appearing_during_snapshot_refuses(tmp_path):
    path, lock = database(tmp_path / "owner")
    with (
        pytest.raises(io.TransitionPreflightRefused, match="database_sidecar_created"),
        io.stopped_snapshots(((path, lock),), maximum_value_bytes=1024),
    ):
        private_file(Path(str(path) + "-journal"), b"")


def test_open_descriptor_detects_same_bytes_path_replacement(tmp_path):
    path = private_file(tmp_path / "input")
    with (
        pytest.raises(io.TransitionPreflightRefused, match="input_changed"),
        io.opened_input(path) as (fd, _),
    ):
        replacement = private_file(tmp_path / "replacement", b"retained")
        os.replace(replacement, path)
        assert os.read(fd, 8) == b"retained"


def test_open_descriptor_detects_parent_directory_replacement(tmp_path):
    parent = tmp_path / "original"
    parent.mkdir()
    path = private_file(parent / "input")
    with (
        pytest.raises(io.TransitionPreflightRefused, match="input_changed"),
        io.opened_input(path),
    ):
        parent.rename(tmp_path / "displaced")
        parent.mkdir()
        private_file(parent / "input")


@pytest.mark.parametrize("kind", ["file_symlink", "parent_symlink", "hardlink", "public_mode"])
def test_input_rejects_untrusted_path_or_permissions(tmp_path, kind):
    parent = tmp_path / "private"
    parent.mkdir()
    original = private_file(parent / "input")
    path = original
    if kind == "file_symlink":
        path = tmp_path / "alias"
        path.symlink_to(original)
    elif kind == "parent_symlink":
        alias = tmp_path / "alias"
        alias.symlink_to(parent, target_is_directory=True)
        path = alias / "input"
    elif kind == "hardlink":
        os.link(original, parent / "alias")
    else:
        original.chmod(0o644)
    with pytest.raises((OSError, ValueError)):
        io.bounded_read(path, 1024)
    assert original.read_bytes() == b"retained"


@pytest.mark.parametrize("body,maximum", [(b"", 1), (b"too large", 2)])
def test_bounded_input_never_accepts_empty_or_oversize(tmp_path, body, maximum):
    path = private_file(tmp_path / "input", body)
    with pytest.raises(io.TransitionPreflightRefused, match="exceeds_selected_bound"):
        io.bounded_read(path, maximum)


def test_checkpoint_reuse_and_new_key_miss(tmp_path):
    cache = io.PreflightCheckpoints(tmp_path / "verification")
    key = "a" * 64
    assert cache.get(key) is None
    result = {"known_requests_retired": True, "runtime_migration_authorized": False}
    cache.put(key, result)
    path = cache.directory / (key + ".json")
    before = io.file_identity(path), path.read_bytes()
    assert metadata_completion(path).exists()
    for _ in range(2):
        assert io.PreflightCheckpoints(cache.directory).get(key) == result
        assert (io.file_identity(path), path.read_bytes()) == before
    assert cache.get("b" * 64) is None


@pytest.mark.parametrize("damage", ["missing", "malformed", "checksum", "key", "noncanonical"])
def test_prior_checkpoint_damage_requires_explicit_repair(tmp_path, damage):
    directory = tmp_path / "verification"
    cache = io.PreflightCheckpoints(directory)
    key = "a" * 64
    cache.put(key, {"retired": 7})
    path = directory / (key + ".json")
    raw = path.read_bytes()
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"{")
    elif damage == "noncanonical":
        path.write_bytes(raw + b"\n")
    else:
        value = json.loads(raw)
        value[damage] = "b" * 64
        path.write_bytes(canonical_json_bytes(value))
    with pytest.raises(
        io.TransitionPreflightRefused, match="verification_metadata_repair_required"
    ):
        io.PreflightCheckpoints(directory).get(key)
    repair = io.PreflightCheckpoints(directory, repair_reason="restore verified fixture result")
    assert repair.get(key) is None
    repair.put(key, {"retired": 7})
    assert io.PreflightCheckpoints(directory).get(key) == {"retired": 7}
    assert not list(directory.glob(".repair-*"))


def test_checkpoint_repair_requires_nonempty_reason(tmp_path):
    with pytest.raises(io.TransitionPreflightRefused, match="repair_requires_reason"):
        io.PreflightCheckpoints(tmp_path / "verification", repair_reason="   ")


def test_checkpoint_write_and_read_enforce_bound(tmp_path, monkeypatch):
    cache = io.PreflightCheckpoints(tmp_path / "verification")
    key = "a" * 64
    cache.put(key, {"original": True})
    path = cache.directory / (key + ".json")
    before = path.read_bytes()
    monkeypatch.setattr(io, "MAX_CHECKPOINT_BYTES", 32)
    with pytest.raises(io.TransitionPreflightRefused, match="checkpoint_exceeds_bound"):
        cache.put("b" * 64, {"oversize": "x" * 64})
    with pytest.raises(io.TransitionPreflightRefused, match="metadata_repair_required"):
        cache.get(key)
    assert path.read_bytes() == before


def test_enrollment_inventory_repeated_then_added_removed_or_replaced(tmp_path):
    directory = tmp_path / "enrollment"
    directory.mkdir()
    private_file(directory / "claim.json")
    before = io.directory_inventory(directory, maximum_entries=3)
    assert io.directory_inventory(directory, maximum_entries=3) == before
    private_file(directory / "participation.json")
    added = io.directory_inventory(directory, maximum_entries=3)
    assert added != before and added[1] == ("claim.json", "participation.json")
    (directory / "participation.json").unlink()
    assert io.directory_inventory(directory, maximum_entries=3) != before
    directory.rename(tmp_path / "old-enrollment")
    directory.mkdir()
    private_file(directory / "claim.json")
    assert io.directory_inventory(directory, maximum_entries=3) != before


@pytest.mark.parametrize("kind", ["symlink", "directory", "too_many"])
def test_enrollment_inventory_rejects_unsupported_tree_and_count(tmp_path, kind):
    directory = tmp_path / "enrollment"
    directory.mkdir()
    original = private_file(directory / "claim.json")
    if kind == "symlink":
        (directory / "linked.json").symlink_to(original)
    elif kind == "directory":
        (directory / "nested").mkdir()
    else:
        private_file(directory / "participation.json")
    with pytest.raises(
        io.TransitionPreflightRefused, match=r"unsupported_enrollment_tree|exceeds_selected"
    ):
        io.directory_inventory(directory, maximum_entries=1)


def test_enrollment_inventory_detects_change_while_enumerating(tmp_path, monkeypatch):
    directory = tmp_path / "enrollment"
    directory.mkdir()
    private_file(directory / "claim.json")
    real_scandir = io.os.scandir

    class ChangingScan:
        def __init__(self, fd):
            self.scan = real_scandir(fd)

        def __enter__(self):
            def rows():
                yield from self.scan
                before = directory.stat()
                private_file(directory / "late.json")
                # Force a distinct timestamp instead of relying on filesystem clock ticks.
                os.utime(directory, ns=(before.st_atime_ns, before.st_mtime_ns + 1))

            return rows()

        def __exit__(self, *_):
            self.scan.close()

    monkeypatch.setattr(io.os, "scandir", ChangingScan)
    with pytest.raises(io.TransitionPreflightRefused, match="enrollment_directory_changed"):
        io.directory_inventory(directory, maximum_entries=4)


def test_failed_explicit_checkpoint_repair_preserves_damage_and_completion(tmp_path, monkeypatch):
    directory = tmp_path / "verification"
    key = "a" * 64
    io.PreflightCheckpoints(directory).put(key, {"retired": 7})
    path = directory / (key + ".json")
    marker = metadata_completion(path)
    path.write_bytes(b"retained-damaged-receipt")
    damaged_identity, damaged_bytes = io.file_identity(path), path.read_bytes()
    marker_identity, marker_bytes = io.file_identity(marker), marker.read_bytes()
    attempted = []

    def fail_before_replace(source, destination):
        temporary = Path(source)
        assert Path(destination) == path
        assert temporary.parent == directory
        assert temporary.name.startswith(".repair-")
        assert temporary.is_file()
        attempted.append(temporary)
        raise OSError("injected interruption before checkpoint replacement")

    repair = io.PreflightCheckpoints(directory, repair_reason="recover damaged fixture receipt")
    assert repair.get(key) is None
    monkeypatch.setattr(io.os, "replace", fail_before_replace)
    with pytest.raises(OSError, match="injected interruption"):
        repair.put(key, {"retired": 7})
    assert attempted and all(not temporary.exists() for temporary in attempted)
    assert not list(directory.glob(".repair-*"))
    assert (io.file_identity(path), path.read_bytes()) == (damaged_identity, damaged_bytes)
    assert (io.file_identity(marker), marker.read_bytes()) == (marker_identity, marker_bytes)
    with pytest.raises(io.TransitionPreflightRefused, match="metadata_repair_required"):
        io.PreflightCheckpoints(directory).get(key)
