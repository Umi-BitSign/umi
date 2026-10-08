"""SQLite sidecar disappearance must not hold a valid owned chain observation."""

import os

import pytest

from umi import competition_chain_state as cache
from umi.protocol import canonical_json_bytes


@pytest.mark.parametrize("database", ["registrations.sqlite3", "finality.sqlite3"])
@pytest.mark.parametrize("suffix", ["-wal", "-shm", "-journal"])
@pytest.mark.parametrize("namespaced", [False, True])
def test_usage_survives_sidecar_removed_after_directory_scan(
    tmp_path, monkeypatch, database, suffix, namespaced
):
    tmp_path.chmod(0o700)
    namespace = "ab" * 32
    folder = tmp_path / namespace if namespaced else tmp_path
    folder.mkdir(mode=0o700, exist_ok=True)
    if namespaced:
        budget = folder / cache._CACHE_BUDGET_FILE
        budget.write_bytes(
            canonical_json_bytes(
                {
                    "schema": "umi-competition-weight-cache-budget/1",
                    "configuration_sha256": namespace,
                    "maximum_namespace_bytes": 1024**2,
                }
            )
        )
        budget.chmod(0o400)
    persistent = folder / database
    persistent.write_bytes(b"persistent database")
    persistent.chmod(0o600)
    sidecar = folder / (database + suffix)
    sidecar.write_bytes(b"transient sqlite bytes")
    sidecar.chmod(0o600)
    original = cache.os.open
    removed = False

    def open_after_checkpoint(path, flags, *args, **kwargs):
        nonlocal removed
        if path == sidecar.name:
            sidecar.unlink()
            removed = True
        return original(path, flags, *args, **kwargs)

    monkeypatch.setattr(cache.os, "open", open_after_checkpoint)
    usage = cache._cache_usage(tmp_path, 2 * 1024**2)
    assert removed and persistent.read_bytes() == b"persistent database"
    expected = persistent.stat().st_size
    if namespaced:
        expected += budget.stat().st_size
    assert usage[namespace if namespaced else "legacy"] == expected


@pytest.mark.parametrize(
    "name,budget",
    [
        ("registrations.sqlite3", False),
        ("finality.sqlite3", False),
        ("namespace-budget.json", True),
        ("namespace.lock", False),
        ("unexpected-wal", False),
        ("registrations.sqlite3-wal", True),
    ],
)
def test_missing_persistent_or_unrecognized_file_still_holds(tmp_path, name, budget):
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises(FileNotFoundError):
            cache._cache_file_info(fd, name, budget=budget)
    finally:
        os.close(fd)


@pytest.mark.parametrize("unsafe", ["symlink", "public", "hardlink"])
def test_existing_unsafe_sidecar_still_holds(tmp_path, unsafe):
    path = tmp_path / "registrations.sqlite3-wal"
    target = tmp_path / "target"
    target.write_bytes(b"unsafe")
    target.chmod(0o600)
    if unsafe == "symlink":
        path.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(target, path)
    else:
        path.write_bytes(b"public")
        path.chmod(0o644)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        with pytest.raises((OSError, ValueError)):
            cache._cache_file_info(fd, path.name)
    finally:
        os.close(fd)
