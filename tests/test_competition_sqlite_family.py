"""SQLite sidecar validation while another supported owner finishes a write."""

import os

import pytest

from umi import competition_worker as worker


@pytest.mark.parametrize("suffix", ["-journal", "-wal", "-shm"])
def test_disappearing_optional_sidecar_does_not_stop_native_reader(tmp_path, monkeypatch, suffix):
    database = tmp_path / "state.sqlite3"
    database.touch(mode=0o600)
    sidecar = tmp_path / (database.name + suffix)
    sidecar.touch(mode=0o600)
    original = worker._verify_private_regular_file

    def disappearing(path, label):
        if path == sidecar:
            sidecar.unlink()
        return original(path, label)

    monkeypatch.setattr(worker, "_verify_private_regular_file", disappearing)
    worker._verify_sqlite_family(database, "test database")


def test_main_database_disappearance_remains_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        worker._verify_sqlite_family(tmp_path / "missing.sqlite3", "test database")


@pytest.mark.parametrize("unsafe", ["dangling_link", "foreign_mode"])
def test_unsafe_sidecars_remain_errors(tmp_path, unsafe):
    database = tmp_path / "state.sqlite3"
    database.touch(mode=0o600)
    sidecar = tmp_path / (database.name + "-journal")
    if unsafe == "dangling_link":
        sidecar.symlink_to(tmp_path / "missing")
    else:
        sidecar.touch(mode=0o600)
        os.chmod(sidecar, 0o644)
    with pytest.raises((OSError, ValueError)):
        worker._verify_sqlite_family(database, "test database")
