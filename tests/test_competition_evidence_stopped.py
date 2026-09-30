"""Metadata guards used by root to inspect stopped service-owned journals."""

import os
import sqlite3

import pytest

from umi.competition_weights import _recovery_journal_snapshot


@pytest.fixture
def journal(tmp_path):
    root = tmp_path / "weights"
    root.mkdir(mode=0o700)
    path = root / "competition-weights.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE retained (body BLOB)")
        db.execute("INSERT INTO retained VALUES (?)", (b"preserved evidence",))
    path.chmod(0o600)
    return path


def test_stopped_inspection_uses_service_owner_not_root(journal, monkeypatch):
    owner = journal.stat().st_uid
    before = _recovery_journal_snapshot(journal)
    # Real files and metadata; only the caller's uid is substituted locally.
    # The Linux qualification also exercises a real root/service ownership split.
    monkeypatch.setattr(os, "getuid", lambda: owner + 1)
    with pytest.raises(ValueError, match="parent is not private"):
        _recovery_journal_snapshot(journal)
    assert _recovery_journal_snapshot(journal, expected_owner=owner) == before
    assert set(journal.parent.iterdir()) == {journal}


@pytest.mark.parametrize("suffix", ["", "-wal", "-shm", "-journal"])
def test_explicit_owner_still_rejects_unsafe_journal_family(journal, suffix):
    path = journal.with_name(journal.name + suffix)
    if suffix:
        path.write_bytes(b"retained sidecar")
    path.chmod(0o644)
    with pytest.raises(ValueError, match="journal is not private"):
        _recovery_journal_snapshot(journal, expected_owner=journal.stat().st_uid)


@pytest.mark.parametrize("fault", ["link", "symlink", "owner"])
def test_explicit_owner_does_not_accept_replacement_family(journal, fault):
    owner = journal.stat().st_uid
    if fault == "link":
        os.link(journal, journal.with_name("alias"))
    elif fault == "symlink":
        journal.with_name(journal.name + "-wal").symlink_to(journal)
    else:
        owner += 1
    with pytest.raises((ValueError, OSError)):
        _recovery_journal_snapshot(journal, expected_owner=owner)


@pytest.mark.parametrize("owner", [-1, True, "0"])
def test_invalid_inspection_owner_rejected_before_io(owner, tmp_path):
    with pytest.raises(ValueError, match="nonnegative uid"):
        _recovery_journal_snapshot(tmp_path / "absent", expected_owner=owner)
