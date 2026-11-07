"""Physical release preserves archived originals and serializes current writers."""

import fcntl
import multiprocessing
import os
import signal
import threading
from types import SimpleNamespace

import pytest

from umi import competition_forecast_compaction as compaction
from umi.competition_forecast import ForecastLedger

from .test_competition_forecast_archive import historical as historical
from .test_competition_forecast_segments import Remote


def open_ledger(root, remote, reserve=0):
    lock = root / "compaction.lock"
    lock.touch(mode=0o600, exist_ok=True)
    return ForecastLedger(
        root / "legacy",
        maximum_bytes=128 * 1024**2,
        remote_store=remote,
        ledger_sha256="b" * 64,
        compaction=None if reserve is None else dict(reserve_bytes=reserve, lock_file=str(lock)),
    )


def high_water(ledger, *, live=0):
    with ledger.db:
        ledger.db.execute("CREATE TABLE retired(body BLOB)")
        ledger.db.execute("INSERT INTO retired VALUES(zeroblob(67108864))")
        ledger.db.execute("DROP TABLE retired")
        if live:
            ledger.db.execute("CREATE TABLE retained_fixture(body BLOB)")
            ledger.db.execute("INSERT INTO retained_fixture VALUES(zeroblob(?))", (live,))
    return ledger.path.stat().st_size


def test_owned_compaction_keeps_originals_head_and_restart_reuse(historical, tmp_path, monkeypatch):
    segment, expected, records = historical
    remote = Remote()
    ledger = open_ledger(tmp_path, remote)
    ledger.maintain_retention()
    head = ledger.head
    before = high_water(ledger)
    calls = remote.reads, remote.uploads
    assert ledger.maintain_retention()
    assert ledger.path.stat().st_size < before // 100
    assert ledger.head == head
    assert ledger.db.execute("PRAGMA user_version").fetchone() == (2,)
    assert ledger.db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert (remote.reads, remote.uploads) == calls
    assert ledger.status(segment.rows[0][2], observed_unix_ms=4000) == expected
    status = ledger.retention.diagnostics()["compaction"]
    assert status["status"] == "completed"
    assert status["released_file_bytes"] == before - ledger.path.stat().st_size
    ledger.close()
    ledger = open_ledger(tmp_path, remote)
    statements = []
    ledger.db.set_trace_callback(statements.append)
    assert not ledger.maintain_retention()
    assert "VACUUM" not in statements
    assert (remote.reads, remote.uploads) == calls
    assert ledger.head == head
    assert ledger.records(segment.rows[0][2]) == records
    ledger.close()


@pytest.mark.parametrize("reason", ["unselected", "capacity", "live_set"])
def test_compaction_refusal_preserves_database(historical, tmp_path, monkeypatch, reason):
    ledger = open_ledger(tmp_path, Remote(), reserve=None if reason == "unselected" else 1234)
    ledger.maintain_retention()
    before = high_water(ledger, live=17 * 1024**2 if reason == "live_set" else 0)
    if reason == "capacity":
        monkeypatch.setattr(
            compaction.os,
            "statvfs",
            lambda path: SimpleNamespace(f_bavail=2 * before + 1233, f_frsize=1),
        )
    statements = []
    ledger.db.set_trace_callback(statements.append)
    assert not ledger.maintain_retention()
    assert "VACUUM" not in statements
    assert ledger.path.stat().st_size == before
    assert (
        ledger.retention.compaction.status["status"]
        == {
            "unselected": "unselected",
            "capacity": "capacity_required",
            "live_set": "waiting_for_archive",
        }[reason]
    )
    ledger.close()


def test_append_waits_for_owner_without_sqlite_timeout(historical, tmp_path):
    ledger = open_ledger(tmp_path, Remote())
    ledger.maintain_retention()
    high_water(ledger)
    compacting, release, appending, appended = (threading.Event() for _ in range(4))
    errors = []

    def traced(sql):
        if sql == "VACUUM":
            compacting.set()
            assert release.wait(5)

    def compact():
        try:
            ledger.maintain_retention()
        except BaseException as error:
            errors.append(error)

    def append():
        appending.set()
        try:
            ledger.append("after:compaction", "c" * 64, "scope_started", {"observed_unix_ms": 5000})
            appended.set()
        except BaseException as error:
            errors.append(error)

    ledger.db.set_trace_callback(traced)
    worker = threading.Thread(target=compact)
    writer = threading.Thread(target=append)
    worker.start()
    try:
        assert compacting.wait(5)
        writer.start()
        assert appending.wait(5)
        assert not appended.wait(0.15)  # Longer than the SQLite writer timeout.
    finally:
        release.set()
        worker.join(5)
        if writer.ident is not None:
            writer.join(5)
    assert not errors
    assert appended.is_set()
    assert ledger.head[1] == 5
    assert ledger.db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    ledger.close()


def test_shared_admission_excludes_another_owner_and_missing_lock_requires_repair(
    historical, tmp_path
):
    ledger = open_ledger(tmp_path, Remote())
    ledger.maintain_retention()
    before = high_water(ledger)
    lock = tmp_path / "compaction.lock"
    ledger.retention.compaction.started -= 5
    with lock.open("rb") as owner:
        fcntl.flock(owner, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert not ledger.maintain_retention()
        assert ledger.path.stat().st_size == before
        assert ledger.retention.compaction.status["status"] == "waiting_for_compaction_owner"
        assert ledger.retention.compaction.status["elapsed_seconds"] >= 5
        assert ledger.retention.compaction.status["eta_seconds"] is None
    lock.unlink()
    with pytest.raises(FileNotFoundError):
        ledger.maintain_retention()
    assert not lock.exists()
    lock.touch(mode=0o600)
    assert ledger.maintain_retention()
    ledger.close()


def _killed_compaction(root, remote, ready):
    ledger = open_ledger(root, remote)
    callbacks = 0

    def pause():
        nonlocal callbacks
        callbacks += 1
        if callbacks == 20:
            ready.set()
            signal.pause()
        return 0

    ledger.db.set_progress_handler(pause, 100)
    ledger.maintain_retention()


def test_process_death_during_vacuum_recovers_without_republication(historical, tmp_path):
    remote = Remote()
    ledger = open_ledger(tmp_path, remote)
    ledger.maintain_retention()
    high_water(ledger, live=8 * 1024**2)
    # Give the VM enough rows to interrupt after real compaction work starts.
    with ledger.db:
        ledger.db.executemany("INSERT INTO retained_fixture VALUES(?)", [(b"kept",)] * 1000)
    head = ledger.head
    ledger.close()
    ctx = multiprocessing.get_context("fork")
    ready = ctx.Event()
    process = ctx.Process(target=_killed_compaction, args=(tmp_path, remote, ready))
    process.start()
    try:
        assert ready.wait(10)
        os.kill(process.pid, signal.SIGKILL)
        process.join(5)
        assert process.exitcode == -signal.SIGKILL
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)
    calls = remote.reads, remote.uploads
    ledger = open_ledger(tmp_path, remote)
    assert ledger.head == head
    assert ledger.db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
    assert ledger.db.execute("SELECT count(*) FROM retained_fixture").fetchone() == (1001,)
    assert ledger.maintain_retention()
    assert not ledger.maintain_retention()
    assert (remote.reads, remote.uploads) == calls
    ledger.close()
