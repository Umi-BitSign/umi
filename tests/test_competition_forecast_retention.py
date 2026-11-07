"""Original ledgers migrate and resume with exact outcomes and durable R2 history."""

import json

import pytest

from umi.competition_forecast import ForecastLedger, ForecastRepairRequired
from umi.competition_forecast_summary import ForecastSummary

from .test_competition_forecast_archive import historical as historical
from .test_competition_forecast_segments import Remote


def opened(tmp_path, remote):
    return ForecastLedger(tmp_path / "legacy", remote_store=remote, ledger_sha256="b" * 64)


def test_legacy_migration_reclaims_only_published_forecasts_and_reuses_restart(
    historical, tmp_path, monkeypatch
):
    segment, expected, records = historical
    remote = Remote()
    ledger = opened(tmp_path, remote)
    try:
        with pytest.raises(ValueError, match="migration pending"):
            ledger.status(segment.rows[0][2], observed_unix_ms=4000)
        assert ledger.maintain_retention()
        assert ledger.retention.index.head == (segment.last_sequence, segment.last_sha256)
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
        assert ledger.db.execute("PRAGMA user_version").fetchone() == (2,)
        actual = ledger.status(segment.rows[0][2], observed_unix_ms=4000)
        assert actual == expected
        assert ledger.records(segment.rows[0][2]) == records
        assert remote.uploads == 1
        reads = remote.reads
        assert ledger.append("scope:start", segment.rows[0][2], "scope_started", {}) == records[0]
        assert remote.reads == reads
        assert ledger.append("attempt:forecast:1", segment.rows[0][2], "forecast", {}) == records[2]
        assert remote.reads == reads + 1
        head = ledger.head
    finally:
        ledger.close()

    def no_replay(*args, **kwargs):
        raise AssertionError("restart and status must not replay completed forecasts")

    monkeypatch.setattr(ForecastSummary, "accept", no_replay)
    with_forecast = opened(tmp_path, remote)
    try:
        assert with_forecast.head == head
        assert not with_forecast.maintain_retention()
        assert with_forecast.status(segment.rows[0][2], observed_unix_ms=4000) == expected
        assert remote.uploads == 1
    finally:
        with_forecast.close()


def test_interrupted_upload_resumes_without_index_replay_or_original_read(
    historical, tmp_path, monkeypatch
):
    segment, _, _ = historical
    remote = Remote()
    ledger = opened(tmp_path, remote)
    put = remote.put_bytes

    def stopped(*args, **kwargs):
        raise OSError("remote temporarily unavailable")

    monkeypatch.setattr(remote, "put_bytes", stopped)
    with pytest.raises(OSError):
        ledger.maintain_retention()
    assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (4,)
    ledger.close()
    monkeypatch.setattr(remote, "put_bytes", put)

    def no_replay(*args, **kwargs):
        raise AssertionError("atomic segment already owns completed indexing")

    monkeypatch.setattr(ForecastSummary, "accept", no_replay)
    ledger = opened(tmp_path, remote)
    try:
        assert ledger.maintain_retention()
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
        assert remote.uploads == 1
        assert ledger.retention.index.head == (segment.last_sequence, segment.last_sha256)
    finally:
        ledger.close()


def test_append_after_migration_and_interrupted_index_commit_recover_exact_original(
    historical, tmp_path, monkeypatch
):
    remote = Remote()
    ledger = opened(tmp_path, remote)
    try:
        ledger.maintain_retention()
        index = ledger.retention.index
        original = index.accept

        def interrupted(row):
            raise OSError("index commit interrupted")

        monkeypatch.setattr(index, "accept", interrupted)
        with pytest.raises(OSError):
            ledger.append("next:started", "c" * 64, "scope_started", {"observed_unix_ms": 5000})
        raw = ledger.db.execute("SELECT body FROM events WHERE sequence=5").fetchone()[0]
        assert ledger.head[1] == 5
        assert index.head[0] == 4
        monkeypatch.setattr(index, "accept", original)
        assert ledger.maintain_retention()
        assert ledger.append("next:started", "c" * 64, "scope_started", {}) == json.loads(raw)
        assert ledger.status("c" * 64, observed_unix_ms=6000)["outcome"] == "unfinished"
        assert not ledger.health["coverage_complete"]
    finally:
        ledger.close()


def test_migrated_ledger_refuses_old_reader_and_missing_retention(historical, tmp_path):
    import shutil

    remote = Remote()
    ledger = opened(tmp_path, remote)
    ledger.maintain_retention()
    ledger.close()
    with pytest.raises(ForecastRepairRequired, match="schema"):
        ForecastLedger(tmp_path / "legacy")
    shutil.rmtree(tmp_path / "legacy" / "retention")
    with pytest.raises(ForecastRepairRequired):
        opened(tmp_path, remote)


async def test_owned_retention_worker_does_not_block_loop_and_drains_on_cancel(
    historical, tmp_path, monkeypatch
):
    import asyncio
    from threading import Event
    from types import SimpleNamespace

    from umi.competition_cohort_lifecycle_host import LifecycleHost

    remote, entered, release = Remote(), Event(), Event()
    put = remote.put_bytes

    def waiting(raw, *, path):
        entered.set()
        if not release.wait(5):
            raise TimeoutError("test publication was not released")
        return put(raw, path=path)

    monkeypatch.setattr(remote, "put_bytes", waiting)
    ledger = opened(tmp_path, remote)
    owner = SimpleNamespace(
        forecast_ledger=ledger,
        config=SimpleNamespace(poll_seconds=1),
        service=SimpleNamespace(config=SimpleNamespace(series=SimpleNamespace(cohorts=()))),
    )
    task = asyncio.create_task(LifecycleHost._forecast_retention_loop(owner, asyncio.Event()))
    try:

        async def started():
            while not entered.is_set():
                await asyncio.sleep(0.001)

        await asyncio.wait_for(started(), 2)
        # The publication thread is blocked, while the event loop remains usable.
        assert not task.done()
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (4,)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done(), "owner cancellation must drain its publication thread"
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 2)
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
    finally:
        release.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
        ledger.close()


def test_small_final_batch_flushes_without_waiting_for_more_events(historical, tmp_path):
    remote = Remote()
    ledger = opened(tmp_path, remote)
    try:
        ledger.maintain_retention()
        ledger.append("next:start", "c" * 64, "scope_started", {"observed_unix_ms": 5000})
        assert not ledger.maintain_retention()
        ledger.retention.last_archive -= 31
        assert ledger.maintain_retention()
        assert ledger.retention.index.latest_archive()["last_sequence"] == 5
        assert remote.uploads == 2
    finally:
        ledger.close()


async def test_damaged_retention_diagnostics_do_not_stop_lifecycle():
    import asyncio
    from types import SimpleNamespace

    from umi.competition_cohort_lifecycle_host import LifecycleHost

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()

    def damaged():
        loop.call_soon_threadsafe(stop.set)
        raise KeyError("damaged diagnostic checkpoint")

    def unavailable(**kwargs):
        raise KeyError("damaged diagnostic summary")

    ledger = SimpleNamespace(
        maintain_retention=damaged, retention=SimpleNamespace(diagnostics=unavailable)
    )
    owner = SimpleNamespace(
        forecast_ledger=ledger,
        config=SimpleNamespace(poll_seconds=1),
        service=SimpleNamespace(config=SimpleNamespace(series=SimpleNamespace(cohorts=()))),
    )
    await asyncio.wait_for(LifecycleHost._forecast_retention_loop(owner, stop), 2)


def test_original_retry_cache_is_bounded_and_restores_evicted_exact_bytes(tmp_path):
    root = tmp_path / "legacy"
    legacy = ForecastLedger(root, maximum_bytes=8 * 1024**2)
    first = legacy.append("start:0", "scope", "scope_started", {"observed_unix_ms": 1000})
    for i in range(1, 600):
        legacy.append(f"start:{i}", "scope", "attempt_started", {"observed_unix_ms": 1000 + i})
    legacy.close()
    remote = Remote()
    ledger = opened(tmp_path, remote)
    try:
        while ledger.maintain_retention():
            pass
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
        assert ledger.retention.index.db.execute("SELECT COUNT(*) FROM originals").fetchone() == (
            512,
        )
        assert ledger.scopes() == ["scope"]
        reads = remote.reads
        assert ledger.append("start:0", "scope", "scope_started", {}) == first
        assert remote.reads == reads + 1
        assert ledger.append("start:0", "scope", "scope_started", {}) == first
        assert remote.reads == reads + 1
        assert ledger.retention.index.db.execute("SELECT COUNT(*) FROM originals").fetchone() == (
            512,
        )
    finally:
        ledger.close()


def test_index_capacity_failure_does_not_mislabel_original_ledger_capacity(
    historical, tmp_path, monkeypatch
):
    import sqlite3

    ledger = opened(tmp_path, Remote())
    try:
        ledger.maintain_retention()

        def full(row):
            raise sqlite3.OperationalError("database or disk is full")

        monkeypatch.setattr(ledger.retention.index, "accept", full)
        with pytest.raises(sqlite3.OperationalError):
            ledger.append("capacity:start", "c" * 64, "scope_started", {"observed_unix_ms": 5000})
        assert not ledger.capacity_required
        assert ledger.health["blocked_capacity_bytes"] is None
        assert ledger.health["last_gap"]["reason"] == "retained_index_capacity_exhausted"
    finally:
        ledger.close()


async def test_reporting_failure_cannot_stop_owned_maintenance(historical, tmp_path):
    import asyncio

    from umi.competition_forecast_maintenance import maintain_forecasts

    ledger = opened(tmp_path, Remote())
    stop = asyncio.Event()

    def damaged_report(status):
        stop.set()
        raise OSError("diagnostic publication failed")

    try:
        await maintain_forecasts(ledger, stop, poll_seconds=0.01, report=damaged_report)
        assert ledger.db.execute("SELECT COUNT(*) FROM events").fetchone() == (0,)
    finally:
        ledger.close()


@pytest.mark.parametrize(
    "damage_sql",
    [
        "UPDATE archives SET receipt=NULL",
        "UPDATE archives SET metadata=x'7b7d'",
        "DELETE FROM archives",
    ],
)
def test_restart_refuses_lost_archive_state_without_replaying_originals(
    historical, tmp_path, damage_sql
):
    remote = Remote()
    ledger = opened(tmp_path, remote)
    ledger.maintain_retention()
    with ledger.retention.index.db:
        ledger.retention.index.db.execute(damage_sql)
    ledger.close()
    with pytest.raises(ValueError, match="repair"):
        opened(tmp_path, remote)
    assert remote.uploads == 1
    assert remote.reads == 0


def test_live_missing_receipt_cannot_be_reported_current(historical, tmp_path):
    ledger = opened(tmp_path, Remote())
    try:
        ledger.maintain_retention()
        with ledger.retention.index.db:
            ledger.retention.index.db.execute("UPDATE archives SET receipt=NULL")
        with pytest.raises(ValueError, match="repair"):
            ledger.retention.diagnostics()
        with pytest.raises(ValueError, match="repair"):
            ledger.maintain_retention()
    finally:
        ledger.close()
