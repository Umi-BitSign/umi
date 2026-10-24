"""Partial native startup survives journal contention without process restart."""

import asyncio
import json
import logging
import sqlite3
import threading

import pytest

from umi import competition_cohort_settlement_boot as boot

BUSY = getattr(sqlite3, "SQLITE_BUSY", 5)
LOCKED = getattr(sqlite3, "SQLITE_LOCKED", 6)
CORRUPT = getattr(sqlite3, "SQLITE_CORRUPT", 11)
IOERR = getattr(sqlite3, "SQLITE_IOERR", 10)


def busy(code):
    error = sqlite3.OperationalError("test journal writer contention")
    error.sqlite_errorcode = code
    return error


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [BUSY, LOCKED, BUSY | (2 << 8), "legacy"])
async def test_busy_startup_preserves_first_journal_and_runs_off_loop(monkeypatch, caplog, code):
    policy, first, second = object(), object(), object()
    opened = {first: object(), second: object()}
    calls, threads = [], []
    main_thread = threading.get_ident()

    def create(config, selected_policy):
        assert selected_policy is policy
        calls.append(config)
        threads.append(threading.get_ident())
        if config is second and calls.count(second) == 1:
            if code == "legacy":
                raise sqlite3.OperationalError("database is locked")
            raise busy(code)
        return opened[config]

    monkeypatch.setattr(boot, "CohortExecutionJournal", create)
    with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
        result = await boot._open_executions((first, second), policy, asyncio.Event())
    assert calls == [first, second, second]
    assert result == (opened[first], opened[second])
    assert all(thread != main_thread for thread in threads)
    events = [json.loads(r.message) for r in caplog.records if r.message.startswith("{")]
    retry = next(r for r in events if r.get("reason_code") == "execution_journal_writer_busy")
    assert retry["completed_units"] == 1 and retry["total_units"] == 2
    assert retry["eta_seconds"] is None
    assert events[-1]["status"] == "completed"
    assert events[-1]["completed_units"] == 2


@pytest.mark.asyncio
async def test_stop_during_busy_startup_does_not_reopen_completed_journal(monkeypatch):
    stop, calls = asyncio.Event(), []
    loop = asyncio.get_running_loop()

    def create(config, policy):
        calls.append(config)
        if config == "first":
            return object()
        loop.call_soon_threadsafe(stop.set)
        raise busy(BUSY)

    monkeypatch.setattr(boot, "CohortExecutionJournal", create)
    assert await boot._open_executions(("first", "second"), object(), stop) is None
    assert calls == ["first", "second"]


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [CORRUPT, IOERR, None])
async def test_noncontention_startup_errors_remain_explicit(monkeypatch, code):
    calls = []

    def create(config, policy):
        calls.append(config)
        raise busy(code)

    monkeypatch.setattr(boot, "CohortExecutionJournal", create)
    with pytest.raises(sqlite3.OperationalError):
        await boot._open_executions(("first",), object(), asyncio.Event())
    assert calls == ["first"]
