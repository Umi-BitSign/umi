"""Capacity shortcuts preserve exact admission and legacy writer behavior."""

import sqlite3
from contextlib import closing

import pytest

from umi.finalized_ancestry import encode_rpc_header
from umi.historical_header_capacity import hint_payload_usage
from umi.historical_header_recovery import HistoricalHeaderRecovery, HistoricalHeaderRecoveryPending

from .test_competition_chain import chain_config as chain_config
from .test_historical_header_recovery import walk as walk
from .test_open_competition import policy as policy


def deny_sum(action, first, second, database, trigger):
    if action == sqlite3.SQLITE_FUNCTION and second.lower() == "sum":
        return sqlite3.SQLITE_DENY
    return sqlite3.SQLITE_OK


@pytest.mark.parametrize("journal", ["DELETE", "WAL"])
async def test_native_single_batch_restart_and_old_writer_skip_full_scans(walk, journal):
    w = walk
    service = HistoricalHeaderRecovery(w.connect)
    service._open().close()
    rows = [(key, encode_rpc_header(value)) for key, value in w.headers.items()]
    with closing(w.connect()) as legacy:
        assert legacy.execute("PRAGMA journal_mode=" + journal).fetchone()[0] == journal.lower()
        legacy.execute("INSERT INTO historical_header_hints VALUES (?,?)", rows[0])

        def connect():
            db = w.connect()
            db.set_authorizer(deny_sum)
            return db

        current = HistoricalHeaderRecovery(connect)
        current._save(*rows[1])
        assert await current.retain_hints((rows[2][1], rows[3][1])) == 2
        # An older opened writer remains supported; there is no cached count
        # that can miss its committed insertion or require an index migration.
        legacy.execute("INSERT INTO historical_header_hints VALUES (?,?)", rows[4])
        restarted = HistoricalHeaderRecovery(connect)
        restarted._save(*rows[5])
        assert await restarted.retain_hints((rows[5][1],)) == 0
        assert legacy.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0] == 6


@pytest.mark.parametrize("journal", ["DELETE", "WAL"])
async def test_loose_page_bound_uses_exact_limit_without_false_refusal(walk, journal):
    w = walk
    rows = [(key, encode_rpc_header(value)) for key, value in w.headers.items()]
    size = sum(len(row[1]) for row in rows[:3])
    service = HistoricalHeaderRecovery(w.connect, maximum_bytes=size)
    service._open().close()
    with closing(w.connect()) as legacy:
        legacy.execute("PRAGMA journal_mode=" + journal)
        # Real registration databases may contain large unrelated tables.
        legacy.execute("CREATE TABLE unrelated(payload BLOB)")
        legacy.execute("INSERT INTO unrelated VALUES (zeroblob(65536))")
        legacy.execute("INSERT INTO historical_header_hints VALUES (?,?)", rows[0])
        service._save(*rows[1])
        assert await service.retain_hints((rows[2][1],)) == 1
        # The exact boundary remains usable; the first excess row is refused.
        with pytest.raises(HistoricalHeaderRecoveryPending, match="capacity"):
            service._save(*rows[3])
        with pytest.raises(HistoricalHeaderRecoveryPending, match="capacity"):
            await service.retain_hints((rows[3][1], rows[4][1]))
        assert (
            legacy.execute("SELECT SUM(length(encoded)) FROM historical_header_hints").fetchone()[0]
            == size
        )
        assert legacy.execute("SELECT COUNT(*) FROM historical_header_hints").fetchone()[0] == 3


def test_capacity_check_requires_insertion_transaction(walk):
    with closing(walk.connect()) as db, pytest.raises(ValueError, match="transaction"):
        hint_payload_usage(db, additional_bytes=1, maximum_bytes=100)
