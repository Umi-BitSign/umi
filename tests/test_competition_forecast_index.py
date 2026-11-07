"""Compact summaries survive restart without replaying original payloads."""

import hashlib
import json
import sqlite3

import pytest

from umi import competition_forecast_index as index
from umi.competition_forecast_io import encode_forecast_json
from umi.competition_forecast_summary import ForecastSummary

from .test_competition_forecast_archive import historical as historical


def test_checkpoint_restart_reuses_completed_rows_and_summary(historical, tmp_path, monkeypatch):
    segment, expected, _ = historical
    root = tmp_path / "index"
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        for row in segment.rows[:2]:
            assert store.accept(row)
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        # A completed row is selected by its retained chain identity. Reuse
        # does not need its original body, which may have been archived/evicted.
        for row in segment.rows[:2]:
            assert not store.accept((*row[:3], None, *row[4:]))
        for row in segment.rows[2:]:
            assert store.accept(row)
    with index.ForecastIndex(root, segment.ledger_sha256) as store:

        def no_replay(*args, **kwargs):
            raise AssertionError("restart/status must not replay forecast events")

        monkeypatch.setattr(ForecastSummary, "accept", no_replay)
        actual = store.status(segment.rows[0][2], 4000)
        assert actual == {key: expected[key] for key in actual}
        assert store.head == (segment.last_sequence, segment.last_sha256)


@pytest.mark.parametrize(
    "damage", ["summary", "missing_summary", "deadline", "checkpoint", "middle", "database"]
)
def test_damaged_retained_index_requires_repair(historical, tmp_path, damage):
    segment, _, _ = historical
    root = tmp_path / "index"
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        for row in segment.rows:
            store.accept(row)
        with store.db:
            if damage == "summary":
                store.db.execute("UPDATE summaries SET body=?", (b"{}",))
            elif damage == "missing_summary":
                store.db.execute("DELETE FROM summaries")
            elif damage == "deadline":
                store.db.execute("DELETE FROM deadlines")
            elif damage == "checkpoint":
                store.db.execute(
                    "DELETE FROM identities WHERE sequence=?", (segment.last_sequence,)
                )
            elif damage == "middle":
                store.db.execute("DELETE FROM identities WHERE sequence=2")
    if damage == "database":
        (root / "index.sqlite3").unlink()
    with (
        pytest.raises(ValueError, match="repair"),
        index.ForecastIndex(root, segment.ledger_sha256) as store,
    ):
        store.status(segment.rows[0][2], 4000)


def test_repeated_deadlines_clock_queries_and_completion_match_original(tmp_path):
    expected = ForecastSummary()
    scope, previous = "a" * 64, "0" * 64
    events = [dict(kind="scope_started", observed_unix_ms=1000)]
    events += [
        dict(
            kind="forecast",
            observed_unix_ms=1001 + i,
            finish_unix_ms=2000 + i % 3,
            eta_seconds=1,
            elapsed_seconds=0,
        )
        for i in range(30)
    ]
    events += [dict(kind="completed", observed_unix_ms=3000)]
    events += [
        dict(
            kind="forecast",
            observed_unix_ms=4000,
            finish_unix_ms=5000,
            eta_seconds=1,
            elapsed_seconds=0,
        )
    ]
    with index.ForecastIndex(tmp_path / "index", "b" * 64) as store:
        for sequence, event in enumerate(events, 1):
            event.update(
                schema="umi-forecast-event/1",
                identity=f"event:{sequence}",
                scope=scope,
                certification_authority=False,
            )
            body = encode_forecast_json(event)
            checksum = hashlib.sha256(previous.encode() + body).hexdigest()
            store.accept((sequence, event["identity"], scope, body, previous, checksum))
            expected.accept(event, sequence=sequence)
            previous = checksum
            for now in (5000, 1500, 2500, 6000):
                assert store.status(scope, now) == expected.status(scope, now)
        assert store.db.execute("SELECT COUNT(*) FROM deadlines").fetchone() == (3,)


def test_failed_row_does_not_advance_checkpoint(historical, tmp_path):
    segment, _, _ = historical
    with index.ForecastIndex(tmp_path / "index", segment.ledger_sha256) as store:
        row = segment.rows[0]
        with pytest.raises(ValueError):
            store.accept((*row[:3], b"{}", *row[4:]))
        assert store.head == (0, "0" * 64)
        assert store.accept(row)
        with pytest.raises(ValueError):
            store.accept((*row[:5], "c" * 64))
        assert store.head == (1, row[-1])


def test_failed_page_rolls_back_summaries_and_restarts_at_completed_head(historical, tmp_path):
    segment, expected, _ = historical
    root = tmp_path / "index"
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        store.accept(segment.rows[0])
        broken = (*segment.rows[-1][:3], b"{}", *segment.rows[-1][4:])
        with pytest.raises(ValueError, match="damaged"):
            store.accept_many((*segment.rows[1:-1], broken))
        assert store.head == (1, segment.rows[0][-1])
        assert store.db.execute("SELECT COUNT(*) FROM identities").fetchone() == (1,)
        assert store.summary(segment.rows[0][2]).forecasts == 0
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        assert store.accept_many(segment.rows[1:]) == [True] * (len(segment.rows) - 1)
        actual = store.status(segment.rows[0][2], 4000)
        assert actual == {key: expected[key] for key in actual}


def test_index_page_is_bounded_before_transaction(historical, tmp_path):
    segment, _, _ = historical
    with index.ForecastIndex(tmp_path / "index", segment.ledger_sha256) as store:
        with pytest.raises(ValueError, match="event bound"):
            store.accept_many([segment.rows[0]] * 4097)
        with pytest.raises(ValueError, match="payload bound"):
            store.accept_many([(*segment.rows[0][:3], b"x" * 16384, *segment.rows[0][4:])] * 513)
        assert store.head == (0, "0" * 64)


def test_index_and_archive_share_one_immutable_payload_validation(
    historical, tmp_path, monkeypatch
):
    from umi.competition_forecast_archive import encode_segment

    segment, expected, _ = historical
    original = hashlib.sha256
    payloads = {row[4].encode() + row[3] for row in segment.rows}
    checked = []

    def counted(value=b"", **kwargs):
        if value in payloads:
            checked.append(value)
        return original(value, **kwargs)

    monkeypatch.setattr(hashlib, "sha256", counted)
    with index.ForecastIndex(tmp_path / "index", segment.ledger_sha256) as store:
        assert store.accept_segment(segment) == [True] * len(segment.rows)
        encode_segment(segment)
        assert len(checked) == len(segment.rows)
        actual = store.status(segment.rows[0][2], 4000)
        assert actual == {key: expected[key] for key in actual}


def test_index_refuses_another_segments_owner(historical, tmp_path):
    segment, _, _ = historical
    with index.ForecastIndex(tmp_path / "index", "c" * 64) as store:
        with pytest.raises(ValueError, match="another index"):
            store.accept_segment(segment)
        assert store.head == (0, "0" * 64)


def mixed_page(count=1024):
    rows, expected, previous = [], {}, "0" * 64
    for sequence in range(1, count + 1):
        scope = f"scope:{sequence % 7}"
        kind = (
            "scope_started"
            if sequence <= 7
            else "completed"
            if 700 <= sequence < 707
            else "forecast"
            if sequence % 3
            else "attempt_started"
        )
        event = dict(
            schema="umi-forecast-event/1",
            identity=f"item:{sequence}",
            scope=scope,
            certification_authority=False,
            kind=kind,
            observed_unix_ms=1000 + sequence,
        )
        if kind == "forecast":
            event.update(finish_unix_ms=3000 + sequence % 3, eta_seconds=1, elapsed_seconds=0)
        body = encode_forecast_json(event)
        checksum = hashlib.sha256(previous.encode() + body).hexdigest()
        rows.append((sequence, event["identity"], scope, body, previous, checksum))
        expected.setdefault(scope, ForecastSummary()).accept(event, sequence=sequence)
        previous = checksum
    return rows, expected


def test_bounded_bulk_pages_preserve_deadline_multiplicity_completion_and_retries(tmp_path):
    rows, expected = mixed_page()
    with index.ForecastIndex(tmp_path / "index", "b" * 64) as store:
        if hasattr(store.db, "setlimit"):
            store.db.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 999)
        statements = []
        store.db.set_trace_callback(statements.append)
        assert store.accept_many(rows[:512]) == [True] * 512
        # Retry the committed prefix and one repeated row from this transaction.
        second = [*rows[500:800], rows[799], *rows[800:]]
        assert store.accept_many(second) == [False] * 12 + [True] * 288 + [False] + [True] * 224
        # Bound database crossings independently of machine timing or CPU speed.
        assert len(statements) < 100
        store.db.set_trace_callback(None)
        for scope, summary in expected.items():
            for now in (1500, 4000, 2500):
                assert store.status(scope, now) == summary.status(scope, now)
        nonforecasts = [r for r in rows if json.loads(r[3])["kind"] != "forecast"]
        assert store.db.execute("SELECT sequence FROM originals ORDER BY used").fetchall() == [
            (r[0],) for r in nonforecasts[-512:]
        ]
    with index.ForecastIndex(tmp_path / "index", "b" * 64) as store:
        assert store.head == (len(rows), rows[-1][-1])
        for scope, summary in expected.items():
            assert store.status(scope, 4000) == summary.status(scope, 4000)


def test_bulk_cache_evicts_oldest_exact_originals_once_per_page(tmp_path):
    rows, _ = mixed_page(7)
    previous = rows[-1][-1]
    for sequence in range(8, 1100):
        event = dict(
            schema="umi-forecast-event/1",
            identity=f"item:{sequence}",
            scope="scope:0",
            certification_authority=False,
            kind="attempt_started",
            observed_unix_ms=sequence,
        )
        body = encode_forecast_json(event)
        checksum = hashlib.sha256(previous.encode() + body).hexdigest()
        rows.append((sequence, event["identity"], "scope:0", body, previous, checksum))
        previous = checksum
    with index.ForecastIndex(tmp_path / "index", "b" * 64) as store:
        store.accept_many(rows[:256])
        store.accept_many(rows[256:])
        assert store.db.execute("SELECT sequence FROM originals ORDER BY used").fetchall() == [
            (r[0],) for r in rows[-512:]
        ]
        assert store.cached_original(1) is None
        assert store.cached_original(rows[-1][0]) == rows[-1][3]


def test_bulk_archive_failure_rolls_back_all_page_state(historical, tmp_path):
    segment, _, _ = historical
    root = tmp_path / "index"
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        store.db.execute(
            "CREATE TRIGGER reject_archive BEFORE INSERT ON archives "
            "BEGIN SELECT RAISE(ABORT,'interrupted archive'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="interrupted archive"):
            store.stage_archive(segment)
        assert store.head == (0, "0" * 64)
        for table in ("identities", "summaries", "deadlines", "originals", "archives"):
            assert store.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
        store.db.execute("DROP TRIGGER reject_archive")
    with index.ForecastIndex(root, segment.ledger_sha256) as store:
        store.stage_archive(segment)
        assert store.head == (segment.last_sequence, segment.last_sha256)
