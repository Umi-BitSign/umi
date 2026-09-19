from __future__ import annotations

import re
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from threading import Barrier

import pytest

from umi.grandpa_finality_accounting import install_accounting, read_usage
from umi.grandpa_finality_supervisor import (
    GrandpaFinalityStoreCorruption,
    GrandpaFinalitySupervisorError,
    GrandpaFinalitySupervisorLimits,
)

from .test_grandpa_finality_supervisor import _attestation, _audit_history, _header, _port
from .test_grandpa_finality_supervisor import chain_observation as chain_observation
from .test_grandpa_finality_supervisor import observer as observer

_MARKER = "evidence_accounting_v1"
_TABLE = "finality_evidence_accounting"


def usage(path):
    with sqlite3.connect(path) as connection:
        return read_usage(connection)


def accounting_triggers(connection):
    return [
        name
        for (name,) in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND tbl_name='finalized_headers' AND sql LIKE ? ORDER BY name",
            (f"%{_TABLE}%",),
        )
    ]


def legacy_database(path):
    """Restore the exact pre-accounting shape, not a broken version-3 store."""
    with sqlite3.connect(path) as connection:
        for name in accounting_triggers(connection):
            connection.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
        connection.execute(f"DROP TABLE {_TABLE}")
        connection.execute("DELETE FROM store_meta WHERE key=?", (_MARKER,))
        connection.execute("PRAGMA user_version=2")


def retained_bytes(path):
    with sqlite3.connect(path) as connection:
        return (
            connection.execute(
                "SELECT * FROM store_meta WHERE key!=? ORDER BY key", (_MARKER,)
            ).fetchall(),
            connection.execute("SELECT * FROM observer_segments ORDER BY segment_index").fetchall(),
            connection.execute("SELECT * FROM finalized_headers ORDER BY height").fetchall(),
        )


def next_record(port, observer):
    binding = port.next_run_binding()
    previous = port.persisted_head()
    height = 10 if previous is None else previous.height + 1
    parent = "0x" + "11" * 32 if previous is None else previous.block_hash
    record = _attestation(
        observer,
        binding,
        block=_header(height, parent_hash=parent, seed=height + 10),
        sequence=0,
        previous=None,
    )
    return binding, record


async def test_legacy_backfill_preserves_config_evidence_and_receipt_bytes(
    tmp_path, observer, chain_observation
):
    port = _port(tmp_path, observer, chain_observation)
    records = _audit_history(port, observer)
    path = tmp_path / "finality.sqlite3"
    receipts = tuple(
        [await port.verified_acceptance_receipt_at(record.block.number) for record in records]
    )
    before = retained_bytes(path)
    legacy_database(path)
    migrated = _port(tmp_path, observer, chain_observation)
    assert retained_bytes(path) == before
    assert (
        tuple(
            [
                await migrated.verified_acceptance_receipt_at(record.block.number)
                for record in records
            ]
        )
        == receipts
    )
    assert usage(path) == (len(records), sum(len(record.canonical_bytes) for record in records))
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
        assert (
            connection.execute("SELECT value FROM store_meta WHERE key=?", (_MARKER,)).fetchone()[0]
            == b"umi-grandpa-evidence-accounting/1"
        )
    migrated.audit()


def test_failed_legacy_audit_does_not_install_or_mark_accounting(
    tmp_path, observer, chain_observation
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer)
    path = tmp_path / "finality.sqlite3"
    legacy_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE finalized_headers SET state_root=? WHERE height=10", ("0x" + "ef" * 32,)
        )
    before = retained_bytes(path)
    with pytest.raises(GrandpaFinalityStoreCorruption, match="normalized_header_mismatch"):
        _port(tmp_path, observer, chain_observation)
    assert retained_bytes(path) == before
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 2
        assert read_usage(connection, allow_missing=True) is None


def test_preopened_legacy_sql_writer_uses_new_triggers_and_rollback(
    tmp_path, observer, chain_observation
):
    port = _port(tmp_path, observer, chain_observation)
    records = _audit_history(port, observer, segment_lengths=(1,))
    path = tmp_path / "finality.sqlite3"
    legacy_database(path)
    # Cache a statement before migration, as an older process could do. The old
    # writer knows no counter API; SQLite's database triggers must account for it.
    with sqlite3.connect(path) as old:
        old.row_factory = sqlite3.Row
        original = dict(old.execute("SELECT * FROM finalized_headers WHERE height=10").fetchone())
        _port(tmp_path, observer, chain_observation)
        initial = (1, len(records[0].canonical_bytes))
        assert read_usage(old) == initial
        old.execute("BEGIN IMMEDIATE")
        raw = {
            **original,
            "height": 111,
            "block_hash": "0x" + "fe" * 32,
            "evidence_sha256": "fd" * 32,
            "transcript_digest": "fc" * 32,
            "acceptance_digest": "fb" * 32,
            "segment_sequence": 99,
            "canonical_evidence": b"synthetic old SQL writer",
        }
        columns = tuple(raw)
        old.execute(
            f"INSERT INTO finalized_headers({','.join(columns)}) "
            f"VALUES ({','.join('?' for _ in columns)})",
            tuple(raw.values()),
        )
        assert read_usage(old) == (2, initial[1] + len(raw["canonical_evidence"]))
        old.execute(
            "UPDATE finalized_headers SET canonical_evidence=? WHERE height=111",
            (b"longer replacement evidence bytes",),
        )
        assert read_usage(old) == (2, initial[1] + len(b"longer replacement evidence bytes"))
        old.execute("DELETE FROM finalized_headers WHERE height=111")
        assert read_usage(old) == initial
        old.execute("UPDATE finalized_headers SET canonical_evidence=x'7b7d' WHERE height=10")
        assert read_usage(old) == (1, 2)
        old.rollback()
        assert read_usage(old) == initial
    port.audit()


@pytest.mark.parametrize(
    "change",
    [
        "count",
        "bytes",
        "singleton",
        "trigger",
        "trigger_sql",
        "marker",
        "marker_bytes",
        "table",
        "type",
    ],
)
def test_startup_rejects_accounting_tamper_without_repair(
    tmp_path, observer, chain_observation, change
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer)
    path = tmp_path / "finality.sqlite3"
    with sqlite3.connect(path) as connection:
        if change == "count":
            connection.execute(f"UPDATE {_TABLE} SET header_count=header_count-1")
        elif change == "bytes":
            connection.execute(f"UPDATE {_TABLE} SET evidence_bytes=evidence_bytes-1")
        elif change == "singleton":
            connection.execute(f"DELETE FROM {_TABLE}")
        elif change in {"trigger", "trigger_sql"}:
            name = accounting_triggers(connection)[0]
            connection.execute('DROP TRIGGER "' + name.replace('"', '""') + '"')
            if change == "trigger_sql":
                connection.execute(
                    'CREATE TRIGGER "'
                    + name.replace('"', '""')
                    + '" AFTER INSERT ON finalized_headers BEGIN SELECT 1; END'
                )
        elif change == "marker":
            connection.execute("DELETE FROM store_meta WHERE key=?", (_MARKER,))
        elif change == "marker_bytes":
            connection.execute("UPDATE store_meta SET value=x'00' WHERE key=?", (_MARKER,))
        elif change == "table":
            connection.execute(f"DROP TABLE {_TABLE}")
        else:
            connection.execute("PRAGMA ignore_check_constraints=ON")
            connection.execute(f"UPDATE {_TABLE} SET evidence_bytes='not-an-integer'")
    before = retained_bytes(path)
    reason = (
        "evidence_accounting|sqlite_quick_check_failed"
        if change == "type"
        else "evidence_accounting"
    )
    with pytest.raises(GrandpaFinalityStoreCorruption, match=reason):
        _port(tmp_path, observer, chain_observation)
    assert retained_bytes(path) == before


def test_version_three_cannot_silently_rebuild_completely_missing_accounting(
    tmp_path, observer, chain_observation
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer)
    path = tmp_path / "finality.sqlite3"
    legacy_database(path)
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=3")
    with pytest.raises(GrandpaFinalityStoreCorruption, match="evidence_accounting"):
        _port(tmp_path, observer, chain_observation)
    with sqlite3.connect(path) as connection:
        assert (
            connection.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_TABLE,)).fetchone()
            is None
        )
        assert (
            connection.execute("SELECT 1 FROM store_meta WHERE key=?", (_MARKER,)).fetchone()
            is None
        )


def test_version_two_with_accounting_objects_is_not_a_legacy_migration(
    tmp_path, observer, chain_observation
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer)
    path = tmp_path / "finality.sqlite3"
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA user_version=2")
    before = retained_bytes(path)
    with pytest.raises(GrandpaFinalityStoreCorruption, match="evidence_accounting"):
        _port(tmp_path, observer, chain_observation)
    assert retained_bytes(path) == before


def test_exact_replay_does_not_charge_headers_or_bytes_again(tmp_path, observer, chain_observation):
    limits = GrandpaFinalitySupervisorLimits(maximum_headers=1, maximum_records_per_process=1)
    port = _port(tmp_path, observer, chain_observation, limits=limits)
    binding, record = next_record(port, observer)
    first = port.accept_attestation(binding, record)
    path = tmp_path / "finality.sqlite3"
    expected = (1, len(record.canonical_bytes))
    for _ in range(4):
        assert port.accept_attestation(binding, record) == first
        assert usage(path) == expected
    reopened = _port(tmp_path, observer, chain_observation, limits=limits)
    assert reopened.accept_attestation(binding, record) == first
    assert usage(path) == expected


@pytest.mark.parametrize("limit", ["headers", "bytes", "exact"])
def test_capacity_limits_and_exact_boundaries_keep_accounting_atomic(
    tmp_path, observer, chain_observation, limit
):
    source = _port(tmp_path, observer, chain_observation, state_name="fixture.sqlite3")
    binding, first = next_record(source, observer)
    second = _attestation(
        observer,
        binding,
        block=_header(11, parent_hash=first.block.hash, seed=21),
        sequence=1,
        previous=first,
    )
    sizes = [len(first.canonical_bytes), len(second.canonical_bytes)]
    limits = GrandpaFinalitySupervisorLimits(
        maximum_headers=1 if limit == "headers" else 2,
        maximum_evidence_bytes=max(sizes),
        maximum_total_evidence_bytes=sum(sizes) - (limit == "bytes"),
        maximum_records_per_process=2,
    )
    port = _port(tmp_path, observer, chain_observation, limits=limits)
    path = tmp_path / "finality.sqlite3"
    port.accept_attestation(binding, first)
    before = retained_bytes(path)
    if limit == "exact":
        port.accept_attestation(binding, second)
        assert usage(path) == (2, sum(sizes))
    else:
        reason = "header_count_limit" if limit == "headers" else "total_evidence_limit"
        with pytest.raises(GrandpaFinalitySupervisorError, match=reason):
            port.accept_attestation(binding, second)
        assert retained_bytes(path) == before
        assert usage(path) == (1, sizes[0])
    port.audit()


def test_failure_after_triggered_insert_rolls_back_segment_header_and_counters(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer, segment_lengths=(1,))
    path = tmp_path / "finality.sqlite3"
    binding, record = next_record(port, observer)
    before, before_usage = retained_bytes(path), usage(path)
    connect = port._connect
    injected = []

    @contextmanager
    def failed_connection(*, read_only):
        with connect(read_only=read_only) as connection:

            class FailAfterInsert:
                def execute(self, sql, *args):
                    if "UPDATE store_meta SET value" in sql and "head_acceptance_digest" in sql:
                        assert read_usage(connection) == (
                            before_usage[0] + 1,
                            before_usage[1] + len(record.canonical_bytes),
                        )
                        injected.append(True)
                        raise sqlite3.OperationalError("injected after header insert")
                    return connection.execute(sql, *args)

                def __getattr__(self, name):
                    return getattr(connection, name)

            yield connection if read_only else FailAfterInsert()

    with monkeypatch.context() as patch:
        patch.setattr(port, "_connect", failed_connection)
        with pytest.raises(GrandpaFinalityStoreCorruption, match="sqlite_write_failed"):
            port.accept_attestation(binding, record)
    assert injected == [True]
    assert retained_bytes(path) == before
    assert usage(path) == before_usage
    port.audit()


def test_acceptance_hot_path_never_aggregates_historical_evidence(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer, segment_lengths=(2,) * 5)
    binding, record = next_record(port, observer)
    connect, statements = port._connect, []

    @contextmanager
    def traced(*, read_only):
        with connect(read_only=read_only) as connection:
            connection.set_trace_callback(statements.append)
            yield connection

    with monkeypatch.context() as patch:
        patch.setattr(port, "_connect", traced)
        port.accept_attestation(binding, record)
        port.accept_attestation(binding, record)
    assert statements
    assert not [
        sql
        for sql in statements
        if "finalized_headers" in sql.lower() and re.search(r"\b(count|sum)\s*\(", sql, re.I)
    ]
    port.audit()


def test_concurrent_legacy_migration_installs_once_without_changing_history(
    tmp_path, observer, chain_observation
):
    port = _port(tmp_path, observer, chain_observation)
    records = _audit_history(port, observer)
    path = tmp_path / "finality.sqlite3"
    legacy_database(path)
    before = retained_bytes(path)
    barrier = Barrier(4)

    def open_port(_index):
        barrier.wait(timeout=5)
        return _port(tmp_path, observer, chain_observation)

    with ThreadPoolExecutor(max_workers=4) as executor:
        ports = list(executor.map(open_port, range(4)))
    assert retained_bytes(path) == before
    assert usage(path) == (len(records), sum(len(record.canonical_bytes) for record in records))
    for candidate in ports:
        candidate.audit()


def test_accounting_install_requires_owning_write_transaction(
    tmp_path, observer, chain_observation
):
    _port(tmp_path, observer, chain_observation)
    path = tmp_path / "finality.sqlite3"
    legacy_database(path)
    with sqlite3.connect(path, isolation_level=None) as connection:
        with pytest.raises(ValueError, match="requires a transaction"):
            install_accounting(connection, (0, 0))
        assert read_usage(connection, allow_missing=True) is None
