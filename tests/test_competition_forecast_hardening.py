"""Capacity gaps, linear routine accounting, and bounded snapshot transfer."""

import hashlib
import json
import shutil

import pytest

from umi import competition_forecast as module
from umi.competition_forecast import (
    ForecastCapacityRequired,
    ForecastLedger,
    ForecastRepairRequired,
    restore_forecast_snapshot,
)
from umi.competition_forecast_health import HEALTH_BYTES
from umi.competition_forecast_io import CHUNK_BYTES, stream_file


def start(ledger):
    ledger.append("start", "scope", "scope_started", {"observed_unix_ms": 1000})


def fill(ledger):
    with pytest.raises(ForecastCapacityRequired):
        for number in range(100):
            ledger.append(str(number), "padding", "diagnostic", {"payload": "x" * 8000})


def test_capacity_gap_survives_same_budget_restart_and_expansion(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root, maximum_bytes=64 * 1024)
    start(ledger)
    fill(ledger)
    previous = ledger.records("scope")
    gap = ledger.status("scope")["accounting_first_gap"]
    assert gap["reason"] == "capacity_exhausted"
    ledger.close()
    for _ in range(2):
        ledger = ForecastLedger(root, maximum_bytes=64 * 1024)
        assert ledger.capacity_required
        with pytest.raises(ForecastCapacityRequired):
            ledger.append("small", "scope", "diagnostic", {})
        assert ledger.records("scope") == previous
        assert ledger.status("scope")["status"] == "capacity_required"
        assert ledger.status("scope")["accounting_first_gap"] == gap
        ledger.close()
    ledger = ForecastLedger(root, maximum_bytes=128 * 1024)
    ledger.append("small", "scope", "diagnostic", {})
    result = ledger.status("scope")
    assert result["status"] == "retained"
    assert result["accounting_coverage_complete"] is False
    assert result["calibration_eligible"] is False
    assert result["accounting_gap_count"] == 1
    assert result["accounting_first_gap"] == gap
    ledger.close()


@pytest.mark.parametrize("damage", ["missing", "torn"])
def test_capacity_health_marker_cannot_be_silently_reset(tmp_path, damage):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root, maximum_bytes=64 * 1024)
    fill(ledger)
    marker = ledger.health_path
    ledger.close()
    if damage == "missing":
        marker.unlink()
    else:
        marker.write_bytes(b"torn" + b" " * (HEALTH_BYTES - 4))
    with pytest.raises(ForecastRepairRequired):
        ForecastLedger(root, maximum_bytes=128 * 1024)


def test_restore_gap_is_durable_and_not_an_eligible_calibration_sample(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    start(ledger)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    ledger.append(
        "lost-forecast",
        "scope",
        "forecast",
        {
            "observed_unix_ms": 2000,
            "finish_unix_ms": 3000,
        },
    )
    ledger.close()
    prior, _ = stream_file(root / "forecasts.sqlite3", maximum_bytes=1024**2)
    restore_forecast_snapshot(root, snapshot, receipt, damaged_sha256=prior)
    for _ in range(2):
        ledger = ForecastLedger(root)
        result = ledger.status("scope", observed_unix_ms=9000)
        assert result["accounting_gap_count"] == 1
        assert result["accounting_last_gap"]["reason"] == "snapshot_restoration_coverage_unknown"
        assert result["accounting_coverage_complete"] is False
        ledger.close()
    ledger = ForecastLedger(root)
    ledger.append(
        "success",
        "scope",
        "attempt_terminal",
        {
            "observed_unix_ms": 10000,
            "state": "completed",
        },
    )
    assert ledger.status("scope")["calibration_eligible"] is False
    assert ledger.status("scope")["duration_sample_eligible"] is False
    ledger.close()


def test_status_never_rehashes_or_decodes_accumulated_scope(tmp_path, monkeypatch):
    ledger = ForecastLedger(tmp_path / "accounting")
    counts = {"decode": 0, "hash": 0}
    decode, hash_ = json.loads, hashlib.sha256

    def counted_decode(*args, **kwargs):
        counts["decode"] += 1
        return decode(*args, **kwargs)

    def counted_hash(*args, **kwargs):
        counts["hash"] += 1
        return hash_(*args, **kwargs)

    monkeypatch.setattr(module.json, "loads", counted_decode)
    monkeypatch.setattr(module.hashlib, "sha256", counted_hash)
    start(ledger)
    for number in range(1200):
        ledger.append(
            str(number),
            "scope",
            "forecast",
            {
                "observed_unix_ms": 2000 + number,
                "finish_unix_ms": 3000 + number,
            },
        )
        ledger.status("scope", observed_unix_ms=2000 + number)
    assert counts == {"decode": 0, "hash": 1201}
    monkeypatch.setattr(ledger, "records", lambda *_: pytest.fail("routine full-scope scan"))
    before = dict(counts)
    for number in range(1200):
        assert (
            ledger.status("scope", observed_unix_ms=10000 + number)["overdue_unfinished_forecasts"]
            == 1200
        )
    assert counts == before
    ledger.close()
    ledger = ForecastLedger(tmp_path / "accounting")
    # Reopen performs one streaming chain validation, then reuses its compact
    # incremental summaries for every subsequent observation.
    before = dict(counts)
    for _ in range(1200):
        ledger.status("scope", observed_unix_ms=10000)
    assert counts == before
    ledger.close()


def test_all_database_hashing_and_restore_copy_use_bounded_reads(tmp_path, monkeypatch):
    from umi import competition_forecast_io as io

    ledger = ForecastLedger(tmp_path / "accounting", maximum_bytes=8 * 1024**2)
    start(ledger)
    for number in range(300):
        ledger.append(str(number), "padding", "diagnostic", {"payload": "x" * 8000})
    snapshot = tmp_path / "retained.sqlite3"
    reads = []
    native_read = io.os.read

    def bounded_read(fd, size):
        assert 0 < size <= CHUNK_BYTES
        reads.append(size)
        return native_read(fd, size)

    native_read_bytes = type(snapshot).read_bytes

    def no_database_read_bytes(path):
        assert not path.name.endswith(".sqlite3"), "whole database was materialized"
        return native_read_bytes(path)

    monkeypatch.setattr(io.os, "read", bounded_read)
    monkeypatch.setattr(type(snapshot), "read_bytes", no_database_read_bytes)
    receipt = ledger.snapshot(snapshot)
    assert receipt["bytes"] > 2 * 1024**2
    ledger.close()
    path = tmp_path / "accounting" / "forecasts.sqlite3"
    with path.open("r+b") as stream:
        stream.seek(100)
        stream.write(b"broken")
    damaged, _ = stream_file(path, maximum_bytes=8 * 1024**2)
    restore_forecast_snapshot(ledger.directory, snapshot, receipt, damaged_sha256=damaged)
    restored, size = stream_file(path, maximum_bytes=8 * 1024**2)
    assert (restored, size) == (receipt["sha256"], receipt["bytes"])
    assert len(reads) > 100
    assert max(reads) == CHUNK_BYTES
    assert (
        stream_file(path.parent / ("damaged-" + damaged + ".sqlite3"), maximum_bytes=8 * 1024**2)[0]
        == damaged
    )


@pytest.mark.parametrize("damage", ["missing", "torn", "empty"])
def test_snapshot_repairs_health_even_when_database_already_matches(tmp_path, damage):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    start(ledger)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    health = ledger.health_path
    ledger.close()
    shutil.copyfile(snapshot, root / "forecasts.sqlite3")
    checksum = None
    if damage == "missing":
        health.unlink()
    else:
        raw = b"torn" if damage == "torn" else b""
        health.write_bytes(raw)
        checksum = hashlib.sha256(raw).hexdigest()
        with pytest.raises(ValueError, match="pinned damaged marker"):
            restore_forecast_snapshot(root, snapshot, receipt, damaged_sha256=receipt["sha256"])
        assert health.read_bytes() == raw
    repaired = restore_forecast_snapshot(
        root,
        snapshot,
        receipt,
        damaged_sha256=receipt["sha256"],
        damaged_health_sha256=checksum,
    )
    assert repaired["health_repaired"] is True
    ledger = ForecastLedger(root)
    assert ledger.status("scope")["accounting_coverage_complete"] is False
    assert ledger.status("scope")["calibration_eligible"] is False
    gap_count = ledger.status("scope")["accounting_gap_count"]
    ledger.close()
    if checksum:
        assert health.with_name(health.name + ".damaged-" + checksum).read_bytes() == raw
    assert (
        restore_forecast_snapshot(root, snapshot, receipt, damaged_sha256=receipt["sha256"])[
            "status"
        ]
        == "already_restored"
    )
    ledger = ForecastLedger(root)
    assert ledger.status("scope")["accounting_gap_count"] == gap_count
    ledger.close()


def test_oversized_event_leaves_durable_coverage_gap(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    start(ledger)
    with pytest.raises(ForecastCapacityRequired, match="event exceeds"):
        ledger.append("large", "scope", "diagnostic", {"payload": "x" * (16 * 1024)})
    ledger.close()
    ledger = ForecastLedger(root)
    result = ledger.status("scope")
    assert result["accounting_coverage_complete"] is False
    assert result["accounting_first_gap"]["reason"] == "event_encoding_capacity_exhausted"
    ledger.close()


@pytest.mark.parametrize("already_matches", [False, True])
def test_pinned_initialization_repair_preserves_damage_and_repeats(tmp_path, already_matches):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    start(ledger)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    marker = ledger.marker
    ledger.close()
    if already_matches:
        shutil.copyfile(snapshot, root / "forecasts.sqlite3")
    prior, _ = stream_file(root / "forecasts.sqlite3", maximum_bytes=1024**2)
    raw = b"umi-forecast-acc"
    marker.write_bytes(raw)
    checksum = hashlib.sha256(raw).hexdigest()
    with pytest.raises(ValueError, match="pinned damaged marker"):
        restore_forecast_snapshot(root, snapshot, receipt, damaged_sha256=prior)
    assert marker.read_bytes() == raw
    repaired = restore_forecast_snapshot(
        root,
        snapshot,
        receipt,
        damaged_sha256=prior,
        damaged_initialized_sha256=checksum,
    )
    assert repaired["initialized_repaired"] is True
    assert marker.read_bytes() == b"umi-forecast-accounting/2\n"
    assert marker.with_name(marker.name + ".damaged-" + checksum).read_bytes() == raw
    ledger = ForecastLedger(root)
    assert ledger.status("scope")["accounting_coverage_complete"] is False
    ledger.close()
    assert (
        restore_forecast_snapshot(
            root, snapshot, receipt, damaged_sha256=prior, damaged_initialized_sha256=checksum
        )["status"]
        == "already_restored"
    )


@pytest.mark.parametrize("obstruction", ["linked_marker", "linked_copy", "conflicting_copy"])
def test_initialization_repair_refuses_links_and_preservation_conflicts(tmp_path, obstruction):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    start(ledger)
    snapshot = tmp_path / "retained.sqlite3"
    receipt = ledger.snapshot(snapshot)
    marker = ledger.marker
    ledger.close()
    prior, _ = stream_file(root / "forecasts.sqlite3", maximum_bytes=1024**2)
    raw = b"umi-forecast-acc"
    checksum = hashlib.sha256(raw).hexdigest()
    marker.write_bytes(raw)
    copy = marker.with_name(marker.name + ".damaged-" + checksum)
    if obstruction == "linked_marker":
        marker.unlink()
        marker.symlink_to(snapshot)
    elif obstruction == "linked_copy":
        copy.symlink_to(snapshot)
    else:
        copy.write_bytes(b"other retained evidence")
    with pytest.raises(ValueError, match=r"bounded and regular|preservation identity"):
        restore_forecast_snapshot(
            root,
            snapshot,
            receipt,
            damaged_sha256=prior,
            damaged_initialized_sha256=checksum,
        )
    assert stream_file(root / "forecasts.sqlite3", maximum_bytes=1024**2)[0] == prior


def test_legacy_marker_migration_keeps_events_and_marks_unknown_coverage(tmp_path):
    root = tmp_path / "accounting"
    ledger = ForecastLedger(root)
    start(ledger)
    retained, head = ledger.records("scope"), ledger.head
    ledger.close()
    ledger.marker.write_bytes(b"umi-forecast-accounting/1\n")
    ledger.health_path.unlink()
    for _ in range(2):
        ledger = ForecastLedger(root)
        assert ledger.head == head
        assert ledger.records("scope") == retained
        result = ledger.status("scope")
        assert result["accounting_coverage_complete"] is False
        assert result["accounting_gap_count"] == 1
        assert result["accounting_last_gap"]["reason"] == "legacy_capacity_history_unknown"
        assert ledger.marker.read_bytes() == b"umi-forecast-accounting/2\n"
        ledger.close()
