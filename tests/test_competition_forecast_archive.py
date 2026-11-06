"""Archive exact historical forecast rows without changing diagnostic outcomes."""

import hashlib
import zlib
from dataclasses import replace

import pytest

from umi import competition_forecast_archive as archive
from umi.competition_forecast import ForecastLedger
from umi.competition_forecast_io import encode_forecast_json
from umi.competition_forecast_summary import ForecastSummary


@pytest.fixture
def historical(tmp_path):
    ledger = ForecastLedger(tmp_path / "legacy")
    scope = "a" * 64
    common = dict(observed_unix_ms=1000, note="Unicode \u00e9 and fractional 1.5", value=1.5)
    ledger.append("scope:start", scope, "scope_started", common)
    ledger.append("attempt:start", scope, "attempt_started", common)
    ledger.append(
        "attempt:forecast:1",
        scope,
        "forecast",
        dict(common, finish_unix_ms=2000, eta_seconds=1.0, elapsed_seconds=0.0),
    )
    ledger.append(
        "attempt:terminal",
        scope,
        "attempt_terminal",
        dict(common, observed_unix_ms=3000, state="completed"),
    )
    rows = tuple(
        ledger.db.execute(
            "SELECT sequence,identity,scope,body,previous,digest FROM events ORDER BY sequence"
        )
    )
    expected = ledger.status(scope, observed_unix_ms=4000)
    records = ledger.records(scope)
    ledger.close()
    return archive.ForecastSegment("b" * 64, 1, "0" * 64, rows), expected, records


def restore(raw, segment):
    return archive.decode_segment(
        raw,
        ledger_sha256=segment.ledger_sha256,
        first_sequence=segment.first_sequence,
        previous_sha256=segment.previous_sha256,
        last_sha256=segment.last_sha256,
    )


def test_original_chain_bytes_and_summary_survive_archive_segments(historical):
    segment, expected, records = historical
    first = replace(segment, rows=segment.rows[:2])
    second = replace(
        segment, first_sequence=3, previous_sha256=first.last_sha256, rows=segment.rows[2:]
    )
    restored = tuple(
        row for part in (first, second) for row in restore(archive.encode_segment(part), part).rows
    )
    assert restored == segment.rows
    summary = ForecastSummary()
    for row, event in zip(restored, records, strict=True):
        assert row[3] == encode_forecast_json(event)
        summary.accept(event, sequence=row[0])
    actual = summary.status(segment.rows[0][2], 4000)
    assert actual["completion_examples"] == 1
    assert actual["first_forecast_error_seconds"] == 1
    assert actual == {key: expected[key] for key in actual}


@pytest.mark.parametrize(
    "field", ["ledger_sha256", "first_sequence", "previous_sha256", "last_sha256"]
)
def test_archive_refuses_different_owner_range_or_endpoint(historical, field):
    segment, _, _ = historical
    selected = {
        "ledger_sha256": segment.ledger_sha256,
        "first_sequence": segment.first_sequence,
        "previous_sha256": segment.previous_sha256,
        "last_sha256": segment.last_sha256,
    }
    selected[field] = 2 if field == "first_sequence" else "c" * 64
    with pytest.raises(ValueError):
        archive.decode_segment(archive.encode_segment(segment), **selected)


@pytest.mark.parametrize("change", ["body", "parent", "sequence", "identity", "scope", "duplicate"])
def test_archive_refuses_changed_original_rows(historical, change):
    segment, _, _ = historical
    rows = list(segment.rows)
    row = list(rows[1])
    positions = {"body": 3, "parent": 4, "sequence": 0, "identity": 1, "scope": 2, "duplicate": 1}
    row[positions[change]] = {
        "body": b"{}",
        "parent": "c" * 64,
        "sequence": 3,
        "identity": "wrong",
        "scope": "wrong",
        "duplicate": rows[0][1],
    }[change]
    rows[1] = tuple(row)
    with pytest.raises(ValueError):
        archive.encode_segment(replace(segment, rows=tuple(rows)))


@pytest.mark.parametrize("damage", ["truncate", "tail", "second_stream", "oversized"])
def test_archive_decompression_is_bounded_and_refuses_extra_streams(historical, damage):
    segment, _, _ = historical
    raw = archive.encode_segment(segment)
    if damage == "truncate":
        raw = raw[:-1]
    elif damage == "tail":
        raw += b"tail"
    elif damage == "second_stream":
        raw += zlib.compress(b"another stream")
    else:
        raw = archive._MAGIC + zlib.compress(b"x" * (archive.MAX_SEGMENT_BYTES + 1))
    with pytest.raises(ValueError):
        restore(raw, segment)


def test_archive_never_adopts_payment_authority(historical):
    segment, _, records = historical
    event = dict(records[0], certification_authority=True)
    body = encode_forecast_json(event)
    original = segment.rows[0]
    row = (
        *original[:3],
        body,
        original[4],
        hashlib.sha256(original[4].encode() + body).hexdigest(),
    )
    with pytest.raises(ValueError):
        archive.encode_segment(replace(segment, rows=(row,)))
