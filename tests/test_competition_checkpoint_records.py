from __future__ import annotations

import hashlib
import sqlite3

import pytest

import umi.competition_store as stores
from umi.competition_store import CompetitionStore
from umi.competition_submission_checkpoint import SubmissionCheckpointError
from umi.protocol import canonical_json_bytes

from .test_competition_checkpoint_successor import _checkpointed_open_scenario
from .test_open_competition import policy as policy

_RECORD_QUERY = (
    "SELECT digest, hotkey, track, sequence, accepted_block, expires_block, "
    "body, receipt, writer_generation FROM submissions ORDER BY digest"
)


@pytest.fixture
def records(tmp_path):
    connection = sqlite3.connect(tmp_path / "checkpoint-records.sqlite3")
    connection.execute(
        "CREATE TABLE submissions (digest TEXT PRIMARY KEY, hotkey TEXT, track TEXT, "
        "sequence INTEGER, accepted_block INTEGER, expires_block INTEGER, body BLOB, "
        "receipt BLOB, writer_generation INTEGER)"
    )
    connection.executemany(
        "INSERT INTO submissions VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                f"{index:064x}",
                f"hotkey-{index}",
                "model" if index == 2 else "endpoint",
                index,
                100 + index,
                900 + index,
                (f"body-{index}".encode() + b"\x00\xff") * 256,
                f'{{"receipt":{index}}}'.encode(),
                2,
            )
            for index in (3, 1, 2)
        ],
    )
    connection.commit()
    try:
        yield connection
    finally:
        connection.close()


def legacy_records(connection):
    """Frozen pre-streaming field mapping and ordering, using real SQLite rows."""
    rows = connection.execute(_RECORD_QUERY).fetchall()
    submissions, commitments = [], []
    for row in rows:
        submissions.append(row[0])
        record = {
            "schema": "umi-competition-admission-record-commitment/1",
            "submission_sha256": row[0],
            "hotkey": row[1],
            "track": row[2],
            "sequence": row[3],
            "accepted_block": row[4],
            "expires_block": row[5],
            "body_sha256": hashlib.sha256(row[6]).hexdigest(),
            "receipt_sha256": hashlib.sha256(row[7]).hexdigest(),
            "writer_generation": row[8],
        }
        commitments.append(hashlib.sha256(canonical_json_bytes(record)).hexdigest())
    return tuple(submissions), tuple(commitments)


class TrackedCursor:
    def __init__(self, cursor, *, fail_on_second=False):
        self.cursor = cursor
        self.read = 0
        self.closed = False
        self.fail_on_second = fail_on_second

    def fetchall(self):
        pytest.fail("checkpoint hashing must not materialize all retained records")

    def __iter__(self):
        return self

    def __next__(self):
        if self.fail_on_second and self.read == 1:
            raise sqlite3.OperationalError("injected row read failure")
        row = next(self.cursor)
        self.read += 1
        return row

    def close(self):
        self.closed = True
        self.cursor.close()


class TrackedConnection:
    def __init__(self, connection, *, fail_on_second=False):
        self.connection = connection
        self.fail_on_second = fail_on_second
        self.cursors = []

    def execute(self, sql):
        assert sql == _RECORD_QUERY
        assert self.connection.in_transaction
        cursor = TrackedCursor(self.connection.execute(sql), fail_on_second=self.fail_on_second)
        self.cursors.append(cursor)
        return cursor


@pytest.mark.parametrize("empty", [False, True])
def test_checkpoint_records_stream_exact_legacy_output(records, monkeypatch, empty):
    if empty:
        records.execute("DELETE FROM submissions")
        records.commit()
    expected = legacy_records(records)
    tracked = TrackedConnection(records)
    hashed = []

    def encode_record(record):
        assert tracked.cursors[0].read == len(hashed) + 1
        hashed.append(record["submission_sha256"])
        return canonical_json_bytes(record)

    records.execute("BEGIN")
    with monkeypatch.context() as patch:
        patch.setattr(stores, "canonical_json_bytes", encode_record)
        result = CompetitionStore._submission_checkpoint_records(tracked)
    assert result == expected
    assert result[0] == tuple(sorted(result[0])) == tuple(hashed)
    assert len(tracked.cursors) == 1 and tracked.cursors[0].closed
    assert records.in_transaction
    records.rollback()


@pytest.mark.parametrize("failure", ["hash", "cursor"])
def test_checkpoint_records_close_cursor_on_failure(records, monkeypatch, failure):
    tracked = TrackedConnection(records, fail_on_second=failure == "cursor")
    expected_error = ValueError("injected record hashing failure")

    def fail_hash(_record):
        raise expected_error

    records.execute("BEGIN")
    with monkeypatch.context() as patch:
        if failure == "hash":
            patch.setattr(stores, "canonical_json_bytes", fail_hash)
        error_type = ValueError if failure == "hash" else sqlite3.OperationalError
        with pytest.raises(error_type) as caught:
            CompetitionStore._submission_checkpoint_records(tracked)
    if failure == "hash":
        assert caught.value is expected_error
    assert len(tracked.cursors) == 1 and tracked.cursors[0].closed
    assert records.in_transaction
    assert records.execute("SELECT COUNT(*) FROM submissions").fetchone() == (3,)
    records.rollback()


@pytest.mark.parametrize(
    ("column", "replacement"),
    [
        ("hotkey", "changed hotkey"),
        ("track", "model"),
        ("sequence", 99),
        ("accepted_block", 999),
        ("expires_block", 9999),
        ("body", b"changed body"),
        ("receipt", b"changed receipt"),
        ("writer_generation", 9),
    ],
)
def test_checkpoint_records_preserve_each_committed_field(records, column, replacement):
    before = legacy_records(records)
    records.execute(
        f"UPDATE submissions SET {column} = ? WHERE digest = ?", (replacement, f"{1:064x}")
    )
    result = CompetitionStore._submission_checkpoint_records(records)
    assert result == legacy_records(records)
    assert result[0] == before[0]
    assert result[1][0] != before[1][0]
    assert result[1][1:] == before[1][1:]


@pytest.mark.parametrize(
    ("column", "replacement"),
    [("body", b"{}"), ("receipt", b"{}"), ("hotkey", "00" * 32)],
)
def test_streamed_checkpoint_still_rejects_retained_mutations(
    policy, tmp_path, column, replacement
):
    scenario, _launch, _checkpoint = _checkpointed_open_scenario(policy, tmp_path)
    store = scenario.store
    before = store._submission_checkpoint.path.read_bytes()
    with store._connection() as connection:
        submission_id = connection.execute(
            "SELECT digest FROM submissions ORDER BY digest LIMIT 1"
        ).fetchone()[0]
        connection.execute(
            f"UPDATE submissions SET {column} = ? WHERE digest = ?", (replacement, submission_id)
        )
    with pytest.raises(SubmissionCheckpointError, match="checkpoint is ahead of or differs"):
        store.retained_submission_head()
    assert store._submission_checkpoint.path.read_bytes() == before
