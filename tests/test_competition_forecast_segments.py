"""Publication interruption and bounded local release preserve original history."""

import hashlib
from dataclasses import replace

import pytest

from umi import competition_forecast_segments as storage

from .test_competition_forecast_archive import historical as historical


class Remote:
    def __init__(self):
        self.objects, self.receipts = {}, {}
        self.uploads = self.reads = 0

    def reference_for_path(self, path):
        return self.receipts.get(path)

    def put_bytes(self, raw, *, path):
        self.uploads += 1
        receipt = dict(
            key=path, content_sha256=hashlib.sha256(raw).hexdigest(), size_bytes=len(raw)
        )
        if path in self.receipts:
            assert self.receipts[path] == receipt
        self.objects[path], self.receipts[path] = raw, receipt
        return receipt

    def validate_reference(self, receipt):
        if self.receipts.get(receipt["key"]) != receipt:
            raise ValueError("damaged remote completion requires repair")

    def read_bytes(self, receipt, *, maximum):
        self.validate_reference(receipt)
        self.reads += 1
        raw = self.objects[receipt["key"]]
        assert len(raw) <= maximum
        return raw


def test_publication_release_restart_and_explicit_history_read(historical, tmp_path, monkeypatch):
    segment, _, _ = historical
    remote = Remote()
    root = tmp_path / "segments"
    with storage.ForecastSegments(root, segment.ledger_sha256, remote) as store:
        metadata = store.stage(segment)
        assert store.index.archive_body(1)
        with pytest.raises(ValueError, match="no completed durable"):
            store.release(1)
        store.publish(1)
        store.release(1)
        assert store.index.archive_state(1)[2]

    def no_payload(*args, **kwargs):
        raise AssertionError("completed publication must not read, hash or encode payload again")

    with storage.ForecastSegments(root, segment.ledger_sha256, remote) as store:
        monkeypatch.setattr(store.index, "archive_body", no_payload)
        assert store.stage(segment) == metadata
        store.publish(1)
        store.release(1)
        assert remote.uploads == 1
        assert remote.reads == 0
        assert store.read(1) == segment
        assert remote.reads == 1


def test_transport_commit_before_owner_commit_reuses_receipt(historical, tmp_path, monkeypatch):
    segment, _, _ = historical
    remote = Remote()
    root = tmp_path / "segments"
    with storage.ForecastSegments(root, segment.ledger_sha256, remote) as store:
        store.stage(segment)

        def interrupted(first_sequence, receipt):
            raise OSError("interrupted owner commit")

        monkeypatch.setattr(store.index, "retain_archive_receipt", interrupted)
        with pytest.raises(OSError, match="interrupted owner"):
            store.publish(1)

    with storage.ForecastSegments(root, segment.ledger_sha256, remote) as store:

        def no_read(*args, **kwargs):
            raise AssertionError("do not reread a completed remote upload")

        monkeypatch.setattr(store.index, "archive_body", no_read)
        store.publish(1)
        store.release(1)
        assert remote.uploads == 1
        assert store.index.archive_state(1)[2]


def test_only_one_unreleased_segment_and_contiguous_chain(historical, tmp_path):
    segment, _, _ = historical
    first = replace(segment, rows=segment.rows[:2])
    second = replace(
        segment, first_sequence=3, previous_sha256=first.last_sha256, rows=segment.rows[2:]
    )
    with storage.ForecastSegments(tmp_path / "segments", segment.ledger_sha256, Remote()) as store:
        store.stage(first)
        with pytest.raises(ValueError, match="pending forecast"):
            store.stage(second)
        store.publish(1)
        store.release(1)
        with pytest.raises(ValueError, match="contiguous"):
            store.stage(replace(second, first_sequence=4))
        store.stage(second)
        assert store.index.db.execute(
            "SELECT COUNT(*) FROM archives WHERE body IS NOT NULL"
        ).fetchone() == (1,)


def test_changed_staging_file_refuses_publication(historical, tmp_path):
    segment, _, _ = historical
    with storage.ForecastSegments(tmp_path / "segments", segment.ledger_sha256, Remote()) as store:
        store.stage(segment)
        with store.index.db:
            store.index.db.execute("UPDATE archives SET body=?", (b"damaged",))
        with pytest.raises(ValueError, match="differs"):
            store.publish(1)
        assert store.index.archive_state(1)[1] is None


def test_store_requires_exclusive_owner(historical, tmp_path):
    segment, _, _ = historical
    root = tmp_path / "segments"
    with (
        storage.ForecastSegments(root, segment.ledger_sha256, Remote()),
        pytest.raises(BlockingIOError),
    ):
        storage.ForecastSegments(root, segment.ledger_sha256, Remote())
