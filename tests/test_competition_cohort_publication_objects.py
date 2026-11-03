"""Native journal export identity, historical bytes, repair and owned cancellation."""

import asyncio
import json
from contextlib import contextmanager
from threading import Event

import pytest

from umi import competition_cohort_publication_objects as module
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_publication_objects import PublicationObjects
from umi.competition_cohort_reward_package import ReplayObjectCollector
from umi.competition_cohort_settlement_delivery import SettlementEvidenceFiles
from umi.competition_round_journal import RoundJournal
from umi.competition_verification_reuse import VerificationSourceChanged
from umi.competition_work_progress import cancellable_work
from umi.concurrency import run_owned_thread
from umi.protocol import canonical_json_bytes


def setup_objects(tmp_path):
    journal = RoundJournal(tmp_path / "journal", {"native_owner": "publication"})
    source = JournalEndpointObjects(journal)
    files = SettlementEvidenceFiles(tmp_path / "exports")
    keys = [source.put({"value": value}) for value in ("first", "second")]

    def reopen():
        return PublicationObjects(source, files, tmp_path / "metadata")

    return source, files, keys, reopen


def test_historical_export_import_preserves_bytes_and_identity_then_restarts_without_reads(
    tmp_path, monkeypatch
):
    source, files, keys, reopen = setup_objects(tmp_path)
    for key in keys:
        files.publish(key, source)
    before = {key: (files._path(key).read_bytes(), module._stamp(files._path(key))) for key in keys}
    first = reopen()
    identities = {key: first.verification_identity(key) for key in keys}
    assert all(
        before[key] == (files._path(key).read_bytes(), module._stamp(files._path(key)))
        for key in keys
    )

    def no_reads(*args):
        pytest.fail("unchanged exported payload was read")

    monkeypatch.setattr(JournalEndpointObjects, "__call__", no_reads)
    monkeypatch.setattr(SettlementEvidenceFiles, "__call__", no_reads)
    restarted = reopen()
    for key in keys:
        assert restarted.verification_identity(key) == identities[key]
        restarted.verification_replay(key)
        assert restarted.verification_size(key) > 0
        restarted.ensure(key, no_reads)


@pytest.mark.parametrize(
    "damage", ["output_missing", "output_corrupt", "metadata_missing", "metadata_corrupt"]
)
def test_repairs_only_affected_object_and_reports_progress(tmp_path, monkeypatch, caplog, damage):
    _source, files, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    for key in keys:
        objects.verification_replay(key)
    original = files._path(keys[0]).read_bytes()
    target = (
        files._path(keys[0])
        if damage.startswith("output")
        else objects.directory / (keys[0] + ".json")
    )
    if damage.endswith("missing"):
        target.unlink()
    else:
        target.chmod(0o600)
        target.write_bytes(b"corrupt")
    reads = []
    native = JournalEndpointObjects.__call__

    def read(self, key):
        reads.append(key)
        return native(self, key)

    monkeypatch.setattr(JournalEndpointObjects, "__call__", read)
    caplog.set_level("INFO", logger="umi.competition.progress")
    restarted = reopen()
    for key in keys:
        restarted.verification_replay(key)
    assert reads == [keys[0]]
    assert files._path(keys[0]).read_bytes() == original
    events = [json.loads(record.message) for record in caplog.records]
    assert any(event.get("state") == "repair_required" for event in events)
    completed = [event for event in events if event.get("state") == "completed"]
    assert any(event["stage"] == "publication_object_repair" for event in completed)
    assert all("elapsed_seconds" in event and "eta_basis" in event for event in completed)


def test_fresh_conflict_fence_cannot_borrow_export(tmp_path):
    source, _, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    objects.verification_replay(keys[0])
    with pytest.raises(ValueError):
        source.journal.put("endpoint_replay_object", keys[0], {"value": "changed"})
    with pytest.raises(VerificationSourceChanged, match="conflict"):
        reopen().verification_replay(keys[0])


def test_missing_original_cannot_borrow_retained_export(tmp_path):
    source, _, keys, reopen = setup_objects(tmp_path)
    reopen().verification_replay(keys[0])
    with source.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind=? AND id=?", ("endpoint_replay_object", keys[0]))
    with pytest.raises(VerificationSourceChanged, match="original is missing"):
        reopen().verification_replay(keys[0])
    with pytest.raises(VerificationSourceChanged, match="original is missing"):
        reopen().ensure(keys[0], lambda _: canonical_json_bytes({"value": "first"}))


def test_receipt_batch_reads_each_descriptor_once_and_preserves_collector_coverage(
    tmp_path, monkeypatch
):
    source, _files, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    for key in keys:
        objects.verification_replay(key)
    objects = reopen()
    reads, snapshots = [], []
    native_read = module.read_verification_metadata
    native_snapshot = source.journal.read_transaction

    def metadata(path):
        reads.append(path.stem)
        return native_read(path)

    @contextmanager
    def snapshot():
        snapshots.append(True)
        with native_snapshot() as db:
            yield db

    def no_payload(*args):
        pytest.fail("unchanged receipt batch read an evidence payload")

    monkeypatch.setattr(module, "read_verification_metadata", metadata)
    monkeypatch.setattr(source.journal, "read_transaction", snapshot)
    monkeypatch.setattr(JournalEndpointObjects, "__call__", no_payload)
    monkeypatch.setattr(SettlementEvidenceFiles, "__call__", no_payload)
    collector = ReplayObjectCollector(objects, 64 * 1024**2)
    for _ in range(2):
        reads.clear()
        snapshots.clear()
        with collector.verification_batch(keys):
            for key in keys:
                # Match the old null-source-identity receipt compatibility path:
                # identity, authenticated SHA, then complete collector replay.
                assert collector.verification_identity(key) is not None
                assert collector.verification_sha256(key) is not None
                collector.verification_replay(key)
                collector.verification_replay(key)
        assert reads == keys
        assert len(snapshots) == 2
        assert set(collector.values) == set(keys)
        assert collector.used == sum(objects.verification_size(key) for key in keys)


def test_receipt_batch_ignores_unrelated_journal_appends_and_conflicts(tmp_path, monkeypatch):
    source, _files, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    identity = objects.verification_identity(keys[0])
    native_read = module.read_verification_metadata
    reads = []

    def metadata(path):
        reads.append(path.stem)
        return native_read(path)

    monkeypatch.setattr(module, "read_verification_metadata", metadata)
    with objects.verification_batch(keys[:1]):
        assert objects.verification_identity(keys[0]) == identity
        source.put({"value": "unrelated new intake"})
        with pytest.raises(ValueError):
            source.journal.put("endpoint_replay_object", keys[1], {"value": "unrelated conflict"})
        objects.verification_replay(keys[0])
        assert objects.verification_identity(keys[0]) == identity
    assert reads == keys[:1]
    assert objects._local.batch is None


def test_receipt_batch_binds_metadata_stamp_to_the_authenticated_read(tmp_path, monkeypatch):
    _source, _files, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    objects.verification_replay(keys[0])
    native_read = objects._read_descriptor

    def replace_after_read(key, **kwargs):
        authenticated = native_read(key, **kwargs)
        path = objects.directory / (key + ".json")
        module._atomic(path, path.read_bytes())
        return authenticated

    monkeypatch.setattr(objects, "_read_descriptor", replace_after_read)
    with (
        pytest.raises(VerificationSourceChanged, match="changed during replay"),
        objects.verification_batch(keys[:1]),
    ):
        objects.verification_replay(keys[0])
    assert objects._local.batch is None


@pytest.mark.parametrize(
    "change", ["binding", "conflict", "original_missing", "export", "metadata"]
)
def test_receipt_batch_rejects_changes_before_returning_and_drops_its_cache(tmp_path, change):
    source, files, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    objects.verification_replay(keys[0])
    with pytest.raises(VerificationSourceChanged), objects.verification_batch(keys[:1]):
        objects.verification_replay(keys[0])
        if change == "binding":
            with source.journal.transaction() as db:
                db.execute("UPDATE binding SET body=?", (canonical_json_bytes({"changed": True}),))
        elif change == "conflict":
            with pytest.raises(ValueError):
                source.journal.put("endpoint_replay_object", keys[0], {"value": "changed"})
        elif change == "original_missing":
            with source.journal.transaction() as db:
                db.execute(
                    "DELETE FROM records WHERE kind=? AND id=?",
                    ("endpoint_replay_object", keys[0]),
                )
        else:
            target = (
                files._path(keys[0])
                if change == "export"
                else objects.directory / (keys[0] + ".json")
            )
            target.unlink()
    assert objects._local.batch is None
    if change in {"export", "metadata"}:
        objects.verification_replay(keys[0])
        assert files(keys[0]) == canonical_json_bytes({"value": "first"})


def test_unsafe_export_link_refuses_repair_without_touching_target(tmp_path):
    _source, files, keys, reopen = setup_objects(tmp_path)
    reopen().verification_replay(keys[0])
    unrelated = tmp_path / "unrelated"
    unrelated.write_bytes(b"preserve")
    files._path(keys[0]).unlink()
    files._path(keys[0]).symlink_to(unrelated)
    with pytest.raises(ValueError, match=r"private|link|ownership"):
        reopen().verification_replay(keys[0])
    assert unrelated.read_bytes() == b"preserve"
    assert files._path(keys[0]).is_symlink()


@pytest.mark.asyncio
async def test_cancel_drains_atomic_object_checkpoint_and_resume_skips_completed_original(
    tmp_path, monkeypatch
):
    _source, files, keys, reopen = setup_objects(tmp_path)
    objects = reopen()
    entered, release, cancel = Event(), Event(), Event()
    atomic = module._atomic

    def held_atomic(path, raw, **kwargs):
        if path == files._path(keys[0]):
            entered.set()
            assert release.wait(5)
        return atomic(path, raw, **kwargs)

    monkeypatch.setattr(module, "_atomic", held_atomic)
    with cancellable_work(cancel):
        task = asyncio.create_task(
            run_owned_thread(objects.verification_replay, keys[0], on_cancel=cancel.set)
        )
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert cancel.is_set()
    assert files(keys[0]) == canonical_json_bytes({"value": "first"})

    def no_reads(*args):
        pytest.fail("completed checkpoint was discarded after cancellation")

    monkeypatch.setattr(JournalEndpointObjects, "__call__", no_reads)
    reopen().verification_replay(keys[0])
