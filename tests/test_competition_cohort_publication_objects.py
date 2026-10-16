"""Native journal export identity, historical bytes, repair and owned cancellation."""

import asyncio
import json
from threading import Event

import pytest

from umi import competition_cohort_publication_objects as module
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_publication_objects import PublicationObjects
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
