"""Imported reclamation reuses original receipt facts and survives interruption."""

import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi.competition_imported_proof_retirement import ImportedProofRetirement
from umi.competition_remote_proof_store import ProofArchiveR2Config, RemoteProofStore
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_proof_archive import RewardProofArchive

from .test_competition_remote_proof_store import EvidenceServer, config


def prepare(tmp_path, monkeypatch, *, count=3):
    server = EvidenceServer()
    exported = tmp_path / "exports"
    imported = tmp_path / "imports"
    raw = config(tmp_path).model_dump(mode="json", by_alias=True)
    raw.update(
        schema="umi-r2-proof-archive/2",
        legacy_read_through=True,
        imported_object_release_batch_files=16,
        archive_release_consumer_abi="umi-proof-read-release-lease/1",
    )
    producer = RemoteProofStore(
        exported / ".remote-state", ProofArchiveR2Config.model_validate(raw), client=server.client()
    )
    raw.update(read_only=True, imported_object_release_batch_files=0)
    observer = RemoteProofStore(
        imported / ".remote-state",
        ProofArchiveR2Config.model_validate(raw),
        client=server.client(),
        receipt_source_directory=producer.journal.root,
    )
    source = RewardProofArchive(exported)
    local = RewardProofArchive(imported)
    references, paths = [], []
    for i in range(count):
        payload = ("proof-" + str(i)).encode() * 1024
        reference = producer.put_bytes(payload)
        sha = local._retain_bytes(payload)
        source._retain_bytes(payload)
        references.append(reference)
        paths.append(imported / "objects" / (sha + ".json"))
    reader = SimpleNamespace(
        archive=RewardProofArchive(imported, remote=observer, legacy_read_through=True),
        export_archive=RewardProofArchive(exported, remote=producer, legacy_read_through=True),
        checkpoints=SimpleNamespace(owner="owner"),
        config_sha256="a" * 64,
        hotkey="retained-hotkey",
        _shutdown_requested=lambda: False,
    )
    monkeypatch.setattr(
        "umi.competition_imported_proof_retirement._publication_clock_ns",
        lambda: time.time_ns() + 1_000_000_000,
    )
    server.calls.clear()
    return reader, server, producer, observer, references, paths


def finish(owner, *, maximum=16):
    for _ in range(40):
        report = owner.run(maximum)
        if report["state"] == "completed":
            return report
    raise AssertionError("bounded retirement did not finish")


def test_metadata_only_retirement_preserves_originals_and_restores_from_r2(tmp_path, monkeypatch):
    reader, server, producer, observer, references, paths = prepare(tmp_path, monkeypatch)
    original_index = producer.journal.path.read_bytes()
    original_objects = sorted((reader.export_archive.root / "objects").iterdir())
    allocated = sum(path.stat().st_blocks * 512 for path in paths)

    def prohibited(*args, **kwargs):
        raise AssertionError("retirement must not traverse/read native payloads")

    monkeypatch.setattr(RewardProofArchive, "_frame", prohibited)
    monkeypatch.setattr(RewardProofArchive, "_bytes", prohibited)
    original_read = Path.read_bytes

    def no_payload_reads(path):
        if path.parent.name == "objects":
            prohibited()
        return original_read(path)

    monkeypatch.setattr(Path, "read_bytes", no_payload_reads)
    owner = ImportedProofRetirement(reader)
    report = finish(owner, maximum=2)
    assert report["removed_files"] == 3
    assert report["reclaimed_allocated_bytes"] == allocated
    assert report["percent"] == 100 and report["eta_seconds"] == 0
    assert all(not path.exists() for path in paths)
    assert all(path.exists() for path in original_objects)
    assert producer.journal.path.read_bytes() == original_index
    assert server.calls == []
    restarted = ImportedProofRetirement(reader)
    assert finish(restarted)["removed_files"] == 3
    assert server.calls == []
    assert observer.read_bytes(references[0], maximum=16384) == b"proof-0" * 1024


def test_active_reader_blocks_release_and_restart_drains_before_new_page(tmp_path, monkeypatch):
    reader, server, _, observer, _, paths = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)
    with reader.archive.read_release_lease():
        report = owner.run(16)
        assert report["local_release_state"] == "waiting_for_active_archive_reader"
        assert report["stalled_or_retrying"] and report["eta_seconds"] is None
        assert all(path.exists() for path in paths)
    restarted = ImportedProofRetirement(reader)

    def no_new_claims(*args, **kwargs):
        raise AssertionError("pending batch must drain before another receipt page")

    monkeypatch.setattr(observer, "completion_page", no_new_claims)
    report = restarted.run(16)
    assert report["removed_files"] == 3
    assert server.calls == []


def test_crash_after_unlink_recovers_intent_without_recounting_or_rereading(tmp_path, monkeypatch):
    reader, server, _, observer, _, paths = prepare(tmp_path, monkeypatch, count=1)
    owner = ImportedProofRetirement(reader)
    directory = paths[0].parent.stat().st_ino
    fsync = os.fsync
    failed = False

    def interrupt_once(fd):
        nonlocal failed
        if not failed and os.fstat(fd).st_ino == directory:
            failed = True
            raise OSError("simulated directory fsync interruption")
        fsync(fd)

    monkeypatch.setattr(os, "fsync", interrupt_once)
    with pytest.raises(OSError, match="simulated directory"):
        owner.run(16)
    assert not paths[0].exists()
    assert owner._report("retrying")["removed_files"] == 0
    restarted = ImportedProofRetirement(reader)
    monkeypatch.setattr(
        observer,
        "completion_page",
        lambda *args, **kwargs: pytest.fail("restart must drain retained intent first"),
    )
    report = restarted.run(16)
    assert report["removed_files"] == 1
    assert report["reclaimed_allocated_bytes"] > 0
    assert server.calls == []


def test_finish_capacity_is_reserved_before_any_unlink(tmp_path, monkeypatch):
    reader, _, _, _, _, paths = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)

    def no_finish_capacity(*args, **kwargs):
        raise ValueError("round journal capacity exhausted")

    monkeypatch.setattr(owner, "_admit_finish_slots", no_finish_capacity)
    with pytest.raises(ValueError, match="capacity exhausted"):
        owner.run(16)
    assert all(path.exists() for path in paths)
    assert owner._state()[1]["pending"] is None
    assert owner._state()[1]["cursor"] is None


def test_metadata_allowance_refuses_before_unlink_and_slots_stay_preallocated(
    tmp_path, monkeypatch
):
    reader, _, _, _, _, paths = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)
    with owner.journal.read_transaction() as db:
        _, used, _ = owner.journal._record_capacity(db)
    original_maximum = owner.journal.maximum_bytes
    owner.journal.maximum_bytes = used + 100
    with pytest.raises(ValueError, match="capacity exhausted"):
        owner.run(16)
    assert all(path.exists() for path in paths)
    owner.journal.maximum_bytes = original_maximum
    finish(owner)
    with owner.journal.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (0,)
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE 'record_reservation%'"
        ).fetchone()
        assert db.execute(
            "SELECT COUNT(*),SUM(intent),SUM(done) FROM imported_object_retirement_files"
        ).fetchone() == (0, None, None)
        assert db.execute(
            "SELECT kind,COUNT(*) FROM records GROUP BY kind ORDER BY kind"
        ).fetchall() == [
            ("imported_object_retirement_owner", 1),
            ("imported_object_retirement_state", 1),
        ]
        _, used, _ = owner.journal._record_capacity(db)
        assert used <= original_maximum
    assert owner.journal.path.stat().st_size <= owner.journal.physical_budget.maximum_database_bytes


def test_interrupted_compaction_reuses_completed_slots_without_scanning_or_unlinking(
    tmp_path, monkeypatch
):
    reader, server, _, observer, _, paths = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)
    compact = owner._compact

    def interrupt_after_compaction(*args):
        compact(*args)
        raise OSError("simulated compaction commit interruption")

    monkeypatch.setattr(owner, "_compact", interrupt_after_compaction)
    with pytest.raises(OSError, match="compaction commit interruption"):
        owner.run(16)
    assert all(not path.exists() for path in paths)
    assert owner._state()[1]["pending"] is not None
    assert owner._report("retrying")["removed_files"] == 3
    restarted = ImportedProofRetirement(reader)
    monkeypatch.setattr(
        observer,
        "completion_page",
        lambda *args, **kwargs: pytest.fail("terminal batch must drain before new metadata"),
    )
    monkeypatch.setattr(
        "umi.competition_imported_proof_retirement.unlink_completed_archive_file",
        lambda *args, **kwargs: pytest.fail("completed unlink must not be repeated"),
    )
    report = restarted.run(16)
    assert report["removed_files"] == 3 and report["state"] == "completed"
    assert restarted._state()[1]["pending"] is None
    assert server.calls == []


def test_imported_root_replacement_holds_before_opening_replacement_journal(tmp_path, monkeypatch):
    reader, _, _, _, _, _ = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)
    reader.archive.root.rename(tmp_path / "original-imports")
    reader.archive.root.mkdir(mode=0o700)
    monkeypatch.setattr(
        owner.journal,
        "locked",
        lambda: pytest.fail("replaced archive must be refused before opening its journal lock"),
    )
    with pytest.raises(HistoryCheckpointRepairRequired, match="archive root changed"):
        owner.run(16)
    assert list(reader.archive.root.iterdir()) == []


def test_missing_enrolled_retirement_journal_is_not_recreated_or_rescanned(tmp_path, monkeypatch):
    reader, server, _, observer, _, _ = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)
    assert finish(owner)["removed_files"] == 3
    root = owner.journal.root
    retained = tmp_path / "retained-retirement"
    root.rename(retained)
    monkeypatch.setattr(
        observer,
        "completion_page",
        lambda *args, **kwargs: pytest.fail("missing progress requires repair, not a new scan"),
    )
    with pytest.raises(HistoryCheckpointRepairRequired, match="journal is missing"):
        ImportedProofRetirement(reader)
    assert not root.exists()
    retained.rename(root)
    restarted = ImportedProofRetirement(reader)
    assert restarted._report("idle")["removed_files"] == 3
    assert server.calls == []


def test_replaced_enrolled_database_inode_requires_explicit_repair(tmp_path, monkeypatch):
    reader, _, _, _, _, paths = prepare(tmp_path, monkeypatch)
    owner = ImportedProofRetirement(reader)
    replacement = owner.journal.root / "replacement.sqlite3"
    replacement.write_bytes(owner.journal.path.read_bytes())
    replacement.chmod(0o600)
    replacement.replace(owner.journal.path)
    with pytest.raises(HistoryCheckpointRepairRequired, match="owner changed"):
        ImportedProofRetirement(reader)
    assert all(path.exists() for path in paths)


def test_interrupted_pristine_enrollment_resumes_without_reclaiming_early(tmp_path, monkeypatch):
    reader, _, _, observer, _, paths = prepare(tmp_path, monkeypatch)
    put_many = observer.journal.put_many

    def interrupted(*args, **kwargs):
        raise OSError("simulated initial enrollment interruption")

    monkeypatch.setattr(observer.journal, "put_many", interrupted)
    with pytest.raises(OSError, match="initial enrollment interruption"):
        ImportedProofRetirement(reader)
    assert all(path.exists() for path in paths)
    monkeypatch.setattr(observer.journal, "put_many", put_many)
    restarted = ImportedProofRetirement(reader)
    assert finish(restarted)["removed_files"] == 3


@pytest.mark.parametrize("held_owner", ["producer", "consumer"])
def test_damage_observed_after_admission_prevents_unlink(tmp_path, monkeypatch, held_owner):
    reader, server, producer, observer, references, paths = prepare(tmp_path, monkeypatch, count=1)
    owner = ImportedProofRetirement(reader)
    with reader.archive.read_release_lease():
        owner.run(16)
    reference = observer.validate_reference(references[0])
    (producer if held_owner == "producer" else observer)._hold(reference)
    with pytest.raises(ValueError, match="repair"):
        owner.run(16)
    assert paths[0].exists()
    assert server.calls == []


def test_changed_local_generation_and_missing_unclaimed_file_hold(tmp_path, monkeypatch):
    reader, _, _, _, _, paths = prepare(tmp_path, monkeypatch, count=1)
    owner = ImportedProofRetirement(reader)
    with reader.archive.read_release_lease():
        owner.run(16)
    paths[0].unlink()
    with pytest.raises(HistoryCheckpointRepairRequired, match="without unlink intent"):
        owner.run(16)
    assert owner._report("repair_required")["removed_files"] == 0


def test_wrong_selected_original_owner_refuses_before_release(tmp_path, monkeypatch):
    reader, _, _, observer, _, paths = prepare(tmp_path, monkeypatch)
    observer.receipt_source = None
    with pytest.raises(HistoryCheckpointRepairRequired, match="original receipt owner"):
        ImportedProofRetirement(reader)
    assert all(path.exists() for path in paths)


@pytest.mark.asyncio
async def test_maintenance_runs_even_when_history_advancement_fails():
    events = []

    async def monitor(reader, stop):
        await stop.wait()

    async def maintain():
        events.append("retirement")

    async def advance(*args, **kwargs):
        events.append("advance")
        raise OSError("RPC unavailable")

    reader = SimpleNamespace(
        _validate_advance=lambda *args, **kwargs: None,
        _next=1,
        _repair_reason=None,
        remote_store=None,
        _shutdown_requested=lambda: False,
        _maintain_imported_retirement=maintain,
        _advance=advance,
        progress=SimpleNamespace(
            start=lambda *args, **kwargs: None,
            report=lambda *args, **kwargs: None,
            monitor=monitor,
            finish=lambda: None,
        ),
    )
    with pytest.raises(OSError, match="RPC unavailable"):
        await RewardControlHistoryReader._observed_advance(
            reader, object(), through_block=3, maximum_blocks=2
        )
    assert events == ["retirement", "advance"]
