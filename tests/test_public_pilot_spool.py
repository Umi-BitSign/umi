from __future__ import annotations

import fcntl
import hashlib
import os
import stat
from pathlib import Path

import pytest

import umi.public_pilot_spool as spool_module
from umi.public_pilot_archive import create_evidence_archive
from umi.public_pilot_coordinator import replay_public_endpoint_pilot
from umi.public_pilot_spool import (
    consume_public_pilot_spool,
    enqueue_publication_archive,
    load_publication_receipt,
)

from .factories import dev_wallet
from .test_public_pilot_publication import _public_bundle


def test_spool_consumer_holds_an_exclusive_process_lock(tmp_path: Path) -> None:
    lock_path = tmp_path / "consumer.lock"

    with spool_module._exclusive_spool_lock(lock_path):
        contender = os.open(lock_path, os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(contender, fcntl.LOCK_EX | fcntl.LOCK_NB)
        finally:
            os.close(contender)


def test_spool_producer_enqueues_one_single_link_file_and_rejects_symlink_dir(
    tmp_path: Path,
) -> None:
    incoming = tmp_path / "incoming"
    incoming.mkdir(mode=0o700)
    archive = tmp_path / "archive.tar.gz"
    archive.write_bytes(b"archive bytes")

    archive_sha256, destination = enqueue_publication_archive(archive, incoming)

    assert archive_sha256 == hashlib.sha256(b"archive bytes").hexdigest()
    metadata = destination.stat()
    assert stat.S_IMODE(metadata.st_mode) == 0o640
    assert metadata.st_nlink == 1

    retained_link = tmp_path / "retained-link"
    os.link(destination, retained_link)
    with pytest.raises(ValueError, match="unsafe ownership, mode, or links"):
        enqueue_publication_archive(archive, incoming)
    retained_link.unlink()

    linked = tmp_path / "incoming-link"
    linked.symlink_to(incoming, target_is_directory=True)
    with pytest.raises(ValueError, match="unsafe"):
        enqueue_publication_archive(archive, linked)


def test_spool_rejects_overlapping_role_directories(tmp_path: Path) -> None:
    directories = {
        name: tmp_path / name
        for name in (
            "incoming",
            "processing",
            "processed",
            "quarantine",
            "receipts",
            "work",
            "published",
        )
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)

    with pytest.raises(ValueError, match="must not overlap"):
        consume_public_pilot_spool(
            incoming_dir=directories["incoming"],
            processing_dir=directories["processing"],
            processed_dir=directories["processing"],
            quarantine_dir=directories["quarantine"],
            receipts_dir=directories["receipts"],
            work_root=directories["work"],
            publication_root=directories["published"],
            config_path=tmp_path / "observer-pilot-feed.json",
            lock_path=tmp_path / "publication.lock",
            spool_lock_path=directories["processing"] / ".consumer.lock",
            public_origin="https://api.umi.vision",
            expected_coordinator_hotkey=dev_wallet("//Coordinator").hotkey.ss58_address,
            producer_uid=os.geteuid(),
            producer_gid=os.getegid(),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("initial_state", ("incoming", "processing"))
async def test_spool_claims_installs_and_receipts_one_verified_archive(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    initial_state: str,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    incoming = tmp_path / "incoming"
    processing = tmp_path / "processing"
    processed = tmp_path / "processed"
    receipts = tmp_path / "receipts"
    quarantine = tmp_path / "quarantine"
    work = tmp_path / "work"
    published = tmp_path / "published"
    for directory in (incoming, processing, processed, receipts, quarantine, work, published):
        directory.mkdir(mode=0o700)
    temporary = tmp_path / "candidate.tar.gz"
    archive_sha256 = create_evidence_archive(bundle, temporary, archive_root="bundle")
    queued = (incoming if initial_state == "incoming" else processing) / (
        f"{archive_sha256}.tar.gz"
    )
    temporary.rename(queued)
    coordinator_hotkey = replay_public_endpoint_pilot(bundle)["coordinator_hotkey"]

    arguments = {
        "incoming_dir": incoming,
        "processing_dir": processing,
        "processed_dir": processed,
        "quarantine_dir": quarantine,
        "receipts_dir": receipts,
        "work_root": work,
        "publication_root": published,
        "config_path": tmp_path / "observer-pilot-feed.json",
        "lock_path": tmp_path / "publication.lock",
        "spool_lock_path": processing / ".consumer.lock",
        "public_origin": "https://api.umi.vision",
        "expected_coordinator_hotkey": coordinator_hotkey,
        "producer_uid": os.geteuid(),
        "producer_gid": os.getegid(),
    }

    results = consume_public_pilot_spool(**arguments)

    assert len(results) == 1
    result = results[0]
    receipt = load_publication_receipt(result.receipt_path)
    assert receipt.archive_sha256 == archive_sha256
    assert receipt.pilot_id == result.pilot_id
    assert receipt.already_installed is False
    assert not queued.exists()
    assert not any(path.name.endswith(".tar.gz") for path in processing.iterdir())
    retained = processed / f"{archive_sha256}.tar.gz"
    assert hashlib.sha256(retained.read_bytes()).hexdigest() == archive_sha256
    assert (published / result.pilot_id / "manifest.json").is_file()

    assert consume_public_pilot_spool(**arguments) == ()


@pytest.mark.asyncio
async def test_spool_recovers_processing_first_and_quarantines_bad_archives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    coordinator_hotkey = replay_public_endpoint_pilot(bundle)["coordinator_hotkey"]
    incoming = tmp_path / "incoming"
    processing = tmp_path / "processing"
    processed = tmp_path / "processed"
    quarantine = tmp_path / "quarantine"
    receipts = tmp_path / "receipts"
    work = tmp_path / "work"
    published = tmp_path / "published"
    for directory in (incoming, processing, processed, quarantine, receipts, work, published):
        directory.mkdir(mode=0o700)

    archive = tmp_path / "candidate.tar.gz"
    archive_sha256 = create_evidence_archive(bundle, archive, archive_root="bundle")
    invalid = b"this is not a gzip tar"
    invalid_sha256 = hashlib.sha256(invalid).hexdigest()
    invalid_path = processing / f"{invalid_sha256}.tar.gz"
    invalid_path.write_bytes(invalid)
    invalid_path.chmod(0o600)
    archive.rename(incoming / f"{archive_sha256}.tar.gz")

    results = consume_public_pilot_spool(
        incoming_dir=incoming,
        processing_dir=processing,
        processed_dir=processed,
        quarantine_dir=quarantine,
        receipts_dir=receipts,
        work_root=work,
        publication_root=published,
        config_path=tmp_path / "observer-pilot-feed.json",
        lock_path=tmp_path / "publication.lock",
        spool_lock_path=processing / ".consumer.lock",
        public_origin="https://api.umi.vision",
        expected_coordinator_hotkey=coordinator_hotkey,
        producer_uid=os.geteuid(),
        producer_gid=os.getegid(),
    )

    assert [result.archive_sha256 for result in results] == [archive_sha256]
    assert (processed / f"{archive_sha256}.tar.gz").is_file()
    assert (quarantine / f"{invalid_sha256}.tar.gz.invalid").is_file()
    assert not any(path.name.endswith(".tar.gz") for path in processing.iterdir())


@pytest.mark.asyncio
async def test_spool_recovers_after_receipt_before_processed_move(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    coordinator_hotkey = replay_public_endpoint_pilot(bundle)["coordinator_hotkey"]
    directories = {
        name: tmp_path / name
        for name in (
            "incoming",
            "processing",
            "processed",
            "quarantine",
            "receipts",
            "work",
            "published",
        )
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    archive = tmp_path / "candidate.tar.gz"
    archive_sha256 = create_evidence_archive(bundle, archive, archive_root="bundle")
    queued = directories["incoming"] / f"{archive_sha256}.tar.gz"
    archive.rename(queued)
    arguments = {
        "incoming_dir": directories["incoming"],
        "processing_dir": directories["processing"],
        "processed_dir": directories["processed"],
        "quarantine_dir": directories["quarantine"],
        "receipts_dir": directories["receipts"],
        "work_root": directories["work"],
        "publication_root": directories["published"],
        "config_path": tmp_path / "observer-pilot-feed.json",
        "lock_path": tmp_path / "publication.lock",
        "spool_lock_path": directories["processing"] / ".consumer.lock",
        "public_origin": "https://api.umi.vision",
        "expected_coordinator_hotkey": coordinator_hotkey,
        "producer_uid": os.geteuid(),
        "producer_gid": os.getegid(),
    }
    retained = directories["processed"] / queued.name
    real_rename = os.rename

    def interrupt_after_receipt(source: str | Path, destination: str | Path) -> None:
        if Path(destination) == retained:
            raise OSError("simulated crash after receipt")
        real_rename(source, destination)

    with monkeypatch.context() as crash:
        crash.setattr(spool_module.os, "rename", interrupt_after_receipt)
        with pytest.raises(OSError, match="simulated crash"):
            consume_public_pilot_spool(**arguments)

    claimed = directories["processing"] / queued.name
    receipt_path = directories["receipts"] / f"{archive_sha256}.json"
    assert claimed.is_file()
    assert receipt_path.is_file()
    assert load_publication_receipt(receipt_path).already_installed is False

    results = consume_public_pilot_spool(**arguments)

    assert [result.archive_sha256 for result in results] == [archive_sha256]
    assert retained.is_file()
    assert not claimed.exists()
    assert load_publication_receipt(receipt_path).already_installed is False


@pytest.mark.asyncio
@pytest.mark.parametrize("unsafe_kind", ("mode", "link", "owner"))
async def test_spool_quarantines_unsafe_producer_file_and_continues(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    unsafe_kind: str,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    coordinator_hotkey = replay_public_endpoint_pilot(bundle)["coordinator_hotkey"]
    directories = {
        name: tmp_path / name
        for name in (
            "incoming",
            "processing",
            "processed",
            "quarantine",
            "receipts",
            "work",
            "published",
        )
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    archive = tmp_path / "unsafe.tar.gz"
    archive_sha256 = create_evidence_archive(bundle, archive, archive_root="bundle")
    queued = directories["incoming"] / f"{archive_sha256}.tar.gz"
    archive.rename(queued)
    producer_uid = os.geteuid()
    if unsafe_kind == "mode":
        queued.chmod(0o660)
    elif unsafe_kind == "link":
        os.link(queued, directories["incoming"] / "retained-producer-link")
    else:
        queued.chmod(0o640)
        producer_uid += 1

    results = consume_public_pilot_spool(
        incoming_dir=directories["incoming"],
        processing_dir=directories["processing"],
        processed_dir=directories["processed"],
        quarantine_dir=directories["quarantine"],
        receipts_dir=directories["receipts"],
        work_root=directories["work"],
        publication_root=directories["published"],
        config_path=tmp_path / "observer-pilot-feed.json",
        lock_path=tmp_path / "publication.lock",
        spool_lock_path=directories["processing"] / ".consumer.lock",
        public_origin="https://api.umi.vision",
        expected_coordinator_hotkey=coordinator_hotkey,
        producer_uid=producer_uid,
        producer_gid=os.getegid(),
    )

    assert results == ()
    assert (directories["quarantine"] / f"{archive_sha256}.tar.gz.invalid").is_file()
    assert not any(directories["published"].iterdir())


@pytest.mark.asyncio
async def test_spool_rejects_bad_coordinator_config_before_claiming(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    directories = {
        name: tmp_path / name
        for name in (
            "incoming",
            "processing",
            "processed",
            "quarantine",
            "receipts",
            "work",
            "published",
        )
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    archive = tmp_path / "candidate.tar.gz"
    archive_sha256 = create_evidence_archive(bundle, archive, archive_root="bundle")
    queued = directories["incoming"] / f"{archive_sha256}.tar.gz"
    archive.rename(queued)

    with pytest.raises(ValueError):
        consume_public_pilot_spool(
            incoming_dir=directories["incoming"],
            processing_dir=directories["processing"],
            processed_dir=directories["processed"],
            quarantine_dir=directories["quarantine"],
            receipts_dir=directories["receipts"],
            work_root=directories["work"],
            publication_root=directories["published"],
            config_path=tmp_path / "observer-pilot-feed.json",
            lock_path=tmp_path / "publication.lock",
            spool_lock_path=directories["processing"] / ".consumer.lock",
            public_origin="https://api.umi.vision",
            expected_coordinator_hotkey="not-an-ss58-address",
            producer_uid=os.geteuid(),
            producer_gid=os.getegid(),
        )

    assert queued.is_file()
    assert not any(directories["processing"].iterdir())
    assert not any(directories["quarantine"].iterdir())


@pytest.mark.asyncio
async def test_spool_quarantines_bundle_from_another_coordinator(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bundle = await _public_bundle(tmp_path, monkeypatch)
    directories = {
        name: tmp_path / name
        for name in (
            "incoming",
            "processing",
            "processed",
            "quarantine",
            "receipts",
            "work",
            "published",
        )
    }
    for directory in directories.values():
        directory.mkdir(mode=0o700)
    archive = tmp_path / "candidate.tar.gz"
    archive_sha256 = create_evidence_archive(bundle, archive, archive_root="bundle")
    archive.rename(directories["incoming"] / f"{archive_sha256}.tar.gz")

    results = consume_public_pilot_spool(
        incoming_dir=directories["incoming"],
        processing_dir=directories["processing"],
        processed_dir=directories["processed"],
        quarantine_dir=directories["quarantine"],
        receipts_dir=directories["receipts"],
        work_root=directories["work"],
        publication_root=directories["published"],
        config_path=tmp_path / "observer-pilot-feed.json",
        lock_path=tmp_path / "publication.lock",
        spool_lock_path=directories["processing"] / ".consumer.lock",
        public_origin="https://api.umi.vision",
        expected_coordinator_hotkey=dev_wallet("//OtherCoordinator").hotkey.ss58_address,
        producer_uid=os.geteuid(),
        producer_gid=os.getegid(),
    )

    assert results == ()
    assert (directories["quarantine"] / f"{archive_sha256}.tar.gz.invalid").is_file()
    assert not any(directories["published"].iterdir())
