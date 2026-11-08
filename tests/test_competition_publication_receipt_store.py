"""Capacity, restart, legacy migration and interrupted retention contracts."""

import hashlib
import os
import sqlite3

import pytest

from umi import competition_publication_receipt_store as store_module
from umi.competition_cohort_request_reuse import (
    PublicationFileStamp,
    PublicationVerificationReceipt,
    load_publication_verification,
    remember_publication_verification,
)
from umi.competition_publication_receipt_store import (
    PublicationReceiptStore,
    PublicationReceiptUnavailable,
)
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes


def receipt(n=0):
    return PublicationVerificationReceipt(
        schema="umi-private-request-publication/1",
        terminal_sha256=hashlib.sha256(str(n).encode()).hexdigest(),
        policy_sha256="a" * 64,
        maximum_bytes=1024,
        opened_at_block=0,
        completed_by_block=100,
        files=(
            PublicationFileStamp(relative_path="objects/" + "b" * 64 + ".json", stamp=("1",) * 9),
        ),
    )


def test_more_than_legacy_capacity_restarts_without_directory_scan(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("retention must not inventory the directory")

    monkeypatch.setattr(type(tmp_path), "iterdir", forbidden)
    for n in range(2050):
        remember_publication_verification(tmp_path, receipt(n))
    for n in (0, 1024, 2047, 2048, 2049):
        value = receipt(n)
        assert (
            load_publication_verification(tmp_path, value.terminal_sha256, value.policy_sha256)
            == value
        )
    db_path = tmp_path / ".publication-verification" / "receipts.sqlite3"
    with sqlite3.connect(db_path) as db:
        assert db.execute("SELECT COUNT(*) FROM receipts").fetchone()[0] == 2050
        assert (
            db.execute("SELECT bytes FROM metadata").fetchone()[0]
            == db.execute("SELECT SUM(length(body)) FROM receipts").fetchone()[0]
        )


def test_legacy_import_preserves_exact_bytes_and_index_survives_legacy_loss(tmp_path):
    value = receipt()
    path = (
        tmp_path
        / ".publication-verification"
        / (value.policy_sha256 + "-" + value.terminal_sha256 + ".json")
    )
    publish_private_model(path, value)
    before = path.read_bytes(), path.stat()
    assert (
        load_publication_verification(tmp_path, value.terminal_sha256, value.policy_sha256) == value
    )
    assert (path.read_bytes(), path.stat()) == before
    path.unlink()
    assert (
        load_publication_verification(tmp_path, value.terminal_sha256, value.policy_sha256) == value
    )


@pytest.mark.parametrize("failure", ["row", "checksum", "database", "directory", "bytes"])
def test_completed_state_damage_is_explicit(tmp_path, failure):
    value = receipt()
    remember_publication_verification(tmp_path, value)
    path = tmp_path / ".publication-verification" / "receipts.sqlite3"
    if failure in {"database", "directory"}:
        path.unlink()
        if failure == "directory":
            (path.parent / ".cache.lock").unlink()
            path.parent.rmdir()
    elif failure == "bytes":
        path.write_bytes(b"broken")
    else:
        with sqlite3.connect(path) as db:
            db.execute("DELETE FROM " + ("receipts" if failure == "row" else "completed"))
    with pytest.raises(PublicationReceiptUnavailable):
        load_publication_verification(tmp_path, value.terminal_sha256, value.policy_sha256)


def test_capacity_failure_is_visible_and_preserves_previous_receipt(tmp_path, monkeypatch):
    value = receipt()
    raw = canonical_json_bytes(value)
    monkeypatch.setattr(store_module, "MAX_STORE_BYTES", len(raw) + 32768)
    store = PublicationReceiptStore(tmp_path / ".publication-verification")
    store.remember("key", raw)
    # Payload capacity test independent of the physical SQLite page budget.
    monkeypatch.setattr(store_module, "MAX_STORE_BYTES", len(raw))
    with pytest.raises(PublicationReceiptUnavailable):
        store.remember("other", raw)
    assert store.load("key") == raw
    assert store.load("other") is None


def test_interrupted_transaction_rolls_back_without_losing_completed_work(tmp_path):
    store = PublicationReceiptStore(tmp_path / ".publication-verification")
    raw = canonical_json_bytes(receipt())
    store.remember("key", raw)
    with pytest.raises(RuntimeError), store.connection(create=True) as db, db:
        db.execute("BEGIN IMMEDIATE")
        db.execute("DELETE FROM receipts")
        raise RuntimeError("interruption before commit")
    assert store.load("key") == raw


def test_interrupted_initial_marker_resumes_committed_database(tmp_path, monkeypatch):
    store = PublicationReceiptStore(tmp_path / ".publication-verification")
    original = os.replace

    def interrupted(*args):
        raise OSError("marker publication interrupted")

    monkeypatch.setattr(os, "replace", interrupted)
    with pytest.raises(PublicationReceiptUnavailable):
        store.remember("key", b"verified")
    monkeypatch.setattr(os, "replace", original)
    store.remember("key", b"verified")
    assert store.load("key") == b"verified"
    assert not list(tmp_path.glob(".publication-verification.*[!d]"))
