"""Unchanged successful metadata checks must not reread full journal bodies."""

import json

import pytest

from umi.competition_round_journal import RoundJournal
from umi.competition_upload_record_versions import UploadRecordRepairRequired, UploadRecordVersions


@pytest.fixture
def records(tmp_path):
    binding = {"schema": "umi-cohort-model-delivery/1"}
    journal = RoundJournal(tmp_path / "journal", binding)
    journal.put_many((("upload", "a" * 64, {"original": "large request"}),))
    versions = UploadRecordVersions(journal, binding)
    return journal, binding, versions


def test_migrate_once_without_reading_original_then_reuse_across_restart(records, monkeypatch):
    journal, binding, versions = records
    checks = []

    def verify(db):
        checks.append(journal.get_raw("upload", "a" * 64, db=db))
        return '{"model":"verified"}'

    with journal.read_transaction() as db:
        assert versions.result("upload", "a" * 64, "test", verify, db=db)[0]
    assert len(checks) == 1
    restarted = UploadRecordVersions(journal, binding)
    original = journal.get_raw

    def no_body(kind, key, **kwargs):
        assert kind != "upload", "unchanged request was read again"
        return original(kind, key, **kwargs)

    monkeypatch.setattr(journal, "get_raw", no_body)
    for owner in (versions, restarted):
        with journal.read_transaction() as db:
            assert owner.result("upload", "a" * 64, "test", verify, db=db) == (
                '{"model":"verified"}',
                False,
            )
    assert len(checks) == 1


@pytest.mark.parametrize("change", ["same_length", "delete_insert", "rekey", "replace"])
def test_every_sql_mutation_invalidates_old_result(records, change):
    journal, _, versions = records
    key = "a" * 64
    with journal.read_transaction() as db:
        before = versions.identity("upload", key, db=db)
    with journal.transaction() as db:
        if change == "same_length":
            db.execute(
                "UPDATE records SET body=? WHERE kind='upload' AND id=?",
                (b'{"original":"other request"}', key),
            )
        elif change == "delete_insert":
            db.execute("DELETE FROM records WHERE kind='upload' AND id=?", (key,))
            db.execute("INSERT INTO records VALUES ('upload',?,?)", (key, b"{}"))
        elif change == "rekey":
            db.execute("UPDATE records SET id=? WHERE kind='upload' AND id=?", ("b" * 64, key))
        else:
            db.execute("INSERT OR REPLACE INTO records VALUES ('upload',?,?)", (key, b"{}"))
    with journal.read_transaction() as db:
        if change == "rekey":
            with pytest.raises(UploadRecordRepairRequired):
                versions.identity("upload", key, db=db)
        else:
            assert versions.identity("upload", key, db=db) != before


def test_old_record_writer_advances_identity_and_current_hold_refuses_reuse(records):
    journal, _, versions = records
    journal.put_many((("bundle", "b" * 64, {"new": "record"}),))
    with journal.read_transaction() as db:
        assert versions.identity("bundle", "b" * 64, db=db)
    with journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", ("b" * 64,))
    with journal.read_transaction() as db, pytest.raises(ValueError, match="held"):
        versions.identity("bundle", "b" * 64, db=db)


@pytest.mark.parametrize("damage", ["trigger", "source", "table", "marker"])
def test_missing_identity_metadata_never_becomes_a_routine_cache_miss(records, damage):
    journal, binding, versions = records
    with journal.transaction() as db:
        if damage == "trigger":
            db.execute("DROP TRIGGER upload_record_version_update")
        elif damage == "source":
            db.execute("DELETE FROM upload_record_versions")
        elif damage == "table":
            db.execute("DROP TABLE upload_record_versions")
        else:
            db.execute("DELETE FROM records WHERE kind='upload_record_version_owner'")
    if damage != "source":
        with pytest.raises(UploadRecordRepairRequired):
            UploadRecordVersions(journal, binding)
    with journal.read_transaction() as db, pytest.raises(UploadRecordRepairRequired):
        versions.identity("upload", "a" * 64, db=db)


def test_lost_completion_acknowledgement_reuses_the_persisted_result(records, monkeypatch):
    from umi.competition_verification_reuse import VerificationReuse

    journal, binding, versions = records
    original = VerificationReuse.remember
    checks = []

    def verify(db):
        checks.append(1)
        return json.dumps({"completed": True})

    def lost_ack(*args):
        original(*args)
        raise OSError("lost acknowledgement")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(VerificationReuse, "remember", lost_ack)
        with journal.read_transaction() as db, pytest.raises(OSError, match="lost acknowledgement"):
            versions.result("upload", "a" * 64, "test", verify, db=db)
    restarted = UploadRecordVersions(journal, binding)
    with journal.read_transaction() as db:
        assert restarted.result("upload", "a" * 64, "test", verify, db=db)[0]
    assert checks == [1]


def test_interrupted_metadata_migration_rolls_back_without_changing_originals(
    tmp_path, monkeypatch
):
    from umi import competition_upload_record_versions as versions_module

    binding = {"schema": "umi-cohort-model-delivery/1"}
    journal = RoundJournal(tmp_path / "journal", binding)
    journal.put_many((("upload", "a" * 64, {"original": "signed bytes"}),))
    before = journal.get_raw("upload", "a" * 64)
    original = versions_module._triggers

    def interrupted_triggers():
        return {**original(), "failure": "INSERT INTO nonexistent VALUES (1)"}

    import sqlite3

    with monkeypatch.context() as interrupted:
        interrupted.setattr(versions_module, "_triggers", interrupted_triggers)
        with pytest.raises(sqlite3.Error):
            UploadRecordVersions(journal, binding)
    with journal.read_transaction() as db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name GLOB 'upload_record_version*'"
        ).fetchone()
        assert journal.get("upload_record_version_owner", "owner", db=db) is None
    UploadRecordVersions(journal, binding)
    assert journal.get_raw("upload", "a" * 64) == before
