"""Retained-format migration, repeat execution, repair and true retry runway."""

import pytest

from umi.competition_cohort_direct_model_attempts import (
    DirectModelAttemptIndex,
    DirectModelAttemptJournal,
    DirectModelAttemptRepairRequired,
    DirectModelMetadataCapacityPending,
    DirectModelUploadIntent,
    attempt_index_key,
)
from umi.competition_round_journal import RoundJournal

BINDING = {"schema": "umi-direct-model-upload-owner-binding/1", "cohort_sha256": "ab" * 32}
UPLOAD = "cd" * 32


def intent(generation):
    return DirectModelUploadIntent(
        schema="umi-direct-model-upload-intent/1",
        cohort_sha256=BINDING["cohort_sha256"],
        upload_sha256=UPLOAD,
        payload_declaration_sha256="ef" * 32,
        attempt_id=f"{generation:064x}",
        generation=generation,
        object_key=f"original/attempt/{generation}",
        created_at_unix_ms=generation * 1000,
        retry_after_unix_ms=generation * 1000 + 100,
    )


def native_legacy(root, generations=(1, 2)):
    journal = RoundJournal(root, BINDING, maximum_rounds=128, maximum_bytes=1024**2)
    journal.put_many(
        (
            ("direct-request", UPLOAD, {"signed": "original request"}),
            ("direct-payload", UPLOAD, {"signed": "original payload"}),
        )
    )
    for generation in generations:
        value = intent(generation)
        index = DirectModelAttemptIndex(
            schema="umi-direct-model-attempt-index/1",
            upload_sha256=UPLOAD,
            generation=generation,
            attempt_id=value.attempt_id,
        )
        journal.put_many(
            (
                ("direct-intent", value.attempt_id, value),
                ("direct-attempt-index", attempt_index_key(UPLOAD, generation), index),
            )
        )
    return journal


def open_current(root, **kwargs):
    return DirectModelAttemptJournal(
        root, BINDING, maximum_uploads=1, maximum_bytes=1024**2, **kwargs
    )


def records(journal):
    with journal.read_transaction() as db:
        return db.execute("SELECT kind,id,body FROM records ORDER BY kind,id").fetchall()


def test_legacy_migration_retains_all_original_bytes_and_latest_generation(tmp_path):
    legacy = native_legacy(tmp_path / "journal")
    before = records(legacy)
    current = open_current(legacy.root)
    assert records(current) == before
    assert current.latest_attempt(UPLOAD) == intent(2)
    assert current._journal_version() == 6
    repeated = open_current(legacy.root)
    assert records(repeated) == before
    assert repeated.latest_attempt(UPLOAD) == intent(2)


def test_retry_history_has_no_upload_times_attempt_count_ceiling(tmp_path, monkeypatch):
    current = open_current(tmp_path / "journal")
    current.retain_request(UPLOAD, {"signed": "request"}, {"signed": "payload"})
    for generation in range(1, 81):
        current.retain_attempt(intent(generation))
    monkeypatch.setattr(
        current, "keys", lambda *a: pytest.fail("current lookup enumerated cohort history")
    )
    assert current.latest_attempt(UPLOAD) == intent(80)
    assert open_current(current.root).latest_attempt(UPLOAD) == intent(80)


def test_live_legacy_reader_and_writer_refuse_after_migration(tmp_path):
    legacy = native_legacy(tmp_path / "journal")
    current = open_current(legacy.root)
    before = records(current)
    with pytest.raises(ValueError, match="unsupported round journal capability"):
        legacy.put("direct-intent", "ff" * 32, {"wrong": "old writer"})
    with pytest.raises(ValueError, match="unsupported round journal capability"):
        legacy.get("direct-request", UPLOAD)
    assert records(current) == before


@pytest.mark.parametrize("damage", ["missing_head", "regressed_head", "missing_schema"])
def test_damage_is_explicit_and_repair_rebuilds_only_derived_state(tmp_path, damage):
    current = open_current(native_legacy(tmp_path / "journal").root)
    before = records(current)
    with current.transaction() as db:
        if damage == "missing_head":
            db.execute("DELETE FROM direct_upload_attempt_heads WHERE upload_sha256=?", (UPLOAD,))
        elif damage == "regressed_head":
            db.execute("UPDATE direct_upload_attempt_heads SET generation=0,attempt_id=NULL")
        else:
            db.execute("DROP TABLE direct_upload_attempt_heads")
    with pytest.raises(DirectModelAttemptRepairRequired):
        current.latest_attempt(UPLOAD)
    fixed = open_current(current.root, repair_attempt_index=True)
    assert fixed.latest_attempt(UPLOAD) == intent(2)
    assert records(fixed) == before


def test_missing_original_intent_refuses_repair_and_rolls_back(tmp_path):
    current = open_current(native_legacy(tmp_path / "journal").root)
    with current.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='direct-intent' AND id=?", (intent(1).attempt_id,)
        )
    before = records(current)
    with pytest.raises(DirectModelAttemptRepairRequired, match="original metadata is incomplete"):
        open_current(current.root, repair_attempt_index=True)
    assert records(current) == before
    with pytest.raises(DirectModelAttemptRepairRequired, match="original metadata is incomplete"):
        current.latest_attempt(UPLOAD)


def test_legacy_gap_refuses_before_changing_capability_or_records(tmp_path):
    legacy = native_legacy(tmp_path / "journal", generations=(1, 3))
    before = records(legacy)
    with pytest.raises(DirectModelAttemptRepairRequired, match="gap"):
        open_current(legacy.root)
    assert records(legacy) == before
    with legacy.read_transaction() as db:
        assert db.execute("PRAGMA user_version").fetchone() == (0,)


def test_interrupted_migration_remains_exactly_retryable(tmp_path, monkeypatch):
    legacy = native_legacy(tmp_path / "journal")
    before = records(legacy)
    native_check = DirectModelAttemptJournal._check_attempt_capacity

    def interrupted(*args):
        raise OSError("injected before migration commit")

    monkeypatch.setattr(DirectModelAttemptJournal, "_check_attempt_capacity", interrupted)
    with pytest.raises(OSError, match="before migration commit"):
        open_current(legacy.root)
    assert records(legacy) == before
    monkeypatch.setattr(DirectModelAttemptJournal, "_check_attempt_capacity", native_check)
    assert open_current(legacy.root).latest_attempt(UPLOAD) == intent(2)


def test_metadata_backpressure_is_atomic_and_capacity_growth_resumes_same_inputs(tmp_path):
    current = open_current(native_legacy(tmp_path / "journal").root)
    before = records(current)
    with current.read_transaction() as db:
        used = current._record_capacity(db)[1]
    current.maximum_bytes = used + 20
    with pytest.raises(DirectModelMetadataCapacityPending, match="capacity pending"):
        current.retain_attempt(intent(3))
    assert records(current) == before
    assert current.latest_attempt(UPLOAD) == intent(2)
    expanded = open_current(current.root)
    expanded.retain_attempt(intent(3))
    assert expanded.latest_attempt(UPLOAD) == intent(3)


def test_downgraded_marker_refuses_old_and_new_runtimes(tmp_path):
    current = open_current(native_legacy(tmp_path / "journal").root)
    with current.transaction() as db:
        db.execute("PRAGMA user_version=0")
    with pytest.raises(DirectModelAttemptRepairRequired, match="downgraded"):
        open_current(current.root)
    with pytest.raises(ValueError, match="downgraded"):
        RoundJournal(current.root, BINDING)


def test_existing_readonly_native_view_preserves_records_and_capability(tmp_path):
    current = open_current(native_legacy(tmp_path / "journal").root)
    before = records(current)
    observer = open_current(current.root, existing_only=True, read_only=True)
    assert observer.latest_attempt(UPLOAD) == intent(2)
    assert records(observer) == before
    with pytest.raises(ValueError, match="read-only"):
        observer.retain_attempt(intent(3))


def test_legacy_orphan_intent_cannot_be_silently_replaced(tmp_path):
    legacy = native_legacy(tmp_path / "journal")
    with legacy.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='direct-attempt-index' AND id=?",
            (attempt_index_key(UPLOAD, 2),),
        )
    before = records(legacy)
    with pytest.raises(DirectModelAttemptRepairRequired, match="original metadata is incomplete"):
        open_current(legacy.root)
    assert records(legacy) == before


def test_request_retry_does_not_recreate_a_lost_head(tmp_path):
    current = open_current(tmp_path / "journal")
    current.retain_request(UPLOAD, {"signed": "request"}, {"signed": "payload"})
    current.retain_attempt(intent(1))
    with current.transaction() as db:
        db.execute("DELETE FROM direct_upload_attempt_heads")
    with pytest.raises(DirectModelAttemptRepairRequired):
        current.retain_request(UPLOAD, {"signed": "request"}, {"signed": "payload"})


def test_repair_cannot_bypass_readonly_validation(tmp_path):
    current = open_current(native_legacy(tmp_path / "journal").root)
    with pytest.raises(ValueError, match="explicit writable owner"):
        open_current(current.root, existing_only=True, read_only=True, repair_attempt_index=True)


def test_large_legacy_migration_works_without_sqlite_json_extension(tmp_path, monkeypatch):
    import sqlite3
    from contextlib import contextmanager

    legacy = native_legacy(tmp_path / "journal", generations=range(1, 81))
    before = records(legacy)
    native_transaction = RoundJournal.transaction

    @contextmanager
    def no_json(self, **kwargs):
        with native_transaction(self, **kwargs) as db:

            def authorize(action, first, second, *unused):
                if action == sqlite3.SQLITE_FUNCTION and (first or second or "").startswith(
                    "json_"
                ):
                    return sqlite3.SQLITE_DENY
                return sqlite3.SQLITE_OK

            db.set_authorizer(authorize)
            yield db

    monkeypatch.setattr(RoundJournal, "transaction", no_json)
    migrated = open_current(legacy.root)
    assert migrated.latest_attempt(UPLOAD) == intent(80)
    assert records(migrated) == before
