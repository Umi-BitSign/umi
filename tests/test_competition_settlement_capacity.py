import pytest
from pydantic import BaseModel, ValidationError

from umi.competition_publication import PublicationReplayLimits
from umi.competition_round_journal import MAX_BYTES, RecordReservation, RoundJournal
from umi.competition_settlement_capacity import settlement_capacity
from umi.competition_settlement_preparation import validate_preparation
from umi.private_files import MAX_PRIVATE_BYTES, publish_private_model, read_private_model

MIB = 1024**2


def limits(evidence=256 * MIB):
    return PublicationReplayLimits(
        maximum_roster_bytes=4 * MIB,
        maximum_evidence_bytes=evidence,
        maximum_certificate_bytes=4 * MIB,
    )


class Envelope(BaseModel):
    evidence: str


def test_explicit_large_profile_keeps_global_caps_and_legacy_profile():
    legacy = settlement_capacity(limits(64 * MIB))
    assert (legacy.preparation_bytes, legacy.page_size, legacy.concurrent_requests) == (
        64 * MIB,
        4,
        2,
    )
    capacity = settlement_capacity(limits())
    assert (capacity.preparation_bytes, capacity.page_size, capacity.concurrent_requests) == (
        320 * MIB,
        1,
        1,
    )
    assert capacity.reply_bytes == 320 * MIB + 8192
    assert MAX_BYTES == MAX_PRIVATE_BYTES == 64 * MIB


def test_profile_rejects_evidence_with_no_room_for_envelope():
    with pytest.raises(ValueError, match="maximum preparation profile"):
        settlement_capacity(limits(512 * MIB))


@pytest.mark.parametrize("maximum", [True, 0, -1, 512 * MIB + 1])
def test_explicit_file_and_record_bounds_fail_before_creating_state(tmp_path, maximum):
    path = tmp_path / "out" / "evidence.json"
    with pytest.raises(ValueError, match="byte bound"):
        publish_private_model(path, Envelope(evidence="small"), maximum_bytes=maximum)
    with pytest.raises(ValueError, match="bounded capacity"):
        RoundJournal(tmp_path / "journal", {}, maximum_record_bytes=maximum)
    assert not path.parent.exists() and not (tmp_path / "journal").exists()


def test_larger_record_envelope_does_not_expand_reserved_credit(tmp_path):
    root = tmp_path / "journal"
    journal = RoundJournal(root, {"stable": True})
    receipt = journal.reserve_records("batch", (RecordReservation("intent", "one", 128),))
    with journal.transaction() as db:
        before = journal._capacity(db)
    larger = RoundJournal(root, {"stable": True}, maximum_record_bytes=320 * MIB)
    assert larger.reservation("batch") == receipt
    with pytest.raises(ValueError, match="reserved allowance"):
        larger.put("intent", "one", {"payload": "x" * 128})
    with larger.transaction() as db:
        assert larger._capacity(db) == before


def test_larger_record_envelope_does_not_expand_total_journal_capacity(tmp_path):
    journal = RoundJournal(
        tmp_path / "journal", {}, maximum_bytes=1024, maximum_record_bytes=320 * MIB
    )
    with pytest.raises(ValueError, match="capacity exhausted"):
        journal.put("intent", "one", {"payload": "x" * 2048})
    assert journal.get("intent", "one") is None


@pytest.mark.parametrize("payload_bytes", [256 * 403547, 256 * MIB])
def test_full_cohort_sized_bytes_cross_64_mib_and_reopen(tmp_path, payload_bytes):
    # 256 * largest C3 void body, measured read-only: 403,547 bytes.
    # This exercises the byte/storage path, not signatures or real-void replay.
    value = Envelope(evidence="v" * payload_bytes)
    profile = settlement_capacity(limits())
    path = tmp_path / "proposals" / "full-cohort.json"
    with pytest.raises(ValueError, match="output exceeds"):
        publish_private_model(path, value)
    publish_private_model(path, value, maximum_bytes=profile.preparation_bytes)
    publish_private_model(path, value, maximum_bytes=profile.preparation_bytes)
    assert read_private_model(path, Envelope, maximum_bytes=profile.preparation_bytes) == value
    with pytest.raises(ValueError, match="input exceeds"):
        read_private_model(path, Envelope)
    with pytest.raises(ValidationError):
        validate_preparation(value, None, limits())
    journal = RoundJournal(
        tmp_path / "journal", {"stable": True}, maximum_record_bytes=profile.preparation_bytes
    )
    journal.put("intent", "full", value)
    recovered = RoundJournal(
        journal.root, {"stable": True}, maximum_record_bytes=profile.preparation_bytes
    )
    assert recovered.get("intent", "full") == value.model_dump()
    recovered.put("intent", "full", value)
    with recovered.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM records").fetchone() == (1,)
    # A downgrade cannot silently reinterpret an enlarged retained object.
    old = RoundJournal(journal.root, {"stable": True})
    with pytest.raises(ValueError, match="retained round object"):
        old.get("intent", "full")
