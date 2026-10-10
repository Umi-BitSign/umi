"""History operational envelopes with tiny real SQLite journals, no large files."""

import pytest

from umi.competition_reward_history import MAX_HISTORY_BYTES, _HistoryJournal
from umi.competition_round_journal import RecordReservation, RoundJournal
from umi.protocol import canonical_json_bytes, sha256_hex


@pytest.mark.parametrize("maximum", [16 * 1024**3 + 1, 64 * 1024**3, MAX_HISTORY_BYTES])
def test_history_supports_explicit_large_budget_without_enlarging_other_journals(tmp_path, maximum):
    ordinary = tmp_path / "ordinary"
    with pytest.raises(ValueError, match="bounded capacity"):
        RoundJournal(ordinary, {}, maximum_bytes=maximum)
    assert not ordinary.exists()

    journal = _HistoryJournal(tmp_path / "history", {}, maximum_bytes=maximum)
    journal.put("control_history_block", "10", {"retained": True})
    with journal.transaction() as db:
        assert db.execute("PRAGMA max_page_count").fetchone()[0] == (maximum + 16 * 1024**2) // 4096
    assert journal.path.stat().st_size < 1024**2
    assert journal.maximum_records == maximum
    assert RoundJournal(tmp_path / "defaults", {}).maximum_records == 1024 * 80


@pytest.mark.parametrize("maximum", [True, 1023, MAX_HISTORY_BYTES + 1])
def test_history_rejects_unsupported_byte_envelope_before_creating_state(tmp_path, maximum):
    root = tmp_path / "invalid"
    with pytest.raises(ValueError, match="bounded capacity"):
        _HistoryJournal(root, {}, maximum_bytes=maximum)
    assert not root.exists()


@pytest.mark.parametrize("kind", [RoundJournal, _HistoryJournal])
def test_history_does_not_expand_round_or_batch_bounds(tmp_path, kind):
    with pytest.raises(ValueError, match="bounded capacity"):
        kind(tmp_path / "invalid", {}, maximum_rounds=65537)
    journal = kind(tmp_path / "bounded", {}, maximum_rounds=1, maximum_bytes=65536)
    with pytest.raises(ValueError, match="batch capacity exhausted"):
        journal.put_many(("control_history_object", str(n), {}) for n in range(81))
    assert journal.get("control_history_object", "0") is None
    with pytest.raises(ValueError, match="record capacity exhausted"):
        journal.put_many([("plan", "one", {}), ("plan", "two", {})])
    assert journal.get("plan", "one") is None


def test_history_crosses_old_total_record_ceiling_using_same_journal(tmp_path):
    root, binding = tmp_path / "history", {"original": "unchanged"}
    old = RoundJournal(root, binding, maximum_rounds=1, maximum_bytes=65536)
    old.put_many(("control_history_object", str(n), {"n": n}) for n in range(80))
    inode = old.path.stat().st_ino
    with pytest.raises(ValueError, match="capacity exhausted"):
        old.put("control_history_object", "80", {"n": 80})

    history = _HistoryJournal(root, binding, maximum_rounds=1, maximum_bytes=65536)
    history.put_many(("control_history_object", str(n), {"n": n}) for n in range(80, 90))
    for _ in range(2):
        history = _HistoryJournal(root, binding, maximum_rounds=1, maximum_bytes=65536)
        assert history.path.stat().st_ino == inode
        for n in range(90):
            assert history.get("control_history_object", str(n)) == {"n": n}
    # An ordinary owner still retains its original capacity rules.
    with pytest.raises(ValueError, match="capacity exhausted"):
        old.put("control_history_object", "90", {"n": 90})


@pytest.mark.parametrize("reserved", [False, True])
def test_original_layout_repeated_history_growth_preserves_binding_and_reservations(
    tmp_path, reserved
):
    root, binding = tmp_path / "old-layout", {"series": "original", "first_block": 10}
    old = RoundJournal(root, binding, maximum_bytes=65536)
    value = {"signed": "original immutable bytes"}
    if reserved:
        spec = RecordReservation(
            "control_history_object", "original", 1024, sha256_hex(canonical_json_bytes(value))
        )
        receipt = old.reserve_records("original", [spec])
    old.put("control_history_object", "original", value)
    inode = old.path.stat().st_ino

    def snapshot(owner):
        with owner.read_transaction() as db:
            tables = sorted(owner._table_names(db))
            return db.execute("PRAGMA user_version").fetchone(), {
                name: db.execute(f'SELECT * FROM "{name}" ORDER BY 1').fetchall() for name in tables
            }

    before = snapshot(old)
    for maximum in [64 * 1024**3, 64 * 1024**3, MAX_HISTORY_BYTES]:
        history = _HistoryJournal(root, binding, maximum_bytes=maximum)
        assert history.path.stat().st_ino == inode
        assert history.get("control_history_object", "original") == value
        if reserved:
            assert history.reservation("original") == receipt
            assert history.reserve_records("original", [spec]) == receipt
        assert snapshot(history) == before
    # Reopening under the original envelope remains compatible while its
    # actual retained work still fits. No schema or reservation format changed.
    assert snapshot(RoundJournal(root, binding, maximum_bytes=65536)) == before


def test_new_large_history_reservation_identity_reopens_and_retains_allowance(tmp_path):
    root, binding = tmp_path / "history", {"original": True}
    history = _HistoryJournal(root, binding, maximum_bytes=64 * 1024**3)
    receipt = history.reserve_records("batch", [RecordReservation("proof", "one", 32)])
    assert receipt["maximum_bytes"] == 64 * 1024**3
    for _ in range(2):
        history = _HistoryJournal(root, binding, maximum_bytes=MAX_HISTORY_BYTES)
        assert history.reservation("batch") == receipt
        with pytest.raises(ValueError, match="reserved allowance"):
            history.put("proof", "one", {"too_large": "x" * 32})
        assert history.get("proof", "one") is None
    history.put("proof", "one", {"ok": True})
    assert history.reservation("batch") == receipt


def test_history_reservations_use_total_byte_envelope_beyond_round_record_count(tmp_path):
    history = _HistoryJournal(tmp_path / "history", {}, maximum_rounds=1, maximum_bytes=65536)
    receipts = []
    for offset in [0, 50]:
        specs = [RecordReservation("proof", str(n), 32) for n in range(offset, offset + 50)]
        receipts.append(history.reserve_records(str(offset), specs))
    history.put_many(("proof", str(n), {"n": n}) for n in range(50))
    history.put_many(("proof", str(n), {"n": n}) for n in range(50, 100))
    for offset, receipt in zip([0, 50], receipts, strict=True):
        assert history.reservation(str(offset)) == receipt


def test_history_byte_failure_and_conflict_still_roll_back_and_hold(tmp_path):
    history = _HistoryJournal(tmp_path / "history", {}, maximum_bytes=1024)
    history.put("proof", "original", {"immutable": True})
    with pytest.raises(ValueError, match="capacity exhausted"):
        history.put_many([("proof", "small", {}), ("proof", "large", {"x": "a" * 1024})])
    assert history.get("proof", "small") is None
    with pytest.raises(ValueError, match="conflict"):
        history.put_many(
            [
                ("proof", "large", {"x": "a" * 1024}),
                ("proof", "original", {"immutable": False}),
            ]
        )
    assert history.get("proof", "large") is None
    with pytest.raises(ValueError, match="conflict held"):
        history.get("proof", "original")
