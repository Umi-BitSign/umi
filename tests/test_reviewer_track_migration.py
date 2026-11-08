import importlib.util
import json
import sqlite3
import unittest
from pathlib import Path

import pytest

from umi.competition_round_journal import RecordReservation, RoundJournal

spec = importlib.util.spec_from_file_location(
    "repair", Path(__file__).resolve().parents[1] / "tools/migrate_reviewer_tracks.py"
)
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


def canonical(v):
    return json.dumps(v, sort_keys=True, separators=(",", ":")).encode()


class RepairTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:")
        self.addCleanup(self.db.close)
        self.db.executescript(
            "CREATE TABLE records(kind TEXT,id TEXT,body BLOB,PRIMARY KEY(kind,id));"
            "CREATE TABLE holds(id TEXT PRIMARY KEY);"
        )
        self.old = dict(
            eligible_tracks=["endpoint", "model"],
            owner="owner",
            series_sha256="series",
            maximum_sample_gap_blocks=10,
        )
        self.new = dict(self.old, eligible_tracks=["model"])
        self.db.execute(
            "INSERT INTO records VALUES(?,?,?)",
            ("phase_review_host", "selection", canonical(self.old)),
        )
        self.db.execute(
            "INSERT INTO records VALUES(?,?,?)", ("signed", "vote", b"exact original signature")
        )
        self.db.executemany("INSERT INTO holds VALUES(?)", [("selection",), ("unrelated",)])

    def run_repair(self, **kw):
        return m.repair(self.db, self.old, self.new, canonical, **kw)

    def test_repair_and_restart_preserve_other_records_and_holds(self):
        result = self.run_repair(prepared=True)
        self.assertEqual(result["record_updates"], 1)
        self.assertEqual(result["holds_removed"], 1)
        self.assertEqual(
            self.db.execute("SELECT body FROM records WHERE kind='signed'").fetchone()[0],
            b"exact original signature",
        )
        self.assertEqual(self.db.execute("SELECT id FROM holds").fetchall(), [("unrelated",)])
        self.assertTrue(self.run_repair(prepared=True)["reused"])

    def test_missing_durable_intent_refused(self):
        with self.assertRaisesRegex(ValueError, "intent"):
            self.run_repair()

    def test_changed_authority_refused(self):
        self.old["owner"] = "changed"
        with self.assertRaisesRegex(ValueError, "original host"):
            self.run_repair(prepared=True)

    def test_unrelated_selection_record_refused(self):
        self.db.execute("INSERT INTO records VALUES(?,?,?)", ("signed", "selection", b"signed"))
        with self.assertRaisesRegex(ValueError, "unrelated"):
            self.run_repair(prepared=True)

    def test_existing_target_with_hold_refused(self):
        self.db.execute(
            "UPDATE records SET body=? WHERE kind='phase_review_host'", (canonical(self.new),)
        )
        with self.assertRaisesRegex(ValueError, "completed repair"):
            self.run_repair(prepared=True)

    def test_exact_config_change_only(self):
        before = dict(
            eligible_tracks=["endpoint", "model"],
            endpoint={"enabled": True},
            series={"signed": "bytes"},
            owner_hotkey="owner",
            maximum_sample_gap_blocks=10,
        )
        after = dict(before, eligible_tracks=["model"])
        after.pop("endpoint")
        _old, new = m.selections(before, after, lambda v: "digest", lambda v: v)
        self.assertEqual(new["eligible_tracks"], ["model"])
        after["maximum_sample_gap_blocks"] = 11
        with self.assertRaisesRegex(ValueError, "unrelated"):
            m.selections(before, after, lambda v: "digest", lambda v: v)


@pytest.mark.parametrize("reserved", [False, True])
def test_installed_journal_versions_preserve_accounting_and_signed_rows(tmp_path, reserved):
    journal = RoundJournal(
        tmp_path / "journal", {"owner": "test"}, maximum_rounds=100, maximum_bytes=1024**2
    )
    old = dict(
        eligible_tracks=["endpoint", "model"],
        owner="owner",
        series_sha256="series",
        maximum_sample_gap_blocks=10,
    )
    new = dict(old, eligible_tracks=["model"])
    journal.put("phase_review_host", "selection", old)
    journal.put("signed_vote", "vote", {"signed": "unchanged"})
    if reserved:
        journal.reserve_records("other", [RecordReservation("signed_vote", "next", 4096)])
    with pytest.raises(ValueError, match="conflict"):
        journal.put("phase_review_host", "selection", new)
    with journal.transaction() as db:
        result = m.repair(db, old, new, canonical, prepared=True)
        assert result["holds_removed"] == 1
        if reserved:
            journal._check_capacity(db)
    assert journal.get("phase_review_host", "selection") == new
    assert journal.get("signed_vote", "vote") == {"signed": "unchanged"}
    restarted = RoundJournal(
        tmp_path / "journal", {"owner": "test"}, maximum_rounds=100, maximum_bytes=1024**2
    )
    with restarted.transaction() as db:
        assert m.repair(db, old, new, canonical, prepared=True)["reused"]
