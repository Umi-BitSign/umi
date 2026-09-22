"""Candidate-copy assertions using actual native weight submission fixtures."""

import hashlib
import json
import sqlite3
from dataclasses import replace

import pytest

from umi.competition_evidence_copy import copy_legacy_weight_journal
from umi.competition_evidence_store import EvidenceBudget, EvidenceStore
from umi.protocol import canonical_json_bytes


def assert_native_copy(item):
    with item.worker._db() as db:
        db.execute("INSERT INTO held_policies VALUES (?)", ("11" * 32,))
        db.execute(
            "INSERT INTO continuity_highwater VALUES (?,?,?,?,?)",
            ("22" * 32, "33" * 32, 5, "44" * 32, "55" * 32),
        )
    before = item.worker.path.read_bytes()
    source = sqlite3.connect(item.worker.path.as_uri() + "?mode=ro", uri=True)
    source.execute("PRAGMA query_only=ON")
    source.execute("BEGIN")
    binding = source.execute("SELECT * FROM binding").fetchall()
    owner = hashlib.sha256(canonical_json_bytes(binding)).hexdigest()
    limits = EvidenceBudget(128 * 1024**2, 1024**3, 10000, 100000)
    with sqlite3.connect(":memory:") as destination:
        destination.execute("BEGIN")
        report = copy_legacy_weight_journal(
            source, destination, expected_binding_sha256=owner, limits=limits
        )
        assert not report["activation_authorized"]
        store = EvidenceStore(destination, owner_binding_sha256=owner, limits=limits)
        for table in ("binding", "attempts", "highwater", "held_policies", "continuity_highwater"):
            assert source.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall() == (
                destination.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall()
            )
        for digest, body in source.execute("SELECT * FROM evidence"):
            assert store.get(digest) == body
        rows = destination.execute("SELECT body FROM attempts").fetchall()
        if rows:
            attempt = json.loads(rows[0][0])
            assert attempt["phase"] == (
                "unknown" if item.behavior == "disconnect" else "recovered_effect"
            )
            assert bytes.fromhex(attempt["signed_extrinsic"][2:]) == item.encoded[0]
            assert attempt["nonce"] == 4
    with sqlite3.connect(":memory:") as destination:
        destination.execute("BEGIN")
        with pytest.raises(ValueError, match="binding"):
            copy_legacy_weight_journal(
                source, destination, expected_binding_sha256="f" * 64, limits=limits
            )
        assert not destination.execute("SELECT name FROM sqlite_master").fetchall()
        if source.execute("SELECT 1 FROM evidence LIMIT 1").fetchone():
            with pytest.raises(ValueError, match="capacity"):
                copy_legacy_weight_journal(
                    source,
                    destination,
                    expected_binding_sha256=owner,
                    limits=replace(limits, stored_bytes=1),
                )
            assert not destination.execute("SELECT name FROM sqlite_master").fetchall()
    if source.execute("SELECT 1 FROM attempts LIMIT 1").fetchone():
        for sql in (
            "DELETE FROM evidence",
            "UPDATE evidence SET body=zeroblob(length(body))",
            "UPDATE attempts SET body=zeroblob(length(body))",
            "UPDATE attempts SET body=zeroblob(262145)",
            "CREATE TABLE unexpected (body BLOB)",
            "CREATE TRIGGER unexpected AFTER INSERT ON evidence BEGIN SELECT 1; END",
        ):
            bad = sqlite3.connect(":memory:")
            source.backup(bad)
            bad.execute(sql)
            bad.commit()
            bad.execute("PRAGMA query_only=ON")
            bad.execute("BEGIN")
            with sqlite3.connect(":memory:") as destination:
                destination.execute("BEGIN")
                with pytest.raises(ValueError):
                    copy_legacy_weight_journal(
                        bad, destination, expected_binding_sha256=owner, limits=limits
                    )
                # A caller catching the failure cannot commit half a copied journal.
                destination.commit()
                assert not destination.execute("SELECT name FROM sqlite_master").fetchall()
            bad.close()
    source.close()
    assert item.worker.path.read_bytes() == before
