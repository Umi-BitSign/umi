from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from dataclasses import replace

import pytest

from umi.competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_METADATA_BYTES,
    MAX_SEGMENTS,
    decode_evidence,
    encode_evidence,
)
from umi.competition_evidence_store import EvidenceBudget, EvidenceStore, observation_reservation
from umi.protocol import canonical_json_bytes

OWNER = "e" * 64
ATTEMPT = "a" * 64
LIMITS = EvidenceBudget(128 * 1024**2, 1024**3, 10000, 100000)


def proof(block=100, recipients=256, runtime=b"r" * 8192):
    # All recipients, repeated trie nodes across batches, changed state roots.
    node = b"node" * 256
    return canonical_json_bytes(
        {
            "block": block,
            "state_root": "0x" + hashlib.sha256(str(block).encode()).hexdigest(),
            "runtime": "0x" + runtime.hex(),
            "claims": [
                {
                    "uid": uid,
                    "key": "0x" + hashlib.sha256(bytes([uid])).hexdigest(),
                    "proof": ["0x" + node.hex(), "0x" + bytes([uid]).hex() * 64],
                }
                for uid in range(recipients)
            ],
        }
    )


def open_store(path, *, create=False, limits=LIMITS, owner=OWNER):
    db = sqlite3.connect(path, isolation_level=None)
    db.execute("PRAGMA synchronous=FULL")
    db.execute("BEGIN IMMEDIATE")
    return db, EvidenceStore(db, owner_binding_sha256=owner, limits=limits, create=create)


@pytest.fixture
def store(tmp_path):
    db, result = open_store(tmp_path / "evidence.sqlite3", create=True)
    yield result
    db.close()


@pytest.mark.parametrize(
    "raw",
    [
        b"\x00\xffnot json\x00",
        b"0x" + b"ab" * 32,
        b'"0x' + b"A1" * 64 + b'"',
        b'"0x' + b"a" * 65 + b'"',
        b'{"b": 3, "a": 1}',
        b'{"text":"escaped \\"0x' + b"ab" * 64 + b'\\" text"}',
        proof(),
    ],
)
def test_codec_preserves_arbitrary_exact_bytes(raw):
    encoded = encode_evidence(raw, kind="proof")
    assert (
        decode_evidence(
            encoded.recipe,
            sha256=encoded.sha256,
            expanded_bytes=len(raw),
            kind="proof",
            resolve=lambda key, _: encoded.objects[key],
        )
        == raw
    )


def test_dedup_retains_original_hash_and_restart(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    db, store = open_store(path, create=True)
    first, second = proof(100), proof(101)
    assert store.put(first, kind="proof") == hashlib.sha256(first).hexdigest()
    used = store.inventory()
    store.put(second, kind="proof")
    final = store.audit()
    assert final.stored_bytes - used.stored_bytes < len(second) // 4
    assert final.stored_bytes < (len(first) + len(second)) // 4
    assert final.objects - used.objects == 2  # Only changed block literal and state root.
    assert final.expanded_bytes == len(first) + len(second)
    assert store.put(first, kind="proof") == hashlib.sha256(first).hexdigest()
    assert store.inventory() == final
    db.commit()
    db.close()
    db, store = open_store(path)
    assert store.audit() == final
    assert store.get(hashlib.sha256(second).hexdigest()) == second
    db.close()


@pytest.mark.parametrize(
    "kind,size",
    [
        ("proof", MAX_EVIDENCE_BYTES),
        ("metadata", MAX_METADATA_BYTES),
    ],
)
def test_protocol_maximum_and_incompressible_bytes(store, kind, size):
    raw = os.urandom(size)
    digest = store.put(raw, kind=kind)
    assert store.get(digest) == raw
    assert store.inventory().stored_bytes < size + 1024
    with pytest.raises(ValueError):
        store.put(raw + b"a", kind=kind)


def test_8mib_runtime_16mib_metadata_and_runtime_change(store):
    raw = proof(runtime=os.urandom(8 * 1024**2))
    metadata = os.urandom(16 * 1024**2)
    for body, kind in [(raw, "proof"), (metadata, "metadata")]:
        assert store.get(store.put(body, kind=kind)) == body
    before = store.inventory()
    store.put(proof(101, runtime=os.urandom(8 * 1024**2)), kind="proof")
    after = store.audit()
    assert 8 * 1024**2 < after.stored_bytes - before.stored_bytes < 9 * 1024**2


@pytest.mark.parametrize(
    "change",
    [
        lambda b: b.update(length=True),
        lambda b: b.update(schema="unsupported"),
        lambda b: b.update(extra="field"),
        lambda b: b.update(segments=[["x", "a" * 64, MAX_EVIDENCE_BYTES]]),
        lambda b: b.update(segments=[["b", "a" * 64, True]]),
        lambda b: b.update(segments=[["nested", "a" * 64, 1]]),
        lambda b: b.update(segments=[["b", "not a hash", 1]]),
        lambda b: b.update(segments=[["b", "a" * 64, 1]] * (MAX_SEGMENTS + 1)),
    ],
)
def test_recipe_attack_rejected_before_object_access(change):
    encoded = encode_evidence(proof(), kind="proof")
    body = json.loads(encoded.recipe)
    change(body)
    calls = []
    with pytest.raises(ValueError):
        decode_evidence(
            canonical_json_bytes(body),
            sha256=encoded.sha256,
            expanded_bytes=encoded.expanded_bytes,
            kind="proof",
            resolve=lambda *args: calls.append(args),
        )
    assert not calls


@pytest.mark.parametrize("mutation", ["object", "missing", "recipe", "rehash_recipe", "binding"])
def test_corruption_rejected(store, mutation):
    digest = store.put(proof(), kind="proof")
    if mutation == "object":
        store.db.execute("UPDATE weight_proof_objects SET body=zeroblob(length(body))")
    elif mutation == "missing":
        store.db.execute("DELETE FROM weight_proof_objects")
    elif mutation == "recipe":
        store.db.execute("UPDATE weight_proof_records SET recipe=?", (b"{}",))
    elif mutation == "rehash_recipe":
        original = json.loads(store._record(digest)[2])
        original["segments"].reverse()
        raw = canonical_json_bytes(original)
        store.db.execute(
            "UPDATE weight_proof_records SET recipe=?,recipe_sha256=?",
            (raw, hashlib.sha256(raw).hexdigest()),
        )
    else:
        store.db.execute("UPDATE weight_proof_binding SET body=?", (b"{}",))
    with pytest.raises(ValueError):
        store.audit()


def test_same_stored_bytes_different_owner_or_capacity_rejected(tmp_path):
    path = tmp_path / "store.db"
    db, _store = open_store(path, create=True)
    db.commit()
    db.close()
    for owner, limits in [("f" * 64, LIMITS), (OWNER, replace(LIMITS, records=9999))]:
        db = sqlite3.connect(path)
        db.execute("BEGIN")
        with pytest.raises(ValueError, match="binding changed"):
            EvidenceStore(db, owner_binding_sha256=owner, limits=limits)
        db.close()


def test_reservation_survives_restart_and_blocks_unreserved_use(tmp_path):
    path = tmp_path / "store.db"
    limits = EvidenceBudget(10000, 10000, 10, 10)
    db, store = open_store(path, create=True, limits=limits)
    budget = EvidenceBudget(9900, 9900, 9, 9)
    store.reserve(ATTEMPT, budget)
    store.reserve(ATTEMPT, budget)
    with pytest.raises(ValueError, match="changed"):
        store.reserve(ATTEMPT, EvidenceBudget(9800, 9800, 8, 8))
    with pytest.raises(ValueError, match="capacity"):
        store.put(b"x" * 100, kind="proof")
    db.commit()
    db.close()
    db, store = open_store(path, limits=limits)
    digest = store.put(b"x" * 100, kind="proof", reservation=ATTEMPT)
    remaining = store._reservations()[ATTEMPT]
    assert remaining.expanded_bytes == 9800
    assert remaining.records == remaining.objects == 8
    store.put(b"x" * 100, kind="proof", reservation=ATTEMPT)
    assert store._reservations()[ATTEMPT] == remaining
    assert store.get(digest) == b"x" * 100
    store.release_reservation(ATTEMPT)
    assert not store._reservations()
    db.close()


def test_failed_insert_rolls_back_objects_even_if_caller_commits(store):
    before = store.inventory()
    store.db.execute(
        "CREATE TEMP TRIGGER fault BEFORE INSERT ON weight_proof_records "
        "BEGIN SELECT RAISE(ABORT, 'injected failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="injected"):
        store.put(proof(), kind="proof")
    assert store.inventory() == before
    assert store.audit() == before


@pytest.mark.parametrize("field", ["stored_bytes", "expanded_bytes", "records", "objects"])
def test_each_capacity_dimension_holds_without_partial_append(tmp_path, field):
    limits = replace(LIMITS, **{field: 1})
    db, store = open_store(tmp_path / "store.db", create=True, limits=limits)
    before = store.inventory()
    with pytest.raises(ValueError, match="capacity"):
        store.put(proof(), kind="proof")
        store.put(proof(101), kind="proof")
    # For the record dimension the first operation succeeds; failed second is atomic.
    assert store.audit().records == (1 if field == "records" else before.records)
    db.close()


@pytest.mark.parametrize("commit", [False, True])
def test_process_death_preserves_commit_boundary(tmp_path, commit):
    path = tmp_path / "store.db"
    db, store = open_store(path, create=True)
    old = store.put(b"retained before process death", kind="proof")
    db.commit()
    db.close()
    script = """
import os, signal, sqlite3, sys
from umi.competition_evidence_store import EvidenceBudget, EvidenceStore
db=sqlite3.connect(sys.argv[1], isolation_level=None)
db.execute('PRAGMA synchronous=FULL')
db.execute('BEGIN IMMEDIATE')
s=EvidenceStore(db, owner_binding_sha256='e'*64,
    limits=EvidenceBudget(128*1024**2,1024**3,10000,100000))
s.reserve('a'*64, EvidenceBudget(10000,10000,10,10))
s.put(b'new evidence before process death',kind='proof',reservation='a'*64)
if sys.argv[2]=='True': db.commit()
os.kill(os.getpid(),signal.SIGKILL)
"""
    result = subprocess.run([sys.executable, "-c", script, str(path), str(commit)], check=False)
    assert result.returncode == -9
    db, store = open_store(path)
    assert store.get(old) == b"retained before process death"
    assert store.audit().records == (2 if commit else 1)
    assert bool(store._reservations()) == commit
    db.close()


def test_operations_require_snapshot_transaction(store):
    store.db.commit()
    with pytest.raises(ValueError, match="transaction"):
        store.put(b"no transaction", kind="proof")


def test_worst_observation_reserve_covers_maximum_proof_and_metadata(tmp_path):
    limits = EvidenceBudget(128 * 1024**2, 1024**3, 10000, 100000)
    db, store = open_store(tmp_path / "reserved.db", create=True, limits=limits)
    reserve = observation_reservation(1)
    store.reserve(ATTEMPT, reserve)
    for kind, size in [("proof", MAX_EVIDENCE_BYTES), ("metadata", MAX_METADATA_BYTES)]:
        raw = os.urandom(size)
        assert store.get(store.put(raw, kind=kind, reservation=ATTEMPT)) == raw
    remaining = store._reservations()[ATTEMPT]
    assert remaining.expanded_bytes == remaining.records == 0
    assert remaining.stored_bytes > 0
    assert store.audit().expanded_bytes == reserve.expanded_bytes
    db.close()


def test_full_series_record_count_with_shared_components(store):
    # 862 publications, three proofs each. Small payload permits a routine CI test;
    # this verifies the complete record horizon, not production disk/lease timing.
    for block in range(862 * 3):
        store.put(proof(block, recipients=4, runtime=b"r" * 1024), kind="proof")
    used = store.audit()
    assert used.records == 2586
    assert used.stored_bytes < used.expanded_bytes // 4
