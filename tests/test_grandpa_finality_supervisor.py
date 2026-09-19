from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import copy
from pathlib import Path

import pytest
import rfc8785

import umi.grandpa_finality_supervisor as finality_supervisor
from umi.grandpa_finality import (
    EVIDENCE_CLASS,
    RECORD_SCHEMA,
    SOURCE_REVISION,
    FinalityAttestation,
    GrandpaFinalityObserver,
    GrandpaFinalityObserverError,
)
from umi.grandpa_finality_supervisor import (
    ACCEPTANCE_RECEIPT_SCHEMA,
    DurableGrandpaFinalityPort,
    GrandpaFinalityStoreConflict,
    GrandpaFinalityStoreCorruption,
    GrandpaFinalitySupervisorError,
    GrandpaFinalitySupervisorLimits,
    ObserverRunBinding,
    parse_finality_acceptance_receipt,
)
from umi.policy import LiveChainObservationPin
from umi.window import QUICKNET_GENESIS_MS

_TRANSCRIPT_DOMAIN = b"umi-grandpa-finality-attestation-v1\0"
_GENESIS = "33" * 32
_BOOTSTRAP = "77" * 32
_POLICY_DIGEST = "44" * 32


def _compact(value: int) -> bytes:
    if value < 1 << 6:
        return bytes([value << 2])
    if value < 1 << 14:
        return ((value << 2) | 1).to_bytes(2, "little")
    return ((value << 2) | 2).to_bytes(4, "little")


def _header(number: int, *, parent_hash: str, seed: int) -> dict[str, object]:
    encoded = (
        bytes.fromhex(parent_hash[2:])
        + _compact(number)
        + bytes([seed]) * 32
        + bytes([(seed + 1) % 256]) * 32
        + b"\x00"
    )
    return {
        "number": number,
        "hash": f"0x{hashlib.blake2b(encoded, digest_size=32).hexdigest()}",
        "parent_hash": parent_hash,
        "state_root": f"0x{bytes([seed]).hex() * 32}",
        "extrinsics_root": f"0x{bytes([(seed + 1) % 256]).hex() * 32}",
        "scale_header": f"0x{encoded.hex()}",
        "timestamp_ms": QUICKNET_GENESIS_MS + number * 12_000,
    }


def _record(
    config: dict[str, object],
    *,
    block: dict[str, object],
    sequence: int,
    complete: bool,
    previous: FinalityAttestation | None,
) -> bytes:
    unsigned: dict[str, object] = {
        "schema": RECORD_SCHEMA,
        "request_id": config["request_id"],
        "evidence_class": EVIDENCE_CLASS,
        "offline_finality_proof": False,
        "source_revision": SOURCE_REVISION,
        "sequence": sequence,
        "chain_spec_sha256": config["chain_spec_sha256"],
        "genesis_hash": config["expected_genesis_hash"],
        "bootstrap_block_number": config["bootstrap_block_number"],
        "bootstrap_block_hash": config["bootstrap_block_hash"],
        "bootstrap_source": "grandpa_checkpoint",
        "bootstrap_selected": True,
        "startup_finalized_block_number": block["number"],
        "startup_finalized_block_hash": block["hash"],
        "block": block,
        "ancestry": [
            {
                "number": block["number"],
                "hash": block["hash"],
                "parent_hash": block["parent_hash"],
            }
        ],
        "ancestry_complete_since_previous": complete,
        "previous_finalized_hash": None if previous is None else previous.block.hash,
        "previous_transcript_digest": (
            "0" * 64 if previous is None else previous.transcript_digest
        ),
    }
    record = {
        **unsigned,
        "transcript_digest": hashlib.sha256(
            _TRANSCRIPT_DOMAIN + rfc8785.dumps(unsigned)
        ).hexdigest(),
    }
    return rfc8785.dumps(record)


def _attestation(
    observer: GrandpaFinalityObserver,
    binding: ObserverRunBinding,
    *,
    block: dict[str, object],
    sequence: int,
    previous: FinalityAttestation | None,
) -> FinalityAttestation:
    encoded = _record(
        observer._config(
            minimum_finalized_block=binding.minimum_finalized_block,
            maximum_records=binding.maximum_records,
            startup_timeout_seconds=binding.startup_timeout_seconds,
        )[0],
        block=block,
        sequence=sequence,
        complete=previous is not None,
        previous=previous,
    )
    return observer.validate_attestation(
        encoded,
        minimum_finalized_block=binding.minimum_finalized_block,
        maximum_records=binding.maximum_records,
        startup_timeout_seconds=binding.startup_timeout_seconds,
        expected_sequence=sequence,
        previous_hash=None if previous is None else previous.block.hash,
        previous_digest="0" * 64 if previous is None else previous.transcript_digest,
        previous_number=None if previous is None else previous.block.number,
        previous_timestamp_ms=None if previous is None else previous.block.timestamp_ms,
    )


def _write_observer(
    path: Path, *, stall_after_output: bool = False, skip_minimum: int | None = None
) -> str:
    source = f'''#!{sys.executable}
import hashlib
import json
import rfc8785
import sys
import threading

config = json.load(sys.stdin)
target = config["minimum_finalized_block"]
if target == {skip_minimum!r}:
    target += 1
parent_hash = "0x" + "{_GENESIS}"
block = None
for number in range(target + 1):
    if number < 64:
        compact = bytes([number << 2])
    elif number < 1 << 14:
        compact = ((number << 2) | 1).to_bytes(2, "little")
    else:
        compact = ((number << 2) | 2).to_bytes(4, "little")
    seed = (number % 200) + 1
    encoded = (
        bytes.fromhex(parent_hash[2:]) + compact + bytes([seed]) * 32
        + bytes([seed + 1]) * 32 + b"\\x00"
    )
    block_hash = "0x" + hashlib.blake2b(encoded, digest_size=32).hexdigest()
    block = {{
        "number": number,
        "hash": block_hash,
        "parent_hash": parent_hash,
        "state_root": "0x" + bytes([seed]).hex() * 32,
        "extrinsics_root": "0x" + bytes([seed + 1]).hex() * 32,
        "scale_header": "0x" + encoded.hex(),
        "timestamp_ms": {QUICKNET_GENESIS_MS} + number * 12000,
    }}
    parent_hash = block_hash
assert block is not None
unsigned = {{
    "schema": "{RECORD_SCHEMA}",
    "request_id": config["request_id"],
    "evidence_class": "{EVIDENCE_CLASS}",
    "offline_finality_proof": False,
    "source_revision": "{SOURCE_REVISION}",
    "sequence": 0,
    "chain_spec_sha256": config["chain_spec_sha256"],
    "genesis_hash": config["expected_genesis_hash"],
    "bootstrap_block_number": config["bootstrap_block_number"],
    "bootstrap_block_hash": config["bootstrap_block_hash"],
    "bootstrap_source": "grandpa_checkpoint",
    "bootstrap_selected": True,
    "startup_finalized_block_number": block["number"],
    "startup_finalized_block_hash": block["hash"],
    "block": block,
    "ancestry": [{{
        "number": block["number"], "hash": block["hash"],
        "parent_hash": block["parent_hash"]
    }}],
    "ancestry_complete_since_previous": False,
    "previous_finalized_hash": None,
    "previous_transcript_digest": "0" * 64,
}}
record = dict(unsigned)
record["transcript_digest"] = hashlib.sha256(
    b"umi-grandpa-finality-attestation-v1\\0" + rfc8785.dumps(unsigned)
).hexdigest()
sys.stdout.buffer.write(rfc8785.dumps(record) + b"\\n")
sys.stdout.buffer.flush()
if {stall_after_output!r}:
    threading.Event().wait()
'''
    path.write_text(source, encoding="utf-8")
    path.chmod(0o500)
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture
def observer(tmp_path: Path) -> GrandpaFinalityObserver:
    binary = tmp_path / "fake-observer"
    binary_hash = _write_observer(binary)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    return GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=binary_hash,
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=hashlib.sha256(b"{}").hexdigest(),
        expected_genesis_hash=f"0x{_GENESIS}",
        bootstrap_block_number=1,
        bootstrap_block_hash=f"0x{_BOOTSTRAP}",
        record_timeout_seconds=5,
    )


@pytest.fixture
def chain_observation() -> LiveChainObservationPin:
    return LiveChainObservationPin(
        network="finney",
        genesis_block_hash=_GENESIS,
        runtime_spec_version=452,
        transaction_version=1,
        state_version=1,
        metadata_sha256="55" * 32,
        subtensor_revision="da06f033663896ef2fdbbfc3ecc68ca908fba0f5",
        live_chain_fixture_set_sha256="66" * 32,
    )


def _port(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
    *,
    state_name: str = "finality.sqlite3",
    limits: GrandpaFinalitySupervisorLimits | None = None,
    scoring_digest: str = _POLICY_DIGEST,
) -> DurableGrandpaFinalityPort:
    return DurableGrandpaFinalityPort(
        observer=observer,
        state_path=tmp_path / state_name,
        scoring_policy_digest=scoring_digest,
        chain_observation=chain_observation,
        finality_verifier_sha256=observer.expected_binary_sha256,
        initial_minimum_finalized_block=10,
        startup_timeout_seconds=1,
        limits=limits or GrandpaFinalitySupervisorLimits(maximum_records_per_process=2),
    )


@pytest.mark.asyncio
async def test_persists_restart_and_exposes_plan_and_scan_ports(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    port = _port(tmp_path, observer, chain_observation)
    binding = port.next_run_binding()
    block10 = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    first = _attestation(observer, binding, block=block10, sequence=0, previous=None)
    block11 = _header(11, parent_hash=str(block10["hash"]), seed=21)
    second = _attestation(observer, binding, block=block11, sequence=1, previous=first)
    port.accept_attestation(binding, first)
    port.accept_attestation(binding, second)

    assert await port.finalized_head_height() == 11
    snapshot = await port.verified_finalized_snapshot()
    assert snapshot.block_number == 11
    assert snapshot.block_hash == block11["hash"]
    assert snapshot.parent_hash == block11["parent_hash"]
    assert snapshot.state_root == block11["state_root"]
    accepted_at = await port.verified_acceptance_time_at(10)
    assert isinstance(accepted_at, int) and accepted_at > 0
    assert await port.verified_acceptance_time_at(12) is None
    plan_block = await port.verified_block_at(10)
    assert plan_block is not None
    assert plan_block.finality_evidence == first.canonical_bytes
    identity = await port.verified_identity_at(11)
    assert identity is not None
    assert identity.parent_snapshot.block_hash == block10["hash"]
    interval = await port.verified_identities(11, 11)
    assert interval == (identity,)
    replay_interval = await port.verified_scan_interval(11, 11)
    assert replay_interval is not None
    assert replay_interval.identities == (identity,)
    assert replay_interval.attestations == (second.canonical_bytes,)
    assert len(replay_interval.acceptance_receipts) == 1
    exact_receipt = await port.verified_acceptance_receipt_at(11)
    assert exact_receipt == replay_interval.acceptance_receipts[0]
    receipt = parse_finality_acceptance_receipt(exact_receipt)
    assert receipt.height == 11
    assert receipt.block_hash == second.block.hash
    assert receipt.evidence_sha256 == hashlib.sha256(second.canonical_bytes).hexdigest()
    assert receipt.accepted_at_unix_ms >= accepted_at
    assert json.loads(receipt.canonical_bytes)["schema"] == ACCEPTANCE_RECEIPT_SCHEMA
    tampered_receipt = json.loads(receipt.canonical_bytes)
    tampered_receipt["accepted_at_unix_ms"] += 1
    with pytest.raises(ValueError, match="receipt digest is invalid"):
        parse_finality_acceptance_receipt(rfc8785.dumps(tampered_receipt))
    assert len(replay_interval.replay_bindings) == 1
    replay_binding = replay_interval.replay_bindings[0]
    assert replay_binding.minimum_finalized_block == binding.minimum_finalized_block
    assert replay_binding.maximum_records == binding.maximum_records
    assert replay_binding.startup_timeout_seconds == binding.startup_timeout_seconds
    assert replay_binding.expected_sequence == 1
    assert replay_binding.previous_number == first.block.number
    assert replay_binding.previous_timestamp_ms == first.block.timestamp_ms
    assert replay_binding.previous_hash == first.block.hash
    assert replay_binding.previous_digest == first.transcript_digest

    restarted = _port(tmp_path, observer, chain_observation)
    assert restarted.persisted_head() == port.persisted_head()
    assert restarted.accept_attestation(binding, second) == port.persisted_head()
    restarted.audit()


@pytest.mark.asyncio
async def test_restart_gap_is_explicit_and_exact_consumers_fail_closed(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    limits = GrandpaFinalitySupervisorLimits(maximum_records_per_process=1)
    port = _port(tmp_path, observer, chain_observation, limits=limits)
    first_binding = port.next_run_binding()
    block10 = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    first = _attestation(observer, first_binding, block=block10, sequence=0, previous=None)
    port.accept_attestation(first_binding, first)

    second_binding = port.next_run_binding()
    block13 = _header(13, parent_hash=f"0x{'77' * 32}", seed=23)
    resumed = _attestation(observer, second_binding, block=block13, sequence=0, previous=None)
    head = port.accept_attestation(second_binding, resumed)
    assert head.restart_gap_before is True
    assert await port.verified_block_at(11) is None
    assert await port.verified_identity_at(13) is None
    assert await port.verified_identities(11, 13) is None
    assert await port.verified_scan_interval(11, 13) is None
    assert (await port.verified_block_after(11, maximum_distance=2)).height == 13
    assert await port.verified_block_after(11, maximum_distance=1) is None
    assert await port.verified_block_after(13, maximum_distance=2) is None
    with pytest.raises(ValueError):
        await port.verified_block_after(11, maximum_distance=2049)


def test_conflicting_replay_and_wrong_store_binding_fail_closed(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    port = _port(tmp_path, observer, chain_observation)
    binding = port.next_run_binding()
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    accepted = _attestation(observer, binding, block=block, sequence=0, previous=None)
    port.accept_attestation(binding, accepted)

    changed_block = _header(10, parent_hash=f"0x{'22' * 32}", seed=30)
    conflicting = _attestation(observer, binding, block=changed_block, sequence=0, previous=None)
    with pytest.raises(GrandpaFinalityStoreConflict, match="finalized_height_conflict"):
        port.accept_attestation(binding, conflicting)
    with pytest.raises(GrandpaFinalityStoreConflict, match="store_binding_mismatch"):
        _port(
            tmp_path,
            observer,
            chain_observation,
            scoring_digest="99" * 32,
        )


def test_startup_audit_detects_normalized_row_corruption(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    port = _port(tmp_path, observer, chain_observation)
    binding = port.next_run_binding()
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    port.accept_attestation(
        binding,
        _attestation(observer, binding, block=block, sequence=0, previous=None),
    )
    database = tmp_path / "finality.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE finalized_headers SET state_root = ? WHERE height = 10",
            (f"0x{'99' * 32}",),
        )
    with pytest.raises(GrandpaFinalityStoreCorruption, match="normalized_header_mismatch"):
        _port(tmp_path, observer, chain_observation)


def test_startup_audit_detects_acceptance_time_tamper(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    port = _port(tmp_path, observer, chain_observation)
    binding = port.next_run_binding()
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    port.accept_attestation(
        binding,
        _attestation(observer, binding, block=block, sequence=0, previous=None),
    )
    database = tmp_path / "finality.sqlite3"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "UPDATE finalized_headers SET accepted_at_unix_ms = accepted_at_unix_ms + 1 "
            "WHERE height = 10"
        )
    with pytest.raises(GrandpaFinalityStoreCorruption, match="acceptance_digest_mismatch"):
        _port(tmp_path, observer, chain_observation)


def test_audit_uses_one_snapshot_while_another_owner_commits(
    tmp_path, observer, chain_observation, monkeypatch
):
    reader = _port(tmp_path, observer, chain_observation)
    binding = reader.next_run_binding()
    block10 = _header(10, parent_hash="0x" + "11" * 32, seed=20)
    first = _attestation(observer, binding, block=block10, sequence=0, previous=None)
    reader.accept_attestation(binding, first)
    writer = _port(tmp_path, observer, chain_observation)
    block11 = _header(11, parent_hash=str(block10["hash"]), seed=21)
    second = _attestation(observer, binding, block=block11, sequence=1, previous=first)
    connect, committed = reader._connect, []

    @contextmanager
    def concurrent_read(*, read_only):
        assert read_only
        with connect(read_only=True) as connection:

            class ConcurrentRead:
                def execute(self, sql, *args):
                    if sql == "SELECT * FROM observer_segments ORDER BY segment_index":
                        # Commit after audit read the head digest, before it reads
                        # segments/headers. A healthy WAL writer must not turn this
                        # audit into a false corruption report.
                        committed.append(writer.accept_attestation(binding, second))
                    return connection.execute(sql, *args)

            yield ConcurrentRead()

    with monkeypatch.context() as patch:
        patch.setattr(reader, "_connect", concurrent_read)
        reader.audit()
    assert len(committed) == 1 and committed[0].height == 11
    assert reader.persisted_head().height == 11
    reader.audit()


def _audit_history(port, observer, *, segment_lengths=(2, 2)):
    records = []
    parent_hash = "0x" + "11" * 32
    height = 10
    for length in segment_lengths:
        binding = port.next_run_binding()
        previous = None
        for sequence in range(length):
            block = _header(height, parent_hash=parent_hash, seed=height + 10)
            attestation = _attestation(
                observer, binding, block=block, sequence=sequence, previous=previous
            )
            port.accept_attestation(binding, attestation)
            records.append(attestation)
            previous = attestation
            parent_hash = str(block["hash"])
            height += 1
    return records


def test_audit_streams_history_before_reading_the_next_header(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    records = _audit_history(port, observer, segment_lengths=(2,) * 12)
    connect = port._connect
    validate = observer.validate_attestation
    counts = {"headers": 0, "segments": 0, "parsed": 0}

    class StreamingCursor:
        def __init__(self, cursor, kind):
            self.cursor, self.kind = cursor, kind

        def fetchall(self):
            pytest.fail("audit must not materialize history")

        def __iter__(self):
            return self

        def __next__(self):
            row = next(self.cursor)
            counts[self.kind] += 1
            return row

    @contextmanager
    def streaming_read(*, read_only):
        assert read_only
        with connect(read_only=True) as connection:

            class StreamingRead:
                def execute(self, sql, *args):
                    cursor = connection.execute(sql, *args)
                    if sql == "SELECT * FROM finalized_headers ORDER BY height":
                        return StreamingCursor(cursor, "headers")
                    if sql == "SELECT * FROM observer_segments ORDER BY segment_index":
                        return StreamingCursor(cursor, "segments")
                    return cursor

            yield StreamingRead()

    def checked_validate(*args, **kwargs):
        assert counts["headers"] == counts["parsed"] + 1
        assert counts["segments"] == counts["parsed"] // 2 + 1
        result = validate(*args, **kwargs)
        counts["parsed"] += 1
        return result

    with monkeypatch.context() as patch:
        patch.setattr(port, "_connect", streaming_read)
        patch.setattr(observer, "validate_attestation", checked_validate)
        port.audit()
    assert counts == {"headers": len(records), "segments": 12, "parsed": len(records)}


def test_audit_snapshot_survives_commit_during_parser_replay(
    tmp_path, observer, chain_observation, monkeypatch
):
    audit_observer = copy(observer)
    reader = _port(tmp_path, audit_observer, chain_observation)
    records = _audit_history(reader, audit_observer, segment_lengths=(2,))
    writer = _port(tmp_path, observer, chain_observation)
    binding = writer.next_run_binding()
    third = _attestation(
        observer,
        binding,
        block=_header(12, parent_hash=records[-1].block.hash, seed=22),
        sequence=0,
        previous=None,
    )
    validate = audit_observer.validate_attestation
    replayed, checkpoints = [], []

    def commit_during_replay(*args, **kwargs):
        result = validate(*args, **kwargs)
        replayed.append(result.block.number)
        if len(replayed) == 1:
            assert writer.accept_attestation(binding, third).height == 12
            with sqlite3.connect(tmp_path / "finality.sqlite3") as connection:
                checkpoints.append(connection.execute("PRAGMA wal_checkpoint(PASSIVE)").fetchone())
        return result

    with monkeypatch.context() as patch:
        patch.setattr(audit_observer, "validate_attestation", commit_during_replay)
        reader.audit()
    assert replayed == [10, 11]
    assert len(checkpoints) == 1 and checkpoints[0][1] > checkpoints[0][2]
    assert reader.persisted_head().height == 12
    with sqlite3.connect(tmp_path / "finality.sqlite3") as connection:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    reader.audit()


@pytest.mark.parametrize(
    ("statements", "reason"),
    [
        (
            ["DELETE FROM finalized_headers WHERE segment_index = 1"],
            "empty_or_orphan_segment",
        ),
        (
            ["UPDATE finalized_headers SET segment_index = 99 WHERE height = 13"],
            "sqlite_foreign_key_check_failed",
        ),
        (
            [
                "UPDATE observer_segments SET segment_index = 2 WHERE segment_index = 1",
                "UPDATE finalized_headers SET segment_index = 2 WHERE segment_index = 1",
            ],
            "nonconsecutive_segment",
        ),
        (
            [
                "UPDATE finalized_headers SET segment_index = 1, segment_sequence = 2 "
                "WHERE height = 10"
            ],
            "global_height_rollback",
        ),
        (
            [
                "UPDATE finalized_headers SET segment_index = 0, segment_sequence = 2 "
                "WHERE height = 13"
            ],
            "global_height_rollback",
        ),
        (
            ["UPDATE finalized_headers SET segment_sequence = 2 WHERE height = 11"],
            "normalized_header_mismatch",
        ),
        (
            ["UPDATE observer_segments SET minimum_finalized_block = 99 WHERE segment_index = 1"],
            "segment_run_binding_mismatch",
        ),
        (
            ["UPDATE observer_segments SET restart_gap = 1 WHERE segment_index = 1"],
            "segment_boundary_mismatch",
        ),
        (
            ["UPDATE store_meta SET value = zeroblob(32) WHERE key = 'head_acceptance_digest'"],
            "head_acceptance_digest_mismatch",
        ),
        (
            ["UPDATE finalized_headers SET canonical_evidence = x'7b7d' WHERE height = 11"],
            "persisted_invalid_record_shape",
        ),
    ],
)
def test_streaming_audit_rejects_corrupt_history(
    tmp_path, observer, chain_observation, statements, reason
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer)
    with sqlite3.connect(tmp_path / "finality.sqlite3") as connection:
        for statement in statements:
            connection.execute(statement)
    with pytest.raises(GrandpaFinalityStoreCorruption, match=reason):
        port.audit()


@pytest.mark.parametrize("exceeded", [None, "headers", "evidence"])
def test_audit_scalar_limits_at_and_above_capacity(tmp_path, observer, chain_observation, exceeded):
    port = _port(tmp_path, observer, chain_observation)
    records = _audit_history(port, observer)
    sizes = [len(record.canonical_bytes) for record in records]
    port._limits = GrandpaFinalitySupervisorLimits(
        maximum_headers=len(records) - (exceeded == "headers"),
        maximum_evidence_bytes=max(sizes),
        maximum_total_evidence_bytes=sum(sizes) - (exceeded == "evidence"),
        maximum_records_per_process=2,
    )
    # Bind this fixture to its chosen exact budget before reopening the audit.
    config = port._config_bytes()
    with sqlite3.connect(tmp_path / "finality.sqlite3") as connection:
        connection.execute("UPDATE store_meta SET value = ? WHERE key = 'config'", (config,))
        connection.execute(
            "UPDATE store_meta SET value = ? WHERE key = 'config_sha256'",
            (hashlib.sha256(config).digest(),),
        )
    if exceeded is None:
        port.audit()
    else:
        reason = "header_count_limit" if exceeded == "headers" else "total_evidence_limit"
        with pytest.raises(GrandpaFinalityStoreCorruption, match=reason):
            port.audit()


def test_failed_streaming_audit_releases_its_snapshot(
    tmp_path, observer, chain_observation, monkeypatch
):
    audit_observer = copy(observer)
    reader = _port(tmp_path, audit_observer, chain_observation)
    records = _audit_history(reader, audit_observer, segment_lengths=(2,))
    writer = _port(tmp_path, observer, chain_observation)
    binding = writer.next_run_binding()
    third = _attestation(
        observer,
        binding,
        block=_header(12, parent_hash=records[-1].block.hash, seed=22),
        sequence=0,
        previous=None,
    )
    validate = audit_observer.validate_attestation
    replayed = []

    def fail_after_commit(*args, **kwargs):
        result = validate(*args, **kwargs)
        replayed.append(result.block.number)
        if len(replayed) == 2:
            writer.accept_attestation(binding, third)
            raise GrandpaFinalityObserverError("invalid_record_shape")
        return result

    with monkeypatch.context() as patch:
        patch.setattr(audit_observer, "validate_attestation", fail_after_commit)
        with pytest.raises(GrandpaFinalityStoreCorruption, match="persisted_invalid_record_shape"):
            reader.audit()
    assert replayed == [10, 11]
    with sqlite3.connect(tmp_path / "finality.sqlite3") as connection:
        assert connection.execute("PRAGMA wal_checkpoint(TRUNCATE)").fetchone() == (0, 0, 0)
    assert reader.persisted_head().height == 12
    reader.audit()


def test_streaming_audit_wraps_cursor_failure_and_closes_connection(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    _audit_history(port, observer, segment_lengths=(2,))
    connect, opened = port._connect, []

    @contextmanager
    def failing_read(*, read_only):
        assert read_only
        with connect(read_only=True) as connection:
            opened.append(connection)

            class FailingCursor:
                def __init__(self, cursor):
                    self.cursor, self.read = cursor, 0

                def __next__(self):
                    self.read += 1
                    if self.read == 2:
                        raise sqlite3.OperationalError("injected cursor failure")
                    return next(self.cursor)

            class FailingRead:
                def execute(self, sql, *args):
                    cursor = connection.execute(sql, *args)
                    if sql == "SELECT * FROM finalized_headers ORDER BY height":
                        return FailingCursor(cursor)
                    return cursor

            yield FailingRead()

    with monkeypatch.context() as patch:
        patch.setattr(port, "_connect", failing_read)
        with pytest.raises(GrandpaFinalityStoreCorruption, match="sqlite_read_failed"):
            port.audit()
    assert len(opened) == 1
    with pytest.raises(sqlite3.ProgrammingError, match="closed database"):
        opened[0].execute("SELECT 1")
    port.audit()


def test_acceptance_clock_rollback_is_rejected_before_insert(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    port = _port(tmp_path, observer, chain_observation)
    binding = port.next_run_binding()
    block10 = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    first = _attestation(observer, binding, block=block10, sequence=0, previous=None)
    monkeypatch.setattr(finality_supervisor.time, "time_ns", lambda: 2_000_000_000_000_000_000)
    port.accept_attestation(binding, first)

    block11 = _header(11, parent_hash=str(block10["hash"]), seed=21)
    second = _attestation(observer, binding, block=block11, sequence=1, previous=first)
    monkeypatch.setattr(finality_supervisor.time, "time_ns", lambda: 1_000_000_000_000_000_000)
    with pytest.raises(GrandpaFinalitySupervisorError, match="acceptance_clock_rollback"):
        port.accept_attestation(binding, second)
    assert port.persisted_head() is not None
    assert port.persisted_head().height == 10  # type: ignore[union-attr]


def test_concurrent_exact_acceptance_serializes_and_limit_failure_rolls_back(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    limits = GrandpaFinalitySupervisorLimits(
        maximum_headers=1,
        maximum_records_per_process=1,
    )
    port = _port(tmp_path, observer, chain_observation, limits=limits)
    second_port = _port(tmp_path, observer, chain_observation, limits=limits)
    binding = port.next_run_binding()
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    attestation = _attestation(observer, binding, block=block, sequence=0, previous=None)
    ports = (port, second_port) * 8
    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda candidate: candidate.accept_attestation(binding, attestation),
                ports,
            )
        )
    assert all(result == results[0] for result in results)

    next_binding = port.next_run_binding()
    next_block = _header(11, parent_hash=str(block["hash"]), seed=21)
    next_attestation = _attestation(
        observer, next_binding, block=next_block, sequence=0, previous=None
    )
    with pytest.raises(GrandpaFinalitySupervisorError, match="header_count_limit"):
        port.accept_attestation(next_binding, next_attestation)
    assert port.persisted_head() == results[0]
    port.audit()
    second_port.audit()


def test_blocking_supervisor_runs_multiple_segments_and_stops_promptly(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    port = _port(
        tmp_path,
        observer,
        chain_observation,
        limits=GrandpaFinalitySupervisorLimits(
            maximum_headers=100,
            maximum_records_per_process=1,
        ),
    )
    stop = threading.Event()
    failure: list[BaseException] = []

    def run() -> None:
        try:
            port.run_blocking(stop)
        except BaseException as error:  # pragma: no cover - asserted below
            failure.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        head = port.persisted_head()
        if head is not None and head.height >= 11:
            break
        time.sleep(0.02)
    else:
        stop.set()
        thread.join(timeout=2)
        pytest.fail("supervisor did not persist two observer segments")
    stop.set()
    thread.join(timeout=2)
    assert not thread.is_alive()
    assert failure == []
    assert port.persisted_head() is not None
    port.audit()


def test_subprocess_timeout_reaps_before_restart_and_shutdown_preserves_gap(
    tmp_path, chain_observation, monkeypatch
):
    binary = tmp_path / "stalled-observer"
    binary_hash = _write_observer(binary, stall_after_output=True, skip_minimum=11)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    selected = GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=binary_hash,
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=hashlib.sha256(b"{}").hexdigest(),
        expected_genesis_hash=f"0x{_GENESIS}",
        bootstrap_block_number=1,
        bootstrap_block_hash=f"0x{_BOOTSTRAP}",
        record_timeout_seconds=0.1,
        first_record_timeout_seconds=5,
    )
    port = _port(tmp_path, selected, chain_observation)
    stop, finished = threading.Event(), threading.Event()
    processes, bindings, failures = [], [], []
    popen, accept = subprocess.Popen, port.accept_attestation

    def spawn(*args, **kwargs):
        # Check the prior handle before starting its replacement. Calling poll()
        # here could reap it ourselves and conceal missing production cleanup.
        if processes:
            assert processes[-1].returncode is not None
        assert len(processes) < 2, "shutdown must not start a third observer"
        process = popen(*args, **kwargs)
        processes.append(process)
        return process

    def accepted(binding, attestation):
        head = accept(binding, attestation)
        bindings.append(binding)
        if len(bindings) == 2:
            stop.set()
        return head

    def run():
        try:
            port.run_blocking(stop)
        except BaseException as error:
            failures.append(error)
        finally:
            finished.set()

    monkeypatch.setattr(subprocess, "Popen", spawn)
    monkeypatch.setattr(port, "accept_attestation", accepted)
    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        assert finished.wait(15), "supervisor did not recover and stop"
        thread.join(timeout=5)
        assert not thread.is_alive()
        assert failures == []
        assert len(processes) == 2
        assert all(process.returncode is not None for process in processes)
        assert [(b.segment_index, b.minimum_finalized_block) for b in bindings] == [
            (0, 10),
            (1, 11),
        ]
        head = port.persisted_head()
        assert head is not None and head.height == 12 and head.restart_gap_before
        assert asyncio.run(port.verified_block_at(11)) is None
        assert asyncio.run(port.verified_scan_interval(11, 12)) is None
        assert port.next_run_binding().segment_index == 2
        port.audit()
    finally:
        stop.set()
        thread.join(timeout=5)
        # Keep failed assertions from leaving fixture children behind. Assertions
        # above require production to reap both handles before this fallback.
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
        thread.join(timeout=5)


def test_timeout_recovery_advances_persisted_head_without_inventing_gap_ancestry(
    tmp_path, observer, chain_observation, monkeypatch, caplog
):
    port = _port(tmp_path, observer, chain_observation)
    stop = threading.Event()
    bindings = []
    waits = []
    finalized = []

    def attestations(**kwargs):
        binding = port.next_run_binding()
        assert kwargs["minimum_finalized_block"] == binding.minimum_finalized_block
        assert len(finalized) == len(bindings), "old iterator must close before replacement"
        bindings.append(binding)
        block = _header(10 if len(bindings) == 1 else 12, parent_hash="0x" + "11" * 32, seed=20)
        try:
            yield _attestation(observer, binding, block=block, sequence=0, previous=None)
            if len(bindings) == 1:
                raise GrandpaFinalityObserverError("record_timeout")
            stop.set()
        finally:
            finalized.append(binding.segment_index)

    monkeypatch.setattr(observer, "attestations", attestations)
    monkeypatch.setattr(stop, "wait", lambda seconds: waits.append(seconds) or False)
    port.run_blocking(stop)
    assert [(b.segment_index, b.minimum_finalized_block) for b in bindings] == [(0, 10), (1, 11)]
    assert waits == [1.0]
    assert finalized == [0, 1]
    head = port.persisted_head()
    assert head is not None and head.height == 12 and head.restart_gap_before
    assert "finality_observer_record_timeout" in caplog.text
    assert asyncio.run(port.verified_block_at(11)) is None
    assert asyncio.run(port.verified_scan_interval(11, 12)) is None
    port.audit()


def test_timeout_recovery_bounds_backoff_and_stop_interrupts_it(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    stop = threading.Event()
    waits = []
    attempts = []

    def attestations(**kwargs):
        attempts.append(kwargs["minimum_finalized_block"])
        raise GrandpaFinalityObserverError("record_timeout")
        yield  # pragma: no cover - keep the test double an iterator

    def wait(seconds):
        waits.append(seconds)
        if len(waits) == 8:
            stop.set()
        return stop.is_set()

    monkeypatch.setattr(observer, "attestations", attestations)
    monkeypatch.setattr(stop, "wait", wait)
    port.run_blocking(stop)
    assert waits == [1.0, 2.0, 4.0, 8.0, 16.0, 30.0, 30.0, 30.0]
    assert attempts == [10] * 8
    assert port.persisted_head() is None
    assert port._run_lock.acquire(blocking=False)
    port._run_lock.release()


@pytest.mark.parametrize(
    "reason", ["observer_failed", "record_size_limit", "invalid_json", "record_count_mismatch"]
)
def test_non_timeout_observer_faults_remain_terminal(
    tmp_path, observer, chain_observation, monkeypatch, reason
):
    port = _port(tmp_path, observer, chain_observation)
    stop = threading.Event()
    calls = []

    def attestations(**kwargs):
        calls.append(kwargs)
        raise GrandpaFinalityObserverError(reason)
        yield  # pragma: no cover

    monkeypatch.setattr(observer, "attestations", attestations)
    with pytest.raises(GrandpaFinalitySupervisorError, match="observer_" + reason):
        port.run_blocking(stop)
    assert len(calls) == 1
    assert port.persisted_head() is None


@pytest.mark.parametrize("cancel_again", [False, True])
async def test_cancellation_waits_for_owned_observer_cleanup(
    tmp_path, observer, chain_observation, monkeypatch, cancel_again
):
    port = _port(tmp_path, observer, chain_observation)
    entered, cleaning = asyncio.Event(), asyncio.Event()
    finish_cleanup, finished = threading.Event(), threading.Event()
    loop = asyncio.get_running_loop()

    def blocking_run(stop):
        loop.call_soon_threadsafe(entered.set)
        stop.wait(3)
        loop.call_soon_threadsafe(cleaning.set)
        finish_cleanup.wait(3)
        finished.set()

    monkeypatch.setattr(port, "run_blocking", blocking_run)
    running = asyncio.create_task(port.run(asyncio.Event()))
    try:
        await asyncio.wait_for(entered.wait(), timeout=3)
        running.cancel()
        await asyncio.wait_for(cleaning.wait(), timeout=3)
        assert not running.done(), "shutdown must wait for the owned process to finish cleanup"
        if cancel_again:
            running.cancel()
            await asyncio.sleep(0)
            assert not running.done()
        finish_cleanup.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(running, timeout=3)
        assert finished.is_set()
    finally:
        finish_cleanup.set()
        await asyncio.gather(running, return_exceptions=True)
        await asyncio.to_thread(finished.wait, 3)


def test_timeout_backoff_resets_only_after_committed_progress(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    stop, waits, calls = threading.Event(), [], []

    def attestations(**kwargs):
        calls.append(kwargs)
        if len(calls) == 3:
            binding = port.next_run_binding()
            block = _header(10, parent_hash="0x" + "11" * 32, seed=20)
            yield _attestation(observer, binding, block=block, sequence=0, previous=None)
        elif len(calls) == 4:
            stop.set()
            return
        raise GrandpaFinalityObserverError("record_timeout")

    monkeypatch.setattr(observer, "attestations", attestations)
    monkeypatch.setattr(stop, "wait", lambda delay: waits.append(delay) or False)
    port.run_blocking(stop)
    assert waits == [1.0, 2.0, 1.0]
    assert [c["minimum_finalized_block"] for c in calls] == [10, 10, 10, 11]
    port.audit()


def test_database_symlink_is_rejected(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    target = tmp_path / "target.sqlite3"
    target.write_bytes(b"")
    target.chmod(0o600)
    link = tmp_path / "link.sqlite3"
    os.symlink(target, link)
    with pytest.raises(GrandpaFinalitySupervisorError, match="unsafe_database_path"):
        _port(tmp_path, observer, chain_observation, state_name="link.sqlite3")


@pytest.mark.asyncio
async def test_async_supervisor_honors_preexisting_stop(
    tmp_path: Path,
    observer: GrandpaFinalityObserver,
    chain_observation: LiveChainObservationPin,
) -> None:
    port = _port(tmp_path, observer, chain_observation)
    stop = asyncio.Event()
    stop.set()
    await asyncio.wait_for(port.run(stop), timeout=1)
    assert port.persisted_head() is None
