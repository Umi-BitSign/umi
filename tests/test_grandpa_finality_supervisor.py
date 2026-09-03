from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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


def _write_observer(path: Path) -> str:
    source = f'''#!{sys.executable}
import hashlib
import json
import rfc8785
import sys

config = json.load(sys.stdin)
target = config["minimum_finalized_block"]
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
    binding = port.next_run_binding()
    block = _header(10, parent_hash=f"0x{'11' * 32}", seed=20)
    attestation = _attestation(observer, binding, block=block, sequence=0, previous=None)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                lambda _index: port.accept_attestation(binding, attestation),
                range(2),
            )
        )
    assert results[0] == results[1]

    next_binding = port.next_run_binding()
    next_block = _header(11, parent_hash=str(block["hash"]), seed=21)
    next_attestation = _attestation(
        observer, next_binding, block=next_block, sequence=0, previous=None
    )
    with pytest.raises(GrandpaFinalitySupervisorError, match="header_count_limit"):
        port.accept_attestation(next_binding, next_attestation)
    assert port.persisted_head() == results[0]
    port.audit()


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
