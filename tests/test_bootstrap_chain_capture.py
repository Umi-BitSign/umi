from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from pathlib import Path

import pytest

from tests.test_bootstrap_result_intake import _finality, _signed_result
from tests.test_grandpa_finality_supervisor import _attestation, _header
from umi.bootstrap_chain_capture import (
    BootstrapChainCaptureError,
    BootstrapChainCollector,
    DurableOwnedFinalityReader,
    OwnedFinalityEvidence,
    _captured_header,
    collect_bootstrap_chain_capture,
    write_new_chain_capture,
)
from umi.bootstrap_result_intake import parse_canonical_chain_capture
from umi.chain import _header_hash
from umi.grandpa_finality import (
    CARGO_LOCK_SHA256,
    EVIDENCE_CLASS,
    FINNEY_BOOTSTRAP_BLOCK_HASH,
    FINNEY_BOOTSTRAP_BLOCK_NUMBER,
    FINNEY_GENESIS_HASH,
    FIXTURE_SET_SHA256,
    SOURCE_REVISION,
    SOURCE_TREE_SHA256,
    GrandpaFinalityObserver,
)
from umi.grandpa_finality_supervisor import (
    _SCHEMA_STATEMENTS,
    STORE_SCHEMA,
    STORE_SCHEMA_VERSION,
    DurableGrandpaFinalityPort,
    GrandpaFinalitySupervisorLimits,
    parse_finality_acceptance_receipt,
)
from umi.policy import LiveChainObservationPin
from umi.protocol import canonical_json_bytes
from umi.validator_chain_scan import FinalityAttestationReplayBinding


def _rpc_header(number: int, parent_hash: str, seed: int) -> tuple[str, dict[str, object]]:
    value: dict[str, object] = {
        "number": hex(number),
        "parentHash": parent_hash,
        "stateRoot": "0x" + f"{seed:02x}" * 32,
        "extrinsicsRoot": "0x" + f"{seed + 1:02x}" * 32,
        "digest": {"logs": []},
    }
    normalized = {**value, "number": number}
    return _header_hash(normalized, "test capture header"), value


def _header_chain(start: int, end: int) -> tuple[dict[int, str], dict[str, dict[str, object]]]:
    hashes: dict[int, str] = {}
    headers: dict[str, dict[str, object]] = {}
    parent = "0x" + "11" * 32
    for number in range(start, end + 1):
        block_hash, header = _rpc_header(number, parent, (number % 200) + 1)
        hashes[number] = block_hash
        headers[block_hash] = header
        parent = block_hash
    return hashes, headers


class _Rpc:
    def __init__(
        self,
        hashes: dict[int, str],
        headers: dict[str, dict[str, object]],
    ) -> None:
        self.hashes = hashes
        self.headers = headers
        self.calls: list[tuple[str, tuple[object, ...]]] = []

    async def request(self, method: str, params):
        params = tuple(params)
        self.calls.append((method, params))
        if method == "chain_getBlockHash":
            return self.hashes[params[0]]
        if method == "chain_getHeader":
            return self.headers[params[0]]
        if method == "chain_getBlock":
            return {
                "block": {
                    "header": self.headers[params[0]],
                    "extrinsics": ["0x01", "0x0203", "0x040506"],
                },
                "justifications": None,
            }
        if method == "state_getRuntimeVersion":
            return {"specVersion": 455, "stateVersion": 1, "transactionVersion": 1}
        if method == "state_getMetadata":
            return "0x6d65746164617461"
        if method == "state_getStorageAt":
            return "0x6576656e7473"
        if method == "state_getReadProof":
            return {"at": params[1], "proof": ["0x0102", "0x0304"]}
        raise AssertionError(method)


class _Finality:
    def __init__(self, header, ancestry: tuple[tuple[int, str, str], ...]) -> None:
        carried = _finality(header, "weight_call")
        self.evidence = OwnedFinalityEvidence(
            attested_header=header,
            ancestry=ancestry,
            attestation=bytes.fromhex(carried.attestation_hex[2:]),
            replay_binding=FinalityAttestationReplayBinding(
                minimum_finalized_block=1,
                maximum_records=1,
                startup_timeout_seconds=10,
                expected_sequence=0,
                previous_number=None,
                previous_timestamp_ms=None,
            ),
            acceptance_receipt=bytes.fromhex(carried.acceptance_receipt_hex[2:]),
        )
        self.calls: list[tuple[int, int]] = []

    async def evidence_at_or_after(self, minimum_height: int, maximum_height: int):
        self.calls.append((minimum_height, maximum_height))
        assert minimum_height <= self.evidence.attested_header.number <= maximum_height
        return self.evidence


def _captured(number: int, hashes, headers):
    return _captured_header(
        headers[hashes[number]],
        expected_number=number,
        expected_hash=hashes[number],
        reason_prefix="test",
    )


@pytest.mark.asyncio
async def test_collects_three_complete_blocks_with_parent_runtime_and_finality_bridge() -> None:
    hashes, headers = _header_chain(119, 132)
    signed = _signed_result(hashes[126], hashes[130])
    owner = canonical_json_bytes(
        {
            "success": True,
            "message": "Success",
            "block_hash": hashes[120],
            "extrinsic_id": "120-0000",
        }
    )
    attested = _captured(132, hashes, headers)
    finality = _Finality(
        attested,
        ((attested.number, attested.block_hash, attested.parent_hash),),
    )
    rpc = _Rpc(hashes, headers)
    capture = await collect_bootstrap_chain_capture(
        signed_result_bytes=canonical_json_bytes(signed),
        owner_cli_response_bytes=owner,
        rpc=rpc,
        finality=finality,
        preserved_owner_rpc_capture=b"original owner RPC bytes\n",
        runtime_key_factory=lambda _metadata, _version: b"\x01\x02",
        bridge_concurrency=3,
    )

    assert parse_canonical_chain_capture(canonical_json_bytes(capture)) == capture
    assert [block.role for block in capture.blocks] == [
        "owner_fence",
        "manifest_anchor",
        "weight_call",
    ]
    assert [len(block.finality.descendant_headers) for block in capture.blocks] == [12, 6, 2]
    assert capture.blocks[0].finality.descendant_headers[0].number == 121
    assert capture.blocks[-1].finality.descendant_headers[-1] == attested
    assert all(
        block.runtime.execution_parent_header.number + 1 == block.header.number
        for block in capture.blocks
    )
    raw_owner = json.loads(bytes.fromhex(capture.blocks[0].raw_rpc_capture_hex[2:]))
    assert bytes.fromhex(raw_owner["preserved_source"]["bytes_hex"][2:]) == (
        b"original owner RPC bytes\n"
    )
    assert [item["method"] for item in raw_owner["rpc_calls"]] == [
        "chain_getBlockHash",
        "chain_getHeader",
        "chain_getBlockHash",
        "chain_getHeader",
        "chain_getBlock",
        "state_getRuntimeVersion",
        "state_getMetadata",
        "state_getStorageAt",
        "state_getReadProof",
    ]
    assert raw_owner["rpc_calls"][5]["params"] == [hashes[119]]
    assert raw_owner["rpc_calls"][7]["params"] == ["0x0102", hashes[120]]


@pytest.mark.asyncio
async def test_rejects_signed_target_when_canonical_height_has_another_hash() -> None:
    hashes, headers = _header_chain(119, 132)
    signed = _signed_result(hashes[126], hashes[130])
    owner = canonical_json_bytes(
        {
            "success": True,
            "message": "Success",
            "block_hash": hashes[120],
            "extrinsic_id": "120-0000",
        }
    )
    rpc = _Rpc(dict(hashes), headers)
    rpc.hashes[126] = hashes[125]
    attested = _captured(132, hashes, headers)
    finality = _Finality(
        attested,
        ((attested.number, attested.block_hash, attested.parent_hash),),
    )
    with pytest.raises(BootstrapChainCaptureError):
        await collect_bootstrap_chain_capture(
            signed_result_bytes=canonical_json_bytes(signed),
            owner_cli_response_bytes=owner,
            rpc=rpc,
            finality=finality,
            runtime_key_factory=lambda _metadata, _version: b"\x01\x02",
        )


@pytest.mark.asyncio
async def test_finality_attestation_that_contains_target_needs_no_rpc_bridge() -> None:
    hashes, headers = _header_chain(119, 132)
    target = _captured(130, hashes, headers)
    attested = _captured(132, hashes, headers)
    finality = _Finality(
        attested,
        (
            (target.number, target.block_hash, target.parent_hash),
            (attested.number, attested.block_hash, attested.parent_hash),
        ),
    )
    collector = BootstrapChainCollector(
        rpc=_Rpc(hashes, headers),
        finality=finality,
        runtime_key_factory=lambda _metadata, _version: b"\x01\x02",
    )
    block = await collector._collect_block(
        type(
            "Target",
            (),
            {
                "role": "weight_call",
                "block_number": 130,
                "block_hash": hashes[130],
                "extrinsic_index": 2,
            },
        )(),
        preserved_source=None,
    )
    assert block.finality.descendant_headers == []


def test_capture_output_is_canonical_create_only_and_mode_0600(tmp_path: Path) -> None:
    # A schema-valid capture is sufficient to exercise the write boundary.
    from tests.test_bootstrap_result_intake import _case

    _signed, _owner, encoded, _ports = _case()
    capture = parse_canonical_chain_capture(encoded)
    target = tmp_path / "capture.json"
    write_new_chain_capture(target, capture)
    assert target.read_bytes() == canonical_json_bytes(capture)
    assert stat_mode(target) == 0o600
    with pytest.raises(BootstrapChainCaptureError, match="already_exists"):
        write_new_chain_capture(target, capture)


def stat_mode(path: Path) -> int:
    return os.stat(path).st_mode & 0o777


def test_durable_reader_rejects_empty_or_replaced_store_without_mutating_it(
    tmp_path: Path,
) -> None:
    binary = tmp_path / "observer"
    binary.write_bytes(b"#!/bin/sh\nexit 1\n")
    binary.chmod(0o500)
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    state = tmp_path / "finality.sqlite3"
    limits = {
        "maximum_headers": 100,
        "maximum_evidence_bytes": 4 * 1024 * 1024,
        "maximum_total_evidence_bytes": 64 * 1024 * 1024,
        "maximum_database_bytes": 128 * 1024 * 1024,
        "maximum_records_per_process": 100,
    }
    config = {
        "schema": STORE_SCHEMA,
        "scoring_policy_hash": "44" * 32,
        "chain_observation": {
            "network": "finney",
            "genesis_block_hash": (
                "2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
            ),
        },
        "finality_verifier_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "observer": {
            "evidence_class": EVIDENCE_CLASS,
            "offline_finality_proof": False,
            "source_revision": SOURCE_REVISION,
            "source_tree_sha256": SOURCE_TREE_SHA256,
            "cargo_lock_sha256": CARGO_LOCK_SHA256,
            "fixture_set_sha256": FIXTURE_SET_SHA256,
            "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "chain_spec_sha256": hashlib.sha256(b"{}").hexdigest(),
            "genesis_hash": ("0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"),
            "bootstrap_block_number": 1,
            "bootstrap_block_hash": "0x" + "77" * 32,
        },
        "initial_minimum_finalized_block": 2,
        "startup_timeout_seconds": 10,
        "limits": limits,
    }
    encoded = canonical_json_bytes(config)
    with sqlite3.connect(state) as connection:
        for statement in _SCHEMA_STATEMENTS:
            connection.execute(statement)
        connection.execute("PRAGMA application_id = 1431128390")
        connection.execute(f"PRAGMA user_version = {STORE_SCHEMA_VERSION}")
        connection.executemany(
            "INSERT INTO store_meta(key, value) VALUES (?, ?)",
            (
                ("config", encoded),
                ("config_sha256", hashlib.sha256(encoded).digest()),
                ("head_acceptance_digest", bytes(32)),
            ),
        )
    state.chmod(0o600)
    before = state.read_bytes()
    reader = DurableOwnedFinalityReader(
        state_path=state.absolute(),
        finality_verifier=binary,
        chain_spec=chain_spec,
    )
    with pytest.raises(BootstrapChainCaptureError, match="owned_finality_head_unavailable"):
        reader._read_evidence(2, 4)
    assert state.read_bytes() == before


@pytest.mark.asyncio
async def test_durable_reader_replays_one_owned_finney_attestation(tmp_path: Path) -> None:
    binary = tmp_path / "observer"
    binary.write_bytes(b"#!/bin/sh\nexit 1\n")
    binary.chmod(0o500)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    chain_spec = tmp_path / "finney.json"
    chain_spec.write_bytes(b"{}")
    chain_spec.chmod(0o400)
    observer = GrandpaFinalityObserver(
        binary_path=binary,
        expected_binary_sha256=binary_sha256,
        chain_spec_path=chain_spec,
        expected_chain_spec_sha256=hashlib.sha256(b"{}").hexdigest(),
        expected_genesis_hash="0x" + FINNEY_GENESIS_HASH,
        bootstrap_block_number=FINNEY_BOOTSTRAP_BLOCK_NUMBER,
        bootstrap_block_hash="0x" + FINNEY_BOOTSTRAP_BLOCK_HASH,
    )
    state = tmp_path / "owned-finality.sqlite3"
    port = DurableGrandpaFinalityPort(
        observer=observer,
        state_path=state,
        scoring_policy_digest="44" * 32,
        chain_observation=LiveChainObservationPin(
            network="finney",
            genesis_block_hash=FINNEY_GENESIS_HASH,
            runtime_spec_version=455,
            transaction_version=1,
            state_version=1,
            metadata_sha256="55" * 32,
            subtensor_revision="runtime-spec-455-test",
            live_chain_fixture_set_sha256="66" * 32,
        ),
        finality_verifier_sha256=binary_sha256,
        initial_minimum_finalized_block=FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1,
        startup_timeout_seconds=10,
        limits=GrandpaFinalitySupervisorLimits(maximum_records_per_process=2),
    )
    binding = port.next_run_binding()
    raw_header = _header(
        FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1,
        parent_hash="0x" + FINNEY_BOOTSTRAP_BLOCK_HASH,
        seed=20,
    )
    accepted = _attestation(
        observer,
        binding,
        block=raw_header,
        sequence=0,
        previous=None,
    )
    port.accept_attestation(binding, accepted)

    reader = DurableOwnedFinalityReader(
        state_path=state.absolute(),
        finality_verifier=binary,
        chain_spec=chain_spec,
    )
    evidence = await reader.evidence_at_or_after(
        FINNEY_BOOTSTRAP_BLOCK_NUMBER + 1,
        FINNEY_BOOTSTRAP_BLOCK_NUMBER + 2,
    )
    assert evidence.attested_header.block_hash == accepted.block.hash
    assert evidence.ancestry == accepted.ancestry
    assert hashlib.sha256(evidence.attestation).hexdigest() == (
        parse_finality_acceptance_receipt(evidence.acceptance_receipt).evidence_sha256
    )
