"""Child-visible synthetic trie/SCALE tools for native spawned reader tests.

Only the cryptographic primitive and SCALE interpreter are fixtures. Archive
parsing, runtime pin/code bindings, native scanning, effects, ownership and
checkpoint/reward consumers execute their production implementations.
"""

import asyncio
import hashlib
import json
import os
import socket
import time
from dataclasses import replace
from pathlib import Path

import bittensor_core

from umi import competition_reward_history_workers as workers
from umi.concurrency import run_owned_thread
from umi.protocol import canonical_json_bytes
from umi.runtime_metadata import RuntimeMetadataExecutor
from umi.substrate_proof import SubprocessStorageProofVerifier

from .test_competition_chain import _Runtime
from .test_validator_chain_scan import Entry

_fixture = None


class FixtureCodec(_Runtime):
    def __init__(self, raw, spec, transaction, *, ss58_format):
        assert (raw, spec, transaction, ss58_format) in _fixture["metadata"]
        self.spec_version, self.transaction_version = spec, transaction

    def storage_key(self, pallet, item, params):
        if (pallet, item) == ("System", "Events"):
            return b"system-events-key"
        return super().storage_key(pallet, item, params)

    def storage_entry(self, pallet, item):
        if (pallet, item) == ("System", "Events"):
            return Entry()
        return super().storage_entry(pallet, item)

    def decode(self, value_type, data, *, strict):
        if value_type == "Vec<EventRecord>":
            assert strict
            return _fixture["events"][data]
        return super().decode(value_type, data, strict=strict)

    def decode_extrinsic(self, raw, strict=True):
        assert strict
        return _fixture["calls"][raw]


class FixtureVerifier:
    def verify_many(self, *, state_root, items, proof, **_):
        return bool(items) and all(
            self(storage_key=k, expected_value=v, state_root=state_root, proof=proof)
            for k, v in items
        )

    def __call__(self, *, state_root, storage_key, expected_value, proof, **_):
        return _fixture["storage"].get((state_root, storage_key)) == (expected_value, proof)

    def verify_extrinsics_root(self, *, expected_root, extrinsics, state_version):
        return state_version == 0 and _fixture["bodies"].get(expected_root) == extrinsics


def invoke_executor(self, code):
    metadata, spec, transaction, state = _fixture["code"][code]
    return (
        canonical_json_bytes(
            {
                "schema": "umi-runtime-metadata-execution/1",
                "runtime_code_sha256": hashlib.sha256(code).hexdigest(),
                "metadata_sha256": hashlib.sha256(metadata).hexdigest(),
                "metadata_hex": metadata.hex(),
                "spec_version": spec,
                "transaction_version": transaction,
                "state_version": state,
                "chain_submission_authorized": False,
            }
        )
        + b"\n"
    )


async def _guarded_work(work):
    delay = _fixture.get("delay", {}).get(work.snapshot.block_number, 0)
    if delay:
        # Deliberately block only this spawned interpreter, proving other
        # blocks progress independently of its CPU/GIL scheduling.
        time.sleep(delay)
    orphan = _fixture.get("orphan_native", {}).get(work.snapshot.block_number)
    if orphan is not None:
        tool = object.__new__(SubprocessStorageProofVerifier)
        tool._timeout_seconds = 5.0
        from functools import partial

        invocation = asyncio.create_task(
            run_owned_thread(
                partial(tool._exchange_staged, Path(orphan[0]), b"{}", maximum_response_bytes=4096)
            )
        )
        for _ in range(1000):
            if Path(orphan[1]).exists():
                os._exit(9)
            if invocation.done():
                invocation.result()
                raise AssertionError("native crash fixture exited before observation")
            await asyncio.sleep(0.005)
        raise AssertionError("native crash fixture never started")
    if work.snapshot.block_number in _fixture.get("crash", ()):
        os._exit(9)
    result = await _verify_work(work)
    if work.snapshot.block_number in _fixture.get("wrong_result", ()):
        return replace(result, request_id="wrong-private-invocation")
    return result


def initialize(selection, fixture):
    global _fixture, _verify_work
    _fixture = fixture
    SubprocessStorageProofVerifier._assert_binary_integrity = lambda self: None
    workers._initialize_worker(selection)
    # Every runtime/slot/body/effect check is shared with the serial wrapper.
    # The child has its own primitive fixtures and never receives a provider.
    verifier = FixtureVerifier()
    workers._tools.proofs._verifier = verifier
    if workers._tools.runtime_proofs is not None:
        workers._tools.runtime_proofs._verifier = verifier
    bittensor_core.Runtime = FixtureCodec
    RuntimeMetadataExecutor._invoke = invoke_executor
    _verify_work = workers._verify_work
    workers._verify_work = _guarded_work

    def forbidden(*_args, **_kwargs):
        raise AssertionError("spawned verifier attempted network access")

    socket.create_connection = forbidden
    socket.socket.connect = forbidden


def fixture_data(observations, decoded, events):
    from umi.grandpa_finality import _decode_header

    fixture = {
        "metadata": set(),
        "storage": {},
        "bodies": {},
        "calls": decoded,
        "events": events,
        "code": {},
    }
    for slot_raw, metadata, writes_raw in observations:
        slot, writes = json.loads(slot_raw), json.loads(writes_raw)
        version = slot["runtime_version"]
        fixture["metadata"].add(
            (metadata, version["specVersion"], version["transactionVersion"], 42)
        )
        root = bytes.fromhex(slot["state_root"][2:])
        proof = tuple(bytes.fromhex(v[2:]) for v in slot["proof"])
        for claim in slot["claims"]:
            fixture["storage"][root, bytes.fromhex(claim["key"][2:])] = (
                None if claim["value"] is None else bytes.fromhex(claim["value"][2:]),
                proof,
            )
        child = _decode_header(writes["header"], maximum_bytes=1024**2)
        fixture["bodies"][bytes.fromhex(child["extrinsics_root"][2:])] = tuple(
            bytes.fromhex(v) for v in writes["extrinsics"]
        )
        event = writes["events"]
        fixture["storage"][root, bytes.fromhex(event["key"])] = (
            None if event["value"] is None else bytes.fromhex(event["value"]),
            tuple(bytes.fromhex(v) for v in event["proof"]),
        )
        parent_metadata = bytes.fromhex(writes["runtime_metadata"])
        parent_version = json.loads(bytes.fromhex(writes["runtime_version"]))
        fixture["metadata"].add(
            (
                parent_metadata,
                parent_version["specVersion"],
                parent_version["transactionVersion"],
                42,
            )
        )
        for body, meta, ver in (
            (slot, metadata, version),
            (writes, parent_metadata, parent_version),
        ):
            execution = body["runtime_execution"]
            if execution is not None:
                code = bytes.fromhex(execution["value"][2:])
                code_proof = tuple(bytes.fromhex(v[2:]) for v in execution["proof"])
                fixture["storage"][bytes.fromhex(execution["state_root"][2:]), b":code"] = (
                    code,
                    code_proof,
                )
                fixture["code"][code] = (
                    meta,
                    ver["specVersion"],
                    ver["transactionVersion"],
                    ver.get("stateVersion", 1),
                )
    return fixture
