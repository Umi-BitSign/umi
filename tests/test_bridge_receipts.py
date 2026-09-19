"""Synthetic authenticated-history fixtures; no network or live signing."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import threading
from types import SimpleNamespace

import pytest

from tests.test_bridge_transactions import ENCODED, signed
from tests.test_bridge_transactions import case as case
from tests.test_bridge_transactions import signed_policy as signed_policy
from tests.test_bridge_transactions import tx as tx
from umi.bridge.policy import RegistrationBridgeError
from umi.bridge.receipts import BridgeReceiptReader, retain_verified_receipt
from umi.bridge.transactions import evolve_journal
from umi.chain import _header_hash


@pytest.fixture
def history(tx, monkeypatch):
    import umi.runtime_metadata as metadata

    old_codec = metadata.bittensor_core.Runtime

    class Codec(old_codec):
        def storage_key(self, pallet, name, params):
            assert (pallet, name, params) == ("System", "Events", [])
            return b"System.Events"

        def storage_entry(self, pallet, name):
            assert (pallet, name) == ("System", "Events")
            return SimpleNamespace(modifier="Default", default_bytes=b"[]", value_type=name)

    monkeypatch.setattr(metadata.bittensor_core, "Runtime", Codec)
    birth = tx.preparing.attempt.preflight_block
    item = SimpleNamespace(
        birth=birth,
        headers={},
        bodies={},
        hashes={},
        values={},
        calls=[],
        verified=[],
        journal=evolve_journal(signed(tx), phase="submitting"),
        rejected_body=False,
        rejected_events=False,
        rejected_code=False,
        fail_call=False,
        heads=0,
    )
    parent = tx.case.header["parentHash"]
    for number in range(birth, birth + 201):
        body = (b"inherent", ENCODED if number == birth + 2 else b"unrelated")
        state_root = (
            tx.case.header["stateRoot"]
            if number == birth
            else "0x" + hashlib.sha256(str(number).encode()).hexdigest()
        )
        root = (
            tx.case.header["extrinsicsRoot"]
            if number == birth
            else "0x" + hashlib.sha256(b"".join(body)).hexdigest()
        )
        header = dict(
            number=number,
            parentHash=parent,
            stateRoot=state_root,
            extrinsicsRoot=root,
            digest={"logs": []},
        )
        block_hash = _header_hash(header, "test")
        item.hashes[number] = block_hash
        item.headers[block_hash] = {**header, "number": hex(number)}
        item.bodies[block_hash] = body
        events = [
            dict(
                module_id="System",
                event_id="ExtrinsicSuccess",
                phase="ApplyExtrinsic",
                extrinsic_idx=index,
            )
            for index in range(2)
        ]
        item.values[state_root] = {
            b":code": f"wasm-at-{number}".encode(),
            b"System.Events": json.dumps(events).encode(),
        }
        parent = block_hash
    assert item.hashes[birth] == tx.preparing.attempt.preflight_block_hash
    item.head = birth + 7

    class Finality:
        async def read_finalized_identity(self):
            item.heads += 1
            return SimpleNamespace(number=item.head, block_hash=item.hashes[item.head])

    class Rpc:
        async def request(self, method, params):
            item.calls.append((method, params))
            if method == "chain_getHeader":
                return copy.deepcopy(item.headers[params[0]])
            if method == "chain_getBlock":
                block_hash = params[0]
                return {
                    "block": {
                        "header": copy.deepcopy(item.headers[block_hash]),
                        "extrinsics": ["0x" + v.hex() for v in item.bodies[block_hash]],
                    }
                }
            if method == "state_getStorageAt":
                key, block_hash = params
                state_root = item.headers[block_hash]["stateRoot"]
                return "0x" + item.values[state_root][bytes.fromhex(key[2:])].hex()
            if method == "state_getReadProof":
                return {"at": params[1], "proof": ["0x" + b"fixture".hex()]}
            pytest.fail(f"unexpected RPC: {method}")

    class Verifier:
        def __call__(self, *, state_root, storage_key, expected_value, proof):
            item.verified.append(("storage", storage_key, state_root))
            if item.rejected_code and storage_key == b":code":
                return False
            if item.rejected_events and storage_key == b"System.Events":
                return False
            return (
                proof == (b"fixture",)
                and item.values["0x" + state_root.hex()][storage_key] == expected_value
            )

        def verify_extrinsics_root(self, *, expected_root, extrinsics, state_version):
            item.verified.append(("body", extrinsics, expected_root))
            return (
                not item.rejected_body
                and state_version == 1
                and hashlib.sha256(b"".join(extrinsics)).digest() == expected_root
            )

    item.rpc, item.finality, item.verifier = Rpc(), Finality(), Verifier()
    item.reader = BridgeReceiptReader(
        finality=item.finality,
        rpc=item.rpc,
        verifier=item.verifier,
        runtime_executor=tx.case.executor,
    )
    return item


@pytest.mark.asyncio
@pytest.mark.parametrize("successful", [True, False])
async def test_exact_inclusion_and_dispatch_failure_are_distinct(history, tx, successful):
    block_hash = history.hashes[history.birth + 2]
    values = history.values[history.headers[block_hash]["stateRoot"]]
    events = json.loads(values[b"System.Events"])
    events[1]["event_id"] = "ExtrinsicSuccess" if successful else "ExtrinsicFailed"
    values[b"System.Events"] = json.dumps(events).encode()
    result = await history.reader.find(history.journal)
    assert result.successful is successful
    assert result.receipt.block_hash == block_hash
    assert result.receipt.extrinsic_index == 1
    assert result.signed_extrinsic_hash == history.journal.signed_extrinsic_hash
    assert result.owned_head.block_number == history.head
    # The parent executes this block, even when :code changes in the child.
    assert tx.case.executed[-1] == f"wasm-at-{history.birth + 1}".encode()
    calls = len(history.calls)
    assert await history.reader.find(history.journal) == result
    assert len(history.calls) == calls


@pytest.mark.asyncio
@pytest.mark.parametrize("target", ["owned", "ancestor", "preflight"])
async def test_altered_header_never_reaches_body_or_runtime(history, tx, target):
    number = {"owned": history.head, "ancestor": history.birth + 1, "preflight": history.birth}[
        target
    ]
    history.headers[history.hashes[number]]["stateRoot"] = "0x" + "99" * 32
    with pytest.raises(RegistrationBridgeError, match="header_mismatch"):
        await history.reader.find(history.journal)
    assert not history.verified and tx.case.executed == [b"verified wasm"]


@pytest.mark.asyncio
@pytest.mark.parametrize("proof", ["body", "code", "events"])
async def test_unverified_body_runtime_or_events_cannot_return_receipt(history, proof):
    setattr(history, "rejected_" + proof, True)
    with pytest.raises(RuntimeError, match=r"root_invalid|storage_proof_verification_failed"):
        await history.reader.find(history.journal)
    assert history.reader._found is None


@pytest.mark.asyncio
async def test_modified_encoded_body_is_rejected_before_event_decode(history):
    block_hash = history.hashes[history.birth + 1]
    history.bodies[block_hash] = (b"inherent", ENCODED)
    with pytest.raises(RegistrationBridgeError, match="body_root_invalid"):
        await history.reader.find(history.journal)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["missing", "duplicate", "bad_phase", "bool_index"])
async def test_status_coverage_must_be_complete_and_unambiguous(history, change):
    values = history.values[history.headers[history.hashes[history.birth + 2]]["stateRoot"]]
    events = json.loads(values[b"System.Events"])
    if change == "missing":
        events.pop()
    elif change == "duplicate":
        events.append(events[1])
    elif change == "bad_phase":
        events[1]["phase"] = "Finalization"
    else:
        events[1]["extrinsic_idx"] = True
    values[b"System.Events"] = json.dumps(events).encode()
    with pytest.raises(RuntimeError, match="extrinsic_status"):
        await history.reader.find(history.journal)


@pytest.mark.asyncio
async def test_long_outage_resumes_hash_walk_after_timeout_without_growing_era_cache(history):
    history.head = history.birth + 200
    history.reader._timeout = 1
    request = history.rpc.request
    pause_hash = history.hashes[history.birth + 130]

    async def delayed(method, params):
        if method == "chain_getHeader" and params == (pause_hash,):
            await asyncio.Event().wait()
        return await request(method, params)

    history.rpc.request = delayed
    with pytest.raises(asyncio.TimeoutError):
        await history.reader.find(history.journal)
    assert history.reader._cursor.snapshot.block_number == history.birth + 131
    counts = len(history.calls)
    history.rpc.request = request
    history.reader._timeout = 60
    result = await history.reader.find(history.journal)
    assert result.successful
    assert history.calls[counts] == ("chain_getHeader", (pause_hash,))
    assert history.heads == 1 and len(history.reader._era) == 8


@pytest.mark.asyncio
async def test_live_era_refreshes_without_redoing_checked_bodies(history):
    history.head = history.birth + 1
    assert await history.reader.find(history.journal) is None
    history.head += 1
    assert (await history.reader.find(history.journal)).successful
    first = history.hashes[history.birth + 1]
    assert history.calls.count(("chain_getBlock", (first,))) == 1


@pytest.mark.asyncio
async def test_no_matching_exact_bytes_is_uncertainty_not_a_receipt(history, tx):
    from umi.bridge.transactions import retain_signed_extrinsic

    preparing = evolve_journal(
        history.journal, phase="preparing", signed_extrinsic=None, signed_extrinsic_hash=None
    )
    different = retain_signed_extrinsic(preparing, b"different", now=tx.case.now)
    assert await history.reader.find(evolve_journal(different, phase="submitting")) is None


@pytest.mark.asyncio
async def test_unsigned_or_unsubmitted_intent_cannot_supply_receipt(history, tx):
    for journal in (tx.preparing, signed(tx)):
        with pytest.raises(RegistrationBridgeError, match="signed_attempt_required"):
            await history.reader.find(journal)
    assert not history.calls


@pytest.mark.asyncio
async def test_failure_is_archived_terminal_and_survives_restart(history, tx, tmp_path):
    import umi.registration_bridge as bridge
    from tests.test_bridge_transactions import begin

    values = history.values[history.headers[history.hashes[history.birth + 2]]["stateRoot"]]
    events = json.loads(values[b"System.Events"])
    events[1]["event_id"] = "ExtrinsicFailed"
    values[b"System.Events"] = json.dumps(events).encode()
    proven = await history.reader.find(history.journal)
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx)
        failed = retain_verified_receipt(journal, proven, now=tx.case.now)
        state.store(failed, archive=True)
        assert failed.phase == "failed" and failed.weight_call is None
        assert failed.failed_call == proven.receipt
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == failed


@pytest.mark.asyncio
async def test_successful_receipt_does_not_claim_current_row_application(history, tx):
    proven = await history.reader.find(history.journal)
    returned = retain_verified_receipt(history.journal, proven, now=tx.case.now)
    assert returned.phase == "receipt_returned" and returned.failed_call is None
    assert returned.weight_call == proven.receipt


@pytest.mark.asyncio
async def test_sdk_receipt_or_another_transaction_cannot_resolve_journal(history, tx):
    from dataclasses import replace

    proven = await history.reader.find(history.journal)
    for invalid in (proven.receipt, replace(proven, signed_extrinsic_hash="0x" + "00" * 32)):
        with pytest.raises(RegistrationBridgeError, match="attempt_mismatch"):
            retain_verified_receipt(history.journal, invalid, now=tx.case.now)


@pytest.mark.asyncio
async def test_repeated_cancellation_drains_native_body_verifier_before_releasing_reader(history):
    entered, release = threading.Event(), threading.Event()
    original = history.verifier.verify_extrinsics_root

    def blocked(**kwargs):
        entered.set()
        assert release.wait(5)
        return original(**kwargs)

    history.verifier.verify_extrinsics_root = blocked
    task = asyncio.create_task(history.reader.find(history.journal))
    try:
        for _ in range(1000):
            if entered.is_set():
                break
            await asyncio.sleep(0.001)
        assert entered.is_set()
        task.cancel()
        await asyncio.sleep(0.01)
        task.cancel()
        await asyncio.sleep(0.01)
        assert not task.done() and history.reader._lock.locked()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert not history.reader._lock.locked()
    history.verifier.verify_extrinsics_root = original
    assert (await history.reader.find(history.journal)).successful


@pytest.mark.asyncio
async def test_missing_body_header_is_not_replaced_with_a_second_header_query(history):
    request = history.rpc.request

    async def missing(method, params):
        value = await request(method, params)
        if method == "chain_getBlock":
            del value["block"]["header"]
        return value

    history.rpc.request = missing
    with pytest.raises(RegistrationBridgeError, match="body_header_missing"):
        await history.reader.find(history.journal)
    assert not history.verified


@pytest.mark.asyncio
async def test_failed_archive_tear_repairs_only_its_direct_predecessor(
    history, tx, tmp_path, monkeypatch
):
    import umi.registration_bridge as bridge
    from tests.test_bridge_transactions import begin

    values = history.values[history.headers[history.hashes[history.birth + 2]]["stateRoot"]]
    events = json.loads(values[b"System.Events"])
    events[1]["event_id"] = "ExtrinsicFailed"
    values[b"System.Events"] = json.dumps(events).encode()
    proven = await history.reader.find(history.journal)
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx)
        failed = retain_verified_receipt(journal, proven, now=tx.case.now)
        with monkeypatch.context() as patch:

            def interrupted(*args):
                raise OSError("interrupted current journal replacement")

            patch.setattr(bridge.os, "replace", interrupted)
            with pytest.raises(OSError, match="interrupted"):
                state.store(failed, archive=True)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == failed
        assert state.load().failed_call == proven.receipt
