"""Binding/failure tests use synthetic proofs, never wallets or live chain RPC."""

from __future__ import annotations

import asyncio
import copy
import json
import threading
from dataclasses import replace
from datetime import timedelta
from types import SimpleNamespace

import pytest

from tests.test_registration_bridge import BLOCK, NOW, NOW_MS, observation
from tests.test_runtime_metadata import response
from umi.bridge.policy import RegistrationBridgeError
from umi.bridge.signing import BridgeSigningState, BridgeSigningStateReader
from umi.chain import _header_hash
from umi.encoding import account_id32
from umi.runtime_metadata import RuntimeMetadataExecutor


@pytest.fixture
def case(monkeypatch, tmp_path):
    header = {
        "number": BLOCK,
        "parentHash": "0x" + "11" * 32,
        "stateRoot": "0x" + "22" * 32,
        "extrinsicsRoot": "0x" + "33" * 32,
        "digest": {"logs": []},
    }
    block_hash = _header_hash(header, "fixture")
    obs = observation(block_hash=block_hash)
    account_key = b"System.Account:" + account_id32(obs.validator_hotkey)
    values = {
        b":code": b"verified wasm",
        account_key: b'{"nonce":7}',
        b"Timestamp.Now": str(NOW_MS).encode(),
    }
    item = SimpleNamespace(
        header=header,
        values=values,
        obs=obs,
        calls=[],
        proofs=[],
        executed=[],
        now=NOW,
        head=SimpleNamespace(number=BLOCK, block_hash=block_hash),
        heads=0,
        reject_proof=False,
        reject_account_proof=False,
    )

    class Finality:
        async def read_finalized_identity(self):
            item.heads += 1
            return copy.copy(item.head)

    class Rpc:
        async def request(self, method, params):
            item.calls.append((method, params))
            if method == "chain_getHeader":
                assert params == (item.obs.block_hash,)
                return copy.deepcopy(item.header)
            if method == "state_getStorageAt":
                key, at = params
                assert at == item.obs.block_hash
                raw = item.values[bytes.fromhex(key[2:])]
                return None if raw is None else "0x" + raw.hex()
            if method == "state_getReadProof":
                keys, at = params
                assert at == item.obs.block_hash
                assert keys and all(bytes.fromhex(key[2:]) in item.values for key in keys)
                return {"at": at, "proof": ["0x" + b"synthetic-proof".hex()]}
            pytest.fail(f"unexpected RPC method: {method}")

    def verifier(*, state_root, proof, **claim):
        assert state_root == bytes.fromhex(header["stateRoot"][2:])
        assert proof == (b"synthetic-proof",)
        item.proofs.append(claim)
        if "items" in claim:
            pairs = claim["items"]
            if item.reject_account_proof:
                return False
        else:
            pairs = ((claim["storage_key"], claim["expected_value"]),)
        return not item.reject_proof and all(item.values[key] == raw for key, raw in pairs)

    verifier.verify_many = verifier

    class Codec:
        def __init__(self, metadata, spec, transaction, **options):
            self.spec_version, self.transaction_version = spec, transaction

        def constant(self, *args):
            assert args == ("System", "SS58Prefix")
            return 42

        def storage_key(self, pallet, name, params):
            if (pallet, name) == ("System", "Account"):
                assert len(params) == 1
                return b"System.Account:" + account_id32(params[0])
            assert (pallet, name, params) == ("Timestamp", "Now", [])
            return b"Timestamp.Now"

        def storage_entry(self, pallet, name):
            default = b'{"nonce":0}' if name == "Account" else b"0"
            return SimpleNamespace(modifier="Default", default_bytes=default, value_type=name)

        def decode(self, value_type, encoded, *, strict):
            assert strict is True
            return json.loads(encoded)

    executor = RuntimeMetadataExecutor(binary_path=tmp_path / "not-run", expected_sha256="a" * 64)

    def invoke(code):
        item.executed.append(code)
        return json.dumps(response(code)).encode() + b"\n"

    monkeypatch.setattr(executor, "_invoke", invoke)
    monkeypatch.setattr("umi.runtime_metadata.bittensor_core.Runtime", Codec)
    item.finality, item.rpc, item.verifier, item.executor = Finality(), Rpc(), verifier, executor
    item.reader = BridgeSigningStateReader(
        finality=item.finality,
        rpc=item.rpc,
        verifier=verifier,
        runtime_executor=executor,
        clock=lambda: item.now,
    )
    item.account_key = account_key
    return item


@pytest.mark.asyncio
async def test_signing_state_is_proven_at_exact_owned_header(case):
    state = await case.reader.capture(case.obs)
    assert state.nonce == 7 and state.timestamp_ms == NOW_MS
    assert state.validator_hotkey == case.obs.validator_hotkey
    assert state.runtime.snapshot.block_hash == case.obs.block_hash
    assert state.runtime.snapshot.state_root == case.header["stateRoot"]
    assert state.runtime.executor_sha256 == "a" * 64
    assert case.executed == [b"verified wasm"]
    assert case.heads == 2 and len(case.proofs) == 2
    assert {name for name, _ in case.calls} == {
        "chain_getHeader",
        "state_getStorageAt",
        "state_getReadProof",
    }
    assert case.obs.storage_proofs_verified is False  # Other bridge state is still SDK data.


@pytest.mark.asyncio
async def test_proof_first_read_chooses_owned_head_without_sdk_observation(case):
    state = await case.reader.read(case.obs.validator_hotkey)
    assert state.nonce == 7 and state.runtime.snapshot.block_hash == case.head.block_hash
    assert case.heads == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("timestamp_mismatch", [False, True])
async def test_chain_collects_sdk_roster_only_at_the_proven_signing_head(case, timestamp_mismatch):
    from umi.registration_bridge import FINNEY_GENESIS_HASH, BittensorRegistrationBridgeChain

    class Substrate:
        async def block_hash(self, number):
            assert number == 0
            return "0x" + FINNEY_GENESIS_HASH

    client = SimpleNamespace(_substrate=Substrate())
    chain = BittensorRegistrationBridgeChain(
        finality_reader=case.finality,
        clock=lambda: case.now,
        signing_reader_factory=lambda **kw: case.reader,
    )

    async def at(sdk, *, validator_hotkey, owned):
        assert sdk is client and validator_hotkey == case.obs.validator_hotkey
        assert (owned.number, owned.block_hash) == (case.head.number, case.head.block_hash)
        assert case.proofs  # The roster is read after proof selection.
        return case.obs.model_copy(
            update={"block_timestamp_ms": case.obs.block_timestamp_ms + int(timestamp_mismatch)}
        )

    chain._observation_at = at
    if timestamp_mismatch:
        with pytest.raises(RegistrationBridgeError, match="timestamp_mismatch"):
            await chain.signing_observation_with_client(
                client, validator_hotkey=case.obs.validator_hotkey
            )
    else:
        obs, state = await chain.signing_observation_with_client(
            client, validator_hotkey=case.obs.validator_hotkey
        )
        assert obs == case.obs and state.nonce == 7


@pytest.mark.asyncio
async def test_raw_rpc_hex_height_hashes_like_sdk_integer_height(case):
    case.header["number"] = hex(BLOCK)
    assert (await case.reader.capture(case.obs)).nonce == 7


@pytest.mark.parametrize(
    "field,value", [("stateRoot", "0x" + "44" * 32), ("number", hex(BLOCK + 1))]
)
@pytest.mark.asyncio
async def test_rpc_header_cannot_supply_an_unowned_state_root(case, field, value):
    case.header[field] = value
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_header_mismatch"):
        await case.reader.capture(case.obs)
    assert not case.executed and not case.proofs


@pytest.mark.asyncio
async def test_matching_hash_with_wrong_owned_height_is_rejected(case):
    case.head.number += 1
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_height_mismatch"):
        await case.reader.capture(case.obs)
    assert not case.executed


@pytest.mark.asyncio
async def test_observation_cannot_select_its_own_head(case):
    obs = case.obs.model_copy(update={"block_hash": "0x" + "44" * 32})
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_observation_changed"):
        await case.reader.capture(obs)
    assert not case.executed


@pytest.mark.asyncio
async def test_bad_code_proof_never_executes_and_never_falls_back(case):
    case.reject_proof = True
    with pytest.raises(RuntimeError, match="storage_proof_verification_failed"):
        await case.reader.capture(case.obs)
    assert not case.executed


@pytest.mark.asyncio
async def test_bad_account_proof_never_returns_a_nonce(case):
    case.reject_account_proof = True
    with pytest.raises(RuntimeError, match="storage_proof_verification_failed"):
        await case.reader.capture(case.obs)


@pytest.mark.parametrize("nonce", [-1, 2**32, True, 1.0, "7", None])
@pytest.mark.asyncio
async def test_nonce_requires_exact_u32(case, nonce):
    case.values[case.account_key] = json.dumps({"nonce": nonce}).encode()
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_nonce_invalid"):
        await case.reader.capture(case.obs)


@pytest.mark.parametrize("nonce", [0, 2**32 - 1])
@pytest.mark.asyncio
async def test_nonce_range_endpoints(case, nonce):
    case.values[case.account_key] = json.dumps({"nonce": nonce}).encode()
    assert (await case.reader.capture(case.obs)).nonce == nonce


@pytest.mark.asyncio
async def test_timestamp_must_match_sdk_observation(case):
    case.values[b"Timestamp.Now"] = str(NOW_MS + 1).encode()
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_timestamp_mismatch"):
        await case.reader.capture(case.obs)


@pytest.mark.parametrize("seconds", [-1, 121])
@pytest.mark.asyncio
async def test_expired_or_future_proven_timestamp_is_rejected(case, seconds):
    case.now = NOW + timedelta(seconds=seconds)
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_snapshot_stale"):
        await case.reader.capture(case.obs)


@pytest.mark.parametrize("advance", [-1, 8])
@pytest.mark.asyncio
async def test_rollback_or_expired_era_during_collection_is_rejected(case, advance, monkeypatch):
    original = case.executor.execute

    def execute(*args):
        result = original(*args)
        case.head.number += advance
        return result

    monkeypatch.setattr(case.executor, "execute", execute)
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_finality_changed"):
        await case.reader.capture(case.obs)


@pytest.mark.asyncio
async def test_same_height_changed_identity_is_rejected(case, monkeypatch):
    original = case.executor.execute

    def execute(*args):
        result = original(*args)
        case.head.block_hash = "0x" + "44" * 32
        return result

    monkeypatch.setattr(case.executor, "execute", execute)
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_finality_changed"):
        await case.reader.capture(case.obs)


@pytest.mark.asyncio
async def test_late_finality_read_cannot_return_expired_evidence(case, monkeypatch):
    original = case.finality.read_finalized_identity

    async def read():
        result = await original()
        if case.heads == 2:
            case.now = NOW + timedelta(seconds=121)
        return result

    monkeypatch.setattr(case.finality, "read_finalized_identity", read)
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_snapshot_stale"):
        await case.reader.capture(case.obs)


@pytest.mark.asyncio
async def test_decoded_value_substitution_cannot_change_verified_nonce(case):
    state = await case.reader.capture(case.obs)
    reads = tuple(replace(read, decoded_value={"nonce": 0}) for read in state.batch.reads)
    rebuilt = BridgeSigningState(
        state.validator_hotkey, state.runtime, replace(state.batch, reads=reads)
    )
    assert rebuilt.nonce == 7 and rebuilt.timestamp_ms == NOW_MS


@pytest.mark.asyncio
async def test_proven_account_cannot_be_rebound_to_another_signer(case):
    state = await case.reader.capture(case.obs)
    other = case.obs.participants[1].hotkey
    with pytest.raises(RegistrationBridgeError, match="bridge_signing_account_proof_invalid"):
        BridgeSigningState(other, state.runtime, state.batch)


@pytest.mark.asyncio
async def test_cancelled_execution_drains_before_the_next_capture(case, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = case.executor.execute

    def execute(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(case.executor, "execute", execute)
    first = asyncio.create_task(case.reader.capture(case.obs))
    second = None
    try:

        async def wait_entered():
            while not entered.is_set():
                await asyncio.sleep(0.001)

        await asyncio.wait_for(wait_entered(), 2)
        first.cancel()
        await asyncio.sleep(0)
        first.cancel()
        second = asyncio.create_task(case.reader.capture(case.obs))
        await asyncio.sleep(0.02)
        assert case.heads == 1 and not first.done() and not second.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await first
        assert (await second).nonce == 7
        assert len(case.executed) == 2
    finally:
        release.set()
        await asyncio.gather(*[t for t in (first, second) if t is not None], return_exceptions=True)


@pytest.mark.asyncio
async def test_timeout_waits_for_executor_before_releasing_capture_lock(case, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = case.executor.execute

    def execute(*args):
        entered.set()
        assert release.wait(5)
        return original(*args)

    monkeypatch.setattr(case.executor, "execute", execute)
    case.reader._timeout = 0.02
    task = asyncio.create_task(case.reader.capture(case.obs))
    try:

        async def wait_entered():
            while not entered.is_set():
                await asyncio.sleep(0.001)

        await asyncio.wait_for(wait_entered(), 2)
        await asyncio.sleep(0.05)
        assert not task.done() and case.reader._lock.locked()
        release.set()
        with pytest.raises(asyncio.TimeoutError):
            await task
        assert not case.reader._lock.locked()
        assert not any(
            name == "state_getStorageAt" and params[0] != "0x3a636f6465"
            for name, params in case.calls
        )
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
async def test_caller_mutation_during_await_cannot_change_captured_account(case, monkeypatch):
    original = case.finality.read_finalized_identity
    hotkey = case.obs.validator_hotkey

    async def read():
        result = await original()
        # Even in-process code bypassing Pydantic's frozen-field guard must
        # not redirect a capture already in flight to another account.
        object.__setattr__(case.obs, "validator_hotkey", case.obs.participants[1].hotkey)
        object.__setattr__(case.obs, "block_timestamp_ms", case.obs.block_timestamp_ms + 1)
        return result

    monkeypatch.setattr(case.finality, "read_finalized_identity", read)
    state = await case.reader.capture(case.obs)
    assert state.validator_hotkey == hotkey and state.timestamp_ms == NOW_MS


@pytest.mark.asyncio
async def test_wrong_executor_identity_cannot_supply_a_signing_runtime(case, monkeypatch):
    original = case.executor.execute

    def execute(*args):
        return replace(original(*args), executor_sha256="b" * 64)

    monkeypatch.setattr(case.executor, "execute", execute)
    with pytest.raises(RuntimeError, match="executed_runtime_binding_invalid"):
        await case.reader.capture(case.obs)
    assert len(case.proofs) == 1  # Account state was never read.


@pytest.mark.asyncio
async def test_account_and_runtime_have_separate_size_bounds(case):
    assert case.reader._code_proofs._limits.maximum_storage_value_bytes == 8 * 1024**2
    case.values[case.account_key] = b" " * 513
    with pytest.raises(RuntimeError, match="storage_value_limit"):
        await case.reader.capture(case.obs)


@pytest.mark.parametrize("timeout", [0, -1, True, float("nan"), float("inf"), 61])
def test_capture_timeout_is_bounded(case, timeout):
    with pytest.raises(ValueError, match="timeout"):
        BridgeSigningStateReader(
            finality=case.finality,
            rpc=case.rpc,
            verifier=case.verifier,
            runtime_executor=case.executor,
            timeout_seconds=timeout,
        )
