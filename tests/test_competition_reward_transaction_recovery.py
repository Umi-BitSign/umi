"""Restart recovery with real SCALE, signatures and the durable transaction journal.

Finality and trie verification are synthetic ports bound to exact fixture bytes.
Allocation selection is supplied by the fixture; these tests grant no reward or
retry authority and make no claim about a live Finney submission.
"""

import asyncio
import hashlib
import json
import threading
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt
import pytest

from umi.competition_cohort_reward_allocation import CohortRewardProjection
from umi.competition_reward_control_archive import HistoricalRewardControlProvider
from umi.competition_reward_transaction_recovery import review_standing_transaction
from umi.competition_reward_transactions import StandingWeightIntent, StandingWeightJournal
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes
from umi.signed_extrinsic import encode_verified_mortal_call
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError

from .test_competition_chain import _Finality
from .test_competition_chain import chain_config as chain_config
from .test_competition_historical_registration import change_block
from .test_open_competition import policy as policy
from .test_signed_extrinsic_native import native_encoding as native_encoding


@pytest.fixture
async def original(native_encoding, chain_config, policy, tmp_path, request):
    codec = native_encoding.context["runtime"]
    config = chain_config.model_copy(
        update={
            "chain_pin": chain_config.chain_pin.model_copy(
                update={
                    "runtime_spec_version": codec.pin.spec_version,
                    "transaction_version": codec.pin.transaction_version,
                    "metadata_sha256": codec.metadata_sha256,
                }
            ),
        }
    )
    finality = _Finality(config, policy)
    clock = SimpleNamespace(now=finality.timestamp + 1000)
    count = getattr(request, "param", 3)
    names = ["Alice", "Bob", "Charlie"] + ["StandingFixture" + str(i) for i in range(3, count)]
    hotkeys = [bt.sp_core.Keypair.from_uri("//" + name).ss58_address for name in names]
    hotkey = hotkeys[0]
    values = {
        ("Timestamp", "Now", ()): finality.timestamp,
        ("System", "Account", (hotkey,)): {
            "nonce": 4,
            "consumers": 0,
            "providers": 1,
            "sufficients": 0,
            "data": {"free": 0, "reserved": 0, "frozen": 0, "flags": 0},
        },
        ("Commitments", "CommitmentOf", (78, hotkey)): {
            "deposit": 0,
            "block": finality.ref.block_number - 1,
            "info": {"fields": [{"Sha256": "0x" + "aa" * 32}]},
        },
        ("SubtensorModule", "Weights", (78, 0)): [],
    }
    for key, value in {
        "NetworksAdded": True,
        "ValidatorPermit": [True] + [False] * (count - 1),
        "LastUpdate": [finality.ref.block_number - 20] + [0] * (count - 1),
        "MechanismCountCurrent": 1,
        "CommitRevealWeightsEnabled": False,
        "WeightsVersionKey": 1,
        "MinAllowedWeights": 1,
        "MaxAllowedUids": 256,
        "MaxWeightsLimit": 65535,
        "WeightsSetRateLimit": 10,
        "SubnetworkN": count,
    }.items():
        values["SubtensorModule", key, (78,)] = value
    for uid, key in enumerate(hotkeys):
        values["SubtensorModule", "Keys", (78, uid)] = key
        values["SubtensorModule", "Uids", (78, key)] = uid
    rpc = SimpleNamespace(values=values)
    item = SimpleNamespace(finality=finality, clock=clock, rpc=rpc)
    encoded = change_block(item, finality.ref.block_number)
    old = await finality.verified_block_at(finality.ref.block_number)
    evidence = canonical_json_bytes(
        {
            **json.loads(old.finality_evidence),
            "block": {"scale_header": encoded},
        }
    )
    old = replace(
        old,
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )
    blocks, raw_values, calls, checked = {old.height: old}, {}, [], []
    for (pallet, key, params), value in values.items():
        storage_key = codec.storage_key(pallet, key, params)
        raw_values[storage_key] = bytes(
            codec._runtime.encode(codec._runtime.storage_entry(pallet, key).value_type, value)
        )

    async def at(height):
        return blocks.get(height)

    async def request(method, params):
        calls.append((method, tuple(params)))
        ref = finality.ref
        if method == "chain_getHeader":
            assert params == (ref.block_hash,)
            return {
                "number": hex(ref.block_number),
                "stateRoot": ref.state_root,
                "parentHash": ref.parent_hash,
            }
        if method == "chain_getBlockHash":
            assert params == (ref.block_number,)
            return ref.block_hash
        assert ref.block_number == old.height, "historical state RPC is disabled after restart"
        assert params[-1] == old.block_hash
        if method == "state_getRuntimeVersion":
            return {
                "specVersion": codec.pin.spec_version,
                "transactionVersion": codec.pin.transaction_version,
                "stateVersion": 1,
            }
        if method == "state_getMetadata":
            return "0x" + codec.metadata_bytes.hex()
        if method == "state_getStorageAt":
            return "0x" + raw_values[bytes.fromhex(params[0][2:])].hex()
        if method == "state_getReadProof":
            return {"at": old.block_hash, "proof": ["0x" + b"fixture-proof".hex()]}
        raise AssertionError(method)

    def verify(**kwargs):
        checked.append(kwargs)
        return (
            kwargs["state_root"] == bytes.fromhex(old.state_root[2:])
            and kwargs["proof"] == (b"fixture-proof",)
            and all(k in raw_values and raw_values[k] == v for k, v in kwargs["items"])
        )

    finality.verified_block_at, rpc.request = at, request

    # The collector checks a callable single-proof port even when only its
    # multiproof entry point is needed by this exact-runtime fixture.
    class Verifier:
        def __call__(self, **kwargs):
            raise AssertionError("unexpected single proof")

        verify_many = staticmethod(verify)

    verifier = Verifier()
    proofs = FinalizedProofCollector(rpc, finality=finality, verifier=verifier)
    providers = []

    def reopen():
        provider = HistoricalRewardControlProvider(
            config,
            policy,
            historical_header_directory=tmp_path / "headers",
            finality=finality,
            proofs=proofs,
            now_ms=lambda: clock.now,
        )
        providers.append(provider)
        return provider

    def journal(intent, chain, control, *, signed=True, path="transactions"):
        store = StandingWeightJournal(
            tmp_path / path,
            series_sha256=intent.series_sha256,
            validator_hotkey=hotkey,
            chain_config_sha256=digest(config),
            maximum_bytes=8 * 1024**2,
        )
        store.reserve(intent, chain=chain, control=control, metadata=codec.metadata_bytes)
        if signed:
            store.retain_signed(intent, item.encoded)
        return store

    try:
        provider = reopen()
        control = await provider.collect_control(hotkey)
        chain = await provider.collect_registered_weights(hotkey)
        intent = StandingWeightIntent(
            schema="umi-standing-weight-intent/1",
            series_sha256="11" * 32,
            decision_sha256=control.control_sha256,
            activation_sha256="22" * 32,
            chain_config_sha256=digest(config),
            validator_hotkey=hotkey,
            block=chain.block,
            block_hash=chain.block_hash,
            nonce=chain.validator_nonce,
            prior_last_update=chain.validator_last_update,
            mortality_period=128,
            weights_version_key=chain.weights_version_key,
            projection=CohortRewardProjection(
                schema="umi-cohort-reward-projection/1",
                allocation_sha256="33" * 32,
                snapshot_sha256="44" * 32,
                recipients=(),
                uids=(1, 2),
                weights=(20000, 45535),
            ),
            destinations=tuple(range(count)),
            weights=(0, 20000, 45535) + (0,) * (count - 3),
            chain_evidence_sha256=chain.evidence_sha256,
            control_evidence_sha256=control.evidence_sha256,
            metadata_sha256=codec.metadata_sha256,
        )
        item.encoded = encode_verified_mortal_call(
            intent.call(),
            runtime=chain.runtime,
            signer=native_encoding.signer,
            validator_hotkey=hotkey,
            nonce=intent.nonce,
            mortality_period=128,
            genesis_hash="0x" + config.chain_pin.genesis_block_hash,
        )
        item.journal = journal(intent, chain.evidence, control.evidence)
        await provider.aclose()
        clock.now += 10 * 60 * 60 * 1000
        header = change_block(item, old.height + 3000)
        fresh_raw = canonical_json_bytes(
            {**json.loads(evidence), "block": {"scale_header": header}}
        )
        blocks[finality.ref.block_number] = replace(
            old,
            height=finality.ref.block_number,
            block_hash=finality.ref.block_hash,
            timestamp_ms=finality.timestamp,
            finality_evidence=fresh_raw,
            finality_evidence_sha256=hashlib.sha256(fresh_raw).hexdigest(),
        )
        item.provider, item.reopen = reopen(), reopen
        item.intent, item.chain, item.control = intent, chain, control
        item.make_journal, item.verifier, item.checked = journal, verifier, checked
        item.hotkey, item.old, item.blocks, item.calls = hotkey, old, blocks, calls
        calls.clear()
        checked.clear()
        yield item
    finally:
        for provider in reversed(providers):
            await provider.aclose()


async def test_restart_verifies_original_state_and_real_signature_without_historical_rpc(original):
    t = original
    before = t.journal.recovery_inputs()
    result = await review_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert result.pending == before.pending
    assert result.query.birth_block == t.old.height
    assert result.query.birth_hash == t.old.block_hash
    assert result.query.mortality_period == 128
    assert bytes.fromhex(result.query.signed_extrinsic) == t.encoded
    assert not result.chain_submission_authorized
    assert t.journal.recovery_inputs() == before
    assert len(t.checked) == 1 + len(json.loads(t.chain.evidence)["storage_batches"])
    assert {method for method, _ in t.calls} == {"chain_getHeader", "chain_getBlockHash"}


@pytest.mark.parametrize("original", [256], indirect=True)
async def test_full_registered_uid_domain_replays_both_mapping_proofs(original):
    t = original
    result = await review_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert len(result.pending.intent.weights) == 256
    assert bytes.fromhex(result.query.signed_extrinsic) == t.encoded
    assert [len(row["items"]) for row in t.checked] == [3, 15, 256, 256, 1]


@pytest.mark.parametrize(
    "field,value",
    [
        ("nonce", 5),
        ("prior_last_update", 0),
        ("weights_version_key", 2),
        ("mortality_period", 256),
        ("block", 9_999_999),
        ("block_hash", "0x" + "ff" * 32),
        ("decision_sha256", "ff" * 32),
    ],
)
async def test_rebound_intent_cannot_override_original_proofs(original, field, value):
    t = original
    intent = t.intent.model_copy(update={field: value})
    store = t.make_journal(intent, t.chain.evidence, t.control.evidence, path="changed-intent")
    with pytest.raises(ValueError):
        await review_standing_transaction(t.provider, store, control_hotkey=t.hotkey)
    assert store.pending().intent == intent


@pytest.mark.parametrize(
    "change", ["nonce", "proof", "root", "version", "header", "missing", "extra"]
)
async def test_rehashed_archive_does_not_bypass_native_checks(original, change):
    t = original
    body = json.loads(t.chain.evidence)
    if change == "nonce":
        key = "0x" + t.chain.runtime.storage_key("System", "Account", (t.hotkey,)).hex()
        claim = next(c for b in body["storage_batches"] for c in b["claims"] if c["key"] == key)
        raw = bytearray.fromhex(claim["value"][2:])
        raw[0] += 1
        claim["value"] = "0x" + raw.hex()
    elif change == "proof":
        body["storage_batches"][-1]["proof"] = ["0xdeadbeef"]
    elif change == "root":
        body["storage_batches"][-1]["state_root"] = "0x" + "ff" * 32
    elif change == "version":
        body["runtime_version"]["specVersion"] += 1
    elif change == "header":
        body["finality"]["block"]["scale_header"] = "0x00"
    elif change == "missing":
        body["storage_batches"] = body["storage_batches"][1:]
    else:
        body["unexpected_authority"] = True
    raw = canonical_json_bytes(body)
    intent = t.intent.model_copy(update={"chain_evidence_sha256": hashlib.sha256(raw).hexdigest()})
    store = t.make_journal(intent, raw, t.control.evidence, path="changed-evidence")
    with pytest.raises((ValueError, ValidatorChainError)):
        await review_standing_transaction(t.provider, store, control_hotkey=t.hotkey)


async def test_unsigned_intent_is_replayed_without_fabricating_a_receipt_query(original):
    t = original
    store = t.make_journal(
        t.intent, t.chain.evidence, t.control.evidence, signed=False, path="unsigned"
    )
    result = await review_standing_transaction(t.provider, store, control_hotkey=t.hotkey)
    assert result.query is None and not result.chain_submission_authorized
    assert store.pending().signed is None


async def test_missing_owned_historical_finality_stays_pending(original):
    t = original
    del t.blocks[t.old.height]
    before = t.journal.recovery_inputs()
    with pytest.raises(FileNotFoundError):
        await review_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    assert t.journal.recovery_inputs() == before


async def test_another_control_key_cannot_select_the_retained_attempt(original):
    t = original
    with pytest.raises(ValueError, match="selected owned proof"):
        await review_standing_transaction(
            t.provider, t.journal, control_hotkey=bt.sp_core.Keypair.from_uri("//Bob").ss58_address
        )


async def test_changed_signed_bytes_are_reverified_after_reopen(original):
    t = original
    store = t.make_journal(
        t.intent, t.chain.evidence, t.control.evidence, signed=False, path="bad-signature"
    )
    changed = bytearray(t.encoded)
    changed[40] ^= 1
    store.retain_signed(t.intent, bytes(changed))  # The journal itself is storage only.
    before = store.recovery_inputs()
    with pytest.raises(ValueError, match="signed transaction"):
        await review_standing_transaction(t.provider, store, control_hotkey=t.hotkey)
    assert store.recovery_inputs() == before


async def test_concurrently_retained_signature_requires_another_review(original, monkeypatch):
    t = original
    store = t.make_journal(
        t.intent, t.chain.evidence, t.control.evidence, signed=False, path="concurrent"
    )
    verify = t.verifier.verify_many
    recorded = False

    def retain_during_proof(**kwargs):
        nonlocal recorded
        if len(kwargs["items"]) > 3 and not recorded:
            store.retain_signed(t.intent, t.encoded)
            recorded = True
        return verify(**kwargs)

    monkeypatch.setattr(t.verifier, "verify_many", retain_during_proof)
    with pytest.raises(ValueError, match="attempt changed"):
        await review_standing_transaction(t.provider, store, control_hotkey=t.hotkey)
    assert store.pending().signed.signed_extrinsic == t.encoded.hex()
    assert (
        await review_standing_transaction(t.provider, store, control_hotkey=t.hotkey)
    ).query is not None


async def test_shutdown_waits_for_cancelled_native_proof_work(original, monkeypatch):
    t = original
    entered, release = threading.Event(), threading.Event()
    original_verify = t.verifier.verify_many

    def slow(**kwargs):
        if len(kwargs["items"]) > 3:
            entered.set()
            assert release.wait(10)
        return original_verify(**kwargs)

    monkeypatch.setattr(t.verifier, "verify_many", slow)
    before = t.journal.recovery_inputs()
    task = asyncio.create_task(
        review_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    )
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        close = asyncio.create_task(t.provider.aclose())
        await asyncio.sleep(0)
        assert not close.done() and not task.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    await close
    assert t.journal.recovery_inputs() == before
    t.provider = t.reopen()
    assert (
        await review_standing_transaction(t.provider, t.journal, control_hotkey=t.hotkey)
    ).query is not None
