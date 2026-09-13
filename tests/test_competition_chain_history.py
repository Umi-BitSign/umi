"""Recent exact-block reads use the same proof collector as current intake."""

from __future__ import annotations

import asyncio
import sqlite3
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_chain import FinalizedRegistrationProvider
from umi.validator_chain import FinalizedProofCollector
from umi.validator_chain_scan import VerifiedFinalizedBlockIdentity

from .test_competition_chain import (
    _HEIGHT,
    _NOW,
    _Finality,
    _hash,
    _Rpc,
    _Runtime,
    _Verifier,
)
from .test_competition_chain import chain_config as chain_config
from .test_competition_chain import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def history(chain_config, policy, monkeypatch):
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _Runtime)
    records, rpcs, verifiers = {}, {}, {}
    for offset in range(-4, 2):
        record = _Finality(chain_config, policy)
        record.ref = FinalizedSnapshotRef(
            _HEIGHT + offset, _hash(10 + offset), _hash(9 + offset), _hash(100 + offset)
        )
        record.timestamp += offset * 12_000
        records[_HEIGHT + offset] = record
        rpcs[_HEIGHT + offset] = _Rpc(record)
        verifiers[_HEIGHT + offset] = _Verifier(record)

    class Finality:
        def __init__(self):
            self.height = _HEIGHT
            self.identities = []

        async def verified_finalized_snapshot(self):
            return records[self.height].ref

        async def verified_block_at(self, height):
            return await records[height].verified_block_at(height)

        async def verified_identity_at(self, height):
            self.identities.append(height)
            if height not in records or height - 1 not in records:
                return None
            block = await self.verified_block_at(height)
            return VerifiedFinalizedBlockIdentity(
                snapshot=records[height].ref,
                parent_snapshot=records[height - 1].ref,
                extrinsics_root=_hash(200),
                finality_verifier_sha256=block.finality_verifier_sha256,
                finality_evidence_sha256=block.finality_evidence_sha256,
            )

    class Rpc:
        async def request(self, method, params):
            if method == "chain_getBlockHash":
                height = params[0]
            else:
                hash_ = (
                    params[1]
                    if method in {"state_getStorageAt", "state_getReadProof"}
                    else params[0]
                )
                height = next(h for h, record in records.items() if record.ref.block_hash == hash_)
            return await rpcs[height].request(method, params)

    class Verifier:
        def __call__(self, **kwargs):
            raise AssertionError("registration collection must use multiproofs")

        def verify_many(self, **kwargs):
            height = next(
                h
                for h, record in records.items()
                if bytes.fromhex(record.ref.state_root[2:]) == kwargs["state_root"]
            )
            return verifiers[height].verify_many(**kwargs)

    finality = Finality()
    proofs = FinalizedProofCollector(Rpc(), finality=finality, verifier=Verifier())
    clock = SimpleNamespace(now=_NOW)

    def provider(config=chain_config):
        return FinalizedRegistrationProvider(
            config, policy, finality=finality, proofs=proofs, now_ms=lambda: clock.now
        )

    return SimpleNamespace(
        provider=provider(),
        restart=provider,
        config=chain_config,
        policy=policy,
        finality=finality,
        records=records,
        rpcs=rpcs,
        verifiers=verifiers,
        proofs=proofs,
        clock=clock,
    )


async def test_exact_prior_membership_is_proven_without_replacing_latest(history):
    current = await history.provider.collect()
    prior_rpc = history.rpcs[_HEIGHT - 1]
    bob, dave = (wallet(n).hotkey.ss58_address for n in ("Bob", "Dave"))
    del prior_rpc.values[("SubtensorModule", "Uids", (78, bob))]
    prior_rpc.values[("SubtensorModule", "Keys", (78, 1))] = dave
    prior_rpc.values[("SubtensorModule", "Uids", (78, dave))] = 1
    previous = await history.provider.collect_at(_HEIGHT - 1)
    assert previous.snapshot.block == _HEIGHT - 1
    assert previous.snapshot.registrations[1].hotkey == dave
    assert current.snapshot.registrations[1].hotkey == bob
    assert len(history.verifiers[_HEIGHT - 1].checked) == 3
    assert all(
        check["state_root"] == bytes.fromhex(previous.provenance["state_root"][2:])
        for check in history.verifiers[_HEIGHT - 1].checked
    )
    assert await history.provider.collect() == current
    assert len(history.verifiers[_HEIGHT].checked) == 3
    with sqlite3.connect(history.provider._path) as db:
        assert db.execute("SELECT block FROM captures ORDER BY block").fetchall() == [
            (_HEIGHT - 1,),
            (_HEIGHT,),
        ]


@pytest.mark.parametrize("mode", ["rollback", "changed_hash"])
async def test_only_historical_reads_still_persist_current_head_guard(history, mode):
    await history.provider.collect_at(_HEIGHT - 2)
    await history.provider.aclose()
    if mode == "rollback":
        history.finality.height -= 1
    else:
        head = history.records[_HEIGHT]
        head.ref = replace(head.ref, block_hash=_hash(250))
    restarted = history.restart()
    with pytest.raises(ValueError, match="rolled back or changed"):
        await restarted.collect_at(_HEIGHT - 2)


async def test_old_cache_without_head_table_still_guards_current_height(history):
    await history.provider.collect()
    with sqlite3.connect(history.provider._path) as db:
        db.execute("DROP TABLE observed_head")
    history.finality.height -= 1
    with pytest.raises(ValueError, match="rolled back or changed"):
        await history.restart().collect_at(_HEIGHT - 2)


@pytest.mark.parametrize("height", [True, -1, 2**53, "10", _HEIGHT + 1])
async def test_invalid_or_future_height_never_requests_historical_proofs(history, height):
    with pytest.raises(ValueError):
        await history.provider.collect_at(height)
    assert not history.finality.identities
    assert not any(v.checked for v in history.verifiers.values())


async def test_history_respects_policy_age_and_minimum(history):
    with pytest.raises(ValueError, match="future or stale"):
        await history.provider.collect_at(_HEIGHT - history.policy.maximum_snapshot_age_blocks - 1)
    with pytest.raises(ValueError, match="configured minimum"):
        await history.provider.collect_at(history.config.minimum_finalized_block - 1)
    assert not history.finality.identities


@pytest.mark.parametrize("mode", ["absent", "untyped", "height", "verifier", "evidence"])
async def test_history_requires_matching_owned_identity(history, monkeypatch, mode):
    correct = await history.finality.verified_identity_at(_HEIGHT - 1)
    if mode == "absent":
        returned = None
    elif mode == "untyped":
        returned = SimpleNamespace(snapshot=correct.snapshot)
    elif mode == "height":
        returned = await history.finality.verified_identity_at(_HEIGHT - 2)
    else:
        key = "finality_verifier_sha256" if mode == "verifier" else "finality_evidence_sha256"
        returned = replace(correct, **{key: "ff" * 32})

    async def identity(height):
        return returned

    monkeypatch.setattr(history.finality, "verified_identity_at", identity)
    with pytest.raises(ValueError, match="historical finalized"):
        await history.provider.collect_at(_HEIGHT - 1)
    assert not any(v.checked for v in history.verifiers.values())


@pytest.mark.parametrize("mode", ["bad_proof", "old_timestamp", "changed_mapping"])
async def test_cached_history_never_bypasses_proof_or_freshness_checks(history, mode):
    previous = await history.provider.collect_at(_HEIGHT - 1)
    rpc = history.rpcs[_HEIGHT - 1]
    if mode == "bad_proof":
        rpc.bad_proof = True
    elif mode == "old_timestamp":
        history.clock.now += 109_000  # Current head is fresh; previous is not.
    else:
        a, b = (wallet(n).hotkey.ss58_address for n in ("Alice", "Bob"))
        for uid, hotkey in enumerate((b, a)):
            rpc.values[("SubtensorModule", "Keys", (78, uid))] = hotkey
            rpc.values[("SubtensorModule", "Uids", (78, hotkey))] = uid
    with pytest.raises((ValueError, RuntimeError)):
        await history.provider.collect_at(_HEIGHT - 1)
    with sqlite3.connect(history.provider._path) as db:
        assert db.execute("SELECT hash FROM captures").fetchall() == [
            (previous.snapshot.block_hash,)
        ]


@pytest.mark.parametrize("mode", ["rollback", "age", "wall_clock"])
async def test_history_checks_again_after_storage_proofs(history, monkeypatch, mode):
    read = history.proofs.storage_reads

    async def delayed(runtime, specs):
        result = await read(runtime, specs)
        if mode == "rollback":
            history.finality.height = _HEIGHT - 1
        elif mode == "age":

            async def advanced():
                return replace(
                    history.records[_HEIGHT].ref,
                    block_number=_HEIGHT + history.policy.maximum_snapshot_age_blocks,
                )

            monkeypatch.setattr(history.finality, "verified_finalized_snapshot", advanced)
        else:
            history.clock.now += 109_000
        return result

    monkeypatch.setattr(history.proofs, "storage_reads", delayed)
    with pytest.raises(ValueError, match=r"stale|rolled back"):
        await history.provider.collect_at(_HEIGHT - 1)
    with sqlite3.connect(history.provider._path) as db:
        assert not db.execute("SELECT block FROM captures").fetchall()
        assert not db.execute("SELECT block FROM observed_head").fetchall()


async def test_history_keeps_startup_and_closed_guards(history):
    provider = history.provider
    provider._owned = True
    with pytest.raises(ValueError, match="not running"):
        await provider.collect_at(_HEIGHT - 1)
    provider._task = asyncio.create_task(asyncio.Event().wait())
    provider._startup_floor = _HEIGHT
    try:
        with pytest.raises(ValueError, match="this observer process"):
            await provider.collect_at(_HEIGHT - 1)
        provider._startup_floor = _HEIGHT - 1
        assert (await provider.collect_at(_HEIGHT - 2)).snapshot.block == _HEIGHT - 2
    finally:
        provider._task.cancel()
        await asyncio.gather(provider._task, return_exceptions=True)
        await provider.aclose()
    with pytest.raises(ValueError, match="closed"):
        await provider.collect_at(_HEIGHT - 1)


async def test_historical_identity_timeout_cancels_and_keeps_cache_empty(history, monkeypatch):
    entered, closed = asyncio.Event(), asyncio.Event()

    async def stalled(height):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            closed.set()

    monkeypatch.setattr(history.finality, "verified_identity_at", stalled)
    config = history.config.model_copy(
        update={
            "collection_timeout_seconds": 1,
            "state_directory": history.config.state_directory + "-timeout",
        }
    )
    provider = history.restart(config)
    with pytest.raises(ValueError, match="timed out"):
        await provider.collect_at(_HEIGHT - 1)
    assert entered.is_set() and closed.is_set()
    with sqlite3.connect(provider._path) as db:
        assert not db.execute("SELECT block FROM captures").fetchall()
        assert not db.execute("SELECT block FROM observed_head").fetchall()


async def test_current_head_must_be_fresh_even_when_requested_history_is_valid(history):
    history.records[_HEIGHT].timestamp = _NOW - 121_000
    with pytest.raises(ValueError, match="stale"):
        await history.provider.collect_at(_HEIGHT - 1)
    assert not history.finality.identities


async def test_same_head_explicit_capture_reproves_membership(history):
    expected = await history.provider.collect()
    assert await history.provider.collect_at(_HEIGHT) == expected
    assert len(history.verifiers[_HEIGHT].checked) == 6
    history.rpcs[_HEIGHT].bad_proof = True
    with pytest.raises(RuntimeError):
        await history.provider.collect_at(_HEIGHT)


async def test_head_observed_at_end_of_history_read_also_guards_restart(history, monkeypatch):
    read = history.proofs.storage_reads

    async def advancing(runtime, specs):
        result = await read(runtime, specs)
        history.finality.height = _HEIGHT + 1
        return result

    monkeypatch.setattr(history.proofs, "storage_reads", advancing)
    await history.provider.collect_at(_HEIGHT - 1)
    history.finality.height = _HEIGHT
    with pytest.raises(ValueError, match="rolled back or changed"):
        await history.restart().collect_at(_HEIGHT - 1)
