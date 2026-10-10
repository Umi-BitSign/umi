"""Exact-block proof reuse without sharing archive replay or mutable codecs."""

import hashlib
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_chain_state import FinalizedCompetitionWeightProvider
from umi.runtime_metadata import MAX_CODE_BYTES, collect_executed_runtime
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError

from .test_runtime_metadata import executor as executor
from .test_validator_chain import FakeFinality, FakeMultiVerifier, _hash, _rpc


def setup(*, budget=4096, verifier=None):
    rpc, finality = _rpc(), FakeFinality()
    verifier = verifier or FakeMultiVerifier()
    collector = FinalizedProofCollector(
        rpc,
        finality=finality,
        verifier=verifier,
        maximum_cached_storage_evidence_bytes=budget,
    )
    return collector, rpc, finality, verifier


async def test_repeated_verified_storage_avoids_rpc_and_proof_work():
    collector, rpc, finality, verifier = setup()
    proof = await collector.storage_evidence(finality.snapshot, b":code")
    assert await collector.storage_evidence(finality.snapshot, b":code") is proof
    assert len(rpc.calls) == 2 and len(verifier.single_calls) == 1
    # Reuse is no substitute for a fresh finality observation.
    await collector.finalized_snapshot()
    await collector.finalized_snapshot()
    assert finality.calls == 2


@pytest.mark.parametrize(
    "change",
    [
        {"block_number": 43},
        {"block_hash": _hash(4)},
        {"parent_hash": _hash(5)},
        {"state_root": _hash(6)},
    ],
)
async def test_every_snapshot_component_binds_reuse(change):
    collector, rpc, finality, verifier = setup()
    first = await collector.storage_evidence(finality.snapshot, b":code")
    changed = replace(finality.snapshot, **change)
    rpc.responses["state_getReadProof"]["at"] = changed.block_hash
    second = await collector.storage_evidence(changed, b":code")
    assert second is not first and second.snapshot == changed
    assert len(rpc.calls) == 4 and len(verifier.single_calls) == 2
    assert verifier.single_calls[-1]["state_root"] == bytes.fromhex(changed.state_root[2:])


async def test_runtime_current_and_parent_share_proof_but_not_codec(executor):
    collector, rpc, finality, verifier = setup()
    first_ref = finality.snapshot
    first = await collect_executed_runtime(collector, executor, first_ref)
    first._runtime.spec_version = 999
    next_ref = replace(
        first_ref, block_number=43, block_hash=_hash(4), parent_hash=first_ref.block_hash
    )
    rpc.responses["state_getReadProof"]["at"] = next_ref.block_hash
    await collect_executed_runtime(collector, executor, next_ref)
    # RPC now only supplies the next block: the earlier parent must reuse its
    # exact prior evidence while the executor constructs a private runtime.
    parent = await collect_executed_runtime(collector, executor, first_ref)
    assert parent.code_evidence is first.code_evidence
    assert parent._runtime is not first._runtime
    assert parent._runtime.spec_version == 459
    assert len(rpc.calls) == 4 and len(verifier.single_calls) == 2


async def test_archive_replay_does_not_inherit_online_reuse():
    collector, rpc, finality, _ = setup(verifier=lambda **kw: kw["expected_value"] == b"value")
    original = await collector.storage_evidence(finality.snapshot, b":code")
    archive = _rpc(value="0x74616d7065726564")
    replay = collector.with_evidence_rpc(archive)
    with pytest.raises(ValidatorChainError, match="storage_proof_verification_failed"):
        await replay.storage_evidence(finality.snapshot, b":code")
    assert len(archive.calls) == 2 and len(rpc.calls) == 2
    assert await collector.storage_evidence(finality.snapshot, b":code") is original


async def test_consecutive_current_then_parent_cycles_reuse_each_prior_block(executor):
    collector, rpc, finality, verifier = setup()
    refs = [finality.snapshot]
    for offset in range(1, 5):
        refs.append(
            replace(
                refs[0],
                block_number=refs[0].block_number + offset,
                block_hash=_hash(10 + offset),
                parent_hash=refs[-1].block_hash,
            )
        )
    originals = {}
    for current, parent in zip(refs[1:], refs[:-1], strict=True):
        for ref in (current, parent):
            rpc.responses["state_getReadProof"]["at"] = ref.block_hash
            runtime = await collect_executed_runtime(collector, executor, ref)
            if ref in originals:
                assert runtime.code_evidence is originals[ref].code_evidence
                assert runtime._runtime is not originals[ref]._runtime
            else:
                originals[ref] = runtime
    assert len(rpc.calls) == 2 * len(refs)
    assert len(verifier.single_calls) == len(refs)


async def test_failed_proof_is_not_cached():
    accepting = False

    def verify(**kw):
        return accepting

    collector, rpc, finality, _ = setup(verifier=verify)
    with pytest.raises(ValidatorChainError, match="storage_proof_verification_failed"):
        await collector.storage_evidence(finality.snapshot, b":code")
    accepting = True
    await collector.storage_evidence(finality.snapshot, b":code")
    assert len(rpc.calls) == 4


async def test_failed_rpc_is_not_cached():
    collector, rpc, finality, _ = setup()
    rpc.responses["state_getStorageAt"] = OSError("offline")
    with pytest.raises(ValidatorChainError, match="storage_proof_rpc_failed"):
        await collector.storage_evidence(finality.snapshot, b":code")
    rpc.responses["state_getStorageAt"] = "0x76616c7565"
    await collector.storage_evidence(finality.snapshot, b":code")
    assert len(rpc.calls) == 3


@pytest.mark.parametrize("budget", [0, 1])
async def test_disabled_or_undersized_budget_preserves_uncached_reads(budget):
    collector, rpc, finality, verifier = setup(budget=budget)
    await collector.storage_evidence(finality.snapshot, b":code")
    await collector.storage_evidence(finality.snapshot, b":code")
    assert len(rpc.calls) == 4 and len(verifier.single_calls) == 2


async def test_storage_reuse_is_bounded_by_entries_and_bytes():
    collector, rpc, finality, _ = setup()
    for key in (b"a", b"b", b"c", b"a", b"d", b"b"):
        await collector.storage_evidence(finality.snapshot, key)
    assert len(rpc.calls) == 10  # b was evicted after d; the a retry reused evidence.
    collector, rpc, finality, _ = setup(budget=15)
    for key in (b"a", b"b", b"a"):
        await collector.storage_evidence(finality.snapshot, key)
    assert len(rpc.calls) == 6  # each 11-byte record fits; two exceed the byte budget.


async def test_absence_and_independent_collectors_still_bind_their_sources():
    first, rpc, finality, _ = setup()
    rpc.responses["state_getStorageAt"] = None
    missing = await first.storage_evidence(finality.snapshot, b"missing")
    assert await first.storage_evidence(finality.snapshot, b"missing") is missing
    other, other_rpc, _, _ = setup()
    assert (await other.storage_evidence(finality.snapshot, b"missing")).value == b"value"
    assert len(other_rpc.calls) == 2


@pytest.mark.parametrize("budget", [-1, True, 1.5, 64 * 1024**2 + 1])
def test_invalid_reuse_budget_rejected(budget):
    with pytest.raises(ValueError, match="reuse budget"):
        setup(budget=budget)


def test_only_owned_runtime_code_collector_selects_bounded_reuse(tmp_path):
    proof = tmp_path / "proof"
    proof.write_bytes(b"#!/bin/sh\nexit 1\n")
    proof.chmod(0o500)
    config = SimpleNamespace(
        rpc_url="wss://unused.invalid",
        proof_rpc_fallback_urls=(),
        runtime_metadata_binary=str(tmp_path / "runtime"),
        runtime_metadata_binary_sha256="a" * 64,
        proof_binary_sha256=hashlib.sha256(proof.read_bytes()).hexdigest(),
    )
    owner = SimpleNamespace(
        _owned=True,
        _runtime_proof_reads=False,
        config=config,
        _finality=FakeFinality(),
        resources=SimpleNamespace(
            proof_binary=str(tmp_path / "proof"), runtime_metadata_binary=str(tmp_path / "runtime")
        ),
    )
    FinalizedCompetitionWeightProvider._configure_weight_collector(owner)
    assert owner._proofs._storage_evidence_budget == 0
    assert owner._runtime_proofs._storage_evidence_budget == 3 * (2 * MAX_CODE_BYTES + 1024**2)
