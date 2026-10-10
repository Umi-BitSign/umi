from __future__ import annotations

import asyncio
import threading
from dataclasses import replace

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.substrate_proof import SubstrateProofVerifierError
from umi.validator_chain import FinalizedProofCollector, ProofCollectionLimits, ValidatorChainError


def snapshot(height):
    def hash_value(value):
        return "0x" + value.to_bytes(32, "big").hex()

    return FinalizedSnapshotRef(
        block_number=height,
        block_hash=hash_value(height),
        parent_hash=hash_value(height - 1),
        state_root=hash_value(height + 100),
    )


class Fixture:
    def __init__(self):
        self.snapshots = [snapshot(42), snapshot(43)]
        self.values = [b"original wasm", b"original wasm"]
        self.calls = []
        self.checked = []
        self.aux_error = None
        self.composite_error = None
        self.wrong_aux_block = False
        self.wrong_aux_shape = False
        self.thread_gate = None
        self.collector = FinalizedProofCollector(
            self,
            finality=self,
            verifier=self,
            read_values_from_proof=True,
            maximum_cached_storage_evidence_bytes=4096,
        )

    async def verified_finalized_snapshot(self):
        return self.snapshots[-1]

    def root_node(self, index):
        return b"root:" + self.snapshots[index].state_root.encode()

    def code_node(self, index):
        return b"code:" + (self.values[index] or b"absent")

    def code_proof(self, index):
        return (self.root_node(index), self.code_node(index), b"code branch")

    async def request(self, method, params):
        self.calls.append((method, params))
        assert method == "state_getReadProof"
        index = next(i for i, s in enumerate(self.snapshots) if s.block_hash == params[1])
        key = bytes.fromhex(params[0][0][2:])
        if key == b":code":
            nodes = self.code_proof(index)
        else:
            assert key == b":heappages"
            nodes = (self.root_node(index), b"heappages branch", b"shared")
        block = self.snapshots[index].block_hash
        if self.wrong_aux_block and key == b":heappages":
            block = self.snapshots[0].block_hash
        return {"at": block, "proof": ["0x" + n.hex() for n in nodes]}

    def read_many(self, *, state_root, storage_keys, proof, **limits):
        assert len(storage_keys) == 1
        key = storage_keys[0]
        index = next(
            i for i, s in enumerate(self.snapshots) if bytes.fromhex(s.state_root[2:]) == state_root
        )
        assert self.root_node(index) in proof
        if key == b":heappages":
            if self.aux_error:
                raise SubstrateProofVerifierError(self.aux_error)
            return ((b"wrong" if self.wrong_aux_shape else key, None),)
        assert key == b":code" and self.code_node(index) in proof
        return ((key, self.values[index]),)

    def __call__(self, *, state_root, storage_key, expected_value, proof):
        assert storage_key == b":code"
        index = next(
            i for i, s in enumerate(self.snapshots) if bytes.fromhex(s.state_root[2:]) == state_root
        )
        self.checked.append((index, proof))
        is_composite = b"heappages branch" in proof
        if is_composite and self.thread_gate:
            entered, release = self.thread_gate
            entered.set()
            assert release.wait(10)
        if is_composite and self.composite_error:
            raise SubstrateProofVerifierError(self.composite_error)
        if (
            self.root_node(index) not in proof
            or self.code_node(index) not in proof
            or expected_value != self.values[index]
        ):
            raise SubstrateProofVerifierError("invalid_proof")
        return True

    async def collect(self, index):
        return await self.collector.storage_evidence(self.snapshots[index], b":code")

    def requested_keys(self):
        return [bytes.fromhex(params[0][0][2:]) for _, params in self.calls]


@pytest.mark.asyncio
async def test_new_root_authenticates_reused_code_and_exact_snapshot_hits_cache():
    f = Fixture()
    old = await f.collect(0)
    new = await f.collect(1)
    assert new.value == old.value and new.snapshot == f.snapshots[1]
    assert new.verified_state_root == f.snapshots[1].state_root
    assert f.requested_keys() == [b":code", b":heappages"]
    assert f.checked[-1][0] == 1
    assert len(set(new.proof)) == len(new.proof)
    assert await f.collect(1) is new
    assert len(f.calls) == 2


@pytest.mark.asyncio
@pytest.mark.parametrize("value", [b"upgraded wasm", None, b""])
async def test_changed_runtime_fetches_full_proof_at_same_new_block(value):
    f = Fixture()
    f.values[1] = value
    await f.collect(0)
    new = await f.collect(1)
    assert new.value == value
    assert new.proof == f.code_proof(1)
    assert f.requested_keys() == [b":code", b":heappages", b":code"]
    assert f.calls[-1][1][1] == f.snapshots[1].block_hash


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure",
    ["invalid_proof", "invalid_input", "invalid_sidecar_response", "wrong_block", "wrong_shape"],
)
async def test_bad_auxiliary_proof_never_falls_back_or_retains_evidence(failure):
    f = Fixture()
    await f.collect(0)
    if failure == "wrong_block":
        f.wrong_aux_block = True
    elif failure == "wrong_shape":
        f.wrong_aux_shape = True
    else:
        f.aux_error = failure
    with pytest.raises(ValidatorChainError):
        await f.collect(1)
    assert f.requested_keys() == [b":code", b":heappages"]
    assert all(e.snapshot == f.snapshots[0] for e, _ in f.collector._storage_evidence.values())


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure", ["sidecar_timeout", "invalid_sidecar_response", "invalid_input"]
)
async def test_verifier_operational_failure_is_not_a_branch_cache_miss(failure):
    f = Fixture()
    await f.collect(0)
    f.composite_error = failure
    with pytest.raises(ValidatorChainError, match="storage_proof_verification_failed"):
        await f.collect(1)
    assert f.requested_keys() == [b":code", b":heappages"]
    assert len(f.collector._storage_evidence) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("bound", ["nodes", "bytes"])
async def test_composed_proof_stays_bounded_and_resets_to_full_proof(bound):
    f = Fixture()
    limit = (
        {"maximum_proof_nodes": 4}
        if bound == "nodes"
        else {"maximum_proof_bytes": 100, "maximum_proof_node_bytes": 100}
    )
    f.collector._limits = ProofCollectionLimits(**limit)
    await f.collect(0)
    new = await f.collect(1)
    assert new.proof == f.code_proof(1)
    assert f.requested_keys() == [b":code", b":heappages", b":code"]
    assert all(b"heappages branch" not in proof for _, proof in f.checked)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["parent", "height", "no_cache"])
async def test_only_adjacent_parent_proofs_are_used(change):
    f = Fixture()
    if change == "parent":
        f.snapshots[1] = replace(f.snapshots[1], parent_hash="0x" + "ff" * 32)
    elif change == "height":
        f.snapshots[1] = replace(f.snapshots[1], block_number=44)
    else:
        f.collector._storage_evidence_budget = 0
    await f.collect(0)
    await f.collect(1)
    assert f.requested_keys() == [b":code", b":code"]


@pytest.mark.asyncio
async def test_repeated_cancellation_drains_composite_check_without_retention():
    f = Fixture()
    await f.collect(0)
    entered, release = threading.Event(), threading.Event()
    f.thread_gate = (entered, release)
    task = asyncio.create_task(f.collect(1))
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
        assert not task.done()
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert len(f.collector._storage_evidence) == 1
    assert f.requested_keys() == [b":code", b":heappages"]
