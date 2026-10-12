"""Native trie extraction against a retained public Finney proof.

The snapshot is a fixture, not a live finality or payment observation.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from pathlib import Path

import pytest

from umi.chain_evidence import FinalizedSnapshotRef
from umi.substrate_proof import SubprocessStorageProofVerifier, SubstrateProofVerifierError
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "rust/substrate-proof-verifier/fixtures/finney-state-v1.json"


@pytest.fixture(scope="module")
def native_verifier(tmp_path_factory):
    configured = os.environ.get("UMI_TEST_PROOF_BINARY")
    path = (
        Path(configured)
        if configured
        else ROOT / "rust/substrate-proof-verifier/target/release/umi-substrate-proof-verifier"
    )
    if not path.is_file():
        if configured:
            pytest.fail("configured native proof binary is missing")
        pytest.skip("native proof binary is not built")
    # Cargo may hardlink its release executable to a build output. Test the
    # same singly linked executable boundary used by deployed installations.
    binary = tmp_path_factory.mktemp("proof-read-binary") / path.name
    shutil.copyfile(path, binary)
    binary.chmod(0o700)
    return SubprocessStorageProofVerifier(
        binary_path=binary,
        expected_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
        timeout_seconds=10,
    )


@pytest.fixture
def proof():
    raw = json.loads(FIXTURE.read_bytes())
    items = tuple(
        (bytes.fromhex(i["key"][2:]), None if i["value"] is None else bytes.fromhex(i["value"][2:]))
        for i in raw["items"]
    )
    return raw, items, tuple(bytes.fromhex(node[2:]) for node in raw["proof"])


def test_native_read_matches_independently_verified_claims(native_verifier, proof):
    raw, items, nodes = proof
    root = bytes.fromhex(raw["state_root"][2:])
    result = native_verifier.read_many(
        state_root=root,
        storage_keys=tuple(key for key, _ in items),
        proof=nodes,
        maximum_total_value_bytes=64 * 1024**2,
    )
    assert result == items
    assert native_verifier.verify_many(state_root=root, items=result, proof=nodes)


def test_native_success_reuse_rejects_changed_claims_roots_and_proofs(native_verifier, proof):
    raw, items, nodes = proof
    request = dict(state_root=bytes.fromhex(raw["state_root"][2:]), items=items, proof=nodes)
    assert native_verifier.verify_many(**request)
    assert native_verifier.verify_many(**request)
    key = next(key for key, value in items if value)
    changed = tuple((k, v + b"\x00" if k == key else v) for k, v in items)
    for fault in (
        {"state_root": bytes(32)},
        {"items": changed},
        {"proof": nodes[:-1]},
        {"proof": (bytes([nodes[0][0] ^ 1]) + nodes[0][1:], *nodes[1:])},
    ):
        with pytest.raises(SubstrateProofVerifierError):
            native_verifier.verify_many(**(request | fault))
    assert native_verifier.verify_many(**request)


@pytest.mark.parametrize("fault", ["root", "missing-node", "changed-node", "limit"])
def test_native_read_rejects_invalid_proofs_without_returning_claims(native_verifier, proof, fault):
    raw, items, nodes = proof
    root, limits = bytes.fromhex(raw["state_root"][2:]), {}
    if fault == "root":
        root = b"\xff" * 32
    elif fault == "missing-node":
        nodes = nodes[:-1]
    elif fault == "changed-node":
        nodes = (bytes([nodes[0][0] ^ 1]) + nodes[0][1:], *nodes[1:])
    else:
        limits["maximum_value_bytes"] = 1
    with pytest.raises(SubstrateProofVerifierError) as error:
        native_verifier.read_many(
            state_root=root,
            storage_keys=tuple(key for key, _ in items),
            proof=nodes,
            **limits,
        )
    assert error.value.reason_code == ("value_limit" if fault == "limit" else "invalid_proof")


@pytest.mark.asyncio
@pytest.mark.parametrize("bad_block", [False, True])
async def test_native_collector_uses_only_one_proof_rpc(native_verifier, proof, bad_block):
    raw, items, _ = proof
    snapshot = FinalizedSnapshotRef(
        block_number=raw["block_number"],
        block_hash=raw["block_hash"],
        parent_hash="0x" + "00" * 32,
        state_root=raw["state_root"],
    )
    calls = []

    class Rpc:
        async def request(self, method, params):
            calls.append((method, params))
            assert method == "state_getReadProof"
            assert params == ([item["key"] for item in raw["items"]], raw["block_hash"])
            return {
                "at": snapshot.parent_hash if bad_block else raw["block_hash"],
                "proof": raw["proof"],
            }

    class UnusedFinality:
        async def verified_finalized_snapshot(self):
            pytest.fail("fixture test should not collect new finality")

    collector = FinalizedProofCollector(Rpc(), finality=UnusedFinality(), verifier=native_verifier)
    if bad_block:
        with pytest.raises(ValidatorChainError, match="storage_proof_block_mismatch"):
            await collector.storage_evidence_many_from_proof(
                snapshot, tuple(key for key, _ in items)
            )
    else:
        result = await collector.storage_evidence_many_from_proof(
            snapshot, tuple(key for key, _ in items)
        )
        assert tuple((claim.storage_key, claim.value) for claim in result.claims) == items
        assert result.snapshot == snapshot
    assert len(calls) == 1
