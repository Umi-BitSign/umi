from __future__ import annotations

import asyncio

import pytest

from umi.competition_chain import FinalizedRegistrationProvider
from umi.competition_chain_state import FinalizedCompetitionWeightProvider
from umi.competition_weight_rpc import WeightProofRpc
from umi.validator_chain import FinalizedProofCollector, ValidatorChainError

from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_chain import policy as policy
from .test_competition_proof_rpc import tables, with_fallback
from .test_competition_proof_rpc import wire as wire


@pytest.fixture
async def weight_rpc(chain, wire):
    rpc = WeightProofRpc(with_fallback(chain.config))
    try:
        yield rpc
    finally:
        await rpc.aclose()


@pytest.mark.parametrize("second", [False, True])
async def test_weight_proof_fallback_keeps_native_validation(chain, wire, weight_rpc, second):
    state, _ = wire
    state.fallback_rpc_error = second
    provider = FinalizedRegistrationProvider(
        with_fallback(chain.config),
        chain.policy,
        finality=chain.finality,
        proofs=FinalizedProofCollector(
            weight_rpc, finality=chain.finality, verifier=chain.verifier
        ),
        now_ms=lambda: chain.clock.now,
    )
    try:
        capture = await provider.collect()
        assert len(capture.snapshot.registrations) == 2
        assert len(chain.verifier.checked) == 3
        expected = "/second-backup" if second else "/fallback"
        assert expected in state.handshakes
        assert state.handshakes.count("/primary") == 1
        for _path, method, params in state.reads:
            assert method != "chain_getFinalizedHead"
            if method in {"state_getStorageAt", "state_getReadProof"}:
                assert params[1] == chain.finality.ref.block_hash
    finally:
        await provider.aclose()
        await weight_rpc.aclose()
    assert all(socket.close_code is not None for socket in state.sockets)


@pytest.mark.parametrize("bad", ["proof", "root", "protocol"])
async def test_invalid_response_or_proof_never_selects_another_provider(
    chain, wire, weight_rpc, bad
):
    state, _ = wire
    if bad == "proof":
        chain.rpc.bad_proof = True
    elif bad == "root":
        chain.rpc.header_root = "0x" + "ff" * 32
    else:
        state.malformed = True
    provider = FinalizedRegistrationProvider(
        with_fallback(chain.config),
        chain.policy,
        finality=chain.finality,
        proofs=FinalizedProofCollector(
            weight_rpc, finality=chain.finality, verifier=chain.verifier
        ),
        now_ms=lambda: chain.clock.now,
    )
    try:
        with pytest.raises((ValueError, RuntimeError, ValidatorChainError)):
            await provider.collect()
        assert tables(provider._path)["captures"] == []
        assert "/second-backup" not in state.handshakes
    finally:
        await provider.aclose()


async def test_prefetched_weights_and_runtime_code_use_fallback_with_separate_pools(
    chain, wire, weight_rpc, monkeypatch
):
    state, _ = wire
    state.fallback_rpc_error = True
    block = chain.finality.ref.block_hash
    code = "0x" + "ab" * (65536 + 1)  # Runtime code must retain the larger receive ceiling.

    async def claims(method, params):
        if method == "state_queryStorageAt":
            assert params[1] == block
            return [{"block": block, "changes": [[key, "0x01"] for key in params[0]]}]
        assert method == "state_getStorageAt" and params == ["0x3a636f6465", block]
        return code

    monkeypatch.setattr(chain.rpc, "request", claims)
    runtime = WeightProofRpc(weight_rpc.config)
    try:
        async with weight_rpc.read_batch(block, (b"a", b"b")):
            assert await weight_rpc.request("state_getStorageAt", ("0x61", block)) == "0x01"
            assert await weight_rpc.request("state_getStorageAt", ("0x62", block)) == "0x01"
            assert await runtime.request("state_getStorageAt", ("0x3a636f6465", block)) == code
            with pytest.raises(ValueError, match="differs"):
                await weight_rpc.request("state_getStorageAt", ("0x61", "0x" + "cd" * 32))
        assert all(
            method != "state_getStorageAt" or params[0] == "0x3a636f6465"
            for _, method, params in state.reads
        )
        assert state.handshakes.count("/primary") == 2
        await weight_rpc.aclose()
        assert await runtime.request("state_getStorageAt", ("0x3a636f6465", block)) == code
    finally:
        await runtime.aclose()
    assert all(socket.close_code is not None for socket in state.sockets)


async def test_cancellation_does_not_try_backup_and_discards_socket(chain, wire, weight_rpc):
    state, _ = wire
    state.primary_status = 0
    state.block = True
    task = asyncio.create_task(
        weight_rpc.request("chain_getHeader", (chain.finality.ref.block_hash,))
    )
    await asyncio.wait_for(state.started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert state.handshakes == ["/primary"]
    state.release.set()
    state.block = False
    assert (await weight_rpc.request("chain_getHeader", (chain.finality.ref.block_hash,)))[
        "stateRoot"
    ] == chain.finality.ref.state_root
    assert state.handshakes == ["/primary", "/primary"]


async def test_owned_weight_and_runtime_collectors_receive_fallback_config(chain, monkeypatch):
    config = with_fallback(chain.config).model_copy(
        update={
            "runtime_metadata_binary": "/test/runtime-executor",
            "runtime_metadata_binary_sha256": "ab" * 32,
        }
    )
    monkeypatch.setattr("umi.competition_chain_state.RuntimeMetadataExecutor", lambda **_: object())
    monkeypatch.setattr(
        "umi.competition_chain_state.SubprocessStorageProofVerifier", lambda **_: chain.verifier
    )
    provider = FinalizedCompetitionWeightProvider(
        config,
        chain.policy,
        finality=chain.finality,
        proofs=chain.proofs,
        now_ms=lambda: chain.clock.now,
    )
    try:
        provider._owned = True
        provider._configure_weight_collector()
        for rpc in (provider._weight_rpc, provider._runtime_rpc):
            assert tuple(t.endpoint for t in rpc._rpc.transports) == (
                config.rpc_url,
                *config.proof_rpc_fallback_urls,
            )
        assert provider._weight_rpc._rpc is not provider._runtime_rpc._rpc
        assert provider._proofs._limits.maximum_storage_value_bytes == 65536
        assert provider._runtime_proofs._limits.maximum_storage_value_bytes > 65536
    finally:
        provider._owned = False
        await provider.aclose()
