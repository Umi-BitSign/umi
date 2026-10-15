"""Real owned provider/store lifecycle with explicitly synthetic chain ports.

The observer transcript source, RPC values and trie verification are deterministic
test ports. The provider constructors, durable GRANDPA store/parser/audit, run
threads, weight collector, root flock, observation capability and shutdown are
the production implementations. This suite grants no live-chain qualification.
"""

from __future__ import annotations

import asyncio
import hashlib
import queue
import threading
import time
from types import SimpleNamespace

import pytest

from umi import competition_chain as chain_module
from umi import competition_chain_state as weight_module
from umi import competition_supervisor_observer as observer_module
from umi import competition_weight_rpc as rpc_module
from umi.chain_evidence import FinalizedSnapshotRef
from umi.competition_chain_resources import CompetitionChainResources
from umi.competition_chain_state import (
    FinalizedCompetitionWeightProvider,
    validate_owned_weight_observation,
)
from umi.competition_supervisor_observer import (
    OwnedSuccessorHostObserver,
    SuccessorHostObserverConfig,
)
from umi.competition_worker_cli import (
    WORKER_CHAIN_SPEC,
    WORKER_FINALITY_BINARY,
    WORKER_FINALITY_STATE_ROOT,
    WORKER_PROOF_BINARY,
)
from umi.grandpa_finality import GrandpaFinalityObserver
from umi.grandpa_finality_supervisor import DurableGrandpaFinalityPort, ObserverRunBinding
from umi.open_competition import digest

from .test_competition_chain import _Rpc, _Runtime, _Verifier
from .test_competition_chain import chain_config as chain_config
from .test_grandpa_finality_supervisor import _attestation, _header
from .test_open_competition import policy as policy
from .test_open_competition import wallet


async def _until(predicate):
    async def wait():
        while not predicate():
            await asyncio.sleep(0.005)

    await asyncio.wait_for(wait(), 5)


@pytest.fixture
def native_lifecycle_case(chain_config, policy, monkeypatch, tmp_path):
    """Map fixed production paths into one isolated test resource directory."""
    binary = tmp_path / "synthetic-observer-port"
    binary.write_bytes(b"#!/bin/sh\nexit 99\n")
    binary.chmod(0o500)
    spec = tmp_path / "synthetic-chain-spec.json"
    spec.write_bytes(b"{}")
    spec.chmod(0o400)
    binary_sha = hashlib.sha256(binary.read_bytes()).hexdigest()
    spec_sha = hashlib.sha256(spec.read_bytes()).hexdigest()
    target = "x86_64-unknown-linux-gnu"
    config = chain_config.model_copy(
        update={
            "target_triple": target,
            "finality_pin": chain_config.finality_pin.model_copy(
                update={
                    "release_sha256_by_target": {target: binary_sha},
                    "chain_spec_sha256": spec_sha,
                }
            ),
            "finality_binary": str(WORKER_FINALITY_BINARY),
            "proof_binary": str(WORKER_PROOF_BINARY),
            "chain_spec": str(WORKER_CHAIN_SPEC),
            "state_directory": str(WORKER_FINALITY_STATE_ROOT),
            "startup_timeout_seconds": 5,
            "minimum_finalized_block": chain_config.minimum_finalized_block + 1,
        }
    )
    resources = CompetitionChainResources(
        finality_binary=str(binary),
        chain_spec=str(spec),
        proof_binary=str(tmp_path / "synthetic-trie-port"),
        state_directory=str(tmp_path / "owned-state"),
    )
    now = time.time_ns() // 1_000_000
    state = SimpleNamespace(timestamp=now, ref=None)
    rpc = _Rpc(state)
    verifier = _Verifier(state, rpc.values)
    hotkey = wallet("Eve").hotkey.ss58_address
    rpc.values.update(
        {
            ("SubtensorModule", name, (78,)): value
            for name, value in {
                "SubnetworkN": 256,
                "ValidatorPermit": [False] * 54 + [True] + [False] * 201,
                "LastUpdate": [0] * 256,
                "MechanismCountCurrent": 1,
                "CommitRevealWeightsEnabled": False,
                "WeightsVersionKey": 2**32,
                "MinAllowedWeights": 256,
                "MaxAllowedUids": 256,
                "MaxWeightsLimit": 65535,
                "WeightsSetRateLimit": 10,
            }.items()
        }
    )
    rpc.values.update(
        {
            ("SubtensorModule", "Uids", (78, hotkey)): 54,
            ("SubtensorModule", "Keys", (78, 54)): hotkey,
            ("SubtensorModule", "Weights", (78, 54)): [[0, 123], [54, 456]],
            ("System", "Account", (hotkey,)): {"nonce": 4, "providers": 1},
            ("Commitments", "CommitmentOf", (78, hotkey)): None,
        }
    )
    case = SimpleNamespace(
        config=config,
        policy=policy,
        resources=resources,
        providers=[],
        sources=[],
        constructor_threads=[],
        before_constructor=None,
        constructor_entered=threading.Event(),
        constructor_release=None,
        rpc_closes=0,
        rpc=rpc,
        verifier=verifier,
        state=state,
        headers={},
    )

    async def close_rpc():
        case.rpc_closes += 1

    original_request = rpc.request

    async def request(method, params):
        if method == "state_queryStorageAt":
            keys, block_hash = params
            return [
                {
                    "block": block_hash,
                    "changes": [
                        [key, await original_request("state_getStorageAt", (key, block_hash))]
                        for key in keys
                    ],
                }
            ]
        return await original_request(method, params)

    monkeypatch.setattr(rpc, "aclose", close_rpc, raising=False)
    monkeypatch.setattr(rpc, "request", request)
    monkeypatch.setattr("umi.validator_chain.bittensor_core.Runtime", _Runtime)
    monkeypatch.setattr(chain_module, "_RegistrationRpc", lambda *a, **kw: rpc)
    monkeypatch.setattr(rpc_module, "_WeightProofTransport", lambda *a, **kw: rpc)
    monkeypatch.setattr(chain_module, "SubprocessStorageProofVerifier", lambda **kw: verifier)
    monkeypatch.setattr(weight_module, "SubprocessStorageProofVerifier", lambda **kw: verifier)

    def synthetic_transcript_source(pin, **kwargs):
        # Explicitly bypass published chain-spec qualification for this synthetic
        # port only. The real parser and store still validate every transcript.
        source = GrandpaFinalityObserver(
            binary_path=resources.finality_binary,
            expected_binary_sha256=pin.release_sha256_by_target[target],
            chain_spec_path=resources.chain_spec,
            expected_chain_spec_sha256=pin.chain_spec_sha256,
            expected_genesis_hash="0x" + pin.expected_genesis_hash,
            bootstrap_block_number=pin.bootstrap_block_number,
            bootstrap_block_hash="0x" + pin.bootstrap_block_hash,
        )
        pending = queue.Queue()
        stopped = threading.Event()

        def attestations(*, stop_requested, **parameters):
            binding = ObserverRunBinding(segment_index=0, **parameters)
            previous = None
            try:
                for sequence in range(parameters["maximum_records"]):
                    while not stop_requested():
                        try:
                            header = pending.get(timeout=0.01)
                        except queue.Empty:
                            continue
                        break
                    else:
                        return
                    previous = _attestation(
                        source, binding, block=header, sequence=sequence, previous=previous
                    )
                    yield previous
            finally:
                stopped.set()

        source.attestations = attestations
        case.sources.append(SimpleNamespace(source=source, pending=pending, stopped=stopped))
        return source

    monkeypatch.setattr(
        chain_module.GrandpaFinalityObserver, "from_policy_pin", synthetic_transcript_source
    )

    def construct(selected_config, selected_policy):
        # A real provider is constructed with its owned (uninjected) finality
        # path. Only local resources and the external chain ports are replaced.
        with pytest.raises(RuntimeError, match="no running event loop"):
            asyncio.get_running_loop()
        case.constructor_threads.append(threading.get_ident())
        if case.before_constructor is not None:
            case.before_constructor()
        provider = FinalizedCompetitionWeightProvider(
            selected_config, selected_policy, resources=resources, now_ms=lambda: now
        )
        case.providers.append(provider)
        case.constructor_entered.set()
        if case.constructor_release is not None:
            assert case.constructor_release.wait(5), "test constructor release was not signaled"
        return provider

    monkeypatch.setattr(observer_module, "FinalizedCompetitionWeightProvider", construct)
    installation = SimpleNamespace(
        config=SimpleNamespace(target_platform="linux/amd64", validator_hotkey=hotkey),
        observer_config=SuccessorHostObserverConfig(
            schema="umi-successor-host-observer-config/1", policy=policy, chain=config
        ),
        checkpoint_finalized_block=config.minimum_finalized_block,
    )

    def validate_test_installation(value):
        if value is not installation:
            raise ValueError("synthetic installation identity mismatch")

    monkeypatch.setattr(
        observer_module, "validate_authenticated_successor_installation", validate_test_installation
    )
    case.installation = installation
    case.observer = OwnedSuccessorHostObserver(installation=installation)

    def advance(height):
        parent = case.headers.get(height - 1, {}).get("hash", "0x" + "11" * 32)
        header = _header(height, parent_hash=parent, seed=height % 200 + 1)
        header["timestamp_ms"] = now
        case.headers[height] = header
        state.ref = FinalizedSnapshotRef(
            height, header["hash"], header["parent_hash"], header["state_root"]
        )
        case.sources[-1].pending.put(header)

    case.advance = advance
    return case


async def _observe_at(case, height, *, config=None):
    expected_config = case.config if config is None else config
    request = asyncio.create_task(
        case.observer.observe()
        if config is None
        else case.observer._capture(config, case.policy, ())
    )

    def ready():
        if request.done():
            request.result()
        return (
            case.observer._provider is not None
            and case.observer._provider.config == expected_config
            and case.observer._provider._task is not None
        )

    try:
        await _until(ready)
        # Allow the owned floor wait to begin before advancing its source.
        await asyncio.sleep(0.02)
        assert not request.done()
        case.advance(height)
        observation = await asyncio.wait_for(request, 5)
    finally:
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)
    validate_owned_weight_observation(observation)
    assert observation.block == height
    assert observation.validator_uid == 54 and observation.validator_permit
    assert observation.validator_row == ((0, 123), (54, 456))
    return observation


async def test_real_owned_store_reused_then_closed_and_reopened(native_lifecycle_case):
    case = native_lifecycle_case
    height = case.config.minimum_finalized_block
    try:
        first = await _observe_at(case, height)
        provider = case.providers[0]
        assert type(provider._finality) is DurableGrandpaFinalityPort
        assert provider._owned and provider._cache_lease is not None
        task = provider._task
        retained = (await provider._finality.verified_block_at(height)).finality_evidence
        second = await _observe_at(case, height + 1)
        assert len(case.providers) == 1 and provider._task is task
        assert second.block > first.block
        assert provider.observation_floor() == height + 1
        with pytest.raises(BlockingIOError):
            await asyncio.to_thread(
                FinalizedCompetitionWeightProvider,
                case.config,
                case.policy,
                resources=case.resources,
            )
        await case.observer.aclose()
        assert task.done() and case.sources[0].stopped.is_set()
        assert provider._closed and provider._cache_lease is None

        case.observer = OwnedSuccessorHostObserver(installation=case.installation)
        third = await _observe_at(case, height + 2)
        reopened = case.providers[-1]
        assert len(case.providers) == 2 and reopened._startup_floor == height + 1
        assert third.block > second.block
        assert (await reopened._finality.verified_block_at(height)).finality_evidence == retained
        await asyncio.to_thread(reopened._finality.audit)
        assert all(t != threading.get_ident() for t in case.constructor_threads)
        assert len(case.verifier.checked) >= 9
    finally:
        await case.observer.aclose()
    assert all(p._task.done() and p._cache_lease is None for p in case.providers)


async def test_config_switch_drains_real_root_lease_before_reconstruction(native_lifecycle_case):
    case = native_lifecycle_case
    height = case.config.minimum_finalized_block
    try:
        await _observe_at(case, height)
        first = case.providers[0]

        def require_previous_drained():
            previous = case.providers[-1]
            assert previous._closed and previous._cache_lease is None
            assert previous._task.done() and case.sources[-1].stopped.is_set()

        case.before_constructor = require_previous_drained
        changed = case.config.model_copy(update={"collection_timeout_seconds": 121})
        second = await _observe_at(case, height + 1, config=changed)
        assert second.chain_config_sha256 == digest(changed)
        assert case.providers[-1]._path != first._path
        third = await _observe_at(case, height + 1)
        assert third.chain_config_sha256 == digest(case.config)
        assert len(case.providers) == 3
        assert case.providers[-1]._path == first._path
        assert case.providers[-1]._startup_floor == height
    finally:
        await case.observer.aclose()
    assert all(p._cache_lease is None and p._task.done() for p in case.providers)


@pytest.mark.parametrize("during_constructor", [False, True])
async def test_cancellation_drains_real_owned_resources(native_lifecycle_case, during_constructor):
    case = native_lifecycle_case
    if during_constructor:
        case.constructor_release = threading.Event()
    request = asyncio.create_task(case.observer.observe())
    try:
        await _until(case.constructor_entered.is_set)
        if not during_constructor:
            await _until(lambda: case.providers[0]._task is not None)
            await asyncio.sleep(0.02)
        request.cancel()
        await asyncio.sleep(0.01)
        request.cancel()
        if during_constructor:
            case.constructor_release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(request, 5)
        provider = case.providers[0]
        assert provider._closed and provider._cache_lease is None
        assert provider._task is None or provider._task.done()
        assert case.observer._provider is None
        # Reacquisition exercises the actual root flock after cancellation.
        case.constructor_release = None
        await _observe_at(case, case.config.minimum_finalized_block)
    finally:
        if case.constructor_release is not None:
            case.constructor_release.set()
        if not request.done():
            request.cancel()
        await case.observer.aclose()
