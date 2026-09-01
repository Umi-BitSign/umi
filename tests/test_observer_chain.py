from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from umi.observer_chain import (
    BittensorChainCollector,
    ChainCollectionError,
    _default_client_factory,
)

BLOCK_HASH = "0x" + "11" * 32
PARENT_HASH = "0x" + "22" * 32
STATE_ROOT = "0x" + "33" * 32
EXTRINSICS_ROOT = "0x" + "44" * 32
BLOCK_TIME = datetime(2026, 9, 1, 16, 0, tzinfo=timezone.utc)


class FinalizedHeaders:
    def __init__(self, header: Any) -> None:
        self.header = header
        self.closed = False
        self.yielded = False

    def __aiter__(self) -> FinalizedHeaders:
        return self

    async def __anext__(self) -> Any:
        if self.yielded:
            raise StopAsyncIteration
        self.yielded = True
        return self.header

    async def aclose(self) -> None:
        self.closed = True


class FakeSubnets:
    def __init__(self, metagraph: Any) -> None:
        self.metagraph_value = metagraph
        self.calls: list[tuple[int, bool]] = []

    async def metagraph(self, *, netuid: int, commitments: bool) -> Any:
        self.calls.append((netuid, commitments))
        return self.metagraph_value


class FakeSnapshot:
    def __init__(self, *, metagraph_block: int = 99, info_state_root: str = STATE_ROOT) -> None:
        self.block = 99
        neurons = [
            SimpleNamespace(
                uid=0,
                hotkey="5Miner",
                active=True,
                validator_permit=False,
                block_at_registration=10,
                last_update=90,
                axon="198.51.100.10:8091",
            ),
            SimpleNamespace(
                uid=1,
                hotkey="5Validator",
                active=True,
                validator_permit=True,
                block_at_registration=11,
                last_update=91,
                axon=None,
            ),
        ]
        self.metagraph = SimpleNamespace(
            netuid=78,
            mechid=0,
            block=metagraph_block,
            neurons=neurons,
            num_uids=2,
            max_uids=256,
            tempo=360,
            last_step=50,
            blocks_since_last_step=49,
            name="Vocence",
            symbol="V",
            identity={"subnet_name": "Vocence", "github_repo": "private-value"},
            raw={
                "hotkeys": ["5Miner", "5Validator"],
                "active": [True, True],
                "validator_permit": [False, True],
                "block_at_registration": [10, 11],
                "last_update": [90, 91],
                "axons": ["198.51.100.10:8091", None],
                "rank": [],
                "trust": [],
                "consensus": [10, 20],
                "incentives": [30, 40],
                "dividends": [50, 60],
                "pruning_score": [],
                "emission": [2**64 - 1, 0],
                "alpha_stake": [2**53, 1],
                "tao_stake": [2**53 - 1, 2],
                "total_stake": [3, 4],
                "tao_in": 2_000_000_000,
                "alpha_in": 1_000_000_000,
            },
        )
        self.subnets = FakeSubnets(self.metagraph)
        self.read_calls: list[tuple[str, dict[str, Any]]] = []
        self.query_calls: list[tuple[str, list[Any] | None]] = []
        self.info_state_root = info_state_root

    async def block_info(self) -> Any:
        return SimpleNamespace(
            number=99,
            hash=BLOCK_HASH,
            timestamp=BLOCK_TIME,
            header={
                "number": 99,
                "parentHash": PARENT_HASH,
                "stateRoot": self.info_state_root,
                "extrinsicsRoot": EXTRINSICS_ROOT,
            },
        )

    async def read(self, name: str, **params: Any) -> Any:
        self.read_calls.append((name, params))
        values = {
            "subnet_hyperparameters": {
                "tempo": 360,
                "min_allowed_weights": 1,
                "weights_version": 0,
                "weights_rate_limit": 100,
                "immunity_period": 5_000,
                "activity_cutoff": 360,
                "max_weights_limit": 65_535,
                "commit_reveal_weights_enabled": True,
                "commit_reveal_period": 1,
                "subnet_is_active": True,
            },
            "epoch_status": {
                "netuid": 78,
                "block": 99,
                "tempo": 360,
                "epoch_index": 123,
                "last_epoch_block": 50,
                "next_epoch_start_block": 410,
                "pending_epoch_at": None,
                "blocks_since_last_step": 49,
                "blocks_remaining": 311,
                "seconds_remaining": 3_732.5,
            },
            "mechanism_count": 1,
            "mechanism_emission_split": [],
            "commit_reveal_enabled": True,
            "reveal_period": 1,
            "subnet_emission_enabled": False,
            "timelocked_weight_commits": {123: [{"hotkey": "5Validator"}]},
        }
        return values[name]

    async def query(self, item: Any, params: list[Any] | None = None) -> Any:
        self.query_calls.append((item.name, params))
        values = {
            "LastRuntimeUpgrade": {"spec_version": 452},
            "CommitRevealWeightsVersion": 4,
            "MaxMechanismCount": 2,
            "NetworksAdded": True,
        }
        return values[item.name]


class FakeClient:
    def __init__(self, snapshot: FakeSnapshot) -> None:
        self.snapshot = snapshot
        self.header_stream: FinalizedHeaders | None = None
        self.at_calls: list[int] = []

    async def __aenter__(self) -> FakeClient:
        return self

    async def __aexit__(self, *_: Any) -> None:
        return None

    def blocks(self, *, finalized: bool) -> FinalizedHeaders:
        assert finalized is True
        header = SimpleNamespace(
            number=99,
            parent_hash=PARENT_HASH,
            raw={
                "number": 99,
                "parentHash": PARENT_HASH,
                "stateRoot": STATE_ROOT,
                "extrinsicsRoot": EXTRINSICS_ROOT,
            },
        )
        self.header_stream = FinalizedHeaders(header)
        return self.header_stream

    async def at(self, block: int) -> FakeSnapshot:
        self.at_calls.append(block)
        return self.snapshot


@pytest.mark.asyncio
async def test_collector_uses_one_finalized_snapshot_and_exact_public_values() -> None:
    snapshot = FakeSnapshot()
    client = FakeClient(snapshot)
    collector = BittensorChainCollector(
        client_factory=lambda _: client,
        clock=lambda: BLOCK_TIME,
    )

    result = await collector.collect()

    assert client.at_calls == [99]
    assert client.header_stream is not None and client.header_stream.closed is True
    assert snapshot.subnets.calls == [(78, False)]
    assert result.sources[0].block is not None
    assert result.sources[0].block.number == "99"
    assert result.sources[0].block.hash == BLOCK_HASH
    assert result.sources[0].block.storage_proofs_verified is False
    assert result.network.runtime_spec_version == "452"
    assert result.network.commit_reveal_version == "4"
    assert result.network.reveal_period_epochs == "1"
    assert result.network.mechanism_count == 1
    assert result.network.maximum_mechanism_count == 2
    assert result.network.pending_weight_commit_count == 1
    assert result.network.subnet_exists is True
    assert result.network.subnet_started is True
    assert result.network.subnet_emission_enabled is False
    assert result.network.price is not None
    assert result.network.price.tao_reserve_rao == "2000000000"
    assert result.network.price.subnet_alpha_reserve_rao == "1000000000"
    assert result.network.price.display_decimal == "2"
    assert result.network.epoch.seconds_remaining is None
    assert "epoch.seconds_remaining" in result.network.unavailable_fields
    assert result.participants[0].chain_metrics.rank is None
    assert result.participants[0].chain_metrics.incentive is not None
    assert result.participants[0].chain_metrics.incentive.raw_numerator == "30"
    assert result.participants[0].chain_metrics.emission is not None
    assert result.participants[0].chain_metrics.emission.raw == str(2**64 - 1)
    assert result.participants[0].chain_metrics.alpha_stake is not None
    assert result.participants[0].chain_metrics.alpha_stake.raw == str(2**53)
    assert result.participants[0].chain_metrics.tao_stake is not None
    assert result.participants[0].chain_metrics.tao_stake.asset == "tao"
    assert result.participants[0].serving_announced is True
    serialized = result.model_dump_json()
    assert "198.51.100.10" not in serialized
    assert "private-value" not in serialized
    assert {name for name, _ in snapshot.query_calls} == {
        "LastRuntimeUpgrade",
        "CommitRevealWeightsVersion",
        "MaxMechanismCount",
        "NetworksAdded",
    }


@pytest.mark.asyncio
async def test_collector_rejects_mixed_block_state() -> None:
    client = FakeClient(FakeSnapshot(metagraph_block=100))
    collector = BittensorChainCollector(client_factory=lambda _: client)

    with pytest.raises(ChainCollectionError) as caught:
        await collector.collect()

    assert caught.value.reason_code == "metagraph_block_mismatch"


@pytest.mark.asyncio
async def test_collector_rejects_header_state_root_conflict() -> None:
    client = FakeClient(FakeSnapshot(info_state_root="0x" + "55" * 32))
    collector = BittensorChainCollector(client_factory=lambda _: client)

    with pytest.raises(ChainCollectionError) as caught:
        await collector.collect()

    assert caught.value.reason_code == "finalized_state_root_mismatch"


@pytest.mark.asyncio
async def test_collector_rejects_missing_required_raw_metagraph_column() -> None:
    snapshot = FakeSnapshot()
    del snapshot.metagraph.raw["active"]
    collector = BittensorChainCollector(client_factory=lambda _: FakeClient(snapshot))

    with pytest.raises(ChainCollectionError) as caught:
        await collector.collect()

    assert caught.value.reason_code == "missing_metagraph_raw_active"


@pytest.mark.asyncio
async def test_default_client_connects_without_token_symbol_cache_write(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import bittensor as bt
    from bittensor._transport import runtime

    class FakeSubstrate:
        def __init__(self) -> None:
            self.connected = False

        async def connect(self) -> None:
            self.connected = True

    class FakeClient:
        def __init__(self, network: str) -> None:
            self.network = network
            self._substrate = FakeSubstrate()
            self.closed = False

        async def __aenter__(self) -> Any:
            return await self.connect()

        async def __aexit__(self, *_: Any) -> None:
            self.closed = True

    def forbidden_cache_write(*_: Any, **__: Any) -> None:
        raise AssertionError("the observer client must not write the token-symbol cache")

    monkeypatch.setattr(bt, "Client", FakeClient)
    monkeypatch.setattr(bt.config, "save_token_symbols", forbidden_cache_write)
    monkeypatch.delenv("BITTENSOR_RUNTIME_CACHE_DIR", raising=False)
    client = _default_client_factory("finney")

    runtime_cache = Path(os.environ["BITTENSOR_RUNTIME_CACHE_DIR"])
    assert runtime_cache.is_dir()
    assert runtime_cache.stat().st_mode & 0o777 == 0o700
    assert runtime_cache != Path.home() / ".bittensor" / "runtime-cache"
    assert runtime._disk_cache_dir() == runtime_cache

    async with client as connected:
        assert connected is client
        assert connected._substrate.connected is True

    assert client.closed is True
