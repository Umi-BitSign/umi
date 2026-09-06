from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from umi.chain import discover_miner_finalized

from .factories import dev_wallet

_BLOCK_TIMESTAMP = datetime(2026, 9, 5, 12, 0, 0, 123000, tzinfo=timezone.utc)
_OBSERVATION_NOW = datetime(2026, 9, 5, 12, 1, 0, tzinfo=timezone.utc)


class _FinalizedStream:
    def __init__(self, header: object) -> None:
        self.header = header
        self.used = False
        self.closed = False

    def __aiter__(self):
        return self

    async def __anext__(self):
        if self.used:
            raise StopAsyncIteration
        self.used = True
        return self.header

    async def aclose(self) -> None:
        self.closed = True


class _Subnets:
    def __init__(self, metagraph: object) -> None:
        self.metagraph_value = metagraph
        self.calls: list[tuple[int, bool]] = []

    async def metagraph(self, *, netuid: int, commitments: bool):
        self.calls.append((netuid, commitments))
        return self.metagraph_value


class _Snapshot:
    def __init__(self, block: int, block_info: object, metagraph: object) -> None:
        self.block = block
        self._block_info = block_info
        self.subnets = _Subnets(metagraph)

    async def block_info(self):
        return self._block_info


class _Substrate:
    def __init__(self, genesis_hash: str) -> None:
        self.genesis_hash = genesis_hash
        self.block_hash_calls: list[int] = []

    async def block_hash(self, block: int) -> str:
        self.block_hash_calls.append(block)
        assert block == 0
        return self.genesis_hash


class _Client:
    def __init__(self, header: object, snapshot: _Snapshot, genesis_hash: str) -> None:
        self.stream = _FinalizedStream(header)
        self.snapshot = snapshot
        self.at_calls: list[int] = []
        self._substrate = _Substrate(genesis_hash)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return None

    def blocks(self, *, finalized: bool):
        assert finalized is True
        return self.stream

    async def at(self, block: int):
        self.at_calls.append(block)
        return self.snapshot


def _client(
    *,
    axon: str = "8.8.8.8:443",
    metagraph_block: int = 99,
    genesis_hash: str = "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
    subscription_digest_logs: list[str] | None = None,
    block_info_digest_logs: list[str] | None = None,
    block_timestamp: datetime = _BLOCK_TIMESTAMP,
):
    hotkey = dev_wallet("//PublicPilotMiner").hotkey.ss58_address
    parent = "0x" + "11" * 32
    state = "0x" + "22" * 32
    extrinsics = "0x" + "33" * 32
    block_hash = "0x6c9d4e0ddd91bd8674ef368ece5d476acc029b2f1da20589ed2640d28c923715"
    raw_header = {
        "number": 99,
        "parentHash": parent,
        "stateRoot": state,
        "extrinsicsRoot": extrinsics,
        "digest": {"logs": subscription_digest_logs or []},
    }
    header = SimpleNamespace(number=99, parent_hash=parent, raw=raw_header)
    block_info = SimpleNamespace(
        number=99,
        hash=block_hash,
        timestamp=block_timestamp,
        header={
            **raw_header,
            "digest": {"logs": block_info_digest_logs or []},
            "hash": block_hash,
        },
    )
    neuron = SimpleNamespace(
        uid=0,
        hotkey=hotkey,
        validator_permit=False,
        axon=axon,
    )
    metagraph = SimpleNamespace(
        netuid=78,
        mechid=0,
        block=metagraph_block,
        num_uids=1,
        neurons=[neuron],
        raw={"hotkeys": [hotkey], "validator_permit": [False]},
    )
    snapshot = _Snapshot(99, block_info, metagraph)
    return hotkey, _Client(header, snapshot, genesis_hash)


@pytest.mark.asyncio
async def test_finalized_miner_discovery_pins_and_cross_checks_one_snapshot() -> None:
    hotkey, client = _client()

    endpoint = await discover_miner_finalized(
        hotkey,
        client_factory=lambda _network: client,
        now=_OBSERVATION_NOW,
    )

    assert endpoint.hotkey == hotkey
    assert endpoint.uid == 0
    assert endpoint.origin == "https://8.8.8.8:443"
    assert endpoint.validator_permit is False
    assert endpoint.network == "finney"
    assert endpoint.genesis_block_hash == (
        "0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"
    )
    assert endpoint.finalized_block_number == 99
    assert endpoint.finalized_block_hash == (
        "0x6c9d4e0ddd91bd8674ef368ece5d476acc029b2f1da20589ed2640d28c923715"
    )
    assert endpoint.finalized_block_timestamp_ms == 1_788_609_600_123
    assert client.at_calls == [99]
    assert client.snapshot.subnets.calls == [(78, False)]
    assert client._substrate.block_hash_calls == [0]
    assert client.stream.closed is True


@pytest.mark.asyncio
async def test_finalized_miner_discovery_rejects_other_network_before_connect() -> None:
    def unexpected_factory(_network: str):
        raise AssertionError("client factory must not be called")

    with pytest.raises(ValueError, match="pinned to Finney"):
        await discover_miner_finalized(
            dev_wallet("//PublicPilotMiner").hotkey.ss58_address,
            network="test",  # type: ignore[arg-type]
            client_factory=unexpected_factory,
            now=_OBSERVATION_NOW,
        )


@pytest.mark.asyncio
async def test_finalized_miner_discovery_rejects_non_finney_genesis() -> None:
    hotkey, client = _client(genesis_hash="0x" + "ff" * 32)

    with pytest.raises(ValueError, match="not connected to Finney"):
        await discover_miner_finalized(
            hotkey,
            client_factory=lambda _network: client,
            now=_OBSERVATION_NOW,
        )

    assert client.stream.used is False


@pytest.mark.asyncio
async def test_finalized_miner_discovery_binds_subscription_header_to_hash() -> None:
    hotkey, client = _client(subscription_digest_logs=["0x00"])

    with pytest.raises(ValueError, match="subscription header hash mismatch"):
        await discover_miner_finalized(
            hotkey,
            client_factory=lambda _network: client,
            now=_OBSERVATION_NOW,
        )


@pytest.mark.asyncio
async def test_finalized_miner_discovery_binds_block_info_header_to_hash() -> None:
    hotkey, client = _client(block_info_digest_logs=["0x00"])

    with pytest.raises(ValueError, match="block-info header hash mismatch"):
        await discover_miner_finalized(
            hotkey,
            client_factory=lambda _network: client,
            now=_OBSERVATION_NOW,
        )


@pytest.mark.asyncio
async def test_finalized_miner_discovery_rejects_mixed_metagraph_block() -> None:
    hotkey, client = _client(metagraph_block=100)

    with pytest.raises(ValueError, match="metagraph block mismatch"):
        await discover_miner_finalized(
            hotkey,
            client_factory=lambda _network: client,
            now=_OBSERVATION_NOW,
        )


@pytest.mark.asyncio
async def test_finalized_miner_discovery_rejects_nonpublic_axon() -> None:
    hotkey, client = _client(axon="127.0.0.1:443")

    with pytest.raises(ValueError, match="public IP and port"):
        await discover_miner_finalized(
            hotkey,
            client_factory=lambda _network: client,
            now=_OBSERVATION_NOW,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("observed_now", "message"),
    (
        (datetime(2026, 9, 5, 12, 2, 1, tzinfo=timezone.utc), "stale finalized head"),
        (datetime(2026, 9, 5, 11, 59, 29, tzinfo=timezone.utc), "future-dated"),
    ),
)
async def test_finalized_miner_discovery_rejects_stale_or_future_head(
    observed_now: datetime,
    message: str,
) -> None:
    hotkey, client = _client()

    with pytest.raises(ValueError, match=message):
        await discover_miner_finalized(
            hotkey,
            client_factory=lambda _network: client,
            now=observed_now,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("block_timestamp", "observed_now"),
    (
        (
            datetime(2026, 9, 5, 11, 59, 0, tzinfo=timezone.utc),
            datetime(2026, 9, 5, 12, 1, 0, tzinfo=timezone.utc),
        ),
        (
            datetime(2026, 9, 5, 12, 1, 30, tzinfo=timezone.utc),
            datetime(2026, 9, 5, 12, 1, 0, tzinfo=timezone.utc),
        ),
    ),
)
async def test_finalized_miner_discovery_accepts_freshness_boundaries(
    block_timestamp: datetime,
    observed_now: datetime,
) -> None:
    hotkey, client = _client(block_timestamp=block_timestamp)

    endpoint = await discover_miner_finalized(
        hotkey,
        client_factory=lambda _network: client,
        now=observed_now,
    )

    assert endpoint.finalized_block_timestamp_ms == int(block_timestamp.timestamp() * 1_000)
