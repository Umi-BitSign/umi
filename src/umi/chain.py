"""Read-only Bittensor discovery for the UMI component runtime."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class MinerEndpoint:
    hotkey: str
    uid: int
    origin: str
    validator_permit: bool


async def discover_miner(
    hotkey: str,
    *,
    network: str = "finney",
    netuid: int = 78,
) -> MinerEndpoint:
    """Resolve one registered miner endpoint without submitting any transaction."""

    if netuid != 78:
        raise ValueError("the version 0.1 component profile is pinned to SN78")
    import bittensor as bt

    async with bt.Subtensor(network) as client:
        metagraph = await client.subnets.metagraph(netuid=netuid)
    neuron = metagraph.by_hotkey(hotkey)
    if neuron is None:
        raise ValueError("miner hotkey is not registered on SN78")
    if neuron.validator_permit:
        raise ValueError("validator-permit hotkeys are not component miner candidates")
    if neuron.axon is None:
        raise ValueError("miner hotkey has no served endpoint")
    endpoint = str(neuron.axon)
    if endpoint.startswith("http://") or endpoint.startswith("https://"):
        origin = endpoint
    else:
        origin = "http://" + endpoint
    return MinerEndpoint(
        hotkey=neuron.hotkey,
        uid=neuron.uid,
        origin=origin,
        validator_permit=bool(neuron.validator_permit),
    )
