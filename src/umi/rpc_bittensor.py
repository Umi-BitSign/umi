"""Apply the same operational RPC routes to the pinned submission SDK."""

from __future__ import annotations

import asyncio

import bittensor as bt
from bittensor._substrate import RpcSubstrate
from bittensor._transport import SubstrateConnection

from .rpc_transport import transport_config_path, websocket_connect


async def _sdk_connect(endpoint: str):
    # Match the pinned SDK's dial limits. Native proof readers retain their
    # smaller method-specific ceilings through their separate connection path.
    return await asyncio.wait_for(
        websocket_connect(endpoint, max_size=2**32, write_limit=2**16, proxy=None),
        timeout=10.0,
    )


class _RoutedSubstrate(RpcSubstrate):
    def _interface(self, endpoint: str, fallbacks: list[str]) -> SubstrateConnection:
        return SubstrateConnection(
            endpoint,
            ss58_format=42,
            fallback_urls=fallbacks,
            retry_forever=self.retry_forever,
            connect_factory=_sdk_connect,
        )


def rpc_client(endpoint: str, **kwargs):
    if transport_config_path() is None:
        return bt.Subtensor(endpoint, **kwargs)
    return bt.Client(substrate=_RoutedSubstrate(endpoint, **kwargs))
