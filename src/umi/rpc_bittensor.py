"""Apply the same operational RPC routes to the pinned submission SDK."""

from __future__ import annotations

import bittensor as bt
from bittensor._substrate import RpcSubstrate
from bittensor._transport import SubstrateConnection

from .rpc_transport import transport_config_path, websocket_connect


class _RoutedSubstrate(RpcSubstrate):
    def _interface(self, endpoint: str, fallbacks: list[str]) -> SubstrateConnection:
        return SubstrateConnection(
            endpoint,
            ss58_format=42,
            fallback_urls=fallbacks,
            retry_forever=self.retry_forever,
            connect_factory=websocket_connect,
        )


def rpc_client(endpoint: str, **kwargs):
    if transport_config_path() is None:
        return bt.Subtensor(endpoint, **kwargs)
    return bt.Client(substrate=_RoutedSubstrate(endpoint, **kwargs))
