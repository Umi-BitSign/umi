"""Bounded connection reuse for successor weight proofs; no transaction RPCs."""

from __future__ import annotations

import re
from contextlib import asynccontextmanager
from types import SimpleNamespace

from .competition_chain import _BatchConnections
from .competition_proof_rpc import FailoverProofRpc
from .validator_chain import BittensorRawJsonRpc, ValidatorChainError


class _WeightProofTransport:
    """One endpoint, with exclusive method-specific connections."""

    bulk_storage_reads = False

    def __init__(self, config, endpoint):
        self.config = config
        self.endpoint = endpoint
        self._closed = False
        self._pools = {
            method: _BatchConnections(1)
            for method in (
                "state_getStorageAt",
                "state_queryStorageAt",
                "state_getReadProof",
                "state_getMetadata",
                "state_getRuntimeVersion",
                "chain_getHeader",
                "chain_getBlock",
                "chain_getBlockHash",
            )
        }

    async def request(self, method, params):
        if self._closed:
            raise ValueError("weight proof RPC is closed")
        pool = self._pools.get(method)
        if pool is None:
            raise ValidatorChainError("proof_rpc_method_forbidden")
        async with pool.lease() as lease:
            rpc = BittensorRawJsonRpc(
                SimpleNamespace(endpoint=self.endpoint),
                connect_factory=lease.connect,
                open_timeout_seconds=min(15, self.config.collection_timeout_seconds),
                request_timeout_seconds=min(60, self.config.collection_timeout_seconds),
            )
            return await rpc.request(method, params)

    async def aclose(self):
        self._closed = True
        for pool in self._pools.values():
            await pool.close()


class WeightProofRpc:
    """Bounded reads with the configured primary and two explicit backups.

    Normal and runtime-code collectors own separate transports. Each endpoint
    keeps method-specific response ceilings and exclusive connection leases.
    Only transport failures permit another endpoint for the same request; native
    proof and finality checks stay in the collector and cannot trigger retries.
    """

    def __init__(self, config):
        self.config = config
        self._closed = False
        self._batch_values = None
        endpoints = (config.rpc_url, *getattr(config, "proof_rpc_fallback_urls", ()))
        transports = tuple(_WeightProofTransport(config, endpoint) for endpoint in endpoints)
        self._rpc = (
            transports[0]
            if len(transports) == 1
            else FailoverProofRpc(transports, timeout_seconds=config.collection_timeout_seconds)
        )

    async def request(self, method, params):
        if self._closed:
            raise ValueError("weight proof RPC is closed")
        if method == "state_getStorageAt" and self._batch_values is not None:
            if not isinstance(params, (list, tuple)) or len(params) != 2:
                raise ValueError("invalid prefetched weight storage request")
            if tuple(params) not in self._batch_values:
                raise ValueError("weight storage request differs from prefetched batch")
            return self._batch_values[tuple(params)]
        return await self._rpc.request(method, params)

    @asynccontextmanager
    async def read_batch(self, block_hash, keys):
        """Fetch bounded untrusted claims; the caller still proves every value."""
        if self._closed or self._batch_values is not None:
            raise ValueError("weight storage batch is unavailable")
        if not isinstance(block_hash, str) or re.fullmatch(r"0x[0-9a-f]{64}", block_hash) is None:
            raise ValueError("weight storage batch block is invalid")
        keys = tuple(keys)
        if (
            not 1 <= len(keys) <= 512
            or any(not isinstance(key, bytes) or not 1 <= len(key) <= 512 for key in keys)
            or len(set(keys)) != len(keys)
        ):
            raise ValueError("weight storage batch keys are invalid")
        encoded = tuple("0x" + key.hex() for key in sorted(keys))
        self._batch_values = {}
        try:
            values = {}
            total_bytes = 0
            for start in range(0, len(encoded), 256):
                selected = encoded[start : start + 256]
                result = await self.request("state_queryStorageAt", (selected, block_hash))
                if (
                    not isinstance(result, list)
                    or len(result) != 1
                    or not isinstance(result[0], dict)
                    or set(result[0]) != {"block", "changes"}
                    or result[0]["block"] != block_hash
                ):
                    raise ValueError("weight storage batch belongs to another block")
                changes = result[0]["changes"]
                if not isinstance(changes, list) or len(changes) != len(selected):
                    raise ValueError("weight storage batch is incomplete")
                for change in changes:
                    if not isinstance(change, list) or len(change) != 2:
                        raise ValueError("weight storage batch entry is malformed")
                    key, value = change
                    if (
                        not isinstance(key, str)
                        or key not in selected
                        or (key, block_hash) in values
                    ):
                        raise ValueError("weight storage batch key is unexpected or duplicated")
                    if value is not None:
                        if (
                            not isinstance(value, str)
                            or len(value) > 2 * 65536 + 2
                            or re.fullmatch(r"0x(?:[0-9a-f]{2})*", value) is None
                        ):
                            raise ValueError("weight storage batch value is invalid or oversized")
                        total_bytes += (len(value) - 2) // 2
                        if total_bytes > 1024**2:
                            raise ValueError("weight storage batch exceeds aggregate value limit")
                    values[key, block_hash] = value
            self._batch_values = values
            yield
        finally:
            self._batch_values = None

    async def aclose(self):
        self._closed = True
        await self._rpc.aclose()
