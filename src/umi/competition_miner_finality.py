"""Miner admission backed by owned finality and verified historical ancestry.

An observer may start after a request window's announcement, or skip its exact
issuance header. Recover those headers through the dispatch proof implementation;
never accept the evaluator's claimed block or an unproved RPC timestamp.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

from .competition_chain import CompetitionChainConfig, OwnedFinalityStale
from .open_competition import CompetitionPolicy
from .policy import ScoringPolicy
from .protocol import canonical_json_bytes


class CompetitionMinerFinality:
    def __init__(self, config, policy, transport):
        # Dispatch imports the HTTP client's protocol constants from miner.
        # Construct the provider only after the miner module has loaded.
        from .competition_dispatch import DispatchFinalityProvider

        config = CompetitionChainConfig.model_validate_json(canonical_json_bytes(config))
        policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        transport = ScoringPolicy.model_validate_json(canonical_json_bytes(transport))
        self._provider = DispatchFinalityProvider(config, policy, transport)
        self._running = False
        self._closed = False

    async def run(self, stop: asyncio.Event) -> None:
        if self._running or self._closed:
            raise RuntimeError("miner finality lifecycle cannot be reused")
        self._running = True
        try:
            await self._provider.start()
            while not stop.is_set():
                self._provider.ensure_observer_running()
                with suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=0.25)
        finally:
            self._closed = True
            self._running = False
            await self._provider.aclose()

    def _check_running(self):
        if not self._running or self._closed:
            raise RuntimeError("miner owned finality is not running")
        self._provider.ensure_observer_running()

    async def finalized_head_height(self) -> int:
        head, _ = await self._verified_blocks()
        return head.height

    async def verified_block_at(self, height: int):
        _, blocks = await self._verified_blocks((height,))
        return blocks[0]

    async def _verified_blocks(self, heights=()):
        """Wait for a recovering observer within one existing collection budget.

        Only stale owned heads are retryable here. Invalid evidence, missing
        history and stopped observers still propagate immediately. No request,
        nonce or inference is repeated, and stale evidence is never returned.
        """
        self._check_running()

        async def collect():
            while True:
                self._check_running()
                try:
                    return await self._provider.verified_blocks(heights)
                except OwnedFinalityStale:
                    await asyncio.sleep(0.25)

        return await asyncio.wait_for(
            collect(), timeout=self._provider.config.collection_timeout_seconds
        )
