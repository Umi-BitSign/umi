"""Miner admission backed by owned finality and verified historical ancestry.

An observer may start after a request window's announcement, or skip its exact
issuance header. Recover those headers through the dispatch proof implementation;
never accept the evaluator's claimed block or an unproved RPC timestamp.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress

from .competition_chain import CompetitionChainConfig
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
        self._check_running()
        head, _ = await self._provider.verified_blocks()
        return head.height

    async def verified_block_at(self, height: int):
        self._check_running()
        _, blocks = await self._provider.verified_blocks((height,))
        return blocks[0]
