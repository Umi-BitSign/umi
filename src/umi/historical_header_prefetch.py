"""Bounded untrusted archive hints; only the ordered owner authenticates links."""

from __future__ import annotations

import asyncio
import re

from .concurrency import await_owned_task
from .finalized_ancestry import MAXIMUM_HEADER_BYTES, encode_rpc_header
from .proof_rpc_concurrency import HEADER_FETCH_CONCURRENCY


class HistoricalHeaderPrefetch:
    minimum_distance = 64
    minimum_missing_streak = 4

    def __init__(self, request, target_height):
        self.request, self.target = request, target_height
        # Only a transport with independently bounded method pools opts in.
        # Generic callbacks retain their existing serial path.
        selected = getattr(
            getattr(request, "__self__", None), "historical_header_prefetch_concurrency", 1
        )
        self.concurrency = (
            selected if type(selected) is int and 1 < selected <= HEADER_FETCH_CONCURRENCY else 1
        )
        self.tasks = {}
        self.missing_streak = 0
        self.disabled = False

    async def _fetch(self, height):
        block_hash = await self.request("chain_getBlockHash", (height,))
        if type(block_hash) is not str or re.fullmatch(r"0x[0-9a-f]{64}", block_hash) is None:
            raise ValueError("archive height lookup did not return a bounded header hash")
        # The transport bounds each raw response. Decode only when the ordered
        # owner consumes it, so malformed committed headers remain native errors.
        return block_hash, await self.request("chain_getHeader", (block_hash,))

    def _fill(self, height):
        for candidate in range(height, max(self.target, height - self.concurrency), -1):
            if candidate not in self.tasks:
                self.tasks[candidate] = asyncio.create_task(self._fetch(candidate))

    async def encoded(self, height, expected_hash):
        self.missing_streak += 1
        if (
            self.disabled
            or self.concurrency == 1
            or (not self.tasks and height - self.target < self.minimum_distance)
            or self.missing_streak < self.minimum_missing_streak
        ):
            return encode_rpc_header(await self.request("chain_getHeader", (expected_hash,)))
        self._fill(height)
        task = self.tasks[height]
        try:
            block_hash, raw = await await_owned_task(task, on_cancel=task.cancel)
        except Exception:
            # Speculative availability is not a native proof result. Preserve
            # the exact parent-hash request and its original failure semantics.
            self.disabled = True
            await self.close()
        else:
            del self.tasks[height]
            if block_hash == expected_hash:
                encoded = encode_rpc_header(raw)
                if len(encoded) > 2 * MAXIMUM_HEADER_BYTES + 2:
                    raise ValueError("prefetched historical header exceeds its native bound")
                return encoded
            # A canonical-height response may belong to a different fork. It
            # cannot change the finalized anchor or become a durable hint here.
            self.disabled = True
            await self.close()
        return encode_rpc_header(await self.request("chain_getHeader", (expected_hash,)))

    async def retained(self):
        self.missing_streak = 0
        await self.close()

    async def close(self):
        if not self.tasks:
            return
        tasks = tuple(self.tasks.values())

        async def drain():
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

        try:
            await await_owned_task(asyncio.create_task(drain()))
        finally:
            self.tasks.clear()
