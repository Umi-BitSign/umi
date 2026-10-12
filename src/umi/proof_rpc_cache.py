"""Bounded reuse of untrusted RPC bytes pinned to an exact block hash.

This cache supplies bytes, never finality or verified storage. Consumers replay
their original checks. Short retention also permits recovery from malformed RPC
results: a failed native proof must not pin a bad transport response forever.
"""

from __future__ import annotations

import asyncio
import json
import re
import time
from collections import OrderedDict
from contextlib import suppress

from .concurrency import await_owned_task
from .protocol import canonical_json_bytes

_HASH = re.compile(r"0x[0-9a-f]{64}\Z")
_ARITY = {
    "chain_getHeader": 1,
    "chain_getBlock": 1,
    "state_getMetadata": 1,
    "state_getRuntimeVersion": 1,
    "state_getStorageAt": 2,
    "state_queryStorageAt": 2,
    "state_getReadProof": 2,
}


class BlockPinnedRpcCache:
    def __init__(
        self,
        fetch,
        *,
        maximum_bytes=64 * 1024**2,
        maximum_entries=512,
        maximum_inflight=64,
        retention_seconds=30,
        monotonic=time.monotonic,
    ):
        if (
            any(
                type(v) is not int or v <= 0
                for v in (
                    maximum_bytes,
                    maximum_entries,
                    maximum_inflight,
                )
            )
            or not 0 < retention_seconds <= 300
        ):
            raise ValueError("RPC cache bounds must be positive")
        self.fetch = fetch
        self.maximum_bytes, self.maximum_entries = maximum_bytes, maximum_entries
        self.maximum_inflight, self.retention_seconds = maximum_inflight, retention_seconds
        self.now = monotonic
        self.entries = OrderedDict()
        self.inflight = {}
        self.waiters = {}
        self.bytes = 0
        self.hits = self.shared_reads = self.network_reads = 0
        self.closed = False

    async def request(self, method, params):
        if self.closed:
            raise ValueError("RPC cache is closed")
        if (
            method not in _ARITY
            or not isinstance(params, (tuple, list))
            or len(params) != _ARITY[method]
            or not isinstance(params[-1], str)
            or _HASH.fullmatch(params[-1]) is None
        ):
            self.network_reads += 1
            return await self.fetch(method, params)
        key = canonical_json_bytes([method, params])
        if len(key) > 2 * 1024**2:
            self.network_reads += 1
            return await self.fetch(method, params)
        while True:
            if self.closed:
                raise ValueError("RPC cache is closed")
            saved = self.entries.get(key)
            if saved is not None:
                until, payload = saved
                if self.now() < until:
                    self.entries.move_to_end(key)
                    self.hits += 1
                    return json.loads(payload)
                self.entries.pop(key)
                self.bytes -= len(key) + len(payload)
            task = self.inflight.get(key)
            if task is not None:
                self.shared_reads += 1
                return await self._wait(key, task)
            if len(self.inflight) < self.maximum_inflight:
                task = asyncio.create_task(self._read(key), name="block-pinned-proof-rpc")
                self.inflight[key] = task
                task.add_done_callback(lambda done: self._finished(key, done))
                return await self._wait(key, task)
            # Await capacity without cancelling another caller's owned read.
            await asyncio.wait(tuple(self.inflight.values()), return_when=asyncio.FIRST_COMPLETED)

    async def _wait(self, key, task):
        self.waiters[task] = self.waiters.get(task, 0) + 1
        released = False
        try:
            await asyncio.wait((task,))
            return json.loads(task.result())
        except asyncio.CancelledError:
            self.waiters[task] -= 1
            released = True
            if self.waiters[task] == 0 and not task.done():
                # No caller still needs this read. Drain its leased sockets;
                # do not let a new caller join an already cancelling task.
                if self.inflight.get(key) is task:
                    self.inflight.pop(key)
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await await_owned_task(task)
            raise
        finally:
            if not released:
                self.waiters[task] -= 1
            if self.waiters[task] == 0:
                self.waiters.pop(task)

    async def _read(self, key):
        method, params = json.loads(key)
        self.network_reads += 1
        value = await self.fetch(method, params)
        payload = json.dumps(
            value, ensure_ascii=True, allow_nan=False, separators=(",", ":")
        ).encode()
        size = len(key) + len(payload)
        if value is not None and size <= self.maximum_bytes and not self.closed:
            while self.entries and (
                self.bytes + size > self.maximum_bytes or len(self.entries) >= self.maximum_entries
            ):
                old_key, (_, old_payload) = self.entries.popitem(last=False)
                self.bytes -= len(old_key) + len(old_payload)
            self.entries[key] = (self.now() + self.retention_seconds, payload)
            self.bytes += size
        return payload

    def _finished(self, key, task):
        if self.inflight.get(key) is task:
            self.inflight.pop(key)
        if not task.cancelled():
            task.exception()  # Consume abandoned failures without logging private RPC data.

    async def aclose(self, *, cancel_inflight=False):
        self.closed = True
        tasks = tuple(self.inflight.values())
        if cancel_inflight:
            for task in tasks:
                task.cancel()
        if tasks:
            await await_owned_task(asyncio.gather(*tasks, return_exceptions=True))
        self.entries.clear()
        self.bytes = 0
