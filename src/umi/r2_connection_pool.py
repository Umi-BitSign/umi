"""Explicit async ownership of bounded R2 HTTP connection reuse."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import httpx

from .concurrency import await_owned_task


class R2ConnectionPool:
    """Share one client within overlapping scopes; drain requests before close.

    Outside a scope, retain the historical per-request client lifecycle. This
    changes transport ownership only: no response cache or automatic retry is
    added, and every exchange is still separately signed and checked.
    """

    def __init__(
        self, *, transport: httpx.AsyncBaseTransport | None, timeout: httpx.Timeout
    ) -> None:
        self.transport, self.timeout = transport, timeout
        self.client: httpx.AsyncClient | None = None
        self.loop: asyncio.AbstractEventLoop | None = None
        self.users = self.active = 0
        self.closing = False
        self.drained: asyncio.Event | None = None

    def _new_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            transport=self.transport,
            timeout=self.timeout,
            follow_redirects=False,
            trust_env=False,
        )

    def _check_loop(self) -> None:
        if self.loop is not None and self.loop is not asyncio.get_running_loop():
            raise RuntimeError("R2 connection scope belongs to another event loop")
        if self.closing:
            raise RuntimeError("R2 connection scope is draining")

    @asynccontextmanager
    async def scope(self) -> AsyncIterator[None]:
        self._check_loop()
        if self.client is None:
            self.client = self._new_client()
            self.loop = asyncio.get_running_loop()
            self.drained = asyncio.Event()
            self.drained.set()
        self.users += 1
        try:
            yield
        finally:
            self.users -= 1
            if self.users == 0:
                self.closing = True
                # Repeated caller cancellation cannot abandon a live response
                # stream or its transport. Requests retain their original HTTP
                # timeouts; this adds no execution or cohort deadline.
                await await_owned_task(asyncio.create_task(self._close()))

    async def _close(self) -> None:
        try:
            await self.drained.wait()
            await self.client.aclose()
        finally:
            self.client = self.loop = self.drained = None
            self.closing = False

    @asynccontextmanager
    async def request_client(self) -> AsyncIterator[httpx.AsyncClient]:
        self._check_loop()
        if self.client is None:
            async with self._new_client() as client:
                yield client
            return
        client = self.client
        self.active += 1
        self.drained.clear()
        try:
            yield client
        finally:
            self.active -= 1
            if self.active == 0:
                self.drained.set()
