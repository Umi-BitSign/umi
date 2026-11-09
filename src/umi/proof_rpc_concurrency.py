"""Fair bounded small reads, with one probe until a transport succeeds."""

from __future__ import annotations

import asyncio
from collections import deque
from contextlib import asynccontextmanager

from .concurrency import await_owned_task

HEADER_FETCH_CONCURRENCY = 4


class ProviderReadGate:
    def __init__(self):
        self.healthy = False
        self.active = 0
        self.exclusive = False
        self.waiters = deque()
        self.condition = asyncio.Condition()
        self.generation = 0

    def succeeded(self, generation):
        if self.generation == generation:
            self.healthy = True

    def failed(self):
        self.generation += 1
        self.healthy = False

    @asynccontextmanager
    async def lease(self, *, small_read):
        token = object()
        async with self.condition:
            self.waiters.append(token)
            try:
                await self.condition.wait_for(
                    lambda: (
                        self.waiters[0] is token
                        and (
                            self.active == 0
                            or (
                                small_read
                                and self.healthy
                                and not self.exclusive
                                and self.active < HEADER_FETCH_CONCURRENCY
                            )
                        )
                    )
                )
            except BaseException:
                self.waiters.remove(token)
                self.condition.notify_all()
                raise
            self.waiters.popleft()
            if self.active == 0:
                self.exclusive = not (small_read and self.healthy)
            self.active += 1
            self.condition.notify_all()
        try:
            yield
        finally:

            async def release():
                async with self.condition:
                    self.active -= 1
                    if self.active == 0:
                        self.exclusive = False
                    self.condition.notify_all()

            await await_owned_task(asyncio.create_task(release()))
