"""Retain exact Quicknet rounds requested by native settlement replay.

This synchronous source runs only in the settlement owner's owned worker. It
does not scan journals, select a current round, or hold private publication
locks during network I/O. Successful originals survive later replay failures.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from threading import Event, Lock

from .competition_endpoint_execution import RetainedRevealPulse
from .concurrency import run_until_stopped
from .drand import QuicknetClient
from .private_files import publish_private_model, read_private_model

logger = logging.getLogger(__name__)
MAX_PULSE_BYTES = 4096


class SettlementPulseSource:
    """Fetch missing originals once per attempt; the service owns later retries."""

    def __init__(self, directory: Path, *, client: QuicknetClient | None = None):
        self.directory = directory
        self.client = QuicknetClient() if client is None else client
        self._stopping = Event()
        self._lock = Lock()
        self._active: tuple[asyncio.AbstractEventLoop, asyncio.Event] | None = None

    def cancel(self) -> None:
        # Interrupt an active async transfer, then retain ownership through its
        # HTTP cleanup. HTTPX's inactivity timeout is not a total-transfer bound.
        self._stopping.set()
        with self._lock:
            if self._active is not None:
                loop, stop = self._active
                loop.call_soon_threadsafe(stop.set)

    async def _fetch(self, number: int):
        stop = asyncio.Event()
        with self._lock:
            if self._active is not None:
                raise RuntimeError("settlement pulse source already has an active worker")
            self._active = asyncio.get_running_loop(), stop
            if self._stopping.is_set():
                stop.set()
        try:
            pulse = await run_until_stopped(self.client.fetch(number), stop)
            if pulse is None:
                raise InterruptedError("settlement pulse retrieval stopped")
            return pulse
        finally:
            # Clear before asyncio.run can close this loop. cancel() holds the
            # same lock while scheduling, so it cannot target a closed loop.
            with self._lock:
                self._active = None

    def __call__(self, number: int) -> RetainedRevealPulse:
        if type(number) is not int or not 1 <= number < 2**64:
            raise ValueError("settlement pulse requires its exact original round")
        if self._stopping.is_set():
            raise InterruptedError("settlement pulse retrieval stopped")
        path = self.directory / (str(number) + ".json")
        fetched = False
        try:
            value = read_private_model(path, RetainedRevealPulse, maximum_bytes=MAX_PULSE_BYTES)
        except FileNotFoundError:
            # QuicknetClient pins the chain and enforces its native per-exchange
            # network/body/header bounds. There is no whole-cohort deadline or
            # finite retry allowance. A later normal service tick retries.
            logger.info("settlement_pulse round=%s status=fetching", number)
            pulse = asyncio.run(self._fetch(number))
            value = RetainedRevealPulse(
                round=pulse.round, randomness=pulse.randomness, signature=pulse.signature
            )
            fetched = True
        if value.round != number:
            raise ValueError("settlement pulse changes its requested original round")
        value.verified()
        if self._stopping.is_set():
            raise InterruptedError("settlement pulse retrieval stopped")
        # Native atomic publication refuses changed existing bytes and preserves
        # account/path ownership. Exact retries also repeat directory durability
        # after a lost acknowledgement; no original is silently overwritten.
        publish_private_model(path, value, maximum_bytes=MAX_PULSE_BYTES)
        if fetched:
            logger.info("settlement_pulse round=%s status=retained", number)
        return value
