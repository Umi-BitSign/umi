"""Give rejected timing attempts a bounded turn after sibling attempts drain.

This is local scheduling, not evidence of host isolation. Other processes and
services remain observable through the unchanged native timing checks.
"""

import asyncio
import json
import logging
import time
from collections import deque
from contextlib import asynccontextmanager

from .competition_transport_verification import TransferProgress
from .concurrency import await_owned_task

_LOG = logging.getLogger("umi.competition.progress")


class TimingAdmissionTimeout(OSError):
    """No native attempt started before the local admission allowance expired."""


class TimingAttemptAdmission:
    def __init__(self, *, clock=None):
        self.clock = time.monotonic if clock is None else clock
        self.observed_ordinary_seconds = 0.0
        self.condition = asyncio.Condition()
        self.active = 0
        self.quiet = False
        self.waiters = deque()

    def retry_allowance(self, fallback, maximum):
        """Reserve one observed ordinary step plus 25% headroom, within the read budget."""
        return min(maximum, max(fallback, self.observed_ordinary_seconds * 1.25))

    async def _acquire(self, quiet, timeout):
        ticket = object() if quiet else None
        async with self.condition:
            if quiet:
                self.waiters.append(ticket)
            try:

                def ready():
                    if self.quiet:
                        return False
                    if quiet:
                        return not self.active and self.waiters[0] is ticket
                    return not self.waiters

                if not ready():
                    loop = asyncio.get_running_loop()
                    deadline = loop.time() + timeout

                    def report(event):
                        remaining = max(0.0, deadline - loop.time())
                        complete = event["status"] == "completed"
                        event.update(
                            admission_remaining_seconds=remaining,
                            active_attempts=self.active,
                            observed_ordinary_step_seconds=self.observed_ordinary_seconds,
                            retry_headroom_multiplier=1.25,
                            queued_retries=len(self.waiters),
                            planning_eta_seconds=None if complete else [0, remaining],
                            eta_scope="local_timing_admission_only",
                            eta_basis="completed"
                            if complete
                            else "bounded_admission_allowance_not_completion_prediction",
                            stalled_or_retrying=not complete,
                        )
                        _LOG.info(json.dumps(event, separators=(",", ":")))

                    with TransferProgress(
                        "timing_attempt_admission",
                        1,
                        report=report,
                        unit="attempts",
                        planning_unit_seconds=(0, timeout),
                    ) as progress:
                        progress.emit(
                            "waiting",
                            reason="drain_sibling_timing_attempts"
                            if quiet
                            else "queued_timing_recovery",
                        )
                        try:
                            await asyncio.wait_for(self.condition.wait_for(ready), timeout)
                        except asyncio.TimeoutError as error:
                            progress.emit("retrying", reason="timing_admission_allowance_expired")
                            raise TimingAdmissionTimeout(
                                "timing_admission_allowance_expired"
                            ) from error
                        progress.advance(1)
                self.active += 1
                self.quiet = quiet
            finally:
                if quiet:
                    self.waiters.remove(ticket)
                    self.condition.notify_all()

    @asynccontextmanager
    async def attempt(self, *, quiet, timeout):
        await self._acquire(quiet, max(0.0, timeout))
        started = self.clock()
        released = False

        async def release():
            nonlocal released
            if released:
                return
            released = True
            if not quiet:
                self.observed_ordinary_seconds = max(
                    self.observed_ordinary_seconds, max(0.0, self.clock() - started)
                )
            # A second cancellation during lock acquisition cannot strand the
            # admission count and block every subsequent timing attempt.
            await await_owned_task(asyncio.create_task(self._release(quiet)))

        try:
            # The executor can release after the native sandbox has drained;
            # journal persistence and final authority checks need no quiet turn.
            yield release
        finally:
            await release()

    async def _release(self, quiet):
        async with self.condition:
            self.active -= 1
            if quiet:
                self.quiet = False
            self.condition.notify_all()
