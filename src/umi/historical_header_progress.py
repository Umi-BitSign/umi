"""Non-authoritative telemetry for one owned ancestry walk, never proof facts."""

from __future__ import annotations

import asyncio
import logging
import time
from contextlib import contextmanager, suppress
from functools import wraps

_LOG = logging.getLogger(__name__)


def _diagnostic(method):
    @wraps(method)
    def safe(*args, **kwargs):
        with suppress(Exception):
            return method(*args, **kwargs)
        return None

    return safe


class HeaderRecoveryTelemetry:
    heartbeat_seconds = 30.0
    stalled_seconds = 60.0
    planning_links_per_second = (1.0, 2000.0)

    def __init__(self):
        self.key = None
        self.latest = {}
        self.active = False
        self.prepared = False
        self.last_emitted = 0.0

    @contextmanager
    def monitor(self):
        self.prepared = False
        loop = asyncio.get_running_loop()
        handle = None

        def heartbeat():
            nonlocal handle
            self.report(force=True)
            handle = loop.call_later(self.heartbeat_seconds, heartbeat)

        handle = loop.call_later(self.heartbeat_seconds, heartbeat)
        try:
            yield
        finally:
            handle.cancel()
            self.active = False

    @_diagnostic
    def begin(self, anchor_identity, anchor_height, target_height, current_height):
        key = (anchor_identity, target_height)
        now = time.monotonic()
        if key != self.key or self.latest.get("state") == "completed":
            self.key = key
            self.started = self.changed = now
            self.native_links = 0
            self.retained_links = self.rpc_links = self.supplied_links = 0
            self.last_emitted = 0.0
        self.anchor, self.target, self.current = anchor_height, target_height, current_height
        self.active = self.prepared = True
        self.state, self.operation = "running", "load_retained_hint"
        self.report()

    @_diagnostic
    def phase(self, operation):
        if self.prepared:
            self.operation = operation
            self.report()

    @_diagnostic
    def advance(self, height, source):
        self.current = height
        self.changed = time.monotonic()
        self.native_links += 1
        if source == "retained":
            self.retained_links += 1
        elif source == "rpc":
            self.rpc_links += 1
        else:
            self.supplied_links += 1
        self.report()

    @_diagnostic
    def finish(self, state, *, error_type=None):
        if not self.prepared:
            return
        self.state = state
        self.report(force=state != "running", error_type=error_type)
        self.active = False

    @_diagnostic
    def report(self, *, force=False, error_type=None):
        if not self.prepared:
            return
        now = time.monotonic()
        elapsed = now - self.started
        total = self.anchor - self.target
        completed = self.anchor - self.current
        remaining = self.current - self.target
        stalled = (
            self.active and self.state == "running" and now - self.changed >= self.stalled_seconds
        )
        state = "stalled" if stalled else self.state
        rate = self.native_links / elapsed if elapsed > 0 and self.native_links else None
        eta = planning = None
        if state == "completed":
            eta, basis = 0.0, "completed_owned_ancestry_interval"
        elif state != "running":
            basis = "withdrawn_" + state
        elif rate and self.native_links >= 3 and elapsed >= 1:
            eta, basis = remaining / rate, "measured_durable_ancestry_links_per_elapsed_second"
        else:
            low, high = self.planning_links_per_second
            planning = [remaining / high, remaining / low]
            basis = "planning_assumption_1_to_2000_local_or_archive_links_per_second"
        self.latest = {
            "stage": "owned_historical_ancestry",
            "operation": self.operation,
            "state": state,
            "anchor_block": self.anchor,
            "target_block": self.target,
            "current_block": self.current,
            "completed_links": completed,
            "total_links": total,
            "remaining_links": remaining,
            "percent": 100.0 * completed / total if total else 100.0,
            "newly_verified_links": self.native_links,
            "reused_process_ancestry_links": max(0, completed - self.native_links),
            "retained_hint_links": self.retained_links,
            "rpc_fetched_links": self.rpc_links,
            "supplied_target_hint_links": self.supplied_links,
            "elapsed_seconds": elapsed,
            "links_per_second": rate,
            "eta_seconds": eta,
            "planning_eta_seconds": planning,
            "eta_basis": basis,
            "eta_scope": "current_owned_ancestry_only_excludes_block_proofs_and_rewards",
            "stalled": stalled,
            "retrying": state == "retrying",
            "error_type": error_type,
            "finality_authority": False,
        }
        if force or now - self.last_emitted >= self.heartbeat_seconds:
            self.last_emitted = now
            _LOG.info("historical_header_recovery_progress %s", self.latest)
