"""Authenticated cached process identity for advisory execution-rate sampling.

These epochs carry no finality or execution authority. Older or unavailable
reviewers leave the rate unknown; retained execution counts remain usable.
"""

import asyncio
import hmac
import json
import time
from secrets import token_hex

import httpx
from fastapi import APIRouter, HTTPException, Request, Response

from .competition_cohort_execution_work import ExecutionWorkObservations, execution_work_routes
from .competition_cohort_review_http import _credential
from .competition_cohort_review_origin import private_review_origin
from .competition_cohort_settlement_progress import (
    SettlementProgressObservations,
    settlement_progress_routes,
)
from .concurrency import wait_for_owned
from .open_competition import identity
from .protocol import canonical_json_bytes

PRODUCER_EPOCH_PATH = "/internal/cohorts/execution-producer"
_MAX_BYTES = 2048
_REFRESH_SECONDS = 3


class _InvalidResponse(ValueError):
    """A fixed local reason code, never remote text or credentials."""


def producer_epoch_routes(signer, *, token, enabled, cohorts=(), settlement=None):
    """Build once per actual reviewer application; GET performs no native work."""
    expected = ("Bearer " + _credential(token)).encode()
    body = dict(
        schema="umi-execution-producer-epoch/1",
        evaluator=identity(signer),
        epoch_sha256=token_hex(32),
        execution_enabled=bool(enabled),
    )
    raw = canonical_json_bytes(body)
    router = APIRouter()

    @router.get(PRODUCER_EPOCH_PATH)
    async def current(request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", "").encode(), expected):
            raise HTTPException(401, "reviewer authentication required")
        return Response(raw, media_type="application/json")

    from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS

    router.include_router(
        execution_work_routes(
            evaluator=body["evaluator"],
            epoch=body["epoch_sha256"],
            token=token,
            enabled=enabled,
            cohorts=cohorts,
            snapshots=PUBLIC_COHORT_PROGRESS,
        )
    )
    router.include_router(
        settlement_progress_routes(
            evaluator=body["evaluator"],
            epoch=body["epoch_sha256"],
            token=token,
            cohorts=cohorts,
            relay=settlement,
        )
    )
    return router


def producer_epoch_client():
    """Advisory requests must not wait for long business requests' pool slots."""
    return httpx.AsyncClient(
        trust_env=False,
        follow_redirects=False,
        limits=httpx.Limits(max_connections=4, max_keepalive_connections=4),
    )


class ExecutionProducerEpochs:
    """One bounded cached observation per configured peer, shared across cohorts."""

    def __init__(self, client, peers, credentials):
        self.client = client
        self.peers = {
            identity(peer.signer): (str(private_review_origin(peer.origin)), _credential(token))
            for peer, token in zip(peers, credentials, strict=True)
        }
        self.cache = {}
        self.capacity = asyncio.Semaphore(4)
        self.work = ExecutionWorkObservations(client, self.peers, self.capacity)
        self.settlement = SettlementProgressObservations(client, self.peers, self.capacity)
        self.probes = {}
        self.refresh_locks = {evaluator: asyncio.Lock() for evaluator in self.peers}
        self.in_flight = self.waiters = 0
        self.attempts = self.failures = self.timeouts = 0

    async def _fetch(self, evaluator, origin, token, probe):
        async with self.capacity:
            probe["http_started"] = time.monotonic()
            probe["queue_seconds"] = probe["http_started"] - probe["started"]
            probe["phase"] = "http_headers"
            try:
                async with self.client.stream(
                    "GET",
                    origin.rstrip("/") + PRODUCER_EPOCH_PATH,
                    headers={"authorization": "Bearer " + token, "accept-encoding": "identity"},
                    timeout=2,
                ) as response:
                    probe["http_status"] = response.status_code
                    if response.status_code != 200:
                        probe.update(status="http_status", failure_type="http_status")
                        return None
                    probe["phase"] = "http_body"
                    raw = bytearray()
                    # Count partial body delivery without buffering the entire
                    # response inside aiter_bytes until EOF or the byte bound.
                    async for part in response.aiter_bytes():
                        probe["received_bytes"] += len(part)
                        if len(raw) + len(part) > _MAX_BYTES:
                            raise _InvalidResponse("oversized_response")
                        raw.extend(part)
            finally:
                probe["http_seconds"] = time.monotonic() - probe["http_started"]
        probe["phase"] = "validate"
        try:
            body = json.loads(raw)
        except (ValueError, UnicodeError):
            raise _InvalidResponse("invalid_json") from None
        if type(body) is not dict or set(body) != {
            "schema",
            "evaluator",
            "epoch_sha256",
            "execution_enabled",
        }:
            raise _InvalidResponse("invalid_shape")
        epoch = body["epoch_sha256"]
        if body["schema"] != "umi-execution-producer-epoch/1" or body["evaluator"] != evaluator:
            raise _InvalidResponse("invalid_binding")
        if body["execution_enabled"] is not True:
            raise _InvalidResponse("execution_disabled")
        if not (
            isinstance(epoch, str)
            and len(epoch) == 64
            and all(c in "0123456789abcdef" for c in epoch)
        ):
            raise _InvalidResponse("invalid_epoch")
        return epoch

    async def _read(self, evaluator):
        lock = self.refresh_locks.get(evaluator)
        if lock is None:
            self.refresh_locks[evaluator] = lock = asyncio.Lock()
        waiting = lock.locked()
        self.waiters += int(waiting)
        try:
            async with lock:
                if waiting:
                    self.waiters -= 1
                    waiting = False
                # Other owner loops share one completed refresh, including a
                # failure. A waiter cannot replace it with an older response.
                previous = self.cache.get(evaluator)
                if previous is not None and time.monotonic() - previous[0] < 30:
                    return previous[1]
                return await self._refresh(evaluator)
        finally:
            self.waiters -= int(waiting)

    async def _refresh(self, evaluator):
        now = time.monotonic()
        selected = self.peers.get(evaluator)
        value = None
        probe = dict(
            status="refreshing",
            http_status=None,
            failure_type=None,
            phase="capacity_queue" if selected is not None else "configuration",
            started=now,
            started_unix_ms=time.time_ns() // 1_000_000,
            finished_unix_ms=None,
            elapsed_seconds=None,
            queue_seconds=None,
            http_started=None,
            http_seconds=None,
            received_bytes=0,
        )
        self.probes[evaluator] = probe
        self.attempts += 1
        self.in_flight += 1
        try:
            if selected is None:
                probe.update(status="unconfigured", failure_type="unconfigured")
            else:
                origin, token = selected
                value = await wait_for_owned(
                    self._fetch(evaluator, origin, token, probe), timeout=_REFRESH_SECONDS
                )
        except httpx.TimeoutException as error:
            self.timeouts += 1
            reason = {
                httpx.ConnectTimeout: "http_connect_timeout",
                httpx.ReadTimeout: "http_read_timeout",
                httpx.WriteTimeout: "http_write_timeout",
                httpx.PoolTimeout: "http_pool_timeout",
            }.get(type(error), "http_timeout")
            probe.update(status="timeout", failure_type=reason)
        except asyncio.TimeoutError:
            self.timeouts += 1
            probe.update(status="timeout", failure_type="outer_deadline")
        except _InvalidResponse as error:
            probe.update(status="invalid_response", failure_type=error.args[0])
        except (httpx.HTTPError, OSError, ValueError, TypeError, AttributeError) as error:
            reason = "http_error" if isinstance(error, httpx.HTTPError) else "local_error"
            probe.update(status="invalid_or_unavailable", failure_type=reason)
        except asyncio.CancelledError:
            # The owned wait drains even under repeated caller cancellation.
            # Cancellation is not a completed refresh or a new cached failure.
            probe.update(status="cancelled", failure_type="cancelled")
            raise
        finally:
            finished = time.monotonic()
            probe["finished_unix_ms"] = time.time_ns() // 1_000_000
            probe["elapsed_seconds"] = finished - now
            if probe["http_started"] is None and selected is not None:
                probe["queue_seconds"] = finished - now
            self.in_flight -= 1
        if value is None:
            self.failures += 1
        else:
            probe.update(status="current", failure_type=None)
        # Never borrow an earlier successful epoch after a failed refresh.
        self.cache[evaluator] = (time.monotonic(), value)
        return value

    async def sample(self, evaluators):
        selected = sorted(set(evaluators))
        if len(selected) > 64:
            raise ValueError("execution rate producer inventory exceeds its bound")
        values = await asyncio.gather(*(self._read(e) for e in selected))
        return {e: value for e, value in zip(selected, values, strict=True) if value is not None}

    def diagnostics(self, evaluators):
        """Cached bounded reason/counters only: no origins, credentials or errors."""
        selected = sorted(set(evaluators))
        if len(selected) > 64:
            raise ValueError("execution rate producer inventory exceeds its bound")
        chosen = next(
            (e for e in selected if self.probes.get(e, {}).get("status") != "current"),
            next(iter(selected), None),
        )
        probe = self.probes.get(chosen, {})
        cached = self.cache.get(chosen)
        elapsed = probe.get("elapsed_seconds")
        if elapsed is None and "started" in probe:
            elapsed = max(0, time.monotonic() - probe["started"])
        result = dict(
            rate_probe_status=probe.get("status", "awaiting_probe" if selected else "current"),
            rate_probe_http_status=probe.get("http_status", None if selected else 200),
            rate_probe_attempts=self.attempts,
            rate_probe_failures=self.failures,
            rate_probe_timeouts=self.timeouts,
            rate_probe_failure_type=probe.get("failure_type"),
            rate_probe_phase=probe.get("phase", "awaiting_probe"),
            rate_probe_started_unix_ms=probe.get("started_unix_ms"),
            rate_probe_finished_unix_ms=probe.get("finished_unix_ms"),
            rate_probe_elapsed_seconds=None if elapsed is None else round(elapsed, 6),
            rate_probe_deadline_overrun_seconds=None
            if elapsed is None
            else round(max(0, elapsed - _REFRESH_SECONDS), 6),
            rate_probe_cache_age_seconds=None
            if cached is None
            else round(max(0, time.monotonic() - cached[0]), 6),
            rate_probe_received_bytes=probe.get("received_bytes", 0),
            rate_probe_in_flight=self.in_flight,
            rate_probe_coalesced_waiters=self.waiters,
            rate_probe_counter_scope="observer_lifetime_all_peers_and_cohorts",
            rate_probe_deadline_seconds=_REFRESH_SECONDS,
        )
        for field in ("queue_seconds", "http_seconds"):
            value = probe.get(field)
            result["rate_probe_" + field] = None if value is None else round(max(0, value), 6)
        return result
