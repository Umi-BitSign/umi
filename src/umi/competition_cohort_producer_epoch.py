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

from .competition_cohort_review_http import _credential
from .competition_cohort_review_origin import private_review_origin
from .open_competition import identity
from .protocol import canonical_json_bytes

PRODUCER_EPOCH_PATH = "/internal/cohorts/execution-producer"
_MAX_BYTES = 2048
_REFRESH_SECONDS = 3


def producer_epoch_routes(signer, *, token, enabled):
    """Build once per actual reviewer application; GET performs no native work."""
    expected = ("Bearer " + _credential(token)).encode()
    raw = canonical_json_bytes(
        dict(
            schema="umi-execution-producer-epoch/1",
            evaluator=identity(signer),
            epoch_sha256=token_hex(32),
            execution_enabled=bool(enabled),
        )
    )
    router = APIRouter()

    @router.get(PRODUCER_EPOCH_PATH)
    async def current(request: Request):
        if not hmac.compare_digest(request.headers.get("authorization", "").encode(), expected):
            raise HTTPException(401, "reviewer authentication required")
        return Response(raw, media_type="application/json")

    return router


def producer_epoch_client():
    """Advisory requests must not wait for long business requests' pool slots."""
    return httpx.AsyncClient(
        trust_env=False, follow_redirects=False,
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
        self.probes = {}
        self.attempts = self.failures = self.timeouts = 0

    async def _fetch(self, evaluator, origin, token):
        async with self.capacity, self.client.stream(
            "GET", origin.rstrip("/") + PRODUCER_EPOCH_PATH,
            headers={"authorization": "Bearer " + token, "accept-encoding": "identity"},
            timeout=2,
        ) as response:
            self.probes[evaluator] = ("http_status", response.status_code)
            if response.status_code != 200:
                return None
            raw = bytearray()
            async for part in response.aiter_bytes(chunk_size=_MAX_BYTES + 1):
                if len(raw) + len(part) > _MAX_BYTES:
                    raise ValueError("producer epoch exceeds its metadata bound")
                raw.extend(part)
            body = json.loads(raw)
            epoch = body.get("epoch_sha256")
            if (
                set(body) == {"schema", "evaluator", "epoch_sha256", "execution_enabled"}
                and body["schema"] == "umi-execution-producer-epoch/1"
                and body["evaluator"] == evaluator
                and body["execution_enabled"] is True
                and isinstance(epoch, str)
                and len(epoch) == 64
                and all(c in "0123456789abcdef" for c in epoch)
            ):
                return epoch
            return None

    async def _read(self, evaluator):
        now = time.monotonic()
        previous = self.cache.get(evaluator)
        if previous is not None and now - previous[0] < 30:
            return previous[1]
        selected = self.peers.get(evaluator)
        value = None
        self.attempts += 1
        self.probes[evaluator] = ("unconfigured", None)
        if selected is not None:
            origin, token = selected
            try:
                value = await asyncio.wait_for(
                    self._fetch(evaluator, origin, token), timeout=_REFRESH_SECONDS
                )
            except (httpx.TimeoutException, asyncio.TimeoutError):
                self.timeouts += 1
                self.probes[evaluator] = ("timeout", None)
            except (httpx.HTTPError, OSError, ValueError, TypeError, AttributeError):
                # Never borrow a previous successful epoch after a failed refresh.
                self.probes[evaluator] = ("invalid_or_unavailable", None)
        if value is None:
            self.failures += 1
        else:
            self.probes[evaluator] = ("current", 200)
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
        states = [self.probes.get(e, ("awaiting_probe", None)) for e in selected]
        failed = next((value for value in states if value[0] != "current"), None)
        return dict(
            rate_probe_status="current" if failed is None else failed[0],
            rate_probe_http_status=200 if failed is None else failed[1],
            rate_probe_attempts=self.attempts,
            rate_probe_failures=self.failures,
            rate_probe_timeouts=self.timeouts,
        )
