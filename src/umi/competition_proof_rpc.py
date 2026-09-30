"""Explicit alternate transports for the same untrusted, block-pinned RPC reads.

Finality selection and proof verification belong to the native collector. This
adapter cannot select another block, accept an RPC finality claim or retry a
failed proof. Each endpoint owns separate connection pools and receive limits.
"""

from __future__ import annotations

import asyncio
import logging
import math
import time
from collections.abc import Sequence
from contextlib import AsyncExitStack, asynccontextmanager
from email.utils import parsedate_to_datetime

from .concurrency import await_owned_task, wait_for_owned
from .validator_chain import _RPC_RESPONSE_LIMITS, ValidatorChainError

_RETRYABLE = {"proof_rpc_rate_limited", "proof_rpc_failed", "proof_rpc_error"}
_LOGGER = logging.getLogger(__name__)


class FailoverProofRpc:
    def __init__(self, transports: tuple, *, timeout_seconds: float):
        if len(transports) != 3 or not 0 < timeout_seconds <= 120:
            raise ValueError("proof RPC failover requires bounded explicit transports")
        self.transports = transports
        self.bulk_storage_reads = all(rpc.bulk_storage_reads for rpc in transports)
        self.timeout_seconds = timeout_seconds
        self._cooldown_until = [0.0] * len(transports)
        self._provider_gates = [asyncio.Lock() for _ in transports]
        self._cooldown_reasons = [None] * len(transports)
        self._now = time.monotonic
        self._closed = False
        self._close_task = None

    async def request(self, method, params):
        if method not in _RPC_RESPONSE_LIMITS:
            raise ValidatorChainError("proof_rpc_method_forbidden")
        if isinstance(params, (str, bytes, bytearray)) or not isinstance(params, Sequence):
            raise TypeError("JSON-RPC params must be a sequence")
        # Freeze parameters once. Every transport receives exactly these bytes'
        # semantic arguments, including the original capture block/hash.
        return await self._attempt("request", (method, tuple(params)))

    async def storage_values(self, block_hash, keys):
        return await self._attempt("storage_values", (block_hash, tuple(keys)))

    async def _attempt(self, operation, arguments):
        if self._closed:
            raise ValueError("registration RPC is closed")
        eligible = [i for i, until in enumerate(self._cooldown_until) if until <= self._now()]
        if not eligible:
            raise ValidatorChainError(self._cooldown_reason())
        # Leave a fair share of the unchanged collection budget for each explicit
        # endpoint, including when a primary stalls rather than returning 429.
        timeout = self.timeout_seconds / len(eligible)
        last_error = None
        for index in eligible:
            if self._closed:
                raise ValueError("registration RPC is closed")
            # Serialize each provider's attempts. Bulk storage reads retain
            # throughput without opening a burst of eight failed handshakes.
            # A waiter rechecks the shared cooldown after acquiring this gate.
            async with self._provider_gates[index]:
                if self._closed:
                    raise ValueError("registration RPC is closed")
                if self._cooldown_until[index] > self._now():
                    continue
                try:
                    return await wait_for_owned(
                        getattr(self.transports[index], operation)(*arguments), timeout=timeout
                    )
                except asyncio.TimeoutError as error:
                    last_error = ValidatorChainError("proof_rpc_failed")
                    last_error.__cause__ = error
                    self._cooldown_until[index] = self._now() + 10.0
                    self._cooldown_reasons[index] = "proof_rpc_failed"
                except ValidatorChainError as error:
                    if error.reason_code not in _RETRYABLE:
                        raise
                    last_error = error
                    if error.reason_code == "proof_rpc_rate_limited":
                        retry_after = _retry_after(error)
                        self._cooldown_until[index] = self._now() + retry_after
                        self._cooldown_reasons[index] = "proof_rpc_rate_limited"
                        _LOGGER.warning(
                            "competition_proof_rpc_throttled",
                            extra={"provider_index": index, "retry_after_seconds": retry_after},
                        )
                    elif error.reason_code == "proof_rpc_failed":
                        self._cooldown_until[index] = self._now() + 10.0
                        self._cooldown_reasons[index] = "proof_rpc_failed"
                    # A JSON-RPC unavailable-state error is block specific, so
                    # historical failure does not quarantine current reads.
        raise last_error or ValidatorChainError(self._cooldown_reason())

    def _cooldown_reason(self):
        return (
            "proof_rpc_rate_limited"
            if any(
                reason == "proof_rpc_rate_limited" and until > self._now()
                for reason, until in zip(self._cooldown_reasons, self._cooldown_until, strict=True)
            )
            else "proof_rpc_failed"
        )

    @asynccontextmanager
    async def batch(self):
        if self._closed:
            raise ValueError("registration RPC is closed")
        async with AsyncExitStack() as stack:
            for rpc in self.transports:
                await stack.enter_async_context(rpc.batch())
            yield

    async def aclose(self):
        self._closed = True
        if self._close_task is None:
            self._close_task = asyncio.create_task(self._close())
        await await_owned_task(self._close_task)

    async def _close(self):
        async with AsyncExitStack() as stack:
            for gate in self._provider_gates:
                await stack.enter_async_context(gate)
            results = await asyncio.gather(
                *(rpc.aclose() for rpc in self.transports), return_exceptions=True
            )
        for result in results:
            if isinstance(result, BaseException):
                raise result


def _retry_after(error):
    # Do not expose headers or bodies. Bound untrusted server cooldowns, while
    # honoring the archive's ordinary Retry-After delta in seconds.
    response = getattr(error.__cause__, "response", None)
    headers = getattr(response, "headers", {})
    try:
        value = headers.get("Retry-After", "10")
        try:
            seconds = float(value)
        except ValueError:
            seconds = parsedate_to_datetime(value).timestamp() - time.time()
    except (AttributeError, LookupError, OverflowError, TypeError, ValueError):
        return 10.0
    return min(3600.0, max(1.0, seconds)) if math.isfinite(seconds) else 10.0
