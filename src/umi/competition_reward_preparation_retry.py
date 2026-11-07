"""Retry unfinished transport reads without replacing the preparation owner."""

import asyncio
import json
import logging
import time

from .validator_chain import ValidatorChainError

_LOG = logging.getLogger(__name__)
_RETRY_SECONDS = 30
_TRANSPORT_FAILURES = {"proof_rpc_failed", "proof_rpc_rate_limited", "proof_rpc_error"}


async def _wait_for_retry(provider):
    deadline = time.monotonic() + _RETRY_SECONDS
    while True:
        provider.ensure_observer_running()
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return
        await asyncio.sleep(min(1, remaining))


async def review_preparation_expiry(review, provider, *, recheck, progress, arguments):
    """Only transport errors retry; native proof and input failures propagate.

    The caller still validates and checkpoints the result. The existing provider
    retains its durable ancestry, verified proofs and shared transport cooldowns.
    No retry creates a result, advances the attempt count or obtains writer rights.
    """
    started, retries = time.monotonic(), 0
    estimate = progress.estimate
    try:
        while True:
            if retries:
                provider.ensure_observer_running()
                recheck()
            try:
                return await review(provider, **arguments)
            except ValidatorChainError as error:
                if error.reason_code not in _TRANSPORT_FAILURES:
                    raise
                provider.ensure_observer_running()
                recheck()
                retries += 1
                progress.estimate = False
                elapsed = time.monotonic() - started
                _LOG.warning(
                    "%s",
                    json.dumps(
                        dict(
                            schema="umi-legacy-preparation-retry/1",
                            stage="legacy_handoff_expiry_transport",
                            status="retrying",
                            completed=progress.completed,
                            total=progress.total,
                            retry_count=retries,
                            elapsed_seconds=elapsed,
                            eta_seconds=None,
                            planning_eta_seconds=None,
                            eta_basis="withdrawn_transport_retry",
                            eta_scope="unfinished_expiry_only_not_handoff_or_rewards",
                            retry_after_seconds=_RETRY_SECONDS,
                            stalled_or_retrying=True,
                            retrying=True,
                            reason_code=error.reason_code,
                            certification_authority=False,
                        ),
                        sort_keys=True,
                    ),
                )
            # Leave the exception scope before waiting, releasing its traceback
            # and any partial graph. Cancellation and observer death propagate.
            await _wait_for_retry(provider)
    finally:
        progress.estimate = estimate
