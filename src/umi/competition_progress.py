"""Bounded phase diagnostics; never authorization or durable progress evidence."""

import asyncio
import inspect
import json
import logging
import os
import time
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from itertools import count

_LOG = logging.getLogger("umi.competition.progress")
_PARENT = ContextVar("competition_progress_parent", default=None)
_IDS = count(1)
_PHASES = frozenset(
    {
        "host_service",
        "host_anchor",
        "initial_inputs",
        "worker_inputs",
        "history_load",
        "reconcile",
        "chain_observation",
        "authorization_gates",
        "stopped_recovery",
        "transaction_recovery",
        "cache_retirement",
        "artifact_staging",
        "package_verification",
        "publication_replay",
        "preflight",
        "worker_start",
        "materializer_anchor",
        "materializer_stage",
        "materializer_observation",
        "materializer_activation",
    }
)
_REASONS = {
    "successor activation headroom is insufficient": "activation_headroom_insufficient",
    "successor directive is not active": "directive_not_active",
    "successor validator permit is absent": "validator_permit_absent",
    "selected validator has no finalized permit": "validator_permit_absent",
    "successor genesis pin changed": "genesis_pin_changed",
    "successor publication replay is held": "publication_replay_held",
    "weight finality rolled back, changed or became stale": "finality_changed_or_stale",
    "recipient or validator registration changed": "registration_changed",
    "successor transaction effects remain unknown": "transaction_effects_unknown",
    "successor worker startup was not confirmed": "worker_start_unconfirmed",
    "weight observation was not issued by the owned proof adapter": "owned_proof_rejected",
    "materializer activation permit or interval is unavailable": "activation_unavailable",
    "materializer finalized observation rolled back or forked": "finality_rollback_or_fork",
}


def configure_progress_logging():
    """Enable only this logger; leave HTTP loggers and root configuration alone."""
    if not _LOG.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        _LOG.addHandler(handler)
    _LOG.setLevel(logging.INFO)
    _LOG.propagate = False


def _reason(error):
    # Match exact static native messages without formatting unknown exceptions.
    if len(error.args) == 1 and type(error.args[0]) is str:
        known = _REASONS.get(error.args[0])
        if known is not None:
            return known
    for kind, code in (
        (asyncio.CancelledError, "cancelled"),
        (TimeoutError, "timeout"),
        (PermissionError, "permission_denied"),
        (OSError, "os_error"),
        (ValueError, "validation_failed"),
        (KeyboardInterrupt, "interrupted"),
        (SystemExit, "process_exit"),
    ):
        if isinstance(error, kind):
            return code
    return "internal_error"


def _emit(body, *, failed=False):
    # Diagnostics must not change validation results or transaction recovery.
    with suppress(Exception):
        _LOG.log(
            logging.WARNING if failed else logging.INFO,
            json.dumps(
                {
                    "schema": "umi-competition-phase/1",
                    "pid": os.getpid(),
                    "observed_unix_ms": time.time_ns() // 1_000_000,
                    **body,
                },
                separators=(",", ":"),
            ),
        )


@contextmanager
def progress_phase(name):
    if name not in _PHASES:
        raise ValueError("unknown competition diagnostic phase")
    identity = next(_IDS)
    common = {"phase": name, "phase_id": identity, "parent_phase_id": _PARENT.get()}
    token = _PARENT.set(identity)
    started = time.monotonic_ns()
    _emit({**common, "event": "started"})
    try:
        yield
    except BaseException as error:
        _emit(
            {
                **common,
                "event": "failed",
                "reason_code": _reason(error),
                "elapsed_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
            },
            failed=True,
        )
        raise
    else:
        _emit(
            {
                **common,
                "event": "completed",
                "elapsed_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
            }
        )
    finally:
        _PARENT.reset(token)


def log_phase(name):
    """Wrap sync or async native work without capturing its arguments/results."""
    if name not in _PHASES:
        raise ValueError("unknown competition diagnostic phase")

    def decorate(operation):
        if inspect.iscoroutinefunction(operation):

            @wraps(operation)
            async def asynchronous(*args, **kwargs):
                with progress_phase(name):
                    return await operation(*args, **kwargs)

            return asynchronous

        @wraps(operation)
        def synchronous(*args, **kwargs):
            with progress_phase(name):
                return operation(*args, **kwargs)

        return synchronous

    return decorate
