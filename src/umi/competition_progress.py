"""Bounded phase diagnostics; never authorization or durable progress evidence."""

import asyncio
import inspect
import json
import logging
import os
import re
import time
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from itertools import count

from .competition_weight_timing import WeightRateLimitWait
from .validator_chain import ValidatorChainError

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
        "cohort_intake_review",
        "cohort_preparation_review",
        "cohort_request_completion_review",
        "cohort_progress_vote",
        "cohort_decision_vote",
        "cohort_service_vote",
        "service_admission_catalog",
        "service_admission_history",
        "service_admission_capture",
        "service_admission_history_review",
        "service_admission_roster",
    }
)
_REASONS = {
    "owned_finality_observer_stopped": "owned_finality_observer_stopped",
    "owned_service_task_stopped": "owned_service_task_stopped",
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
    native = getattr(error, "reason_code", None)
    if (
        type(error).__module__.startswith("umi.")
        and type(native) is str
        and re.fullmatch(r"[a-z][a-z0-9_]{0,95}", native)
    ):
        return native
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


def _failure_details(error):
    causes, seen = [], set()
    while error is not None and id(error) not in seen and len(causes) < 8:
        seen.add(id(error))
        frames, tb = [], error.__traceback__
        while tb is not None:
            module = tb.tb_frame.f_globals.get("__name__", "")
            if type(module) is str and module.startswith("umi."):
                frames.append(
                    {
                        "module": module[:160],
                        "function": tb.tb_frame.f_code.co_name[:160],
                        "line": tb.tb_lineno,
                    }
                )
            tb = tb.tb_next
        causes.append(
            {
                "error_type": (type(error).__module__ + "." + type(error).__qualname__)[:200],
                "reason_code": _reason(error),
                "source_frames": frames[-8:],
            }
        )
        if isinstance(error, ValidatorChainError):
            for name in (
                "rpc_method",
                "rpc_error_code",
                "rpc_block_hash",
                "rpc_http_status",
                "rpc_transport_error",
            ):
                value = getattr(error, name)
                if value is not None:
                    causes[-1][name] = value
            if error.rpc_failures:
                causes[-1]["rpc_failures"] = error.rpc_failures
        error = error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return causes


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


def report_admission_failure(operation, stage, error):
    """Report native failure boundaries without request data or exception messages."""
    if operation not in {"model_delivery", "service_claim", "service_readiness"}:
        operation = "unknown"
    if stage not in {
        "body",
        "retry",
        "capture",
        "reserve",
        "status",
        "chunk",
        "admit",
        "queue_unavailable",
        "owner_inputs_unavailable",
        "archive_unavailable",
    }:
        stage = "unknown"
    _emit(
        {
            "event": "admission_held",
            "operation": operation,
            "stage": stage,
            "causes": _failure_details(error),
        },
        failed=True,
    )


def report_container_command_failure(command, returncode, stderr):
    """Keep runtime errors useful without logging arguments or bearer URLs."""
    if command not in {"info", "ps", "image", "container", "load", "create", "start", "stop", "rm"}:
        command = "unknown"
    detail = stderr.decode("utf-8", errors="replace")[:16384]
    detail = re.sub(r"(?:https?|wss?)://[^\s<>\"']+", "[redacted URL]", detail)
    detail = re.sub(r"/v1/clips/[^\s<>\"']+", "/v1/clips/[redacted]", detail)
    _emit(
        {
            "event": "container_command_failed",
            "command": command,
            "returncode": returncode,
            "stderr": detail,
        },
        failed=True,
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
    except WeightRateLimitWait as wait:
        _emit(
            {
                **common,
                "event": "waiting",
                "reason_code": wait.reason_code,
                "observed_block": wait.observed_block,
                "next_eligible_block": wait.next_eligible_block,
                "elapsed_ms": max(0, (time.monotonic_ns() - started) // 1_000_000),
            }
        )
        raise
    except BaseException as error:
        _emit(
            {
                **common,
                "event": "failed",
                "reason_code": _reason(error),
                "causes": _failure_details(error),
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
