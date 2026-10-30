"""Bounded phase diagnostics; never authorization or durable progress evidence."""

import asyncio
import inspect
import json
import logging
import os
import re
import sqlite3
import time
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from functools import wraps
from itertools import count

from .competition_weight_timing import WeightRateLimitWait
from .r2_evidence import R2EvidenceHTTPError
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
        "cohort_request_tail_adoption_vote",
        "cohort_model_delivery_adoption_vote",
        "cohort_evaluation_suite_adoption_vote",
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
    "cohort authority changed before execution progress": "execution_authority_changed",
    "waiting for finalized block after cohort preparation": "execution_finality_after_preparation",
    "shared incumbent source remains unfinished": "execution_incumbent_source_pending",
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
    if isinstance(error, sqlite3.Error):
        code = _sqlite_details(error).get("sqlite_errorcode")
        return {
            5: "sqlite_busy",
            6: "sqlite_locked",
            8: "sqlite_readonly",
            10: "sqlite_io_error",
            11: "sqlite_corrupt",
            13: "sqlite_full",
            14: "sqlite_cannot_open",
        }.get(None if code is None else code & 255, "sqlite_error")
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


def _sqlite_details(error):
    """Expose numeric native failures, never SQL, paths or exception text.

    Older supported Python versions may omit these attributes. Names must be
    constants from the running sqlite3 module and agree with the numeric code.
    """
    if not isinstance(error, sqlite3.Error):
        return {}
    code = getattr(error, "sqlite_errorcode", None)
    if type(code) is not int or not 0 <= code <= 65535:
        return {}
    result = {"sqlite_errorcode": code}
    name = getattr(error, "sqlite_errorname", None)
    if (
        type(name) is str
        and re.fullmatch(r"SQLITE_[A-Z0-9_]{1,64}", name)
        and getattr(sqlite3, name, None) == code
    ):
        result["sqlite_errorname"] = name
    return result


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
                **_sqlite_details(error),
            }
        )
        if isinstance(error, R2EvidenceHTTPError):
            status = getattr(error, "status_code", None)
            if type(status) is int and 100 <= status <= 599:
                causes[-1]["r2_http_status"] = status
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


def report_settlement_retry(*, cohort, role, stage, error):
    """Record bounded causes before memory cleanup, without retaining inputs."""
    # Failed diagnostics cannot replace the retry or alter work ownership.
    with suppress(Exception):
        _emit(
            {
                "event": "settlement_retry",
                "cohort_sha256": (
                    cohort
                    if type(cohort) is str and re.fullmatch(r"[0-9a-f]{64}", cohort)
                    else None
                ),
                "role": role if role in {"coordinator", "reviewer"} else "unknown",
                "stage": stage if stage in {"tick", "maintenance"} else "unknown",
                "reason_code": _reason(error),
                "causes": _failure_details(error),
                "state": "retrying",
                "eta_seconds": None,
                "eta_basis": "retry_requires_new_progress_sample",
                "certification_authority": False,
            },
            failed=True,
        )


def report_execution_retry(
    *, slot, error, retry_count=None, retry_elapsed_seconds=None, retry_remaining_seconds=None
):
    """Expose native execution failures without exception text or retained inputs."""
    _emit(
        {
            "event": "execution_retry",
            "slot": slot if type(slot) is str and re.fullmatch(r"[0-9a-f]{64}", slot) else None,
            "reason_code": _reason(error),
            "causes": _failure_details(error),
            "state": "retrying",
            "eta_seconds": None,
            "eta_basis": "retry_requires_new_progress_sample",
            "certification_authority": False,
            **(
                {
                    "stage": "resident_execution_recovery",
                    "completed": 0,
                    "total": 1,
                    "retry_count": retry_count,
                    "elapsed_seconds": round(retry_elapsed_seconds, 3),
                    "retry_remaining_seconds": round(retry_remaining_seconds, 3),
                    "planning_eta_seconds": [0, round(retry_remaining_seconds, 3)],
                    "eta_basis": "bounded_retry_allowance_not_completion_prediction",
                    "eta_scope": "failed_resident_operation_only",
                    "stalled_or_retrying": True,
                }
                if retry_count is not None
                else {}
            ),
        },
        failed=True,
    )


def report_container_command_failure(
    command,
    returncode,
    stderr,
    *,
    source="stderr",
    observed_bytes=None,
    elapsed_ms=None,
    outcome="failed",
):
    """Classify bounded untrusted output; never publish its text or arguments."""
    if command not in {
        "info",
        "ps",
        "image",
        "container",
        "load",
        "create",
        "start",
        "stop",
        "rm",
        "system",
        "unshare",
    }:
        command = "unknown"
    detail = stderr[:16384].lower() if type(stderr) is bytes else b""
    # Fixed labels remain useful even when a tool echoes credentials, an entire
    # environment or a model-controlled path around the recognized phrase.
    reasons = [
        code
        for phrase, code in (
            (b"cannot mount tmpfs on /tmp", "tmpfs_mount_failed"),
            (b"create_sandbox failed", "network_sandbox_failed"),
            (b"permission denied", "permission_denied"),
            (b"operation not permitted", "operation_not_permitted"),
            (b"no space left on device", "storage_full"),
            (b"no such file or directory", "path_missing"),
            (b"connection refused", "connection_refused"),
            (b"read-only file system", "read_only_filesystem"),
        )
        if phrase in detail
    ]
    components = [
        name
        for name in ("slirp4netns", "crun", "conmon", "dbus", "systemd")
        if name.encode("ascii") in detail
    ]
    count = (
        observed_bytes
        if type(observed_bytes) is int and observed_bytes >= 0
        else len(stderr)
        if type(stderr) is bytes
        else 0
    )
    _emit(
        {
            "event": "container_command_failed",
            "outcome": outcome if outcome in {"failed", "timeout", "cancelled"} else "unknown",
            "command": command,
            "returncode": returncode if type(returncode) is int else None,
            "source": source if source in {"stderr", "owned_state_error"} else "unknown",
            "reason_codes": reasons or ["unclassified_runtime_error"],
            "components": components,
            "observed_bytes": count,
            "classified_bytes": len(detail),
            "truncated": count > len(detail),
            "elapsed_ms": elapsed_ms if type(elapsed_ms) is int and elapsed_ms >= 0 else None,
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
