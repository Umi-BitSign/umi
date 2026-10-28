"""Refuse damaged retained request owners before loading their large declarations.

This is a fresh native read, never a repair, readiness verdict or reusable proof.
Successful initialization still performs every original input and journal check.
"""

import sqlite3
import time
from pathlib import Path

from .competition_round_journal import RoundJournal


class RequestOwnerRepairRequired(ValueError):
    def __init__(self, reason_code: str, elapsed_seconds: float):
        super().__init__(reason_code)
        self.reason_code, self.elapsed_seconds = reason_code, elapsed_seconds

    def report(self):
        return {
            "status": "cohort_lifecycle_repair_required",
            "reason_code": self.reason_code,
            "repair_required": True,
            "completed": 0,
            "total": 1,
            "unit": "journals",
            "elapsed_seconds": self.elapsed_seconds,
            "eta_seconds": None,
            "eta_basis": "native_request_owner_repair_required",
            "eta_scope": "request_owner_initialization",
            "stalled_or_retrying": True,
        }


class _RequestOwnerReadOnly(RoundJournal):
    def _validate_existing(self, binding):
        # A live writer's rollback sidecar is not evidence of damage. The native
        # read-only snapshot can inspect committed state, and still refuses a hot
        # journal that actually requires recovery. No sidecar is removed/repaired.
        return super()._validate_existing(binding, require_clean_rollback=False)


def preflight_request_owner(root: Path, binding: dict, cohort: str, *, maximum_bytes: int) -> None:
    started = time.monotonic()
    try:
        root.lstat()
    except FileNotFoundError:
        return  # First initialization stays with the original constructor.
    try:
        journal = _RequestOwnerReadOnly(
            root,
            binding,
            maximum_rounds=65536,
            maximum_bytes=maximum_bytes,
            existing_only=True,
            read_only=True,
        )
        # Holds are keyed by id across record kinds. Do not bypass a held key to
        # inspect its previous bytes or guess which configuration change caused it.
        journal.get("request_phase_binding", cohort)
    except ValueError as error:
        reason = {
            "round journal conflict held": "request_owner_conflict_held",
            "existing journal binding requires explicit migration": "request_owner_binding_changed",
        }.get(str(error), "request_owner_journal_invalid")
        if str(error) == "existing journal requires original directory, database and lock":
            reason = "request_owner_journal_incomplete"
        raise RequestOwnerRepairRequired(reason, time.monotonic() - started) from error
    except sqlite3.DatabaseError as error:
        # Busy/locked, I/O and read-only recovery failures remain ordinary
        # retryable owner errors. Only established schema/corruption failures
        # become repair diagnostics; nothing is latched across the next attempt.
        code = getattr(error, "sqlite_errorcode", None)
        if code is None or code & 0xFF not in {
            sqlite3.SQLITE_CORRUPT,
            sqlite3.SQLITE_NOTADB,
            sqlite3.SQLITE_SCHEMA,
            sqlite3.SQLITE_ERROR,
        }:
            raise
        raise RequestOwnerRepairRequired(
            "request_owner_journal_invalid", time.monotonic() - started
        ) from error
