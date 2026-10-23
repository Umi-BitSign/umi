"""Private byte-verification checkpoints and non-authoritative transfer progress.

These records prove only exact local bytes, never consent, execution, admission,
certification or current authority. Damaged records receive visible scoped repair.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import tempfile
import time
from contextlib import suppress
from contextvars import ContextVar
from itertools import count
from pathlib import Path
from threading import Event, RLock, Thread

from .competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS, PUBLIC_COHORT_SCOPE
from .competition_reward_proof_archive import _publication_clock_ns
from .competition_verification_rules import runtime_identity
from .file_identity import file_fingerprint
from .private_files import ensure_private_directory, lock_private_file, private_path

_LOG = logging.getLogger("umi.competition.progress")
_CURRENT = ContextVar("umi_transport_progress", default=None)
BYTE_VERIFIER_ABI = "umi-local-byte-verification/1"
_PUBLIC_WORK_IDS = count(1)


def verifier_semantics():
    # The release manifest guards qualified source changes independently from
    # this stable receipt ABI. Compatible releases keep completed byte checks.
    return [BYTE_VERIFIER_ABI, runtime_identity()]


def current_progress():
    return _CURRENT.get()


def verification_tick(ctime_ns, progress):
    """Start verification after the source's Linux coarse timestamp tick.

    Waiting happens before the byte check, never after it to upgrade an earlier
    same-tick result. Unqualified platforms visibly retain native verification.
    """
    tick = _publication_clock_ns()
    if tick is None:
        progress.emit("running", reason="byte_identity_clock_unqualified_reuse_disabled")
        return False
    if ctime_ns >= tick:
        progress.emit("waiting", reason="byte_identity_timestamp_tick")
        for _ in range(10):
            time.sleep(0.01)
            tick = _publication_clock_ns()
            if tick is None:
                return False
            if ctime_ns < tick:
                break
        else:
            # This bounds only an optimization wait, never native verification
            # or cohort execution. A skewed clock cannot hang an owned thread.
            progress.emit("running", reason="byte_identity_clock_not_advanced_reuse_disabled")
            return False
        progress.emit("running", reason="byte_identity_timestamp_ready")
    return True


def _raw(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def _sha(value):
    return hashlib.sha256(_raw(value)).hexdigest()


class TransferProgress:
    """Count restored bytes without treating them as measured native throughput."""

    heartbeat_seconds = 30.0
    stalled_seconds = 60.0
    emit_seconds = 10.0

    def __init__(
        self,
        stage,
        total,
        report=None,
        *,
        unit="bytes",
        planning_work_bytes=None,
        total_operations=None,
        planning_unit_seconds=(1.0, 300.0),
    ):
        self.stage, self.total, self.report = stage, total, report
        self.unit = unit
        if total_operations is not None and (
            type(total_operations) is not int or total_operations < 0
        ):
            raise ValueError("transfer operation count must be nonnegative")
        self.total_operations = total_operations
        self.completed_operations = self.native_operations = 0
        self.planning_work_bytes = planning_work_bytes
        self.planning_unit_seconds = planning_unit_seconds
        self.last_emit = 0.0
        self.token = None
        self.started = self.changed = self.rate_started = time.monotonic()
        self.completed = self.native = 0
        self.state = "running"
        self.reason = None
        self.lock, self.stop = RLock(), Event()
        self.thread = None
        self.child = None
        self.public_cohort = PUBLIC_COHORT_SCOPE.get()
        self.public_work_id = -next(_PUBLIC_WORK_IDS)

    def __enter__(self):
        self.token = _CURRENT.set(self)
        self.emit("started")
        self.thread = Thread(target=self._monitor, daemon=True)
        self.thread.start()
        return self

    def __exit__(self, kind, value, traceback):
        self.stop.set()
        if self.thread is not None:
            self.thread.join()
        self.emit(
            "completed" if kind is None and self._complete() else "retrying",
            reason="stage_completed" if kind is None and self._complete() else "stage_interrupted",
        )
        if self.token is not None:
            _CURRENT.reset(self.token)

    def _complete(self):
        return self.completed == self.total and (
            self.total_operations is None or self.completed_operations == self.total_operations
        )

    def advance_operations(self, count, *, restored=False):
        """Count completed exchanges; restored exchanges never inflate native rate."""
        with self.lock:
            if (
                self.total_operations is None
                or type(count) is not int
                or not 0 <= count <= self.total_operations - self.completed_operations
            ):
                raise ValueError("transfer operations exceed declared work")
            self.completed_operations += count
            if not restored:
                self.native_operations += count
            if count:
                self.changed = time.monotonic()
            if (
                self.completed_operations == self.total_operations
                or time.monotonic() - self.last_emit >= self.emit_seconds
            ):
                self.emit(
                    "running", reason="restored_operations" if restored else "native_operations"
                )

    def _monitor(self):
        while not self.stop.wait(self.heartbeat_seconds):
            self.emit(self.state)

    def advance(self, count, *, restored=False):
        with self.lock:
            self.completed += count
            if not restored:
                self.native += count
            if count:
                self.child = None
                self.changed = time.monotonic()
            if (
                self.completed == count
                or self.completed == self.total
                or time.monotonic() - self.last_emit >= self.emit_seconds
            ):
                self.emit(
                    "running", reason="restored_checkpoint" if restored else "native_progress"
                )

    def child_report(self):
        """Observe one child scope without claiming its work as parent completion.

        Only increasing completed counts refresh activity; heartbeat, retries and
        a new child's zero count cannot conceal a stalled operation. Each bounded
        child gets a separate reporter so later windows can start from zero.
        """
        previous = {}
        with self.lock:
            self.child = None

        def report(event):
            with self.lock, suppress(Exception):
                # Keep the child's own stage, rate and terminal visible.
                if self.report is None:
                    _LOG.info(json.dumps(event, separators=(",", ":")))
                else:
                    self.report(event)
                count, total = event.get("completed_units"), event.get("total_units")
                if type(count) is not int or type(total) is not int or not 0 <= count <= total:
                    return
                scope = (event.get("stage"), event.get("unit"), total)
                prior_count, prior_elapsed = previous.get(scope, (0, None))
                elapsed = event.get("elapsed_seconds")
                if count < prior_count and (
                    event.get("status") == "started"
                    or (
                        isinstance(elapsed, (int, float))
                        and isinstance(prior_elapsed, (int, float))
                        and elapsed < prior_elapsed
                    )
                ):
                    prior_count = 0
                previous[scope] = (max(prior_count, count), elapsed)
                self.child = {
                    key: event.get(key)
                    for key in (
                        "stage",
                        "status",
                        "completed_units",
                        "total_units",
                        "unit",
                        "eta_seconds",
                        "eta_basis",
                    )
                }
                state = event.get("status")
                if state in {"stalled", "retrying", "refused", "repair_required", "waiting"}:
                    self.emit(state, reason="child_" + state)
                elif count > prior_count and state in {"running", "started", "completed"}:
                    self.changed = time.monotonic()
                    self.emit("running", reason="child_progress")

        return report

    def set_completed(self, count, *, restored=False):
        with self.lock:
            if not 0 <= count <= self.total:
                raise ValueError("transfer progress exceeds its declared work")
            if count < self.completed:
                self.completed = self.native = 0
                self.rate_started = self.changed = time.monotonic()
                self.emit("retrying", reason="transfer_generation_reset")
            self.advance(count - self.completed, restored=restored)

    def emit(self, state, *, reason=None):
        # Progress sinks cannot change a successful verification or its refusal.
        with self.lock, suppress(Exception):
            now = time.monotonic()
            self.state = state
            self.last_emit = now
            if reason is not None:
                self.reason = reason
            elapsed = now - self.started
            stalled = state == "stalled" or (
                state in {"running", "waiting"} and now - self.changed >= self.stalled_seconds
            )
            remaining = max(0, self.total - self.completed)
            measured_elapsed = now - self.rate_started
            rate = self.native / measured_elapsed if measured_elapsed >= 1 and self.native else None
            eta, planning = None, None
            basis = "waiting_for_native_samples"
            if state == "completed":
                eta, basis = 0, "completed_scope"
            elif stalled or state in {"retrying", "refused", "repair_required"}:
                basis = "withdrawn_stalled_or_retrying"
            elif state == "waiting":
                planning, basis = [5, 300], "planning_external_owner_starts_now_excludes_queue"
            elif rate is not None:
                eta, basis = remaining / rate, "native_work_units_per_elapsed_second"
            elif remaining and self.unit == "bytes":
                planning = [remaining / (100 * 1024**2), remaining / 1024**2]
                basis = "planning_1_to_100_mib_per_second_excludes_external_waits"
            elif remaining and self.planning_work_bytes is not None:
                planning = [
                    self.planning_work_bytes / (100 * 1024**2),
                    self.planning_work_bytes / 1024**2,
                ]
                basis = "planning_native_check_1_to_100_mib_per_second_excludes_owner_wait"
            elif remaining:
                planning, basis = (
                    [remaining * seconds for seconds in self.planning_unit_seconds],
                    "planning_seconds_per_work_unit_excludes_queue_and_retries",
                )
            operation_eta = None
            if (
                self.total_operations is not None
                and state != "completed"
                and not stalled
                and state not in {"retrying", "refused", "repair_required", "waiting"}
            ):
                operations_left = self.total_operations - self.completed_operations
                if operations_left and self.native_operations and measured_elapsed >= 1:
                    operation_eta = operations_left * measured_elapsed / self.native_operations
                    eta = max(eta or 0, operation_eta)
                    basis = "maximum_native_byte_and_operation_extrapolations"
                elif operations_left and remaining == 0:
                    eta, basis = None, "waiting_for_native_operation_samples"
            if (
                remaining == 0
                and self.child is not None
                and self.child.get("status") != "completed"
                and state != "completed"
                and operation_eta is None
            ):
                eta, basis = None, "required_child_scope_incomplete"
            event = {
                "schema": "umi-transport-work-progress/1",
                "stage": self.stage,
                "status": "stalled" if stalled else state,
                "completed_units": self.completed,
                "total_units": self.total,
                "unit": self.unit,
                "percent": 100.0
                if state == "completed"
                else min(99.9, 100 * self.completed / self.total)
                if self.total
                else 0.0,
                "native_units": self.native,
                "restored_units": self.completed - self.native,
                "elapsed_seconds": elapsed,
                "measured_elapsed_seconds": measured_elapsed,
                "eta_seconds": eta,
                "planning_eta_seconds": planning,
                "eta_basis": basis,
                "eta_scope": "current_transfer_substage",
                "planning_seconds_per_unit": list(self.planning_unit_seconds)
                if planning is not None and basis.startswith("planning_seconds_per_work_unit")
                else None,
                "reason_code": self.reason,
                "certification_authority": False,
                "active_child": self.child,
            }
            if self.total_operations is not None:
                event.update(
                    completed_operations=self.completed_operations,
                    total_operations=self.total_operations,
                    native_operations=self.native_operations,
                    restored_operations=self.completed_operations - self.native_operations,
                    operation_eta_seconds=operation_eta,
                )
            if self.unit == "bytes":
                event.update(
                    completed_bytes=self.completed,
                    total_bytes=self.total,
                    native_bytes=self.native,
                    restored_bytes=self.completed - self.native,
                )
            PUBLIC_COHORT_PROGRESS.record(
                "work",
                {
                    **event,
                    "cohort_sha256": self.public_cohort,
                    "work_id": self.public_work_id,
                    "state": "running"
                    if not self.stop.is_set()
                    and state in {"started", "running", "repair_completed", "retrying", "waiting"}
                    else "completed"
                    if state == "completed"
                    else "interrupted",
                    "completed": self.completed,
                    "total": self.total,
                    "stalled_or_retrying": stalled
                    or state in {"retrying", "refused", "repair_required", "waiting"},
                },
            )
            if self.report is None:
                _LOG.info(json.dumps(event, separators=(",", ":")))
            else:
                self.report(event)


class ByteCheckpoints:
    """One serialized private completion store, keyed independently of metadata.

    File stamps and explicit verifier semantics are receipt dependencies, not cache
    filenames: changed dependencies and missing completed records remain visible.
    """

    def __init__(self, root, context, progress):
        self.root, self.context, self.progress = Path(root), _sha(context), progress
        self.descriptor = None
        self.repairs = set()

    def __enter__(self):
        ensure_private_directory(self.root)
        self.descriptor = lock_private_file(self.root / ".verification.lock")
        return self

    def __exit__(self, *_):
        if self.descriptor is not None:
            os.close(self.descriptor)

    def path(self, slot):
        return self.root / (_sha(slot) + ".json")

    def _read(self, path):
        # Corrupt owned content is repairable. Unsafe links, modes, owners and
        # concurrent metadata changes are refusals, never ordinary cache misses.
        private_path(str(path))
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink != 1
                or before.st_uid != os.getuid()
                or before.st_mode & 0o077
            ):
                raise ValueError("byte checkpoint requires an owned private regular file")
            raw = stream.read(before.st_size + 1)
            if (
                len(raw) != before.st_size
                or file_fingerprint(os.fstat(stream.fileno())) != file_fingerprint(before)
                or file_fingerprint(path.lstat()) != file_fingerprint(before)
            ):
                raise ValueError("byte checkpoint changed while reading")
            return raw

    def _repair(self, slot, reason):
        self.repairs.add(_sha(slot))
        self.progress.emit("repair_required", reason=reason)

    @staticmethod
    def _validated_record(raw):
        """Decode intact private metadata; this alone does not authorize reuse."""
        value = json.loads(raw)
        if not isinstance(value, dict) or set(value) != {
            "schema",
            "context",
            "identity",
            "result",
            "checksum",
        }:
            raise ValueError("byte receipt fields differ")
        checksum = value.pop("checksum")
        if checksum != _sha(value) or value["schema"] != "umi-private-byte-verification/1":
            raise ValueError("byte receipt checksum differs")
        for field in ("context", "result"):
            if (
                not isinstance(value[field], str)
                or len(value[field]) != 64
                or any(c not in "0123456789abcdef" for c in value[field])
            ):
                raise ValueError("byte receipt identity differs")
        return value

    def load(self, slot, identity, *, repair_completion=True):
        """Read a validated fact; migration can leave legacy markers untouched."""
        path = self.path(slot)
        marker = path.with_suffix(".complete")
        try:
            try:
                complete = self._read(marker)
            except FileNotFoundError:
                complete = None
            try:
                raw = self._read(path)
            except FileNotFoundError:
                if complete is not None:
                    self._repair(slot, "completed_byte_receipt_missing")
                return None
        except (OSError, ValueError):
            self.progress.emit("refused", reason="byte_checkpoint_unsafe_or_unstable")
            raise
        try:
            value = self._validated_record(raw)
            if value["context"] != self.context or value["identity"] != identity:
                self._repair(slot, "byte_verification_dependencies_changed")
                return None
        except (TypeError, ValueError, UnicodeError):
            self._repair(slot, "byte_receipt_damaged")
            return None
        if complete != path.stem.encode():
            self.progress.emit(
                "repair_required", reason="byte_completion_marker_missing_or_damaged"
            )
            if repair_completion:
                self._write(marker, path.stem.encode())
                self.progress.emit(
                    "repair_completed", reason="byte_completion_marker_restored_from_receipt"
                )
        return value["result"]

    def _write(self, path, raw):
        descriptor, pending = tempfile.mkstemp(prefix=".byte-verification-", dir=self.root)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(pending, path)
            directory = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            Path(pending).unlink(missing_ok=True)

    def remember(self, slot, identity, result):
        value = {
            "schema": "umi-private-byte-verification/1",
            "context": self.context,
            "identity": identity,
            "result": result,
        }
        value["checksum"] = _sha(value)
        path = self.path(slot)
        self._write(path, _raw(value))
        self._write(path.with_suffix(".complete"), path.stem.encode())
        if _sha(slot) in self.repairs:
            self.repairs.remove(_sha(slot))
            self.progress.emit("repair_completed", reason="byte_receipt_native_repair_persisted")


class ProgressReader:
    """Keep the original native reader while counting its actual byte reads."""

    def __init__(self, stream, progress):
        self.stream, self.progress = stream, progress

    def fileno(self):
        return self.stream.fileno()

    def read(self, size):
        data = self.stream.read(size)
        self.progress.advance(len(data))
        return data
