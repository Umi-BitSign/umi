"""Prospective predecode capacity qualification, separate from native verdicts.

The trusted caller supplies immutable identities only after authenticating its
source. Counts authorize a bounded decode, never semantic validity, signatures
or inference quality. No native verification context or legacy bound changes.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
import threading
import traceback
from contextlib import contextmanager, nullcontext
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .host_memory_request_bounds import count_json_shape
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_SEMANTICS = "umi-workload-json-shape/1"
_ISSUER = object()
_selected = ContextVar("host_memory_workload_profile", default=None)
_budget = ContextVar("host_memory_workload_budget", default=None)
Positive = Annotated[int, Field(gt=0, strict=True)]


class WorkloadQualificationPending(OSError):
    """Capacity or qualification is unavailable; never a model quality result."""

    def __init__(self, reason: str, *, kind=None):
        self.reason_code = "workload_qualification_pending"
        self.qualification_reason = reason
        self.kind = kind
        super().__init__("workload qualification pending: " + reason)


def _absolute(value):
    path = Path(value)
    if (
        type(value) is not str
        or not path.is_absolute()
        or str(path) != value
        or ".." in path.parts
        or "\0" in value
        or path == Path(path.anchor)
    ):
        raise ValueError("workload paths require canonical absolute locations")
    return path


class WorkloadProfileSelection(StrictProtocolModel):
    path: str
    sha256: Hex32

    @model_validator(mode="after")
    def location(self):
        _absolute(self.path)
        return self


class WorkloadBounds(StrictProtocolModel):
    maximum_records: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_objects: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_services: Annotated[int, Field(gt=0, le=262144, strict=True)]
    maximum_orders: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_inventory_entries: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_participants: Annotated[int, Field(gt=0, le=65536, strict=True)]
    maximum_catalogs: Annotated[int, Field(gt=0, le=64, strict=True)]
    maximum_input_bytes: Positive
    maximum_object_bytes: Positive
    maximum_declaration_bytes: Positive
    maximum_json_values: Positive
    maximum_json_depth: Annotated[int, Field(gt=0, le=256, strict=True)]

    @model_validator(mode="after")
    def subordinate_bytes(self):
        if (
            max(self.maximum_object_bytes, self.maximum_declaration_bytes)
            > self.maximum_input_bytes
        ):
            raise ValueError("workload member bound exceeds its input bound")
        return self


class WorkloadProfile(StrictProtocolModel):
    schema_: Literal["umi-host-memory-workload-profile/1"] = Field(alias="schema")
    roles: Annotated[
        tuple[Literal["intake", "phase_reviewer", "settlement"], ...],
        Field(min_length=1, max_length=3),
    ]
    protocol_policy_sha256: Hex32
    evaluation_runtime_sha256: Hex32
    series_sha256: Hex32 | None
    authority_sha256: Hex32 | None
    qualification_sha256: Hex32
    bounds: WorkloadBounds
    maximum_queued_input_bytes: Positive
    maximum_http_inflight: Annotated[int, Field(gt=0, le=64, strict=True)]
    maximum_preparation_workers: Annotated[int, Field(gt=0, le=64, strict=True)]
    maximum_receipt_entries: Annotated[int, Field(gt=0, le=10000000, strict=True)]
    receipt_directories: Annotated[dict[str, str], Field(min_length=1, max_length=64)]
    count_reuse_profile: WorkloadProfileSelection | None = None

    @model_serializer(mode="wrap")
    def preserve_legacy_bytes(self, handler):
        value = handler(self)
        if self.count_reuse_profile is None:
            value.pop("count_reuse_profile", None)
        return value

    @model_validator(mode="after")
    def scope_and_storage(self):
        if len(set(self.roles)) != len(self.roles):
            raise ValueError("workload profile repeats a role")
        if (self.series_sha256 is None) != (self.authority_sha256 is None):
            raise ValueError("workload series and authority must be selected together")
        for uid, path in self.receipt_directories.items():
            if not uid.isdecimal() or str(int(uid)) != uid:
                raise ValueError("workload receipt owner is invalid")
            _absolute(path)
        if len(set(self.receipt_directories.values())) != len(self.receipt_directories):
            raise ValueError("workload receipt owners need separate private stores")
        return self


def _private_directory(path):
    from .host_memory_admission import _open_directory

    path = _absolute(str(path))
    parent = leaf = None
    try:
        # Root-controlled, nonwritable ancestry prevents replacement of the
        # service-owned private leaf. Reject symlinks while opening each part.
        parent = _open_directory(path.parent)
        leaf = os.open(
            path.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent
        )
        info = os.fstat(leaf)
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise WorkloadQualificationPending("receipt_directory_not_private")
    except WorkloadQualificationPending:
        raise
    except (OSError, ValueError):
        raise WorkloadQualificationPending("receipt_directory_ancestry_changed") from None
    finally:
        if leaf is not None:
            os.close(leaf)
        if parent is not None:
            os.close(parent)
    return path


def _owned_file(path):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise WorkloadQualificationPending("receipt_file_not_private")


class _CountStore:
    """Atomic bounded metadata, with explicit missing/corrupt completion errors."""

    def __init__(self, directory, maximum):
        self.directory, self.maximum = _private_directory(directory), maximum
        self.path = self.directory / "workload-counts.sqlite3"
        self.marker = self.directory / "workload-counts.initialized"
        self.lock_path = self.directory / "workload-counts.lock"
        self.lock = threading.RLock()

    @contextmanager
    def serialized(self):
        """One count/scan/persist owner, including other profile instances.

        The thread lock serializes this store's workers; the file lock covers
        a separately loaded profile or another process using the same receipts.
        Neither a second scan nor budget updates can race the first completion.
        """
        with self.lock:
            _private_directory(self.directory)
            descriptor = os.open(
                self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600
            )
            try:
                _owned_file(self.lock_path)
                opened, selected = os.fstat(descriptor), self.lock_path.lstat()
                if (opened.st_dev, opened.st_ino) != (selected.st_dev, selected.st_ino):
                    raise WorkloadQualificationPending("receipt_lock_changed")
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                os.close(descriptor)

    @contextmanager
    def connection(self):
        _private_directory(self.directory)
        initialized = os.path.lexists(self.marker)
        if initialized:
            _owned_file(self.marker)
            if (
                self.marker.stat().st_size != 27
                or self.marker.read_bytes() != b"umi-workload-count-store/1\n"
            ):
                raise WorkloadQualificationPending("receipt_store_marker_changed")
            if not os.path.lexists(self.path):
                raise WorkloadQualificationPending("completed_receipt_store_missing")
        if not os.path.lexists(self.path):
            try:
                fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            except FileExistsError:
                pass
            else:
                os.close(fd)
        _owned_file(self.path)
        db = None
        try:
            db = sqlite3.connect(str(self.path), timeout=1)
            db.execute("PRAGMA synchronous=FULL")
            db.execute("PRAGMA temp_store=MEMORY")
            if initialized:
                if db.execute("SELECT format FROM metadata WHERE id=1").fetchone() != (_SEMANTICS,):
                    raise WorkloadQualificationPending("completed_receipt_store_format_changed")
            else:
                with db:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS counts "
                        "(key TEXT PRIMARY KEY, body BLOB NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS completed "
                        "(key TEXT PRIMARY KEY, checksum TEXT NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS size "
                        "(id INTEGER PRIMARY KEY CHECK(id=1), n INTEGER NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS metadata "
                        "(id INTEGER PRIMARY KEY CHECK(id=1), format TEXT NOT NULL)"
                    )
                    db.execute("INSERT OR IGNORE INTO size VALUES (1,0)")
                    db.execute("INSERT OR IGNORE INTO metadata VALUES (1,?)", (_SEMANTICS,))
                if db.execute("SELECT format FROM metadata WHERE id=1").fetchone() != (_SEMANTICS,):
                    raise WorkloadQualificationPending("receipt_store_format_changed")
            if not initialized:
                try:
                    fd = os.open(
                        self.marker, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                    )
                except FileExistsError:
                    pass
                else:
                    try:
                        os.write(fd, b"umi-workload-count-store/1\n")
                        os.fsync(fd)
                    finally:
                        os.close(fd)
                    directory = os.open(self.directory, os.O_RDONLY | os.O_DIRECTORY)
                    try:
                        os.fsync(directory)
                    finally:
                        os.close(directory)
            yield db
        except sqlite3.Error:
            raise WorkloadQualificationPending("receipt_store_repair_required") from None
        finally:
            if db is not None:
                db.close()

    def read(self, key, expected):
        with self.connection() as db:
            completion = db.execute("SELECT checksum FROM completed WHERE key=?", (key,)).fetchone()
            row = db.execute("SELECT body FROM counts WHERE key=?", (key,)).fetchone()
        if completion is None and row is None:
            return None
        if completion is None or row is None:
            raise WorkloadQualificationPending("completed_count_record_missing")
        raw = row[0]
        if (
            type(raw) is not bytes
            or len(raw) > 16384
            or hashlib.sha256(raw).hexdigest() != completion[0]
        ):
            raise WorkloadQualificationPending("count_record_changed")
        try:
            value = json.loads(raw)
        except (ValueError, TypeError):
            raise WorkloadQualificationPending("count_record_invalid") from None
        if (
            type(value) is not dict
            or set(value) != {*expected, "values"}
            or any(value.get(k) != v for k, v in expected.items())
            or type(value["values"]) is not int
            or value["values"] <= 0
        ):
            raise WorkloadQualificationPending("count_record_binding_changed")
        return value["values"]

    def remember(self, key, expected, values):
        raw = canonical_json_bytes(dict(expected, values=values))
        checksum = hashlib.sha256(raw).hexdigest()
        with self.connection() as db, db:
            db.execute("BEGIN IMMEDIATE")
            prior = db.execute("SELECT body FROM counts WHERE key=?", (key,)).fetchone()
            completion = db.execute("SELECT checksum FROM completed WHERE key=?", (key,)).fetchone()
            if prior is not None or completion is not None:
                if prior != (raw,) or completion != (checksum,):
                    raise WorkloadQualificationPending("count_record_conflict")
                return
            count = db.execute("SELECT n FROM size WHERE id=1").fetchone()
            if count is None or type(count[0]) is not int or not 0 <= count[0] < self.maximum:
                raise WorkloadQualificationPending("receipt_store_capacity")
            db.execute("INSERT INTO counts VALUES (?,?)", (key, raw))
            db.execute("INSERT INTO completed VALUES (?,?)", (key, checksum))
            db.execute("UPDATE size SET n=n+1 WHERE id=1")


@dataclass(frozen=True)
class LoadedWorkloadProfile:
    profile: WorkloadProfile
    sha256: str
    role: str
    counts: _CountStore
    count_profile_sha256: str

    @property
    def bounds(self):
        return self.profile.bounds


def load_workload_profile(selection, controller_binding):
    """Authenticate root-owned metadata and an explicit actual controller scope."""
    # Local import avoids the policy-schema/admission/profile import cycle.
    from .host_memory_admission import _read_policy

    if not isinstance(selection, WorkloadProfileSelection):
        selection = WorkloadProfileSelection.model_validate(selection)
    raw = _read_policy(_absolute(selection.path))
    if hashlib.sha256(raw).hexdigest() != selection.sha256:
        raise WorkloadQualificationPending("profile_selection_changed")
    profile = WorkloadProfile.model_validate_json(raw)
    fields = (
        "protocol_policy_sha256",
        "evaluation_runtime_sha256",
        "series_sha256",
        "authority_sha256",
    )
    if controller_binding.get("role") not in profile.roles or any(
        controller_binding.get(name) != getattr(profile, name) for name in fields
    ):
        raise WorkloadQualificationPending("profile_controller_scope_changed")
    directory = profile.receipt_directories.get(str(os.getuid()))
    if directory is None:
        raise WorkloadQualificationPending("profile_receipt_owner_unselected")
    count_identity = selection.sha256
    reuse = profile.count_reuse_profile
    if reuse is not None:
        previous_raw = _read_policy(_absolute(reuse.path))
        if hashlib.sha256(previous_raw).hexdigest() != reuse.sha256:
            raise WorkloadQualificationPending("count_reuse_profile_changed")
        previous = WorkloadProfile.model_validate_json(previous_raw)
        # Keep one immutable original count binding, not a chain of historical
        # startup profiles. Only HTTP scheduling and its qualification may
        # change; bounds, authority, receipt ownership and capacity must match.
        excluded = {
            "maximum_http_inflight",
            "maximum_queued_input_bytes",
            "qualification_sha256",
            "count_reuse_profile",
        }
        if previous.count_reuse_profile is not None or profile.model_dump(
            exclude=excluded
        ) != previous.model_dump(exclude=excluded):
            raise WorkloadQualificationPending("count_reuse_dependencies_changed")
        count_identity = reuse.sha256
    counts = _CountStore(Path(directory), profile.maximum_receipt_entries)
    return LoadedWorkloadProfile(
        profile, selection.sha256, controller_binding["role"], counts, count_identity
    )


@dataclass(frozen=True)
class WorkloadInputIdentity:
    namespace: str
    identity: str
    size: int
    _issuer: object


def trusted_workload_identity(namespace, identity, size):
    """Adapt an already authenticated immutable native identity, never user input.

    Native snapshot/read owners must recheck their source stamp/authority before
    calling. This adapter does not authenticate a supplied digest on their behalf.
    Only bounded identity metadata is hashed, never the unchanged payload.
    """
    if (
        type(namespace) is not str
        or not 1 <= len(namespace) <= 128
        or type(size) is not int
        or size <= 0
    ):
        raise WorkloadQualificationPending("invalid_trusted_input_identity")
    raw = canonical_json_bytes(identity)
    if len(raw) > 8192:
        raise WorkloadQualificationPending("input_identity_metadata_exceeds_bound")
    return WorkloadInputIdentity(namespace, raw.decode("utf-8"), size, _ISSUER)


def selected_workload():
    return _selected.get()


@contextmanager
def workload_runtime(profile):
    previous = selected_workload()
    if profile is None:
        if previous is not None:
            raise WorkloadQualificationPending("nested_workload_selection_omitted")
        yield None
        return
    if previous is not None and (previous.sha256, previous.role) != (profile.sha256, profile.role):
        raise WorkloadQualificationPending("nested_workload_selection_changed")
    token = _selected.set(profile)
    try:
        yield profile
    finally:
        _selected.reset(token)


@contextmanager
def workload_input_budget():
    """Bound one complete graph operation, reusing native identities once."""
    profile = selected_workload()
    if profile is None or _budget.get() is not None:
        yield
        return
    token = _budget.set(
        dict(remaining=profile.bounds.maximum_json_values, seen={}, lock=threading.RLock())
    )
    try:
        yield
    finally:
        _budget.reset(token)


def check_workload_input(raw, kind="input", *, identity=None):
    profile = selected_workload()
    if profile is None:
        return None
    if kind not in {"input", "object", "declaration"}:
        raise WorkloadQualificationPending("unknown_input_kind")
    if type(raw) is not bytes or not 0 < len(raw) <= getattr(
        profile.bounds, "maximum_" + kind + "_bytes"
    ):
        raise WorkloadQualificationPending("input_byte_bound", kind=kind)
    expected = key = None
    if identity is not None:
        if (
            not isinstance(identity, WorkloadInputIdentity)
            or identity._issuer is not _ISSUER
            or identity.size != len(raw)
        ):
            raise WorkloadQualificationPending("untrusted_or_changed_input_identity", kind=kind)
        expected = dict(
            profile_sha256=profile.count_profile_sha256,
            semantics=_SEMANTICS,
            kind=kind,
            namespace=identity.namespace,
            identity=identity.identity,
            size=identity.size,
        )
        key = hashlib.sha256(canonical_json_bytes(expected)).hexdigest()
    budget = _budget.get()
    # ContextVars copy references into run_owned_thread, so the budget object is
    # shared. Hold its lock across read/scan/remember and the aggregate update.
    # Preparation worker count separately bounds simultaneously decoded copies;
    # identity reuse is not a live-memory reservation for those copies.
    with budget["lock"] if budget is not None else nullcontext():
        if budget is not None and key is not None and key in budget["seen"]:
            return budget["seen"][key]
        with profile.counts.serialized() if key is not None else nullcontext():
            values = None if key is None else profile.counts.read(key, expected)
            if values is None:
                failure = None
                try:
                    values = count_json_shape(raw, bounds=profile.bounds, kind=kind)
                except ValueError as error:
                    traceback.clear_frames(error.__traceback__)
                    failure = WorkloadQualificationPending("input_shape_bound", kind=kind)
                if failure is not None:
                    raise failure from None
                if key is not None:
                    profile.counts.remember(key, expected, values)
            if not 0 < values <= profile.bounds.maximum_json_values or (
                budget is not None and values > budget["remaining"]
            ):
                raise WorkloadQualificationPending("aggregate_value_bound", kind=kind)
            if budget is not None:
                budget["remaining"] -= values
                if key is not None:
                    budget["seen"][key] = values
            return values
