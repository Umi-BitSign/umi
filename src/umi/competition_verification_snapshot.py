"""Durable owner snapshots of already authenticated immutable package inputs.

The original published package stays untouched. Its actual file identity binds
an extracted native envelope and raw object files. Unchanged files need metadata
checks only; native semantic verdicts remain separate owner-private records.
"""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_aggregate_files import read_aggregate_model
from .competition_cohort_capacity import check_aggregate_evidence_bytes
from .competition_cohort_endpoint_archive import MAX_ARCHIVE_OBJECT_BYTES, read_endpoint_object
from .competition_cohort_object_codec import endpoint_object_bytes
from .competition_verification_reuse import (
    VerificationSourceChanged,
    _event,
    metadata_completion,
    read_verification_metadata,
    remember_metadata_completion,
)
from .competition_work_progress import WorkProgress, progress_items
from .host_memory_request_bounds import (
    check_stage_json,
    replay_stage_json_shape,
    stage_count,
    stage_limit,
    stage_shape_identity,
)
from .open_competition import digest
from .private_files import _read_bounded_private_bytes, ensure_private_directory, private_path
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()
_STORAGE_SEMANTICS = hashlib.sha256(b"umi-canonical-object-snapshot/1").hexdigest()
# Early owner snapshots used the native ABI as their storage identity. Their
# canonical bytes and descriptor contract are identical; migrate metadata only.
_EARLY_STORAGE_SEMANTICS = hashlib.sha256(b"umi-native-request-verification/1").hexdigest()
Stamp = tuple[str, ...]


def _stamp(path: Path, *, readonly=False) -> Stamp:
    private_path(str(path))
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
        or (readonly and info.st_mode & 0o222)
    ):
        raise VerificationSourceChanged("verification source has unsafe ownership or links")
    return tuple(
        str(n)
        for n in (
            info.st_dev,
            info.st_ino,
            info.st_uid,
            info.st_gid,
            info.st_mode,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    )


def _atomic(path, raw, *, readonly=False):
    ensure_private_directory(path.parent)
    fd, pending = tempfile.mkstemp(prefix=".verification-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            if readonly:
                os.fchmod(stream.fileno(), 0o400)
            os.fsync(stream.fileno())
        os.replace(pending, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(pending).unlink(missing_ok=True)


class _Checksummed(StrictProtocolModel):
    checksum: Hex32 = "0" * 64

    def sealed(self):
        value = self.model_dump(mode="json", by_alias=True, exclude={"checksum"})
        return self.model_copy(
            update={"checksum": hashlib.sha256(canonical_json_bytes(value)).hexdigest()}
        )

    def checked(self):
        if self.sealed().checksum != self.checksum:
            raise ValueError("verification metadata checksum differs")
        return self


class SnapshotObject(_Checksummed):
    key: Hex32
    sha256: Hex32
    size: Annotated[int, Field(gt=0)]
    stamp: Stamp
    shape_bounds: str
    shape_values: int | None


class PackageSnapshotRecord(_Checksummed):
    schema_: Literal["umi-private-verification-snapshot/1"] = Field(alias="schema")
    semantics: Hex32
    original_path: str
    original_stamp: Stamp
    package_sha256: Hex32
    envelope_json: str
    objects: tuple[SnapshotObject, ...]


class _ConsumedObjects(Mapping):
    def __init__(self, collector):
        self.collector = collector

    def __iter__(self):
        return iter(self.collector.consumed)

    def __len__(self):
        return len(self.collector.consumed)

    def __contains__(self, key):
        return key in self.collector.consumed

    def __getitem__(self, key):
        if key not in self.collector.consumed:
            raise KeyError(key)
        return self.collector(key)


class SnapshotCollector:
    """Count exact dependencies without reading already checked payloads."""

    def __init__(self, snapshot, maximum_bytes):
        self.snapshot = snapshot
        self.maximum_bytes = maximum_bytes
        self.consumed = set()
        self.used = 0
        self.values = _ConsumedObjects(self)

    def verification_identity(self, key):
        return self.snapshot.identity(key)

    def verification_sha256(self, key):
        return self.snapshot.records[key].sha256

    def verification_size(self, key):
        self.snapshot.identity(key)
        return self.snapshot.records[key].size

    def verification_replay(self, key):
        descriptor = self.snapshot.records[key]
        self.snapshot.identity(key)
        new = key not in self.consumed
        stage_count("maximum_objects", len(self.consumed) + int(new))
        if self.used + (descriptor.size if new else 0) > min(
            self.maximum_bytes, stage_limit("maximum_input_bytes", self.maximum_bytes)
        ):
            raise ValueError("reward package evidence exceeds its bound")
        # The collector can outlive one native operation. Shape accounting is
        # per operation and the helper deduplicates within that operation only.
        self.snapshot.charge_shape(key)
        if key not in self.consumed:
            self.used += descriptor.size
            self.consumed.add(key)

    def __call__(self, key):
        self.verification_replay(key)
        return self.snapshot.read(key)


@dataclass(frozen=True, init=False, eq=False)
class VerifiedPackageSnapshot:
    """Capability produced only by the local owning store's native import."""

    def __init__(self, store, record, package, *, issuer):
        if issuer is not _ISSUER:
            raise TypeError("verification snapshots require a native owning-store import")
        object.__setattr__(self, "store", store)
        object.__setattr__(self, "record", record)
        object.__setattr__(self, "package", package)
        object.__setattr__(self, "records", MappingProxyType({r.key: r for r in record.objects}))
        if len(self.records) != len(record.objects):
            raise ValueError("verification snapshot repeats an object")

    def __getattr__(self, name):
        # Expose native envelope fields only. A snapshot must never silently
        # serialize as its incomplete header through model_dump/model_copy.
        if name in type(self.package).model_fields and name != "objects":
            return getattr(self.package, name)
        raise AttributeError(name)

    @property
    def sha256(self):
        return self.record.package_sha256

    def check(self, package, expected_sha256, maximum_bytes):
        if (
            package is not self.package
            or canonical_json_bytes(package).decode() != self.record.envelope_json
            or expected_sha256 != self.sha256
            or int(self.record.original_stamp[6]) > maximum_bytes
            or _stamp(Path(self.record.original_path)) != self.record.original_stamp
        ):
            raise VerificationSourceChanged("verification snapshot changed its selected package")

    def identity(self, key):
        descriptor = self.records[key]
        path = self.store.object_path(key)
        try:
            current = _stamp(path, readonly=True)
        except (OSError, ValueError) as error:
            raise VerificationSourceChanged("verified object needs restoration") from error
        if current != descriptor.stamp:
            raise VerificationSourceChanged("verified object changed its immutable identity")
        return canonical_json_bytes([str(path), current]).decode()

    def read(self, key):
        before = self.identity(key)
        raw = _read_bounded_private_bytes(
            self.store.object_path(key), maximum_bytes=self.records[key].size
        )
        if self.identity(key) != before:
            raise VerificationSourceChanged("verified object changed while reading")
        return raw

    def charge_shape(self, key):
        descriptor = self.records[key]
        selected = stage_shape_identity()
        if descriptor.shape_bounds != selected:
            shape_path = self.store.objects / (key + "-shape-" + selected + ".json")
            try:
                retained = SnapshotObject.model_validate_json(
                    read_verification_metadata(shape_path)
                ).checked()
                if (
                    retained.key != key
                    or retained.sha256 != descriptor.sha256
                    or retained.size != descriptor.size
                    or retained.stamp != descriptor.stamp
                    or retained.shape_bounds != selected
                ):
                    raise ValueError("retained shape changed its source identity")
                descriptor = retained
            except (OSError, ValueError):
                values = check_stage_json(self.read(key), kind="object")
                descriptor = descriptor.model_copy(
                    update={"shape_bounds": selected, "shape_values": values}
                ).sealed()
                _atomic(shape_path, canonical_json_bytes(descriptor))
        if not replay_stage_json_shape(
            byte_sha256=descriptor.sha256,
            size=descriptor.size,
            values=descriptor.shape_values,
            bounds_sha256=descriptor.shape_bounds,
            maximum_bytes=MAX_ARCHIVE_OBJECT_BYTES,
        ):
            raise VerificationSourceChanged("shape context changed during verification")

    def collector(self, maximum_bytes):
        return SnapshotCollector(self, maximum_bytes)


class VerificationPackageStore:
    def __init__(self, directory: Path):
        ensure_private_directory(directory)
        self.directory = directory
        self.objects = directory / "objects"
        ensure_private_directory(self.objects)

    def object_path(self, key):
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid verification object identity")
        return self.objects / (key + ".bin")

    def load(self, path: Path, model, *, maximum_bytes, expected_sha256=None):
        check_aggregate_evidence_bytes(maximum_bytes)
        current = _stamp(path)
        if int(current[6]) > maximum_bytes:
            raise ValueError("package exceeds its selected native byte bound")
        key = hashlib.sha256(canonical_json_bytes([str(path), current])).hexdigest()
        metadata = self.directory / (key + ".json")
        try:
            raw = read_verification_metadata(metadata)
            record = PackageSnapshotRecord.model_validate_json(raw).checked()
            if (
                record.semantics not in {_STORAGE_SEMANTICS, _EARLY_STORAGE_SEMANTICS}
                or record.original_path != str(path)
                or record.original_stamp != current
            ):
                raise VerificationSourceChanged("verification snapshot identity changed")
            package = model.model_validate_json(record.envelope_json)
            snapshot = VerifiedPackageSnapshot(self, record, package, issuer=_ISSUER)
            if expected_sha256 is not None and snapshot.sha256 != expected_sha256:
                raise ValueError("verified package differs from independently selected identity")
            with WorkProgress(
                "verification_snapshot_identity", len(record.objects), unit="objects"
            ) as progress:
                for item in record.objects:
                    snapshot.identity(item.key)
                    progress.advance()
        except FileNotFoundError:
            _event(
                "verification_snapshot",
                "repair_required" if metadata_completion(metadata).exists() else "miss",
            )
        except (OSError, ValueError):
            _event("verification_snapshot", "repair_required")
        else:
            if record.semantics == _EARLY_STORAGE_SEMANTICS:
                record = record.model_copy(update={"semantics": _STORAGE_SEMANTICS}).sealed()
                _atomic(metadata, canonical_json_bytes(record))
                snapshot = VerifiedPackageSnapshot(self, record, package, issuer=_ISSUER)
                _event("verification_snapshot", "metadata_migrated")
            remember_metadata_completion(metadata)
            _event("verification_snapshot", "hit", len(record.objects))
            return snapshot
        preparation_started = time.monotonic()
        _event(
            "verification_snapshot_prepare",
            "started",
            planning_range=[
                round(int(current[6]) / (10 * 1024**2), 1),
                round(int(current[6]) / 1024**2, 1),
            ],
        )
        with WorkProgress(
            "verification_snapshot_prepare", 2, unit="steps", estimate=False
        ) as progress:
            package = read_aggregate_model(path, model, maximum_bytes=maximum_bytes)
            progress.advance()
            package_sha = digest(package)
            progress.advance()
        _event(
            "verification_snapshot_prepare",
            "retained",
            elapsed=time.monotonic() - preparation_started,
        )
        if expected_sha256 is not None and package_sha != expected_sha256:
            raise ValueError("package differs from independently selected identity")
        records = []
        for item in progress_items(
            package.objects, stage="verification_snapshot_import", unit="objects"
        ):
            raw = endpoint_object_bytes(item.value, item.sha256)
            destination = self.object_path(item.sha256)
            # Imported originals are immutable. Existing trusted contents are
            # reused only through their retained descriptor, never the filename.
            descriptor_path = self.objects / (item.sha256 + ".json")
            try:
                prior = SnapshotObject.model_validate_json(
                    read_verification_metadata(descriptor_path)
                ).checked()
                unchanged = (
                    prior.key == item.sha256
                    and prior.sha256 == hashlib.sha256(raw).hexdigest()
                    and prior.stamp == _stamp(destination, readonly=True)
                )
            except (OSError, ValueError):
                unchanged = False
            if unchanged and prior.shape_bounds == stage_shape_identity():
                records.append(prior)
                continue
            if not unchanged:
                read_endpoint_object(lambda _, data=raw: data, item.sha256)
                _atomic(destination, raw, readonly=True)
            shape = check_stage_json(raw, kind="object")
            records.append(
                SnapshotObject(
                    key=item.sha256,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    size=len(raw),
                    stamp=_stamp(destination, readonly=True),
                    shape_bounds=stage_shape_identity(),
                    shape_values=shape,
                ).sealed()
            )
            _atomic(descriptor_path, canonical_json_bytes(records[-1]))
        if _stamp(path) != current:
            raise VerificationSourceChanged("package changed during native snapshot import")
        envelope = package.model_copy(update={"objects": ()})
        record = PackageSnapshotRecord(
            schema="umi-private-verification-snapshot/1",
            semantics=_STORAGE_SEMANTICS,
            original_path=str(path),
            original_stamp=current,
            package_sha256=package_sha,
            envelope_json=canonical_json_bytes(envelope).decode(),
            objects=tuple(records),
        ).sealed()
        raw = canonical_json_bytes(record)
        _atomic(metadata, raw)
        remember_metadata_completion(metadata)
        return VerifiedPackageSnapshot(self, record, envelope, issuer=_ISSUER)


def verified_package_digest(package):
    if type(package) is VerifiedPackageSnapshot:
        package.check(package.package, package.sha256, int(package.record.original_stamp[6]))
        return package.sha256
    return digest(package)
