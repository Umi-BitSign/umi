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
from typing import Annotated, Literal, get_args

from pydantic import Field

from .canonical_aggregate import _parts
from .competition_aggregate_replica_binding import VerifiedAggregateReplica
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
from .private_files import (
    PrivateStateBusyError,
    _read_bounded_private_bytes,
    ensure_private_directory,
    lock_private_file,
    private_path,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_ISSUER = object()
_STORAGE_SEMANTICS = hashlib.sha256(b"umi-canonical-object-snapshot/1").hexdigest()
# Early owner snapshots used the native ABI as their storage identity. Their
# canonical bytes and descriptor contract are identical; migrate metadata only.
_EARLY_STORAGE_SEMANTICS = hashlib.sha256(b"umi-native-request-verification/1").hexdigest()
Stamp = tuple[str, ...]


class VerificationSnapshotUnavailable(VerificationSourceChanged):
    """The consumer needs an explicit first import of its selected original."""


class VerificationSnapshotRepairRequired(VerificationSourceChanged):
    """A retained snapshot needs explicit repair, never a hidden full import."""


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
    return _info_stamp(info)


def _info_stamp(info):
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


class SnapshotSelection(_Checksummed):
    """A path binding survives replacement of the selected file's inode."""

    schema_: Literal["umi-private-verification-selection/1"] = Field(alias="schema")
    original_path: str
    original_stamp: Stamp
    metadata_key: Hex32
    package_sha256: Hex32 | None = None
    state: Literal["preparing", "complete"]
    repair_reason: str | None = None


class SnapshotInput(StrictProtocolModel):
    key: Hex32
    offset: Annotated[int, Field(ge=0)]
    size: Annotated[int, Field(gt=0)]


class SnapshotPreparation(_Checksummed):
    """Completed native decoding, with exact original slices for remaining items."""

    schema_: Literal["umi-private-verification-preparation/1"] = Field(alias="schema")
    semantics: Hex32
    original_path: str
    original_stamp: Stamp
    package_sha256: Hex32
    envelope_json: str
    inputs: tuple[SnapshotInput, ...]


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

    def original_identity(self, *, maximum_bytes=None):
        """Return the selected source stamp only after checking this capability."""
        maximum = int(self.record.original_stamp[6]) if maximum_bytes is None else maximum_bytes
        self.check(self.package, self.sha256, maximum)
        return Path(self.record.original_path), self.record.original_stamp

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
            except FileNotFoundError:
                if metadata_completion(shape_path).exists():
                    raise VerificationSnapshotRepairRequired(
                        "completed shape verification needs repair"
                    ) from None
                values = check_stage_json(self.read(key), kind="object")
                descriptor = descriptor.model_copy(
                    update={"shape_bounds": selected, "shape_values": values}
                ).sealed()
                _atomic(shape_path, canonical_json_bytes(descriptor))
                remember_metadata_completion(shape_path)
            except (OSError, ValueError) as error:
                raise VerificationSnapshotRepairRequired(
                    "retained shape verification needs repair"
                ) from error
            else:
                remember_metadata_completion(shape_path)
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
        self.selections = directory / "selections"
        self.preparations = directory / "preparations"
        self.identities = directory / "identities"
        for child in (self.objects, self.selections, self.preparations, self.identities):
            ensure_private_directory(child)

    def object_path(self, key):
        if len(key) != 64 or any(c not in "0123456789abcdef" for c in key):
            raise ValueError("invalid verification object identity")
        return self.objects / (key + ".bin")

    def selection_path(self, path):
        """Stable owner binding; unlike snapshot filenames this excludes the inode."""
        key = hashlib.sha256(str(path).encode()).hexdigest()
        return self.selections / (key + ".json")

    def package_identity_path(self, path, sha256):
        # A genuine first copy of identical bytes has a different source path.
        # Preserve missing-binding detection for this exact source/package pair.
        key = hashlib.sha256(canonical_json_bytes([str(path), sha256])).hexdigest()
        return self.identities / (key + ".json")

    def _paths(self, path, current):
        key = hashlib.sha256(canonical_json_bytes([str(path), current])).hexdigest()
        return self.directory / (key + ".json"), self.preparations / (key + ".json")

    def _legacy_candidates(self, path):
        # A healthy stable binding identifies metadata belonging to another
        # original even if that original's derived metadata is damaged. Do not
        # let that damage block a genuinely new cohort. Ambiguous legacy state
        # still needs explicit repair; no corrupt record becomes a cache miss.
        unrelated = set()
        for selected in self.selections.glob("*.json"):
            try:
                value = SnapshotSelection.model_validate_json(
                    read_verification_metadata(selected)
                ).checked()
                original = Path(value.original_path)
                expected_metadata, _ = self._paths(original, value.original_stamp)
                if (
                    original != path
                    and selected == self.selection_path(original)
                    and value.metadata_key == expected_metadata.stem
                ):
                    unrelated.add(expected_metadata.name)
            except (OSError, ValueError):
                continue
        return tuple(item for item in self.directory.glob("*.json") if item.name not in unrelated)

    def _selection(self, path, current, metadata, expected):
        selected = self.selection_path(path)
        try:
            value = SnapshotSelection.model_validate_json(
                read_verification_metadata(selected)
            ).checked()
        except FileNotFoundError:
            if metadata_completion(selected).exists():
                raise VerificationSnapshotRepairRequired(
                    "completed source binding is missing"
                ) from None
            value = None
        if value is not None:
            if (
                value.original_path != str(path)
                or value.original_stamp != current
                or value.metadata_key != metadata.stem
                or (expected is not None and value.package_sha256 not in (None, expected))
            ):
                raise VerificationSnapshotRepairRequired("selected immutable source changed")
            return value
        # Older supported stores predate stable source bindings. Recover that
        # binding from retained metadata, without opening any original payload.
        candidates = (metadata,) if metadata.exists() else self._legacy_candidates(path)
        for candidate in candidates:
            old = PackageSnapshotRecord.model_validate_json(
                read_verification_metadata(candidate)
            ).checked()
            if old.original_path != str(path):
                continue
            if old.original_stamp != current or candidate != metadata:
                raise VerificationSnapshotRepairRequired("legacy selected source changed")
            return SnapshotSelection(
                schema="umi-private-verification-selection/1",
                original_path=str(path),
                original_stamp=current,
                metadata_key=metadata.stem,
                package_sha256=old.package_sha256,
                state="complete",
            ).sealed()
        if metadata_completion(metadata).exists() or (
            expected is not None
            and metadata_completion(self.package_identity_path(path, expected)).exists()
        ):
            raise VerificationSnapshotRepairRequired("completed package binding is missing")
        return None

    def _remember_selection(self, path, selection):
        target = self.selection_path(path)
        raw = canonical_json_bytes(selection.sealed())
        try:
            unchanged = read_verification_metadata(target) == raw
        except (OSError, ValueError):
            unchanged = False
        if not unchanged:
            _atomic(target, raw)
        # Once begun, losing this binding is damage, even during the first pass.
        remember_metadata_completion(target)
        if selection.state == "complete":
            identity = self.package_identity_path(path, selection.package_sha256)
            remember_metadata_completion(identity)

    def _snapshot(self, metadata, path, current, model, expected):
        record = PackageSnapshotRecord.model_validate_json(
            read_verification_metadata(metadata)
        ).checked()
        if (
            record.semantics not in {_STORAGE_SEMANTICS, _EARLY_STORAGE_SEMANTICS}
            or record.original_path != str(path)
            or record.original_stamp != current
            or (expected is not None and record.package_sha256 != expected)
        ):
            raise VerificationSnapshotRepairRequired("verification snapshot identity changed")
        package = model.model_validate_json(record.envelope_json)
        snapshot = VerifiedPackageSnapshot(self, record, package, issuer=_ISSUER)
        with WorkProgress(
            "verification_snapshot_identity", len(record.objects), unit="objects"
        ) as p:
            for item in record.objects:
                snapshot.identity(item.key)
                p.advance()
        if record.semantics == _EARLY_STORAGE_SEMANTICS:
            record = record.model_copy(update={"semantics": _STORAGE_SEMANTICS}).sealed()
            _atomic(metadata, canonical_json_bytes(record))
            snapshot = VerifiedPackageSnapshot(self, record, package, issuer=_ISSUER)
            _event("verification_snapshot", "metadata_migrated")
        remember_metadata_completion(metadata)
        return snapshot

    def load_existing(self, path: Path, model, *, maximum_bytes, expected_sha256=None):
        """Load retained results only; first preparation is explicitly unavailable."""
        return self.load(
            path,
            model,
            maximum_bytes=maximum_bytes,
            expected_sha256=expected_sha256,
            existing_only=True,
        )

    def load(self, path: Path, model, *, maximum_bytes, expected_sha256=None, existing_only=False):
        """Prepare a genuine first selection, or reuse its completed import.

        A begun import resumes its per-object checkpoints. Missing/damaged
        completed records and changed source identities require ``repair``;
        periodic consumers never turn those conditions into a full import.
        """
        lock = lock_private_file(self.selection_path(path).with_suffix(".lock"))
        try:
            return self._load(path, model, maximum_bytes, expected_sha256, existing_only)
        finally:
            os.close(lock)

    def _load(self, path, model, maximum_bytes, expected, existing_only):
        check_aggregate_evidence_bytes(maximum_bytes)
        try:
            current = _stamp(path)
        except FileNotFoundError as error:
            selected = self.selection_path(path)
            known_source = selected.exists() or metadata_completion(selected).exists()
            if expected is not None:
                known_source = (
                    known_source
                    or metadata_completion(self.package_identity_path(path, expected)).exists()
                )
            if not known_source:
                # Supported legacy stores did not yet have a path index.
                # Their small metadata is sufficient to distinguish restoration
                # from first delivery without opening any package payload.
                try:
                    for candidate in self._legacy_candidates(path):
                        prior = PackageSnapshotRecord.model_validate_json(
                            read_verification_metadata(candidate)
                        ).checked()
                        if prior.original_path == str(path):
                            known_source = True
                            break
                except (OSError, ValueError) as damaged:
                    _event("verification_snapshot", "repair_required")
                    raise VerificationSnapshotRepairRequired(
                        "legacy original selection metadata needs repair"
                    ) from damaged
            if known_source:
                _event("verification_snapshot", "repair_required")
                raise VerificationSnapshotRepairRequired(
                    "previously selected original package needs restoration"
                ) from error
            raise
        if int(current[6]) > maximum_bytes:
            raise ValueError("package exceeds its selected native byte bound")
        metadata, preparation = self._paths(path, current)
        try:
            selection = self._selection(path, current, metadata, expected)
            if expected is None and selection is not None:
                expected = selection.package_sha256
            if (
                selection is not None
                and selection.state == "preparing"
                and selection.repair_reason is not None
                and not existing_only
            ):
                return self._prepare(
                    path,
                    model,
                    maximum_bytes,
                    expected,
                    current,
                    metadata,
                    preparation,
                    selection,
                    repair=True,
                )
            if metadata.exists():
                snapshot = self._snapshot(metadata, path, current, model, expected)
                selection = SnapshotSelection(
                    schema="umi-private-verification-selection/1",
                    original_path=str(path),
                    original_stamp=current,
                    metadata_key=metadata.stem,
                    package_sha256=snapshot.sha256,
                    state="complete",
                    repair_reason=None if selection is None else selection.repair_reason,
                )
                self._remember_selection(path, selection)
                _event("verification_snapshot", "hit", len(snapshot.records))
                return snapshot
            if selection is not None and selection.state == "complete":
                raise VerificationSnapshotRepairRequired("completed snapshot metadata is missing")
            if existing_only:
                _event("verification_snapshot", "preparation_required")
                raise VerificationSnapshotUnavailable("selected package needs first preparation")
            if selection is None:
                selection = SnapshotSelection(
                    schema="umi-private-verification-selection/1",
                    original_path=str(path),
                    original_stamp=current,
                    metadata_key=metadata.stem,
                    package_sha256=expected,
                    state="preparing",
                )
                self._remember_selection(path, selection)
            return self._prepare(
                path,
                model,
                maximum_bytes,
                expected,
                current,
                metadata,
                preparation,
                selection,
                repair=False,
            )
        except (VerificationSnapshotUnavailable, InterruptedError):
            raise
        except PrivateStateBusyError:
            _event("verification_snapshot", "retrying")
            raise
        except (OSError, ValueError) as error:
            _event("verification_snapshot", "repair_required")
            if isinstance(error, VerificationSnapshotRepairRequired):
                raise
            raise VerificationSnapshotRepairRequired(
                "retained package state requires explicit repair"
            ) from error

    def _repair_expected(self, path, current):
        """Recover the prior selected digest, never infer it from replacement bytes."""
        selected = self.selection_path(path)
        try:
            prior = SnapshotSelection.model_validate_json(
                read_verification_metadata(selected)
            ).checked()
            original = Path(prior.original_path)
            expected_metadata, _ = self._paths(original, prior.original_stamp)
            if original != path or prior.metadata_key != expected_metadata.stem:
                raise ValueError("repair source binding changed its original")
        except (OSError, ValueError):
            prior = None
        if prior is not None and prior.package_sha256 is not None:
            return prior.package_sha256
        identities = set()
        for directory, record_model in (
            (self.directory, PackageSnapshotRecord),
            (self.preparations, SnapshotPreparation),
        ):
            for candidate in directory.glob("*.json"):
                try:
                    record = record_model.model_validate_json(
                        read_verification_metadata(candidate)
                    ).checked()
                    if record.original_path != str(path) or record.semantics not in {
                        _STORAGE_SEMANTICS,
                        _EARLY_STORAGE_SEMANTICS,
                    }:
                        continue
                    metadata, preparation = self._paths(path, record.original_stamp)
                    if candidate != (
                        metadata if record_model is PackageSnapshotRecord else preparation
                    ):
                        continue
                    identities.add(record.package_sha256)
                except (OSError, ValueError):
                    # These records are being explicitly repaired. A separate
                    # surviving native binding can still recover their identity.
                    continue
        if len(identities) == 1:
            return identities.pop()
        if (
            not identities
            and prior is not None
            and prior.state == "preparing"
            and prior.original_stamp == current
        ):
            # The exact first import was interrupted before a digest existed.
            # Its original immutable source binding is still healthy and exact.
            return None
        _event("verification_snapshot_repair", "repair_required")
        raise VerificationSnapshotRepairRequired(
            "repair needs an independently selected digest; prior identity is lost or ambiguous"
        )

    def repair(self, path: Path, model, *, maximum_bytes, expected_sha256=None, reason):
        """Explicitly repair owner-derived state, preserving signed source bytes.

        A surviving preparation restores only damaged objects from their exact
        source slices. Legacy or lost preparation needs one visible native pass.
        The operator's reason remains attached across interruption and restart.
        """
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("snapshot repair requires a nonempty reason")
        lock = lock_private_file(self.selection_path(path).with_suffix(".lock"))
        try:
            check_aggregate_evidence_bytes(maximum_bytes)
            current = _stamp(path)
            if int(current[6]) > maximum_bytes:
                raise ValueError("package exceeds its selected native byte bound")
            metadata, preparation = self._paths(path, current)
            expected = expected_sha256
            if expected is None:
                expected = self._repair_expected(path, current)
            selection = SnapshotSelection(
                schema="umi-private-verification-selection/1",
                original_path=str(path),
                original_stamp=current,
                metadata_key=metadata.stem,
                package_sha256=expected,
                state="preparing",
                repair_reason=reason,
            )
            self._remember_selection(path, selection)
            _event("verification_snapshot_repair", "started")
            return self._prepare(
                path,
                model,
                maximum_bytes,
                expected,
                current,
                metadata,
                preparation,
                selection,
                repair=True,
            )
        finally:
            os.close(lock)

    def bind_replica(self, snapshot, binding, *, maximum_bytes):
        """Attach a native snapshot to an independently byte-checked replica.

        This grants no semantic authority. Object transfer uses the original
        opaque snapshot; a matching shared store requires metadata checks only.
        """
        if (
            type(snapshot) is not VerifiedPackageSnapshot
            or type(binding) is not VerifiedAggregateReplica
        ):
            raise TypeError("snapshot replica binding requires native capabilities")
        snapshot.original_identity(maximum_bytes=maximum_bytes)
        path, current = binding.check(snapshot.sha256, maximum_bytes)
        lock = lock_private_file(self.selection_path(path).with_suffix(".lock"))
        try:
            metadata, preparation = self._paths(path, current)
            if metadata.exists() or self.selection_path(path).exists():
                return self._load(
                    path, type(snapshot.package), maximum_bytes, snapshot.sha256, True
                )
            if (
                metadata_completion(metadata).exists()
                or metadata_completion(self.selection_path(path)).exists()
            ):
                raise VerificationSnapshotRepairRequired("replica snapshot binding needs repair")
            records = []
            with WorkProgress(
                "verification_snapshot_bind_replica", len(snapshot.records), unit="objects"
            ) as p:
                for item in snapshot.record.objects:
                    object_lock = lock_private_file(self.objects / (item.key + ".lock"))
                    try:
                        snapshot.identity(item.key)
                        destination = self.object_path(item.key)
                        if destination == snapshot.store.object_path(item.key):
                            retained = item
                        else:
                            descriptor_path = self.objects / (item.key + ".json")
                            try:
                                retained = SnapshotObject.model_validate_json(
                                    read_verification_metadata(descriptor_path)
                                ).checked()
                                if (
                                    retained.key != item.key
                                    or retained.sha256 != item.sha256
                                    or retained.stamp != _stamp(destination, readonly=True)
                                ):
                                    raise ValueError(
                                        "replica object differs from verified original"
                                    )
                            except FileNotFoundError:
                                if metadata_completion(descriptor_path).exists():
                                    raise VerificationSnapshotRepairRequired(
                                        "replica object needs repair"
                                    ) from None
                                raw = snapshot.read(item.key)
                                _atomic(destination, raw, readonly=True)
                                retained = item.model_copy(
                                    update={"stamp": _stamp(destination, readonly=True)}
                                ).sealed()
                                _atomic(descriptor_path, canonical_json_bytes(retained))
                                remember_metadata_completion(descriptor_path)
                        records.append(retained)
                        p.advance()
                    finally:
                        os.close(object_lock)
            snapshot.original_identity(maximum_bytes=maximum_bytes)
            if binding.check(snapshot.sha256, maximum_bytes) != (path, current):
                raise VerificationSourceChanged("replica changed while binding snapshot")
            # Exact copied aggregate bytes preserve per-object slice offsets.
            source_preparation = snapshot.store._paths(
                Path(snapshot.record.original_path), snapshot.record.original_stamp
            )[1]
            try:
                prepared = SnapshotPreparation.model_validate_json(
                    read_verification_metadata(source_preparation)
                ).checked()
                if (
                    prepared.original_path != snapshot.record.original_path
                    or prepared.original_stamp != snapshot.record.original_stamp
                    or prepared.package_sha256 != snapshot.sha256
                ):
                    raise ValueError("replica preparation differs from native source")
            except FileNotFoundError:
                if metadata_completion(source_preparation).exists():
                    raise VerificationSnapshotRepairRequired(
                        "replica source preparation needs repair"
                    ) from None
                # Supported legacy snapshots have no preparation; their current
                # complete object descriptors still bind unchanged exact bytes.
            else:
                prepared = prepared.model_copy(
                    update={"original_path": str(path), "original_stamp": current}
                ).sealed()
                _atomic(preparation, canonical_json_bytes(prepared))
                remember_metadata_completion(preparation)
            record = snapshot.record.model_copy(
                update={
                    "original_path": str(path),
                    "original_stamp": current,
                    "objects": tuple(records),
                }
            ).sealed()
            bound = VerifiedPackageSnapshot(self, record, snapshot.package, issuer=_ISSUER)
            _atomic(metadata, canonical_json_bytes(record))
            remember_metadata_completion(metadata)
            self._remember_selection(
                path,
                SnapshotSelection(
                    schema="umi-private-verification-selection/1",
                    original_path=str(path),
                    original_stamp=current,
                    metadata_key=metadata.stem,
                    package_sha256=snapshot.sha256,
                    state="complete",
                ),
            )
            _event("verification_snapshot_bind_replica", "retained", len(records))
            return bound
        finally:
            os.close(lock)

    def _decode(self, path, model, maximum_bytes, current):
        started = time.monotonic()
        _event(
            "verification_snapshot_prepare",
            "started",
            planning_range=[
                round(int(current[6]) / (10 * 1024**2), 1),
                round(int(current[6]) / 1024**2, 1),
            ],
        )
        with WorkProgress("verification_snapshot_prepare", 2, unit="steps", estimate=False) as p:
            package = read_aggregate_model(path, model, maximum_bytes=maximum_bytes)
            p.advance()
            # Native canonical aggregate serialization gives exact slice offsets.
            # This completed preparation survives interruption of later objects.
            parts = _parts(package)
            if (
                "objects" not in parts
                or parts["objects"][1] is None
                or model.model_fields["objects"].serialization_alias not in (None, "objects")
            ):
                raise ValueError("snapshot requires a plain native object inventory")
            values, adapter = parts["objects"]
            metadata = package.model_dump(mode="json", by_alias=True, exclude={"objects"})
            sha, offset, inputs = hashlib.sha256(b"umi-open-competition-v1\0"), 0, []

            def emit(raw):
                nonlocal offset
                sha.update(raw)
                offset += len(raw)

            emit(b"{")
            for index, key in enumerate(
                sorted(metadata.keys() | {"objects"}, key=lambda k: k.encode("utf-16be"))
            ):
                if index:
                    emit(b",")
                emit(canonical_json_bytes(key) + b":")
                if key != "objects":
                    emit(canonical_json_bytes(metadata[key]))
                    continue
                emit(b"[")
                for position, item in enumerate(values):
                    if position:
                        emit(b",")
                    raw = canonical_json_bytes(
                        adapter.dump_python(item, mode="json", by_alias=True)
                    )
                    inputs.append(SnapshotInput(key=item.sha256, offset=offset, size=len(raw)))
                    emit(raw)
                emit(b"]")
            emit(b"}")
            if offset != int(current[6]) or _stamp(path) != current:
                raise VerificationSourceChanged("package changed during native preparation")
            envelope = package.model_copy(update={"objects": ()})
            prepared = SnapshotPreparation(
                schema="umi-private-verification-preparation/1",
                semantics=_STORAGE_SEMANTICS,
                original_path=str(path),
                original_stamp=current,
                package_sha256=sha.hexdigest(),
                envelope_json=canonical_json_bytes(envelope).decode(),
                inputs=tuple(inputs),
            ).sealed()
            p.advance()
        _event("verification_snapshot_prepare", "retained", elapsed=time.monotonic() - started)
        return prepared, package

    def _prepare(
        self,
        path,
        model,
        maximum_bytes,
        expected,
        current,
        metadata,
        preparation,
        selection,
        *,
        repair,
    ):
        package = None
        try:
            prepared = SnapshotPreparation.model_validate_json(
                read_verification_metadata(preparation)
            ).checked()
            if (
                prepared.semantics != _STORAGE_SEMANTICS
                or prepared.original_path != str(path)
                or prepared.original_stamp != current
            ):
                raise ValueError("package preparation identity changed")
        except (OSError, ValueError) as error:
            if not repair and (preparation.exists() or metadata_completion(preparation).exists()):
                raise VerificationSnapshotRepairRequired(
                    "completed preparation needs repair"
                ) from error
            prepared, package = self._decode(path, model, maximum_bytes, current)
            if expected is not None and prepared.package_sha256 != expected:
                raise ValueError("package differs from independently selected identity") from None
            _atomic(preparation, canonical_json_bytes(prepared))
            remember_metadata_completion(preparation)
        else:
            _event("verification_snapshot_prepare", "hit", len(prepared.inputs))
        if expected is not None and prepared.package_sha256 != expected:
            raise ValueError("prepared package differs from independently selected identity")
        envelope = model.model_validate_json(prepared.envelope_json)
        item_model = get_args(model.model_fields["objects"].annotation)[0]
        records = []
        for index, item in enumerate(
            progress_items(prepared.inputs, stage="verification_snapshot_import", unit="objects")
        ):
            object_lock = lock_private_file(self.objects / (item.key + ".lock"))
            try:
                descriptor_path = self.objects / (item.key + ".json")
                destination = self.object_path(item.key)
                prior = None
                try:
                    prior = SnapshotObject.model_validate_json(
                        read_verification_metadata(descriptor_path)
                    ).checked()
                    if prior.key != item.key or prior.stamp != _stamp(destination, readonly=True):
                        raise ValueError("verified object identity changed")
                except (OSError, ValueError) as error:
                    if not repair and (
                        descriptor_path.exists() or metadata_completion(descriptor_path).exists()
                    ):
                        raise VerificationSnapshotRepairRequired(
                            "completed object needs repair"
                        ) from error
                    prior = None
                if prior is not None and prior.shape_bounds == stage_shape_identity():
                    if repair:
                        shape_path = self.objects / (
                            item.key + "-shape-" + prior.shape_bounds + ".json"
                        )
                        _atomic(shape_path, canonical_json_bytes(prior))
                        remember_metadata_completion(shape_path)
                    records.append(prior)
                    continue
                if prior is not None:
                    shape_path = self.objects / (
                        item.key + "-shape-" + stage_shape_identity() + ".json"
                    )
                    try:
                        shaped = SnapshotObject.model_validate_json(
                            read_verification_metadata(shape_path)
                        ).checked()
                        if (
                            shaped.key != prior.key
                            or shaped.sha256 != prior.sha256
                            or shaped.size != prior.size
                            or shaped.stamp != prior.stamp
                            or shaped.shape_bounds != stage_shape_identity()
                        ):
                            raise ValueError("retained shape changed its original identity")
                    except (OSError, ValueError) as error:
                        if not repair and (
                            shape_path.exists() or metadata_completion(shape_path).exists()
                        ):
                            raise VerificationSnapshotRepairRequired(
                                "completed shape needs repair"
                            ) from error
                    else:
                        records.append(shaped)
                        continue
                    raw = _read_bounded_private_bytes(destination, maximum_bytes=prior.size)
                    if _stamp(destination, readonly=True) != prior.stamp:
                        raise VerificationSourceChanged("object changed during shape verification")
                else:
                    if package is not None:
                        member = package.objects[index]
                    else:
                        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
                        with os.fdopen(descriptor, "rb") as source:
                            if _info_stamp(os.fstat(source.fileno())) != current:
                                raise VerificationSourceChanged(
                                    "restoration opened a changed source"
                                )
                            source.seek(item.offset)
                            member_raw = source.read(item.size)
                            if _info_stamp(os.fstat(source.fileno())) != current:
                                raise VerificationSourceChanged(
                                    "source changed while restoring object"
                                )
                        if len(member_raw) != item.size or _stamp(path) != current:
                            raise VerificationSourceChanged(
                                "source changed during object restoration"
                            )
                        member = item_model.model_validate_json(member_raw)
                    if member.sha256 != item.key:
                        raise VerificationSourceChanged(
                            "prepared object changed its selected identity"
                        )
                    raw = endpoint_object_bytes(member.value, member.sha256)
                    read_endpoint_object(lambda _, data=raw: data, item.key)
                    _atomic(destination, raw, readonly=True)
                shape = check_stage_json(raw, kind="object")
                retained = SnapshotObject(
                    key=item.key,
                    sha256=prior.sha256 if prior is not None else hashlib.sha256(raw).hexdigest(),
                    size=len(raw),
                    stamp=_stamp(destination, readonly=True),
                    shape_bounds=stage_shape_identity(),
                    shape_values=shape,
                ).sealed()
                _atomic(descriptor_path, canonical_json_bytes(retained))
                remember_metadata_completion(descriptor_path)
                if repair or prior is not None:
                    # Previously issued snapshots can retain another shape in
                    # their primary descriptor; repair their shared secondary
                    # receipt as well as this import's primary descriptor.
                    shape_path = self.objects / (
                        item.key + "-shape-" + retained.shape_bounds + ".json"
                    )
                    _atomic(shape_path, canonical_json_bytes(retained))
                    remember_metadata_completion(shape_path)
                records.append(retained)
            finally:
                os.close(object_lock)
        if _stamp(path) != current:
            raise VerificationSourceChanged("package changed during native snapshot import")
        record = PackageSnapshotRecord(
            schema="umi-private-verification-snapshot/1",
            semantics=_STORAGE_SEMANTICS,
            original_path=str(path),
            original_stamp=current,
            package_sha256=prepared.package_sha256,
            envelope_json=prepared.envelope_json,
            objects=tuple(records),
        ).sealed()
        snapshot = VerifiedPackageSnapshot(self, record, envelope, issuer=_ISSUER)
        _atomic(metadata, canonical_json_bytes(record))
        remember_metadata_completion(metadata)
        self._remember_selection(
            path,
            selection.model_copy(
                update={"state": "complete", "package_sha256": record.package_sha256}
            ),
        )
        _event("verification_snapshot", "retained", len(records))
        return snapshot


def verified_package_digest(package):
    if type(package) is VerifiedPackageSnapshot:
        package.check(package.package, package.sha256, int(package.record.original_stamp[6]))
        return package.sha256
    return digest(package)
