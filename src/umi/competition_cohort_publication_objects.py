"""Journal-authenticated immutable settlement exports and durable object checkpoints.

The original journal remains authoritative. Its content-addressed object is
authenticated once before export; private descriptors bind that exact export's
file identity. Fresh journal conflict fences remain mandatory on every reuse.
No payload copy or journal schema migration is needed for historical exports.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os

from .competition_cohort_endpoint_archive import MAX_ARCHIVE_OBJECT_BYTES, read_endpoint_object
from .competition_cohort_reward_package import RewardPackageObject
from .competition_verification_reuse import (
    VerificationSourceChanged,
    _event,
    metadata_completion,
    read_verification_metadata,
    remember_metadata_completion,
)
from .competition_verification_snapshot import SnapshotObject, _atomic, _stamp
from .competition_work_progress import WorkProgress, check_work_cancelled
from .host_memory_request_bounds import (
    check_stage_json,
    replay_stage_json_shape,
    stage_shape_identity,
)
from .private_files import ensure_private_directory, lock_private_file
from .protocol import canonical_json_bytes


class PublicationObjects:
    def __init__(self, source, files, directory):
        self.source, self.files, self.directory = source, files, directory
        ensure_private_directory(directory)
        with source.journal.read_transaction() as db:
            self.binding = source.journal._binding(db)
        self.owner = hashlib.sha256(canonical_json_bytes(self.binding)).hexdigest()
        self.directory = directory / self.owner
        ensure_private_directory(self.directory)

    def _fence(self, key):
        check_work_cancelled()
        # Check the native immutable-record owner and fresh conflict fence, not
        # row numbers, SQLite mtimes or an unauthenticated caller-provided hash.
        with self.source.journal.read_transaction() as db:
            if self.source.journal._binding(db) != self.binding:
                raise VerificationSourceChanged("publication journal owner changed")
            if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                raise VerificationSourceChanged("publication journal conflict held")
            if not db.execute(
                "SELECT 1 FROM records WHERE kind=? AND id=?", ("endpoint_replay_object", key)
            ).fetchone():
                raise VerificationSourceChanged("publication journal original is missing")

    def _descriptor(self, key):
        self.files._path(key)  # Validate before deriving any metadata path.
        self._fence(key)
        path = self.directory / (key + ".json")
        repair = False
        try:
            descriptor = SnapshotObject.model_validate_json(
                read_verification_metadata(path)
            ).checked()
            if descriptor.key != key:
                raise ValueError("publication descriptor changed its object")
            if (
                descriptor.stamp == _stamp(self.files._path(key))
                and descriptor.shape_bounds == stage_shape_identity()
            ):
                remember_metadata_completion(path)
                return descriptor
            repair = True
        except FileNotFoundError:
            repair = metadata_completion(path).exists()
        except (OSError, ValueError):
            repair = True
        return self._prepare(key, path, repair=repair)

    def _prepare(self, key, path, *, repair):
        with self.source.journal.read_transaction() as db:
            size = db.execute(
                "SELECT length(body) FROM records WHERE kind=? AND id=?",
                ("endpoint_replay_object", key),
            ).fetchone()
        if size is None:
            raise VerificationSourceChanged("publication original needs restoration")
        _event(
            "publication_object",
            "repair_required" if repair else "preparing",
            planning_range=(max(0.1, size[0] / (10 * 1024**2)), max(1, size[0] / 1024**2)),
            planning_basis="unmeasured_journal_decode_export_at_1_to_10_mib_per_second",
            planning_scope="single_object_identity_and_export_excludes_semantic_replay",
        )
        with WorkProgress(
            "publication_object_repair" if repair else "publication_object_prepare",
            1,
            unit="objects",
        ) as progress:
            # Interrupted first passes resume at the last atomically completed
            # object. Restoration reads only this affected native original.
            raw = read_endpoint_object(self.source, key)
            shape = check_stage_json(raw, kind="object")
            self._fence(key)
            target = self.files._path(key)
            lock = lock_private_file(target.parent / ".publish.lock")
            try:
                retained = None
                if target.exists() or target.is_symlink():
                    _stamp(target)  # Never replace unsafe links/foreign files.
                    try:
                        retained = self.files(key)
                    except (OSError, ValueError):
                        _event("publication_object", "repair_required")
                wrapper = RewardPackageObject(sha256=key, value=json.loads(raw))
                # Exact historical wrapper, canonical bytes and atomic durability.
                # Derived corrupt/missing exports are repaired from the original.
                if retained != raw:
                    _atomic(target, canonical_json_bytes(wrapper), readonly=True)
                descriptor = SnapshotObject(
                    key=key,
                    sha256=hashlib.sha256(raw).hexdigest(),
                    size=len(raw),
                    stamp=_stamp(target),
                    shape_bounds=stage_shape_identity(),
                    shape_values=shape,
                ).sealed()
                _atomic(path, canonical_json_bytes(descriptor))
                remember_metadata_completion(path)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
                os.close(lock)
            progress.advance()
            return descriptor

    def verification_identity(self, key):
        descriptor = self._descriptor(key)
        return canonical_json_bytes(
            [self.binding, str(self.files._path(key)), descriptor.stamp]
        ).decode()

    def verification_sha256(self, key):
        return self._descriptor(key).sha256

    def verification_size(self, key):
        return self._descriptor(key).size

    def verification_replay(self, key):
        descriptor = self._descriptor(key)
        if not replay_stage_json_shape(
            byte_sha256=descriptor.sha256,
            size=descriptor.size,
            values=descriptor.shape_values,
            bounds_sha256=descriptor.shape_bounds,
            maximum_bytes=MAX_ARCHIVE_OBJECT_BYTES,
        ):
            raise VerificationSourceChanged("publication shape context changed")

    def __call__(self, key):
        before = self.verification_identity(key)
        raw = self.files(key)
        if self.verification_identity(key) != before:
            raise VerificationSourceChanged("publication export changed while reading")
        return raw

    def ensure(self, key, source, *, derived=False):
        # Seals retained by a collector are derived from the fresh queue fence,
        # and need not already be endpoint objects in the original journal.
        # The caller must identify those exact seals, never infer permission
        # from a newly missing original row after export.
        if derived:
            self.files.publish(key, source)
        else:
            self.verification_replay(key)
