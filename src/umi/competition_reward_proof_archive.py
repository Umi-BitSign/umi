"""Portable original proof content, separate from live recovery databases.

Frames are untrusted lookup hints. The receiving history/coverage consumer must
replay native proofs before retaining evidence or crediting an interval. Flat
recipes use the existing bounded codec; no archive extraction or SQLite copy
is needed to deliver the files to another host.
"""

from __future__ import annotations

import hashlib
import os
import stat
import sys
import time
from collections import OrderedDict
from contextlib import contextmanager, suppress
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, JsonValue

from .canonical_reuse import canonical_json_reuse
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_PROOF_OBJECT_BYTES,
    MAX_RECIPE_BYTES,
    PreparedEvidenceEncoding,
    checked_digest,
    checked_size,
    decode_evidence,
    encode_evidence,
    inspect_recipe,
    prepare_evidence_with_recipe,
)
from .competition_journal_physical_budget import ArchivePhysicalBudget
from .open_competition import digest, identity
from .private_files import (
    ensure_private_directory,
    lock_private_file,
    private_path,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .r2_evidence import r2_evidence_connection_scope

MAX_FRAME_BYTES = 64 * 1024
MAX_FIELD_BYTES = 256 * 1024**2
# A complete native endpoint can contain more than 4,096 distinct proof pieces.
# Keep its working receipts together; saturation still uses ordinary I/O rather
# than rejecting evidence. The independent payload-byte budget is unchanged.
_MAX_PUBLISHED_OBJECTS = 8192
_MAX_READ_OBJECTS = 8192
_MAX_READ_BYTES = 32 * 1024**2
_MAX_REMOTE_BATCH_OBJECTS = 256
Kind = Literal["history", "endpoint", "interval", "registration"]


class _RemotePublicationBatch:
    """Borrow bounded immutable objects across fields before the frame barrier."""

    def __init__(self, remote):
        self.remote, self.objects, self.nbytes = remote, {}, 0

    def retain(self, raw, *, sha=None):
        checked_size(len(raw), MAX_PROOF_OBJECT_BYTES)
        sha = hashlib.sha256(raw).hexdigest() if sha is None else sha
        if sha in self.objects:
            if self.objects[sha] != raw:
                raise ValueError("proof publication batch changes an object's original bytes")
            return sha
        if self.nbytes + len(raw) > MAX_PROOF_OBJECT_BYTES or (
            len(self.objects) >= _MAX_REMOTE_BATCH_OBJECTS
        ):
            self.flush()
        self.objects[sha] = raw
        self.nbytes += len(raw)
        return sha

    def flush(self):
        if self.objects:
            # The existing store owns eight workers, its aggregate active-byte
            # budget and each durable completion. No frame is published here.
            self.remote.put_many(self.objects)
            self.objects, self.nbytes = {}, 0


def _publication_clock_ns():
    # Linux inode ctime may use the coarse realtime clock (clock ID 5).
    # A file changed within that same tick can retain every stamp field.
    # Other platforms keep ordinary publication until their clock is qualified.
    if sys.platform == "linux":
        with suppress(OSError, ValueError):
            return time.clock_gettime_ns(5)
    return None


class _Bytes(StrictProtocolModel):
    hex: str


class _Part(StrictProtocolModel):
    sha256: Hex32
    expanded_bytes: Annotated[int, Field(ge=1, le=MAX_EVIDENCE_BYTES)]
    recipe_sha256: Hex32


class _Frame(StrictProtocolModel):
    schema_: Literal["umi-reward-proof-frame/1"] = Field(alias="schema")
    kind: Kind
    key: Hex32
    context: dict[str, JsonValue]
    fields: dict[str, tuple[_Part, ...]]


def history_archive_key(chain_sha256: str, hotkey: str, height: int) -> str:
    checked_digest(chain_sha256)
    checked_size(height, 2**53 - 1)
    return digest({"chain": chain_sha256, "control": identity(hotkey), "block": height})


def _directory_identity(info):
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("reward archive object directory must be owned and private")
    return info.st_dev, info.st_ino, info.st_uid, info.st_gid, info.st_mode


def _object_identity(path, parent, info):
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or info.st_mode & 0o077
    ):
        raise ValueError("reward archive object is not an owned private regular file")
    return (
        str(path),
        *_directory_identity(parent),
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


class _ObjectDirectory:
    """Pin one selected private object directory for one synchronous operation.

    Leaf receipts still bind complete inode metadata. First/final namespace
    checks prevent a renamed directory or ancestor symlink from turning this
    descriptor into authority for another selected path. Actual reads and durable
    publications retain their ordinary canonical, bounded private-file paths.
    """

    def __init__(self, path):
        self.path = path
        self.pid = os.getpid()
        ensure_private_directory(path)
        self.fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            self.identity = _directory_identity(os.fstat(self.fd))
            if not self.unchanged():
                raise ValueError("reward archive object directory changed while opening")
        except BaseException:
            self.close()
            raise

    def unchanged(self):
        private_path(str(self.path))
        current = _directory_identity(self.path.lstat())
        return os.getpid() == self.pid and current == self.identity

    def stamp(self, path):
        if os.getpid() != self.pid:
            return RewardProofArchive._object_stamp(path)
        parent = os.fstat(self.fd)
        info = os.stat(path.name, dir_fd=self.fd, follow_symlinks=False)
        return _object_identity(path, parent, info)

    def close(self):
        os.close(self.fd)


class _FrameRead:
    """Bounded duplicate resolution within one frame, never proof authority.

    Only the ordinary verified reader can supply a reusable inode receipt. Every
    reused receipt is checked again before eviction or before returning a frame;
    subsequent reads still perform their own namespace and object checks. Remote
    reads retain the transport's receipt/restore behavior without this shortcut.
    """

    def __init__(self, archive, directory=None):
        self.archive = archive
        self.directory = directory
        self.pid = os.getpid()
        self.objects = OrderedDict()
        self.bytes = 0

    def _check(self, sha, entry, directory=None):
        stamp, raw, reused = entry
        if not reused and self.directory is None:
            return
        path = self.archive.root / "objects" / (sha + ".json")
        current_stamp = self.archive._object_stamp if directory is None else directory.stamp
        if os.getpid() != self.pid or current_stamp(path) != stamp:
            # A valid same-byte replacement remains compatible. Changed or
            # damaged storage must take the original canonical/hash checks.
            self.archive._read_object(path, sha, len(raw))

    def resolve(self, sha: str, maximum: int) -> bytes:
        if os.getpid() != self.pid:
            # Do not use a receipt or acquire an inherited lock after fork.
            return self.archive._bytes(sha, maximum)
        entry = self.objects.get(sha)
        if entry is not None:
            checked_size(maximum, MAX_EVIDENCE_BYTES)
            checked_size(len(entry[1]), maximum)
            self.objects.move_to_end(sha)
            entry[2] = True
            return entry[1]
        raw, stamp = self.archive._verified_bytes(sha, maximum, directory=self.directory)
        if stamp is not None and len(raw) <= _MAX_READ_BYTES and _MAX_READ_OBJECTS > 0:
            while self.objects and (
                self.bytes + len(raw) > _MAX_READ_BYTES or len(self.objects) >= _MAX_READ_OBJECTS
            ):
                old_sha, old = self.objects.popitem(last=False)
                # Evicted receipts cannot escape their selected namespace check.
                self._check(old_sha, old)
                self.bytes -= len(old[1])
            self.objects[sha] = [stamp, raw, False]
            self.bytes += len(raw)
        return raw

    def finish(self):
        directory = self.directory
        if directory is not None and not directory.unchanged():
            directory = None
        for sha, entry in self.objects.items():
            self._check(sha, entry, directory)
        if directory is not None and not directory.unchanged():
            for sha, entry in self.objects.items():
                self._check(sha, entry)


class RewardProofArchive:
    """Private immutable output and read-only imported input use separate roots.

    Each object is bounded; disk quota/headroom belongs to the owning service.
    Interrupted export retains reusable objects but publishes no partial frame.
    Transport/replication of these files is independent of proof verification.
    """

    def __init__(
        self,
        root: Path,
        *,
        remote=None,
        physical_budget: ArchivePhysicalBudget | None = None,
        legacy_read_through: bool = False,
    ):
        if physical_budget is not None and (
            type(physical_budget) is not ArchivePhysicalBudget or remote is not None
        ):
            raise ValueError("physical archive budget requires selected local transport")
        self.physical_budget = physical_budget
        if type(legacy_read_through) is not bool or (legacy_read_through and remote is None):
            raise ValueError("retained local proof reads require a selected remote store")
        self.legacy_read_through = legacy_read_through
        self.root = Path(private_path(str(root)))
        self.remote = remote
        if remote is not None:
            self._ensure_root()
        self._published = OrderedDict()
        self._publication_lock = Lock()
        self._read_objects = OrderedDict()
        self._read_bytes = 0
        self._read_lock = Lock()
        self._pid = os.getpid()

    @contextmanager
    def read_release_lease(self, *, exclusive=False):
        """Coordinate selected native readers with online local release.

        Hold the shared lease through frame resolution AND finish(), including
        local fallback reads. Release uses an exclusive nonblocking lease; a
        current reader defers cleanup rather than receiving missing-file errors.
        """
        if not self.root.exists():
            yield
            return
        fd = lock_private_file(self.root / ".proof-read-release.lock", shared=not exclusive)
        try:
            yield
        finally:
            os.close(fd)

    def _ensure_root(self):
        # Legacy publication created private children beneath an owned root
        # using the process umask. Secure that supported layout in place before
        # creating transport receipts, preserving all payload bytes and inodes.
        private_path(str(self.root))
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = self.root.stat()
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
            raise ValueError("proof archive root must be owned by its transport owner")
        if info.st_mode & 0o077:
            os.chmod(self.root, stat.S_IMODE(info.st_mode) & ~0o077)

    @staticmethod
    def _object_stamp(path):
        private_path(str(path))
        ensure_private_directory(path.parent)
        parent, info = path.parent.lstat(), path.lstat()
        return _object_identity(path, parent, info)

    @contextmanager
    def _directory_scope(self, *, enabled=True):
        if self.remote is not None:
            with r2_evidence_connection_scope(getattr(self.remote, "client", None)):
                yield None
            return
        if not enabled or os.getpid() != self._pid:
            yield None
            return
        directory = _ObjectDirectory(self.root / "objects")
        try:
            yield directory
        finally:
            directory.close()

    def _path(self, kind: Kind, key: str) -> Path:
        if kind not in ("history", "endpoint", "interval", "registration"):
            raise ValueError("unknown reward archive frame kind")
        return self.root / kind / (checked_digest(key) + ".json")

    def _retain_bytes(self, raw: bytes, *, directory=None) -> str:
        checked_size(len(raw), MAX_EVIDENCE_BYTES)
        sha = hashlib.sha256(raw).hexdigest()
        if self.remote is not None:
            receipt = self.remote.put_bytes(raw)
            if receipt["content_sha256"] != sha:
                raise ValueError("remote proof publication changed its content identity")
            return sha
        path = self.root / "objects" / (sha + ".json")
        if os.getpid() != self._pid:
            # Do not acquire a possibly inherited thread lock after fork.
            self._publish_bytes(path, raw)
            return sha
        object_stamp = self._object_stamp if directory is None else directory.stamp
        with self._publication_lock:
            prior = self._published.pop(sha, None)
            if prior is not None:
                with suppress(OSError, ValueError):
                    if object_stamp(path) == prior:
                        self._published[sha] = prior
                        return sha
            verification_tick = _publication_clock_ns()
            self._publish_bytes(path, raw)
            # Only a completed durable publication creates a reusable receipt.
            # Retain bounded metadata, never object payloads or proof authority.
            with suppress(OSError, ValueError):
                # Ordinary publication uses the selected pathname. A pinned
                # directory may have moved while it ran and cannot authenticate
                # the newly published object's receipt on that path.
                stamp = self._object_stamp(path)
                # Only cache a file whose ctime predates this verification.
                # A newly written file must be checked after its creation tick;
                # waiting alone cannot make an earlier same-tick check reusable.
                if verification_tick is not None and stamp[-1] < verification_tick:
                    self._published[sha] = stamp
                    while len(self._published) > _MAX_PUBLISHED_OBJECTS:
                        self._published.popitem(last=False)
        return sha

    def _publish_bytes(self, path, raw):
        if self.physical_budget is not None:
            self.physical_budget.check(self.root, 2 * len(raw) + len(b'{"hex":""}'))
        # Model validation and publication serialize the same hex object. Reuse
        # those exact canonical bytes within this call only; the current file,
        # publication lock, schema and durability checks still run on every retry.
        with canonical_json_reuse(maximum_bytes=32 * 1024**2):
            publish_private_model(
                path,
                _Bytes(hex=raw.hex()),
                maximum_bytes=MAX_PROOF_OBJECT_BYTES,
            )

    def _published_object_present(self, sha: str, size: int) -> bool:
        """Reuse only this process's completed, clock-qualified publication.

        This is transport presence, never native evidence acceptance. A fresh
        process, different destination, changed inode or unqualified clock takes
        the ordinary resolver/digest/publication path.
        """
        if self.remote is not None:
            reference = self.remote.reference_for_path("objects/" + sha)
            if reference is None:
                return False
            completed = self.remote.validate_reference(reference)
            if (completed.content_sha256, completed.size_bytes) != (sha, size):
                raise ValueError("completed remote object differs from encoded transport")
            return True
        if os.getpid() != self._pid:
            return False
        with self._publication_lock:
            prior = self._published.pop(sha, None)
            if prior is not None:
                with suppress(OSError, ValueError):
                    path = self.root / "objects" / (sha + ".json")
                    if (
                        prior[-3] == 2 * size + len(b'{"hex":""}')
                        and self._object_stamp(path) == prior
                    ):
                        self._published[sha] = prior
                        return True
        return False

    def _bytes(self, sha: str, maximum: int) -> bytes:
        return self._verified_bytes(sha, maximum)[0]

    def _verified_bytes(
        self, sha: str, maximum: int, *, directory=None
    ) -> tuple[bytes, tuple | None]:
        if self.remote is not None and not self._retained_local("objects/" + sha, "objects", sha):
            return self.remote.read_object(checked_digest(sha), maximum=maximum), None
        path = self.root / "objects" / (checked_digest(sha) + ".json")
        checked_size(maximum, MAX_EVIDENCE_BYTES)
        if os.getpid() != self._pid:
            # Inherited locks and verification receipts are not usable after fork.
            return self._read_object(path, sha, maximum), None
        object_stamp = self._object_stamp if directory is None else directory.stamp
        with self._read_lock:
            prior = self._read_objects.pop(sha, None)
            if prior is not None:
                self._read_bytes -= len(prior[1])
            stamp = object_stamp(path)
            if prior is not None and prior[0] == stamp:
                checked_size(len(prior[1]), maximum)
                self._read_objects[sha] = prior
                self._read_bytes += len(prior[1])
                return prior[1], stamp
            if directory is not None:
                # The cold reader resolves the selected pathname, not our held
                # descriptor. Pair its bytes only with ordinary pathname stamps;
                # otherwise a concurrent directory swap could seed a receipt for
                # an inode whose content was never actually read.
                stamp = self._object_stamp(path)
            verification_tick = _publication_clock_ns()
            raw = self._read_object(path, sha, maximum)
            # Reuse only verified bytes from an unchanged, private object whose
            # ctime predates this read. Frames and native proofs are still checked.
            if (
                verification_tick is not None
                and stamp[-1] < verification_tick
                and len(raw) <= _MAX_READ_BYTES
                and self._object_stamp(path) == stamp
            ):
                self._read_objects[sha] = (stamp, raw)
                self._read_bytes += len(raw)
                while (
                    self._read_bytes > _MAX_READ_BYTES
                    or len(self._read_objects) > _MAX_READ_OBJECTS
                ):
                    _, (_, removed) = self._read_objects.popitem(last=False)
                    self._read_bytes -= len(removed)
                return raw, stamp
            return raw, None

    @staticmethod
    def _read_object(path: Path, sha: str, maximum: int) -> bytes:
        value = read_private_model(
            path,
            _Bytes,
            maximum_bytes=2 * maximum + 1024,
        )
        if not 0 < len(value.hex) <= 2 * maximum:
            raise ValueError("reward archive object exceeds its bound")
        raw = bytes.fromhex(value.hex)
        if raw.hex() != value.hex or hashlib.sha256(raw).hexdigest() != sha:
            raise ValueError("reward archive object differs from its identity")
        return raw

    def write(
        self,
        kind: Kind,
        key: str,
        *,
        context: dict,
        fields: dict[str, bytes],
        prepared_encodings: dict[str, tuple[PreparedEvidenceEncoding, ...]] | None = None,
    ) -> None:
        # Local import avoids the progress module's publication-clock import
        # cycle. This measures owner wall time, not summed concurrent transfers.
        from .competition_transport_verification import TransferProgress

        with TransferProgress(
            "proof_archive_export", 1, unit="frames", planning_unit_seconds=(0.01, 300)
        ) as progress:
            self._write(
                kind, key, context=context, fields=fields, prepared_encodings=prepared_encodings
            )
            progress.advance(1)

    def _write(self, kind, key, *, context, fields, prepared_encodings):
        path = self._path(kind, key)
        if len(fields) > 4:
            raise ValueError("reward archive field count exceeds its bound")
        if prepared_encodings is not None and not set(prepared_encodings) <= set(fields):
            raise ValueError("prepared encodings name another archive field")
        existing = None
        if prepared_encodings or self.legacy_read_through:
            # Decoder-valid legacy recipes need not equal the current encoder's
            # chosen representation. Reuse those only when the already published
            # frame names exactly that recipe; otherwise retain the old encoder
            # path, including its immutable-frame conflict behavior.
            with suppress(FileNotFoundError):
                existing = self._frame(kind, key)
            if existing is not None and (
                existing.kind != kind
                or existing.key != key
                or existing.context != context
                or set(existing.fields) != set(fields)
            ):
                raise ValueError("retained archive frame differs from selected publication")
        with self._directory_scope(enabled=bool(fields)) as directory:
            refs = {}
            publication = None if self.remote is None else _RemotePublicationBatch(self.remote)
            for name, raw in fields.items():
                if type(raw) is not bytes:
                    raise ValueError("reward archive requires original byte evidence")
                checked_size(len(raw), MAX_FIELD_BYTES)
                prepared = None if prepared_encodings is None else prepared_encodings.get(name)
                if (
                    prepared is not None
                    and len(prepared) != (len(raw) + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
                ):
                    raise ValueError("prepared encoding count differs from original archive bytes")
                parts = []
                for number, offset in enumerate(range(0, len(raw), MAX_EVIDENCE_BYTES)):
                    chunk = raw[offset : offset + MAX_EVIDENCE_BYTES]
                    if (
                        prepared is not None
                        and type(prepared[number]) is not PreparedEvidenceEncoding
                    ):
                        raise ValueError("archive export requires a codec-owned prepared encoding")
                    encoded = (
                        encode_evidence(
                            chunk,
                            kind="proof",
                            single_object=self.remote is not None and existing is None,
                        )
                        if prepared is None
                        else prepared[number].for_bytes(chunk, kind="proof")
                    )
                    if (
                        self.remote is not None
                        and existing is not None
                        and number < len(existing.fields[name])
                    ):
                        original = existing.fields[name][number]
                        if (
                            original.sha256 == encoded.sha256
                            and original.expanded_bytes == encoded.expanded_bytes
                            and original.recipe_sha256 != hashlib.sha256(encoded.recipe).hexdigest()
                        ):
                            recipe = self.remote.read_object(
                                original.recipe_sha256, maximum=MAX_RECIPE_BYTES
                            )
                            encoded = prepare_evidence_with_recipe(
                                chunk, recipe, kind="proof"
                            ).for_bytes(chunk, kind="proof")
                    if (
                        prepared is not None
                        and not prepared[number].canonical_encoder
                        and (self.remote is None or existing is not None)
                    ):
                        part = _Part(
                            sha256=encoded.sha256,
                            expanded_bytes=encoded.expanded_bytes,
                            recipe_sha256=hashlib.sha256(encoded.recipe).hexdigest(),
                        )
                        if (
                            existing is None
                            or number >= len(existing.fields[name])
                            or existing.fields[name][number] != part
                        ):
                            encoded = encode_evidence(chunk, kind="proof")
                    if self.remote is None:
                        for value in encoded.objects.values():
                            self._retain_bytes(value, directory=directory)
                        recipe_sha = self._retain_bytes(encoded.recipe, directory=directory)
                    else:
                        for sha, value in encoded.objects.items():
                            publication.retain(value, sha=sha)
                        recipe_sha = publication.retain(encoded.recipe)
                    parts.append(
                        _Part(
                            sha256=encoded.sha256,
                            expanded_bytes=encoded.expanded_bytes,
                            recipe_sha256=recipe_sha,
                        )
                    )
                refs[name] = tuple(parts)
            frame = _Frame(
                schema="umi-reward-proof-frame/1", kind=kind, key=key, context=context, fields=refs
            )
            if self.legacy_read_through and existing is not None and existing != frame:
                raise ValueError("retained archive frame differs from selected publication")
            if directory is not None and not directory.unchanged():
                raise ValueError("reward archive object directory changed during publication")
            if self.remote is None:
                if self.physical_budget is not None:
                    self.physical_budget.check(self.root, MAX_FRAME_BYTES)
                publish_private_model(path, frame, maximum_bytes=MAX_FRAME_BYTES)
            else:
                raw = canonical_json_bytes(frame)
                checked_size(len(raw), MAX_FRAME_BYTES)
                publication.flush()
                # The original /1 frame and codec recipes form the immutable object
                # index. Publish the frame only after every referenced byte object.
                self.remote.put_bytes(raw, path="frames/" + kind + "/" + key)

    def copy_encoded_transport(self, kind: Kind, key: str, *, context, fields, resolve) -> bool:
        """Transfer existing recipes without issuing any proof acceptance.

        Native reuse consumers must authenticate their original checkpoint and
        exact source revisions separately. Recipes retain their original expanded
        digests; a receiving proof consumer still runs ordinary codec and native
        checks. Different existing frame encodings require the caller's legacy
        decode/encode path, including its immutable conflict checks.
        """
        from .competition_transport_verification import TransferProgress

        progress = TransferProgress(
            "proof_archive_export", 1, unit="frames", planning_unit_seconds=(0.01, 300)
        )
        path = self._path(kind, key)
        if not fields or len(fields) > 4:
            raise ValueError("reward archive field count exceeds its bound")
        refs = {}
        recipes = []
        for name, parts in fields.items():
            if (
                type(parts) is not tuple
                or not 0
                < len(parts)
                <= (MAX_FIELD_BYTES + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
            ):
                raise ValueError("reward archive encoded part count exceeds its bound")
            total = 0
            refs[name] = []
            for sha, size, recipe in parts:
                checked_digest(sha)
                segments = inspect_recipe(recipe, expanded_bytes=size, kind="proof")
                total += size
                checked_size(total, MAX_FIELD_BYTES)
                refs[name].append(
                    _Part(
                        sha256=sha,
                        expanded_bytes=size,
                        recipe_sha256=hashlib.sha256(recipe).hexdigest(),
                    )
                )
                recipes.append((recipe, segments))
            refs[name] = tuple(refs[name])
        frame = _Frame(
            schema="umi-reward-proof-frame/1", kind=kind, key=key, context=context, fields=refs
        )
        with suppress(FileNotFoundError):
            if self._frame(kind, key) != frame:
                return False
        # Publish no frame until every bounded referenced object is durable.
        # Repeated objects within this transfer need only one resolver read.
        # Start reporting only once compatibility selects an actual export.
        # A normal legacy fallback returns above without claiming either a
        # completed frame or an interrupted transfer. The timer still includes
        # this call's bounded compatibility preparation on successful exports.
        with progress, self._directory_scope():
            retained = {}
            publication = None if self.remote is None else _RemotePublicationBatch(self.remote)

            def retain(raw):
                if self.remote is None:
                    return self._retain_bytes(raw)
                return publication.retain(raw)

            for recipe, segments in recipes:
                for _, sha, size in segments:
                    if sha in retained:
                        if retained[sha] != size:
                            raise ValueError("encoded transport object length differs")
                        continue
                    if self._published_object_present(sha, size):
                        retained[sha] = size
                        continue
                    raw = resolve(sha, size)
                    if type(raw) is not bytes or len(raw) != size:
                        raise ValueError("encoded transport object size differs")
                    if retain(raw) != sha:
                        raise ValueError("encoded transport object digest differs")
                    retained[sha] = size
                retain(recipe)
            if publication is not None:
                publication.flush()
            if self.remote is None:
                if self.physical_budget is not None:
                    self.physical_budget.check(self.root, MAX_FRAME_BYTES)
                publish_private_model(path, frame, maximum_bytes=MAX_FRAME_BYTES)
            else:
                raw = canonical_json_bytes(frame)
                checked_size(len(raw), MAX_FRAME_BYTES)
                self.remote.put_bytes(raw, path="frames/" + kind + "/" + key)
            progress.advance(1)
            return True

    def _frame(self, kind: Kind, key: str) -> _Frame:
        path = self._path(kind, key)
        if self.remote is None or self._retained_local("frames/" + kind + "/" + key, kind, key):
            return read_private_model(path, _Frame, maximum_bytes=MAX_FRAME_BYTES)
        raw = self.remote.read_path("frames/" + kind + "/" + key, maximum=MAX_FRAME_BYTES)
        frame = _Frame.model_validate_json(raw)
        if canonical_json_bytes(frame) != raw:
            raise ValueError("remote proof frame does not retain canonical original bytes")
        return frame

    def _retained_local(self, remote_path: str, kind: str, key: str) -> bool:
        """Use an original only if no completed remote generation owns this name.

        A missing/damaged receipt or previously observed remote loss must still
        refuse through the normal remote repair fence, even when an old local
        copy exists. Merely selecting this mode never walks or migrates history.
        """
        if not self.legacy_read_through:
            return False
        checked_digest(key)
        if self.remote.reference_for_path(remote_path) is not None:
            return False
        return (self.root / kind / (key + ".json")).exists()

    def read(
        self, kind: Kind, key: str, *, bounds: dict[str, int]
    ) -> tuple[dict, dict[str, bytes]]:
        with self.read_release_lease():
            frame = self._frame(kind, key)
            return self._read_frame(frame, kind, key, bounds)

    def read_if_present(
        self, kind: Kind, key: str, *, bounds: dict[str, int]
    ) -> tuple[dict, dict[str, bytes]] | None:
        """Absent lookup hints may defer; missing referenced evidence is a repair.

        Frame selection is separate from payload resolution so a caller cannot
        mistake a damaged present archive for an unavailable lookup source.
        Completed remote transport fences retain their existing repair errors.
        """
        with self.read_release_lease():
            try:
                frame = self._frame(kind, key)
            except FileNotFoundError:
                return None
            return self._read_frame(frame, kind, key, bounds)

    def _read_frame(self, frame, kind, key, bounds):
        if frame.kind != kind or frame.key != key or set(frame.fields) != set(bounds):
            raise ValueError("reward archive frame changes its requested domain")
        with self._directory_scope(enabled=bool(frame.fields)) as directory:
            resolver = _FrameRead(self, directory)
            result = {}
            for name, maximum in bounds.items():
                checked_size(maximum, MAX_FIELD_BYTES)
                parts = frame.fields[name]
                if (
                    not 0 < len(parts) <= (maximum + MAX_EVIDENCE_BYTES - 1) // MAX_EVIDENCE_BYTES
                    or sum(p.expanded_bytes for p in parts) > maximum
                ):
                    raise ValueError("reward archive field expansion exceeds its bound")
                result[name] = b"".join(
                    decode_evidence(
                        resolver.resolve(p.recipe_sha256, MAX_RECIPE_BYTES),
                        sha256=p.sha256,
                        expanded_bytes=p.expanded_bytes,
                        kind="proof",
                        resolve=resolver.resolve,
                    )
                    for p in parts
                )
            resolver.finish()
            return frame.context, result

    def interval(self, key: str) -> dict:
        context, _ = self.read("interval", key, bounds={})
        return context

    def retain_interval(self, key: str, value) -> None:
        self.write("interval", key, context=value.model_dump(mode="json", by_alias=True), fields={})
