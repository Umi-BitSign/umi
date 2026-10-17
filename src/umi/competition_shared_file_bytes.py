"""Same-account native file facts shared across independently selected packages.

These facts establish byte validity only. Every caller still authenticates its
own model, policy, rights and admission. Exact ordered chunks and current remote
generations are dependencies; a supplied file digest is never a successful fact.
"""

from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path

from .competition_transport_verification import ByteCheckpoints, verifier_semantics
from .file_identity import file_fingerprint
from .open_competition import digest
from .private_files import ensure_private_directory, private_path
from .protocol import canonical_json_bytes, sha256_hex

FILE_ABI = "umi-shared-remote-file-bytes/1"


def _write(path, raw):
    ensure_private_directory(path.parent)
    descriptor, pending = tempfile.mkstemp(prefix=".file-scope-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    finally:
        Path(pending).unlink(missing_ok=True)


def _bounded_metadata(path, maximum):
    """Refuse unsafe state and read only bounded, stable private metadata."""
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
            raise ValueError("shared file metadata requires an owned private regular file")
        raw = stream.read(maximum + 1) if before.st_size <= maximum else b""
        if file_fingerprint(before) != file_fingerprint(
            os.fstat(stream.fileno())
        ) or file_fingerprint(before) != file_fingerprint(path.lstat()):
            raise ValueError("shared file metadata changed while reading")
        if before.st_size <= maximum and len(raw) != before.st_size:
            raise ValueError("shared file metadata changed while reading")
        return raw


class SharedRemoteFileBytes:
    """One native lock per immutable file; preserve every older package receipt."""

    def __init__(self, reader, record, item, heads, progress):
        self.record, self.progress = record, progress
        self.source = reader._source(item, heads)
        scope = {
            "semantics": [FILE_ABI, verifier_semantics()],
            "policy": reader.selection.binding.policy_sha256,
            "namespace": reader._namespace(),
        }
        file_identity = {
            "sha256": record.sha256,
            "size_bytes": record.size_bytes,
            "chunks": [{"sha256": c.sha256, "size_bytes": c.size_bytes} for c in item.chunks],
        }
        namespace, key = digest(scope), digest(file_identity)
        shard = Path(namespace) / key[:2] / key[2:4]
        self.root = reader.root / "shared-file-bytes-v1" / shard / key
        self.index = reader.root / "shared-file-index-v1" / shard / (key + ".json")
        self.index_raw = canonical_json_bytes(
            {
                "schema": "umi-shared-file-byte-scope/1",
                "namespace_sha256": namespace,
                "file_identity_sha256": key,
            }
        )
        self.checks = ByteCheckpoints(self.root, {**scope, "file": file_identity}, progress)
        self.result = None
        self.was_known = False
        self.missing_reported = False

    def __enter__(self):
        private_path(str(self.index))
        existed = self.root.exists()
        self.checks.__enter__()
        try:
            try:
                prior = _bounded_metadata(self.index, 64 * 1024)
            except FileNotFoundError:
                prior = None
            self.was_known = prior is not None or existed
            if prior != self.index_raw:
                if self.was_known:
                    self.progress.emit(
                        "repair_required", reason="shared_file_scope_missing_or_damaged"
                    )
                _write(self.index, self.index_raw)
                if self.was_known:
                    self.progress.emit("repair_completed", reason="shared_file_scope_repaired")
            if prior is not None and not existed:
                self.progress.emit("repair_required", reason="shared_file_byte_store_missing")
            return self
        except BaseException:
            self.checks.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        self.checks.__exit__(*args)

    def load(self):
        self.result = self.checks.load("contents", self.source)
        if self.result is not None and self.result != self.record.sha256:
            self.checks._repair("contents", "shared_file_byte_result_changed")
            self.result = None
        if self.result is None and self.was_known:
            self.progress.emit(
                "repair_required", reason="shared_file_byte_check_incomplete_or_missing"
            )
            self.missing_reported = True
        return self.result

    def document(self, maximum):
        try:
            raw = _bounded_metadata(self.root / "contents.document", maximum)
        except FileNotFoundError:
            return None
        if (
            len(raw) > maximum
            or len(raw) != self.record.size_bytes
            or sha256_hex(raw) != self.record.sha256
        ):
            self.missing_reported = True
            self.progress.emit("repair_required", reason="shared_file_document_damaged")
            return None
        return raw

    def remember_verified(self, document=None):
        # Called only after a valid old native receipt, another exact shared
        # fact, or the original full-file hash pass has established this result.
        if self.result != self.record.sha256:
            self.checks.remember("contents", self.source, self.record.sha256)
            self.result = self.record.sha256
        if document is not None:
            if (
                len(document) != self.record.size_bytes
                or sha256_hex(document) != self.record.sha256
            ):
                raise ValueError("shared file document differs from its verified bytes")
            if self.document(len(document) or 1) != document:
                _write(self.root / "contents.document", document)
        if self.missing_reported:
            self.progress.emit(
                "repair_completed", reason="shared_file_bytes_restored_from_native_fact"
            )
            self.missing_reported = False
