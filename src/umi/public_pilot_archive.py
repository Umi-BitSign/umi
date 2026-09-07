"""Deterministic, allowlisted archives for public-pilot evidence trees."""

from __future__ import annotations

import gzip
import hashlib
import hmac
import io
import json
import os
import re
import stat
import tarfile
import tempfile
import zlib
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any

from .audit import (
    MAX_COMPONENT_MANIFEST_BYTES,
    MAX_COMPONENT_OBJECT_BYTES,
    MAX_COMPONENT_TOTAL_OBJECT_BYTES,
    EvidenceStore,
    ObjectRef,
    _read_bounded_regular_file,
)
from .protocol import canonical_json_bytes

_DIGEST = re.compile(r"^[0-9a-f]{64}$")
MAX_PUBLIC_PILOT_ARCHIVE_BYTES = 96 * 1024 * 1024
MAX_PUBLIC_PILOT_UNCOMPRESSED_ARCHIVE_BYTES = (
    MAX_COMPONENT_TOTAL_OBJECT_BYTES + MAX_COMPONENT_MANIFEST_BYTES + 16 * 1024 * 1024
)


def _object_references(value: Any) -> tuple[ObjectRef, ...]:
    references: list[ObjectRef] = []
    if isinstance(value, dict):
        if set(value) == {"sha256", "media_type", "size_bytes"}:
            try:
                references.append(
                    ObjectRef(
                        sha256=value["sha256"],
                        media_type=value["media_type"],
                        size_bytes=value["size_bytes"],
                    )
                )
            except (TypeError, ValueError) as error:
                raise ValueError("pilot archive contains a malformed object reference") from error
        else:
            for item in value.values():
                references.extend(_object_references(item))
    elif isinstance(value, list):
        for item in value:
            references.extend(_object_references(item))
    return tuple(references)


def _referenced_objects(root: Path) -> dict[str, bytes]:
    store = EvidenceStore(root)
    manifest, manifest_bytes = store.load_manifest_with_bytes()
    pending = list(_object_references(manifest))
    objects: dict[str, bytes] = {}
    declared: dict[str, ObjectRef] = {}
    while pending:
        reference = pending.pop()
        prior = declared.get(reference.sha256)
        if prior is not None:
            if prior != reference:
                raise ValueError("pilot archive declares one object inconsistently")
            continue
        declared[reference.sha256] = reference
        data = store.read(reference)
        objects[reference.sha256] = data
        if reference.media_type == "application/json":
            try:
                value = json.loads(data)
            except (UnicodeDecodeError, json.JSONDecodeError) as error:
                raise ValueError("pilot JSON object is invalid") from error
            if canonical_json_bytes(value) != data:
                raise ValueError("pilot JSON object is not canonical")
            pending.extend(_object_references(value))

    entries = tuple(root.iterdir())
    if {entry.name for entry in entries} != {"manifest.json", "objects"}:
        raise ValueError("pilot archive source contains an unexpected top-level entry")
    object_entries = tuple((root / "objects").iterdir())
    names = {entry.name for entry in object_entries}
    if len(names) != len(object_entries) or names != set(objects):
        raise ValueError("pilot archive source has missing or unreferenced objects")
    for entry in (root, root / "objects", root / "manifest.json", *object_entries):
        metadata = entry.lstat()
        expected = stat.S_ISDIR if entry in {root, root / "objects"} else stat.S_ISREG
        if entry.is_symlink() or not expected(metadata.st_mode):
            raise ValueError("pilot archive source contains an unsafe path")
        if not stat.S_ISDIR(metadata.st_mode) and metadata.st_nlink != 1:
            raise ValueError("pilot archive source contains a linked file")
    return {"manifest.json": manifest_bytes, **{f"objects/{k}": v for k, v in objects.items()}}


def _tar_info(name: str, size: int, *, directory: bool) -> tarfile.TarInfo:
    info = tarfile.TarInfo(name)
    info.size = 0 if directory else size
    info.mode = 0o700 if directory else 0o600
    info.uid = 0
    info.gid = 0
    info.uname = ""
    info.gname = ""
    info.mtime = 0
    info.type = tarfile.DIRTYPE if directory else tarfile.REGTYPE
    return info


def create_evidence_archive(root: Path, output: Path, *, archive_root: str) -> str:
    """Create a deterministic gzip-compressed tar containing only referenced evidence."""

    if PurePosixPath(archive_root).parts != (archive_root,) or not archive_root:
        raise ValueError("pilot archive root must be one safe path component")
    source = root.expanduser().resolve(strict=True)
    destination = output.expanduser().resolve(strict=False)
    if destination.exists():
        raise FileExistsError("pilot archive output already exists")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    files = _referenced_objects(source)
    descriptor: int | None = None
    temporary: str | None = None
    try:
        descriptor, temporary = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        os.fchmod(descriptor, 0o600)
        with (
            os.fdopen(descriptor, "wb", closefd=False) as raw,
            gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed,
            tarfile.open(mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT) as opened,
        ):
            opened.addfile(_tar_info(archive_root, 0, directory=True))
            opened.addfile(_tar_info(f"{archive_root}/objects", 0, directory=True))
            for relative, data in sorted(files.items()):
                name = f"{archive_root}/{relative}"
                opened.addfile(_tar_info(name, len(data), directory=False), io.BytesIO(data))
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if metadata.st_size > MAX_PUBLIC_PILOT_ARCHIVE_BYTES:
            raise ValueError("pilot archive exceeds its compressed byte ceiling")
        os.close(descriptor)
        descriptor = None
        os.link(temporary, destination, follow_symlinks=False)
        os.unlink(temporary)
        temporary = None
        directory = os.open(destination.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if temporary is not None:
            with suppress(FileNotFoundError):
                os.unlink(temporary)
    return hashlib.sha256(
        _read_bounded_regular_file(destination, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
    ).hexdigest()


def _decompress_canonical_gzip(compressed: bytes) -> bytes:
    """Bound gzip output before tar parsing and reject concatenated/trailing members."""

    decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
    output = bytearray()
    offset = 0
    while offset < len(compressed):
        chunk = compressed[offset : offset + 64 * 1024]
        offset += len(chunk)
        pending = chunk
        while pending:
            remaining = MAX_PUBLIC_PILOT_UNCOMPRESSED_ARCHIVE_BYTES - len(output)
            if remaining < 0:
                raise ValueError("pilot archive exceeds its uncompressed byte ceiling")
            try:
                decoded = decoder.decompress(pending, remaining + 1)
            except zlib.error as error:
                raise ValueError("public-pilot archive has invalid gzip framing") from error
            output.extend(decoded)
            if len(output) > MAX_PUBLIC_PILOT_UNCOMPRESSED_ARCHIVE_BYTES:
                raise ValueError("pilot archive exceeds its uncompressed byte ceiling")
            pending = decoder.unconsumed_tail
            if decoder.eof:
                if pending or decoder.unused_data or offset != len(compressed):
                    raise ValueError("pilot archive contains trailing or concatenated gzip data")
                break
    remaining = MAX_PUBLIC_PILOT_UNCOMPRESSED_ARCHIVE_BYTES - len(output)
    try:
        output.extend(decoder.flush(remaining + 1))
    except zlib.error as error:
        raise ValueError("public-pilot archive has invalid gzip framing") from error
    if len(output) > MAX_PUBLIC_PILOT_UNCOMPRESSED_ARCHIVE_BYTES:
        raise ValueError("pilot archive exceeds its uncompressed byte ceiling")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("pilot archive gzip stream is incomplete or noncanonical")
    return bytes(output)


def extract_evidence_archive(archive: Path, output: Path, *, archive_root: str) -> Path:
    """Extract one strict pilot archive without links, sparse files, or extra paths."""

    source = archive.expanduser().resolve(strict=True)
    destination = output.expanduser().resolve(strict=False)
    if destination.exists():
        raise FileExistsError("pilot archive extraction destination already exists")
    compressed = _read_bounded_regular_file(source, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
    uncompressed = _decompress_canonical_gzip(compressed)
    total = 0
    members: dict[str, bytes] = {}
    with tarfile.open(mode="r:", fileobj=io.BytesIO(uncompressed)) as opened:
        seen: set[str] = set()
        for member in opened:
            if member.name in seen:
                raise ValueError("pilot archive repeats a member name")
            seen.add(member.name)
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts or "." in path.parts:
                raise ValueError("pilot archive contains an unsafe member path")
            expected_directory = member.name in {archive_root, f"{archive_root}/objects"}
            expected_file = member.name == f"{archive_root}/manifest.json" or (
                len(path.parts) == 3
                and path.parts[:2] == (archive_root, "objects")
                and _DIGEST.fullmatch(path.parts[2]) is not None
            )
            if member.pax_headers:
                raise ValueError("pilot archive contains extended tar metadata")
            if expected_directory:
                if member.type != tarfile.DIRTYPE or member.size != 0:
                    raise ValueError("pilot archive directory member is invalid")
                continue
            if not expected_file or member.type != tarfile.REGTYPE or member.size < 0:
                raise ValueError("pilot archive contains a disallowed member")
            ceiling = (
                MAX_COMPONENT_MANIFEST_BYTES
                if member.name.endswith("/manifest.json")
                else MAX_COMPONENT_OBJECT_BYTES
            )
            maximum_total = MAX_COMPONENT_TOTAL_OBJECT_BYTES + MAX_COMPONENT_MANIFEST_BYTES
            if member.size > ceiling or total + member.size > maximum_total:
                raise ValueError("pilot archive exceeds its uncompressed byte ceiling")
            extracted = opened.extractfile(member)
            if extracted is None:
                raise ValueError("pilot archive member has no readable body")
            data = extracted.read(ceiling + 1)
            if len(data) != member.size or len(data) > ceiling:
                raise ValueError("pilot archive member length is invalid")
            total += len(data)
            relative = "/".join(path.parts[1:])
            members[relative] = data

    if {archive_root, f"{archive_root}/objects"} - seen:
        raise ValueError("pilot archive omits required directories")
    if "manifest.json" not in members:
        raise ValueError("pilot archive omits its manifest")
    destination.mkdir(mode=0o700, parents=False)
    objects = destination / "objects"
    objects.mkdir(mode=0o700)
    try:
        for relative, data in sorted(members.items()):
            path = destination / relative
            descriptor = os.open(
                path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
                0o600,
            )
            try:
                offset = 0
                while offset < len(data):
                    written = os.write(descriptor, data[offset:])
                    if written <= 0:
                        raise OSError("pilot archive extraction made no progress")
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        for directory_path in (objects, destination):
            descriptor = os.open(directory_path, os.O_RDONLY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        _referenced_objects(destination)
        descriptor, canonical_name = tempfile.mkstemp(
            prefix=".pilot-archive-replay-", dir=destination.parent
        )
        os.close(descriptor)
        os.unlink(canonical_name)
        canonical_path = Path(canonical_name)
        try:
            create_evidence_archive(destination, canonical_path, archive_root=archive_root)
            canonical = _read_bounded_regular_file(canonical_path, MAX_PUBLIC_PILOT_ARCHIVE_BYTES)
            if not hmac.compare_digest(canonical, compressed):
                raise ValueError("pilot archive is not the canonical deterministic encoding")
        finally:
            canonical_path.unlink(missing_ok=True)
    except BaseException:
        import shutil

        shutil.rmtree(destination, ignore_errors=True)
        raise
    return destination
