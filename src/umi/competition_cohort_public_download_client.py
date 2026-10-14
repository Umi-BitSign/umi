"""Resume bounded public R2 downloads without granting native model acceptance.

Only the public API is renewable authority for GET capabilities. Local progress
is private owner state: completed bytes are reused by exact filesystem identity,
never by trusting a URL or by treating a missing verdict as a cache miss.
"""

from __future__ import annotations

import errno
import fcntl
import hashlib
import json
import logging
import math
import os
import re
import shutil
import sqlite3
import stat
from collections.abc import Callable, Iterable
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

from .competition_transport_verification import TransferProgress, verification_tick
from .http_logging import video_fetch_logging
from .open_competition import BundleFile, ModelBundle, digest
from .private_files import ensure_private_directory, lock_private_file, private_path
from .protocol import canonical_json_bytes

CHUNK_BYTES = 8 * 1024**2
READ_BYTES = 128 * 1024
METADATA_BYTES = 8 * 1024**2
VERIFIER = "umi-public-model-download-client/1"
_LOG = logging.getLogger(__name__)
_HEX = re.compile(r"[0-9a-f]{64}\Z")


class PublicDownloadError(ValueError):
    """A safe reason code; never includes a signed URL or provider response body."""


def _fail(reason: str) -> None:
    raise PublicDownloadError(reason)


def _json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _url(value: str) -> str:
    try:
        parts = urlsplit(value)
        permitted = parts.scheme == "https" or (
            parts.scheme == "http" and parts.hostname in ("127.0.0.1", "localhost", "::1")
        )
        if not permitted or not parts.netloc or parts.username or parts.password or parts.fragment:
            _fail("download_url_invalid")
    except (TypeError, ValueError):
        raise PublicDownloadError("download_url_invalid") from None
    return value


def _stamp(path: Path) -> list[int]:
    private_path(str(path))
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.getuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        _fail("download_local_file_unsafe")
    return [
        info.st_dev,
        info.st_ino,
        info.st_uid,
        info.st_gid,
        info.st_mode,
        info.st_nlink,
        info.st_size,
        info.st_mtime_ns,
        info.st_ctime_ns,
    ]


def _sync(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _metadata(client: httpx.Client, url: str) -> dict:
    try:
        with (
            video_fetch_logging(),
            client.stream(
                "GET",
                _url(url),
                headers={"Accept-Encoding": "identity"},
                follow_redirects=False,
            ) as response,
        ):
            if response.status_code != 200:
                _fail("download_metadata_unavailable_retry_unchanged")
            if response.headers.get("content-encoding", "identity") != "identity":
                _fail("download_metadata_encoding_invalid")
            raw = bytearray()
            for piece in response.iter_raw(READ_BYTES):
                if len(raw) + len(piece) > METADATA_BYTES:
                    _fail("download_metadata_byte_bound")
                raw.extend(piece)
        value = json.loads(raw)
        if not isinstance(value, dict):
            _fail("download_metadata_shape_invalid")
        return value
    except httpx.HTTPError:
        raise PublicDownloadError("download_metadata_transport_unavailable") from None
    except (json.JSONDecodeError, UnicodeError):
        raise PublicDownloadError("download_metadata_json_invalid") from None


@dataclass(frozen=True)
class Download:
    base_url: str
    cohort: str
    model: str
    format: str
    bundle: ModelBundle
    files_url: str
    payload_sha256: str | None
    payload_bytes: int

    @classmethod
    def fetch(cls, client: httpx.Client, base_url: str, cohort: str, model: str) -> Download:
        if not _HEX.fullmatch(cohort) or not _HEX.fullmatch(model):
            _fail("download_identity_invalid")
        base = _url(base_url.rstrip("/"))
        parts = urlsplit(base)
        if parts.path or parts.query:
            _fail("download_api_origin_required")
        path = f"/v1/competition/cohorts/{cohort}/models/{model}/download"
        body = _metadata(client, base + path)
        try:
            bundle = ModelBundle.model_validate_json(json.dumps(body["bundle"]))
            kind = body["format"]
            if (
                body.get("schema") != "umi-public-model-download-response/1"
                or body.get("cohort_sha256") != cohort
                or body.get("model_sha256") != model
                or digest(bundle) != model
                or body.get("method") != "GET"
                or body.get("chain_submission_authorized") is not False
                or body.get("files_url") != path + "-files"
                or kind not in ("preserved_chunks", "concatenated_payload")
            ):
                _fail("download_manifest_binding_invalid")
            payload = body.get("payload")
            total = sum(file.size_bytes for file in bundle.files)
            if kind == "concatenated_payload":
                if (
                    not isinstance(payload, dict)
                    or not _HEX.fullmatch(payload["sha256"])
                    or type(payload["size_bytes"]) is not int
                    or payload["size_bytes"] != total
                ):
                    _fail("download_payload_binding_invalid")
            elif payload is not None:
                _fail("download_payload_unexpected")
            return cls(
                base,
                cohort,
                model,
                kind,
                bundle,
                base + path + "-files",
                None if payload is None else payload["sha256"],
                total,
            )
        except (KeyError, TypeError, ValueError):
            raise PublicDownloadError("download_manifest_invalid") from None

    def binding(self) -> dict:
        return {
            "verifier": VERIFIER,
            "api_origin": self.base_url,
            "cohort_sha256": self.cohort,
            "model_sha256": self.model,
            "format": self.format,
            "manifest_sha256": hashlib.sha256(canonical_json_bytes(self.bundle)).hexdigest(),
            "payload_sha256": self.payload_sha256,
            "payload_bytes": self.payload_bytes,
        }

    def segments(self, client: httpx.Client, index: int, offset: int) -> list[dict]:
        native = self.bundle.files[index]
        url = f"{self.files_url}?file_index={index}&offset={offset}&limit=128"
        body = _metadata(client, url)
        try:
            if (
                body["model_sha256"] != self.model
                or body["file_index"] != index
                or body.get("method") != "GET"
                or BundleFile.model_validate_json(json.dumps(body["file"])) != native
            ):
                _fail("download_file_binding_changed")
            page = body["segments"]
            total = (
                math.ceil(native.size_bytes / CHUNK_BYTES)
                if self.format == "preserved_chunks"
                else int(native.size_bytes > 0)
            )
            count = min(128, total - offset)
            if (
                type(page["total"]) is not int
                or page["total"] != total
                or page["offset"] != offset
                or len(page["items"]) != count
                or page["next_offset"] != (offset + count if offset + count < total else None)
            ):
                _fail("download_segment_page_invalid")
            result = []
            for n, segment in enumerate(page["items"], start=offset):
                if self.format == "preserved_chunks":
                    size = min(CHUNK_BYTES, native.size_bytes - n * CHUNK_BYTES)
                    if "range_start" in segment:
                        _fail("download_chunk_geometry_changed")
                    start = None
                else:
                    size = native.size_bytes
                    start = sum(file.size_bytes for file in self.bundle.files[:index])
                    if segment.get("range_start") != start or segment["sha256"] != native.sha256:
                        _fail("download_range_binding_changed")
                if (
                    type(segment["size_bytes"]) is not int
                    or segment["size_bytes"] != size
                    or not _HEX.fullmatch(segment["sha256"])
                ):
                    _fail("download_segment_geometry_invalid")
                result.append(
                    {
                        "sha256": segment["sha256"],
                        "size_bytes": size,
                        "range_start": start,
                        "url": _url(segment["url"]),
                    }
                )
            return result
        except (KeyError, TypeError, ValueError):
            raise PublicDownloadError("download_file_metadata_invalid") from None


class DownloadState:
    """One owner, bounded append intents and durable per-file native verdicts."""

    def __init__(self, root: Path, download: Download, report=None):
        self.root, self.download = root, download
        self.report = report
        ensure_private_directory(root)
        state = root / ".umi-download"
        if not state.exists() and any(root.iterdir()):
            _fail("download_output_not_empty")
        ensure_private_directory(state)
        self.lock = lock_private_file(state / "owner.lock")
        self.db = None
        try:
            database = state / "state.sqlite3"
            existing = database.exists()
            if existing:
                _stamp(database)
            elif any(path.name != "owner.lock" for path in state.iterdir()) or any(
                path.name != ".umi-download" for path in root.iterdir()
            ):
                _fail("download_checkpoint_missing_repair_required")
            for path in state.iterdir():
                if path.name.startswith("state.sqlite3"):
                    _stamp(path)
            if not existing:
                fd = os.open(database, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
            self.db = sqlite3.connect(database)
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("PRAGMA journal_mode=DELETE")
            if self.db.execute("PRAGMA quick_check").fetchone() != ("ok",):
                _fail("download_checkpoint_damaged_repair_required")
            tables = {
                row[0]
                for row in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")
            }
            if (
                not tables
                and not any(path.name != ".umi-download" for path in root.iterdir())
                and all(
                    path.name in ("owner.lock", "state.sqlite3", "state.sqlite3-journal")
                    for path in state.iterdir()
                )
            ):
                with self.db:
                    self.db.execute("BEGIN IMMEDIATE")
                    self.db.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
                    self.db.execute(
                        "CREATE TABLE files (idx INTEGER PRIMARY KEY, body TEXT NOT NULL)"
                    )
                    self.db.execute(
                        "CREATE TABLE pieces (file_idx INTEGER, idx INTEGER, "
                        "descriptor TEXT NOT NULL, PRIMARY KEY(file_idx,idx))"
                    )
                    self.db.execute(
                        "INSERT INTO meta VALUES ('binding',?)", (_json(download.binding()),)
                    )
                    self.db.execute("INSERT INTO meta VALUES ('manifest_phase','publishing')")
                _sync(state)
            row = self.db.execute("SELECT value FROM meta WHERE key='binding'").fetchone()
            if row != (_json(download.binding()),):
                _fail("download_checkpoint_binding_changed")
            self.stage = state / "files"
            ensure_private_directory(self.stage)
            ensure_private_directory(root / "model")
            manifest = root / "manifest.json"
            expected = canonical_json_bytes(download.bundle)
            phase = self.db.execute("SELECT value FROM meta WHERE key='manifest_phase'").fetchone()
            if phase not in (("publishing",), ("complete",)):
                _fail("download_manifest_checkpoint_needs_repair")
            if phase == ("publishing",) and not manifest.exists():
                pending = state / "manifest.pending"
                if pending.exists() or pending.is_symlink():
                    _stamp(pending)
                    pending.unlink()
                fd = os.open(pending, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                with os.fdopen(fd, "wb") as stream:
                    stream.write(expected)
                    stream.flush()
                    os.fsync(stream.fileno())
                os.rename(pending, manifest)
                _sync(root)
            if (
                not manifest.exists()
                or _stamp(manifest)[6] != len(expected)
                or manifest.read_bytes() != expected
            ):
                _fail("download_manifest_damaged_repair_required")
            if phase == ("publishing",):
                with self.db:
                    self.db.execute("UPDATE meta SET value='complete' WHERE key='manifest_phase'")
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        if self.db is not None:
            self.db.close()
        fcntl.flock(self.lock, fcntl.LOCK_UN)
        os.close(self.lock)

    def save(self, index: int, body: dict) -> None:
        with self.db:
            self.db.execute("INSERT OR REPLACE INTO files VALUES (?,?)", (index, _json(body)))

    def path(self, index: int, *, published: bool = False) -> Path:
        if not published:
            return self.stage / f"{index}.part"
        return self.root / "model" / self.download.bundle.files[index].path

    def recover(self, index: int, *, repair: bool = False) -> dict:
        row = self.db.execute("SELECT body FROM files WHERE idx=?", (index,)).fetchone()
        body = None if row is None else json.loads(row[0])
        if repair:
            body = {**(body or {}), "phase": "repairing"}
            self.save(index, body)
        if body is not None and body["phase"] == "repairing":
            for path in (self.path(index), self.path(index, published=True)):
                if path.exists() or path.is_symlink():
                    _stamp(path)
                    path.unlink()
                    _sync(path.parent)
            with self.db:
                self.db.execute("DELETE FROM pieces WHERE file_idx=?", (index,))
                self.db.execute("DELETE FROM files WHERE idx=?", (index,))
            body = None
        if body is None:
            if self.path(index).exists() or self.path(index, published=True).exists():
                _fail("download_file_checkpoint_missing_repair_required")
            body = {"phase": "creating", "written": 0, "pieces": 0, "stamp": None, "pending": None}
            self.save(index, body)
        native = self.download.bundle.files[index]
        if (
            type(body.get("written")) is not int
            or type(body.get("pieces")) is not int
            or not 0 <= body["written"] <= native.size_bytes
            or not 0 <= body["pieces"] <= math.ceil(native.size_bytes / CHUNK_BYTES)
            or body["written"] != min(body["pieces"] * CHUNK_BYTES, native.size_bytes)
            or (
                body["phase"] in ("publishing", "complete")
                and (body["written"] != native.size_bytes or body.get("pending") is not None)
            )
        ):
            _fail("download_file_checkpoint_invalid_repair_required")
        if body["phase"] == "writing":
            count, first, last = self.db.execute(
                "SELECT COUNT(*),MIN(idx),MAX(idx) FROM pieces WHERE file_idx=?", (index,)
            ).fetchone()
            if not body["pieces"] <= count <= body["pieces"] + 1 or (
                count and (first != 0 or last != count - 1)
            ):
                _fail("download_piece_checkpoint_missing_repair_required")
        stage, target = self.path(index), self.path(index, published=True)
        if body["phase"] == "creating":
            if not stage.exists():
                fd = os.open(stage, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
                os.close(fd)
                _sync(stage.parent)
            stamp = _stamp(stage)
            if stamp[6] != 0 or target.exists():
                _fail("download_creation_repair_required")
            body.update(phase="writing", stamp=stamp)
            self.save(index, body)
        already_complete = body["phase"] == "complete"
        if body["phase"] == "publishing":
            self.publish(index, body, recovering=True)
        elif body["phase"] == "writing" and body["pending"] is not None:
            stamp = _stamp(stage)
            if (
                stamp[:6] != body["stamp"][:6]
                or not body["written"]
                <= stamp[6]
                <= body["written"] + body["pending"]["size_bytes"]
            ):
                _fail("download_pending_append_changed_repair_required")
            with stage.open("r+b") as stream:
                stream.truncate(body["written"])
                stream.flush()
                os.fsync(stream.fileno())
            body.update(stamp=_stamp(stage), pending=None)
            self.save(index, body)
        current = target if body["phase"] == "complete" else stage
        if body["phase"] not in ("writing", "complete") or _stamp(current) != body["stamp"]:
            _fail("download_verified_file_changed_repair_required")
        if already_complete and body.get("reusable") is not True:
            # An unqualified clock never creates a stamp-only native verdict.
            # Older in-progress client checkpoints receive the same visible,
            # file-scoped qualification rather than being silently trusted.
            self.verify(index, body, reason="completed_file_identity_requires_native_check")
        return body

    def plan(self, index: int, piece: int, segment: dict) -> None:
        descriptor = _json({key: value for key, value in segment.items() if key != "url"})
        row = self.db.execute(
            "SELECT descriptor FROM pieces WHERE file_idx=? AND idx=?", (index, piece)
        ).fetchone()
        if row is not None and row != (descriptor,):
            _fail("download_remote_piece_changed")
        with self.db:
            self.db.execute(
                "INSERT OR IGNORE INTO pieces VALUES (?,?,?)", (index, piece, descriptor)
            )

    def verify(self, index: int, body: dict, *, reason: str | None = None) -> None:
        native = self.download.bundle.files[index]
        target = self.path(index, published=True)
        with TransferProgress(
            "public_model_native_file_verification", native.size_bytes, self.report
        ) as progress:
            if reason:
                progress.emit("repair_required", reason=reason)
            pin = _stamp(target)
            if pin[6] != native.size_bytes:
                _fail("download_native_size_invalid_repair_file_required")
            # Publication itself changes ctime. Qualify the final identity before
            # its first native read, never promote a pre-rename check afterward.
            reusable = verification_tick(pin[-1], progress)
            checksum, remaining = hashlib.sha256(), native.size_bytes
            with target.open("rb") as stream:
                while remaining:
                    data = stream.read(min(READ_BYTES, remaining))
                    if not data:
                        _fail("download_native_size_invalid_repair_file_required")
                    remaining -= len(data)
                    checksum.update(data)
                    progress.advance(len(data))
                if stream.read(1):
                    _fail("download_native_size_invalid_repair_file_required")
            if _stamp(target) != pin or checksum.hexdigest() != native.sha256:
                _fail("download_native_digest_invalid_repair_file_required")
            body.update(phase="complete", stamp=pin, reusable=reusable)
            self.save(index, body)

    def publish(self, index: int, body: dict, *, recovering: bool = False) -> None:
        stage, target = self.path(index), self.path(index, published=True)
        parent = self.root / "model"
        for part in Path(self.download.bundle.files[index].path).parts[:-1]:
            parent /= part
            ensure_private_directory(parent)
        if stage.exists():
            if _stamp(stage) != body["stamp"] or target.exists() or target.is_symlink():
                _fail("download_publication_conflict_repair_required")
            os.rename(stage, target)
            _sync(stage.parent)
        pin = _stamp(target)
        if pin[:8] != body["stamp"][:8]:
            _fail("download_publication_identity_changed_repair_required")
        _sync(target.parent)
        self.verify(
            index,
            body,
            reason="interrupted_publication_requires_native_check" if recovering else None,
        )

    def confirm_complete(self) -> None:
        # Earlier files can change while later files download. Recheck metadata,
        # not payloads, at the boundary where the caller receives usable output.
        with TransferProgress(
            "public_model_download_completion",
            len(self.download.bundle.files),
            self.report,
            unit="items",
            planning_unit_seconds=(0.001, 0.1),
        ) as progress:
            for index in range(len(self.download.bundle.files)):
                row = self.db.execute("SELECT body FROM files WHERE idx=?", (index,)).fetchone()
                body = None if row is None else json.loads(row[0])
                if (
                    body is None
                    or body["phase"] != "complete"
                    or _stamp(self.path(index, published=True)) != body["stamp"]
                ):
                    _fail("download_final_file_changed_repair_required")
                progress.advance(1)


def _transfer(
    client: httpx.Client,
    url: str,
    stream,
    size: int,
    start: int | None,
    total: int,
    expected_sha: str | None,
) -> bool:
    """False asks the owner to renew the same metadata, without logging the URL."""
    headers = {"Accept-Encoding": "identity"}
    if start is not None:
        headers["Range"] = f"bytes={start}-{start + size - 1}"
    try:
        with (
            video_fetch_logging(),
            client.stream("GET", _url(url), headers=headers, follow_redirects=False) as response,
        ):
            if response.status_code in (401, 403, 404, 410):
                return False
            if response.status_code != (200 if start is None else 206):
                _fail("download_payload_status_invalid_retry_unchanged")
            if (
                response.headers.get("content-encoding", "identity") != "identity"
                or response.headers.get("content-length") not in (None, str(size))
                or (
                    start is not None
                    and response.headers.get("content-range")
                    != f"bytes {start}-{start + size - 1}/{total}"
                )
            ):
                _fail("download_payload_geometry_invalid")
            received, checksum = 0, hashlib.sha256()
            for data in response.iter_raw(READ_BYTES):
                received += len(data)
                if received > size:
                    _fail("download_payload_exceeds_piece")
                stream.write(data)
                checksum.update(data)
            if received != size:
                _fail("download_payload_truncated_retry_unchanged")
            if expected_sha is not None and checksum.hexdigest() != expected_sha:
                _fail("download_chunk_digest_invalid_retry_unchanged")
            return True
    except httpx.HTTPError:
        raise PublicDownloadError(
            "download_payload_transport_unavailable_retry_unchanged"
        ) from None


def _download_file(
    client: httpx.Client,
    state: DownloadState,
    index: int,
    body: dict,
    transfer: TransferProgress,
    refresh_attempts: int,
) -> None:
    download, native = state.download, state.download.bundle.files[index]
    if body["phase"] == "complete":
        transfer.advance(native.size_bytes, restored=True)
        return
    transfer.advance(body["written"], restored=True)
    segments: dict[int, dict] = {}
    while body["written"] < native.size_bytes:
        number = body["pieces"]
        segment_index = number if download.format == "preserved_chunks" else 0
        for attempt in range(refresh_attempts + 1):
            if segment_index not in segments or attempt:
                page = download.segments(client, index, segment_index)
                segments.update({segment_index + n: item for n, item in enumerate(page)})
            original = segments[segment_index]
            if download.format == "preserved_chunks":
                segment = original
                expected = segment["sha256"]
            else:
                segment = {
                    **original,
                    "size_bytes": min(CHUNK_BYTES, native.size_bytes - body["written"]),
                    "range_start": original["range_start"] + body["written"],
                }
                expected = None  # Native whole-file verification is required before publication.
            state.plan(index, number, segment)
            stage = state.path(index)
            if _stamp(stage) != body["stamp"]:
                _fail("download_append_file_changed_repair_required")
            body["pending"] = {key: value for key, value in segment.items() if key != "url"}
            state.save(index, body)
            with stage.open("r+b") as stream:
                stream.seek(body["written"])
                complete = _transfer(
                    client,
                    segment["url"],
                    stream,
                    segment["size_bytes"],
                    segment["range_start"],
                    download.payload_bytes,
                    expected,
                )
                stream.flush()
                os.fsync(stream.fileno())
            if complete:
                body.update(
                    written=body["written"] + segment["size_bytes"],
                    pieces=number + 1,
                    stamp=_stamp(stage),
                    pending=None,
                )
                state.save(index, body)
                transfer.advance(segment["size_bytes"])
                if download.format == "preserved_chunks":
                    segments.pop(segment_index, None)
                break
            body.update(pending=None, stamp=_stamp(stage))
            state.save(index, body)
            transfer.emit("retrying", reason="renewing_expired_or_missing_transport_capability")
        else:
            _fail("download_url_renewal_exhausted_retry_unchanged")
    body["phase"] = "publishing"
    state.save(index, body)
    state.publish(index, body)


@contextmanager
def _client(client: httpx.Client | None, timeout: float):
    if client is not None:
        yield client
    else:
        with httpx.Client(timeout=timeout, follow_redirects=False, trust_env=False) as owned:
            yield owned


def download_model(
    base_url: str,
    cohort_sha256: str,
    model_sha256: str,
    output: Path,
    *,
    client: httpx.Client | None = None,
    timeout: float = 60,
    refresh_attempts: int = 3,
    repair_files: Iterable[str] = (),
    report: Callable[[dict], None] | None = None,
) -> Path:
    """Materialize manifest.json/model; resume with exactly the same arguments.

    Only explicit ``repair_files`` removes an affected owned local file. Other
    completed native verdicts and pieces remain intact. No archive is extracted,
    no model code is executed and no acceptance/certification receipt is created.
    """
    if (
        type(refresh_attempts) is not int
        or not 0 <= refresh_attempts <= 16
        or not math.isfinite(timeout)
        or timeout <= 0
    ):
        _fail("download_local_request_options_invalid")
    output = output.absolute()

    def emit(event: dict) -> None:
        parent = output
        while not parent.exists() and parent != parent.parent:
            parent = parent.parent
        event = {
            **event,
            "local_available_bytes": shutil.disk_usage(parent).free,
            "maximum_stream_buffer_bytes": READ_BYTES,
            "maximum_pending_piece_bytes": CHUNK_BYTES,
        }
        if report is None:
            _LOG.info(json.dumps(event))
        else:
            report(event)

    progress = None
    try:
        with _client(client, timeout) as session:
            with TransferProgress(
                "public_model_download_metadata", 1, emit, unit="items"
            ) as progress:
                download = Download.fetch(session, base_url, cohort_sha256, model_sha256)
                repairs = set(repair_files)
                if not repairs <= {file.path for file in download.bundle.files}:
                    _fail("download_repair_path_not_in_manifest")
                state = DownloadState(output, download, emit)
                progress.advance(1)
            try:
                with TransferProgress(
                    "public_model_download", download.payload_bytes, emit
                ) as progress:
                    for index, native in enumerate(download.bundle.files):
                        body = state.recover(index, repair=native.path in repairs)
                        _download_file(session, state, index, body, progress, refresh_attempts)
                    state.confirm_complete()
            finally:
                state.close()
    except PublicDownloadError as error:
        if progress is not None:
            progress.emit(
                "repair_required" if "repair" in str(error) else "retrying", reason=str(error)
            )
        raise
    except OSError as error:
        if error.errno in (errno.ENOSPC, errno.EDQUOT):
            reason = "download_local_space_unavailable_retry_unchanged"
            if progress is not None:
                progress.emit("retrying", reason=reason)
        else:
            reason = "download_local_state_needs_repair"
            if progress is not None:
                progress.emit("repair_required", reason=reason)
        raise PublicDownloadError(reason) from None
    except (sqlite3.Error, KeyError, TypeError, json.JSONDecodeError, ValueError):
        if progress is not None:
            progress.emit("repair_required", reason="download_local_state_needs_repair")
        raise PublicDownloadError("download_local_state_needs_repair") from None
    return output
