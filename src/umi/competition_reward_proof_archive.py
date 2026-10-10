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
from contextlib import suppress
from pathlib import Path
from threading import Lock
from typing import Annotated, Literal

from pydantic import Field, JsonValue

from .canonical_reuse import canonical_json_reuse
from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_RECIPE_BYTES,
    checked_digest,
    checked_size,
    decode_evidence,
    encode_evidence,
)
from .open_competition import digest, identity
from .private_files import (
    ensure_private_directory,
    private_path,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel

MAX_FRAME_BYTES = 64 * 1024
MAX_FIELD_BYTES = 256 * 1024**2
_MAX_PUBLISHED_OBJECTS = 4096
_MAX_READ_OBJECTS = 4096
_MAX_READ_BYTES = 32 * 1024**2
Kind = Literal["history", "endpoint", "interval", "registration"]


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


class RewardProofArchive:
    """Private immutable output and read-only imported input use separate roots.

    Each object is bounded; disk quota/headroom belongs to the owning service.
    Interrupted export retains reusable objects but publishes no partial frame.
    Transport/replication of these files is independent of proof verification.
    """

    def __init__(self, root: Path):
        self.root = Path(private_path(str(root)))
        self._published = OrderedDict()
        self._publication_lock = Lock()
        self._read_objects = OrderedDict()
        self._read_bytes = 0
        self._read_lock = Lock()
        self._pid = os.getpid()

    @staticmethod
    def _object_stamp(path):
        private_path(str(path))
        ensure_private_directory(path.parent)
        parent, info = path.parent.lstat(), path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("reward archive object is not an owned private regular file")
        return (
            str(path),
            parent.st_dev,
            parent.st_ino,
            parent.st_uid,
            parent.st_gid,
            parent.st_mode,
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

    def _path(self, kind: Kind, key: str) -> Path:
        if kind not in ("history", "endpoint", "interval", "registration"):
            raise ValueError("unknown reward archive frame kind")
        return self.root / kind / (checked_digest(key) + ".json")

    def _retain_bytes(self, raw: bytes) -> str:
        checked_size(len(raw), MAX_EVIDENCE_BYTES)
        sha = hashlib.sha256(raw).hexdigest()
        path = self.root / "objects" / (sha + ".json")
        if os.getpid() != self._pid:
            # Do not acquire a possibly inherited thread lock after fork.
            self._publish_bytes(path, raw)
            return sha
        with self._publication_lock:
            prior = self._published.pop(sha, None)
            if prior is not None:
                with suppress(OSError, ValueError):
                    if self._object_stamp(path) == prior:
                        self._published[sha] = prior
                        return sha
            verification_tick = _publication_clock_ns()
            self._publish_bytes(path, raw)
            # Only a completed durable publication creates a reusable receipt.
            # Retain bounded metadata, never object payloads or proof authority.
            with suppress(OSError, ValueError):
                stamp = self._object_stamp(path)
                # Only cache a file whose ctime predates this verification.
                # A newly written file must be checked after its creation tick;
                # waiting alone cannot make an earlier same-tick check reusable.
                if verification_tick is not None and stamp[-1] < verification_tick:
                    self._published[sha] = stamp
                    while len(self._published) > _MAX_PUBLISHED_OBJECTS:
                        self._published.popitem(last=False)
        return sha

    @staticmethod
    def _publish_bytes(path, raw):
        # Model validation and publication serialize the same hex object. Reuse
        # those exact canonical bytes within this call only; the current file,
        # publication lock, schema and durability checks still run on every retry.
        with canonical_json_reuse(maximum_bytes=32 * 1024**2):
            publish_private_model(
                path,
                _Bytes(hex=raw.hex()),
                maximum_bytes=2 * MAX_EVIDENCE_BYTES + 1024,
            )

    def _bytes(self, sha: str, maximum: int) -> bytes:
        path = self.root / "objects" / (checked_digest(sha) + ".json")
        checked_size(maximum, MAX_EVIDENCE_BYTES)
        if os.getpid() != self._pid:
            # Inherited locks and verification receipts are not usable after fork.
            return self._read_object(path, sha, maximum)
        with self._read_lock:
            prior = self._read_objects.pop(sha, None)
            if prior is not None:
                self._read_bytes -= len(prior[1])
            stamp = self._object_stamp(path)
            if prior is not None and prior[0] == stamp:
                checked_size(len(prior[1]), maximum)
                self._read_objects[sha] = prior
                self._read_bytes += len(prior[1])
                return prior[1]
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
            return raw

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

    def write(self, kind: Kind, key: str, *, context: dict, fields: dict[str, bytes]) -> None:
        path = self._path(kind, key)
        if len(fields) > 4:
            raise ValueError("reward archive field count exceeds its bound")
        refs = {}
        for name, raw in fields.items():
            if type(raw) is not bytes:
                raise ValueError("reward archive requires original byte evidence")
            checked_size(len(raw), MAX_FIELD_BYTES)
            parts = []
            for offset in range(0, len(raw), MAX_EVIDENCE_BYTES):
                encoded = encode_evidence(raw[offset : offset + MAX_EVIDENCE_BYTES], kind="proof")
                for value in encoded.objects.values():
                    self._retain_bytes(value)
                parts.append(
                    _Part(
                        sha256=encoded.sha256,
                        expanded_bytes=encoded.expanded_bytes,
                        recipe_sha256=self._retain_bytes(encoded.recipe),
                    )
                )
            refs[name] = tuple(parts)
        publish_private_model(
            path,
            _Frame(
                schema="umi-reward-proof-frame/1", kind=kind, key=key, context=context, fields=refs
            ),
            maximum_bytes=MAX_FRAME_BYTES,
        )

    def read(
        self, kind: Kind, key: str, *, bounds: dict[str, int]
    ) -> tuple[dict, dict[str, bytes]]:
        frame = read_private_model(self._path(kind, key), _Frame, maximum_bytes=MAX_FRAME_BYTES)
        if frame.kind != kind or frame.key != key or set(frame.fields) != set(bounds):
            raise ValueError("reward archive frame changes its requested domain")
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
                    self._bytes(p.recipe_sha256, MAX_RECIPE_BYTES),
                    sha256=p.sha256,
                    expanded_bytes=p.expanded_bytes,
                    kind="proof",
                    resolve=self._bytes,
                )
                for p in parts
            )
        return frame.context, result

    def interval(self, key: str) -> dict:
        context, _ = self.read("interval", key, bounds={})
        return context

    def retain_interval(self, key: str, value) -> None:
        self.write("interval", key, context=value.model_dump(mode="json", by_alias=True), fields={})
