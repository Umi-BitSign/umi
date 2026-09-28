"""Portable original proof content, separate from live recovery databases.

Frames are untrusted lookup hints. The receiving history/coverage consumer must
replay native proofs before retaining evidence or crediting an interval. Flat
recipes use the existing bounded codec; no archive extraction or SQLite copy
is needed to deliver the files to another host.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, JsonValue

from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_RECIPE_BYTES,
    checked_digest,
    checked_size,
    decode_evidence,
    encode_evidence,
)
from .open_competition import digest, identity
from .private_files import private_path, publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel

MAX_FRAME_BYTES = 64 * 1024
MAX_FIELD_BYTES = 256 * 1024**2
Kind = Literal["history", "endpoint", "interval"]


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

    def _path(self, kind: Kind, key: str) -> Path:
        if kind not in ("history", "endpoint", "interval"):
            raise ValueError("unknown reward archive frame kind")
        return self.root / kind / (checked_digest(key) + ".json")

    def _retain_bytes(self, raw: bytes) -> str:
        checked_size(len(raw), MAX_EVIDENCE_BYTES)
        sha = hashlib.sha256(raw).hexdigest()
        publish_private_model(
            self.root / "objects" / (sha + ".json"),
            _Bytes(hex=raw.hex()),
            maximum_bytes=2 * MAX_EVIDENCE_BYTES + 1024,
        )
        return sha

    def _bytes(self, sha: str, maximum: int) -> bytes:
        value = read_private_model(
            self.root / "objects" / (checked_digest(sha) + ".json"),
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
