"""Private, immutable per-round artifact discovery; no private evidence or replay."""

from __future__ import annotations

import hashlib
import os
import re
import stat
import tempfile
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_public_results import (
    MAXIMUM_PUBLIC_RESULTS_BYTES,
    PublicResultsSource,
    PublicSettlementScores,
)
from .open_competition import Hex32, StrictProtocolModel
from .protocol import canonical_json_bytes


class PublicResultsDirectory(StrictProtocolModel):
    directory: Annotated[str, Field(min_length=1, max_length=4096)]

    @model_validator(mode="after")
    def absolute_directory(self):
        path = Path(self.directory)
        if not path.is_absolute() or path == Path(path.anchor) or ".." in path.parts:
            raise ValueError("public results need a dedicated absolute directory")
        return self


class PublicResultsDescriptor(StrictProtocolModel):
    schema_: Literal["umi-public-results-descriptor/1"] = Field(alias="schema")
    round_sha256: Hex32
    artifact_sha256: Hex32


def owned_directory(path: Path, *, create: bool = False) -> None:
    if not path.is_absolute() or path.resolve() != path or path == Path(path.anchor):
        raise ValueError("public results directory must not traverse symlinks")
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("public results directory must be private and operator-owned")


def read_owned_file(path: Path, maximum: int) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
            or info.st_size > maximum
        ):
            raise ValueError("public results file has unsafe ownership, layout or size")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("public results file exceeds its byte bound")
    return raw


def atomic_write(path: Path, raw: bytes, *, immutable: bool = True) -> None:
    """Called with the directory's exporter lease; never replace another artifact."""
    if immutable:
        try:
            previous = read_owned_file(path, max(len(raw), MAXIMUM_PUBLIC_RESULTS_BYTES))
        except FileNotFoundError:
            pass
        else:
            if previous != raw:
                raise ValueError("public results publication conflicts with retained bytes")
            return
    fd, pending = tempfile.mkstemp(prefix=".publish-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        Path(pending).unlink(missing_ok=True)


def discover_source(config: PublicResultsDirectory, round_id: str) -> PublicResultsSource | None:
    if re.fullmatch(r"[0-9a-f]{64}", round_id) is None:
        return None
    root = Path(config.directory)
    try:
        owned_directory(root)
        owned_directory(root / "rounds")
        raw = read_owned_file(root / "rounds" / (round_id + ".json"), 2048)
    except FileNotFoundError:
        return None
    descriptor = PublicResultsDescriptor.model_validate_json(raw)
    if descriptor.round_sha256 != round_id:
        raise ValueError("public results descriptor belongs to another round")
    owned_directory(root / "artifacts")
    return PublicResultsSource(
        round_sha256=round_id,
        artifact_sha256=descriptor.artifact_sha256,
        path=str(root / "artifacts" / (descriptor.artifact_sha256 + ".json")),
    )


def resolve_source(config, pinned, round_id):
    dynamic = None if config is None else discover_source(config, round_id)
    fixed = pinned.get(round_id)
    if (
        fixed is not None
        and dynamic is not None
        and (fixed.artifact_sha256 != dynamic.artifact_sha256)
    ):
        raise ValueError("dynamic public results conflict with the configured artifact")
    source = fixed or dynamic
    if dynamic is not None:
        raw = read_owned_file(Path(dynamic.path), MAXIMUM_PUBLIC_RESULTS_BYTES)
        if hashlib.sha256(raw).hexdigest() != dynamic.artifact_sha256:
            raise ValueError("dynamic public results artifact digest differs")
    return source


def publish_scores(config: PublicResultsDirectory, scores: PublicSettlementScores):
    """Install artifact before descriptor. Caller owns the exporter lease."""
    scores = PublicSettlementScores.model_validate_json(canonical_json_bytes(scores))
    raw = canonical_json_bytes(scores)
    if len(raw) > MAXIMUM_PUBLIC_RESULTS_BYTES:
        raise ValueError("public results exceed their byte bound")
    descriptor = PublicResultsDescriptor(
        schema="umi-public-results-descriptor/1",
        round_sha256=scores.round_sha256,
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
    )
    root = Path(config.directory)
    for path in (root, root / "artifacts", root / "rounds"):
        owned_directory(path, create=True)
    descriptor_path = root / "rounds" / (scores.round_sha256 + ".json")
    try:
        previous = read_owned_file(descriptor_path, 2048)
    except FileNotFoundError:
        pass
    else:
        if previous != canonical_json_bytes(descriptor):
            raise ValueError("public results descriptor conflicts with retained bytes")
    atomic_write(root / "artifacts" / (descriptor.artifact_sha256 + ".json"), raw)
    atomic_write(descriptor_path, canonical_json_bytes(descriptor))
    return descriptor
