"""Restart-safe, bounded settlement discovery and immutable score publication."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import sqlite3
import stat
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_policy_lineage import PolicyLineage
from .competition_public_results import public_results_page
from .competition_public_results_directory import (
    PublicResultsDirectory,
    atomic_write,
    discover_source,
    owned_directory,
    publish_scores,
    read_owned_file,
)
from .competition_public_results_export import (
    PublicResultsExportLimits,
    export_round,
    readonly_snapshot,
)
from .competition_round_discovery import MAXIMUM_ROUND_BYTES
from .open_competition import CompetitionPolicy, EvaluationRound, Hex32, StrictProtocolModel, digest
from .policy import ScoringPolicy, scoring_policy_hash, validate_scoring_runtime
from .protocol import canonical_json_bytes

FilePath = Annotated[str, Field(min_length=1, max_length=4096)]


class PublicResultsPublisherConfig(StrictProtocolModel):
    schema_: Literal["umi-public-results-publisher-config/1"] = Field(alias="schema")
    database: FilePath
    policy_path: FilePath
    policy_sha256: Hex32
    scoring_policy_path: FilePath
    scoring_policy_sha256: Hex32
    predecessor_policy_paths: Annotated[tuple[FilePath, ...], Field(max_length=8)] = ()
    public_results_directory: PublicResultsDirectory
    limits: PublicResultsExportLimits = Field(default_factory=PublicResultsExportLimits)
    maximum_rounds_per_poll: Annotated[int, Field(ge=1, le=100)] = 8
    poll_seconds: Annotated[int, Field(ge=1, le=3600)] = 60

    @model_validator(mode="after")
    def paths(self):
        for value in (
            self.database,
            self.policy_path,
            self.scoring_policy_path,
            *self.predecessor_policy_paths,
        ):
            path = Path(value)
            if not path.is_absolute() or path == Path(path.anchor) or ".." in path.parts:
                raise ValueError("public results publisher requires absolute file paths")
        return self


def read_config_file(path: Path, maximum: int = 4 * 1024**2) -> bytes:
    """Policies may be public-readable; reject links, special files and oversize."""
    if not path.is_absolute() or path.resolve() != path:
        raise ValueError("configuration must be absolute and not traverse symlinks")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > maximum:
            raise ValueError("invalid or oversized publisher configuration")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError("oversized publisher configuration")
    return raw


@contextmanager
def publisher_lease(root: Path):
    owned_directory(root, create=True)
    fd = os.open(
        root / "publisher.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600
    )
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid():
            raise ValueError("unsafe publisher lease")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        os.close(fd)


class PublicResultsPublisher:
    def __init__(self, config: PublicResultsPublisherConfig):
        self.config = PublicResultsPublisherConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(
            read_config_file(Path(config.policy_path))
        )
        self.scoring = ScoringPolicy.model_validate_json(
            read_config_file(Path(config.scoring_policy_path))
        )
        if (
            digest(self.policy) != config.policy_sha256
            or scoring_policy_hash(self.scoring) != config.scoring_policy_sha256
        ):
            raise ValueError("publisher policy digest differs from configuration")
        self.predecessors = tuple(
            CompetitionPolicy.model_validate_json(read_config_file(Path(path)))
            for path in config.predecessor_policy_paths
        )
        PolicyLineage(self.policy, self.predecessors)
        validate_scoring_runtime(self.scoring)
        self.root = Path(config.public_results_directory.directory)
        self.cursor_binding = hashlib.sha256(
            canonical_json_bytes(
                [config.database, config.policy_sha256, config.scoring_policy_sha256]
            )
        ).hexdigest()

    def poll_once(self) -> dict:
        """A broken round advances the cursor too; later rounds cannot starve.

        Wrap at the end so late settlements and repaired failures are retried.
        The descriptor is the durable completion marker; cursor loss is harmless.
        """
        report = dict(
            schema="umi-public-results-publisher-status/1",
            published=[],
            retained=[],
            held=[],
            skipped_policy=[],
            chain_submission_authorized=False,
        )
        with publisher_lease(self.root):
            try:
                cursor = json.loads(read_owned_file(self.root / "cursor.json", 2048))
            except FileNotFoundError:
                cursor = dict(binding=self.cursor_binding, after="")
            if (
                not isinstance(cursor, dict)
                or set(cursor) != {"binding", "after"}
                or cursor["binding"] != self.cursor_binding
                or not isinstance(cursor["after"], str)
                or (
                    cursor["after"]
                    and (
                        len(cursor["after"]) != 64
                        or any(c not in "0123456789abcdef" for c in cursor["after"])
                    )
                )
            ):
                raise ValueError("public results publisher cursor binding differs")
            with readonly_snapshot(Path(self.config.database)) as db:
                rounds = db.execute(
                    "SELECT s.round, CASE WHEN length(r.body)<=? THEN r.body END "
                    "FROM competition_settlements s LEFT JOIN rounds r ON r.digest=s.round "
                    "WHERE s.round>? "
                    "ORDER BY s.round LIMIT ?",
                    (
                        MAXIMUM_ROUND_BYTES,
                        cursor["after"],
                        self.config.maximum_rounds_per_poll,
                    ),
                ).fetchall()
            for round_id, round_raw in rounds:
                try:
                    if round_raw is None:
                        raise ValueError("retained round unavailable or oversized")
                    round_ = EvaluationRound.model_validate_json(round_raw)
                    if digest(round_) != round_id:
                        raise ValueError("retained round digest mismatch")
                    if round_.policy_sha256 != self.config.policy_sha256:
                        report["skipped_policy"].append(round_id)
                        continue
                    existing = discover_source(self.config.public_results_directory, round_id)
                    if existing is not None and Path(existing.path).exists():
                        read_owned_file(Path(existing.path), 8 * 1024**2)
                        public_results_page(Path(self.config.database), existing, limit=1)
                        report["retained"].append(round_id)
                    else:
                        scores = export_round(
                            Path(self.config.database),
                            round_id,
                            policy=self.policy,
                            scoring_policy=self.scoring,
                            predecessors=self.predecessors,
                            limits=self.config.limits,
                        )
                        publish_scores(self.config.public_results_directory, scores)
                        report["published"].append(round_id)
                except (OSError, ValueError, RuntimeError, sqlite3.Error) as error:
                    # Error messages can contain private paths or validation inputs.
                    report["held"].append(
                        dict(round_sha256=round_id, error_type=type(error).__name__)
                    )
                finally:
                    cursor["after"] = round_id
                    atomic_write(
                        self.root / "cursor.json", canonical_json_bytes(cursor), immutable=False
                    )
            if not rounds:
                cursor["after"] = ""
                atomic_write(
                    self.root / "cursor.json", canonical_json_bytes(cursor), immutable=False
                )
        return report
