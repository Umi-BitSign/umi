"""Open an existing promotion source without initializing or repairing its owner.

Use the source's exact policy, role, launch and checkpoint configuration. This
is a native read of retained history, not an intake writer or a chain capability.
Promotion receipt authentication remains in the ordinary store readers.
"""

from __future__ import annotations

import os
import sqlite3
import stat
from typing import TYPE_CHECKING

from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_store import CompetitionStore


def connect_existing(store: CompetitionStore) -> sqlite3.Connection:
    path = store.path
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != os.geteuid()
        or info.st_nlink != 1
        or info.st_mode & 0o077
    ):
        raise ValueError("existing competition database must be private and owned")
    connection = sqlite3.connect(
        path.as_uri() + "?mode=ro", uri=True, timeout=10, isolation_level=None
    )
    try:
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        current = path.lstat()
        if (current.st_dev, current.st_ino) != (info.st_dev, info.st_ino):
            raise ValueError("existing competition database identity changed")
        bindings = dict(
            connection.execute(
                "SELECT key,value FROM metadata WHERE key IN "
                "('policy','role','public_launch_identity','submission_head_checkpoint_binding',"
                "'submission_head_checkpoint_required','historical_intake_archives',"
                "'retained_submission_head')"
            )
        )
        if bindings.get("policy") != store._deal_policy_binding():
            raise ValueError("existing reader requires the current migrated policy binding")
        if bindings.get("role") != store.role:
            raise ValueError("existing reader has a different store role")
        if bindings.get("public_launch_identity") != store.public_launch_id:
            raise ValueError("existing reader requires its exact public launch")
        for key in ("submission_head_checkpoint_binding", "submission_head_checkpoint_required"):
            if bindings.get(key) != store._submission_checkpoint_binding:
                raise ValueError("existing reader requires its configured submission checkpoint")
        archives = store.historical_intake_archive_bindings
        expected = (
            None
            if archives is None
            else canonical_json_bytes(
                [item.model_dump(mode="json", by_alias=True) for item in archives]
            ).decode()
        )
        if bindings.get("historical_intake_archives") != expected:
            raise ValueError("existing reader requires its historical intake archive bindings")
        for table in store._WRITER_FENCED_TABLES:
            for operation in ("INSERT", "UPDATE", "DELETE"):
                name = f"writer_2_{operation.lower()}_{table}"
                sql = (
                    f"CREATE TRIGGER {name} BEFORE {operation} ON {table} "
                    "BEGIN SELECT CASE WHEN umi_writer_generation() != 2 "
                    "THEN RAISE(ABORT, 'competition writer generation mismatch') END; END"
                )
                if connection.execute(
                    "SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?", (name,)
                ).fetchone() != (sql,):
                    raise ValueError("existing competition writer fence changed")
        checkpoint = store._submission_checkpoint
        if checkpoint is not None:
            value = checkpoint.load()
            if value is None:
                raise ValueError("existing reader submission checkpoint is missing")
            head = store._submission_head_body(connection)
            if (
                value.public_launch_sha256 != store.public_launch_id
                or value.submission_sha256s != store._submission_ids(connection)
                or bindings.get("retained_submission_head") != canonical_json_bytes(head).decode()
            ):
                raise ValueError("existing reader submission checkpoint differs from ledger")
        return connection
    except BaseException:
        connection.close()
        raise
