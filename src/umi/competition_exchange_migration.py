"""Explicit exchange launch migration following a committed intake amendment.

This operation requires stopped writers and verified backups. It never applies
an intake amendment, invents a finalized observation, or resets delivery state.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
from pathlib import Path

from .competition_launch_amendment import SignedLaunchAmendment, verify_launch_amendment
from .competition_submission_checkpoint import SubmissionHeadCheckpointFile
from .open_competition import CompetitionPolicy, digest
from .private_files import MAX_PRIVATE_BYTES, private_path
from .protocol import canonical_json_bytes

TABLE = "exchange_launch_migrations"
JOURNAL_TABLES = ("binding", "events", "audience", "collected", "highwater")
OPERATIONAL_FIELDS = {"maximum_orders", "maximum_events", "maximum_bytes", "port", "host"}


def exchange_binding(config) -> bytes:
    return canonical_json_bytes(
        config.model_dump(mode="json", by_alias=True, exclude=OPERATIONAL_FIELDS)
    )


def launch_fences() -> dict[str, str]:
    fences = {}
    for table in (*JOURNAL_TABLES, TABLE):
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"exchange_launch_writer_{table}_{operation.lower()}"
            fences[name] = (
                f"CREATE TRIGGER {name} BEFORE {operation} ON {table} "
                "BEGIN SELECT CASE WHEN umi_exchange_launch_writer("
                "(SELECT body FROM binding)) IS NOT 1 "
                "THEN RAISE(ABORT,'stale exchange launch writer') END; END"
            )
    for operation in ("UPDATE", "DELETE"):
        name = f"exchange_launch_immutable_{operation.lower()}"
        fences[name] = (
            f"CREATE TRIGGER {name} BEFORE {operation} ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT,'immutable exchange launch migration'); END"
        )
    return fences


def check_launch_fences(db: sqlite3.Connection) -> bool:
    """A migrated namespace must retain every old-writer SQL fence."""
    if not db.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    ).fetchone():
        return False
    retained = dict(db.execute("SELECT name, sql FROM sqlite_master WHERE type='trigger'"))
    if any(retained.get(name) != sql for name, sql in launch_fences().items()):
        raise ValueError("exchange launch writer fences changed")
    return True


def _existing_private_database(path: Path) -> None:
    private_path(str(path))
    directory = path.parent.stat()
    if directory.st_uid != os.getuid() or directory.st_mode & 0o077:
        raise ValueError("migration requires an owned private database directory")
    for suffix in ("", "-journal", "-wal", "-shm"):
        item = Path(str(path) + suffix)
        if suffix and not item.exists() and not item.is_symlink():
            continue
        info = item.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("migration requires an existing owned private database")


def _retained_authorization(db, previous, replacement, policy):
    metadata = dict(
        db.execute(
            "SELECT key,value FROM metadata WHERE key IN "
            "('policy','role','public_launch_identity',"
            "'submission_head_checkpoint_binding','submission_head_checkpoint_required')"
        )
    )
    checkpoint_file = SubmissionHeadCheckpointFile(
        Path(replacement.submission_head_checkpoint_directory),
        policy_sha256=digest(policy),
        public_launch_sha256=digest(replacement.public_launch),
    )
    if metadata != {
        "policy": f"writer-2:{digest(policy)}",
        "role": "intake",
        "public_launch_identity": digest(replacement.public_launch),
        "submission_head_checkpoint_binding": checkpoint_file.binding_sha256,
        "submission_head_checkpoint_required": checkpoint_file.binding_sha256,
    }:
        raise ValueError("intake has not committed this policy and replacement launch")
    checkpoint = checkpoint_file.load()
    if checkpoint is None or checkpoint.public_launch_sha256 != digest(replacement.public_launch):
        raise ValueError("intake launch amendment checkpoint is missing or stale")
    rows = db.execute(
        "SELECT sequence,digest,schedule,substr(body,1,?),length(body) "
        "FROM public_launch_history ORDER BY sequence DESC LIMIT 2",
        (MAX_PRIVATE_BYTES + 1,),
    ).fetchall()
    if len(rows) != 2 or rows[1][0] < 1 or rows[0][0] != rows[1][0] + 1:
        raise ValueError("intake launch amendment is not an immediate retained successor")
    for row, expected in zip(
        rows, (replacement.public_launch, previous.public_launch), strict=True
    ):
        if row[1:] != (
            digest(expected),
            digest(expected.round_schedule),
            canonical_json_bytes(expected),
            len(canonical_json_bytes(expected)),
        ):
            raise ValueError("intake launch history differs from the exchange transition")
    row = db.execute(
        "SELECT substr(body,1,?),length(body) FROM public_launch_amendments WHERE successor=?",
        (MAX_PRIVATE_BYTES + 1, digest(replacement.public_launch)),
    ).fetchone()
    if row is None or not 1 <= row[1] <= MAX_PRIVATE_BYTES:
        raise ValueError("intake has no bounded retained signed launch amendment")
    signed = SignedLaunchAmendment.model_validate_json(row[0])
    if canonical_json_bytes(signed) != row[0]:
        raise ValueError("retained launch amendment is not canonical")
    verify_launch_amendment(signed, previous.public_launch, replacement.public_launch, policy)
    # load() validates policy and the canonical exact admission commitment.
    return {
        "schema": "umi-exchange-retained-launch-migration/1",
        "policy_sha256": digest(policy),
        "previous_launch_sha256": digest(previous.public_launch),
        "replacement_launch_sha256": digest(replacement.public_launch),
        "previous_binding_sha256": hashlib.sha256(exchange_binding(previous)).hexdigest(),
        "replacement_binding_sha256": hashlib.sha256(exchange_binding(replacement)).hexdigest(),
        "intake_history_sequence": rows[0][0],
        "signed_amendment": signed.model_dump(mode="json", by_alias=True),
    }


def migrate_exchange_launch(previous, replacement, policy, *, confirmed: bool) -> dict:
    """Migrate exactly one launch, after native intake migration has completed.

    Both configs must name the same existing namespace and differ only in
    public_launch. The caller must stop intake and exchange writers and verify
    backups of both ledgers and the independent submission checkpoint. A retry
    is idempotent only with the exact retained authorization. Old binaries are
    write-fenced after commit; restarting requires this control release.
    """
    from .competition_exchange import ExchangeConfig

    if confirmed is not True:
        raise ValueError("exchange migration requires quiesced writers and verified backups")
    previous = ExchangeConfig.model_validate_json(canonical_json_bytes(previous))
    replacement = ExchangeConfig.model_validate_json(canonical_json_bytes(replacement))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    if (
        previous.public_launch is None
        or replacement.public_launch is None
        or previous.public_launch == replacement.public_launch
        or previous.model_dump(exclude={"public_launch"})
        != replacement.model_dump(exclude={"public_launch"})
        or replacement.policy_sha256 != digest(policy)
    ):
        raise ValueError("exchange migration must change only an existing public launch")
    intake_path = Path(replacement.intake_directory) / "competition.sqlite3"
    exchange_path = Path(replacement.state_directory) / "exchange.sqlite3"
    _existing_private_database(intake_path)
    _existing_private_database(exchange_path)
    old_binding, new_binding = exchange_binding(previous), exchange_binding(replacement)
    intake = sqlite3.connect(intake_path.as_uri() + "?mode=ro", uri=True, isolation_level=None)
    db = None
    try:
        intake.execute("PRAGMA query_only=ON")
        intake.execute("BEGIN")
        receipt = _retained_authorization(intake, previous, replacement, policy)
        body = canonical_json_bytes(receipt)
        db = sqlite3.connect(exchange_path.as_uri() + "?mode=rw", uri=True, isolation_level=None)
        db.create_function(
            "umi_exchange_launch_writer", 1, lambda b: b in (old_binding, new_binding)
        )
        db.execute("PRAGMA synchronous=FULL")
        db.execute("BEGIN IMMEDIATE")
        migrated = check_launch_fences(db)
        binding = db.execute("SELECT body FROM binding").fetchall()
        if binding == [(new_binding,)]:
            if not migrated or db.execute(
                f"SELECT body FROM {TABLE} WHERE successor_launch=?",
                (digest(replacement.public_launch),),
            ).fetchone() != (body,):
                raise ValueError("exchange migration retry differs from retained authorization")
            db.rollback()
            return {"status": "already_migrated", **receipt}
        if binding != [(old_binding,)]:
            raise ValueError("exchange configuration changed before launch migration")
        db.execute(
            f"CREATE TABLE IF NOT EXISTS {TABLE} (sequence INTEGER PRIMARY KEY, "
            "previous_launch TEXT UNIQUE NOT NULL, successor_launch TEXT UNIQUE NOT NULL, "
            "body BLOB NOT NULL)"
        )
        db.execute("UPDATE binding SET body=?", (new_binding,))
        db.execute(
            f"INSERT INTO {TABLE} (previous_launch,successor_launch,body) VALUES (?,?,?)",
            (digest(previous.public_launch), digest(replacement.public_launch), body),
        )
        if not migrated:
            for sql in launch_fences().values():
                db.execute(sql)
        check_launch_fences(db)
        db.commit()
        return {"status": "migrated", **receipt}
    finally:
        if db is not None:
            db.close()
        intake.close()
