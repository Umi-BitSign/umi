"""Durable one-writer state for the public-pilot authorization queue."""

from __future__ import annotations

import os
import sqlite3
import stat
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Literal

from .encoding import account_id32
from .public_pilot_authorization import VerifiedPublicPilotAuthorization
from .public_pilot_readiness import ReadyToIssuePayload

AuthorizationState = Literal[
    "queued",
    "processing",
    "case_ready",
    "attempt_started",
    "complete",
    "incomplete",
    "superseded",
]


@dataclass(frozen=True, slots=True)
class QueuedAuthorization:
    authorization_id: str
    action: Literal["ready_for_case", "ready_to_issue"]
    issue_id: int
    issue_node_id: str
    issue_number: int
    bot_comment_id: int
    command_comment_id: int
    miner_hotkey: str
    miner_account_id32: str
    expected_miner_uid: int
    umi_revision: str
    predecessor_authorization_id: str | None
    case_manifest_sha256: str | None
    expected_origin: str | None
    state: AuthorizationState


@dataclass(frozen=True, slots=True)
class PreparedCaseState:
    authorization_id: str
    miner_hotkey: str
    miner_account_id32: str
    expected_miner_uid: int
    case_root: str
    case_manifest_sha256: str
    case_archive_sha256: str
    case_archive_size_bytes: int
    case_archive_url: str
    expected_origin: str
    response_close_round: int
    reveal_round: int
    response_close_unix_s: int
    reveal_unix_s: int
    active: bool


_SCHEMA = """
CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS authorizations (
    authorization_id TEXT PRIMARY KEY,
    action TEXT NOT NULL CHECK (action IN ('ready_for_case', 'ready_to_issue')),
    issue_id INTEGER NOT NULL,
    issue_node_id TEXT NOT NULL,
    issue_number INTEGER NOT NULL,
    bot_comment_id INTEGER NOT NULL UNIQUE,
    command_comment_id INTEGER NOT NULL UNIQUE,
    miner_hotkey TEXT NOT NULL,
    miner_account_id32 TEXT NOT NULL,
    expected_miner_uid INTEGER NOT NULL,
    umi_revision TEXT NOT NULL,
    predecessor_authorization_id TEXT,
    case_manifest_sha256 TEXT,
    expected_origin TEXT,
    state TEXT NOT NULL CHECK (state IN (
        'queued', 'processing', 'case_ready', 'attempt_started', 'complete',
        'incomplete', 'superseded'
    )),
    inserted_unix_s INTEGER NOT NULL,
    updated_unix_s INTEGER NOT NULL,
    result_sha256 TEXT
) STRICT;
CREATE TABLE IF NOT EXISTS prepared_cases (
    authorization_id TEXT PRIMARY KEY REFERENCES authorizations(authorization_id),
    miner_hotkey TEXT NOT NULL,
    miner_account_id32 TEXT NOT NULL,
    expected_miner_uid INTEGER NOT NULL,
    case_root TEXT NOT NULL,
    case_manifest_sha256 TEXT NOT NULL,
    case_archive_sha256 TEXT NOT NULL,
    case_archive_size_bytes INTEGER NOT NULL,
    case_archive_url TEXT NOT NULL,
    expected_origin TEXT NOT NULL,
    response_close_round INTEGER NOT NULL,
    reveal_round INTEGER NOT NULL,
    response_close_unix_s INTEGER NOT NULL,
    reveal_unix_s INTEGER NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1))
) STRICT;
CREATE UNIQUE INDEX IF NOT EXISTS one_active_public_pilot_case
ON prepared_cases(active) WHERE active = 1;
CREATE UNIQUE INDEX IF NOT EXISTS one_processing_public_pilot_transition
ON authorizations(state) WHERE state = 'processing';
CREATE TABLE IF NOT EXISTS completed_miners (
    miner_account_id32 TEXT PRIMARY KEY,
    authorization_id TEXT NOT NULL UNIQUE REFERENCES authorizations(authorization_id)
) STRICT;
CREATE TABLE IF NOT EXISTS seen_bot_comments (
    comment_id INTEGER PRIMARY KEY,
    disposition TEXT NOT NULL CHECK (disposition IN ('accepted', 'ignored')),
    reason_code TEXT NOT NULL
) STRICT;
CREATE TABLE IF NOT EXISTS runtime_state (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
) STRICT;
"""


class PublicPilotAutomationState:
    """SQLite-backed queue with a global active-case and per-miner attempt guard."""

    def __init__(self, path: Path, *, metadata: dict[str, str]) -> None:
        destination = path.expanduser().resolve(strict=False)
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        parent = destination.parent.lstat()
        if (
            destination.parent.is_symlink()
            or not stat.S_ISDIR(parent.st_mode)
            or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077
        ):
            raise ValueError("public-pilot state directory is unsafe")
        if destination.exists():
            current = destination.lstat()
            if (
                destination.is_symlink()
                or not stat.S_ISREG(current.st_mode)
                or current.st_uid != os.geteuid()
                or current.st_mode & 0o077
            ):
                raise ValueError("public-pilot state database is unsafe")
        self.path = destination
        self._db = sqlite3.connect(destination, isolation_level=None, timeout=30)
        try:
            os.chmod(destination, 0o600)
            self._db.execute("PRAGMA trusted_schema = OFF")
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.execute("PRAGMA synchronous = FULL")
            self._db.executescript(_SCHEMA)
            self._bind_metadata(metadata)
        except BaseException:
            self._db.close()
            raise

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> PublicPilotAutomationState:
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def _bind_metadata(self, metadata: dict[str, str]) -> None:
        if not metadata or any(
            not key or not isinstance(value, str) for key, value in metadata.items()
        ):
            raise ValueError("public-pilot state metadata is invalid")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            existing = dict(self._db.execute("SELECT key, value FROM metadata").fetchall())
            if existing and existing != metadata:
                raise ValueError("public-pilot state belongs to another deployment")
            if not existing:
                self._db.executemany(
                    "INSERT INTO metadata(key, value) VALUES (?, ?)",
                    tuple(sorted(metadata.items())),
                )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    @staticmethod
    def _row(row: tuple[object, ...]) -> QueuedAuthorization:
        return QueuedAuthorization(
            authorization_id=str(row[0]),
            action=str(row[1]),  # type: ignore[arg-type]
            issue_id=int(row[2]),
            issue_node_id=str(row[3]),
            issue_number=int(row[4]),
            bot_comment_id=int(row[5]),
            command_comment_id=int(row[6]),
            miner_hotkey=str(row[7]),
            miner_account_id32=str(row[8]),
            expected_miner_uid=int(row[9]),
            umi_revision=str(row[10]),
            predecessor_authorization_id=None if row[11] is None else str(row[11]),
            case_manifest_sha256=None if row[12] is None else str(row[12]),
            expected_origin=None if row[13] is None else str(row[13]),
            state=str(row[14]),  # type: ignore[arg-type]
        )

    def enqueue(self, verified: VerifiedPublicPilotAuthorization) -> bool:
        authorization = verified.authorization
        readiness = verified.readiness.payload
        case_manifest_sha256 = (
            readiness.case_manifest_sha256 if isinstance(readiness, ReadyToIssuePayload) else None
        )
        expected_origin = (
            readiness.expected_origin if isinstance(readiness, ReadyToIssuePayload) else None
        )
        now = int(time.time())
        values = (
            authorization.authorization_id,
            authorization.action,
            authorization.issue_id,
            authorization.issue_node_id,
            authorization.issue_number,
            verified.bot_comment.id,
            authorization.command_comment_id,
            verified.enrollment.miner_hotkey,
            account_id32(verified.enrollment.miner_hotkey).hex(),
            verified.enrollment.uid,
            authorization.umi_revision,
            authorization.predecessor_authorization_id,
            case_manifest_sha256,
            expected_origin,
            "queued",
            now,
            now,
        )
        cursor = self._db.execute(
            """
            INSERT OR IGNORE INTO authorizations(
                authorization_id, action, issue_id, issue_node_id, issue_number,
                bot_comment_id, command_comment_id, miner_hotkey, miner_account_id32,
                expected_miner_uid, umi_revision, predecessor_authorization_id,
                case_manifest_sha256, expected_origin, state,
                inserted_unix_s, updated_unix_s
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            values,
        )
        if cursor.rowcount == 0:
            row = self.get(authorization.authorization_id)
            if row is None or row.bot_comment_id != verified.bot_comment.id:
                raise ValueError("public-pilot authorization conflicts with durable state")
            return False
        return True

    def get(self, authorization_id: str) -> QueuedAuthorization | None:
        row = self._db.execute(
            """
            SELECT authorization_id, action, issue_id, issue_node_id, issue_number,
                   bot_comment_id, command_comment_id, miner_hotkey, miner_account_id32,
                   expected_miner_uid, umi_revision, predecessor_authorization_id,
                   case_manifest_sha256, expected_origin, state
            FROM authorizations WHERE authorization_id = ?
            """,
            (authorization_id,),
        ).fetchone()
        return None if row is None else self._row(row)

    def in_states(self, *states: AuthorizationState) -> tuple[QueuedAuthorization, ...]:
        if not states:
            return ()
        if any(
            state
            not in {
                "queued",
                "processing",
                "case_ready",
                "attempt_started",
                "complete",
                "incomplete",
                "superseded",
            }
            for state in states
        ):
            raise ValueError("authorization state is invalid")
        placeholders = ",".join("?" for _ in states)
        rows = self._db.execute(
            f"""
            SELECT authorization_id, action, issue_id, issue_node_id, issue_number,
                   bot_comment_id, command_comment_id, miner_hotkey, miner_account_id32,
                   expected_miner_uid, umi_revision, predecessor_authorization_id,
                   case_manifest_sha256, expected_origin, state
            FROM authorizations WHERE state IN ({placeholders})
            ORDER BY bot_comment_id
            """,
            states,
        ).fetchall()
        return tuple(self._row(row) for row in rows)

    def bot_comment_seen(self, comment_id: int) -> bool:
        return (
            self._db.execute(
                "SELECT 1 FROM seen_bot_comments WHERE comment_id = ?", (comment_id,)
            ).fetchone()
            is not None
        )

    def record_bot_comment(
        self,
        comment_id: int,
        *,
        disposition: Literal["accepted", "ignored"],
        reason_code: str,
    ) -> None:
        if not reason_code or len(reason_code) > 64:
            raise ValueError("bot-comment reason code is invalid")
        self._db.execute(
            "INSERT OR IGNORE INTO seen_bot_comments(comment_id, disposition, reason_code) "
            "VALUES (?, ?, ?)",
            (comment_id, disposition, reason_code),
        )

    def runtime_value(self, key: str, *, default: str) -> str:
        row = self._db.execute("SELECT value FROM runtime_state WHERE key = ?", (key,)).fetchone()
        return default if row is None else str(row[0])

    def set_runtime_value(self, key: str, value: str) -> None:
        if not key or not isinstance(value, str):
            raise ValueError("runtime-state value is invalid")
        self._db.execute(
            "INSERT INTO runtime_state(key, value) VALUES (?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    def active_case(self) -> PreparedCaseState | None:
        row = self._db.execute(
            """
            SELECT authorization_id, miner_hotkey, miner_account_id32, expected_miner_uid,
                   case_root, case_manifest_sha256, case_archive_sha256,
                   case_archive_size_bytes, case_archive_url, expected_origin,
                   response_close_round, reveal_round, response_close_unix_s,
                   reveal_unix_s, active
            FROM prepared_cases WHERE active = 1
            """
        ).fetchone()
        return None if row is None else PreparedCaseState(*row[:-1], active=bool(row[-1]))

    def case(self, authorization_id: str) -> PreparedCaseState | None:
        row = self._db.execute(
            """
            SELECT authorization_id, miner_hotkey, miner_account_id32, expected_miner_uid,
                   case_root, case_manifest_sha256, case_archive_sha256,
                   case_archive_size_bytes, case_archive_url, expected_origin,
                   response_close_round, reveal_round, response_close_unix_s,
                   reveal_unix_s, active
            FROM prepared_cases WHERE authorization_id = ?
            """,
            (authorization_id,),
        ).fetchone()
        return None if row is None else PreparedCaseState(*row[:-1], active=bool(row[-1]))

    def claim_next(self) -> QueuedAuthorization | None:
        """Claim issue authorization first, otherwise one case request if capacity is free."""

        self._db.execute("BEGIN IMMEDIATE")
        try:
            row = self._db.execute(
                """
                SELECT a.authorization_id, a.action, a.issue_id, a.issue_node_id,
                       a.issue_number, a.bot_comment_id, a.command_comment_id,
                       a.miner_hotkey, a.miner_account_id32, a.expected_miner_uid,
                       a.umi_revision, a.predecessor_authorization_id, a.case_manifest_sha256,
                       a.expected_origin, a.state
                FROM authorizations AS a
                LEFT JOIN prepared_cases AS c
                  ON c.authorization_id = a.predecessor_authorization_id
                WHERE a.state = 'queued'
                  AND (
                    (a.action = 'ready_to_issue' AND c.active = 1
                     AND a.miner_account_id32 = c.miner_account_id32
                     AND a.expected_miner_uid = c.expected_miner_uid
                     AND a.case_manifest_sha256 = c.case_manifest_sha256
                     AND a.expected_origin = c.expected_origin)
                    OR
                    (a.action = 'ready_for_case' AND NOT EXISTS (
                        SELECT 1 FROM prepared_cases WHERE active = 1
                    ) AND NOT EXISTS (
                        SELECT 1 FROM completed_miners AS completed
                        WHERE completed.miner_account_id32 = a.miner_account_id32
                    ))
                  )
                ORDER BY CASE a.action WHEN 'ready_to_issue' THEN 0 ELSE 1 END,
                         a.bot_comment_id
                LIMIT 1
                """
            ).fetchone()
            if row is None:
                self._db.execute("COMMIT")
                return None
            authorization = self._row(row)
            changed = self._db.execute(
                "UPDATE authorizations SET state = 'processing', updated_unix_s = ? "
                "WHERE authorization_id = ? AND state = 'queued'",
                (int(time.time()), authorization.authorization_id),
            ).rowcount
            if changed != 1:
                raise RuntimeError("public-pilot authorization claim lost its state race")
            self._db.execute("COMMIT")
            return replace(authorization, state="processing")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def record_case_ready(self, case: PreparedCaseState, *, result_sha256: str) -> None:
        if len(result_sha256) != 64 or any(
            character not in "0123456789abcdef" for character in result_sha256
        ):
            raise ValueError("case result digest is invalid")
        self._db.execute("BEGIN IMMEDIATE")
        try:
            authorization = self.get(case.authorization_id)
            if authorization is None or authorization.state != "processing":
                raise ValueError("case authorization is not processing")
            if authorization.action != "ready_for_case":
                raise ValueError("only READY_FOR_CASE can produce a prepared case")
            if (
                authorization.miner_account_id32 != case.miner_account_id32
                or authorization.expected_miner_uid != case.expected_miner_uid
                or account_id32(authorization.miner_hotkey) != account_id32(case.miner_hotkey)
            ):
                raise ValueError("prepared case does not match its miner authorization")
            self._db.execute(
                """
                INSERT INTO prepared_cases VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
                """,
                (
                    case.authorization_id,
                    case.miner_hotkey,
                    case.miner_account_id32,
                    case.expected_miner_uid,
                    case.case_root,
                    case.case_manifest_sha256,
                    case.case_archive_sha256,
                    case.case_archive_size_bytes,
                    case.case_archive_url,
                    case.expected_origin,
                    case.response_close_round,
                    case.reveal_round,
                    case.response_close_unix_s,
                    case.reveal_unix_s,
                ),
            )
            self._db.execute(
                "UPDATE authorizations SET state = 'case_ready', result_sha256 = ?, "
                "updated_unix_s = ? WHERE authorization_id = ?",
                (result_sha256, int(time.time()), case.authorization_id),
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def expire_active_case(self, *, now_unix_s: int, safety_margin_seconds: int = 300) -> bool:
        case = self.active_case()
        if case is None or now_unix_s < case.response_close_unix_s - safety_margin_seconds:
            return False
        self._db.execute("BEGIN IMMEDIATE")
        try:
            self._db.execute(
                "UPDATE prepared_cases SET active = 0 WHERE authorization_id = ? AND active = 1",
                (case.authorization_id,),
            )
            self._db.execute(
                "UPDATE authorizations SET state = 'superseded', updated_unix_s = ? "
                "WHERE authorization_id = ? AND state = 'case_ready'",
                (now_unix_s, case.authorization_id),
            )
            self._db.execute(
                "UPDATE authorizations SET state = 'superseded', updated_unix_s = ? "
                "WHERE predecessor_authorization_id = ? AND state IN ('queued', 'processing')",
                (now_unix_s, case.authorization_id),
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise
        return True

    def record_attempt_started(self, authorization_id: str) -> None:
        self._db.execute("BEGIN IMMEDIATE")
        try:
            authorization = self.get(authorization_id)
            if authorization is None or authorization.state != "processing":
                raise ValueError("issue authorization is not processing")
            if authorization.action != "ready_to_issue":
                raise ValueError("only READY_TO_ISSUE can start an attempt")
            case = self.active_case()
            if case is None or case.authorization_id != authorization.predecessor_authorization_id:
                raise ValueError("issue authorization does not match the active case")
            if (
                authorization.miner_account_id32 != case.miner_account_id32
                or authorization.expected_miner_uid != case.expected_miner_uid
                or authorization.case_manifest_sha256 != case.case_manifest_sha256
                or authorization.expected_origin != case.expected_origin
            ):
                raise ValueError("issue authorization does not bind the active case exactly")
            duplicate = self._db.execute(
                "SELECT 1 FROM completed_miners WHERE miner_account_id32 = ?",
                (authorization.miner_account_id32,),
            ).fetchone()
            if duplicate is not None:
                raise ValueError("miner already has a public-pilot attempt in this campaign")
            self._db.execute(
                "INSERT INTO completed_miners(miner_account_id32, authorization_id) VALUES (?, ?)",
                (authorization.miner_account_id32, authorization_id),
            )
            self._db.execute(
                "UPDATE authorizations SET state = 'attempt_started', updated_unix_s = ? "
                "WHERE authorization_id = ?",
                (int(time.time()), authorization_id),
            )
            self._db.execute(
                "UPDATE prepared_cases SET active = 0 WHERE authorization_id = ?",
                (case.authorization_id,),
            )
            self._db.execute("COMMIT")
        except BaseException:
            self._db.execute("ROLLBACK")
            raise

    def finish_attempt(
        self,
        authorization_id: str,
        *,
        state: Literal["complete", "incomplete"],
        result_sha256: str,
    ) -> None:
        changed = self._db.execute(
            "UPDATE authorizations SET state = ?, result_sha256 = ?, updated_unix_s = ? "
            "WHERE authorization_id = ? AND state = 'attempt_started'",
            (state, result_sha256, int(time.time()), authorization_id),
        ).rowcount
        if changed != 1:
            raise ValueError("public-pilot attempt is not in its durable started state")

    def requeue_precontact(self, authorization_id: str) -> None:
        changed = self._db.execute(
            "UPDATE authorizations SET state = 'queued', updated_unix_s = ? "
            "WHERE authorization_id = ? AND state = 'processing'",
            (int(time.time()), authorization_id),
        ).rowcount
        if changed != 1:
            raise ValueError("only a pre-contact processing authorization can be requeued")

    def supersede_precontact(self, authorization_id: str) -> None:
        """Retire one deterministically invalid authorization without blocking the queue."""

        changed = self._db.execute(
            "UPDATE authorizations SET state = 'superseded', updated_unix_s = ? "
            "WHERE authorization_id = ? AND state = 'processing'",
            (int(time.time()), authorization_id),
        ).rowcount
        if changed != 1:
            raise ValueError("only a pre-contact processing authorization can be superseded")


__all__ = [
    "PreparedCaseState",
    "PublicPilotAutomationState",
    "QueuedAuthorization",
]
