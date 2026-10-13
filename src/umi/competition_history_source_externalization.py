"""Keep original SQL source identities while moving exact payload bytes to R2.

Aliases are charged immutable journal records, not successful proof verdicts.
The ordinary source mutation triggers remain active. Only the exact original
revision followed by its one deletion can resolve to the original token. Older
runtimes refuse this storage capability before opening an apparently empty owner.
"""

from __future__ import annotations

import hashlib
import json
import re

from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .protocol import canonical_json_bytes

ALIAS_KIND = "control_history_remote_source"
MARKER_TABLE = "round_generation_history_remote"
SCHEMA = "umi-journal-remote-source/1"


def _name(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-z][a-z0-9_]*", value) is None:
        raise ValueError("unsupported source journal identifier")
    return value


def _fence_schema(marker_table, alias_kind):
    marker_table, alias_kind = _name(marker_table), _name(alias_kind)
    table = (
        f"CREATE TABLE {marker_table} (id INTEGER PRIMARY KEY CHECK(id=1), "
        "schema TEXT NOT NULL, namespace TEXT NOT NULL)"
    )
    triggers = {}
    for action in ("UPDATE", "DELETE"):
        name = f"{marker_table}_{action.lower()}"
        triggers[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            f"WHEN OLD.kind='{alias_kind}' BEGIN SELECT "
            "RAISE(ABORT,'remote source alias is immutable; explicit repair required'); END"
        )
    return table, triggers


def source_journal_version(
    db, *, marker_table=MARKER_TABLE, alias_kind=ALIAS_KIND, remote_namespace=None
):
    """History/coverage-only v3 reader; reservation-generation owners are separate."""
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version != 3:
        return RoundJournal._version(db)
    table, triggers = _fence_schema(marker_table, alias_kind)
    actual = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (marker_table,)
    ).fetchone()
    if actual != (table,):
        raise ValueError("remote source journal fence missing or changed; repair required")
    rows = db.execute(f"SELECT id,schema,namespace FROM {marker_table} LIMIT 2").fetchall()
    if rows != [(1, SCHEMA, remote_namespace)] or remote_namespace is None:
        raise ValueError("remote source journal requires its original selected R2 namespace")
    actual_triggers = dict(
        db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
            (marker_table + "_*",),
        )
    )
    if actual_triggers != triggers:
        raise ValueError("remote source journal alias fences changed; repair required")
    # The history-specific storage capability uses charged normal records. It
    # does not opt into or downgrade the unrelated reservation generation.
    return 0


class JournalSourceExternalizer:
    def __init__(
        self,
        journal,
        checkpoints,
        remote,
        *,
        source_table="history_source_identity",
        source_kinds,
        alias_kind=ALIAS_KIND,
        marker_table=MARKER_TABLE,
        repair_error=ValueError,
    ):
        self.journal, self.checkpoints, self.remote = journal, checkpoints, remote
        self.source_table, self.alias_kind = _name(source_table), _name(alias_kind)
        self.marker_table = _name(marker_table)
        self.source_kinds, self.repair_error = tuple(source_kinds), repair_error

    def _identity(self, kind, key, db):
        if kind not in self.source_kinds or type(key) is not str:
            raise self.repair_error("unsupported remote source kind or key")
        row = db.execute(
            f"SELECT revision,present FROM {self.source_table} WHERE kind=? AND id=?",
            (kind, key),
        ).fetchone()
        present = db.execute("SELECT 1 FROM records WHERE kind=? AND id=?", (kind, key)).fetchone()
        if (
            row is None
            or type(row[0]) is not int
            or row[0] < 0
            or row[1] not in (0, 1)
            or bool(row[1]) != bool(present)
            or db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone()
        ):
            raise self.repair_error("source identity missing or conflict held; repair required")
        return row

    def _alias(self, kind, key, db):
        try:
            value = self.journal.get(self.alias_kind, digest([kind, key]), db=db)
            if value is None:
                return None
            if (
                self.remote is None
                or type(value) is not dict
                or set(value)
                != {"schema", "owner", "kind", "key", "revision", "raw_sha256", "size", "remote"}
                or value["schema"] != SCHEMA
                or value["owner"] != self.checkpoints.owner
                or (value["kind"], value["key"]) != (kind, key)
                or type(value["revision"]) is not int
                or value["revision"] < 0
                or type(value["size"]) is not int
                or not 0 < value["size"] <= self.journal.maximum_record_bytes
            ):
                raise ValueError("invalid remote source alias")
            reference = self.remote.validate_reference(value["remote"])
            if (reference.content_sha256, reference.size_bytes) != (
                value["raw_sha256"],
                value["size"],
            ):
                raise ValueError("remote source alias changes original bytes")
        except (TypeError, KeyError, ValueError) as error:
            raise self.repair_error(
                "remote source alias or receipt damaged; repair required"
            ) from error
        return value

    def source_token(self, kind, key, db):
        """Resolve only compact owner metadata; never read a payload or use RPC."""
        row = self._identity(kind, key, db)
        alias = self._alias(kind, key, db)
        if alias is None:
            if row[1] != 1:
                raise self.repair_error("remote source alias missing; explicit repair required")
            return [kind, key, row[0]]
        if row != (alias["revision"] + 1, 0):
            raise self.repair_error("externalized source was mutated; explicit repair required")
        return [kind, key, alias["revision"]]

    def get_raw(self, kind, key, *, db):
        alias = self._alias(kind, key, db)
        if alias is None:
            # A never-captured source remains an ordinary absence. Under the
            # remote capability a tombstone must not turn a missing alias into
            # a new RPC replay. Legacy unverified gaps can still be captured;
            # a completed legacy checkpoint checks its sources before here.
            row = db.execute(
                f"SELECT 1 FROM {self.source_table} WHERE kind=? AND id=? AND present=0",
                (kind, key),
            ).fetchone()
            if row and db.execute("PRAGMA user_version").fetchone()[0] == 3:
                raise self.repair_error("deleted retained source requires explicit repair")
            return self.journal.get_raw(kind, key, db=db)
        self.source_token(kind, key, db)
        try:
            raw = self.remote.read_bytes(alias["remote"], maximum=self.journal.maximum_record_bytes)
            # The transport authenticates the original receipt's hash and size.
            # Decoding still preserves the journal's exact canonical byte rule.
            if canonical_json_bytes(json.loads(raw)) != raw:
                raise ValueError("remote source is not canonical")
            return raw
        except ValueError as error:
            raise self.repair_error("remote source restoration needs explicit repair") from error

    def get(self, kind, key, *, db):
        raw = self.get_raw(kind, key, db=db)
        return None if raw is None else json.loads(raw)

    def filter_records(self, records):
        """Deduplicated captures must not resurrect an externalized shared object."""
        remaining = []
        with self.journal.read_transaction() as db:
            for kind, key, value in records:
                alias = self._alias(kind, key, db)
                if alias is None:
                    remaining.append((kind, key, value))
                    continue
                self.source_token(kind, key, db)
                raw = canonical_json_bytes(value)
                if (hashlib.sha256(raw).hexdigest(), len(raw)) != (
                    alias["raw_sha256"],
                    alias["size"],
                ):
                    raise self.repair_error("captured source differs from externalized original")
        return remaining

    def _install(self):
        if self.remote is None or self.remote.config.read_only:
            raise ValueError("source externalization requires its writable R2 store")
        table, triggers = _fence_schema(self.marker_table, self.alias_kind)
        with self.journal.read_transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 3:
                return  # the journal reader checked the exact selected fence
        with self.journal.transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 3:
                source_journal_version(
                    db,
                    marker_table=self.marker_table,
                    alias_kind=self.alias_kind,
                    remote_namespace=self.remote.namespace_sha256,
                )
                return
            if version != 0:
                raise ValueError("source externalization refuses reservation-generation migration")
            self.checkpoints.check_schema(db)
            db.execute(table)
            db.execute(
                f"INSERT INTO {self.marker_table} VALUES (1,?,?)",
                (SCHEMA, self.remote.namespace_sha256),
            )
            for sql in triggers.values():
                db.execute(sql)
            db.execute("PRAGMA user_version=3")

    def externalize(self, kind, key):
        """Upload outside the writer transaction; atomically alias and delete once.

        Deletion releases logical journal capacity and reusable SQLite pages.
        It does not promise to shrink the database inode or its allocated file.
        Callers serialize consumer ownership; read snapshots/pinned bytes retain
        their own bounded working sets until released.
        """
        self._install()
        with self.journal.read_transaction() as db:
            self.checkpoints.check_schema(db)
            token = self.source_token(kind, key, db)
            alias = self._alias(kind, key, db)
            if alias is not None:
                return {"restored": True, "released_logical_bytes": 0}
            raw = self.journal.get_raw(kind, key, db=db)
        reference = self.remote.put_bytes(raw)
        receipt = self.remote.validate_reference(reference)
        alias = {
            "schema": SCHEMA,
            "owner": self.checkpoints.owner,
            "kind": kind,
            "key": key,
            "revision": token[2],
            "raw_sha256": receipt.content_sha256,
            "size": len(raw),
            "remote": reference,
        }

        self._commit_alias(kind, key, token, alias)
        return {
            "restored": False,
            "released_logical_bytes": len(raw) - len(canonical_json_bytes(alias)),
        }

    def _commit_alias(self, kind, key, token, alias):
        raw = canonical_json_bytes(alias)
        if len(raw) > self.journal.maximum_record_bytes:
            raise ValueError("remote source alias exceeds its journal record bound")
        alias_key = digest([kind, key])
        with self.journal.transaction() as db:
            self.checkpoints.check_schema(db)
            if self._identity(kind, key, db) != (token[2], 1):
                raise self.repair_error("source changed during upload; original retained")
            if self.journal.get_raw(self.alias_kind, alias_key, db=db) is not None:
                raise self.repair_error("remote source alias already exists; repair required")
            self.remote.validate_reference(alias["remote"])  # metadata only, no network
            # Release original logical capacity before charging the replacement,
            # inside the same transaction. A full legacy owner needs no extra
            # alias-sized headroom; capacity counters and source triggers remain
            # enabled and any failure restores the exact original record.
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (kind, key))
            db.execute("INSERT INTO records VALUES (?,?,?)", (self.alias_kind, alias_key, raw))
            count, used, _ = self.journal._record_capacity(db)
            if count > self.journal.maximum_records or used > self.journal.maximum_bytes:
                raise ValueError("remote source replacement exceeds journal capacity")
            if self.source_token(kind, key, db) != token:
                raise self.repair_error("externalized source changed its original token")

    def externalize_many(self, keys):
        self._install()
        # Reclaim large payloads before expanding small frame records into
        # aliases. This bounded batch reads SQL lengths, never payload bytes.
        selected = list(dict.fromkeys(keys))
        with self.journal.read_transaction() as db:
            sizes = {}
            for kind, key in selected:
                row = db.execute(
                    "SELECT LENGTH(body) FROM records WHERE kind=? AND id=?", (kind, key)
                ).fetchone()
                sizes[kind, key] = 0 if row is None else row[0]
        selected.sort(key=lambda item: sizes[item], reverse=True)
        released = restored = 0
        with TransferProgress(
            "journal_source_replication", len(selected), unit="records"
        ) as progress:
            try:
                for kind, key in selected:
                    result = self.externalize(kind, key)
                    released += result["released_logical_bytes"]
                    restored += int(result["restored"])
                    progress.advance(1, restored=result["restored"])
            except self.repair_error:
                progress.emit("repair_required", reason="retained_source_requires_explicit_repair")
                raise
        return {
            "replicated_records": len(selected),
            "restored_records": restored,
            "released_logical_bytes": released,
            "disk_reclamation_basis": "reusable_sqlite_pages_not_database_file_shrink",
        }
