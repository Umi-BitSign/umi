"""Private native preparation facts, retained independently of publication.

The preparation owner supplies verified facts. This store preserves their exact
identity and completion state; it neither verifies a reward nor authorizes a row.
"""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_cohort_reward_allocation import MAX_REWARD_ALLOCATION_BYTES
from .competition_round_journal import RoundJournal
from .open_competition import digest
from .private_files import (
    MAX_PRIVATE_BYTES,
    PrivateStateBusyError,
    publish_private_model,
    read_private_model,
)
from .protocol import StrictProtocolModel, canonical_json_bytes
from .sqlite_contention import is_sqlite_contention

SCHEMA = "umi-standing-reward-preparation-checkpoints/1"
OWNER = "preparation_checkpoint_owner"
STARTED = "preparation_checkpoint_started"
NATIVE = "preparation_checkpoint_native"
COMPLETE = "preparation_checkpoint_complete"
TABLE = "preparation_checkpoint_ledger"
COUNTS = "preparation_checkpoint_counts"
SQL = (
    f"CREATE TABLE {TABLE} (kind TEXT NOT NULL, id TEXT NOT NULL, "
    "activation TEXT NOT NULL, reviewed_at_block INTEGER NOT NULL, "
    "body BLOB NOT NULL, PRIMARY KEY(kind,id))"
)
COUNT_SQL = (
    f"CREATE TABLE {COUNTS} (kind TEXT PRIMARY KEY NOT NULL, "
    "number INTEGER NOT NULL, bytes INTEGER NOT NULL)"
)
INDEX = TABLE + "_selection"
INDEX_SQL = f"CREATE INDEX {INDEX} ON {TABLE}(kind,activation,reviewed_at_block)"
KINDS = (STARTED, NATIVE, COMPLETE)


class PreparationCheckpointRepairRequired(ValueError):
    """Original completed metadata must be restored by its preparation owner."""


class _Owner(StrictProtocolModel):
    schema_: Literal["umi-standing-reward-preparation-checkpoints/1"] = Field(alias="schema")
    binding_sha256: str
    identity: tuple[tuple[int, int, int], tuple[int, int, int]]


def _triggers():
    result = {}
    for action in ("UPDATE", "DELETE"):
        name = TABLE + "_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT,'preparation completion is immutable'); END"
        )
        name = TABLE + "_owner_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            f"WHEN OLD.kind='{OWNER}' BEGIN SELECT "
            "RAISE(ABORT,'preparation owner is immutable'); END"
        )
    name = TABLE + "_count"
    result[name] = (
        f"CREATE TRIGGER {name} AFTER INSERT ON {TABLE} BEGIN "
        f"UPDATE {COUNTS} SET number=number+1,bytes=bytes+LENGTH(NEW.body) "
        "WHERE kind=NEW.kind; SELECT CASE WHEN changes()!=1 THEN "
        "RAISE(ABORT,'preparation completion count is missing') END; END"
    )
    return result


def _hex(value):
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError("preparation identity must be a lowercase SHA256")
    return value


def _block(value):
    if type(value) is not int or not 0 <= value <= 2**53 - 1:
        raise ValueError("preparation reviewed block is invalid")
    return value


class PreparationCheckpoints:
    """Keep resumable starts and immutable native/completed results separately.

    A sibling marker retains the original journal identity. Each result has an
    immutable ledger copy and an append-only count, so missing successful work
    becomes an explicit repair instead of a fresh preparation.
    """

    def __init__(self, root: Path, binding: dict):
        if type(binding) is not dict:
            raise ValueError("preparation checkpoint binding must be an object")
        self.root = root
        self.marker = root.parent / (root.name + "-owner.json")
        self.binding = {"schema": SCHEMA, "context": binding}
        self.binding_bytes = canonical_json_bytes(self.binding)
        try:
            try:
                retained = read_private_model(self.marker, _Owner, maximum_bytes=64 * 1024)
            except FileNotFoundError:
                retained = None
            path = root / "rounds.sqlite3"
            if retained is not None and (
                not path.is_file()
                or retained.identity != self._identity(root, path)
                or retained.binding_sha256 != digest(self.binding)
            ):
                raise PreparationCheckpointRepairRequired(
                    "preparation original journal or binding requires repair"
                )
            self.journal = RoundJournal(
                root,
                self.binding,
                maximum_bytes=RoundJournal.MAXIMUM_BYTES,
                maximum_rounds=65536,
                # A maximum-sized valid allocation still needs its native
                # dependency envelope. Keep both existing protocol allowances.
                maximum_record_bytes=MAX_REWARD_ALLOCATION_BYTES + MAX_PRIVATE_BYTES,
            )
            self.owner = _Owner(
                schema=SCHEMA,
                binding_sha256=digest(self.binding),
                identity=self._identity(root, path),
            ).model_dump(mode="json", by_alias=True)
            with self.journal.locked(), self.journal.transaction() as db:
                installed = db.execute(
                    "SELECT name FROM sqlite_master WHERE name GLOB ?",
                    (TABLE + "*",),
                ).fetchall()
                occupied = db.execute("SELECT 1 FROM records LIMIT 1").fetchone()
                counts = db.execute(
                    "SELECT 1 FROM sqlite_master WHERE name=?", (COUNTS,)
                ).fetchone()
                if retained is None and (installed or occupied or counts):
                    raise PreparationCheckpointRepairRequired(
                        "preparation original owner marker was lost"
                    )
                if not installed and not occupied and not counts:
                    # The owner is durable before the first successful record.
                    # A crash here leaves only an empty, resumable owned store.
                    publish_private_model(
                        self.marker,
                        _Owner.model_validate_json(canonical_json_bytes(self.owner)),
                        maximum_bytes=64 * 1024,
                    )
                    db.execute(SQL)
                    db.execute(COUNT_SQL)
                    db.execute(INDEX_SQL)
                    db.executemany(f"INSERT INTO {COUNTS} VALUES (?,0,0)", ((k,) for k in KINDS))
                    for statement in _triggers().values():
                        db.execute(statement)
                    db.execute(
                        "INSERT INTO records VALUES (?,?,?)",
                        (OWNER, "owner", canonical_json_bytes(self.owner)),
                    )
                self._check(db)
        except (ValueError, OSError, sqlite3.DatabaseError, TypeError, KeyError) as error:
            if isinstance(error, PrivateStateBusyError) or is_sqlite_contention(error):
                raise
            if isinstance(error, PreparationCheckpointRepairRequired):
                raise
            raise PreparationCheckpointRepairRequired(
                "preparation original owner metadata requires repair"
            ) from error

    @staticmethod
    def _identity(root, path):
        return tuple((s.st_dev, s.st_ino, s.st_uid) for s in (root.stat(), path.stat()))

    @staticmethod
    def key(activation_sha256: str, reviewed_at_block: int) -> str:
        return f"{_hex(activation_sha256)}:{_block(reviewed_at_block)}"

    @classmethod
    def _split_key(cls, key):
        if type(key) is not str or not 66 <= len(key) <= 81 or ":" not in key:
            raise ValueError("preparation native key is invalid")
        activation, block = key.split(":", 1)
        try:
            number = int(block)
        except ValueError as error:
            raise ValueError("preparation native key is invalid") from error
        if cls.key(activation, number) != key:
            raise ValueError("preparation native key is noncanonical")
        return activation, number

    @contextmanager
    def _transaction(self, *, write=False):
        try:
            with self.journal.locked():
                transaction = self.journal.transaction if write else self.journal.read_transaction
                with transaction() as db:
                    self._check(db)
                    yield db
        except (ValueError, OSError, sqlite3.DatabaseError, TypeError, KeyError) as error:
            if isinstance(error, PrivateStateBusyError) or is_sqlite_contention(error):
                raise
            if isinstance(error, PreparationCheckpointRepairRequired):
                raise
            raise PreparationCheckpointRepairRequired(
                "preparation retained metadata requires repair"
            ) from error

    def _check(self, db):
        if (
            [list(v) for v in self._identity(self.root, self.journal.path)]
            != self.owner["identity"]
            or read_private_model(self.marker, _Owner, maximum_bytes=64 * 1024).model_dump(
                mode="json", by_alias=True
            )
            != self.owner
            or self.journal.get(OWNER, "owner", db=db) != self.owner
            or db.execute("SELECT body FROM binding LIMIT 2").fetchall() != [(self.binding_bytes,)]
        ):
            raise PreparationCheckpointRepairRequired("preparation original owner requires repair")
        for kind, name, expected in (
            ("table", TABLE, SQL),
            ("table", COUNTS, COUNT_SQL),
            ("index", INDEX, INDEX_SQL),
        ):
            if db.execute(
                "SELECT sql FROM sqlite_master WHERE type=? AND name=?", (kind, name)
            ).fetchone() != (expected,):
                raise PreparationCheckpointRepairRequired(
                    "preparation ledger schema requires repair"
                )
        if (
            dict(
                db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
                    (TABLE + "_*",),
                )
            )
            != _triggers()
        ):
            raise PreparationCheckpointRepairRequired("preparation ledger triggers require repair")
        counts = {row[0]: (row[1], row[2]) for row in db.execute(f"SELECT * FROM {COUNTS}")}
        if set(counts) != set(KINDS):
            raise PreparationCheckpointRepairRequired(
                "preparation completion counts require repair"
            )
        primary = {
            row[0]: (row[1], row[2])
            for row in db.execute(
                "SELECT kind,number,nbytes FROM round_record_capacity_kinds WHERE kind IN (?,?,?)",
                KINDS,
            )
        }
        mirror = {
            row[0]: (row[1], row[2])
            for row in db.execute(
                f"SELECT kind,COUNT(*),SUM(LENGTH(body)) FROM {TABLE} GROUP BY kind"
            )
        }
        if set(mirror) - set(KINDS) or any(
            counts[k] != primary.get(k, (0, 0)) or counts[k] != mirror.get(k, (0, 0)) for k in KINDS
        ):
            raise PreparationCheckpointRepairRequired("preparation completed records were lost")

    def _load(self, db, kind, key, activation, block):
        raw = self.journal.get_raw(kind, key, db=db)
        row = db.execute(
            f"SELECT activation,reviewed_at_block,LENGTH(body) FROM {TABLE} WHERE kind=? AND id=?",
            (kind, key),
        ).fetchone()
        if row is None and raw is None:
            return None
        if row is None or raw is None or row != (activation, block, len(raw)):
            raise PreparationCheckpointRepairRequired(
                "preparation completed record requires repair"
            )
        mirror = db.execute(
            f"SELECT body FROM {TABLE} WHERE kind=? AND id=?", (kind, key)
        ).fetchone()[0]
        if bytes(mirror) != raw:
            raise PreparationCheckpointRepairRequired(
                "preparation completed record requires repair"
            )
        value = json.loads(raw)
        if type(value) is not dict:
            raise PreparationCheckpointRepairRequired(
                "preparation completed object requires repair"
            )
        return value

    def _retain(self, db, kind, key, activation, block, value):
        prior = self._load(db, kind, key, activation, block)
        raw = canonical_json_bytes(value)
        if prior is not None:
            if canonical_json_bytes(prior) != raw:
                raise PreparationCheckpointRepairRequired("preparation completed value changed")
            return
        if len(raw) > self.journal.maximum_record_bytes:
            raise ValueError("preparation metadata exceeds its record capacity")
        count, used, _ = self.journal._record_capacity(db)
        rows, size = db.execute(f"SELECT SUM(number),SUM(bytes) FROM {COUNTS}").fetchone()
        if count + rows + 2 > self.journal.maximum_records or (
            used + size + 2 * len(raw) > self.journal.maximum_bytes
        ):
            raise ValueError("preparation metadata capacity exhausted")
        db.execute("INSERT INTO records VALUES (?,?,?)", (kind, key, raw))
        db.execute(f"INSERT INTO {TABLE} VALUES (?,?,?,?,?)", (kind, key, activation, block, raw))

    def begin(self, activation_sha256: str, package_sha256: str) -> None:
        activation, package = _hex(activation_sha256), _hex(package_sha256)
        with self._transaction(write=True) as db:
            self._retain(
                db,
                STARTED,
                activation,
                activation,
                -1,
                {
                    "activation_sha256": activation,
                    "package_sha256": package,
                },
            )

    def status(
        self, activation_sha256: str, through_block: int, *, context: dict | None = None
    ) -> dict | None:
        activation, block = _hex(activation_sha256), _block(through_block)
        if context is not None and (type(context) is not dict or not context):
            raise ValueError("preparation selection requires a nonempty exact context")
        with self._transaction() as db:
            started = self._load(db, STARTED, activation, activation, -1)
            rows = db.execute(
                f"SELECT id,reviewed_at_block FROM {TABLE} WHERE kind=? AND activation=? "
                "AND reviewed_at_block<=? ORDER BY reviewed_at_block",
                (NATIVE, activation, block),
            )
            found = False
            for row in rows:
                found = True
                value = self._load(db, NATIVE, row[0], activation, row[1])
                if (
                    started is None
                    or row[0] != self.key(activation, row[1])
                    or value.get("activation_sha256") != activation
                    or value.get("reviewed_at_block") != row[1]
                    or value.get("package_sha256") != started.get("package_sha256")
                ):
                    raise PreparationCheckpointRepairRequired(
                        "preparation native binding requires repair"
                    )
                if context is None or all(
                    value.get(key) == expected for key, expected in context.items()
                ):
                    return value
            if found and context is not None:
                raise PreparationCheckpointRepairRequired(
                    "completed preparation has no retained fact matching this consumer context"
                )
            return None

    def retain_native(self, activation_sha256: str, reviewed_at_block: int, value: dict) -> None:
        key = self.key(activation_sha256, reviewed_at_block)
        if type(value) is not dict or (
            value.get("activation_sha256") != activation_sha256
            or type(value.get("reviewed_at_block")) is not int
            or value["reviewed_at_block"] != reviewed_at_block
        ):
            raise ValueError("preparation native result changes its activation or reviewed block")
        _hex(value.get("package_sha256"))
        with self._transaction(write=True) as db:
            started = self._load(db, STARTED, activation_sha256, activation_sha256, -1)
            if started != {
                "activation_sha256": activation_sha256,
                "package_sha256": value["package_sha256"],
            }:
                raise PreparationCheckpointRepairRequired(
                    "preparation native result lacks its start"
                )
            self._retain(db, NATIVE, key, activation_sha256, reviewed_at_block, value)

    def consumer_fact(self, activation_sha256: str, *, context: dict) -> dict | None:
        """Find this consumer's exact local binding, without historical authority.

        A later fact cannot establish an earlier allocation or review time. The
        preparation owner must separately select an eligible historical fact
        and prove unchanged semantics and completed dependencies before reuse.
        """
        return self.status(activation_sha256, 2**53 - 1, context=context)

    def load_completion(self, native_key: str) -> dict | None:
        activation, block = self._split_key(native_key)
        with self._transaction() as db:
            native = self._load(db, NATIVE, native_key, activation, block)
            completed = self._load(db, COMPLETE, native_key, activation, block)
            if completed is None:
                return None
            if (
                native is None
                or set(completed) != {"native_key", "native_sha256", "value"}
                or completed["native_key"] != native_key
                or completed["native_sha256"] != digest(native)
                or type(completed["value"]) is not dict
            ):
                raise PreparationCheckpointRepairRequired(
                    "preparation completion binding requires repair"
                )
            return completed["value"]

    def retain_completion(self, native_key: str, value: dict) -> None:
        activation, block = self._split_key(native_key)
        if type(value) is not dict:
            raise ValueError("preparation completion must be an object")
        with self._transaction(write=True) as db:
            native = self._load(db, NATIVE, native_key, activation, block)
            if native is None:
                raise PreparationCheckpointRepairRequired(
                    "preparation completion lacks its native result"
                )
            self._retain(
                db,
                COMPLETE,
                native_key,
                activation,
                block,
                {
                    "native_key": native_key,
                    "native_sha256": digest(native),
                    "value": value,
                },
            )
