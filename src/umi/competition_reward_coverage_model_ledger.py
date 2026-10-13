"""Permanent compact model qualifications, independent of replaceable files."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import publish_private_model, read_private_model
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_KIND = "model_qualification"
_TABLE = "round_generation_model_qualification"
_SCHEMA = (
    "CREATE TABLE round_generation_model_qualification "
    "(id INTEGER PRIMARY KEY CHECK(id=1), completed INTEGER NOT NULL "
    "CHECK(TYPEOF(completed)='integer' AND completed>=0))"
)


class ModelDependencyQualification(StrictProtocolModel):
    schema_: Literal["umi-coverage-model-qualification/1"] = Field(alias="schema")
    context_sha256: Hex32
    dependency_sha256: Hex32


class _Owner(StrictProtocolModel):
    schema_: Literal["umi-coverage-model-qualification-owner/1"] = Field(alias="schema")
    receipts_identity: tuple[int, int, int]
    ledger_identity: tuple[int, int, int]


def _identity(path):
    value = path.stat()
    return value.st_dev, value.st_ino, value.st_uid


def _triggers():
    result = {}
    for action in ("UPDATE", "DELETE"):
        name = _TABLE + "_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            f"WHEN OLD.kind='{_KIND}' BEGIN SELECT "
            "RAISE(ABORT,'model qualification completion is immutable'); END"
        )
    name = _TABLE + "_insert"
    result[name] = (
        f"CREATE TRIGGER {name} AFTER INSERT ON records WHEN NEW.kind='{_KIND}' BEGIN "
        f"UPDATE {_TABLE} SET completed=completed+1 WHERE id=1; "
        "SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,"
        "'model qualification completion owner is missing') END; END"
    )
    return result


class _QualificationJournal(RoundJournal):
    @property
    def maximum_records(self):
        # Capacity follows compact metadata bytes, not unrelated round counts.
        return self.maximum_bytes

    def _enable_reservations(self, db):
        raise ValueError("model qualification ledger does not support reservations")

    @staticmethod
    def _version(db):
        if db.execute("PRAGMA user_version").fetchone()[0] != 5:
            return RoundJournal._version(db)
        table = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_TABLE,)
        ).fetchone()
        triggers = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
                (_TABLE + "_*",),
            )
        )
        if table != (_SCHEMA,) or triggers != _triggers():
            raise ValueError("model qualification completion ledger requires original repair")
        completed = db.execute(
            "SELECT number FROM round_record_capacity_kinds WHERE kind=?", (_KIND,)
        ).fetchone()
        if db.execute(f"SELECT id,completed FROM {_TABLE} LIMIT 2").fetchall() != [
            (1, 0 if completed is None else completed[0])
        ]:
            raise ValueError("model qualification completion count requires original repair")
        return 0


class QualificationLedger:
    """A lost completed item cannot become an ordinary native migration.

    The independent private owner binds the original database inode. Restore a
    lost/damaged ledger and owner from durable metadata; never reset either to
    bypass a repair. Legacy qualification files migrate without rewriting bytes.
    """

    def __init__(self, receipts: Path):
        root = receipts / "coverage-qualification-ledger"
        path = root / "rounds.sqlite3"
        marker = receipts / "coverage-qualification-owner.json"
        try:
            retained = read_private_model(marker, _Owner, maximum_bytes=64 * 1024)
        except FileNotFoundError:
            retained = None
        if retained is not None and (
            retained.receipts_identity != _identity(receipts)
            or not path.exists()
            or retained.ledger_identity != _identity(path)
        ):
            raise ValueError("model qualification original owner or ledger is missing")
        self.journal = _QualificationJournal(
            root,
            {
                "schema": "umi-coverage-model-qualification-ledger/1",
                "receipts": str(receipts),
                "identity": _identity(receipts),
            },
            maximum_bytes=RoundJournal.MAXIMUM_BYTES,
            maximum_record_bytes=64 * 1024,
        )
        with self.journal.read_transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if retained is None and version != 0:
                raise ValueError("model qualification original owner marker is missing")
        owner = _Owner(
            schema="umi-coverage-model-qualification-owner/1",
            receipts_identity=_identity(receipts),
            ledger_identity=_identity(path),
        )
        publish_private_model(marker, owner, maximum_bytes=64 * 1024)
        if version == 0:
            self._migrate(receipts)

    def _migrate(self, receipts):
        legacy = receipts / "coverage-dependency-qualifications"
        with TransferProgress(
            "coverage_model_qualification_ledger_inventory",
            1,
            unit="directories",
            planning_unit_seconds=(0.01, 60.0),
        ) as progress:
            total = sum(1 for _ in legacy.glob("*/*/*.json"))
            progress.advance(1)
        with (
            TransferProgress(
                "coverage_model_qualification_ledger_migration",
                total,
                unit="qualifications",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress,
            self.journal.transaction() as db,
        ):
            if db.execute("PRAGMA user_version").fetchone()[0] == 5:
                return
            # A crash may leave a newly owned empty database, never a
            # partially migrated successful set: this transaction is atomic.
            if db.execute("SELECT 1 FROM records LIMIT 1").fetchone():
                raise ValueError("model qualification ledger migration lost its owner")
            db.execute(_SCHEMA)
            for sql in _triggers().values():
                db.execute(sql)
            db.execute(f"INSERT INTO {_TABLE} VALUES (1,0)")
            for path in legacy.glob("*/*/*.json"):
                value = read_private_model(
                    path, ModelDependencyQualification, maximum_bytes=64 * 1024
                )
                context, cohort, submission = (
                    path.parent.parent.name,
                    path.parent.name,
                    path.stem,
                )
                if context != value.context_sha256 or any(
                    len(key) != 64 or any(c not in "0123456789abcdef" for c in key)
                    for key in (cohort, submission)
                ):
                    raise ValueError("legacy model qualification identity requires repair")
                raw = canonical_json_bytes(value)
                count, used, _ = self.journal._record_capacity(db)
                if count + 1 > self.journal.maximum_records or used + len(raw) > (
                    self.journal.maximum_bytes
                ):
                    raise ValueError("model qualification ledger capacity exhausted")
                db.execute(
                    "INSERT INTO records VALUES (?,?,?)",
                    (_KIND, digest([context, cohort, submission]), raw),
                )
                progress.advance(1, restored=True)
            db.execute("PRAGMA user_version=5")

    def load(self, context, item):
        raw = self.journal.get(_KIND, self.key(context, item))
        return None if raw is None else ModelDependencyQualification.model_validate(raw)

    def remember(self, context, item, value):
        self.journal.put(
            _KIND, self.key(context, item), value.model_dump(mode="json", by_alias=True)
        )

    @staticmethod
    def key(context, item):
        return digest([digest(context), item.cohort_sha256, item.submission_sha256])
