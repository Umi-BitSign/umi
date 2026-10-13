"""Durable native coverage facts bound to original owner and SQL source generations.

Imported points remain hints. Only the coverage journal's native retain/replay
path records these private verdicts after exact original evidence has succeeded.
"""

from __future__ import annotations

import sqlite3

from .competition_reward_coverage_intervals import CoveragePoint, coverage_point
from .competition_reward_coverage_models import (
    CoverageModelDependencies,
    check_coverage_model_metadata,
)
from .competition_transport_verification import TransferProgress
from .competition_verification_rules import runtime_identity
from .open_competition import digest
from .protocol import canonical_json_bytes

KINDS = ("coverage_endpoint", "coverage_blob_proof", "coverage_blob_metadata", "coverage_object")
ABI = "umi-native-coverage-endpoint/1"
LEDGER_SCHEMA = "umi-coverage-completion-ledger/1"
LEDGER_TABLE = "CREATE TABLE coverage_completion_ledger(id TEXT PRIMARY KEY,owner TEXT NOT NULL)"


def _ledger_triggers():
    values = {}
    for action in ("UPDATE", "DELETE"):
        name = "coverage_completion_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON coverage_completion_ledger "
            "BEGIN SELECT RAISE(ABORT,'coverage completion is permanent'); END"
        )
        name = "coverage_completion_owner_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            "WHEN OLD.kind='coverage_checkpoint_owner' BEGIN SELECT "
            "RAISE(ABORT,'coverage completion owner is immutable'); END"
        )
    return values


class CoverageCheckpointRepairRequired(ValueError):
    """A completed native result needs explicit scoped owner repair."""


def _triggers():
    kinds = ",".join("'" + kind + "'" for kind in KINDS)
    values = {}
    for action in ("INSERT", "UPDATE", "DELETE"):
        row = "OLD" if action == "DELETE" else "NEW"
        name = "coverage_source_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records WHEN {row}.kind IN ({kinds}) "
            "BEGIN INSERT INTO coverage_source_identity(kind,id,revision,present) "
            f"VALUES({row}.kind,{row}.id,1,{int(action != 'DELETE')}) "
            "ON CONFLICT(kind,id) DO UPDATE SET revision=revision+1,"
            f"present={int(action != 'DELETE')}; END"
        )
    values["coverage_source_rekey"] = (
        "CREATE TRIGGER coverage_source_rekey AFTER UPDATE ON records "
        f"WHEN OLD.kind IN ({kinds}) AND (OLD.kind!=NEW.kind OR OLD.id!=NEW.id) "
        "BEGIN UPDATE coverage_source_identity SET revision=revision+1,present=0 "
        "WHERE kind=OLD.kind AND id=OLD.id; END"
    )
    return values


class CoverageCheckpoints:
    def __init__(self, journal, rule):
        self.journal, self.rule = journal, rule
        self.identity = self._identity()
        self.owner = digest(
            {"rule": digest(rule), "path": str(journal.root), "identity": self.identity}
        )
        self.semantics = digest([ABI, runtime_identity()])
        self.externalized = None
        self.triggers = _triggers()
        self.ledger_triggers = _ledger_triggers()
        self.ledger_marker = {"schema": LEDGER_SCHEMA, "owner": self.owner}
        with journal.transaction() as db:
            installed = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='coverage_source_identity'"
            ).fetchone()
            if not installed:
                if db.execute(
                    "SELECT 1 FROM records WHERE kind IN "
                    "('coverage_verified','coverage_verified_done','coverage_checkpoint_owner') "
                    "LIMIT 1"
                ).fetchone():
                    raise CoverageCheckpointRepairRequired("coverage source metadata was lost")
                total = sum(
                    db.execute("SELECT COUNT(*) FROM records WHERE kind=?", (kind,)).fetchone()[0]
                    for kind in KINDS
                )
                with TransferProgress(
                    "coverage_source_migration",
                    total,
                    unit="records",
                    planning_unit_seconds=(0.00001, 0.01),
                ) as progress:
                    db.execute(
                        "CREATE TABLE coverage_source_identity(kind TEXT,id TEXT,"
                        "revision INTEGER NOT NULL,present INTEGER NOT NULL,PRIMARY KEY(kind,id))"
                    )
                    db.execute(
                        "CREATE TABLE coverage_checkpoint_index("
                        "id TEXT PRIMARY KEY, result TEXT NOT NULL)"
                    )
                    for kind in KINDS:
                        count = db.execute(
                            "INSERT INTO coverage_source_identity "
                            "SELECT kind,id,0,1 FROM records WHERE kind=?",
                            (kind,),
                        ).rowcount
                        progress.advance(count)
                    for sql in self.triggers.values():
                        db.execute(sql)
            self._check_source_schema(db)
        self._install_completion_ledger()
        with journal.read_transaction() as db:
            self.check_schema(db)

    def _identity(self):
        return [
            [s.st_dev, s.st_ino, s.st_uid]
            for s in (self.journal.root.stat(), self.journal.path.stat())
        ]

    def _check_source_schema(self, db):
        if self._identity() != self.identity:
            raise CoverageCheckpointRepairRequired(
                "coverage original owner directory or database changed"
            )
        actual = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'coverage_source_*'"
            )
        )
        if actual != self.triggers:
            raise CoverageCheckpointRepairRequired("coverage source mutation triggers changed")
        db.execute("SELECT id,result FROM coverage_checkpoint_index LIMIT 0")

    def _install_completion_ledger(self):
        """Migrate exact retained facts, refusing orphaned completed results.

        The separate ledger survives simultaneous loss of the replaceable index
        and endpoint marker. Its owner record distinguishes a legacy installation
        from a damaged ledger; both are installed in one transaction.
        """
        with self.journal.read_transaction() as db:
            installed = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name='coverage_completion_ledger'"
            ).fetchone()
            marker = self.journal.get("coverage_checkpoint_owner", "owner", db=db)
            fences = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'coverage_completion_*' LIMIT 1"
            ).fetchone()
            if installed or marker is not None or fences:
                self.check_schema(db)
                return

        def initialize(db):
            self._check_source_schema(db)
            db.execute("CREATE TEMP TABLE coverage_completion_migration_keys(id TEXT PRIMARY KEY)")
            db.execute(
                "INSERT INTO coverage_completion_migration_keys "
                "SELECT id FROM coverage_checkpoint_index"
            )
            db.execute(
                "INSERT OR IGNORE INTO coverage_completion_migration_keys "
                "SELECT id FROM records WHERE kind='coverage_verified_done'"
            )
            # Include successful immutable facts so losing both an endpoint's
            # marker and index cannot be mistaken for a never-verified endpoint.
            facts = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='coverage_verified'"
            ).fetchone()[0]
            with TransferProgress(
                "coverage_completion_inventory",
                facts,
                unit="results",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress:
                for (key,) in db.execute("SELECT id FROM records WHERE kind='coverage_verified'"):
                    value = self.journal.get("coverage_verified", key, db=db)
                    try:
                        if type(value) is not dict or digest(value) != key:
                            raise ValueError("changed result")
                        db.execute(
                            "INSERT OR IGNORE INTO coverage_completion_migration_keys VALUES (?)",
                            (CoveragePoint.model_validate(value["point"]).key(),),
                        )
                    except (ValueError, KeyError, TypeError) as error:
                        raise CoverageCheckpointRepairRequired(
                            "coverage completed result requires repair before ledger migration"
                        ) from error
                    progress.advance(1, restored=True)
            total = db.execute(
                "SELECT COUNT(*) FROM coverage_completion_migration_keys"
            ).fetchone()[0]
            with TransferProgress(
                "coverage_completion_migration",
                total,
                unit="endpoints",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress:
                db.execute(LEDGER_TABLE)
                for (key,) in db.execute(
                    "SELECT id FROM coverage_completion_migration_keys ORDER BY id"
                ):
                    if self._load(key, db, ledger=False) is None:
                        raise CoverageCheckpointRepairRequired(
                            "coverage completed result lost its marker and index"
                        )
                    db.execute(
                        "INSERT INTO coverage_completion_ledger VALUES (?,?)", (key, self.owner)
                    )
                    progress.advance(1, restored=True)
                for sql in self.ledger_triggers.values():
                    db.execute(sql)
            db.execute("DROP TABLE coverage_completion_migration_keys")

        self.journal.put_many(
            (("coverage_checkpoint_owner", "owner", self.ledger_marker),), index=initialize
        )

    def check_schema(self, db):
        self._check_source_schema(db)
        table = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='coverage_completion_ledger'"
        ).fetchone()
        actual = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' "
                "AND name GLOB 'coverage_completion_*'"
            )
        )
        if (
            table != (LEDGER_TABLE,)
            or actual != self.ledger_triggers
            or self.journal.get("coverage_checkpoint_owner", "owner", db=db) != self.ledger_marker
        ):
            raise CoverageCheckpointRepairRequired(
                "coverage completion ledger or original owner is missing or damaged"
            )

    def sources(self, keys, db):
        self.check_schema(db)
        values = []
        for kind, key in sorted(set(keys)):
            if self.externalized is not None:
                values.append(self.externalized.source_token(kind, key, db))
                continue
            row = db.execute(
                "SELECT revision,present FROM coverage_source_identity WHERE kind=? AND id=?",
                (kind, key),
            ).fetchone()
            if row is None or db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
                raise CoverageCheckpointRepairRequired("coverage source missing or conflict held")
            if row[1] != 1:
                raise CoverageCheckpointRepairRequired("coverage source no longer retained")
            values.append([kind, key, row[0]])
        return values

    def _load(self, key, db, *, ledger=True):
        if ledger:
            self.check_schema(db)
            completed = db.execute(
                "SELECT owner FROM coverage_completion_ledger WHERE id=?", (key,)
            ).fetchone()
        else:
            self._check_source_schema(db)
            completed = None
        marker = self.journal.get("coverage_verified_done", key, db=db)
        index = db.execute(
            "SELECT result FROM coverage_checkpoint_index WHERE id=?", (key,)
        ).fetchone()
        if marker is None:
            if index is not None or completed is not None:
                raise CoverageCheckpointRepairRequired("coverage completion marker missing")
            return None
        if ledger and completed != (self.owner,):
            raise CoverageCheckpointRepairRequired("coverage completed ledger entry damaged")
        if marker != {"owner": self.owner, "key": key} or index is None:
            raise CoverageCheckpointRepairRequired("coverage completion marker damaged")
        value = self.journal.get("coverage_verified", index[0], db=db)
        if (
            type(value) is not dict
            or digest(value) != index[0]
            or set(value) - {"model_dependencies"}
            != {
                "schema",
                "owner",
                "semantics",
                "point",
                "package_sha256",
                "policy_sha256",
                "requirement_sha256",
                "cohort_sha256",
                "sources",
                "repair",
            }
            or value["schema"] != ABI
            or value["owner"] != self.owner
            or value["semantics"] != self.semantics
        ):
            raise CoverageCheckpointRepairRequired(
                "coverage result, owner or native semantics changed"
            )
        point = CoveragePoint.model_validate(value["point"])
        if "model_dependencies" in value:
            check_coverage_model_metadata(
                CoverageModelDependencies.model_validate_json(
                    canonical_json_bytes(value["model_dependencies"])
                )
            )
        if (
            point.key() != key
            or point.series_sha256 != self.rule.series_sha256
            or point.runtime_profile_sha256 != self.rule.runtime_profile_sha256
        ):
            raise CoverageCheckpointRepairRequired("coverage result changed its selected domain")
        # Migration only records that native completion previously existed. It
        # grants no usable endpoint; consumer loads still check every original
        # source after the journal has attached its selected remote resolver.
        if (
            ledger
            and self.sources(((v[0], v[1]) for v in value["sources"]), db) != value["sources"]
        ):
            raise CoverageCheckpointRepairRequired("coverage original source changed")
        return value

    def load(self, key):
        with TransferProgress("coverage_checkpoint_restore", 1, unit="endpoints") as progress:
            try:
                with self.journal.read_transaction() as db:
                    value = self._load(key, db)
            except (ValueError, KeyError, IndexError, TypeError, sqlite3.DatabaseError) as error:
                progress.emit("repair_required", reason="coverage_completed_result_changed")
                raise CoverageCheckpointRepairRequired(
                    "coverage checkpoint requires explicit scoped repair"
                ) from error
            progress.advance(1, restored=value is not None)
            return value

    def remember(self, endpoint, keys, *, expected_sources=None, repair_reason=None):
        point = coverage_point(endpoint, self.rule)
        with self.journal.read_transaction() as db:
            tokens = self.sources(keys, db)
            if expected_sources is not None and tokens != expected_sources:
                raise CoverageCheckpointRepairRequired(
                    "coverage sources changed after native verification"
                )
            prior = self._load(point.key(), db) if repair_reason is None else None
        prepared = endpoint.prepared
        value = {
            "schema": ABI,
            "owner": self.owner,
            "semantics": self.semantics,
            "point": point.model_dump(mode="json"),
            "package_sha256": prepared.activation.package_sha256,
            "policy_sha256": endpoint.eligibility.policy_sha256,
            "requirement_sha256": prepared.requirement_sha256,
            "cohort_sha256": prepared.activation.cohort_sha256,
            "sources": tokens,
            "repair": repair_reason,
        }
        dependencies = getattr(endpoint, "model_dependencies", None)
        if dependencies is not None:
            dependencies = CoverageModelDependencies.model_validate_json(
                canonical_json_bytes(dependencies)
            )
            check_coverage_model_metadata(dependencies)
            value["model_dependencies"] = dependencies.model_dump(mode="json", by_alias=True)
        migration = False
        if prior is not None:
            if {**prior, "repair": None} == value:
                return
            if "model_dependencies" not in prior and {**prior, "repair": None} == {
                k: v for k, v in value.items() if k != "model_dependencies"
            }:
                migration = True
                value["repair"] = "native model dependency migration"
            else:
                raise CoverageCheckpointRepairRequired("coverage successful result changed")

        def recheck(db):
            if self.sources(((v[0], v[1]) for v in tokens), db) != tokens:
                raise CoverageCheckpointRepairRequired("coverage sources changed before completion")
            completed = db.execute(
                "SELECT owner FROM coverage_completion_ledger WHERE id=?", (point.key(),)
            ).fetchone()
            if completed is not None and completed != (self.owner,):
                raise CoverageCheckpointRepairRequired("coverage completed ledger owner changed")
            db.execute(
                "INSERT OR IGNORE INTO coverage_completion_ledger VALUES (?,?)",
                (point.key(), self.owner),
            )
            db.execute(
                "INSERT INTO coverage_checkpoint_index VALUES (?,?) "
                "ON CONFLICT(id) DO UPDATE SET result=excluded.result",
                (point.key(), digest(value)),
            )

        with TransferProgress(
            "coverage_model_dependency_checkpoint_migration"
            if migration
            else "coverage_checkpoint_commit",
            1,
            unit="endpoints",
            planning_unit_seconds=(0.00001, 0.01),
        ) as progress:
            self.journal.put_many(
                (
                    ("coverage_verified", digest(value), value),
                    (
                        "coverage_verified_done",
                        point.key(),
                        {"owner": self.owner, "key": point.key()},
                    ),
                ),
                index=recheck,
            )
            progress.advance(1)
