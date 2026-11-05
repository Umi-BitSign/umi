"""Resumable metadata discovery of legacy native preparation completions.

An endpoint lookup is a hint. Only the coverage owner's existing restoration
path can establish its authority and dependencies. This index never reads an
original package, model, history proof or coverage source payload.
"""

from .competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired
from .competition_reward_coverage_intervals import CoveragePoint
from .competition_transport_verification import TransferProgress
from .open_competition import digest

PREFIX = "preparation_coverage_lookup"
TABLE = PREFIX + "_endpoints"
STATE = PREFIX + "_state"
PENDING = PREFIX + "_pending"
INDEX = PREFIX + "_activation"
SCHEMA = {
    TABLE: f"CREATE TABLE {TABLE}(position INTEGER UNIQUE NOT NULL,id TEXT PRIMARY KEY,"
    "activation TEXT NOT NULL,block INTEGER NOT NULL,result TEXT NOT NULL)",
    STATE: f"CREATE TABLE {STATE}(id INTEGER PRIMARY KEY CHECK(id=1),"
    "position INTEGER NOT NULL,number INTEGER NOT NULL)",
    PENDING: f"CREATE TABLE {PENDING}(id TEXT PRIMARY KEY)",
    INDEX: f"CREATE INDEX {INDEX} ON {TABLE}(activation,block,id)",
}


def _triggers():
    result = {
        PREFIX + "_identity": (
            f"CREATE TRIGGER {PREFIX}_identity BEFORE UPDATE ON {TABLE} "
            "WHEN OLD.position!=NEW.position OR OLD.id!=NEW.id OR "
            "OLD.activation!=NEW.activation OR OLD.block!=NEW.block BEGIN SELECT "
            "RAISE(ABORT,'preparation completion identity is immutable'); END"
        ),
        PREFIX + "_result": (
            f"CREATE TRIGGER {PREFIX}_result BEFORE UPDATE ON {TABLE} "
            "WHEN NOT EXISTS(SELECT 1 FROM coverage_checkpoint_index "
            "WHERE id=NEW.id AND result=NEW.result) BEGIN SELECT "
            "RAISE(ABORT,'preparation completion result lacks its native index'); END"
        ),
    }
    for action in ("INSERT", "DELETE"):
        result[PREFIX + "_count_" + action.lower()] = (
            f"CREATE TRIGGER {PREFIX}_count_{action.lower()} AFTER {action} ON {TABLE} "
            f"BEGIN UPDATE {STATE} SET number=number{'+' if action == 'INSERT' else '-'}1 "
            "WHERE id=1; SELECT CASE WHEN changes()!=1 THEN "
            "RAISE(ABORT,'preparation coverage lookup lost its count') END; END"
        )
    for action in ("UPDATE", "DELETE"):
        suffix = action.lower()
        result[PREFIX + "_checkpoint_" + suffix] = (
            f"CREATE TRIGGER {PREFIX}_checkpoint_{suffix} AFTER {action} "
            "ON coverage_checkpoint_index "
            + ("WHEN OLD.result!=NEW.result OR OLD.id!=NEW.id " if action == "UPDATE" else "")
            + f"BEGIN INSERT OR IGNORE INTO {PENDING} VALUES (OLD.id); END"
        )
        result[PREFIX + "_owner_" + suffix] = (
            f"CREATE TRIGGER {PREFIX}_owner_{suffix} BEFORE {action} ON records "
            f"WHEN OLD.kind='{PREFIX}' BEGIN SELECT "
            "RAISE(ABORT,'preparation coverage lookup owner is immutable'); END"
        )
    return result


class PreparationCoverageIndex:
    """Index each completed endpoint once, in bounded restartable transactions."""

    def __init__(self, owner):
        self.owner, self.journal = owner, owner.journal
        self.marker = {
            "schema": "umi-preparation-coverage-lookup/1",
            "owner": owner.checkpoints.owner,
        }
        self.triggers = _triggers()
        before = self.journal.get(PREFIX, "owner")

        def initialize(db):
            installed = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB ? LIMIT 1", (PREFIX + "_*",)
            ).fetchone()
            if installed is None and before is None:
                for sql in SCHEMA.values():
                    db.execute(sql)
                db.execute(f"INSERT INTO {STATE} VALUES (1,0,0)")
                for sql in self.triggers.values():
                    db.execute(sql)
            elif installed is None or before != self.marker:
                raise CoverageCheckpointRepairRequired("preparation coverage lookup owner changed")
            self._state(db)

        self.journal.put_many(((PREFIX, "owner", self.marker),), index=initialize)

    def _state(self, db):
        self.owner.checkpoints.check_schema(db)
        actual = dict(
            db.execute("SELECT name,sql FROM sqlite_master WHERE name GLOB ?", (PREFIX + "_*",))
        )
        if (
            actual != SCHEMA | self.triggers
            or self.journal.get(PREFIX, "owner", db=db) != self.marker
        ):
            raise CoverageCheckpointRepairRequired("preparation coverage lookup schema changed")
        state = db.execute(f"SELECT position,number FROM {STATE} WHERE id=1").fetchone()
        last = db.execute(
            "SELECT COALESCE(MAX(rowid),0) FROM coverage_completion_ledger"
        ).fetchone()[0]
        if state is None or state[0] != state[1] or not 0 <= state[0] <= last:
            raise CoverageCheckpointRepairRequired("preparation coverage lookup progress changed")
        return state[0], last

    def _retain(self, db, position, key):
        retained = db.execute(
            "SELECT result FROM coverage_checkpoint_index WHERE id=?", (key,)
        ).fetchone()
        if retained is None:
            raise CoverageCheckpointRepairRequired(
                "completed endpoint lost its native result index"
            )
        value = self.journal.get("coverage_verified", retained[0], db=db)
        marker = self.journal.get("coverage_verified_done", key, db=db)
        try:
            if (
                type(value) is not dict
                or digest(value) != retained[0]
                or value["owner"] != self.owner.checkpoints.owner
                or marker != {"owner": self.owner.checkpoints.owner, "key": key}
            ):
                raise ValueError("changed completion")
            point = CoveragePoint.model_validate(value["point"])
            if point.key() != key or point.series_sha256 != self.owner.rule.series_sha256:
                raise ValueError("changed completion domain")
        except (ValueError, KeyError, TypeError) as error:
            raise CoverageCheckpointRepairRequired(
                "completed endpoint metadata requires repair"
            ) from error
        # Discovery does not check sources or treat this metadata as a verdict.
        # The selected endpoint goes through the original native owner once.
        db.execute(
            f"INSERT INTO {TABLE} VALUES (?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET "
            "activation=excluded.activation,block=excluded.block,result=excluded.result",
            (position, key, point.activation_sha256, point.block, retained[0]),
        )

    def advance(self, activation, *, maximum_endpoints=256):
        """Return (drained, endpoint); no match is meaningful only when drained."""
        if type(maximum_endpoints) is not int or maximum_endpoints < 1:
            raise ValueError("preparation discovery requires a positive metadata batch")
        with self.journal.locked(), self.journal.transaction() as db:
            position, last = self._state(db)
            pending = db.execute(
                f"SELECT id FROM {PENDING} ORDER BY id LIMIT ?", (maximum_endpoints,)
            ).fetchall()
            with TransferProgress(
                "standing_preparation_completion_inventory",
                last + db.execute(f"SELECT COUNT(*) FROM {PENDING}").fetchone()[0],
                unit="endpoints",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress:
                progress.advance(position, restored=True)
                for (key,) in pending:
                    row = db.execute(
                        "SELECT rowid,owner FROM coverage_completion_ledger WHERE id=?", (key,)
                    ).fetchone()
                    if row is None or row[1] != self.owner.checkpoints.owner:
                        raise CoverageCheckpointRepairRequired(
                            "completed endpoint lost its original owner"
                        )
                    # A future ledger page owns as-yet-unindexed endpoints.
                    if row[0] <= position:
                        self._retain(db, row[0], key)
                    db.execute(f"DELETE FROM {PENDING} WHERE id=?", (key,))
                    progress.advance(1)
                rows = db.execute(
                    "SELECT rowid,id,owner FROM coverage_completion_ledger WHERE rowid>? "
                    "ORDER BY rowid LIMIT ?",
                    (position, maximum_endpoints - len(pending)),
                ).fetchall()
                for number, key, owner in rows:
                    if number != position + 1 or owner != self.owner.checkpoints.owner:
                        raise CoverageCheckpointRepairRequired(
                            "coverage completion inventory changed"
                        )
                    self._retain(db, number, key)
                    position = number
                    db.execute(f"UPDATE {STATE} SET position=? WHERE id=1", (position,))
                    progress.advance(1)
                self._state(db)
                drained = (
                    position == last
                    and db.execute(f"SELECT 1 FROM {PENDING} LIMIT 1").fetchone() is None
                )
                if not drained:
                    progress.emit("pending", reason="retained_completion_metadata_remaining")
                    return False, None
                selected = db.execute(
                    f"SELECT id,result FROM {TABLE} WHERE activation=? ORDER BY block,id LIMIT 1",
                    (digest(activation),),
                ).fetchone()
                if selected is None:
                    return True, None
                actual = db.execute(
                    "SELECT result FROM coverage_checkpoint_index WHERE id=?", (selected[0],)
                ).fetchone()
                if actual != (selected[1],):
                    raise CoverageCheckpointRepairRequired(
                        "selected preparation endpoint index changed"
                    )
                return True, selected[0]
