"""Compatible receipt-mutation identity for bounded native result reuse.

Ordinary completed-object appends do not change this identity. Original receipt
mutations, damage and holds do. Existing read-only /4 producers remain readable;
only owners install the component. A fresh enrollment nonce makes losing the
whole component distinguishable from an unchanged prior frontier.
"""

import secrets

from .protocol import canonical_json_bytes

TABLE = "round_proof_receipt_mutation"
MARKER = "remote_proof_mutation_owner"
SCHEMA = "umi-proof-receipt-mutation/1"
TABLE_SQL = (
    f"CREATE TABLE {TABLE}(id INTEGER PRIMARY KEY CHECK(id=1),schema TEXT NOT NULL,"
    "namespace TEXT NOT NULL,epoch TEXT NOT NULL,revision INTEGER NOT NULL "
    "CHECK(TYPEOF(revision)='integer' AND revision>=0 AND revision<=9007199254740991))"
)


def triggers():
    change = f"UPDATE {TABLE} SET revision=revision+1 WHERE id=1; "
    change += (
        "SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,'receipt mutation owner missing') END;"
    )
    result = {}
    kinds = "('remote_proof_object','remote_proof_damage')"
    for action in ("UPDATE", "DELETE"):
        name = TABLE + "_receipt_" + action.lower()
        condition = f"OLD.kind IN {kinds}"
        if action == "UPDATE":
            condition += f" OR NEW.kind IN {kinds}"
        result[name] = (
            f"CREATE TRIGGER {name} AFTER {action} ON records WHEN {condition} BEGIN {change} END"
        )
        name = TABLE + "_owner_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records WHEN OLD.kind='{MARKER}' "
            "BEGIN SELECT RAISE(ABORT,'receipt mutation enrollment is immutable'); END"
        )
    name = TABLE + "_damage_insert"
    result[name] = (
        f"CREATE TRIGGER {name} AFTER INSERT ON records WHEN NEW.kind='remote_proof_damage' "
        f"BEGIN {change} END"
    )
    for action in ("INSERT", "UPDATE", "DELETE"):
        name = TABLE + "_hold_" + action.lower()
        result[name] = f"CREATE TRIGGER {name} AFTER {action} ON holds BEGIN {change} END"
    return result


def owner(namespace, epoch):
    return dict(schema=SCHEMA, namespace=namespace, epoch=epoch)


def validate_generation(db, namespace):
    table = db.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
    ).fetchone()
    fences = dict(
        db.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
            (TABLE + "_*",),
        )
    )
    marker = db.execute(
        "SELECT body FROM records WHERE kind=? AND id='owner'", (MARKER,)
    ).fetchone()
    if table is None and not fences and marker is None:
        return None
    if table != (TABLE_SQL,) or fences != triggers():
        raise ValueError(
            "remote proof receipt mutation generation missing or damaged; restore original metadata"
        )
    rows = db.execute(f"SELECT id,schema,namespace,epoch,revision FROM {TABLE} LIMIT 2").fetchall()
    if len(rows) != 1:
        raise ValueError("remote proof receipt mutation owner damaged")
    number, schema, selected, epoch, revision = rows[0]
    if (
        (number, schema, selected) != (1, SCHEMA, namespace)
        or type(epoch) is not str
        or len(epoch) != 64
        or any(c not in "0123456789abcdef" for c in epoch)
        or type(revision) is not int
        or not 0 <= revision <= 2**53 - 1
        or marker != (canonical_json_bytes(owner(namespace, epoch)),)
        or db.execute("SELECT 1 FROM holds WHERE id='owner'").fetchone() is not None
    ):
        raise ValueError("remote proof receipt mutation enrollment damaged")
    return dict(epoch=epoch, revision=revision)


def install_generation(journal, namespace):
    """Small transactional owner migration; never scan or rewrite receipts."""
    with journal.read_transaction() as db:
        if validate_generation(db, namespace) is not None:
            return
    epoch = secrets.token_hex(32)

    def initialize(db):
        # The immutable enrollment record has joined this same transaction;
        # pre-existing remnants were refused above, before insertion.
        if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone():
            raise ValueError("receipt mutation enrollment raced another owner")
        db.execute(TABLE_SQL)
        db.execute(f"INSERT INTO {TABLE} VALUES (1,?,?,?,0)", (SCHEMA, namespace, epoch))
        for statement in triggers().values():
            db.execute(statement)
        validate_generation(db, namespace)

    journal.put_many(((MARKER, "owner", owner(namespace, epoch)),), index=initialize)


def generation_identity(db):
    """Called within a native index snapshot whose schema was just validated."""
    if not db.in_transaction or db.execute("PRAGMA query_only").fetchone() != (1,):
        raise ValueError("receipt mutation identity requires its query-only snapshot")
    if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (TABLE,)).fetchone() is None:
        return None
    row = db.execute(f"SELECT epoch,revision FROM {TABLE} WHERE id=1").fetchone()
    return dict(epoch=row[0], revision=row[1])
