"""Private evaluator order/artifact obligations, consumed by their native writes.

Reservation never admits an order or starts execution. The caller must derive
the complete artifact inventory and validate the eventual signed order before
admission. Logical byte budgets exclude SQLite and filesystem overhead.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

from .competition_evaluator_orders import EvaluationOrder, SignedEvaluationOrder
from .open_competition import digest
from .private_files import MAX_PRIVATE_BYTES
from .protocol import canonical_json_bytes

GENERATION = 2
_HEX = re.compile(r"[0-9a-f]{64}")
_KIND = re.compile(r"[A-Za-z0-9_:+-]{1,160}")
_TABLES = (
    "binding",
    "orders",
    "artifacts",
    "capacity_identity",
    "capacity_batches",
    "capacity_orders",
    "capacity_artifacts",
)


@dataclass(frozen=True)
class ArtifactReservation:
    kind: str
    maximum_bytes: int


@dataclass(frozen=True)
class OrderReservation:
    slot: str
    order_sha256: str
    maximum_bytes: int
    artifacts: tuple[ArtifactReservation, ...]


class ReservedOrderConflict(ValueError):
    """The caller must commit a native hold before propagating this error."""


def order_binding(order: EvaluationOrder) -> str:
    """Bind fixed order bytes, excluding the not-yet-created publication quorum."""
    value = order.model_dump(mode="json", by_alias=True)
    if order.publication is not None:
        value["publication"] = order.publication.publication.model_dump(mode="json", by_alias=True)
    return digest(value)


def _fences():
    for table in _TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"capacity_{table}_{operation.lower()}"
            yield (
                name,
                (
                    f"CREATE TRIGGER {name} BEFORE {operation} ON {table} "
                    "BEGIN SELECT CASE WHEN umi_evaluator_writer_generation() IS NOT 2 "
                    "THEN RAISE(ABORT, 'evaluator writer generation mismatch') END; END"
                ),
            )


def connect(db):
    db.create_function("umi_evaluator_writer_generation", 0, lambda: GENERATION)


def generation(db):
    version = db.execute("PRAGMA user_version").fetchone()[0]
    if version not in (0, GENERATION):
        raise ValueError("unsupported evaluator journal generation")
    if (
        version == 0
        and db.execute(
            "SELECT 1 FROM sqlite_master WHERE name GLOB 'capacity_*' LIMIT 1"
        ).fetchone()
    ):
        raise ValueError("evaluator capacity generation marker was downgraded")
    if version == GENERATION:
        actual = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'"))
        if any(actual.get(name) != sql for name, sql in _fences()):
            raise ValueError("evaluator capacity writer fences changed")
        identity = db.execute("SELECT value FROM capacity_identity").fetchall()
        if (
            len(identity) != 1
            or not isinstance(identity[0][0], str)
            or not _HEX.fullmatch(identity[0][0])
        ):
            raise ValueError("evaluator capacity journal identity changed")
    return version


def _install(db):
    if generation(db):
        return
    if db.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'capacity_%'").fetchone():
        raise ValueError("partial evaluator capacity migration")
    db.execute("CREATE TABLE capacity_identity (value TEXT NOT NULL)")
    db.execute("INSERT INTO capacity_identity VALUES (?)", (uuid.uuid4().hex + uuid.uuid4().hex,))
    db.execute("CREATE TABLE capacity_batches (id TEXT PRIMARY KEY, body BLOB NOT NULL)")
    db.execute(
        "CREATE TABLE capacity_orders (slot TEXT PRIMARY KEY, binding TEXT NOT NULL, "
        "maximum_bytes INTEGER NOT NULL, consumed INTEGER NOT NULL CHECK(consumed IN (0,1)), "
        "conflict INTEGER NOT NULL DEFAULT 0 CHECK(conflict IN (0,1)))"
    )
    db.execute(
        "CREATE TABLE capacity_artifacts (slot TEXT NOT NULL, kind TEXT NOT NULL, "
        "maximum_bytes INTEGER NOT NULL, consumed INTEGER NOT NULL CHECK(consumed IN (0,1)), "
        "PRIMARY KEY(slot,kind))"
    )
    for _, sql in _fences():
        db.execute(sql)
    db.execute(f"PRAGMA user_version={GENERATION}")


def usage(db):
    """Return reserved logical bytes and unconsumed order slots."""
    if db.execute("PRAGMA user_version").fetchone()[0] == 0:
        return 0, 0
    pending = sum(
        db.execute(
            f"SELECT COALESCE(SUM(maximum_bytes),0) FROM {table} WHERE consumed=0"
        ).fetchone()[0]
        for table in ("capacity_orders", "capacity_artifacts")
    )
    metadata = db.execute("SELECT COALESCE(SUM(length(body)),0) FROM capacity_batches").fetchone()[
        0
    ]
    count = db.execute("SELECT count(*) FROM capacity_orders WHERE consumed=0").fetchone()[0]
    return pending + metadata, count


def credit(db, slot, kind, raw, *, binding=None):
    """Check an exact obligation; return its pending allowance without consuming it."""
    if db.execute("PRAGMA user_version").fetchone()[0] == 0:
        return 0
    if kind is None:
        row = db.execute(
            "SELECT maximum_bytes,consumed,binding,conflict FROM capacity_orders WHERE slot=?",
            (slot,),
        ).fetchone()
        if row and (binding != row[2] or row[3]):
            raise ReservedOrderConflict(
                "evaluation order differs from reserved identity or is held"
            )
    else:
        row = db.execute(
            "SELECT maximum_bytes,consumed FROM capacity_artifacts WHERE slot=? AND kind=?",
            (slot, kind),
        ).fetchone()
    if row is None:
        return 0
    if row[1] or len(raw) > row[0]:
        raise ValueError("evaluator artifact exceeds or has lost its reserved allowance")
    return row[0]


def consume(db, slot, kind):
    if db.execute("PRAGMA user_version").fetchone()[0] == 0:
        return
    if kind is None:
        db.execute("UPDATE capacity_orders SET consumed=1 WHERE slot=?", (slot,))
    else:
        db.execute("UPDATE capacity_artifacts SET consumed=1 WHERE slot=? AND kind=?", (slot, kind))


def _size(value):
    if type(value) is not int or not 0 < value <= MAX_PRIVATE_BYTES:
        raise ValueError("invalid evaluator artifact allowance")


def normalize(specs, maximum_orders, maximum_bytes):
    """Bound staging and require one explicit allowance per exact native slot."""
    result, slots, staged = [], set(), 0
    for spec in specs:
        if not isinstance(spec, OrderReservation) or len(result) >= maximum_orders:
            raise ValueError("invalid or excessive evaluator order reservation")
        if (
            not isinstance(spec.slot, str)
            or not _HEX.fullmatch(spec.slot)
            or not isinstance(spec.order_sha256, str)
            or not _HEX.fullmatch(spec.order_sha256)
            or spec.slot in slots
        ):
            raise ValueError("invalid or duplicate evaluator reserved identity")
        _size(spec.maximum_bytes)
        artifacts, kinds = [], set()
        for artifact in spec.artifacts:
            if not isinstance(artifact, ArtifactReservation) or len(artifacts) >= 4096:
                raise ValueError("invalid or excessive evaluator artifact reservation")
            if (
                not isinstance(artifact.kind, str)
                or not _KIND.fullmatch(artifact.kind)
                or artifact.kind.startswith("conflict:")
                or artifact.kind in kinds
            ):
                raise ValueError("invalid or duplicate reserved evaluator artifact kind")
            _size(artifact.maximum_bytes)
            artifacts.append(artifact)
            kinds.add(artifact.kind)
            staged += len(canonical_json_bytes(asdict(artifact))) + 1
            if staged > maximum_bytes:
                raise ValueError("evaluator reservation staging exceeds capacity")
        result.append(
            OrderReservation(
                spec.slot,
                spec.order_sha256,
                spec.maximum_bytes,
                tuple(sorted(artifacts, key=lambda item: item.kind)),
            )
        )
        slots.add(spec.slot)
        staged += (
            len(
                canonical_json_bytes(
                    {
                        "slot": spec.slot,
                        "order_sha256": spec.order_sha256,
                        "maximum_bytes": spec.maximum_bytes,
                        "artifacts": [],
                    }
                )
            )
            + 1
        )
        if staged > maximum_bytes:
            raise ValueError("evaluator reservation staging exceeds capacity")
    if not result:
        raise ValueError("empty evaluator reservation")
    return tuple(sorted(result, key=lambda item: item.slot))


def parse_receipt(raw):
    """Parse bounded private metadata without accepting a different generation."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_PRIVATE_BYTES:
        raise ValueError("evaluator reservation receipt exceeds its byte bound")
    try:
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema",
                "batch_id",
                "generation",
                "journal_path",
                "journal_identity",
                "binding_sha256",
                "orders",
            }
            or value["schema"] != "umi-private-evaluator-reservation/1"
            or type(value["generation"]) is not int
            or value["generation"] != GENERATION
        ):
            raise ValueError("invalid evaluator reservation receipt schema")
        if any(
            not isinstance(value[key], str) or not _HEX.fullmatch(value[key])
            for key in ("batch_id", "journal_identity", "binding_sha256")
        ):
            raise ValueError("invalid evaluator reservation receipt identity")
        if (
            not isinstance(value["journal_path"], str)
            or not 0 < len(value["journal_path"]) <= 4096
            or not Path(value["journal_path"]).is_absolute()
            or not isinstance(value["orders"], list)
        ):
            raise ValueError("invalid evaluator reservation receipt path or orders")
        specs = []
        for order in value["orders"]:
            if (
                not isinstance(order, dict)
                or set(order) != {"slot", "order_sha256", "maximum_bytes", "artifacts"}
                or not isinstance(order["artifacts"], list)
            ):
                raise ValueError("invalid evaluator reservation receipt order")
            artifacts = []
            for artifact in order["artifacts"]:
                if not isinstance(artifact, dict) or set(artifact) != {"kind", "maximum_bytes"}:
                    raise ValueError("invalid evaluator reservation receipt artifact")
                artifacts.append(ArtifactReservation(**artifact))
            specs.append(
                OrderReservation(
                    order["slot"], order["order_sha256"], order["maximum_bytes"], tuple(artifacts)
                )
            )
        normalized = normalize(specs, 65536, MAX_PRIVATE_BYTES)
        value["orders"] = [asdict(spec) for spec in normalized]
        if canonical_json_bytes(value) != raw:
            raise ValueError("evaluator reservation receipt is not canonical and ordered")
        return value
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid evaluator reservation receipt") from exc


def reserve(db, batch_id, specs, *, path, config, check_capacity):
    if not isinstance(batch_id, str) or not _HEX.fullmatch(batch_id):
        raise ValueError("invalid evaluator reservation batch identity")
    _install(db)
    receipt = {
        "schema": "umi-private-evaluator-reservation/1",
        "batch_id": batch_id,
        "generation": GENERATION,
        "journal_path": str(path.resolve()),
        "journal_identity": db.execute("SELECT value FROM capacity_identity").fetchone()[0],
        "binding_sha256": hashlib.sha256(
            bytes(db.execute("SELECT body FROM binding").fetchone()[0])
        ).hexdigest(),
        "orders": [],
    }
    envelope = len(canonical_json_bytes(receipt))
    specs = normalize(
        specs,
        config.maximum_orders,
        min(config.maximum_journal_bytes, MAX_PRIVATE_BYTES) - envelope,
    )
    receipt["orders"] = [asdict(spec) for spec in specs]
    raw = canonical_json_bytes(receipt)
    if len(raw) > MAX_PRIVATE_BYTES:
        raise ValueError("evaluator reservation receipt exceeds its byte bound")
    previous_size = db.execute(
        "SELECT length(body) FROM capacity_batches WHERE id=?", (batch_id,)
    ).fetchone()
    if previous_size is not None and not 0 < previous_size[0] <= MAX_PRIVATE_BYTES:
        raise ValueError("retained evaluator reservation receipt exceeds its byte bound")
    old = db.execute("SELECT body FROM capacity_batches WHERE id=?", (batch_id,)).fetchone()
    if old:
        if bytes(old[0]) != raw:
            raise ValueError("evaluator reservation batch changed")
        parse_receipt(bytes(old[0]))
        verify(db, receipt)
        check_capacity(db, 0)
        return receipt
    if db.execute("SELECT count(*) FROM capacity_batches").fetchone()[0] >= config.maximum_orders:
        raise ValueError("evaluator reservation batch capacity exhausted")
    for spec in specs:
        current = db.execute(
            "SELECT binding,maximum_bytes,conflict FROM capacity_orders WHERE slot=?", (spec.slot,)
        ).fetchone()
        if current and current != (spec.order_sha256, spec.maximum_bytes, 0):
            raise ValueError("overlapping evaluator order reservation changed")
        order = db.execute("SELECT body,conflict FROM orders WHERE slot=?", (spec.slot,)).fetchone()
        if order and (
            order[1]
            or len(order[0]) > spec.maximum_bytes
            or order_binding(SignedEvaluationOrder.model_validate_json(order[0]).order)
            != spec.order_sha256
        ):
            raise ValueError("retained order does not match evaluator reservation")
        if not current:
            db.execute(
                "INSERT INTO capacity_orders(slot,binding,maximum_bytes,consumed) VALUES (?,?,?,?)",
                (spec.slot, spec.order_sha256, spec.maximum_bytes, int(order is not None)),
            )
        for artifact in spec.artifacts:
            current = db.execute(
                "SELECT maximum_bytes FROM capacity_artifacts WHERE slot=? AND kind=?",
                (spec.slot, artifact.kind),
            ).fetchone()
            if current and current[0] != artifact.maximum_bytes:
                raise ValueError("overlapping evaluator artifact reservation changed")
            retained = db.execute(
                "SELECT length(body) FROM artifacts WHERE slot=? AND kind=?",
                (spec.slot, artifact.kind),
            ).fetchone()
            if retained and retained[0] > artifact.maximum_bytes:
                raise ValueError("retained evaluator artifact exceeds reservation")
            if not current:
                db.execute(
                    "INSERT INTO capacity_artifacts VALUES (?,?,?,?)",
                    (spec.slot, artifact.kind, artifact.maximum_bytes, int(retained is not None)),
                )
    db.execute("INSERT INTO capacity_batches VALUES (?,?)", (batch_id, raw))
    if (
        db.execute("SELECT count(*) FROM orders").fetchone()[0] + usage(db)[1]
        > config.maximum_orders
    ):
        raise ValueError("evaluator reserved order capacity exhausted")
    check_capacity(db, 0)
    verify(db, receipt)
    return receipt


def verify(db, receipt):
    """Check that each receipt still has its native pending credit or retained row."""
    if (
        generation(db) != GENERATION
        or db.execute("SELECT value FROM capacity_identity").fetchone()[0]
        != receipt["journal_identity"]
    ):
        raise ValueError("evaluator reservation journal identity mismatch")
    for spec in receipt["orders"]:
        row = db.execute(
            "SELECT binding,maximum_bytes,consumed,conflict FROM capacity_orders WHERE slot=?",
            (spec["slot"],),
        ).fetchone()
        if row is None or row[:2] != (spec["order_sha256"], spec["maximum_bytes"]) or row[3]:
            raise ValueError("evaluator reserved order missing or changed")
        retained = db.execute(
            "SELECT body,conflict FROM orders WHERE slot=?", (spec["slot"],)
        ).fetchone()
        if bool(row[2]) != (retained is not None) or (
            retained
            and (
                retained[1]
                or len(retained[0]) > row[1]
                or order_binding(SignedEvaluationOrder.model_validate_json(retained[0]).order)
                != row[0]
            )
        ):
            raise ValueError("evaluator reserved order consumption mismatch")
        for artifact in spec["artifacts"]:
            row = db.execute(
                "SELECT maximum_bytes,consumed FROM capacity_artifacts WHERE slot=? AND kind=?",
                (spec["slot"], artifact["kind"]),
            ).fetchone()
            retained = db.execute(
                "SELECT length(body) FROM artifacts WHERE slot=? AND kind=?",
                (spec["slot"], artifact["kind"]),
            ).fetchone()
            if (
                row is None
                or row[0] != artifact["maximum_bytes"]
                or bool(row[1]) != (retained is not None)
                or (retained and retained[0] > row[0])
            ):
                raise ValueError("evaluator reserved artifact consumption mismatch")
