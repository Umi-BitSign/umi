"""Candidate evidence storage primitive; deliberately not wired into live workers.

The owner supplies a locked SQLite connection and commits with synchronous=FULL.
Every operation needs an explicit transaction, including reads (one snapshot).
Stored payload budgets exclude SQLite pages/indices and need a separate host disk
reservation. This format cannot be substituted for a v1 journal without an
authorized release transition and a qualified stopped migration.
"""

from __future__ import annotations

import hashlib
import sqlite3
from contextlib import contextmanager
from dataclasses import asdict, dataclass

from .competition_evidence_codec import (
    MAX_EVIDENCE_BYTES,
    MAX_METADATA_BYTES,
    MAX_RECIPE_BYTES,
    MAX_SEGMENTS,
    checked_digest,
    checked_size,
    decode_evidence,
    encode_evidence,
    inspect_recipe,
)
from .protocol import canonical_json_bytes

_SCHEMA = "umi-weight-evidence-store/1"
_TABLES = {
    "weight_proof_binding": "(id INTEGER PRIMARY KEY CHECK(id=1), body BLOB NOT NULL)",
    "weight_proof_objects": "(sha256 TEXT PRIMARY KEY, body BLOB NOT NULL)",
    "weight_proof_records": "(sha256 TEXT PRIMARY KEY, kind TEXT NOT NULL, "
    "expanded_bytes INTEGER NOT NULL, recipe BLOB NOT NULL, recipe_sha256 TEXT NOT NULL)",
    "weight_proof_reservations": "(id TEXT PRIMARY KEY, stored_bytes INTEGER NOT NULL, "
    "expanded_bytes INTEGER NOT NULL, records INTEGER NOT NULL, objects INTEGER NOT NULL)",
}


@dataclass(frozen=True)
class EvidenceBudget:
    stored_bytes: int
    expanded_bytes: int
    records: int
    objects: int

    def __post_init__(self):
        for value, maximum in zip(
            self.values(), (16 * 1024**3, 128 * 1024**3, 65536, 2000000), strict=True
        ):
            checked_size(value, maximum, minimum=0)

    def values(self) -> tuple[int, int, int, int]:
        return self.stored_bytes, self.expanded_bytes, self.records, self.objects

    def contains(self, other: EvidenceBudget) -> bool:
        return all(a >= b for a, b in zip(self.values(), other.values(), strict=True))


def observation_reservation(captures: int) -> EvidenceBudget:
    """Worst payload allowance for fresh proof+metadata pairs, without dedup credit.

    The owner chooses a finite recovery count and separately reserves physical
    SQLite/disk overhead. Unspent allowances remain durable until explicit release.
    """
    checked_size(captures, 65536)
    expanded = captures * (MAX_EVIDENCE_BYTES + MAX_METADATA_BYTES)
    return EvidenceBudget(
        expanded + captures * 2 * MAX_RECIPE_BYTES,
        expanded,
        captures * 2,
        captures * (MAX_SEGMENTS + 1),
    )


class EvidenceStore:
    def __init__(
        self,
        db: sqlite3.Connection,
        *,
        owner_binding_sha256: str,
        limits: EvidenceBudget,
        create: bool = False,
    ):
        self.db, self.limits = db, limits
        if min(limits.values()) <= 0:
            raise ValueError("evidence store needs explicit positive limits")
        self.binding = canonical_json_bytes(
            {
                "schema": _SCHEMA,
                "owner_binding_sha256": checked_digest(owner_binding_sha256),
                "limits": asdict(limits),
            }
        )
        self._transaction()
        existing = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='table'"))
        if create:
            if any(name in existing for name in _TABLES):
                raise ValueError("evidence store already exists or is incomplete")
            with self._atomic():
                for name, definition in _TABLES.items():
                    db.execute(f"CREATE TABLE {name} {definition}")
                db.execute("INSERT INTO weight_proof_binding VALUES (1,?)", (self.binding,))
        elif any(
            existing.get(name) != f"CREATE TABLE {name} {sql}" for name, sql in _TABLES.items()
        ):
            raise ValueError("evidence store schema missing or changed")
        self._bound()

    def _transaction(self):
        if not self.db.in_transaction:
            raise ValueError("evidence operation requires an owned SQLite transaction")

    def _bound(self):
        self._transaction()
        if self.db.execute("SELECT id,length(body) FROM weight_proof_binding").fetchall() != [
            (1, len(self.binding))
        ]:
            raise ValueError("evidence storage binding changed")
        if self.db.execute("SELECT id,body FROM weight_proof_binding").fetchall() != [
            (1, self.binding)
        ]:
            raise ValueError("evidence storage binding changed")

    @contextmanager
    def _atomic(self):
        self._transaction()
        self.db.execute("SAVEPOINT weight_proof_operation")
        try:
            yield
        except BaseException:
            self.db.execute("ROLLBACK TO weight_proof_operation")
            self.db.execute("RELEASE weight_proof_operation")
            raise
        else:
            self.db.execute("RELEASE weight_proof_operation")

    def inventory(self) -> EvidenceBudget:
        """Bounded size inventory only; use audit() to authenticate retained bytes."""
        self._bound()
        count, size, maximum = self.db.execute(
            "SELECT COUNT(*),COALESCE(SUM(length(body)),0),COALESCE(MAX(length(body)),0) "
            "FROM weight_proof_objects"
        ).fetchone()
        records, expanded, recipes, recipe_max = self.db.execute(
            "SELECT COUNT(*),COALESCE(SUM(expanded_bytes),0),COALESCE(SUM(length(recipe)),0),"
            "COALESCE(MAX(length(recipe)),0) FROM weight_proof_records"
        ).fetchone()
        if maximum > MAX_EVIDENCE_BYTES or recipe_max > MAX_RECIPE_BYTES:
            raise ValueError("evidence store contains oversized content")
        if (
            self.db.execute(
                "SELECT 1 FROM weight_proof_objects WHERE length(sha256)!=64 LIMIT 1"
            ).fetchone()
            or self.db.execute(
                "SELECT 1 FROM weight_proof_records WHERE length(sha256)!=64 "
                "OR length(recipe_sha256)!=64 OR length(kind)>8 LIMIT 1"
            ).fetchone()
        ):
            raise ValueError("evidence store identity exceeds bounds")
        usage = EvidenceBudget(size + recipes, expanded, records, count)
        if not self.limits.contains(usage):
            raise ValueError("evidence store exceeds limits")
        return usage

    def _reservations(self) -> dict[str, EvidenceBudget]:
        count, largest = self.db.execute(
            "SELECT COUNT(*),COALESCE(MAX(length(id)),0) FROM weight_proof_reservations"
        ).fetchone()
        if count > self.limits.records or largest > 64:
            raise ValueError("too many evidence reservations")
        return {
            checked_digest(row[0]): EvidenceBudget(*row[1:])
            for row in self.db.execute("SELECT * FROM weight_proof_reservations")
        }

    def _check_capacity(self, usage: EvidenceBudget, reservations: dict[str, EvidenceBudget]):
        totals = list(usage.values())
        for reserved in reservations.values():
            totals = [a + b for a, b in zip(totals, reserved.values(), strict=True)]
        if any(a > b for a, b in zip(totals, self.limits.values(), strict=True)):
            raise ValueError("evidence capacity exhausted including reservations")

    def reserve(self, identity: str, budget: EvidenceBudget):
        """Persist before signing; identity must be the owner's durable attempt ID."""
        checked_digest(identity)
        usage = self.inventory()
        reservations = self._reservations()
        self._check_capacity(usage, reservations)
        if identity in reservations:
            if reservations[identity] != budget:
                raise ValueError("existing evidence reservation changed")
            return
        if len(reservations) >= self.limits.records:
            raise ValueError("evidence reservation count exhausted")
        reservations[identity] = budget
        self._check_capacity(usage, reservations)
        with self._atomic():
            self.db.execute(
                "INSERT INTO weight_proof_reservations VALUES (?,?,?,?,?)",
                (identity, *budget.values()),
            )

    def release_reservation(self, identity: str):
        """Caller must establish terminal effect; this primitive grants no such proof."""
        self._bound()
        checked_digest(identity)
        self.db.execute("DELETE FROM weight_proof_reservations WHERE id=?", (identity,))

    def remaining_reservation(self, identity: str) -> EvidenceBudget | None:
        self._bound()
        return self._reservations().get(checked_digest(identity))

    def ensure_reservation(self, identity: str, minimum: EvidenceBudget):
        """Increase an existing allowance if capacity permits; never discard credit."""
        checked_digest(identity)
        usage = self.inventory()
        reservations = self._reservations()
        self._check_capacity(usage, reservations)
        previous = reservations.get(identity)
        if previous is None:
            self.reserve(identity, minimum)
            return
        raised = EvidenceBudget(
            *(max(a, b) for a, b in zip(previous.values(), minimum.values(), strict=True))
        )
        reservations[identity] = raised
        self._check_capacity(usage, reservations)
        self.db.execute(
            "UPDATE weight_proof_reservations SET stored_bytes=?,expanded_bytes=?,"
            "records=?,objects=? WHERE id=?",
            (*raised.values(), identity),
        )

    def _object(self, identity: str, size: int) -> bytes:
        found = self.db.execute(
            "SELECT length(body) FROM weight_proof_objects WHERE sha256=?", (identity,)
        ).fetchone()
        if found != (size,):
            raise ValueError("evidence object missing or wrong size")
        raw = self.db.execute(
            "SELECT body FROM weight_proof_objects WHERE sha256=?", (identity,)
        ).fetchone()[0]
        if not isinstance(raw, bytes) or hashlib.sha256(raw).hexdigest() != identity:
            raise ValueError("evidence object digest changed")
        return raw

    def _record(self, identity: str):
        checked_digest(identity)
        found = self.db.execute(
            "SELECT length(recipe),length(kind),length(recipe_sha256) "
            "FROM weight_proof_records WHERE sha256=?",
            (identity,),
        ).fetchone()
        if (
            found is None
            or not 0 < found[0] <= MAX_RECIPE_BYTES
            or not 0 < found[1] <= 8
            or found[2] != 64
        ):
            raise ValueError("evidence recipe missing or oversized")
        kind, expanded, recipe, checksum = self.db.execute(
            "SELECT kind,expanded_bytes,recipe,recipe_sha256 FROM weight_proof_records "
            "WHERE sha256=?",
            (identity,),
        ).fetchone()
        if not isinstance(recipe, bytes) or hashlib.sha256(recipe).hexdigest() != checksum:
            raise ValueError("evidence recipe digest changed")
        return kind, expanded, recipe

    def get(self, identity: str) -> bytes:
        self._bound()
        kind, size, recipe = self._record(identity)
        return decode_evidence(
            recipe, sha256=identity, expanded_bytes=size, kind=kind, resolve=self._object
        )

    def put(self, raw: bytes, *, kind: str, reservation: str | None = None) -> str:
        encoded = encode_evidence(raw, kind=kind)
        usage = self.inventory()
        reservations = self._reservations()
        self._check_capacity(usage, reservations)
        if reservation is not None and reservation not in reservations:
            raise ValueError("evidence reservation missing")
        if self.db.execute(
            "SELECT 1 FROM weight_proof_records WHERE sha256=?", (encoded.sha256,)
        ).fetchone():
            # v1 copies have no trustworthy persisted kind tag. An incoming
            # metadata body has already met the stricter metadata bound above;
            # reuse identical imported bytes without relabeling the old record.
            if self.get(encoded.sha256) != raw:
                raise ValueError("existing evidence identity changed")
            return encoded.sha256
        additions = {}
        for key, value in encoded.objects.items():
            if self.db.execute(
                "SELECT 1 FROM weight_proof_objects WHERE sha256=?", (key,)
            ).fetchone():
                if self._object(key, len(value)) != value:
                    raise ValueError("existing evidence object changed")
            else:
                additions[key] = value
        delta = EvidenceBudget(
            len(encoded.recipe) + sum(map(len, additions.values())), len(raw), 1, len(additions)
        )
        if reservation is not None:
            prior = reservations[reservation]
            if not prior.contains(delta):
                raise ValueError("evidence exceeds its reserved budget")
            reservations[reservation] = EvidenceBudget(
                *(a - b for a, b in zip(prior.values(), delta.values(), strict=True))
            )
        # Avoid constructing a capped Budget until the total has been checked.
        totals = tuple(a + b for a, b in zip(usage.values(), delta.values(), strict=True))
        if any(a > b for a, b in zip(totals, self.limits.values(), strict=True)):
            raise ValueError("evidence capacity exhausted")
        self._check_capacity(EvidenceBudget(*totals), reservations)
        with self._atomic():
            self.db.executemany("INSERT INTO weight_proof_objects VALUES (?,?)", additions.items())
            self.db.execute(
                "INSERT INTO weight_proof_records VALUES (?,?,?,?,?)",
                (
                    encoded.sha256,
                    kind,
                    len(raw),
                    encoded.recipe,
                    hashlib.sha256(encoded.recipe).hexdigest(),
                ),
            )
            if reservation is not None:
                self.db.execute(
                    "UPDATE weight_proof_reservations SET stored_bytes=?,expanded_bytes=?,"
                    "records=?,objects=? WHERE id=?",
                    (*reservations[reservation].values(), reservation),
                )
        return encoded.sha256

    def audit(self) -> EvidenceBudget:
        """Reconstruct every original hash, including evidence not referenced by an attempt.

        Cost is proportional to *expanded* history. No unchecked memoization skips
        this validation. Integration must account for that cost in lease timing.
        """
        usage = self.inventory()
        self._check_capacity(usage, self._reservations())
        for key, size in self.db.execute("SELECT sha256,length(body) FROM weight_proof_objects"):
            checked_digest(key)
            checked_size(size, MAX_EVIDENCE_BYTES)
            self._object(key, size)
        for (key,) in self.db.execute("SELECT sha256 FROM weight_proof_records"):
            kind, size, recipe = self._record(key)
            inspect_recipe(recipe, expanded_bytes=size, kind=kind)
            self.get(key)
        return usage
