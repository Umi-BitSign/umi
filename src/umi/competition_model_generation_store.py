"""Account-owned immutable model generations and durable damage/repair fences.

The root-controlled selection names the retention owner and exact R2 namespace.
This is transport state, not model admission, rights, certification or a promise
of present availability. All consumers sharing an owner must select this same
durable root. Remote deletion/replacement is deliberately not an owner operation.
"""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from contextlib import closing
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import (
    ensure_private_directory,
    lock_private_file,
    publish_private_model,
    read_private_model,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .sqlite_contention import is_sqlite_contention

CHUNKED_MODEL_BYTE_ABI = "umi-chunked-model-backup-bytes/1"


class ModelGenerationRepairRequired(ValueError):
    """Restore original owner metadata or explicitly repair its original object."""


class ModelGenerationOwnerBusy(OSError):
    """A live SQLite writer still owns recovery; retry without changing evidence."""


class ModelGenerationStoreConfig(StrictProtocolModel):
    schema_: Literal["umi-model-generation-owner/1"] = Field(alias="schema")
    owner_sha256: Hex32
    namespace_sha256: Hex32
    retention: Literal["retain_original_generations_until_authenticated_release"]
    maximum_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)] = 256 * 1024**2

    @model_validator(mode="after")
    def explicit_owner(self):
        if "0" * 64 in (self.owner_sha256, self.namespace_sha256):
            raise ValueError("model generation reuse requires an explicit namespace and owner")
        return self


_MARKER = "round_generation_model_owner"
_CAPACITY_HOLD = "model-generation-capacity-repair"
_SCHEMA = (
    "CREATE TABLE round_generation_model_owner (id INTEGER PRIMARY KEY CHECK(id=1), "
    "binding TEXT NOT NULL, completed INTEGER NOT NULL CHECK(completed>=0))"
)


def _triggers():
    result = {}
    for action in ("UPDATE", "DELETE"):
        name = _MARKER + "_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records BEGIN SELECT "
            "RAISE(ABORT,'model generation history is immutable; restore original metadata'); END"
        )
    name = _MARKER + "_insert"
    result[name] = (
        f"CREATE TRIGGER {name} AFTER INSERT ON records BEGIN "
        f"UPDATE {_MARKER} SET completed=completed+1 WHERE id=1; "
        "SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,"
        "'model generation owner missing; restore original metadata') END; END"
    )
    return result


class _GenerationIndex(RoundJournal):
    def _validate_existing(self, binding):
        rollback = Path(str(self.path) + "-journal")
        if rollback.exists():
            # mode=rw cannot create a missing database. SQLite itself obtains
            # the recovery lock: a live writer remains its owner, while an
            # abandoned hot journal is rolled back to committed original bytes.
            # Never delete a sidecar or replace the database with an older copy.
            with TransferProgress(
                "model_generation_owner_recovery",
                1,
                unit="owners",
                planning_unit_seconds=(0.001, 5),
            ) as progress:
                try:
                    with closing(
                        sqlite3.connect(
                            self.path.resolve().as_uri() + "?mode=rw",
                            uri=True,
                            isolation_level=None,
                            timeout=5,
                        )
                    ) as db:
                        db.execute("PRAGMA cache_size=-8192")
                        expected = canonical_json_bytes(binding)
                        rows = db.execute(
                            "SELECT CASE WHEN LENGTH(body)<=? THEN body END FROM binding LIMIT 2",
                            (len(expected),),
                        ).fetchall()
                        if rows != [(expected,)]:
                            raise ModelGenerationRepairRequired("recovered owner binding differs")
                    progress.advance(1, restored=True)
                except sqlite3.OperationalError as error:
                    if is_sqlite_contention(error):
                        progress.emit("retrying", reason="model_generation_live_writer")
                        raise ModelGenerationOwnerBusy(
                            "model generation owner has a live writer"
                        ) from error
                    raise
        # Validate a committed read snapshot while another selected consumer
        # owns a live rollback journal. No connection is retained. Actual writes
        # still acquire SQLite's writer transaction after construction finishes.
        previous = self.read_only
        self.read_only = True
        try:
            return super()._validate_existing(binding, require_clean_rollback=False)
        finally:
            self.read_only = previous

    @property
    def maximum_records(self):
        return self.maximum_bytes

    @staticmethod
    def _version(db):
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version != 5:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_MARKER,)).fetchone():
                raise ModelGenerationRepairRequired("model generation owner was downgraded")
            return RoundJournal._version(db)
        schema = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (_MARKER,)
        ).fetchone()
        triggers = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
                (_MARKER + "_*",),
            )
        )
        binding = db.execute("SELECT body FROM binding LIMIT 2").fetchall()
        capacity = db.execute("SELECT number FROM round_record_capacity WHERE id=1").fetchone()
        if (
            schema != (_SCHEMA,)
            or triggers != _triggers()
            or len(binding) != 1
            or capacity is None
            or db.execute(f"SELECT id,binding,completed FROM {_MARKER} LIMIT 2").fetchall()
            != [(1, digest(json.loads(binding[0][0])), capacity[0])]
        ):
            raise ModelGenerationRepairRequired("model generation ledger damaged; restore metadata")
        if db.execute("SELECT 1 FROM holds WHERE id=?", (_CAPACITY_HOLD,)).fetchone():
            raise ModelGenerationRepairRequired(
                "model generation capacity hold; owner repair required"
            )
        return 0

    def initialize(self, binding):
        with self.transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 5:
                return
            if db.execute("SELECT 1 FROM records LIMIT 1").fetchone():
                raise ModelGenerationRepairRequired(
                    "generation initialization requires empty owner"
                )
            db.execute(_SCHEMA)
            db.execute(f"INSERT INTO {_MARKER} VALUES (1,?,0)", (digest(binding),))
            for sql in _triggers().values():
                db.execute(sql)
            db.execute("PRAGMA user_version=5")

    def insert_event(self, db, kind, key, raw):
        self.maximum_bytes = self.capacity(db, self.enrolled_capacity)[0]
        pending_kind = "pending-" + kind
        # A capacity decision may have committed while its pending-event
        # migration is still running. Preserve the first held observation until
        # that exact event is applied, even though ordinary space is now free.
        if self.pending(db, pending_kind) is not None:
            return False
        count, used, _ = self._record_capacity(db)
        if count + 1 > self.maximum_records or used + len(raw) > self.maximum_bytes:
            event = json.loads(raw)
            category, object_id = kind.split(":", 1)
            if category not in {"damage", "repair"} or event.get("object") != object_id:
                raise ModelGenerationRepairRequired("pending generation event identity differs")
            original = self.get("object", object_id, db=db)
            if original is None or (category == "damage" and event.get("generation") != original):
                raise ModelGenerationRepairRequired("pending event lacks original generation")
            # No repair can clear an unapplied pending event. Coalescing further
            # observations of that same affected object cannot forget a repair.
            compact = (
                {"object": object_id, "reason": event["reason"]} if category == "damage" else event
            )
            body = canonical_json_bytes(compact)
            if len(body) > 512:
                raise ValueError("pending model generation event exceeds its metadata bound")
            # At most one outstanding compact damage and repair per completed
            # object. This bounded emergency allowance is separate from ordinary
            # admission; immutable records/counters protect it across crashes.
            db.execute("INSERT INTO records VALUES (?,?,?)", (pending_kind, key, body))
            return False
        db.execute("INSERT INTO records(kind,id,body) VALUES (?,?,?)", (kind, key, raw))
        return True

    def pending(self, db, kind):
        row = db.execute(
            "SELECT id FROM records WHERE kind=? ORDER BY id DESC LIMIT 1", (kind,)
        ).fetchone()
        if row is None:
            return None
        key = row[0]
        value = self.get(kind, key, db=db)
        applied = self.get("applied-" + kind, key, db=db)
        if applied is not None and applied != {"pending": digest(value)}:
            raise ModelGenerationRepairRequired("pending generation migration marker differs")
        return None if applied is not None else (key, value)

    def capacity(self, db, initial):
        row = db.execute(
            "SELECT id FROM records WHERE kind='owner-capacity' ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if row is None:
            return initial, 0
        value = self.get("owner-capacity", row[0], db=db)
        if (
            set(value) != {"owner", "previous_maximum_bytes", "maximum_bytes"}
            or value["owner"] != self.owner_binding
            or type(value["maximum_bytes"]) is not int
            or not initial < value["maximum_bytes"] <= 16 * 1024**3
            or type(value["previous_maximum_bytes"]) is not int
            or not initial <= value["previous_maximum_bytes"] < value["maximum_bytes"]
            or len(row[0]) != 16
            or not row[0].isdigit()
        ):
            raise ModelGenerationRepairRequired("model owner capacity history differs")
        return value["maximum_bytes"], int(row[0])


def _binding(config, semantics):
    return {
        "schema": "umi-model-generation-ledger/1",
        "owner": config.model_dump(mode="json", by_alias=True),
        "semantics": semantics,
    }


def _paths(root, config):
    root = Path(root) / "generation-owners-v1"
    return root, root / config.owner_sha256, root / (config.owner_sha256 + ".json")


def initialize_generation_owner(root, config, *, semantics, report=None):
    """Explicit native provisioning only. Readers can never create a lost owner.

    The external enrollment and journal must both survive. Interrupted initial
    provisioning is a visible metadata repair, never an implicit empty owner.
    No model or remote state is read, changed, or declared completed here.
    """
    directory, target, marker = _paths(root, config)
    ensure_private_directory(directory)
    descriptor = lock_private_file(directory / ".initialization.lock")
    try:
        with TransferProgress(
            "model_generation_owner_initialization",
            1,
            report,
            unit="owners",
            planning_unit_seconds=(0.001, 1),
        ) as progress:
            if target.exists() and not marker.exists():
                # A renamed initial journal is the durable provisioning intent.
                # Resume only exact, empty native state; a lost enrollment on an
                # established owner must never recreate authority or erase work.
                initial = _GenerationIndex(
                    target,
                    _binding(config, semantics),
                    maximum_bytes=config.maximum_bytes,
                    existing_only=True,
                )
                with initial.read_transaction() as db:
                    if (
                        db.execute("PRAGMA user_version").fetchone()[0] != 5
                        or db.execute("SELECT 1 FROM records LIMIT 1").fetchone()
                        or db.execute("SELECT 1 FROM holds LIMIT 1").fetchone()
                    ):
                        raise ModelGenerationRepairRequired(
                            "established generation enrollment missing; restore exact metadata"
                        )
                publish_private_model(marker, config)
                progress.advance(1, restored=True)
                return
            if target.exists() or marker.exists():
                store = ModelGenerationStore(root, config, semantics=semantics)
                store.close()
                progress.advance(1, restored=True)
                return
            binding = _binding(config, semantics)
            with tempfile.TemporaryDirectory(
                prefix=".new-generation-owner-", dir=directory
            ) as work:
                path = Path(work) / "owner"
                journal = _GenerationIndex(path, binding, maximum_bytes=config.maximum_bytes)
                journal.initialize(binding)
                os.rename(path, target)
            publish_private_model(marker, config)
            parent = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(parent)
            finally:
                os.close(parent)
            progress.advance(1)
    finally:
        os.close(descriptor)


class ModelGenerationStore:
    """A fresh metadata view per operation; immutable byte results never expire."""

    def __init__(self, root, config, *, semantics, capacity_recovery=False):
        self.config, self.semantics = config, semantics
        _, path, marker = _paths(root, config)
        try:
            enrolled = read_private_model(marker, ModelGenerationStoreConfig)
            if (
                enrolled.model_dump(exclude={"maximum_bytes"})
                != config.model_dump(exclude={"maximum_bytes"})
                or config.maximum_bytes < enrolled.maximum_bytes
            ):
                raise ValueError("generation owner selection changed")
            self.enrolled = enrolled
            binding = _binding(enrolled, semantics)
            self.journal = _GenerationIndex(
                path,
                binding,
                maximum_bytes=enrolled.maximum_bytes,
                maximum_record_bytes=64 * 1024**2,
                existing_only=True,
            )
            self.journal.owner_binding = digest(binding)
            self.journal.enrolled_capacity = enrolled.maximum_bytes
            with self.journal.read_transaction() as db:
                if db.execute("PRAGMA user_version").fetchone()[0] != 5:
                    raise ValueError("generation owner completion marker missing")
                capacity, _ = self.journal.capacity(db, enrolled.maximum_bytes)
                if config.maximum_bytes > capacity and not capacity_recovery:
                    raise ModelGenerationRepairRequired(
                        "model generation limit increase requires native grow-generations"
                    )
                self.journal.maximum_bytes = capacity
        except ModelGenerationOwnerBusy:
            raise
        except ModelGenerationRepairRequired:
            raise
        except (OSError, ValueError, sqlite3.Error) as error:
            raise ModelGenerationRepairRequired(
                "selected model generation owner unavailable; explicit metadata repair required"
            ) from error

    def close(self):
        # The journal owns no persistent connection or descriptor.
        pass

    def object_id(self, value):
        return digest(
            {
                "namespace": self.config.namespace_sha256,
                "semantics": self.semantics,
                "key": value["key"],
                "sha256": value["sha256"],
                "size_bytes": value["size_bytes"],
            }
        )

    def _damage(self, db, object_id):
        kind = "damage:" + object_id
        row = db.execute(
            "SELECT id FROM records WHERE kind=? ORDER BY id DESC LIMIT 1", (kind,)
        ).fetchone()
        if row is None:
            return None
        key = row[0]
        value = self.journal.get(kind, key, db=db)
        if not isinstance(value, dict) or value.get("object") != object_id:
            raise ModelGenerationRepairRequired("model damage history requires metadata repair")
        repair = self.journal.get("repair:" + object_id, key, db=db)
        if repair is not None and repair != {"damage": digest(value), "object": object_id}:
            raise ModelGenerationRepairRequired("model repair history requires metadata repair")
        return (key, value, repair is None)

    def _require(self, db, value, *, allow_damage=False):
        key = self.object_id(value)
        completed = self.journal.get("object", key, db=db)
        if completed != value:
            raise ModelGenerationRepairRequired(
                "original model generation completion requires repair"
            )
        if any(
            self.journal.pending(db, kind + key) is not None
            for kind in ("pending-damage:", "pending-repair:")
        ):
            raise ModelGenerationRepairRequired(
                "model generation held for capacity growth; original pending event retained"
            )
        damage = self._damage(db, key)
        if damage is not None and damage[2] and not allow_damage:
            raise ModelGenerationRepairRequired(
                "model generation held; explicit original repair required"
            )
        return damage

    def known(self, declarations):
        result = {}
        with self.journal.read_transaction() as db:
            for value in declarations:
                key = self.object_id(value)
                completed = self.journal.get("object", key, db=db)
                if completed is not None:
                    self._require(db, completed)
                    result[value["sha256"]] = completed
        return result

    def scope(self, context, declarations, *, allow_damage=False):
        """Return retained original generations; a lost completed scope is held."""
        key = digest(context)
        with self.journal.read_transaction() as db:
            enrollment = self.journal.get("scope-start", key, db=db)
            completed = self.journal.get("scope", key, db=db)
            if completed is None:
                # A started scope resumes only its still-unfinished records. A
                # separate immutable final marker exposes loss of completed state.
                if self.journal.get("scope-finished", key, db=db) is not None:
                    raise ModelGenerationRepairRequired("completed model scope metadata is missing")
                return None
            if enrollment != {"context": context, "objects": declarations}:
                raise ModelGenerationRepairRequired("model generation enrollment changed")
            if set(completed) != {"objects"} or len(completed["objects"]) != len(declarations):
                raise ModelGenerationRepairRequired("model generation scope is damaged")
            if self.journal.get("scope-finished", key, db=db) != {"scope": digest(completed)}:
                raise ModelGenerationRepairRequired("model generation scope marker is missing")
            result = {}
            with TransferProgress(
                "model_generation_reuse",
                len(declarations),
                unit="objects",
                planning_unit_seconds=(0.00001, 0.001),
            ) as progress:
                for declared, value in zip(declarations, completed["objects"], strict=True):
                    if {k: value.get(k) for k in declared} != declared:
                        raise ModelGenerationRepairRequired(
                            "model generation scope coverage changed"
                        )
                    self._require(db, value, allow_damage=allow_damage)
                    result[value["sha256"]] = value
                    progress.advance(1, restored=True)
            return result

    def begin(self, context, declarations):
        self.journal.put(
            "scope-start", digest(context), {"context": context, "objects": declarations}
        )

    def complete(self, context, declarations, objects, *, report=None):
        """Checkpoint exact native results; this API never discovers generations."""
        self.begin(context, declarations)
        values = [objects[value["sha256"]] for value in declarations]
        with TransferProgress(
            "model_generation_completion",
            len(values),
            report,
            unit="objects",
            planning_unit_seconds=(0.0001, 0.01),
        ) as progress:
            for value in values:
                self.journal.put("object", self.object_id(value), value)
                with self.journal.read_transaction() as db:
                    self._require(db, value)
                progress.advance(1)
            completed = {"objects": values}
            self.journal.put_many(
                (
                    ("scope", digest(context), completed),
                    ("scope-finished", digest(context), {"scope": digest(completed)}),
                )
            )

    def remember_objects(self, objects):
        """Import already authenticated native byte-generation facts only."""
        self.journal.put_many(("object", self.object_id(value), value) for value in objects)

    def hold(self, value, *, reason):
        """Publish actual missing/changed/corrupt evidence, never a network retry."""
        key = self.object_id(value)
        with self.journal.transaction() as db:
            if self.journal.get("object", key, db=db) is None:
                return  # No successful generation exists to invalidate yet.
            damage = self._damage(db, key)
            sequence = 1 if damage is None else int(damage[0]) + 1
            record = {"object": key, "generation": value, "reason": reason}
            raw = canonical_json_bytes(record)
            recorded = self.journal.insert_event(db, "damage:" + key, f"{sequence:016d}", raw)
        if not recorded:
            raise ModelGenerationRepairRequired("model generation pending capacity event retained")

    def repair_token(self, value):
        with self.journal.read_transaction() as db:
            damage = self._require(db, value, allow_damage=True)
            return None if damage is None or not damage[2] else (damage[0], digest(damage[1]))

    def finish_repair(self, value, token):
        """Call only after this owner actually read/verified the original object."""
        if token is None:
            return
        key = self.object_id(value)
        recorded = True
        with self.journal.transaction() as db:
            damage = self._require(db, value, allow_damage=True)
            if damage is None or (damage[0], digest(damage[1])) != token:
                raise ModelGenerationRepairRequired("model generation damage changed during repair")
            raw = canonical_json_bytes({"damage": token[1], "object": key})
            prior = self.journal.get_raw("repair:" + key, token[0], db=db)
            if prior is None:
                recorded = self.journal.insert_event(db, "repair:" + key, token[0], raw)
            elif prior != raw:
                raise ModelGenerationRepairRequired("model repair history changed")
        if not recorded:
            raise ModelGenerationRepairRequired("model generation pending capacity event retained")


def grow_generation_owner(root, config, *, semantics, report=None):
    """Authenticated metadata-only capacity growth, preserving every pending event.

    Original enrollment/binding bytes never change. Existing consumers adopt the
    retained larger admission limit on reopen. Each pending event and its applied
    marker commit together; interruption resumes the remaining metadata only.
    Object damage is not cleared by this operation.
    """
    directory, _, _ = _paths(root, config)
    descriptor = lock_private_file(directory / ".initialization.lock")
    try:
        owner = ModelGenerationStore(root, config, semantics=semantics, capacity_recovery=True)
        journal = owner.journal
        pending_where = (
            "p.kind GLOB 'pending-*:*' AND NOT EXISTS (SELECT 1 FROM records a "
            "WHERE a.kind='applied-'||p.kind AND a.id=p.id)"
        )
        with journal.read_transaction() as db:
            highwater = db.execute("SELECT COALESCE(MAX(rowid),0) FROM records").fetchone()[0]
            pending_where += " AND p.rowid<=?"
            total = db.execute(
                "SELECT COUNT(*) FROM records p WHERE " + pending_where, (highwater,)
            ).fetchone()[0]
        with TransferProgress(
            "model_generation_capacity_recovery",
            total + 1,
            report,
            unit="records",
            planning_unit_seconds=(0.0001, 0.1),
        ) as progress:
            with journal.transaction() as db:
                capacity, sequence = journal.capacity(db, owner.enrolled.maximum_bytes)
                if config.maximum_bytes < capacity:
                    raise ValueError("model generation capacity cannot shrink")
                if config.maximum_bytes > capacity:
                    value = {
                        "owner": journal.owner_binding,
                        "previous_maximum_bytes": capacity,
                        "maximum_bytes": config.maximum_bytes,
                    }
                    raw = canonical_json_bytes(value)
                    _, used, _ = journal._record_capacity(db)
                    if used + len(raw) > config.maximum_bytes:
                        raise ModelGenerationRepairRequired(
                            "selected capacity cannot contain retained pending history"
                        )
                    db.execute(
                        "INSERT INTO records VALUES ('owner-capacity',?,?)",
                        (f"{sequence + 1:016d}", raw),
                    )
                    capacity = config.maximum_bytes
                journal.maximum_bytes = capacity
            progress.advance(1)
            while True:
                with journal.read_transaction() as db:
                    row = db.execute(
                        "SELECT p.kind,p.id FROM records p WHERE "
                        + pending_where
                        + " ORDER BY p.kind,p.id LIMIT 1",
                        (highwater,),
                    ).fetchone()
                if row is None:
                    break
                kind, key = row
                with journal.transaction() as db:
                    pending = journal.get(kind, key, db=db)
                    applied = {"pending": digest(pending)}
                    if journal.get("applied-" + kind, key, db=db) is not None:
                        continue
                    category, object_id = kind.removeprefix("pending-").split(":", 1)
                    original = journal.get("object", object_id, db=db)
                    if (
                        original is None
                        or owner.object_id(original) != object_id
                        or pending.get("object") != object_id
                        or category not in {"damage", "repair"}
                        or len(key) != 16
                        or not key.isdigit()
                        or set(pending)
                        != {"object", "reason" if category == "damage" else "damage"}
                    ):
                        raise ModelGenerationRepairRequired("pending model event metadata differs")
                    event = {**pending, "generation": original} if category == "damage" else pending
                    if category == "repair":
                        prior_damage = journal.get("damage:" + object_id, key, db=db)
                        if prior_damage is None or digest(prior_damage) != pending["damage"]:
                            raise ModelGenerationRepairRequired(
                                "pending repair lost its damage event"
                            )
                    target_kind = category + ":" + object_id
                    raw, marker = canonical_json_bytes(event), canonical_json_bytes(applied)
                    prior = journal.get_raw(target_kind, key, db=db)
                    if prior is not None and prior != raw:
                        raise ModelGenerationRepairRequired(
                            "pending model event conflicts with history"
                        )
                    _, used, _ = journal._record_capacity(db)
                    required = len(marker) + (0 if prior is not None else len(raw))
                    if used + required > capacity:
                        progress.emit(
                            "repair_required", reason="model_generation_more_capacity_required"
                        )
                        raise ModelGenerationRepairRequired(
                            "more capacity required; remaining original events stay held"
                        )
                    if prior is None:
                        db.execute("INSERT INTO records VALUES (?,?,?)", (target_kind, key, raw))
                    db.execute(
                        "INSERT INTO records VALUES (?,?,?)", ("applied-" + kind, key, marker)
                    )
                progress.advance(1, restored=True)
    finally:
        os.close(descriptor)
