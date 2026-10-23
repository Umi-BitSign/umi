"""Conservative model allocations in the unchanged legacy upload journal.

The journal's immutable original bundle/request records remain authoritative.
The small derived state index is checked against immutable transition records;
missing or damaged accounting is an explicit repair, never free capacity.

This module does not authorize remote adoption, consumer release, or deletion.
Its release transitions are private integration ports for a future qualified
consumer-release owner. No configured runtime currently invokes those ports.
The full two-copy charge survives qualification, preparation and partial unlink.
"""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_artifacts import _directory
from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import VerificationReuse, metadata_completion
from .open_competition import ModelBundle, digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_SCHEMA = {
    "model_allocation_identity": (
        "CREATE TABLE model_allocation_identity (id INTEGER PRIMARY KEY CHECK(id=1), "
        "schema TEXT NOT NULL)"
    ),
    "model_allocation_state": (
        "CREATE TABLE model_allocation_state (model TEXT PRIMARY KEY NOT NULL, "
        "phase TEXT NOT NULL, record_sha256 TEXT NOT NULL)"
    ),
}
_VERSION = "umi-cohort-model-allocation/1"
_KINDS = {
    "local_reserved": "model_allocation",
    "remote_qualified": "model_remote_qualified",
    "release_prepared": "model_release_prepared",
    "released": "model_release_completed",
}


class ModelAllocationRepairRequired(OSError):
    """Allocation metadata must be repaired before any local write or refund."""


class _VerifiedAllocation(StrictProtocolModel):
    schema_: Literal["umi-cohort-model-allocation/1"] = Field(alias="schema")
    model_sha256: Hex32
    reserved_bytes: Annotated[int, Field(ge=0, le=2**53 - 1)]


def _allocation(bundle):
    return {
        "schema": _VERSION,
        "model_sha256": digest(bundle),
        "reserved_bytes": 2 * sum(item.size_bytes for item in bundle.files),
    }


class ModelReservationLedger:
    def __init__(self, journal, *, report=None, repair_bundle_verification=False):
        if type(repair_bundle_verification) is not bool:
            raise ValueError("allocation verification repair requires an explicit boolean")
        self.journal, self.report = journal, report
        self._repair_bundle_verification = repair_bundle_verification
        self._verification_repairs = 0
        with journal.locked():
            with journal.read_transaction() as db:
                binding = json.loads(bytes(db.execute("SELECT body FROM binding").fetchone()[0]))
                if binding.get("schema") != "umi-cohort-model-delivery/1":
                    raise ValueError("model allocations require the native upload journal")
                self._bundle_verification = VerificationReuse(
                    journal.root / "model-allocation-verification",
                    owner={"schema": "umi-model-allocation-bundle-facts/1", "binding": binding},
                )
                self.archive = Path(binding["archive"])
                self.files = journal.root.parent / "files"
                names = {
                    row[0]
                    for row in db.execute(
                        "SELECT name FROM sqlite_master WHERE type='table' "
                        "AND name IN ('model_allocation_identity','model_allocation_state')"
                    )
                }
                existing = db.execute(
                    "SELECT 1 FROM records WHERE kind IN (?,?,?,?) LIMIT 1",
                    tuple(_KINDS.values()),
                ).fetchone()
            if names:
                self.snapshot()
                return
            if existing:
                self._repair("model allocation tables are missing")
            models = journal.keys("bundle")
            with TransferProgress(
                "model_allocation_migration",
                len(models),
                report,
                unit="models",
                planning_unit_seconds=(0.001, 0.1),
            ) as progress:
                records = []
                for model in models:
                    records.append(("model_allocation", model, self._original_allocation(model)))
                    progress.advance(1)

                def initialize(db):
                    for statement in _SCHEMA.values():
                        db.execute(statement)
                    db.execute("INSERT INTO model_allocation_identity VALUES (1,?)", (_VERSION,))
                    for _, model, value in records:
                        db.execute(
                            "INSERT INTO model_allocation_state VALUES (?, 'local_reserved', ?)",
                            (model, digest(value)),
                        )

                journal.put_many(records, index=initialize)
            self.snapshot()

    def _repair(self, reason):
        with TransferProgress("model_allocation_repair", 1, self.report, unit="models") as progress:
            progress.emit("repair_required", reason="model_allocation_metadata_missing_or_damaged")
            raise ModelAllocationRepairRequired(reason)

    def _schema(self, db):
        for name, expected in _SCHEMA.items():
            row = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
            ).fetchone()
            if row != (expected,):
                self._repair("model allocation schema requires repair")
        rows = db.execute("SELECT id,schema FROM model_allocation_identity LIMIT 2").fetchall()
        if rows != [(1, _VERSION)]:
            self._repair("model allocation version requires repair")

    def _original_allocation(self, model, db=None):
        """Reuse static bundle validation; fresh accounting/fences stay in _state.

        Every lookup reads the current native canonical row and conflict fence.
        Its exact byte identity, bound owner and verifier ABI scope the receipt.
        No model payload files are read and no release authority is cached.
        """
        raw = self.journal.get_raw("bundle", model, db=db)
        if raw is None:
            self._repair("model allocation lost its original bundle")
        reuse = self._bundle_verification
        key = hashlib.sha256(
            canonical_json_bytes(
                {
                    "owner": reuse.owner,
                    "runtime": reuse.runtime,
                    "profile": "umi-model-allocation-bundle-facts/1",
                    "model_sha256": model,
                    "canonical_bundle_sha256": hashlib.sha256(raw).hexdigest(),
                }
            )
        ).hexdigest()
        with reuse.exclusive():
            path = reuse.directory / (key + ".json")
            existed = os.path.lexists(path) or metadata_completion(path).exists()
            receipt = reuse.load(key)
            if receipt is not None:
                try:
                    value = _VerifiedAllocation.model_validate_json(receipt.result_json)
                except ValueError:
                    self._repair("model allocation verification result requires repair")
                if receipt.dependencies or value.model_sha256 != model:
                    self._repair("model allocation verification binding requires repair")
                return value.model_dump(mode="json", by_alias=True)
            if existed and not self._repair_bundle_verification:
                self._repair("completed model allocation verification requires repair")
            with TransferProgress(
                "model_allocation_bundle_verification_repair"
                if existed
                else "model_allocation_bundle_verification",
                1,
                self.report,
                unit="models",
                planning_unit_seconds=(0.01, 2.0),
            ) as progress:
                bundle = ModelBundle.model_validate_json(raw)
                original = _allocation(bundle)
                if original["model_sha256"] != model:
                    self._repair("model allocation original bundle changed")
                # Checkpoint each successful original independently. Interrupted
                # initial scans retain earlier work for the next startup/retry.
                reuse.remember(key, (), canonical_json_bytes(original).decode())
                self._verification_repairs += int(existed)
                progress.advance(1)
            return original

    def _state(self, model, db):
        self._schema(db)
        row = db.execute(
            "SELECT phase,record_sha256 FROM model_allocation_state WHERE model=?", (model,)
        ).fetchone()
        if row is None or row[0] not in _KINDS:
            self._repair("model allocation state requires repair")
        original = self._original_allocation(model, db)
        if self.journal.get("model_allocation", model, db=db) != original:
            self._repair("model allocation reservation requires repair")
        phases = list(_KINDS)
        previous = original
        for phase in phases[1:]:
            retained = self.journal.get(_KINDS[phase], model, db=db)
            if phases.index(phase) <= phases.index(row[0]):
                if (
                    not isinstance(retained, dict)
                    or retained.get("schema") != "umi-cohort-model-allocation-transition/1"
                    or retained.get("phase") != phase
                    or retained.get("model_sha256") != model
                    or retained.get("previous_sha256") != digest(previous)
                ):
                    self._repair("model allocation transition requires repair")
                previous = retained
            elif retained is not None:
                self._repair("model allocation state trails a committed transition")
        if digest(previous) != row[1]:
            self._repair("model allocation state differs from its transition")
        return row[0], previous, original["reserved_bytes"]

    def state(self, model):
        with self.journal.read_transaction() as db:
            return self._state(model, db)[0]

    def require_local(self, model):
        if self.state(model) in {"release_prepared", "released"}:
            raise OSError("local model reservation is fenced for remote release")

    def snapshot(self):
        with self.journal.read_transaction() as db:
            self._schema(db)
            models = [row[0] for row in db.execute("SELECT model FROM model_allocation_state")]
            originals = [row[0] for row in db.execute("SELECT id FROM records WHERE kind='bundle'")]
            allocations = [
                row[0] for row in db.execute("SELECT id FROM records WHERE kind='model_allocation'")
            ]
            if set(models) != set(originals) or set(models) != set(allocations):
                self._repair("model allocation inventory requires repair")
            counts = dict.fromkeys(_KINDS, 0)
            reserved = released = 0
            for model in models:
                phase, _, size = self._state(model, db)
                counts[phase] += 1
                if phase == "released":
                    released += size
                else:
                    reserved += size
            return {
                "models": len(models),
                "active_reserved_bytes": reserved,
                "released_reserved_bytes": released,
                "states": counts,
                "archive_release_authority": "not_configured",
            }

    def reservation_record(self, bundle):
        return "model_allocation", digest(bundle), _allocation(bundle)

    def index_reserved(self, db, bundle):
        """Called in the same put_many transaction as original bundle/request."""
        self._schema(db)
        model = digest(bundle)
        prior = db.execute(
            "SELECT phase FROM model_allocation_state WHERE model=?", (model,)
        ).fetchone()
        if prior is None:
            db.execute(
                "INSERT INTO model_allocation_state VALUES (?, 'local_reserved', ?)",
                (model, digest(_allocation(bundle))),
            )
        self._state(model, db)

    def _transition(self, model, phase, *, evidence):
        """Private accounting port; evidence pins do not issue deletion authority.

        Its future owner must hold the upload journal, model transfer and complete
        consumer-release leases. There is deliberately no configured caller yet.
        """
        with self.journal.read_transaction() as db:
            before, prior, _ = self._state(model, db)
            phases = list(_KINDS)
            if phase == before:
                if prior.get("evidence") != evidence:
                    raise ValueError("model allocation retry changes release evidence")
                return
            if phases.index(phase) != phases.index(before) + 1:
                raise ValueError("model allocation transition is out of order")
        value = {
            "schema": "umi-cohort-model-allocation-transition/1",
            "model_sha256": model,
            "phase": phase,
            "previous_sha256": digest(prior),
            "evidence": evidence,
        }

        def index(db):
            # The immutable next record is already inserted in this transaction.
            row = db.execute(
                "SELECT phase,record_sha256 FROM model_allocation_state WHERE model=?", (model,)
            ).fetchone()
            if row != (before, digest(prior)):
                raise OSError("model allocation transition lost its owner")
            db.execute(
                "UPDATE model_allocation_state SET phase=?,record_sha256=? WHERE model=?",
                (phase, digest(value), model),
            )
            self._state(model, db)

        self.journal.put_many(((_KINDS[phase], model, value),), index=index)

    def _complete_release(self, model):
        """Credit only after a prepared release has actually reclaimed payloads.

        Never delete here, and never credit preparation or partial deletion.
        Caller owns the same leases required by _transition. Original manifests,
        journals, review inputs and verification evidence remain outside payloads.
        """
        if self.state(model) not in {"release_prepared", "released"}:
            raise ValueError("model release must be prepared before local reclamation")
        archive, staging = self.archive, self.files / model
        pending = archive / (".pending-" + model)
        if pending.exists() or pending.is_symlink():
            raise OSError("model release still has interrupted archive payloads")
        for path in (archive / model / "model", staging / "model"):
            if path.exists() or path.is_symlink():
                raise OSError("model release still has local payloads")
            with _directory(path.parent) as descriptor:
                os.fsync(descriptor)
        if any(Path(staging).glob("partial-*")):
            raise OSError("model release still has interrupted upload payloads")
        # The pending archive entry belongs to the archive parent, separate
        # from the final model's payload directory entry.
        with _directory(archive) as descriptor:
            os.fsync(descriptor)
        with _directory(Path(staging)) as descriptor:
            os.fsync(descriptor)
        self._transition(
            model,
            "released",
            evidence={"archive": str(archive), "staging": str(staging), "payload_absent": True},
        )


def repair_model_allocation_verification(journal, *, report=None):
    """Explicitly restore only damaged derived bundle-verification receipts.

    The constructor's owned snapshot verifies original allocations and all
    current transitions. Successful unaffected bundle receipts remain reusable;
    no signed record, capacity charge, release state or journal is replaced.
    """
    ledger = ModelReservationLedger(journal, report=report, repair_bundle_verification=True)
    return {"status": "completed", "verification_receipts_repaired": ledger._verification_repairs}


def repair_model_allocation_index(journal, *, report=None):
    """Explicitly restore a missing derived index from intact immutable records.

    A retained index referring to a lost transition is not downgraded: restore
    that record from the owned backup first. No signed original or transition is
    rewritten. This cannot invent byte verification or consumer-release proof.
    """
    with journal.locked(), journal.transaction() as source:
        models = journal.keys("bundle")
        rows = []
        prior_schema = source.execute(
            "SELECT sql FROM sqlite_master WHERE name='model_allocation_state' AND type='table'"
        ).fetchone()
        if prior_schema not in (None, (_SCHEMA["model_allocation_state"],)):
            raise ModelAllocationRepairRequired("unsupported model allocation index schema")
        with TransferProgress(
            "model_allocation_index_repair",
            len(models),
            report,
            unit="models",
            planning_unit_seconds=(0.001, 0.1),
        ) as progress:
            for model in models:
                bundle = ModelBundle.model_validate_json(
                    journal.get_raw("bundle", model, db=source)
                )
                previous = _allocation(bundle)
                if (
                    digest(bundle) != model
                    or journal.get("model_allocation", model, db=source) != previous
                ):
                    raise ModelAllocationRepairRequired(
                        "restore original allocation before index repair"
                    )
                phase, missing = "local_reserved", False
                for next_phase, kind in list(_KINDS.items())[1:]:
                    retained = journal.get(kind, model, db=source)
                    if retained is None:
                        missing = True
                        continue
                    if (
                        missing
                        or not isinstance(retained, dict)
                        or retained.get("schema") != "umi-cohort-model-allocation-transition/1"
                        or retained.get("phase") != next_phase
                        or retained.get("model_sha256") != model
                        or retained.get("previous_sha256") != digest(previous)
                    ):
                        raise ModelAllocationRepairRequired(
                            "restore allocation transition before index repair"
                        )
                    phase, previous = next_phase, retained
                if prior_schema is not None:
                    prior = source.execute(
                        "SELECT phase FROM model_allocation_state WHERE model=?", (model,)
                    ).fetchone()
                    if prior and (
                        prior[0] not in _KINDS
                        or list(_KINDS).index(prior[0]) > list(_KINDS).index(phase)
                    ):
                        raise ModelAllocationRepairRequired(
                            "index references a lost allocation transition"
                        )
                rows.append((model, phase, digest(previous)))
                progress.advance(1)
            # The caller's outer journal lock prevents concurrent migration,
            # reservation or release while this private index is reconstructed.
            for name, statement in _SCHEMA.items():
                existing = source.execute(
                    "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,)
                ).fetchone()
                if existing is None:
                    source.execute(statement)
                elif existing == (statement,):
                    source.execute("DELETE FROM " + name)
                else:
                    raise ModelAllocationRepairRequired("unsupported model allocation schema")
            source.execute("INSERT INTO model_allocation_identity VALUES (1,?)", (_VERSION,))
            source.executemany("INSERT INTO model_allocation_state VALUES (?,?,?)", rows)
