"""Supplementary package authorization without repeating native or byte replay.

The original preparation owner retains an explicit inventory, including an empty
one, of the package's direct acceptances. This scope does not replace block,
coverage, model-byte, signature or reward verification receipts.
"""

from __future__ import annotations

import json
import sqlite3
from typing import Literal

from pydantic import Field

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_model_acceptance import verify_model_acceptance
from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .competition_verification_snapshot import verified_package_digest
from .open_competition import digest
from .private_files import publish_private_model, read_private_model
from .protocol import StrictProtocolModel, canonical_json_bytes

SCOPE = "umi-package-model-transport-authorization/1"
KIND = "package_model_transport_authorization"
OWNER = "package_model_transport_owner"
TABLE = "package_model_transport_completion"
SQL = (
    "CREATE TABLE package_model_transport_completion "
    "(id TEXT PRIMARY KEY NOT NULL, body BLOB NOT NULL)"
)


class PackageTransportRepairRequired(ValueError):
    """Completed supplementary metadata requires explicit original-owner repair."""


class _Owner(StrictProtocolModel):
    schema_: Literal["umi-package-model-transport-authorization/1"] = Field(alias="schema")
    identity: tuple[tuple[int, int, int], tuple[int, int, int]]


def _triggers():
    values = {}
    for action in ("UPDATE", "DELETE"):
        name = TABLE + "_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON {TABLE} "
            "BEGIN SELECT RAISE(ABORT,'package transport completion is immutable'); END"
        )
        name = TABLE + "_owner_" + action.lower()
        values[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            f"WHEN OLD.kind='{OWNER}' BEGIN SELECT "
            "RAISE(ABORT,'package transport owner is immutable'); END"
        )
    return values


class PackageTransportQualifications:
    """Use only under preparation/coverage ownership; each operation also locks.

    A permanent completion ledger distinguishes old installations from missing
    completed records. Explicit repair restores only the exact supplementary
    record from that ledger and preserves damaged metadata in an audit record.
    Ledger/owner damage requires restoration of its original durable metadata.
    """

    def __init__(self, preparation):
        self.preparation = preparation
        self.root = preparation.verification_reuse.directory / "model-transport"
        self.marker = self.root.parent / "model-transport-owner.json"
        try:
            retained_owner = read_private_model(self.marker, _Owner, maximum_bytes=64 * 1024)
        except FileNotFoundError:
            retained_owner = None
        except ValueError as error:
            raise PackageTransportRepairRequired(
                "package transport original owner marker requires repair"
            ) from error
        if retained_owner is not None and (
            not (self.root / "rounds.sqlite3").is_file()
            or retained_owner.identity
            != tuple(
                (s.st_dev, s.st_ino, s.st_uid)
                for s in (self.root.stat(), (self.root / "rounds.sqlite3").stat())
            )
        ):
            raise PackageTransportRepairRequired("original package transport journal was lost")
        self.journal = RoundJournal(
            self.root,
            {
                "schema": SCOPE,
                "series": preparation.series_sha256,
                "policy": preparation.policy_sha256,
                "chain": preparation.reader.chain_config_sha256,
            },
            maximum_bytes=RoundJournal.MAXIMUM_BYTES,
            maximum_rounds=65536,
            maximum_record_bytes=1024**2,
        )
        self.owner = {"schema": SCOPE, "identity": self._identity()}
        with self.journal.locked(), self.journal.transaction() as db:
            retained = self.journal.get(OWNER, "owner", db=db)
            installed = db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
            ).fetchone()
            if retained_owner is None and (retained is not None or installed is not None):
                raise PackageTransportRepairRequired("package transport owner marker was lost")
            publish_private_model(
                self.marker,
                _Owner.model_validate_json(canonical_json_bytes(self.owner)),
                maximum_bytes=64 * 1024,
            )
            if retained is None and installed is None:
                if db.execute("SELECT 1 FROM records LIMIT 1").fetchone():
                    raise PackageTransportRepairRequired("package transport owner was lost")
                db.execute(SQL)
                for sql in _triggers().values():
                    db.execute(sql)
                db.execute(
                    "INSERT INTO records VALUES (?,?,?)",
                    (OWNER, "owner", canonical_json_bytes(self.owner)),
                )
            self._check_owner(db)
            self._check_capacity(db)

    def _check_capacity(self, db):
        count, used, _ = self.journal._record_capacity(db)
        rows, size = db.execute(
            f"SELECT COUNT(*),COALESCE(SUM(LENGTH(id)+LENGTH(body)),0) FROM {TABLE}"
        ).fetchone()
        if count + rows > self.journal.maximum_records or used + size > self.journal.maximum_bytes:
            raise ValueError("package transport metadata capacity exhausted")

    def _identity(self):
        return [
            [s.st_dev, s.st_ino, s.st_uid] for s in (self.root.stat(), self.journal.path.stat())
        ]

    def _check_owner(self, db):
        if (
            self._identity() != self.owner["identity"]
            or read_private_model(self.marker, _Owner, maximum_bytes=64 * 1024).model_dump(
                mode="json", by_alias=True
            )
            != self.owner
            or self.journal.get(OWNER, "owner", db=db) != self.owner
            or db.execute(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (TABLE,)
            ).fetchone()
            != (SQL,)
            or dict(
                db.execute(
                    "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
                    (TABLE + "_*",),
                )
            )
            != _triggers()
        ):
            raise PackageTransportRepairRequired("package transport original ledger needs repair")

    def _context(self, package_sha256, cohort_sha256):
        p = self.preparation
        p._authority()
        return {
            "schema": SCOPE,
            "package_sha256": package_sha256,
            "cohort_sha256": cohort_sha256,
            "policy_sha256": p.policy_sha256,
            "series_sha256": p.series_sha256,
            "authority_sha256": digest(p.reader.series.recovery.authority),
            "requirement_sha256": digest(p.manifest.requirement(cohort_sha256)),
            "owner_sha256": digest(self.owner),
        }

    def _load(self, db, context):
        self._check_owner(db)
        key = digest(context)
        row = db.execute(f"SELECT body FROM {TABLE} WHERE id=?", (key,)).fetchone()
        value = self.journal.get(KIND, key, db=db)
        if row is None and value is None:
            return None
        if row is None:
            raise PackageTransportRepairRequired("package transport completion ledger was lost")
        completed = json.loads(bytes(row[0]))
        if (
            value != completed
            or completed.get("context") != context
            or set(completed) != {"context", "history_sha256", "direct_acceptances"}
            or completed["direct_acceptances"] != sorted(set(completed["direct_acceptances"]))
        ):
            raise PackageTransportRepairRequired("completed package transport record needs repair")
        return value

    def load(self, package_sha256, cohort_sha256):
        context = self._context(package_sha256, cohort_sha256)
        progress = TransferProgress(
            "package_model_transport_restore",
            1,
            unit="packages",
            planning_unit_seconds=(0.00001, 0.01),
        )
        try:
            with progress:
                with self.journal.locked(), self.journal.read_transaction() as db:
                    result = self._load(db, context)
                progress.advance(1, restored=result is not None)
        except (ValueError, OSError, sqlite3.DatabaseError, TypeError, KeyError) as error:
            # Emit after the progress context closes so generic interruption
            # telemetry cannot replace the required-repair status with retrying.
            progress.emit("repair_required", reason="completed_package_transport_changed")
            raise PackageTransportRepairRequired(
                "completed package transport metadata requires scoped repair"
            ) from error
        return result

    def qualify(self, package, *, package_sha256, cohort_sha256):
        context = self._context(package_sha256, cohort_sha256)
        if verified_package_digest(package) != package_sha256:
            raise ValueError("package transport requires the exact original package")
        with self.journal.locked():
            with self.journal.read_transaction() as db:
                prior = self._load(db, context)
            if prior is not None:
                return prior
            history = package.inputs.history
            if (
                package.policy_sha256 != context["policy_sha256"]
                or digest(history.plan) != cohort_sha256
                or digest(history.authority.authority) != context["authority_sha256"]
            ):
                raise ValueError("package transport changes original authority")
            tip = history.transitions[-1].transition if history.transitions else history.genesis
            block = tip.observed_at_block if history.transitions else tip.admitted_at_block
            verify_cohort_history(
                history,
                self.preparation.reader.policy,
                expected_tip_sha256=digest(tip),
                current_block=block,
            )
            award = package.allocation.model_award
            certificates = (
                ()
                if award is None
                else tuple(c for c in award.acceptances if c.acceptance.direct_artifact is not None)
            )
            participants = {
                digest(p.record.request.signed_submission.submission): p.record
                for p in package.inputs.roster.participants
            }
            progress = TransferProgress(
                "package_model_transport_authorization",
                len(certificates),
                unit="acceptances",
                planning_unit_seconds=(0.001, 1.0),
            )
            try:
                with progress:
                    for certificate in certificates:
                        record = participants.get(certificate.acceptance.submission_sha256)
                        if record is None:
                            raise ValueError("package transport lacks its original participant")
                        verify_model_acceptance(
                            certificate,
                            record,
                            history,
                            self.preparation.reader.policy,
                            maximum_block=block,
                        )
                        progress.advance(1)
                    value = {
                        "context": context,
                        "history_sha256": digest(history),
                        "direct_acceptances": sorted(digest(c) for c in certificates),
                    }
                    if len(value["direct_acceptances"]) != len(set(value["direct_acceptances"])):
                        raise ValueError("package transport inventory repeats an acceptance")

                    def complete(db):
                        self._check_owner(db)
                        db.execute(
                            f"INSERT INTO {TABLE} VALUES (?,?)",
                            (digest(context), canonical_json_bytes(value)),
                        )
                        self._check_capacity(db)

                    self.journal.put_many(((KIND, digest(context), value),), index=complete)
            except Exception as error:
                progress.emit(
                    "retrying" if isinstance(error, OSError) else "repair_required",
                    reason="package_transport_io_interrupted"
                    if isinstance(error, OSError)
                    else "package_transport_not_qualified",
                )
                raise
            return value

    def repair(self, package_sha256, cohort_sha256, *, reason):
        """Restore completed metadata, never authorize a new or changed input."""
        if type(reason) is not str or not reason.strip() or len(reason) > 1024:
            raise ValueError("package transport repair requires a bounded explicit reason")
        context = self._context(package_sha256, cohort_sha256)
        key = digest(context)
        with (
            self.journal.locked(),
            TransferProgress(
                "package_model_transport_metadata_repair",
                1,
                unit="qualifications",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress,
            self.journal.transaction() as db,
        ):
            self._check_owner(db)
            row = db.execute(f"SELECT body FROM {TABLE} WHERE id=?", (key,)).fetchone()
            if row is None:
                raise PackageTransportRepairRequired("restore original completion ledger first")
            raw = bytes(row[0])
            value = json.loads(raw)
            if value.get("context") != context:
                raise PackageTransportRepairRequired("original transport context changed")
            damaged = db.execute(
                "SELECT body FROM records WHERE kind=? AND id=?", (KIND, key)
            ).fetchone()
            if damaged is not None and bytes(damaged[0]) == raw:
                progress.advance(1, restored=True)
                return value
            audit = {
                "context": context,
                "reason": reason,
                "damaged_hex": None if damaged is None else bytes(damaged[0]).hex(),
                "restored_sha256": digest(value),
            }
            audit_raw = canonical_json_bytes(audit)
            if max(len(raw), len(audit_raw)) > self.journal.maximum_record_bytes:
                raise ValueError("package transport repair exceeds metadata record capacity")
            count, used, _ = self.journal._record_capacity(db)
            needed = len(raw) + len(audit_raw) - (0 if damaged is None else len(damaged[0]))
            if (
                used + needed > self.journal.maximum_bytes
                or count + 2 > self.journal.maximum_records
            ):
                raise ValueError("package transport repair exceeds journal capacity")
            db.execute(
                "INSERT OR IGNORE INTO records VALUES (?,?,?)",
                (KIND + "_repair", digest(audit), audit_raw),
            )
            db.execute("DELETE FROM records WHERE kind=? AND id=?", (KIND, key))
            db.execute("INSERT INTO records VALUES (?,?,?)", (KIND, key, raw))
            self._load(db, context)
            self._check_capacity(db)
            progress.advance(1, restored=True)
            return value
