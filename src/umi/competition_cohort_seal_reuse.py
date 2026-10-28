"""Intake-owned durable results for exact native seal dependencies.

SQL mutation identities advance with original writes, including older writers.
Only small current indexes and compact native projections are read on reuse.
Original signed evidence remains authoritative and is never rewritten here.
"""

from __future__ import annotations

import json
import os
import secrets
import sqlite3
from contextlib import contextmanager

from pydantic import RootModel

from .competition_cohort_intake_records import read_participation
from .competition_cohort_intake_seal import (
    CohortIntakeSeal,
    IntakeParticipationProjection,
    _build_intake_seal_from_projections,
    project_participation,
)
from .competition_cohort_model_acceptance import verify_model_acceptance
from .competition_cohort_model_acceptance_store import (
    PendingModelArtifacts,
    acceptance_tables,
    read_publication,
)
from .competition_cohort_recovery import ModelRewardCohortAuthority
from .competition_store import AdmissionCapacityError
from .competition_transport_verification import TransferProgress
from .competition_verification_reuse import (
    metadata_completion,
    read_verification_metadata,
    remember_metadata_completion,
)
from .competition_verification_rules import runtime_identity
from .open_competition import digest, identity
from .private_files import _write_private_bytes, ensure_private_directory, publish_private_model
from .protocol import canonical_json_bytes

ABI = "umi-intake-seal-reuse/1"
SOURCES = {
    "consent": ("cohort_consents", "consent"),
    "acceptance": ("cohort_model_acceptances", "submission"),
    "seal": ("cohort_intake_seals", "tip"),
}
TABLES = {
    "intake_seal_reuse_owner": "CREATE TABLE intake_seal_reuse_owner(body BLOB NOT NULL)",
    "intake_seal_reuse_sources": "CREATE TABLE intake_seal_reuse_sources(kind TEXT,cohort TEXT,"
    "id TEXT,revision INTEGER NOT NULL,present INTEGER NOT NULL,epoch TEXT NOT NULL,"
    "verified TEXT NOT NULL,"
    "PRIMARY KEY(kind,cohort,id))",
    "intake_seal_reuse_results": "CREATE TABLE intake_seal_reuse_results(kind TEXT,cohort TEXT,"
    "id TEXT,context TEXT NOT NULL,body BLOB NOT NULL,PRIMARY KEY(kind,cohort,id,context))",
    "intake_seal_reuse_completions": "CREATE TABLE intake_seal_reuse_completions(kind TEXT,"
    "cohort TEXT,id TEXT,context TEXT NOT NULL,PRIMARY KEY(kind,cohort,id,context))",
    "intake_seal_reuse_repairs": "CREATE TABLE intake_seal_reuse_repairs(id TEXT PRIMARY KEY,"
    "body BLOB NOT NULL)",
}


class IntakeSealRepairRequired(ValueError):
    """Missing or damaged completed work requires explicit native repair."""


@contextmanager
def transaction(db):
    db.execute("SAVEPOINT intake_seal_reuse")
    try:
        yield
        db.execute("RELEASE intake_seal_reuse")
    except BaseException:
        db.execute("ROLLBACK TO intake_seal_reuse")
        db.execute("RELEASE intake_seal_reuse")
        raise


def _triggers():
    result = {}
    for kind, (table, key) in SOURCES.items():
        for action in ("INSERT", "UPDATE", "DELETE"):
            row = "OLD" if action == "DELETE" else "NEW"
            name = f"intake_seal_reuse_{kind}_{action.lower()}"
            result[name] = (
                f"CREATE TRIGGER {name} AFTER {action} ON {table} BEGIN "
                "INSERT INTO intake_seal_reuse_sources VALUES "
                f"('{kind}',{row}.cohort,{row}.{key},1,{int(action != 'DELETE')},'0','{{}}') "
                "ON CONFLICT(kind,cohort,id) DO UPDATE SET revision=revision+1,"
                f"present={int(action != 'DELETE')},verified='{{}}'; END"
            )
        name = f"intake_seal_reuse_{kind}_rekey"
        result[name] = (
            f"CREATE TRIGGER {name} AFTER UPDATE ON {table} "
            f"WHEN OLD.cohort!=NEW.cohort OR OLD.{key}!=NEW.{key} BEGIN "
            "INSERT INTO intake_seal_reuse_sources VALUES "
            f"('{kind}',OLD.cohort,OLD.{key},1,0,'0','{{}}') "
            "ON CONFLICT(kind,cohort,id) DO UPDATE SET "
            "revision=revision+1,present=0,verified='{}'; END"
        )
    return result


def retained_metadata_bytes(db):
    total = 0
    names = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    for table in TABLES.keys() & names:
        columns = [r[1] for r in db.execute(f"PRAGMA table_info({table})")]
        lengths = "+".join(f"LENGTH(CAST({column} AS BLOB))" for column in columns)
        total += db.execute(f"SELECT COALESCE(SUM({lengths}),0) FROM {table}").fetchone()[0]
    return total


def _valid_registry(raw):
    try:
        IntakeSealReuse._registry(raw)
        return True
    except IntakeSealRepairRequired:
        return False


def _acceptance_fact(value):
    if (
        not isinstance(value, list)
        or len(value) != 3
        or any(type(n) is not int or n < 0 for n in value)
    ):
        raise ValueError("intake certificate fact is malformed")


class IntakeSealReuse:
    def __init__(self, intake, db, *, repair_reason=None):
        self.intake, self.db = intake, db
        self.repair_reason = repair_reason
        self.binding = digest(json.loads(intake._binding_bytes()))
        self.files = [
            [s.st_dev, s.st_ino, s.st_uid]
            for s in (intake.directory.stat(), (intake.directory / "intake.sqlite3").stat())
        ]
        self.owner = digest([ABI, self.binding, str(intake.directory), self.files])
        self.marker = {"schema": ABI, "binding": self.binding, "owner": self.owner}
        self.triggers = _triggers()
        self.marker_path = intake.directory / "seal-reuse" / "installed.json"
        self.semantics = runtime_identity()
        if repair_reason is not None:
            self.repair_metadata(repair_reason)
            return
        actual = self.schema()
        if not actual:
            if self.marker_path.exists() or metadata_completion(self.marker_path).exists():
                raise IntakeSealRepairRequired("intake seal source metadata is missing")
            self.initialize()
        self.check()
        # SQL installation precedes this idempotent marker. A crash in between
        # restores only the marker, with no original row or proof work repeated.
        ensure_private_directory(self.marker_path.parent)
        if not self.marker_path.exists():
            if metadata_completion(self.marker_path).exists():
                raise IntakeSealRepairRequired("intake seal owner marker is missing")
            publish_private_model(self.marker_path, RootModel(self.marker))
        if read_verification_metadata(self.marker_path) != canonical_json_bytes(self.marker):
            raise IntakeSealRepairRequired("intake seal owner marker changed")
        remember_metadata_completion(self.marker_path)

    def schema(self):
        return dict(
            self.db.execute(
                "SELECT name,sql FROM sqlite_master WHERE name GLOB 'intake_seal_reuse_*'"
            )
        )

    def initialize(self):
        acceptance_tables(self.db)
        total = sum(
            self.db.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            for table, _ in SOURCES.values()
        )
        with (
            transaction(self.db),
            TransferProgress(
                "intake_seal_identity_migration",
                total,
                unit="records",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress,
        ):
            for sql in TABLES.values():
                self.db.execute(sql)
            self.db.execute(
                "INSERT INTO intake_seal_reuse_owner VALUES (?)",
                (canonical_json_bytes(self.marker),),
            )
            for kind, (table, key) in SOURCES.items():
                count = self.db.execute(
                    "INSERT INTO intake_seal_reuse_sources "
                    f"SELECT ?,cohort,{key},0,1,'0','{{}}' FROM {table}",
                    (kind,),
                ).rowcount
                progress.advance(count)
            for sql in self.triggers.values():
                self.db.execute(sql)
            self.capacity()

    def check(self):
        if self.schema() != {**TABLES, **self.triggers}:
            raise IntakeSealRepairRequired("intake seal mutation fences or metadata schema changed")
        rows = self.db.execute("SELECT body FROM intake_seal_reuse_owner LIMIT 2").fetchall()
        if rows != [(canonical_json_bytes(self.marker),)]:
            raise IntakeSealRepairRequired("intake seal original owner changed")

    def capacity(self):
        # The same native allowance covers original evidence and derived state.
        if self.intake.retained_bytes(self.db) > self.intake.capacity.maximum_bytes:
            raise AdmissionCapacityError("intake seal verification metadata exceeds capacity")

    def sources(self, kind, cohort):
        table, key = SOURCES[kind]
        extra = ",hotkey,track,sequence,observed,recovery_tip" if kind == "consent" else ""
        live = {
            row[0]: list(row[1:])
            for row in self.db.execute(
                f"SELECT {key}{extra} FROM {table} WHERE cohort=? ORDER BY {key}",
                (cohort,),
            )
        }
        sources = {}
        for source, revision, present, epoch, verified in self.db.execute(
            "SELECT id,revision,present,epoch,verified FROM intake_seal_reuse_sources "
            "WHERE kind=? AND cohort=? ORDER BY id",
            (kind, cohort),
        ):
            if (
                type(revision) is not int
                or revision < 0
                or present not in (0, 1)
                or not isinstance(epoch, str)
                or not 1 <= len(epoch) <= 64
            ):
                raise IntakeSealRepairRequired("intake seal source identity is damaged")
            self._registry(verified)
            if present != int(source in live):
                raise IntakeSealRepairRequired("intake seal source membership changed")
            if present:
                sources[source] = [revision, live[source], epoch]
        if sources.keys() != live.keys():
            raise IntakeSealRepairRequired("intake seal source identity is missing")
        return sources

    def context(self, history):
        return digest(
            [ABI, self.owner, self.semantics, digest(history), digest(self.intake.policy)]
        )

    @staticmethod
    def _registry(raw):
        try:
            value = json.loads(raw)
            if not isinstance(value, dict) or any(
                kind not in {"seal", "participation", "excluded", "acceptance"}
                or not isinstance(contexts, list)
                or len(contexts) != len(set(contexts))
                or any(not isinstance(context, str) or len(context) != 64 for context in contexts)
                for kind, contexts in value.items()
            ):
                raise ValueError("invalid result registry")
            return value
        except (ValueError, TypeError) as error:
            raise IntakeSealRepairRequired("intake seal completion registry is damaged") from error

    def _source_registry(self, kind, cohort, key):
        source_kind = "consent" if kind in {"participation", "excluded"} else kind
        row = self.db.execute(
            "SELECT verified FROM intake_seal_reuse_sources WHERE kind=? AND cohort=? AND id=?",
            (source_kind, cohort, key),
        ).fetchone()
        if row is None:
            raise IntakeSealRepairRequired("intake seal completion source is missing")
        return source_kind, self._registry(row[0])

    def result(self, kind, cohort, key, context, produce, *, repair=False, validate=None):
        row = self.db.execute(
            "SELECT body FROM intake_seal_reuse_results "
            "WHERE kind=? AND cohort=? AND id=? AND context=?",
            (kind, cohort, key, context),
        ).fetchone()
        completed = self.db.execute(
            "SELECT context FROM intake_seal_reuse_completions "
            "WHERE kind=? AND cohort=? AND id=? AND context=?",
            (kind, cohort, key, context),
        ).fetchone()
        _, registry = self._source_registry(kind, cohort, key)
        value = None
        if row is not None:
            try:
                value = json.loads(row[0])
                if (
                    set(value) != {"context", "result", "checksum"}
                    or value["checksum"] != digest([value["context"], value["result"]])
                    or canonical_json_bytes(value) != row[0]
                ):
                    value = None
            except (ValueError, TypeError):
                value = None
        damaged = (
            (row is not None and value is None)
            or (
                completed is not None
                and completed[0] == context
                and (value is None or value["context"] != context)
            )
            or (row is not None and completed is None)
            or (row is not None and context not in registry.get(kind, []))
            or (context in registry.get(kind, []) and (row is None or completed is None))
        )
        if not damaged and value is not None and value["context"] == context and validate:
            try:
                validate(value["result"])
            except (ValueError, TypeError, KeyError, IndexError):
                damaged = True
        if damaged and not repair:
            with TransferProgress("intake_seal_verification_repair", 1) as progress:
                progress.emit("repair_required", reason="completed_intake_check_damaged")
            raise IntakeSealRepairRequired("completed intake seal check requires repair")
        if not damaged and value is not None and value["context"] == context:
            return value["result"]
        if damaged:
            audit = {
                "schema": "umi-intake-seal-result-repair/1",
                "kind": kind,
                "cohort": cohort,
                "id": key,
                "context": context,
                "reason": self.repair_reason,
            }
            with transaction(self.db):
                self.db.execute(
                    "INSERT OR IGNORE INTO intake_seal_reuse_repairs VALUES (?,?)",
                    (digest(audit), canonical_json_bytes(audit)),
                )
                self.capacity()
        result = produce()
        if validate is not None:
            validate(result)
        self.remember(kind, cohort, key, context, result)
        return result

    def remember(self, kind, cohort, key, context, result):
        value = {"context": context, "result": result, "checksum": digest([context, result])}
        with transaction(self.db):
            source_kind, registry = self._source_registry(kind, cohort, key)
            registry[kind] = sorted({*registry.get(kind, []), context})
            self.db.execute(
                "UPDATE intake_seal_reuse_sources SET verified=? "
                "WHERE kind=? AND cohort=? AND id=?",
                (canonical_json_bytes(registry).decode(), source_kind, cohort, key),
            )
            self.db.execute(
                "INSERT INTO intake_seal_reuse_results VALUES (?,?,?,?,?) "
                "ON CONFLICT(kind,cohort,id,context) DO UPDATE SET body=excluded.body",
                (kind, cohort, key, context, canonical_json_bytes(value)),
            )
            self.db.execute(
                "INSERT OR IGNORE INTO intake_seal_reuse_completions VALUES (?,?,?,?)",
                (kind, cohort, key, context),
            )
            self.capacity()

    def _record(self, key, history, row):
        raw = self.db.execute(
            "SELECT substr(body,1,4194305) FROM cohort_consents WHERE consent=?", (key,)
        ).fetchone()
        if raw is None:
            raise IntakeSealRepairRequired("intake original consent disappeared")
        retained = read_participation(raw[0])
        sub = retained.request.signed_submission.submission
        expected = [
            identity(sub.hotkey),
            sub.track,
            sub.sequence,
            retained.observation.block,
            retained.proposed_admission.recovery_tip_sha256,
        ]
        if row[1] != expected or retained.proposed_admission.cohort_sha256 != digest(history.plan):
            raise ValueError("retained consent index differs from its body")
        return retained

    def build(self, history, observation, snapshot, tip, *, repair=False, report=None):
        cohort, context = digest(history.plan), self.context(history)
        sources = self.sources("consent", cohort)
        tips = {digest(history.genesis), *(digest(t.transition) for t in history.transitions)}
        with TransferProgress(
            "intake_seal_participations",
            len(sources),
            unit="records",
            planning_unit_seconds=(0.001, 0.5),
        ) as progress:

            def projections():
                for key, row in sources.items():

                    def produce(key=key, row=row):
                        retained = self._record(key, history, row)
                        # All indexed rows are checked, including original rows
                        # outside this historical prefix; only prefix members aggregate.
                        return project_participation(
                            key, retained, history, self.intake.policy
                        ).model_dump(mode="json")

                    if row[1][-1] not in tips:
                        # Preserve the historical reader's index/body consistency check.
                        self.result(
                            "excluded",
                            cohort,
                            key,
                            digest([context, row]),
                            lambda key=key, row=row: bool(self._record(key, history, row)),
                            repair=repair,
                        )
                        progress.advance(1)
                        continue
                    value = self.result(
                        "participation",
                        cohort,
                        key,
                        digest([context, row]),
                        produce,
                        repair=repair,
                        validate=IntakeParticipationProjection.model_validate,
                    )
                    progress.advance(1)
                    yield IntakeParticipationProjection.model_validate(value)

            seal = _build_intake_seal_from_projections(
                history,
                self.intake.policy,
                observation,
                snapshot,
                projections(),
                expected_tip_sha256=tip,
            )
        self.acceptances(history, seal, sources, repair=repair, report=report)
        return seal

    def acceptances(self, history, seal, consents, *, repair=False, report=None):
        if not isinstance(history.authority.authority, ModelRewardCohortAuthority):
            return
        sources = self.sources("acceptance", seal.cohort_sha256)
        selected = [s for s in seal.selected if s.track == "model"]
        missing = [s.submission_sha256 for s in selected if s.submission_sha256 not in sources]
        inventory = {
            "cohort_sha256": seal.cohort_sha256,
            "roster_sha256": digest([s.model_dump(mode="json") for s in selected]),
            "completed": len(selected) - len(missing),
            "total": len(selected),
            "pending_submission_sha256s": tuple(missing),
        }
        if report is not None:
            report(inventory)
        if missing:
            error = PendingModelArtifacts("selected model artifact acceptance is pending")
            error.submission_sha256 = missing[0]
            error.inventory = inventory
            raise error
        facts = []
        with TransferProgress(
            "intake_seal_acceptances",
            len(selected),
            unit="certificates",
            planning_unit_seconds=(0.001, 1),
        ) as progress:
            for item in selected:
                key = item.submission_sha256
                context = digest(
                    [
                        self.context(history),
                        sources[key],
                        consents[item.consent_sha256],
                    ]
                )

                def produce(key=key, item=item):
                    publication = read_publication(self.db, seal.cohort_sha256, key)
                    retained = self._record(
                        item.consent_sha256, history, consents[item.consent_sha256]
                    )
                    verify_model_acceptance(
                        publication.certificate,
                        retained,
                        history,
                        self.intake.policy,
                        maximum_block=seal.observation.block,
                    )
                    accepted = publication.certificate.acceptance
                    return [
                        accepted.accepted_ordinal,
                        accepted.accepted_at_block,
                        retained.request.consent.consent.signed_at_block,
                    ]

                fact = self.result(
                    "acceptance",
                    seal.cohort_sha256,
                    key,
                    context,
                    produce,
                    repair=repair,
                    validate=_acceptance_fact,
                )
                # Native signatures/terms are unchanged. Only their two monotone
                # time bounds depend on a newer observation during a retry.
                if max(fact[1:]) > seal.observation.block:
                    raise ValueError("model artifact acceptance predates its seal bound")
                facts.append(fact)
                progress.advance(1)
        ordered = sorted(facts)
        if len({f[0] for f in ordered}) != len(ordered):
            raise ValueError("model acceptances repeat a completion ordinal")
        blocks = [f[1] for f in ordered]
        if blocks != sorted(blocks):
            raise ValueError("model acceptance ordinals contradict their block order")

    def seal_context(self, history, tip, seal):
        acceptances = None
        if isinstance(history.authority.authority, ModelRewardCohortAuthority):
            sources = self.sources("acceptance", seal.cohort_sha256)
            acceptances = {
                selected.submission_sha256: sources.get(selected.submission_sha256)
                for selected in seal.selected
                if selected.track == "model"
            }
        return digest(
            [
                self.context(history),
                self.sources("seal", seal.cohort_sha256).get(tip),
                self.sources("consent", seal.cohort_sha256),
                acceptances,
            ]
        )

    def verify(self, history, tip, seal, *, repair=False):
        context = self.seal_context(history, tip, seal)

        def produce():
            result = self.build(history, seal.observation, seal.snapshot, tip, repair=repair)
            if result != seal:
                raise ValueError("retained intake seal differs from its original records")
            return seal.model_dump(mode="json", by_alias=True)

        def validate(value):
            result = CohortIntakeSeal.model_validate_json(canonical_json_bytes(value))
            if result != seal:
                raise IntakeSealRepairRequired("completed intake seal result differs")

        value = self.result(
            "seal", seal.cohort_sha256, tip, context, produce, repair=repair, validate=validate
        )
        return CohortIntakeSeal.model_validate_json(canonical_json_bytes(value))

    def record_created(self, history, tip, seal):
        self.remember(
            "seal",
            seal.cohort_sha256,
            tip,
            self.seal_context(history, tip, seal),
            seal.model_dump(mode="json", by_alias=True),
        )

    def repair_metadata(self, reason):
        if not isinstance(reason, str) or not 1 <= len(reason) <= 1024:
            raise ValueError("intake seal repair requires an explicit bounded reason")
        actual = self.schema()
        trusted = actual.get("intake_seal_reuse_sources") == TABLES[
            "intake_seal_reuse_sources"
        ] and all(actual.get(name) == sql for name, sql in self.triggers.items())
        if trusted:
            try:
                trusted = self.db.execute(
                    "SELECT body FROM intake_seal_reuse_owner LIMIT 2"
                ).fetchall() == [(canonical_json_bytes(self.marker),)]
            except sqlite3.DatabaseError:
                trusted = False
        live = {}
        acceptance_tables(self.db)
        for kind, (table, key) in SOURCES.items():
            live.update(
                {
                    (kind, c, k): True
                    for c, k in self.db.execute(f"SELECT cohort,{key} FROM {table}")
                }
            )
        known = {}
        if trusted:
            known = {
                (kind, c, k): (revision, present, epoch, verified)
                for kind, c, k, revision, present, epoch, verified in self.db.execute(
                    "SELECT * FROM intake_seal_reuse_sources"
                )
            }
        damaged = [
            key
            for key in set(live) | set(known)
            if key not in known
            or type(known[key][0]) is not int
            or known[key][0] < 0
            or known[key][1] != int(key in live)
            or not isinstance(known[key][2], str)
            or not 1 <= len(known[key][2]) <= 64
            or not _valid_registry(known[key][3])
        ]
        changed_tables = [name for name, sql in TABLES.items() if actual.get(name) != sql]
        if trusted and not damaged and not changed_tables:
            try:
                if read_verification_metadata(self.marker_path) == canonical_json_bytes(
                    self.marker
                ):
                    return
            except (OSError, ValueError):
                pass
        nonce = secrets.token_hex(32)
        audit = {
            "schema": "umi-intake-seal-repair/1",
            "reason": reason,
            "owner": self.owner,
            "nonce": nonce,
            "source_identities_preserved": trusted,
            "source_records_repaired": len(damaged),
            "metadata_tables_repaired": changed_tables,
        }
        with (
            transaction(self.db),
            TransferProgress(
                "intake_seal_metadata_repair",
                len(damaged),
                unit="records",
                planning_unit_seconds=(0.00001, 0.01),
            ) as progress,
        ):
            if not trusted:
                for name in self.triggers:
                    self.db.execute("DROP TRIGGER IF EXISTS " + name)
                self.db.execute("DROP TABLE IF EXISTS intake_seal_reuse_sources")
            for name in changed_tables:
                self.db.execute("DROP TABLE IF EXISTS " + name)
            for name, sql in TABLES.items():
                if name in changed_tables or (name == "intake_seal_reuse_sources" and not trusted):
                    self.db.execute(sql)
            self.db.execute("DELETE FROM intake_seal_reuse_owner")
            self.db.execute(
                "INSERT INTO intake_seal_reuse_owner VALUES (?)",
                (canonical_json_bytes(self.marker),),
            )
            for kind, cohort, key in damaged:
                self.db.execute(
                    "INSERT INTO intake_seal_reuse_sources VALUES (?,?,?,0,?,?,'{}') "
                    "ON CONFLICT(kind,cohort,id) DO UPDATE SET "
                    "revision=0,present=excluded.present,epoch=excluded.epoch,verified='{}'",
                    (kind, cohort, key, int((kind, cohort, key) in live), nonce),
                )
                progress.advance(1)
            if not trusted:
                for sql in self.triggers.values():
                    self.db.execute(sql)
            self.db.execute(
                "INSERT INTO intake_seal_reuse_repairs VALUES (?,?)",
                (digest(audit), canonical_json_bytes(audit)),
            )
            self.capacity()
        # The intake owner fence serializes this explicit derived-marker repair.
        ensure_private_directory(self.marker_path.parent)
        _write_private_bytes(self.marker_path, canonical_json_bytes(self.marker))
        directory = os.open(self.marker_path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        remember_metadata_completion(self.marker_path)
        self.check()
