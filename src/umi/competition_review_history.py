"""Evaluator-owned receipts for independently checked, quorum-certified rosters.

These record arrival time, never the coordinator's claimed admission time.
The store cannot accept miner enrollments or prepare coordinator settlements.
"""

from __future__ import annotations

import json
import secrets
from contextlib import contextmanager
from dataclasses import asdict, dataclass

from .competition_publication import (
    PublicationReplayLimits,
    SignedCutoffPublication,
    verify_cutoff_publication,
)
from .competition_store import AdmissionCapacityError, CompetitionStore, _advance_block
from .competition_void import MAX_VOID_BYTES
from .open_competition import SignedSubmission, digest, identity
from .protocol import canonical_json_bytes, sha256_hex


@dataclass(frozen=True, slots=True)
class ReviewReservation:
    """Future outcome bodies for one already reviewed roster entry."""

    round_sha256: str
    submission_sha256: str
    maximum_certificate_bytes: int
    maximum_independent_bytes: int
    maximum_void_bytes: int


_CAPACITY_TABLES = {
    "review_capacity_identity": "CREATE TABLE review_capacity_identity (body BLOB NOT NULL)",
    "review_capacity_batches": (
        "CREATE TABLE review_capacity_batches (id TEXT PRIMARY KEY, body BLOB NOT NULL)"
    ),
    "review_capacity_specs": (
        "CREATE TABLE review_capacity_specs (round TEXT NOT NULL, submission TEXT NOT NULL, "
        "body BLOB NOT NULL, PRIMARY KEY(round,submission))"
    ),
    "review_capacity_consumptions": (
        "CREATE TABLE review_capacity_consumptions (round TEXT NOT NULL, submission TEXT NOT NULL, "
        "kind TEXT NOT NULL, digest TEXT NOT NULL, body_sha256 TEXT NOT NULL, "
        "PRIMARY KEY(round,submission,kind))"
    ),
}
_KINDS = {
    "certificate": ("evaluation_results", "maximum_certificate_bytes", "observed_block"),
    "independent": (
        "independent_evaluation_evidence",
        "maximum_independent_bytes",
        "first_observed_block",
    ),
    "void": ("void_evaluation_evidence", "maximum_void_bytes", "first_observed_block"),
}
_MAX_MANIFEST_BYTES = 16 * 1024**2


class EvaluatorReviewStore(CompetitionStore):
    def __init__(self, directory, policy, *, limits, **kwargs):
        self.limits = PublicationReplayLimits.model_validate_json(canonical_json_bytes(limits))
        super().__init__(directory, policy, role="evaluator_review", **kwargs)
        with self._transaction() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS reviewed_cutoffs "
                "(round TEXT PRIMARY KEY, observed_block INTEGER NOT NULL, body BLOB NOT NULL)"
            )
            prior = connection.execute(
                "SELECT value FROM metadata WHERE key='review_limits'"
            ).fetchone()
            bound = canonical_json_bytes(self.limits).decode()
            if prior is None:
                connection.execute("INSERT INTO metadata VALUES ('review_limits', ?)", (bound,))
            elif prior[0] != bound:
                raise ValueError("review history limits changed")
            usage = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM reviewed_cutoffs"
            ).fetchone()
            if usage[0] > self.preparation_capacity.maximum_records or (
                usage[1] > self.preparation_capacity.maximum_bytes
            ):
                raise ValueError("review history exceeds its capacity")
            for (round_id,) in connection.execute("SELECT digest FROM rounds").fetchall():
                self._read_cutoff(connection, round_id)

    @staticmethod
    def _hex(value):
        return (
            type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)
        )

    @classmethod
    def _fences(cls):
        for table in (*cls._WRITER_FENCED_TABLES, "reviewed_cutoffs", *_CAPACITY_TABLES):
            for operation in ("INSERT", "UPDATE", "DELETE"):
                name = f"review_capacity_{table}_{operation.lower()}"
                yield (
                    name,
                    (
                        f"CREATE TRIGGER {name} BEFORE {operation} ON {table} BEGIN "
                        "SELECT CASE WHEN umi_review_writer_generation() IS NOT 2 "
                        "THEN RAISE(ABORT,'review writer generation mismatch') END; END"
                    ),
                )
                if table in _CAPACITY_TABLES and operation != "INSERT":
                    name = f"{table}_immutable_{operation.lower()}"
                    yield (
                        name,
                        (
                            f"CREATE TRIGGER {name} BEFORE {operation} ON {table} BEGIN "
                            "SELECT RAISE(ABORT,'review capacity evidence is append-only'); END"
                        ),
                    )

    def _generation(self, connection):
        version = connection.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            if connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'review_capacity_*' "
                "OR name GLOB 'review_writer_*' LIMIT 1"
            ).fetchone():
                raise ValueError("review capacity generation marker missing")
            return 0
        if version != 2:
            raise ValueError("unsupported review capacity generation")
        objects = dict(connection.execute("SELECT name,sql FROM sqlite_master"))
        if any(
            objects.get(name) != sql for name, sql in (*_CAPACITY_TABLES.items(), *self._fences())
        ):
            raise ValueError("review capacity schema or writer fence changed")
        return version

    @contextmanager
    def _connection(self):
        with super()._connection() as connection:
            connection.create_function("umi_review_writer_generation", 0, lambda: 2)
            self._generation(connection)
            yield connection

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            holds = {}
            try:
                if self._generation(connection):
                    self._verify_obligations(connection)
                    holds = {
                        table: connection.execute(
                            f"SELECT COALESCE(MAX(rowid),0) FROM {table}"
                        ).fetchone()[0]
                        for table in ("round_conflicts", "settlement_disputes")
                    }
                connection.execute("SAVEPOINT review_retention")
                yield connection
                if self._generation(connection):
                    self._consume_outcomes(connection)
                    self._check_capacity(connection)
                connection.execute("RELEASE SAVEPOINT review_retention")
                connection.commit()
            except AdmissionCapacityError:
                # Authenticated conflict holds survive failure to retain another
                # large body. Other tentative rows and credit consumption do not.
                new_holds = {
                    table: connection.execute(
                        f"SELECT round,detected_block FROM {table} WHERE rowid>?", (mark,)
                    ).fetchall()
                    for table, mark in holds.items()
                }
                if any(new_holds.values()):
                    try:
                        # Keep the original writer lock while discarding bodies
                        # and restoring holds. A full rollback would permit a
                        # competing writer to advance the watermark or act on
                        # the briefly unheld round before recovery commits.
                        connection.execute("ROLLBACK TO SAVEPOINT review_retention")
                        for table, rows in new_holds.items():
                            connection.executemany(
                                f"INSERT OR IGNORE INTO {table} VALUES (?,?)", rows
                            )
                        _advance_block(
                            connection,
                            max(block for rows in new_holds.values() for _, block in rows),
                        )
                        connection.execute("RELEASE SAVEPOINT review_retention")
                        connection.commit()
                    except BaseException:
                        connection.rollback()
                        raise
                else:
                    connection.rollback()
                raise
            except BaseException:
                connection.rollback()
                raise

    def _binding(self):
        return {
            "journal_path": str(self.path.resolve()),
            "policy_sha256": digest(self.policy),
            "limits_sha256": digest(self.limits),
            "role": "evaluator_review",
            "generation": 2,
        }

    def _enable_capacity(self, connection):
        if self._generation(connection):
            return
        if connection.execute(
            "SELECT 1 FROM sqlite_master WHERE name LIKE 'review_capacity_%'"
        ).fetchone():
            raise ValueError("partial review capacity migration")
        for sql in _CAPACITY_TABLES.values():
            connection.execute(sql)
        connection.execute(
            "INSERT INTO review_capacity_identity VALUES (?)",
            (canonical_json_bytes({**self._binding(), "journal_identity": secrets.token_hex(32)}),),
        )
        for _, sql in self._fences():
            connection.execute(sql)
        connection.execute("PRAGMA user_version=2")

    @staticmethod
    def _blob(connection, table, *, where="", arguments=(), maximum=_MAX_MANIFEST_BYTES):
        sizes = connection.execute(
            f"SELECT LENGTH(body),TYPEOF(body) FROM {table} {where} LIMIT 2", arguments
        ).fetchall()
        if not sizes:
            return None
        if len(sizes) != 1 or sizes[0][1] != "blob" or not 0 < sizes[0][0] <= maximum:
            raise ValueError("review capacity retained body exceeds bound")
        return bytes(
            connection.execute(f"SELECT body FROM {table} {where} LIMIT 1", arguments).fetchone()[0]
        )

    @staticmethod
    def _document(raw):
        try:
            value = json.loads(raw)
            if type(value) is not dict or canonical_json_bytes(value) != raw:
                raise ValueError("review capacity document is not canonical")
            return value
        except (TypeError, UnicodeError, json.JSONDecodeError, RecursionError) as error:
            raise ValueError("review capacity document is invalid") from error

    def _spec(self, value):
        fields = {"round_sha256", "submission_sha256", *(item[1] for item in _KINDS.values())}
        if (
            type(value) is not dict
            or set(value) != fields
            or not (self._hex(value["round_sha256"]) and self._hex(value["submission_sha256"]))
        ):
            raise ValueError("invalid review reservation identity or fields")
        bounds = {
            "maximum_certificate_bytes": self.limits.maximum_certificate_bytes,
            "maximum_independent_bytes": self.limits.maximum_evidence_bytes,
            "maximum_void_bytes": min(MAX_VOID_BYTES, self.limits.maximum_evidence_bytes),
        }
        if any(
            type(value[key]) is not int or not 1 <= value[key] <= bound
            for key, bound in bounds.items()
        ):
            raise ValueError("invalid review reservation body bound")
        return value

    def _specs(self, connection):
        count = connection.execute("SELECT COUNT(*) FROM review_capacity_specs").fetchone()[0]
        if count > self.admission_capacity.maximum_records:
            raise AdmissionCapacityError("review reservation record capacity exhausted")
        if connection.execute(
            "SELECT 1 FROM review_capacity_specs WHERE TYPEOF(round)!='text' "
            "OR TYPEOF(submission)!='text' OR LENGTH(round)!=64 "
            "OR LENGTH(submission)!=64 LIMIT 1"
        ).fetchone():
            raise ValueError("invalid retained review reservation identity")
        for round_id, submission_id, size in connection.execute(
            "SELECT round,submission,LENGTH(body) FROM review_capacity_specs "
            "ORDER BY round,submission"
        ):
            if not self._hex(round_id) or not self._hex(submission_id) or not 0 < size <= 2048:
                raise ValueError("invalid retained review reservation")
            raw = self._blob(
                connection,
                "review_capacity_specs",
                where="WHERE round=? AND submission=?",
                arguments=(round_id, submission_id),
                maximum=2048,
            )
            doc = self._spec(self._document(raw))
            if (doc["round_sha256"], doc["submission_sha256"]) != (round_id, submission_id):
                raise ValueError("review reservation SQL identity changed")
            yield doc

    def _outcome(self, connection, doc, kind):
        table, bound, observed = _KINDS[kind]
        key = (doc["round_sha256"], doc["submission_sha256"])
        consumed = connection.execute(
            "SELECT CASE WHEN TYPEOF(digest)='text' AND LENGTH(digest)=64 THEN digest END, "
            "CASE WHEN TYPEOF(body_sha256)='text' AND LENGTH(body_sha256)=64 THEN body_sha256 END "
            "FROM review_capacity_consumptions WHERE round=? AND submission=? AND kind=?",
            (*key, kind),
        ).fetchone()
        if consumed is None:
            row = connection.execute(
                "SELECT CASE WHEN TYPEOF(digest)='text' AND LENGTH(digest)=64 THEN digest END "
                f"FROM {table} WHERE round=? AND submission=? ORDER BY {observed},digest LIMIT 1",
                key,
            ).fetchone()
            if row is not None and not self._hex(row[0]):
                raise ValueError("review outcome identity invalid")
            return None if row is None else (row[0], None)
        if not all(self._hex(value) for value in consumed):
            raise ValueError("review capacity consumption identity invalid")
        row = connection.execute(
            f"SELECT round,submission FROM {table} WHERE digest=?", (consumed[0],)
        ).fetchone()
        raw = self._blob(
            connection, table, where="WHERE digest=?", arguments=(consumed[0],), maximum=doc[bound]
        )
        if row != key or raw is None or sha256_hex(raw) != consumed[1]:
            raise ValueError("review capacity consumed evidence missing or changed")
        return consumed

    def _verify_obligations(self, connection):
        self._identity(connection)
        for offset, (batch_id,) in enumerate(
            connection.execute(
                "SELECT CASE WHEN TYPEOF(id)='text' AND LENGTH(id)=64 THEN id END "
                "FROM review_capacity_batches"
            )
        ):
            if offset >= self.admission_capacity.maximum_records or not self._hex(batch_id):
                raise ValueError("invalid or oversized retained review batch identities")
            self._manifest(connection, batch_id)
        for doc in self._specs(connection):
            for kind in _KINDS:
                outcome = self._outcome(connection, doc, kind)
                if outcome is not None and outcome[1] is None:
                    raise ValueError("review capacity consumption receipt missing")

    def _consume_outcomes(self, connection):
        for doc in self._specs(connection):
            key = (doc["round_sha256"], doc["submission_sha256"])
            for kind, (table, bound, _observed) in _KINDS.items():
                outcome = self._outcome(connection, doc, kind)
                if outcome is None or outcome[1] is not None:
                    continue
                size = connection.execute(
                    f"SELECT LENGTH(body) FROM {table} WHERE digest=?", (outcome[0],)
                ).fetchone()[0]
                if size > doc[bound]:
                    raise AdmissionCapacityError("review body exceeds its reserved allowance")
                raw = self._blob(
                    connection,
                    table,
                    where="WHERE digest=?",
                    arguments=(outcome[0],),
                    maximum=doc[bound],
                )
                connection.execute(
                    "INSERT INTO review_capacity_consumptions VALUES (?,?,?,?,?)",
                    (*key, kind, outcome[0], sha256_hex(raw)),
                )

    def _identity(self, connection):
        raw = self._blob(connection, "review_capacity_identity", maximum=65536)
        doc = self._document(raw)
        expected = self._binding()
        if (
            set(doc) != {*expected, "journal_identity"}
            or not self._hex(doc.get("journal_identity"))
            or any(
                type(doc[key]) is not type(value) or doc[key] != value
                for key, value in expected.items()
            )
        ):
            raise ValueError("review capacity journal binding changed")
        return doc

    def _usage(self, connection):
        count = used = 0
        for table in (*self._WRITER_FENCED_TABLES, "reviewed_cutoffs", *_CAPACITY_TABLES):
            columns = [row[1] for row in connection.execute(f"PRAGMA table_info({table})")]
            sizes = "+".join(f"COALESCE(LENGTH(CAST({column} AS BLOB)),0)" for column in columns)
            rows, size = connection.execute(
                f"SELECT COUNT(*),COALESCE(SUM({sizes}),0) FROM {table}"
            ).fetchone()
            count, used = count + rows, used + size
        # The base constructor materializes this derived index on reopen.
        missing = connection.execute(
            "SELECT COUNT(*) FROM rounds r WHERE NOT EXISTS "
            "(SELECT 1 FROM public_schedule_usage p WHERE p.round=r.digest)"
        ).fetchone()[0]
        count, used = count + missing, used + missing * 192
        # Preserve space for the monotonically increasing observation metadata.
        observed = connection.execute(
            "SELECT LENGTH(value) FROM metadata WHERE key='observed_block'"
        ).fetchone()
        used += max(0, 16 - (observed[0] if observed else 0))
        if observed is None:
            count, used = count + 1, used + len("observed_block")
        for doc in self._specs(connection):
            for kind, (_table, bound, _observed) in _KINDS.items():
                outcome = self._outcome(connection, doc, kind)
                if outcome is None:
                    count += 1
                    used += len(kind) + 256  # Future consumption receipt.
                if kind == "certificate":
                    maximum_rows = 1 + len(self.policy.evaluators)
                    maximum = (
                        doc[bound]
                        + 208
                        + sum(128 + len(e.control_group.encode()) for e in self.policy.evaluators)
                    )
                    actual_rows = actual = 0
                    if outcome is not None:
                        actual_rows, actual = connection.execute(
                            "SELECT COUNT(*),COALESCE(SUM(LENGTH(digest)+LENGTH(round)"
                            "+LENGTH(submission)+LENGTH(body)"
                            "+LENGTH(CAST(observed_block AS BLOB))),0) "
                            "FROM evaluation_results WHERE digest=?",
                            (outcome[0],),
                        ).fetchone()
                        rows, size = connection.execute(
                            "SELECT COUNT(*),COALESCE(SUM(LENGTH(result)+LENGTH(signer)"
                            "+LENGTH(control_group)+LENGTH(body)),0) "
                            "FROM evaluation_signatures WHERE result=?",
                            (outcome[0],),
                        ).fetchone()
                        body_bytes = connection.execute(
                            "SELECT LENGTH(body) FROM evaluation_results WHERE digest=?",
                            (outcome[0],),
                        ).fetchone()[0]
                        body_bytes += connection.execute(
                            "SELECT COALESCE(SUM(LENGTH(body)),0) FROM evaluation_signatures "
                            "WHERE result=?",
                            (outcome[0],),
                        ).fetchone()[0]
                        actual_rows, actual = actual_rows + rows, actual + size
                        if body_bytes > doc[bound] or actual_rows > maximum_rows:
                            raise AdmissionCapacityError(
                                "review certificate exceeds its reserved allowance"
                            )
                    count += maximum_rows - actual_rows
                    used += max(0, maximum - actual)
                elif outcome is None:
                    count += 1
                    used += doc[bound] + 272  # Four digests and one observation block.
        return count, used

    def _check_capacity(self, connection):
        count, used = self._usage(connection)
        if (
            count > self.admission_capacity.maximum_records
            or used > self.admission_capacity.maximum_bytes
        ):
            raise AdmissionCapacityError("review history retained and pending capacity exhausted")
        return count, used

    def reserve_evidence(self, batch_id: str, specs):
        """Reserve future outcomes after independently retaining their cutoff."""
        if not self._hex(batch_id):
            raise ValueError("invalid review reservation batch identity")
        documents = {}
        used = 0
        for offset, spec in enumerate(specs):
            if offset >= self.admission_capacity.maximum_records or not isinstance(
                spec, ReviewReservation
            ):
                raise ValueError("invalid or oversized review reservation batch")
            doc = self._spec(asdict(spec))
            key = (doc["round_sha256"], doc["submission_sha256"])
            if key in documents:
                if documents[key] != doc:
                    raise ValueError("review reservation identity changed")
                continue
            used += len(canonical_json_bytes(doc))
            if used > _MAX_MANIFEST_BYTES:
                raise ValueError("review reservation manifest exceeds bound")
            documents[key] = doc
        body = canonical_json_bytes(
            {"batch_id": batch_id, "specs": [documents[key] for key in sorted(documents)]}
        )
        if len(body) > _MAX_MANIFEST_BYTES:
            raise ValueError("review reservation manifest exceeds bound")
        with self._transaction() as connection:
            self._enable_capacity(connection)
            old = self._blob(
                connection, "review_capacity_batches", where="WHERE id=?", arguments=(batch_id,)
            )
            if old is not None:
                if old != body:
                    raise ValueError("review reservation batch changed")
                return self._reservation(connection, batch_id)
            rosters = {}
            for key, doc in documents.items():
                round_id, submission_id = key
                if round_id not in rosters:
                    self._assert_action_allowed(connection, round_id)
                    rosters[round_id] = {
                        digest(s.submission) for s in self._read_cutoff(connection, round_id)[1]
                    }
                if submission_id not in rosters[round_id]:
                    raise ValueError("review reservation submission is absent from the cutoff")
                raw = canonical_json_bytes(doc)
                prior = self._blob(
                    connection,
                    "review_capacity_specs",
                    where="WHERE round=? AND submission=?",
                    arguments=key,
                    maximum=2048,
                )
                if prior is not None and prior != raw:
                    raise ValueError("review reservation identity changed")
                if prior is None:
                    connection.execute(
                        "INSERT INTO review_capacity_specs VALUES (?,?,?)", (*key, raw)
                    )
            connection.execute("INSERT INTO review_capacity_batches VALUES (?,?)", (batch_id, body))
            self._consume_outcomes(connection)
            self._check_capacity(connection)
            return self._reservation(connection, batch_id)

    def _manifest(self, connection, batch_id):
        raw = self._blob(
            connection, "review_capacity_batches", where="WHERE id=?", arguments=(batch_id,)
        )
        if raw is None:
            return None
        doc = self._document(raw)
        if (
            set(doc) != {"batch_id", "specs"}
            or doc["batch_id"] != batch_id
            or type(doc["specs"]) is not list
            or len(doc["specs"]) > self.admission_capacity.maximum_records
        ):
            raise ValueError("review reservation manifest changed")
        previous = None
        for item in doc["specs"]:
            item = self._spec(item)
            key = (item["round_sha256"], item["submission_sha256"])
            if previous is not None and key <= previous:
                raise ValueError("review reservation identities must be unique and sorted")
            previous = key
            retained = self._blob(
                connection,
                "review_capacity_specs",
                where="WHERE round=? AND submission=?",
                arguments=key,
                maximum=2048,
            )
            if retained != canonical_json_bytes(item):
                raise ValueError("review reservation obligation missing or changed")
        return raw

    def _reservation(self, connection, batch_id):
        identity_ = self._identity(connection)
        raw = self._manifest(connection, batch_id)
        if raw is None:
            return None
        self._verify_obligations(connection)
        self._check_capacity(connection)
        return {**identity_, "batch_id": batch_id, "manifest_sha256": sha256_hex(raw)}

    def reservation(self, batch_id: str):
        if not self._hex(batch_id):
            raise ValueError("invalid review reservation batch identity")
        with self._transaction() as connection:
            return self._reservation(connection, batch_id) if self._generation(connection) else None

    @property
    def maximum_cutoff_bytes(self):
        return self.limits.maximum_certificate_bytes + self.limits.maximum_roster_bytes + 4096

    def _read_cutoff(self, connection, round_id):
        row = connection.execute(
            "SELECT observed_block,length(body) FROM reviewed_cutoffs WHERE round=?", (round_id,)
        ).fetchone()
        if row is None or row[1] > self.maximum_cutoff_bytes:
            raise ValueError("review cutoff receipt missing or oversized")
        raw = connection.execute(
            "SELECT body FROM reviewed_cutoffs WHERE round=?", (round_id,)
        ).fetchone()[0]
        body = json.loads(raw)
        if not isinstance(body, dict) or (
            canonical_json_bytes(body) != raw or set(body) != {"certificate", "submissions"}
        ):
            raise ValueError("review cutoff receipt is not canonical")
        certificate = SignedCutoffPublication.model_validate_json(
            canonical_json_bytes(body["certificate"])
        )
        submissions = tuple(
            SignedSubmission.model_validate_json(canonical_json_bytes(s))
            for s in body["submissions"]
        )
        publication = verify_cutoff_publication(
            certificate, policy=self.policy, submissions=submissions, limits=self.limits
        )
        round_ = publication.round
        if (
            type(row[0]) is not int
            or digest(round_) != round_id
            or not (round_.submission_close_block <= row[0] < round_.evaluation_close_block)
        ):
            raise ValueError("review cutoff has an invalid local receipt block")
        high_water = connection.execute(
            "SELECT value FROM metadata WHERE key='observed_block'"
        ).fetchone()
        if high_water is None or row[0] > int(high_water[0]):
            raise ValueError("review cutoff exceeds its local observation history")
        stored = connection.execute(
            "SELECT body FROM rounds WHERE digest=?", (round_id,)
        ).fetchone()
        if stored is None or stored[0] != canonical_json_bytes(round_):
            raise ValueError("review cutoff differs from local round history")
        for signed in submissions:
            stored = connection.execute(
                "SELECT body FROM submissions WHERE digest=?", (digest(signed.submission),)
            ).fetchone()
            if stored is None or stored[0] != canonical_json_bytes(signed):
                raise ValueError("review cutoff differs from local submission history")
        return publication, submissions, row[0]

    def _assert_action_allowed(self, connection, round_sha256):
        super()._assert_action_allowed(connection, round_sha256)
        self._read_cutoff(connection, round_sha256)

    def _fixed_cutoff(self, connection, round_sha256):
        publication, _, _ = self._read_cutoff(connection, round_sha256)
        return publication.cutoff_schedule

    def observe_cutoff(self, certificate, submissions, *, snapshot, observed_block):
        """Caller supplies its independently proved cutoff snapshot and current head."""
        publication = verify_cutoff_publication(
            certificate, policy=self.policy, submissions=submissions, limits=self.limits
        )
        round_ = publication.round
        if publication.registration_snapshot != snapshot:
            raise ValueError("review cutoff differs from the independently proved snapshot")
        body = canonical_json_bytes(
            {
                "certificate": certificate.model_dump(mode="json", by_alias=True),
                "submissions": [s.model_dump(mode="json", by_alias=True) for s in submissions],
            }
        )
        if len(body) > self.maximum_cutoff_bytes:
            raise ValueError("review cutoff exceeds its byte bound")
        round_id = digest(round_)
        with self._transaction() as connection:
            prior = connection.execute(
                "SELECT 1 FROM reviewed_cutoffs WHERE round=?", (round_id,)
            ).fetchone()
            if prior:
                old, roster, observed = self._read_cutoff(connection, round_id)
                if old != publication or roster != tuple(submissions):
                    raise ValueError("review cutoff retry changes its original decision")
                return observed
            if type(observed_block) is not int or not (
                round_.submission_close_block <= observed_block < round_.evaluation_close_block
            ):
                raise ValueError("review cutoff arrived outside its execution window")
            _advance_block(connection, observed_block)
            baseline = connection.execute(
                "SELECT model FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if baseline is None or baseline[0] != round_.incumbent_model_sha256:
                raise ValueError("review cutoff incumbent is not the preserved local baseline")
            latest = connection.execute("SELECT MAX(sequence) FROM rounds").fetchone()[0]
            if latest is not None and latest >= round_.sequence:
                raise ValueError("review cutoff sequence did not advance")
            if connection.execute(
                "SELECT 1 FROM suite_usage WHERE suite=?", (round_.suite_sha256,)
            ).fetchone():
                raise ValueError("review cutoff reused a prior suite")
            count, size = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(body)),0) FROM reviewed_cutoffs"
            ).fetchone()
            if count + 1 > self.preparation_capacity.maximum_records or (
                size + len(body) > self.preparation_capacity.maximum_bytes
            ):
                raise AdmissionCapacityError("review cutoff capacity is exhausted")
            records, payload = connection.execute(
                "SELECT records,payload_bytes FROM admission_usage WHERE singleton=1"
            ).fetchone()
            for signed in submissions:
                sub = signed.submission
                sub_id = digest(sub)
                raw = canonical_json_bytes(signed)
                old = connection.execute(
                    "SELECT body FROM submissions WHERE digest=?", (sub_id,)
                ).fetchone()
                if old is not None:
                    if old[0] != raw:
                        raise ValueError("review submission history is corrupt")
                    continue
                receipt = canonical_json_bytes(
                    {
                        "schema": "umi-evaluator-roster-observation/1",
                        "submission_sha256": sub_id,
                        "round_sha256": round_id,
                        "first_observed_block": observed_block,
                        "admission_timing_proven": False,
                        "chain_submission_authorized": False,
                    }
                )
                records, payload = records + 1, payload + len(raw) + len(receipt)
                if records > self.admission_capacity.maximum_records or (
                    payload > self.admission_capacity.maximum_bytes
                ):
                    raise AdmissionCapacityError("review submission capacity is exhausted")
                self._insert_admission(
                    connection,
                    (
                        sub_id,
                        identity(sub.hotkey),
                        sub.track,
                        sub.sequence,
                        observed_block,
                        sub.valid_through_block,
                        raw,
                        receipt,
                    ),
                    records=records,
                    payload_bytes=payload,
                )
            connection.execute(
                "INSERT INTO rounds VALUES (?,?,?)",
                (round_id, round_.sequence, canonical_json_bytes(round_)),
            )
            connection.execute(
                "INSERT INTO suite_usage VALUES (?,?)", (round_.suite_sha256, round_id)
            )
            connection.execute(
                "INSERT INTO reviewed_cutoffs VALUES (?,?,?)", (round_id, observed_block, body)
            )
            return observed_block
