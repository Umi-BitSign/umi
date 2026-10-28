"""Metadata-bounded direct-upload retries with a recoverable current-attempt index.

Generation six fences earlier journal readers before they can ignore later
attempts. Migration and explicit derived-index repair preserve every original
record. Only the configured metadata allowance bounds retained retry history;
the legacy per-upload attempt setting is not a lifetime admission cutoff.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, sha256_hex

_MARKER = "round_generation_direct_upload_attempts"
_HEADS = "direct_upload_attempt_heads"
_SCHEMA = "umi-direct-upload-attempt-index/1"
_MARKER_SQL = (
    f"CREATE TABLE {_MARKER} (id INTEGER PRIMARY KEY CHECK(id=1), "
    "schema TEXT NOT NULL, owner_sha256 TEXT NOT NULL)"
)
_HEADS_SQL = (
    f"CREATE TABLE {_HEADS} (upload_sha256 TEXT PRIMARY KEY NOT NULL, "
    "generation INTEGER NOT NULL CHECK(TYPEOF(generation)='integer' AND generation>=0), "
    "attempt_id TEXT)"
)
_POLL_CURSOR = "direct_upload_poll_cursor"
_POLL_CURSOR_SQL = (
    f"CREATE TABLE {_POLL_CURSOR} (id INTEGER PRIMARY KEY CHECK(id=1), "
    "after_key TEXT NOT NULL)"
)


class DirectModelAttemptRepairRequired(RuntimeError):
    """Retained attempt metadata needs explicit repair, never a fresh upload."""


class DirectModelMetadataCapacityPending(OSError):
    """Metadata needs additional capacity; the original signed upload can resume."""


class DirectModelUploadIntent(StrictProtocolModel):
    schema_: Literal["umi-direct-model-upload-intent/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    upload_sha256: Hex32
    payload_declaration_sha256: Hex32
    attempt_id: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    object_key: Annotated[str, Field(min_length=1, max_length=1024)]
    created_at_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]
    retry_after_unix_ms: Annotated[int, Field(ge=0, le=2**63 - 1)]

    @model_validator(mode="after")
    def ordered(self) -> Self:
        if self.retry_after_unix_ms <= self.created_at_unix_ms:
            raise ValueError("direct upload attempt lease differs")
        return self


class DirectModelAttemptIndex(StrictProtocolModel):
    schema_: Literal["umi-direct-model-attempt-index/1"] = Field(alias="schema")
    upload_sha256: Hex32
    generation: Annotated[int, Field(ge=1, le=2**32 - 1)]
    attempt_id: Hex32


def attempt_index_key(upload_sha256: str, generation: int) -> str:
    return sha256_hex(f"umi-direct-model-attempt-index/1:{upload_sha256}:{generation}".encode())


class DirectModelAttemptJournal(RoundJournal):
    """One metadata owner, with no independent lifetime attempt-count limit."""

    def __init__(
        self,
        root: Path,
        binding: dict,
        *,
        maximum_uploads: int,
        maximum_bytes: int,
        repair_attempt_index: bool = False,
        existing_only: bool = False,
        read_only: bool = False,
    ):
        if type(maximum_uploads) is not int or not 1 <= maximum_uploads <= 4096:
            raise ValueError("direct upload request capacity must be between 1 and 4096")
        if type(repair_attempt_index) is not bool or (
            repair_attempt_index and (existing_only or read_only)
        ):
            raise ValueError("direct upload attempt repair requires an explicit writable owner")
        self._attempt_owner = digest(binding)
        self._attempt_cohort = binding["cohort_sha256"]
        self._repair_attempt_index = repair_attempt_index
        super().__init__(
            root,
            binding,
            maximum_rounds=maximum_uploads,
            maximum_bytes=maximum_bytes,
            existing_only=existing_only,
            read_only=read_only,
        )
        if not self.existing_only:
            self._install_attempt_index()
        elif self._journal_version() != 6:
            raise DirectModelAttemptRepairRequired(
                "direct upload journal needs its supported migration"
            )

    @property
    def maximum_records(self):
        # Every record consumes at least one logical byte. The metadata byte
        # allowance, rather than a multiplication of upload/attempt counts,
        # bounds retained history. Request enumeration remains separately bounded.
        return self.maximum_bytes

    def keys(self, kind, *, db=None):
        """Borrow one owner snapshot for the bounded scheduling projection."""
        if db is None:
            return super().keys(kind)
        rows = db.execute(
            "SELECT id FROM records WHERE kind=? ORDER BY id LIMIT ?",
            (kind, self.maximum_rounds + 1),
        ).fetchall()
        if len(rows) > self.maximum_rounds:
            raise ValueError("round journal record limit")
        return [row[0] for row in rows]

    def selection_fence(self, db):
        """Native immutable-input additions/holds; independent of payload work."""
        _, _, kinds = self._record_capacity(db)
        self._check_original_counts(kinds)
        return (
            kinds.get("direct-request", 0),
            kinds.get("direct-reservation", 0),
            db.execute("SELECT COUNT(*) FROM holds").fetchone()[0],
        )

    def _journal_version(self):
        with self.read_transaction() as db:
            return db.execute("PRAGMA user_version").fetchone()[0]

    def _version(self, db):
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version != 6:
            if db.execute("SELECT 1 FROM sqlite_master WHERE name=?", (_MARKER,)).fetchone():
                raise DirectModelAttemptRepairRequired(
                    "direct upload journal marker was downgraded"
                )
            if version != 0:
                raise ValueError("unsupported direct upload journal capability")
            return RoundJournal._version(db)
        if not self._repair_attempt_index:
            self._check_attempt_schema(db)
        # This journal does not enable unrelated round-record reservations.
        return 0

    def _check_attempt_schema(self, db):
        for name, expected in ((_MARKER, _MARKER_SQL), (_HEADS, _HEADS_SQL)):
            if db.execute("SELECT sql FROM sqlite_master WHERE name=?", (name,)).fetchone() != (
                expected,
            ):
                raise DirectModelAttemptRepairRequired(
                    "direct upload attempt index schema needs repair"
                )
        if db.execute(f"SELECT id,schema,owner_sha256 FROM {_MARKER} LIMIT 2").fetchall() != [
            (1, _SCHEMA, self._attempt_owner)
        ]:
            raise DirectModelAttemptRepairRequired("direct upload attempt owner needs repair")

    def _install_attempt_index(self):
        with self.transaction() as db:
            version = db.execute("PRAGMA user_version").fetchone()[0]
            if version == 6 and not self._repair_attempt_index:
                return
            if version not in (0, 6):
                raise ValueError("unsupported direct upload attempt migration")
            request_count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='direct-request'"
            ).fetchone()[0]
            attempt_count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='direct-attempt-index'"
            ).fetchone()[0]
            intent_count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='direct-intent'"
            ).fetchone()[0]
            if (
                intent_count != attempt_count
                or db.execute(
                    "SELECT 1 FROM records r WHERE r.kind='direct-request' AND NOT EXISTS "
                    "(SELECT 1 FROM records p WHERE p.kind='direct-payload' AND p.id=r.id) LIMIT 1"
                ).fetchone()
            ):
                raise DirectModelAttemptRepairRequired(
                    "direct upload original metadata is incomplete; restore required"
                )
            if request_count > self.maximum_rounds:
                raise ValueError("retained direct requests exceed configured upload capacity")
            stage = (
                "direct_upload_attempt_index_repair"
                if version == 6
                else "direct_upload_attempt_index_migration"
            )
            with TransferProgress(stage, request_count + attempt_count, unit="records") as progress:
                if version == 6:
                    db.execute(f"DROP TABLE IF EXISTS {_HEADS}")
                    db.execute(f"DROP TABLE IF EXISTS {_MARKER}")
                db.execute(_HEADS_SQL)
                db.execute(
                    f"INSERT INTO {_HEADS} SELECT id,0,NULL FROM records "
                    "WHERE kind='direct-request'"
                )
                progress.advance(request_count)
                cursor = db.execute(
                    "SELECT id FROM records WHERE kind='direct-attempt-index' ORDER BY id"
                )
                # One small integer per retained request bounds migration memory.
                # Unique digest keys and positive generations mean count == max
                # proves there are no missing generations, regardless of key order.
                counts = {}
                try:
                    for (key,) in cursor:
                        index = DirectModelAttemptIndex.model_validate_json(
                            self.get_raw("direct-attempt-index", key, db=db)
                        )
                        if key != attempt_index_key(index.upload_sha256, index.generation):
                            raise DirectModelAttemptRepairRequired(
                                "direct upload attempt index key changed"
                            )
                        intent = self._intent(index, db)
                        changed = db.execute(
                            f"UPDATE {_HEADS} SET "
                            "attempt_id=CASE WHEN generation<? THEN ? ELSE attempt_id END, "
                            "generation=MAX(generation,?) WHERE upload_sha256=?",
                            (
                                intent.generation,
                                intent.attempt_id,
                                intent.generation,
                                intent.upload_sha256,
                            ),
                        ).rowcount
                        if changed != 1:
                            raise DirectModelAttemptRepairRequired(
                                "direct upload attempt has no retained request"
                            )
                        counts[intent.upload_sha256] = counts.get(intent.upload_sha256, 0) + 1
                        progress.advance(1)
                finally:
                    cursor.close()
                for upload, count in counts.items():
                    maximum = db.execute(
                        f"SELECT generation FROM {_HEADS} WHERE upload_sha256=?", (upload,)
                    ).fetchone()[0]
                    if maximum != count:
                        raise DirectModelAttemptRepairRequired("direct upload attempts have a gap")
                db.execute(_MARKER_SQL)
                db.execute(f"INSERT INTO {_MARKER} VALUES (1,?,?)", (_SCHEMA, self._attempt_owner))
                db.execute("PRAGMA user_version=6")
                self._check_attempt_schema(db)
                self._check_attempt_capacity(db)
        self._repair_attempt_index = False

    def _check_attempt_capacity(self, db):
        count, used, _ = self._record_capacity(db)
        heads, head_bytes = db.execute(
            f"SELECT COUNT(*),COALESCE(SUM(LENGTH(upload_sha256)+"
            f"LENGTH(CAST(generation AS TEXT))+COALESCE(LENGTH(attempt_id),0)),0) FROM {_HEADS}"
        ).fetchone()
        cursor_bytes = 64 if self._poll_cursor(db) is not None else 0
        if (
            count + heads > self.maximum_records
            or used + head_bytes + cursor_bytes > self.maximum_bytes
        ):
            raise DirectModelMetadataCapacityPending("direct upload metadata capacity pending")

    def _poll_cursor(self, db):
        schema = db.execute(
            "SELECT sql FROM sqlite_master WHERE name=?", (_POLL_CURSOR,)
        ).fetchone()
        if schema is None:
            return None  # Original journals have no scheduling cursor.
        if schema != (_POLL_CURSOR_SQL,):
            raise DirectModelAttemptRepairRequired("direct upload poll cursor schema needs repair")
        rows = db.execute(
            "SELECT id,CASE WHEN TYPEOF(after_key)='text' "
            "AND LENGTH(CAST(after_key AS BLOB)) IN (0,64) THEN after_key ELSE NULL END "
            f"FROM {_POLL_CURSOR} LIMIT 2"
        ).fetchall()
        if len(rows) != 1 or rows[0][0] != 1:
            raise DirectModelAttemptRepairRequired("direct upload poll cursor needs repair")
        after = rows[0][1]
        if type(after) is not str or (
            after and (len(after) != 64 or any(c not in "0123456789abcdef" for c in after))
        ):
            raise DirectModelAttemptRepairRequired("direct upload poll cursor needs repair")
        return after

    def initialize_poll_cursor(self, *, repair=False):
        """Add one bounded scheduling hint, preserving all original signed records."""
        if type(repair) is not bool or self.existing_only:
            raise ValueError("direct upload poll cursor initialization requires a writable owner")
        with self.transaction() as db:
            if repair or self._poll_cursor(db) is None:
                stage = (
                    "direct_upload_poll_cursor_repair"
                    if repair
                    else "direct_upload_poll_cursor_install"
                )
                with TransferProgress(stage, 1, unit="records") as progress:
                    if repair:
                        db.execute(f"DROP TABLE IF EXISTS {_POLL_CURSOR}")
                    db.execute(_POLL_CURSOR_SQL)
                    db.execute(f"INSERT INTO {_POLL_CURSOR} VALUES (1,'')")
                    self._check_attempt_capacity(db)
                    progress.advance(1)

    def poll_cursor(self):
        with self.read_transaction() as db:
            after = self._poll_cursor(db)
        if after is None:
            raise DirectModelAttemptRepairRequired("direct upload poll cursor is missing")
        return after

    def advance_poll_cursor(self, reservation_sha256):
        """Checkpoint a selected attempt before I/O; this never acknowledges completion."""
        if (
            type(reservation_sha256) is not str
            or len(reservation_sha256) != 64
            or any(c not in "0123456789abcdef" for c in reservation_sha256)
        ):
            raise ValueError("direct upload poll reservation differs")
        with self.transaction() as db:
            after = self._poll_cursor(db)
            if after is None:
                raise DirectModelAttemptRepairRequired("direct upload poll cursor is missing")
            if after != reservation_sha256:
                db.execute(
                    f"UPDATE {_POLL_CURSOR} SET after_key=? WHERE id=1", (reservation_sha256,)
                )

    def put_many(self, records, *, index=None):
        def bounded(db):
            if index is not None:
                index(db)
            self._check_attempt_capacity(db)

        try:
            return super().put_many(records, index=bounded)
        except ValueError as error:
            if str(error) == "round journal capacity exhausted":
                raise DirectModelMetadataCapacityPending(
                    "direct upload metadata capacity pending"
                ) from error
            raise

    def metadata_snapshot(self):
        with self.read_transaction() as db:
            _, used, kinds = self._record_capacity(db)
            requests, head_bytes, maximum_generation = db.execute(
                f"SELECT COUNT(*),COALESCE(SUM(LENGTH(upload_sha256)+"
                f"LENGTH(CAST(generation AS TEXT))+COALESCE(LENGTH(attempt_id),0)),0),"
                f"COALESCE(MAX(generation),0) FROM {_HEADS}"
            ).fetchone()
            cursor_bytes = 64 if self._poll_cursor(db) is not None else 0
        if requests != kinds.get("direct-request", 0):
            raise DirectModelAttemptRepairRequired("direct upload request heads need repair")
        self._check_original_counts(kinds)
        return {
            "metadata_bytes": used + head_bytes + cursor_bytes,
            "maximum_metadata_bytes": self.maximum_bytes,
            "remaining_metadata_bytes": max(
                0, self.maximum_bytes - used - head_bytes - cursor_bytes
            ),
            "retained_uploads": requests,
            "maximum_uploads": self.maximum_rounds,
            "retained_attempts": kinds.get("direct-intent", 0),
            "highest_generation": maximum_generation,
        }

    @staticmethod
    def _check_original_counts(kinds):
        if kinds.get("direct-intent", 0) != kinds.get("direct-attempt-index", 0) or kinds.get(
            "direct-request", 0
        ) != kinds.get("direct-payload", 0):
            raise DirectModelAttemptRepairRequired(
                "direct upload original metadata is incomplete; restore required"
            )

    def _intent(self, index, db):
        raw = self.get_raw("direct-intent", index.attempt_id, db=db)
        if raw is None:
            raise DirectModelAttemptRepairRequired("direct upload attempt intent is missing")
        intent = DirectModelUploadIntent.model_validate_json(raw)
        if intent.cohort_sha256 != self._attempt_cohort or (
            intent.upload_sha256,
            intent.generation,
            intent.attempt_id,
        ) != (index.upload_sha256, index.generation, index.attempt_id):
            raise DirectModelAttemptRepairRequired("direct upload attempt identity changed")
        return intent

    def latest_attempt(self, upload_sha256: str):
        try:
            with self.read_transaction() as db:
                self._check_original_counts(self._record_capacity(db)[2])
                return self._latest_attempt(upload_sha256, db)
        except (ValueError, TypeError) as error:
            raise DirectModelAttemptRepairRequired(
                "retained direct upload attempt metadata needs repair"
            ) from error

    def _latest_attempt(self, upload_sha256, db, *, check_next=True):
        row = db.execute(
            f"SELECT generation,attempt_id FROM {_HEADS} WHERE upload_sha256=?", (upload_sha256,)
        ).fetchone()
        if row is None:
            if db.execute(
                "SELECT 1 FROM records WHERE kind='direct-request' AND id=?", (upload_sha256,)
            ).fetchone():
                raise DirectModelAttemptRepairRequired(
                    "direct upload current attempt is missing; repair required"
                )
            return None
        generation, attempt_id = row
        if type(generation) is not int or not 0 <= generation <= 2**32 - 1:
            raise DirectModelAttemptRepairRequired("direct upload current generation changed")
        if (
            check_next
            and self.get_raw(
                "direct-attempt-index", attempt_index_key(upload_sha256, generation + 1), db=db
            )
            is not None
        ):
            raise DirectModelAttemptRepairRequired(
                "direct upload current attempt regressed; repair required"
            )
        if generation == 0:
            if attempt_id is not None:
                raise DirectModelAttemptRepairRequired("empty direct upload attempt changed")
            return None
        raw = self.get_raw(
            "direct-attempt-index", attempt_index_key(upload_sha256, generation), db=db
        )
        if raw is None:
            raise DirectModelAttemptRepairRequired(
                "direct upload current index is missing; repair required"
            )
        index = DirectModelAttemptIndex.model_validate_json(raw)
        if (index.upload_sha256, index.generation, index.attempt_id) != (
            upload_sha256,
            generation,
            attempt_id,
        ):
            raise DirectModelAttemptRepairRequired("direct upload current index changed")
        return self._intent(index, db)

    def retain_request(self, upload_sha256, request, payload):
        if self.get_raw("direct-request", upload_sha256) is not None:
            # An exact retry must not silently rebuild lost current metadata.
            self.latest_attempt(upload_sha256)

        def initialize(db):
            db.execute(f"INSERT OR IGNORE INTO {_HEADS} VALUES (?,0,NULL)", (upload_sha256,))

        self.put_many(
            (
                ("direct-request", upload_sha256, request),
                ("direct-payload", upload_sha256, payload),
            ),
            index=initialize,
        )

    def retain_attempt(self, intent: DirectModelUploadIntent):
        index = DirectModelAttemptIndex(
            schema="umi-direct-model-attempt-index/1",
            upload_sha256=intent.upload_sha256,
            generation=intent.generation,
            attempt_id=intent.attempt_id,
        )

        def advance(db):
            previous = self._latest_attempt(intent.upload_sha256, db, check_next=False)
            generation = 0 if previous is None else previous.generation
            if generation == intent.generation and previous == intent:
                return
            if generation + 1 != intent.generation:
                raise DirectModelAttemptRepairRequired(
                    "direct upload attempt did not extend its current generation"
                )
            changed = db.execute(
                f"UPDATE {_HEADS} SET generation=?,attempt_id=? "
                "WHERE upload_sha256=? AND generation=?",
                (intent.generation, intent.attempt_id, intent.upload_sha256, generation),
            ).rowcount
            if changed != 1:
                raise DirectModelAttemptRepairRequired("direct upload attempt head changed")

        self.put_many(
            (
                ("direct-intent", intent.attempt_id, intent),
                (
                    "direct-attempt-index",
                    attempt_index_key(intent.upload_sha256, intent.generation),
                    index,
                ),
            ),
            index=advance,
        )
