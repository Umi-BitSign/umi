"""Durable immutable R2 receipts and a bounded disposable in-memory proof cache.

Private receipts attest completed transport only. Independent consumers still
perform native proof verification; their successful verdicts live elsewhere.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from threading import Condition, Event, RLock
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_evidence_codec import MAX_PROOF_OBJECT_BYTES, checked_digest
from .competition_remote_proof_generation import install_generation, validate_generation
from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .r2_evidence import EvidenceObjectHead, R2EvidenceClient, r2_evidence_connection_scope
from .r2_publish_batch import (
    MAX_PUBLISH_OBJECT_BYTES,
    MAX_PUBLISH_OBJECTS,
    R2ProofPublishBatch,
    R2PublishBatchUnavailable,
)
from .r2_sigv4 import R2SigV4, load_r2_credentials

PROOF_PUBLICATION_WORKERS = 8
MAX_ACTIVE_PROOF_PUBLICATION_BYTES = 2 * MAX_PROOF_OBJECT_BYTES


class ProofArchiveR2Config(StrictProtocolModel):
    schema_: Literal["umi-r2-proof-archive/1", "umi-r2-proof-archive/2"] = Field(alias="schema")
    credentials_file: Directory
    bucket: Annotated[str, Field(min_length=3, max_length=63)]
    prefix: Annotated[str, Field(pattern=r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,95}$")]
    read_only: bool
    maximum_cache_bytes: Annotated[int, Field(ge=MAX_PROOF_OBJECT_BYTES, le=16 * 1024**3)]
    maximum_index_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)]
    timeout_seconds: Annotated[int, Field(ge=1, le=300)] = 60
    legacy_read_through: bool = False
    source_release_batch_records: Annotated[int, Field(ge=0, le=4096)] = 0
    archive_backfill_batch_frames: Annotated[int, Field(ge=0, le=256)] = 0
    archive_release_batch_files: Annotated[int, Field(ge=0, le=4096)] = 0
    archive_release_consumer_abi: Literal["umi-proof-read-release-lease/1"] | None = None

    @model_validator(mode="after")
    def legacy_selection(self):
        if self.legacy_read_through and self.schema_ != "umi-r2-proof-archive/2":
            raise ValueError("retained local proof reads require explicit archive/2 selection")
        if self.source_release_batch_records and (not self.legacy_read_through or self.read_only):
            raise ValueError("source release requires writable retained-local archive/2 selection")
        if (self.archive_backfill_batch_frames or self.archive_release_batch_files) and (
            not self.legacy_read_through or self.read_only
        ):
            raise ValueError("online archive migration requires writable retained-local archive/2")
        if self.archive_release_batch_files and not self.archive_backfill_batch_frames:
            raise ValueError("online archive release requires its bounded backfill cursor")
        if self.archive_release_batch_files and self.archive_release_consumer_abi is None:
            raise ValueError("online release requires explicit selected-consumer lease ABI")
        return self

    @model_serializer(mode="wrap")
    def original_bytes(self, handler):
        value = handler(self)
        if not self.legacy_read_through:
            value.pop("legacy_read_through", None)
        if not self.source_release_batch_records:
            value.pop("source_release_batch_records", None)
        for name in (
            "archive_backfill_batch_frames",
            "archive_release_batch_files",
            "archive_release_consumer_abi",
        ):
            if not getattr(self, name):
                value.pop(name, None)
        return value


class ProofArchiveStores(StrictProtocolModel):
    schema_: Literal["umi-proof-archive-stores/1"] = Field(alias="schema")
    imported: ProofArchiveR2Config | None = None
    exported: ProofArchiveR2Config | None = None

    @model_validator(mode="after")
    def directions(self):
        if self.imported is not None and not self.imported.read_only:
            raise ValueError("imported proof transport must be read-only")
        if self.exported is not None and self.exported.read_only:
            raise ValueError("exported proof transport must permit publication")
        if self.imported is None and self.exported is None:
            raise ValueError("proof transport selection requires at least one remote store")
        return self

    def credential_paths(self) -> tuple[Path, ...]:
        return tuple(
            dict.fromkeys(
                Path(config.credentials_file)
                for config in (self.imported, self.exported)
                if config is not None
            )
        )


class RemoteProofReference(StrictProtocolModel):
    schema_: Literal["umi-r2-proof-reference/1"] = Field(alias="schema")
    namespace_sha256: Hex32
    key: Annotated[str, Field(min_length=1, max_length=1024)]
    content_sha256: Hex32
    size_bytes: Annotated[int, Field(ge=1, le=MAX_PROOF_OBJECT_BYTES)]
    etag: Annotated[str, Field(min_length=1, max_length=256)]


_COMPLETION_KIND = "remote_proof_completion"
_COMPLETION_MARKER = "round_generation_proof_completion"
_COMPLETION_SCHEMA = (
    "CREATE TABLE round_generation_proof_completion (id INTEGER PRIMARY KEY CHECK(id=1), "
    "schema TEXT NOT NULL, namespace TEXT NOT NULL, "
    "completed INTEGER NOT NULL CHECK(TYPEOF(completed)='integer' AND completed>=0))"
)


def _completion_triggers():
    result = {}
    for action in ("UPDATE", "DELETE"):
        name = _COMPLETION_MARKER + "_" + action.lower()
        result[name] = (
            f"CREATE TRIGGER {name} BEFORE {action} ON records "
            f"WHEN OLD.kind='{_COMPLETION_KIND}' BEGIN SELECT "
            "RAISE(ABORT,'remote proof completion ledger is immutable; "
            "restore original metadata'); END"
        )
    name = _COMPLETION_MARKER + "_insert"
    result[name] = (
        f"CREATE TRIGGER {name} AFTER INSERT ON records "
        f"WHEN NEW.kind='{_COMPLETION_KIND}' BEGIN "
        f"UPDATE {_COMPLETION_MARKER} SET completed=completed+1 WHERE id=1; "
        "SELECT CASE WHEN changes()!=1 THEN RAISE(ABORT,"
        "'remote proof completion owner missing; restore original metadata') END; END"
    )
    return result


class _ProofIndex(RoundJournal):
    def _validate_existing(self, binding):
        # A producer may be writing another immutable receipt. SQLite's mode=ro
        # connection provides its committed snapshot without writing the source.
        # It still refuses a hot journal that actually needs rollback recovery;
        # the ordinary stopped-owner transfer reader keeps its clean-file fence.
        return super()._validate_existing(binding, require_clean_rollback=not self.read_only)

    @property
    def maximum_records(self):
        return self.maximum_bytes

    def _enable_reservations(self, db):
        raise ValueError("remote proof completion index does not support reservations")

    @staticmethod
    def _version(db):
        if db.execute("PRAGMA user_version").fetchone()[0] != 4:
            if db.execute(
                "SELECT 1 FROM sqlite_master WHERE name=?", (_COMPLETION_MARKER,)
            ).fetchone():
                raise ValueError("remote proof completion marker was downgraded")
            return RoundJournal._version(db)
        table = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?",
            (_COMPLETION_MARKER,),
        ).fetchone()
        triggers = dict(
            db.execute(
                "SELECT name,sql FROM sqlite_master WHERE type='trigger' AND name GLOB ?",
                (_COMPLETION_MARKER + "_*",),
            )
        )
        if table != (_COMPLETION_SCHEMA,) or triggers != _completion_triggers():
            raise ValueError("remote proof completion ledger damaged; restore original metadata")
        rows = db.execute(
            f"SELECT id,schema,namespace,completed FROM {_COMPLETION_MARKER} LIMIT 2"
        ).fetchall()
        binding = db.execute("SELECT body FROM binding LIMIT 2").fetchall()
        count = db.execute(
            "SELECT number FROM round_record_capacity_kinds WHERE kind=?", (_COMPLETION_KIND,)
        ).fetchone()
        completed = 0 if count is None else count[0]
        if len(binding) != 1 or rows != [
            (1, "umi-r2-proof-completion/1", digest(json.loads(binding[0][0])), completed)
        ]:
            raise ValueError("remote proof completion owner damaged; restore original metadata")
        validate_generation(db, digest(json.loads(binding[0][0])))
        # This private capability does not enable reservation-generation semantics.
        return 0

    def migrate_completions(self, namespace):
        """Transactional metadata-only upgrade; original receipts and inode stay intact.

        This compatibility migration is needed only by pre-completion-ledger
        installations. A damaged upgraded owner can never re-enter migration.
        """
        with self.transaction() as db:
            if db.execute("PRAGMA user_version").fetchone()[0] == 4:
                return
            if db.execute("PRAGMA user_version").fetchone()[0] != 0:
                raise ValueError("unsupported remote proof completion migration")
            if db.execute(
                "SELECT 1 FROM records WHERE kind=? LIMIT 1", (_COMPLETION_KIND,)
            ).fetchone():
                raise ValueError(
                    "remote proof completion marker missing; restore original metadata"
                )
            total = db.execute(
                "SELECT count(*) FROM records WHERE kind='remote_proof_object'"
            ).fetchone()[0]
            with TransferProgress(
                "proof_receipt_migration",
                total,
                unit="receipts",
                planning_unit_seconds=(0.00001, 0.001),
            ) as progress:
                with closing(
                    db.execute(
                        "SELECT id FROM records WHERE kind='remote_proof_object' ORDER BY id"
                    )
                ) as records:
                    for (key,) in records:
                        raw = self.get_raw("remote_proof_object", key, db=db)
                        reference = RemoteProofReference.model_validate_json(raw)
                        if (
                            reference.namespace_sha256 != namespace
                            or hashlib.sha256(reference.key.encode()).hexdigest() != key
                        ):
                            raise ValueError("remote proof legacy receipt identity damaged")
                        self.insert_completion_record(db, _COMPLETION_KIND, key, raw)
                        progress.advance(1)
                db.execute(_COMPLETION_SCHEMA)
                db.execute(
                    f"INSERT INTO {_COMPLETION_MARKER} VALUES (1,?,?,?)",
                    ("umi-r2-proof-completion/1", namespace, total),
                )
                for statement in _completion_triggers().values():
                    db.execute(statement)
                db.execute("PRAGMA user_version=4")

    def insert_completion_record(self, db, kind, key, raw):
        count, used, _ = self._record_capacity(db)
        if count + 1 > self.maximum_records or used + len(raw) > self.maximum_bytes:
            raise ValueError("remote proof completion index capacity exhausted")
        db.execute("INSERT INTO records VALUES (?,?,?)", (kind, key, raw))


class RemoteProofStore:
    """One authenticated namespace with metadata independent of cached bytes.

    All synchronous callers already run inside owned I/O threads. Publication
    admits bounded independent objects while keeping receipt mutations serial.
    A pinned cache entry cannot be evicted;
    insufficient space for another lease is a retry, never an unbounded allocation.

    An explicit receipt source opens the original completed ledger readonly.
    The consumer's separate index retains only its independent damage holds;
    missing original receipts never trigger remote adoption or index copying.
    """

    def __init__(
        self,
        root: Path,
        config: ProofArchiveR2Config,
        *,
        client=None,
        receipt_source_directory: Path | None = None,
    ):
        if receipt_source_directory is not None and (
            not config.read_only or root.resolve() == receipt_source_directory.resolve()
        ):
            raise ValueError("receipt source requires an independent read-only consumer")
        self.config = config
        if client is None:
            credentials = load_r2_credentials(Path(config.credentials_file))
            client = R2EvidenceClient(
                R2SigV4(credentials.endpoint, config.bucket, credentials.credentials),
                timeout_seconds=config.timeout_seconds,
            )
        if client.signer.bucket != config.bucket:
            raise ValueError("proof transport selects another bucket")
        self.client = client
        self.binding = {
            "schema": "umi-r2-proof-store/1",
            "endpoint": client.signer.endpoint,
            "bucket": client.signer.bucket,
            "prefix": config.prefix,
        }
        self.namespace_sha256 = digest(self.binding)
        self.journal = _ProofIndex(
            root,
            self.binding,
            maximum_rounds=65536,
            maximum_bytes=config.maximum_index_bytes,
            maximum_record_bytes=64 * 1024,
        )
        self.journal.migrate_completions(self.namespace_sha256)
        install_generation(self.journal, self.namespace_sha256)
        self.receipt_source = None
        if receipt_source_directory is not None:
            self.receipt_source = _ProofIndex(
                receipt_source_directory,
                self.binding,
                maximum_rounds=65536,
                maximum_bytes=config.maximum_index_bytes,
                maximum_record_bytes=64 * 1024,
                existing_only=True,
                read_only=True,
            )
            with self.receipt_source.read_transaction() as db:
                if db.execute("PRAGMA user_version").fetchone()[0] != 4:
                    raise ValueError("receipt source requires its completed immutable ledger")
        self._cache, self._pins, self._bytes = OrderedDict(), {}, 0
        self._lock = RLock()
        self._publication_condition = Condition(self._lock)
        self._publishing_keys: set[str] = set()
        self._publishing_bytes = 0
        self._publish_batch = (
            R2ProofPublishBatch(client)
            if isinstance(client, R2EvidenceClient)
            and client.signer.credentials.proof_publish_batch_origin is not None
            and not config.read_only
            else None
        )
        self._publish_batch_failure = None

    def _key(self, path: str) -> str:
        key = self.config.prefix + "/" + path
        self.client.signer.object_url(key)
        return key

    def _reference(self, key: str, head: EvidenceObjectHead) -> RemoteProofReference:
        return RemoteProofReference(
            schema="umi-r2-proof-reference/1",
            namespace_sha256=self.namespace_sha256,
            key=key,
            content_sha256=head.content_sha256,
            size_bytes=head.size_bytes,
            etag=head.etag,
        )

    def _completion(self, key: str, db) -> RemoteProofReference | None:
        try:
            value = self.journal.get(
                _COMPLETION_KIND, hashlib.sha256(key.encode()).hexdigest(), db=db
            )
            if value is None:
                return None
            reference = RemoteProofReference.model_validate(value)
            if reference.key != key or reference.namespace_sha256 != self.namespace_sha256:
                raise ValueError("completion identity differs")
        except (TypeError, ValueError) as error:
            raise ValueError(
                "remote proof completion ledger damaged; restore original metadata"
            ) from error
        return reference

    def _retained(self, key: str) -> RemoteProofReference | None:
        journal = self.receipt_source or self.journal
        with journal.read_transaction() as db:
            return self._retained_snapshot(key, db)

    def _retained_snapshot(self, key: str, db) -> RemoteProofReference | None:
        """Read completion and original receipt from one caller-owned snapshot."""
        completed = self._completion(key, db)
        try:
            raw = self.journal.get_raw(
                "remote_proof_object", hashlib.sha256(key.encode()).hexdigest(), db=db
            )
            reference = None if raw is None else RemoteProofReference.model_validate_json(raw)
        except (TypeError, ValueError) as error:
            raise ValueError(
                "remote proof replication receipt damaged; "
                "explicit original-generation repair required"
            ) from error
        if completed is None:
            if reference is not None:
                raise ValueError(
                    "remote proof completion ledger missing; restore original metadata"
                )
            return None
        if reference != completed:
            raise ValueError(
                "remote proof replication receipt is missing or damaged; "
                "explicit original-generation repair required"
            )
        return completed

    def _remember(self, reference: RemoteProofReference) -> None:
        if self.receipt_source is not None:
            raise ValueError("read-only receipt consumer cannot adopt new producer receipts")
        key = hashlib.sha256(reference.key.encode()).hexdigest()
        self.journal.put_many(
            (
                (_COMPLETION_KIND, key, reference),
                ("remote_proof_object", key, reference),
            )
        )

    def _damage_key(self, reference: RemoteProofReference) -> str:
        return hashlib.sha256(reference.key.encode()).hexdigest()

    def _hold(self, reference: RemoteProofReference) -> None:
        self.journal.put(
            "remote_proof_damage",
            self._damage_key(reference),
            {
                "schema": "umi-r2-proof-damage/1",
                "reference_sha256": digest(reference),
                "reason": "remote_proof_missing_changed_or_corrupt",
            },
        )

    def validate_reference(self, value: dict) -> RemoteProofReference:
        """Check this owner's durable replication fact without reading payloads.

        This attests completed replication, not a new remote availability probe. Any
        fetch still checks the observed object generation and authenticates its bytes.
        """
        with self.reference_snapshot() as validate:
            return validate(value)

    def _require_undamaged(self, reference, db, damage_db):
        owner = self.receipt_source or self.journal
        key = self._damage_key(reference)
        if owner.get("remote_proof_damage", key, db=db) is not None or (
            self.receipt_source is not None
            and self.journal.get("remote_proof_damage", key, db=damage_db) is not None
        ):
            raise ValueError("remote proof requires explicit original-generation repair")

    @contextmanager
    def reference_snapshot(self):
        """Check at most 256 references in fresh, bounded receipt snapshots.

        Callers already holding source metadata open these afterward, and close
        them before any finality check. Every later batch reopens both owners;
        receipt/schema/hold facts never become cross-batch cached verdicts.
        """
        owner = self.receipt_source or self.journal
        with (
            owner.read_transaction() as db,
            (
                self.journal.read_transaction()
                if self.receipt_source is not None
                else nullcontext(db)
            ) as damage_db,
        ):
            active, remaining = True, 256

            def validate(value):
                nonlocal remaining
                if not active or remaining == 0:
                    raise ValueError("remote proof receipt snapshot is closed or exhausted")
                remaining -= 1
                reference = RemoteProofReference.model_validate(value)
                if (
                    reference.namespace_sha256 != self.namespace_sha256
                    or not reference.key.startswith(self.config.prefix + "/")
                ):
                    raise ValueError(
                        "remote proof reference selects another authenticated namespace"
                    )
                if self._retained_snapshot(reference.key, db) != reference:
                    raise ValueError("remote proof replication receipt is missing or damaged")
                self._require_undamaged(reference, db, damage_db)
                return reference

            try:
                yield validate
            finally:
                active = False

    def repair_reference(self, value: dict) -> None:
        """Requalify the exact original generation; never adopt changed bytes.

        Call only from an explicit owner repair. Successful past replication
        survives ordinary eviction, while an observed loss persists across restart.
        """
        reference = RemoteProofReference.model_validate(value)
        if reference.namespace_sha256 != self.namespace_sha256 or not reference.key.startswith(
            self.config.prefix + "/"
        ):
            raise ValueError("remote proof repair requires its original owner receipt")
        expected = EvidenceObjectHead(
            reference.size_bytes, reference.etag, reference.content_sha256
        )
        with self._lock, TransferProgress("proof_repair", reference.size_bytes) as progress:
            receipt_owner = self.receipt_source or self.journal
            with receipt_owner.read_transaction() as db:
                if self._completion(reference.key, db) != reference:
                    progress.emit("repair_required", reason="original_completion_metadata_required")
                    raise ValueError("remote proof repair requires its original completion ledger")
            if self.receipt_source is not None:
                self._check_producer_receipt(reference)
            try:
                if self.client.head(reference.key) != expected:
                    raise ValueError("remote proof repair requires the original object generation")
                self.client.read(reference.key, expected, maximum=MAX_PROOF_OBJECT_BYTES)
            except ValueError:
                self._hold(reference)
                progress.emit("repair_required", reason="remote_proof_original_not_restored")
                raise
            with self.journal.transaction() as db:
                if self.receipt_source is not None:
                    self._check_producer_receipt(reference)
                elif self._completion(reference.key, db) != reference:
                    raise ValueError("remote proof completion changed during explicit repair")
                key = self._damage_key(reference)
                # Preserve the original completed transport fact. Only its exact
                # damaged/missing replica and a prior availability hold are repaired.
                if self.receipt_source is None:
                    db.execute(
                        "DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,)
                    )
                    self.journal.insert_completion_record(
                        db, "remote_proof_object", key, canonical_json_bytes(reference)
                    )
                db.execute("DELETE FROM records WHERE kind='remote_proof_damage' AND id=?", (key,))
            progress.advance(reference.size_bytes)

    def _check_producer_receipt(self, reference: RemoteProofReference) -> None:
        """Never let a consumer repair clear a producer's independent hold."""
        if (
            self._retained(reference.key) != reference
            or self.receipt_source.get("remote_proof_damage", self._damage_key(reference))
            is not None
        ):
            raise ValueError("producer proof receipt requires explicit original-generation repair")

    def put_bytes(self, raw: bytes, *, path: str | None = None) -> dict:
        return self._put_bytes(raw, path=path)[0]

    def _put_bytes(self, raw: bytes, *, path: str | None = None) -> tuple[dict, bool]:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROOF_OBJECT_BYTES:
            raise ValueError("remote proof object exceeds its original byte bound")
        if self.config.read_only:
            raise ValueError("selected proof archive is read-only")
        sha = hashlib.sha256(raw).hexdigest()
        key = self._key("objects/" + sha if path is None else path)
        with (
            TransferProgress("proof_replication", len(raw)) as progress,
            self._publication_slot(key, len(raw), progress),
        ):
            with self._lock:
                prior = self._retained(key)
                if prior is not None:
                    self.validate_reference(prior.model_dump(mode="json", by_alias=True))
                    if (prior.content_sha256, prior.size_bytes) != (sha, len(raw)):
                        raise ValueError("immutable proof index conflicts with its original bytes")
                    progress.advance(len(raw), restored=True)
                    return prior.model_dump(mode="json", by_alias=True), True
            head = self.client.publish(key, raw, sha)
            reference = self._reference(key, head)
            with self._lock:
                self._remember(reference)
                # This owner already has the exact bytes just durably published.
                # Keep them under the existing disposable byte/pin budget so a
                # following export does not immediately HEAD/GET them again.
                cache_key = digest(reference)
                if cache_key not in self._cache:
                    try:
                        self._space(len(raw))
                    except OSError:
                        pass  # Cache pressure must not undo completed transport.
                    else:
                        self._cache[cache_key] = raw
                        self._bytes += len(raw)
            progress.advance(len(raw))
            return reference.model_dump(mode="json", by_alias=True), False

    @contextmanager
    def _publication_slot(self, key, size, progress):
        with self._publication_slots({key: size}, progress):
            yield

    @contextmanager
    def _publication_slots(self, sizes, progress):
        # Two maximum supported objects or eight ordinary smaller objects can
        # share the bounded active-byte window. Admission waits, never drops.
        size = sum(sizes.values())
        if (
            not sizes
            or len(sizes) > PROOF_PUBLICATION_WORKERS
            or size > MAX_ACTIVE_PROOF_PUBLICATION_BYTES
        ):
            raise ValueError("proof publication admission exceeds aggregate bounds")
        waited = False
        with self._publication_condition:
            while True:
                if self._publishing_keys.intersection(sizes):
                    reason = "proof_publication_same_key_wait"
                elif len(self._publishing_keys) + len(sizes) > PROOF_PUBLICATION_WORKERS:
                    reason = "proof_publication_worker_limit_wait"
                elif self._publishing_bytes + size > MAX_ACTIVE_PROOF_PUBLICATION_BYTES:
                    reason = "proof_publication_byte_budget_wait"
                else:
                    break
                progress.emit("waiting", reason=reason)
                waited = True
                self._publication_condition.wait(timeout=1)
            self._publishing_keys.update(sizes)
            self._publishing_bytes += size
        if waited:
            progress.emit("running", reason="proof_publication_admitted")
        try:
            yield
        finally:
            with self._publication_condition:
                self._publishing_keys.difference_update(sizes)
                self._publishing_bytes -= size
                self._publication_condition.notify_all()

    def _batch_publications(self, pending, progress):
        """Retain exact per-item receipts, including success before a partial failure."""
        remaining = []
        small = [(sha, raw) for sha, raw in pending if len(raw) <= MAX_PUBLISH_OBJECT_BYTES]
        remaining.extend((sha, raw) for sha, raw in pending if len(raw) > MAX_PUBLISH_OBJECT_BYTES)
        limit = min(MAX_PUBLISH_OBJECTS, PROOF_PUBLICATION_WORKERS)
        for offset in range(0, len(small), limit):
            selected = small[offset : offset + limit]
            if self._publish_batch_failure is not None:
                remaining.extend(selected)
                continue
            with TransferProgress(
                "proof_publication_batch",
                len(selected),
                unit="objects",
                total_operations=1,
                planning_unit_seconds=(0.01, 60),
            ) as batch:
                sizes = {self._key("objects/" + sha): len(raw) for sha, raw in selected}
                with self._publication_slots(sizes, batch):
                    # Another graph may have disabled the route while this
                    # batch waited for the same global admission budget.
                    if self._publish_batch_failure is not None:
                        remaining.extend(selected)
                        batch.emit("retrying", reason=self._publish_batch_failure)
                        continue
                    objects = {}
                    with self._lock:
                        for sha, raw in selected:
                            key = self._key("objects/" + sha)
                            prior = self._retained(key)
                            if prior is not None:
                                self.validate_reference(
                                    prior.model_dump(mode="json", by_alias=True)
                                )
                                if (prior.content_sha256, prior.size_bytes) != (
                                    hashlib.sha256(raw).hexdigest(),
                                    len(raw),
                                ):
                                    raise ValueError(
                                        "immutable proof index conflicts with its original bytes"
                                    )
                                progress.advance(len(raw), restored=True)
                                progress.advance_operations(1, restored=True)
                                batch.advance(1, restored=True)
                            else:
                                objects[key] = raw
                    if not objects:
                        batch.advance_operations(1, restored=True)
                        continue
                    try:
                        results = self._publish_batch.publish(objects)
                    except R2PublishBatchUnavailable as error:
                        self._publish_batch_failure = error.reason_code
                        batch.emit("retrying", reason=error.reason_code)
                        remaining.extend(
                            (key.rsplit("/", 1)[1], raw) for key, raw in objects.items()
                        )
                        continue
                    batch.advance_operations(1)
                    completed = [
                        (self._reference(key, head), objects[key])
                        for key, head in results.items()
                        if isinstance(head, EvidenceObjectHead)
                    ]
                    with self._lock:
                        # One atomic metadata transaction retains each existing /1
                        # receipt separately. No batch receipt substitutes for it.
                        records = []
                        for reference, _raw in completed:
                            ident = hashlib.sha256(reference.key.encode()).hexdigest()
                            records.extend(
                                (
                                    (_COMPLETION_KIND, ident, reference),
                                    ("remote_proof_object", ident, reference),
                                )
                            )
                        if records:
                            self.journal.put_many(records)
                        for reference, raw in completed:
                            cache_key = digest(reference)
                            if cache_key not in self._cache:
                                try:
                                    self._space(len(raw))
                                except OSError:
                                    pass
                                else:
                                    self._cache[cache_key] = raw
                                    self._bytes += len(raw)
                    for _reference, raw in completed:
                        progress.advance(len(raw))
                        progress.advance_operations(1)
                        batch.advance(1)
                    if any(value == 409 for value in results.values()):
                        raise ValueError("immutable R2 evidence object conflicts with publication")
                    failed = [
                        (key.rsplit("/", 1)[1], objects[key])
                        for key, value in results.items()
                        if value == 503
                    ]
                    if failed:
                        self._publish_batch_failure = "r2_publish_batch_item_unavailable"
                        batch.emit("retrying", reason=self._publish_batch_failure)
                        remaining.extend(failed)
        return remaining

    def put_many(self, objects: Mapping[str, bytes]) -> None:
        """Publish one encoder-owned graph before its recipe/frame can be exposed.

        Workers borrow the already materialized codec bytes. Each owns and closes
        its HTTP scope; a failed worker stops new jobs and drains active transfers.
        Successful durable receipts remain reusable by the unchanged retry.
        """
        if not objects:
            return
        if self.config.read_only:
            raise ValueError("selected proof archive is read-only")
        for sha, raw in objects.items():
            checked_digest(sha)
            if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROOF_OBJECT_BYTES:
                raise ValueError("remote proof object exceeds its original byte bound")
        stop = Event()
        fallback = None
        fallback_keys = set()

        def publish_lane(lane):
            try:
                with r2_evidence_connection_scope(self.client):
                    for sha, raw in lane:
                        if stop.is_set():
                            return
                        reference, restored = self._put_bytes(raw)
                        if reference["content_sha256"] != sha:
                            raise ValueError(
                                "encoded proof object differs from its content identity"
                            )
                        progress.advance(len(raw), restored=restored)
                        progress.advance_operations(1, restored=restored)
                        if sha in fallback_keys:
                            fallback.advance(1, restored=restored)
            except BaseException:
                stop.set()
                raise

        with TransferProgress(
            "proof_graph_replication",
            sum(len(raw) for raw in objects.values()),
            total_operations=len(objects),
        ) as progress:
            # A warm graph must not create a thread and two fresh journal
            # transactions for every already completed object. Check immutable
            # receipts and damage holds once in bounded fresh snapshots, then
            # send only unfinished objects to the ordinary publication workers.
            pending = self._pending_publications(objects, progress)
            if not pending:
                return
            if self._publish_batch is not None:
                pending = self._batch_publications(pending, progress)
                if not pending:
                    return
                if self._publish_batch_failure is not None:
                    fallback_keys = {
                        sha for sha, raw in pending if len(raw) <= MAX_PUBLISH_OBJECT_BYTES
                    }
                    if fallback_keys:
                        fallback = TransferProgress(
                            "proof_publication_fallback",
                            len(fallback_keys),
                            unit="objects",
                            planning_unit_seconds=(0.01, 60),
                        )
            lanes = [[] for _ in range(min(PROOF_PUBLICATION_WORKERS, len(pending)))]
            for number, item in enumerate(pending):
                lanes[number % len(lanes)].append(item)
            with fallback if fallback is not None else nullcontext():
                if fallback is not None:
                    fallback.emit("retrying", reason=self._publish_batch_failure)
                if len(lanes) == 1:
                    publish_lane(lanes[0])
                    return
                with ThreadPoolExecutor(
                    max_workers=len(lanes), thread_name_prefix="umi-proof-publish"
                ) as pool:
                    futures = [pool.submit(publish_lane, lane) for lane in lanes]
                    for future in futures:
                        future.result()

    def _pending_publications(self, objects, progress):
        owner = self.receipt_source or self.journal
        pending, batch = [], []

        def inspect_batch():
            restored_bytes = restored_count = 0
            with (
                self._lock,
                owner.read_transaction() as db,
                (
                    self.journal.read_transaction()
                    if self.receipt_source is not None
                    else nullcontext(db)
                ) as damage_db,
            ):
                for sha, raw in batch:
                    reference = self._retained_snapshot(self._key("objects/" + sha), db)
                    if reference is None:
                        pending.append((sha, raw))
                        continue
                    self._require_undamaged(reference, db, damage_db)
                    if (reference.content_sha256, reference.size_bytes) != (sha, len(raw)) or (
                        hashlib.sha256(raw).hexdigest() != sha
                    ):
                        raise ValueError("encoded proof object differs from its content identity")
                    restored_bytes += len(raw)
                    restored_count += 1
            if restored_count:
                progress.advance(restored_bytes, restored=True)
                progress.advance_operations(restored_count, restored=True)

        with TransferProgress(
            "proof_graph_receipt_lookup",
            len(objects),
            unit="objects",
            planning_unit_seconds=(0.00001, 0.01),
        ) as lookup:
            for item in objects.items():
                batch.append(item)
                if len(batch) == 256:
                    inspect_batch()
                    lookup.advance(len(batch))
                    batch.clear()
            if batch:
                inspect_batch()
                lookup.advance(len(batch))
        return pending

    def _space(self, required: int) -> None:
        for sha in tuple(self._cache):
            if self._bytes + required <= self.config.maximum_cache_bytes:
                break
            if not self._pins.get(sha):
                self._bytes -= len(self._cache.pop(sha))
        if self._bytes + required > self.config.maximum_cache_bytes:
            raise OSError("proof cache capacity is held by active leases")

    @contextmanager
    def pin(self, value: dict, *, maximum: int):
        reference = self.validate_reference(value)
        if not 0 < reference.size_bytes <= maximum <= MAX_PROOF_OBJECT_BYTES:
            raise ValueError("remote proof read exceeds its consumer bound")
        sha = digest(reference)
        with self._lock, TransferProgress("proof_fetch", reference.size_bytes) as progress:
            raw = self._cache.pop(sha, None)
            if raw is None:
                self._space(reference.size_bytes)
                expected = EvidenceObjectHead(
                    reference.size_bytes, reference.etag, reference.content_sha256
                )
                try:
                    if self.client.head(reference.key) != expected:
                        raise ValueError("remote proof object is missing or its generation changed")
                    raw = self.client.read(reference.key, expected, maximum=maximum)
                except ValueError:
                    self._hold(reference)
                    progress.emit(
                        "repair_required", reason="remote_proof_missing_changed_or_corrupt"
                    )
                    raise
                self._bytes += len(raw)
                progress.advance(len(raw))
            else:
                progress.advance(len(raw), restored=True)
            self._cache[sha] = raw
            self._pins[sha] = self._pins.get(sha, 0) + 1
        try:
            yield raw
        finally:
            with self._lock:
                self._pins[sha] -= 1
                if not self._pins[sha]:
                    del self._pins[sha]

    def read_bytes(self, value: dict, *, maximum: int) -> bytes:
        with self.pin(value, maximum=maximum) as raw:
            return raw

    def read_path(self, path: str, *, maximum: int, expected_sha256=None) -> bytes:
        key = self._key(path)
        with self._lock:
            reference = self._retained(key)
            if reference is None:
                if self.receipt_source is not None:
                    raise ValueError("producer proof receipt is missing; explicit repair required")
                with TransferProgress("proof_import", 1, unit="objects") as progress:
                    head = self.client.head(key)
                    if head is None:
                        raise FileNotFoundError("selected remote proof object is unavailable")
                    if expected_sha256 is not None and head.content_sha256 != expected_sha256:
                        raise ValueError("remote proof path changes its content address")
                    if not 0 < head.size_bytes <= maximum <= MAX_PROOF_OBJECT_BYTES:
                        raise ValueError("remote proof import exceeds its consumer bound")
                    self._space(head.size_bytes)
                    raw = self.client.read(key, head, maximum=maximum)
                    reference = self._reference(key, head)
                    self._remember(reference)
                    sha = digest(reference)
                    self._cache[sha] = raw
                    self._bytes += len(raw)
                    progress.advance(1)
            if expected_sha256 is not None and reference.content_sha256 != expected_sha256:
                raise ValueError("remote proof receipt changes its content address")
            return self.read_bytes(
                reference.model_dump(mode="json", by_alias=True), maximum=maximum
            )

    def read_object(self, sha256: str, *, maximum: int) -> bytes:
        checked_digest(sha256)
        return self.read_path("objects/" + sha256, maximum=maximum, expected_sha256=sha256)

    def reference_for_path(self, path: str) -> dict | None:
        reference = self._retained(self._key(path))
        if reference is None:
            return None
        value = reference.model_dump(mode="json", by_alias=True)
        self.validate_reference(value)
        return value

    def evict_cache(self) -> int:
        with self._lock, TransferProgress("proof_cache_eviction", 1, unit="objects") as progress:
            before = self._bytes
            for sha in tuple(self._cache):
                if not self._pins.get(sha):
                    self._bytes -= len(self._cache.pop(sha))
            progress.advance(1)
            return before - self._bytes
