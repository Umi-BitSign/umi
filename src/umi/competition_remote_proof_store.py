"""Durable immutable R2 receipts and a bounded disposable in-memory proof cache.

Private receipts attest completed transport only. Independent consumers still
perform native proof verification; their successful verdicts live elsewhere.
"""

from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from contextlib import closing, contextmanager
from pathlib import Path
from threading import RLock
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from .competition_evidence_codec import MAX_EVIDENCE_BYTES, checked_digest
from .competition_round_journal import RoundJournal
from .competition_transport_verification import TransferProgress
from .open_competition import digest
from .private_files import Directory
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .r2_evidence import EvidenceObjectHead, R2EvidenceClient
from .r2_sigv4 import R2SigV4, load_r2_credentials

MAX_PROOF_OBJECT_BYTES = 2 * MAX_EVIDENCE_BYTES + 1024


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

    @model_validator(mode="after")
    def legacy_selection(self):
        if self.legacy_read_through and self.schema_ != "umi-r2-proof-archive/2":
            raise ValueError("retained local proof reads require explicit archive/2 selection")
        return self

    @model_serializer(mode="wrap")
    def original_bytes(self, handler):
        value = handler(self)
        if not self.legacy_read_through:
            value.pop("legacy_read_through", None)
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

    All synchronous callers already run inside owned I/O threads. Serialization
    admits one bounded transfer per store. A pinned cache entry cannot be evicted;
    insufficient space for another lease is a retry, never an unbounded allocation.
    """

    def __init__(self, root: Path, config: ProofArchiveR2Config, *, client=None):
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
        self._cache, self._pins, self._bytes = OrderedDict(), {}, 0
        self._lock = RLock()

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
        with self.journal.read_transaction() as db:
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
        reference = RemoteProofReference.model_validate(value)
        if reference.namespace_sha256 != self.namespace_sha256 or not reference.key.startswith(
            self.config.prefix + "/"
        ):
            raise ValueError("remote proof reference selects another authenticated namespace")
        if self._retained(reference.key) != reference:
            raise ValueError("remote proof replication receipt is missing or damaged")
        if self.journal.get("remote_proof_damage", self._damage_key(reference)) is not None:
            raise ValueError("remote proof requires explicit original-generation repair")
        return reference

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
            with self.journal.read_transaction() as db:
                if self._completion(reference.key, db) != reference:
                    progress.emit("repair_required", reason="original_completion_metadata_required")
                    raise ValueError("remote proof repair requires its original completion ledger")
            try:
                if self.client.head(reference.key) != expected:
                    raise ValueError("remote proof repair requires the original object generation")
                self.client.read(reference.key, expected, maximum=MAX_PROOF_OBJECT_BYTES)
            except ValueError:
                self._hold(reference)
                progress.emit("repair_required", reason="remote_proof_original_not_restored")
                raise
            with self.journal.transaction() as db:
                if self._completion(reference.key, db) != reference:
                    raise ValueError("remote proof completion changed during explicit repair")
                key = self._damage_key(reference)
                # Preserve the original completed transport fact. Only its exact
                # damaged/missing replica and a prior availability hold are repaired.
                db.execute("DELETE FROM records WHERE kind='remote_proof_object' AND id=?", (key,))
                self.journal.insert_completion_record(
                    db, "remote_proof_object", key, canonical_json_bytes(reference)
                )
                db.execute("DELETE FROM records WHERE kind='remote_proof_damage' AND id=?", (key,))
            progress.advance(reference.size_bytes)

    def put_bytes(self, raw: bytes, *, path: str | None = None) -> dict:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_PROOF_OBJECT_BYTES:
            raise ValueError("remote proof object exceeds its original byte bound")
        if self.config.read_only:
            raise ValueError("selected proof archive is read-only")
        sha = hashlib.sha256(raw).hexdigest()
        key = self._key("objects/" + sha if path is None else path)
        with self._lock, TransferProgress("proof_replication", len(raw)) as progress:
            prior = self._retained(key)
            if prior is not None:
                self.validate_reference(prior.model_dump(mode="json", by_alias=True))
                if (prior.content_sha256, prior.size_bytes) != (sha, len(raw)):
                    raise ValueError("immutable proof index conflicts with its original bytes")
                progress.advance(len(raw), restored=True)
                return prior.model_dump(mode="json", by_alias=True)
            head = self.client.publish(key, raw, sha)
            reference = self._reference(key, head)
            self._remember(reference)
            progress.advance(len(raw))
            return reference.model_dump(mode="json", by_alias=True)

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
