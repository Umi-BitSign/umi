"""Durable wallet-free replay of competition publication packages.

The worker replays exact signed publication evidence into a private local
journal.  Its receipt records a local historical result.  A separate current
status is recomputed on every invocation because later retained certificates
can place the round on hold.  Neither object proves execution, runtime
identity, finalized timing, or the global absence of conflicts.
"""

from __future__ import annotations

import fcntl
import hashlib
import os
import re
import secrets
import sqlite3
import stat
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_package import (
    CompetitionPackageLimits,
    CompetitionReleaseIdentity,
    VerifiedCompetitionPackage,
    competition_release_identity_digest,
    load_competition_package,
)
from .competition_policy_lineage import replay_lineage
from .competition_publication import (
    PublicationCapacityError,
    PublicationJournal,
    PublicationJournalCapacity,
    SignedCutoffPublication,
    SignedSettlementPublication,
    cutoff_publication_digest,
    settlement_publication_digest,
    signed_cutoff_publication_digest,
    signed_settlement_publication_digest,
)
from .open_competition import StrictProtocolModel
from .protocol import Hex32, canonical_json_bytes

_RECEIPT_DOMAIN = b"umi-competition-replay-worker-receipt-v1\0"
_JOURNAL_STATUS_DOMAIN = b"umi-competition-local-publication-status-v1\0"
_MAX_RECEIPTS = 65_536
_MAX_WORKER_BYTES = 16 * 1024**3
_MAX_PACKAGE_MANIFEST_BYTES = 256 * 1024
_MAX_RECEIPT_BYTES = 64 * 1024
_MAX_PUBLICATION_CERTIFICATES = 4_096
_MAX_PUBLICATION_CERTIFICATE_BYTES = 512 * 1024**2
_MAX_PUBLICATION_BYTES = 2 * 1024**3
_MAX_PATH_BYTES = 4096


class CompetitionWorkerCapacity(StrictProtocolModel):
    """Explicit logical journal ceilings, excluding SQLite/filesystem overhead."""

    maximum_receipts: Annotated[int, Field(ge=1, le=_MAX_RECEIPTS)]
    maximum_bytes: Annotated[int, Field(ge=1, le=_MAX_WORKER_BYTES)]
    publication_journal: PublicationJournalCapacity

    @model_validator(mode="after")
    def bounded_publication_journal(self) -> Self:
        if (
            self.publication_journal.maximum_certificates > _MAX_PUBLICATION_CERTIFICATES
            or self.publication_journal.maximum_bytes > _MAX_PUBLICATION_BYTES
        ):
            raise ValueError("worker publication journal exceeds the fixed profile")
        return self


class CompetitionWorkerReceipt(StrictProtocolModel):
    schema_: Literal["umi-competition-replay-worker-receipt/1"] = Field(alias="schema")
    package_sha256: Hex32
    manifest_sha256: Hex32
    policy_sha256: Hex32
    round_sha256: Hex32
    cutoff_publication_sha256: Hex32
    cutoff_certificate_sha256: Hex32
    settlement_publication_sha256: Hex32
    settlement_certificate_sha256: Hex32
    settlement_sha256: Hex32
    projection_sha256: Hex32
    release_identity_sha256: Hex32
    publication_journal_status_sha256: Hex32
    status: Literal["replayed_no_weight", "held_conflict", "rejected"]
    reason: Literal["publication_capacity_exhausted"] | None
    cutoff_certificate_retained: bool
    settlement_certificate_retained: bool
    wallet_used: Literal[False] = False
    network_used: Literal[False] = False
    execution_proven: Literal[False] = False
    runtime_identity_authenticated: Literal[False] = False
    finalized_receipt_timing_proven: Literal[False] = False
    global_conflict_absence_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def status_matches_retention(self) -> Self:
        if self.status == "rejected":
            if self.reason is None or self.settlement_certificate_retained:
                raise ValueError("rejected receipt has invalid reason or retention state")
        elif (
            self.reason is not None
            or not self.cutoff_certificate_retained
            or not self.settlement_certificate_retained
        ):
            raise ValueError("completed receipt must retain both certificates")
        if self.settlement_certificate_retained and not self.cutoff_certificate_retained:
            raise ValueError("settlement certificate cannot be retained without its cutoff")
        return self


class CompetitionWorkerCurrentStatus(StrictProtocolModel):
    schema_: Literal["umi-competition-replay-worker-current-status/1"] = Field(alias="schema")
    package_sha256: Hex32
    receipt_sha256: Hex32
    policy_sha256: Hex32
    round_sha256: Hex32
    cutoff_publication_sha256: Hex32
    settlement_publication_sha256: Hex32
    publication_journal_status_sha256: Hex32
    held: bool
    halt_reason: Annotated[str, Field(min_length=1, max_length=64)] | None
    publication_conflicts: Annotated[int, Field(ge=0, le=_MAX_PUBLICATION_CERTIFICATES)]
    round_sequence_conflicts: Annotated[int, Field(ge=0, le=_MAX_PUBLICATION_CERTIFICATES)]
    cutoff_certificate_retained: bool
    settlement_certificate_retained: bool
    wallet_used: Literal[False] = False
    network_used: Literal[False] = False
    runtime_identity_authenticated: Literal[False] = False
    finalized_receipt_timing_proven: Literal[False] = False
    global_conflict_absence_proven: Literal[False] = False
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def current_retention_is_fail_closed(self) -> Self:
        if self.settlement_certificate_retained and not self.cutoff_certificate_retained:
            raise ValueError("current settlement retention lacks its cutoff")
        if (not self.cutoff_certificate_retained or not self.settlement_certificate_retained) and (
            not self.held
        ):
            raise ValueError("incomplete current retention must remain held")
        return self


class CompetitionWorkerResult(StrictProtocolModel):
    schema_: Literal["umi-competition-replay-worker-result/1"] = Field(alias="schema")
    receipt: CompetitionWorkerReceipt
    current_status: CompetitionWorkerCurrentStatus
    chain_submission_authorized: Literal[False] = False

    @model_validator(mode="after")
    def bind_current_status(self) -> Self:
        receipt = self.receipt
        current = self.current_status
        if (
            current.receipt_sha256 != competition_worker_receipt_digest(receipt)
            or current.package_sha256 != receipt.package_sha256
            or current.policy_sha256 != receipt.policy_sha256
            or current.round_sha256 != receipt.round_sha256
            or current.cutoff_publication_sha256 != receipt.cutoff_publication_sha256
            or current.settlement_publication_sha256 != receipt.settlement_publication_sha256
        ):
            raise ValueError("worker result current status binding mismatch")
        return self


class CompetitionWorkerCapacityError(ValueError):
    """A new package cannot be reserved without evicting retained history."""


class CompetitionWorkerBusyError(ValueError):
    """Another process currently owns the fixed replay worker."""


def competition_worker_receipt_digest(receipt: CompetitionWorkerReceipt) -> str:
    receipt = CompetitionWorkerReceipt.model_validate_json(
        canonical_json_bytes(receipt), strict=True
    )
    return hashlib.sha256(_RECEIPT_DOMAIN + canonical_json_bytes(receipt)).hexdigest()


class CompetitionReplayWorker:
    """Replay immutable packages into one bounded, private local state tree."""

    def __init__(
        self,
        state_root: Path,
        *,
        package_limits: CompetitionPackageLimits,
        capacity: CompetitionWorkerCapacity,
    ) -> None:
        self.package_limits = CompetitionPackageLimits.model_validate_json(
            canonical_json_bytes(package_limits), strict=True
        )
        self.capacity = CompetitionWorkerCapacity.model_validate_json(
            canonical_json_bytes(capacity), strict=True
        )
        self.state_root = _prepare_private_directory(state_root, "worker state")
        root_fd = _open_directory_without_links(self.state_root)
        try:
            _ensure_private_child(root_fd, "publication")
            self._prepare_state_file(root_fd, "competition-worker.lock")
            self._prepare_state_file(root_fd, "competition-worker.sqlite3")
        finally:
            os.close(root_fd)
        self.publication_root = self.state_root / "publication"
        self.lock_path = self.state_root / "competition-worker.lock"
        self.path = self.state_root / "competition-worker.sqlite3"
        self._last_publication_snapshot = None
        with self._exclusive_lock():
            self._initialize()

    def run(
        self,
        package_path: Path,
        *,
        expected_package_sha256: str,
        expected_policy_sha256: str,
        observed_release: CompetitionReleaseIdentity,
    ) -> CompetitionWorkerResult:
        self._last_publication_snapshot = None
        package = load_competition_package(
            package_path,
            expected_package_sha256=expected_package_sha256,
            expected_policy_sha256=expected_policy_sha256,
            observed_release=observed_release,
            limits=self.package_limits,
        )
        with (
            self._exclusive_lock(),
            replay_lineage(package.policy, package.roster.predecessor_policies),
        ):
            retained = self._reserve(package)
            journal = self._publication_journal(package)
            cutoff_retained = False
            settlement_retained = False
            rejection: Literal["publication_capacity_exhausted"] | None = None
            try:
                journal.record_cutoff(
                    package.cutoff_certificate,
                    submissions=package.roster.submissions,
                    limits=package.replay_limits,
                )
                cutoff_retained = True
                journal.record_settlement(
                    package.settlement_certificate,
                    cutoff_certificate=package.cutoff_certificate,
                    submissions=package.roster.submissions,
                    evidence=tuple(
                        (item.submission, item.evidence) for item in package.evidence.entries
                    ),
                    retained_settlement=package.retained_settlement,
                    limits=package.replay_limits,
                )
                settlement_retained = True
            except PublicationCapacityError:
                rejection = "publication_capacity_exhausted"

            publication_path = (
                self.publication_root
                / package.manifest.policy_sha256
                / "competition-publication.sqlite3"
            )
            publication_before = _publication_fingerprint(publication_path)
            self._audit_publication_state(package.manifest.policy_sha256)
            journal_status = journal.round_status(package.manifest.round_sha256)
            if retained is None:
                receipt = self._new_receipt(
                    package,
                    journal_status,
                    cutoff_retained=cutoff_retained,
                    settlement_retained=settlement_retained,
                    rejection=rejection,
                )
                self._finalize(package, receipt)
            else:
                receipt = retained
                if (
                    receipt.cutoff_certificate_retained != cutoff_retained
                    or receipt.settlement_certificate_retained != settlement_retained
                    or (receipt.status == "rejected") != (rejection is not None)
                ):
                    raise ValueError("historical worker receipt retention state changed")
            current = _current_status(
                package,
                receipt,
                journal_status,
                cutoff_retained=cutoff_retained,
                settlement_retained=settlement_retained,
            )
            result = CompetitionWorkerResult(
                schema="umi-competition-replay-worker-result/1",
                receipt=receipt,
                current_status=current,
            )
            publication_after = _publication_fingerprint(publication_path)
            self._last_publication_snapshot = (
                (result, publication_path, publication_after)
                if publication_before == publication_after
                else None
            )
            return result

    def verify_publication_unchanged(self, result: CompetitionWorkerResult) -> None:
        """Check a process-local audited journal snapshot, without package replay."""
        retained = self._last_publication_snapshot
        if (
            retained is None
            or retained[0] is not result
            or _publication_fingerprint(retained[1]) != retained[2]
        ):
            raise ValueError("publication journal changed after verified replay")

    @staticmethod
    def _prepare_state_file(root_fd: int, name: str) -> None:
        descriptor = os.open(
            name,
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            0o600,
            dir_fd=root_fd,
        )
        try:
            info = os.fstat(descriptor)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o600
            ):
                raise ValueError("worker state file must be an owned mode-0600 regular file")
        finally:
            os.close(descriptor)

    @contextmanager
    def _connection(self):
        _verify_sqlite_family(self.path, "worker database")
        connection = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        try:
            connection.execute("PRAGMA journal_mode=DELETE")
            connection.execute("PRAGMA synchronous=FULL")
            connection.execute("PRAGMA foreign_keys=ON")
            yield connection
        finally:
            connection.close()

    @contextmanager
    def _transaction(self):
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
                connection.commit()
            except BaseException:
                connection.rollback()
                raise

    @contextmanager
    def _exclusive_lock(self):
        descriptor = _open_private_regular_file(self.lock_path, "worker lock")
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise CompetitionWorkerBusyError("competition replay worker is busy") from error
            yield
        finally:
            with suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _initialize(self) -> None:
        with self._transaction() as connection:
            statements = (
                """CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                )""",
                """CREATE TABLE IF NOT EXISTS publication_bindings (
                    policy TEXT PRIMARY KEY,
                    generation TEXT NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('initializing', 'ready'))
                )""",
                """CREATE TABLE IF NOT EXISTS runs (
                    package TEXT PRIMARY KEY,
                    policy TEXT NOT NULL,
                    round TEXT NOT NULL,
                    manifest_sha256 TEXT NOT NULL,
                    manifest BLOB NOT NULL,
                    cutoff_certificate TEXT NOT NULL,
                    settlement_certificate TEXT NOT NULL,
                    reserved INTEGER NOT NULL CHECK(reserved>0),
                    status TEXT NOT NULL CHECK(status IN ('running', 'complete', 'rejected')),
                    cutoff_retained INTEGER,
                    settlement_retained INTEGER,
                    receipt_sha256 TEXT,
                    receipt BLOB
                )""",
                """CREATE TABLE IF NOT EXISTS known_publication_certificates (
                    policy TEXT NOT NULL,
                    digest TEXT NOT NULL,
                    kind TEXT NOT NULL,
                    round TEXT NOT NULL,
                    round_sequence INTEGER NOT NULL,
                    publication TEXT NOT NULL,
                    PRIMARY KEY(policy, digest)
                )""",
                """CREATE TABLE IF NOT EXISTS worker_usage (
                    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                    records INTEGER NOT NULL CHECK(records>=0),
                    reserved_bytes INTEGER NOT NULL CHECK(reserved_bytes>=0)
                )""",
            )
            for statement in statements:
                connection.execute(statement)
            schema = connection.execute("SELECT value FROM metadata WHERE key='schema'").fetchone()
            if schema is None:
                connection.execute(
                    "INSERT INTO metadata VALUES ('schema', 'umi-competition-replay-worker/1')"
                )
            elif schema[0] != "umi-competition-replay-worker/1":
                raise ValueError("worker database has another schema")
            bad_reservation = connection.execute(
                "SELECT 1 FROM runs WHERE "
                "length(CAST(manifest AS BLOB)) NOT BETWEEN 1 AND ? "
                "OR reserved<>length(CAST(manifest AS BLOB))+? "
                "OR (receipt IS NOT NULL AND "
                "length(CAST(receipt AS BLOB)) NOT BETWEEN 1 AND ?) LIMIT 1",
                (_MAX_PACKAGE_MANIFEST_BYTES, _MAX_RECEIPT_BYTES, _MAX_RECEIPT_BYTES),
            ).fetchone()
            if bad_reservation is not None:
                raise ValueError("worker database has a corrupt byte reservation")
            usage = connection.execute(
                "SELECT COUNT(*), COALESCE(SUM(reserved), 0) FROM runs"
            ).fetchone()
            connection.execute(
                "INSERT INTO worker_usage VALUES (1, ?, ?) "
                "ON CONFLICT(singleton) DO UPDATE SET records=excluded.records, "
                "reserved_bytes=excluded.reserved_bytes",
                usage,
            )
            if usage[0] > self.capacity.maximum_receipts or usage[1] > self.capacity.maximum_bytes:
                connection.execute(
                    "INSERT OR REPLACE INTO metadata VALUES ('worker_halted', 'capacity_exhausted')"
                )
            if connection.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("worker database integrity check failed")

    def _reserve(self, package: VerifiedCompetitionPackage) -> CompetitionWorkerReceipt | None:
        manifest_body = canonical_json_bytes(package.manifest)
        reserve = len(manifest_body) + _MAX_RECEIPT_BYTES
        manifest = package.manifest
        exhausted = False
        with self._transaction() as connection:
            metadata = connection.execute(
                "SELECT policy, round, manifest_sha256, cutoff_certificate, "
                "settlement_certificate, status, cutoff_retained, settlement_retained, "
                "receipt_sha256, length(CAST(manifest AS BLOB)), "
                "CASE WHEN receipt IS NULL THEN NULL ELSE length(CAST(receipt AS BLOB)) END "
                "FROM runs WHERE package=?",
                (package.package_sha256,),
            ).fetchone()
            expected_metadata = (
                manifest.policy_sha256,
                manifest.round_sha256,
                package.manifest_sha256,
                manifest.cutoff_certificate_sha256,
                manifest.settlement_certificate_sha256,
            )
            if metadata is not None:
                if metadata[:5] != expected_metadata:
                    raise ValueError("stored package identity is corrupt")
                manifest_size, receipt_size = metadata[9:]
                if manifest_size != len(manifest_body):
                    raise ValueError("stored package manifest size is corrupt")
                if receipt_size is not None and not 1 <= receipt_size <= _MAX_RECEIPT_BYTES:
                    raise ValueError("stored worker receipt size is corrupt")
                blobs = connection.execute(
                    "SELECT manifest, receipt FROM runs WHERE package=?",
                    (package.package_sha256,),
                ).fetchone()
                if blobs is None or bytes(blobs[0]) != manifest_body:
                    raise ValueError("stored package manifest is corrupt")
                status = metadata[5]
                if status == "running":
                    if any(value is not None for value in (*metadata[6:9], receipt_size, blobs[1])):
                        raise ValueError("running package has a stored receipt")
                    return None
                row = (
                    *metadata[:3],
                    bytes(blobs[0]),
                    *metadata[3:9],
                    blobs[1],
                )
                return _parse_stored_receipt(package, row)

            halted = connection.execute(
                "SELECT value FROM metadata WHERE key='worker_halted'"
            ).fetchone()
            usage = connection.execute(
                "SELECT records, reserved_bytes FROM worker_usage WHERE singleton=1"
            ).fetchone()
            if usage is None:
                raise ValueError("worker usage ledger is unavailable")
            next_records = usage[0] + 1
            next_bytes = usage[1] + reserve
            if (
                halted is not None
                or next_records > self.capacity.maximum_receipts
                or next_bytes > self.capacity.maximum_bytes
            ):
                connection.execute(
                    "INSERT OR REPLACE INTO metadata VALUES ('worker_halted', 'capacity_exhausted')"
                )
                exhausted = True
            else:
                connection.execute(
                    "INSERT INTO runs VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'running', "
                    "NULL, NULL, NULL, NULL)",
                    (
                        package.package_sha256,
                        *expected_metadata[:3],
                        manifest_body,
                        *expected_metadata[3:],
                        reserve,
                    ),
                )
                connection.execute(
                    "UPDATE worker_usage SET records=?, reserved_bytes=? WHERE singleton=1",
                    (next_records, next_bytes),
                )
        if exhausted:
            raise CompetitionWorkerCapacityError("competition replay worker capacity is exhausted")
        return None

    def _publication_journal(self, package: VerifiedCompetitionPackage) -> PublicationJournal:
        policy_sha256 = package.manifest.policy_sha256
        policy_directory = self.publication_root / policy_sha256
        database = policy_directory / "competition-publication.sqlite3"
        with self._transaction() as connection:
            binding = connection.execute(
                "SELECT generation, status FROM publication_bindings WHERE policy=?",
                (policy_sha256,),
            ).fetchone()
            directory_exists = _entry_exists(self.publication_root, policy_sha256)
            if binding is None:
                if directory_exists:
                    raise ValueError("unbound publication state already exists")
                generation = secrets.token_hex(32)
                connection.execute(
                    "INSERT INTO publication_bindings VALUES (?, ?, 'initializing')",
                    (policy_sha256, generation),
                )
                binding_status = "initializing"
            else:
                generation, binding_status = binding
                if re.fullmatch(r"[0-9a-f]{64}", generation) is None:
                    raise ValueError("publication state generation is corrupt")
                if binding_status == "ready" and (
                    not directory_exists or not _entry_exists(policy_directory, database.name)
                ):
                    raise ValueError("bound publication state is missing")

        if not directory_exists:
            root_fd = _open_directory_without_links(self.publication_root)
            try:
                _ensure_private_child(root_fd, policy_sha256)
            finally:
                os.close(root_fd)
        _verify_private_directory(policy_directory, "publication state")
        policy_fd = _open_directory_without_links(policy_directory)
        try:
            self._prepare_state_file(policy_fd, database.name)
        finally:
            os.close(policy_fd)
        # PublicationJournal opens its SQLite path during construction. Pin a
        # private regular file first and reject unsafe SQLite sidecars before
        # that constructor can touch either one.
        _verify_sqlite_family(database, "publication database")
        journal = PublicationJournal(
            policy_directory,
            package.policy,
            capacity=self.capacity.publication_journal,
        )
        _verify_sqlite_family(database, "publication database")
        with _sqlite_transaction(database) as publication:
            retained = publication.execute(
                "SELECT value FROM metadata WHERE key='replay_worker_generation'"
            ).fetchone()
            if retained is None:
                if binding_status != "initializing":
                    raise ValueError("publication state generation is missing")
                publication.execute(
                    "INSERT INTO metadata VALUES ('replay_worker_generation', ?)",
                    (generation,),
                )
            elif retained[0] != generation:
                raise ValueError("publication state generation mismatch")
            if publication.execute("PRAGMA quick_check").fetchone()[0] != "ok":
                raise ValueError("publication database integrity check failed")
        with self._transaction() as connection:
            changed = connection.execute(
                "UPDATE publication_bindings SET status='ready' "
                "WHERE policy=? AND generation=? AND status='initializing'",
                (policy_sha256, generation),
            ).rowcount
            if changed not in {0, 1}:
                raise ValueError("publication state binding update failed")
            ready = connection.execute(
                "SELECT generation, status FROM publication_bindings WHERE policy=?",
                (policy_sha256,),
            ).fetchone()
            if ready != (generation, "ready"):
                raise ValueError("publication state binding is not ready")
        self._audit_publication_state(policy_sha256)
        return journal

    def _audit_publication_state(self, policy_sha256: str) -> None:
        database = self.publication_root / policy_sha256 / "competition-publication.sqlite3"
        _verify_sqlite_family(database, "publication database")
        certificates: dict[str, tuple[str, str, int, str]] = {}
        publications: dict[tuple[str, str], set[str]] = {}
        rounds: dict[int, set[str]] = {}
        with _sqlite_connection(database) as publication:
            measured = publication.execute(
                "SELECT COUNT(*), COALESCE(SUM(length(CAST(body AS BLOB))), 0) FROM certificates"
            ).fetchone()
            if (
                measured[0] > self.capacity.publication_journal.maximum_certificates
                or measured[1] > self.capacity.publication_journal.maximum_bytes
            ):
                raise ValueError("publication database exceeds its retained capacity")
            for (body_size,) in publication.execute(
                "SELECT length(CAST(body AS BLOB)) FROM certificates"
            ):
                if not 1 <= body_size <= _MAX_PUBLICATION_CERTIFICATE_BYTES:
                    raise ValueError("publication certificate has an invalid stored size")
            certificate_rows = publication.execute(
                "SELECT digest, kind, round, round_sequence, publication, body "
                "FROM certificates ORDER BY digest"
            )
            for certificate_id, kind, round_id, sequence, publication_id, body in certificate_rows:
                raw = bytes(body)
                if kind == "cutoff":
                    parsed = SignedCutoffPublication.model_validate_json(raw, strict=True)
                    actual_certificate = signed_cutoff_publication_digest(parsed)
                    actual_publication = cutoff_publication_digest(parsed.publication)
                elif kind == "settlement":
                    parsed = SignedSettlementPublication.model_validate_json(raw, strict=True)
                    actual_certificate = signed_settlement_publication_digest(parsed)
                    actual_publication = settlement_publication_digest(parsed.publication)
                else:
                    raise ValueError("publication database has an invalid certificate kind")
                if (
                    canonical_json_bytes(parsed) != raw
                    or certificate_id != actual_certificate
                    or publication_id != actual_publication
                    or round_id != parsed.publication.round_sha256
                    or sequence != parsed.publication.round.sequence
                    or parsed.publication.policy_sha256 != policy_sha256
                    or certificate_id in certificates
                ):
                    raise ValueError("publication database certificate is corrupt")
                certificates[certificate_id] = (kind, round_id, sequence, publication_id)
                publications.setdefault((kind, round_id), set()).add(publication_id)
                rounds.setdefault(sequence, set()).add(round_id)

            heads = {
                (kind, round_id): publication_id
                for kind, round_id, publication_id in publication.execute(
                    "SELECT kind, round, publication FROM publication_heads"
                )
            }
            if set(heads) != set(publications) or any(
                head not in publications[key] for key, head in heads.items()
            ):
                raise ValueError("publication heads do not match retained certificates")
            expected_conflicts = {
                (kind, round_id, heads[(kind, round_id)], other)
                for (kind, round_id), values in publications.items()
                for other in values
                if other != heads[(kind, round_id)]
            }
            actual_conflicts = set(
                publication.execute(
                    "SELECT kind, round, first_publication, other_publication "
                    "FROM publication_conflicts"
                )
            )
            if actual_conflicts != expected_conflicts:
                raise ValueError("publication conflicts do not match retained certificates")

            round_heads = dict(
                publication.execute("SELECT round_sequence, round FROM round_bindings")
            )
            if set(round_heads) != set(rounds) or any(
                head not in rounds[sequence] for sequence, head in round_heads.items()
            ):
                raise ValueError("round bindings do not match retained certificates")
            expected_round_conflicts = {
                (sequence, round_heads[sequence], other)
                for sequence, values in rounds.items()
                for other in values
                if other != round_heads[sequence]
            }
            actual_round_conflicts = set(
                publication.execute(
                    "SELECT round_sequence, first_round, other_round FROM round_sequence_conflicts"
                )
            )
            if actual_round_conflicts != expected_round_conflicts:
                raise ValueError("round conflicts do not match retained certificates")
            usage = publication.execute(
                "SELECT records, payload_bytes FROM publication_usage WHERE singleton=1"
            ).fetchone()
            if usage != measured:
                raise ValueError("publication usage ledger is corrupt")

        with self._transaction() as connection:
            known = {
                row[0]: row[1:]
                for row in connection.execute(
                    "SELECT digest, kind, round, round_sequence, publication "
                    "FROM known_publication_certificates WHERE policy=?",
                    (policy_sha256,),
                )
            }
            if any(
                certificates.get(certificate_id) != value for certificate_id, value in known.items()
            ):
                raise ValueError("publication state lost a previously retained certificate")
            for certificate_id, value in certificates.items():
                connection.execute(
                    "INSERT OR IGNORE INTO known_publication_certificates "
                    "VALUES (?, ?, ?, ?, ?, ?)",
                    (policy_sha256, certificate_id, *value),
                )

    def _new_receipt(
        self,
        package: VerifiedCompetitionPackage,
        journal_status: dict,
        *,
        cutoff_retained: bool,
        settlement_retained: bool,
        rejection: Literal["publication_capacity_exhausted"] | None,
    ) -> CompetitionWorkerReceipt:
        _validate_journal_status(package, journal_status)
        if rejection is not None:
            status: Literal["replayed_no_weight", "held_conflict", "rejected"] = "rejected"
        elif journal_status["held"]:
            status = "held_conflict"
        else:
            status = "replayed_no_weight"
        manifest = package.manifest
        return CompetitionWorkerReceipt(
            schema="umi-competition-replay-worker-receipt/1",
            package_sha256=package.package_sha256,
            manifest_sha256=package.manifest_sha256,
            policy_sha256=manifest.policy_sha256,
            round_sha256=manifest.round_sha256,
            cutoff_publication_sha256=manifest.cutoff_publication_sha256,
            cutoff_certificate_sha256=manifest.cutoff_certificate_sha256,
            settlement_publication_sha256=manifest.settlement_publication_sha256,
            settlement_certificate_sha256=manifest.settlement_certificate_sha256,
            settlement_sha256=manifest.settlement_sha256,
            projection_sha256=manifest.projection_sha256,
            release_identity_sha256=competition_release_identity_digest(package.release_identity),
            publication_journal_status_sha256=_journal_status_digest(journal_status),
            status=status,
            reason=rejection,
            cutoff_certificate_retained=cutoff_retained,
            settlement_certificate_retained=settlement_retained,
        )

    def _finalize(
        self,
        package: VerifiedCompetitionPackage,
        receipt: CompetitionWorkerReceipt,
    ) -> None:
        body = canonical_json_bytes(receipt)
        if len(body) > _MAX_RECEIPT_BYTES:
            raise ValueError("worker receipt exceeds its reserved byte limit")
        status = "rejected" if receipt.status == "rejected" else "complete"
        with self._transaction() as connection:
            row = connection.execute(
                "SELECT manifest, status, receipt FROM runs WHERE package=?",
                (package.package_sha256,),
            ).fetchone()
            if row != (canonical_json_bytes(package.manifest), "running", None):
                raise ValueError("worker package reservation changed before completion")
            changed = connection.execute(
                "UPDATE runs SET status=?, cutoff_retained=?, settlement_retained=?, "
                "receipt_sha256=?, receipt=? WHERE package=? AND status='running'",
                (
                    status,
                    int(receipt.cutoff_certificate_retained),
                    int(receipt.settlement_certificate_retained),
                    competition_worker_receipt_digest(receipt),
                    body,
                    package.package_sha256,
                ),
            ).rowcount
            if changed != 1:
                raise ValueError("worker package could not be completed atomically")


def _parse_stored_receipt(
    package: VerifiedCompetitionPackage,
    row: tuple,
) -> CompetitionWorkerReceipt:
    status, cutoff_retained, settlement_retained, receipt_sha256, raw = row[6:]
    if (
        cutoff_retained not in {0, 1}
        or settlement_retained not in {0, 1}
        or not isinstance(receipt_sha256, str)
        or raw is None
    ):
        raise ValueError("stored worker receipt is incomplete")
    body = bytes(raw)
    if not 1 <= len(body) <= _MAX_RECEIPT_BYTES:
        raise ValueError("stored worker receipt size is corrupt")
    receipt = CompetitionWorkerReceipt.model_validate_json(body, strict=True)
    manifest = package.manifest
    if (
        canonical_json_bytes(receipt) != body
        or competition_worker_receipt_digest(receipt) != receipt_sha256
        or receipt.package_sha256 != package.package_sha256
        or receipt.manifest_sha256 != package.manifest_sha256
        or receipt.policy_sha256 != manifest.policy_sha256
        or receipt.round_sha256 != manifest.round_sha256
        or receipt.cutoff_publication_sha256 != manifest.cutoff_publication_sha256
        or receipt.cutoff_certificate_sha256 != manifest.cutoff_certificate_sha256
        or receipt.settlement_publication_sha256 != manifest.settlement_publication_sha256
        or receipt.settlement_certificate_sha256 != manifest.settlement_certificate_sha256
        or receipt.settlement_sha256 != manifest.settlement_sha256
        or receipt.projection_sha256 != manifest.projection_sha256
        or receipt.release_identity_sha256 != manifest.release_identity_sha256
        or receipt.cutoff_certificate_retained != bool(cutoff_retained)
        or receipt.settlement_certificate_retained != bool(settlement_retained)
        or (status == "rejected") != (receipt.status == "rejected")
    ):
        raise ValueError("stored worker receipt is corrupt")
    return receipt


def _publication_fingerprint(path: Path) -> tuple[int, ...]:
    _verify_sqlite_family(path, "publication snapshot")
    # Production journals use DELETE mode. An in-progress rollback journal or
    # WAL must not be accepted as stable state while a chain proof is captured.
    parent = _open_directory_without_links(path.parent)
    try:
        for suffix in ("-journal", "-wal", "-shm"):
            try:
                os.stat(path.name + suffix, dir_fd=parent, follow_symlinks=False)
            except FileNotFoundError:
                continue
            raise ValueError("publication journal has an in-progress SQLite sidecar")
    finally:
        os.close(parent)
    descriptor = _open_private_regular_file(path, "publication snapshot")
    try:
        info = os.fstat(descriptor)
        return (
            info.st_dev,
            info.st_ino,
            info.st_mode,
            info.st_uid,
            info.st_gid,
            info.st_nlink,
            info.st_size,
            info.st_mtime_ns,
            info.st_ctime_ns,
        )
    finally:
        os.close(descriptor)


def _current_status(
    package: VerifiedCompetitionPackage,
    receipt: CompetitionWorkerReceipt,
    journal_status: dict,
    *,
    cutoff_retained: bool,
    settlement_retained: bool,
) -> CompetitionWorkerCurrentStatus:
    _validate_journal_status(package, journal_status)
    return CompetitionWorkerCurrentStatus(
        schema="umi-competition-replay-worker-current-status/1",
        package_sha256=package.package_sha256,
        receipt_sha256=competition_worker_receipt_digest(receipt),
        policy_sha256=package.manifest.policy_sha256,
        round_sha256=package.manifest.round_sha256,
        cutoff_publication_sha256=package.manifest.cutoff_publication_sha256,
        settlement_publication_sha256=package.manifest.settlement_publication_sha256,
        publication_journal_status_sha256=_journal_status_digest(journal_status),
        held=journal_status["held"],
        halt_reason=journal_status["halt_reason"],
        publication_conflicts=len(journal_status["conflicts"]),
        round_sequence_conflicts=len(journal_status["round_sequence_conflicts"]),
        cutoff_certificate_retained=cutoff_retained,
        settlement_certificate_retained=settlement_retained,
    )


def _validate_journal_status(
    package: VerifiedCompetitionPackage,
    journal_status: dict,
) -> None:
    if (
        journal_status.get("schema") != "umi-competition-publication-journal-status/1"
        or journal_status.get("policy_sha256") != package.manifest.policy_sha256
        or journal_status.get("round_sha256") != package.manifest.round_sha256
        or not isinstance(journal_status.get("held"), bool)
        or journal_status.get("finalized_receipt_timing_proven") is not False
        or journal_status.get("global_conflict_absence_proven") is not False
        or journal_status.get("chain_submission_authorized") is not False
    ):
        raise ValueError("publication journal returned an invalid current status")


def _journal_status_digest(status: dict) -> str:
    return hashlib.sha256(_JOURNAL_STATUS_DOMAIN + canonical_json_bytes(status)).hexdigest()


def _prepare_private_directory(path: Path, label: str) -> Path:
    path = _canonical_absolute_path(path, label)
    parent_fd = _open_directory_without_links(path.parent)
    try:
        with suppress(FileExistsError):
            os.mkdir(path.name, 0o700, dir_fd=parent_fd)
    finally:
        os.close(parent_fd)
    _verify_private_directory(path, label)
    return path


def _ensure_private_child(root_fd: int, name: str) -> None:
    with suppress(FileExistsError):
        os.mkdir(name, 0o700, dir_fd=root_fd)
    descriptor = os.open(
        name,
        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK,
        dir_fd=root_fd,
    )
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError("worker child directory must be owned and mode 0700")
    finally:
        os.close(descriptor)


def _entry_exists(parent: Path, name: str) -> bool:
    descriptor = _open_directory_without_links(parent)
    try:
        try:
            os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return False
        return True
    finally:
        os.close(descriptor)


def _canonical_absolute_path(path: Path, label: str) -> Path:
    path = Path(path)
    if (
        not path.is_absolute()
        or path == Path(path.anchor)
        or path != Path(os.path.abspath(path))
        or len(os.fsencode(path)) > _MAX_PATH_BYTES
    ):
        raise ValueError(f"{label} must be a dedicated canonical absolute path")
    return path


def _open_directory_without_links(path: Path) -> int:
    path = Path(path)
    if path != Path(path.anchor):
        path = _canonical_absolute_path(path, "directory")
    elif not path.is_absolute():
        raise ValueError("directory path must be absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = os.open(path.anchor, flags)
    try:
        for component in path.parts[1:]:
            child = os.open(component, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _verify_private_directory(path: Path, label: str) -> None:
    descriptor = _open_directory_without_links(path)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise ValueError(f"{label} must be owned by this user and mode 0700")
    finally:
        os.close(descriptor)


def _open_private_regular_file(path: Path, label: str) -> int:
    path = _canonical_absolute_path(path, label)
    parent = _open_directory_without_links(path.parent)
    try:
        descriptor = os.open(
            path.name,
            os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent,
        )
    finally:
        os.close(parent)
    info = os.fstat(descriptor)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_nlink != 1
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o600
    ):
        os.close(descriptor)
        raise ValueError(f"{label} must be an owned mode-0600 regular file")
    return descriptor


def _verify_private_regular_file(path: Path, label: str) -> None:
    descriptor = _open_private_regular_file(path, label)
    os.close(descriptor)


def _verify_sqlite_family(path: Path, label: str) -> None:
    _verify_private_regular_file(path, label)
    for suffix in ("-journal", "-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        if sidecar.exists() or sidecar.is_symlink():
            _verify_private_regular_file(sidecar, f"{label} sidecar")


@contextmanager
def _sqlite_connection(path: Path):
    _verify_sqlite_family(path, "publication database")
    connection = sqlite3.connect(path, timeout=10, isolation_level=None)
    try:
        connection.execute("PRAGMA synchronous=FULL")
        yield connection
    finally:
        connection.close()


@contextmanager
def _sqlite_transaction(path: Path):
    with _sqlite_connection(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise


__all__ = [
    "CompetitionReplayWorker",
    "CompetitionWorkerBusyError",
    "CompetitionWorkerCapacity",
    "CompetitionWorkerCapacityError",
    "CompetitionWorkerCurrentStatus",
    "CompetitionWorkerReceipt",
    "CompetitionWorkerResult",
    "competition_worker_receipt_digest",
]
