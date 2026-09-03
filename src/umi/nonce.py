"""Bounded persistent ``btauth/1`` replay protection for the miner service."""

from __future__ import annotations

import hashlib
import math
import os
import sqlite3
import stat
import threading
import time
from collections.abc import Iterable
from pathlib import Path

from .encoding import account_id32

_SCHEMA_VERSION = "umi-miner-nonce-store/1"
_DEFAULT_MAXIMUM_NONCES_PER_HOTKEY = 1_024
_DEFAULT_MAXIMUM_TOTAL_NONCES = 16_384
_DEFAULT_MAXIMUM_DATABASE_BYTES = 8 * 1024 * 1024
_MINIMUM_DATABASE_BYTES = 128 * 1024


class NonceStoreError(RuntimeError):
    """The durable replay store cannot safely accept another nonce."""

    def __init__(self, reason_code: str) -> None:
        super().__init__(reason_code)
        self.reason_code = reason_code


class NonceStoreCapacityError(NonceStoreError):
    """The configured row or file ceiling has been reached."""


class NonceStoreAuthorizationError(NonceStoreError):
    """A caller outside the store's bound validator set was presented."""


class SQLiteNonceStore:
    """Atomic, capacity-bounded nonce storage backed by SQLite.

    Production stores are bound to the policy validator AccountId32 set. The
    binding collapses alternate SS58 encodings of the same account and prevents a
    valid but unlisted hotkey from consuming durable replay state. SQLite's main
    database has a hard page ceiling; DELETE journaling avoids an unbounded WAL,
    while the transient rollback journal is checked against the same byte ceiling.
    """

    def __init__(
        self,
        path: str | Path,
        *,
        retention_seconds: float = 60.0,
        allowed_hotkeys: Iterable[str] | None = None,
        maximum_nonces_per_hotkey: int = _DEFAULT_MAXIMUM_NONCES_PER_HOTKEY,
        maximum_total_nonces: int = _DEFAULT_MAXIMUM_TOTAL_NONCES,
        maximum_database_bytes: int = _DEFAULT_MAXIMUM_DATABASE_BYTES,
    ) -> None:
        self.path = Path(path).expanduser().absolute()
        if (
            isinstance(retention_seconds, bool)
            or not isinstance(retention_seconds, (int, float))
            or not math.isfinite(retention_seconds)
            or retention_seconds <= 0
        ):
            raise ValueError("nonce retention must be positive")
        self.retention = float(retention_seconds)
        self.retention_ns = int(self.retention * 1_000_000_000)
        self.maximum_nonces_per_hotkey = _positive_integer(
            maximum_nonces_per_hotkey,
            "maximum_nonces_per_hotkey",
        )
        self.maximum_total_nonces = _positive_integer(
            maximum_total_nonces,
            "maximum_total_nonces",
        )
        self.maximum_database_bytes = _positive_integer(
            maximum_database_bytes,
            "maximum_database_bytes",
        )
        if self.maximum_database_bytes < _MINIMUM_DATABASE_BYTES:
            raise ValueError(f"maximum_database_bytes must be at least {_MINIMUM_DATABASE_BYTES}")
        if self.maximum_total_nonces < self.maximum_nonces_per_hotkey:
            raise ValueError("maximum_total_nonces must be at least maximum_nonces_per_hotkey")

        raw_allowed = None if allowed_hotkeys is None else tuple(allowed_hotkeys)
        if raw_allowed is not None:
            if not raw_allowed:
                raise ValueError("allowed_hotkeys must not be empty")
            accounts = tuple(account_id32(value).hex() for value in raw_allowed)
            if len(set(accounts)) != len(accounts):
                raise ValueError("allowed_hotkeys contains duplicate AccountId32 values")
            self._allowed_accounts: frozenset[str] | None = frozenset(accounts)
            if self.maximum_total_nonces < (
                self.maximum_nonces_per_hotkey * len(self._allowed_accounts)
            ):
                raise ValueError(
                    "maximum_total_nonces must reserve the per-hotkey ceiling for every "
                    "allowed account"
                )
        else:
            # The unbound form exists for reusable component tests. The production
            # miner always supplies its policy registry.
            self._allowed_accounts = None

        self._initialize_lock = threading.Lock()
        self._initialized = False
        self._initialize()

    def _initialize(self) -> None:
        with self._initialize_lock:
            if self._initialized:
                return
            self._prepare_private_path()
            self._validate_database_files(allow_legacy_wal=True)
            try:
                connection = self._connect()
                try:
                    journal_mode = str(
                        connection.execute("PRAGMA journal_mode = DELETE").fetchone()[0]
                    ).lower()
                    if journal_mode != "delete":
                        raise NonceStoreError("nonce_database_journal_mode")
                    connection.execute("PRAGMA synchronous = FULL")
                    page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
                    maximum_pages = self.maximum_database_bytes // page_size
                    if maximum_pages <= 0:
                        raise NonceStoreError("nonce_database_page_ceiling")
                    configured_pages = int(
                        connection.execute(f"PRAGMA max_page_count = {maximum_pages}").fetchone()[0]
                    )
                    if configured_pages > maximum_pages:
                        raise NonceStoreCapacityError("nonce_database_capacity")
                    try:
                        connection.execute("BEGIN IMMEDIATE")
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS accepted_nonces (
                                hotkey_ss58 TEXT NOT NULL,
                                nonce_ns INTEGER NOT NULL,
                                accepted_at_ns INTEGER NOT NULL,
                                PRIMARY KEY (hotkey_ss58, nonce_ns)
                            ) WITHOUT ROWID
                            """
                        )
                        connection.execute(
                            """
                            CREATE TABLE IF NOT EXISTS nonce_store_metadata (
                                key TEXT PRIMARY KEY,
                                value TEXT NOT NULL
                            ) WITHOUT ROWID
                            """
                        )
                        self._bind_metadata(connection)
                        self._audit(connection)
                        connection.commit()
                    except BaseException:
                        connection.rollback()
                        raise
                finally:
                    connection.close()
            except NonceStoreError:
                raise
            except sqlite3.Error as error:
                raise NonceStoreError("nonce_database_failure") from error
            os.chmod(self.path, 0o600, follow_symlinks=False)
            self._validate_database_files(allow_legacy_wal=False)
            self._initialized = True

    def _prepare_private_path(self) -> None:
        parent_existed = self.path.parent.exists()
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if not parent_existed:
            os.chmod(self.path.parent, 0o700)
        parent = self.path.parent.lstat()
        if (
            not stat.S_ISDIR(parent.st_mode)
            or self.path.parent.is_symlink()
            or parent.st_uid != os.geteuid()
            or parent.st_mode & 0o077
        ):
            raise ValueError("nonce database parent must be a private directory owned by this user")
        if os.path.lexists(self.path):
            details = self.path.lstat()
            if (
                not stat.S_ISREG(details.st_mode)
                or self.path.is_symlink()
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
                or details.st_mode & 0o077
            ):
                raise ValueError("nonce database must be a private regular non-symlink file")
            return
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.path, flags, 0o600)
        except OSError as error:
            raise ValueError("nonce database could not be created safely") from error
        else:
            os.close(descriptor)
            _fsync_directory(self.path.parent)

    def _validate_database_files(self, *, allow_legacy_wal: bool) -> None:
        total_bytes = 0
        for suffix in ("", "-journal", "-wal", "-shm"):
            candidate = Path(f"{self.path}{suffix}")
            if not os.path.lexists(candidate):
                continue
            details = candidate.lstat()
            if (
                candidate.is_symlink()
                or not stat.S_ISREG(details.st_mode)
                or details.st_uid != os.geteuid()
                or details.st_nlink != 1
                or details.st_mode & 0o077
            ):
                raise NonceStoreError("nonce_database_path_unsafe")
            if details.st_size > self.maximum_database_bytes:
                raise NonceStoreCapacityError("nonce_database_capacity")
            if suffix in {"-wal", "-shm"} and not allow_legacy_wal and details.st_size > 0:
                raise NonceStoreError("nonce_database_unexpected_wal")
            total_bytes += details.st_size
        # A hot rollback journal can coexist with the bounded main database after
        # process failure. No other auxiliary file is permitted in steady state.
        if total_bytes > 2 * self.maximum_database_bytes:
            raise NonceStoreCapacityError("nonce_database_capacity")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _metadata_values(self) -> dict[str, str]:
        if self._allowed_accounts is None:
            allowlist_digest = "unbound"
        else:
            payload = b"".join(bytes.fromhex(value) for value in sorted(self._allowed_accounts))
            allowlist_digest = hashlib.sha256(
                b"umi-miner-nonce-allowlist-v1\0"
                + len(self._allowed_accounts).to_bytes(4, "big")
                + payload
            ).hexdigest()
        return {
            "schema": _SCHEMA_VERSION,
            "allowlist_digest": allowlist_digest,
            "retention_ns": str(self.retention_ns),
            "maximum_nonces_per_hotkey": str(self.maximum_nonces_per_hotkey),
            "maximum_total_nonces": str(self.maximum_total_nonces),
            "maximum_database_bytes": str(self.maximum_database_bytes),
            "journal_mode": "delete",
        }

    def _bind_metadata(self, connection: sqlite3.Connection) -> None:
        expected = self._metadata_values()
        existing = dict(connection.execute("SELECT key, value FROM nonce_store_metadata"))
        if existing and existing != expected:
            raise NonceStoreError("nonce_database_metadata_mismatch")
        if not existing:
            rows = int(connection.execute("SELECT COUNT(*) FROM accepted_nonces").fetchone()[0])
            if rows and self._allowed_accounts is not None:
                raise NonceStoreError("nonce_database_legacy_state_unbound")
            connection.executemany(
                "INSERT INTO nonce_store_metadata (key, value) VALUES (?, ?)",
                tuple(sorted(expected.items())),
            )

    def _audit(self, connection: sqlite3.Connection) -> None:
        result = str(connection.execute("PRAGMA quick_check").fetchone()[0])
        if result != "ok":
            raise NonceStoreError("nonce_database_corrupt")
        page_size = int(connection.execute("PRAGMA page_size").fetchone()[0])
        page_count = int(connection.execute("PRAGMA page_count").fetchone()[0])
        if page_size * page_count > self.maximum_database_bytes:
            raise NonceStoreCapacityError("nonce_database_capacity")
        total = int(connection.execute("SELECT COUNT(*) FROM accepted_nonces").fetchone()[0])
        if total > self.maximum_total_nonces:
            raise NonceStoreCapacityError("nonce_database_capacity")
        if self._allowed_accounts is not None:
            rows = connection.execute(
                "SELECT hotkey_ss58, COUNT(*) FROM accepted_nonces GROUP BY hotkey_ss58"
            ).fetchall()
            for key, count in rows:
                if key not in self._allowed_accounts:
                    raise NonceStoreAuthorizationError("nonce_database_unlisted_account")
                if int(count) > self.maximum_nonces_per_hotkey:
                    raise NonceStoreCapacityError("nonce_database_capacity")

    def _storage_key(self, hotkey_ss58: str) -> str:
        if not hotkey_ss58:
            raise ValueError("nonce hotkey must not be empty")
        if self._allowed_accounts is None:
            return hotkey_ss58
        try:
            key = account_id32(hotkey_ss58).hex()
        except ValueError as error:
            raise NonceStoreAuthorizationError("nonce_unlisted_account") from error
        if key not in self._allowed_accounts:
            raise NonceStoreAuthorizationError("nonce_unlisted_account")
        return key

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        key = self._storage_key(hotkey_ss58)
        if isinstance(nonce_ns, bool) or not isinstance(nonce_ns, int) or nonce_ns < 0:
            raise ValueError("nonce must be a non-negative integer")
        now_ns = time.time_ns()
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM accepted_nonces WHERE accepted_at_ns < ?",
                (now_ns - self.retention_ns,),
            )
            duplicate = connection.execute(
                "SELECT 1 FROM accepted_nonces WHERE hotkey_ss58 = ? AND nonce_ns = ?",
                (key, nonce_ns),
            ).fetchone()
            if duplicate is not None:
                connection.commit()
                return False
            per_hotkey = int(
                connection.execute(
                    "SELECT COUNT(*) FROM accepted_nonces WHERE hotkey_ss58 = ?",
                    (key,),
                ).fetchone()[0]
            )
            total = int(connection.execute("SELECT COUNT(*) FROM accepted_nonces").fetchone()[0])
            if per_hotkey >= self.maximum_nonces_per_hotkey or total >= self.maximum_total_nonces:
                raise NonceStoreCapacityError("nonce_store_capacity")
            connection.execute(
                "INSERT INTO accepted_nonces VALUES (?, ?, ?)",
                (key, nonce_ns, now_ns),
            )
            connection.commit()
        except NonceStoreError:
            connection.rollback()
            raise
        except sqlite3.DatabaseError as error:
            connection.rollback()
            message = str(error).lower()
            if "full" in message or "too many pages" in message:
                raise NonceStoreCapacityError("nonce_database_capacity") from error
            raise NonceStoreError("nonce_database_failure") from error
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()
        self._validate_database_files(allow_legacy_wal=False)
        return True

    def row_count(self) -> int:
        """Return the bounded row count for health checks and regression tests."""

        connection = self._connect()
        try:
            return int(connection.execute("SELECT COUNT(*) FROM accepted_nonces").fetchone()[0])
        except sqlite3.DatabaseError as error:
            raise NonceStoreError("nonce_database_failure") from error
        finally:
            connection.close()


def _positive_integer(value: int, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{field_name} must be a positive integer")
    return value


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "NonceStoreAuthorizationError",
    "NonceStoreCapacityError",
    "NonceStoreError",
    "SQLiteNonceStore",
]
