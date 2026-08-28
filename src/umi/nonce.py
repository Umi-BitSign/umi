"""Persistent btauth replay protection for multi-process miner deployments."""

from __future__ import annotations

import os
import sqlite3
import stat
import threading
import time
from pathlib import Path


class SQLiteNonceStore:
    """Atomic same-host nonce storage backed by a WAL-mode SQLite database."""

    def __init__(self, path: str | Path, *, retention_seconds: float = 60.0) -> None:
        self.path = Path(path).expanduser().absolute()
        if retention_seconds <= 0:
            raise ValueError("nonce retention must be positive")
        self.retention = float(retention_seconds)
        self.retention_ns = int(self.retention * 1_000_000_000)
        self._initialize_lock = threading.Lock()
        self._initialized = False
        self._initialize()

    def _initialize(self) -> None:
        with self._initialize_lock:
            if self._initialized:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            if self.path.parent.is_symlink() or not self.path.parent.is_dir():
                raise ValueError("nonce database parent must be a real directory")
            if self.path.exists():
                metadata = self.path.lstat()
                if not stat.S_ISREG(metadata.st_mode) or self.path.is_symlink():
                    raise ValueError("nonce database must be a regular non-symlink file")
            connection = self._connect()
            try:
                connection.execute("PRAGMA journal_mode=WAL")
                connection.execute("PRAGMA synchronous=FULL")
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
                connection.commit()
            finally:
                connection.close()
            os.chmod(self.path, 0o600)
            self._initialized = True

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    def check_and_store(self, hotkey_ss58: str, nonce_ns: int) -> bool:
        if not hotkey_ss58:
            raise ValueError("nonce hotkey must not be empty")
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
            cursor = connection.execute(
                "INSERT OR IGNORE INTO accepted_nonces VALUES (?, ?, ?)",
                (hotkey_ss58, nonce_ns, now_ns),
            )
            connection.commit()
            return cursor.rowcount == 1
        except Exception:
            connection.rollback()
            raise
        finally:
            connection.close()


__all__ = ["SQLiteNonceStore"]
