"""Identify SQLite contention and storage exhaustion across Python versions."""

import sqlite3
import sys

_ERROR_CODES_AVAILABLE = sys.version_info >= (3, 11)


def is_sqlite_full(error: sqlite3.Error) -> bool:
    code = getattr(error, "sqlite_errorcode", None)
    if code is not None:
        return code & 0xFF == 13  # SQLITE_FULL
    return not _ERROR_CODES_AVAILABLE and str(error) == "database or disk is full"


def is_sqlite_contention(error: sqlite3.OperationalError) -> bool:
    code = getattr(error, "sqlite_errorcode", None)
    if code is not None:
        return code & 0xFF in {5, 6}  # SQLITE_BUSY / SQLITE_LOCKED, including extended codes.
    # CPython 3.10 exposes only SQLite's message. Restrict that fallback to the
    # exact standard messages; permission, I/O and corruption errors must raise.
    return not _ERROR_CODES_AVAILABLE and str(error) in {
        "database is locked",
        "database table is locked",
        "database schema is locked",
    }
