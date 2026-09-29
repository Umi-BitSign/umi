import sqlite3

import pytest

from umi import sqlite_contention as module


@pytest.mark.parametrize("codes_available", [False, True])
@pytest.mark.parametrize("code", [None, 13, 5, 10, 11])
@pytest.mark.parametrize("message", ["database or disk is full", "disk I/O error", "full"])
def test_only_identified_storage_exhaustion_is_full(monkeypatch, codes_available, code, message):
    monkeypatch.setattr(module, "_ERROR_CODES_AVAILABLE", codes_available)
    error = sqlite3.OperationalError(message)
    if code is not None:
        error.sqlite_errorcode = code
    expected = (
        code == 13
        if code is not None
        else (not codes_available and message == "database or disk is full")
    )
    assert module.is_sqlite_full(error) is expected


@pytest.mark.parametrize("codes_available", [False, True])
@pytest.mark.parametrize("code", [None, 5, 6, 261, 262, 10, 11])
@pytest.mark.parametrize(
    "message",
    [
        "database is locked",
        "database table is locked",
        "database schema is locked",
        "disk I/O error",
        "database disk image is malformed",
        "locked",
        "",
    ],
)
def test_only_identified_contention_is_retryable(monkeypatch, codes_available, code, message):
    monkeypatch.setattr(module, "_ERROR_CODES_AVAILABLE", codes_available)
    error = sqlite3.OperationalError(message)
    if code is not None:
        error.sqlite_errorcode = code
    expected = (
        code in {5, 6, 261, 262}
        if code is not None
        else (
            not codes_available
            and message
            in {
                "database is locked",
                "database table is locked",
                "database schema is locked",
            }
        )
    )
    assert module.is_sqlite_contention(error) is expected
