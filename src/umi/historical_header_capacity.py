"""Bound hint payload usage without scanning it when SQLite pages suffice."""

from __future__ import annotations


def hint_payload_usage(connection, *, additional_bytes: int, maximum_bytes: int) -> int:
    """Return a conservative usage, exact when needed to decide admission.

    Call under the same write transaction as insertion. SQLite pages bound the
    stored ASCII header text, including committed WAL pages and this transaction's
    changes. Indexes, free pages and unrelated tables can make that bound loose;
    use the original exact sum before refusing a payload that might still fit.
    No new schema, cache receipt or assumption about other writers is needed.
    """
    if not connection.in_transaction:
        raise ValueError("header capacity requires the insertion transaction")
    used = (
        connection.execute("PRAGMA page_count").fetchone()[0]
        * connection.execute("PRAGMA page_size").fetchone()[0]
    )
    if used + additional_bytes > maximum_bytes:
        used = connection.execute(
            "SELECT COALESCE(SUM(length(encoded)),0) FROM historical_header_hints"
        ).fetchone()[0]
    return used
