"""Append-only local receipts for reviewed, unrewarded runtime ports."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from .competition_artifacts import verify_preserved_bundle
from .competition_runtime_port import (
    RuntimePortReceipt,
    SignedRuntimePortReview,
    baseline_record_digest,
    runtime_port_record,
    verify_runtime_port,
)
from .open_competition import EvaluationRound, digest, model_content_digest
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_store import CompetitionStore

_MARKER = "runtime_port_writer"
_PREFIX = "runtime_port_receipt:"
_MAX_BYTES = 4 * 1024**2


def _fences(tables):
    for table in tables:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"runtime_port_{table}_{operation.lower()}"
            yield (
                name,
                (
                    f"CREATE TRIGGER {name} BEFORE {operation} ON {table} BEGIN "
                    "SELECT CASE WHEN umi_runtime_port_writer() IS NOT 1 "
                    "THEN RAISE(ABORT,'runtime port writer mismatch') END; END"
                ),
            )


def verify_runtime_port_fence(connection: sqlite3.Connection, tables) -> None:
    objects = dict(connection.execute("SELECT name,sql FROM sqlite_master"))
    if "metadata" not in objects:
        return
    marker = connection.execute("SELECT value FROM metadata WHERE key=?", (_MARKER,)).fetchone()
    names = {name for name in objects if name.startswith("runtime_port_")}
    if marker is None:
        if (
            names
            or connection.execute(
                "SELECT 1 FROM metadata WHERE key GLOB 'runtime_port_receipt:*' LIMIT 1"
            ).fetchone()
        ):
            raise ValueError("runtime port writer fence is missing")
        return
    expected = dict(_fences(tables))
    if (
        marker != ("1",)
        or names != set(expected)
        or any(objects[n] != sql for n, sql in expected.items())
    ):
        raise ValueError("runtime port writer fence changed")


def _read_parent(connection, review):
    row = connection.execute(
        "SELECT digest,model,contributor,body FROM promotions WHERE sequence=?",
        (review.sequence - 1,),
    ).fetchone()
    if row is None:
        raise ValueError("runtime port parent is missing")
    parent = json.loads(row[3])
    if (
        row[0] != review.previous_promotion_sha256
        or baseline_record_digest(parent) != row[0]
        or canonical_json_bytes(parent) != row[3]
        or row[1] != digest(review.original)
        or parent.get("model_sha256") != row[1]
        or parent.get("sequence") != review.sequence - 1
        or row[2] is not None
        or parent.get("contributor_hotkey") is not None
        or parent.get("kind") not in {"initial_reference_no_reward", "runtime_port_no_reward"}
    ):
        raise ValueError("runtime port requires its exact unrewarded parent baseline")


def read_runtime_port_receipt(store: CompetitionStore, connection, record, maximum_bytes=None):
    limit = min(_MAX_BYTES, maximum_bytes or _MAX_BYTES)
    key = _PREFIX + str(record["sequence"])
    size = connection.execute(
        "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key=?", (key,)
    ).fetchone()
    if size is None or not 0 < size[0] <= limit:
        raise ValueError("runtime port receipt missing or oversized")
    raw = (
        connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0].encode()
    )
    receipt = RuntimePortReceipt.model_validate_json(raw)
    if canonical_json_bytes(receipt) != raw:
        raise ValueError("runtime port receipt is not canonical")
    certificate = verify_runtime_port(receipt.certificate, store.lineage)
    review = certificate.review
    if record != runtime_port_record(review):
        raise ValueError("runtime port differs from its reviewed decision")
    _read_parent(connection, review)
    high_water = connection.execute(
        "SELECT value FROM metadata WHERE key='observed_block'"
    ).fetchone()
    if (
        not review.not_before_block <= receipt.observed_block <= review.valid_through_block
        or high_water is None
        or receipt.observed_block > int(high_water[0])
    ):
        raise ValueError("runtime port receipt exceeds the local observation history")
    return receipt


def _require_between_rounds(store, connection, block):
    if connection.execute(
        "SELECT 1 FROM round_conflicts UNION ALL SELECT 1 FROM settlement_disputes LIMIT 1"
    ).fetchone():
        raise ValueError("runtime port cannot bypass disputed history")
    for (raw,) in connection.execute("SELECT body FROM rounds"):
        round_ = EvaluationRound.model_validate_json(raw)
        if block <= round_.valid_through_block:
            raise ValueError("runtime port cannot replace a baseline during a retained round")
    launch = store._require_current_public_launch(connection)
    if launch is not None:
        start = launch.round_schedule.roster_close_earliest_block
        if block >= start:
            cycle = (
                (block - start) // launch.round_stride_blocks if launch.round_stride_blocks else 0
            )
            if block <= launch.schedule_for_cycle(cycle).round_valid_through_block:
                raise ValueError("runtime port cannot replace a baseline during a published round")


def apply_runtime_port(
    store: CompetitionStore,
    certificate: SignedRuntimePortReview,
    *,
    archive: Path,
    observed_block: int | Callable[[], int],
) -> dict:
    """Caller must quiesce services and supply a freshly owned finalized block.

    This store does not authorize chain observations. Both policy quorums attest
    the external qualification and source review; callers retain those artifacts.
    """
    certificate = verify_runtime_port(certificate, store.lineage)
    review = certificate.review
    record = runtime_port_record(review)
    if (
        len(canonical_json_bytes(certificate)) > _MAX_BYTES
        or len(canonical_json_bytes(record)) > _MAX_BYTES
    ):
        raise ValueError("runtime port evidence exceeds its byte bound")
    if review.policy_sha256 != digest(store.policy):
        raise ValueError("runtime port must activate under its target policy")
    verify_preserved_bundle(
        review.original, archive, store.lineage.policy(review.source_policy_sha256)
    )
    verify_preserved_bundle(review.replacement, archive, store.policy)
    # Hashing large preserved bundles can take longer than the head freshness
    # allowance. Live callers collect their owned observation after that work.
    if callable(observed_block):
        observed_block = observed_block()
    receipt = RuntimePortReceipt(certificate=certificate, observed_block=observed_block)
    raw = canonical_json_bytes(receipt)
    if len(raw) > _MAX_BYTES:
        raise ValueError("runtime port receipt exceeds its byte bound")
    with store._transaction() as connection:
        prior = connection.execute(
            "SELECT body FROM promotions WHERE sequence=?", (review.sequence,)
        ).fetchone()
        if prior is not None:
            if json.loads(prior[0]) != record:
                raise ValueError("runtime port retry changes its original decision")
            read_runtime_port_receipt(store, connection, record)
            return record
        if (
            type(observed_block) is not int
            or not review.not_before_block <= observed_block <= review.valid_through_block
        ):
            raise ValueError("runtime port is outside its application window")
        previous = connection.execute(
            "SELECT value FROM metadata WHERE key='observed_block'"
        ).fetchone()
        if previous and observed_block < int(previous[0]):
            raise ValueError("competition state cannot move to an earlier finalized block")
        _require_between_rounds(store, connection, observed_block)
        _read_parent(connection, review)
        head = connection.execute(
            "SELECT digest FROM promotions ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if head != (review.previous_promotion_sha256,):
            raise ValueError("runtime port parent is no longer the current head")
        # Block already running older writers as well as future old-code opens.
        if connection.execute("SELECT 1 FROM metadata WHERE key=?", (_MARKER,)).fetchone() is None:
            for _, sql in _fences(store._WRITER_FENCED_TABLES):
                connection.execute(sql)
            connection.execute("INSERT INTO metadata VALUES (?, '1')", (_MARKER,))
        connection.execute(
            "INSERT OR REPLACE INTO metadata VALUES ('observed_block', ?)", (str(observed_block),)
        )
        connection.execute(
            "INSERT INTO metadata VALUES (?, ?)", (_PREFIX + str(review.sequence), raw.decode())
        )
        connection.execute(
            "INSERT INTO promotions VALUES (?, ?, ?, ?, ?)",
            (
                review.sequence,
                baseline_record_digest(record),
                digest(review.replacement),
                None,
                canonical_json_bytes(record),
            ),
        )
        connection.execute(
            "INSERT INTO model_identities VALUES (?, ?)",
            (model_content_digest(review.replacement), digest(review.replacement)),
        )
        return record
