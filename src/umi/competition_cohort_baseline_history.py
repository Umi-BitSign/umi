"""Append and reread a quorum-reviewed cohort winner without replaying payloads.

The certificate attests the native source preparation. Applying it requires the
original current head, a current finalized observation and quiesced round writers.
This changes the reference for new rounds; retained rounds and signed submissions
keep their original bindings. It grants no chain weight authority.
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Callable
from typing import TYPE_CHECKING

from .competition_cohort_baseline_review import (
    CertifiedCohortBaselineReview,
    cohort_baseline_record,
    verify_baseline_review,
)
from .competition_cohort_recovery import Block
from .competition_runtime_port import baseline_record_digest
from .competition_runtime_port_history import _require_no_retained_round_activity
from .competition_transport_verification import TransferProgress
from .open_competition import digest, identity, model_content_digest
from .protocol import StrictProtocolModel, canonical_json_bytes

if TYPE_CHECKING:
    from .competition_store import CompetitionStore

_MAX_BYTES = 4 * 1024**2
_MARKER = "cohort_baseline_writer"
_PREFIX = "cohort_baseline_receipt:"


class CohortBaselineReceipt(StrictProtocolModel):
    certificate: CertifiedCohortBaselineReview
    observed_block: Block


def _fences(tables):
    for table in tables:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"cohort_baseline_{table}_{operation.lower()}"
            yield (
                name,
                (
                    f"CREATE TRIGGER {name} BEFORE {operation} ON {table} BEGIN "
                    "SELECT CASE WHEN umi_cohort_baseline_writer() IS NOT 1 "
                    "THEN RAISE(ABORT,'cohort baseline writer mismatch') END; END"
                ),
            )


def verify_cohort_baseline_fence(connection: sqlite3.Connection, tables) -> None:
    objects = dict(connection.execute("SELECT name,sql FROM sqlite_master"))
    if "metadata" not in objects:
        return
    marker = connection.execute("SELECT value FROM metadata WHERE key=?", (_MARKER,)).fetchone()
    names = {name for name in objects if name.startswith("cohort_baseline_")}
    if marker is None:
        if (
            names
            or connection.execute(
                "SELECT 1 FROM metadata WHERE key GLOB 'cohort_baseline_receipt:*' LIMIT 1"
            ).fetchone()
        ):
            raise ValueError("cohort baseline writer fence is missing")
        return
    expected = dict(_fences(tables))
    if (
        marker != ("1",)
        or names != set(expected)
        or any(objects[name] != sql for name, sql in expected.items())
    ):
        raise ValueError("cohort baseline writer fence changed")


def _read_parent(connection, review):
    row = connection.execute(
        "SELECT digest,model,contributor,body FROM promotions WHERE sequence=?",
        (review.previous.sequence,),
    ).fetchone()
    if row is None:
        raise ValueError("cohort baseline parent is missing")
    record = json.loads(row[3])
    previous = review.previous
    if (
        row[0] != previous.promotion_sha256
        or baseline_record_digest(record) != row[0]
        or canonical_json_bytes(record) != row[3]
        or record.get("sequence") != previous.sequence
        or record.get("model_sha256") != previous.model_sha256
        or row[1] != previous.model_sha256
        or record.get("contributor_hotkey") != previous.contributor_hotkey
        or row[2]
        != (None if previous.contributor_hotkey is None else identity(previous.contributor_hotkey))
    ):
        raise ValueError("cohort baseline differs from its exact parent")


def read_cohort_baseline_receipt(store: CompetitionStore, connection, record, maximum_bytes=None):
    limit = min(_MAX_BYTES, maximum_bytes if maximum_bytes is not None else _MAX_BYTES)
    key = _PREFIX + str(record["sequence"])
    size = connection.execute(
        "SELECT length(CAST(value AS BLOB)) FROM metadata WHERE key=?", (key,)
    ).fetchone()
    if size is None or not 0 < size[0] <= limit:
        raise ValueError("cohort baseline receipt missing or oversized; explicit repair required")
    raw = (
        connection.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()[0].encode()
    )
    receipt = CohortBaselineReceipt.model_validate_json(raw)
    if canonical_json_bytes(receipt) != raw:
        raise ValueError("cohort baseline receipt is not canonical")
    policy = store.lineage.policy(record["policy_sha256"])
    certificate = verify_baseline_review(receipt.certificate, policy)
    review = certificate.review
    if record != cohort_baseline_record(review):
        raise ValueError("cohort baseline differs from its reviewed decision")
    _read_parent(connection, review)
    high_water = connection.execute(
        "SELECT value FROM metadata WHERE key='observed_block'"
    ).fetchone()
    if (
        not review.not_before_block <= receipt.observed_block <= review.valid_through_block
        or high_water is None
        or receipt.observed_block > int(high_water[0])
    ):
        raise ValueError("cohort baseline receipt exceeds the local observation history")
    return receipt


def _advance_intake_anchor(store, connection, review, record):
    retained = connection.execute(
        "SELECT value FROM metadata WHERE key='retained_intake_anchor'"
    ).fetchone()
    if retained is None:
        return
    if len(retained[0].encode()) > _MAX_BYTES:
        raise ValueError("cohort baseline intake anchor exceeds its byte bound")
    try:
        required = tuple(json.loads(retained[0])["required_submission_sha256s"])
    except (KeyError, TypeError, ValueError) as error:
        raise ValueError("cohort baseline intake anchor is corrupt") from error
    store._verify_retained_intake_state_locked(
        connection,
        baseline_promotion_sha256=review.previous.promotion_sha256,
        required_submission_sha256s=required,
    )
    anchor = json.loads(
        connection.execute(
            "SELECT value FROM metadata WHERE key='retained_intake_anchor'"
        ).fetchone()[0]
    )
    anchor["baseline_promotion_sha256"] = baseline_record_digest(record)
    connection.execute(
        "INSERT INTO metadata VALUES (?, ?)",
        ("cohort_baseline_prior_intake_anchor:" + str(record["sequence"]), retained[0]),
    )
    connection.execute(
        "UPDATE metadata SET value=? WHERE key='retained_intake_anchor'",
        (canonical_json_bytes(anchor).decode(),),
    )


def cohort_baseline_application_status(
    store: CompetitionStore,
    certificate: CertifiedCohortBaselineReview,
    *,
    required_submission_sha256s: tuple[str, ...] | None = None,
) -> str:
    """Inspect existing history without creating, migrating or repairing state.

    A completed receipt is authenticated before returning ``completed``; damage
    requires explicit repair rather than another append or payload verification.
    Intake callers also bind the exact retained required-submission list. This
    is metadata inspection, not a native preparation or a chain observation.
    """
    certificate = verify_baseline_review(certificate, store.policy)
    review = certificate.review
    record = cohort_baseline_record(review)
    target = baseline_record_digest(record)
    with store._connection() as connection:
        if not connection.in_transaction:
            connection.execute("BEGIN")
        head = connection.execute(
            "SELECT digest FROM promotions ORDER BY sequence DESC LIMIT 1"
        ).fetchone()
        if head not in {(review.previous.promotion_sha256,), (target,)}:
            raise ValueError("cohort baseline source has another current promotion head")
        store._verify_retained_baseline(connection, head[0])
        _read_parent(connection, review)
        if required_submission_sha256s is not None:
            expected = canonical_json_bytes(
                {
                    "schema": "umi-competition-retained-intake-anchor/1",
                    "policy_sha256": review.policy_sha256,
                    "baseline_promotion_sha256": head[0],
                    "required_submission_sha256s": list(required_submission_sha256s),
                }
            ).decode()
            anchor = connection.execute(
                "SELECT value FROM metadata WHERE key='retained_intake_anchor'"
            ).fetchone()
            if anchor != (expected,):
                raise ValueError("cohort baseline config differs from its retained intake anchor")
        if head == (target,):
            read_cohort_baseline_receipt(store, connection, record)
            return "completed"
        prior = connection.execute(
            "SELECT 1 FROM promotions WHERE sequence=?", (record["sequence"],)
        ).fetchone()
        if prior is not None:
            raise ValueError("cohort baseline sequence is already occupied")
        return "pending"


def apply_cohort_baseline(
    store: CompetitionStore,
    certificate: CertifiedCohortBaselineReview,
    *,
    observed_block: int | Callable[[], int],
) -> dict:
    """Apply reviewed metadata atomically; never reverify immutable model payloads.

    Independent signers must use the native preparation factory, and deployment
    must qualify every reader before applying the new format. This API does not
    issue a chain observation or relax any cohort hold or signed clock.
    """
    with TransferProgress(
        "cohort_baseline_history_append", 1, unit="promotions", planning_unit_seconds=(0.001, 30)
    ) as progress:
        # Independent evaluator histories need the same quorum-reviewed head.
        # Recording it grants no intake authority: admission and round mutation
        # retain their separate role checks, as with agreed/runtime-port heads.
        certificate = verify_baseline_review(certificate, store.policy)
        review = certificate.review
        record = cohort_baseline_record(review)
        if len(canonical_json_bytes(record)) > _MAX_BYTES:
            raise ValueError("cohort baseline record exceeds its metadata bound")
        with store._transaction() as connection:
            prior = connection.execute(
                "SELECT body FROM promotions WHERE sequence=?", (record["sequence"],)
            ).fetchone()
            if prior is not None:
                if json.loads(prior[0]) != record:
                    raise ValueError("cohort baseline retry changes its original decision")
                read_cohort_baseline_receipt(store, connection, record)
                progress.advance(1)
                return record
            block = observed_block() if callable(observed_block) else observed_block
            if (
                type(block) is not int
                or not review.not_before_block <= block <= review.valid_through_block
            ):
                raise ValueError("cohort baseline is outside its application window")
            previous_block = connection.execute(
                "SELECT value FROM metadata WHERE key='observed_block'"
            ).fetchone()
            if previous_block and block < int(previous_block[0]):
                raise ValueError("competition state cannot move to an earlier finalized block")
            # A certified cohort winner advances the reference for future work.
            # An unused cycle of the legacy continuous calendar is not a retained
            # round; it must not indefinitely block the cohort's reviewed winner.
            # Actual retained rounds and disputed history still fence the append.
            _require_no_retained_round_activity(connection, block)
            _read_parent(connection, review)
            head = connection.execute(
                "SELECT digest FROM promotions ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            if head != (review.previous.promotion_sha256,):
                raise ValueError("cohort baseline parent is no longer the current head")
            content = model_content_digest(review.model)
            model = digest(review.model)
            known = connection.execute(
                "SELECT model FROM model_identities WHERE content=?", (content,)
            ).fetchone()
            if known is not None and known != (model,):
                raise ValueError("cohort baseline content has a different retained model identity")
            receipt = canonical_json_bytes(
                CohortBaselineReceipt(certificate=certificate, observed_block=block)
            )
            if len(receipt) > _MAX_BYTES:
                raise ValueError("cohort baseline receipt exceeds its metadata bound")
            _advance_intake_anchor(store, connection, review, record)
            if (
                connection.execute("SELECT 1 FROM metadata WHERE key=?", (_MARKER,)).fetchone()
                is None
            ):
                for _, sql in _fences(store._WRITER_FENCED_TABLES):
                    connection.execute(sql)
                connection.execute("INSERT INTO metadata VALUES (?, '1')", (_MARKER,))
            connection.execute(
                "INSERT OR REPLACE INTO metadata VALUES ('observed_block', ?)", (str(block),)
            )
            connection.execute(
                "INSERT INTO metadata VALUES (?, ?)",
                (_PREFIX + str(record["sequence"]), receipt.decode()),
            )
            connection.execute(
                "INSERT INTO promotions VALUES (?, ?, ?, ?, ?)",
                (
                    record["sequence"],
                    baseline_record_digest(record),
                    model,
                    identity(review.candidate.contributor_hotkey),
                    canonical_json_bytes(record),
                ),
            )
            if known is None:
                connection.execute("INSERT INTO model_identities VALUES (?, ?)", (content, model))
        progress.advance(1)
        return record
