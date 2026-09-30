"""Verified private scheduling reservation receipts for whole-round admission."""

from __future__ import annotations

import json
import re
import threading
import time
from collections import OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .competition_authorization import (
    EndpointAuthorizationPublication,
    SignedEndpointAuthorization,
    scheduled_assignment_key,
    validate_publication_body,
)
from .open_competition import digest, identity
from .protocol import canonical_json_bytes, is_canonical_json, sha256_hex

if TYPE_CHECKING:
    import sqlite3

    from .competition_scheduling import AssignmentPublicationJournal

TABLES: tuple[str, ...] = (
    "metadata",
    "blocks",
    "rounds",
    "publications",
    "assignments",
    "events",
    "reservation_batches",
    "reservation_publications",
    "reservation_assignments",
    "reservation_consumptions",
    "reservation_qualifications",
)


def writer_fences() -> Iterator[tuple[str, str]]:
    for table in TABLES:
        for operation in ("INSERT", "UPDATE", "DELETE"):
            name = f"generation_{table}_{operation.lower()}"
            yield (
                name,
                (
                    f"CREATE TRIGGER {name} BEFORE {operation} ON {table} "
                    "BEGIN SELECT CASE WHEN umi_scheduling_writer_generation() IS NOT 2 "
                    "THEN RAISE(ABORT,'scheduling writer generation mismatch') END; END"
                ),
            )


def _bounded(raw: bytes, maximum: int) -> Any:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= maximum:
        raise ValueError("scheduling receipt exceeds its byte bound")
    value = json.loads(raw)
    if not is_canonical_json(raw):
        raise ValueError("scheduling receipt is not canonical")
    return value


@dataclass(frozen=True)
class _PublicationFacts:
    round_sha256: str
    round_sequence: int
    assignments: tuple[tuple[str, bytes], ...]
    allowance: int
    proof_end: int
    proof_starts: frozenset[int]


_VALIDATED_PUBLICATIONS: OrderedDict[tuple[str, str], _PublicationFacts] = OrderedDict()
_VALIDATED_PUBLICATIONS_LOCK = threading.Lock()
_VALIDATED_PUBLICATIONS_MAXIMUM = 512
_FACTS_ENTRY_MAXIMUM_BYTES = 64 * 1024
_CONSUMED_PUBLICATIONS: OrderedDict[tuple[str, str], None] = OrderedDict()
_PUBLICATION_DOMAIN = b"umi-open-competition-v1\0"


def _validated_publication(raw: bytes, publication_id: str, journal, context: str):
    """Memoize immutable derivations; callers still reread every durable row.

    The context binds the complete current policies and outcome-size allowance.
    No cached model or mutable container escapes to a caller. Different bytes,
    policy changes and changed allowances cannot reuse a previous validation.
    """
    if sha256_hex(_PUBLICATION_DOMAIN + raw) != publication_id:
        raise ValueError("scheduling reservation publication binding changed")
    key = (context, publication_id)
    with _VALIDATED_PUBLICATIONS_LOCK:
        cached = _VALIDATED_PUBLICATIONS.get(key)
        if cached is not None:
            _VALIDATED_PUBLICATIONS.move_to_end(key)
            return cached
    body = validate_publication_body(
        EndpointAuthorizationPublication.model_validate_json(raw),
        journal.policy,
        journal.legacy_policy,
    )
    if canonical_json_bytes(body) != raw or digest(body) != publication_id:
        raise ValueError("scheduling reservation publication binding changed")
    assignments = tuple(
        (scheduled_assignment_key(body, assignment), canonical_json_bytes(assignment))
        for assignment in body.assignments
    )
    rows = [(None, None, encoded) for _, encoded in assignments]
    legacy = journal.legacy_policy
    facts = _PublicationFacts(
        round_sha256=digest(body.round),
        round_sequence=body.round.sequence,
        assignments=assignments,
        allowance=journal._publication_allowance(body, rows),
        proof_end=max(a.request.deadline_block for a in body.assignments),
        proof_starts=frozenset(
            legacy.activation_block
            + (
                (a.request.issued_block - legacy.activation_block)
                // legacy.clock.window_stride_blocks
            )
            * legacy.clock.window_stride_blocks
            for a in body.assignments
        ),
    )
    # Bound retained encoded data to 32 MiB, with a bounded number of keys.
    encoded_size = sum(len(assignment_id) + len(encoded) for assignment_id, encoded in assignments)
    encoded_size += len(facts.round_sha256) + 8 * len(facts.proof_starts) + 16
    if encoded_size <= _FACTS_ENTRY_MAXIMUM_BYTES:
        with _VALIDATED_PUBLICATIONS_LOCK:
            _VALIDATED_PUBLICATIONS[key] = facts
            _VALIDATED_PUBLICATIONS.move_to_end(key)
            while len(_VALIDATED_PUBLICATIONS) > _VALIDATED_PUBLICATIONS_MAXIMUM:
                _VALIDATED_PUBLICATIONS.popitem(last=False)
    return facts


def _validate_consumed(raw: bytes, reserved: bytes, publication_id: str) -> None:
    key = (publication_id, sha256_hex(raw))
    with _VALIDATED_PUBLICATIONS_LOCK:
        if key in _CONSUMED_PUBLICATIONS:
            _CONSUMED_PUBLICATIONS.move_to_end(key)
            return
    signed = SignedEndpointAuthorization.model_validate_json(raw)
    if canonical_json_bytes(signed.publication) != reserved:
        raise ValueError("consumed scheduling reservation differs from publication")
    with _VALIDATED_PUBLICATIONS_LOCK:
        _CONSUMED_PUBLICATIONS[key] = None
        _CONSUMED_PUBLICATIONS.move_to_end(key)
        while len(_CONSUMED_PUBLICATIONS) > _VALIDATED_PUBLICATIONS_MAXIMUM:
            _CONSUMED_PUBLICATIONS.popitem(last=False)


def reservation(
    journal: AssignmentPublicationJournal,
    db: sqlite3.Connection,
    batch_id: str,
    evaluator_hotkey: str,
    *,
    requalify: bool = True,
) -> dict[str, Any] | None:
    if not isinstance(batch_id, str) or not re.fullmatch("[0-9a-f]{64}", batch_id):
        raise ValueError("invalid scheduling reservation identity")
    if not journal._reservation_enabled(db):
        return None
    fences = dict(db.execute("SELECT name,sql FROM sqlite_master WHERE type='trigger'"))
    if any(fences.get(name) != sql for name, sql in writer_fences()):
        raise ValueError("scheduling reservation writer fences changed")
    metadata = dict(db.execute("SELECT key,value FROM metadata"))
    journal_id = metadata.get("reservation_journal_identity", "")
    if not re.fullmatch("[0-9a-f]{64}", journal_id):
        raise ValueError("scheduling reservation journal identity changed")
    size = db.execute(
        "SELECT length(document) FROM reservation_batches WHERE id=?", (batch_id,)
    ).fetchone()
    if size is None:
        return None
    if not 0 < size[0] <= 1024**2:
        raise ValueError("scheduling receipt exceeds its byte bound")
    row = db.execute("SELECT * FROM reservation_batches WHERE id=?", (batch_id,)).fetchone()
    value = _bounded(bytes(row["document"]), 1024**2)
    if (
        set(value) != {"batch_id", "publications", "proof_start", "proof_end"}
        or value["batch_id"] != batch_id
        or value["proof_start"] != row["proof_start"]
        or value["proof_end"] != row["proof_end"]
    ):
        raise ValueError("scheduling reservation batch binding changed")
    entries = db.execute(
        "SELECT id,length(body) AS size FROM reservation_publications WHERE batch_id=? ORDER BY id",
        (batch_id,),
    ).fetchall()
    if (
        not 1 <= len(entries) <= journal.maximum_publications
        or [r["id"] for r in entries] != value["publications"]
    ):
        raise ValueError("scheduling reservation lost an original publication")
    context = sha256_hex(
        canonical_json_bytes(
            {
                "policy": journal.policy.model_dump(mode="json", by_alias=True),
                "legacy_policy": journal.legacy_policy.model_dump(mode="json", by_alias=True),
                "maximum_outcome_bytes": journal.maximum_outcome_bytes,
            }
        )
    )
    proof_end, starts = 0, set()
    for entry in entries:
        if not 0 < entry["size"] <= 16 * 1024**2:
            raise ValueError("reserved scheduling publication exceeds its byte bound")
        saved = db.execute(
            "SELECT * FROM reservation_publications WHERE id=?", (entry["id"],)
        ).fetchone()
        raw = bytes(saved["body"])
        facts = _validated_publication(raw, entry["id"], journal, context)
        if (
            facts.round_sha256 != row["round_sha256"]
            or facts.round_sequence != row["round_sequence"]
        ):
            raise ValueError("scheduling reservation publication binding changed")
        assigned = sorted(key for key, _ in facts.assignments)
        retained = [
            r[0]
            for r in db.execute(
                "SELECT id FROM reservation_assignments WHERE publication_id=? ORDER BY id",
                (entry["id"],),
            )
        ]
        rows = [(None, None, encoded) for _, encoded in facts.assignments]
        if (
            retained != assigned
            or saved["assignment_count"] != len(assigned)
            or saved["allowance"] != facts.allowance
        ):
            raise ValueError("scheduling reservation assignment allowance changed")
        consumed = db.execute(
            "SELECT 1 FROM reservation_consumptions WHERE publication_id=?",
            (entry["id"],),
        ).fetchone()
        published_size = db.execute(
            "SELECT length(signed) FROM publications WHERE id=?", (entry["id"],)
        ).fetchone()
        if published_size is not None and not 0 < published_size[0] <= 16 * 1024**2:
            raise ValueError("consumed scheduling publication exceeds its byte bound")
        published = db.execute(
            "SELECT signed,reserved FROM publications WHERE id=?", (entry["id"],)
        ).fetchone()
        if bool(consumed) != bool(published):
            raise ValueError("scheduling reservation consumption changed")
        if published is not None:
            _validate_consumed(bytes(published[0]), raw, entry["id"])
            if (
                published[1] != journal._publication_bytes(len(published[0]), rows)
                or published[1] > saved["allowance"]
            ):
                raise ValueError("consumed scheduling reservation differs from publication")
            for assignment_key, encoded in facts.assignments:
                current = db.execute(
                    "SELECT body,publication_id FROM assignments WHERE id=?",
                    (assignment_key,),
                ).fetchone()
                if current is None or bytes(current[0]) != encoded or current[1] != entry["id"]:
                    raise ValueError("consumed scheduling reservation lost an assignment")
        proof_end = max(proof_end, facts.proof_end)
        starts.update(facts.proof_starts)
    if proof_end != row["proof_end"]:
        raise ValueError("scheduling reservation proof interval changed")
    if min(starts) != row["proof_start"]:
        raise ValueError("scheduling reservation proof start changed")
    for height in starts:
        journal._retained_block(db, height)
    qualification_size = db.execute(
        "SELECT length(document) FROM reservation_qualifications WHERE batch_id=? AND evaluator=?",
        (batch_id, identity(evaluator_hotkey)),
    ).fetchone()
    if qualification_size is None or not 0 < qualification_size[0] <= 1024**2:
        raise ValueError("scheduling timing receipt is missing or oversized")
    qualification = journal._recover_capacity(
        db,
        batch_id,
        evaluator_hotkey,
        time.time_ns() // 1_000_000,
        requalify=requalify,
    )
    journal._capacity(db)
    return {
        "schema": "umi-private-scheduling-receipt/1",
        "generation": 2,
        "journal_identity": journal_id,
        "journal_path": str(journal.path.resolve()),
        "policy_sha256": metadata["policy"],
        "legacy_policy_sha256": metadata["legacy_policy"],
        "maximum_outcome_bytes": journal.maximum_outcome_bytes,
        "batch_id": batch_id,
        "evaluator": identity(evaluator_hotkey),
        "document_sha256": sha256_hex(bytes(row["document"])),
        "qualification_sha256": digest(qualification),
    }
