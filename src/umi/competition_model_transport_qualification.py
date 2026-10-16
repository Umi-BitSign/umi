"""Supplementary authorization for retained direct-model artifacts.

This domain is independent of native block and byte-verification receipts. The
caller selects authenticated owner history and holds its original journal lock.
Read/publish ports use that same durable journal and atomically publish the pair
and its permanent completion ledger. The ledger is never an evictable cache.
No payload, RPC, signer, new acceptance or reward authority is involved.
"""

import json
import logging
import time
from collections.abc import Callable
from contextlib import contextmanager
from typing import TYPE_CHECKING

from .competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from .competition_cohort_model_acceptance import ModelArtifactAcceptance
from .competition_cohort_model_transport import verify_direct_model_transport
from .open_competition import digest
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    from .competition_round_journal import RoundJournal

SCOPE = "umi-model-transport-authorization/1"
RECORD = "model_transport_authorization"
MARKER = "model_transport_authorization_complete"
COMPLETION = "model_transport_authorization_ledger"
COMPLETION_SCOPE = "umi-model-transport-authorization-ledger/1"
QUALIFICATION_KINDS = (RECORD, MARKER, COMPLETION)
REPAIR = "model_transport_authorization_repair"
REPAIR_SCOPE = "umi-model-transport-authorization-repair/1"
MAX_REPAIR_BYTES = 65536
_LOG = logging.getLogger("umi.competition.progress")


def _progress(state, started, completed, report, *, operation="qualification"):
    value = {
        "stage": "model_transport_authorization",
        "operation": operation,
        "state": state,
        "completed": completed,
        "total": 1,
        "percent": completed * 100,
        "elapsed_seconds": time.monotonic() - started,
        "eta_seconds": 0 if completed else None,
        "planning_eta_seconds": [0, 5] if state == "running" else None,
        "eta_basis": "complete"
        if completed
        else "single_metadata_check"
        if state == "running"
        else "retry_after_io_failure"
        if state == "retrying"
        else "repair_required",
        "eta_scope": "supplementary_transport_check_only",
        "retrying": state == "retrying",
        "stalled": state == "repair_required",
    }
    _emit(value, report)


def _emit(value, report):
    if report is not None:
        try:
            report(value)
        except Exception:
            _LOG.exception("model transport progress sink failed")
    else:
        _LOG.info("model_transport_qualification %s", json.dumps(value, sort_keys=True))


@contextmanager
def committed_transport_repair_progress(report=None):
    """Delay completion until an enclosing owner transaction has committed."""
    started = time.monotonic()
    pending = None
    last_state = None

    def emit(value):
        nonlocal pending, last_state
        last_state = value["state"]
        if value["state"] == "completed":
            pending = value
        else:
            _emit(value, report)

    try:
        yield emit
    except Exception as error:
        if last_state not in ("retrying", "repair_required"):
            _progress(
                "retrying" if isinstance(error, OSError) else "repair_required",
                started,
                0,
                report,
                operation="repair",
            )
        raise
    if pending is not None:
        pending["elapsed_seconds"] = time.monotonic() - started
        _emit(pending, report)


def _expected(acceptance, history, policy):
    acceptance = ModelArtifactAcceptance.model_validate_json(canonical_json_bytes(acceptance))
    if acceptance.direct_artifact is None:
        return None
    history = CohortRecoveryHistory.model_validate_json(canonical_json_bytes(history))
    selected = history.transitions[-1].transition if history.transitions else history.genesis
    tip_block = selected.observed_at_block if history.transitions else selected.admitted_at_block
    verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=digest(selected),
        current_block=max(tip_block, acceptance.accepted_at_block),
    )
    if (
        acceptance.policy_sha256 != digest(policy)
        or acceptance.cohort_sha256 != digest(history.plan)
        or acceptance.authority_sha256 != digest(history.authority.authority)
    ):
        raise ValueError("model transport qualification changes acceptance authority")
    prefix = history.model_copy(
        update={
            "transitions": tuple(
                value
                for value in history.transitions
                if value.transition.observed_at_block <= acceptance.accepted_at_block
            )
        }
    )
    key = digest(acceptance)
    expected = {
        "schema": SCOPE,
        "acceptance_sha256": key,
        "reservation_sha256": digest(acceptance.direct_artifact),
        "policy_sha256": digest(policy),
        "authority_sha256": digest(history.authority),
        "cohort_sha256": acceptance.cohort_sha256,
        "accepted_at_block": acceptance.accepted_at_block,
        "history_prefix_sha256": digest(prefix),
    }
    marker = {"schema": SCOPE, "qualification_sha256": digest(expected)}
    return acceptance, history, key, expected, marker


def _completion(expected, marker):
    return {"schema": COMPLETION_SCOPE, "qualification": expected, "marker": marker}


def qualify_model_transport(acceptance, history, policy, *, read, publish, report=None):
    """Reuse this predicate only, preserving all older successful proof domains.

    ``read(kind, key)`` returns the native JSON record or None.
    ``publish(records)`` atomically retains immutable (kind, key, JSON) records
    using the caller's normal capacity accounting. A supported old installation
    lacks the pair and completion ledger. Any retained completion makes a missing
    pair damage requiring scoped repair, even if both records disappeared. Old
    pairs predating the ledger use explicit repair to install the completion.
    Fresh owned history selection and rollback/fork protection remain caller duties.
    """
    started = time.monotonic()
    context = _expected(acceptance, history, policy)
    if context is None:
        return None
    acceptance, history, key, expected, marker = context
    completion = _completion(expected, marker)
    try:
        retained = tuple(read(kind, key) for kind in QUALIFICATION_KINDS)
    except Exception:
        _progress("repair_required", started, 0, report)
        raise
    if any(value is not None for value in retained):
        if tuple(canonical_json_bytes(value) for value in retained) != tuple(
            canonical_json_bytes(value) for value in (expected, marker, completion)
        ):
            _progress("repair_required", started, 0, report)
            raise ValueError(
                "model transport qualification missing or changed; scoped repair required"
            )
        return expected
    _progress("running", started, 0, report)
    try:
        verify_direct_model_transport(
            acceptance.direct_artifact,
            history,
            policy,
            accepted_at_block=acceptance.accepted_at_block,
        )
        publish(((RECORD, key, expected), (MARKER, key, marker), (COMPLETION, key, completion)))
    except Exception:
        _progress("repair_required", started, 0, report)
        raise
    _progress("completed", started, 1, report)
    return expected


def repair_model_transport(
    acceptance,
    history,
    policy,
    *,
    reason: str,
    read_raw: Callable[[str, str], bytes | None],
    replace: Callable[[str, tuple[bytes | None, ...], tuple[tuple[str, str, object], ...]], None],
    report=None,
):
    """Explicitly repair only a damaged supplementary authorization pair.

    The owner holds its original lock and selects original retained acceptance
    and authenticated history. ``replace(key, observed, records)`` must compare
    all exact observed blobs again, then atomically restore the pair and completion
    and immutably retain REPAIR using ordinary capacity and conflict accounting.
    It must roll back everything on error. The audit retains damaged bytes;
    signed acceptance, request, intent, vote and history records are never targets.

    A fully absent pair without a completion belongs to first migration. A valid
    permanent completion restores either or both missing records without repeating
    the successful predicate. A pre-ledger pair receives an explicit native
    metadata check and ledger migration. Exact completed triples make repeated
    repair and lost acknowledgements idempotent. No payload,
    RPC, fresh signing, or unrelated proof domain is opened by this operation.
    """
    started = time.monotonic()
    try:
        if type(reason) is not str or not reason.strip() or len(reason.encode()) > 1024:
            raise ValueError("model transport repair requires an explicit bounded reason")
        context = _expected(acceptance, history, policy)
        if context is None:
            raise ValueError("legacy model acceptance has no supplementary transport repair")
        acceptance, history, key, expected, marker = context
        completion = _completion(expected, marker)
        expected_raw = tuple(canonical_json_bytes(v) for v in (expected, marker, completion))
        observed = tuple(read_raw(kind, key) for kind in QUALIFICATION_KINDS)
        if any(
            raw is not None and (type(raw) is not bytes or len(raw) > MAX_REPAIR_BYTES)
            for raw in observed
        ):
            raise ValueError("damaged model transport metadata exceeds scoped repair bound")
        if observed == expected_raw:
            _progress("completed", started, 1, report, operation="repair")
            return expected
        if observed == (None, None, None):
            raise ValueError("absent model transport qualification requires first migration")
        _progress("running", started, 0, report, operation="repair")
        if observed[2] != expected_raw[2]:
            verify_direct_model_transport(
                acceptance.direct_artifact,
                history,
                policy,
                accepted_at_block=acceptance.accepted_at_block,
            )
        audit = {
            "schema": REPAIR_SCOPE,
            "scope": SCOPE,
            "acceptance_sha256": key,
            "reason": reason,
            "originals": [
                {"kind": kind, "body_hex": None if raw is None else raw.hex()}
                for kind, raw in zip(QUALIFICATION_KINDS, observed, strict=True)
            ],
            "qualification_sha256": digest(expected),
            "marker_sha256": digest(marker),
            "completion_sha256": digest(completion),
        }
        replace(
            key,
            observed,
            (
                (RECORD, key, expected),
                (MARKER, key, marker),
                (COMPLETION, key, completion),
                (REPAIR, digest(audit), audit),
            ),
        )
    except Exception as error:
        _progress(
            "retrying" if isinstance(error, OSError) else "repair_required",
            started,
            0,
            report,
            operation="repair",
        )
        raise
    _progress("completed", started, 1, report, operation="repair")
    return expected


def repair_journal_model_transport(
    journal: "RoundJournal", acceptance, history, policy, *, reason: str, report=None
):
    """Repair metadata inside a RoundJournal without changing signed records.

    The caller holds the journal lock through source selection and this call.
    Generation fences, conflict holds, reservation obligations and derived
    record accounting remain enforced, including on supported older journals.
    """

    def raw(db, kind, key):
        if kind not in QUALIFICATION_KINDS:
            raise ValueError("model transport repair cannot select signed record kinds")
        if db.execute("SELECT 1 FROM holds WHERE id=?", (key,)).fetchone():
            raise ValueError("round journal conflict held")
        row = db.execute(
            "SELECT length(body),typeof(body),substr(body,1,?) FROM records WHERE kind=? AND id=?",
            (MAX_REPAIR_BYTES + 1, kind, key),
        ).fetchone()
        if row is None:
            return None
        if row[1] != "blob" or not 0 <= row[0] <= MAX_REPAIR_BYTES:
            raise ValueError("damaged model transport metadata exceeds scoped repair bound")
        return b"" if row[0] == 0 else bytes(row[2])

    def read(kind, key):
        with journal.read_transaction() as db:
            return raw(db, kind, key)

    def replace(key, observed, records):
        with journal.transaction() as db:
            if tuple(raw(db, kind, key) for kind in QUALIFICATION_KINDS) != observed:
                raise ValueError("model transport qualification changed during scoped repair")
            originals = dict(zip(QUALIFICATION_KINDS, observed, strict=True))
            for kind, record_key, body in records:
                if kind not in (*QUALIFICATION_KINDS, REPAIR) or (
                    kind != REPAIR and record_key != key
                ):
                    raise ValueError("model transport repair attempted unrelated record")
                if db.execute("SELECT 1 FROM holds WHERE id=?", (record_key,)).fetchone():
                    raise ValueError("round journal conflict held")
                encoded = canonical_json_bytes(body)
                if len(encoded) > journal.maximum_record_bytes:
                    raise ValueError("model transport repair audit exceeds journal byte bound")
                if journal._version(db) == 2:
                    obligation = journal._obligation(db, kind, record_key)
                    if obligation is not None and (
                        len(encoded) > obligation["maximum_bytes"]
                        or obligation["value_sha256"] not in (None, digest(body))
                    ):
                        raise ValueError("model transport repair changes record reservation")
                if kind != REPAIR and originals[kind] == encoded:
                    continue
                if kind == REPAIR:
                    prior = journal.get_raw(kind, record_key, db=db)
                    if prior is not None and prior != encoded:
                        raise ValueError("model transport repair audit changed")
                    db.execute(
                        "INSERT OR IGNORE INTO records VALUES (?,?,?)", (kind, record_key, encoded)
                    )
                else:
                    db.execute(
                        "INSERT INTO records VALUES (?,?,?) ON CONFLICT(kind,id) "
                        "DO UPDATE SET body=excluded.body",
                        (kind, record_key, encoded),
                    )
            if journal._version(db) == 2:
                journal._check_capacity(db)
            else:
                count, used, _ = journal._record_capacity(db)
                if count > journal.maximum_records or used > journal.maximum_bytes:
                    raise ValueError("round journal capacity exhausted")

    return repair_model_transport(
        acceptance, history, policy, reason=reason, read_raw=read, replace=replace, report=report
    )
