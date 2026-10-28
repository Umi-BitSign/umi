"""Resolve accepted uploads before sealing, using bounded durable metadata."""

import sqlite3
import time
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_direct_model_selection import (
    SCHEDULING_HOLD_REASONS,
    IssuedModelUpload,
    select_issued_model_uploads,
)
from .open_competition import digest
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_MAX_BYTES = 2 * 1024**2


class _Drain(StrictProtocolModel):
    schema_: Literal["umi-direct-admission-drain-snapshot/1"] = Field(alias="schema")
    cohort_sha256: Hex32
    deadline_sha256: Hex32
    owner_sha256: Hex32
    selected: Annotated[tuple[IssuedModelUpload, ...], Field(max_length=4096)]
    started_ms: Annotated[int, Field(ge=0)]
    resolved: dict[
        Hex32, Literal["admitted", "superseded_by_admitted_sequence", "terminal_failure"]
    ]

    @model_validator(mode="after")
    def bounded_resolution(self):
        keys = [item.upload for item in self.selected]
        if keys != sorted(set(keys)) or not self.resolved.keys() <= set(keys):
            raise ValueError("retained admission snapshot has inconsistent resolution identities")
        return self


class DirectAdmissionDrain:
    """Retain the closed upload snapshot once and revisit unfinished metadata only."""

    def __init__(self, owners):
        self.owners = owners.owners if hasattr(owners, "owners") else dict(owners)
        self._snapshots = {}
        self._table_ready = False

    def _snapshot(self, cohort, db, owner, deadline):
        permitted = {
            row[0]
            for row in db.execute(
                "SELECT request FROM cohort_admission_reservations "
                "WHERE cohort=? AND admitted_ms<?",
                (cohort, deadline.close_new_admissions_at_unix_ms),
            )
        }
        selected = select_issued_model_uploads(
            owner, cohort, deadline=deadline, permitted=permitted
        ).selected
        return _Drain(
            schema="umi-direct-admission-drain-snapshot/1",
            cohort_sha256=cohort,
            deadline_sha256=digest(deadline),
            owner_sha256=digest(owner.config),
            selected=selected,
            started_ms=time.time_ns() // 1_000_000,
            resolved={},
        )

    @staticmethod
    def _persist(db, state, *, initial=False):
        raw = canonical_json_bytes(state)
        if len(raw) > _MAX_BYTES:
            raise ValueError("retained admission snapshot exceeds its metadata bound")
        if initial:
            db.execute(
                "INSERT INTO cohort_admission_drain_snapshots VALUES (?,?)",
                (state.cohort_sha256, raw),
            )
        else:
            changed = db.execute(
                "UPDATE cohort_admission_drain_snapshots SET body=? WHERE cohort=?",
                (raw, state.cohort_sha256),
            ).rowcount
            if changed != 1:
                raise ValueError("retained admission snapshot disappeared; repair required")

    def __call__(self, cohort, db, deadline):
        owner = self.owners.get(cohort)
        if owner is None:
            return self._repair("admission_upload_owner_unavailable")
        try:
            if not self._table_ready:
                db.execute(
                    "CREATE TABLE IF NOT EXISTS cohort_admission_drain_snapshots "
                    "(cohort TEXT PRIMARY KEY,body BLOB NOT NULL)"
                )
                self._table_ready = True
            key = (cohort, digest(deadline), digest(owner.config))
            state = self._snapshots.get(key)
            if state is None:
                row = db.execute(
                    "SELECT substr(body,1,2097153) FROM cohort_admission_drain_snapshots "
                    "WHERE cohort=?",
                    (cohort,),
                ).fetchone()
                if row is None:
                    if owner._mutex.locked():
                        return {
                            "stage": "accepted_upload_admission_drain",
                            "completed": 0,
                            "total": 1,
                            "pending": 1,
                            "blocked_count": 0,
                            "percent": 0,
                            "elapsed_seconds": 0,
                            "reason_code": "reservation_issuance_in_progress",
                            "eta_seconds": None,
                            "eta_basis": "awaiting_inflight_reservation_issuance",
                            "eta_scope": "accepted_upload_admission_drain_only",
                            "stalled_or_retrying": True,
                        }
                    state = self._snapshot(cohort, db, owner, deadline)
                    self._persist(db, state, initial=True)
                else:
                    if len(row[0]) > _MAX_BYTES:
                        raise ValueError("retained admission snapshot exceeds its metadata bound")
                    state = _Drain.model_validate_json(row[0])
                    if (state.cohort_sha256, state.deadline_sha256, state.owner_sha256) != key:
                        raise ValueError(
                            "retained admission snapshot selection changed; repair required"
                        )
                self._snapshots[key] = state
            admitted = {}
            for hotkey, sequence, consent in db.execute(
                "SELECT hotkey,sequence,consent FROM cohort_consents "
                "WHERE cohort=? AND track='model'",
                (cohort,),
            ):
                if hotkey not in admitted or sequence > admitted[hotkey][0]:
                    admitted[hotkey] = (sequence, consent)
            resolved = dict(state.resolved)
            for item in state.selected:
                if item.upload in resolved:
                    continue
                prior = admitted.get(item.hotkey)
                if prior is not None and prior[0] >= item.sequence:
                    resolved[item.upload] = (
                        "admitted"
                        if prior[1] == item.consent
                        else "superseded_by_admitted_sequence"
                    )
                    continue
                attempt = owner._latest_attempt(item.upload)
                if attempt is None:
                    continue
                reservation = owner._signed_reservation(attempt)
                if reservation is None:
                    continue
                status = owner.status(digest(reservation.reservation))
                if status.upload_sha256 != item.upload:
                    raise ValueError("current retained upload status identity differs")
                if (
                    status.hold_reason_code is not None
                    and status.hold_reason_code not in SCHEDULING_HOLD_REASONS
                ):
                    resolved[item.upload] = "terminal_failure"
            if resolved != state.resolved:
                state = state.model_copy(update={"resolved": resolved})
                self._persist(db, state)
                self._snapshots[key] = state
            return self._report(state)
        except (ValueError, OSError, RuntimeError, sqlite3.Error) as error:
            detail = str(error) if type(error) is ValueError else type(error).__name__
            return self._repair("accepted_upload_metadata_repair_required", detail)

    @staticmethod
    def _repair(reason, detail=None):
        return {
            "stage": "accepted_upload_admission_drain",
            "completed": 0,
            "total": 1,
            "pending": 1,
            "blocked_count": 1,
            "repair_required": True,
            "reason_code": reason,
            "repair_detail": detail,
            "percent": 0,
            "elapsed_seconds": 0,
            "eta_seconds": None,
            "eta_basis": "blocked_on_retained_upload_metadata_repair",
            "eta_scope": "accepted_upload_admission_drain_only",
            "stalled_or_retrying": True,
        }

    @staticmethod
    def _report(state):
        total, completed = len(state.selected), len(state.resolved)
        pending = total - completed
        return {
            "stage": "accepted_upload_admission_drain",
            "completed": completed,
            "total": total,
            "pending": pending,
            "failed_resolved": sum(v == "terminal_failure" for v in state.resolved.values()),
            "superseded": sum(
                v == "superseded_by_admitted_sequence" for v in state.resolved.values()
            ),
            "blocked_count": 0,
            "percent": 100 * completed / total if total else 100,
            "elapsed_seconds": max(0, time.time_ns() // 1_000_000 - state.started_ms) / 1000,
            "eta_seconds": None if pending else 0,
            "eta_basis": "awaiting_accepted_upload_completion_or_participation"
            if pending
            else "complete",
            "eta_scope": "accepted_upload_admission_drain_only",
            "stalled_or_retrying": bool(pending),
        }
