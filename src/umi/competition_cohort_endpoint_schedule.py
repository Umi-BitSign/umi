"""Durable endpoint scheduling and complete, locally retained terminal selections.

Every terminal reference replays its signed case decision and retained ancestry.
The aggregate is not a phase-closure certificate, scoring evidence or a reward.
"""

from __future__ import annotations

from typing import Literal

from pydantic import Field

from .competition_cohort_attempt_worker import CohortEndpointAttemptWorker
from .competition_cohort_endpoint import endpoint_obligation_sha256
from .competition_cohort_endpoint_terminal import EndpointTerminalCase as EndpointTerminalCase
from .competition_cohort_endpoint_terminal import (
    EndpointTerminalSelection as EndpointTerminalSelection,
)
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_order_signer import order_slot
from .competition_round_journal import RecordReservation
from .open_competition import digest
from .policy import ScoringPolicy
from .protocol import StrictProtocolModel, canonical_json_bytes


class EndpointScheduledAssignment(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-scheduled-assignment/1"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    transport_policy: ScoringPolicy


class CohortEndpointSchedule:
    def __init__(self, attempts: CohortEndpointAttemptWorker, *, maximum_cases: int = 65536):
        if type(maximum_cases) is not int or not 1 <= maximum_cases <= 1048576:
            raise ValueError("endpoint schedule capacity is outside bounds")
        self.attempts, self.maximum_cases = attempts, maximum_cases
        self.owner = attempts.recovery.journal
        self.journal = self.owner.journal
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_schedule_queue "
                "(obligation TEXT PRIMARY KEY, slot TEXT NOT NULL, case_id TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_schedule_cursor "
                "(name TEXT PRIMARY KEY, position TEXT NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_schedule_case_cursor "
                "(slot TEXT PRIMARY KEY, position TEXT NOT NULL)"
            )

    def _validate(self, value: EndpointScheduledAssignment, slot: str):
        value = EndpointScheduledAssignment.model_validate_json(canonical_json_bytes(value))
        job = self.owner.validate_assignment(value.assignment)
        if (
            order_slot(value.assignment.certificate.order) != slot
            or job.mode != "endpoint_incumbent"
            or job.round.cohort_sha256 not in self.owner.cohorts
            or value.transport_policy.netuid != self.owner.policy.netuid
            or len({case.case_id for case in job.cases}) != len(job.cases)
        ):
            raise ValueError("scheduled endpoint assignment differs from its owner or slot")
        return value, job

    def load(self, slot: str) -> EndpointScheduledAssignment | None:
        raw = self.journal.get("endpoint_schedule_assignment", slot)
        if raw is None:
            return None
        return self._validate(
            EndpointScheduledAssignment.model_validate_json(canonical_json_bytes(raw)), slot
        )[0]

    def register(self, assignment: CohortExecutionAssignment, transport: ScoringPolicy):
        slot = order_slot(assignment.certificate.order)
        value, job = self._validate(
            EndpointScheduledAssignment(
                schema="umi-cohort-endpoint-scheduled-assignment/1",
                assignment=assignment,
                transport_policy=transport,
            ),
            slot,
        )
        old = self.load(slot)
        if old is not None:
            if old != value:
                raise ValueError("endpoint schedule assignment is already selected")
            return old
        # Reserve the terminal receipts before making the assignment runnable.
        self.journal.reserve_records(
            digest(["umi-cohort-endpoint-schedule-reservation/1", slot]),
            (
                RecordReservation(
                    "endpoint_terminal_selection", slot, 1024 + len(job.cases) * 1024
                ),
                *(
                    RecordReservation(
                        "endpoint_terminal_case", endpoint_obligation_sha256(job, c.case_id), 1024
                    )
                    for c in job.cases
                ),
            ),
        )

        def index(db):
            for case in job.cases:
                db.execute(
                    "INSERT INTO endpoint_schedule_queue VALUES (?,?,?)",
                    (endpoint_obligation_sha256(job, case.case_id), slot, case.case_id),
                )
            if (
                db.execute("SELECT COUNT(*) FROM endpoint_schedule_queue").fetchone()[0]
                > self.maximum_cases
            ):
                raise ValueError("endpoint schedule capacity exhausted")

        # The complete case inventory and its assignment commit together.
        self.journal.put_many((("endpoint_schedule_assignment", slot, value),), index=index)
        return value

    def cursor(self, name: str) -> str:
        if name not in {"inbox", "cases"}:
            raise ValueError("unknown endpoint schedule cursor")
        with self.journal.transaction() as db:
            row = db.execute(
                "SELECT position FROM endpoint_schedule_cursor WHERE name=?", (name,)
            ).fetchone()
            return "" if row is None else row[0]

    def advance_inbox(self, position: str):
        with self.journal.transaction() as db:
            db.execute(
                "INSERT INTO endpoint_schedule_cursor VALUES ('inbox',?) "
                "ON CONFLICT(name) DO UPDATE SET position=excluded.position",
                (position,),
            )

    def has_pending_cases(self, slot: str) -> bool:
        """Scheduling hint only; aggregate creation still authenticates every case."""
        with self.journal.read_transaction() as db:
            return (
                db.execute(
                    "SELECT 1 FROM endpoint_schedule_queue q WHERE q.slot=? "
                    "AND NOT EXISTS (SELECT 1 FROM records r "
                    "WHERE r.kind='endpoint_terminal_case' AND r.id=q.obligation) LIMIT 1",
                    (slot,),
                ).fetchone()
                is not None
            )

    def pending(
        self, limit: int, *, exclude: tuple[str, ...] = (), advance: bool = True
    ) -> tuple[tuple[str, str, str], ...]:
        if type(limit) is not int or not 1 <= limit <= 256:
            raise ValueError("endpoint schedule batch is outside bounds")
        if (
            type(exclude) is not tuple
            or len(exclude) > 128
            or any(
                type(slot) is not str
                or len(slot) != 64
                or any(c not in "0123456789abcdef" for c in slot)
                for slot in exclude
            )
        ):
            raise ValueError("endpoint schedule exclusions are outside bounds")
        if len(set(exclude)) != len(exclude):
            raise ValueError("endpoint schedule exclusions must be unique")
        exclusions = (
            " AND q.slot NOT IN (" + ",".join("?" for _ in exclude) + ")" if exclude else ""
        )
        with self.journal.transaction() as db:
            row = db.execute(
                "SELECT position FROM endpoint_schedule_cursor WHERE name='cases'"
            ).fetchone()
            cursor = "" if row is None else row[0]
            # Prioritize durable selected requests over registered assignments
            # still awaiting preparation. The inbox cursor independently revisits
            # those assignments; they cannot displace dispatch/recovery work.
            # Rotate assignments and each assignment's cases independently.
            # A global obligation cursor can repeatedly wrap past all but the
            # first case of an assignment when another has larger hashes.
            rows = db.execute(
                "WITH pending AS (SELECT q.obligation,q.slot,q.case_id,"
                "CASE WHEN q.slot>? THEN 0 ELSE 1 END AS band,"
                "CASE WHEN EXISTS (SELECT 1 FROM records s "
                "WHERE s.kind='endpoint_recovery_selection' AND s.id=q.slot) "
                "THEN 0 ELSE 1 END AS ready_band,"
                "ROW_NUMBER() OVER (PARTITION BY q.slot ORDER BY "
                "CASE WHEN q.obligation>COALESCE(c.position,'') THEN 0 ELSE 1 END,"
                "q.obligation) AS rank "
                "FROM endpoint_schedule_queue q LEFT JOIN endpoint_schedule_case_cursor c "
                "ON c.slot=q.slot WHERE NOT EXISTS "
                "(SELECT 1 FROM records r WHERE r.kind='endpoint_terminal_case' "
                "AND r.id=q.obligation)" + exclusions + ") "
                "SELECT obligation,slot,case_id FROM pending WHERE rank=1 "
                "ORDER BY ready_band,band,slot LIMIT ?",
                (cursor, *exclude, limit),
            ).fetchall()
            if rows and advance:
                db.execute(
                    "INSERT INTO endpoint_schedule_cursor VALUES ('cases',?) "
                    "ON CONFLICT(name) DO UPDATE SET position=excluded.position",
                    (rows[-1][1],),
                )
                db.executemany(
                    "INSERT INTO endpoint_schedule_case_cursor VALUES (?,?) "
                    "ON CONFLICT(slot) DO UPDATE SET position=excluded.position",
                    ((slot, obligation) for obligation, slot, _ in rows),
                )
            return tuple(rows)

    def admit_case(self, row):
        """Advance a case cursor only after its bounded operation is admitted."""
        obligation, slot, _case_id = row
        with self.journal.transaction() as db:
            if (
                db.execute(
                    "SELECT 1 FROM endpoint_schedule_queue "
                    "WHERE obligation=? AND slot=? AND case_id=?",
                    row,
                ).fetchone()
                is None
            ):
                raise ValueError("endpoint admission changed its scheduled case")
            db.execute(
                "INSERT INTO endpoint_schedule_case_cursor VALUES (?,?) "
                "ON CONFLICT(slot) DO UPDATE SET position=excluded.position",
                (slot, obligation),
            )

    def advance_case_scan(self, slot):
        with self.journal.transaction() as db:
            db.execute(
                "INSERT INTO endpoint_schedule_cursor VALUES ('cases',?) "
                "ON CONFLICT(name) DO UPDATE SET position=excluded.position",
                (slot,),
            )

    def reference(self, original_slot: str, case_id: str) -> EndpointTerminalCase | None:
        """Authenticate the selected ancestry, retirement, response and quorum."""
        value = self.load(original_slot)
        if value is None:
            raise FileNotFoundError("endpoint schedule assignment is missing")
        slot, selected, assignment, _ = self.attempts.current(original_slot, case_id)
        if assignment != value.assignment or selected.transport_policy != value.transport_policy:
            raise ValueError("terminal response changed its scheduled assignment")
        certificate = self.attempts.decisions.retained(slot, case_id)
        if certificate is None or certificate.decision.disposition != "retain_response":
            return None
        review = self.attempts.decisions._review(slot, case_id)
        return EndpointTerminalCase(
            case_id=case_id,
            selection_slot=slot,
            selection_sha256=digest(selected),
            review_sha256=digest(review),
            decision_sha256=digest(certificate),
        )

    def retain_case(self, slot: str, case_id: str) -> EndpointTerminalCase:
        value = self.load(slot)
        if value is None:
            raise FileNotFoundError("endpoint schedule assignment is missing")
        job = self.owner.validate_assignment(value.assignment)
        key = endpoint_obligation_sha256(job, case_id)
        reference = self.reference(slot, case_id)
        if reference is None:
            raise ValueError("endpoint case has no certified terminal response")
        self.journal.put("endpoint_terminal_case", key, reference)
        return reference

    def complete(self, slot: str) -> EndpointTerminalSelection | None:
        value = self.load(slot)
        if value is None:
            return None
        job = self.owner.validate_assignment(value.assignment)
        old = self.journal.get("endpoint_terminal_selection", slot)
        cases = []
        for case in job.cases:
            key = endpoint_obligation_sha256(job, case.case_id)
            raw = self.journal.get("endpoint_terminal_case", key)
            if raw is None:
                if old is not None:
                    raise ValueError("complete endpoint selection is missing a terminal case")
                return None
            retained = EndpointTerminalCase.model_validate_json(canonical_json_bytes(raw))
            if retained != self.reference(slot, case.case_id):
                raise ValueError("terminal case differs from its certified retained evidence")
            cases.append(retained)
        terminal = EndpointTerminalSelection(
            schema="umi-cohort-endpoint-terminal-selection/1",
            assignment_sha256=digest(value.assignment),
            job_sha256=digest(job),
            cases=tuple(cases),
        )
        if old is not None:
            if canonical_json_bytes(old) != canonical_json_bytes(terminal):
                raise ValueError("complete endpoint selection changed")
        else:
            self.journal.put("endpoint_terminal_selection", slot, terminal)
        return terminal
