"""Private dispatch-profile binding and transactional workload qualification.

The scheduler owns the transaction and storage reservation. This module reads
that same transaction's inventory and applies the pure timing calculation.
Configured budgets are qualification assumptions, not measured by this code.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import TYPE_CHECKING, Any

from .competition_authorization import EndpointAuthorizationPublication, SignedEndpointAuthorization
from .competition_dispatch_capacity import (
    DispatchCapacityPlan,
    DispatchTimingBudget,
    DispatchTimingLimits,
    capacity_job,
    plan_dispatch_capacity,
    timing_profile_sha256,
)
from .competition_dispatch_inbox import publication_names
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

if TYPE_CHECKING:
    import sqlite3

    from .competition_scheduling import AssignmentPublicationJournal
    from .validator_plans import VerifiedFinalizedBlock


def _profile_key(evaluator_hotkey: str) -> str:
    return "dispatch_profile:" + identity(evaluator_hotkey)


def check_dispatch_profile(
    db: sqlite3.Connection, evaluator_hotkey: str, expected: str | None
) -> None:
    """Bind runtime settings inside the caller's active claim write transaction.

    The caller retains the transaction through the claim; this check does not
    commit, roll back, or open another connection.
    """
    row = db.execute(
        "SELECT value FROM metadata WHERE key=?", (_profile_key(evaluator_hotkey),)
    ).fetchone()
    if row is None:
        if expected is not None or db.execute("PRAGMA user_version").fetchone()[0] == 2:
            raise ValueError("dispatch claim requires its configured timing profile")
        return
    profile = json.loads(row[0])
    if expected is None or expected != timing_profile_sha256(profile["limits"], profile["budget"]):
        raise ValueError("dispatch claim timing profile differs from its runtime")


def _bodies(db: sqlite3.Connection, evaluator: str) -> dict[str, EndpointAuthorizationPublication]:
    """Read pending bodies without decoding completed historical bodies.

    ``evaluator`` is normalized; ``db`` is the caller's transaction snapshot.
    """
    bodies = {}
    for (raw,) in db.execute(
        "SELECT p.signed FROM publications p WHERE EXISTS (SELECT 1 FROM assignments a "
        "WHERE a.publication_id=p.id AND a.evaluator=? AND COALESCE("
        "(SELECT kind FROM events e WHERE e.assignment_id=a.id ORDER BY ordinal DESC LIMIT 1),"
        "'') NOT IN ('completed','expired'))",
        (evaluator,),
    ):
        body = SignedEndpointAuthorization.model_validate_json(bytes(raw)).publication
        bodies[digest(body)] = body
    if db.execute("PRAGMA user_version").fetchone()[0] == 2:
        for (raw,) in db.execute(
            "SELECT body FROM reservation_publications p WHERE NOT EXISTS "
            "(SELECT 1 FROM reservation_consumptions c WHERE c.publication_id=p.id)"
        ):
            body = EndpointAuthorizationPublication.model_validate_json(bytes(raw))
            key = digest(body)
            if key in bodies and bodies[key] != body:
                raise ValueError("dispatch workload publication binding changed")
            bodies[key] = body
    return bodies


def _states(db: sqlite3.Connection) -> dict[str, str]:
    """Read latest assignment states from the caller's transaction snapshot."""
    return dict(
        db.execute(
            "SELECT e.assignment_id,e.kind FROM events e WHERE e.ordinal="
            "(SELECT MAX(last.ordinal) FROM events last WHERE last.assignment_id=e.assignment_id)"
        )
    )


def configure_dispatch(
    journal: AssignmentPublicationJournal,
    *,
    evaluator_hotkey: str,
    limits: DispatchTimingLimits,
    budget: DispatchTimingBudget | None,
    publication_directory: str | Path | None = None,
) -> None:
    """Record actual dispatcher settings, refusing changes with unfinished work.

    An omitted budget is compatible with a legacy unqualified dispatcher only.
    Once configured, dropping it cannot silently bypass reserved assumptions.
    This does not migrate a journal or reserve/authorize any work.
    This entry point opens and owns its journal write transaction.
    """
    evaluator = identity(evaluator_hotkey)
    if evaluator not in {identity(e.hotkey) for e in journal.policy.evaluators}:
        raise ValueError("dispatch timing profile belongs to an unknown evaluator")
    limits = DispatchTimingLimits.model_validate_json(canonical_json_bytes(limits))
    if budget is not None:
        budget = DispatchTimingBudget.model_validate_json(canonical_json_bytes(budget))
        if publication_directory is None:
            raise ValueError("dispatch timing profile requires its publication inbox")
        path = Path(publication_directory)
        if (
            not path.is_absolute()
            or path == Path(path.anchor)
            or ".." in path.parts
            or any(p.is_symlink() for p in (path, *path.parents))
        ):
            raise ValueError("dispatch timing profile requires a dedicated absolute inbox")
    profile = (
        None
        if budget is None
        else canonical_json_bytes(
            {
                "limits": limits.model_dump(mode="json"),
                "budget": budget.model_dump(mode="json"),
                "publication_directory": str(path),
            }
        )
    )
    key = _profile_key(evaluator_hotkey)
    with journal._transaction() as db:
        old = db.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        if profile is None:
            if old is not None:
                raise ValueError("dispatcher must retain its configured timing budget")
            return
        if old is not None and old[0] == profile.decode():
            return
        if old is not None:
            states = _states(db)
            for body in _bodies(db, evaluator).values():
                for assignment in body.assignments:
                    if identity(assignment.evaluator_hotkey) != evaluator:
                        continue
                    key_ = capacity_job(body, assignment, journal.legacy_policy).assignment_key
                    if states.get(key_) not in {"completed", "expired"}:
                        raise ValueError("dispatch timing profile has unfinished assigned work")
        db.execute(
            "INSERT INTO metadata VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, profile.decode()),
        )
        journal._capacity(db)


def recover_dispatch_qualification(
    db: sqlite3.Connection, batch_id: str, evaluator_hotkey: str, now: int
) -> dict[str, Any]:
    """Continue the same admitted cohort without admitting its work twice.

    Some assignments may already be dispatched while later authorizations or
    evaluation orders collect signatures. Those claims are neither retried nor
    a reason to block this exact cohort's remaining endorsements. Fresh signing
    still checks the original window and finality; new cohorts requalify fully.

    The caller owns the active write transaction and supplies Unix milliseconds
    in ``now``. This function reads the retained receipt without extending it
    or changing the transaction boundary.
    """
    evaluator = identity(evaluator_hotkey)
    row = db.execute(
        "SELECT document FROM reservation_qualifications WHERE batch_id=? AND evaluator=?",
        (batch_id, evaluator),
    ).fetchone()
    profile = db.execute(
        "SELECT value FROM metadata WHERE key=?", (_profile_key(evaluator_hotkey),)
    ).fetchone()
    if row is None or profile is None:
        raise ValueError("reserved cohort is missing its original timing qualification")
    receipt = json.loads(bytes(row[0]))
    if (
        set(receipt) != {"evaluator", "profile", "plan", "qualified_at_unix_ms"}
        or receipt["evaluator"] != evaluator
        or canonical_json_bytes(receipt) != bytes(row[0])
        or canonical_json_bytes(receipt["profile"]).decode() != profile[0]
    ):
        raise ValueError("reserved cohort timing profile changed")
    plan = DispatchCapacityPlan.model_validate_json(canonical_json_bytes(receipt["plan"]))
    expected = timing_profile_sha256(receipt["profile"]["limits"], receipt["profile"]["budget"])
    if plan.profile_sha256 != expected:
        raise ValueError("reserved cohort timing qualification binding changed")
    started = receipt["qualified_at_unix_ms"]
    if type(started) is not int or not 0 <= started <= now:
        raise ValueError("reserved cohort qualification clock is invalid")
    delivery_close = started + receipt["profile"]["budget"]["publication_delay_ms"]
    if (
        now > delivery_close
        and db.execute(
            "SELECT 1 FROM reservation_publications r WHERE batch_id=? AND NOT EXISTS "
            "(SELECT 1 FROM publications p WHERE p.id=r.id AND p.observed_ms<=?) LIMIT 1",
            (batch_id, delivery_close),
        ).fetchone()
    ):
        raise ValueError("reserved cohort publication delivery allowance elapsed")
    return receipt


def qualify_dispatch(
    journal: AssignmentPublicationJournal,
    db: sqlite3.Connection,
    publications: tuple[EndpointAuthorizationPublication, ...],
    observed: VerifiedFinalizedBlock,
    now: int,
    evaluator_hotkey: str,
) -> dict[str, Any]:
    """Check all local pending work before a new endorsement, in one snapshot.

    An uncompleted claim cannot be distinguished from a live request here, so
    further admission waits for its recorded outcome. It is never retried.
    Elapsed reservations remain charged by the scheduler even when they cannot
    run. The current inbox inventory includes old files a restart would ingest.

    The caller owns the active write transaction and the validated cohort and
    finality observation. ``now`` is Unix milliseconds. The returned receipt
    must be retained in that same transaction; this function does not commit.
    """
    row = db.execute(
        "SELECT value FROM metadata WHERE key=?", (_profile_key(evaluator_hotkey),)
    ).fetchone()
    if row is None:
        raise ValueError("whole-round dispatch capacity profile is not configured")
    profile = json.loads(row[0])
    if (
        set(profile) != {"limits", "budget", "publication_directory"}
        or canonical_json_bytes(profile).decode() != row[0]
    ):
        raise ValueError("dispatch timing profile is not canonical")
    limits = DispatchTimingLimits.model_validate_json(canonical_json_bytes(profile["limits"]))
    budget = DispatchTimingBudget.model_validate_json(canonical_json_bytes(profile["budget"]))
    evaluator = identity(evaluator_hotkey)
    bodies = _bodies(db, evaluator)
    required = {digest(body) for body in publications}
    for body in publications:
        bodies[digest(body)] = body
    states = _states(db)
    jobs = []
    for body_id, body in bodies.items():
        for assignment in body.assignments:
            if identity(assignment.evaluator_hotkey) != evaluator:
                continue
            job = capacity_job(body, assignment, journal.legacy_policy)
            state = states.get(job.assignment_key)
            if state == "dispatched":
                raise ValueError("dispatch capacity awaits the prior claim outcome")
            if state in {"completed", "expired"}:
                continue
            if body_id not in required and (
                now >= job.issue_close_ms or observed.height > job.deadline_block
            ):
                continue
            jobs.append(job)
    active_publications = {job.publication_sha256 for job in jobs}
    fd = os.open(profile["publication_directory"], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        # Retained history is not the inbox. Count only files actually present,
        # plus active bodies whose signed files are still to be delivered.
        names = publication_names(fd)
    finally:
        os.close(fd)
    expected_files = {key + ".json" for key in active_publications}
    additional = sum(name not in expected_files for name in names)
    result = plan_dispatch_capacity(
        jobs,
        limits=limits,
        budget=budget,
        now_ms=now,
        observed_block=observed.height,
        additional_inbox_publications=additional,
    )
    return {
        "evaluator": evaluator,
        "profile": profile,
        "plan": result.model_dump(mode="json", by_alias=True),
        "qualified_at_unix_ms": now,
    }
