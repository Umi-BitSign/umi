"""Paired model execution and retained receipts on a wallet-free evaluator host.

The CLI owns its finalized registration provider. Test adapters are in-process
injections only. A local job is not an authenticated publication of a round,
and its receipts are host observations, not portable proofs of execution.
There is no weight submission or automatic hotkey signing in this module.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import sqlite3
import stat
from collections import Counter
from collections.abc import Awaitable, Callable
from contextlib import contextmanager
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator
from typing_extensions import Self

from .competition_artifacts import verify_preserved_bundle
from .competition_chain import OwnedFinalityStale, RegistrationCapture
from .competition_evidence import EvaluatorRunRecord
from .competition_policy_lineage import submission_policy_admitted
from .competition_runner import (
    OfflineCaseExecution,
    OfflineRuntime,
    execute_offline_case,
    validate_case_execution,
    verify_runtime,
)
from .open_competition import (
    DEPENDENCE_POLICY_SCHEMA,
    Block,
    CaseOutput,
    CompetitionPolicy,
    EvaluationResult,
    EvaluationRound,
    EvaluationSuite,
    Hotkey,
    ModelBundle,
    RegistrationSnapshot,
    SignedSubmission,
    Stratum,
    _quality,
    digest,
    has_case_coverage,
    identity,
    validate_bundle_policy,
    validate_suite_profile,
)
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

_MAX_EVIDENCE_BYTES = 208 * 1024**2
_MAX_STEP_BYTES = 48 * 1024
_MAX_RESERVATION_RECEIPT_BYTES = 16 * 1024**2
_FRESH_BOUNDARY_WAIT_SECONDS = 300
_FRESH_BOUNDARY_POLL_SECONDS = 1


async def _fresh_execution_boundary(provider):
    """Wait for a fresh owned head, without rerunning inference or relaxing proof checks."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + _FRESH_BOUNDARY_WAIT_SECONDS
    while True:
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError
        attempt = asyncio.ensure_future(provider())
        try:
            # Nested wait_for can swallow outer cancellation on Python 3.10
            # when the provider completes in the same loop turn. Own the task
            # explicitly so the overall deadline and cancellation both survive.
            done, _ = await asyncio.wait((attempt,), timeout=min(20, remaining))
            if not done or loop.time() >= deadline:
                raise asyncio.TimeoutError
            return attempt.result()
        except OwnedFinalityStale:
            # Only typed staleness is recoverable. Proof/binding faults,
            # provider timeouts and cancellation still fail the job.
            pass
        finally:
            if not attempt.done():
                attempt.cancel()
            await asyncio.gather(attempt, return_exceptions=True)
        remaining = deadline - loop.time()
        if remaining <= 0:
            raise asyncio.TimeoutError
        await asyncio.sleep(min(_FRESH_BOUNDARY_POLL_SECONDS, remaining))


class ExecutionCase(StrictProtocolModel):
    """No references, URL credentials, or caller-selected filesystem paths."""

    case_id: Hex32
    video_sha256: Hex32
    stratum: Stratum


class ModelEvaluationJob(StrictProtocolModel):
    schema_: Literal["umi-model-evaluation-job/1"] = Field(alias="schema")
    round: EvaluationRound
    submission: SignedSubmission
    incumbent: ModelBundle
    runtime: OfflineRuntime
    evaluator_hotkey: Hotkey
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]

    @model_validator(mode="after")
    def unique_cases(self) -> Self:
        if len({c.case_id for c in self.cases}) != len(self.cases):
            raise ValueError("execution case IDs must be unique")
        return self


class EndpointIncumbentJob(ModelEvaluationJob):
    """Execute only the preserved comparator for an endpoint submission."""

    schema_: Literal["umi-endpoint-incumbent-job/1"] = Field(alias="schema")


class RegistrationBoundary(StrictProtocolModel):
    """Reference into the owned provider's retained proof cache."""

    source: Literal["verifier_attested_finality", "verified_finalized_ancestry"]
    block: Block
    block_hash: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    state_root: Annotated[str, Field(pattern=r"^0x[0-9a-f]{64}$")]
    snapshot_sha256: Hex32
    evidence_sha256: Hex32


class ExecutionBoundary(RegistrationBoundary):
    """Execution timing requires a current original observer capture."""

    source: Literal["verifier_attested_finality"]


def registration_boundary(capture: RegistrationCapture) -> RegistrationBoundary:
    """Call only with a capture from the process-owned finalized provider."""
    snapshot = RegistrationSnapshot.model_validate_json(canonical_json_bytes(capture.snapshot))
    p = capture.provenance
    if (
        p.get("schema") != "umi-competition-registration-provenance/1"
        or p.get("evidence_class")
        not in {"verifier_attested_finality", "verified_finalized_ancestry"}
        or p.get("offline_finality_proof") is not False
        or p.get("chain_submission_authorized") is not False
        or p.get("snapshot_sha256") != digest(snapshot)
        or p.get("block") != snapshot.block
        or p.get("block_hash") != snapshot.block_hash
    ):
        raise ValueError("execution boundary has inconsistent registration provenance")
    return RegistrationBoundary(
        source=p["evidence_class"],
        block=snapshot.block,
        block_hash=snapshot.block_hash,
        state_root=p["state_root"],
        snapshot_sha256=digest(snapshot),
        evidence_sha256=p["evidence_sha256"],
    )


def execution_boundary(capture: RegistrationCapture) -> ExecutionBoundary:
    return ExecutionBoundary.model_validate_json(
        canonical_json_bytes(registration_boundary(capture))
    )


class ExecutionStep(StrictProtocolModel):
    role: Literal["candidate", "incumbent"]
    started: ExecutionBoundary
    finished: ExecutionBoundary
    execution: OfflineCaseExecution


class PendingExecutionStep(StrictProtocolModel):
    role: Literal["candidate", "incumbent"]
    started: ExecutionBoundary
    execution: OfflineCaseExecution


class ModelExecutionEvidence(StrictProtocolModel):
    schema_: Literal["umi-model-execution-evidence/1"] = Field(alias="schema")
    job: ModelEvaluationJob
    steps: Annotated[tuple[ExecutionStep, ...], Field(min_length=6, max_length=4096)]
    chain_submission_authorized: Literal[False] = False


class EndpointIncumbentEvidence(StrictProtocolModel):
    schema_: Literal["umi-endpoint-incumbent-evidence/1"] = Field(alias="schema")
    job: EndpointIncumbentJob
    steps: Annotated[tuple[ExecutionStep, ...], Field(min_length=3, max_length=2048)]
    chain_submission_authorized: Literal[False] = False


def validate_job(job: ModelEvaluationJob, policy: CompetitionPolicy) -> ModelEvaluationJob:
    return _validate_job(job, policy, ModelEvaluationJob, "model")


def validate_incumbent_job(job, policy) -> EndpointIncumbentJob:
    return _validate_job(job, policy, EndpointIncumbentJob, "endpoint")


def _validate_job(job, policy, model, track):
    job = model.model_validate_json(canonical_json_bytes(job))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    round_, sub = job.round, job.submission.submission
    if (
        round_.policy_sha256 != digest(policy)
        or not submission_policy_admitted(policy, sub.policy_sha256)
        or sub.accepted_terms_sha256 != policy.contribution_terms_sha256
        or digest(sub) not in round_.roster
        or sub.track != track
        or (track == "model" and sub.model_bundle is None)
        or digest(job.incumbent) != round_.incumbent_model_sha256
        or digest(job.runtime) != round_.runtime_sha256
        or round_.runtime_sha256 != policy.evaluation_runtime_sha256
    ):
        raise ValueError(
            "model execution job has incorrect policy, roster, model or runtime binding"
        )
    if not (
        policy.valid_from_block
        <= round_.submission_close_block
        < round_.evaluation_close_block
        < round_.reveal_block
        <= round_.valid_through_block
        <= policy.valid_through_block
        and sub.valid_from_block <= round_.submission_close_block
        and sub.valid_through_block >= round_.evaluation_close_block
        and policy.valid_from_block <= sub.valid_from_block
        and sub.valid_through_block <= policy.valid_through_block
        and sub.valid_through_block - sub.valid_from_block
        <= policy.maximum_submission_lifetime_blocks
    ):
        raise ValueError("model execution job is outside the policy/submission interval")
    evaluator = identity(job.evaluator_hotkey)
    if evaluator not in {identity(e.hotkey) for e in policy.evaluators} or evaluator == identity(
        sub.hotkey
    ):
        raise ValueError("unauthorized or self-evaluating model execution job")
    if not has_case_coverage(job.cases, policy):
        raise ValueError("model execution job has insufficient stratum coverage")
    video_counts = Counter(case.video_sha256 for case in job.cases)
    if (policy.schema_ != DEPENDENCE_POLICY_SCHEMA and len(video_counts) != len(job.cases)) or any(
        count > 2 for count in video_counts.values()
    ):
        raise ValueError("model execution job has invalid repeated videos")
    if track == "model":
        validate_bundle_policy(sub.model_bundle, policy)
    validate_bundle_policy(job.incumbent, policy)
    return job


def _journal_job(job, policy):
    return (
        validate_incumbent_job(job, policy)
        if isinstance(job, EndpointIncumbentJob)
        else validate_job(job, policy)
    )


def _runs_per_case(job):
    return 1 if isinstance(job, EndpointIncumbentJob) else 2


def execution_key(job: ModelEvaluationJob) -> str:
    """One attempt per evaluator/round/submission, even if assignment bytes change."""
    return execution_slot(job.round, job.submission, job.evaluator_hotkey)


def execution_slot(round_, submission, evaluator_hotkey) -> str:
    """Locate a retained execution without accepting a new assignment."""
    if submission.submission.track not in {"endpoint", "model"}:
        raise ValueError("unsupported execution track")
    return hashlib.sha256(
        (
            b"umi-endpoint-incumbent-execution-key-v1\0"
            if submission.submission.track == "endpoint"
            else b"umi-model-execution-key-v1\0"
        )
        + canonical_json_bytes(
            [
                round_.policy_sha256,
                digest(round_),
                digest(submission.submission),
                identity(evaluator_hotkey),
            ]
        )
    ).hexdigest()


def _incumbent_scope(job: EndpointIncumbentJob) -> str:
    return hashlib.sha256(
        b"umi-round-endpoint-incumbent-v1\0"
        + canonical_json_bytes([digest(job.round), identity(job.evaluator_hotkey)])
    ).hexdigest()


def _incumbent_inputs(job: EndpointIncumbentJob) -> bytes:
    # A round fixes the whole roster and interval. Only the submitting miner
    # differs: neither the comparator nor its reference-free inputs may change.
    inputs = job.model_dump(mode="json", by_alias=True, exclude={"submission"})
    inputs["evaluator_hotkey"] = identity(job.evaluator_hotkey)
    return canonical_json_bytes(inputs)


def _ordered(boundary: ExecutionBoundary, previous: ExecutionBoundary | None, job) -> None:
    boundary = ExecutionBoundary.model_validate_json(canonical_json_bytes(boundary))
    if not job.round.submission_close_block < boundary.block <= job.round.evaluation_close_block:
        raise ValueError("execution boundary is outside the frozen evaluation interval")
    if previous is not None and (
        boundary.block < previous.block
        or (
            boundary.block == previous.block
            and (boundary.block_hash, boundary.state_root, boundary.snapshot_sha256)
            != (previous.block_hash, previous.state_root, previous.snapshot_sha256)
        )
    ):
        raise ValueError("execution boundary rolled back or changed at the same block")


def validate_execution(evidence: ModelExecutionEvidence, policy: CompetitionPolicy) -> None:
    model = (
        EndpointIncumbentEvidence
        if isinstance(evidence, EndpointIncumbentEvidence)
        else ModelExecutionEvidence
    )
    evidence = model.model_validate_json(canonical_json_bytes(evidence))
    job = _journal_job(evidence.job, policy)
    width = _runs_per_case(job)
    if len(evidence.steps) != width * len(job.cases):
        raise ValueError("execution evidence omits assigned runs")
    previous = None
    for index, step in enumerate(evidence.steps):
        case = job.cases[index // width]
        role = "candidate" if width == 2 and index % 2 == 0 else "incumbent"
        expected_model = (
            job.submission.submission.model_revision
            if role == "candidate"
            else digest(job.incumbent)
        )
        if (
            step.role != role
            or step.execution.output.case_id != case.case_id
            or step.execution.video_sha256 != case.video_sha256
            or step.execution.model_sha256 != expected_model
        ):
            raise ValueError("execution step assignment/model binding mismatch")
        validate_case_execution(step.execution, policy)
        _ordered(step.started, previous, job)
        _ordered(step.finished, step.started, job)
        previous = step.finished


def _private_directory(path: Path) -> None:
    if not path.is_absolute() or path == Path(path.anchor) or path.is_symlink():
        raise ValueError("execution journal needs a dedicated absolute directory")
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    info = path.stat()
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("execution journal must be owned by this user and mode 0700")


def _job_allowance(job, raw: bytes) -> int:
    # Preserve the existing receipt budget, including pending observations and
    # JSON escaping of hypotheses, for every consumer of a shared incumbent.
    return len(raw) + _runs_per_case(job) * len(job.cases) * _MAX_STEP_BYTES + 4096


class _ExecutionObligation(StrictProtocolModel):
    execution_key: Hex32
    job_sha256: Hex32
    reserved_bytes: Annotated[int, Field(ge=1, le=16 * 1024**3)]


class _ExecutionReservation(StrictProtocolModel):
    schema_: Literal["umi-execution-capacity-receipt/1"] = Field(alias="schema")
    batch_id: Hex32
    policy_sha256: Hex32
    journal_identity: Hex32
    journal_path: Annotated[str, Field(min_length=1, max_length=4096)]
    generation: Literal[2] = 2
    jobs: Annotated[tuple[_ExecutionObligation, ...], Field(max_length=65536)]
    chain_submission_authorized: Literal[False] = False


_EXECUTION_RESERVATION_SCHEMA = "umi-execution-capacity/1"
_EXECUTION_RESERVATION_TABLES = {
    "reservation_batches": (
        "CREATE TABLE reservation_batches (id TEXT PRIMARY KEY NOT NULL "
        "CHECK(length(id)=64), document BLOB NOT NULL CHECK(typeof(document)='blob'))"
    ),
    "reservation_jobs": (
        "CREATE TABLE reservation_jobs (id TEXT PRIMARY KEY NOT NULL CHECK(length(id)=64), "
        "job BLOB NOT NULL CHECK(typeof(job)='blob'), reserved INTEGER NOT NULL "
        "CHECK(typeof(reserved)='integer' AND reserved>0))"
    ),
}
_EXECUTION_TABLES = (
    "metadata",
    "jobs",
    "steps",
    "pending_steps",
    "endpoint_incumbents",
    *_EXECUTION_RESERVATION_TABLES,
)
_EXECUTION_FENCES = {
    f"generation_{table}_{operation.lower()}": (
        f"CREATE TRIGGER generation_{table}_{operation.lower()} BEFORE {operation} ON {table} "
        "BEGIN SELECT CASE WHEN umi_execution_writer_generation() IS NOT 2 "
        "THEN RAISE(ABORT,'execution writer generation mismatch') END; END"
    )
    for table in _EXECUTION_TABLES
    for operation in ("INSERT", "UPDATE", "DELETE")
}
_EXECUTION_FENCES.update(
    {
        f"immutable_{table}_{operation.lower()}": (
            f"CREATE TRIGGER immutable_{table}_{operation.lower()} BEFORE {operation} ON {table} "
            "BEGIN SELECT RAISE(ABORT,'immutable execution reservation'); END"
        )
        for table, operations in (
            ("reservation_batches", ("UPDATE", "DELETE")),
            ("reservation_jobs", ("UPDATE",)),
        )
        for operation in operations
    }
)


def _execution_batch_id(value: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(c not in "0123456789abcdef" for c in value)
    ):
        raise ValueError("execution reservation batch ID must be a SHA-256 digest")
    return value


class ExecutionJournal:
    """Reserve before execution. An interrupted/failed attempt never auto-runs again.

    Capacity reserves each job's worst-case retained receipt size at admission.
    It bounds logical data, not SQLite/filesystem overhead or archived models.
    """

    def __init__(
        self,
        directory: Path,
        policy: CompetitionPolicy,
        *,
        maximum_jobs: int = 1024,
        maximum_bytes: int = 1024**3,
    ):
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        if type(maximum_jobs) is not int or not 1 <= maximum_jobs <= 65536:
            raise ValueError("invalid execution job capacity")
        if type(maximum_bytes) is not int or not 1024 <= maximum_bytes <= 16 * 1024**3:
            raise ValueError("invalid execution byte capacity")
        self.maximum_jobs, self.maximum_bytes = maximum_jobs, maximum_bytes
        _private_directory(directory)
        self.path = directory / "execution.sqlite3"
        for suffix in ("", "-journal", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.is_symlink():
                raise ValueError("execution database must not be a symlink")
            if p.exists():
                info = p.stat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                ):
                    raise ValueError("execution database must be a private regular file")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        self.path.chmod(0o600)
        with self._transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT)")
            existing = db.execute("SELECT value FROM metadata WHERE key='policy'").fetchone()
            if existing and existing[0] != digest(self.policy):
                raise ValueError("execution journal belongs to another policy")
            db.execute(
                "INSERT OR IGNORE INTO metadata VALUES ('policy', ?)", (digest(self.policy),)
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY, job BLOB NOT NULL, "
                "reserved INTEGER NOT NULL, status TEXT NOT NULL, reason TEXT)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS steps (job_id TEXT NOT NULL, ordinal INTEGER NOT NULL, "
                "body BLOB NOT NULL, PRIMARY KEY(job_id, ordinal))"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS pending_steps "
                "(job_id TEXT PRIMARY KEY, body BLOB NOT NULL)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS endpoint_incumbents "
                "(scope TEXT PRIMARY KEY, source_job TEXT NOT NULL)"
            )
            if self._reservation_enabled(db):
                self._capacity(db)

    @contextmanager
    def _transaction(self):
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.create_function("umi_execution_writer_generation", 0, lambda: 2)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            self._check_generation(db)
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    @staticmethod
    def _reservation_enabled(db):
        return db.execute("PRAGMA user_version").fetchone()[0] == 2

    def _check_generation(self, db):
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            objects = db.execute(
                "SELECT 1 FROM sqlite_master WHERE name GLOB 'reservation_*' "
                "OR name GLOB 'generation_*' OR name GLOB 'immutable_reservation_*' LIMIT 1"
            ).fetchone()
            has_metadata = db.execute(
                "SELECT 1 FROM sqlite_master WHERE type='table' AND name='metadata'"
            ).fetchone()
            marker = (
                has_metadata
                and db.execute(
                    "SELECT 1 FROM metadata WHERE key IN "
                    "('capacity_schema','journal_identity','journal_path') LIMIT 1"
                ).fetchone()
            )
            if objects or marker:
                raise ValueError("execution reservation generation marker was downgraded")
            return
        if version != 2:
            raise ValueError("unsupported execution journal generation")
        metadata = dict(db.execute("SELECT key,value FROM metadata"))
        if (
            metadata.get("capacity_schema") != _EXECUTION_RESERVATION_SCHEMA
            or metadata.get("policy") != digest(self.policy)
            or metadata.get("journal_path") != str(self.path.resolve())
        ):
            raise ValueError("execution reservation journal binding mismatch")
        _execution_batch_id(metadata.get("journal_identity"))
        expected = {**_EXECUTION_RESERVATION_TABLES, **_EXECUTION_FENCES}
        placeholders = ",".join("?" for _ in expected)
        objects = dict(
            db.execute(
                f"SELECT name,sql FROM sqlite_master WHERE name IN ({placeholders})",
                tuple(expected),
            )
        )
        if objects != expected:
            raise ValueError("execution reservation capability schema differs")

    def _enable_reservations(self, db):
        if self._reservation_enabled(db):
            return
        if db.execute("SELECT 1 FROM jobs WHERE status='running' LIMIT 1").fetchone():
            raise ValueError("drain running jobs before execution reservation migration")
        # Historical allowances were computed by the same formula. Do not use
        # malformed or undersized retained data as free capacity during migration.
        for key, raw, reserved, status in db.execute("SELECT id,job,reserved,status FROM jobs"):
            model = (
                EndpointIncumbentJob
                if json.loads(raw).get("schema") == "umi-endpoint-incumbent-job/1"
                else ModelEvaluationJob
            )
            job = _journal_job(model.model_validate_json(raw), self.policy)
            if (
                execution_key(job) != key
                or canonical_json_bytes(job) != bytes(raw)
                or type(reserved) is not int
                or reserved != _job_allowance(job, bytes(raw))
                or status not in {"complete", "failed"}
            ):
                raise ValueError("retained execution job cannot be safely migrated")
        for statement in _EXECUTION_RESERVATION_TABLES.values():
            db.execute(statement)
        db.executemany(
            "INSERT INTO metadata VALUES (?,?)",
            (
                ("capacity_schema", _EXECUTION_RESERVATION_SCHEMA),
                ("journal_identity", os.urandom(32).hex()),
                ("journal_path", str(self.path.resolve())),
            ),
        )
        for statement in _EXECUTION_FENCES.values():
            db.execute(statement)
        db.execute("PRAGMA user_version=2")

    def _usage(self, db):
        count, used = db.execute("SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM jobs").fetchone()
        if self._reservation_enabled(db):
            pending, pending_bytes = db.execute(
                "SELECT COUNT(*),COALESCE(SUM(reserved),0) FROM reservation_jobs"
            ).fetchone()
            metadata = db.execute(
                "SELECT COALESCE(SUM(length(CAST(key AS BLOB))"
                "+length(CAST(value AS BLOB))),0) FROM metadata"
            ).fetchone()[0]
            batches = db.execute(
                "SELECT COALESCE(SUM(length(CAST(id AS BLOB))+length(document)),0) "
                "FROM reservation_batches"
            ).fetchone()[0]
            count, used = count + pending, used + pending_bytes + metadata + batches
        return count, used

    def _capacity(self, db, *, jobs=0, reserved=0):
        count, used = self._usage(db)
        if count + jobs > self.maximum_jobs or used + reserved > self.maximum_bytes:
            raise ValueError(
                "execution journal capacity exhausted; retain history and provision capacity"
            )
        return count, used

    @staticmethod
    def _receipt_value(receipt, raw):
        return {
            **receipt.model_dump(mode="json", by_alias=True),
            "receipt_sha256": hashlib.sha256(raw).hexdigest(),
        }

    def _reservation(self, db, batch_id):
        if not self._reservation_enabled(db):
            return None
        row = db.execute(
            "SELECT document FROM reservation_batches WHERE id=?", (batch_id,)
        ).fetchone()
        if row is None:
            return None
        raw = bytes(row[0])
        if len(raw) > _MAX_RESERVATION_RECEIPT_BYTES:
            raise ValueError("execution reservation receipt exceeds its byte bound")
        receipt = _ExecutionReservation.model_validate_json(raw)
        metadata = dict(db.execute("SELECT key,value FROM metadata"))
        keys = tuple(item.execution_key for item in receipt.jobs)
        if (
            canonical_json_bytes(receipt) != raw
            or receipt.batch_id != batch_id
            or receipt.policy_sha256 != digest(self.policy)
            or receipt.journal_identity != metadata["journal_identity"]
            or receipt.journal_path != str(self.path.resolve())
            or keys != tuple(sorted(set(keys)))
        ):
            raise ValueError("execution reservation receipt binding mismatch")
        for item in receipt.jobs:
            existing = db.execute(
                "SELECT job,reserved FROM jobs WHERE id=?", (item.execution_key,)
            ).fetchone()
            pending = db.execute(
                "SELECT job,reserved FROM reservation_jobs WHERE id=?", (item.execution_key,)
            ).fetchone()
            if (existing is None) == (pending is None):
                raise ValueError("execution reservation obligation is missing or duplicated")
            job_raw, reserved = existing if existing is not None else pending
            if (
                hashlib.sha256(bytes(job_raw)).hexdigest() != item.job_sha256
                or reserved != item.reserved_bytes
            ):
                raise ValueError("execution reservation obligation differs from receipt")
        return self._receipt_value(receipt, raw)

    def reservation(self, batch_id: str) -> dict | None:
        """Read and revalidate immutable capacity evidence without claiming work."""
        batch_id = _execution_batch_id(batch_id)
        with self._transaction() as db:
            if self._reservation_enabled(db):
                self._capacity(db)
            return self._reservation(db, batch_id)

    def reserve_jobs(self, batch_id: str, jobs) -> dict:
        """Reserve a whole exact job cohort without changing execution status.

        This enables the private reservation generation atomically on success.
        It does not authorize execution or make failed/incomplete jobs retryable.
        Overlapping batches share pending job credit, but retain their own receipts.
        An empty cohort is supported and charges its immutable metadata only.
        """
        batch_id = _execution_batch_id(batch_id)
        with self._transaction() as db:
            prior = self._reservation(db, batch_id)
            self._enable_reservations(db)
            count, used = self._capacity(db)
            specs, seen = [], set()
            for index, supplied in enumerate(jobs):
                if index >= 65536:
                    raise ValueError("execution reservation batch exceeds its job bound")
                job = _journal_job(supplied, self.policy)
                raw, key = canonical_json_bytes(job), execution_key(job)
                reserved = _job_allowance(job, raw)
                if key in seen:
                    raise ValueError("execution reservation repeats a job identity")
                seen.add(key)
                spec = _ExecutionObligation(
                    execution_key=key,
                    job_sha256=hashlib.sha256(raw).hexdigest(),
                    reserved_bytes=reserved,
                )
                specs.append(spec)
                existing = db.execute("SELECT job,reserved FROM jobs WHERE id=?", (key,)).fetchone()
                pending = db.execute(
                    "SELECT job,reserved FROM reservation_jobs WHERE id=?", (key,)
                ).fetchone()
                if existing is not None and pending is not None:
                    raise ValueError("execution reservation obligation is duplicated")
                retained = existing if existing is not None else pending
                if retained is not None:
                    if bytes(retained[0]) != raw or retained[1] != reserved:
                        raise ValueError("execution identity already has a different assignment")
                elif prior is not None:
                    raise ValueError("execution reservation retry has an unknown job")
                else:
                    if count + 1 > self.maximum_jobs or used + reserved > self.maximum_bytes:
                        raise ValueError(
                            "execution journal capacity exhausted; "
                            "retain history and provision capacity"
                        )
                    db.execute("INSERT INTO reservation_jobs VALUES (?,?,?)", (key, raw, reserved))
                    count, used = count + 1, used + reserved
            metadata = dict(db.execute("SELECT key,value FROM metadata"))
            receipt = _ExecutionReservation(
                schema="umi-execution-capacity-receipt/1",
                batch_id=batch_id,
                policy_sha256=digest(self.policy),
                journal_identity=metadata["journal_identity"],
                journal_path=str(self.path.resolve()),
                jobs=tuple(sorted(specs, key=lambda item: item.execution_key)),
            )
            raw = canonical_json_bytes(receipt)
            if len(raw) > _MAX_RESERVATION_RECEIPT_BYTES:
                raise ValueError("execution reservation receipt exceeds its byte bound")
            value = self._receipt_value(receipt, raw)
            if prior is not None:
                if value != prior:
                    raise ValueError("execution reservation batch already has different jobs")
                return prior
            db.execute("INSERT INTO reservation_batches VALUES (?,?)", (batch_id, raw))
            self._capacity(db)
            return value

    def status(self, key: str) -> dict | None:
        with self._transaction() as db:
            row = db.execute("SELECT status, reason FROM jobs WHERE id=?", (key,)).fetchone()
            if row is None:
                return None
            count = db.execute("SELECT COUNT(*) FROM steps WHERE job_id=?", (key,)).fetchone()[0]
            pending = db.execute(
                "SELECT COUNT(*) FROM pending_steps WHERE job_id=?", (key,)
            ).fetchone()[0]
        return {
            "execution_key": key,
            "status": row[0],
            "reason": row[1],
            "retained_steps": count,
            "pending_observations": pending,
            "chain_submission_authorized": False,
        }

    def reserve(self, job: ModelEvaluationJob) -> ModelExecutionEvidence | None:
        job = _journal_job(job, self.policy)
        raw, key = canonical_json_bytes(job), execution_key(job)
        reserved = _job_allowance(job, raw)
        with self._transaction() as db:
            existing = db.execute("SELECT job, status FROM jobs WHERE id=?", (key,)).fetchone()
            if existing:
                if bytes(existing[0]) != raw:
                    raise ValueError("execution identity already has a different assignment")
                if existing[1] != "complete":
                    raise ValueError(
                        "prior execution is incomplete or failed; automatic rerun refused"
                    )
                return self._evidence(db, job)
            pending = None
            if self._reservation_enabled(db):
                pending = db.execute(
                    "SELECT job,reserved FROM reservation_jobs WHERE id=?", (key,)
                ).fetchone()
            if pending is not None:
                if bytes(pending[0]) != raw or pending[1] != reserved:
                    raise ValueError("execution identity already has a different assignment")
                self._capacity(db)
                db.execute("DELETE FROM reservation_jobs WHERE id=?", (key,))
            else:
                self._capacity(db, jobs=1, reserved=reserved)
            db.execute("INSERT INTO jobs VALUES (?,?,?,'running',NULL)", (key, raw, reserved))
        return None

    def append(self, job: ModelEvaluationJob, step: ExecutionStep) -> None:
        raw = canonical_json_bytes(step)
        if len(raw) > _MAX_STEP_BYTES:
            raise ValueError("execution step exceeds reserved receipt capacity")
        with self._transaction() as db:
            key = execution_key(job)
            row = db.execute("SELECT job, status FROM jobs WHERE id=?", (key,)).fetchone()
            if row is None or row[1] != "running" or bytes(row[0]) != canonical_json_bytes(job):
                raise ValueError("execution job is not reserved for these inputs")
            index = db.execute("SELECT COUNT(*) FROM steps WHERE job_id=?", (key,)).fetchone()[0]
            if index >= _runs_per_case(job) * len(job.cases):
                raise ValueError("execution has too many steps")
            pending = db.execute("SELECT body FROM pending_steps WHERE job_id=?", (key,)).fetchone()
            expected = PendingExecutionStep(
                role=step.role, started=step.started, execution=step.execution
            )
            if pending is None or bytes(pending[0]) != canonical_json_bytes(expected):
                raise ValueError("finished step does not match its retained observation")
            db.execute("INSERT INTO steps VALUES (?,?,?)", (key, index, raw))
            db.execute("DELETE FROM pending_steps WHERE job_id=?", (key,))

    def reuse_endpoint_incumbent(
        self, job: EndpointIncumbentJob
    ) -> EndpointIncumbentEvidence | None:
        """Reserve one comparator attempt per round, or retain its exact receipts.

        Called after reserving this submission, before any external operation.
        Failed/incomplete source runs hold all consumers; a different miner cannot
        cause another attempt. Existing per-submission evidence remains readable.
        Older rounds without this reservation must finish under their old code or
        be replaced by a new round, never retroactively select a winning attempt.
        """
        job = validate_incumbent_job(job, self.policy)
        key, raw, scope = execution_key(job), canonical_json_bytes(job), _incumbent_scope(job)
        with self._transaction() as db:
            own = db.execute("SELECT job, status FROM jobs WHERE id=?", (key,)).fetchone()
            if own is None or own[1] != "running" or bytes(own[0]) != raw:
                raise ValueError("incumbent consumer is not reserved for these inputs")
            if (
                db.execute("SELECT 1 FROM steps WHERE job_id=?", (key,)).fetchone()
                or db.execute("SELECT 1 FROM pending_steps WHERE job_id=?", (key,)).fetchone()
            ):
                raise ValueError("incumbent consumer already has execution observations")
            cached = db.execute(
                "SELECT source_job FROM endpoint_incumbents WHERE scope=?", (scope,)
            ).fetchone()
            if cached is None:
                # Never adopt an arbitrary pre-upgrade run or retry a failed one
                # just because its round predates the shared reservation table.
                for (old_raw,) in db.execute("SELECT job FROM jobs WHERE id!=?", (key,)):
                    if json.loads(old_raw).get("schema") != "umi-endpoint-incumbent-job/1":
                        continue
                    old = validate_incumbent_job(
                        EndpointIncumbentJob.model_validate_json(old_raw), self.policy
                    )
                    if _incumbent_scope(old) == scope:
                        raise ValueError("round has legacy incumbent attempts; use a new round")
                db.execute("INSERT INTO endpoint_incumbents VALUES (?,?)", (scope, key))
                return None
            source_key = cached[0]
            source = db.execute("SELECT job, status FROM jobs WHERE id=?", (source_key,)).fetchone()
            if source is None:
                raise ValueError("shared incumbent source is missing")
            source_job = validate_incumbent_job(
                EndpointIncumbentJob.model_validate_json(source[0]), self.policy
            )
            if (
                execution_key(source_job) != source_key
                or _incumbent_scope(source_job) != scope
                or _incumbent_inputs(source_job) != _incumbent_inputs(job)
            ):
                raise ValueError("shared incumbent assignment conflicts with the reserved round")
            if source[1] != "complete":
                raise ValueError(
                    "shared incumbent is incomplete or failed; automatic rerun refused"
                )
            evidence = self._evidence(db, source_job)
            # Keep the original owned boundaries and runtime observations. Do not
            # relabel their times as a new execution or reuse across evaluators.
            for index, step in enumerate(evidence.steps):
                step_raw = canonical_json_bytes(step)
                if len(step_raw) > _MAX_STEP_BYTES:
                    raise ValueError("shared incumbent exceeds reserved receipt capacity")
                db.execute("INSERT INTO steps VALUES (?,?,?)", (key, index, step_raw))
            retained = self._evidence(db, job)
            db.execute("UPDATE jobs SET status='complete' WHERE id=?", (key,))
            return retained

    def observe(self, job: ModelEvaluationJob, pending: PendingExecutionStep) -> None:
        """Retain stdout before awaiting another network/finality operation."""
        pending = PendingExecutionStep.model_validate_json(canonical_json_bytes(pending))
        validate_case_execution(pending.execution, self.policy)
        raw = canonical_json_bytes(pending)
        if len(raw) > _MAX_STEP_BYTES:
            raise ValueError("execution observation exceeds reserved receipt capacity")
        key = execution_key(job)
        with self._transaction() as db:
            row = db.execute("SELECT job, status FROM jobs WHERE id=?", (key,)).fetchone()
            if row is None or row[1] != "running" or bytes(row[0]) != canonical_json_bytes(job):
                raise ValueError("execution job is not reserved for these inputs")
            index = db.execute("SELECT COUNT(*) FROM steps WHERE job_id=?", (key,)).fetchone()[0]
            if index >= _runs_per_case(job) * len(job.cases):
                raise ValueError("execution has too many observations")
            db.execute("INSERT INTO pending_steps VALUES (?,?)", (key, raw))

    def _evidence(self, db, job) -> ModelExecutionEvidence:
        if db.execute(
            "SELECT 1 FROM pending_steps WHERE job_id=?", (execution_key(job),)
        ).fetchone():
            raise ValueError("execution still has an observation without a finished boundary")
        rows = db.execute(
            "SELECT body FROM steps WHERE job_id=? ORDER BY ordinal", (execution_key(job),)
        ).fetchall()
        model = (
            EndpointIncumbentEvidence
            if isinstance(job, EndpointIncumbentJob)
            else ModelExecutionEvidence
        )
        evidence = model(
            schema=(
                "umi-endpoint-incumbent-evidence/1"
                if isinstance(job, EndpointIncumbentJob)
                else "umi-model-execution-evidence/1"
            ),
            job=job,
            steps=tuple(ExecutionStep.model_validate_json(bytes(row[0])) for row in rows),
        )
        validate_execution(evidence, self.policy)
        if len(canonical_json_bytes(evidence)) > _MAX_EVIDENCE_BYTES:
            raise ValueError("complete execution evidence exceeds its byte bound")
        return evidence

    def complete(self, job: ModelEvaluationJob) -> ModelExecutionEvidence:
        with self._transaction() as db:
            evidence = self._evidence(db, job)
            changed = db.execute(
                "UPDATE jobs SET status='complete' WHERE id=? AND status='running' AND job=?",
                (execution_key(job), canonical_json_bytes(job)),
            ).rowcount
            if changed != 1:
                raise ValueError("execution job is not in the running state")
        return evidence

    def fail(self, job: ModelEvaluationJob, *, cancelled: bool = False) -> None:
        with self._transaction() as db:
            db.execute(
                "UPDATE jobs SET status='failed', reason=? WHERE id=? AND status='running'",
                (
                    "cancelled" if cancelled else "infrastructure_or_binding_failure",
                    execution_key(job),
                ),
            )


def read_case_video(directory: Path, sha256: str, maximum: int) -> bytes:
    # Content-addressed filenames only. The directory is operator-owned and
    # never mounted into a model; the runner mounts a separate one-video copy.
    fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        video_fd = os.open(sha256 + ".mp4", os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW, dir_fd=fd)
        with os.fdopen(video_fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > maximum:
                raise ValueError("evaluation video is not a bounded single-link regular file")
            data = stream.read(maximum + 1)
    finally:
        os.close(fd)
    if len(data) > maximum or hashlib.sha256(data).hexdigest() != sha256:
        raise ValueError("evaluation video differs from its assigned digest")
    return data


async def run_model_evaluation(
    *,
    job: ModelEvaluationJob,
    policy: CompetitionPolicy,
    archive: Path,
    videos: Path,
    journal: ExecutionJournal,
    boundary_provider: Callable[[], Awaitable[ExecutionBoundary]],
    prepare_boundaries: Callable[[], Awaitable[None]] | None = None,
) -> ModelExecutionEvidence:
    return await _run_evaluation(
        job=validate_job(job, policy),
        policy=policy,
        archive=archive,
        videos=videos,
        journal=journal,
        boundary_provider=boundary_provider,
        prepare_boundaries=prepare_boundaries,
    )


async def run_endpoint_incumbent(
    *,
    job: EndpointIncumbentJob,
    policy: CompetitionPolicy,
    archive: Path,
    videos: Path,
    journal: ExecutionJournal,
    boundary_provider: Callable[[], Awaitable[ExecutionBoundary]],
    prepare_boundaries: Callable[[], Awaitable[None]] | None = None,
) -> EndpointIncumbentEvidence:
    """Run the actual archived baseline before reveal, without contacting a miner."""
    return await _run_evaluation(
        job=validate_incumbent_job(job, policy),
        policy=policy,
        archive=archive,
        videos=videos,
        journal=journal,
        boundary_provider=boundary_provider,
        prepare_boundaries=prepare_boundaries,
    )


async def _run_evaluation(
    *,
    job,
    policy,
    archive,
    videos,
    journal,
    boundary_provider,
    prepare_boundaries,
):
    """Sequential candidate/incumbent execution, with no references or signer.

    Reserve first, retain each invocation before the next one, and refuse to
    rerun after ambiguous failure. Recovery of a complete job uses its exact
    persisted evidence even when finality or the model archive is unavailable.
    """
    job = _journal_job(job, policy)
    if digest(journal.policy) != digest(policy):
        raise ValueError("execution journal policy mismatch")
    saved = journal.reserve(job)
    if saved is not None:
        return saved
    previous = None

    async def boundary():
        nonlocal previous
        observed = await _fresh_execution_boundary(boundary_provider)
        observed = ExecutionBoundary.model_validate_json(canonical_json_bytes(observed))
        _ordered(observed, previous, job)
        previous = observed
        return observed

    try:
        if isinstance(job, EndpointIncumbentJob):
            shared = journal.reuse_endpoint_incumbent(job)
            if shared is not None:
                return shared
        if prepare_boundaries is not None:
            await prepare_boundaries()
        await verify_runtime(job.runtime, policy)
        candidate = job.submission.submission.model_bundle
        if not isinstance(job, EndpointIncumbentJob):
            assert candidate is not None
            verify_preserved_bundle(candidate, archive, policy)
        verify_preserved_bundle(job.incumbent, archive, policy)
        runs = (
            (("incumbent", job.incumbent),)
            if isinstance(job, EndpointIncumbentJob)
            else (("candidate", candidate), ("incumbent", job.incumbent))
        )
        for case in job.cases:
            video = read_case_video(videos, case.video_sha256, job.runtime.maximum_video_bytes)
            for role, model in runs:
                started = await boundary()
                record = await execute_offline_case(
                    bundle=model,
                    archive=archive,
                    runtime=job.runtime,
                    policy=policy,
                    case_id=case.case_id,
                    video_sha256=case.video_sha256,
                    video=video,
                )
                journal.observe(
                    job, PendingExecutionStep(role=role, started=started, execution=record)
                )
                finished = await boundary()
                journal.append(
                    job,
                    ExecutionStep(role=role, started=started, finished=finished, execution=record),
                )
        return journal.complete(job)
    except BaseException as error:
        journal.fail(job, cancelled=isinstance(error, asyncio.CancelledError))
        raise


def _outputs(evidence, role: str) -> tuple[CaseOutput, ...]:
    return tuple(s.execution.output for s in evidence.steps if s.role == role)


def validate_revealed_execution(evidence, suite, policy, *, current_block: int) -> None:
    view = revealed_execution_observations(evidence, suite, policy, current_block=current_block)
    _quality(view["candidate"], suite, policy)
    _quality(view["incumbent"], suite, policy, incumbent=True)


def revealed_execution_observations(evidence, suite, policy, *, current_block: int):
    """Validate complete retained observations without assigning a quality score.

    Infrastructure failures remain observable for an explicit void review. This
    function never makes them eligible for scoring or model promotion.
    """
    evidence = ModelExecutionEvidence.model_validate_json(canonical_json_bytes(evidence))
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    validate_execution(evidence, policy)
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    validate_suite_profile(suite, policy)
    job = evidence.job
    if (
        type(current_block) is not int
        or not job.round.reveal_block <= current_block <= job.round.valid_through_block
    ):
        raise ValueError("execution scoring is premature or expired")
    expected = tuple(
        ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
        for c in suite.cases
    )
    if (
        digest(suite) != job.round.suite_sha256
        or suite.policy_sha256 != digest(policy)
        or job.cases != expected
    ):
        raise ValueError("execution assignment differs from the committed revealed suite")
    return {
        "job": job,
        "candidate": _outputs(evidence, "candidate"),
        "incumbent": _outputs(evidence, "incumbent"),
        "started_block": evidence.steps[0].started.block,
        "finished_block": evidence.steps[-1].finished.block,
        "evidence_sha256": digest(evidence),
    }


def common_execution_result(
    evidence: tuple[ModelExecutionEvidence, ...],
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    current_block: int,
) -> EvaluationResult:
    """Propose one common transcript; this function supplies no signatures.

    Exact output/status and resource eligibility must agree. The common timing
    is the maximum measured time per case and completion block across runs.
    Each evaluator must later check its own retained run before co-signing.
    """
    if not 1 <= len(evidence) <= 64:
        raise ValueError("invalid execution aggregation size")
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    views = tuple(_evaluation_view(e, suite, policy, current_block) for e in evidence)
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    seen = set()
    first = views[0]["job"]
    for item in views:
        job = item["job"]
        group = groups[identity(job.evaluator_hotkey)]
        if group in seen or (job.round, job.submission, job.incumbent, job.runtime, job.cases) != (
            first.round,
            first.submission,
            first.incumbent,
            first.runtime,
            first.cases,
        ):
            raise ValueError("duplicate evaluator group or mismatched execution assignments")
        seen.add(group)
    if len(seen) < policy.required_evaluator_groups:
        raise ValueError("insufficient independent execution groups")

    def agreed(role):
        runs = [item[role] for item in views]
        merged = []
        for outputs in zip(*runs, strict=True):

            def observation(o):
                return (
                    o.case_id,
                    o.status,
                    o.hypothesis,
                    o.status == "ok"
                    and o.elapsed_ms <= policy.maximum_inference_ms
                    and len(o.hypothesis.encode("utf-8")) <= policy.maximum_output_bytes,
                )

            if len({observation(o) for o in outputs}) != 1:
                raise ValueError("independent executions disagree; cannot propose a common result")
            merged.append(
                outputs[0].model_copy(update={"elapsed_ms": max(o.elapsed_ms for o in outputs)})
            )
        return tuple(merged)

    return EvaluationResult(
        schema="umi-competition-result/1",
        round_sha256=digest(first.round),
        submission_sha256=digest(first.submission.submission),
        model_revision=first.submission.submission.model_revision,
        incumbent_model_sha256=digest(first.incumbent),
        runtime_sha256=digest(first.runtime),
        finished_block=max(item["finished_block"] for item in views),
        candidate=agreed("candidate"),
        incumbent=agreed("incumbent"),
    )


def run_record_from_execution(
    evidence: ModelExecutionEvidence,
    common: EvaluationResult,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
    *,
    current_block: int,
) -> EvaluatorRunRecord:
    """Validate the proposed common result against one evaluator's retained run."""
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    view = _evaluation_view(evidence, suite, policy, current_block)
    common = EvaluationResult.model_validate_json(canonical_json_bytes(common))
    job = view["job"]
    if (
        common.round_sha256 != digest(job.round)
        or common.submission_sha256 != digest(job.submission.submission)
        or common.model_revision != job.submission.submission.model_revision
        or common.incumbent_model_sha256 != digest(job.incumbent)
        or common.runtime_sha256 != digest(job.runtime)
        or not view["finished_block"] <= common.finished_block <= job.round.evaluation_close_block
    ):
        raise ValueError("common result does not bind this completed execution")
    for role in ("candidate", "incumbent"):
        own = view[role]
        proposed = getattr(common, role)
        if len(own) != len(proposed):
            raise ValueError("common result has incomplete output coverage")
        for left, right in zip(own, proposed, strict=True):
            if (left.case_id, left.status, left.hypothesis) != (
                right.case_id,
                right.status,
                right.hypothesis,
            ) or right.elapsed_ms < left.elapsed_ms:
                raise ValueError("common result disagrees with retained execution")
        if _quality(own, suite, policy, incumbent=role == "incumbent") != _quality(
            proposed, suite, policy, incumbent=role == "incumbent"
        ):
            raise ValueError("common result changes resource eligibility or score")
        for left, right in zip(own, proposed, strict=True):
            if (left.status == "ok" and left.elapsed_ms <= policy.maximum_inference_ms) != (
                right.status == "ok" and right.elapsed_ms <= policy.maximum_inference_ms
            ):
                raise ValueError("common result changes per-case resource eligibility")
    return EvaluatorRunRecord(
        schema="umi-competition-evaluator-run/1",
        evaluator_hotkey=job.evaluator_hotkey,
        policy_sha256=digest(policy),
        round_sha256=digest(job.round),
        submission_sha256=digest(job.submission.submission),
        common_result_sha256=digest(common),
        suite_sha256=digest(suite),
        model_revision=job.submission.submission.model_revision,
        incumbent_model_sha256=digest(job.incumbent),
        runtime_sha256=digest(job.runtime),
        started_block=view["started_block"],
        finished_block=view["finished_block"],
        candidate=view["candidate"],
        incumbent=view["incumbent"],
        execution_evidence_sha256=view["evidence_sha256"],
    )


def _evaluation_view(evidence, suite, policy, current_block):
    from .competition_endpoint_execution import EndpointPairedEvidence, endpoint_evaluation_view

    if isinstance(evidence, EndpointPairedEvidence):
        return endpoint_evaluation_view(evidence, suite, policy, current_block=current_block)
    evidence = ModelExecutionEvidence.model_validate_json(canonical_json_bytes(evidence))
    validate_revealed_execution(evidence, suite, policy, current_block=current_block)
    return {
        "job": evidence.job,
        "candidate": _outputs(evidence, "candidate"),
        "incumbent": _outputs(evidence, "incumbent"),
        "started_block": evidence.steps[0].started.block,
        "finished_block": evidence.steps[-1].finished.block,
        "evidence_sha256": digest(evidence),
    }
