"""Continuous, journaled evaluation and peer agreement for both reward tracks.

Orders require an independent policy quorum. Execution uses the existing CPU
runner; only the evaluator hotkey signs fixed evidence types after reveal.
Private inbox/outbox delivery is external. This worker never submits weights.
"""

from __future__ import annotations

import asyncio
import fcntl
import os
import signal
import sqlite3
import stat
import tempfile
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

from .competition_authorization import SignedEndpointAuthorization
from .competition_chain import CompetitionChainConfig, FinalizedRegistrationProvider
from .competition_endpoint_execution import (
    EndpointPairedEvidence,
    RetainedRevealPulse,
    assemble_endpoint_evidence,
    prepare_incumbent_job,
)
from .competition_evidence import (
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    replay_independent_evaluation,
    sign_evaluator_run,
    verify_evaluator_run,
)
from .competition_execution import (
    EndpointIncumbentJob,
    ExecutionCase,
    ExecutionJournal,
    ModelEvaluationJob,
    ModelExecutionEvidence,
    _evaluation_view,
    common_execution_result,
    execution_boundary,
    execution_key,
    run_endpoint_incumbent,
    run_model_evaluation,
    run_record_from_execution,
    validate_job,
)
from .competition_runner import OfflineCpuRuntime
from .competition_scheduling import AssignmentPublicationJournal
from .drand import QuicknetClient
from .open_competition import (
    AttestedResult,
    CompetitionPolicy,
    EvaluationResult,
    EvaluationRound,
    EvaluationSuite,
    Hotkey,
    ModelBundle,
    Signature,
    SignedSubmission,
    digest,
    identity,
    sign_object,
    verify_signature,
)
from .policy import scoring_policy_hash
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes

MAX_BYTES = 64 * 1024**2


class EvaluationOrder(StrictProtocolModel):
    schema_: Literal["umi-evaluation-order/1"] = Field(alias="schema")
    round: EvaluationRound
    submission: SignedSubmission
    incumbent: ModelBundle
    runtime: OfflineCpuRuntime
    cases: Annotated[tuple[ExecutionCase, ...], Field(min_length=3, max_length=2048)]
    evaluators: Annotated[tuple[Hotkey, ...], Field(min_length=1, max_length=64)]
    publication: SignedEndpointAuthorization | None = None
    no_weight: Literal[True] = True


class SignedEvaluationOrder(StrictProtocolModel):
    order: EvaluationOrder
    signatures: Annotated[tuple[Signature, ...], Field(min_length=1, max_length=64)]


class ExecutionAnnouncement(StrictProtocolModel):
    schema_: Literal["umi-execution-announcement/1"] = Field(alias="schema")
    order_sha256: Hex32
    evaluator_hotkey: Hotkey
    evidence: ModelExecutionEvidence | EndpointPairedEvidence


class SignedExecutionAnnouncement(StrictProtocolModel):
    announcement: ExecutionAnnouncement
    signature: Signature


class EvaluationVote(StrictProtocolModel):
    schema_: Literal["umi-evaluation-vote/1"] = Field(alias="schema")
    order_sha256: Hex32
    result: EvaluationResult
    result_signature: Signature
    run: SignedEvaluatorRunRecord


def _path(value):
    p = Path(value)
    if (
        not p.is_absolute()
        or p == Path(p.anchor)
        or ".." in p.parts
        or "\x00" in value
        or any(x.is_symlink() for x in (p, *p.parents))
    ):
        raise ValueError("evaluator paths must be explicit absolute non-symlink directories")
    return value


Directory = Annotated[str, Field(min_length=1, max_length=4096), AfterValidator(_path)]


class EvaluatorConfig(StrictProtocolModel):
    schema_: Literal["umi-evaluator-config/1"] = Field(alias="schema")
    policy_sha256: Hex32
    chain: CompetitionChainConfig
    evaluator_hotkey: Hotkey
    wallet_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    hotkey_name: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    wallet_path: Directory
    state_directory: Directory
    order_directory: Directory
    reveal_directory: Directory
    peer_directory: Directory
    outbox_directory: Directory
    archive_directory: Directory
    video_directory: Directory
    dispatch_directory: Directory | None = None
    legacy_policy_sha256: Hex32 | None = None
    exchange_origin: str | None = None
    assignment_directory: Directory | None = None
    poll_seconds: Annotated[int, Field(ge=1, le=30)] = 5
    maximum_orders: Annotated[int, Field(ge=1, le=65536)] = 1024
    page_size: Annotated[int, Field(ge=1, le=16)] = 4
    maximum_journal_bytes: Annotated[int, Field(ge=1024, le=16 * 1024**3)] = 1024**3
    no_weight: Literal[True] = True

    @model_validator(mode="after")
    def bindings(self):
        if self.exchange_origin is not None:
            from .competition_client import validate_intake_origin

            validate_intake_origin(self.exchange_origin)
        if self.assignment_directory is not None and (
            self.exchange_origin is None or self.legacy_policy_sha256 is None
        ):
            raise ValueError("assignment delivery requires an exchange and transport policy")
        paths = [
            Path(v).resolve()
            for k, v in self.model_dump().items()
            if (k.endswith("_directory") or k == "wallet_path") and v is not None
        ] + [Path(_path(self.chain.state_directory)).resolve()]
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("evaluator data, wallet and verifier directories must not overlap")
        if (
            self.chain.policy_sha256 != self.policy_sha256
            or self.chain.collection_timeout_seconds > 15
        ):
            raise ValueError("evaluator requires a matching bounded owned-finality provider")
        if (self.dispatch_directory is None) != (self.legacy_policy_sha256 is None):
            raise ValueError("endpoint dispatch journal and transport policy must be paired")
        return self


def order_job(order, evaluator, policy, legacy=None):
    """Validate the same reference-free assignment for each nominated evaluator."""
    fields = {
        k: getattr(order, k) for k in ("round", "submission", "incumbent", "runtime", "cases")
    }
    if order.submission.submission.track == "model":
        if order.publication is not None:
            raise ValueError("model order must not contain endpoint authorization")
        return validate_job(
            ModelEvaluationJob(
                schema="umi-model-evaluation-job/1", evaluator_hotkey=evaluator, **fields
            ),
            policy,
        )
    if order.publication is None or legacy is None:
        raise ValueError("endpoint order requires its signed transport authorization")
    job = prepare_incumbent_job(
        publication=order.publication,
        submission_sha256=digest(order.submission.submission),
        incumbent=order.incumbent,
        runtime=order.runtime,
        evaluator_hotkey=evaluator,
        policy=policy,
        legacy_policy=legacy,
    )
    if any(getattr(job, k) != v for k, v in fields.items()):
        raise ValueError("endpoint order differs from signed transport assignments")
    return job


def validate_order(signed, policy, legacy=None):
    signed = SignedEvaluationOrder.model_validate_json(canonical_json_bytes(signed))
    order = signed.order
    groups = {identity(e.hotkey): e.control_group for e in policy.evaluators}
    keys = [identity(k) for k in order.evaluators]
    if keys != sorted(set(keys)) or any(k not in groups for k in keys):
        raise ValueError("order evaluators must be canonical authorized identities")
    if len({groups[k] for k in keys}) != len(keys) or len(keys) < policy.required_evaluator_groups:
        raise ValueError("order requires distinct independent evaluator groups")
    signers = set()
    signer_groups = set()
    for signature in signed.signatures:
        key = identity(signature.hotkey)
        if key not in groups or key in signers or groups[key] in signer_groups:
            raise ValueError("order signature is unauthorized or repeats a control group")
        verify_signature(order, signature)
        signers.add(key)
        signer_groups.add(groups[key])
    if len(signer_groups) < policy.required_evaluator_groups:
        raise ValueError("order lacks independent quorum signatures")
    for evaluator in order.evaluators:
        order_job(order, evaluator, policy, legacy)
    return signed


def _private(path):
    _path(str(path))
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("evaluator directory must be owned and private")


def _read(path, model):
    _path(str(path))
    _private(path.parent)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("evaluator input must be an owned private regular file")
        if not 1 <= info.st_size <= MAX_BYTES:
            raise ValueError("evaluator input exceeds its byte bound")
        raw = stream.read(MAX_BYTES + 1)
    value = model.model_validate_json(raw)
    if len(raw) != info.st_size or raw != canonical_json_bytes(value):
        raise ValueError("evaluator input must have stable canonical bytes")
    return value


def _publish(path, value):
    raw = canonical_json_bytes(value)
    if len(raw) > MAX_BYTES:
        raise ValueError("evaluator output exceeds its byte bound")
    _private(path.parent)
    lock = _lock_file(path.parent / ".publish.lock")
    try:
        _publish_locked(path, value, raw)
    finally:
        os.close(lock)


def _lock_file(path):
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("evaluator lock must be an owned private regular file")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BaseException:
        os.close(fd)
        raise
    return fd


def _publish_locked(path, value, raw):
    if path.exists() or path.is_symlink():
        if canonical_json_bytes(_read(path, type(value))) != raw:
            raise ValueError("evaluator outbox already contains different bytes")
        return
    fd, name = tempfile.mkstemp(prefix=".pending-", dir=path.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        # All writers hold the dedicated directory lock. Atomic rename publishes
        # one link, including when the process dies immediately afterward.
        os.rename(name, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(name):
            os.unlink(name)


class EvaluatorJournal:
    """Bounded immutable orders/artifacts, including the pre-sign result intent."""

    def __init__(self, config):
        self.config = config
        root = Path(config.state_directory)
        _private(root)
        self.path = root / "evaluator.sqlite3"
        for suffix in ("", "-journal", "-wal", "-shm"):
            p = Path(str(self.path) + suffix)
            if p.is_symlink():
                raise ValueError("evaluator database must not be a symlink")
            if p.exists():
                info = p.stat()
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.getuid()
                    or info.st_mode & 0o077
                ):
                    raise ValueError("evaluator database must be an owned private regular file")
        fd = os.open(self.path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        with self.transaction() as db:
            db.execute("CREATE TABLE IF NOT EXISTS binding (body BLOB NOT NULL)")
            old = db.execute("SELECT body FROM binding").fetchall()
            # Bind all configured paths and identity; an existing journal cannot
            # be used with another archive, transport policy or wallet.
            binding = canonical_json_bytes(
                config.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={
                        "maximum_orders",
                        "maximum_journal_bytes",
                        "page_size",
                        "poll_seconds",
                        *(
                            k
                            for k in ("exchange_origin", "assignment_directory")
                            if getattr(config, k) is None
                        ),
                    },
                )
            )
            if old and (len(old) != 1 or bytes(old[0][0]) != binding):
                raise ValueError("evaluator journal configuration changed")
            if not old:
                db.execute("INSERT INTO binding VALUES (?)", (binding,))
            db.execute(
                "CREATE TABLE IF NOT EXISTS orders (slot TEXT PRIMARY KEY, "
                "body BLOB NOT NULL, conflict INTEGER NOT NULL DEFAULT 0)"
            )
            db.execute(
                "CREATE TABLE IF NOT EXISTS artifacts (slot TEXT NOT NULL, kind TEXT NOT NULL, "
                "body BLOB NOT NULL, PRIMARY KEY(slot,kind))"
            )

    @contextmanager
    def transaction(self):
        db = sqlite3.connect(self.path, isolation_level=None, timeout=5)
        try:
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            yield db
            db.commit()
        except BaseException:
            db.rollback()
            raise
        finally:
            db.close()

    def _capacity(self, db, size):
        used = sum(
            db.execute(f"SELECT COALESCE(SUM(LENGTH(body)),0) FROM {table}").fetchone()[0]
            for table in ("orders", "artifacts")
        )
        if size > MAX_BYTES or used + size > self.config.maximum_journal_bytes:
            raise ValueError("evaluator journal capacity exhausted; preserve its history")

    def admit(self, signed, slot):
        raw = canonical_json_bytes(signed)
        conflict = False
        with self.transaction() as db:
            old = db.execute("SELECT body FROM orders WHERE slot=?", (slot,)).fetchone()
            if old:
                saved = SignedEvaluationOrder.model_validate_json(old[0])
                conflict = saved.order != signed.order
                if conflict:
                    db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
                    # The hold survives even if there is no room for extra bytes.
                    try:
                        self._capacity(db, len(raw))
                    except ValueError:
                        pass
                    else:
                        db.execute(
                            "INSERT OR IGNORE INTO artifacts VALUES (?,?,?)",
                            (slot, "conflict:" + digest(signed.order), raw),
                        )
            else:
                if (
                    db.execute("SELECT COUNT(*) FROM orders").fetchone()[0]
                    >= self.config.maximum_orders
                ):
                    raise ValueError("evaluator order capacity exhausted")
                self._capacity(db, len(raw))
                db.execute("INSERT INTO orders(slot,body) VALUES (?,?)", (slot, raw))
        if conflict:
            raise ValueError("conflicting signed evaluation order retained")

    def orders(self, *, after="", limit=4):
        if type(limit) is not int or not 1 <= limit <= 16:
            raise ValueError("invalid evaluator order page size")
        with self.transaction() as db:
            rows = db.execute(
                "SELECT slot,body,conflict FROM orders WHERE slot>? ORDER BY slot LIMIT ?",
                (after, limit),
            ).fetchall()
            if not rows and after:
                rows = db.execute(
                    "SELECT slot,body,conflict FROM orders ORDER BY slot LIMIT ?", (limit,)
                ).fetchall()
        return [
            (slot, SignedEvaluationOrder.model_validate_json(raw), bool(conflict))
            for slot, raw, conflict in rows
        ]

    def get(self, slot, kind, model):
        with self.transaction() as db:
            row = db.execute(
                "SELECT body FROM artifacts WHERE slot=? AND kind=?", (slot, kind)
            ).fetchone()
        return None if row is None else model.model_validate_json(row[0])

    def put(self, slot, kind, value):
        raw = canonical_json_bytes(value)
        conflict = False
        with self.transaction() as db:
            row = db.execute(
                "SELECT body FROM artifacts WHERE slot=? AND kind=?", (slot, kind)
            ).fetchone()
            if row:
                if bytes(row[0]) != raw:
                    conflict = True
                    db.execute("UPDATE orders SET conflict=1 WHERE slot=?", (slot,))
                    try:
                        self._capacity(db, len(raw))
                    except ValueError:
                        pass
                    else:
                        db.execute(
                            "INSERT OR IGNORE INTO artifacts VALUES (?,?,?)",
                            (slot, "conflict:" + kind + ":" + digest(value), raw),
                        )
            else:
                self._capacity(db, len(raw))
                db.execute("INSERT INTO artifacts VALUES (?,?,?)", (slot, kind, raw))
        if conflict:
            raise ValueError("retained evaluator artifact changed; conflict held")


class ContinuousEvaluator:
    def __init__(self, config, policy, wallet, provider, *, legacy=None, pulse_client=None):
        import bittensor as bt

        self.config = EvaluatorConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.legacy = legacy
        if config.policy_sha256 != digest(self.policy):
            raise ValueError("evaluator policy mismatch")
        if (legacy is None) != (config.legacy_policy_sha256 is None) or (
            legacy is not None and scoring_policy_hash(legacy) != config.legacy_policy_sha256
        ):
            raise ValueError("evaluator transport policy mismatch")
        if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
            config.evaluator_hotkey
        ):
            raise ValueError("evaluator wallet does not hold the named hotkey")
        if identity(config.evaluator_hotkey) not in {identity(e.hotkey) for e in policy.evaluators}:
            raise ValueError("evaluator is absent from the policy")
        self.wallet, self.provider = wallet, provider
        self.pulses = pulse_client or QuicknetClient()
        self.journal = EvaluatorJournal(config)
        self.executions = ExecutionJournal(
            Path(config.state_directory) / "executions",
            policy,
            maximum_jobs=config.maximum_orders,
            maximum_bytes=config.maximum_journal_bytes,
        )
        self.dispatch = (
            None
            if legacy is None
            else AssignmentPublicationJournal(Path(config.dispatch_directory), policy, legacy)
        )
        for name in ("order_directory", "reveal_directory", "peer_directory", "outbox_directory"):
            _private(Path(getattr(config, name)))
        self._cursor = None
        self._seen_orders = set()
        self._order_cursor = ""
        self._tasks = {}
        self._exchange_task = None
        self.exchange = None
        if config.exchange_origin is not None:
            from .competition_exchange import EvaluatorExchangeClient

            self.exchange = EvaluatorExchangeClient(self, config.exchange_origin)

    async def boundary(self):
        return execution_boundary(await self.provider.collect())

    async def signing_head(self, order):
        head = (await self.boundary()).block
        if not order.round.reveal_block <= head <= order.round.valid_through_block:
            raise ValueError("evaluation signing is premature or expired")
        return head

    def ingest_once(self):
        directory = Path(self.config.order_directory)
        names = []
        with os.scandir(directory) as entries:
            for entry in entries:
                if len(names) >= self.config.maximum_orders:
                    raise ValueError("evaluator inbox exceeds its file capacity")
                names.append(entry.name)
        names = sorted(n for n in names if n.endswith(".json") and n not in self._seen_orders)
        if not names:
            return
        after = [n for n in names if self._cursor is None or n > self._cursor]
        name = (after or names)[0]
        self._cursor = name
        signed = validate_order(
            _read(directory / name, SignedEvaluationOrder), self.policy, self.legacy
        )
        if name != digest(signed.order) + ".json":
            raise ValueError("evaluator order filename differs from its body digest")
        if identity(self.config.evaluator_hotkey) not in {
            identity(k) for k in signed.order.evaluators
        }:
            self._seen_orders.add(name)
            return
        job = order_job(signed.order, self.config.evaluator_hotkey, self.policy, self.legacy)
        self.journal.admit(signed, execution_key(job))
        self._seen_orders.add(name)

    async def _execute(self, job):
        fn = (
            run_endpoint_incumbent
            if isinstance(job, EndpointIncumbentJob)
            else run_model_evaluation
        )
        return await fn(
            job=job,
            policy=self.policy,
            archive=Path(self.config.archive_directory),
            videos=Path(self.config.video_directory),
            journal=self.executions,
            boundary_provider=self.boundary,
        )

    def _output(self, order, kind, value):
        name = f"{digest(order)}.{identity(self.config.evaluator_hotkey)}.{kind}.json"
        _publish(Path(self.config.outbox_directory) / name, value)

    def _peer(self, slot, order, hotkey, kind, model):
        name = f"{digest(order)}.{identity(hotkey)}.{kind}.json"
        try:
            return _read(Path(self.config.peer_directory) / name, model)
        except FileNotFoundError:
            saved = self.journal.get(slot, "peer_" + kind + ":" + identity(hotkey), model)
            if saved is None:
                raise
            return saved

    async def advance(self, slot, signed, head):
        order = signed.order
        job = order_job(order, self.config.evaluator_hotkey, self.policy, self.legacy)
        final = self.journal.get(slot, "independent", IndependentEvaluationEvidence)
        if final is not None:
            self._output(order, "independent", final)
            return "complete"
        if head > order.round.valid_through_block:
            return "expired"
        state = self.executions.status(execution_key(job))
        if state is None:
            if head <= order.round.submission_close_block:
                return "scheduled"
            if head > order.round.evaluation_close_block:
                return "expired"
            if not self._tasks:
                self._tasks[slot] = asyncio.create_task(self._execute(job))
            return "executing"
        if state["status"] != "complete":
            return "executing" if slot in self._tasks else "held"
        if head < order.round.reveal_block:
            return "waiting_reveal"
        suite = _read(
            Path(self.config.reveal_directory) / (order.round.suite_sha256 + ".json"),
            EvaluationSuite,
        )
        if digest(suite) != order.round.suite_sha256:
            raise ValueError("revealed suite differs from the committed hash")
        own = self.journal.get(slot, "announcement", SignedExecutionAnnouncement)
        if own is None:
            retained = self.executions.reserve(job)
            assert retained is not None
            if isinstance(job, EndpointIncumbentJob):
                pulses = {}
                for number in sorted(
                    {
                        a.request.reveal_round
                        for a in order.publication.publication.assignments
                        if identity(a.evaluator_hotkey) == identity(job.evaluator_hotkey)
                        and a.submission_sha256 == digest(job.submission.submission)
                    }
                ):
                    key = "pulse:" + str(number)
                    pulse = self.journal.get(slot, key, RetainedRevealPulse)
                    if pulse is None:
                        fetched = await self.pulses.fetch(number)
                        pulse = RetainedRevealPulse(
                            round=fetched.round,
                            randomness=fetched.randomness,
                            signature=fetched.signature,
                        )
                        pulse.verified()
                        if pulse.round != number:
                            raise ValueError("wrong reveal pulse")
                        self.journal.put(slot, key, pulse)
                    pulses[number] = pulse
                retained = assemble_endpoint_evidence(
                    incumbent=retained,
                    journal=self.dispatch,
                    publication_sha256=digest(order.publication.publication),
                    suite=suite,
                    pulses=pulses,
                    current_block=head,
                )
            _evaluation_view(retained, suite, self.policy, head)
            announcement = ExecutionAnnouncement(
                schema="umi-execution-announcement/1",
                order_sha256=digest(order),
                evaluator_hotkey=job.evaluator_hotkey,
                evidence=retained,
            )
            self.journal.put(slot, "announcement_intent", announcement)
            head = await self.signing_head(order)
            own = SignedExecutionAnnouncement(
                announcement=announcement, signature=sign_object(announcement, self.wallet)
            )
            self.journal.put(slot, "announcement", own)
        self._output(order, "execution", own)
        executions = []
        for evaluator in order.evaluators:
            value = (
                own
                if identity(evaluator) == identity(job.evaluator_hotkey)
                else self._peer(slot, order, evaluator, "execution", SignedExecutionAnnouncement)
            )
            body = value.announcement
            verify_signature(body, value.signature)
            if (
                body.order_sha256 != digest(order)
                or identity(body.evaluator_hotkey) != identity(evaluator)
                or identity(value.signature.hotkey) != identity(evaluator)
            ):
                raise ValueError("peer execution signer/order mismatch")
            view = _evaluation_view(body.evidence, suite, self.policy, head)
            if view["job"] != order_job(order, evaluator, self.policy, self.legacy):
                raise ValueError("peer execution differs from the assigned job")
            self.journal.put(slot, "peer_execution:" + identity(evaluator), value)
            executions.append(body.evidence)
        common = common_execution_result(tuple(executions), suite, self.policy, current_block=head)
        record = run_record_from_execution(
            own.announcement.evidence, common, suite, self.policy, current_block=head
        )
        # Reserve exact bytes before either signing operation. A restart may
        # sign these same bytes again, never a second result for this slot.
        self.journal.put(slot, "result_intent", common)
        self.journal.put(slot, "run_intent", record)
        vote = self.journal.get(slot, "vote", EvaluationVote)
        if vote is None:
            head = await self.signing_head(order)
            vote = EvaluationVote(
                schema="umi-evaluation-vote/1",
                order_sha256=digest(order),
                result=common,
                result_signature=sign_object(common, self.wallet),
                run=SignedEvaluatorRunRecord(
                    run=record, signature=sign_evaluator_run(record, self.wallet)
                ),
            )
            self.journal.put(slot, "vote", vote)
        self._output(order, "vote", vote)
        votes = []
        for evaluator, evidence in zip(order.evaluators, executions, strict=True):
            value = (
                vote
                if identity(evaluator) == identity(job.evaluator_hotkey)
                else self._peer(slot, order, evaluator, "vote", EvaluationVote)
            )
            verify_signature(value.result, value.result_signature)
            verify_evaluator_run(value.run)
            expected = run_record_from_execution(
                evidence, common, suite, self.policy, current_block=head
            )
            if (
                value.order_sha256 != digest(order)
                or value.result != common
                or identity(value.result_signature.hotkey) != identity(evaluator)
                or value.run.run != expected
            ):
                raise ValueError("peer vote differs from retained independent execution")
            self.journal.put(slot, "peer_vote:" + identity(evaluator), value)
            votes.append(value)
        final = IndependentEvaluationEvidence(
            schema="umi-competition-independent-evaluation/1",
            attested_result=AttestedResult(
                result=common, signatures=tuple(v.result_signature for v in votes)
            ),
            evaluator_runs=tuple(v.run for v in votes),
        )
        head = await self.signing_head(order)
        replay_independent_evaluation(
            final, order.submission, order.round, suite, self.policy, current_block=head
        )
        self.journal.put(slot, "independent", final)
        self._output(order, "independent", final)
        return "complete"

    async def poll_once(self):
        counts = {"held": 0, "waiting": 0, "complete": 0, "expired": 0, "executing": 0}
        if self.exchange is not None:
            if self._exchange_task is not None and self._exchange_task.done():
                try:
                    self._exchange_task.result()
                except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                    counts["waiting"] += 1
                self._exchange_task = None
            if self._exchange_task is None:
                self._exchange_task = asyncio.create_task(self.exchange.sync_once())
        for slot, task in list(self._tasks.items()):
            if task.done():
                with suppress(Exception, asyncio.CancelledError):
                    task.result()
                del self._tasks[slot]
        for _ in range(self.config.page_size):
            try:
                self.ingest_once()
            except (OSError, ValueError, RuntimeError):
                counts["held"] += 1
        try:
            head = (await self.boundary()).block
        except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
            return {
                "status": "waiting_finality",
                "no_weight": True,
                "chain_submission_authorized": False,
            }
        for slot, signed, conflict in self.journal.orders(
            after=self._order_cursor, limit=self.config.page_size
        ):
            self._order_cursor = slot
            if conflict:
                if slot in self._tasks:
                    self._tasks[slot].cancel()
                counts["held"] += 1
                continue
            try:
                result = await self.advance(slot, signed, head)
                counts[result if result in counts else "waiting"] += 1
            except FileNotFoundError:
                counts["waiting"] += 1
            except (OSError, ValueError, RuntimeError, asyncio.TimeoutError):
                counts["held"] += 1
        return {
            "status": "poll_complete",
            **counts,
            "in_flight": len(self._tasks),
            "no_weight": True,
            "chain_submission_authorized": False,
        }

    async def aclose(self):
        if self._exchange_task is not None:
            self._exchange_task.cancel()
            await asyncio.gather(self._exchange_task, return_exceptions=True)
            self._exchange_task = None
        for task in self._tasks.values():
            task.cancel()
        await asyncio.gather(*self._tasks.values(), return_exceptions=True)
        self._tasks.clear()


async def run_evaluator(config, policy, *, legacy=None, once=False, report=None):
    import bittensor as bt

    config = EvaluatorConfig.model_validate_json(canonical_json_bytes(config))
    _private(Path(config.state_directory))
    lease = _lock_file(Path(config.state_directory) / "evaluator.lock")
    provider = worker = None
    stop, loop, handlers = asyncio.Event(), asyncio.get_running_loop(), []
    try:
        wallet = bt.Wallet(
            name=config.wallet_name, hotkey=config.hotkey_name, path=config.wallet_path
        )
        if identity(bt.resolve_signer(wallet, role="hotkey").ss58_address) != identity(
            config.evaluator_hotkey
        ):
            raise ValueError("evaluator wallet does not hold the named hotkey")
        provider = FinalizedRegistrationProvider(config.chain, policy)
        worker = ContinuousEvaluator(config, policy, wallet, provider, legacy=legacy)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
            handlers.append(sig)
        await provider.start()

        async def cycle():
            result = await worker.poll_once()
            if once:
                await asyncio.gather(*worker._tasks.values(), return_exceptions=True)
                result = {**result, "in_flight": 0}
            return result

        while not stop.is_set():
            result = await _until_stop(cycle(), stop)
            if result is None:
                break
            if report is not None:
                report(result)
            if once:
                return result
            with suppress(asyncio.TimeoutError):
                await asyncio.wait_for(stop.wait(), timeout=config.poll_seconds)
        return {"status": "stopped", "no_weight": True, "chain_submission_authorized": False}
    finally:
        try:
            if worker is not None:
                await worker.aclose()
            if provider is not None:
                await provider.aclose()
        finally:
            for sig in handlers:
                loop.remove_signal_handler(sig)
            os.close(lease)


async def _until_stop(operation, stop):
    task, stopper = asyncio.create_task(operation), asyncio.create_task(stop.wait())
    try:
        done, _ = await asyncio.wait((task, stopper), return_when=asyncio.FIRST_COMPLETED)
        return None if stopper in done else task.result()
    finally:
        task.cancel()
        stopper.cancel()
        await asyncio.gather(task, stopper, return_exceptions=True)
