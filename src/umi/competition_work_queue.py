"""Wallet-free preparation, quorum collection and immutable work delivery.

The round coordinator supplies a verified work plan from its protected suite.
Owned providers determine signing boundaries. A persisted endpoint statement
keeps its original issuance even after a crash or a missed publication window.
"""

from __future__ import annotations

import asyncio
import time
from functools import partial
from pathlib import Path

from .competition_authorization import SignedEndpointAuthorization, validate_publication
from .competition_evaluator import EvaluationOrder, SignedEvaluationOrder, validate_order
from .competition_execution import execution_boundary
from .competition_round_journal import RoundJournal
from .competition_work_plans import (
    _verified_transport_block,
    endpoint_proposals,
    evaluation_order_proposals,
    validate_work_plan,
)
from .competition_work_signing import (
    WorkEndorsement,
    WorkStatement,
    _StatementValidator,
    statement_slot,
)
from .competition_work_signing import validate_statement as validate_statement
from .concurrency import run_owned_thread
from .open_competition import digest, identity, verify_signature
from .policy import scoring_policy_hash
from .private_files import ensure_private_directory as _private
from .private_files import publish_private_model as _publish
from .private_files import read_private_model
from .protocol import canonical_json_bytes
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div


def issue_close_ms(statement, legacy):
    body = statement.body
    if isinstance(body, EvaluationOrder):
        body = None if body.publication is None else body.publication.publication
    if body is None:
        return None
    if legacy is None:
        raise ValueError("endpoint statement needs a transport policy")
    margin = ceil_div(legacy.clock.response_window_seconds, 3)
    return min(
        QUICKNET_GENESIS_MS + (a.request.response_close_round - margin - 1) * QUICKNET_PERIOD_MS
        for a in body.assignments
    )


def verify_work_endorsement(vote, statement):
    vote = WorkEndorsement.model_validate_json(canonical_json_bytes(vote))
    if vote.statement_sha256 != digest(statement) or identity(vote.signature.hotkey) not in {
        identity(k) for k in statement.plan.evaluators
    }:
        raise ValueError("work endorsement signer or statement binding mismatch")
    verify_signature(statement.body, vote.signature)
    return vote


class WorkQueue:
    def __init__(
        self,
        root,
        policy,
        provider,
        *,
        order_directory,
        publication_directory,
        minimum_issue_ms,
        legacy=None,
        transport_provider=None,
        maximum_orders=1024,
        maximum_bytes=1024**3,
    ):
        if type(minimum_issue_ms) is not int or not 1 <= minimum_issue_ms <= 300_000:
            raise ValueError("work queue requires an explicit bounded issue margin")
        paths = tuple(Path(p) for p in (root, order_directory, publication_directory))
        if any(
            a == b or a in b.parents or b in a.parents
            for i, a in enumerate(paths)
            for b in paths[i + 1 :]
        ):
            raise ValueError("work queue state and delivery directories must be separate")
        for p in paths:
            _private(p)
        self.policy, self.provider = policy, provider
        self.legacy, self.transport_provider = legacy, transport_provider
        self.order_directory, self.publication_directory = paths[1:]
        self.minimum_issue_ms = minimum_issue_ms
        self.journal = RoundJournal(
            paths[0],
            {
                "schema": "umi-work-queue/1",
                "policy": digest(policy),
                "legacy": None if legacy is None else scoring_policy_hash(legacy),
                "order_directory": str(paths[1]),
                "publication_directory": str(paths[2]),
                "minimum_issue_ms": minimum_issue_ms,
            },
            maximum_rounds=maximum_orders,
            maximum_bytes=maximum_bytes,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS work_index ("
                "sequence INTEGER PRIMARY KEY AUTOINCREMENT, slot TEXT UNIQUE NOT NULL, "
                "statement TEXT UNIQUE NOT NULL, plan TEXT NOT NULL, "
                "opens INTEGER NOT NULL, closes INTEGER NOT NULL, issue_close INTEGER)"
            )
        self.serial = asyncio.Lock()

    async def _head(self):
        head = execution_boundary(await self.provider.collect())
        if not self.policy.valid_from_block <= head.block <= self.policy.valid_through_block:
            raise ValueError("work queue policy is not current")
        await run_owned_thread(self.journal.observe, head.block)
        return head.block

    def _open(self, statement, block):
        round_ = statement.body.round
        close = issue_close_ms(statement, self.legacy)
        return round_.submission_close_block <= block < round_.evaluation_close_block and (
            close is None or time.time_ns() // 1_000_000 + self.minimum_issue_ms < close
        )

    def _retain(self, statement):
        return self._retain_many((statement,))[0]

    def _retain_many(self, statements, *, new_block=None):
        indexes = []
        validator = _StatementValidator(self.policy, self.legacy)

        def records():
            for statement in statements:
                statement = validator.validate(statement)
                metadata = self._index_record(statement)
                indexes.append(metadata)
                yield "intent", metadata[0], statement

        def index(db):
            # Serialization and SQLite lock waits can consume the issue margin.
            # Expired retained work may still repair its unchanged index.
            if new_block is not None:
                now = time.time_ns() // 1_000_000 + self.minimum_issue_ms
                if any(
                    not opens <= new_block < closes or (issue is not None and now >= issue)
                    for _, _, _, opens, closes, issue in indexes
                ):
                    raise ValueError("work preparation elapsed during batch retention")
            self._write_indexes(db, indexes)

        self.journal.put_many(records(), index=index)
        return tuple(row[0] for row in indexes)

    def _index_record(self, statement):
        return (
            statement_slot(statement),
            digest(statement),
            digest(statement.plan),
            statement.body.round.submission_close_block,
            statement.body.round.evaluation_close_block,
            issue_close_ms(statement, self.legacy),
        )

    @staticmethod
    def _write_indexes(db, indexes):
        for slot, *metadata in indexes:
            old = db.execute(
                "SELECT statement,plan,opens,closes,issue_close FROM work_index WHERE slot=?",
                (slot,),
            ).fetchone()
            if old is not None and tuple(old) != tuple(metadata):
                raise ValueError("retained work index differs from its statement")
            if old is None:
                db.execute(
                    "INSERT INTO work_index(slot,statement,plan,opens,closes,issue_close) "
                    "VALUES (?,?,?,?,?,?)",
                    (slot, *metadata),
                )

    def _repair_endpoints(self, slots):
        validator = _StatementValidator(self.policy, self.legacy)

        def index(db):
            self._write_indexes(
                db,
                (
                    self._index_record(self._statement(slot, db=db, validator=validator))
                    for slot in slots
                ),
            )

        self.journal.put_many((), index=index)

    def _statement(self, slot, *, db=None, validator: _StatementValidator | None = None):
        raw = self.journal.get("intent", slot, db=db)
        if raw is None:
            raise ValueError("work statement is missing its retained intent")
        if validator is None:
            validator = _StatementValidator(self.policy, self.legacy)
        statement = validator.validate(raw)
        if statement_slot(statement) != slot:
            raise ValueError("retained work statement slot mismatch")
        if self.journal.get("work-plan", statement.body.round.suite_sha256, db=db) != (
            statement.plan.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError("work statement is missing its original frozen plan")
        return statement

    async def prepare(self, plan, *, videos=()):
        """Called repeatedly for a frozen round; never retime retained work."""
        async with self.serial:
            # Coordinate separate queue instances before either chooses issuance.
            # The sibling file lock is nonblocking; no SQLite transaction spans I/O.
            # Owned thread awaits drain before either lock can be released.
            with self.journal.locked():
                await self._prepare(plan, videos)

    async def _prepare(self, plan, videos):
        plan = await run_owned_thread(validate_work_plan, plan, self.policy)
        block = await self._head()
        round_ = plan.cutoff.publication.round
        if not round_.submission_close_block <= block < round_.evaluation_close_block:
            raise ValueError("work preparation is outside its execution window")
        await run_owned_thread(self.journal.put, "work-plan", round_.suite_sha256, plan)
        await self._orders(plan, ())
        retained, statements = await self._endpoints(plan, videos)
        block = await self._head()
        if retained:
            await run_owned_thread(self._repair_endpoints, retained)
        else:
            await run_owned_thread(partial(self._retain_many, statements, new_block=block))
        publications = []
        for slot in retained:
            statement = await run_owned_thread(self._statement, slot)
            certificate = await self._publish(statement, block)
            if certificate is not None:
                publications.append(certificate)
        # Model orders need no endpoint authorization. Endpoint orders enter
        # this same queue only after their authorization has its own quorum.
        await self._orders(plan, tuple(publications))

    def _retained_endpoints(self, plan):
        round_ = plan.cutoff.publication.round
        retained, total = [], 0
        validator = _StatementValidator(self.policy, self.legacy)
        for sub in plan.submissions:
            if sub.submission.track != "endpoint":
                continue
            total += 1
            slot = digest(
                {
                    "policy": round_.policy_sha256,
                    "sequence": round_.sequence,
                    "submission": digest(sub.submission),
                    "kind": "umi-endpoint-authorization-publication/1",
                }
            )
            if self.journal.get("intent", slot) is not None:
                statement = self._statement(slot, validator=validator)
                if statement.plan != plan:
                    raise ValueError("retained authorization has a different work plan")
                retained.append(slot)
        if retained and len(retained) != total:
            raise ValueError("partial endpoint batch requires explicit recovery")
        return tuple(retained), total

    async def _endpoints(self, plan, videos):
        retained, total = await run_owned_thread(self._retained_endpoints, plan)
        if len(retained) == total:
            return retained, ()
        announcement, issuance = await self._issuance()

        def statements():
            # Generate one body at a time so the journal can enforce its byte
            # budget without staging every publication in memory first.
            # The atomic batch chooses one fresh issuance when construction
            # starts. Serialization time must not give later members a different
            # freshness decision. Retention still checks the real clock against
            # the original issue deadline before committing the whole batch.
            construction_ms = time.time_ns() // 1_000_000
            for sub in plan.submissions:
                if sub.submission.track != "endpoint":
                    continue
                body = endpoint_proposals(
                    plan=plan,
                    policy=self.policy,
                    legacy=self.legacy,
                    videos=videos,
                    announcement=announcement,
                    issuance=issuance,
                    now_ms=construction_ms,
                    minimum_issue_ms=self.minimum_issue_ms,
                    submission_sha256=digest(sub.submission),
                )[0]
                yield WorkStatement(schema="umi-work-statement/1", plan=plan, body=body)

        return (), statements()

    async def _issuance(self):
        if self.transport_provider is None or self.legacy is None:
            raise ValueError("endpoint preparation requires owned transport finality")
        head, _ = await self.transport_provider.verified_blocks()
        _verified_transport_block(head, self.legacy)
        index = (
            head.height - self.legacy.activation_block
        ) // self.legacy.clock.window_stride_blocks
        announcement_height = (
            self.legacy.activation_block + index * self.legacy.clock.window_stride_blocks
        )
        current, blocks = await self.transport_provider.verified_blocks(
            (announcement_height, head.height)
        )
        _verified_transport_block(current, self.legacy)
        now = time.time_ns() // 1_000_000
        if (
            len(blocks) != 2
            or current.height < head.height
            or blocks[1] != head
            or not now - 60_000 <= current.timestamp_ms <= now + 5_000
        ):
            raise ValueError("owned issuance changed during work preparation")
        return blocks

    def _retain_order(self, plan, body, block):
        statement = WorkStatement(schema="umi-work-statement/1", plan=plan, body=body)
        if not self._open(statement, block):
            return None
        self._retain(statement)
        return statement

    async def _orders(self, plan, publications):
        bodies = await run_owned_thread(
            partial(
                evaluation_order_proposals,
                plan=plan,
                policy=self.policy,
                publications=publications,
                legacy=self.legacy,
            )
        )
        block = await self._head()
        for body in bodies:
            statement = await run_owned_thread(self._retain_order, plan, body, block)
            if statement is not None:
                await self._publish(statement, block)

    def _certificate(self, statement, block):
        slot = statement_slot(statement)
        raw = self.journal.get("certificate", slot)
        if raw is None:
            signatures = []
            for hotkey in statement.plan.evaluators:
                vote = self.journal.get("vote", slot + ":" + identity(hotkey))
                if vote is None:
                    return None
                signatures.append(
                    verify_work_endorsement(
                        WorkEndorsement.model_validate_json(canonical_json_bytes(vote)), statement
                    ).signature
                )
            if not self._open(statement, block):
                return None
            if isinstance(statement.body, EvaluationOrder):
                result = SignedEvaluationOrder(order=statement.body, signatures=tuple(signatures))
            else:
                result = SignedEndpointAuthorization(
                    publication=statement.body, signatures=tuple(signatures)
                )
        elif isinstance(statement.body, EvaluationOrder):
            result = SignedEvaluationOrder.model_validate_json(canonical_json_bytes(raw))
        else:
            result = SignedEndpointAuthorization.model_validate_json(canonical_json_bytes(raw))
        if isinstance(result, SignedEvaluationOrder):
            validate_order(result, self.policy, self.legacy)
            body = result.order
        else:
            validate_publication(result, self.policy, self.legacy)
            body = result.publication
        if body != statement.body:
            raise ValueError("work certificate differs from its original statement")
        self.journal.put("certificate", slot, result)
        return result

    def _delivery_path(self, result):
        if isinstance(result, SignedEvaluationOrder):
            body, directory = result.order, self.order_directory
        else:
            body, directory = result.publication, self.publication_directory
        return directory / (digest(body) + ".json")

    def _delivered(self, result):
        try:
            retained = read_private_model(self._delivery_path(result), type(result))
        except FileNotFoundError:
            return False
        if canonical_json_bytes(retained) != canonical_json_bytes(result):
            raise ValueError("evaluator outbox already contains different bytes")
        return True

    def _deliver(self, statement, result, block):
        # Retry after a crash can repair only a currently usable delivery.
        # Retained certificates are evidence, not permission to reopen work.
        if self._open(statement, block):
            _publish(self._delivery_path(result), result)

    async def _publish(self, statement, block):
        result = await run_owned_thread(self._certificate, statement, block)
        if result is not None and not await run_owned_thread(self._delivered, result):
            # Validation and durable retention can outlive the captured head.
            # Reobserve before creating a delivery without replacing issuance.
            # An exact existing delivery needs no further chain observation.
            block = await self._head()
            await run_owned_thread(self._deliver, statement, result, block)
        return result

    def _verified_vote(self, vote):
        vote = WorkEndorsement.model_validate_json(canonical_json_bytes(vote))
        with self.journal.transaction() as db:
            entry = db.execute(
                "SELECT slot FROM work_index WHERE statement=?", (vote.statement_sha256,)
            ).fetchone()
        if entry is None:
            raise ValueError("unknown work statement")
        statement = self._statement(entry[0])
        vote = verify_work_endorsement(vote, statement)
        return statement, vote, entry[0] + ":" + identity(vote.signature.hotkey)

    def _retain_vote(self, statement, vote, key, block):
        if self.journal.get("vote", key) is None and not self._open(statement, block):
            raise ValueError("new work endorsement arrived outside its original window")
        self.journal.put("vote", key, vote)

    async def accept(self, vote):
        async with self.serial:
            statement, vote, key = await run_owned_thread(self._verified_vote, vote)
            block = await self._head()
            await run_owned_thread(self._retain_vote, statement, vote, key, block)
            certificate = await self._publish(statement, block)
            if isinstance(certificate, SignedEndpointAuthorization):
                await self._orders(statement.plan, (certificate,))
            return await run_owned_thread(digest, statement)

    async def pending(self, hotkey, *, after=0):
        async with self.serial:
            if type(after) is not int or not 0 <= after <= 2**53 - 1:
                raise ValueError("work discovery cursor is invalid")
            if identity(hotkey) not in {identity(e.hotkey) for e in self.policy.evaluators}:
                raise ValueError("work discovery requires a policy evaluator")
            block = await self._head()
            return await run_owned_thread(self._pending, hotkey, after, block)

    def _pending(self, hotkey, after, block):
        now = time.time_ns() // 1_000_000 + self.minimum_issue_ms
        validator = _StatementValidator(self.policy, self.legacy)
        with self.journal.transaction() as db:
            # The page limit also bounds validation work. The client wraps
            # its cursor so other evaluators' rows cannot starve this one.
            entries = db.execute(
                "SELECT sequence,slot,statement,plan,opens,closes,issue_close FROM work_index "
                "WHERE sequence>? AND opens<=? AND closes>? "
                "AND (issue_close IS NULL OR issue_close>?) ORDER BY sequence LIMIT 4",
                (after, block, block, now),
            ).fetchall()
        result, cursor = [], after
        for sequence, slot, statement_id, plan_id, opens, closes, issue_close in entries:
            cursor = sequence
            # Conflicts are held, not rediscovered as clean work.
            try:
                statement = self._statement(slot, validator=validator)
            except ValueError:
                continue
            if (
                digest(statement) != statement_id
                or digest(statement.plan) != plan_id
                or statement.body.round.submission_close_block != opens
                or statement.body.round.evaluation_close_block != closes
                or issue_close_ms(statement, self.legacy) != issue_close
            ):
                raise ValueError("work discovery index binding mismatch")
            if identity(hotkey) in {identity(k) for k in statement.plan.evaluators} and (
                self.journal.get("certificate", slot) is None
                and self.journal.get("vote", slot + ":" + identity(hotkey)) is None
            ):
                result.append(statement)
        return cursor, tuple(result)
