"""Wallet-free preparation, quorum collection and immutable work delivery.

The round coordinator supplies a verified work plan from its protected suite.
Owned providers determine signing boundaries. A persisted endpoint statement
keeps its original issuance even after a crash or a missed publication window.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

from .competition_authorization import SignedEndpointAuthorization, validate_publication
from .competition_evaluator import EvaluationOrder, SignedEvaluationOrder, _publish, validate_order
from .competition_execution import execution_boundary
from .competition_rounds import RoundJournal
from .competition_work_plans import (
    _verified_transport_block,
    endpoint_proposals,
    evaluation_order_proposals,
    validate_work_plan,
)
from .competition_work_signing import (
    WorkEndorsement,
    WorkStatement,
    statement_slot,
    validate_statement,
)
from .open_competition import digest, identity, verify_signature
from .policy import scoring_policy_hash
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
        from .competition_evaluator import _private

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
        self.journal.observe(head.block)
        return head.block

    def _open(self, statement, block):
        round_ = statement.body.round
        close = issue_close_ms(statement, self.legacy)
        return round_.submission_close_block <= block < round_.evaluation_close_block and (
            close is None or time.time_ns() // 1_000_000 + self.minimum_issue_ms < close
        )

    def _retain(self, statement):
        statement = validate_statement(statement, self.policy, self.legacy)
        slot = statement_slot(statement)
        self.journal.put("intent", slot, statement)
        metadata = (
            digest(statement),
            digest(statement.plan),
            statement.body.round.submission_close_block,
            statement.body.round.evaluation_close_block,
            issue_close_ms(statement, self.legacy),
        )
        # The durable intent precedes indexing. An interrupted insertion is
        # repaired by the exact same preparation, without choosing new times.
        with self.journal.transaction() as db:
            old = db.execute(
                "SELECT statement,plan,opens,closes,issue_close FROM work_index WHERE slot=?",
                (slot,),
            ).fetchone()
            if old is not None and tuple(old) != metadata:
                raise ValueError("retained work index differs from its statement")
            if old is None:
                db.execute(
                    "INSERT INTO work_index(slot,statement,plan,opens,closes,issue_close) "
                    "VALUES (?,?,?,?,?,?)",
                    (slot, *metadata),
                )
        return slot

    def _statement(self, slot):
        raw = self.journal.get("intent", slot)
        if raw is None:
            raise ValueError("work statement is missing its retained intent")
        statement = validate_statement(
            WorkStatement.model_validate_json(canonical_json_bytes(raw)), self.policy, self.legacy
        )
        if statement_slot(statement) != slot:
            raise ValueError("retained work statement slot mismatch")
        if self.journal.get("work-plan", statement.body.round.suite_sha256) != (
            statement.plan.model_dump(mode="json", by_alias=True)
        ):
            raise ValueError("work statement is missing its original frozen plan")
        return statement

    async def prepare(self, plan, *, videos=()):
        """Called repeatedly for a frozen round; never retime retained work."""
        async with self.serial:
            plan = validate_work_plan(plan, self.policy)
            block = await self._head()
            round_ = plan.cutoff.publication.round
            if not round_.submission_close_block <= block < round_.evaluation_close_block:
                raise ValueError("work preparation is outside its execution window")
            self.journal.put("work-plan", round_.suite_sha256, plan)
            self._orders(plan, (), block)
            publications = []
            issuance = None
            for sub in plan.submissions:
                if sub.submission.track != "endpoint":
                    continue
                # Compute the same stable slot without constructing a new wire window.
                slot = digest(
                    {
                        "policy": round_.policy_sha256,
                        "sequence": round_.sequence,
                        "submission": digest(sub.submission),
                        "kind": "umi-endpoint-authorization-publication/1",
                    }
                )
                retained = self.journal.get("intent", slot)
                if retained is not None:
                    statement = self._statement(slot)
                    if statement.plan != plan:
                        raise ValueError("retained authorization has a different work plan")
                    self._retain(statement)
                    certificate = self._publish(statement, block)
                    if certificate is not None:
                        publications.append(certificate)
                    continue
                if self.transport_provider is None or self.legacy is None:
                    raise ValueError("endpoint preparation requires owned transport finality")
                if issuance is None:
                    head, _ = await self.transport_provider.verified_blocks()
                    _verified_transport_block(head, self.legacy)
                    index = (
                        head.height - self.legacy.activation_block
                    ) // self.legacy.clock.window_stride_blocks
                    announcement_height = (
                        self.legacy.activation_block
                        + index * self.legacy.clock.window_stride_blocks
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
                    issuance = blocks
                body = endpoint_proposals(
                    plan=plan,
                    policy=self.policy,
                    legacy=self.legacy,
                    videos=videos,
                    announcement=issuance[0],
                    issuance=issuance[1],
                    now_ms=time.time_ns() // 1_000_000,
                    minimum_issue_ms=self.minimum_issue_ms,
                    submission_sha256=digest(sub.submission),
                )[0]
                statement = WorkStatement(schema="umi-work-statement/1", plan=plan, body=body)
                if not self._open(statement, await self._head()):
                    raise ValueError("work preparation elapsed during proof collection")
                self._retain(statement)
            # Model orders need no endpoint authorization. Endpoint orders enter
            # this same queue only after their authorization has its own quorum.
            self._orders(plan, tuple(publications), await self._head())

    def _orders(self, plan, publications, block):
        for body in evaluation_order_proposals(
            plan=plan, policy=self.policy, publications=publications, legacy=self.legacy
        ):
            statement = WorkStatement(schema="umi-work-statement/1", plan=plan, body=body)
            if self._open(statement, block):
                self._retain(statement)
                self._publish(statement, block)

    def _publish(self, statement, block):
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
            body, directory = result.order, self.order_directory
        else:
            validate_publication(result, self.policy, self.legacy)
            body, directory = result.publication, self.publication_directory
        if body != statement.body:
            raise ValueError("work certificate differs from its original statement")
        self.journal.put("certificate", slot, result)
        # Retry after a crash can repair only a currently usable delivery.
        # Retained certificates are evidence, not permission to reopen work.
        if self._open(statement, block):
            _publish(directory / (digest(body) + ".json"), result)
        return result

    async def accept(self, vote):
        async with self.serial:
            vote = WorkEndorsement.model_validate_json(canonical_json_bytes(vote))
            with self.journal.transaction() as db:
                entry = db.execute(
                    "SELECT slot FROM work_index WHERE statement=?", (vote.statement_sha256,)
                ).fetchone()
            if entry is None:
                raise ValueError("unknown work statement")
            statement = self._statement(entry[0])
            vote = verify_work_endorsement(vote, statement)
            block = await self._head()
            key = entry[0] + ":" + identity(vote.signature.hotkey)
            if self.journal.get("vote", key) is None and not self._open(statement, block):
                raise ValueError("new work endorsement arrived outside its original window")
            self.journal.put("vote", key, vote)
            certificate = self._publish(statement, block)
            if isinstance(certificate, SignedEndpointAuthorization):
                self._orders(statement.plan, (certificate,), await self._head())
            return digest(statement)

    async def pending(self, hotkey, *, after=0):
        async with self.serial:
            if type(after) is not int or not 0 <= after <= 2**53 - 1:
                raise ValueError("work discovery cursor is invalid")
            if identity(hotkey) not in {identity(e.hotkey) for e in self.policy.evaluators}:
                raise ValueError("work discovery requires a policy evaluator")
            block = await self._head()
            now = time.time_ns() // 1_000_000 + self.minimum_issue_ms
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
                    statement = self._statement(slot)
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
