"""Independent hotkey endorsements for frozen endpoint and model work.

The signer requires its own retained cutoff reservation and fresh local proof
sources. Endpoint issuance is reconstructed from its own transport provider.
No endorsement alone executes work or grants chain-submission permission.
"""

from __future__ import annotations

import asyncio
import contextvars
import threading
import time
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path
from typing import Literal

from pydantic import Field

from .competition_authorization import EndpointAuthorizationPublication, validate_publication_body
from .competition_evaluator import EvaluationOrder, validate_order_body
from .competition_execution import registration_boundary
from .competition_round_journal import RoundJournal
from .competition_round_plan import RoundProposal
from .competition_rounds import (
    CutoffEndorsement,
    verified_local_cutoff_snapshot,
    verify_endorsement,
)
from .competition_work_admission import WorkAdmission
from .competition_work_plans import (
    WorkPlan,
    _verified_transport_block,
    endpoint_proposals,
    validate_work_plan,
)
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import (
    CompetitionPolicy,
    Signature,
    digest,
    identity,
    sign_object,
    verify_signature,
)
from .policy import ScoringPolicy
from .protocol import Hex32, StrictProtocolModel, canonical_json_bytes
from .window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS, ceil_div


class WorkStatement(StrictProtocolModel):
    schema_: Literal["umi-work-statement/1"] = Field(alias="schema")
    plan: WorkPlan
    body: EndpointAuthorizationPublication | EvaluationOrder
    chain_submission_authorized: Literal[False] = False


class WorkEndorsement(StrictProtocolModel):
    statement_sha256: Hex32
    signature: Signature


def _parse_statement(statement: object) -> WorkStatement:
    raw = canonical_json_bytes(statement)
    if len(raw) > 16 * 1024**2:
        raise ValueError("work statement exceeds its byte bound")
    return WorkStatement.model_validate_json(raw)


def _validate_statement_body(
    statement: WorkStatement,
    plan: WorkPlan,
    policy: CompetitionPolicy,
    legacy: ScoringPolicy | None,
) -> WorkStatement:
    body = statement.body
    if body.round != plan.cutoff.publication.round:
        raise ValueError("work statement round differs from its cutoff")
    if isinstance(body, EvaluationOrder):
        validate_order_body(body, policy, legacy)
        if (
            body.submission not in plan.submissions
            or body.cases != plan.cases
            or body.incumbent != plan.incumbent
            or body.runtime != plan.runtime
            or body.evaluators != plan.evaluators
        ):
            raise ValueError("work order differs from its frozen plan")
    else:
        if legacy is None:
            raise ValueError("work authorization requires the transport policy")
        validate_publication_body(body, policy, legacy)
        if (
            len(body.submissions) != 1
            or body.submissions[0] not in plan.submissions
            or (
                tuple(c.model_dump() for c in body.cases)
                != tuple(c.model_dump() for c in plan.cases)
                or {identity(a.evaluator_hotkey) for a in body.assignments}
                != {identity(k) for k in plan.evaluators}
            )
        ):
            raise ValueError("work authorization differs from its frozen plan")
    return statement


def validate_statement(statement, policy, legacy=None):
    statement = _parse_statement(statement)
    plan = validate_work_plan(statement.plan, policy)
    return _validate_statement_body(statement, plan, policy, legacy)


class _StatementValidator:
    """Authenticate one exact plan per synchronous batch or discovery page.

    Policy snapshots and the last authenticated plan are owned by this operation.
    Never retain this validator on a service or across awaits. Each call reparses
    the complete statement and validates its body. The cached plan is separately
    parsed and is never returned, so callers cannot mutate its nested values.
    """

    def __init__(self, policy: CompetitionPolicy, legacy: ScoringPolicy | None = None):
        self._policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self._legacy = (
            None
            if legacy is None
            else ScoringPolicy.model_validate_json(canonical_json_bytes(legacy))
        )
        self._last_plan: tuple[bytes, WorkPlan] | None = None

    def validate(self, statement: object) -> WorkStatement:
        statement = _parse_statement(statement)
        raw_plan = canonical_json_bytes(statement.plan)
        if self._last_plan is None or self._last_plan[0] != raw_plan:
            plan = validate_work_plan(statement.plan, self._policy)
            self._last_plan = raw_plan, plan
        return _validate_statement_body(statement, self._last_plan[1], self._policy, self._legacy)


def statement_slot(statement):
    body = statement.body
    sub = body.submission if isinstance(body, EvaluationOrder) else body.submissions[0]
    return digest(
        {
            "policy": body.round.policy_sha256,
            "sequence": body.round.sequence,
            "submission": digest(sub.submission),
            "kind": body.schema_,
        }
    )


class IndependentWorkSigner:
    def __init__(
        self, worker, cutoff_journal, *, minimum_issue_ms, transport_provider=None, legacy=None
    ):
        self.worker, self.cutoffs = worker, cutoff_journal
        self.transport_provider, self.legacy = transport_provider, legacy
        if type(minimum_issue_ms) is not int or not 1 <= minimum_issue_ms <= 300_000:
            raise ValueError("work signer issue margin must be bounded")
        self.minimum_issue_ms = minimum_issue_ms
        self.journal = RoundJournal(
            Path(worker.config.state_directory) / "work-signing",
            {
                "policy": digest(worker.policy),
                "hotkey": identity(worker.config.evaluator_hotkey),
                "legacy": None if legacy is None else digest(legacy),
                "minimum_issue_ms": minimum_issue_ms,
            },
            maximum_rounds=worker.config.maximum_orders,
            maximum_bytes=worker.config.maximum_journal_bytes,
        )
        self.serial = asyncio.Lock()
        self.admission = WorkAdmission(worker, self.journal)

    def _reserved_cutoff(self, statement):
        slot = str(statement.body.round.sequence)
        raw = self.cutoffs.get("intent", slot)
        vote = self.cutoffs.get("vote", slot)
        if raw is None or vote is None:
            raise ValueError("work signer has not independently endorsed this cutoff")
        proposal = RoundProposal.model_validate_json(canonical_json_bytes(raw))
        vote = CutoffEndorsement.model_validate_json(canonical_json_bytes(vote))
        verify_endorsement(vote, proposal, self.worker.policy)
        if self.cutoffs.get("suite", statement.body.round.suite_sha256) != {
            "proposal": digest(proposal)
        }:
            raise ValueError("work signer cutoff is missing its original suite reservation")
        if identity(vote.signature.hotkey) != identity(self.worker.config.evaluator_hotkey) or (
            proposal.cutoff != statement.plan.cutoff.publication
            or proposal.submissions != statement.plan.submissions
        ):
            raise ValueError("work signer cutoff reservation differs from this plan")
        return proposal

    async def _endpoint_window(self, statement):
        body = statement.body
        if isinstance(body, EvaluationOrder):
            if body.publication is None:
                return
            body = body.publication.publication
        if self.transport_provider is None or self.legacy is None:
            raise ValueError("work signer needs its owned transport finality provider")
        heights = {a.request.issued_block for a in body.assignments}
        if len(heights) != 1:
            raise ValueError("work authorization mixes issuance boundaries")
        issued = next(iter(heights))
        legacy = self.legacy
        index = (issued - legacy.activation_block) // legacy.clock.window_stride_blocks
        announcement_height = legacy.activation_block + index * legacy.clock.window_stride_blocks
        head, blocks = await self.transport_provider.verified_blocks((announcement_height, issued))
        if len(blocks) != 2:
            raise ValueError("owned transport provider omitted a required block")
        _verified_transport_block(head, legacy)
        announcement, issuance = blocks
        now_ms = time.time_ns() // 1_000_000
        if (
            head.height < issued
            or head.timestamp_ms < issuance.timestamp_ms
            or not now_ms - 60_000 <= head.timestamp_ms <= now_ms + 5_000
        ):
            raise ValueError("work signer transport head is stale or precedes issuance")
        videos = {}
        for a in body.assignments:
            prior = videos.setdefault(a.case_sha256, a.request.video)
            if prior != a.request.video:
                raise ValueError("work authorization has inconsistent video descriptors")
        expected = await run_owned_thread(
            partial(
                endpoint_proposals,
                plan=statement.plan,
                policy=self.worker.policy,
                legacy=legacy,
                videos=tuple(videos[digest(c)] for c in body.cases),
                announcement=announcement,
                issuance=issuance,
                now_ms=time.time_ns() // 1_000_000,
                minimum_issue_ms=self.minimum_issue_ms,
                verification_head=head,
            )
        )
        if body not in expected:
            raise ValueError("work authorization differs from the independently derived window")
        return expected, head, (announcement,)

    async def _current(self, statement):
        head = await self.worker.boundary()
        await run_owned_thread(self.journal.observe, head.block)
        round_ = statement.body.round
        if not round_.submission_close_block <= head.block < round_.evaluation_close_block:
            raise ValueError("work signing is outside its execution window")
        self._issue_time(statement)

    def _issue_time(self, statement):
        body = statement.body
        if isinstance(body, EvaluationOrder):
            body = None if body.publication is None else body.publication.publication
        if body is not None:
            now = time.time_ns() // 1_000_000
            margin = ceil_div(self.legacy.clock.response_window_seconds, 3)
            if any(
                now + self.minimum_issue_ms
                >= QUICKNET_GENESIS_MS
                + (a.request.response_close_round - margin - 1) * QUICKNET_PERIOD_MS
                for a in body.assignments
            ):
                raise ValueError("work signing issue window elapsed")

    async def endorse(self, statement):
        async with self.serial:
            with self.journal.locked():
                return await self._endorse_locked(statement)

    async def _endorse_locked(self, statement):
        statement = await run_owned_thread(
            validate_statement, statement, self.worker.policy, self.legacy
        )
        if identity(self.worker.config.evaluator_hotkey) not in {
            identity(k) for k in statement.plan.evaluators
        }:
            raise ValueError("work signer is not a nominated evaluator")
        proposal = await run_owned_thread(self._reserved_cutoff, statement)
        reviews = getattr(self.worker, "review_store", None)
        if reviews is not None:
            snapshot = statement.plan.cutoff.publication.registration_snapshot
            retained = await run_owned_thread(
                self.cutoffs.get, "owned-proof", str(statement.body.round.sequence)
            )
            if retained is None:
                # Older journals have no authenticated proof receipt. They
                # still require an independent fresh collection, never a
                # coordinator snapshot substituted for local verification.
                capture = await self.worker.provider.collect_at(snapshot.block)
                registration_boundary(capture)
                snapshot = capture.snapshot
            else:
                snapshot = verified_local_cutoff_snapshot(
                    retained, proposal, self.worker.policy, self.worker.config.evaluator_hotkey
                )
            head = await self.worker.boundary()
            await run_owned_thread(self.journal.observe, head.block)
            await run_owned_thread(
                partial(
                    reviews.observe_cutoff,
                    statement.plan.cutoff,
                    statement.plan.submissions,
                    snapshot=snapshot,
                    observed_block=head.block,
                )
            )
        slot, old = await run_owned_thread(self._retained_vote, statement)
        if old is not None:
            return old
        await self._current(statement)
        capacity = await self._endpoint_window(statement)
        await self._current(statement)
        if capacity is not None:
            if self.worker.dispatch is None:
                raise ValueError("work signer requires its owned scheduling journal")
            publications, observed, announcements = capacity
            await run_owned_thread(
                partial(
                    self.worker.dispatch.reserve_batch,
                    batch_id=digest(statement.plan),
                    publications=publications,
                    observed=observed,
                    announcements=announcements,
                    evaluator_hotkey=self.worker.config.evaluator_hotkey,
                )
            )
        else:
            publications = await run_owned_thread(self.admission.publications, statement.plan)
        await run_owned_thread(self.admission.reserve, statement.plan, publications, statement.body)
        # Capacity derivation and native commits may have used the issue margin.
        await self._current(statement)
        loop = asyncio.get_running_loop()
        stopped = threading.Event()

        def current_gate() -> None:
            if stopped.is_set():
                raise RuntimeError("work signing cancelled")
            pending = asyncio.run_coroutine_threadsafe(
                asyncio.wait_for(
                    self._current(statement),
                    timeout=self.worker.config.chain.collection_timeout_seconds,
                ),
                loop,
            )
            # The coroutine owns its timeout and drains provider cancellation.
            # Cancelling this Future instead could release the signing lease
            # while the provider's cleanup still runs on the event loop.
            pending.result()
            if stopped.is_set():
                raise RuntimeError("work signing cancelled")

        context = contextvars.copy_context()
        # Finality collection itself uses the default executor. A signing
        # thread waiting for that collection must not occupy its last worker.
        with ThreadPoolExecutor(max_workers=1, thread_name_prefix="umi-work-signing") as executor:

            async def sign() -> WorkEndorsement:
                return await loop.run_in_executor(
                    executor, context.run, self._sign_reserved, statement, slot, current_gate
                )

            return await await_owned_task(asyncio.create_task(sign()), on_cancel=stopped.set)

    def _retained_vote(self, statement: WorkStatement) -> tuple[str, WorkEndorsement | None]:
        """Read and authenticate an earlier result under the caller's signing lease."""
        slot = statement_slot(statement)
        intent = self.journal.get("intent", slot)
        if intent is not None:
            self.journal.put("intent", slot, statement)
        old = self.journal.get("vote", slot)
        if old is None:
            return slot, None
        if intent is None or self.journal.get("suite", statement.body.round.suite_sha256) != {
            "plan": digest(statement.plan)
        }:
            raise ValueError("work signature is missing its original reservations")
        vote = WorkEndorsement.model_validate_json(canonical_json_bytes(old))
        if vote.statement_sha256 != digest(statement) or identity(
            vote.signature.hotkey
        ) != identity(self.worker.config.evaluator_hotkey):
            raise ValueError("retained work signature binding mismatch")
        verify_signature(statement.body, vote.signature)
        return slot, vote

    def _sign_reserved(
        self, statement: WorkStatement, slot: str, current_gate: Callable[[], None]
    ) -> WorkEndorsement:
        """The caller retains its process lease until this bounded operation stops."""
        self.admission.verify(statement.plan)
        # Executor queueing and native receipt checks can outlast the preceding
        # head. Recollect after both, including model orders with no issue clock.
        current_gate()
        self._issue_time(statement)
        self.journal.put("intent", slot, statement)
        self.journal.put(
            "suite", statement.body.round.suite_sha256, {"plan": digest(statement.plan)}
        )
        vote = WorkEndorsement(
            statement_sha256=digest(statement),
            signature=sign_object(statement.body, self.worker.wallet),
        )
        if identity(vote.signature.hotkey) != identity(self.worker.config.evaluator_hotkey):
            raise ValueError("work signer wallet differs from its configured hotkey")
        verify_signature(statement.body, vote.signature)
        self.journal.put("vote", slot, vote)
        return vote
