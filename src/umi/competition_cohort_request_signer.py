"""Durable endpoint request votes, including expired windows awaiting retirement.

Each reviewer captures its own verified transport blocks. A finished signature
is recoverable offline; an unfinished signature still checks current cohort
authority. Completing old signatures never grants fresh inference authority.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field

from .competition_cohort_admission_journal import CohortAdmissionSignerConfig
from .competition_cohort_endpoint import (
    RecoverableEndpointOrder,
    SignedRecoverableEndpointOrder,
    endpoint_obligation_sha256,
    validate_endpoint_order_body,
    validate_recoverable_endpoint_transport,
)
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    EvaluationMinerGrant,
    RecoverableEndpointCaseOrder,
    SignedRecoverableEndpointCaseOrder,
    validate_case_attempt,
    validate_case_order_body,
    verify_case_order_parent,
)
from .competition_cohort_miner_contracts import CohortMinerGrant
from .competition_cohort_order_queue import check_delivery_receipt
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    remember_order_history,
    review_order,
)
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_recovery import verify_recovery_quorum
from .competition_cohort_request_window import EndpointRequestWindow, capture_request_window
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_round_journal import RecordReservation, RoundJournal
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import CompetitionPolicy, Signature, digest, identity, verify_signature
from .policy import ScoringPolicy
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_REQUEST_INTENT_BYTES = 64 * 1024**2
RequestBody = Annotated[
    RecoverableEndpointOrder | RecoverableEndpointCaseOrder, Field(discriminator="schema_")
]


class EndpointRequestPlan(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-request-plan/1"] = Field(alias="schema")
    assignment: CohortExecutionAssignment
    body: RequestBody
    transport: ScoringPolicy
    parent: EvaluationMinerGrant | None = None


def request_slot(body: RequestBody):
    if isinstance(body, RecoverableEndpointCaseOrder):
        return digest(
            [
                "umi-cohort-endpoint-request-slot/2",
                endpoint_obligation_sha256(body.job, body.case_id),
                body.attempt_number,
            ]
        )
    return digest(["umi-cohort-endpoint-request-slot/1", digest(body.job)])


def validate_request_plan(plan: EndpointRequestPlan, policy: CompetitionPolicy):
    raw = canonical_json_bytes(plan)
    if len(raw) > MAX_REQUEST_INTENT_BYTES // 2:
        raise ValueError("endpoint request plan exceeds its byte bound")
    plan = EndpointRequestPlan.model_validate_json(raw)
    assignment, body = plan.assignment, plan.body
    order = assignment.certificate.order
    verify_recovery_quorum(order, assignment.certificate.signatures, policy)
    miner = identity(order.submission.submission.hotkey)
    if any(identity(s.hotkey) == miner for s in assignment.certificate.signatures):
        raise ValueError("miner cannot authorize its own request assignment")
    receipt = check_delivery_receipt(assignment.certificate, assignment.delivery)
    if body.job != recoverable_order_job(order, receipt.receipt.evaluator_hotkey):
        raise ValueError("request body differs from its acknowledged assignment")
    if isinstance(body, RecoverableEndpointOrder):
        validate_endpoint_order_body(body, policy, plan.transport)
        if plan.parent is not None or body.attempt_number != 1:
            raise ValueError("initial request requires attempt one without a parent")
    else:
        validate_case_order_body(body, policy, plan.transport)
        parent = plan.parent
        if parent is None:
            raise ValueError("replacement request requires its signed parent")
        if isinstance(parent, CohortCaseMinerGrant):
            validate_case_attempt(parent.attempt, policy, plan.transport)
        else:
            validate_recoverable_endpoint_transport(parent.attempt, policy, plan.transport)
            if parent.attempt.order.attempt_number != 1:
                raise ValueError("initial parent has an invalid attempt")
        verify_case_order_parent(body, assignment, parent)
    return plan


class EndpointRequestIntent(StrictProtocolModel):
    schema_: Literal["umi-cohort-endpoint-request-intent/1"] = Field(alias="schema")
    plan: EndpointRequestPlan
    source: CohortOrderHistory
    observation: ExecutionBoundary
    windows: Annotated[tuple[EndpointRequestWindow, ...], Field(min_length=1, max_length=2048)]


class EndpointRequestSignerConfig(CohortAdmissionSignerConfig):
    schema_: Literal["umi-cohort-endpoint-request-signer/1"] = Field(alias="schema")
    read_timeout_seconds: Annotated[int, Field(ge=1, le=3600)] = 300


def _vote_key(slot, hotkey):
    return digest(["umi-cohort-endpoint-request-vote/1", slot, identity(hotkey)])


class EndpointRequestJournal:
    def __init__(self, config: EndpointRequestSignerConfig, policy: CompetitionPolicy):
        self.config = EndpointRequestSignerConfig.model_validate_json(canonical_json_bytes(config))
        self.policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
        self.reviewers = {identity(e.hotkey): e.hotkey for e in self.policy.evaluators}
        if (
            config.policy_sha256 != digest(self.policy)
            or identity(config.signer) not in self.reviewers
        ):
            raise ValueError("request signer is outside configured policy")
        self.cohorts = {c.cohort_sha256: c.authority_sha256 for c in config.cohorts}
        self.journal = RoundJournal(
            Path(config.directory),
            config.model_dump(
                mode="json",
                by_alias=True,
                exclude={
                    "maximum_votes",
                    "maximum_bytes",
                    "signing_timeout_seconds",
                    "read_timeout_seconds",
                },
            ),
            maximum_rounds=config.maximum_votes,
            maximum_bytes=config.maximum_bytes,
            maximum_record_bytes=MAX_REQUEST_INTENT_BYTES,
        )
        with self.journal.transaction() as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS order_heads "
                "(cohort TEXT PRIMARY KEY, history TEXT NOT NULL)"
            )

    def remember(self, source, block):
        remember_order_history(self.journal, self.cohorts, self.policy, source, block)

    def check(self, value: EndpointRequestIntent):
        raw = canonical_json_bytes(value)
        if len(raw) > MAX_REQUEST_INTENT_BYTES:
            raise ValueError("request intent exceeds its byte bound")
        value = EndpointRequestIntent.model_validate_json(raw)
        plan = validate_request_plan(value.plan, self.policy)
        if self.cohorts.get(plan.body.job.round.cohort_sha256) != digest(
            value.source.history.authority.authority
        ) or identity(self.config.signer) == identity(plan.body.job.submission.submission.hotkey):
            raise ValueError("request intent differs from signer authority")
        review_order(
            plan.assignment.certificate.order,
            plan.assignment.participant,
            value.source,
            self.policy,
            value.observation.block,
        )
        windows = {w.issuance.height: w for w in value.windows}
        if len(windows) != len(value.windows) or set(windows) != {
            r.issued_block for r in plan.body.requests
        }:
            raise ValueError("request intent requires exactly its issuance proofs")
        view = verify_cohort_history(
            value.source.history,
            self.policy,
            expected_tip_sha256=history_tip(value.source.history),
            current_block=value.observation.block,
        )
        for request in plan.body.requests:
            if request.issued_block <= view.closure("preparation").observed_at_block:
                raise ValueError("request issuance precedes certified preparation")
            if request.issued_block > value.observation.block:
                raise ValueError("request issuance was not finalized at observation")
            windows[request.issued_block].check(request, plan.transport)
        return value

    def load(self, slot):
        raw = self.journal.get("request_intent", slot)
        if raw is None:
            return None
        intent = self.check(EndpointRequestIntent.model_validate_json(canonical_json_bytes(raw)))
        if request_slot(intent.plan.body) != slot:
            raise ValueError("request intent changed its slot")
        return intent

    def reserve(self, intent):
        intent = self.check(intent)
        slot = request_slot(intent.plan.body)
        old = self.load(slot)
        if old is not None:
            if old.plan != intent.plan:
                raise ValueError("request slot already reserved for different inputs")
            return old
        self.journal.reserve_records(
            slot,
            (
                RecordReservation(
                    "request_certificate",
                    slot,
                    len(canonical_json_bytes(intent.plan.body)) + 32 * 1024,
                ),
                *(
                    RecordReservation("request_vote", _vote_key(slot, k), 2048)
                    for k in self.reviewers.values()
                ),
            ),
        )

        def bounded(db):
            count = db.execute(
                "SELECT COUNT(*) FROM records WHERE kind='request_intent'"
            ).fetchone()[0]
            if count > self.config.maximum_votes:
                raise ValueError("request intent capacity exhausted")

        self.journal.put_many((("request_intent", slot, intent),), index=bounded)
        return intent

    def _vote(self, intent, signature):
        signature = Signature.model_validate_json(canonical_json_bytes(signature))
        if identity(signature.hotkey) not in self.reviewers or identity(
            signature.hotkey
        ) == identity(intent.plan.body.job.submission.submission.hotkey):
            raise ValueError("request vote has an unauthorized reviewer")
        verify_signature(intent.plan.body, signature)
        return signature

    def vote(self, slot, hotkey):
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("request intent is not retained")
        raw = self.journal.get("request_vote", _vote_key(slot, hotkey))
        if raw is None:
            return None
        signature = self._vote(intent, raw)
        if identity(signature.hotkey) != identity(hotkey):
            raise ValueError("request vote changed its reviewer key")
        return signature

    def collect(self, slot, signature):
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("request intent is not retained")
        signature = self._vote(intent, signature)
        old = self.vote(slot, signature.hotkey)
        if old is not None:
            return old
        self.journal.put("request_vote", _vote_key(slot, signature.hotkey), signature)
        return signature

    def certificate(self, slot):
        intent = self.load(slot)
        if intent is None:
            return None
        raw = self.journal.get("request_certificate", slot)
        if raw is None:
            return None
        cls, validate = (
            (SignedRecoverableEndpointCaseOrder, validate_case_attempt)
            if isinstance(intent.plan.body, RecoverableEndpointCaseOrder)
            else (SignedRecoverableEndpointOrder, validate_recoverable_endpoint_transport)
        )
        value = validate(
            cls.model_validate_json(canonical_json_bytes(raw)), self.policy, intent.plan.transport
        )
        if value.order != intent.plan.body:
            raise ValueError("request certificate differs from retained intent")
        return value

    def certify(self, slot):
        old = self.certificate(slot)
        if old is not None:
            return old
        intent = self.load(slot)
        if intent is None:
            raise FileNotFoundError("request intent is not retained")
        groups = {identity(e.hotkey): e.control_group for e in self.policy.evaluators}
        seen, signatures = set(), []
        for account, key in sorted(self.reviewers.items()):
            vote = self.vote(slot, key)
            if vote is not None and groups[account] not in seen:
                seen.add(groups[account])
                signatures.append(vote)
        verify_recovery_quorum(intent.plan.body, tuple(signatures), self.policy)
        cls = (
            SignedRecoverableEndpointCaseOrder
            if isinstance(intent.plan.body, RecoverableEndpointCaseOrder)
            else SignedRecoverableEndpointOrder
        )
        certificate = cls(order=intent.plan.body, signatures=tuple(signatures))
        self.journal.put("request_certificate", slot, certificate)
        return certificate


class EndpointRequestSigner:
    def __init__(self, journal: EndpointRequestJournal, provider, blocks, history, sign):
        if provider.policy != journal.policy:
            raise ValueError("request finality belongs to another policy")
        self.journal, self.provider, self.blocks = journal, provider, blocks
        self.history, self.sign, self.serial = history, sign, asyncio.Lock()

    async def _source(self, plan):
        timeout = self.journal.config.read_timeout_seconds
        source = await wait_for_owned(
            self.history(plan.body.job.round.cohort_sha256), timeout=timeout
        )
        observation = execution_boundary(
            await wait_for_owned(self.provider.collect(), timeout=timeout)
        )
        await run_owned_thread(self.journal.remember, source, observation.block)
        await run_owned_thread(
            review_order,
            plan.assignment.certificate.order,
            plan.assignment.participant,
            source,
            self.journal.policy,
            observation.block,
        )
        return source, observation

    async def attest(self, plan: EndpointRequestPlan):
        plan = await run_owned_thread(validate_request_plan, plan, self.journal.policy)
        slot, config = request_slot(plan.body), self.journal.config
        async with self.serial:
            with self.journal.journal.locked():
                old = await run_owned_thread(self.journal.load, slot)
                if old is not None:
                    if old.plan != plan:
                        raise ValueError("request slot already reserved for different inputs")
                    vote = await run_owned_thread(self.journal.vote, slot, config.signer)
                    if vote is not None:
                        return vote
                source, observation = await self._source(plan)
                if old is None:
                    windows = []
                    for height in sorted({r.issued_block for r in plan.body.requests}):
                        windows.append(
                            await wait_for_owned(
                                capture_request_window(plan.transport, self.blocks, height),
                                timeout=config.read_timeout_seconds,
                            )
                        )
                    old = EndpointRequestIntent(
                        schema="umi-cohort-endpoint-request-intent/1",
                        plan=plan,
                        source=source,
                        observation=observation,
                        windows=tuple(windows),
                    )
                    await run_owned_thread(self.journal.reserve, old)
                # Current authority still gates unfinished votes, but historical
                # transport proofs need no renewal or live window after a crash.
                current = await wait_for_owned(
                    self.history(plan.body.job.round.cohort_sha256),
                    timeout=config.read_timeout_seconds,
                )
                if current != source:
                    await self._source(plan)
                    raise OSError("request authority changed during review")

                async def commit():
                    signature = await self.sign(plan.body)
                    if identity(signature.hotkey) != identity(config.signer):
                        raise ValueError("request signed by another reviewer")
                    return await run_owned_thread(self.journal.collect, slot, signature)

                return await wait_for_owned(commit(), timeout=config.signing_timeout_seconds)

    async def recover(self, slot):
        intent = await run_owned_thread(self.journal.load, slot)
        if intent is None:
            raise FileNotFoundError("request intent is not retained")
        return await self.attest(intent.plan)

    async def collect(self, slot, vote):
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.collect, slot, vote)

    async def certify(self, slot):
        async with self.serial:
            with self.journal.journal.locked():
                return await run_owned_thread(self.journal.certify, slot)


def request_grant(plan: EndpointRequestPlan, certificate):
    if certificate.order != plan.body:
        raise ValueError("request certificate changed its plan")
    cls = (
        CohortCaseMinerGrant
        if isinstance(plan.body, RecoverableEndpointCaseOrder)
        else CohortMinerGrant
    )
    version = 2 if cls is CohortCaseMinerGrant else 1
    return cls(
        schema=f"umi-cohort-miner-grant/{version}", assignment=plan.assignment, attempt=certificate
    )
