"""Build, certify and deliver the evaluator's retained endpoint request selection."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from .competition_cohort_endpoint import RecoverableEndpointOrder, endpoint_obligation_sha256
from .competition_cohort_execution import RecoverableExecutionJob
from .competition_cohort_miner_case import (
    CohortCaseMinerGrant,
    RecoverableEndpointCaseOrder,
    grant_slot,
)
from .competition_cohort_orders import recoverable_order_job
from .competition_cohort_request_signer import (
    EndpointRequestPlan,
    EndpointRequestSigner,
    request_grant,
    request_slot,
    validate_request_plan,
)
from .competition_cohort_request_window import capture_request_window
from .competition_execution import ExecutionCase
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .policy import scoring_policy_hash
from .protocol import Video, canonical_json_bytes

EndpointVideoSource = Callable[[RecoverableExecutionJob, ExecutionCase], Awaitable[Video]]


@dataclass(frozen=True)
class EndpointRequestOutcome:
    status: str
    reason: str
    selection: object | None = None


class CohortEndpointRequestWorker:
    def __init__(
        self,
        signer: EndpointRequestSigner,
        recovery,
        request_vote,
        *,
        video_source: EndpointVideoSource | None = None,
    ):
        if (
            signer.journal.policy != recovery.journal.policy
            or signer.journal.cohorts != recovery.journal.cohorts
            or identity(signer.journal.config.signer) != identity(recovery.journal.config.signer)
        ):
            raise ValueError("request coordinator differs from its evaluator")
        self.signer, self.recovery, self.request_vote = signer, recovery, request_vote
        self.video_source = video_source

    async def video(self, job: RecoverableExecutionJob, case: ExecutionCase) -> Video:
        if self.video_source is None:
            raise ValueError("endpoint video source is not configured")
        value = await wait_for_owned(
            self.video_source(job, case),
            timeout=self.signer.journal.config.read_timeout_seconds,
        )
        value = Video.model_validate_json(canonical_json_bytes(value))
        if value.sha256 != case.video_sha256:
            raise ValueError("endpoint video source changed the assigned clip")
        return value

    async def _window(self, transport):
        async def capture():
            blocks = self.signer.blocks_for(transport)
            height = await blocks.finalized_head_height()
            return await capture_request_window(transport, blocks, height)

        return await wait_for_owned(
            capture(), timeout=self.signer.journal.config.read_timeout_seconds
        )

    async def initial(self, assignment, transport, videos=None):
        job = self.recovery.journal.validate_assignment(assignment)
        slot = digest(["umi-cohort-endpoint-request-slot/1", digest(job)])
        old = await run_owned_thread(self.signer.journal.load, slot)
        if old is not None:
            if old.plan.assignment != assignment or old.plan.transport != transport:
                raise ValueError("initial request selection changed its assignment or transport")
            return old.plan
        if videos is None:
            videos = [await self.video(job, case) for case in job.cases]
        if len(videos) != len(job.cases):
            raise ValueError("initial request requires each assigned video")
        window = await self._window(transport)
        body = RecoverableEndpointOrder(
            schema="umi-recoverable-endpoint-order/1",
            job=job,
            transport_policy_sha256=scoring_policy_hash(transport),
            attempt_number=1,
            requests=tuple(
                window.request(job, case, video, 1, transport)
                for case, video in zip(job.cases, videos, strict=True)
            ),
        )
        plan = EndpointRequestPlan(
            schema="umi-cohort-endpoint-request-plan/1",
            assignment=assignment,
            body=body,
            transport=transport,
        )
        # attest reserves the exact body and verified windows before any signature.
        await self.signer.attest(plan)
        return plan

    async def replacement(self, parent, certificate, retirement, transport, video=None):
        body, decision = parent.attempt.order, certificate.decision
        job = body.job
        number, case_id = body.attempt_number + 1, decision.case_id
        slot = digest(
            ["umi-cohort-endpoint-request-slot/2", endpoint_obligation_sha256(job, case_id), number]
        )
        old = await run_owned_thread(self.signer.journal.load, slot)
        if old is not None:
            plan = old.plan
            if (
                plan.parent != parent
                or plan.transport != transport
                or plan.body.prior_decision != certificate
                or plan.body.prior_retirement != retirement
            ):
                raise ValueError("replacement request selection changed its retry evidence")
            return plan
        case = next(c for c in job.cases if c.case_id == case_id)
        if video is None:
            video = await self.video(job, case)
        window = await self._window(transport)
        selected = RecoverableEndpointCaseOrder(
            schema="umi-recoverable-endpoint-case-order/1",
            job=job,
            transport_policy_sha256=scoring_policy_hash(transport),
            case_id=case_id,
            attempt_number=number,
            requests=(window.request(job, case, video, number, transport),),
            parent_grant_slot=grant_slot(parent),
            parent_grant_sha256=digest(parent),
            prior_decision=certificate,
            prior_retirement=retirement,
        )
        plan = EndpointRequestPlan(
            schema="umi-cohort-endpoint-request-plan/1",
            assignment=parent.assignment,
            body=selected,
            transport=transport,
            parent=parent,
        )
        await self.signer.attest(plan)
        return plan

    async def _certificate(self, slot):
        try:
            return await self.signer.certify(slot)
        except ValueError as error:
            if str(error) != "cohort recovery lacks the policy evaluator quorum":
                raise
            return None

    async def advance(self, plan):
        policy = self.signer.journal.policy
        plan = await run_owned_thread(validate_request_plan, plan, policy)
        if plan.body.job != recoverable_order_job(
            plan.assignment.certificate.order, self.recovery.journal.config.signer
        ):
            raise ValueError("request coordinator is not the assigned evaluator")
        await self.signer.attest(plan)
        slot = request_slot(plan.body)
        certificate = await self._certificate(slot)
        for reviewer in policy.evaluators:
            if certificate is not None:
                break
            if await run_owned_thread(self.signer.journal.vote, slot, reviewer.hotkey):
                continue
            try:
                vote = await wait_for_owned(
                    self.request_vote(reviewer.hotkey, plan),
                    timeout=self.signer.journal.config.read_timeout_seconds,
                )
                if identity(vote.hotkey) != identity(reviewer.hotkey):
                    raise ValueError("request reviewer returned another identity")
                await self.signer.collect(slot, vote)
                certificate = await self._certificate(slot)
            except (OSError, ValueError, asyncio.TimeoutError):
                continue
        if certificate is None:
            return EndpointRequestOutcome("pending", "request_quorum_pending")
        grant = request_grant(plan, certificate)
        if isinstance(grant, CohortCaseMinerGrant):
            selected = await self.recovery.prepare_case(grant, plan.transport)
        else:
            selected = await self.recovery.prepare(plan.assignment, certificate, plan.transport)
        return EndpointRequestOutcome("certified", "request_selection_retained", selected)

    async def recover(self, slot):
        intent = await run_owned_thread(self.signer.journal.load, slot)
        if intent is None:
            raise FileNotFoundError("request intent is not retained")
        return await self.advance(intent.plan)
