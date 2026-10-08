"""Current native authority and chain-proven origin for accepted service work."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable

from .canonical_reuse import canonical_json_reuse
from .competition_chain import FinalizedRegistrationProvider, RegistrationCapture
from .competition_cohort_order_signer import CohortOrderHistory, remember_order_history
from .competition_cohort_origin import CohortEndpointFinalityProvider
from .competition_cohort_origin_scope import CohortServiceOriginScope, review_origin_recovery_scope
from .competition_cohort_service_queue import ServiceWorkQueue
from .competition_cohort_service_work import ServiceWorkAssignment
from .competition_execution import execution_boundary
from .competition_origin import EndpointOriginCapture, public_https_origin
from .competition_round_journal import FinalizedHeadRegression
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest
from .private_files import PrivateStateBusyError
from .private_state_wait import run_private_state_operation
from .protocol import canonical_json_bytes


class ServiceWorkAuthority:
    def __init__(
        self,
        queue: ServiceWorkQueue,
        provider: FinalizedRegistrationProvider,
        history: Callable[[str], Awaitable[CohortOrderHistory]],
        origins: CohortEndpointFinalityProvider,
        *,
        timeout_seconds: int = 2400,
    ):
        if provider.policy != queue.policy or origins.policy != queue.policy:
            raise ValueError("service authority providers belong to another policy")
        if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 3600:
            raise ValueError("service authority timeout is outside bounds")
        self.queue, self.provider, self.history, self.origins = queue, provider, history, origins
        self.timeout = timeout_seconds

    def _owned(self, assignment):
        assignment = ServiceWorkAssignment.model_validate_json(canonical_json_bytes(assignment))
        if self.queue.assignment(assignment.admission.claim) != assignment:
            raise ValueError("service authority changed its original accepted work")
        return assignment

    @canonical_json_reuse()
    def _remember(self, assignment, source, block):
        catalog = assignment.catalog.catalog
        with self.queue.journal.locked():
            # Record valid closure/revocation before refusing execution, so a
            # later stale owner response cannot roll the phase back open.
            remember_order_history(
                self.queue.journal,
                {catalog.cohort_sha256: catalog.authority_sha256},
                self.queue.policy,
                source,
                block,
            )
            scope = CohortServiceOriginScope(
                schema="umi-cohort-service-origin-scope/1",
                assignment=assignment,
                source=source,
            )
            review_origin_recovery_scope(
                scope, assignment.admission.submission, self.queue.policy, block
            )
            self.queue.journal.put("service_origin_scope", digest(scope), scope)
        return scope

    async def _current(self, assignment, *, minimum_block=None):
        cohort = assignment.catalog.catalog.cohort_sha256
        loop = asyncio.get_running_loop()
        deadline = loop.time() + self.timeout
        regressed = False
        while True:
            source = await wait_for_owned(self.history(cohort), timeout=self.timeout)
            collect_at_least = getattr(self.provider, "collect_at_least", None)
            collection = (
                collect_at_least(minimum_block)
                if minimum_block is not None and callable(collect_at_least)
                else self.provider.collect()
            )
            capture = await wait_for_owned(collection, timeout=self.timeout)
            if minimum_block is not None and execution_boundary(capture).block < minimum_block:
                raise OSError("owned registration head precedes required origin")
            try:
                await run_owned_thread(
                    self._remember, assignment, source, execution_boundary(capture).block
                )
                return source, capture
            except FinalizedHeadRegression:
                # Another operation can persist a newer owned observation while
                # this one waits for its journal. Recollect history and require
                # a genuinely newer capture once; never waive the high-water
                # fence or loop indefinitely on a lagging provider.
                if regressed or loop.time() >= deadline:
                    raise
                regressed = True
                minimum_block = max(minimum_block or 0, execution_boundary(capture).block + 1)
            except PrivateStateBusyError:
                remaining = deadline - loop.time()
                if remaining <= 0:
                    raise
                # Refresh both inputs; lock contention cannot extend an old head.
                await asyncio.sleep(min(1.0, remaining))

    async def observe(
        self, assignment: ServiceWorkAssignment, *, minimum_block=None
    ) -> tuple[CohortOrderHistory, RegistrationCapture]:
        assignment = await run_private_state_operation(
            self._owned, assignment, timeout=self.timeout
        )
        source, capture = await self._current(assignment, minimum_block=minimum_block)
        if (
            await wait_for_owned(self.history(assignment.round.cohort_sha256), timeout=self.timeout)
            != source
        ):
            await self._current(assignment, minimum_block=minimum_block)
            raise OSError("service authority changed during observation")
        return source, capture

    async def origin(self, assignment: ServiceWorkAssignment) -> EndpointOriginCapture:
        assignment = await run_private_state_operation(
            self._owned, assignment, timeout=self.timeout
        )
        source, started = await self.observe(assignment)
        scope = CohortServiceOriginScope(
            schema="umi-cohort-service-origin-scope/1",
            assignment=assignment,
            source=source,
        )
        capture = await self.origins._collect_origin_locked(
            assignment.admission.submission,
            public_https_origin(assignment.admission.submission.submission.endpoint_url),
            recovery=scope,
        )
        current, finished = await self.observe(assignment, minimum_block=capture.block)
        if current != source:
            raise OSError("service authority changed during origin collection")
        before, after = execution_boundary(started), execution_boundary(finished)
        if not before.block <= capture.block <= after.block or any(
            boundary.block == capture.block
            and (boundary.block_hash, boundary.state_root)
            != (capture.block_hash, capture.state_root)
            for boundary in (before, after)
        ):
            raise ValueError("service origin differs from owned finalized observations")
        self.origins._fresh(capture.timestamp_ms)
        return capture
