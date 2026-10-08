"""Current chain origins for acknowledged recoverable endpoint assignments.

Retained scope and proof bytes survive restart. Current authority and owned
finality must be checked again before use; cached proofs are not delivery grants.
"""

from __future__ import annotations

import asyncio
import time

from .competition_chain import CompetitionChainConfig
from .competition_cohort_execution_journal import CohortExecutionAssignment
from .competition_cohort_executor import CohortExecutionAuthority
from .competition_cohort_order_signer import CohortOrderHistory, order_slot
from .competition_cohort_origin_scope import CohortEndpointOriginScope
from .competition_execution import ExecutionBoundary, execution_boundary
from .competition_origin import (
    EndpointOriginCapture,
    FinalizedEndpointProvider,
    public_https_origin,
)
from .competition_round_journal import FinalizedHeadRegression
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest
from .protocol import canonical_json_bytes
from .validator_chain import FinalizedSnapshotRef


class CohortEndpointFinalityProvider(FinalizedEndpointProvider):
    """Separate C5+ proof cache with adjustable operational capacity/timeouts.

    Existing legacy cache bindings are deliberately not adopted by this port.
    Chain identity, verifier pins and freshness bounds remain immutable.
    """

    @staticmethod
    def _config_binding_hash(config: CompetitionChainConfig) -> str:
        body = config.model_dump(
            mode="json",
            by_alias=True,
            exclude={
                "policy_sha256",
                "maximum_cache_bytes",
                "collection_timeout_seconds",
                "startup_timeout_seconds",
                "finality_segment_startup_timeout_seconds",
            },
        )
        return digest({"schema": "umi-cohort-origin-cache-binding/1", "chain": body})

    def _acceptable_cache_bindings(self) -> frozenset[str]:
        accepted = {self._cache_binding_hash()}
        if self.config.maximum_head_age_ms in {120_000, 300_000} and (
            self.config.finality_segment_startup_timeout_seconds in {None, 900}
        ):
            for maximum_head_age_ms in (120_000, 300_000):
                released = self.config.model_copy(
                    update={
                        "maximum_head_age_ms": maximum_head_age_ms,
                        "finality_segment_startup_timeout_seconds": None,
                    }
                )
                body = released.model_dump(
                    mode="json",
                    by_alias=True,
                    exclude={
                        "policy_sha256",
                        "maximum_cache_bytes",
                        "collection_timeout_seconds",
                        "startup_timeout_seconds",
                    },
                )
                accepted.add(digest({"schema": "umi-cohort-origin-cache-binding/1", "chain": body}))
        return frozenset(accepted)


class CohortEndpointOrigin:
    def __init__(
        self, authority: CohortExecutionAuthority, provider: CohortEndpointFinalityProvider
    ):
        if provider.policy != authority.journal.policy:
            raise ValueError("endpoint origin and assignment policies differ")
        self.authority, self.provider = authority, provider

    async def collect(self, assignment: CohortExecutionAssignment) -> EndpointOriginCapture:
        assignment = CohortExecutionAssignment.model_validate_json(canonical_json_bytes(assignment))
        journal = self.authority.journal
        job = journal.validate_assignment(assignment)
        if job.mode != "endpoint_incumbent":
            raise ValueError("origin discovery requires an endpoint assignment")
        with journal.locked(order_slot(assignment.certificate.order)):
            source, started = await self.authority.current(assignment)
            await run_owned_thread(journal.retain, assignment, source, started.block)
            scope = CohortEndpointOriginScope(
                schema="umi-cohort-endpoint-origin-scope/1", assignment=assignment, source=source
            )
            # Retain original authority before any native proof references it.
            await run_owned_thread(
                journal.journal.put, "endpoint_origin_scope", digest(scope), scope
            )
            # The independently owned observer may lag the authority observer.
            # Align their heights before spending RPC on a capture that cannot
            # fit between the original start and finish observations.
            await self._wait_origin_head(started.block)
            capture = await self.provider._collect_origin_locked(
                job.submission,
                public_https_origin(job.submission.submission.endpoint_url),
                recovery=scope,
            )
            finished = await self._confirm(
                assignment,
                source,
                minimum_block=capture.block,
                capture_timestamp_ms=capture.timestamp_ms,
            )
            if not started.block <= capture.block <= finished.block or any(
                boundary.block == capture.block
                and (boundary.block_hash, boundary.state_root)
                != (capture.block_hash, capture.state_root)
                for boundary in (started, finished)
            ):
                raise ValueError("endpoint origin differs from owned execution observations")
            self.provider._fresh(capture.timestamp_ms)
            return capture

    async def _wait_origin_head(self, minimum_block: int) -> None:
        deadline = time.monotonic() + self.authority.journal.config.read_timeout_seconds
        while True:
            if self.provider._closed:
                raise ValueError("endpoint provider is closed")
            if self.provider._owned and (self.provider._task is None or self.provider._task.done()):
                raise ValueError("owned finality observer is not running")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError("owned origin observer precedes execution start")
            ref = await wait_for_owned(
                self.provider._finality.verified_finalized_snapshot(), timeout=remaining
            )
            if not isinstance(ref, FinalizedSnapshotRef):
                raise ValueError("endpoint finalized snapshot is invalid")
            if ref.block_number >= minimum_block:
                return
            # This reads the owned observer only, without RPC/header collection.
            await asyncio.sleep(min(1.0, max(0.0, deadline - time.monotonic())))

    async def _confirm(
        self,
        assignment: CohortExecutionAssignment,
        source: CohortOrderHistory,
        *,
        minimum_block: int,
        capture_timestamp_ms: int,
    ) -> ExecutionBoundary:
        """Recheck unchanged authenticated authority without repeating slow replay."""
        authority = self.authority
        cohort = assignment.certificate.order.round.cohort_sha256
        timeout = authority.journal.config.read_timeout_seconds

        async def unchanged():
            current = await wait_for_owned(authority.history(cohort), timeout=timeout)
            if current != source:
                # Remember a valid new closure/revocation before refusing use.
                await authority.current(assignment)
                raise OSError("cohort authority changed during origin collection")

        def retained(boundary: ExecutionBoundary):
            journal = authority.journal.journal
            journal.observe(boundary.block)
            with journal.transaction() as db:
                row = db.execute(
                    "SELECT history FROM order_heads WHERE cohort=?", (cohort,)
                ).fetchone()
                if row != (digest(source),):
                    raise ValueError("retained endpoint authority changed during collection")

        # A lagging owned observer does not invalidate the already collected
        # proof. Wait within the operational read allowance while keeping its
        # freshness and unchanged authority checks. Never substitute highwater
        # or an RPC head for owned finality.
        deadline = time.monotonic() + timeout
        while True:
            self.provider._fresh(capture_timestamp_ms)
            await unchanged()
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise OSError("owned confirmation precedes collected origin")
            boundary = execution_boundary(
                await wait_for_owned(authority.provider.collect(), timeout=remaining)
            )
            await unchanged()
            self.provider._fresh(capture_timestamp_ms)
            if boundary.block >= minimum_block:
                try:
                    await run_owned_thread(retained, boundary)
                except FinalizedHeadRegression:
                    if time.monotonic() >= deadline:
                        raise
                else:
                    return boundary
            await asyncio.sleep(min(1.0, max(0.0, deadline - time.monotonic())))
