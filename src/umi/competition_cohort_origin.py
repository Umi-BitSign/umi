"""Current chain origins for acknowledged recoverable endpoint assignments.

Retained scope and proof bytes survive restart. Current authority and owned
finality must be checked again before use; cached proofs are not delivery grants.
"""

from __future__ import annotations

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
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest
from .protocol import canonical_json_bytes


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
            },
        )
        return digest({"schema": "umi-cohort-origin-cache-binding/1", "chain": body})

    def _acceptable_cache_bindings(self) -> frozenset[str]:
        return frozenset({self._cache_binding_hash()})


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
            capture = await self.provider._collect_origin_locked(
                job.submission,
                public_https_origin(job.submission.submission.endpoint_url),
                recovery=scope,
            )
            finished = await self._confirm(assignment, source)
            if not started.block <= capture.block <= finished.block or any(
                boundary.block == capture.block
                and (boundary.block_hash, boundary.state_root)
                != (capture.block_hash, capture.state_root)
                for boundary in (started, finished)
            ):
                raise ValueError("endpoint origin differs from owned execution observations")
            self.provider._fresh(capture.timestamp_ms)
            return capture

    async def _confirm(
        self, assignment: CohortExecutionAssignment, source: CohortOrderHistory
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

        await unchanged()
        boundary = execution_boundary(
            await wait_for_owned(authority.provider.collect(), timeout=timeout)
        )
        await unchanged()

        def retained():
            journal = authority.journal.journal
            journal.observe(boundary.block)
            with journal.transaction() as db:
                row = db.execute(
                    "SELECT history FROM order_heads WHERE cohort=?", (cohort,)
                ).fetchone()
                if row != (digest(source),):
                    raise ValueError("retained endpoint authority changed during collection")

        await run_owned_thread(retained)
        return boundary
