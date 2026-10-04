"""Combine owned dispatch readiness with fresh, authenticated evaluator probes."""

import asyncio
import logging
import sqlite3

from fastapi import APIRouter, HTTPException, Query, Response

from .competition_cohort_history import verify_cohort_history
from .competition_cohort_intake import history_tip
from .competition_cohort_request_probe import (
    RequestProbe,
    RequestReadinessPeer,
    journal_stamp,
    tasks_running,
)
from .competition_cohort_request_readiness import RequestReadiness
from .competition_execution import execution_boundary
from .concurrency import run_owned_thread, wait_for_owned
from .open_competition import digest, identity
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


class CombinedRequestReadiness:
    def __init__(self, service, lifecycle, dispatch, orders, client, credentials, running):
        self.service, self.lifecycle, self.dispatch, self.orders = (
            service,
            lifecycle,
            dispatch,
            orders,
        )
        self.running, self.selected = running, {}
        self.last_reports = {}
        self.selection_stamp = None
        self.peers = tuple(
            (
                identity(peer.signer),
                RequestReadinessPeer(
                    client,
                    peer.origin,
                    token,
                    timeout_seconds=peer.timeout_seconds,
                ),
            )
            for peer, token in zip(
                service.config.admission_owner.reviewers, credentials, strict=True
            )
        )

    def report(self, cohort, reason):
        if self.last_reports.get(cohort) != reason:
            self.last_reports[cohort] = reason
            logger.info("cohort_request_readiness cohort=%s status=%s", cohort, reason)

    def _orders(self, source):
        cohort = source.cohort
        stamp = journal_stamp(self.orders.queue.journal)
        if stamp != self.selection_stamp:
            self.selected.clear()
        if cohort not in self.selected:
            if self.orders._retained(cohort) is None:
                raise FileNotFoundError("complete benchmark roster is not selected")
            selected = self.orders.queue.journal.get("order_host_roster", cohort)
            self.selected[cohort] = tuple(
                self.orders.queue.intent(slot).order for slot in selected["slots"]
            )
        orders = self.selected[cohort]
        if any(order.round != source.roster.round for order in orders):
            raise ValueError("request readiness changed the prepared round")
        if journal_stamp(self.orders.queue.journal) != stamp:
            self.selected.clear()
            raise OSError("order selection changed during readiness; retry")
        self.selection_stamp = stamp
        return orders

    def _running(self, catalogs):
        return (
            self.running()
            and tasks_running(self.service.runtime_tasks)
            and all(
                key in self.dispatch.workers
                and key in self.dispatch.tasks
                and tasks_running((self.dispatch.tasks[key],))
                for key in catalogs
            )
        )

    async def observe(self, cohort, nonce):
        service = self.service
        requirement = service.config.manifest.requirement(cohort)
        service.provider.ensure_observer_running()
        self.dispatch.origins.ensure_observer_running()
        capture = await service.capture()
        observation = execution_boundary(capture)
        history = await service.history(cohort)
        tip = history_tip(history.history)
        view = verify_cohort_history(
            history.history,
            service.intake.policy,
            expected_tip_sha256=tip,
            current_block=observation.block,
        )
        catalogs = requirement.catalog_sha256s
        ready = view.state.phase == "requests" and self._running(catalogs)
        if ready:
            source = self.lifecycle.requests.get(cohort)
            if source is None:
                raise FileNotFoundError("native request owner is not ready")
            orders = await run_owned_thread(self._orders, source)
            videos = {
                item.video_sha256 for catalog in source.catalogs for item in catalog.catalog.work
            }
            for video in sorted(videos):
                await self.dispatch.clips(video)
            probes = tuple(
                RequestProbe(
                    schema="umi-cohort-request-probe/1",
                    nonce=nonce,
                    policy_sha256=digest(service.intake.policy),
                    cohort_sha256=cohort,
                    recovery_tip_sha256=tip,
                    round_sha256=digest(source.roster.round),
                    catalog_sha256s=catalogs,
                    order_sha256s=tuple(
                        sorted(
                            digest(order)
                            for order in orders
                            if who in {identity(e) for e in order.evaluators}
                        )
                    ),
                )
                for who, _ in self.peers
            )
            answers = await asyncio.gather(
                *(
                    peer.ready(probe, observation, source.gap)
                    for (_, peer), probe in zip(self.peers, probes, strict=True)
                )
            )
            current = await service.history(cohort)
            ready = (
                bool(answers)
                and all(answers)
                and self._running(catalogs)
                and history_tip(current.history) == tip
            )
        self.report(cohort, "ready" if ready else "unavailable")
        return RequestReadiness(
            schema="umi-cohort-request-readiness/1",
            nonce=nonce,
            policy_sha256=digest(service.intake.policy),
            cohort_sha256=cohort,
            recovery_tip_sha256=tip,
            catalog_sha256s=catalogs,
            observation=observation,
            ready=ready,
        )


def request_readiness_routes(service):
    router = APIRouter()

    @router.get("/v1/competition/cohorts/{cohort}/requests/readiness")
    async def readiness(cohort: str, nonce: str = Query(pattern=r"^[0-9a-f]{32}$")):
        if cohort not in service.intake.bindings:
            raise HTTPException(404, "recoverable cohort not found")
        if service.request_readiness is None:
            raise HTTPException(503, "request workers unavailable; retry later")
        try:
            dispatch = service.config.dispatch
            if dispatch is None:
                raise RuntimeError("request readiness requires configured dispatch")
            value = await wait_for_owned(
                service.request_readiness.observe(cohort, nonce),
                timeout=dispatch.operation_timeout_seconds,
            )
        except (OSError, ValueError, RuntimeError, sqlite3.Error, asyncio.TimeoutError) as error:
            if service.request_readiness is not None:
                service.request_readiness.report(cohort, type(error).__name__)
            raise HTTPException(503, "request workers unavailable; retry later") from error
        return Response(
            canonical_json_bytes(value),
            media_type="application/json",
            headers={"cache-control": "no-store"},
        )

    return router
