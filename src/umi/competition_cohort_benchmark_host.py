"""Evaluator-owned order inbox, pinned CPU execution and completion exports.

The listener owns the key and finality provider for this host. Endpoint requests
need their additional transport worker; CPU completion alone never closes them.
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .competition_cohort_execution_journal import CohortExecutionConfig, CohortExecutionJournal
from .competition_cohort_executor import CohortExecutionWorker, CohortExecutor
from .competition_cohort_history_http import CohortHistoryHTTPClient, CohortHistoryReader
from .competition_cohort_order_http import order_routes
from .competition_cohort_order_inbox import CohortOrderInbox, CohortOrderInboxConfig
from .competition_cohort_order_signer import (
    CohortOrderJournal,
    CohortOrderSigner,
    CohortOrderSignerConfig,
)
from .competition_cohort_request_export_worker import RequestExportWorker
from .competition_cohort_request_files import RequestCompletionFiles
from .competition_cohort_sandbox import CohortCpuSandbox
from .competition_reward_boot import _disjoint
from .competition_round_journal import RoundJournal
from .concurrency import await_owned_task
from .open_competition import digest, identity
from .private_files import Directory
from .protocol import StrictProtocolModel, canonical_json_bytes

logger = logging.getLogger(__name__)


class BenchmarkHostConfig(StrictProtocolModel):
    schema_: Literal["umi-cohort-benchmark-host/1"] = Field(alias="schema")
    directory: Directory
    orders: CohortOrderSignerConfig
    inbox: CohortOrderInboxConfig
    execution: CohortExecutionConfig
    archive_directory: Directory
    videos_directory: Directory
    workspace_directory: Directory
    request_export_directory: Directory
    batch_size: Annotated[int, Field(ge=1, le=256)] = 16
    concurrency: Annotated[int, Field(ge=1, le=32)] = 4
    poll_seconds: Annotated[int, Field(ge=1, le=60)] = 5
    maximum_state_bytes: Annotated[int, Field(ge=1024**2, le=16 * 1024**3)] = 1024**3

    def stores(self):
        return tuple(
            Path(p)
            for p in (
                self.directory,
                self.orders.directory,
                self.inbox.directory,
                self.execution.directory,
                self.archive_directory,
                self.videos_directory,
                self.workspace_directory,
                self.request_export_directory,
            )
        )

    @model_validator(mode="after")
    def bindings(self):
        for config in (self.inbox, self.execution):
            if (
                config.policy_sha256 != self.orders.policy_sha256
                or config.cohorts != self.orders.cohorts
                or identity(config.signer) != identity(self.orders.signer)
            ):
                raise ValueError("benchmark orders, inbox and execution change evaluator scope")
        _disjoint(self.stores())
        return self


class BenchmarkHost:
    def __init__(self, config, provider, client, owner_token, vote_token, sign):
        self.config = c = BenchmarkHostConfig.model_validate_json(
            canonical_json_bytes(config.benchmark)
        )
        self.policy, self.provider = config.policy, provider
        timeout = min(config.review_timeout_seconds, c.execution.read_timeout_seconds)
        self.history = CohortHistoryReader(
            config.owner_hotkey,
            CohortHistoryHTTPClient(
                client,
                config.owner_origin,
                token=owner_token,
                timeout_seconds=timeout,
            ),
            timeout_seconds=timeout,
        )
        self.signer = CohortOrderSigner(
            CohortOrderJournal(c.orders, config.policy), provider, self.history, sign
        )
        self.inbox = CohortOrderInbox(c.inbox, config.policy, provider, self.history, sign)
        self.execution = CohortExecutionJournal(c.execution, config.policy)
        self.sandbox = CohortCpuSandbox(
            config.policy,
            archive=Path(c.archive_directory),
            videos=Path(c.videos_directory),
            workspace=Path(c.workspace_directory),
        )
        self.worker = CohortExecutionWorker(
            self.inbox,
            CohortExecutor(self.execution, provider, self.history, self.sandbox),
            batch_size=c.batch_size,
            concurrency=c.concurrency,
        )
        self.journal = RoundJournal(
            Path(c.directory),
            {
                "schema": "umi-cohort-benchmark-host-state/1",
                "series": digest(config.series),
                "policy": digest(config.policy),
                "owner": identity(config.owner_hotkey),
                "evaluator": identity(c.orders.signer),
            },
            maximum_rounds=65536,
            maximum_bytes=c.maximum_state_bytes,
        )
        self.files = RequestCompletionFiles(Path(c.request_export_directory))
        self.exporter = RequestExportWorker(
            (self.execution,), provider, sign, self.files, self.journal, batch_size=c.batch_size
        )
        self.routes = order_routes(
            self.signer, self.inbox, token=vote_token, timeout_seconds=config.review_timeout_seconds
        )
        self.tasks, self.last_reports = {}, {}

    def report(self, name, result):
        previous = self.last_reports.get(name)
        self.last_reports[name] = result
        if previous != result:
            logger.info(
                "benchmark_worker worker=%s report=%s", name, canonical_json_bytes(result).decode()
            )

    async def run(self, stop):
        if self.tasks:
            raise RuntimeError("benchmark workers are already running")
        stopping = asyncio.create_task(stop.wait())
        try:
            for name, worker in (("execution", self.worker), ("exports", self.exporter)):
                self.tasks[name] = asyncio.create_task(
                    worker.run(
                        stop,
                        poll_seconds=self.config.poll_seconds,
                        report=lambda result, name=name: self.report(name, result),
                    )
                )
            done, _ = await asyncio.wait(
                (*self.tasks.values(), stopping), return_when=asyncio.FIRST_COMPLETED
            )
            for task in done - {stopping}:
                task.result()
            if not stop.is_set():
                raise RuntimeError("benchmark worker exited before shutdown")
        finally:

            async def drain():
                for task in (*self.tasks.values(), stopping):
                    task.cancel()
                await asyncio.gather(*self.tasks.values(), stopping, return_exceptions=True)

            try:
                await await_owned_task(asyncio.create_task(drain()))
            finally:
                self.tasks.clear()
