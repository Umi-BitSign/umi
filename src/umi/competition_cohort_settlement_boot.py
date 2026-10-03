"""Own settlement process locks, SQLite, finality and named-key lifetimes."""

import asyncio
import os
import sqlite3
import stat
from contextlib import AsyncExitStack, contextmanager
from pathlib import Path

from .competition_cohort_direct_model_review import (
    DirectModelArtifactReviewer,
    DirectModelSettlementVerifier,
)
from .competition_cohort_execution_journal import CohortExecutionJournal
from .competition_cohort_recovery_store import CohortRecoveryStore
from .competition_cohort_request_export_worker import RequestExportWorker
from .competition_cohort_request_files import RequestCompletionFiles
from .competition_cohort_settlement_config import SettlementServiceConfig
from .competition_cohort_settlement_proofs import SettlementRegistrationFiles
from .competition_cohort_settlement_service import CohortSettlementService
from .competition_historical_registration import HistoricalRegistrationProvider
from .competition_reward_service import _close_provider, _stop_task
from .competition_round_journal import RoundJournal
from .competition_store import CompetitionStore
from .concurrency import run_owned_thread
from .named_hotkey import load_named_hotkey
from .open_competition import digest, sign_object
from .private_files import ensure_private_directory, lock_private_file
from .protocol import canonical_json_bytes


@contextmanager
def settlement_store(root: Path, maximum_bytes: int):
    """Keep a checked private inode open; the event loop owns the connection."""
    ensure_private_directory(root)
    path = root / "history.sqlite3"
    lease = lock_private_file(root / "history.lock")
    descriptor = None
    db = None
    try:
        for suffix in ("-journal", "-wal", "-shm"):
            auxiliary = Path(str(path) + suffix)
            try:
                info = auxiliary.lstat()
            except FileNotFoundError:
                continue
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_nlink != 1
                or info.st_uid != os.getuid()
                or info.st_mode & 0o077
            ):
                raise ValueError(
                    "settlement database auxiliary file must be private and singly linked"
                )
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
            or info.st_mode & 0o077
        ):
            raise ValueError("settlement database must be private and singly linked")
        db = sqlite3.connect(path, isolation_level=None)
        held, current = os.fstat(descriptor), path.lstat()
        if (held.st_dev, held.st_ino) != (current.st_dev, current.st_ino):
            raise ValueError("settlement database changed while opening")
        db.execute("PRAGMA journal_mode=DELETE")
        db.execute("PRAGMA synchronous=FULL")
        page = db.execute("PRAGMA page_size").fetchone()[0]
        if db.execute("PRAGMA page_count").fetchone()[0] * page > maximum_bytes:
            raise ValueError("settlement database exceeds its configured capacity")
        db.execute(f"PRAGMA max_page_count={maximum_bytes // page}")
        store = CohortRecoveryStore(db)
        parent = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
        yield store
    finally:
        if db is not None:
            db.close()
        if descriptor is not None:
            os.close(descriptor)
        os.close(lease)


async def run_settlement_service(config: SettlementServiceConfig, stop: asyncio.Event):
    config = SettlementServiceConfig.model_validate_json(canonical_json_bytes(config))
    root = Path(config.state_directory) / digest(config.series)
    ensure_private_directory(root)
    descriptor = lock_private_file(root / "service.lock")
    async with AsyncExitStack() as resources:
        resources.callback(os.close, descriptor)
        provider = HistoricalRegistrationProvider(config.chain, config.policy)
        resources.push_async_callback(_close_provider, provider)
        key = await run_owned_thread(
            load_named_hotkey, Path(config.signer_key_file), config.signer_hotkey
        )

        async def sign(body):
            return await run_owned_thread(sign_object, body, key)

        executions = tuple(CohortExecutionJournal(c, config.policy) for c in config.executions)
        proofs = SettlementRegistrationFiles(
            provider,
            inbox=Path(config.proof_import_directory),
            outbox=Path(config.proof_export_directory),
        )
        promotion = CompetitionStore(Path(config.promotion_directory), config.policy)
        direct_artifacts = (
            None
            if config.direct_model_review is None
            else DirectModelArtifactReviewer(
                config.direct_model_review,
                config.policy,
                config.proposer_hotkey,
            )
        )
        nodes = []
        for plan in config.series.cohorts:
            store = resources.enter_context(
                settlement_store(root / digest(plan), config.maximum_state_bytes)
            )
            nodes.append(
                CohortSettlementService(
                    config,
                    plan,
                    store=store,
                    provider=provider,
                    proofs=proofs,
                    promotion=promotion,
                    executions=executions,
                    sign=sign,
                    model_artifacts=(
                        None
                        if direct_artifacts is None
                        else DirectModelSettlementVerifier(
                            direct_artifacts,
                            promotion.directory / "model-reward-artifacts",
                            root / digest(plan) / "direct-model-settlement-receipts",
                        )
                    ),
                )
            )
        exports = None
        if config.request_export_directory is not None:
            exports = RequestExportWorker(
                executions,
                provider,
                sign,
                RequestCompletionFiles(
                    Path(config.request_export_directory),
                    maximum_bytes=config.maximum_package_bytes,
                ),
                RoundJournal(
                    root / "request-exports",
                    {
                        "schema": "umi-cohort-request-export-owner/1",
                        "series": digest(config.series),
                        "signer": config.signer_hotkey,
                        "executions": [e.directory for e in config.executions],
                        "destination": config.request_export_directory,
                    },
                    maximum_bytes=config.maximum_state_bytes,
                ),
            )
        await provider.start()
        tasks = [asyncio.create_task(node.run(stop)) for node in nodes]
        if exports is not None:
            tasks.append(asyncio.create_task(exports.run(stop, poll_seconds=config.poll_seconds)))
        for task in tasks:
            resources.push_async_callback(_stop_task, task)
        done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
        for task in done:
            task.result()
        if not stop.is_set():
            raise RuntimeError("settlement component exited before shutdown")
