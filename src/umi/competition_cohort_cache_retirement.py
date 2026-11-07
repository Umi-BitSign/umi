"""Retire one terminal cohort's idle candidate through its existing cache owner.

The execution worker calls this only after draining its current operations.
Original terminal histories and byte results stay in their existing journals;
an interrupted unlink resumes its immutable intent without rechecking payloads.
"""

import logging
import time
from contextlib import asynccontextmanager
from functools import partial
from pathlib import Path

from .competition_artifacts import _file_identity
from .competition_chunked_model_retirement import retirement_generation_lease
from .competition_cohort_order_signer import (
    CohortOrderHistory,
    remember_closed_order_history,
    verified_order_history,
)
from .competition_model_cache_space import BootDiskModelCache, managed_model_slot
from .competition_transport_verification import TransferProgress
from .concurrency import run_owned_thread
from .open_competition import digest
from .protocol import canonical_json_bytes

logger = logging.getLogger(__name__)


class TerminalModelCacheRetirement:
    def __init__(self, worker, journal, promotion):
        self.worker, self.journal, self.promotion = worker, journal, promotion
        self.port = worker.executor.sandbox
        self.refreshed = {}
        self.pending_after = ""

    def _pending(self):
        with self.journal.read_transaction() as db:
            query = (
                "SELECT i.id FROM records i LEFT JOIN records c "
                "ON c.kind='model_cache_retired' AND c.id=i.id "
                "WHERE i.kind='model_cache_retirement' AND c.id IS NULL AND i.id>? "
                "ORDER BY i.id LIMIT 1"
            )
            row = db.execute(query, (self.pending_after,)).fetchone()
            if row is None and self.pending_after:
                row = db.execute(query, ("",)).fetchone()
        if row is None:
            return None
        self.pending_after = row[0]
        intent = self.journal.get("model_cache_retirement", row[0])
        if digest(intent) != row[0]:
            raise ValueError("cache retirement intent identity requires repair")
        return row[0], intent

    def _retained_history(self, cohort):
        journal = self.worker.executor.journal.journal
        with journal.read_transaction() as db:
            row = db.execute("SELECT history FROM order_heads WHERE cohort=?", (cohort,)).fetchone()
            raw = None if row is None else journal.get("order_history", row[0], db=db)
        if row is not None and raw is None:
            raise ValueError("cache retirement retained history requires repair")
        return (
            None
            if raw is None
            else CohortOrderHistory.model_validate_json(canonical_json_bytes(raw))
        )

    async def _terminal(self, cohort):
        executor = self.worker.executor
        source = await run_owned_thread(self._retained_history, cohort)

        def complete(source):
            if digest(source.history.plan) != cohort or executor.journal.cohorts.get(
                cohort
            ) != digest(source.history.authority.authority):
                raise ValueError("cache retirement terminal history changed its cohort authority")
            return (
                executor._verified(
                    verified_order_history, source, executor.journal.policy
                ).state.phase
                == "complete"
            )

        if source is not None and await run_owned_thread(complete, source):
            return source
        if time.monotonic() - self.refreshed.get(cohort, float("-inf")) < 60:
            return None
        self.refreshed[cohort] = time.monotonic()
        # A completed batch is not terminal cohort authority. Discover the
        # signed closure once through the same authenticated owner history port.
        source = await executor.history(cohort)
        if not await run_owned_thread(complete, source):
            return None
        await run_owned_thread(
            executor._verified,
            remember_closed_order_history,
            executor.journal.journal,
            executor.journal.cohorts,
            executor.journal.policy,
            source,
        )
        return source

    @staticmethod
    def _slot_identity(path):
        info = path.lstat()
        return [str(v) for v in (info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid)]

    def _protected(self, model):
        baseline = self.promotion.baseline_summary()
        # Exclusions only: an unavailable/conflicted head cannot authorize a
        # cleanup, and the current incumbent is never a retirement candidate.
        return (
            baseline is None
            or baseline["held_for_conflict"]
            or baseline["model_sha256"] == model
            or self.worker.inbox.protects_incumbent(model)
        )

    @asynccontextmanager
    async def _idle_slot(self, path):
        port, parallel = self.port, self.port.parallel
        lock = port.materializations if parallel is None else parallel.condition
        async with lock:
            busy = (
                port.active_candidate_invocations or port.paired_execution.locked()
                if parallel is None
                else (
                    parallel.readers[path]
                    or parallel.pins[parallel.assigned.get(path)]
                    or parallel.locks[path].locked()
                )
            )
            if busy:
                yield False
                return
            with BootDiskModelCache(
                port.boot,
                reserve_bytes=port.artifacts.config.materialization_free_space_reserve_bytes,
            ).allocation_lease():
                yield True

    async def _retire(self, key, intent):
        if digest(intent) != key:
            raise ValueError("cache retirement intent identity requires repair")
        path = Path(intent["slot"])
        if not managed_model_slot(path, self.port.cache):
            raise ValueError("cache retirement intent selects an unmanaged slot")
        if await run_owned_thread(self._protected, intent["model_sha256"]):
            return {
                "status": "waiting",
                "retired_models": 0,
                "reason": "current_incumbent_or_unavailable_head",
            }
        async with self._idle_slot(path) as idle:
            if not idle:
                return {
                    "status": "waiting",
                    "retired_models": 0,
                    "reason": "active_model_cache_consumer",
                }
            async with retirement_generation_lease(intent):
                # Durable remote facts survive cache eviction. Changed completion
                # records require explicit repair, never a new payload pass.
                for name, stamp in intent["remote_records"].items():
                    if _file_identity(Path(name).lstat()) != stamp:
                        raise ValueError("cache retirement remote completion changed")
                if path.exists() or path.is_symlink():
                    if self._slot_identity(path) != intent["slot_identity"]:
                        raise ValueError("cache retirement slot was replaced")
                    await self.port._evict_archive(path, leased=True)
                if self.port.parallel is not None:
                    self.port.parallel.assigned.pop(path, None)
                    self.port.parallel.recency.pop(path, None)
                await run_owned_thread(
                    self.journal.put,
                    "model_cache_retired",
                    key,
                    {"intent_sha256": digest(intent), "payload_bytes": intent["payload_bytes"]},
                )
                return {
                    "status": "completed",
                    "retired_models": 1,
                    "payload_bytes": intent["payload_bytes"],
                }

    async def __call__(self):
        if self.port.boot is None or self.promotion is None:
            return {"status": "unsupported_cache_layout", "retired_models": 0}
        with TransferProgress("terminal_model_cache_retirement", 1, unit="models") as progress:
            held, blocked = None, set()
            pending = await run_owned_thread(self._pending)
            if pending is not None:
                blocked.add(Path(pending[1]["slot"]))
                try:
                    result = await self._retire(*pending)
                except (OSError, ValueError) as error:
                    held = "terminal_cache_intent_requires_repair"
                    progress.emit("repair_required", reason=held)
                    logger.warning("terminal_model_cache_retirement_requires_repair: %s", error)
                else:
                    if result["status"] == "completed":
                        progress.advance(1, restored=True)
                        return result
                    held = result["reason"]
                    progress.emit("waiting", reason=held)
            revisions = await run_owned_thread(self.port.resume_model_revisions)
            for model in revisions:
                if await run_owned_thread(self._protected, model):
                    held = "current_or_frozen_incumbent"
                    continue
                slots = await run_owned_thread(
                    partial(self.worker.inbox.assignments_for_models, (model,), limit=32)
                )
                if not slots:
                    held = "retained_candidate_assignment_unavailable"
                for slot in slots:
                    assignment = await run_owned_thread(self.worker.inbox.assignment, slot)
                    order = assignment.certificate.order
                    if order.round.incumbent_model_sha256 == model:
                        continue
                    executor = self.worker.executor
                    if await executor._completed(assignment, slot) is None:
                        held = "candidate_execution_pending"
                        continue
                    terminal = await self._terminal(order.round.cohort_sha256)
                    if terminal is None:
                        held = "cohort_not_terminal"
                        continue
                    job = await run_owned_thread(executor.journal.validate_assignment, assignment)
                    plan = await self.port._source_plan(job, "candidate")
                    check = (
                        None
                        if plan is None
                        else getattr(plan.materializer, "completed_cache_retirement", None)
                    )
                    if check is None:
                        held = "source_retirement_not_supported"
                        continue  # Unrecognized sources retain their original storage.
                    for path in tuple(self.port.cache.iterdir()):
                        if (
                            path in blocked
                            or not managed_model_slot(path, self.port.cache)
                            or not (path / model).is_dir()
                        ):
                            continue
                        if (path / "materialization-pending.json").exists():
                            held = "unfinished_materialization"
                            continue
                        async with self._idle_slot(path) as idle:
                            if not idle:
                                held = "active_model_cache_consumer"
                                continue
                            facts = await run_owned_thread(check, plan.request, path)
                            intent = dict(
                                facts,
                                slot=str(path),
                                slot_identity=self._slot_identity(path),
                                cohort_sha256=order.round.cohort_sha256,
                                terminal_history_sha256=digest(terminal),
                            )
                            key = digest(intent)
                            await run_owned_thread(
                                self.journal.put, "model_cache_retirement", key, intent
                            )
                        result = await self._retire(key, intent)
                        if result["status"] == "completed":
                            progress.advance(1)
                        else:
                            progress.emit("waiting", reason=result["reason"])
                        return result
            if held is not None:
                progress.emit("waiting", reason=held)
                return {"status": "waiting", "retired_models": 0, "reason": held}
            progress.advance(1)
            return {"status": "current", "retired_models": 0}
