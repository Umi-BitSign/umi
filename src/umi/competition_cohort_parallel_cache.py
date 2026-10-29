"""Bounded resident pairs with per-slot readers and shared host preparation."""

import asyncio
import json
import logging
import time
from collections import Counter
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass

from .competition_cohort_public_progress import execution_job_scope
from .competition_model_cache_space import BootDiskModelCache, managed_model_slot
from .competition_transport_verification import TransferProgress
from .concurrency import await_owned_task, run_owned_thread
from .open_competition import digest
from .private_files import PrivateStateBusyError


@dataclass(frozen=True)
class ModelPlan:
    request: object
    bundle: object
    materializer: object
    identity: str


class ParallelModelCache:
    capacity_poll_seconds = 10.0

    def __init__(self, port, admission, concurrency):
        if type(concurrency) is not int or not 1 <= concurrency <= 32:
            raise ValueError("parallel model capacity is outside benchmark bounds")
        self.port, self.admission = port, admission
        self.concurrency = min(concurrency, len(admission.slots))
        needed = (
            port.cache / "archive",
            port.cache / "standby",
            *(port.cache / f"slot-{index:04d}" for index in range(2, self.concurrency + 1)),
        )
        self.slots = tuple(
            dict.fromkeys(
                (
                    *needed,
                    *(
                        path
                        for path in sorted(port.cache.iterdir())
                        if managed_model_slot(path, port.cache)
                    ),
                )
            )
        )
        self.condition = asyncio.Condition()
        self.pairs, self.pins, self.readers = {}, Counter(), Counter()
        self.assigned, self.recency = {}, {}
        self.locks = {path: asyncio.Lock() for path in self.slots}
        self.exclusive = False

    def budget(self):
        return BootDiskModelCache(
            self.port.boot,
            reserve_bytes=self.port.artifacts.config.materialization_free_space_reserve_bytes,
        )

    def plan(self, job, role):
        selected = self.pairs.get(digest(job))
        if selected is not None and role not in selected:
            raise ValueError("execution requested a role omitted by its validated model scope")
        return None if selected is None else selected[role]

    def owns(self, job):
        return digest(job) in self.pairs

    def _models(self, plans):
        models = {}
        for selected in (*self.pairs.values(), plans):
            for plan in selected.values():
                if plan is not None:
                    previous = models.setdefault(plan.identity, plan.bundle)
                    if previous != plan.bundle:
                        raise ValueError("materialization identity changed its immutable model")
        return models

    async def _resident_capacity(self, budget):
        try:
            with budget.allocation_lease():
                return await run_owned_thread(budget.resident_capacity, self.port.cache)
        except PrivateStateBusyError:
            return None

    async def _fits(self, budget, models):
        try:
            with budget.allocation_lease():
                return await run_owned_thread(budget.fits_materializations, models)
        except PrivateStateBusyError:
            return None

    async def _capacity_changed(self):
        # Peer release notifies immediately. External archival/reclamation is
        # not an asyncio peer, so also sample its changing metadata periodically.
        # This is a queue wake-up, not an execution watchdog or failed attempt.
        with suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self.condition.wait(), self.capacity_poll_seconds)

    @asynccontextmanager
    async def scope(
        self,
        job,
        *,
        runtime_authorization=None,
        before_reserve=None,
        model_roles=("candidate", "incumbent"),
    ):
        runtime_options = (
            {}
            if runtime_authorization is None
            else {"runtime_authorization": runtime_authorization}
        )
        with execution_job_scope(digest(job)):
            async with self._scope(job, runtime_options, before_reserve, model_roles) as enabled:
                yield enabled

    @staticmethod
    def _roles(roles):
        if roles not in (("candidate", "incumbent"), ("candidate",), ("incumbent",)):
            raise ValueError("invalid validated model execution roles")
        return roles

    @asynccontextmanager
    async def _scope(
        self, job, runtime_options, before_reserve=None, model_roles=("candidate", "incumbent")
    ):
        plans = {role: await self.port._source_plan(job, role) for role in self._roles(model_roles)}
        budget = self.budget()
        sizes = {p.identity: budget.model_bytes(p.bundle) for p in plans.values() if p}
        if any(size > budget.maximum_bytes for size in sizes.values()):
            raise OSError("selected model exceeds the bounded boot cache")
        if before_reserve is not None:
            remaining = await before_reserve()
            if remaining is not None:
                if not set(self._roles(remaining)) <= plans.keys():
                    raise ValueError("authenticated reservation expanded its model scope")
                plans = {role: plans[role] for role in remaining}
                sizes = {p.identity: sizes[p.identity] for p in plans.values() if p}
        async with self._reserve_pair(job, plans, budget, sizes) as exclusive:
            if not exclusive:
                async with self.admission.hold(job.runtime, preparation=True, **runtime_options):
                    selected = []
                    async with self.condition:
                        for plan in {p.identity: p for p in plans.values() if p}.values():
                            selected.append((await self._select(plan), plan))
                        await self._fit({path: p.bundle for path, p in selected})
                    for path, plan in selected:
                        await self._load(path, plan)
            yield True

    async def _selection(self, plans, budget, sizes):
        """Select a mode without holding scarce inference/preparation slots."""
        capacity = await self._resident_capacity(budget)
        counts = dict(
            resident_capacity_bytes=capacity,
            requested_model_count=len(sizes),
            requested_model_bytes=sum(sizes.values()),
            largest_requested_model_bytes=max(sizes.values(), default=0),
            active_pair_count=len(self.pairs),
            pair_limit=self.concurrency,
            model_slot_limit=len(self.slots),
        )
        if capacity is None:
            return None, "cache_allocation_owner", counts
        if any(size > capacity for size in sizes.values()):
            return None, "individual_model_capacity", counts
        exclusive = sum(sizes.values()) > capacity
        if self.pairs:
            if exclusive:
                return None, "requested_pair_exclusive", counts
            if self.exclusive:
                return None, "active_pair_exclusive", counts
            if len(self.pairs) >= self.concurrency:
                return None, "pair_concurrency", counts
            working_set = self._models(plans)
            counts["working_model_count"] = len(working_set)
            if len(working_set) > len(self.slots):
                return None, "model_slot_count", counts
            counts["working_model_bytes"] = sum(budget.model_bytes(b) for b in working_set.values())
            if counts["working_model_bytes"] > capacity:
                return None, "cumulative_model_bytes", counts
        return exclusive, None, counts

    @asynccontextmanager
    async def _reserve_pair(self, job, plans, budget, sizes):
        key = digest(job)
        last_decision = None
        with TransferProgress("model_pair_queue", 1, unit="jobs") as progress:
            while True:
                async with self.condition:
                    exclusive, reason, counts = await self._selection(plans, budget, sizes)
                    if exclusive is None:
                        progress.emit("waiting", reason=reason)
                        decision = (reason, counts)
                        if decision != last_decision:
                            logging.getLogger("umi.competition.progress").info(
                                json.dumps(
                                    dict(
                                        schema="umi-model-pair-capacity-progress/1",
                                        stage="model_pair_capacity",
                                        status="waiting",
                                        job_sha256=key,
                                        reason_code=reason,
                                        completed=0,
                                        total=1,
                                        unit="working_sets",
                                        elapsed_seconds=round(
                                            time.monotonic() - progress.started, 3
                                        ),
                                        eta_seconds=None,
                                        eta_basis="waiting_for_resident_capacity_release",
                                        stalled_or_retrying=True,
                                        **counts,
                                    ),
                                    separators=(",", ":"),
                                )
                            )
                            last_decision = decision
                        await self._capacity_changed()
                        continue
                    if key in self.pairs:
                        raise ValueError("paired job already owns resident capacity")
                    self.pairs[key] = plans
                    self.exclusive = exclusive
                    self.pins.update(p.identity for p in plans.values() if p)
                    progress.advance(1)
                    break
        # Pairs own disk residency only. Native invocation admission follows
        # preparation and ends after container cleanup, before another swap.
        # Holding model-memory slots here lets idle pairs exhaust the headroom
        # their preparation needs, preventing every owner from reaching work.
        completed = False
        try:
            yield exclusive
            completed = True
        finally:
            await self._release_pair(key, plans, completed)

    async def _release_pair(self, key, plans, completed):
        async def release():
            async with self.condition:
                self.pairs.pop(key)
                self.pins.subtract(p.identity for p in plans.values() if p)
                self.exclusive = False
                for path in self.slots:
                    if (
                        not self.readers[path]
                        and not self.pins[self.assigned.get(path)]
                        and path.name.startswith("slot-")
                        and completed
                        and plans.get("candidate") is not None
                        and self.assigned.get(path) == plans["candidate"].identity
                    ):
                        # Expanded idle slots are disposable after the last
                        # reader; keep original slots and unfinished transfers.
                        with suppress(PrivateStateBusyError):
                            await self._evict(path)
                self.condition.notify_all()

        await await_owned_task(asyncio.create_task(release()))

    async def _select(self, plan):
        for path in self.slots:
            if self.assigned.get(path) == plan.identity:
                return path
        for path in self.slots:
            if self.readers[path] or self.pins[self.assigned.get(path)]:
                continue
            if path.exists() and await plan.materializer.resumable(plan.request, path):
                self.assigned[path] = plan.identity
                return path
        eligible = [
            path
            for path in self.slots
            if not self.readers[path] and not self.pins[self.assigned.get(path)]
        ]
        if not eligible and self.exclusive:
            eligible = [path for path in self.slots if not self.readers[path]]
        if not eligible:
            raise OSError("all model slots have active consumers")
        path = min(eligible, key=lambda p: (p.exists(), self.recency.get(p, 0)))
        await self._evict(path)
        self.assigned[path] = plan.identity
        return path

    async def _evict(self, path):
        if self.readers[path]:
            raise OSError("model slot still has an active reader")
        if path.exists():
            await self.port._evict_archive(path)
        self.port.slot_identities.pop(path, None)
        self.assigned.pop(path, None)

    async def _fit(self, models):
        budget = self.budget()
        with TransferProgress("model_cache_capacity", 1, unit="working_sets") as progress:
            while True:
                fits = await self._fits(budget, models)
                if fits:
                    progress.advance(1)
                    return
                if fits is None:
                    progress.emit("waiting", reason="cache_allocation_owner")
                    await self._capacity_changed()
                    continue
                evicted = False
                for path in self.slots:
                    if (
                        path not in models
                        and not self.readers[path]
                        and (not self.pins[self.assigned.get(path)] or self.exclusive)
                    ):
                        evicted = evicted or path.exists()
                        await self._evict(path)
                if evicted and await self._fits(budget, models):
                    progress.advance(1)
                    return
                progress.emit("waiting", reason="physical_model_working_set")
                await self._capacity_changed()

    async def _load(self, path, plan):
        async with self.locks[path]:
            reusable = (path / digest(plan.bundle)).is_dir() and (
                self.port.slot_identities.get(path) == plan.identity
                or await plan.materializer.materialized(plan.request, path)
            )
            if not reusable:
                self.port.slot_identities.pop(path, None)
                if path.exists() and not await plan.materializer.resumable(plan.request, path):
                    async with self.condition:
                        await self._evict(path)
                        self.assigned[path] = plan.identity
                await plan.materializer.materialize(plan.request, path)
            self.port.slot_identities[path] = plan.identity
            self.recency[path] = self.port.slot_clock = self.port.slot_clock + 1
        async with self.condition:
            self.condition.notify_all()

    async def acquire(self, plan, runtime, *, runtime_authorization=None):
        # Resident reads never join the global transfer lane. An unrelated
        # model download must not postpone a ready invocation or its release.
        async with self.condition:
            path = next((p for p in self.slots if self.assigned.get(p) == plan.identity), None)
            if (
                path is not None
                and self.port.slot_identities.get(path) == plan.identity
                and (path / digest(plan.bundle)).is_dir()
            ):
                self.readers[path] += 1
                return path
        runtime_options = (
            {}
            if runtime_authorization is None
            else {"runtime_authorization": runtime_authorization}
        )
        async with self.admission.hold(runtime, preparation=True, **runtime_options):
            async with self.condition:
                self.pins[plan.identity] += 1
            try:
                async with self.condition:
                    path = await self._select(plan)
                    await self._fit({path: plan.bundle})
                await self._load(path, plan)
                async with self.condition:
                    self.readers[path] += 1
                return path
            finally:
                async with self.condition:
                    self.pins[plan.identity] -= 1
                    self.condition.notify_all()

    async def release(self, path):
        async with self.condition:
            if self.readers[path] < 1:
                raise RuntimeError("parallel model invocation lease changed")
            self.readers[path] -= 1
            self.condition.notify_all()
