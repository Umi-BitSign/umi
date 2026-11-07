"""Small-read concurrency preserves provider probing, fairness and cooldowns."""

import asyncio
from types import SimpleNamespace

from umi.competition_proof_rpc import FailoverProofRpc
from umi.proof_rpc_concurrency import ProviderReadGate
from umi.validator_chain import ValidatorChainError


async def test_failover_probes_once_then_admits_four_small_reads():
    probing, parallel = asyncio.Event(), asyncio.Event()
    release_probe, release_reads = asyncio.Event(), asyncio.Event()

    class Transport:
        bulk_storage_reads = False

        def __init__(self):
            self.calls = self.active = self.peak = 0

        async def request(self, method, params):
            self.calls += 1
            first = self.calls == 1
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                if first:
                    probing.set()
                    await release_probe.wait()
                else:
                    if self.active == 4:
                        parallel.set()
                    await release_reads.wait()
                return method, params
            finally:
                self.active -= 1

    transports = tuple(Transport() for _ in range(3))
    router = FailoverProofRpc(transports, timeout_seconds=15)
    tasks = [asyncio.create_task(router.request("chain_getHeader", (i,))) for i in range(12)]
    try:
        await asyncio.wait_for(probing.wait(), 5)
        await asyncio.sleep(0)
        assert transports[0].calls == transports[0].active == 1
        release_probe.set()
        await asyncio.wait_for(parallel.wait(), 5)
        assert transports[0].active == 4
        release_reads.set()
        assert await asyncio.wait_for(asyncio.gather(*tasks), 5) == [
            ("chain_getHeader", (i,)) for i in range(12)
        ]
        assert transports[0].peak == 4 and transports[0].active == 0
        assert transports[1].calls == transports[2].calls == 0
        assert all(gate.active == 0 and not gate.waiters for gate in router._provider_gates)
    finally:
        release_probe.set()
        release_reads.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def test_large_read_keeps_fifo_exclusivity_amid_parallel_headers():
    gate = ProviderReadGate()
    gate.healthy = True
    entered, release = [asyncio.Event() for _ in range(4)], [asyncio.Event() for _ in range(4)]

    async def operation(index, small):
        async with gate.lease(small_read=small):
            entered[index].set()
            await release[index].wait()

    tasks = [asyncio.create_task(operation(i, True)) for i in range(2)]
    try:
        await asyncio.wait_for(asyncio.gather(*(event.wait() for event in entered[:2])), 5)
        tasks.append(asyncio.create_task(operation(2, False)))
        await asyncio.sleep(0)
        tasks.append(asyncio.create_task(operation(3, True)))
        await asyncio.sleep(0)
        assert not entered[2].is_set() and not entered[3].is_set()
        release[0].set()
        release[1].set()
        await asyncio.wait_for(entered[2].wait(), 5)
        assert gate.active == 1 and not entered[3].is_set()
        release[2].set()
        await asyncio.wait_for(entered[3].wait(), 5)
        release[3].set()
        await asyncio.gather(*tasks)
        assert gate.active == 0 and not gate.waiters
    finally:
        for event in release:
            event.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def test_late_success_and_timeout_cannot_erase_parallel_throttling():
    entered = asyncio.Event()
    throttle, timeout, late = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Primary:
        bulk_storage_reads = False
        calls = active = 0

        async def request(self, method, params):
            self.calls += 1
            if params == ("probe",):
                return params
            self.active += 1
            if self.active == 4:
                entered.set()
            try:
                if params == (0,):
                    await throttle.wait()
                    cause = RuntimeError("private")
                    cause.response = SimpleNamespace(headers={"Retry-After": "60"})
                    raise ValidatorChainError("proof_rpc_rate_limited") from cause
                if params == (1,):
                    await timeout.wait()
                    raise asyncio.TimeoutError
                await late.wait()
                return params
            finally:
                self.active -= 1

    class Backup:
        bulk_storage_reads = False

        async def request(self, method, params):
            return params

    primary = Primary()
    router = FailoverProofRpc((primary, Backup(), Backup()), timeout_seconds=15)
    router._now = lambda: 1000.0
    await router.request("chain_getHeader", ("probe",))
    tasks = [asyncio.create_task(router.request("chain_getHeader", (i,))) for i in range(12)]
    try:
        await asyncio.wait_for(entered.wait(), 5)
        throttle.set()
        assert await asyncio.wait_for(tasks[0], 5) == (0,)
        timeout.set()
        assert await asyncio.wait_for(tasks[1], 5) == (1,)
        late.set()
        assert await asyncio.wait_for(asyncio.gather(*tasks), 5) == [(i,) for i in range(12)]
        assert primary.calls == 5 and primary.active == 0
        assert router._cooldown_until[0] == 1060.0
        assert router._cooldown_reasons[0] == "proof_rpc_rate_limited"
        assert not router._provider_gates[0].healthy
        assert all(gate.active == 0 and not gate.waiters for gate in router._provider_gates)
    finally:
        throttle.set()
        timeout.set()
        late.set()
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
