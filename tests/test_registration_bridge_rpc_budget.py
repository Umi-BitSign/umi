import asyncio
from types import SimpleNamespace

import pytest

from umi.registration_bridge import RegistrationBridgeError, _registration_bindings


@pytest.mark.parametrize("count", [0, 1, 63, 64, 65, 255, 256])
def test_roster_bindings_use_bounded_batches_and_keep_uid_order(count):
    async def run():
        class Snapshot:
            active = peak = count = calls = 0

            async def query(self, *_):
                raise AssertionError("roster must not use point reads")

            async def query_batch(self, item, params):
                assert 0 < len(params) <= 64
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.count += len(params)
                self.calls += 1
                try:
                    await asyncio.sleep(0)
                    return [p[-1] for p in params]
                finally:
                    self.active -= 1

        snapshot = Snapshot()
        participants = [SimpleNamespace(uid=uid, hotkey=f"hotkey-{uid}") for uid in range(count)]
        rows = await _registration_bindings(snapshot, participants)
        assert rows == [(uid, f"hotkey-{uid}", uid, f"hotkey-{uid}") for uid in range(count)]
        assert snapshot.count == 4 * count
        assert snapshot.calls == 4 * ((count + 63) // 64)
        assert snapshot.peak <= 1 and snapshot.active == 0

    asyncio.run(run())


@pytest.mark.parametrize("cancel", [False, True])
def test_failed_or_cancelled_snapshot_leaves_no_pending_reads(cancel):
    async def run():
        entered = asyncio.Event()

        class Snapshot:
            active = calls = 0

            async def query_batch(self, item, params):
                self.active += 1
                self.calls += 1
                try:
                    entered.set()
                    if not cancel:
                        await asyncio.sleep(0)
                        raise RuntimeError("RPC budget exhausted")
                    await asyncio.Event().wait()
                finally:
                    self.active -= 1

        snapshot = Snapshot()
        participants = [SimpleNamespace(uid=uid, hotkey=f"hotkey-{uid}") for uid in range(256)]
        task = asyncio.create_task(_registration_bindings(snapshot, participants))
        await entered.wait()
        if cancel:
            task.cancel()
        with pytest.raises(asyncio.CancelledError if cancel else RuntimeError):
            await task
        assert snapshot.active == 0 and snapshot.calls == 1
        assert not (asyncio.all_tasks() - {asyncio.current_task()})

    asyncio.run(run())


@pytest.mark.parametrize("result", [None, {}, (), [], [1, 2]])
def test_incomplete_or_malformed_batch_holds_snapshot(result):
    class Snapshot:
        async def query_batch(self, item, params):
            return result

    with pytest.raises(RegistrationBridgeError, match="registration_binding_batch_shape"):
        asyncio.run(_registration_bindings(Snapshot(), [SimpleNamespace(uid=0, hotkey="hotkey")]))
