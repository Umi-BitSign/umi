import asyncio
from types import SimpleNamespace

import pytest

from umi.registration_bridge import _registration_bindings


def test_roster_binding_reads_are_bounded_and_keep_uid_order():
    async def run():
        class Snapshot:
            active = peak = count = 0

            async def query(self, item, params):
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.count += 1
                try:
                    await asyncio.sleep(0)
                    return params[-1]
                finally:
                    self.active -= 1

        snapshot = Snapshot()
        participants = [SimpleNamespace(uid=uid, hotkey=f"hotkey-{uid}") for uid in range(256)]
        rows = await _registration_bindings(snapshot, participants)
        assert rows == [(uid, f"hotkey-{uid}", uid, f"hotkey-{uid}") for uid in range(256)]
        assert snapshot.count == 1024 and snapshot.peak <= 8 and snapshot.active == 0

    asyncio.run(run())


@pytest.mark.parametrize("cancel", [False, True])
def test_failed_or_cancelled_snapshot_drains_all_pending_reads(cancel):
    async def run():
        entered = asyncio.Event()

        class Snapshot:
            active = 0

            async def query(self, item, params):
                self.active += 1
                try:
                    entered.set()
                    if params[-1] == 0 and not cancel:
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
        assert snapshot.active == 0
        assert not (asyncio.all_tasks() - {asyncio.current_task()})

    asyncio.run(run())
