"""Fresh proof collection and service-owned pin work have separate lifetimes."""

import asyncio
import threading
from types import SimpleNamespace

import pytest

from umi.competition_cohort_service_host import ServiceAdmissionHost
from umi.competition_cohort_readiness_wake import CohortReadinessWakes
from umi.competition_registration_pins import RegistrationPinProjectionPending
from umi.private_files import PrivateStateBusyError

from .test_competition_chain import _HEIGHT
from .test_competition_chain import chain as chain
from .test_competition_chain import chain_config as chain_config
from .test_competition_registration_retention import advance, retained_rows
from .test_open_competition import policy as policy


def host_for(queues):
    host = object.__new__(ServiceAdmissionHost)
    host.queues = queues
    host.cohorts = {key: key for key in queues}
    host._registration_pin_cursor = 0
    host.config = SimpleNamespace(poll_seconds=0.01)
    host.uploads = host.direct_uploads = host.models = None
    host.intake = SimpleNamespace(
        config=SimpleNamespace(cohorts=()), readiness_wakes=CohortReadinessWakes()
    )
    return host


async def test_fresh_capture_finishes_while_background_projection_is_slow(chain, monkeypatch):
    provider = chain.provider
    await provider.collect()
    before = retained_rows(provider)
    advance(chain, _HEIGHT + chain.policy.maximum_snapshot_age_blocks + 1)
    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    modes = []

    def pins(*, complete_only=False):
        modes.append(complete_only)
        if complete_only:
            raise RegistrationPinProjectionPending(0, 1)
        entered.set()
        try:
            assert release.wait(120)
            return frozenset({_HEIGHT})
        finally:
            finished.set()

    host = host_for({"a" * 64: SimpleNamespace(retained_registration_blocks=pins)})
    monkeypatch.setattr(
        provider,
        "_retained_capture_blocks",
        lambda: host.retained_registration_blocks(complete_only=True),
    )
    background = asyncio.create_task(host._poll_registration_pins())
    try:
        assert await asyncio.to_thread(entered.wait, 120)
        capture = await asyncio.wait_for(provider.collect(), 120)
        assert capture.snapshot.block == chain.finality.ref.block_number
        assert not background.done() and not finished.is_set()
        assert retained_rows(provider)[0] == before[0]
        assert modes == [False, True]
    finally:
        release.set()
        await asyncio.wait_for(background, 120)
    assert finished.is_set() and background.result()["status"] == "complete"


@pytest.mark.parametrize("restricted", [False, True])
async def test_projection_owner_drains_on_cancellation_and_never_overlaps(monkeypatch, restricted):
    import umi.competition_cohort_service_host as module

    entered, release, finished = threading.Event(), threading.Event(), threading.Event()
    calls = []

    def pins(*, complete_only=False):
        assert not complete_only
        calls.append(1)
        entered.set()
        try:
            assert release.wait(120)
            return frozenset()
        finally:
            finished.set()

    host = host_for({"a" * 64: SimpleNamespace(retained_registration_blocks=pins)})
    monkeypatch.setattr(module, "requests_stage_policy", lambda: object() if restricted else None)
    host._poll_catalogs = lambda: asyncio.sleep(0, result={"status": "ready"})
    task = asyncio.create_task(host._poll(asyncio.Event()))
    try:
        assert await asyncio.to_thread(entered.wait, 120)
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and not finished.is_set()
        task.cancel()
        await asyncio.sleep(0.02)
        assert not task.done() and calls == [1]
    finally:
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, 120)
    assert finished.is_set()


async def test_background_projection_rotates_queues_after_pending_and_busy():
    calls = []

    def pending():
        calls.append("pending")
        raise RegistrationPinProjectionPending(3, 8)

    def busy():
        calls.append("busy")
        raise PrivateStateBusyError("writer", "aa" * 32, None)

    def complete():
        calls.append("complete")
        return frozenset({400})

    host = host_for(
        {
            "a" * 64: SimpleNamespace(retained_registration_blocks=pending),
            "b" * 64: SimpleNamespace(retained_registration_blocks=busy),
            "c" * 64: SimpleNamespace(retained_registration_blocks=complete),
        }
    )
    first = await host._poll_registration_pins()
    assert (first["completed"], first["total"], first["unit"]) == (3, 8, "admissions")
    with pytest.raises(PrivateStateBusyError):
        await host._poll_registration_pins()
    assert (await host._poll_registration_pins())["status"] == "complete"
    assert calls == ["pending", "busy", "complete"]
