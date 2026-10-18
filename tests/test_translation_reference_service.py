"""Native-controller loop and cooperative ownership with real private journals."""

import asyncio
import os
import threading

import pytest

from umi.open_competition import digest
from umi.private_files import lock_private_file
from umi.translation_reference_service import TranslationReferencePublisherService

from .test_translation_reference_channel import channel_case as channel_case
from .test_translation_reference_publication import (
    base_policy as base_policy,
)
from .test_translation_reference_publication import (
    chain as chain,
)
from .test_translation_reference_publication import (
    chain_config as chain_config,
)
from .test_translation_reference_publication import (
    control as control,
)
from .test_translation_reference_publication import (
    policy as policy,
)
from .test_translation_reference_publication import (
    publication_case as publication_case,
)
from .test_translation_reference_publication import (
    series_case as series_case,
)


def owner(c, root, **changes):
    def allocation(sha):
        assert sha == digest(c.native.reward)
        return c.native.reward

    args = dict(
        root=root,
        reader=c.native.c.reader,
        provider=c.native.item.provider,
        approval=c.native.reopen(),
        channels=(c.reopen(),),
        decisions=c.native.c.source,
        allocations=allocation,
        horizons={digest(p): c.horizon for p in c.native.c.series.cohorts},
        poll_seconds=1,
        progress=c.events.append,
    )
    args.update(changes)
    return TranslationReferencePublisherService(**args)


async def test_native_tick_selects_current_then_successor_without_operator_intervention(
    channel_case, tmp_path
):
    c = channel_case
    await c.native.inputs()
    service = owner(c, tmp_path / "service")
    assert await service.tick() == "selected"
    next_activation = c.native.activation.model_copy(
        update={"cohort_sha256": digest(c.native.c.series.cohorts[1])}
    )
    tip = c.native.c.decision(c.native.tip, 6, activation=next_activation)
    await c.native.inputs(tip)
    assert await service.tick() == "selected"
    assert len(c.signatures) == 2
    assert c.events[-1]["status"] == "complete" and c.events[-1]["eta_seconds"] == 0


async def test_native_revocation_tick_stops_channel_without_collecting_allocation_or_weights(
    channel_case, tmp_path, monkeypatch
):
    c = channel_case
    await c.native.inputs()
    service = owner(c, tmp_path / "service")
    assert await service.tick() == "selected"
    revoked = c.native.c.decision(c.native.tip, kind="revoke")
    await c.native.inputs(revoked)

    def forbidden(*args, **kwargs):
        raise AssertionError("hold cannot require a new allocation or complete registry")

    async def forbidden_async(*args, **kwargs):
        forbidden()

    service.allocations = forbidden
    monkeypatch.setattr(service.provider, "collect_registered_weights", forbidden_async)
    assert await service.tick() == "revoked"
    assert len(c.signatures) == 2


async def test_missing_input_is_visible_wait_and_shutdown_drains_provider(channel_case, tmp_path):
    c = channel_case
    await c.native.inputs()
    stop = asyncio.Event()

    def missing(sha):
        stop.set()
        raise FileNotFoundError("replica has not arrived")

    service = owner(c, tmp_path / "service", allocations=missing)
    await service.run(stop)
    assert service.provider._closed
    assert c.events[-1]["status"] == "waiting_inputs"
    assert c.events[-1]["eta_seconds"] is None
    assert not c.signatures and not c.native.calls


async def test_cancellation_drains_started_io_before_releasing_service_lock(channel_case, tmp_path):
    c = channel_case
    await c.native.inputs()
    entered, release = threading.Event(), threading.Event()

    def blocked(sha):
        entered.set()
        assert release.wait(5)
        return c.native.reward

    service = owner(c, tmp_path / "service", allocations=blocked)
    task = asyncio.create_task(service.run(asyncio.Event()))
    try:
        assert await asyncio.to_thread(entered.wait, 5)
        task.cancel()
        await asyncio.sleep(0.03)
        assert not task.done()
        with pytest.raises(BlockingIOError):
            descriptor = lock_private_file(service.root / "reference-owner.lock")
            os.close(descriptor)
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert service.provider._closed and not c.signatures
    descriptor = lock_private_file(service.root / "reference-owner.lock")
    os.close(descriptor)


async def test_invalid_future_horizon_refuses_before_start_or_signer(channel_case, tmp_path):
    c = channel_case
    with pytest.raises(ValueError, match="explicit valid cohort horizons"):
        owner(c, tmp_path / "service", horizons={})
    assert not c.signatures and not (tmp_path / "service").exists()
