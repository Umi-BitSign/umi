"""Real settlement ownership must leave HTTP admission and finality responsive."""

from __future__ import annotations

import asyncio
import threading
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from tests.async_ownership import PausedCall
from tests.test_competition_settlement_delivery import (
    chain_config as chain_config,
)
from tests.test_competition_settlement_delivery import (
    package_limits as package_limits,
)
from tests.test_competition_settlement_delivery import (
    policy as policy,
)
from tests.test_competition_settlement_delivery import (
    release_identity as release_identity,
)
from tests.test_competition_settlement_delivery import (
    replay_limits as replay_limits,
)
from tests.test_competition_settlement_delivery import (
    setup as setup,
)
from tests.test_competition_settlement_delivery import (
    signed_query,
)
from tests.test_competition_settlement_delivery import (
    signing_setup as signing_setup,
)
from tests.test_competition_settlement_loopback import listening
from umi import competition_rounds as rounds
from umi import competition_settlement_delivery as delivery
from umi import competition_settlement_preparation as preparation
from umi import competition_settlement_transport as transport
from umi.protocol import canonical_json_bytes


def loop_owned_provider(s, monkeypatch):
    original = s.provider.collect
    loop_thread = threading.get_ident()

    async def collect():
        assert threading.get_ident() == loop_thread
        return await original()

    monkeypatch.setattr(s.provider, "collect", collect)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize("stage", ["material", "settle", "publish", "read", "prepare"])
async def test_cycle_drains_blocking_stages_before_releasing_both_locks(
    setup, monkeypatch, stage, cancel
):
    s = setup
    loop_owned_provider(s, monkeypatch)
    owner, name = {
        "material": (s.coordinator.store, "settlement_material"),
        "settle": (s.coordinator.store, "settle"),
        "publish": (preparation, "_publish"),
        "read": (s.coordinator, "_settlement_prepared"),
        "prepare": (delivery, "validate_preparation"),
    }[stage]
    paused = PausedCall(getattr(owner, name))
    monkeypatch.setattr(owner, name, paused)
    task = asyncio.create_task(s.coordinator.cycle())
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=5)
        assert paused.thread_id != threading.get_ident()
        assert s.coordinator.serial.locked() and s.queue.serial.locked()
        contender_entered = asyncio.Event()

        async def contender():
            async with s.queue.serial:
                contender_entered.set()

        contender_task = asyncio.create_task(contender())
        if cancel:
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done() and not contender_entered.is_set()
                assert s.coordinator.serial.locked() and s.queue.serial.locked()
        paused.release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=5)
        else:
            assert (await asyncio.wait_for(task, timeout=5))["settlement_prepared"] == 1
        await asyncio.wait_for(contender_task, timeout=5)
        assert paused.finished.is_set()
        assert not s.coordinator.serial.locked() and not s.queue.serial.locked()
        # A drained partial commit remains retryable through the native path.
        assert (await s.coordinator.cycle())["settlement_prepared"] == 1
    finally:
        paused.release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
@pytest.mark.parametrize(
    "stage", ["prepare", "pending", "accept", "certificate", "package", "deliver"]
)
async def test_queue_blocking_stages_preserve_serial_and_provider_ownership(
    setup, monkeypatch, stage, cancel
):
    s = setup
    loop_owned_provider(s, monkeypatch)
    votes = [await signer.endorse(s.prepared) for signer in s.signers]
    if stage != "prepare":
        await s.queue.prepare(s.prepared)
    if stage in {"certificate", "package", "deliver"}:
        await s.queue.accept(votes[0])
    owner, name = {
        "prepare": (delivery, "validate_preparation"),
        "pending": (s.queue, "_prepared"),
        "accept": (s.queue, "_prepared"),
        "certificate": (s.queue, "_verify_certificate"),
        "package": (delivery, "prepare_competition_package"),
        "deliver": (delivery, "_publish"),
    }[stage]
    paused = PausedCall(getattr(owner, name))
    monkeypatch.setattr(owner, name, paused)
    if stage == "prepare":
        operation = s.queue.prepare(s.prepared)
    elif stage == "pending":
        operation = s.queue.pending(votes[0].signature.hotkey)
    else:
        operation = s.queue.accept(votes[-1])
    if cancel:
        with pytest.raises(asyncio.CancelledError):
            await paused.drive(operation, s.queue.serial, cancel=True)
    else:
        await paused.drive(operation, s.queue.serial)


@pytest.mark.asyncio
async def test_live_socket_authenticates_during_recurring_coordinator_cycle(setup, monkeypatch):
    s = setup
    loop_owned_provider(s, monkeypatch)
    # Reuse the real coordinator and queue so the app's actual lifespan drives
    # recurring native cycles against the same journals as its HTTP route.
    monkeypatch.setattr(rounds, "RoundCoordinator", lambda *a, **kw: s.coordinator)
    completed = []
    app = rounds.create_round_app(
        s.config.model_copy(update={"poll_seconds": 1}),
        s.policy,
        provider_factory=lambda *_: s.provider,
        report=completed.append,
    )
    paused = PausedCall(s.coordinator.store.settlement_material)
    monkeypatch.setattr(s.coordinator.store, "settlement_material", paused)
    admitted = asyncio.Event()
    original = transport.SQLiteNonceStore.check_and_store
    loop = asyncio.get_running_loop()

    def nonce(*args):
        result = original(*args)
        if result:
            loop.call_soon_threadsafe(admitted.set)
        return result

    monkeypatch.setattr(transport.SQLiteNonceStore, "check_and_store", nonce)
    now = [time.time_ns()]
    monkeypatch.setattr(transport, "time", SimpleNamespace(time_ns=lambda: now[0]))
    signed = signed_query(s)
    now[0] = int(signed.query.nonce_unix_ns)
    try:
        async with app.router.lifespan_context(app), listening(app) as port:
            await asyncio.wait_for(paused.entered.wait(), timeout=5)
            assert s.queue.serial.locked()
            request = asyncio.create_task(
                transport.request_settlement("https://rounds.example", signed, loopback_port=port)
            )
            await asyncio.wait_for(admitted.wait(), timeout=1)
            assert not request.done() and s.queue.serial.locked()
            # Advance only the test's admission clock after authentication. The
            # same request may wait >30s for replay; the nonce rule is unchanged.
            expired = signed_query(s, name="Dave")
            now[0] += 31_000_000_000
            paused.release.set()
            reply = await asyncio.wait_for(request, timeout=5)
            assert len(reply.proposals) == 1
            async with asyncio.timeout(5):
                while len(completed) < 2:
                    await asyncio.sleep(0.01)
            assert all(result["settlement_prepared"] == 1 for result in completed)
            # Admission still rejects an expired newly arriving signed request.
            with pytest.raises(ValueError, match="request rejected"):
                await transport.request_settlement(
                    "https://rounds.example", expired, loopback_port=port
                )
    finally:
        paused.release.set()


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["timeout", "cancel", "cancel_during_timeout"])
@pytest.mark.parametrize("native_client", [False, True])
@pytest.mark.parametrize("replay_limits", [256 * 1024**2], indirect=True)
async def test_http_timeout_and_repeated_cancel_drain_worker_before_releasing_capacity(
    setup, monkeypatch, mode, native_client
):
    s = setup
    await s.queue.prepare(s.prepared)
    app = FastAPI()
    transport.attach_settlement_route(app, s.queue)
    paused = PausedCall(s.queue._prepared)
    monkeypatch.setattr(s.queue, "_prepared", paused)
    # Exercise the actual timeout/cancellation path without a two-hour test.
    monkeypatch.setattr(
        type(s.queue.capacity),
        "operation_timeout_seconds",
        property(lambda _: 7200 if mode == "cancel" else 0.01),
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://rounds.example"
    ) as client:

        async def query():
            return await client.post(
                transport.ROUTE,
                content=canonical_json_bytes(signed_query(s)),
                headers={"Content-Type": "application/json"},
            )

        if native_client:
            task = asyncio.create_task(
                transport.request_settlement(
                    "https://rounds.example",
                    signed_query(s),
                    transport=httpx.ASGITransport(app=app),
                    capacity=s.queue.capacity,
                )
            )
        else:
            task = asyncio.create_task(query())
        try:
            await asyncio.wait_for(paused.entered.wait(), timeout=5)
            await asyncio.sleep(0.03)
            assert s.queue.serial.locked() and not task.done()
            if mode != "timeout":
                for _ in range(2):
                    task.cancel()
                    await asyncio.sleep(0)
                    assert not task.done() and s.queue.serial.locked()
            # No second large response can enter while the first worker drains.
            assert (await query()).status_code == 503
            assert s.queue.serial.locked() and not task.done()
            paused.release.set()
            if mode == "cancel" or (native_client and mode == "cancel_during_timeout"):
                with pytest.raises(asyncio.CancelledError):
                    await asyncio.wait_for(task, timeout=5)
            elif native_client:
                with pytest.raises(ValueError, match="request rejected"):
                    await asyncio.wait_for(task, timeout=5)
            else:
                assert (await asyncio.wait_for(task, timeout=5)).status_code == 503
            assert paused.finished.is_set() and not s.queue.serial.locked()
            monkeypatch.setattr(
                type(s.queue.capacity), "operation_timeout_seconds", property(lambda _: 7200)
            )
            assert (await query()).status_code == 200
        finally:
            paused.release.set()
            await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("replay_limits", [256 * 1024**2], indirect=True)
async def test_response_serialization_drains_before_request_capacity_is_released(
    setup, monkeypatch
):
    s = setup
    await s.queue.prepare(s.prepared)
    app = FastAPI()
    transport.attach_settlement_route(app, s.queue)
    paused = PausedCall(transport._reply_bytes)
    monkeypatch.setattr(transport, "_reply_bytes", paused)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://rounds.example"
    ) as client:

        async def query():
            return await client.post(
                transport.ROUTE,
                content=canonical_json_bytes(signed_query(s)),
                headers={"Content-Type": "application/json"},
            )

        task = asyncio.create_task(query())
        try:
            await asyncio.wait_for(paused.entered.wait(), timeout=5)
            assert paused.thread_id != threading.get_ident()
            assert not s.queue.serial.locked()
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                assert not task.done()
            assert (await query()).status_code == 503
            paused.release.set()
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=5)
            assert paused.finished.is_set()
            assert (await query()).status_code == 200
        finally:
            paused.release.set()
            await asyncio.gather(task, return_exceptions=True)
