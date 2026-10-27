"""Initial baseline control readiness reuses one provider and preserves failures."""

import asyncio
from types import SimpleNamespace

import pytest

from umi import competition_reward_baseline_restore as baseline
from umi.competition_chain import _AwaitingFinality
from umi.grandpa_finality_supervisor import GrandpaFinalitySupervisorError


def provider(collect, *, timeout=1, observer=lambda: None):
    return SimpleNamespace(
        collect_control=collect,
        config=SimpleNamespace(startup_timeout_seconds=timeout),
        ensure_observer_running=observer,
    )


@pytest.mark.parametrize(
    "initial",
    [
        None,
        _AwaitingFinality("pending"),
        GrandpaFinalitySupervisorError("no_verified_finalized_head"),
    ],
)
async def test_same_control_observer_waits_only_until_first_owned_head(
    initial, monkeypatch, caplog
):
    observation, attempts = object(), []
    caplog.set_level("INFO", logger="umi.competition.progress")

    async def collect(hotkey):
        attempts.append(hotkey)
        if initial is not None and len(attempts) == 1:
            raise initial
        return observation

    async def no_delay(_):
        pass

    monkeypatch.setattr(baseline.asyncio, "sleep", no_delay)
    assert await baseline._collect_initial_control(provider(collect), "control") is observation
    assert attempts == ["control"] * (1 if initial is None else 2)
    output = caplog.text
    assert '"stage":"cohort_baseline_initial_finality"' in output
    assert '"status":"completed"' in output
    if initial is not None:
        assert '"reason_code":"awaiting_initial_verified_finality"' in output


@pytest.mark.parametrize(
    "error",
    [
        ValueError("bad proof"),
        OSError("transport failure"),
        GrandpaFinalitySupervisorError("checkpoint_conflict"),
    ],
)
async def test_control_readiness_does_not_retry_proof_transport_or_store_failure(error):
    attempts = []

    async def collect(_):
        attempts.append(1)
        raise error

    with pytest.raises(type(error)) as raised:
        await baseline._collect_initial_control(provider(collect), "control")
    assert raised.value is error
    assert attempts == [1]


async def test_control_readiness_observer_failure_is_immediate():
    async def collect(_):
        pytest.fail("failed observer cannot authorize a control read")

    def failed():
        raise RuntimeError("owned_finality_observer_stopped")

    with pytest.raises(RuntimeError, match="observer_stopped"):
        await baseline._collect_initial_control(provider(collect, observer=failed), "control")


@pytest.mark.parametrize("cancel", [False, True])
async def test_control_readiness_timeout_and_cancellation_drain_inflight_read(cancel):
    entered, drained = asyncio.Event(), asyncio.Event()

    async def collect(_):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            drained.set()

    task = asyncio.create_task(
        baseline._collect_initial_control(provider(collect, timeout=0.1), "control")
    )
    await entered.wait()
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else asyncio.TimeoutError):
        await task
    assert drained.is_set()
