"""Transport retry retains one owner without retrying native validity failures."""

import asyncio
import json
from types import SimpleNamespace

import pytest

from umi import competition_reward_preparation_retry as retry
from umi.validator_chain import ValidatorChainError


@pytest.mark.parametrize("reason", sorted(retry._TRANSPORT_FAILURES))
async def test_retry_reuses_exact_inputs_and_withdraws_eta(reason, monkeypatch, caplog):
    progress = SimpleNamespace(estimate=True, completed=3, total=449)
    arguments = dict(attempt=b"signed", chain=b"owned", metadata=b"retained")
    events, calls = [], []
    provider = SimpleNamespace(ensure_observer_running=lambda: events.append("observer"))
    result = object()

    async def review(actual, **inputs):
        assert actual is provider and inputs == arguments
        calls.append(inputs)
        if len(calls) == 1:
            raise ValidatorChainError(reason)
        assert events == ["observer", "recheck", "wait", "observer", "recheck"]
        return result

    async def wait(actual):
        assert actual is provider and not progress.estimate
        events.append("wait")

    monkeypatch.setattr(retry, "_wait_for_retry", wait)
    assert (
        await retry.review_preparation_expiry(
            review,
            provider,
            recheck=lambda: events.append("recheck"),
            progress=progress,
            arguments=arguments,
        )
        is result
    )
    assert len(calls) == 2 and progress.completed == 3 and progress.estimate
    report = json.loads(caplog.records[-1].getMessage())
    assert report["retrying"] and report["eta_seconds"] is None
    assert report["stalled_or_retrying"] and "stalled" not in report
    assert report["retry_count"] == 1 and report["completed"] == 3
    assert report["reason_code"] == reason and not report["certification_authority"]


@pytest.mark.parametrize("failure", [ValueError("bad proof"), ValidatorChainError("proof_invalid")])
async def test_native_failure_is_never_retried(failure):
    async def review(*args, **kwargs):
        raise failure

    def forbidden():
        pytest.fail("native validity error reached transport retry")

    progress = SimpleNamespace(estimate=True)
    with pytest.raises(type(failure)) as caught:
        await retry.review_preparation_expiry(
            review,
            SimpleNamespace(ensure_observer_running=forbidden),
            recheck=forbidden,
            progress=progress,
            arguments={},
        )
    assert caught.value is failure and progress.estimate


@pytest.mark.parametrize("changed", ["observer", "source"])
async def test_retry_refuses_failed_observer_or_changed_input(changed):
    calls = 0

    async def review(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise ValidatorChainError("proof_rpc_failed")

    def check(kind):
        if kind == changed:
            raise ValueError("changed " + kind)

    with pytest.raises(ValueError, match="changed " + changed):
        await retry.review_preparation_expiry(
            review,
            SimpleNamespace(ensure_observer_running=lambda: check("observer")),
            recheck=lambda: check("source"),
            progress=SimpleNamespace(estimate=True),
            arguments={},
        )
    assert calls == 1


async def test_cancellation_during_backoff_exits_without_another_review(monkeypatch):
    entered = asyncio.Event()
    calls = 0
    progress = SimpleNamespace(estimate=True, completed=0, total=449)

    async def review(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise ValidatorChainError("proof_rpc_rate_limited")

    async def wait(provider):
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(retry, "_wait_for_retry", wait)
    task = asyncio.create_task(
        retry.review_preparation_expiry(
            review,
            SimpleNamespace(ensure_observer_running=lambda: None),
            recheck=lambda: None,
            progress=progress,
            arguments={},
        )
    )
    await asyncio.wait_for(entered.wait(), 2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert calls == 1 and progress.estimate


async def test_wait_observes_native_observer_death(monkeypatch):
    calls = 0

    def observer():
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("observer exited")

    monkeypatch.setattr(retry, "_RETRY_SECONDS", 0.005)
    with pytest.raises(RuntimeError, match="observer exited"):
        await retry._wait_for_retry(SimpleNamespace(ensure_observer_running=observer))
