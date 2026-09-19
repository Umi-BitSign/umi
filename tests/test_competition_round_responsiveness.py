"""A coordinator must retain ownership without blocking its event loop."""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.async_ownership import PausedCall
from tests.test_competition_round_assets import policy as policy
from tests.test_competition_round_assets import runtime as runtime
from tests.test_competition_round_assets import setup as setup
from tests.test_competition_round_assets import work as work
from umi import competition_rounds as rounds
from umi import competition_work_plans as plans
from umi.private_files import publish_private_model


@pytest.fixture
def prepared_coordinator(setup, tmp_path):
    item = setup
    coordinator = object.__new__(rounds.RoundCoordinator)
    coordinator.policy = item.policy
    coordinator.serial = asyncio.Lock()
    coordinator.config = SimpleNamespace(
        work=SimpleNamespace(asset_directory=str(tmp_path / "assets")),
        promotion_delivery=SimpleNamespace(archive_directory=str(item.archive)),
    )
    coordinator.journal = rounds.RoundJournal(tmp_path / "rounds", {"test": "ownership"})
    coordinator.publish_certificate = lambda _: item.work.plan.cutoff
    calls = []

    async def prepare(plan, *, videos):
        calls.append((plan, videos, threading.get_ident()))

    coordinator.work_queue = SimpleNamespace(prepare=prepare)
    schedule = item.round.public_schedule
    plan = rounds.RoundPlan(
        schema="umi-round-plan/2",
        suite=item.work.item.suite,
        public_schedule=schedule,
        eligible_tracks=item.round.eligible_tracks,
        intake_opened_block=schedule.intake_opened_block,
        not_before_block=schedule.roster_close_earliest_block,
        admission_close_by_block=schedule.roster_close_latest_block,
        signing_close_block=schedule.work_signing_close_block,
        evaluation_close_block=schedule.evaluation_close_block,
        reveal_block=schedule.protected_reference_reveal_block,
        evidence_cutoff_block=schedule.evidence_cutoff_block,
        valid_through_block=schedule.round_valid_through_block,
    )
    coordinator.journal.put("plan", item.round.suite_sha256, plan)
    publish_private_model(
        Path(coordinator.config.work.asset_directory) / (item.round.suite_sha256 + ".json"),
        item.assets,
    )
    proposal = rounds.RoundProposal(
        schema="umi-round-proposal/1",
        cutoff=item.work.plan.cutoff.publication,
        submissions=item.work.plan.submissions,
        signing_close_block=plan.signing_close_block,
    )
    return coordinator, proposal, calls, item


@pytest.mark.asyncio
@pytest.mark.parametrize("entry", ["prepare_work", "_publish_cutoff_and_work"])
@pytest.mark.parametrize("operation", ["certificate", "assets", "plan"])
@pytest.mark.parametrize("cancel", [False, True])
async def test_preparation_is_responsive_and_drains_before_unlock(
    prepared_coordinator, monkeypatch, operation, cancel, entry
):
    coordinator, proposal, calls, item = prepared_coordinator
    owner, name = {
        "certificate": (coordinator, "publish_certificate"),
        "assets": (rounds, "_read"),
        "plan": (plans, "prepare_work_plan"),
    }[operation]
    paused = PausedCall(getattr(owner, name))
    monkeypatch.setattr(owner, name, paused)

    async def prepare():
        async with coordinator.serial:
            await getattr(coordinator, entry)(proposal)

    task = asyncio.create_task(prepare())
    try:
        await asyncio.wait_for(paused.entered.wait(), timeout=5)
        assert paused.thread_id != threading.get_ident()
        assert coordinator.serial.locked() and not task.done()
        if cancel:
            for _ in range(2):
                task.cancel()
                await asyncio.sleep(0)
                assert coordinator.serial.locked() and not task.done()
        paused.release.set()
        if cancel:
            with pytest.raises(asyncio.CancelledError):
                await asyncio.wait_for(task, timeout=5)
            assert not calls
        else:
            await asyncio.wait_for(task, timeout=5)
            assert calls == [(item.work.plan, item.work.options["videos"], threading.get_ident())]
        assert paused.finished.is_set() and not coordinator.serial.locked()
    finally:
        paused.release.set()
        await asyncio.gather(task, return_exceptions=True)


@pytest.mark.asyncio
@pytest.mark.parametrize("with_work", [False, True])
async def test_cutoff_is_published_once_with_or_without_work(prepared_coordinator, with_work):
    coordinator, proposal, calls, item = prepared_coordinator
    published = []

    def publish(proposal):
        published.append(threading.get_ident())
        return item.work.plan.cutoff

    coordinator.publish_certificate = publish
    if not with_work:
        coordinator.work_queue = None
    await coordinator._publish_cutoff_and_work(proposal)
    assert len(published) == 1
    assert published[0] != threading.get_ident()
    assert len(calls) == int(with_work)


@pytest.mark.asyncio
async def test_missing_quorum_does_not_read_assets_or_prepare_work(
    prepared_coordinator, monkeypatch
):
    coordinator, proposal, calls, _ = prepared_coordinator
    coordinator.publish_certificate = lambda _: None

    def unexpected(*args):
        pytest.fail("missing quorum must not read assets")

    monkeypatch.setattr(rounds, "_read", unexpected)
    await coordinator.prepare_work(proposal)
    assert not calls
