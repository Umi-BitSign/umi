"""A later ancestry step must not inherit hours spent on preceding history."""

from collections import OrderedDict
from types import SimpleNamespace

import pytest

from umi import competition_reward_cutover as module
from umi.competition_reward_cutover_ownership import hold_reward_cutover_owner

from .test_competition_reward_cutover import chain as chain
from .test_competition_reward_cutover import chain_config as chain_config
from .test_competition_reward_cutover import config_case as config_case
from .test_competition_reward_cutover import control as control
from .test_competition_reward_cutover import cutover_case as cutover_case
from .test_competition_reward_cutover import historical as historical
from .test_competition_reward_cutover import inputs as inputs
from .test_competition_reward_cutover import original_chain as original_chain
from .test_competition_reward_cutover import original_chain_config as original_chain_config
from .test_competition_reward_cutover import policy as policy
from .test_competition_reward_cutover import series_case as series_case


@pytest.fixture
def progress(monkeypatch):
    clock = SimpleNamespace(now=20000.0)
    recovery = SimpleNamespace(_anchor=("anchor", 1000), progress=OrderedDict())
    owner = object.__new__(module.NativeRewardCutoverReview)
    owner.provider = SimpleNamespace(_historical_headers=recovery)
    owner._recovery_sample = None
    monkeypatch.setattr(module.time, "monotonic", lambda: clock.now)
    monkeypatch.setattr(module, "_decode_header", lambda raw, **_: {"number": raw})
    return owner, recovery, clock


def test_late_stage_uses_cursor_deltas_and_withdraws_stalled_estimate(progress):
    owner, recovery, clock = progress
    recovery.progress[("anchor", 0)] = 900
    first = owner._recovery_progress()
    assert first["recovery_elapsed_seconds"] == 0
    assert first["recovery_eta_seconds"] is None
    assert first["recovery_planning_eta_seconds"] == [0.45, 900]
    assert first["recovery_eta_scope"] == "historical_header_recovery_only"
    clock.now += 10
    recovery.progress[("anchor", 0)] = 800
    measured = owner._recovery_progress()
    assert measured["recovery_elapsed_seconds"] == 10
    assert measured["recovery_eta_seconds"] == 80
    assert measured["recovery_percent"] == 20
    clock.now += 59
    assert not owner._recovery_progress()["recovery_stalled"]
    clock.now += 1
    stalled = owner._recovery_progress()
    assert stalled["recovery_stalled"] and stalled["recovery_eta_seconds"] is None
    assert stalled["recovery_planning_eta_seconds"] is None
    clock.now += 1
    recovery.progress[("anchor", 0)] = 0
    complete = owner._recovery_progress()
    assert complete["recovery_eta_seconds"] == 0
    assert complete["recovery_percent"] == 100 and not complete["recovery_stalled"]


@pytest.mark.parametrize("change", ["target", "anchor", "anchor_same_height", "rollback"])
def test_different_or_regressed_cursor_does_not_borrow_previous_speed(progress, change):
    owner, recovery, clock = progress
    recovery.progress[("anchor", 0)] = 900
    owner._recovery_progress()
    clock.now += 10
    recovery.progress[("anchor", 0)] = 700
    assert owner._recovery_progress()["recovery_eta_seconds"] == 35
    clock.now += 10
    if change == "target":
        recovery.progress[("anchor", 100)] = 600
    elif change in {"anchor", "anchor_same_height"}:
        recovery._anchor = ("later", 1100 if change == "anchor" else 1000)
        recovery.progress[("later", 0)] = 900
    else:
        recovery.progress[("anchor", 0)] = 800
    changed = owner._recovery_progress()
    assert changed["recovery_elapsed_seconds"] == 0
    assert changed["recovery_eta_seconds"] is None


def test_absent_cursor_does_not_publish_an_old_process_duration(progress):
    owner, _, _ = progress
    value = owner._recovery_progress()
    assert value["recovery_elapsed_seconds"] == 0 and value["recovery_eta_seconds"] is None


@pytest.mark.parametrize("missing", ["progress", "anchor", "matching_anchor"])
def test_disappearing_cursor_resets_rate_before_same_range_returns(progress, missing):
    owner, recovery, clock = progress
    recovery.progress[("anchor", 0)] = 900
    owner._recovery_progress()
    clock.now += 10
    recovery.progress[("anchor", 0)] = 700
    assert owner._recovery_progress()["recovery_eta_seconds"] == 35
    if missing == "progress":
        recovery.progress.clear()
    elif missing == "anchor":
        recovery._anchor = None
    else:
        recovery._anchor = ("new", 1000)
    assert owner._recovery_progress()["recovery_eta_seconds"] is None
    clock.now += 1000
    recovery._anchor = ("anchor", 1000)
    recovery.progress[("anchor", 0)] = 600
    restarted = owner._recovery_progress()
    assert restarted["recovery_elapsed_seconds"] == 0
    assert restarted["recovery_eta_seconds"] is None
    assert restarted["recovery_planning_eta_seconds"] == [0.3, 600]


def test_cursor_from_another_anchor_does_not_change_active_progress(progress):
    owner, recovery, clock = progress
    recovery.progress[("anchor", 0)] = 900
    owner._recovery_progress()
    clock.now += 10
    recovery.progress[("anchor", 0)] = 800
    recovery.progress[("other", 0)] = 400
    value = owner._recovery_progress()
    assert value["recovery_completed_headers"] == 200
    assert value["recovery_eta_seconds"] == 80


def test_planning_range_is_withdrawn_when_no_cursor_advance_occurs(progress):
    owner, recovery, clock = progress
    recovery.progress[("anchor", 0)] = 900
    assert owner._recovery_progress()["recovery_planning_eta_seconds"] == [0.45, 900]
    clock.now += 60
    stalled = owner._recovery_progress()
    assert stalled["recovery_stalled"]
    assert stalled["recovery_eta_seconds"] is None
    assert stalled["recovery_planning_eta_seconds"] is None


def test_same_clock_tick_is_planning_then_measured_and_restart_resets_sample(progress):
    owner, recovery, clock = progress
    recovery.progress[("anchor", 0)] = 900
    owner._recovery_progress()
    recovery.progress[("anchor", 0)] = 800
    assert owner._recovery_progress()["recovery_eta_seconds"] is None
    clock.now += 10
    measured = owner._recovery_progress()
    assert measured["recovery_eta_seconds"] == 80
    restarted = object.__new__(module.NativeRewardCutoverReview)
    restarted.provider, restarted._recovery_sample = owner.provider, None
    fresh = restarted._recovery_progress()
    assert fresh["recovery_elapsed_seconds"] == 0
    assert fresh["recovery_eta_seconds"] is None
    assert fresh["recovery_completed_headers"] == measured["recovery_completed_headers"]


@pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)
@pytest.mark.parametrize("capacity", [False, True])
async def test_native_step_withdraws_planning_estimate_until_capacity_repair(
    cutover_case, monkeypatch, capacity
):
    c = cutover_case
    with hold_reward_cutover_owner(c.config) as lease:
        owner = c.review(lease)
        recovery = owner.provider._historical_headers
        recovery._anchor = ("anchor", 1000)
        recovery.progress[("anchor", 0)] = 900
        monkeypatch.setattr(module, "_decode_header", lambda raw, **_: {"number": raw})

        async def unfinished(*_):
            error = (
                module.HistoricalHeaderRecoveryPending
                if capacity
                else module.HistoricalHeaderRecoveryProgress
            )
            raise error("synthetic bounded native recovery")

        monkeypatch.setattr(owner, "_recover", unfinished)
        result = await owner.step(c.cohort)
        assert result["recovery_eta_seconds"] is None
        assert result["recovery_planning_eta_seconds"] == (None if capacity else [0.45, 900])
        assert result["capacity_repair_required"] is capacity
        assert not result["publication_authorized"]
