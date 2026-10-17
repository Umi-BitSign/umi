"""Scheduling over isolated synthetic endpoints; native capture is qualified separately."""

import asyncio
from types import SimpleNamespace

import pytest

from umi.competition_reward_coverage_collector import RewardCoverageCollector
from umi.competition_reward_coverage_intervals import (
    CoveragePoint,
    _issue_retained_coverage,
    coverage_point,
)
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.competition_reward_coverage_source import (
    CoverageHistoryPending,
    NativeRewardCoverageSource,
)
from umi.competition_reward_opportunity import opportunity_rule
from umi.open_competition import digest, identity

from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case


@pytest.fixture
def lanes(opportunity_case, tmp_path, monkeypatch):
    c = opportunity_case
    manifest = c.manifest.model_copy(
        update={
            "opportunity": c.manifest.opportunity.model_copy(
                update={"minimum_validator_ms": 86_400_000}
            )
        }
    )
    series = c.series.model_copy(update={"manifest_sha256": digest(manifest)})
    rule = opportunity_rule(manifest, series, c.policy)
    root = tmp_path / "gap-coverage"
    state = SimpleNamespace(head=120, calls=[], replays=[], endpoints={}, fail=set())

    def journal():
        result = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))

        # The fixture supplies synthetic endpoints only at the existing private
        # retention boundary. Real proof/checkpoint refusal and restart behavior
        # are covered by the native-consumer integration test.
        def synthetic_retained(endpoint):
            point = coverage_point(endpoint, rule)
            assert state.endpoints[point.key()] is endpoint

        monkeypatch.setattr(result, "_validate_retained", synthetic_retained)
        return result

    class Source:
        async def finalized_height(self):
            return state.head

        async def capture(self, hotkey, height):
            state.calls.append((hotkey, height))
            if (hotkey, height) in state.fail:
                raise CoverageHistoryPending
            point = CoveragePoint(
                series_sha256=digest(series),
                runtime_profile_sha256=rule.runtime_profile_sha256,
                activation_sha256=digest(c.activation),
                allocation_sha256=c.activation.allocation_sha256,
                projection_sha256="ee" * 32,
                validator_account_id=identity(hotkey),
                chain_config_sha256="11" * 32,
                block=height,
                block_hash="0x" + f"{height:064x}",
                parent_hash="0x" + f"{height - 1:064x}",
                state_root="0x" + "22" * 32,
                timestamp_ms=12_000 * height,
                covered=True,
            )
            endpoint = state.endpoints.get(point.key())
            if endpoint is None:
                endpoint = _issue_retained_coverage(point, c.activation.package_sha256, "aa" * 32)
                state.endpoints[point.key()] = endpoint
            return endpoint

        async def replay(self, key):
            state.replays.append(key)
            return state.endpoints[key]

    def owner(**kwargs):
        selected = journal()
        collector = RewardCoverageCollector(
            selected,
            Source(),
            manifest=manifest,
            series=series,
            policy=c.policy,
            activation=c.activation,
            first_block=99,
            maximum_endpoints_per_validator=2,
            maximum_backfill_endpoints_per_validator=3,
            **kwargs,
        )
        return collector, selected

    return SimpleNamespace(c=c, state=state, owner=owner, rule=rule, validators=series.validators)


async def test_new_head_checks_precede_gap_capture_and_never_credit_the_jump(lanes):
    h = lanes
    owner, journal = h.owner()
    first = await owner.step()
    expected_fresh = [(k, b) for k in h.validators for b in (117, 118)]
    expected_gap = [(k, b) for k in h.validators for b in (99, 100, 101)]
    assert h.state.calls == expected_fresh + expected_gap
    assert first.immediate and not first.errors
    h.state.calls.clear()
    h.state.head = 132
    second = await owner.step()
    assert h.state.calls == (
        [(k, b) for k in h.validators for b in (129, 130)]
        + [(k, b) for k in h.validators for b in (102, 103, 104)]
    )
    assert dict(second.credited_ms) == {k: 7 * 12_000 for k in h.validators}
    for key in await journal.interval_keys():
        interval = await journal.retained_interval(key)
        left = coverage_point(h.state.endpoints[interval.left], h.rule)
        right = coverage_point(h.state.endpoints[interval.right], h.rule)
        assert right.block == left.block + 1


@pytest.mark.parametrize("failure", ["pending", "lost_ack"])
async def test_failed_gap_block_is_retried_after_new_fresh_checks(lanes, monkeypatch, failure):
    h = lanes
    owner, journal = h.owner()
    hotkey = h.validators[0]
    if failure == "pending":
        h.state.fail.add((hotkey, 100))
    else:
        credit = journal.credit
        failed = False

        async def lost_ack(left, right):
            nonlocal failed
            value = await credit(left, right)
            point = coverage_point(right, h.rule)
            if not failed and point.block == 100 and point.validator_account_id == identity(hotkey):
                failed = True
                raise OSError("diagnostic URL must not leak")
            return value

        monkeypatch.setattr(journal, "credit", lost_ack)
    result = await owner.step()
    assert result.errors and not result.immediate
    assert owner._backfill_next[hotkey] == 100
    assert coverage_point(owner._backfill_left[hotkey], h.rule).block == 99
    h.state.head = 132
    h.state.fail.clear()
    h.state.calls.clear()
    result = await owner.step()
    assert h.state.calls[:2] == [(hotkey, 129), (hotkey, 130)]
    assert (hotkey, 100) in h.state.calls
    assert owner._backfill_next[hotkey] == 103
    assert dict(result.credited_ms)[hotkey] == 5 * 12_000


async def test_restart_replays_intervals_and_recovers_the_missing_lane_boundary(lanes):
    h = lanes
    owner, journal = h.owner()
    await owner.step()
    retained = await journal.interval_keys()
    assert retained
    restarted, fresh = h.owner()
    assert not any(v for _, v in await restarted._totals())
    for _ in range(8):
        await restarted.step()
    # All adjacent intervals in 99..120, including 116->117 between lanes.
    assert dict(await restarted._totals()) == {k: 21 * 12_000 for k in h.validators}
    assert len(await fresh.interval_keys()) == 21 * len(h.validators)
    before = await restarted._totals()
    for _ in range(3):
        await restarted.step()
    assert await restarted._totals() == before
    assert h.state.replays


async def test_backfill_progress_withdraws_eta_on_retry_and_separates_credit(lanes, caplog):
    h = lanes
    owner, _ = h.owner()
    h.state.fail.add((h.validators[0], 100))
    with caplog.at_level("INFO"):
        await owner.step()
    assert "coverage_backfill_progress" in caplog.text
    assert "withdrawn_retrying" in caplog.text
    assert "reward_opportunity_percent" in caplog.text
    assert "successor_activation_eta_seconds" in caplog.text


async def test_source_capture_restores_exact_owned_history_before_attempting_rpc(monkeypatch):
    from umi.competition_reward_coverage_checkpoint import CoverageCheckpointRepairRequired

    source = object.__new__(NativeRewardCoverageSource)
    rule = SimpleNamespace(series_sha256="aa" * 32)
    source.journal = SimpleNamespace(rule=rule, checkpoints=SimpleNamespace())
    hotkey = "5FLKx6h7DwWRuqq1dcfQafsBw5i9cbchNEFAEHrqSRthGnDZ"
    ref = SimpleNamespace(block_number=100, block_hash="0x" + "01" * 32)
    loaded, restored = [], []
    endpoint = object()

    async def history(height):
        assert height == 100
        return SimpleNamespace(tip=ref)

    def completed(key):
        loaded.append(key)
        return {"completed": True}

    async def replay(key):
        restored.append(key)
        return endpoint

    source._history, source._replay = history, replay
    source.journal.checkpoints.load = completed
    assert await source._capture(hotkey, 100) is endpoint
    key = digest(
        {"series": rule.series_sha256, "validator": identity(hotkey), "block_hash": ref.block_hash}
    )
    assert loaded == restored == [key]

    def damaged(key):
        raise CoverageCheckpointRepairRequired("original result missing")

    source.journal.checkpoints.load = damaged
    with pytest.raises(CoverageCheckpointRepairRequired):
        await source._capture(hotkey, 100)
    ref.block_number = 101
    with pytest.raises(ValueError, match="requested finalized block"):
        await source._capture(hotkey, 100)


@pytest.mark.parametrize("retrying", [False, True])
async def test_collection_failure_keeps_backoff_despite_discovery_progress(retrying):
    from umi.competition_reward_coverage_service import (
        StandingRewardCoverageService,
        _CollectionOutcome,
    )
    from umi.historical_header_recovery import HistoricalHeaderRecoveryProgress

    service = object.__new__(StandingRewardCoverageService)
    service._lock = asyncio.Lock()

    async def collection():
        return _CollectionOutcome(immediate=True, retrying=retrying)

    async def discovery():
        raise HistoricalHeaderRecoveryProgress("bounded owned ancestry advanced")

    service._collect, service._discover = collection, discovery
    assert await service.step() is (not retrying)
