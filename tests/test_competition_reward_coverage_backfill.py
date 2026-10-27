"""Scheduling over isolated synthetic endpoints; native capture is qualified separately."""

import asyncio
from types import SimpleNamespace

import pytest

from umi import competition_reward_coordinator_cli, competition_supervisor_cli
from umi.competition_reward_coverage_collector import RewardCoverageCollector, _log_retry
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
from umi.r2_evidence import R2EvidenceHTTPError

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
    if failure == "lost_ack":
        assert not owner._retained_inventory_drained
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
    expected = {k: 21 * 12_000 for k in h.validators}
    for _ in range(32):
        await restarted.step()
        if dict(await restarted._totals()) == expected:
            break
    # All adjacent intervals in 99..120, including 116->117 between lanes.
    assert dict(await restarted._totals()) == expected
    assert len(await fresh.interval_keys()) == 21 * len(h.validators)
    before = await restarted._totals()
    for _ in range(3):
        await restarted.step()
    assert await restarted._totals() == before
    assert h.state.replays


async def test_completed_retained_scan_is_not_repeated_after_new_owned_credit(lanes, monkeypatch):
    h = lanes
    owner, journal = h.owner()
    await owner.step()
    assert owner._retained_inventory_drained
    before = len(await journal.interval_keys())
    assert before

    async def repeated_inventory(*, after=None, limit=256):
        pytest.fail("completed retained interval inventory was scanned again")

    monkeypatch.setattr(journal, "interval_keys", repeated_inventory)
    h.state.head = 132
    await owner.step()
    assert len(journal.journal.keys("coverage_interval")) > before


async def test_failed_retained_scan_retries_before_marking_it_complete(lanes, monkeypatch):
    h = lanes
    first, _ = h.owner()
    await first.step()
    restarted, _ = h.owner(maximum_replay_intervals=64)
    replay = restarted.source.replay
    fail_once = True

    async def interrupted(key):
        nonlocal fail_once
        if fail_once:
            fail_once = False
            raise OSError("interrupted retained endpoint read")
        return await replay(key)

    monkeypatch.setattr(restarted.source, "replay", interrupted)
    assert (await restarted.step()).errors
    assert not restarted._retained_inventory_drained
    assert not (await restarted.step()).errors
    assert restarted._retained_inventory_drained


async def test_failed_full_retained_page_prevents_later_clean_drain(lanes, monkeypatch, caplog):
    h = lanes
    first, journal = h.owner()
    await first.step()
    keys = await journal.interval_keys(limit=4096)
    assert len(keys) > 2
    first_interval = await journal.retained_interval(keys[0])
    restarted, _ = h.owner(maximum_replay_intervals=1)
    replay = restarted.source.replay
    fail_once = True

    async def interrupted(key):
        nonlocal fail_once
        if fail_once and key == first_interval.left:
            fail_once = False
            raise OSError("interrupted retained endpoint read")
        return await replay(key)

    monkeypatch.setattr(restarted.source, "replay", interrupted)
    with caplog.at_level("INFO"):
        assert (await restarted.step()).errors
    assert any(
        "coverage_retained_inventory_progress" in record.message
        and "withdrawn_retrying" in record.message
        for record in caplog.records
    )
    for _ in keys:
        await restarted.step()
    assert not restarted._retained_inventory_drained
    assert restarted._cursor is None
    await restarted.step()
    assert keys[0] in restarted._replayed


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


async def test_credit_progress_separates_finite_saved_replay_after_restart(lanes, caplog):
    h = lanes
    owner, _ = h.owner()
    original = await owner.step()
    expected = dict(original.credited_ms)
    restarted, _ = h.owner()
    with caplog.at_level("INFO", logger="umi.competition_reward_coverage_collector"):
        restored = await restarted.step()
    phases = {
        r.args["phase"]: r.args for r in caplog.records if r.msg == "coverage_credit_progress %s"
    }
    assert phases["retained_interval_replay"]["credited_delta_ms"] == expected
    zero = {k: 0 for k in h.validators}
    assert phases["recent_block_capture"]["credited_delta_ms"] == zero
    assert phases["historical_gap_capture"]["credited_delta_ms"] == zero
    assert dict(restored.credited_ms) == expected
    assert all(
        p["eta_scope"] == "this_pass_and_phase_only_not_remaining_opportunity"
        for p in phases.values()
    )


@pytest.mark.parametrize("role", ["writer", "coordinator"])
async def test_actual_cli_reports_failed_gap_without_exception_secrets(
    lanes, monkeypatch, capsys, role
):
    h = lanes
    owner, journal = h.owner()
    credit = journal.credit
    hotkey = h.validators[0]

    async def failed_credit(left, right):
        if coverage_point(right, h.rule).block == 100:
            raise OSError("https://rpc.invalid/?token=private-diagnostic-value")
        return await credit(left, right)

    monkeypatch.setattr(journal, "credit", failed_credit)
    logs = (
        competition_supervisor_cli._standing_logs
        if role == "writer"
        else competition_reward_coordinator_cli._logs
    )
    with logs():
        result = await owner.step()
    emitted = capsys.readouterr().err
    assert "coverage_backfill_progress" in emitted
    assert "coverage_retry" in emitted
    assert "'phase': 'backfill'" in emitted
    assert "'operation': 'credit_interval'" in emitted
    assert "'block': 100" in emitted and "'error_type': 'OSError'" in emitted
    assert "competition_reward_coverage_collector" in emitted
    assert "private-diagnostic-value" not in emitted and "rpc.invalid" not in emitted
    assert (hotkey, "OSError") in result.errors
    assert owner._backfill_next[hotkey] == 100
    assert coverage_point(owner._backfill_left[hotkey], h.rule).block == 99


@pytest.mark.parametrize("status", [429, 503])
def test_coverage_retry_logs_bounded_r2_http_status_without_response_data(caplog, status):
    try:
        raise R2EvidenceHTTPError(status)
    except R2EvidenceHTTPError as error:
        with caplog.at_level("INFO", logger="umi.competition_reward_coverage_collector"):
            _log_retry(error, phase="replay", operation="restore_and_credit_interval")
    report = [
        record.args for record in caplog.records if record.msg == "coverage_retry %s"
    ]
    assert len(report) == 1
    assert report[0]["r2_http_status"] == status
    assert report[0]["reason_codes"] == ["r2_http_failure"]
    assert "secret" not in caplog.text.lower()


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


async def test_first_adoption_drains_successful_retained_page_before_moving_head(lanes):
    h = lanes
    original, _ = h.owner()
    await original.step()
    # These intervals have real journal credit but predate native credit facts:
    # the fixture's private endpoint boundary supplies no checkpoint body.
    restarted, fresh = h.owner(maximum_replay_intervals=2)
    h.state.calls.clear()
    result = await restarted.step()
    assert result.immediate and not result.errors
    assert len(h.state.replays) == 4
    assert not h.state.calls  # No fresh moving-head/history work between pages.
    assert sum(dict(result.credited_ms).values()) == 24_000
    assert len(await fresh.interval_keys()) > 2
    await restarted.step()
    assert len(h.state.replays) == 8
    assert not h.state.calls


async def test_retained_page_drain_does_not_discover_new_moving_head():
    from umi.competition_reward_coverage_service import (
        StandingRewardCoverageService,
        _CollectionOutcome,
    )

    service = object.__new__(StandingRewardCoverageService)
    service._lock = asyncio.Lock()

    async def collection():
        return _CollectionOutcome(immediate=True, retrying=False, retained_page=True)

    async def discovery():
        pytest.fail("bounded retained drain must not start fresh discovery")

    service._collect, service._discover = collection, discovery
    assert await service.step()


async def test_mixed_activation_full_inventory_page_still_drains_before_fresh_capture(lanes):
    h = lanes
    original, journal = h.owner()
    await original.step()
    keys = await journal.interval_keys()
    first = await journal.retained_interval(keys[0])
    foreign = first.model_copy(
        update={"activation_sha256": "f" * 64, "left": "d" * 64, "right": "e" * 64}
    )
    journal.journal.put("coverage_interval", foreign.key(), foreign)
    restarted, _ = h.owner(maximum_replay_intervals=len(keys) + 1)
    h.state.calls.clear()
    result = await restarted.step()
    assert result.retained_page and result.immediate and not result.errors
    assert not h.state.calls
    assert len(h.state.replays) == 2 * len(keys)
