"""Migrate original native coverage into preparation completion before replay."""

import asyncio
from types import SimpleNamespace

import pytest

from umi import competition_reward_preparation as preparation_module
from umi.competition_reward_coverage_service import (
    StandingPreparationRepairRequired,
    StandingRewardCoverageService,
)
from umi.competition_reward_decisions import RewardActivation
from umi.competition_reward_preparation import StandingRewardPreparation
from umi.competition_reward_transition_anchor import RewardLiveAnchorMissing
from umi.open_competition import digest

from .test_competition_reward_preparation import base_policy as base_policy
from .test_competition_reward_preparation import chain as chain
from .test_competition_reward_preparation import chain_config as chain_config
from .test_competition_reward_preparation import (
    complete_preparation_case as complete_preparation_case,
)
from .test_competition_reward_preparation import endpoint as endpoint
from .test_competition_reward_preparation import execution as execution
from .test_competition_reward_preparation import granted as granted
from .test_competition_reward_preparation import harness as harness
from .test_competition_reward_preparation import known_video_bytes as known_video_bytes
from .test_competition_reward_preparation import legacy_scenario as legacy_scenario
from .test_competition_reward_preparation import miner_policy as miner_policy
from .test_competition_reward_preparation import native_package as native_package
from .test_competition_reward_preparation import original_chain as original_chain
from .test_competition_reward_preparation import original_chain_config as original_chain_config
from .test_competition_reward_preparation import original_harness as original_harness
from .test_competition_reward_preparation import original_policy as original_policy
from .test_competition_reward_preparation import policy as policy
from .test_competition_reward_preparation import preparation_case as preparation_case
from .test_competition_reward_preparation import receipt_scenario as receipt_scenario
from .test_competition_reward_preparation import recovery as recovery
from .test_competition_reward_preparation import recovery_case as recovery_case
from .test_competition_reward_preparation import registered_case as registered_case
from .test_competition_reward_preparation import relay as relay
from .test_competition_reward_preparation import runtime as runtime
from .test_competition_reward_preparation import scenario as scenario
from .test_competition_reward_preparation import service as service
from .test_competition_reward_preparation import service_catalog_inputs as service_catalog_inputs
from .test_competition_reward_preparation import service_closed as service_closed
from .test_competition_reward_preparation import service_owner as service_owner
from .test_competition_reward_preparation import service_quality_inputs as service_quality_inputs
from .test_competition_reward_preparation import shared_control_group as shared_control_group


@pytest.fixture
def coverage_test_live_row():
    return True


def activation():
    return RewardActivation(
        cohort_sha256="11" * 32,
        package_sha256="22" * 32,
        allocation_sha256="33" * 32,
        recovery_tip_sha256="44" * 32,
        prior_opportunity_sha256="55" * 32,
    )


def no_work(*args, **kwargs):
    pytest.fail("completed native work repeated package, model or proof replay")


@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_original_native_coverage_migrates_without_preparation_checkpoint(
    complete_preparation_case, coverage_test_live_row, tmp_path, monkeypatch
):
    from umi.competition_reward_coverage_intervals import coverage_point
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_reward_preparation_checkpoint import PreparationCheckpointRepairRequired
    from umi.competition_verification_snapshot import VerifiedPackageSnapshot

    h = complete_preparation_case
    p, c = h.package_case, h.c
    # The fixture's synthetic chain contains an actual current row-write.
    # Package replay, snapshot storage and coverage issuance remain native.
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    files = StandingRewardFiles(
        tmp_path / "retained-inputs",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    snapshot = files.verified_package(digest(p.package))
    root = tmp_path / "retained-coverage"

    def owner():
        return StandingRewardPreparation(
            c.reader,
            p.store,
            p.manifest,
            maximum_promotion_bytes=1_000_000,
            allocation_sink=files.retain_allocation,
        )

    original = owner()

    class OriginalPreparationRetention:
        """Emulate the old producer's absence of the new preparation store only."""

        async def restore(self, *args):
            return None

        def retain(self, *args):
            pass

        async def finish(self, package, prepared, **kwargs):
            original._export_allocations(package.allocation, prepared.allocation)
            return prepared

    original._preparation_reuse = OriginalPreparationRetention()
    journal = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
    source = NativeRewardCoverageSource(
        provider=h.item.provider,
        journal=journal,
        history=h.reader,
        preparation=original,
        package=snapshot,
        decisions=c.source,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )
    for _ in range(100):
        try:
            retained = await source.capture(h.validator_hotkey, h.end)
            break
        except CoverageHistoryPending:
            pass
    else:
        pytest.fail("native coverage fixture failed to converge")
    await journal.retain_endpoint(retained)
    point = coverage_point(retained, rule)
    assert retained.row_matches and point.covered
    assert retained.eligibility.subject.validator_last_update == point.block
    assert (
        journal.first_live_anchor(
            retained.prepared.activation,
            validators=c.series.validators,
            chain_config_sha256=c.reader.admission_chain_config_sha256,
            not_before_block=c.series.recovery.authority.issued_at_block,
        )
        == point.key()
    )

    restored_owner = owner()
    restarted_journal = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
    coverage = StandingRewardCoverageService(
        provider=h.item.provider,
        journal=restarted_journal,
        # Startup and executor first authenticate their shared control-history
        # owner. The compatibility hook cannot restore a cold history itself.
        history=h.reader,
        preparation=restored_owner,
        files=files,
        profile=h.item.profile,
        maximum_history_blocks=4096,
    )
    selected = retained.prepared.activation
    assert restored_owner.preparation_reuse.store.status(digest(selected), h.end) is None
    # Older completion records predate the live-row lookup index. Losing that
    # index also cannot turn completed native work into first preparation.
    with restarted_journal.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind GLOB 'coverage_live_anchor_*'")
    monkeypatch.setattr(preparation_module, "_replay_detached_reward_package", no_work)
    monkeypatch.setattr(VerifiedPackageSnapshot, "read", no_work)
    monkeypatch.setattr(coverage.history, "advance", no_work)
    # Missing the old compact export is repairable metadata loss, not permission
    # to replay the package or manufacture a replacement allocation.
    allocation_path = files.root / "allocations" / (digest(retained.prepared.allocation) + ".json")
    saved = allocation_path.with_suffix(".saved")
    allocation_path.rename(saved)
    with pytest.raises(StandingPreparationRepairRequired):
        await coverage.restore_preparation(selected, through_block=h.end)
    saved.rename(allocation_path)
    with pytest.raises(StandingPreparationRepairRequired, match="selected activation"):
        await coverage.restore_preparation(selected, through_block=h.end - 1)
    restored = await coverage.restore_preparation(selected, through_block=h.end)
    assert restored.activation == selected
    assert restored.allocation == retained.prepared.allocation
    assert not restored.chain_submission_authorized
    assert restored_owner.baseline_candidate(restored) == original.baseline_candidate(
        retained.prepared
    )
    # The migrated preparation now takes precedence over the compatibility path.
    monkeypatch.setattr(restarted_journal, "first_live_anchor", no_work)
    assert await coverage.restore_preparation(selected, through_block=h.end) is None
    with restored_owner.preparation_reuse.store.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='preparation_checkpoint_native'")
    with pytest.raises(StandingPreparationRepairRequired) as error:
        await coverage.restore_preparation(selected, through_block=h.end)
    assert isinstance(error.value.__cause__, PreparationCheckpointRepairRequired)


@pytest.mark.parametrize(
    "state", ["new", "interrupted", "native", "damaged_native", "lost_endpoint"]
)
async def test_compatibility_discovery_never_infers_completion_from_host_state(state):
    from umi.competition_reward_preparation_checkpoint import PreparationCheckpointRepairRequired

    selected = activation()
    calls = []

    def status(key, block):
        calls.append("native")
        assert (key, block) == (digest(selected), 100)
        if state == "damaged_native":
            raise PreparationCheckpointRepairRequired("native completion missing")
        return {} if state == "native" else None

    def anchor(*args, **kwargs):
        calls.append("anchor")
        if state != "lost_endpoint":
            raise RewardLiveAnchorMissing("no indexed live row")
        return "aa" * 32

    async def restore(*args, **kwargs):
        calls.append("endpoint")
        return None

    async def inventory(*args):
        calls.append("inventory")
        return None

    coverage = object.__new__(StandingRewardCoverageService)
    coverage.preparation = SimpleNamespace(
        preparation_reuse=SimpleNamespace(store=SimpleNamespace(status=status)),
        reader=SimpleNamespace(
            series=SimpleNamespace(
                validators=("validator",),
                recovery=SimpleNamespace(authority=SimpleNamespace(issued_at_block=1)),
            ),
            admission_chain_config_sha256="bb" * 32,
        ),
    )
    coverage.files = SimpleNamespace()
    coverage.journal = SimpleNamespace(first_live_anchor=anchor, restore_endpoint=restore)
    coverage.provider, coverage.profile = object(), object()
    coverage.history = SimpleNamespace(verified_prefix=no_work)
    coverage._package_guard = asyncio.Lock()
    coverage._preparation_model_groups = {}
    coverage._preparation_endpoint = inventory
    if state in {"damaged_native", "lost_endpoint"}:
        with pytest.raises(StandingPreparationRepairRequired):
            await coverage.restore_preparation(selected, through_block=100)
    else:
        assert await coverage.restore_preparation(selected, through_block=100) is None
    assert calls == (
        ["native"]
        if state in {"native", "damaged_native"}
        else ["native", "anchor", "endpoint"]
        if state == "lost_endpoint"
        else ["native", "anchor", "inventory"]
    )


async def test_boot_restores_original_initial_activation_before_package_loading():
    from umi.competition_reward_service import _prepare_first

    initial = activation()
    current = initial.model_copy(update={"cohort_sha256": "99" * 32})
    prepared = SimpleNamespace(activation=initial)
    calls = []

    async def prefix(_):
        return "native history"

    async def control(*args):
        return SimpleNamespace(control_sha256="aa" * 32)

    async def restore(selected, *, through_block):
        calls.append((selected, through_block))
        return prepared

    reader = SimpleNamespace(
        review_history=lambda *args: SimpleNamespace(
            initial_selection=SimpleNamespace(activation=initial),
            effective_selection=SimpleNamespace(activation=current),
        )
    )
    history = SimpleNamespace(first_block=1, verified_prefix=prefix, review_control=control)
    result = await _prepare_first(
        SimpleNamespace(reader=reader),
        object(),
        history,
        no_work,
        object(),
        100,
        64,
        coverage=SimpleNamespace(restore_preparation=restore),
    )
    assert result is prepared and calls == [(initial, 100)]


async def test_executor_restores_selected_activation_before_package_loading():
    from umi.competition_reward_executor import StandingRewardExecutor

    selected = activation()
    prepared = object()
    calls = []

    async def restore(value, *, through_block):
        calls.append((value, through_block))
        return prepared

    executor = object.__new__(StandingRewardExecutor)
    executor.coverage = SimpleNamespace(restore_preparation=restore)
    executor.packages = no_work
    result = await executor._prepare_package(
        selected, SimpleNamespace(snapshot=SimpleNamespace(block_number=100)), object()
    )
    assert result is prepared and calls == [(selected, 100)]
