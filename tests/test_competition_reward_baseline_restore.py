"""Restore native baseline metadata from completed coverage without package replay."""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_preparation as preparation
from umi.competition_reward_preparation import StandingRewardPreparation
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
def coverage_test_row():
    return []


@pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_baseline_preparation_restores_completed_native_coverage_without_payload_replay(
    complete_preparation_case, coverage_test_row, tmp_path, monkeypatch
):
    from umi.competition_reward_coverage_intervals import (
        OwnedRetainedCoverageEndpoint,
        coverage_point,
    )
    from umi.competition_reward_coverage_journal import RewardCoverageJournal
    from umi.competition_reward_coverage_source import (
        CoverageHistoryPending,
        NativeRewardCoverageSource,
    )
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_opportunity import opportunity_rule
    from umi.competition_verification_snapshot import VerifiedPackageSnapshot

    h = complete_preparation_case
    p, c = h.package_case, h.c
    # Baseline eligibility depends on certified quality, not a matching paid row.
    assert coverage_test_row == []
    rule = opportunity_rule(p.manifest, c.series, c.reader.policy)
    files = StandingRewardFiles(
        tmp_path / "baseline-inputs",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    snapshot = files.verified_package(digest(p.package))
    root = tmp_path / "baseline-coverage"

    def setup(*, sink=None):
        owner = StandingRewardPreparation(
            c.reader,
            p.store,
            p.manifest,
            maximum_promotion_bytes=1_000_000,
            allocation_sink=sink,
        )
        journal = RewardCoverageJournal(root, rule, expected_rule_sha256=digest(rule))
        source = NativeRewardCoverageSource(
            provider=h.item.provider,
            journal=journal,
            history=h.reader,
            preparation=owner,
            package=snapshot,
            decisions=c.source,
            profile=h.item.profile,
            maximum_history_blocks=4096,
        )
        return owner, journal, source

    original, journal, source = setup()
    for _ in range(100):
        try:
            endpoint = await source.capture(h.validator_hotkey, h.end)
            break
        except CoverageHistoryPending:
            pass
    else:
        pytest.fail("native baseline coverage fixture failed to converge")
    await journal.retain_endpoint(endpoint)
    assert not endpoint.row_matches
    expected = original.baseline_candidate(endpoint.prepared)
    assert endpoint.prepared.allocation.model_award is not None
    args = dict(
        activation=endpoint.prepared.activation,
        allocation=endpoint.prepared.allocation,
        package=snapshot,
    )
    expected_models = original._baseline_models[digest(args["activation"])]

    def forbid_payload(*args, **kwargs):
        pytest.fail("completed native coverage must not repeat package/model payload or proof work")

    monkeypatch.setattr(preparation, "_replay_detached_reward_package", forbid_payload)
    monkeypatch.setattr(VerifiedPackageSnapshot, "read", forbid_payload)
    restored_owner, _, _ = setup()
    # New owner accepts a fresh native endpoint; a second process restores the
    # retained endpoint through the actual selected journal/history boundary.
    fresh = await restored_owner.prepare_from_completed_coverage(endpoint, **args)
    assert restored_owner.baseline_candidate(fresh) == expected
    assert restored_owner._baseline_models[digest(args["activation"])] == expected_models
    assert not fresh.chain_submission_authorized
    assert await restored_owner.prepare_from_completed_coverage(endpoint, **args) is fresh
    restarted, _, restarted_source = setup()
    retained = await restarted_source.replay(coverage_point(endpoint, rule).key())
    assert type(retained) is OwnedRetainedCoverageEndpoint
    assert not retained.covered
    result = await restarted.prepare_from_completed_coverage(retained, **args)
    assert restarted.baseline_candidate(result) == expected
    assert restarted._baseline_models[digest(args["activation"])] == expected_models
    with pytest.raises(ValueError, match="native provenance"):
        await restarted.prepare_from_completed_coverage(replace(retained, _issuer=None), **args)
    with pytest.raises(TypeError, match="retained verified package"):
        await restarted.prepare_from_completed_coverage(retained, **(args | {"package": p.package}))
    with pytest.raises(ValueError, match="differs from selected"):
        changed = args["activation"].model_copy(update={"recovery_tip_sha256": "ff" * 32})
        await restarted.prepare_from_completed_coverage(
            retained, **(args | {"activation": changed})
        )
    with pytest.raises(ValueError, match="differs from selected"):
        changed = args["allocation"].model_copy(update={"round_sha256": "ff" * 32})
        await restarted.prepare_from_completed_coverage(
            retained, **(args | {"allocation": changed})
        )
    with pytest.raises(ValueError, match="native replay owner"):
        original.baseline_candidate(result)
    # A failed metadata export must resume after the completed preparation was
    # retained. Retry cannot falsely report completion while its sink is absent.
    exports = []

    def fail_once(allocation):
        exports.append(allocation)
        if len(exports) == 1:
            raise OSError("interrupted allocation export")

    interrupted, _, _ = setup(sink=fail_once)
    with pytest.raises(OSError, match="interrupted allocation export"):
        await interrupted.prepare_from_completed_coverage(retained, **args)
    completed = await interrupted.prepare_from_completed_coverage(retained, **args)
    assert exports == [args["allocation"], args["allocation"]]
    assert interrupted.baseline_candidate(completed) == expected


@pytest.mark.parametrize("failure", ["superseded_activation", "missing_checkpoint"])
async def test_owned_baseline_hook_does_not_replay_missing_or_superseded_work(failure, monkeypatch):
    from umi import competition_reward_baseline_restore as restore_module
    from umi.competition_chain import _AwaitingFinality
    from umi.competition_reward_baseline_restore import (
        CompletedCoverageBaselineRequest,
        prepare_completed_coverage_baseline,
    )
    from umi.competition_reward_decisions import RewardActivation
    from umi.competition_settlement import PromotionHeadBinding

    activation = RewardActivation(
        cohort_sha256="a" * 64,
        allocation_sha256="b" * 64,
        package_sha256="c" * 64,
        recovery_tip_sha256="d" * 64,
        prior_opportunity_sha256="e" * 64,
    )
    request = CompletedCoverageBaselineRequest(
        endpoint_key="f" * 64,
        activation=activation,
        target_cohort_sha256="1" * 64,
        previous=PromotionHeadBinding(
            sequence=0,
            promotion_sha256="2" * 64,
            model_sha256="3" * 64,
            contributor_hotkey=None,
        ),
        not_before_block=100,
        valid_through_block=200,
    )
    restored, collected, selected_controls = [], [], []

    async def no_delay(_):
        pass

    monkeypatch.setattr(restore_module.asyncio, "sleep", no_delay)

    async def control(_):
        collected.append("same started provider")
        if len(collected) == 1:
            raise _AwaitingFinality("first owned head pending")
        return "owned current observation"

    def selected(control, _):
        selected_controls.append(control)
        assert control == "owned current observation"
        return SimpleNamespace(
            state="selected", activation=activation if failure == "missing_checkpoint" else None
        )

    async def source(_):
        return SimpleNamespace(_history=object(), _completed_model_groups={})

    async def restore(key, **context):
        restored.append(key)
        assert context["expected_package_sha256"] == activation.package_sha256
        return None

    coverage = SimpleNamespace(
        provider=SimpleNamespace(
            collect_control=control,
            ensure_observer_running=lambda: None,
            config=SimpleNamespace(startup_timeout_seconds=1),
        ),
        preparation=SimpleNamespace(
            reader=SimpleNamespace(
                series=SimpleNamespace(control_hotkey="control"), select=selected
            )
        ),
        # No package, allocation, capture, replay or signing API is available.
        files=SimpleNamespace(decision=object()),
        journal=SimpleNamespace(restore_endpoint=restore),
        profile=object(),
        _source=source,
    )
    with pytest.raises(ValueError, match=r"current authenticated|existing completed"):
        await prepare_completed_coverage_baseline(coverage, request)
    assert restored == ([request.endpoint_key] if failure == "missing_checkpoint" else [])
    assert len(collected) == 2
    assert selected_controls == ["owned current observation"]
