"""Native original package replay with authenticated effective economics.

These tests substitute current control selection, as the preparation fixture
documents. Adoption signatures, original package replay, durable native reuse,
effective arithmetic and projection remain real.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
)
from umi.competition_reward_coverage_prepared import (
    CoveragePackageReplayRequired,
    RetainedCoveragePackage,
    prepare_retained_coverage,
)
from umi.competition_reward_decisions import (
    HistoricalStandingRewardSelection,
    HistoryVerifiedStandingRewardSelection,
)
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import signatures
from .test_competition_reward_preparation import base_policy as base_policy
from .test_competition_reward_preparation import chain as chain
from .test_competition_reward_preparation import chain_config as chain_config
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
from .test_competition_reward_preparation import replay_args
from .test_competition_reward_preparation import runtime as runtime
from .test_competition_reward_preparation import scenario as scenario
from .test_competition_reward_preparation import service as service
from .test_competition_reward_preparation import service_catalog_inputs as service_catalog_inputs
from .test_competition_reward_preparation import service_closed as service_closed
from .test_competition_reward_preparation import service_owner as service_owner
from .test_competition_reward_preparation import service_quality_inputs as service_quality_inputs
from .test_competition_reward_preparation import shared_control_group as shared_control_group

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


def _adoption(p, parameters, *, revision=1, predecessor=None):
    allocation = derive_effective_reward_allocation(p.package, parameters)
    old = p.active.decision.activation
    body = RewardModelAdoption(
        schema="umi-standing-model-reward-adoption/1",
        series_sha256=digest(p.reader.series),
        policy_sha256=digest(p.reader.policy),
        cohort_sha256=old.cohort_sha256,
        authority_sha256=digest(p.reader.series.recovery.authority),
        package_sha256=old.package_sha256,
        allocation_sha256=old.allocation_sha256,
        service_certificate_sha256=digest(p.package.service),
        quality_manifest_sha256=digest(p.package.benchmark),
        effective_allocation_sha256=digest(allocation),
        parameters=parameters,
        revision=revision,
        predecessor_adoption_sha256=None if predecessor is None else digest(predecessor.adoption),
        issued_at_block=p.active.decision.observed_at_block,
        lifetime="until_first_verified_live_reward_then_locked",
    )
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    activation = old.model_copy(
        update={
            "reward_adoption_sha256": digest(body),
            "effective_allocation_sha256": digest(allocation),
        }
    )
    return signed, activation, allocation


@pytest.mark.parametrize(
    ("parameter_version", "revision_version"),
    [(1, 1), (1, 2), (2, 2)],
    ids=["legacy_v1", "upgrade_to_score_v2", "score_v2"],
)
async def test_native_preparation_preserves_package_and_isolates_adopted_revisions(
    preparation_case, monkeypatch, parameter_version, revision_version
):
    p = preparation_case
    original_bytes = canonical_json_bytes(p.package)
    observations = await p.observations()
    original = await p.preparation.prepare(p.package, **replay_args(observations))
    selected = p.reader.select_history(**replay_args(observations))
    first, activation, effective = _adoption(
        p, GeometricRewardParameters(schema=f"umi-geometric-reward-parameters/{parameter_version}")
    )
    p.reader.reward_adoptions = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=(first,)
    )
    with pytest.raises(ValueError, match="require a native activation revision"):
        await p.preparation.project(original, **observations)
    chosen = SimpleNamespace(activation=activation)

    def current(*args, **kwargs):
        selection = replace(selected.selection, activation=chosen.activation)
        return HistoryVerifiedStandingRewardSelection(selection, p.history, selection)

    def historical(control, source, history):
        value = current()
        return HistoricalStandingRewardSelection(
            control, value.selection, history, value.effective_selection
        )

    monkeypatch.setattr(p.reader, "select_history", current)
    monkeypatch.setattr(p.reader, "review_history", historical)
    adopted = await p.preparation.prepare(p.package, **replay_args(observations))
    assert adopted.allocation == effective
    assert adopted.allocation.model_award.parameters.schema_.endswith(f"/{parameter_version}")
    assert adopted.allocation.model_award.parameters.score_duplicate_tolerance_bps == (
        None if parameter_version == 1 else 1
    )
    assert adopted.activation.allocation_sha256 == digest(original.allocation)
    assert adopted.activation.package_sha256 == original.activation.package_sha256
    with pytest.raises(ValueError, match="reward package differs from current standing activation"):
        await p.preparation.prepare(
            p.package.model_copy(update={"policy_sha256": "ee" * 32}),
            **replay_args(observations),
        )
    with pytest.raises(ValueError, match="current standing selection"):
        await p.preparation.project(original, **observations)
    projected = await p.preparation.project(adopted, **observations)
    assert projected.projection.allocation_sha256 == digest(effective)
    assert sum(projected.projection.weights) == 65535
    assert not projected.chain_submission_authorized
    second, activation2, effective2 = _adoption(
        p,
        GeometricRewardParameters(
            schema=f"umi-geometric-reward-parameters/{revision_version}",
            band_width_bps=first.adoption.parameters.band_width_bps,
            band_decay_bps=first.adoption.parameters.band_decay_bps,
            within_band_decay_bps=6000,
        ),
        revision=2,
        predecessor=first,
    )
    p.reader.reward_adoptions = p.reader.reward_adoptions.model_copy(
        update={"adoptions": (first, second)}
    )
    chosen.activation = activation2
    # A retained original package is only a hint. New economics must obtain its
    # own native preparation; it cannot borrow the prior effective allocation.
    retained = RetainedCoveragePackage(adopted)
    with pytest.raises(CoveragePackageReplayRequired):
        await prepare_retained_coverage(p.preparation, retained, **replay_args(observations))
    revised = await p.preparation.prepare(p.package, **replay_args(observations))
    assert revised.allocation == effective2 and revised.activation != adopted.activation
    assert revised.allocation.model_award.parameters.schema_.endswith(f"/{revision_version}")
    assert (
        await prepare_retained_coverage(p.preparation, retained, **replay_args(observations))
        is revised
    )
    with pytest.raises(ValueError, match="current standing selection"):
        await p.preparation.project(adopted, **observations)
    reopened = p.reopen()
    restored = await reopened.prepare(p.package, **replay_args(observations))
    assert restored.allocation == revised.allocation
    chosen.activation = original.activation
    assert await p.preparation.prepare(p.package, **replay_args(observations)) is original
    assert canonical_json_bytes(p.package) == original_bytes
    chosen.activation = activation2
    p.reader.reward_adoptions = None
    with pytest.raises(ValueError, match="explicit host adoption"):
        await reopened.project(restored, **observations)


@pytest.mark.parametrize("parameter_version", [1, 2], ids=["legacy_v1", "score_v2"])
async def test_preparation_rejects_adoption_with_wrong_effective_allocation(
    preparation_case, monkeypatch, parameter_version
):
    p = preparation_case
    observations = await p.observations()
    selected = p.reader.select_history(**replay_args(observations))
    signed, activation, _ = _adoption(
        p, GeometricRewardParameters(schema=f"umi-geometric-reward-parameters/{parameter_version}")
    )
    body = signed.adoption.model_copy(update={"effective_allocation_sha256": "ef" * 32})
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    activation = activation.model_copy(
        update={"reward_adoption_sha256": digest(body), "effective_allocation_sha256": "ef" * 32}
    )
    p.reader.reward_adoptions = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=(signed,)
    )
    selection = replace(selected.selection, activation=activation)
    monkeypatch.setattr(
        p.reader,
        "select_history",
        lambda *a, **kw: HistoryVerifiedStandingRewardSelection(selection, p.history, selection),
    )
    with pytest.raises(ValueError, match=r"effective.*allocation"):
        await p.preparation.prepare(p.package, **replay_args(observations))
    assert not p.preparation._prepared
