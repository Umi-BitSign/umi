"""Native original package replay with authenticated effective economics.

These tests substitute current control selection, as the preparation fixture
documents. Adoption signatures, original package replay, durable native reuse,
effective arithmetic and projection remain real.
"""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi.competition_cohort_reward_allocation import derive_effective_reward_allocation
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    prepare_initial_reward_adoption,
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


@pytest.mark.parametrize("complete_preparation_case", ["opportunity"], indirect=True)
async def test_native_adopted_decision_exports_both_allocations_before_signing(
    complete_preparation_case, tmp_path
):
    from umi.competition_reward_decision_review import review_reward_decision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
    from umi.historical_header_recovery import HistoricalHeaderRecoveryPending

    h = complete_preparation_case
    c, p = h.c, h.package_case
    observed = c.active.decision.observed_at_block - 1
    handoff = LegacyRewardHandoffPlan(
        schema="umi-legacy-reward-handoff-plan/1",
        series_sha256=digest(c.series),
        cohort_sha256=digest(c.series.cohorts[0]),
        legacy_policy_sha256="11" * 32,
        legacy_round_sha256="22" * 32,
        legacy_package_sha256="33" * 32,
    )
    files = StandingRewardFiles(
        tmp_path / "adopted-decision-review",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    package = files.verified_package(digest(p.package))
    proposal = prepare_initial_reward_adoption(
        package, series=c.series, policy=c.reader.policy, issued_at_block=observed, previous=None
    )
    c.reader.reward_adoptions = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=proposal, signatures=signatures(proposal)),),
    )
    body = c.active.decision.model_copy(
        update={
            "schema_": "umi-reward-control-decision/3",
            "observed_at_block": observed,
            "activation": c.active.decision.activation.model_copy(
                update={
                    "prior_opportunity_sha256": digest(handoff),
                    "reward_adoption_sha256": digest(proposal),
                    "effective_allocation_sha256": proposal.effective_allocation_sha256,
                }
            ),
        }
    )
    for _ in range(100):
        try:
            progress = await h.reader.advance(
                h.item.provider, through_block=observed, maximum_blocks=4096
            )
        except HistoricalHeaderRecoveryPending:
            continue
        if progress.history is not None:
            break
    else:
        pytest.fail("native adopted signing history did not converge")
    control = await h.reader.review_control(h.item.provider, observed)
    exported = []

    def retain(allocation):
        files.retain_allocation(allocation)
        exported.append(digest(allocation))

    accepted = review_reward_decision(
        c.reader,
        p.manifest,
        (c.genesis,),
        body,
        control=control,
        history=progress.history,
        package=package,
        promotion_store=p.store,
        approved_handoff=handoff,
        maximum_promotion_bytes=1_000_000,
        allocation_sink=retain,
    )
    assert accepted.intent.decision == body
    assert accepted.chain_submission_authorized is False
    assert exported == [proposal.allocation_sha256, proposal.effective_allocation_sha256]
    assert files.allocation(proposal.allocation_sha256) == p.allocation
    effective = derive_effective_reward_allocation(package, proposal.parameters)
    assert files.allocation(proposal.effective_allocation_sha256) == effective


@pytest.mark.parametrize("interrupt_after", ["original", "effective"])
async def test_adopted_allocation_publication_recovers_delivery_and_old_completed_decisions(
    preparation_case, tmp_path, monkeypatch, interrupt_after
):
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_publication import retain_standing_reward_inputs

    from .reward_snapshot_assertions import forbid_expensive_native_replay
    from .test_competition_reward_decisions import signed

    p = preparation_case
    adoption, activation, effective = _adoption(p, GeometricRewardParameters())
    original_sha, effective_sha = digest(p.allocation), digest(effective)
    assert original_sha != effective_sha
    selection = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=(adoption,)
    )
    genesis = SignedRewardControlDecision.model_validate_json(
        p.objects[p.active.decision.predecessor_sha256]
    )
    active = signed(
        p.active.decision.model_copy(
            update={"schema_": "umi-reward-control-decision/3", "activation": activation}
        )
    )
    prefix = (genesis, active)
    files = StandingRewardFiles(
        tmp_path / "adopted-publication",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    retain = files.retain_allocation
    target = original_sha if interrupt_after == "original" else effective_sha
    attempts = []

    def interrupted(allocation):
        attempts.append(digest(allocation))
        retain(allocation)
        if digest(allocation) == target:
            raise OSError("compact allocation acknowledgement lost")

    monkeypatch.setattr(files, "retain_allocation", interrupted)
    with pytest.raises(OSError, match="allocation acknowledgement"):
        retain_standing_reward_inputs(
            files,
            p.reader.series,
            p.reader.policy,
            prefix,
            lambda _: p.package,
            reward_adoptions=selection,
        )
    expected = [original_sha] if interrupt_after == "original" else [original_sha, effective_sha]
    assert attempts == expected
    assert not tuple((files.root / "decisions").glob("*.json"))
    before = {path: (path.read_bytes(), path.stat()) for path in files.root.rglob("*.json")}
    reopened = StandingRewardFiles(
        files.root, maximum_package_bytes=64 * 1024**2, maximum_witness_bytes=1024**2
    )
    snapshot = reopened.verified_package(activation.package_sha256)

    def unavailable(*args, **kwargs):
        pytest.fail("compact allocation repair reopened source, payload or native work")

    # Publication consumes the existing compact package/adoption values. It must
    # not reopen individual model/case objects or invoke native replay to repair.
    forbid_expensive_native_replay(monkeypatch)
    monkeypatch.setattr(type(snapshot), "read", unavailable)

    def publish():
        return retain_standing_reward_inputs(
            reopened,
            p.reader.series,
            p.reader.policy,
            prefix,
            unavailable,
            reward_adoptions=selection,
        )

    assert publish() == digest(active.decision)
    assert reopened.allocation(original_sha) == p.allocation
    assert reopened.allocation(effective_sha) == effective
    for path, (raw, identity) in before.items():
        assert path.read_bytes() == raw
        assert path.stat().st_ino == identity.st_ino
        assert path.stat().st_mtime_ns == identity.st_mtime_ns
    assert reopened.decision(digest(active.decision)) == canonical_json_bytes(active)
    signed_bytes = {path: path.read_bytes() for path in (files.root / "decisions").glob("*.json")}
    # Older certified hosts can have complete signed inputs but no compact
    # allocations. The ordinary publication retry repairs only these outputs.
    for sha in (original_sha, effective_sha):
        (files.root / "allocations" / (sha + ".json")).unlink()
    assert publish() == digest(active.decision)
    assert reopened.allocation(original_sha) == p.allocation
    assert reopened.allocation(effective_sha) == effective
    assert all(path.read_bytes() == raw for path, raw in signed_bytes.items())


async def test_adopted_publication_refuses_invalid_effective_allocation_before_export(
    preparation_case, tmp_path
):
    from umi.competition_reward_decisions import SignedRewardControlDecision
    from umi.competition_reward_files import StandingRewardFiles
    from umi.competition_reward_publication import retain_standing_reward_inputs

    from .test_competition_reward_decisions import signed

    p = preparation_case
    adoption, activation, _ = _adoption(p, GeometricRewardParameters())
    body = adoption.adoption.model_copy(update={"effective_allocation_sha256": "ef" * 32})
    adoption = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    activation = activation.model_copy(
        update={"reward_adoption_sha256": digest(body), "effective_allocation_sha256": "ef" * 32}
    )
    selection = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1", adoptions=(adoption,)
    )
    genesis = SignedRewardControlDecision.model_validate_json(
        p.objects[p.active.decision.predecessor_sha256]
    )
    active = signed(
        p.active.decision.model_copy(
            update={"schema_": "umi-reward-control-decision/3", "activation": activation}
        )
    )
    files = StandingRewardFiles(
        tmp_path / "invalid-adopted-publication",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    with pytest.raises(ValueError, match="effective allocation"):
        retain_standing_reward_inputs(
            files,
            p.reader.series,
            p.reader.policy,
            (genesis, active),
            lambda _: p.package,
            reward_adoptions=selection,
        )
    assert not tuple((files.root / "allocations").glob("*.json"))
    assert not tuple((files.root / "decisions").glob("*.json"))


async def test_initial_adoption_proposal_uses_verified_package_without_replaying_objects(
    preparation_case, tmp_path, monkeypatch
):
    from umi.competition_reward_files import StandingRewardFiles

    p = preparation_case
    files = StandingRewardFiles(
        tmp_path / "adoption-inputs",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    snapshot = files.verified_package(digest(p.package))
    parameters = GeometricRewardParameters(
        band_width_bps=250,
        band_decay_bps=7500,
        within_band_decay_bps=7500,
        score_duplicate_tolerance_bps=1,
    )
    original, _, _ = _adoption(p, parameters)

    def no_object_read(_self, _key):
        raise AssertionError("proposal must not reread retained package objects")

    monkeypatch.setattr(type(snapshot), "read", no_object_read)
    proposed = prepare_initial_reward_adoption(
        snapshot,
        series=p.reader.series,
        policy=p.reader.policy,
        issued_at_block=p.active.decision.observed_at_block,
        previous=None,
    )
    assert proposed == original.adoption
    with pytest.raises(TypeError, match="verified package snapshot"):
        prepare_initial_reward_adoption(
            p.package,
            series=p.reader.series,
            policy=p.reader.policy,
            parameters=parameters,
            issued_at_block=p.active.decision.observed_at_block,
            previous=None,
        )
    with pytest.raises(ValueError, match="initial revision"):
        prepare_initial_reward_adoption(
            snapshot,
            series=p.reader.series,
            policy=p.reader.policy,
            parameters=parameters,
            issued_at_block=p.active.decision.observed_at_block,
            previous=RewardAdoptionSelection(
                schema="umi-standing-reward-adoption-selection/1",
                adoptions=(original,),
            ),
        )


@pytest.mark.parametrize(
    ("parameter_version", "revision_version"),
    [(1, 1), (1, 2), (2, 2)],
    ids=["legacy_v1", "upgrade_to_score_v2", "score_v2"],
)
async def test_native_preparation_preserves_package_and_isolates_adopted_revisions(
    preparation_case, tmp_path, monkeypatch, parameter_version, revision_version, record_property
):
    from umi.competition_reward_files import StandingRewardFiles

    from .reward_snapshot_assertions import NativeContextReads, forbid_expensive_native_replay

    p = preparation_case
    original_bytes = canonical_json_bytes(p.package)
    files = StandingRewardFiles(
        tmp_path / "adopted-reward-inputs",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    package_sha = digest(p.package)
    snapshot = files.verified_package(package_sha)
    p.preparation = p.reopen(allocation_sink=files.retain_allocation)
    observations = await p.observations()
    original = await p.preparation.prepare(snapshot, **replay_args(observations))
    assert files.allocation(digest(original.allocation)) == original.allocation
    reads = NativeContextReads(monkeypatch, p.package, snapshot)
    forbid_expensive_native_replay(monkeypatch)
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
    adopted = await p.preparation.prepare(snapshot, **replay_args(observations))
    assert adopted.allocation == effective
    assert files.allocation(digest(effective)) == effective
    assert files.allocation(digest(original.allocation)) == original.allocation
    assert reads.check()["objects"] > 0
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
    revised = await p.preparation.prepare(snapshot, **replay_args(observations))
    assert revised.allocation == effective2 and revised.activation != adopted.activation
    reads.check()
    assert revised.allocation.model_award.parameters.schema_.endswith(f"/{revision_version}")
    assert (
        await prepare_retained_coverage(p.preparation, retained, **replay_args(observations))
        is revised
    )
    with pytest.raises(ValueError, match="current standing selection"):
        await p.preparation.project(adopted, **observations)
    reopened = p.reopen(allocation_sink=files.retain_allocation)
    snapshot = files.verified_package(package_sha)
    restored = await reopened.prepare(snapshot, **replay_args(observations))
    assert restored.allocation == revised.allocation
    assert files.allocation(digest(restored.allocation)) == restored.allocation
    reads.check()
    chosen.activation = original.activation
    assert await p.preparation.prepare(snapshot, **replay_args(observations)) is original
    assert canonical_json_bytes(p.package) == original_bytes
    chosen.activation = activation2
    p.reader.reward_adoptions = None
    with pytest.raises(ValueError, match="explicit host adoption"):
        await reopened.project(restored, **observations)
    record_property("warm_context_reads", json.dumps(reads.checks))


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
