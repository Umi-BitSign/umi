"""Native package reuse with explicit synthetic reviewer and owned-proof boundaries.

Package semantics, retained snapshots and receipt reuse remain real. These tests
neither sign nor qualify installed production services.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_control_archive as historical
from umi import competition_reward_transition_native as native
from umi.competition_reward_adoption import prepare_initial_reward_adoption
from umi.competition_reward_coordinator import StandingRewardDecisionReviewer
from umi.competition_reward_decisions import SignedRewardControlDecision
from umi.competition_reward_files import StandingRewardFiles
from umi.open_competition import digest

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


@pytest.fixture
async def transition_case(preparation_case, tmp_path):
    p = preparation_case
    files = StandingRewardFiles(
        tmp_path / "transition-inputs",
        maximum_package_bytes=64 * 1024**2,
        maximum_witness_bytes=1024**2,
    )
    files.retain_package(p.package)
    package = files.verified_package(digest(p.package))
    prior = SignedRewardControlDecision.model_validate_json(
        p.objects[p.active.decision.predecessor_sha256]
    )
    observed = await p.control(prior)
    # Existing reviewer ownership is the substituted construction boundary;
    # its actual native replay scope and all retained package readers are used.
    reviewer = object.__new__(StandingRewardDecisionReviewer)
    reviewer.reader, reviewer.manifest, reviewer.store = p.reader, p.manifest, p.store
    reviewer.files, reviewer.model_artifacts = files, None
    reviewer.maximum_promotion_bytes = 1_000_000
    reviewer.verification_reuse = p.preparation.verification_reuse
    proposal = prepare_initial_reward_adoption(
        package,
        series=p.reader.series,
        policy=p.reader.policy,
        issued_at_block=observed.snapshot.block_number,
        previous=None,
    )
    return SimpleNamespace(
        p=p,
        files=files,
        package=package,
        reviewer=reviewer,
        owner=native.NativeRewardTransitionReviewer(reviewer),
        args=dict(package=package, proposal=proposal, predecessor=prior, observation=observed),
    )


def historical_control(observed):
    # This issuer stands in for already completed native historical verification.
    # Current/historical proof verification itself has separate native tests.
    value = historical.OwnedHistoricalRewardControl(
        snapshot=observed.snapshot,
        control_hotkey=observed.control_hotkey,
        control_sha256=observed.control_sha256,
        committed_at_block=observed.committed_at_block,
        evidence_sha256=observed.evidence_sha256,
        metadata_sha256=observed.runtime.metadata_sha256,
        chain_config_sha256=observed.chain_config_sha256,
        timestamp_ms=observed.timestamp_ms,
        evidence=observed.evidence,
        metadata=observed.runtime.metadata_bytes,
        _issuer=historical._ISSUER,
    )
    return replace(value, _binding=historical._binding(value))


async def test_native_review_reuses_completed_semantics_across_review_and_preparation(
    transition_case, monkeypatch
):
    from .reward_snapshot_assertions import NativeContextReads, forbid_expensive_native_replay

    c = transition_case
    result = await c.owner.review(**c.args)
    intent = native.validate_reward_adoption_review(result)
    assert intent.proposal == c.args["proposal"]
    assert intent.predecessor_decision_sha256 == digest(c.args["predecessor"].decision)
    assert result.chain_submission_authorized is False
    reads = NativeContextReads(monkeypatch, c.p.package, c.package)
    forbid_expensive_native_replay(monkeypatch)
    assert await c.owner.review(**c.args) == result
    reads.check()
    observations = await c.p.observations()
    completed = await c.p.preparation.prepare(c.package, **replay_args(observations))
    assert digest(completed.allocation) == intent.proposal.allocation_sha256
    reads.check()
    with pytest.raises(ValueError, match="native pre-signing"):
        native.validate_reward_adoption_review(replace(result, _issuer=None))
    changed = intent.model_copy(update={"manifest_sha256": "aa" * 32})
    with pytest.raises(ValueError, match="native pre-signing"):
        native.validate_reward_adoption_review(replace(result, intent=changed))


@pytest.mark.parametrize(
    "change", ["package", "allocation", "effective", "issuance", "predecessor"]
)
async def test_changed_proposal_refuses_before_native_replay(transition_case, monkeypatch, change):
    c = transition_case

    async def unexpected(*args):
        pytest.fail("changed proposal must fail before native package work")

    monkeypatch.setattr(c.owner, "_package", unexpected)
    args = dict(c.args)
    if change == "predecessor":
        args["predecessor"] = args["predecessor"].model_copy(
            update={
                "decision": args["predecessor"].decision.model_copy(
                    update={"observed_at_block": 159}
                )
            }
        )
    else:
        fields = {
            "package": "package_sha256",
            "allocation": "allocation_sha256",
            "effective": "effective_allocation_sha256",
            "issuance": "issued_at_block",
        }
        value = args["proposal"].issued_at_block + 1 if change == "issuance" else "aa" * 32
        args["proposal"] = args["proposal"].model_copy(update={fields[change]: value})
    with pytest.raises(ValueError):
        await c.owner.review(**args)


async def test_pinned_history_uses_separate_fresh_control_without_matching_tip_evidence(
    transition_case,
):
    c = transition_case
    pinned = historical_control(c.args["observation"])
    current = await c.p.control(
        SignedRewardControlDecision.model_validate_json(
            c.p.objects[digest(c.args["predecessor"].decision)]
        )
    )
    result = await c.owner.review(
        **(c.args | {"observation": pinned, "current_observation": current})
    )
    intent = native.validate_reward_adoption_review(result)
    assert intent.control_evidence_sha256 == pinned.evidence_sha256
    assert intent.control_metadata_sha256 == pinned.metadata_sha256
    with pytest.raises(ValueError, match="fresh current"):
        await c.owner.review(**(c.args | {"observation": pinned}))
    changed = await c.p.control(c.p.active)
    with pytest.raises(ValueError, match="no longer selected"):
        await c.owner.review(**(c.args | {"observation": pinned, "current_observation": changed}))


async def test_completed_semantics_survive_final_current_fence_failure(
    transition_case, monkeypatch
):
    from .reward_snapshot_assertions import NativeContextReads, forbid_expensive_native_replay

    c = transition_case
    pinned = historical_control(c.args["observation"])
    original_package = c.owner._package
    original_control = c.owner._control
    package_complete = False

    async def package(*args):
        nonlocal package_complete
        await original_package(*args)
        package_complete = True

    def control(observation, predecessor, *, current=False):
        original_control(observation, predecessor, current=current)
        if current and package_complete:
            raise ValueError("current observation expired after native review")

    monkeypatch.setattr(c.owner, "_package", package)
    monkeypatch.setattr(c.owner, "_control", control)
    args = c.args | {"observation": pinned, "current_observation": c.args["observation"]}
    with pytest.raises(ValueError, match="expired after native"):
        await c.owner.review(**args)
    assert package_complete
    monkeypatch.setattr(c.owner, "_control", original_control)
    reads = NativeContextReads(monkeypatch, c.p.package, c.package)
    forbid_expensive_native_replay(monkeypatch)
    assert (
        native.validate_reward_adoption_review(await c.owner.review(**args)).proposal
        == args["proposal"]
    )
    reads.check()


@pytest.mark.parametrize("kind", ["unsigned", "missing_quorum", "changed_signature"])
async def test_adoption_requires_predecessor_quorum_before_package_work(
    transition_case, monkeypatch, kind
):
    c = transition_case
    signed = c.args["predecessor"]

    async def unexpected(*args):
        pytest.fail("missing predecessor quorum must not start package work")

    monkeypatch.setattr(c.owner, "_package", unexpected)
    if kind == "unsigned":
        bad = signed.decision
    elif kind == "missing_quorum":
        bad = signed.model_copy(update={"signatures": signed.signatures[:1]})
    else:
        first = signed.signatures[0].model_copy(update={"signature": "0x" + "00" * 64})
        bad = signed.model_copy(update={"signatures": (first, *signed.signatures[1:])})
    with pytest.raises(ValueError):
        await c.owner.review(**(c.args | {"predecessor": bad}))
