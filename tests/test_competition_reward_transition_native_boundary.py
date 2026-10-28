"""Pinned automatic-release facts reuse their independently owned native endpoints.

The package envelope here is an explicit substituted boundary; complete native
package replay and reuse are exercised in test_competition_reward_transition_native.
"""

from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_transition_native as native
from umi.competition_reward_adoption import RewardAdoptionSelection, SignedRewardModelAdoption
from umi.competition_reward_coordinator import StandingRewardDecisionReviewer
from umi.competition_reward_opportunity import prepare_early_release_revision
from umi.competition_reward_transition_review import predecessor_live_age_from_owned_control
from umi.open_competition import digest

from .test_competition_reward_adoption_feed import initial
from .test_competition_reward_decisions import signatures
from .test_competition_reward_transition_native import historical_control
from .test_competition_reward_transition_review import chain as chain
from .test_competition_reward_transition_review import chain_config as chain_config
from .test_competition_reward_transition_review import control as control
from .test_competition_reward_transition_review import live_case as live_case
from .test_competition_reward_transition_review import manifest_case as manifest_case
from .test_competition_reward_transition_review import opportunity_case as opportunity_case
from .test_competition_reward_transition_review import policy as policy
from .test_competition_reward_transition_review import series_case as series_case


async def test_automatic_age_uses_pinned_historical_observation_without_new_proof_reads(live_case):
    c = live_case
    before = (len(c.control.rpc.calls), len(c.control.verifier.checked))
    expected = predecessor_live_age_from_owned_control(**c.args)
    pinned = historical_control(c.args["observation"])
    assert predecessor_live_age_from_owned_control(**(c.args | {"observation": pinned})) == expected
    assert (len(c.control.rpc.calls), len(c.control.verifier.checked)) == before
    with pytest.raises(ValueError, match="owned proof"):
        predecessor_live_age_from_owned_control(
            **(c.args | {"observation": replace(pinned, _issuer=None)})
        )


async def test_native_automatic_revision_rebuilds_exact_owned_historical_age(
    live_case, monkeypatch
):
    h, c = live_case, live_case.c
    pinned = historical_control(h.args["observation"])
    package = SimpleNamespace(
        allocation={"native_allocation": 1},
        service={"certificate": 1},
        benchmark={"quality": 1},
        policy_sha256=digest(c.policy),
        inputs=SimpleNamespace(
            history=SimpleNamespace(plan=c.series.cohorts[1], authority=c.series.recovery)
        ),
    )
    prior = (
        initial(c)
        .adoptions[0]
        .adoption.model_copy(
            update={
                "allocation_sha256": digest(package.allocation),
                "service_certificate_sha256": digest(package.service),
                "quality_manifest_sha256": digest(package.benchmark),
            }
        )
    )
    selection = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=prior, signatures=signatures(prior)),),
    )
    age = predecessor_live_age_from_owned_control(**(h.args | {"observation": pinned}))
    proposal = prepare_early_release_revision(
        selection,
        series=c.series,
        policy=c.policy,
        manifest=c.manifest,
        predecessor=h.args["predecessor"],
        successor_cohort_sha256=prior.cohort_sha256,
        issued_at_block=pinned.snapshot.block_number,
        reason="Configured successor release policy",
        live_age=age,
    )
    reviewer = object.__new__(StandingRewardDecisionReviewer)
    reviewer.reader = SimpleNamespace(
        series=c.series,
        policy=c.policy,
        reward_adoptions=selection,
        chain_config_sha256=digest(h.control.config),
    )
    reviewer.manifest, reviewer.verification_reuse = c.manifest, object()
    owner = native.NativeRewardTransitionReviewer(reviewer)
    monkeypatch.setattr(native, "verified_package_digest", lambda value: prior.package_sha256)
    owner._proposal(package, proposal, h.args["predecessor"], pinned, h.args["live_endpoint"])
    wrong = proposal.model_copy(
        update={
            "early_release": proposal.early_release.model_copy(
                update={"live_age": age.model_copy(update={"live_endpoint_sha256": "ff" * 32})}
            )
        }
    )
    with pytest.raises(ValueError, match="pinned native live age"):
        owner._proposal(package, wrong, h.args["predecessor"], pinned, h.args["live_endpoint"])
    with pytest.raises(ValueError):
        owner._proposal(package, proposal, h.args["predecessor"], pinned, None)
