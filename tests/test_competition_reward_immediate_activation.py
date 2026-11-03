"""Prospective signed START semantics; legacy evidence is never reinterpreted."""

from types import SimpleNamespace

import pytest

from umi import competition_reward_opportunity as opportunity
from umi import competition_reward_transition_native as native
from umi.competition_reward_adoption import (
    RewardAdoptionSelection,
    RewardModelAdoption,
    SignedRewardModelAdoption,
    verify_adoption_selection,
)
from umi.competition_reward_coordinator import StandingRewardDecisionReviewer
from umi.competition_reward_decisions import RewardControlDecision
from umi.competition_reward_opportunity import prepare_early_release_revision
from umi.competition_reward_timing import IMMEDIATE_ACTIVATION_RULE, activation_effective_block
from umi.competition_reward_transition_controls import (
    RewardTransitionApproval,
    SignedRewardTransitionApproval,
    verify_transition_approval,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import signatures
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_competition_reward_transition_timing import age, initial, predecessor
from .test_open_competition import wallet


def proposed(c, selected, *, immediate=True, automatic=False):
    return prepare_early_release_revision(
        selected,
        series=c.series,
        policy=c.policy,
        manifest=c.manifest,
        predecessor=predecessor(c),
        successor_cohort_sha256=digest(c.series.cohorts[1]),
        issued_at_block=202,
        reason="Release the exact certified successor at finalized commitment",
        live_age=age(c) if automatic else None,
        activation_rule=IMMEDIATE_ACTIVATION_RULE if immediate else None,
    )


@pytest.mark.parametrize("automatic", [False, True])
def test_first_adoption_contains_explicit_start_rule_without_extra_revision(
    opportunity_case, monkeypatch, automatic
):
    c = opportunity_case
    original = initial(c).adoptions[0].adoption.model_copy(update={"issued_at_block": 202})
    package = object()

    def imported_package(actual, **kwargs):
        # Completed compact package derivation is separately qualified. This
        # boundary checks that no intermediate signed adoption is required.
        assert actual is package and kwargs["previous"] is None
        return original

    monkeypatch.setattr(opportunity, "prepare_initial_reward_adoption", imported_package)
    body = opportunity.prepare_initial_early_release_adoption(
        package,
        selection=None,
        series=c.series,
        policy=c.policy,
        manifest=c.manifest,
        predecessor=predecessor(c),
        issued_at_block=202,
        reason="Release the certified successor",
        live_age=age(c) if automatic else None,
        activation_rule=IMMEDIATE_ACTIVATION_RULE,
    )
    assert body.schema_ == "umi-standing-model-reward-adoption/7"
    assert body.revision == 1 and body.predecessor_adoption_sha256 is None
    assert body.activation_rule == IMMEDIATE_ACTIVATION_RULE and body.activation_age is None


@pytest.mark.parametrize("automatic", [False, True])
def test_new_timing_is_signed_and_legacy_versions_cannot_gain_it(opportunity_case, automatic):
    c = opportunity_case
    before = initial(c)
    body = proposed(c, before, automatic=automatic)
    assert body.schema_ == "umi-standing-model-reward-adoption/7"
    assert body.activation_age is None
    raw = canonical_json_bytes(body)
    assert canonical_json_bytes(RewardModelAdoption.model_validate_json(raw)) == raw
    for change in (
        {
            "schema": "umi-standing-model-reward-adoption/6"
            if automatic
            else "umi-standing-model-reward-adoption/5"
        },
        {"activation_rule": None},
        {"activation_rule": "immediately_without_finality"},
    ):
        with pytest.raises(ValueError):
            RewardModelAdoption.model_validate_json(
                canonical_json_bytes({**body.model_dump(by_alias=True), **change})
            )
    signed = SignedRewardModelAdoption(adoption=body, signatures=signatures(body))
    changed = body.model_copy(update={"issued_at_block": 203})
    forged = signed.model_copy(update={"adoption": changed})
    bad = RewardAdoptionSelection(schema=before.schema_, adoptions=(*before.adoptions, forged))
    with pytest.raises(ValueError):
        verify_adoption_selection(bad, c.series, c.policy)


@pytest.mark.parametrize("automatic", [False, True])
def test_new_selection_does_not_accelerate_an_older_decision(opportunity_case, automatic):
    c = opportunity_case
    old = initial(c)
    original = old.adoptions[0].adoption
    body = proposed(c, old, automatic=automatic)
    selected = RewardAdoptionSelection(
        schema=old.schema_,
        adoptions=(
            *old.adoptions,
            SignedRewardModelAdoption(adoption=body, signatures=signatures(body)),
        ),
    )
    selected = verify_adoption_selection(selected, c.series, c.policy)
    legacy = RewardControlDecision(
        schema="umi-reward-control-decision/3",
        series_sha256=digest(c.series),
        sequence=2,
        predecessor_sha256=digest(predecessor(c)),
        kind="activate",
        observed_at_block=202,
        activation=c.activation.model_copy(
            update={
                "cohort_sha256": original.cohort_sha256,
                "package_sha256": original.package_sha256,
                "allocation_sha256": original.allocation_sha256,
                "effective_allocation_sha256": original.effective_allocation_sha256,
                "reward_adoption_sha256": digest(original),
            }
        ),
    )
    raw = canonical_json_bytes(old.adoptions[0])
    assert b'"activation_rule"' not in raw
    assert canonical_json_bytes(selected.adoptions[0]) == raw
    assert activation_effective_block(c.series, legacy, 203, selected) == (
        203 + c.series.maximum_proof_lag_blocks + c.series.maximum_transaction_lifetime_blocks
    )


@pytest.mark.parametrize("immediate", [False, True])
@pytest.mark.parametrize("automatic", [False, True])
def test_independent_native_reviewer_reconstructs_exact_signed_timing(
    opportunity_case, monkeypatch, immediate, automatic
):
    c = opportunity_case
    # Native package/proof ownership is an explicit fixture boundary here.
    # The real versioned builders, signed lineage and exact package join run.
    package = SimpleNamespace(
        allocation={"allocation": 1},
        service={"service": 2},
        benchmark={"quality": 3},
        inputs=SimpleNamespace(
            history=SimpleNamespace(
                plan=c.series.cohorts[1],
                authority=SimpleNamespace(authority=c.series.recovery.authority),
            )
        ),
        policy_sha256=digest(c.policy),
    )
    original = (
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
    selected = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=(SignedRewardModelAdoption(adoption=original, signatures=signatures(original)),),
    )
    body = proposed(c, selected, immediate=immediate, automatic=automatic)
    reviewer = object.__new__(StandingRewardDecisionReviewer)
    reviewer.verification_reuse = None
    reviewer.reader = SimpleNamespace(
        series=c.series, policy=c.policy, reward_adoptions=selected, chain_config_sha256="11" * 32
    )
    reviewer.manifest = c.manifest
    owner = native.NativeRewardTransitionReviewer(reviewer)
    observation = SimpleNamespace(snapshot=SimpleNamespace(block_number=202))

    def owned_control(actual, prior):
        assert actual is observation and prior == predecessor(c)

    def completed_package(actual):
        assert actual is package
        return original.package_sha256

    monkeypatch.setattr(owner, "_control", owned_control)
    monkeypatch.setattr(native, "verified_package_digest", completed_package)
    monkeypatch.setattr(native, "predecessor_live_age_from_owned_control", lambda **_: age(c))
    owner._proposal(package, body, predecessor(c), observation, object() if automatic else None)
    with pytest.raises(ValueError, match="native exact-package proposal"):
        owner._proposal(
            package,
            body.model_copy(update={"effective_allocation_sha256": "ff" * 32}),
            predecessor(c),
            observation,
            object() if automatic else None,
        )


@pytest.mark.parametrize("immediate", [False, True])
def test_operator_approval_must_authenticate_the_same_start_rule(opportunity_case, immediate):
    c = opportunity_case
    proposal = proposed(c, initial(c), immediate=immediate)
    approval = RewardTransitionApproval(
        schema="umi-reward-transition-approval/2"
        if immediate
        else "umi-reward-transition-approval/1",
        series_sha256=digest(c.series),
        predecessor_decision_sha256=digest(predecessor(c)),
        successor_cohort_sha256=proposal.cohort_sha256,
        successor_package_sha256=proposal.package_sha256,
        reason=proposal.early_release.reason,
        activation_rule=proposal.activation_rule,
    )
    signed = SignedRewardTransitionApproval(
        approval=approval, signature=sign_object(approval, wallet("Ferdie"))
    )
    assert verify_transition_approval(signed, series=c.series, proposal=proposal) == signed
    raw = canonical_json_bytes(approval)
    assert (b'"activation_rule"' in raw) is immediate
    assert canonical_json_bytes(RewardTransitionApproval.model_validate_json(raw)) == raw
    other = proposed(c, initial(c), immediate=not immediate)
    with pytest.raises(ValueError, match="exact proposed release"):
        verify_transition_approval(signed, series=c.series, proposal=other)
    with pytest.raises(ValueError, match="versioned approval"):
        RewardTransitionApproval.model_validate_json(
            canonical_json_bytes(
                {
                    **approval.model_dump(by_alias=True),
                    "schema": "umi-reward-transition-approval/1"
                    if immediate
                    else "umi-reward-transition-approval/2",
                }
            )
        )
