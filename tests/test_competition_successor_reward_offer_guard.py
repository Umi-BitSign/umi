"""Future cohorts cannot offer an unadopted or old-style model allocation."""

from types import SimpleNamespace

import pytest

from umi import competition_reward_offers as offers_module
from umi.competition_cohort_recovery import GeometricModelRewardCohortAuthority
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_reward_offers import StandingRewardOffers, successor_reward_rule_ready


def _signed(parameters):
    return SimpleNamespace(adoption=SimpleNamespace(parameters=parameters))


def test_c6_and_later_require_their_announced_economics():
    original_authority = object()
    for sequence in (*range(6, 11), 100):
        expected = cohort_reward_parameters(sequence)
        old_width = expected.model_copy(update={"band_width_bps": 500})
        old_decay = expected.model_copy(update={"within_band_decay_bps": 10000})
        plan = SimpleNamespace(sequence=sequence)
        assert not successor_reward_rule_ready(plan, original_authority, None)
        assert not successor_reward_rule_ready(plan, original_authority, _signed(old_width))
        assert not successor_reward_rule_ready(plan, original_authority, _signed(old_decay))
        assert successor_reward_rule_ready(plan, original_authority, _signed(expected))
        wrong_cohort = cohort_reward_parameters(7 if sequence == 6 else 6)
        assert not successor_reward_rule_ready(plan, original_authority, _signed(wrong_cohort))
    assert successor_reward_rule_ready(SimpleNamespace(sequence=5), original_authority, None)


def test_native_signed_geometric_authority_needs_no_second_adoption():
    expected = cohort_reward_parameters(11)
    authority = GeometricModelRewardCohortAuthority.model_construct(
        model_reward_parameters=expected
    )
    assert successor_reward_rule_ready(SimpleNamespace(sequence=11), authority, None)
    changed = authority.model_copy(
        update={"model_reward_parameters": expected.model_copy(update={"band_width_bps": 500})}
    )
    assert not successor_reward_rule_ready(SimpleNamespace(sequence=11), changed, None)
    assert not successor_reward_rule_ready(
        SimpleNamespace(sequence=11), authority, _signed(changed.model_reward_parameters)
    )


def test_c7_announcement_requires_relative_grace_as_well_as_decay():
    plan = SimpleNamespace(sequence=7)
    expected = cohort_reward_parameters(7)
    without_grace = expected.model_copy(update={"baseline_grace_bps": 0})
    old_schema = cohort_reward_parameters(6).model_copy(
        update={"band_decay_bps": 8500, "within_band_decay_bps": 8500}
    )
    for wrong in (without_grace, old_schema):
        assert not successor_reward_rule_ready(plan, object(), _signed(wrong))
    assert successor_reward_rule_ready(plan, object(), _signed(expected))


@pytest.mark.parametrize("sequence", [6, 7, 8, 100])
def test_missing_adoption_stops_offer_before_package_io(sequence, monkeypatch, caplog):
    cohort = "ab" * 32
    plan = SimpleNamespace(sequence=sequence)
    prefix = (SimpleNamespace(decision=SimpleNamespace(kind="admit_series")),)
    monkeypatch.setattr(offers_module, "verify_reward_decisions", lambda *a, **k: prefix)
    monkeypatch.setattr(offers_module, "digest", lambda _: cohort)
    offers = object.__new__(StandingRewardOffers)
    offers.series = SimpleNamespace(cohorts=(plan,), recovery=SimpleNamespace(authority=object()))
    offers.policy = object()
    offers._configure_reward_adoptions(None, series=offers.series, policy=offers.policy)
    offers._reported_missing_successor_adoptions = set()
    for _ in range(2):
        assert offers(cohort, prefix) is None
        assert offers.pending_reason == "reward_adoption_pending"
    assert caplog.text.count("reward_offer_waiting_for_announced_economics") == 1


@pytest.mark.parametrize("changed", ["plan", "policy", "authority", "terms", "catalogs"])
def test_adoption_discovery_rejects_unapproved_package_inputs(changed, tmp_path, monkeypatch):
    """Discovery cannot expose an unrelated package merely because it completed."""
    cohort = "ab" * 32
    plan = SimpleNamespace(sequence=7)
    prefix = (SimpleNamespace(decision=SimpleNamespace(kind="admit_series")),)
    monkeypatch.setattr(offers_module, "verify_reward_decisions", lambda *a, **k: prefix)
    monkeypatch.setattr(offers_module, "digest", lambda value: cohort if value is plan else value)
    history = SimpleNamespace(plan=plan, authority=SimpleNamespace(authority="authority"))
    inputs = SimpleNamespace(
        history=history, terms="terms", catalogs=(SimpleNamespace(catalog="catalog"),)
    )
    package = SimpleNamespace(policy_sha256="policy", inputs=inputs)
    if changed == "plan":
        history.plan = SimpleNamespace(sequence=8)
    elif changed == "policy":
        package.policy_sha256 = "another-policy"
    elif changed == "authority":
        history.authority.authority = "another-authority"
    elif changed == "terms":
        inputs.terms = "other-terms"
    else:
        inputs.catalogs = (SimpleNamespace(catalog="another-catalog"),)

    def forbidden_retention(_):
        pytest.fail("discovery retained a package outside the approved cohort inputs")

    offers = object.__new__(StandingRewardOffers)
    offers.series = SimpleNamespace(
        cohorts=(plan,), recovery=SimpleNamespace(authority="authority")
    )
    offers.policy = "policy"
    offers._configure_reward_adoptions(None, series=offers.series, policy=offers.policy)
    offers.settlements = tmp_path
    offers.packages = SimpleNamespace(load=lambda *a, **k: package)
    offers.files = SimpleNamespace(maximum_package_bytes=1024, retain_package=forbidden_retention)
    offers.manifest = SimpleNamespace(
        requirement=lambda _: SimpleNamespace(terms_sha256="terms", catalog_sha256s=("catalog",))
    )
    with pytest.raises(ValueError, match="approved cohort inputs"):
        offers.completed_package(cohort, prefix)
