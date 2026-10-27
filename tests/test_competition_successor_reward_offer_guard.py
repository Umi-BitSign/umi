"""Future cohorts cannot offer an unadopted or old-style model allocation."""

from types import SimpleNamespace

from umi import competition_reward_offers as offers_module
from umi.competition_cohort_recovery import GeometricModelRewardCohortAuthority
from umi.competition_geometric_rewards import GeometricRewardParameters
from umi.competition_reward_offers import StandingRewardOffers, successor_reward_rule_ready


def _signed(parameters):
    return SimpleNamespace(adoption=SimpleNamespace(parameters=parameters))


def test_c6_and_later_require_selected_c5_style_economics():
    original_authority = object()
    expected = GeometricRewardParameters(
        band_width_bps=250,
        band_decay_bps=7500,
        within_band_decay_bps=7500,
        score_duplicate_tolerance_bps=1,
    )
    old_width = expected.model_copy(update={"band_width_bps": 500})
    old_decay = expected.model_copy(update={"within_band_decay_bps": 10000})
    for sequence in range(6, 11):
        plan = SimpleNamespace(sequence=sequence)
        assert not successor_reward_rule_ready(plan, original_authority, None)
        assert not successor_reward_rule_ready(plan, original_authority, _signed(old_width))
        assert not successor_reward_rule_ready(plan, original_authority, _signed(old_decay))
        assert successor_reward_rule_ready(plan, original_authority, _signed(expected))
    assert successor_reward_rule_ready(SimpleNamespace(sequence=5), original_authority, None)


def test_native_signed_geometric_authority_needs_no_second_adoption():
    expected = GeometricRewardParameters(band_width_bps=250)
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


def test_missing_c6_adoption_stops_offer_before_package_io(monkeypatch, caplog):
    cohort = "ab" * 32
    plan = SimpleNamespace(sequence=6)
    prefix = (SimpleNamespace(decision=SimpleNamespace(kind="admit_series")),)
    monkeypatch.setattr(offers_module, "verify_reward_decisions", lambda *a, **k: prefix)
    monkeypatch.setattr(offers_module, "digest", lambda _: cohort)
    offers = object.__new__(StandingRewardOffers)
    offers.series = SimpleNamespace(cohorts=(plan,), recovery=SimpleNamespace(authority=object()))
    offers.policy = object()
    offers.reward_adoptions = None
    offers._reported_missing_successor_adoptions = set()
    for _ in range(2):
        assert offers(cohort, prefix) is None
        assert offers.pending_reason == "reward_adoption_pending"
    assert caplog.text.count("reward_offer_waiting_for_c5_style_economics") == 1
