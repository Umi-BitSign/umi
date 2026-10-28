"""Installed native owners consume new signed selections without reconstruction."""

import pytest

from umi import competition_reward_adoption_consumer as consumer
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.competition_reward_decisions import MAX_DECISION_BYTES, StandingRewardControlReader
from umi.competition_reward_exchange import RewardReviewExchange
from umi.competition_reward_files import StandingRewardFiles
from umi.competition_reward_handoff_models import LegacyRewardHandoffPlan
from umi.competition_reward_offers import StandingRewardOffers
from umi.competition_reward_opportunity import opportunity_rule
from umi.competition_reward_signing import RewardDecisionJournal, RewardDecisionSigner
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_adoption_feed import initial, owner, revision
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_open_competition import wallet


def test_running_reader_signer_offers_share_accepted_frontier(
    opportunity_case, tmp_path, monkeypatch
):
    c = opportunity_case
    producer = owner(tmp_path, c)
    feed = owner(tmp_path, c, name="consumer")
    selected = initial(c)
    common = dict(reward_adoptions=selected, reward_adoption_feed=feed)
    reader = StandingRewardControlReader(
        tmp_path / "native-reader",
        c.series,
        c.policy,
        expected_series_sha256=digest(c.series),
        expected_chain_config_sha256=c.reader.chain_config_sha256,
        maximum_bytes=8 * 1024**2,
        **common,
    )
    signer = RewardDecisionJournal(
        tmp_path / "native-signer",
        c.series,
        c.policy,
        wallet("Charlie").hotkey.ss58_address,
        expected_chain_config_sha256=c.reader.chain_config_sha256,
        maximum_bytes=8 * 1024**2,
        **common,
    )
    rule = opportunity_rule(c.manifest, c.series, c.policy)
    offers = StandingRewardOffers(
        series=c.series,
        policy=c.policy,
        manifest=c.manifest,
        handoff=LegacyRewardHandoffPlan(
            schema="umi-legacy-reward-handoff-plan/1",
            series_sha256=digest(c.series),
            cohort_sha256=digest(c.series.cohorts[0]),
            legacy_policy_sha256="11" * 32,
            legacy_round_sha256="22" * 32,
            legacy_package_sha256="33" * 32,
        ),
        settlements=tmp_path / "settlements",
        files=StandingRewardFiles(
            tmp_path / "files", maximum_package_bytes=1024**2, maximum_witness_bytes=1024**2
        ),
        coverage=RewardCoverageJournal(
            tmp_path / "coverage", rule, expected_rule_sha256=digest(rule)
        ),
        **common,
    )

    async def forbidden_sign(_):
        pytest.fail("feed delivery cannot sign a decision")

    exchange = RewardReviewExchange(
        signer=RewardDecisionSigner(signer, forbidden_sign),
        proposer=wallet("Charlie").hotkey.ss58_address,
        inbox=tmp_path / "inbox",
        outbox=tmp_path / "outbox",
    )
    advanced = producer.publish(revision(c))
    advanced = advanced.model_copy(update={"maximum_decisions": advanced.maximum_decisions + 1})
    (tmp_path / "selection.json").write_bytes(canonical_json_bytes(advanced))
    assert reader.reward_adoptions == signer.reward_adoptions == offers.reward_adoptions == selected
    assert reader.refresh_reward_adoptions() == advanced
    assert signer._slot(advanced.maximum_decisions - 1)
    assert exchange.maximum_bytes == advanced.maximum_decisions * MAX_DECISION_BYTES

    def repeated(*args, **kwargs):
        pytest.fail("cached getter must not read or reverify the signed selection")

    monkeypatch.setattr(feed, "refresh", repeated)
    monkeypatch.setattr(consumer, "verify_adoption_selection", repeated)
    for native in (reader, signer, offers):
        assert native.reward_adoptions == advanced
        with pytest.raises(ValueError, match="owner"):
            native.reward_adoptions = selected
    assert owner(tmp_path, c, name="consumer").selected == advanced


def test_feed_consumer_rejects_mismatched_authority_or_initial_lineage(opportunity_case, tmp_path):
    c = opportunity_case
    feed = owner(tmp_path, c)
    native = consumer.RewardAdoptionConsumer()
    with pytest.raises(ValueError, match="authority"):
        native._configure_reward_adoptions(
            initial(c),
            series=c.series.model_copy(update={"manifest_sha256": "aa" * 32}),
            policy=c.policy,
            feed=feed,
        )
    advanced = initial(c).model_copy(update={"adoptions": (*initial(c).adoptions, revision(c))})
    with pytest.raises(ValueError, match="lineage"):
        native._configure_reward_adoptions(advanced, series=c.series, policy=c.policy, feed=feed)


def test_absent_feed_preserves_static_selection_and_opens_no_owner(tmp_path):
    assert (
        consumer.open_reward_adoption_feed(
            tmp_path / "unused", source=None, series=None, policy=None, initial=None
        )
        is None
    )
    assert not (tmp_path / "unused").exists()
