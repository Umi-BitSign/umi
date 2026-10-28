"""Signed adoption delivery survives repeats and interruption without rollback."""

import os

import pytest

from umi import competition_reward_adoption_delivery as delivery_module
from umi import competition_reward_adoption_feed as module
from umi.competition_geometric_rewards import cohort_reward_parameters
from umi.competition_reward_adoption import RewardAdoptionSelection, SignedRewardModelAdoption
from umi.competition_reward_adoption_delivery import RewardPackageSelection
from umi.competition_reward_opportunity import prepare_early_release_revision
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_decisions import signatures
from .test_competition_reward_opportunity import chain as chain
from .test_competition_reward_opportunity import chain_config as chain_config
from .test_competition_reward_opportunity import control as control
from .test_competition_reward_opportunity import manifest_case as manifest_case
from .test_competition_reward_opportunity import opportunity_case as opportunity_case
from .test_competition_reward_opportunity import policy as policy
from .test_competition_reward_opportunity import series_case as series_case
from .test_competition_reward_transition_timing import age, predecessor
from .test_competition_reward_transition_timing import initial as make_initial


def initial(case):
    # sr25519 signing is randomized; all consumers receive the same retained
    # signed artifact, not independently re-signed copies of the same body.
    if not hasattr(case, "feed_initial"):
        case.feed_initial = make_initial(case)
    return case.feed_initial


def owner(tmp_path, case, *, name="producer", selected=None):
    return module.RewardAdoptionFeed(
        tmp_path / name,
        source=module.RewardAdoptionFeedConfig(path=str(tmp_path / "selection.json")),
        series=case.series,
        policy=case.policy,
        initial=initial(case) if selected is None else selected,
    )


def revision(case, *, automatic=False):
    body = prepare_early_release_revision(
        initial(case),
        series=case.series,
        policy=case.policy,
        manifest=case.manifest,
        predecessor=predecessor(case),
        successor_cohort_sha256=digest(case.series.cohorts[1]),
        issued_at_block=202,
        reason="Configured successor release policy",
        live_age=age(case) if automatic else None,
    )
    return SignedRewardModelAdoption(adoption=body, signatures=signatures(body))


@pytest.mark.parametrize("automatic", [False, True])
def test_signed_extension_reaches_independent_consumers_and_restart(
    tmp_path, opportunity_case, automatic
):
    c = opportunity_case
    producer = owner(tmp_path, c)
    reader = owner(tmp_path, c, name="consumer")
    old = canonical_json_bytes(reader.selected.adoptions[0])
    signed = revision(c, automatic=automatic)
    selected = producer.publish(signed)
    assert reader.refresh() == selected
    assert canonical_json_bytes(reader.selected.adoptions[0]) == old
    assert producer.publish(signed) == selected
    assert producer.journal.keys("feed_selection") == ["000000"]
    assert owner(tmp_path, c, name="consumer").refresh() == selected
    assert os.stat(tmp_path / "selection.json").st_mode & 0o777 == 0o644


def test_unchanged_poll_does_not_verify_or_append_again(tmp_path, opportunity_case, monkeypatch):
    feed = owner(tmp_path, opportunity_case)
    selected = feed.publish(revision(opportunity_case))

    def repeated(*args, **kwargs):
        raise AssertionError("unchanged signed selection was verified twice")

    monkeypatch.setattr(module, "verify_adoption_selection", repeated)
    monkeypatch.setattr(feed.journal, "put", repeated)
    monkeypatch.setattr(module.os, "fdopen", repeated)
    assert feed.refresh() == selected
    assert feed.refresh() == selected


@pytest.mark.parametrize(
    "damage", ["missing", "rollback", "malformed", "noncanonical", "oversized"]
)
def test_transport_damage_never_replaces_retained_frontier(tmp_path, opportunity_case, damage):
    feed = owner(tmp_path, opportunity_case)
    selected = feed.publish(revision(opportunity_case))
    path = tmp_path / "selection.json"
    if damage == "missing":
        path.unlink()
    elif damage == "rollback":
        path.write_bytes(canonical_json_bytes(initial(opportunity_case)))
    elif damage == "malformed":
        path.write_bytes(b"{")
    elif damage == "noncanonical":
        path.write_bytes(canonical_json_bytes(selected) + b"\n")
    else:
        path.write_bytes(b" " * (feed.source.maximum_bytes + 1))
    with pytest.raises(ValueError):
        feed.refresh()
    assert feed.selected == selected
    assert feed.journal.keys("feed_selection") == ["000000"]


def test_transport_publish_recovered_after_replace_before_receipt(
    tmp_path, opportunity_case, monkeypatch
):
    feed = owner(tmp_path, opportunity_case)
    signed = revision(opportunity_case)

    def interrupted(*args, **kwargs):
        raise OSError("simulated interruption after transport replacement")

    monkeypatch.setattr(feed.journal, "put", interrupted)
    with pytest.raises(OSError, match="simulated interruption"):
        feed.publish(signed)
    restored = owner(tmp_path, opportunity_case)
    assert restored.publish(signed).adoptions[-1] == signed
    assert restored.journal.keys("feed_selection") == ["000000"]


def test_feed_rejects_unapproved_signature_and_changed_authority(tmp_path, opportunity_case):
    c = opportunity_case
    feed = owner(tmp_path, c)
    signed = revision(c)
    changed = signed.adoption.model_copy(update={"policy_sha256": "ff" * 32})
    wrong_authority = SignedRewardModelAdoption(adoption=changed, signatures=signatures(changed))
    changed_unsigned = signed.adoption.model_copy(update={"issued_at_block": 203})
    for candidate in (signed.model_copy(update={"adoption": changed_unsigned}), wrong_authority):
        with pytest.raises(ValueError):
            feed.publish(candidate)
    assert not (tmp_path / "selection.json").exists()
    assert feed.journal.keys("feed_selection") == []


def test_feed_rejects_fifo_without_waiting_and_preserves_hardlinks(tmp_path, opportunity_case):
    feed = owner(tmp_path, opportunity_case)
    path = tmp_path / "selection.json"
    os.mkfifo(path)
    with pytest.raises(ValueError, match="bound"):
        feed.refresh()
    path.unlink()
    unrelated = tmp_path / "keep.json"
    unrelated.write_bytes(b"unrelated bytes")
    os.link(unrelated, tmp_path / "selection.json.publishing")
    with pytest.raises(ValueError, match="owned regular file"):
        feed.publish(revision(opportunity_case))
    assert unrelated.read_bytes() == b"unrelated bytes"


def test_corrupt_owner_checkpoint_is_not_treated_as_empty(tmp_path, opportunity_case):
    feed = owner(tmp_path, opportunity_case)
    feed.journal.put("feed_selection", "000001", initial(opportunity_case))
    with pytest.raises(ValueError, match="repair"):
        owner(tmp_path, opportunity_case)


def test_independent_consumer_rejects_capacity_rollback(tmp_path, opportunity_case):
    c = opportunity_case
    feed = owner(tmp_path, c)
    selected = feed.publish(revision(c))
    smaller = RewardAdoptionSelection(
        schema="umi-standing-reward-adoption-selection/1",
        adoptions=selected.adoptions,
        maximum_decisions=selected.maximum_decisions - 1,
    )
    (tmp_path / "selection.json").write_bytes(canonical_json_bytes(smaller))
    with pytest.raises(ValueError, match="rolled back"):
        owner(tmp_path, c).refresh()


def test_newer_boot_frontier_is_checkpointed_without_erasing_consumer_state(
    tmp_path, opportunity_case
):
    c = opportunity_case
    feed = owner(tmp_path, c)
    selected = feed.publish(revision(c))
    advanced = selected.model_copy(update={"maximum_decisions": selected.maximum_decisions + 1})
    restored = owner(tmp_path, c, selected=advanced)
    assert restored.selected == advanced
    assert restored.journal.keys("feed_selection") == ["000000", "000001"]
    delta = restored.journal.get("feed_selection", "000001")
    assert delta["added"] == []
    assert owner(tmp_path, c).selected == advanced
    with pytest.raises(ValueError, match="rolled back"):
        restored.refresh()  # Transport still advertises the previous capacity.


def test_checkpoint_growth_retains_each_signed_revision_only_once(tmp_path, opportunity_case):
    c = opportunity_case
    feed = owner(tmp_path, c)
    path = tmp_path / "selection.json"
    path.write_bytes(canonical_json_bytes(initial(c)))
    # No new frontier yet: the immutable boot already selected these bytes.
    assert feed.refresh() == initial(c)
    feed.publish(revision(c))
    selected = feed.selected.model_copy(update={"maximum_decisions": 1025})
    path.write_bytes(canonical_json_bytes(selected))
    feed.refresh()
    records = [
        feed.journal.get("feed_selection", key) for key in feed.journal.keys("feed_selection")
    ]
    assert sum(len(record["added"]) for record in records) == len(selected.adoptions)
    assert owner(tmp_path, c).selected == selected


def test_delivery_discovers_new_adopted_cohort_without_restart(tmp_path, opportunity_case):
    c = opportunity_case
    producer = owner(tmp_path, c)
    delivery = RewardPackageSelection(
        tmp_path / "delivery",
        series=c.series,
        policy=c.policy,
        initial=initial(c),
        source=producer.source,
    )
    assert not (tmp_path / "delivery").exists()
    before = frozenset({digest(c.series.cohorts[1]) + ".json"})
    assert delivery() == before
    next_plan = c.series.cohorts[2]
    body = (
        initial(c)
        .adoptions[0]
        .adoption.model_copy(
            update={
                "cohort_sha256": digest(next_plan),
                "parameters": cohort_reward_parameters(next_plan.sequence),
            }
        )
    )
    producer.publish(SignedRewardModelAdoption(adoption=body, signatures=signatures(body)))
    assert delivery() == before | {digest(next_plan) + ".json"}
    assert digest(c.series.cohorts[0]) + ".json" not in delivery()
    resumed = RewardPackageSelection(
        tmp_path / "delivery",
        series=c.series,
        policy=c.policy,
        initial=initial(c),
        source=producer.source,
    )
    assert resumed() == delivery()


@pytest.mark.parametrize("existing_adoption", [False, True])
def test_producer_delivery_discovers_completed_successors_before_adoption(
    tmp_path, opportunity_case, monkeypatch, existing_adoption
):
    c = opportunity_case
    source = module.RewardAdoptionFeedConfig(path=str(tmp_path / "selection.json"))
    delivery = RewardPackageSelection(
        tmp_path / "delivery",
        series=c.series,
        policy=c.policy,
        initial=initial(c) if existing_adoption else None,
        source=source,
        allow_completed_successors=True,
    )
    expected = frozenset(digest(p) + ".json" for p in c.series.cohorts if p.sequence >= 6)
    assert digest(c.series.cohorts[2]) + ".json" in expected
    assert digest(c.series.cohorts[0]) + ".json" not in expected

    def repeated(*args, **kwargs):
        raise AssertionError("unchanged discovery repeated authority or directory work")

    monkeypatch.setattr(delivery_module, "verify_recovery_authority", repeated)
    monkeypatch.setattr(delivery_module, "digest", repeated)
    assert delivery() == expected
    assert delivery() == expected
    assert delivery.reward_adoptions == (initial(c) if existing_adoption else None)


def test_producer_discovery_still_refuses_damaged_feed(tmp_path, opportunity_case):
    c = opportunity_case
    producer = owner(tmp_path, c)
    producer.publish(revision(c))
    delivery = RewardPackageSelection(
        tmp_path / "delivery",
        series=c.series,
        policy=c.policy,
        initial=initial(c),
        source=producer.source,
        allow_completed_successors=True,
    )
    assert digest(c.series.cohorts[2]) + ".json" in delivery()
    (tmp_path / "selection.json").write_bytes(b"{")
    with pytest.raises(ValueError):
        delivery()


@pytest.mark.parametrize("invalid", ["no_feed", "flag", "policy", "cohorts", "signature"])
def test_completed_successor_discovery_requires_exact_admitted_authority(
    tmp_path, opportunity_case, invalid
):
    c = opportunity_case
    args = dict(
        series=c.series,
        policy=c.policy,
        initial=None,
        source=module.RewardAdoptionFeedConfig(path=str(tmp_path / "selection.json")),
        allow_completed_successors=True,
    )
    if invalid == "no_feed":
        args["source"] = None
    elif invalid == "flag":
        args["allow_completed_successors"] = 1
    elif invalid == "policy":
        args["policy"] = c.policy.model_copy(update={"sequence": c.policy.sequence + 1})
    elif invalid == "cohorts":
        args["series"] = c.series.model_copy(update={"cohorts": c.series.cohorts[:-1]})
    else:
        bad = c.series.recovery.signatures[0].model_copy(update={"signature": "0x" + "00" * 64})
        recovery = c.series.recovery.model_copy(
            update={"signatures": (bad, *c.series.recovery.signatures[1:])}
        )
        args["series"] = c.series.model_copy(update={"recovery": recovery})
    with pytest.raises((ValueError, TypeError)):
        RewardPackageSelection(tmp_path / "delivery", **args)
    assert not (tmp_path / "delivery").exists()


def test_deferred_owner_does_not_open_or_change_frontier_before_protected_poll(
    tmp_path, opportunity_case
):
    c = opportunity_case
    producer = owner(tmp_path, c)
    advanced = producer.publish(revision(c))
    root = tmp_path / "deferred-owner"
    feed = module.RewardAdoptionFeed(
        root,
        source=producer.source,
        series=c.series,
        policy=c.policy,
        initial=initial(c),
        deferred=True,
    )
    assert feed.selected == initial(c)
    assert not root.exists()
    assert feed.refresh() == advanced
    assert root.exists()


def test_publish_seeds_transport_from_existing_signed_boot_without_resigning(
    tmp_path, opportunity_case
):
    feed = owner(tmp_path, opportunity_case)
    original = initial(opportunity_case)
    assert not (tmp_path / "selection.json").exists()
    assert feed.publish(original.adoptions[0]) == original
    assert (tmp_path / "selection.json").read_bytes() == canonical_json_bytes(original)
