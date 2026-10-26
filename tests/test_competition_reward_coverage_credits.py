"""Native credit receipts reuse completed exact endpoint verdicts across restart."""

from types import SimpleNamespace as NS

import pytest

from umi.competition_reward_coverage_credits import (
    CoverageCreditRepairRequired,
    validate_native_credit,
)
from umi.competition_reward_coverage_intervals import _interval
from umi.competition_reward_coverage_journal import RewardCoverageJournal
from umi.open_competition import digest

from .test_competition_reward_coverage_intervals import following, point, rule


@pytest.fixture
def credit_case(tmp_path, monkeypatch):
    from umi import competition_reward_coverage_credits as module

    selected = rule()
    root = tmp_path / "native-credit"
    journal = RewardCoverageJournal(root, selected, expected_rule_sha256=digest(selected))
    historical = NS(identity={"owner": "history", "revision": 0})
    monkeypatch.setattr(module, "history_identity", lambda history: dict(history.identity))
    left, right = point(), following()
    interval = _interval(left, right, selected)
    values = [
        dict(
            point=p.model_dump(mode="json"),
            package_sha256="a" * 64,
            policy_sha256="b" * 64,
            requirement_sha256="c" * 64,
            cohort_sha256="d" * 64,
            model_dependencies=dict(
                schema="umi-coverage-model-dependencies/1", mode="not_selected", context=None
            ),
        )
        for p in (left, right)
    ]
    # This isolated boundary supplies already-qualified native verdict identities;
    # full proof issuer and preparation behavior are qualified separately below.
    with journal.journal.transaction() as db:
        for p, v in zip((left, right), values, strict=True):
            db.execute("INSERT INTO coverage_checkpoint_index VALUES (?,?)", (p.key(), digest(v)))
    return NS(
        journal=journal,
        history=historical,
        values=values,
        interval=interval,
        root=root,
        rule=selected,
        points=(left, right),
    )


def test_exact_native_credit_restarts_without_payload_or_endpoint_replay(credit_case, monkeypatch):
    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)
    fresh = RewardCoverageJournal(c.root, c.rule, expected_rule_sha256=digest(c.rule))
    fact, groups, state = fresh.native_credits.load(c.interval.key(), c.history)
    assert len(groups) == 2
    assert digest(groups[0]["dependencies"]) == digest(groups[1]["dependencies"])
    assert groups[0] == groups[1]  # One shared native dependency group.
    fresh.native_credits.recheck(state, c.history)
    native = fresh.native_credits.apply(fact)
    assert validate_native_credit(native, fresh) == (c.interval, c.points[-1].block)
    assert fresh._verified == {c.interval.key(): c.interval}
    with pytest.raises(CoverageCreditRepairRequired):
        validate_native_credit(native, c.journal)


@pytest.mark.parametrize(
    "damage", ["fact", "selection", "endpoint", "source", "group", "history", "fence"]
)
def test_exact_dependency_damage_never_becomes_a_fresh_native_credit(credit_case, damage):
    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)
    if damage == "history":
        c.history.identity["revision"] += 1
    else:
        with c.journal.journal.transaction() as db:
            if damage == "fact":
                db.execute("DELETE FROM records WHERE kind='coverage_credit_verified'")
            elif damage == "selection":
                db.execute("DELETE FROM coverage_credit_index")
            elif damage == "endpoint":
                db.execute("UPDATE coverage_checkpoint_index SET result=?", ("f" * 64,))
            elif damage == "source":
                db.execute(
                    "INSERT INTO coverage_source_identity VALUES ('coverage_object','new',0,1)"
                )
                db.execute("UPDATE coverage_source_identity SET revision=revision+1")
            elif damage == "group":
                db.execute("DELETE FROM records WHERE kind='coverage_credit_dependency_group'")
            else:
                db.execute("DROP TRIGGER coverage_credit_records_delete")
    with pytest.raises(CoverageCreditRepairRequired):
        c.journal.native_credits.load(c.interval.key(), c.history)
    assert not c.journal._verified


def test_native_credit_cannot_be_seeded_from_unverified_interval_hint(credit_case):
    c = credit_case
    c.journal.journal.put("coverage_interval", c.interval.key(), c.interval)
    assert c.journal.native_credits.load(c.interval.key(), c.history) is None


def test_ordinary_appends_preserve_native_credit_and_current_snapshot(credit_case):
    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)
    before = c.journal.native_credits.load(c.interval.key(), c.history)
    c.journal.journal.put("coverage_object", "a" * 64, {"hex": "01"})
    after = c.journal.native_credits.load(c.interval.key(), c.history)
    assert before == after


def test_mutation_during_native_group_refresh_is_rechecked(credit_case):
    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)
    _, _, snapshot = c.journal.native_credits.load(c.interval.key(), c.history)
    with c.journal.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES ('observed')")
    with pytest.raises(CoverageCreditRepairRequired):
        c.journal.native_credits.recheck(snapshot, c.history)


async def test_native_owner_counts_are_bounded_and_not_credited_hint_authority(credit_case):
    c = credit_case
    c.journal.journal.put("coverage_interval", c.interval.key(), c.interval)
    counts = await c.journal.diagnostic_counts()
    assert counts["retained_intervals"] == 1 and counts["revalidated_intervals"] == 0
    assert counts["retained_count_scope"] == "all_activations_in_this_owner_not_native_credit"


@pytest.mark.parametrize("damage", ["selection", "fact", "history", "group"])
def test_explicit_metadata_repair_revalidates_exact_original_and_is_repeatable(credit_case, damage):
    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)
    if damage == "history":
        c.history.identity["revision"] += 1
    else:
        with c.journal.journal.transaction() as db:
            if damage == "selection":
                db.execute("DELETE FROM coverage_credit_index")
            elif damage == "fact":
                db.execute("DELETE FROM records WHERE kind='coverage_credit_verified'")
            else:
                db.execute("DELETE FROM records WHERE kind='coverage_credit_dependency_group'")
    with pytest.raises(CoverageCreditRepairRequired):
        c.journal.native_credits.load(c.interval.key(), c.history)
    with pytest.raises(CoverageCreditRepairRequired):
        c.journal.native_credits.remember(c.interval, c.values, c.history)
    # The native source must restore both original endpoints before this private
    # journal boundary is called, qualified by the full native integration test.
    c.journal.native_credits.remember(
        c.interval, c.values, c.history, repair_reason="original endpoints restored"
    )
    fact, _, _ = c.journal.native_credits.load(c.interval.key(), c.history)
    assert fact["interval"] == c.interval.model_dump(mode="json", by_alias=True)
    c.journal.native_credits.remember(
        c.interval, c.values, c.history, repair_reason="original endpoints restored"
    )
    assert c.journal.native_credits.load(c.interval.key(), c.history)[0] == fact
    assert c.journal.journal.keys("coverage_credit_repair")


def test_credit_repair_cannot_invent_lost_permanent_completion(credit_case):
    c = credit_case
    with pytest.raises(CoverageCreditRepairRequired, match="original completion"):
        c.journal.native_credits.remember(
            c.interval, c.values, c.history, repair_reason="not completed"
        )


def test_credit_repair_still_requires_exact_native_endpoint_verdict(credit_case):
    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)
    with c.journal.journal.transaction() as db:
        db.execute("UPDATE coverage_checkpoint_index SET result=?", ("f" * 64,))
    with pytest.raises(CoverageCreditRepairRequired, match="endpoint changed"):
        c.journal.native_credits.remember(
            c.interval, c.values, c.history, repair_reason="unrestored endpoint"
        )


def test_completed_credit_generation_loss_requires_repair_not_legacy_fallback(
    credit_case, monkeypatch
):
    from umi import competition_reward_coverage_credits as module

    c = credit_case
    c.journal.native_credits.remember(c.interval, c.values, c.history)

    def unavailable(_):
        raise module.CreditReuseUnavailable("generation component missing")

    monkeypatch.setattr(module, "history_identity", unavailable)
    for action in (
        lambda: c.journal.native_credits.load(c.interval.key(), c.history),
        lambda: c.journal.native_credits.remember(c.interval, c.values, c.history),
    ):
        with pytest.raises(CoverageCreditRepairRequired, match="generation is missing"):
            action()
    assert c.journal.native_credits.load("f" * 64, c.history) is None
