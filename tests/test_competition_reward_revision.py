"""Revision races with explicit synthetic native coverage/finality boundaries.

These tests qualify orchestration, restart and refusal behavior. They do not
establish installed chain proof validity; existing native coverage tests own it.
"""

from types import SimpleNamespace

import pytest

from umi.competition_reward_coverage_intervals import CoveragePoint, _issue_retained_coverage
from umi.competition_reward_coverage_service import StandingRewardCoverageService
from umi.competition_reward_opportunity import RewardCoverageRule
from umi.competition_reward_revision import (
    NativeRewardRevisionReviewer,
    RewardEconomicsLocked,
    RewardRevisionPending,
    validate_revision_clearance,
)
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest, identity

from .test_competition_reward_adoption import (
    adoption_case,
    revised,
    transition,
)
from .test_competition_reward_adoption import (
    chain as chain,
)
from .test_competition_reward_adoption import (
    chain_config as chain_config,
)
from .test_competition_reward_adoption import (
    control as control,
)
from .test_competition_reward_adoption import (
    policy as policy,
)
from .test_competition_reward_adoption import (
    series_case as series_case,
)


@pytest.fixture
def revision_case(series_case, tmp_path):
    c = series_case
    old, _ = adoption_case(c)
    prefix = (c.genesis, old)
    suspended = transition(c, prefix, "suspend_activation", old.decision.activation)
    prefix += (suspended,)
    series = c.series.model_copy(
        update={"maximum_proof_lag_blocks": 1, "maximum_transaction_lifetime_blocks": 2}
    )
    journal = RoundJournal(tmp_path / "revision", series)
    reader = SimpleNamespace(series=series)
    reader.review_history = lambda control, source, history: SimpleNamespace(
        selection=SimpleNamespace(
            decision_sha256=digest(h.suspension.decision), committed_at_block=h.suspension_block
        )
    )
    coverage = object.__new__(StandingRewardCoverageService)
    coverage.preparation = SimpleNamespace(reader=reader)
    rule = RewardCoverageRule(
        schema="umi-reward-coverage-rule/1",
        series_sha256=digest(series),
        runtime_profile_sha256="ab" * 32,
        maximum_interval_ms=1000,
    )
    coverage.journal = SimpleNamespace(journal=journal, rule=rule)
    h = SimpleNamespace(
        coverage=coverage,
        prefix=prefix,
        journal=journal,
        rule=rule,
        captured=[],
        replayed=[],
        items={},
        live=None,
        damaged=False,
        suspension=suspended,
        suspension_block=501,
        prepared_activation=old.decision.activation,
        source_activations=[],
    )

    async def capture(hotkey, block):
        h.captured.append((hotkey, block))
        matched = (hotkey, block) == h.live
        point = CoveragePoint(
            series_sha256=digest(series),
            runtime_profile_sha256=rule.runtime_profile_sha256,
            activation_sha256=digest(h.prepared_activation),
            allocation_sha256=h.prepared_activation.allocation_sha256,
            projection_sha256="bc" * 32,
            validator_account_id=identity(hotkey),
            chain_config_sha256="cd" * 32,
            block=block,
            block_hash="0x" + f"{block:064x}",
            parent_hash="0x" + f"{block - 1:064x}",
            state_root="0x" + "de" * 32,
            timestamp_ms=block * 1000,
            covered=False,
        )
        result = _issue_retained_coverage(
            point,
            old.decision.activation.package_sha256,
            "ef" * 32,
            row_state={"row_matches": matched, "validator_last_update": block if matched else 0},
        )
        h.items[point.key()] = result
        return result

    async def replay(key):
        h.replayed.append(key)
        if h.damaged:
            raise ValueError("damaged native coverage completion")
        return h.items[key]

    h.source = SimpleNamespace(capture=capture, replay=replay)

    async def source(activation):
        assert activation.package_sha256 == old.decision.activation.package_sha256
        h.prepared_activation = activation
        h.source_activations.append(activation)
        return h.source

    async def retain(endpoint):
        return endpoint.point.key()

    coverage._source = source
    coverage.journal.retain_endpoint = retain
    coverage.journal.checkpoints = SimpleNamespace(load=lambda key: h.items.get(key))

    async def native_prefix(block):
        return SimpleNamespace(
            tip=SimpleNamespace(
                block_number=block,
                block_hash="0x" + f"{block:064x}",
            )
        )

    coverage.history = SimpleNamespace(verified_prefix=native_prefix)
    h.history = SimpleNamespace(
        writes=(
            SimpleNamespace(decision_sha256=digest(old.decision), block_number=500),
            SimpleNamespace(decision_sha256=digest(suspended.decision), block_number=501),
        )
    )
    h.control = lambda block: SimpleNamespace(
        snapshot=SimpleNamespace(block_number=block),
        control_sha256=digest(h.suspension.decision),
        committed_at_block=h.suspension_block,
    )
    h.owner = lambda n=64: NativeRewardRevisionReviewer(coverage=coverage, maximum_endpoints=n)
    h.old = old.decision.activation
    return h


async def test_suspension_must_drain_before_any_absence_claim(revision_case):
    h = revision_case
    with pytest.raises(RewardRevisionPending, match="drain"):
        await h.owner().review(prefix=h.prefix, control=h.control(503), history=h.history)
    assert h.captured == []


async def test_bounded_restart_reuses_native_endpoints_and_rechecks_dependencies(revision_case):
    h = revision_case
    for _ in range(2):
        with pytest.raises(RewardRevisionPending, match="bounded"):
            await h.owner(2).review(prefix=h.prefix, control=h.control(505), history=h.history)
    complete = await h.owner(2).review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert complete.clearance.reviewed_endpoints == 6
    assert len(h.captured) == len(set(h.captured)) == 6
    assert len(h.replayed) == 6
    h.damaged = True
    with pytest.raises(ValueError, match="damaged native"):
        await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert len(h.captured) == 6


async def test_earlier_matching_row_locks_even_if_latest_row_or_eligibility_differs(revision_case):
    h = revision_case
    h.live = (h.coverage.preparation.reader.series.validators[1], 503)
    owner = h.owner()
    with pytest.raises(RewardEconomicsLocked, match="finalized rewards"):
        await owner.review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert await h.owner().locked(h.old)
    before = len(h.captured)
    with pytest.raises(RewardEconomicsLocked, match="retained"):
        await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert len(h.captured) == before


async def test_missing_completed_index_repairs_original_without_new_capture(revision_case, caplog):
    h = revision_case
    with pytest.raises(RewardRevisionPending):
        await h.owner(1).review(prefix=h.prefix, control=h.control(505), history=h.history)
    with h.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='reward_revision_endpoint'")
    with caplog.at_level("INFO"):
        await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert len(h.captured) == len(set(h.captured)) == 6
    assert "reward_revision_metadata_repair" in caplog.text


async def test_lost_both_endpoint_records_are_visibly_repaired(revision_case, caplog):
    h = revision_case
    with pytest.raises(RewardRevisionPending):
        await h.owner(1).review(prefix=h.prefix, control=h.control(505), history=h.history)
    with h.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind LIKE 'reward_revision_endpoint%'")
    with caplog.at_level("INFO"):
        await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert len(h.captured) == len(set(h.captured)) == 6
    assert "reward_revision_metadata_repair" in caplog.text


async def test_audit_target_is_frozen_across_restart_and_head_growth(revision_case):
    h = revision_case
    with pytest.raises(RewardRevisionPending, match="drain"):
        await h.owner().target(h.suspension.decision, h.control(503))
    assert await h.owner().target(h.suspension.decision, h.control(505)) == 505
    assert await h.owner().target(h.suspension.decision, h.control(900)) == 505
    with h.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='reward_revision_target'")
    assert await h.owner().target(h.suspension.decision, h.control(900)) == 505


async def test_damaged_revision_ledger_is_not_reinitialized(revision_case):
    h = revision_case
    await h.owner().target(h.suspension.decision, h.control(505))
    with h.journal.transaction() as db:
        db.execute("DROP TABLE reward_revision_completion")
    with pytest.raises(ValueError, match="metadata repair"):
        h.owner()


async def test_interrupted_index_publication_restores_completed_native_endpoint(
    revision_case,
    monkeypatch,
):
    h = revision_case
    owner = h.owner()

    def fail(_):
        raise OSError("interrupted revision index publication")

    monkeypatch.setattr(owner.journal, "put_many", fail)
    with pytest.raises(OSError, match="interrupted"):
        await owner.review(prefix=h.prefix, control=h.control(505), history=h.history)
    await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    assert len(h.captured) == len(set(h.captured)) == 6
    assert len(h.replayed) == 1


async def test_clearance_rechecks_exact_native_first_and_last_boundaries(
    revision_case, series_case
):
    h, c = revision_case, series_case
    complete = await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    _, selection = adoption_case(c)
    proposal = transition(
        c,
        h.prefix,
        "revise_activation",
        revised(h.old, selection.adoptions[0]),
        clearance=digest(complete.clearance),
        observed=505,
    ).decision
    series = h.coverage.preparation.reader.series
    assert (
        validate_revision_clearance(
            complete,
            decision=proposal,
            prefix=h.prefix,
            series=series,
            history=h.history,
        )
        == complete.clearance
    )
    changed = SimpleNamespace(
        writes=(
            SimpleNamespace(decision_sha256=digest(h.prefix[1].decision), block_number=501),
            h.history.writes[1],
        )
    )
    with pytest.raises(ValueError, match="fenced selection"):
        validate_revision_clearance(
            complete,
            decision=proposal,
            prefix=h.prefix,
            series=series,
            history=changed,
        )
    assert min(block for _, block in h.captured) == 503
    assert max(block for _, block in h.captured) == 505
    assert set(hotkey for hotkey, block in h.captured if block == 503) == set(series.validators)


async def test_repeated_revision_reuses_original_endpoints_and_selects_historical_source(
    revision_case,
    series_case,
):
    h, c = revision_case, series_case
    await h.owner().review(prefix=h.prefix, control=h.control(505), history=h.history)
    first_captured = set(h.captured)
    _, selected = adoption_case(c)
    active = revised(h.old, selected.adoptions[0])
    revision = transition(
        c, h.prefix, "revise_activation", active, clearance="c1" * 32, observed=505
    )
    prefix = (*h.prefix, revision)
    h.suspension = transition(c, prefix, "suspend_activation", active, observed=510)
    h.suspension_block = 511
    h.prefix = (*prefix, h.suspension)
    h.history = SimpleNamespace(
        writes=(
            *h.history.writes,
            SimpleNamespace(decision_sha256=digest(revision.decision), block_number=506),
            SimpleNamespace(decision_sha256=digest(h.suspension.decision), block_number=511),
        )
    )
    complete = await h.owner().review(prefix=h.prefix, control=h.control(514), history=h.history)
    assert complete.clearance.reviewed_endpoints == 24
    assert len(h.captured) == len(set(h.captured)) == 24
    assert first_captured <= set(h.captured)
    assert h.source_activations[-2:] == [h.old, active]
    points = [v.point for v in h.items.values()]
    assert {p.activation_sha256 for p in points if p.block < 509} == {digest(h.old)}
    assert {p.activation_sha256 for p in points if p.block >= 509} == {digest(active)}
