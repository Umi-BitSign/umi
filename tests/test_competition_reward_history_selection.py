"""Signed selection over native history/current readers with synthetic chain ports."""

import hashlib
import json
from dataclasses import replace

import pytest

from umi.competition_reward_control import FinalizedRewardControlProvider
from umi.competition_reward_decisions import (
    StandingRewardControlReader,
    StandingRewardSeries,
)
from umi.competition_reward_history import RewardControlHistoryReader
from umi.finalized_ancestry import encode_rpc_header
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from . import test_competition_reward_decisions as decision_tests
from . import test_open_competition as competition_tests
from .test_competition_chain import _HEIGHT
from .test_competition_reward_decisions import signatures, signed
from .test_competition_reward_history import chain as chain
from .test_competition_reward_history import chain_config as chain_config
from .test_competition_reward_history import control as control
from .test_competition_reward_history import historical as historical
from .test_competition_reward_history import history_case as history_case
from .test_competition_reward_history import make_history_case

base_series_case = decision_tests.series_case
base_policy = competition_tests.policy

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


@pytest.fixture
def policy(base_policy):
    return base_policy.model_copy(update={"valid_through_block": _HEIGHT + 2})


@pytest.fixture
def series_case(base_series_case, request, tmp_path):
    c = base_series_case
    mode = getattr(request, "param", "normal")
    policy = c.control.policy
    plans = tuple(p.model_copy(update={"policy_sha256": digest(policy)}) for p in c.series.cohorts)
    authority = c.series.recovery.authority.model_copy(
        update={
            "policy_sha256": digest(policy),
            "cohort_sha256s": tuple(sorted(digest(p) for p in plans)),
            "issued_at_block": _HEIGHT,
        }
    )
    recovery = c.series.recovery.model_copy(
        update={"authority": authority, "signatures": signatures(authority)}
    )
    c.series = StandingRewardSeries.model_validate_json(
        canonical_json_bytes(
            c.series.model_copy(
                update={"policy_sha256": digest(policy), "cohorts": plans, "recovery": recovery}
            )
        )
    )
    c.control.policy = c.control.finality.policy = policy
    if mode.startswith("handoff"):
        # Small fixture fences exercise exact boundaries without prescribing
        # production timing or simulating a certified minimum opportunity.
        c.series = c.series.model_copy(
            update={"maximum_proof_lag_blocks": 1, "maximum_transaction_lifetime_blocks": 1}
        )
    old_decision = c.decision

    def decision(parent=None, cohort=None, *, observed=_HEIGHT, **changes):
        raw = old_decision(parent, cohort, observed=observed, **changes).decision
        body = raw.model_copy(
            update={
                "series_sha256": digest(c.series),
                "activation": None
                if raw.activation is None
                else raw.activation.model_copy(update={"cohort_sha256": digest(plans[cohort - 5])}),
            }
        )
        result = signed(body)
        c.objects[digest(body)] = canonical_json_bytes(result)
        return result

    def reopen():
        return StandingRewardControlReader(
            tmp_path / "complete-reader",
            c.series,
            policy,
            expected_series_sha256=digest(c.series),
            expected_chain_config_sha256=digest(c.control.config),
            maximum_bytes=8 * 1024**2,
        )

    c.decision, c.reopen = decision, reopen
    c.genesis = decision()
    c.active = decision(c.genesis, 5, observed=_HEIGHT + 1)
    revoke = decision(c.active, kind="revoke", observed=_HEIGHT + 2)
    a, g, r = (digest(x.decision) for x in (c.active, c.genesis, revoke))
    cases = {
        "normal": [(g,), (a,), (), (), (a,)],
        "cleared": [(g,), (a,), (), (), (a,)],
        "revoke": [(g,), (a,), (r,), (), ()],
        "overwritten_revoke": [(g,), (a,), (r, a), (), ()],
        "rollback": [(g,), (a,), (g, a), (), ()],
        "unknown_write": [(g,), (a,), ("dd" * 32, a), (), ()],
        "missing_genesis": [(), (a,), (), (), ()],
        "late_genesis": [(), (), (), (g,), (a,)],
        "backdated": [(g, a), (), (), (), ()],
        "same_block": [
            (g,),
            (a, digest(decision(c.active, kind="revoke", observed=_HEIGHT + 1).decision)),
            (),
            (),
            (),
        ],
        "same_block_admission": [(g, digest(decision(c.genesis, 5).decision)), (), (), (), ()],
        "repeat_genesis": [(g,), (), (), (), (g,)],
        "empty_before_admission": [(), (g,), (a,), (), ()],
        "uncommitted_parent": [
            (g,),
            (a,),
            (
                digest(
                    decision(
                        decision(c.active, 6, observed=_HEIGHT + 2), 7, observed=_HEIGHT + 2
                    ).decision
                ),
            ),
            (),
            (),
        ],
    }
    if mode.startswith("handoff"):
        c.successor = decision(c.active, 6, observed=_HEIGHT + 3)
        if mode == "handoff_same_allocation":
            c.successor = signed(
                c.successor.decision.model_copy(
                    update={
                        "activation": c.successor.decision.activation.model_copy(
                            update={
                                "allocation_sha256": c.active.decision.activation.allocation_sha256
                            }
                        )
                    }
                )
            )
            c.objects[digest(c.successor.decision)] = canonical_json_bytes(c.successor)
        b = digest(c.successor.decision)
        writes = [(g,), (a,), (), (b,), (), (b,), ()]
        if mode == "handoff_revoke":
            revocation = decision(c.successor, kind="revoke", observed=_HEIGHT + 4)
            writes[4:] = [(digest(revocation.decision),), (), ()]
        if mode == "handoff_unknown_write":
            writes[3] = ("dd" * 32, b)
        cases[mode] = writes
    c.control_writes = {_HEIGHT + i: writes for i, writes in enumerate(cases[mode])}
    c.cleared_blocks = {_HEIGHT + 3} if getattr(request, "param", None) == "cleared" else set()
    c.reader = reopen()
    return c


@pytest.fixture
async def handoff_case(historical, monkeypatch, tmp_path):
    return await make_history_case(historical, monkeypatch, tmp_path, distance=7)


async def current(h, tip, *, validator_hotkey=None, eligibility_profile=None):
    """Collect through the real current-control adapter at the history's tip."""
    item, w = h.item, h.source.w
    header = w.headers[tip.block_hash]
    stamp = w.original.timestamp_ms + (tip.block_number - h.old.height) * 12000
    evidence = canonical_json_bytes(
        {
            **json.loads(w.head.finality_evidence),
            "block": {"scale_header": encode_rpc_header(header)},
        }
    )
    h.blocks[tip.block_number] = replace(
        w.head,
        height=tip.block_number,
        block_hash=tip.block_hash,
        state_root=tip.state_root,
        timestamp_ms=stamp,
        finality_evidence=evidence,
        finality_evidence_sha256=hashlib.sha256(evidence).hexdigest(),
    )
    previous = (item.finality.ref, item.finality.timestamp, item.clock.now)
    item.finality.ref = tip
    item.finality.timestamp = stamp
    item.clock.now = stamp + 1000
    await item.provider.aclose()
    provider = FinalizedRewardControlProvider(
        item.config,
        item.policy,
        finality=item.finality,
        proofs=item.proofs,
        now_ms=lambda: item.clock.now,
    )
    try:
        control = await provider.collect_control(item.hotkey)
        if validator_hotkey is None:
            return control
        weights = await provider.collect_registered_weights(validator_hotkey, at=control.snapshot)
        if eligibility_profile is not None:
            from umi.competition_reward_eligibility import collect_reward_eligibility

            return control, await collect_reward_eligibility(
                provider,
                weights,
                eligibility_profile,
                expected_runtime_profile_sha256=digest(eligibility_profile),
            )
        return control, weights
    finally:
        await provider.aclose()
        item.finality.ref, item.finality.timestamp, item.clock.now = previous


async def test_restart_replays_every_write_and_duplicate_does_not_reset_activation(history_case):
    h, c = history_case, history_case.c
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    value = c.reader.select_history(await current(h, history.tip), c.source, history)
    assert value.selection.state == "draining"
    assert value.effective_selection is None
    assert value.selection.committed_at_block == h.old.height + 1
    assert value.selection.effective_at_block == h.old.height + 161
    assert not value.chain_submission_authorized and not value.selection.chain_submission_authorized
    c.reader, h.reader = c.reopen(), await h.restart()
    h.offline_through = h.end - 1
    replay = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    c.objects.clear()
    again = c.reader.select_history(await current(h, replay.tip), c.source, replay)
    assert again.selection == value.selection
    assert h.body_requests == list(range(h.old.height, h.end + 1))


@pytest.mark.parametrize("series_case", ["revoke", "same_block"], indirect=True)
async def test_native_history_selects_revocation(history_case):
    h = history_case
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    result = h.c.reader.select_history(await current(h, history.tip), h.c.source, history)
    assert result.selection.state == "revoked" and result.selection.activation is None
    assert result.effective_selection is None


@pytest.mark.parametrize("series_case", ["handoff"], indirect=True)
@pytest.mark.parametrize("offset", [1, 2, 3, 4, 5, 6])
async def test_effective_allocation_crosses_each_fence_and_recovers_offline(handoff_case, offset):
    h, c = handoff_case, handoff_case.c
    height = h.old.height + offset
    history = (await h.reader.advance(h.item.provider, through_block=height)).history
    result = c.reader.select_history(await current(h, history.tip), c.source, history)
    tip = c.active if offset < 3 else c.successor
    assert result.selection.decision_sha256 == digest(tip.decision)
    assert result.selection.activation == tip.decision.activation
    effective = c.active if 3 <= offset < 5 else c.successor if offset >= 5 else None
    if effective is None:
        assert result.effective_selection is None
    else:
        assert result.effective_selection.decision_sha256 == digest(effective.decision)
        assert result.effective_selection.activation == effective.decision.activation
        assert result.effective_selection.state == "selected"
        assert result.effective_selection.effective_at_block == h.old.height + (
            3 if effective is c.active else 5
        )
        assert not result.effective_selection.chain_submission_authorized
    assert result.selection.state == ("selected" if offset >= 5 else "draining")
    assert not result.chain_submission_authorized

    # Reconstruct from retained native block proofs and signed decisions. The
    # duplicate at +5 cannot move the successor fence from +5 to +7.
    c.reader, h.reader = c.reopen(), await h.restart()
    h.offline_through = height - 1
    c.objects.clear()
    replay = (await h.reader.advance(h.item.provider, through_block=height)).history
    recovered = c.reader.select_history(await current(h, replay.tip), c.source, replay)
    assert recovered == result
    assert h.body_requests == list(range(h.old.height, height + 1))


@pytest.mark.parametrize("series_case", ["handoff_same_allocation"], indirect=True)
@pytest.mark.parametrize("offset", [4, 5])
async def test_same_reward_amounts_do_not_merge_cohort_activation_identity(handoff_case, offset):
    h, c = handoff_case, handoff_case.c
    history = (await h.reader.advance(h.item.provider, through_block=h.old.height + offset)).history
    result = c.reader.select_history(await current(h, history.tip), c.source, history)
    old, new = c.active.decision.activation, c.successor.decision.activation
    assert old.allocation_sha256 == new.allocation_sha256
    assert digest(old) != digest(new)
    assert result.selection.activation == new
    assert result.effective_selection.activation == (old if offset == 4 else new)


@pytest.mark.parametrize("series_case", ["handoff_revoke"], indirect=True)
@pytest.mark.parametrize("offset", [4, 6])
async def test_revocation_removes_preceding_allocation_during_and_after_drain(handoff_case, offset):
    h, c = handoff_case, handoff_case.c
    history = (await h.reader.advance(h.item.provider, through_block=h.old.height + offset)).history
    result = c.reader.select_history(await current(h, history.tip), c.source, history)
    assert result.selection.state == "revoked"
    assert result.effective_selection is None


@pytest.mark.parametrize("series_case", ["handoff_unknown_write"], indirect=True)
async def test_unknown_intervening_write_cannot_fall_back_to_preceding_allocation(handoff_case):
    h, c = handoff_case, handoff_case.c
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    with pytest.raises(ValueError, match="changed, skipped or backdated"):
        c.reader.select_history(await current(h, history.tip), c.source, history)
    assert c.reader.journal.keys("reward_control_decision") == []


@pytest.mark.parametrize(
    "series_case",
    [
        "overwritten_revoke",
        "rollback",
        "unknown_write",
        "missing_genesis",
        "late_genesis",
        "backdated",
        "uncommitted_parent",
        "cleared",
    ],
    indirect=True,
)
async def test_cold_reader_rejects_hidden_or_uncommitted_history_before_retention(history_case):
    h = history_case
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    with pytest.raises(ValueError):
        h.c.reader.select_history(await current(h, history.tip), h.c.source, history)
    assert h.c.reader.journal.keys("reward_control_decision") == []


@pytest.mark.parametrize("series_case", ["same_block_admission", "repeat_genesis"], indirect=True)
async def test_timely_genesis_is_proven_even_when_the_slot_no_longer_records_it(history_case):
    h = history_case
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    result = h.c.reader.select_history(await current(h, history.tip), h.c.source, history)
    assert result.selection.committed_at_block == h.old.height
    assert not result.chain_submission_authorized


@pytest.mark.parametrize("series_case", ["empty_before_admission"], indirect=True)
async def test_complete_empty_blocks_before_genesis_do_not_require_renewal(history_case):
    h = history_case
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    result = h.c.reader.select_history(await current(h, history.tip), h.c.source, history)
    assert result.selection.committed_at_block == h.old.height + 2


async def test_authentic_but_shorter_native_history_cannot_choose_its_own_start(
    history_case, tmp_path
):
    h = history_case
    partial = RewardControlHistoryReader(
        tmp_path / "later-history",
        control_hotkey=h.item.hotkey,
        chain_config_sha256=digest(h.item.config),
        first_block=h.old.height + 1,
    )
    history = (await partial.advance(h.item.provider, through_block=h.end)).history
    with pytest.raises(ValueError, match="native interval"):
        h.c.reader.select_history(await current(h, history.tip), h.c.source, history)
    assert h.c.reader.journal.keys("reward_control_decision") == []


@pytest.mark.parametrize("mutation", ["first", "tip", "writes", "issuer"])
async def test_history_cannot_skip_earlier_blocks_or_replace_native_provenance(
    history_case, mutation
):
    h = history_case
    history = (await h.reader.advance(h.item.provider, through_block=h.end)).history
    changes = {
        "first": {"first_block": history.first_block + 1},
        "tip": {"tip": replace(history.tip, block_number=history.tip.block_number - 1)},
        "writes": {"writes": history.writes[1:]},
        "issuer": {"_issuer": None},
    }
    with pytest.raises(ValueError, match="native interval"):
        h.c.reader.select_history(
            await current(h, history.tip), h.c.source, replace(history, **changes[mutation])
        )
    assert h.c.reader.journal.keys("reward_control_decision") == []
