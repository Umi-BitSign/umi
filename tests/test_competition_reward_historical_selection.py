"""Past selection through native history/proof consumers with synthetic chain ports."""

from dataclasses import replace

import pytest

from umi.competition_reward_decisions import (
    HistoricalStandingRewardSelection,
    StandingRewardControlReader,
)
from umi.open_competition import digest

from .test_competition_reward_history_selection import base_policy as base_policy
from .test_competition_reward_history_selection import base_series_case as base_series_case
from .test_competition_reward_history_selection import chain as chain
from .test_competition_reward_history_selection import chain_config as chain_config
from .test_competition_reward_history_selection import control as control
from .test_competition_reward_history_selection import current
from .test_competition_reward_history_selection import handoff_case as handoff_case
from .test_competition_reward_history_selection import historical as historical
from .test_competition_reward_history_selection import history_case as history_case
from .test_competition_reward_history_selection import policy as policy
from .test_competition_reward_history_selection import series_case as series_case

pytestmark = pytest.mark.parametrize("historical", ["exact_runtime"], indirect=True)


async def captured(h, height):
    history = (await h.reader.advance(h.item.provider, through_block=height)).history
    return history, h.reader._tip.slot


def highwater(reader):
    with reader.journal.transaction() as db:
        return db.execute("SELECT block FROM highwater").fetchall()


@pytest.mark.parametrize("series_case", ["handoff"], indirect=True)
@pytest.mark.parametrize("offset", [0, 1, 2, 3, 4, 5, 6])
async def test_past_selection_after_newer_checkpoint_and_offline_restart(handoff_case, offset):
    h, c = handoff_case, handoff_case.c
    height = h.old.height + offset
    past, observation = await captured(h, height)
    latest, _ = await captured(h, h.end)
    c.reader.select_history(await current(h, latest.tip), c.source, latest)
    assert highwater(c.reader) == [(h.end,)]
    before = c.reader.journal.path.read_bytes()
    result = c.reader.review_history(observation, c.source, past)
    assert type(result) is HistoricalStandingRewardSelection
    assert c.reader.journal.path.read_bytes() == before
    assert highwater(c.reader) == [(h.end,)]
    tip = c.genesis if offset == 0 else c.active if offset < 3 else c.successor
    assert result.selection.decision_sha256 == digest(tip.decision)
    effective = c.active if 3 <= offset < 5 else c.successor if offset >= 5 else None
    if effective is None:
        assert result.effective_selection is None
    else:
        assert result.effective_selection.decision_sha256 == digest(effective.decision)
    assert not result.chain_submission_authorized

    # A process restart replays retained native block evidence, with no old
    # block/state RPC or coordinator decision source. No freshness clock is reset.
    c.reader, h.reader = c.reopen(), await h.restart()
    h.offline_through = h.end
    c.objects.clear()
    h.item.clock.now += 30 * 86400 * 1000
    replay = (await h.reader.advance(h.item.provider, through_block=height)).history
    recovered = await h.item.provider.review_control(observation.evidence, observation.metadata)
    again = c.reader.review_history(recovered, c.source, replay)
    assert again.selection == result.selection
    assert again.effective_selection == result.effective_selection
    assert highwater(c.reader) == [(h.end,)]
    assert h.body_requests == list(range(h.old.height, h.end + 1))
    with pytest.raises(ValueError, match="current proof adapter"):
        c.reader.select_history(recovered, c.source, replay)
    assert highwater(c.reader) == [(h.end,)]


@pytest.mark.parametrize("series_case", ["revoke", "same_block"], indirect=True)
async def test_past_revocation_is_effective_without_current_authority(history_case):
    h = history_case
    history, observation = await captured(h, h.end)
    result = h.c.reader.review_history(observation, h.c.source, history)
    assert result.selection.state == "revoked"
    assert result.effective_selection is None
    assert highwater(h.c.reader) == []


@pytest.mark.parametrize("series_case", ["handoff_revoke"], indirect=True)
async def test_later_revocation_does_not_erase_provable_earlier_selection(handoff_case):
    h, c = handoff_case, handoff_case.c
    earlier, observation = await captured(h, h.old.height + 3)
    latest, _ = await captured(h, h.end)
    current_result = c.reader.select_history(await current(h, latest.tip), c.source, latest)
    assert current_result.selection.state == "revoked"
    result = c.reader.review_history(observation, c.source, earlier)
    assert result.effective_selection.activation == c.active.decision.activation
    assert not result.chain_submission_authorized
    assert highwater(c.reader) == [(h.end,)]


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
async def test_historical_review_rejects_hidden_writes_before_retaining_history(history_case):
    h = history_case
    history, observation = await captured(h, h.end)
    with pytest.raises(ValueError):
        h.c.reader.review_history(observation, h.c.source, history)
    assert h.c.reader.journal.keys("reward_control_decision") == []
    assert highwater(h.c.reader) == []


@pytest.mark.parametrize("mutation", ["start", "tip", "writes", "issuer", "control"])
async def test_historical_provenance_and_complete_interval_are_required(history_case, mutation):
    h = history_case
    history, observation = await captured(h, h.end)
    if mutation == "control":
        observation = replace(observation, _issuer=None)
    else:
        changes = {
            "start": {"first_block": history.first_block + 1},
            "tip": {"tip": replace(history.tip, state_root="0x" + "ee" * 32)},
            "writes": {"writes": history.writes[1:]},
            "issuer": {"_issuer": None},
        }
        history = replace(history, **changes[mutation])
    with pytest.raises(ValueError):
        h.c.reader.review_history(observation, h.c.source, history)
    assert h.c.reader.journal.keys("reward_control_decision") == []
    assert highwater(h.c.reader) == []


async def test_historical_replay_uses_independently_selected_original_configuration(history_case):
    h, c = history_case, history_case.c
    history, observation = await captured(h, h.end)
    reader = StandingRewardControlReader(
        c.reader.journal.root,
        c.series,
        c.control.policy,
        expected_series_sha256=digest(c.series),
        expected_chain_config_sha256="ee" * 32,
        expected_admission_chain_config_sha256=digest(c.control.config),
        maximum_bytes=8 * 1024**2,
    )
    result = reader.review_history(observation, c.source, history)
    assert result.selection.activation == c.active.decision.activation
    assert highwater(reader) == []
    reader.admission_chain_config_sha256 = "dd" * 32
    with pytest.raises(ValueError, match="selected owned proof"):
        reader.review_history(observation, c.source, history)


async def test_current_observation_does_not_impersonate_archived_provenance(history_case):
    h = history_case
    history, _ = await captured(h, h.end)
    with pytest.raises(ValueError, match="selected owned proof"):
        h.c.reader.review_history(await current(h, history.tip), h.c.source, history)
    assert highwater(h.c.reader) == []


async def test_conflicting_retained_signed_prefix_is_not_overwritten(history_case):
    h, c = history_case, history_case.c
    history, observation = await captured(h, h.end)
    other = c.decision(c.genesis, 5, observed=h.old.height + 2)
    c.reader.journal.put_many(
        (
            ("reward_control_decision", "0000", c.genesis),
            ("reward_control_decision", "0001", other),
        )
    )
    before = c.reader.journal.path.read_bytes()
    with pytest.raises(ValueError, match="conflicts with retained history"):
        c.reader.review_history(observation, c.source, history)
    assert c.reader.journal.path.read_bytes() == before
    assert highwater(c.reader) == []


async def test_lost_historical_retention_acknowledgement_retries_without_highwater(
    history_case,
    monkeypatch,
):
    h, c = history_case, history_case.c
    history, observation = await captured(h, h.end)
    original = c.reader.journal.put_many

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("lost acknowledgement")

    monkeypatch.setattr(c.reader.journal, "put_many", interrupted)
    with pytest.raises(OSError):
        c.reader.review_history(observation, c.source, history)
    c.reader = c.reopen()
    c.objects.clear()
    result = c.reader.review_history(observation, c.source, history)
    assert result.selection.activation == c.active.decision.activation
    assert highwater(c.reader) == []
