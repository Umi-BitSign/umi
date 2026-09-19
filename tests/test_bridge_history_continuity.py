"""Both history consumers preserve ordering across resolved attempts and pages."""

from dataclasses import replace

import pytest

from tests.test_bridge_signing import case as case
from tests.test_bridge_transactions import advance, prepare
from tests.test_bridge_transactions import tx as tx
from tests.test_competition_bridge_recovery import add_attempt
from tests.test_competition_bridge_recovery import completed as completed
from tests.test_competition_bridge_transactions import files_at, finish
from tests.test_competition_upgrade import write
from tests.test_registration_bridge import BLOCK, NOW, observation, replace_participant
from tests.test_registration_bridge import signed_policy as signed_policy
from umi.bridge.policy import RegistrationBridgeError
from umi.bridge.state import RegistrationBridgeState
from umi.competition_bridge_recovery import HISTORY, audit_bridge_history
from umi.protocol import canonical_json_bytes


@pytest.mark.parametrize("reader", ["running", "stopped"])
@pytest.mark.parametrize("mutation", ["none", "last_update", "overlap"])
def test_history_consumers_agree_on_cross_attempt_continuity(
    tmp_path, completed, signed_policy, reader, mutation
):
    files = dict(completed.files)
    if mutation == "last_update":
        obs = replace_participant(
            observation(block_number=BLOCK + 500), 54, last_update=BLOCK + 499
        )
        add_attempt(files, signed_policy, obs)
    elif mutation == "overlap":
        first = completed.first.model_copy(
            update={"last_observed_block": completed.current.attempt.preflight_block + 1}
        )
        files[f"{HISTORY}/{first.attempt.attempt_id}-applied.json"] = canonical_json_bytes(first)
    root = tmp_path.resolve() / "state"
    for name, raw in files.items():
        write(root / name, raw, 0o600)

    def audit():
        if reader == "stopped":
            return audit_bridge_history(files, hotkey=completed.current.validator_hotkey)
        with RegistrationBridgeState(root) as state:
            return state.initialize(observation(block_number=BLOCK + 1000), now=NOW)

    if mutation == "none":
        audit()
    else:
        reason = {
            "running": {
                "last_update": "history_lastupdate_gap",
                "overlap": "history_preflight_predates_observation",
            },
            "stopped": {"last_update": "LastUpdate gap", "overlap": "preflight predates"},
        }[reader][mutation]
        with pytest.raises((ValueError, RegistrationBridgeError), match=reason):
            audit()
    assert files_at(root) == files


@pytest.mark.parametrize("split", [0, 1, 2])
def test_paged_history_has_the_same_boundary_as_one_pass(completed, split):
    from umi.bridge.journal_history import HistoryContinuity, audit_history_sequence

    records = (completed.first, completed.current)
    whole = audit_history_sequence(iter(records))
    partial = audit_history_sequence(iter(records[:split]))
    assert audit_history_sequence(iter(records[split:]), after=partial) == whole
    assert whole == HistoryContinuity.following(completed.current)
    assert whole.last_update == completed.current.weight_call.block_number


@pytest.mark.parametrize("field", ["preflight_block", "last_update", "observed_block"])
def test_each_boundary_constraint_is_checked_on_the_next_page(completed, field):
    from umi.bridge.journal_history import HistoryContinuity, audit_history_sequence

    boundary = HistoryContinuity.following(completed.first)
    invalid = {
        "preflight_block": completed.current.attempt.preflight_block,
        "last_update": completed.first.weight_call.block_number + 1,
        "observed_block": completed.current.attempt.preflight_block + 1,
    }
    with pytest.raises(RegistrationBridgeError):
        audit_history_sequence(
            (completed.current,), after=replace(boundary, **{field: invalid[field]})
        )


@pytest.mark.parametrize("phase", ["applied", "failed", "expired_nonce_available"])
@pytest.mark.parametrize("gap", [False, True])
async def test_writer_checks_continuity_before_publishing_next_intent(tmp_path, tx, phase, gap):
    root = tmp_path.resolve() / "writer"
    with RegistrationBridgeState(root) as state:
        previous = await finish(state, tx, phase)
        proven = await advance(tx.case, 250, nonce=7 if phase == "expired_nonce_available" else 8)
        expected_update = (
            previous.weight_call.block_number
            if previous.weight_call is not None
            else previous.attempt.prior_last_update
        )
        tx.case.obs = replace_participant(tx.case.obs, 54, last_update=expected_update + int(gap))
        current = prepare(tx.policy, tx.case, proven, previous)
        before = files_at(root)
        if gap:
            with pytest.raises(RegistrationBridgeError, match="history_lastupdate_gap"):
                state.store(current, archive=True)
            assert files_at(root) == before
            state.require_unchanged()
        else:
            from umi.bridge.journal_history import audit_history_sequence

            state.store(current, archive=True)
            expected = audit_history_sequence((previous, current))
            assert expected == audit_history_sequence(
                (current,), after=audit_history_sequence((previous,))
            )
            assert expected.last_update == expected_update
    if not gap:
        with RegistrationBridgeState(root) as state:
            assert state.initialize(tx.case.obs, now=tx.case.now) == current
