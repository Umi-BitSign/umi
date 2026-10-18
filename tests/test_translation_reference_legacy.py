"""Original bridge phase semantics survive the candidate automatic handoff."""

from datetime import timedelta

import pytest

from tests.test_competition_bridge_recovery import add_attempt
from tests.test_registration_bridge import BLOCK, observation, replace_participant, signed_policy
from tests.test_translation_reference_state import read, reference_case, signing_case
from umi.competition_bridge_recovery import JOURNAL
from umi.protocol import canonical_json_bytes
from umi.translation_reference_legacy import inspect_translation_legacy
from umi.translation_reference_state import TranslationReferenceError

__all__ = ["reference_case", "signed_policy", "signing_case"]


@pytest.fixture
def legacy_case(reference_case, signed_policy):
    case = reference_case
    case.files = {"service.lock": b""}
    participants = [
        p.model_copy(update={"last_update": BLOCK - 1000, "registered_at_block": BLOCK - 1000})
        for p in observation().participants
    ]
    first = add_attempt(
        case.files, signed_policy, observation(block_number=BLOCK - 600, participants=participants)
    )
    second_obs = replace_participant(
        observation(
            block_number=BLOCK - 300,
            validator_row=first.attempt.expected_row,
            participants=participants,
        ),
        54,
        last_update=first.weight_call.block_number,
    )
    case.terminal = add_attempt(case.files, signed_policy, second_obs)
    case.updates[54] = case.terminal.weight_call.block_number
    case.set_value("LastUpdate", case.updates)
    case.set_value("Weights", case.terminal.attempt.expected_row, 78, 54)
    return case


@pytest.mark.asyncio
async def test_complete_historical_bridge_keeps_exact_bytes_and_current_native_binding(legacy_case):
    case = legacy_case
    before = case.files.copy()
    state = await read(case)
    result = inspect_translation_legacy(case.files, state, case.policy, now=case.now)
    assert result.terminal_attempts == 2
    assert result.last_weight_update == case.updates[54]
    assert not result.chain_submission_authorized
    assert case.files == before


@pytest.mark.asyncio
async def test_row_equality_cannot_clear_an_old_unknown_submission(legacy_case):
    case = legacy_case
    unknown = case.terminal.model_copy(update={"phase": "outcome_unknown", "weight_call": None})
    identity = unknown.attempt.attempt_id
    case.files = {
        name: raw
        for name, raw in case.files.items()
        if identity not in name or name.endswith("-submitting.json")
    }
    case.files[JOURNAL] = canonical_json_bytes(unknown)
    case.files[f"registration-bridge-history/{identity}-outcome_unknown.json"] = (
        canonical_json_bytes(unknown)
    )
    state = await read(case)
    with pytest.raises(TranslationReferenceError, match="native_recovery_required"):
        inspect_translation_legacy(case.files, state, case.policy, now=case.now)


@pytest.mark.asyncio
@pytest.mark.parametrize("change", ["unclassified", "row", "update", "missing_current"])
async def test_unknown_layout_or_changed_native_owner_state_holds(legacy_case, change):
    case = legacy_case
    if change == "unclassified":
        case.files["bootstrap-transactions/orphan/journal.json"] = b"{}"
    elif change == "row":
        case.set_value("Weights", case.row, 78, 54)
    elif change == "update":
        case.updates[54] += 1
        case.set_value("LastUpdate", case.updates)
    else:
        del case.files[JOURNAL]
    state = await read(case)
    with pytest.raises(TranslationReferenceError):
        inspect_translation_legacy(case.files, state, case.policy, now=case.now)


@pytest.mark.asyncio
async def test_old_gate_is_not_reused_after_freshness_expires(legacy_case):
    case = legacy_case
    state = await read(case)
    with pytest.raises(TranslationReferenceError, match="snapshot_stale"):
        inspect_translation_legacy(
            case.files, state, case.policy, now=case.now + timedelta(seconds=121)
        )
