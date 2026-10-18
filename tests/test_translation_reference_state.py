"""Synthetic native ports exercise real proof collection and runtime decoding.

No production policy, wallet, chain transaction or external adoption is involved.
"""

import json
from dataclasses import replace
from datetime import timedelta

import pytest

from tests.test_bridge_signing import case as signing_case  # noqa: F401
from tests.test_registration_bridge import BLOCK, hotkey
from tests.test_translation_reference_policy import case as policy_case
from umi.protocol import canonical_json_bytes
from umi.translation_reference_state import (
    TranslationReferenceError,
    TranslationReferenceStateReader,
)


@pytest.fixture
def reference_case(signing_case, monkeypatch):  # noqa: F811
    case = signing_case
    _, _, signed = policy_case()
    case.policy = signed.policy.model_copy(
        update={
            "reference_hotkey": hotkey(200),
            "minimum_reference_update_block": BLOCK - 1000,
        }
    )
    import umi.runtime_metadata as metadata

    original = metadata.bittensor_core.Runtime

    class Codec(original):
        def storage_key(self, pallet, name, params):
            if pallet == "SubtensorModule":
                return canonical_json_bytes([pallet, name, list(params)])
            return super().storage_key(pallet, name, params)

        def storage_entry(self, pallet, name):
            if pallet == "SubtensorModule":
                from types import SimpleNamespace

                return SimpleNamespace(modifier="Optional", default_bytes=b"", value_type=name)
            return super().storage_entry(pallet, name)

    monkeypatch.setattr(metadata.bittensor_core, "Runtime", Codec)

    def set_value(name, value, *params):
        case.values[canonical_json_bytes(["SubtensorModule", name, list(params or (78,))])] = (
            json.dumps(value).encode()
        )

    case.set_value = set_value
    case.row = [[uid, 65535 if uid == 104 else 0] for uid in range(256)]
    case.permits = [uid in (54, 200) for uid in range(256)]
    case.active = case.permits.copy()
    case.updates = [BLOCK - 500] * 256
    case.updates[200] = BLOCK - 20
    values = {
        "NetworksAdded": True,
        "SubnetworkN": 256,
        "ValidatorPermit": case.permits,
        "Active": case.active,
        "LastUpdate": case.updates,
        "Tempo": 360,
        "ActivityCutoffFactorMilli": 1000,
        "LastEpochBlock": BLOCK - 30,
        "MechanismCountCurrent": 1,
        "CommitRevealWeightsEnabled": False,
        "WeightsVersionKey": 4_294_967_296,
        "MinAllowedWeights": 256,
        "MaxAllowedUids": 256,
        "MaxWeightsLimit": 65535,
        "WeightsSetRateLimit": 100,
    }
    for name, value in values.items():
        set_value(name, value)
    for uid in (54, 200):
        set_value("Uids", uid, 78, hotkey(uid))
        set_value("Keys", hotkey(uid), 78, uid)
        set_value("Weights", case.row, 78, uid)
    case.reader = TranslationReferenceStateReader(
        finality=case.finality,
        rpc=case.rpc,
        verifier=case.verifier,
        runtime_executor=case.executor,
        clock=lambda: case.now,
    )
    return case


async def read(case):
    return await case.reader.read(case.obs.validator_hotkey, case.policy)


@pytest.mark.asyncio
async def test_proves_exact_reference_and_own_state_at_one_owned_root(reference_case):
    case = reference_case
    state = await read(case)
    decision = state.decision(case.policy, now=case.now)
    assert decision.action == "submit" and decision.writer_uid == 54
    assert decision.reference_uid == 200 and decision.reference_last_update == BLOCK - 20
    assert decision.row == tuple(map(tuple, case.row))
    assert state.signing.nonce == 7
    assert case.heads == 3 and len(case.proofs) == 4
    assert not any(
        method in {"state_getMetadata", "author_submitExtrinsic"} for method, _ in case.calls
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("age,passes", [(359, True), (360, False), (361, False)])
async def test_uses_epoch_cutoff_instead_of_legacy_5000_block_clock(reference_case, age, passes):
    case = reference_case
    case.updates[200] = BLOCK - age
    case.set_value("LastUpdate", case.updates)
    if passes:
        assert (await read(case)).decision(
            case.policy, now=case.now
        ).reference_last_update == BLOCK - age
    else:
        with pytest.raises(TranslationReferenceError, match="reference_update_stale"):
            await read(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "name,uid", [("Active", 200), ("ValidatorPermit", 200), ("ValidatorPermit", 54)]
)
async def test_inactive_reference_or_missing_permit_holds(reference_case, name, uid):
    case = reference_case
    vector = (case.active if name == "Active" else case.permits).copy()
    vector[uid] = False
    case.set_value(name, vector)
    with pytest.raises(TranslationReferenceError, match=r"inactive|permit_missing"):
        await read(case)


@pytest.mark.asyncio
async def test_recycled_reference_uid_is_not_accepted(reference_case):
    case = reference_case
    case.set_value("Keys", hotkey(201), 78, 200)
    with pytest.raises(TranslationReferenceError, match="registration_changed"):
        await read(case)


@pytest.mark.asyncio
async def test_policy_cutover_floor_cannot_follow_pre_c5_row(reference_case):
    case = reference_case
    case.policy = case.policy.model_copy(update={"minimum_reference_update_block": BLOCK - 10})
    with pytest.raises(TranslationReferenceError, match="cutover_not_reached"):
        await read(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "change,age,action",
    [(False, 239, "wait"), (False, 240, "submit"), (True, 99, "wait"), (True, 100, "submit")],
)
async def test_refreshes_unchanged_rows_and_rate_limits_new_rows(
    reference_case, change, age, action
):
    case = reference_case
    case.updates[54] = BLOCK - age
    case.set_value("LastUpdate", case.updates)
    if change:
        # Same authenticated delegation follows a C6+ row change automatically.
        changed = [[uid, 65535 if uid == 119 else 0] for uid in range(256)]
        case.set_value("Weights", changed, 78, 200)
    decision = (await read(case)).decision(case.policy, now=case.now)
    assert decision.action == action
    if change:
        assert decision.row[119][1] == 65535


@pytest.mark.asyncio
@pytest.mark.parametrize("row", [[], [[0, 65535]] * 256, [[uid, -1] for uid in range(256)]])
async def test_incomplete_duplicate_or_invalid_weight_rows_hold(reference_case, row):
    case = reference_case
    case.set_value("Weights", row, 78, 200)
    with pytest.raises(TranslationReferenceError, match=r"row_|unsigned_value"):
        await read(case)


@pytest.mark.asyncio
async def test_decoded_value_substitution_does_not_change_proved_row(reference_case):
    case = reference_case
    state = await read(case)
    reads = tuple(replace(r, decoded_value=False) for r in state.base.reads)
    altered = replace(state, base=replace(state.base, reads=reads))
    assert altered.decision(case.policy, now=case.now) == state.decision(case.policy, now=case.now)


@pytest.mark.asyncio
async def test_bad_storage_proof_cannot_become_selection_authority(reference_case):
    case = reference_case
    case.reject_account_proof = True
    with pytest.raises(RuntimeError, match="storage_proof_verification_failed"):
        await read(case)


@pytest.mark.asyncio
async def test_delayed_snapshot_cannot_authorize_a_later_submission(reference_case):
    case = reference_case
    state = await read(case)
    with pytest.raises(TranslationReferenceError, match="snapshot_stale"):
        state.decision(case.policy, now=case.now + timedelta(seconds=121))


@pytest.mark.asyncio
async def test_own_inactivity_does_not_prevent_eligible_writer_reactivation(reference_case):
    case = reference_case
    case.active[54] = False
    case.set_value("Active", case.active)
    assert (await read(case)).decision(case.policy, now=case.now).action == "submit"


@pytest.mark.asyncio
async def test_finality_advancing_past_mortal_era_refuses_capture(reference_case):
    case = reference_case
    original = case.finality.read_finalized_identity

    async def advancing():
        head = await original()
        if case.heads == 3:
            head.number += 8
        return head

    case.finality.read_finalized_identity = advancing
    with pytest.raises(TranslationReferenceError, match="finality_advanced_during_capture"):
        await read(case)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "item,value",
    [
        ("CommitRevealWeightsEnabled", True),
        ("Tempo", 120),
        ("MaxWeightsLimit", 1000),
        ("WeightsVersionKey", True),
    ],
)
async def test_changed_chain_settings_hold_instead_of_shortening_budget(
    reference_case, item, value
):
    case = reference_case
    case.set_value(item, value)
    with pytest.raises(
        TranslationReferenceError, match=r"settings_incompatible|budget_incompatible"
    ):
        await read(case)


@pytest.mark.asyncio
async def test_success_and_retry_telemetry_separate_capture_from_full_rollout(reference_case):
    case = reference_case
    events = []
    case.reader._progress = events.append
    await read(case)
    assert [e["completed"] for e in events] == [0, 1, 2, 3]
    assert events[-1]["eta_seconds"] == 0
    assert all(e["chain_submission_authorized"] is False for e in events)
    events.clear()
    case.active[200] = False
    case.set_value("Active", case.active)
    with pytest.raises(TranslationReferenceError):
        await read(case)
    assert events[-1]["retrying"] and events[-1]["stalled"]
    assert events[-1]["eta_seconds"] is None
    assert events[-1]["planning_seconds"] is None
