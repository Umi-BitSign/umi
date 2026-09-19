"""Synthetic proof fixtures exercise persistence, never sign or broadcast."""

from __future__ import annotations

import hashlib
import json
from datetime import timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio
from pydantic import ValidationError

import umi.registration_bridge as bridge
from tests.test_bridge_signing import case as case
from tests.test_registration_bridge import REVISION, decision, health, replace_participant
from tests.test_registration_bridge import signed_policy as signed_policy
from umi.bridge import state as persistence
from umi.bridge.transactions import (
    TRANSACTION_JOURNAL_SCHEMA,
    BridgeSigningRecord,
    evolve_journal,
    new_transaction_journal,
    parse_bridge_journal,
    reconcile_transaction_journal,
    retain_signed_extrinsic,
)
from umi.chain import _header_hash
from umi.encoding import datetime_to_unix_ms
from umi.protocol import canonical_json_bytes

# Opaque fixture bytes for journal identity tests; these are not chain extrinsics.
ENCODED = b"synthetic-signed-extrinsic"


def idle(obs):
    return bridge.RegistrationBridgeJournal(
        schema=bridge.REGISTRATION_BRIDGE_JOURNAL_SCHEMA,
        validator_hotkey=obs.validator_hotkey,
        legacy_journal_sha256=None,
        phase="idle",
        attempt=None,
        weight_call=None,
        last_observed_block=obs.block_number,
        last_observed_block_hash=obs.block_hash,
        updated_at_unix_ms=obs.block_timestamp_ms,
    )


async def advance(case, blocks=8, *, nonce=7):
    """Advance the synthetic reader's owned head, timestamp and account proof."""
    case.header["number"] = case.obs.block_number + blocks
    case.header["parentHash"] = case.obs.block_hash
    block_hash = _header_hash(case.header, "fixture")
    case.now += timedelta(seconds=blocks * 12)
    case.values[case.account_key] = json.dumps({"nonce": nonce}).encode()
    case.values[b"Timestamp.Now"] = str(datetime_to_unix_ms(case.now)).encode()
    case.obs = case.obs.model_copy(
        update={
            "block_number": case.header["number"],
            "block_hash": block_hash,
            "block_timestamp_ms": datetime_to_unix_ms(case.now),
        }
    )
    case.head.number, case.head.block_hash = case.obs.block_number, block_hash
    return await case.reader.capture(case.obs)


def prepare(policy, case, state, previous):
    receipts = health(case.obs, checked_at=case.obs.block_timestamp_ms)
    selected = bridge.validate_registration_bridge_observation(
        policy,
        case.obs,
        receipts,
        expected_revision=REVISION,
        now=case.now,
    )
    return new_transaction_journal(
        policy,
        case.obs,
        selected,
        receipts,
        signing_state=state,
        previous=previous,
        now=case.now,
    )


@pytest_asyncio.fixture
async def tx(case, signed_policy):
    state = await case.reader.capture(case.obs)
    journal = prepare(signed_policy, case, state, idle(case.obs))
    return SimpleNamespace(case=case, policy=signed_policy, state=state, preparing=journal)


def signed(tx):
    return retain_signed_extrinsic(tx.preparing, ENCODED, now=tx.case.now)


def begin(state, tx, phase="submitting"):
    state.initialize(tx.case.obs, now=tx.case.now)
    state.store(tx.preparing, archive=True)
    journal = tx.preparing
    if phase != "preparing":
        journal = signed(tx)
        state.store(journal, archive=True)
    if phase in {"submitting", "outcome_unknown"}:
        journal = evolve_journal(journal, phase="submitting")
        state.store(journal, archive=True)
    if phase == "outcome_unknown":
        journal = evolve_journal(journal, phase="outcome_unknown")
        state.store(journal, archive=True)
    return journal


def archive_bytes(root):
    return {p.name: p.read_bytes() for p in (root / "registration-bridge-history").iterdir()}


def test_v2_domain_is_distinct_and_both_versions_roundtrip(tx):
    old = idle(tx.case.obs)
    legacy_attempt = bridge._new_attempt(
        tx.policy, tx.case.obs, decision(tx.policy, tx.case.obs), health(tx.case.obs)
    )
    assert tx.preparing.attempt.attempt_id != legacy_attempt.attempt_id
    for journal in (old, tx.preparing, signed(tx)):
        raw = canonical_json_bytes(journal)
        restored = parse_bridge_journal(raw)
        assert type(restored) is type(journal) and canonical_json_bytes(restored) == raw
    assert tx.preparing.schema_ == TRANSACTION_JOURNAL_SCHEMA
    assert tx.preparing.attempt.signing.nonce == 7
    assert tx.preparing.attempt.era_death == tx.case.obs.block_number + 8
    assert tx.preparing.signed_extrinsic is None
    assert len(canonical_json_bytes(tx.preparing)) < bridge.MAX_DOCUMENT_BYTES


@pytest.mark.parametrize(
    "change", ["hash", "bytes", "missing_hash", "missing_bytes", "empty", "oversize"]
)
def test_signed_record_requires_exact_bounded_bytes_and_hash(tx, change):
    journal = signed(tx)
    updates = {
        "hash": {"signed_extrinsic_hash": "0x" + "00" * 32},
        "bytes": {"signed_extrinsic": b"different".hex()},
        "missing_hash": {"signed_extrinsic_hash": None},
        "missing_bytes": {"signed_extrinsic": None},
        "empty": {"signed_extrinsic": ""},
        "oversize": {"signed_extrinsic": "ab" * 65537},
    }[change]
    with pytest.raises((ValidationError, ValueError)):
        evolve_journal(journal, **updates)


def test_signed_record_cannot_be_encoded_twice(tx):
    with pytest.raises(bridge.RegistrationBridgeError, match="already_signed"):
        retain_signed_extrinsic(signed(tx), b"another", now=tx.case.now)


@pytest.mark.asyncio
async def test_commitment_binds_runtime_and_account_inputs(tx):
    first = BridgeSigningRecord.from_state(tx.state)
    tx.case.values[tx.case.account_key] = b'{"nonce":8}'
    second = BridgeSigningRecord.from_state(await tx.case.reader.capture(tx.case.obs))
    assert first.proof_inputs_sha256 != second.proof_inputs_sha256
    assert first.runtime_metadata_sha256 == second.runtime_metadata_sha256


@pytest.mark.parametrize("phase", ["preparing", "signed", "submitting", "outcome_unknown"])
@pytest.mark.asyncio
async def test_uncertain_new_attempt_resolves_only_after_era_and_proven_nonce(tx, phase):
    journal = tx.preparing if phase == "preparing" else evolve_journal(signed(tx), phase=phase)
    with pytest.raises(bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"):
        reconcile_transaction_journal(journal, tx.case.obs, now=tx.case.now, signing_state=tx.state)
    state = await advance(tx.case)
    with pytest.raises(bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"):
        reconcile_transaction_journal(journal, tx.case.obs, now=tx.case.now)
    result = reconcile_transaction_journal(
        journal, tx.case.obs, now=tx.case.now, signing_state=state
    )
    assert result.phase == "expired_nonce_available"
    assert result.attempt == journal.attempt
    assert result.signed_extrinsic == journal.signed_extrinsic
    assert result.weight_call is None
    assert result.expiry_observation.nonce == 7


@pytest.mark.parametrize("nonce", [0, 6, 8, 2**32 - 1])
@pytest.mark.asyncio
async def test_changed_nonce_cannot_resolve_uncertain_attempt(tx, nonce):
    state = await advance(tx.case, nonce=nonce)
    with pytest.raises(bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"):
        reconcile_transaction_journal(signed(tx), tx.case.obs, now=tx.case.now, signing_state=state)


@pytest.mark.asyncio
async def test_exact_signed_bytes_do_not_resolve_legacy_ambiguity(tx):
    attempt = bridge._new_attempt(
        tx.policy, tx.case.obs, decision(tx.policy, tx.case.obs), health(tx.case.obs)
    )
    legacy = evolve_journal(idle(tx.case.obs), phase="outcome_unknown", attempt=attempt)
    raw = canonical_json_bytes(legacy)
    state = await advance(tx.case)
    with pytest.raises(bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"):
        reconcile_transaction_journal(legacy, tx.case.obs, now=tx.case.now, signing_state=state)
    assert canonical_json_bytes(legacy) == raw


@pytest.mark.asyncio
async def test_record_without_live_proof_object_is_not_recovery_authority(tx):
    state = await advance(tx.case)
    with pytest.raises(bridge.RegistrationBridgeError, match="prior_submission_outcome_unknown"):
        reconcile_transaction_journal(
            signed(tx),
            tx.case.obs,
            now=tx.case.now,
            signing_state=BridgeSigningRecord.from_state(state),
        )


@pytest.mark.asyncio
async def test_expiry_proof_is_fresh_and_matches_the_observation(tx):
    journal = signed(tx)
    state = await advance(tx.case)
    with pytest.raises(bridge.RegistrationBridgeError, match="snapshot_stale"):
        reconcile_transaction_journal(
            journal, tx.case.obs, now=tx.case.now + timedelta(seconds=121), signing_state=state
        )
    changed = tx.case.obs.model_copy(update={"block_hash": "0x" + "44" * 32})
    with pytest.raises(bridge.RegistrationBridgeError, match="observation_changed"):
        reconcile_transaction_journal(journal, changed, now=tx.case.now, signing_state=state)


def test_attempt_cannot_precede_previous_observed_head(tx):
    previous = evolve_journal(idle(tx.case.obs), last_observed_block=tx.case.obs.block_number + 1)
    with pytest.raises(bridge.RegistrationBridgeError, match="finality_rollback"):
        prepare(tx.policy, tx.case, tx.state, previous)


@pytest.mark.parametrize("phase", ["preparing", "signed", "submitting", "outcome_unknown"])
@pytest.mark.asyncio
async def test_restart_retains_exact_unknown_history_and_allows_new_attempt_after_expiry(
    tmp_path, tx, phase
):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx, phase)
    old = archive_bytes(root)
    original = root.joinpath("registration-bridge-journal.json").read_bytes()
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == journal
        assert state.path.read_bytes() == original
        proven = await advance(tx.case)
        resolved = reconcile_transaction_journal(
            journal, tx.case.obs, now=tx.case.now, signing_state=proven
        )
        state.store(resolved, archive=True)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == resolved
        # This is a new intent, never a rebroadcast or rewrite of the old one.
        next_journal = prepare(tx.policy, tx.case, proven, resolved)
        state.store(next_journal, archive=True)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == next_journal
        assert next_journal.attempt.attempt_id != journal.attempt.attempt_id
        assert next_journal.signed_extrinsic is None
    assert all(archive_bytes(root)[name] == raw for name, raw in old.items())


@pytest.mark.parametrize("stage", ["preparing", "signed", "submitting", "outcome_unknown"])
def test_crash_after_archive_before_current_rolls_forward_exact_archived_transition(
    tmp_path, tx, monkeypatch, stage
):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        if stage == "preparing":
            state.initialize(tx.case.obs, now=tx.case.now)
            target = tx.preparing
        else:
            previous_stage = {
                "signed": "preparing",
                "submitting": "signed",
                "outcome_unknown": "submitting",
            }[stage]
            before = begin(state, tx, previous_stage)
            target = signed(tx) if stage == "signed" else evolve_journal(before, phase=stage)
        replace = bridge.os.replace

        def crash(source, destination):
            if destination == state.path:
                raise OSError("injected crash before current replace")
            replace(source, destination)

        with monkeypatch.context() as patch:
            patch.setattr(bridge.os, "replace", crash)
            with pytest.raises(OSError, match="injected crash"):
                state.store(target, archive=True)
    retained = archive_bytes(root)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == target
        assert state.path.read_bytes() == canonical_json_bytes(target)
    assert archive_bytes(root) == retained


def test_store_rejects_version_downgrade(tmp_path, tx):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        begin(state, tx)
        with pytest.raises(bridge.RegistrationBridgeError, match="downgrade"):
            state.store(idle(tx.case.obs))


@pytest.mark.parametrize(
    "mutation,reason",
    [
        ("skip_signed", "without_signing_transition"),
        ("unsigned_unknown", "signed_extrinsic_changed"),
        ("different_signed", "signed_extrinsic_changed"),
        ("no_archive", "transition_invalid"),
    ],
)
def test_store_validates_transaction_before_any_write(tmp_path, tx, mutation, reason):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        journal = begin(state, tx, "preparing" if mutation == "skip_signed" else "signed")
        raw, history = state.path.read_bytes(), archive_bytes(state.root)
        if mutation == "skip_signed":
            target = evolve_journal(signed(tx), phase="submitting")
        elif mutation == "unsigned_unknown":
            target = evolve_journal(
                journal, phase="outcome_unknown", signed_extrinsic=None, signed_extrinsic_hash=None
            )
        elif mutation == "different_signed":
            target = retain_signed_extrinsic(tx.preparing, b"other", now=tx.case.now)
        else:
            target = evolve_journal(journal, phase="submitting")
        with pytest.raises(bridge.RegistrationBridgeError, match=reason):
            state.store(target, archive=mutation != "no_archive")
        assert state.path.read_bytes() == raw and archive_bytes(state.root) == history


@pytest.mark.parametrize("phase", ["preparing", "signed"])
def test_missing_mandatory_archive_rejected_on_restart(tmp_path, tx, phase):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx)
    path = root / "registration-bridge-history" / f"{journal.attempt.attempt_id}-{phase}.json"
    path.unlink()
    with (
        bridge.RegistrationBridgeState(root) as state,
        pytest.raises(bridge.RegistrationBridgeError, match=r"history_.*missing"),
    ):
        state.initialize(tx.case.obs, now=tx.case.now)


def test_same_hash_field_cannot_hide_changed_archive_bytes(tmp_path, tx):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx)
    path = root / "registration-bridge-history" / f"{journal.attempt.attempt_id}-signed.json"
    modified = json.loads(path.read_bytes())
    modified["signed_extrinsic"] = b"other".hex()
    modified["signed_extrinsic_hash"] = "0x" + hashlib.blake2b(b"other", digest_size=32).hexdigest()
    path.write_bytes(canonical_json_bytes(modified))
    with (
        bridge.RegistrationBridgeState(root) as state,
        pytest.raises(bridge.RegistrationBridgeError, match="signed_extrinsic_changed"),
    ):
        state.initialize(tx.case.obs, now=tx.case.now)


@pytest.mark.parametrize("resource", ["files", "bytes", "disk", "document"])
def test_reserve_all_transition_capacity_before_first_intent(tmp_path, tx, monkeypatch, resource):
    with bridge.RegistrationBridgeState(tmp_path.resolve() / "state") as state:
        state.initialize(tx.case.obs, now=tx.case.now)
        original = state.path.read_bytes()
        maximum = (
            len(canonical_json_bytes(tx.preparing)) + 2 * bridge.MAX_SIGNED_EXTRINSIC_BYTES + 4096
        )
        if resource == "files":
            monkeypatch.setattr(persistence, "MAX_HISTORY_FILES", 6)
        elif resource == "bytes":
            monkeypatch.setattr(persistence, "MAX_HISTORY_BYTES", len(original) + 8 * maximum - 1)
        elif resource == "disk":
            monkeypatch.setattr(
                bridge.os,
                "statvfs",
                lambda path: SimpleNamespace(f_bavail=9 * maximum - 1, f_frsize=1),
            )
        else:
            monkeypatch.setattr(persistence, "MAX_DOCUMENT_BYTES", maximum - 1)
        with pytest.raises(bridge.RegistrationBridgeError, match="headroom_insufficient"):
            state.store(tx.preparing, archive=True)
        assert state.path.read_bytes() == original
        assert not (state.root / "registration-bridge-history").exists()


def test_legacy_repair_cannot_resolve_new_format_using_only_matching_call(tx):
    from umi.registration_bridge_recover import prove_applied_attempt

    with pytest.raises(bridge.RegistrationBridgeError, match="requires_exact_transaction_proof"):
        prove_applied_attempt(
            evolve_journal(signed(tx), phase="outcome_unknown"), tx.case.obs, None, []
        )


def test_two_archives_ahead_of_current_are_not_treated_as_one_interrupted_write(tmp_path, tx):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        begin(state, tx)
    # Losing two acknowledged current writes is not the supported archive-first
    # tear. Do not let replay silently conceal a rolled-back current journal.
    path = root / "registration-bridge-journal.json"
    path.write_bytes(canonical_json_bytes(tx.preparing))
    with (
        bridge.RegistrationBridgeState(root) as state,
        pytest.raises(bridge.RegistrationBridgeError, match="current_journal_rolled_back"),
    ):
        state.initialize(tx.case.obs, now=tx.case.now)


def test_archive_sync_is_retried_before_repair_reports_success(tmp_path, tx, monkeypatch):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        begin(state, tx, "preparing")
        original = state.path.read_bytes()
        sync = bridge._fsync

        def unavailable(path):
            if path.name == "registration-bridge-history":
                raise OSError("injected archive sync failure")
            sync(path)

        with monkeypatch.context() as patch:
            patch.setattr(persistence, "_fsync", unavailable)
            with pytest.raises(OSError, match="injected archive sync"):
                state.store(signed(tx), archive=True)
    with bridge.RegistrationBridgeState(root) as state:
        with monkeypatch.context() as patch:
            patch.setattr(persistence, "_fsync", unavailable)
            with pytest.raises(OSError, match="injected archive sync"):
                state.initialize(tx.case.obs, now=tx.case.now)
        assert state.path.read_bytes() == original
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == signed(tx)


@pytest.mark.asyncio
async def test_applied_and_expired_histories_cannot_coexist(tmp_path, tx):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx)
        proven = await advance(tx.case)
        expired = reconcile_transaction_journal(
            journal, tx.case.obs, now=tx.case.now, signing_state=proven
        )
        state.store(expired, archive=True)
    receipt = bridge.BootstrapExtrinsicReference(
        extrinsic_id=f"{journal.attempt.preflight_block + 1}-0001",
        block_number=journal.attempt.preflight_block + 1,
        extrinsic_index=1,
        block_hash="0x" + "44" * 32,
    )
    for phase in ("receipt_returned", "applied"):
        changed = evolve_journal(expired, phase=phase, weight_call=receipt, expiry_observation=None)
        path = root / "registration-bridge-history" / f"{journal.attempt.attempt_id}-{phase}.json"
        path.write_bytes(canonical_json_bytes(changed))
        path.chmod(0o600)
    with (
        bridge.RegistrationBridgeState(root) as state,
        pytest.raises(bridge.RegistrationBridgeError, match="history_conflicting_resolution"),
    ):
        state.initialize(tx.case.obs, now=tx.case.now)


@pytest.mark.parametrize("phase", ["receipt_returned", "applied", "expired_nonce_available"])
@pytest.mark.asyncio
async def test_restart_completes_archived_result_without_rewriting_evidence(
    tmp_path, tx, monkeypatch, phase
):
    root = tmp_path.resolve() / "state"
    with bridge.RegistrationBridgeState(root) as state:
        journal = begin(state, tx)
        if phase == "expired_nonce_available":
            proven = await advance(tx.case)
            target = reconcile_transaction_journal(
                journal, tx.case.obs, now=tx.case.now, signing_state=proven
            )
        else:
            await advance(tx.case, 1, nonce=8)
            receipt = bridge.BootstrapExtrinsicReference(
                extrinsic_id=f"{tx.case.obs.block_number}-0001",
                block_number=tx.case.obs.block_number,
                extrinsic_index=1,
                block_hash=tx.case.obs.block_hash,
            )
            target = evolve_journal(journal, phase="receipt_returned", weight_call=receipt)
            if phase == "applied":
                state.store(target, archive=True)
                target = evolve_journal(
                    target,
                    phase="applied",
                    last_observed_block=tx.case.obs.block_number,
                    last_observed_block_hash=tx.case.obs.block_hash,
                )
        replace = bridge.os.replace

        def crash(source, destination):
            if destination == state.path:
                raise OSError("injected result publication crash")
            replace(source, destination)

        with monkeypatch.context() as patch:
            patch.setattr(bridge.os, "replace", crash)
            with pytest.raises(OSError, match="injected result publication crash"):
                state.store(target, archive=True)
    retained = archive_bytes(root)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == target
        assert state.path.read_bytes() == canonical_json_bytes(target)
    assert archive_bytes(root) == retained


@pytest.mark.asyncio
async def test_upgrade_from_resolved_v1_preserves_every_legacy_byte(tmp_path, tx):
    root = tmp_path.resolve() / "state"
    attempt = bridge._new_attempt(
        tx.policy, tx.case.obs, decision(tx.policy, tx.case.obs), health(tx.case.obs)
    )
    with bridge.RegistrationBridgeState(root) as state:
        old = state.initialize(tx.case.obs, now=tx.case.now)
        old = evolve_journal(old, phase="submitting", attempt=attempt)
        state.store(old, archive=True)
        await advance(tx.case, 1, nonce=8)
        receipt = bridge.BootstrapExtrinsicReference(
            extrinsic_id=f"{tx.case.obs.block_number}-0001",
            block_number=tx.case.obs.block_number,
            extrinsic_index=1,
            block_hash=tx.case.obs.block_hash,
        )
        old = evolve_journal(old, phase="receipt_returned", weight_call=receipt)
        state.store(old, archive=True)
        old = evolve_journal(
            old,
            phase="applied",
            last_observed_block=tx.case.obs.block_number,
            last_observed_block_hash=tx.case.obs.block_hash,
        )
        state.store(old, archive=True)
    retained = archive_bytes(root)
    tx.case.obs = replace_participant(tx.case.obs, 54, last_update=receipt.block_number)
    tx.case.obs = tx.case.obs.model_copy(update={"validator_row": attempt.expected_row})
    refresh_blocks = (
        tx.policy.body.required_activity_cutoff_blocks - tx.policy.body.refresh_margin_blocks
    )
    proven = await advance(tx.case, refresh_blocks, nonce=8)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == old
        upgraded = prepare(tx.policy, tx.case, proven, old)
        state.store(upgraded, archive=True)
    with bridge.RegistrationBridgeState(root) as state:
        assert state.initialize(tx.case.obs, now=tx.case.now) == upgraded
    assert all(archive_bytes(root)[name] == raw for name, raw in retained.items())
