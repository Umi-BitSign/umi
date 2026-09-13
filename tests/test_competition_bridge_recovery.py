from __future__ import annotations

import hashlib
import os
from types import SimpleNamespace

import pytest

from tests.test_competition_recovery import limits
from tests.test_competition_upgrade import write
from tests.test_registration_bridge import (
    BLOCK,
    NOW_MS,
    decision,
    health,
    observation,
    replace_participant,
    signed_policy,
)
from tests.test_registration_bridge_funding import setup as funding_setup
from umi import competition_recovery as recovery
from umi import registration_bridge as bridge
from umi.competition_bridge_recovery import ARCHIVE, HISTORY, JOURNAL, audit_bridge_history
from umi.protocol import canonical_json_bytes

__all__ = ["funding_setup", "limits", "signed_policy"]


def add_attempt(files, policy, obs, *, legacy_sha=None, phase="applied"):
    attempt = bridge._new_attempt(policy, obs, decision(policy, obs), health(obs))
    intent = bridge.RegistrationBridgeJournal(
        schema=bridge.REGISTRATION_BRIDGE_JOURNAL_SCHEMA,
        validator_hotkey=obs.validator_hotkey,
        legacy_journal_sha256=legacy_sha,
        phase="submitting",
        attempt=attempt,
        weight_call=None,
        last_observed_block=obs.block_number,
        last_observed_block_hash=obs.block_hash,
        updated_at_unix_ms=NOW_MS,
    )
    records = [intent]
    if phase == "outcome_unknown":
        records.append(intent.model_copy(update={"phase": phase}))
    if phase in {"receipt_returned", "applied"}:
        receipt = bridge.BootstrapExtrinsicReference(
            extrinsic_id=f"{obs.block_number + 1}-0002",
            block_number=obs.block_number + 1,
            extrinsic_index=2,
            block_hash="0x" + "22" * 32,
        )
        returned = intent.model_copy(update={"phase": "receipt_returned", "weight_call": receipt})
        records.append(returned)
        if phase == "applied":
            records.append(
                returned.model_copy(
                    update={
                        "phase": "applied",
                        "last_observed_block": receipt.block_number,
                        "last_observed_block_hash": receipt.block_hash,
                    }
                )
            )
    for record in records:
        files[f"{HISTORY}/{attempt.attempt_id}-{record.phase}.json"] = canonical_json_bytes(record)
    files[JOURNAL] = canonical_json_bytes(records[-1])
    return records[-1]


@pytest.fixture
def completed(signed_policy):
    files = {"service.lock": b""}
    first = add_attempt(files, signed_policy, observation())
    obs = replace_participant(
        observation(block_number=BLOCK + 250, validator_row=first.attempt.expected_row),
        54,
        last_update=first.weight_call.block_number,
    )
    current = add_attempt(files, signed_policy, obs)
    owned = SimpleNamespace(
        validator_hotkey=current.validator_hotkey,
        validator_uid=54,
        validator_row=tuple(tuple(pair) for pair in current.attempt.expected_row),
        validator_last_update=current.weight_call.block_number,
        block=current.last_observed_block + 1,
        block_hash="0x" + "33" * 32,
        manifest_anchor_sha256=None,
        manifest_anchor_block=None,
        commit_reveal_enabled=False,
    )
    return SimpleNamespace(files=files, first=first, current=current, owned=owned)


def test_complete_history_binds_each_prior_lastupdate(completed):
    audit = audit_bridge_history(completed.files, hotkey=completed.current.validator_hotkey)
    assert len(audit.attempts) == 2
    assert audit.attempts[-1] == (JOURNAL, completed.current)
    assert not audit.holds
    assert audit.recognized == frozenset(completed.files) - {"service.lock"}


@pytest.mark.parametrize("phase", ["submitting", "outcome_unknown"])
def test_unknown_current_attempt_never_reconciles_by_row_equality(completed, signed_policy, phase):
    obs = replace_participant(
        observation(block_number=BLOCK + 500),
        54,
        last_update=completed.current.weight_call.block_number,
    )
    current = add_attempt(completed.files, signed_policy, obs, phase=phase)
    audit = audit_bridge_history(completed.files, hotkey=current.validator_hotkey)
    assert "registration_bridge_attempt_mortality_unknown" in audit.holds


@pytest.mark.parametrize("phase", ["submitting", "receipt_returned"])
def test_missing_durable_phase_is_rejected(completed, phase):
    del completed.files[f"{HISTORY}/{completed.current.attempt.attempt_id}-{phase}.json"]
    with pytest.raises(ValueError, match=r"intent|receipt"):
        audit_bridge_history(completed.files, hotkey=completed.current.validator_hotkey)


@pytest.mark.parametrize(
    "mutation", ["rollback", "wrong_hotkey", "archive", "filename", "noncanonical"]
)
def test_history_identity_failures(completed, mutation):
    hotkey = completed.current.validator_hotkey
    if mutation == "rollback":
        completed.files[JOURNAL] = canonical_json_bytes(completed.first)
    elif mutation == "wrong_hotkey":
        hotkey = observation().participants[55].hotkey
    elif mutation == "archive":
        completed.files[ARCHIVE] = b"{}"
    elif mutation == "filename":
        path = next(path for path in completed.files if path.startswith(HISTORY))
        completed.files[path + ".json"] = completed.files.pop(path)
    else:
        completed.files[JOURNAL] += b"\n"
    with pytest.raises(ValueError):
        audit_bridge_history(completed.files, hotkey=hotkey)


def test_unexplained_external_weight_update_is_not_erased(completed, signed_policy):
    obs = replace_participant(observation(block_number=BLOCK + 500), 54, last_update=BLOCK + 499)
    add_attempt(completed.files, signed_policy, obs)
    with pytest.raises(ValueError, match="LastUpdate gap"):
        audit_bridge_history(completed.files, hotkey=completed.current.validator_hotkey)


def snapshot(root, item, limits):
    for path, raw in item.files.items():
        write(root / path, raw, 0o600)
    return recovery.snapshot_legacy_bootstrap(
        root,
        expected_hotkey=item.current.validator_hotkey,
        service_uid=os.geteuid(),
        accepted_sequence=10,
        accepted_directive_sha256="33" * 32,
        accepted_at_finalized_block=BLOCK - 1000,
        config_sha256="44" * 32,
        installation_sha256="55" * 32,
        limits=limits,
    )


def test_stopped_snapshot_retains_every_bridge_byte_and_reconciles_latest_row(
    tmp_path, completed, limits
):
    with snapshot(tmp_path / "worker", completed, limits) as snap:
        assert not snap.manifest.holds
        assert snap._files == completed.files
        effects, holds = recovery._reconcile_snapshot(snap, completed.owned, ())
        assert not holds
        assert {item.classification for item in effects} == {
            "proven_current_weight",
            "proven_superseded_weight",
        }
        assert len(effects) == 2


def test_funding_bridge_upgrade_preserves_v1_history_and_reconciles_v2(
    tmp_path, funding_setup, limits
):
    obs, _, _, funded_policy, old_policy = funding_setup
    files = {"service.lock": b""}
    first = add_attempt(files, old_policy, obs)
    prior_history = {path: raw for path, raw in files.items() if path.startswith(HISTORY + "/")}
    next_obs = replace_participant(
        obs.model_copy(
            update={"block_number": BLOCK + 250, "validator_row": first.attempt.expected_row}
        ),
        54,
        last_update=first.weight_call.block_number,
    )
    current = add_attempt(files, funded_policy, next_obs)
    assert first.attempt.expected_row != current.attempt.expected_row
    item = SimpleNamespace(
        files=files,
        current=current,
        owned=SimpleNamespace(
            validator_hotkey=current.validator_hotkey,
            validator_uid=54,
            validator_row=tuple(tuple(pair) for pair in current.attempt.expected_row),
            validator_last_update=current.weight_call.block_number,
            block=current.last_observed_block + 1,
            block_hash="0x" + "33" * 32,
            manifest_anchor_sha256=None,
            manifest_anchor_block=None,
            commit_reveal_enabled=False,
        ),
    )
    with snapshot(tmp_path / "worker", item, limits) as snap:
        assert not snap.manifest.holds
        assert snap._files == files
        assert all(snap._files[path] == raw for path, raw in prior_history.items())
        recovery._check_current_manifest(
            snap,
            SimpleNamespace(
                validator_hotkey=current.validator_hotkey,
                expected_manifest_sha256=None,
                expected_registration_bridge_policy_sha256=(
                    bridge.registration_bridge_policy_sha256(funded_policy)
                ),
            ),
        )
        effects, holds = recovery._reconcile_snapshot(snap, item.owned, ())
        assert not holds
        assert [effect.classification for effect in effects] == [
            "proven_superseded_weight",
            "proven_current_weight",
        ]


@pytest.mark.parametrize(
    "field,value",
    [
        ("validator_row", ()),
        ("validator_last_update", BLOCK),
        ("validator_uid", 55),
        ("block", BLOCK),
        ("commit_reveal_enabled", True),
    ],
)
def test_chain_mismatch_retains_held_checkpoint(tmp_path, completed, limits, field, value):
    setattr(completed.owned, field, value)
    with snapshot(tmp_path / "worker", completed, limits) as snap:
        _, holds = recovery._reconcile_snapshot(snap, completed.owned, ())
        assert holds


def test_unknown_files_are_preserved_and_block_recovery(tmp_path, completed, limits):
    completed.files[".registration-bridge-partial.tmp"] = b"partial"
    with snapshot(tmp_path / "worker", completed, limits) as snap:
        assert "unclassified_legacy_file" in snap.manifest.holds
        assert snap._files == completed.files


def test_installed_bridge_policy_must_match_latest_attempt(tmp_path, completed, limits):
    stopped = SimpleNamespace(
        validator_hotkey=completed.current.validator_hotkey,
        expected_manifest_sha256=None,
        expected_registration_bridge_policy_sha256=completed.current.attempt.policy_sha256,
    )
    with snapshot(tmp_path / "worker", completed, limits) as snap:
        recovery._check_current_manifest(snap, stopped)
        stopped.expected_registration_bridge_policy_sha256 = "00" * 32
        with pytest.raises(ValueError, match="installed signed policy"):
            recovery._check_current_manifest(snap, stopped)


def test_copy_of_unresolved_frozen_pilot_journal_cannot_count_as_retired(completed):
    # The archived old bytes must be exactly the old terminal record. Their
    # digest alone cannot authorize a bridge-to-successor migration.
    raw = b"{}"
    completed.files["journal.json"] = completed.files[ARCHIVE] = raw
    current = completed.current.model_copy(
        update={"legacy_journal_sha256": hashlib.sha256(raw).hexdigest()}
    )
    completed.files[JOURNAL] = canonical_json_bytes(current)
    with pytest.raises(ValueError):
        audit_bridge_history(completed.files, hotkey=current.validator_hotkey)


def retain_old_journal(completed, old):
    raw = canonical_json_bytes(old)
    completed.files["journal.json"] = completed.files[ARCHIVE] = raw
    sha = hashlib.sha256(raw).hexdigest()
    for path, body in list(completed.files.items()):
        if path == JOURNAL or path.startswith(HISTORY + "/"):
            record = bridge.RegistrationBridgeJournal.model_validate_json(body)
            completed.files[path] = canonical_json_bytes(
                record.model_copy(update={"legacy_journal_sha256": sha})
            )


def test_bridge_proof_does_not_clear_missing_frozen_pilot_context(tmp_path, completed, limits):
    from tests.test_registration_bridge_runtime import old_applied

    old = old_applied(
        SimpleNamespace(hotkey=SimpleNamespace(ss58_address=completed.current.validator_hotkey))
    )
    retain_old_journal(completed, old)
    with snapshot(tmp_path / "worker", completed, limits) as snap:
        assert "common_historical_context_missing" in snap.manifest.holds
        _, holds = recovery._reconcile_snapshot(snap, completed.owned, ())
        assert "common_historical_context_missing" in holds


def test_bridge_cannot_retire_an_uncertain_old_journal(tmp_path, completed, limits):
    from tests.test_registration_bridge_runtime import old_applied

    wallet = SimpleNamespace(
        hotkey=SimpleNamespace(ss58_address=completed.current.validator_hotkey)
    )
    old = old_applied(wallet, phase="recovered_applied")
    retain_old_journal(completed, old)
    with (
        pytest.raises(ValueError, match="not terminal"),
        snapshot(tmp_path / "worker", completed, limits),
    ):
        pytest.fail("row equality cannot resolve an uncertain old attempt")
