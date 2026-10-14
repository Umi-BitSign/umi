"""Retained C5 native transcript and exact empty-store upgrade qualification.

The record fixture was exported read-only from the retired owner snapshot at
height 9184789. It is an actual native record, not reconstructed test output.
Artifact integrity itself is separately qualified by observer constructor tests.
No native process or RPC is started by these store/parser tests.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path

import pytest
import rfc8785

import umi.grandpa_finality_supervisor as supervisor
from umi.grandpa_finality import (
    CURRENT_OBSERVER_BUILD,
    SOURCE_REVISION,
    GrandpaFinalityObserver,
    GrandpaFinalityObserverError,
)
from umi.grandpa_finality_supervisor import (
    DurableGrandpaFinalityPort,
    GrandpaFinalityStoreConflict,
    GrandpaFinalityStoreCorruption,
    GrandpaFinalitySupervisorLimits,
    ObserverRunBinding,
)
from umi.policy import FinalityVerifierPin, LiveChainObservationPin
from umi.protocol import canonical_json_bytes

from .test_grandpa_finality_accounting import legacy_database

_ROOT = Path(__file__).parents[1]
_FIXTURE = json.loads(
    (_ROOT / "tests/fixtures/grandpa-finality/c5-retained-observer-record.json").read_bytes()
)
_RECORD = rfc8785.dumps(_FIXTURE["record"])
_CONFIG = _FIXTURE["store_config"]
_BINDING = ObserverRunBinding(segment_index=0, **_FIXTURE["binding"])


@pytest.fixture
def retained_observer(tmp_path, monkeypatch):
    pin = FinalityVerifierPin.model_validate(
        json.loads((_ROOT / "docs/competition/C5_TRANSPORT_POLICY.json").read_bytes())[
            "implementation_pins"
        ]["finality_verifier"]
    )
    # This fixture never executes or substitutes a native binary; it exercises
    # the actual selected-pin constructor's parsing and persistent store path.
    monkeypatch.setattr(GrandpaFinalityObserver, "_assert_file_integrity", lambda *a, **k: None)
    observer = GrandpaFinalityObserver.from_policy_pin(
        pin,
        target_triple="x86_64-unknown-linux-gnu",
        binary_path=tmp_path / "unused-original-binary",
        chain_spec_path=tmp_path / "unused-original-spec",
    )
    assert observer.retained_policy_pin
    assert observer.build_identity.source_revision == _FIXTURE["record"]["source_revision"]
    assert observer.build_identity != CURRENT_OBSERVER_BUILD
    return observer


def _port(path, observer, **overrides):
    settings = dict(
        observer=observer,
        state_path=path,
        scoring_policy_digest=_CONFIG["scoring_policy_hash"],
        chain_observation=LiveChainObservationPin.model_validate(_CONFIG["chain_observation"]),
        finality_verifier_sha256=_CONFIG["finality_verifier_sha256"],
        initial_minimum_finalized_block=_CONFIG["initial_minimum_finalized_block"],
        startup_timeout_seconds=_CONFIG["startup_timeout_seconds"],
        limits=GrandpaFinalitySupervisorLimits(**_CONFIG["limits"]),
    )
    return DurableGrandpaFinalityPort(**(settings | overrides))


def _parse(observer, encoded=_RECORD):
    return observer.validate_attestation(
        encoded,
        **_FIXTURE["binding"],
        expected_sequence=0,
        previous_hash=None,
        previous_digest="0" * 64,
        previous_number=None,
        previous_timestamp_ms=None,
    )


def _metadata(path):
    with sqlite3.connect(path) as connection:
        return dict(connection.execute("SELECT key,value FROM store_meta"))


def _break_build(path, **changes):
    with sqlite3.connect(path) as connection:
        value = json.loads(_metadata(path)["config"])
        value["observer"].update(
            # Fixed historical misbinding, independent of future current builds
            # and independent of the production repair's compatibility constant.
            source_revision=(
                _FIXTURE["record"]["source_revision"] + "+ruzstd-0.9.1-rustsec-2026-0344"
            ),
            source_tree_sha256="dac8079bc2041bd2512cb599846ea822aa5b53d77d62437bf9b02774acb73488",
            cargo_lock_sha256="c7e0530a519f59c4ba389846081f1aca5ec5eb171e987b81ecdd071ee2ec14d3",
            fixture_set_sha256="b5522352dc04cbd88eb7916ba95e65330c89915619e292f3512ed3acebd11655",
        )
        value.update(changes)
        raw = canonical_json_bytes(value)
        connection.execute("UPDATE store_meta SET value=? WHERE key='config'", (raw,))
        connection.execute(
            "UPDATE store_meta SET value=? WHERE key='config_sha256'",
            (hashlib.sha256(raw).digest(),),
        )
    return raw


@pytest.mark.asyncio
async def test_actual_retained_native_record_accept_audit_restart_and_cache_replay(
    tmp_path, retained_observer
):
    # Exact canonical bytes read from the original retired SQLite record.
    assert len(_RECORD) == 2468
    assert hashlib.sha256(_RECORD).hexdigest() == (
        "fcca73581becc109faa4906cad95f1114556c6afa6bd9ad48d1075387eb54901"
    )
    attestation = _parse(retained_observer)
    assert attestation.canonical_bytes == _RECORD
    assert attestation.block.number == 9184789
    path = tmp_path / "retained.sqlite3"
    port = _port(path, retained_observer)
    original_inode = path.stat().st_ino
    assert port._config_bytes() == canonical_json_bytes(_CONFIG)
    assert port.next_run_binding() == _BINDING
    first = port.accept_attestation(_BINDING, attestation)
    before = _metadata(path)
    receipt = await port.verified_acceptance_receipt_at(first.height)
    original = await port.verified_block_at(first.height)
    assert original.finality_evidence == _RECORD
    port.audit()
    port.close()

    restarted = _port(path, retained_observer)
    assert restarted.persisted_head() == first
    assert restarted.accept_attestation(_BINDING, attestation) == first
    assert await restarted.verified_acceptance_receipt_at(first.height) == receipt
    assert await restarted.verified_block_at(first.height) == original
    assert await restarted.verified_block_after(first.height - 1, maximum_distance=1) == original
    replay = restarted._stored_replay_range(first.height, first.height)
    assert len(replay) == 1
    stored, binding = replay[0]
    assert stored.canonical_evidence == _RECORD
    assert binding.minimum_finalized_block == _BINDING.minimum_finalized_block
    assert binding.expected_sequence == 0
    restarted.audit()
    assert _metadata(path) == before
    assert path.stat().st_ino == original_inode


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("source_revision", SOURCE_REVISION),
        ("chain_spec_sha256", "a1" * 32),
        ("genesis_hash", "0x" + "a1" * 32),
        ("bootstrap_block_number", 8867449),
        ("bootstrap_block_hash", "0x" + "a1" * 32),
        ("bootstrap_source", "genesis"),
        ("bootstrap_selected", False),
        ("request_id", "a1" * 32),
    ],
)
def test_retained_record_still_rejects_changed_pins_with_valid_digest(
    retained_observer, field, value
):
    record = json.loads(_RECORD)
    del record["transcript_digest"]
    record[field] = value
    record["transcript_digest"] = hashlib.sha256(
        b"umi-grandpa-finality-attestation-v1\0" + rfc8785.dumps(record)
    ).hexdigest()
    with pytest.raises(GrandpaFinalityObserverError):
        _parse(retained_observer, rfc8785.dumps(record))


@pytest.mark.parametrize("predecessor", [False, True])
@pytest.mark.parametrize("legacy", [False, True])
def test_exact_empty_constructor_only_layout_repairs_in_place_once(
    tmp_path, retained_observer, predecessor, legacy, caplog
):
    path = tmp_path / "empty.sqlite3"
    _port(path, retained_observer).close()
    original_inode = path.stat().st_ino
    previous = _break_build(path)
    if legacy:
        legacy_database(path)
    options = (
        dict(
            scoring_policy_digest="b1" * 32,
            accepted_predecessor_policy_digests=(_CONFIG["scoring_policy_hash"],),
        )
        if predecessor
        else {}
    )
    caplog.set_level("INFO", logger="umi.grandpa_finality_supervisor")
    repaired = _port(path, retained_observer, **options)
    repaired.audit()
    assert repaired.persisted_head() is None
    assert path.stat().st_ino == original_inode
    after = _metadata(path)
    assert after["observer_build_binding_repair_original"] == previous
    expected = dict(_CONFIG)
    if predecessor:
        expected["scoring_policy_hash"] = "b1" * 32
    assert after["config"] == canonical_json_bytes(expected)
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 3
    assert "state=completed" in caplog.text
    caplog.clear()
    repaired.close()
    _port(path, retained_observer, **options).audit()
    assert _metadata(path) == after
    assert "empty_finality_binding_repair" not in caplog.text


def test_known_constructor_only_repair_survives_future_current_build(
    tmp_path, retained_observer, monkeypatch
):
    path = tmp_path / "future-runtime.sqlite3"
    _port(path, retained_observer).close()
    previous = _break_build(path)
    # Simulate imported current build constants advancing in a future release.
    # Recognition must depend on the explicit historical compatibility identity.
    for field in (
        "SOURCE_REVISION",
        "SOURCE_TREE_SHA256",
        "CARGO_LOCK_SHA256",
        "FIXTURE_SET_SHA256",
    ):
        monkeypatch.setattr(supervisor, field, "future-build", raising=False)
    repaired = _port(path, retained_observer)
    repaired.audit()
    assert _metadata(path)["observer_build_binding_repair_original"] == previous
    assert _metadata(path)["config"] == canonical_json_bytes(_CONFIG)


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        ("populated", "retained_observer_build_repair_requires_empty_store"),
        ("digest", "config_digest_mismatch"),
        ("head_missing", "store_meta_missing"),
        ("digest_missing", "store_meta_missing"),
        ("unrelated_policy", "store_binding_mismatch"),
        ("unrelated_limit", "store_binding_mismatch"),
        ("damaged_accounting", "evidence_accounting_corrupt"),
    ],
)
def test_empty_repair_refuses_damaged_or_unrelated_store_without_partial_changes(
    tmp_path, retained_observer, fault, reason
):
    path = tmp_path / "refusal.sqlite3"
    port = _port(path, retained_observer)
    if fault == "populated":
        port.accept_attestation(_BINDING, _parse(retained_observer))
    port.close()
    changes = {}
    if fault == "unrelated_policy":
        changes["scoring_policy_hash"] = "b1" * 32
    if fault == "unrelated_limit":
        changes["startup_timeout_seconds"] = 901
    _break_build(path, **changes)
    with sqlite3.connect(path) as connection:
        if fault == "digest":
            connection.execute(
                "UPDATE store_meta SET value=? WHERE key='config_sha256'", (b"x" * 32,)
            )
        elif fault in ("head_missing", "digest_missing"):
            key = "head_acceptance_digest" if fault == "head_missing" else "config_sha256"
            connection.execute("DELETE FROM store_meta WHERE key=?", (key,))
        elif fault == "damaged_accounting":
            connection.execute("DROP TRIGGER finality_evidence_insert")
    before = _metadata(path)
    inode = path.stat().st_ino
    with pytest.raises(
        (GrandpaFinalityStoreConflict, GrandpaFinalityStoreCorruption), match=reason
    ):
        _port(path, retained_observer)
    assert _metadata(path) == before
    assert path.stat().st_ino == inode
    assert "observer_build_binding_repair_original" not in before
