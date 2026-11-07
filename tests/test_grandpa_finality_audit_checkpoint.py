"""Interrupted native startup audits resume only unchanged verified prefixes."""

import gc
import json
import logging
import multiprocessing
import os
import shutil
import sqlite3
from dataclasses import replace

import pytest

from umi.grandpa_finality_frontier import FinalityAuditCheckpoint
from umi.grandpa_finality_supervisor import (
    DurableGrandpaFinalityPort,
    GrandpaFinalityStoreCorruption,
)

from .test_grandpa_finality_accounting import legacy_database, retained_bytes
from .test_grandpa_finality_supervisor import (
    _audit_history,
    _port,
)
from .test_grandpa_finality_supervisor import (
    chain_observation as chain_observation,
)
from .test_grandpa_finality_supervisor import (
    observer as observer,
)


class InterruptedAudit(RuntimeError):
    pass


@pytest.mark.parametrize("layout", ["current", "schema2", "policy", "capacity"])
def test_process_death_resumes_upgrade_without_rechecking_prefix(
    tmp_path, observer, chain_observation, monkeypatch, layout
):
    port, records = retained_legacy(tmp_path, observer, chain_observation)
    options = {}
    if layout == "schema2":
        legacy_database(port._path)
    elif layout == "policy":
        options = {"scoring_digest": "55" * 32, "predecessor_digests": ("44" * 32,)}
    elif layout == "capacity":
        from umi.grandpa_finality_supervisor import GrandpaFinalitySupervisorLimits

        old = GrandpaFinalitySupervisorLimits(maximum_records_per_process=2)
        options = {
            "limits": replace(old, maximum_database_bytes=old.maximum_database_bytes * 2),
            "predecessor_capacity": old,
        }
    original = retained_bytes(port._path)
    save = FinalityAuditCheckpoint.save

    def child():
        def crash(checkpoint, state):
            save(checkpoint, state)
            if state["completed"] == 3:
                os._exit(73)

        FinalityAuditCheckpoint.save = crash
        _port(tmp_path, observer, chain_observation, **options)

    process = multiprocessing.get_context("fork").Process(target=child)
    process.start()
    try:
        process.join(10)
        assert process.exitcode == 73
    finally:
        if process.is_alive():
            process.kill()
            process.join(5)
        process.close()
    saved = json.loads((port._frontier.root / "audit-progress.json").read_bytes())
    assert saved["state"]["completed"] == 3
    validate, calls = observer.validate_attestation, []

    def remaining(raw, **kwargs):
        assert raw not in [r.canonical_bytes for r in records[:3]]
        calls.append(raw)
        return validate(raw, **kwargs)

    monkeypatch.setattr(observer, "validate_attestation", remaining)
    monkeypatch.setattr(
        DurableGrandpaFinalityPort,
        "_audit_inputs",
        lambda *a, **k: pytest.fail("completed integrity/count work repeated after death"),
    )
    resumed = _port(tmp_path, observer, chain_observation, **options)
    assert len(calls) == 3
    assert resumed.persisted_head().height == records[-1].block.number
    assert retained_bytes(port._path)[1:] == original[1:]
    # Diagnostic readers must not leave writable handles whose eventual
    # collection checkpoints the WAL behind the native completion record.
    gc.collect()
    assert (
        _port(tmp_path, observer, chain_observation, **options).persisted_head()
        == resumed.persisted_head()
    )


def retained_legacy(tmp_path, observer, chain_observation):
    port = _port(tmp_path, observer, chain_observation)
    records = _audit_history(port, observer, segment_lengths=(2, 2, 2))
    shutil.rmtree(port._frontier.root)
    return port, records


def interrupt_at(tmp_path, observer, chain_observation, monkeypatch, completed):
    save = FinalityAuditCheckpoint.save

    def interrupt(checkpoint, state):
        save(checkpoint, state)
        if state["completed"] == completed:
            raise InterruptedAudit("after durable checkpoint")

    with monkeypatch.context() as patch:
        patch.setattr(FinalityAuditCheckpoint, "save", interrupt)
        with pytest.raises(InterruptedAudit):
            _port(tmp_path, observer, chain_observation)


@pytest.mark.parametrize("completed", [0, 1, 2, 3, 4, 6])
def test_restart_skips_completed_integrity_and_rows(
    tmp_path, observer, chain_observation, monkeypatch, completed, caplog
):
    port, records = retained_legacy(tmp_path, observer, chain_observation)
    interrupt_at(tmp_path, observer, chain_observation, monkeypatch, completed)
    saved = json.loads((port._frontier.root / "audit-progress.json").read_bytes())
    assert saved["state"]["completed"] == completed
    assert "canonical_evidence" not in str(saved)
    validate = observer.validate_attestation
    calls = []

    def remaining(raw, **kwargs):
        calls.append(raw)
        assert raw not in [r.canonical_bytes for r in records[:completed]]
        return validate(raw, **kwargs)

    with monkeypatch.context() as patch, caplog.at_level(logging.INFO):
        patch.setattr(observer, "validate_attestation", remaining)
        patch.setattr(
            DurableGrandpaFinalityPort,
            "_audit_inputs",
            lambda *a, **k: pytest.fail("completed snapshot integrity/count work repeated"),
        )
        resumed = _port(tmp_path, observer, chain_observation)
    assert len(calls) == len(records) - completed
    assert resumed.persisted_head().height == records[-1].block.number
    assert f"reused={completed}" in caplog.text


def test_change_before_resume_rejects_corrupt_completed_prefix(
    tmp_path, observer, chain_observation, monkeypatch, caplog
):
    port, records = retained_legacy(tmp_path, observer, chain_observation)
    interrupt_at(tmp_path, observer, chain_observation, monkeypatch, 3)
    with sqlite3.connect(port._path) as db:
        db.execute(
            "UPDATE finalized_headers SET state_root=? WHERE height=?",
            ("0x" + "99" * 32, records[0].block.number),
        )
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(GrandpaFinalityStoreCorruption, match="normalized_header_mismatch"),
    ):
        _port(tmp_path, observer, chain_observation)
    assert "audit_checkpoint_database_changed" in caplog.text
    assert not port._frontier.record.exists()


@pytest.mark.parametrize("damage", ["missing", "checksum", "malformed", "state"])
def test_damaged_partial_checkpoint_runs_reported_repair(
    tmp_path, observer, chain_observation, monkeypatch, caplog, damage
):
    port, records = retained_legacy(tmp_path, observer, chain_observation)
    interrupt_at(tmp_path, observer, chain_observation, monkeypatch, 3)
    path = port._frontier.root / "audit-progress.json"
    value = json.loads(path.read_bytes())
    import hashlib

    from umi.protocol import canonical_json_bytes

    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"[]")
    else:
        value["state"]["completed"] = 8
        if damage == "state":
            value["state_sha256"] = hashlib.sha256(canonical_json_bytes(value["state"])).hexdigest()
        path.write_bytes(canonical_json_bytes(value))
    validate, calls = observer.validate_attestation, []

    def counted(raw, **kwargs):
        calls.append(raw)
        return validate(raw, **kwargs)

    with monkeypatch.context() as patch, caplog.at_level(logging.INFO):
        patch.setattr(observer, "validate_attestation", counted)
        resumed = _port(tmp_path, observer, chain_observation)
    assert len(calls) == len(records)
    assert resumed.persisted_head().height == records[-1].block.number
    assert "requires_repair" in caplog.text or "repair_required" in caplog.text
