"""Native checkpoint maintenance preserves proof bytes and audit reuse."""

import json
import sqlite3

import pytest

from umi import grandpa_finality_checkpoint as checkpoint
from umi import grandpa_finality_supervisor as supervisor
from umi.grandpa_finality_supervisor import DurableGrandpaFinalityPort

from .test_grandpa_finality_frontier import first
from .test_grandpa_finality_supervisor import _attestation, _header, _port
from .test_grandpa_finality_supervisor import chain_observation as chain_observation
from .test_grandpa_finality_supervisor import observer as observer


def following(port, observer, binding, previous):
    return _attestation(
        observer,
        binding,
        block=_header(11, parent_hash=previous.block.hash, seed=21),
        sequence=1,
        previous=previous,
    )


def no_audit(*args, **kwargs):
    pytest.fail("owned checkpoint repeated completed native verification")


async def test_owned_checkpoint_preserves_evidence_and_restart_reuse(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    binding, _, original = first(port, observer)
    receipt = await port.verified_acceptance_receipt_at(10)
    monkeypatch.setattr(checkpoint, "CHECKPOINT_BYTES", 1)
    monkeypatch.setattr(DurableGrandpaFinalityPort, "_audit_snapshot", no_audit)
    accepted = following(port, observer, binding, original)
    port.accept_attestation(binding, accepted)
    assert port._path.with_name(port._path.name + "-wal").stat().st_size == 0
    with port._frontier.owner():
        assert port._frontier.inspect(port._config_bytes()) is None
    restarted = _port(tmp_path, observer, chain_observation)
    assert restarted.persisted_head().height == 11
    assert await restarted.verified_acceptance_receipt_at(10) == receipt
    with restarted._connect(read_only=True) as connection:
        rows = connection.execute(
            "SELECT canonical_evidence FROM finalized_headers ORDER BY height"
        ).fetchall()
    assert [row[0] for row in rows] == [original.canonical_bytes, accepted.canonical_bytes]


def test_busy_reader_defers_checkpoint_without_losing_native_completion(
    tmp_path, observer, chain_observation, monkeypatch, caplog
):
    port = _port(tmp_path, observer, chain_observation)
    binding, _, original = first(port, observer)
    monkeypatch.setattr(checkpoint, "CHECKPOINT_BYTES", 1)
    monkeypatch.setattr(DurableGrandpaFinalityPort, "_audit_snapshot", no_audit)
    with port._connect(read_only=True) as reader:
        reader.execute("BEGIN")
        reader.execute("SELECT COUNT(*) FROM finalized_headers").fetchall()
        with caplog.at_level("INFO", logger=checkpoint.__name__):
            port.accept_attestation(binding, following(port, observer, binding, original))
        assert port.persisted_head().height == 11
        with port._frontier.owner():
            assert port._frontier.inspect(port._config_bytes()) is None
    messages = [
        json.loads(record.message)
        for record in caplog.records
        if record.name == checkpoint.__name__
    ]
    assert any(row.get("status") == "retrying" for row in messages)
    # The next native scope retries maintenance without replaying an accepted
    # block, changing its receipt, or retaining a new long-lived connection.
    with port._frontier.owner(), port._native_mutation() as connection:
        assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == port._busy_timeout_ms
    assert port._path.with_name(port._path.name + "-wal").stat().st_size == 0
    assert _port(tmp_path, observer, chain_observation).persisted_head().height == 11


def test_failed_native_body_keeps_original_error_and_verified_head(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    first(port, observer)
    monkeypatch.setattr(checkpoint, "CHECKPOINT_BYTES", 1)
    monkeypatch.setattr(DurableGrandpaFinalityPort, "_audit_snapshot", no_audit)
    error = RuntimeError("native operation rejected")
    with (
        pytest.raises(RuntimeError) as raised,
        port._frontier.owner(),
        port._native_mutation() as connection,
    ):
        connection.execute(
            "UPDATE store_meta SET value=? WHERE key='head_acceptance_digest'", (b"bad",)
        )
        raise error
    assert raised.value is error
    assert _port(tmp_path, observer, chain_observation).persisted_head().height == 10


def test_checkpoint_failure_requires_repair_before_committed_head_reuse(
    tmp_path, observer, chain_observation, monkeypatch, caplog
):
    port = _port(tmp_path, observer, chain_observation)
    binding, _, original = first(port, observer)
    monkeypatch.setattr(checkpoint, "CHECKPOINT_BYTES", 1)

    def denied(connection, path):
        def authorize(action, name, *rest):
            if action == sqlite3.SQLITE_PRAGMA and name == "wal_checkpoint":
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        connection.set_authorizer(authorize)
        try:
            checkpoint.checkpoint_wal(connection, path)
        finally:
            connection.set_authorizer(None)
            assert connection.execute("PRAGMA busy_timeout").fetchone()[0] == port._busy_timeout_ms

    monkeypatch.setattr(supervisor, "checkpoint_wal", denied)
    with (
        caplog.at_level("INFO", logger=checkpoint.__name__),
        pytest.raises(supervisor.GrandpaFinalityStoreCorruption, match="sqlite_write_failed"),
    ):
        port.accept_attestation(binding, following(port, observer, binding, original))
    with port._frontier.owner():
        assert port._frontier.inspect(port._config_bytes()) == "database_or_wal_changed"
    monkeypatch.setattr(supervisor, "checkpoint_wal", checkpoint.checkpoint_wal)
    with caplog.at_level("INFO", logger=supervisor.__name__):
        repaired = _port(tmp_path, observer, chain_observation)
    assert "state=repair_required reason=database_or_wal_changed" in caplog.text
    assert "checkpoint_failed_native_owner_must_resolve_before_reuse" in caplog.text
    assert repaired.persisted_head().height == 11
    monkeypatch.setattr(DurableGrandpaFinalityPort, "_audit_snapshot", no_audit)
    assert _port(tmp_path, observer, chain_observation).persisted_head().height == 11
