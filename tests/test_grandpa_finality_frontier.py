"""Actual WAL mutations, startup reuse and interrupted completion publication."""

import json
import logging
import sqlite3
from contextlib import contextmanager

import pytest

from umi.grandpa_finality_frontier import FinalityAuditFrontier, FinalityFrontierError
from umi.grandpa_finality_supervisor import DurableGrandpaFinalityPort

from .test_grandpa_finality_supervisor import (
    _attestation,
    _header,
    _port,
)
from .test_grandpa_finality_supervisor import (
    chain_observation as chain_observation,
)
from .test_grandpa_finality_supervisor import (
    observer as observer,
)


def first(port, observer):
    binding = port.next_run_binding()
    block = _header(10, parent_hash="0x" + "11" * 32, seed=20)
    record = _attestation(observer, binding, block=block, sequence=0, previous=None)
    port.accept_attestation(binding, record)
    return binding, block, record


def test_startup_and_native_append_reuse_completed_history(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    binding, block, record = first(port, observer)
    next_block = _header(11, parent_hash=str(block["hash"]), seed=21)
    following = _attestation(observer, binding, block=next_block, sequence=1, previous=record)

    def no_audit(*args, **kwargs):
        pytest.fail("unchanged retained history was audited again")

    monkeypatch.setattr(DurableGrandpaFinalityPort, "_audit_snapshot", no_audit)
    peer = _port(tmp_path, observer, chain_observation)
    peer.accept_attestation(binding, following)
    assert _port(tmp_path, observer, chain_observation).persisted_head().height == 11
    assert port.persisted_head().height == 11


@pytest.mark.parametrize("damage", ["missing", "malformed", "array", "scalar", "binding"])
def test_lost_completion_is_explicit_repair_then_reused(
    tmp_path, observer, chain_observation, monkeypatch, caplog, damage
):
    port = _port(tmp_path, observer, chain_observation)
    first(port, observer)
    path = port._frontier.record
    if damage == "missing":
        path.unlink()
    elif damage == "malformed":
        path.write_bytes(b"bad")
    elif damage in ("array", "scalar"):
        path.write_bytes(b"[]" if damage == "array" else b"null")
    else:
        value = json.loads(path.read_bytes())
        value["binding"]["semantics"] = "changed"
        from umi.protocol import canonical_json_bytes

        path.write_bytes(canonical_json_bytes(value))
    with caplog.at_level(logging.INFO):
        repaired = _port(tmp_path, observer, chain_observation)
    assert "state=repair_required" in caplog.text
    assert "state=completed completed=1 total=1" in caplog.text
    assert repaired.persisted_head().height == 10
    monkeypatch.setattr(
        DurableGrandpaFinalityPort,
        "_audit_snapshot",
        lambda *a, **k: pytest.fail("completed repair repeated"),
    )
    _port(tmp_path, observer, chain_observation)


def test_commit_before_completion_failure_is_repaired_without_reinserting(
    tmp_path, observer, chain_observation, monkeypatch, caplog
):
    port = _port(tmp_path, observer, chain_observation)
    with monkeypatch.context() as patch:
        patch.setattr(
            port._frontier,
            "publish",
            lambda *a, **k: (_ for _ in ()).throw(RuntimeError("interrupted publication")),
        )
        with pytest.raises(RuntimeError, match="interrupted publication"):
            first(port, observer)
    with caplog.at_level(logging.INFO):
        resumed = _port(tmp_path, observer, chain_observation)
    assert resumed.persisted_head().height == 10
    assert "state=repair_required reason=database_or_wal_changed" in caplog.text
    with resumed._connect(read_only=True) as db:
        assert db.execute("SELECT COUNT(*) FROM finalized_headers").fetchone()[0] == 1


def test_snapshot_cannot_bless_an_unmanaged_write(tmp_path, observer, chain_observation):
    port = _port(tmp_path, observer, chain_observation)
    frontier = port._frontier
    with frontier.owner():
        before = frontier.snapshot()
        with sqlite3.connect(port._path) as db:
            db.execute("INSERT INTO store_meta VALUES ('unmanaged',X'00')")
        with pytest.raises(FinalityFrontierError, match="database_changed_outside_native_owner"):
            frontier.publish(port._config_bytes(), expected_snapshot=before)


def test_completion_publication_rechecks_snapshot(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    frontier = port._frontier
    previous = frontier.record.read_bytes()
    import umi.grandpa_finality_frontier as module

    sync = module.os.fsync
    changed = []

    def mutate(fd):
        sync(fd)
        if not changed:
            changed.append(True)
            with sqlite3.connect(port._path) as db:
                db.execute("INSERT INTO store_meta VALUES ('unmanaged',X'00')")

    with frontier.owner(), monkeypatch.context() as patch:
        snapshot = frontier.snapshot()
        patch.setattr(module.os, "fsync", mutate)
        with pytest.raises(FinalityFrontierError, match="database_changed_during_publication"):
            frontier.publish(port._config_bytes(), expected_snapshot=snapshot)
    assert frontier.record.read_bytes() == previous
    assert not list(frontier.root.glob(".completion-*"))


def test_native_owner_serializes_distinct_instances(tmp_path, observer, chain_observation):
    port = _port(tmp_path, observer, chain_observation)
    peer = FinalityAuditFrontier(port._path, busy_timeout_ms=1)
    with (
        port._frontier.owner(),
        pytest.raises(FinalityFrontierError, match="frontier_owner_busy"),
        peer.owner(),
    ):
        pytest.fail("competing native mutation acquired ownership")


def test_symlink_completion_is_never_followed(tmp_path, observer, chain_observation):
    port = _port(tmp_path, observer, chain_observation)
    target = tmp_path / "unrelated"
    target.write_bytes(b"retain me")
    port._frontier.record.unlink()
    port._frontier.record.symlink_to(target)
    with pytest.raises(Exception, match="unsafe_frontier_path"):
        _port(tmp_path, observer, chain_observation)
    assert target.read_bytes() == b"retain me"


def test_unmanaged_commit_between_native_commit_and_close_is_not_blessed(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    original = port._transaction
    retained = port._frontier.record.read_bytes()

    @contextmanager
    def commit_then_unmanaged_write(db):
        with original(db):
            yield
        with sqlite3.connect(port._path) as other:
            other.execute("INSERT INTO store_meta VALUES ('unmanaged',X'00')")

    monkeypatch.setattr(port, "_transaction", commit_then_unmanaged_write)
    with pytest.raises(Exception, match="database_changed_outside_native_owner"):
        first(port, observer)
    assert port._frontier.record.read_bytes() == retained


def test_rolled_back_native_attempt_keeps_completed_audit(
    tmp_path, observer, chain_observation, monkeypatch
):
    port = _port(tmp_path, observer, chain_observation)
    binding, _block, _record = first(port, observer)
    altered = _attestation(
        observer,
        binding,
        block=_header(10, parent_hash="0x" + "11" * 32, seed=22),
        sequence=0,
        previous=None,
    )
    with pytest.raises(Exception, match="finalized_height_conflict"):
        port.accept_attestation(binding, altered)
    monkeypatch.setattr(
        DurableGrandpaFinalityPort,
        "_audit_snapshot",
        lambda *a, **k: pytest.fail("rolled-back native attempt repeated history audit"),
    )
    assert _port(tmp_path, observer, chain_observation).persisted_head().height == 10
