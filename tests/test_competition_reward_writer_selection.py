"""Real preparation ownership and kernel exchange; no native authority inferred."""

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest

from umi import competition_reward_history_preparation as preparation
from umi import competition_reward_writer_selection as selection
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_history_preparation import (  # noqa: F401
    activation_case,
    anchor_case,
    boot_inputs,
    chain,
    chain_config,
    control,
    explicit,
    installed_case,
    limits,
    package_case,
    package_limits,
    policy,
    release_identity,
    replay_limits,
    series_case,
    successor_release,
    trusted_ports,
    worker_capacity,
)
from .test_competition_reward_history_preparation import case as staging_case  # noqa: F401


@pytest.fixture
def prepared(staging_case):  # noqa: F811
    case = staging_case
    with case.open():
        pass
    original = (
        Path(case.anchor.config.state_root)
        / "standing-rewards"
        / digest(case.config.series)
        / "history"
    )
    original.mkdir(mode=0o700, parents=True)
    original.parent.chmod(0o700)
    if os.getgid() == 0:
        os.chown(original.parent, os.getuid(), case.approval.service_gid)
        os.chown(original, os.getuid(), case.approval.service_gid)
    for root, marker in ((original, b"original"), (case.root / "history", b"candidate")):
        for name in ("rounds.sqlite3", "rounds.lock"):
            path = root / name
            path.write_bytes(marker)
            path.chmod(0o600)
            if os.getgid() == 0:
                os.chown(path, os.getuid(), case.approval.service_gid)
    case.original = original
    return case


def recover(case):
    return selection.recover_writer_history_selection(
        case.anchor,
        standing_boot=case.boot,
        approval_path=case.path,
        operation="qualified-v1",
    )


def journal(case):
    return selection._journal_path(case.root, "qualified-v1")


def marker(path):
    return (path / "rounds.sqlite3").read_bytes()


def test_exchange_and_context_rollback_keep_original_lease_and_inodes(prepared):
    case = prepared
    original, staged = case.original.stat().st_ino, (case.root / "history").stat().st_ino
    with case.open() as lease:
        binding, scope = lease._binding, lease._lock_bytes
        with selection.hold_writer_history_selection(lease, operation="qualified-v1") as current:
            current.exchange()
            assert current.recheck() == "selected"
            assert case.original.stat().st_ino == staged
            assert (case.root / "history").stat().st_ino == original
            assert marker(case.original) == b"candidate"
            with pytest.raises(preparation.HistoryPreparationError, match="identity changed"):
                lease.recheck()
            assert (lease._binding, lease._lock_bytes) == (binding, scope)
        lease.recheck()
        assert case.original.stat().st_ino == original
        assert (case.root / "history").stat().st_ino == staged
        with pytest.raises(ValueError, match="closed"):
            current.recheck()
    assert recover(case) == "rolled_back"
    assert recover(case) == "rolled_back"


def test_commit_retains_both_directories_and_repeat_recovery_never_rolls_back(prepared, caplog):
    caplog.set_level("INFO", logger=selection.__name__)
    case = prepared
    with (
        case.open() as lease,
        selection.hold_writer_history_selection(lease, operation="qualified-v1") as current,
    ):
        current.exchange()
        current.exchange()
        current.commit()
        current.commit()
        with pytest.raises(ValueError, match="separately qualified"):
            current.rollback()
    assert recover(case) == "committed"
    assert recover(case) == "committed"
    assert marker(case.original) == b"candidate"
    assert marker(case.root / "history") == b"original"
    assert "directory_selection_only_excludes_native_reconciliation_and_rewards" in caplog.text
    assert "'percent': 100.0" in caplog.text


@pytest.mark.parametrize("phase", ["prepared", "exchange_pending", "exchanged", "rollback_pending"])
@pytest.mark.parametrize("swapped", [False, True])
def test_interrupted_selection_recovers_exact_original_mapping(prepared, phase, swapped):
    case = prepared
    with case.open() as lease:
        current = selection.WriterHistorySelection(lease, operation="qualified-v1")
        current._phase(phase)
        if swapped:
            selection._exchange(case.original, case.root / "history")
    assert recover(case) == "rolled_back"
    assert marker(case.original) == b"original"
    assert marker(case.root / "history") == b"candidate"
    with (
        case.open() as lease,
        selection.hold_writer_history_selection(lease, operation="qualified-v1") as resumed,
    ):
        resumed.exchange()
    assert marker(case.original) == b"original"


def test_recovery_cannot_overlap_live_preparation_owner(prepared):
    with prepared.open() as lease:
        selection.WriterHistorySelection(lease, operation="qualified-v1")
        with pytest.raises(BlockingIOError):
            recover(prepared)


def test_forged_or_closed_lease_cannot_start_exchange(prepared):
    with (
        prepared.open() as lease,
        pytest.raises(preparation.HistoryPreparationError, match="altered"),
    ):
        selection.WriterHistorySelection(replace(lease, first_block=0), operation="bad")
    with pytest.raises(preparation.HistoryPreparationError, match="closed"):
        selection.WriterHistorySelection(lease, operation="bad")
    assert not journal(prepared).exists()


def test_database_replacement_refuses_recovery_without_overwriting_either_history(prepared):
    case = prepared
    with case.open() as lease:
        current = selection.WriterHistorySelection(lease, operation="qualified-v1")
        current.exchange()
    database = case.original / "rounds.sqlite3"
    database.rename(database.with_suffix(".retained"))
    database.write_bytes(b"replacement")
    database.chmod(0o600)
    if os.getgid() == 0:
        os.chown(database, os.getuid(), case.approval.service_gid)
    with pytest.raises(ValueError, match="identity changed"):
        recover(case)
    assert marker(case.original) == b"replacement"
    assert marker(case.root / "history") == b"original"


@pytest.mark.parametrize("side", ["original", "staged"])
def test_same_inode_same_length_database_change_refuses_exchange(prepared, side):
    case = prepared
    with case.open() as lease:
        with selection.hold_writer_history_selection(lease, operation="qualified-v1") as current:
            root = case.original if side == "original" else case.root / "history"
            path = root / "rounds.sqlite3"
            inode = path.stat().st_ino
            data = path.read_bytes()
            path.write_bytes(b"x" * len(data))
            assert path.stat().st_ino == inode
            with pytest.raises(ValueError, match="bytes changed"):
                current.exchange()
        lease.recheck()
    assert json.loads(journal(case).read_bytes())["phase"] == "rolled_back"


@pytest.mark.parametrize("sidecar", ["-journal", "-wal", "-shm"])
def test_active_sqlite_sidecar_refuses_before_creating_selection(prepared, sidecar):
    with prepared.open() as lease:
        path = lease.logical_history / ("rounds.sqlite3" + sidecar)
        path.touch(mode=0o600)
        if os.getgid() == 0:
            os.chown(path, os.getuid(), prepared.approval.service_gid)
        with pytest.raises(ValueError, match="quiescent"):
            selection.WriterHistorySelection(lease, operation="qualified-v1")
    assert not journal(prepared).exists()


def test_monitor_allows_candidate_sqlite_activity_but_commit_waits_for_drain(prepared):
    case = prepared
    with (
        case.open() as lease,
        selection.hold_writer_history_selection(lease, operation="qualified-v1") as current,
    ):
        current.exchange()
        path = case.original / "rounds.sqlite3-journal"
        path.touch(mode=0o600)
        if os.getgid() == 0:
            os.chown(path, os.getuid(), case.approval.service_gid)
        assert current.recheck(allow_busy=True) == "selected"
        with pytest.raises(ValueError, match="quiescent"):
            current.commit()
        with pytest.raises(ValueError, match="quiescent"):
            current.rollback()
        path.unlink()
        # Native candidate review may commit metadata under its sole ownership.
        (case.original / "rounds.sqlite3").write_bytes(b"candidate-metadata-repaired")
        current.commit()
    assert recover(case) == "committed"


def test_monitor_refuses_unsafe_candidate_sidecar(prepared):
    case = prepared
    with (
        case.open() as lease,
        selection.hold_writer_history_selection(lease, operation="qualified-v1") as current,
    ):
        current.exchange()
        path = case.original / "rounds.sqlite3-journal"
        path.symlink_to(case.original / "rounds.sqlite3")
        with pytest.raises(ValueError, match="unsafe SQLite"):
            current.recheck(allow_busy=True)
        path.unlink()


@pytest.mark.parametrize("length", [0, 1, 30, None])
def test_unpublished_pending_phase_is_validated_and_recovery_rolls_back(prepared, length):
    case = prepared
    with case.open() as lease:
        current = selection.WriterHistorySelection(lease, operation="qualified-v1")
        current.exchange()
        pending = canonical_json_bytes({**current.value, "phase": "committed"})
        journal(case).with_suffix(".pending").write_bytes(pending[:length])
        journal(case).with_suffix(".pending").chmod(0o600)
    assert recover(case) == "rolled_back"
    assert not journal(case).with_suffix(".pending").exists()
    assert marker(case.original) == b"original"


def test_different_pending_scope_refuses_without_exchange(prepared):
    case = prepared
    with case.open() as lease:
        current = selection.WriterHistorySelection(lease, operation="qualified-v1")
        current.exchange()
    path = journal(case).with_suffix(".pending")
    path.write_bytes(b'{"anchor":"another-installed-owner"}')
    path.chmod(0o600)
    with pytest.raises(ValueError, match="pending history selection differs"):
        recover(case)
    assert marker(case.original) == b"candidate"
    assert path.exists()


@pytest.mark.parametrize("length", [0, 30])
def test_torn_first_journal_publication_resumes_under_genuine_lease(prepared, length, monkeypatch):
    case = prepared
    original_write = selection._write

    def torn(path, value):
        pending = path.with_suffix(".pending")
        pending.write_bytes(canonical_json_bytes(value)[:length])
        pending.chmod(0o600)
        raise OSError("injected first publication interruption")

    with case.open() as lease:
        monkeypatch.setattr(selection, "_write", torn)
        with pytest.raises(OSError, match="first publication"):
            selection.WriterHistorySelection(lease, operation="qualified-v1")
        assert not journal(case).exists()
        assert marker(case.original) == b"original"
        monkeypatch.setattr(selection, "_write", original_write)
        with selection.hold_writer_history_selection(lease, operation="qualified-v1") as current:
            assert current.recheck() == "original"
        lease.recheck()
    assert not journal(case).with_suffix(".pending").exists()


def test_changed_root_sealed_control_refuses_recovery(prepared):
    case = prepared
    with case.open() as lease:
        current = selection.WriterHistorySelection(lease, operation="qualified-v1")
        current.exchange()
    changed = case.approval.model_copy(update={"reason": "different selection"})
    case.save(case.path, canonical_json_bytes(changed))
    with pytest.raises(ValueError, match="scope"):
        recover(case)
    assert marker(case.original) == b"candidate"


def test_exchange_failure_retains_original_mapping_and_resumable_journal(prepared, monkeypatch):
    case = prepared
    with case.open() as lease:
        with (
            pytest.raises(OSError, match="injected"),
            selection.hold_writer_history_selection(lease, operation="qualified-v1") as current,
        ):
            monkeypatch.setattr(
                selection, "_exchange", lambda *_: (_ for _ in ()).throw(OSError("injected"))
            )
            current.exchange()
        lease.recheck()
    assert marker(case.original) == b"original"
    assert json.loads(journal(case).read_bytes())["phase"] == "rolled_back"


def test_uncommitted_native_child_failure_rolls_back_before_context_closes(prepared):
    case = prepared
    with case.open() as lease:
        with (
            pytest.raises(RuntimeError, match="native candidate"),
            selection.hold_writer_history_selection(lease, operation="qualified-v1") as current,
        ):
            current.exchange()
            raise RuntimeError("native candidate reconciliation failed")
        lease.recheck()
    assert marker(case.original) == b"original"
