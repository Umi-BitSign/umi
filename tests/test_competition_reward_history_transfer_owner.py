"""Actual stopped-owner leases; synthetic systemd/container ports from installed fixtures."""

import asyncio
import fcntl
import json
import logging
import os
import threading
from dataclasses import replace
from types import SimpleNamespace

import pytest

from umi import competition_reward_history_transfer_owner as transfer
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_round_journal import RoundJournal
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import config_case
from .test_competition_reward_cutover_runtime import components
from .test_competition_reward_decisions import (
    chain as chain,
)
from .test_competition_reward_decisions import (
    control as control,
)
from .test_competition_reward_decisions import (
    series_case as series_case,
)
from .test_competition_reward_writer_reconciliation import (
    activation_case as activation_case,
)
from .test_competition_reward_writer_reconciliation import (
    anchor_case as anchor_case,
)
from .test_competition_reward_writer_reconciliation import (
    chain_config as chain_config,
)
from .test_competition_reward_writer_reconciliation import (
    explicit as explicit,
)
from .test_competition_reward_writer_reconciliation import (
    limits as limits,
)
from .test_competition_reward_writer_reconciliation import (
    owner_case as owner_case,
)
from .test_competition_reward_writer_reconciliation import (
    package_case as package_case,
)
from .test_competition_reward_writer_reconciliation import (
    package_limits as package_limits,
)
from .test_competition_reward_writer_reconciliation import (
    policy as policy,
)
from .test_competition_reward_writer_reconciliation import (
    release_identity as release_identity,
)
from .test_competition_reward_writer_reconciliation import (
    replay_limits as replay_limits,
)
from .test_competition_reward_writer_reconciliation import (
    signed_case as signed_case,
)
from .test_competition_reward_writer_reconciliation import (
    successor_release as successor_release,
)
from .test_competition_reward_writer_reconciliation import (
    trusted_ports as trusted_ports,
)
from .test_competition_reward_writer_reconciliation import (
    worker_capacity as worker_capacity,
)
from .test_competition_reward_writer_review import selected_boot as selected_boot


@pytest.fixture
def pair(selected_boot, tmp_path):
    writer, boot = selected_boot
    source_input = SimpleNamespace(
        value=boot.value, path=tmp_path / "coordinator.json", save=boot.save, c=boot.c
    )
    source = config_case.__wrapped__(source_input, tmp_path)
    source_root, _, source_history, _, _ = components(source.config)
    target_root = writer.root / "standing-rewards" / digest(boot.value.series)
    target_root.parent.mkdir(mode=0o700)
    target_root.mkdir(mode=0o700)
    target_history = RewardControlHistoryReader(
        target_root / "history",
        control_hotkey=boot.value.series.control_hotkey,
        chain_config_sha256=digest(boot.value.chain),
        first_block=boot.value.series.recovery.authority.issued_at_block,
        maximum_bytes=boot.value.maximum_history_bytes,
    )
    RoundJournal(target_root / "control", {"fixture": "control"}, maximum_bytes=8 * 1024**2)
    lock = target_root.parent / "standing-writer.lock"
    lock.write_bytes(b"original writer lock")
    lock.chmod(0o600)
    return SimpleNamespace(
        writer=writer,
        boot=boot,
        source=source,
        source_root=source_root,
        target_root=target_root,
        source_history=source_history,
        target_history=target_history,
        writer_lock=lock,
    )


def hold(p):
    return transfer.hold_history_transfer_owner(
        p.writer.anchor,
        unit=p.writer.unit,
        config_path=p.writer.config_path,
        standing_boot=p.boot.path,
        coordinator_config=p.source.path,
    )


async def test_root_preparsed_source_survives_drop_without_revisiting_signer_path(
    pair, monkeypatch
):
    p = pair
    monkeypatch.setattr(transfer, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0))
    selected = transfer.prepare_history_transfer_source(p.source.path)
    monkeypatch.setattr(transfer, "os", SimpleNamespace(getuid=lambda: 993, geteuid=lambda: 993))
    monkeypatch.setattr(
        transfer,
        "load_reward_coordinator_config",
        lambda path: pytest.fail("configuration path validators repeated after privilege drop"),
    )
    async with transfer.hold_history_transfer_owner(
        p.writer.anchor,
        unit=p.writer.unit,
        config_path=p.writer.config_path,
        standing_boot=p.boot.path,
        coordinator_config=selected,
    ) as owner:
        owner.recheck(p.source_history, p.target_history)
    assert selected.recheck() == p.source.config


def test_preparsed_source_refuses_nonroot_forgery_and_changed_config(pair, monkeypatch):
    p = pair
    monkeypatch.setattr(transfer, "os", SimpleNamespace(getuid=lambda: 993, geteuid=lambda: 993))
    with pytest.raises(ValueError, match="requires root"):
        transfer.prepare_history_transfer_source(p.source.path)
    monkeypatch.setattr(transfer, "os", SimpleNamespace(getuid=lambda: 0, geteuid=lambda: 0))
    selected = transfer.prepare_history_transfer_source(p.source.path)
    for changed in (
        replace(selected, _issuer=None),
        replace(selected, raw_sha256="f" * 64),
        replace(selected, config=p.source.config.model_copy(update={"maximum_history_bytes": 1})),
    ):
        with pytest.raises(ValueError, match="absent or altered"):
            changed.recheck()
    p.source.path.chmod(0o644)
    p.source.path.write_bytes(p.source.path.read_bytes() + b"\n")
    p.source.path.chmod(0o444)
    with pytest.raises(ValueError, match="configuration changed"):
        selected.recheck()


async def test_actual_pair_is_bound_to_original_readers_and_closes(pair, caplog):
    p = pair
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    originals = [
        (root.stat().st_ino, (root / "rounds.sqlite3").stat().st_ino)
        for root in (p.source_history.journal.root, p.target_history.journal.root)
    ]
    async with hold(p) as owner:
        owner.recheck(p.source_history, p.target_history)
        rows = [
            json.loads(r.getMessage())
            for r in caplog.records
            if r.name == "umi.competition.progress"
        ]
        preparation = [r for r in rows if r.get("stage") == "history_transfer_owner_preparation"]
        assert preparation[-1]["status"] == "completed"
        assert preparation[-1]["completed_units"] == 7
        assert preparation[-1]["eta_seconds"] == 0
        assert preparation[0]["planning_eta_seconds"]

        with pytest.raises(ValueError, match="outside"):
            owner.recheck(p.target_history, p.source_history)
        forged = replace(owner, context_sha256="a" * 64)
        with pytest.raises(ValueError, match="original stopped"):
            forged.recheck()
    with pytest.raises(ValueError, match="original stopped"):
        owner.recheck()
    assert originals == [
        (root.stat().st_ino, (root / "rounds.sqlite3").stat().st_ino)
        for root in (p.source_history.journal.root, p.target_history.journal.root)
    ]


@pytest.mark.parametrize("which", ["source", "writer"])
async def test_active_owner_refused_before_opening_history(pair, which):
    p = pair
    path = p.source_root / "service.lock" if which == "source" else p.writer_lock
    before = [
        (root / "rounds.sqlite3").read_bytes()
        for root in (p.source_history.journal.root, p.target_history.journal.root)
    ]
    fd = os.open(path, os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError):
            async with hold(p):
                pytest.fail("live owner passed transfer boundary")
    finally:
        os.close(fd)
    assert before == [
        (root / "rounds.sqlite3").read_bytes()
        for root in (p.source_history.journal.root, p.target_history.journal.root)
    ]


async def test_changed_root_configuration_refuses_during_transfer(pair):
    p = pair
    async with hold(p) as owner:
        p.source.save(p.source.path, b" " + canonical_json_bytes(p.source.config))
        with pytest.raises(ValueError, match="configuration changed"):
            owner.recheck()
        p.source.save(p.source.path, canonical_json_bytes(p.source.config))


@pytest.mark.parametrize("field", transfer._CONTEXT)
def test_each_authority_context_component_must_match(pair, field):
    p = pair
    target = SimpleNamespace(
        **{name: getattr(p.boot.value, name) for name in transfer._CONTEXT},
        predecessor_series=None,
        proof_stores=None,
    )
    setattr(target, field, {"changed": True})
    with pytest.raises(ValueError, match="configuration differs"):
        transfer.matching_history_context(p.source.config, target)


def test_remote_alias_selection_refuses_before_transfer(pair):
    p = pair
    source = p.source.config.model_copy(update={"proof_stores": {"remote": "unqualified"}})
    with pytest.raises(ValueError, match="remote source aliases"):
        transfer.matching_history_context(source, p.boot.value)


def preparation_events(caplog, stage):
    result = []
    for record in caplog.records:
        if record.name != "umi.competition.progress":
            continue
        try:
            value = json.loads(record.getMessage())
        except ValueError:
            continue
        if value.get("stage") == stage:
            result.append(value)
    return result


async def test_owner_and_reader_preparation_have_complete_scoped_progress(pair, caplog):
    from umi.competition_reward_history_transfer_runtime import _open_readers
    from umi.concurrency import run_owned_thread

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    async with hold(pair) as owner:
        owners = preparation_events(caplog, "history_transfer_owner_preparation")
        assert owners[0]["planning_eta_seconds"] == [0.07, 210.0]
        assert owners[-1]["status"] == "completed"
        assert owners[-1]["completed_units"] == owners[-1]["total_units"] == 7
        assert owners[-1]["eta_seconds"] == 0
        source, target = await run_owned_thread(_open_readers, owner)
        owner.recheck(source, target)
        readers = preparation_events(caplog, "history_transfer_reader_preparation")
        assert readers[0]["planning_eta_seconds"] == [0.03, 900.0]
        assert readers[-1]["status"] == "completed"
        assert readers[-1]["completed_units"] == readers[-1]["total_units"] == 3
        assert readers[-1]["eta_seconds"] == 0
    assert preparation_events(caplog, "history_transfer_owner_preparation") == owners
    assert preparation_events(caplog, "history_transfer_reader_preparation") == readers


async def test_owner_preparation_stall_withdraws_eta_and_finishes_after_resume(
    pair, monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    monkeypatch.setattr(transfer.TransferProgress, "heartbeat_seconds", 0.01)
    monkeypatch.setattr(transfer.TransferProgress, "stalled_seconds", 0.02)
    started, release = threading.Event(), threading.Event()
    original = transfer.load_reward_coordinator_config

    def delayed(path):
        started.set()
        assert release.wait(10), "test did not release configuration load"
        return original(path)

    monkeypatch.setattr(transfer, "load_reward_coordinator_config", delayed)

    async def prepare():
        async with hold(pair) as owner:
            owner.recheck()

    task = asyncio.create_task(prepare())
    try:
        assert await asyncio.to_thread(started.wait, 10)
        await asyncio.sleep(0.06)
        pending = preparation_events(caplog, "history_transfer_owner_preparation")
        stalled = [value for value in pending if value["status"] == "stalled"]
        assert stalled and all(value["eta_seconds"] is None for value in stalled)
        assert all(value["eta_basis"] == "withdrawn_stalled_or_retrying" for value in stalled)
        release.set()
        await task
    finally:
        release.set()
        await asyncio.gather(task, return_exceptions=True)
    assert (
        preparation_events(caplog, "history_transfer_owner_preparation")[-1]["status"]
        == "completed"
    )


async def test_reader_preparation_failure_exposes_retry_without_completed_scope(
    pair, monkeypatch, caplog
):
    from umi import competition_reward_history_transfer_runtime as runtime
    from umi.concurrency import run_owned_thread

    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    original = runtime.RewardControlHistoryReader

    def fail_second(root, **kwargs):
        if root == pair.target_history.journal.root:
            raise ValueError("fixture reader preparation failure")
        return original(root, **kwargs)

    monkeypatch.setattr(runtime, "RewardControlHistoryReader", fail_second)
    async with hold(pair) as owner:
        with pytest.raises(ValueError, match="preparation failure"):
            await run_owned_thread(runtime._open_readers, owner)
        owner.recheck()
    rows = preparation_events(caplog, "history_transfer_reader_preparation")
    assert rows[-1]["status"] == "retrying"
    assert rows[-1]["completed_units"] == 1
    assert rows[-1]["eta_seconds"] is None
    assert not any(value["status"] == "completed" for value in rows)
