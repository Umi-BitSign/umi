"""Real selected config/locks/journals; provider and review ports are synthetic."""

import asyncio
import fcntl
import json
import logging
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_cutover_cli as cli
from umi import competition_reward_cutover_ownership as ownership
from umi import competition_reward_cutover_runtime as runtime
from umi.competition_reward_control_journal import RewardControlTransactionJournal
from umi.competition_reward_decisions import StandingRewardControlReader
from umi.competition_reward_history import RewardControlHistoryReader
from umi.competition_reward_signing import RewardDecisionJournal
from umi.open_competition import digest

from .test_competition_reward_coordinator_boot import chain as chain
from .test_competition_reward_coordinator_boot import chain_config as chain_config
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_coordinator_boot import control as control
from .test_competition_reward_coordinator_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import policy as policy
from .test_competition_reward_coordinator_boot import series_case as series_case


def components(config):
    """Establish an installed fixture before testing a no-create owner."""
    root = Path(config.state_directory) / digest(config.series)
    root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    root.mkdir(mode=0o700, exist_ok=True)
    chain = digest(config.chain)
    reader = StandingRewardControlReader(
        root / "control",
        config.series,
        config.policy,
        expected_series_sha256=digest(config.series),
        expected_chain_config_sha256=chain,
        maximum_bytes=config.maximum_reader_bytes,
        reward_adoptions=config.reward_adoptions,
    )
    history = RewardControlHistoryReader(
        root / "history",
        control_hotkey=config.series.control_hotkey,
        chain_config_sha256=chain,
        first_block=config.series.recovery.authority.issued_at_block,
        maximum_bytes=config.maximum_history_bytes,
    )
    decisions = RewardDecisionJournal(
        root / "decisions",
        config.series,
        config.policy,
        config.signer_hotkey,
        expected_chain_config_sha256=chain,
        maximum_bytes=config.service.maximum_journal_bytes,
        reward_adoptions=config.reward_adoptions,
    )
    transactions = RewardControlTransactionJournal(
        root / "transactions",
        config.series,
        config_sha256=chain,
        maximum_bytes=config.service.maximum_journal_bytes,
    )
    for path in (
        root / "service.lock",
        root.parent / "control-writer.lock",
        root / "transactions/control-writer.lock",
    ):
        path.touch(mode=0o600, exist_ok=True)
    return root, reader, history, decisions, transactions


@pytest.mark.parametrize("which", [0, 1, 2])
def test_existing_process_lock_contention_does_not_open_old_state(config_case, which):
    config = config_case.config
    root, *_ = components(config)
    paths = (
        root / "service.lock",
        root.parent / "control-writer.lock",
        root / "transactions/control-writer.lock",
    )
    before = {p: p.stat().st_ino for p in root.rglob("rounds.sqlite3")}
    fd = os.open(paths[which], os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(BlockingIOError), ownership.hold_reward_cutover_owner(config):
            pytest.fail("busy owner entered")
    finally:
        os.close(fd)
    assert before == {p: p.stat().st_ino for p in root.rglob("rounds.sqlite3")}
    with ownership.hold_reward_cutover_owner(config) as lease:
        lease.recheck(config)
        # Native compound locks remain usable while all process owners are fenced.
        for _, journal in (
            ("history", components(config)[2]),
            ("decisions", components(config)[3]),
        ):
            with journal.journal.locked():
                pass


def test_missing_state_refused_without_recreation_and_closed_lease_invalid(config_case):
    config = config_case.config
    root, *_ = components(config)
    with ownership.hold_reward_cutover_owner(config) as lease:
        lease.recheck(config)
    with pytest.raises(ValueError, match="live coordinator"):
        lease.recheck(config)
    missing = root / "decisions/rounds.sqlite3"
    missing.unlink()
    with pytest.raises(FileNotFoundError), ownership.hold_reward_cutover_owner(config):
        pytest.fail("missing original accepted")
    assert not missing.exists()


def test_replaced_path_and_forged_lease_rejected(config_case):
    config = config_case.config
    root, *_ = components(config)
    with ownership.hold_reward_cutover_owner(config) as lease:
        with pytest.raises(ValueError, match="live coordinator"):
            ownership.RewardCutoverLease(root, digest(config), {}, (), None).recheck(config)
        old = root / "service.lock"
        old.rename(root / "old-lock")
        old.touch(mode=0o600)
        with pytest.raises(ValueError, match=r"identity changed|lock was replaced"):
            lease.recheck(config)


@pytest.mark.parametrize("mode", ["success", "error", "cancel", "progress"])
async def test_runtime_cleanup_is_inside_genuine_lease_no_publishing(
    config_case, monkeypatch, mode
):
    config = config_case.config
    root, *_ = components(config)
    events, started = [], asyncio.Event()

    def locked():
        with pytest.raises(BlockingIOError), ownership.hold_reward_cutover_owner(config):
            pytest.fail("owner lost")

    class Provider:
        def __init__(self, *args, **kwargs):
            locked()
            events.append("construct")
            self.config = config.chain

        async def start(self):
            locked()
            events.append("start")

        def ensure_observer_running(self):
            locked()

        async def current_finalized_block(self):
            return config.chain.minimum_finalized_block

    class Review:
        def __init__(self, **kwargs):
            kwargs["lease"].recheck(config)
            assert type(kwargs["history"]) is RewardControlHistoryReader
            assert kwargs["provider"].__class__ is Provider

        async def step(self, cohort):
            locked()
            started.set()
            events.append("review")
            if mode == "progress" and events.count("review") == 1:
                return {"status": "historical_recovery_progress", "publication_authorized": False}
            if mode == "cancel":
                await asyncio.Event().wait()
            if mode == "error":
                raise ValueError("synthetic review failure")
            return {"status": "reconciled", "publication_authorized": False}

    async def close(provider):
        locked()
        events.append("closed")

    monkeypatch.setattr(runtime, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(runtime, "NativeRewardCutoverReview", Review)
    monkeypatch.setattr(runtime, "_close_provider", close)
    work = asyncio.create_task(
        runtime.reconcile_reward_cutover(
            config_case.path,
            cohort=digest(config.series.cohorts[0]),
            operation="fixture-v1",
        )
    )
    if mode == "cancel":
        await started.wait()
        work.cancel()
        with pytest.raises(asyncio.CancelledError):
            await work
    elif mode == "error":
        with pytest.raises(ValueError, match="synthetic"):
            await work
    else:
        result = await work
        assert not result["publication_authorized"]
        assert not result["publishing_roles_started"]
        assert not result["service_restart_performed"]
    assert events == [
        "construct",
        "start",
        "review",
        *(["review"] if mode == "progress" else []),
        "closed",
    ]
    with ownership.hold_reward_cutover_owner(config):
        pass
    assert not (root / "transactions").joinpath("signed").exists()


async def test_original_missing_migration_fails_before_provider(config_case, monkeypatch):
    config = config_case.config
    root, *_ = components(config)
    selection = {
        "owner_uid": os.getuid(),
        "paths": {"service_root": str(root)},
        "series_sha256": digest(config.series),
        "policy_sha256": digest(config.policy),
        "chain_config_sha256": digest(config.chain),
        "configuration": {"sha256": digest(config)},
    }
    # Only the independent root/kernel provenance port is replaced.
    monkeypatch.setattr(ownership, "load_provenance", lambda _: selection)
    monkeypatch.setattr(ownership, "validate_provenance", lambda *a, **k: None)
    monkeypatch.setattr(
        runtime,
        "HistoricalRewardControlProvider",
        lambda *a, **k: pytest.fail("provider opened before migration"),
    )
    with pytest.raises(ValueError, match="completed-admission migration"):
        await runtime.reconcile_reward_cutover(
            config_case.path,
            cohort=digest(config.series.cohorts[0]),
            operation="fixture-v1",
            original_owner_selection=Path("fixture-only.json"),
        )
    selection["configuration"]["sha256"] = "00" * 32
    with (
        pytest.raises(ValueError, match="selected original owner"),
        ownership.hold_reward_cutover_owner(config, original_owner_selection=Path("fixture")),
    ):
        pytest.fail("changed configuration accepted")


def test_cli_only_reports_error_type(config_case, monkeypatch, capsys):
    async def fail(_):
        raise ValueError("wss://private.example/?credential=do-not-print")

    monkeypatch.setattr(cli, "_run", fail)
    with pytest.raises(SystemExit):
        cli.main(
            ["--config", str(config_case.path), "--cohort", "aa" * 32, "--operation", "fixture-v1"]
        )
    value = json.loads(capsys.readouterr().out)
    assert value == {
        "status": "repair_required",
        "error_type": "ValueError",
        "publication_authorized": False,
    }


def test_cli_interruption_is_not_reported_as_success(monkeypatch, capsys):
    async def interrupted(_):
        return None

    monkeypatch.setattr(cli, "_run", interrupted)
    with pytest.raises(SystemExit) as result:
        cli.main(["--config", "/fixture/config", "--cohort", "aa" * 32, "--operation", "fixture"])
    assert result.value.code == 130
    assert json.loads(capsys.readouterr().out)["status"] == "interrupted"


async def test_initial_finality_retries_only_missing_head_and_keeps_selected_budget(
    monkeypatch, caplog
):
    caplog.set_level(logging.INFO, logger=runtime.__name__)
    config = SimpleNamespace(minimum_finalized_block=5, startup_timeout_seconds=1800)
    calls = []

    async def observed():
        calls.append("observed")
        if len(calls) == 1:
            raise runtime.GrandpaFinalitySupervisorError("no_verified_finalized_head")
        return 5

    async def pause(_):
        pass

    monkeypatch.setattr(runtime.asyncio, "sleep", pause)
    provider = SimpleNamespace(
        config=config,
        ensure_observer_running=lambda: None,
        current_finalized_block=observed,
    )
    assert await runtime._await_initial_finality(provider) == 5
    assert len(calls) == 2
    events = [r.args for r in caplog.records if r.msg == "reward_cutover_initial_finality %s"]
    assert [v["state"] for v in events] == ["pending", "completed"]
    assert events[-1]["eta_seconds"] == 0 and events[-1]["percent"] == 100

    async def corrupt():
        raise runtime.GrandpaFinalitySupervisorError("fixture_corrupt_history")

    provider.current_finalized_block = corrupt
    with pytest.raises(runtime.GrandpaFinalitySupervisorError):
        await runtime._await_initial_finality(provider)
