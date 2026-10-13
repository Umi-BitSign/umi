"""Exclusive repair CLI assembly; no chain endpoint or deployed state is touched."""

import asyncio
import json
import os
import signal
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_reward_coordinator_cli as cli
from umi import competition_reward_history_repair as repair
from umi.competition_reward_coordinator_ownership import owned_reward_state
from umi.competition_reward_handoff_models import StandingRewardHandoffPlan
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.competition_reward_history_workers import HistoryVerificationProfile
from umi.open_competition import digest
from umi.private_files import PrivateStateBusyError, ensure_private_directory, lock_private_file

from .test_competition_reward_coordinator_boot import chain as chain
from .test_competition_reward_coordinator_boot import chain_config as chain_config
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_competition_reward_coordinator_boot import control as control
from .test_competition_reward_coordinator_boot import inputs as inputs
from .test_competition_reward_coordinator_boot import policy as policy
from .test_competition_reward_coordinator_boot import series_case as series_case
from .test_competition_reward_decisions import successor_series


def with_predecessor(old):
    successor = successor_series(old.series)
    manifest = old.manifest.model_copy(
        update={
            "cohorts": tuple(
                requirement.model_copy(update={"cohort_sha256": digest(plan)})
                for requirement, plan in zip(old.manifest.cohorts, successor.cohorts, strict=False)
            )
        }
    )
    successor = successor.model_copy(update={"manifest_sha256": digest(manifest)})
    handoff = StandingRewardHandoffPlan(
        schema="umi-standing-reward-handoff-plan/1",
        series_sha256=digest(successor),
        cohort_sha256=digest(successor.cohorts[0]),
        predecessor=successor.predecessor,
    )
    return type(old).model_validate(
        old.model_dump(by_alias=True)
        | dict(
            schema="umi-reward-coordinator-config/3",
            series=successor,
            manifest=manifest,
            handoff=handoff,
            predecessor_series=old.series,
            predecessor_manifest=old.manifest,
            predecessor_eligibility=old.eligibility,
        )
    )


@pytest.mark.parametrize("lock", ["service", "control_writer"])
async def test_repair_refuses_live_owner_before_any_history_or_provider_read(
    config_case, monkeypatch, lock
):
    config = config_case.config
    root = Path(config.state_directory) / digest(config.series)
    ensure_private_directory(root)
    path = root / "service.lock" if lock == "service" else root.parent / "control-writer.lock"
    descriptor = lock_private_file(path)

    def forbidden(*args, **kwargs):
        pytest.fail("repair inspected state before obtaining exclusive ownership")

    monkeypatch.setattr(repair, "RewardControlHistoryReader", forbidden)
    monkeypatch.setattr(repair, "selected_proof_archives", forbidden)
    monkeypatch.setattr(repair, "HistoricalRewardControlProvider", forbidden)
    monkeypatch.setattr(Path, "is_file", forbidden)
    try:
        with pytest.raises(PrivateStateBusyError):
            await repair.run_reward_history_repair(
                config, asyncio.Event(), through_block=200, reason="retained source restored"
            )
    finally:
        os.close(descriptor)
    with owned_reward_state(config):
        pass  # Failed ownership must release any earlier acquired service lock.


@pytest.mark.parametrize("role", ["coordinator", "reviewer"])
def test_successor_ownership_excludes_predecessor_and_releases_all_locks(config_case, role):
    original = config_case.config
    config = SimpleNamespace(
        state_directory=original.state_directory,
        role=role,
        series=successor_series(original.series),
        predecessor_series=original.series,
    )
    old_root = Path(config.state_directory) / digest(original.series)
    with owned_reward_state(config), pytest.raises(PrivateStateBusyError):
        lock_private_file(old_root / "service.lock")
    descriptor = lock_private_file(old_root / "service.lock")
    try:
        with pytest.raises(PrivateStateBusyError), owned_reward_state(config):
            pytest.fail("successor overlapped a predecessor owner")
    finally:
        os.close(descriptor)
    with owned_reward_state(config):
        pass


@pytest.mark.parametrize("failure", [None, "metadata", "start", "repair"])
@pytest.mark.parametrize("selection", ["current", "predecessor"])
async def test_repair_uses_original_bindings_no_keys_and_closes_provider(
    config_case, monkeypatch, caplog, failure, selection
):
    config = config_case.config if selection == "current" else with_predecessor(config_case.config)
    history_profile = HistoryVerificationProfile(schema="umi-history-verification-profile/1")
    config = config.model_copy(
        update={
            "service": config.service.model_copy(update={"history_verification": history_profile})
        }
    )
    selected_series = config.series if selection == "current" else config.predecessor_series
    root = Path(config.state_directory) / digest(selected_series)
    owner_root = Path(config.state_directory) / digest(config.series)
    ensure_private_directory(root)
    ensure_private_directory(root / "history")
    (root / "history" / "rounds.sqlite3").touch(mode=0o600)
    providers, arguments = [], []

    class Request:
        sha256 = "11" * 32

        def __init__(self, reader, target, reason):
            assert target == 200 and reason == "original restored"

        def finish(self, history):
            pass  # Native intent/result persistence is qualified by consuming tests.

    class Reader:
        def __init__(self, selected, **kwargs):
            assert selected == root / "history"
            assert kwargs["chain_config_sha256"] == digest(config.chain)
            assert kwargs["control_hotkey"] == selected_series.control_hotkey
            assert kwargs["first_block"] == selected_series.recovery.authority.issued_at_block
            assert kwargs["maximum_bytes"] == config.maximum_history_bytes
            assert kwargs["repair_record_capacity"] is True
            assert kwargs["verification_profile"] == history_profile
            with pytest.raises(PrivateStateBusyError):
                lock_private_file(root / "service.lock")
            if failure == "metadata":
                raise HistoryCheckpointRepairRequired("original identity metadata lost")
            self.progress = SimpleNamespace(latest={})

        async def repair_checkpoints(self, provider, **kwargs):
            assert provider.started
            arguments.append(kwargs)
            if failure == "repair":
                raise ValueError("unsupported retained source")
            self.progress.latest = {
                "state": "completed",
                "completed_blocks": 51,
                "total_blocks": 51,
                "percent": 100.0,
                "eta_seconds": 0.0,
                "eta_basis": "complete_selected_history_interval",
                "elapsed_seconds": 1.0,
                "native_completed": 1,
                "restored_completed": 50,
            }
            return SimpleNamespace(history=object())

    class Provider:
        def __init__(self, chain, policy, **kwargs):
            assert chain == config.chain and policy == config.policy
            assert kwargs["historical_header_directory"] == owner_root / "headers"
            assert kwargs["runtime_proof_reads"] == config.runtime_proof_reads
            self.started = self.closed = False
            providers.append(self)

        async def start(self):
            if failure == "start":
                raise OSError("private provider URL must not escape")
            self.started = True

        async def aclose(self):
            self.closed = True

    def forbidden(*args, **kwargs):
        pytest.fail("repair must never load a signing key")

    monkeypatch.setattr("umi.competition_reward_coordinator_boot.load_named_hotkey", forbidden)
    monkeypatch.setattr(repair, "RewardControlHistoryReader", Reader)
    monkeypatch.setattr(repair, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(repair, "HistoryRepairRequest", Request)
    with caplog.at_level("INFO"):
        if failure:
            expected = OSError if failure == "start" else ValueError
            with pytest.raises(expected):
                await repair.run_reward_history_repair(
                    config,
                    asyncio.Event(),
                    through_block=200,
                    reason="original restored",
                    history=selection,
                )
        else:
            result = await repair.run_reward_history_repair(
                config,
                asyncio.Event(),
                through_block=200,
                reason="original restored",
                history=selection,
            )
            assert result["status"] == "history_repaired" and result["percent"] == 100
            assert result["reason"] == "original restored"
            assert arguments == [
                dict(
                    through_block=200,
                    reason="original restored",
                    maximum_blocks=config.service.maximum_history_blocks,
                )
            ]
    assert all(provider.closed for provider in providers)
    with owned_reward_state(config):
        pass
    events = [
        json.loads(record.args[0]) for record in caplog.records if record.name == repair.__name__
    ]
    assert events[0]["planning_eta_seconds"] == [5, 120]
    assert "planning_assumption" in events[0]["eta_basis"]
    if failure == "metadata":
        assert not providers and events[-1]["state"] == "repair_required"
        assert events[-1]["percent"] is None and events[-1]["eta_seconds"] is None


async def test_missing_original_journal_is_not_created_by_repair(config_case):
    config = config_case.config
    with pytest.raises(FileNotFoundError, match="existing original"):
        await repair.run_reward_history_repair(
            config, asyncio.Event(), through_block=200, reason="restore supported journal"
        )
    root = Path(config.state_directory) / digest(config.series)
    assert not (root / "history").exists()


@pytest.mark.parametrize(
    "options",
    [
        {"reason": " "},
        {"through_block": True},
        {"through_block": 1},
        {"history": "predecessor"},
        {"history": "unknown"},
    ],
)
async def test_unsupported_scope_refuses_before_owner_state(config_case, options):
    config = config_case.config
    with pytest.raises(ValueError):
        await repair.run_reward_history_repair(
            config, asyncio.Event(), **(dict(through_block=200, reason="restored") | options)
        )
    assert not Path(config.state_directory).exists()


@pytest.mark.parametrize("options", [[], ["--through-block", "200"], ["--reason", "restored"]])
def test_cli_repair_requires_explicit_scope_and_reason(config_case, options):
    with pytest.raises(SystemExit) as error:
        cli.main(["repair-history", "--config", str(config_case.path), *options])
    assert error.value.code == 2


@pytest.mark.parametrize("action", ["check", "run"])
def test_cli_repair_options_cannot_silently_change_other_actions(config_case, action):
    with pytest.raises(SystemExit) as error:
        cli.main([action, "--config", str(config_case.path), "--reason", "restored"])
    assert error.value.code == 2


def test_cli_routes_scoped_repair_and_reports_safe_metadata_failure(
    config_case, monkeypatch, capsys
):
    calls = []

    async def run(config, *, repair):
        calls.append((config, repair))
        if len(calls) == 2:
            raise HistoryCheckpointRepairRequired("https://secret.invalid/?token=private")
        return {"status": "history_repaired", "percent": 100}

    monkeypatch.setattr(cli, "_run", run)
    command = [
        "repair-history",
        "--config",
        str(config_case.path),
        "--through-block",
        "200",
        "--reason",
        "original restored",
    ]
    cli.main(command)
    assert json.loads(capsys.readouterr().out) == {"status": "history_repaired", "percent": 100}
    assert calls == [
        (
            config_case.config,
            dict(
                through_block=200,
                reason="original restored",
                history="current",
            ),
        )
    ]
    with pytest.raises(SystemExit) as error:
        cli.main(command)
    assert error.value.code == 1
    assert json.loads(capsys.readouterr().out) == dict(
        status="repair_required",
        error_type="HistoryCheckpointRepairRequired",
        recovery="restore_original_metadata_and_source_in_place_no_reset",
    )


async def test_repair_signal_drains_owned_work_before_releasing_handlers(monkeypatch):
    loop, handlers, events = asyncio.get_running_loop(), {}, []

    async def run(config, stop, **kwargs):
        events.append("started")
        handlers[signal.SIGTERM]()
        try:
            await asyncio.Event().wait()
        finally:
            await asyncio.sleep(0)
            events.append("drained")

    def remove(signum):
        assert events == ["started", "drained"]
        del handlers[signum]

    monkeypatch.setattr(loop, "add_signal_handler", lambda sig, cb: handlers.update({sig: cb}))
    monkeypatch.setattr(loop, "remove_signal_handler", remove)
    monkeypatch.setattr(cli, "run_reward_history_repair", run)
    assert await cli._run(object(), repair=dict(through_block=200, reason="restored")) is None
    assert not handlers
