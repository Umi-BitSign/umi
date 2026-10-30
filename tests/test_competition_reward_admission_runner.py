"""No-launch runner ownership with isolated configuration/provider ports.

The migration port explicitly models its original-lock lifetime and enters the
runner's real provider factory. Native proof, journal, root-seal and kernel-lock
qualification remains in test_competition_reward_admission_migration; these
tests do not manufacture a native migration result or qualify a deployment.
"""

import asyncio
import copy
import logging
import threading
from contextlib import contextmanager
from types import SimpleNamespace

import pytest

from umi import competition_reward_admission_runner as runner
from umi import competition_reward_coordinator_boot as boot
from umi import competition_reward_service as service
from umi.competition_reward_admission_migration import CompletedAdmissionMigration
from umi.competition_reward_executor import StandingRewardExecutor
from umi.competition_reward_history_checkpoint import HistoryCheckpointRepairRequired
from umi.open_competition import digest

from .logging_helpers import progress_payloads


@pytest.fixture
def isolated_runner(tmp_path, monkeypatch):
    """Substitute external ports while keeping actual thread/cancellation ownership."""
    config = SimpleNamespace(
        series={"selected_series": True},
        policy={"selected_policy": True},
        chain={"cache_bytes": 29 * 1024**2, "state_directory": str(tmp_path / "chain-cache")},
        state_directory=str(tmp_path / "original-state"),
        runtime_proof_reads=True,
        host_memory_admission=object(),
        maximum_history_bytes=19 * 1024**3,
        maximum_header_bytes=23 * 1024**2,
        maximum_header_database_bytes=31 * 1024**2,
        maximum_package_bytes=7 * 1024**3,
    )
    root = tmp_path / "original-state" / digest(config.series)
    selection = {
        "owner_uid": 993,
        "configuration": {"path": str(tmp_path / "original-root-config.json")},
        "paths": {"service_root": str(root)},
    }
    h = SimpleNamespace(
        config=config,
        root=root,
        selection=selection,
        selection_path=tmp_path / "root-sealed-selection.json",
        events=[],
        locked=False,
        memory_active=False,
        providers=[],
        provider_arguments=None,
        memory_arguments=None,
        migration_arguments=None,
        source_error=None,
        start_error=None,
        migration_error=None,
        factory_selection=None,
        constructor_hook=None,
        close_hook=None,
    )
    monkeypatch.setattr(runner, "os", SimpleNamespace(getuid=lambda: 993, geteuid=lambda: 993))

    def load(path):
        assert path == h.selection_path
        h.events.append("selection_read")
        return selection

    def validate(value, *, require_stopped):
        assert value is selection and require_stopped is True
        h.events.append("original_stopped_selection_checked")

    def load_config(path):
        assert str(path) == selection["configuration"]["path"]
        h.events.append("selected_config_read")
        return config

    def read_source(value):
        assert h.locked and value is selection
        h.events.append("source_read_under_locks")
        if h.source_error:
            raise h.source_error
        return {"fixture_only": True}

    @contextmanager
    def memory(selection, **kwargs):
        assert h.locked and not h.memory_active
        h.memory_arguments = selection, kwargs
        h.memory_active = True
        h.events.append("memory_enter")
        try:
            yield
        finally:
            assert h.locked
            h.events.append("memory_exit")
            h.memory_active = False

    class Provider:
        def __init__(self, *args, **kwargs):
            assert h.locked and h.memory_active
            h.events.append("provider_construct_enter")
            h.provider_arguments = args, kwargs
            self.started = self.closed = False
            h.providers.append(self)
            if h.constructor_hook:
                h.constructor_hook()
            h.events.append("provider_construct_return")

        async def start(self):
            assert h.locked and h.memory_active
            h.events.append("provider_start")
            if h.start_error:
                raise h.start_error
            self.started = True

        async def aclose(self):
            assert h.locked and h.memory_active and not self.closed
            h.events.append("provider_close_enter")
            if h.close_hook:
                await h.close_hook()
            assert h.locked and h.memory_active
            self.closed = True
            h.events.append("provider_close_return")

    async def migrate(path, *, provider_factory, series, policy, maximum_history_bytes):
        assert path == h.selection_path and not h.locked
        h.migration_arguments = series, policy, maximum_history_bytes
        h.locked = True
        h.events.append("original_locks_enter")
        try:
            selected = h.factory_selection if h.factory_selection is not None else selection
            async with provider_factory(selected) as provider:
                assert provider is h.providers[0] and provider.started
                h.events.append("migration_body")
                if h.migration_error:
                    raise h.migration_error
                return CompletedAdmissionMigration(
                    checkpoint={"fixture_only": True},
                    reconciliation={
                        "status": "stopped_owner_economics_reconciliation_required",
                        "publication_authorized": False,
                    },
                )
        finally:
            h.events.append("original_locks_exit")
            h.locked = False

    def publishing_forbidden(*args, **kwargs):
        pytest.fail("no-launch admission runner constructed or started a publishing role")

    for cls in (
        boot.StandingRewardCoordinator,
        boot.StandingRewardDecisionReviewer,
        boot.StandingControlPublisher,
        boot.RewardDecisionJournal,
        boot.RewardDecisionSigner,
        StandingRewardExecutor,
    ):
        monkeypatch.setattr(cls, "__init__", publishing_forbidden)
    monkeypatch.setattr(boot, "run_reward_coordinator", publishing_forbidden)
    monkeypatch.setattr(boot, "load_named_hotkey", publishing_forbidden)
    monkeypatch.setattr(service, "run_standing_reward_service", publishing_forbidden)
    monkeypatch.setattr(runner, "load_provenance", load)
    monkeypatch.setattr(runner, "validate_provenance", validate)
    monkeypatch.setattr(runner, "load_reward_coordinator_config", load_config)
    monkeypatch.setattr(runner, "read_admission_source", read_source)
    monkeypatch.setattr(runner, "memory_runtime", memory)
    monkeypatch.setattr(runner, "HistoricalRewardControlProvider", Provider)
    monkeypatch.setattr(runner, "migrate_completed_admission", migrate)
    return h


@pytest.mark.parametrize("uid_port", ["getuid", "geteuid"])
async def test_wrong_original_uid_refuses_before_config_provider_or_migration(
    isolated_runner, monkeypatch, uid_port
):
    h = isolated_runner
    monkeypatch.setattr(runner.os, uid_port, lambda: 0)
    with pytest.raises(HistoryCheckpointRepairRequired, match="original service UID"):
        await runner.run_original_admission_migration(h.selection_path)
    assert h.events == ["selection_read"]
    assert not h.providers and not h.locked


async def test_selected_config_limits_and_provider_lifetime_remain_owned(
    isolated_runner, caplog, http_log_redaction
):
    h = isolated_runner
    caplog.set_level(logging.INFO, logger=runner.__name__)
    result = await runner.run_original_admission_migration(h.selection_path)
    assert h.provider_arguments == (
        (h.config.chain, h.config.policy),
        {
            "runtime_proof_reads": True,
            "historical_header_directory": h.root / "headers",
            "historical_header_maximum_bytes": h.config.maximum_header_bytes,
            "historical_header_database_maximum_bytes": h.config.maximum_header_database_bytes,
        },
    )
    assert h.provider_arguments[0][0] is h.config.chain
    assert h.memory_arguments == (
        h.config.host_memory_admission,
        {"maximum_aggregate_bytes": h.config.maximum_package_bytes, "role": "reward_coordinator"},
    )
    assert h.migration_arguments == (
        h.config.series,
        h.config.policy,
        h.config.maximum_history_bytes,
    )
    assert result["inherited_limits"] == {
        name: getattr(h.config, name)
        for name in (
            "maximum_history_bytes",
            "maximum_header_bytes",
            "maximum_header_database_bytes",
            "maximum_package_bytes",
        )
    }
    assert result["reconciliation"]["publication_authorized"] is False
    assert result["reconciliation"]["status"] == ("stopped_owner_economics_reconciliation_required")
    assert result["publishing_roles_started"] is result["service_restart_performed"] is False
    assert result["owner_uid"] == 993 and result["elapsed_seconds"] >= 0
    assert h.events == [
        "selection_read",
        "original_stopped_selection_checked",
        "selected_config_read",
        "original_locks_enter",
        "source_read_under_locks",
        "memory_enter",
        "provider_construct_enter",
        "provider_construct_return",
        "provider_start",
        "migration_body",
        "provider_close_enter",
        "provider_close_return",
        "memory_exit",
        "original_locks_exit",
    ]
    assert h.providers[0].closed and not h.locked and not h.memory_active
    progress = progress_payloads(
        caplog.records, logger=runner.__name__, event="reward_admission_runner_progress"
    )
    assert [p["completed_items"] for p in progress] == [0, 1, 2, 3]
    assert progress[-1]["eta_seconds"] == 0
    assert all(
        p["eta_scope"] == "migration_runner_excludes_tail_and_economics_reconciliation"
        for p in progress
    )


@pytest.mark.parametrize("changed", ["root", "locked_selection", "missing_completion"])
async def test_changed_binding_or_missing_completion_refuses_before_provider(
    isolated_runner, changed
):
    h = isolated_runner
    if changed == "root":
        h.config.state_directory += "-replacement"
    elif changed == "locked_selection":
        h.factory_selection = copy.deepcopy(h.selection)
        h.factory_selection["owner_uid"] += 1
    else:
        h.source_error = HistoryCheckpointRepairRequired("native completion missing")
    with pytest.raises(HistoryCheckpointRepairRequired):
        await runner.run_original_admission_migration(h.selection_path)
    assert not h.providers and h.memory_arguments is None and not h.locked


@pytest.mark.parametrize("failure", ["start_error", "migration_error"])
async def test_provider_closes_before_unlock_after_start_or_migration_failure(
    isolated_runner, failure
):
    h = isolated_runner
    setattr(h, failure, RuntimeError("isolated failure"))
    with pytest.raises(RuntimeError, match="isolated failure"):
        await runner.run_original_admission_migration(h.selection_path)
    assert h.providers[0].closed
    assert h.events[-4:] == [
        "provider_close_enter",
        "provider_close_return",
        "memory_exit",
        "original_locks_exit",
    ]
    assert not h.locked and not h.memory_active


async def test_cancelled_blocking_constructor_drains_close_before_releasing_locks(
    isolated_runner,
):
    h = isolated_runner
    entered, closing, finish_close = (asyncio.Event() for _ in range(3))
    finish_constructor = threading.Event()
    loop = asyncio.get_running_loop()

    def blocked_constructor():
        loop.call_soon_threadsafe(entered.set)
        if not finish_constructor.wait(5):
            raise TimeoutError("test did not release its constructor")

    async def blocked_close():
        closing.set()
        await finish_close.wait()

    h.constructor_hook, h.close_hook = blocked_constructor, blocked_close
    task = asyncio.create_task(runner.run_original_admission_migration(h.selection_path))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and h.locked and h.memory_active
        finish_constructor.set()
        await asyncio.wait_for(closing.wait(), timeout=5)
        assert not task.done() and h.locked and not h.providers[0].closed
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and h.locked
        finish_close.set()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=5)
        assert h.providers[0].closed and not h.providers[0].started
        assert "migration_body" not in h.events
        assert h.events[-5:] == [
            "provider_construct_return",
            "provider_close_enter",
            "provider_close_return",
            "memory_exit",
            "original_locks_exit",
        ]
        assert not h.locked and not h.memory_active
    finally:
        finish_constructor.set()
        finish_close.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
