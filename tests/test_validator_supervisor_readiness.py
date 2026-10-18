from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from tests.test_validator_supervisor_adapters import _config
from umi.validator_supervisor_adapters import (
    RootlessPodmanWorkerAdapter,
    ValidatorSupervisorAdapterError,
)
from umi.validator_supervisor_readiness import wait_for_worker_readiness


@pytest.mark.asyncio
async def test_real_delayed_container_creation_is_allowed_until_identity_checked(tmp_path: Path):
    started = asyncio.get_running_loop().time()
    activation = SimpleNamespace(directive_sha256="ab" * 32, mode="translation_weights")
    process = SimpleNamespace(returncode=None)
    progress = []
    directive_sha = activation.directive_sha256

    async def command(arguments, **_kwargs):
        elapsed = asyncio.get_running_loop().time() - started
        if "inspect" in arguments:
            if elapsed < 0.05:
                raise ValidatorSupervisorAdapterError("podman_command_failed")
            return json.dumps(
                [
                    {
                        "State": {"Running": True, "Status": "running"},
                        "Config": {
                            "Labels": {
                                "vision.umi.supervisor.directive-sha256": directive_sha,
                                "vision.umi.supervisor.mode": activation.mode,
                            }
                        },
                    }
                ]
            ).encode()
        assert "ps" in arguments
        return b"[]"

    adapter = RootlessPodmanWorkerAdapter(_config(tmp_path), command_runner=command)
    adapter._expected_activation = activation
    adapter._process = process
    assert await wait_for_worker_readiness(
        probe=adapter._worker_readiness,
        process_exited=lambda: process.returncode is not None,
        budget_seconds=1,
        progress=progress.append,
    )
    assert progress[-1]["completed"] == 1
    assert progress[-1]["eta_seconds"] == 0
    assert progress[-1]["elapsed_seconds"] >= 0.05


@pytest.mark.asyncio
@pytest.mark.parametrize("status", ["configured", "created", "initialized"])
async def test_matching_created_container_can_finish_starting(tmp_path: Path, status: str):
    activation = SimpleNamespace(directive_sha256="ab" * 32, mode="translation_weights")
    probes = 0

    async def command(_arguments, **_kwargs):
        nonlocal probes
        probes += 1
        return json.dumps(
            [
                {
                    "State": {
                        "Running": probes > 1,
                        "Status": status if probes == 1 else "running",
                    },
                    "Config": {
                        "Labels": {
                            "vision.umi.supervisor.directive-sha256": activation.directive_sha256,
                            "vision.umi.supervisor.mode": activation.mode,
                        }
                    },
                }
            ]
        ).encode()

    adapter = RootlessPodmanWorkerAdapter(_config(tmp_path), command_runner=command)
    adapter._expected_activation = activation
    adapter._process = SimpleNamespace(returncode=None)
    assert await wait_for_worker_readiness(
        probe=adapter._worker_readiness,
        process_exited=lambda: False,
        budget_seconds=1,
        progress=lambda _v: None,
    )
    assert probes == 2


@pytest.mark.asyncio
async def test_wrong_running_worker_identity_refuses_without_retry(tmp_path: Path):
    probes = 0

    async def command(_arguments, **_kwargs):
        nonlocal probes
        probes += 1
        return json.dumps(
            [
                {
                    "State": {"Running": True},
                    "Config": {
                        "Labels": {
                            "vision.umi.supervisor.directive-sha256": "ff" * 32,
                            "vision.umi.supervisor.mode": "translation_weights",
                        }
                    },
                }
            ]
        ).encode()

    adapter = RootlessPodmanWorkerAdapter(_config(tmp_path), command_runner=command)
    adapter._expected_activation = SimpleNamespace(
        directive_sha256="ab" * 32, mode="translation_weights"
    )
    adapter._process = SimpleNamespace(returncode=None)
    progress = []
    assert not await wait_for_worker_readiness(
        probe=adapter._worker_readiness,
        process_exited=lambda: False,
        budget_seconds=30,
        progress=progress.append,
    )
    assert probes == 1
    assert progress[-1]["status"] == "refused"


@pytest.mark.asyncio
async def test_exited_launcher_is_not_retried():
    async def probe():
        raise AssertionError("must not probe after process exit")

    assert not await wait_for_worker_readiness(
        probe=probe, process_exited=lambda: True, budget_seconds=30, progress=lambda _v: None
    )


@pytest.mark.asyncio
async def test_stuck_creation_has_visible_terminal_refusal():
    progress = []

    async def probe():
        return "starting"

    assert not await wait_for_worker_readiness(
        probe=probe, process_exited=lambda: False, budget_seconds=0.02, progress=progress.append
    )
    assert progress[-1]["elapsed_seconds"] >= 0.02
    assert progress[-1]["stalled"] is True
    assert progress[-1]["completed"] == 0


@pytest.mark.asyncio
async def test_cancelled_startup_leaves_cleanup_to_runtime_owner():
    entered = asyncio.Event()

    async def probe():
        entered.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(
        wait_for_worker_readiness(
            probe=probe, process_exited=lambda: False, budget_seconds=30, progress=lambda _v: None
        )
    )
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_unresponsive_probe_is_cancelled_at_startup_budget():
    cancelled = asyncio.Event()

    async def probe():
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    assert not await wait_for_worker_readiness(
        probe=probe,
        process_exited=lambda: False,
        budget_seconds=0.02,
        progress=lambda _v: None,
    )
    assert cancelled.is_set()
