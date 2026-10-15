"""Early native-resource refusal and diagnostic-only execution regressions."""

import asyncio
import hashlib
import json
import logging
import os
import sys
from types import SimpleNamespace

import pytest

from umi import competition_chain_resource_preflight as preflight
from umi.competition_chain_resources import CompetitionChainResources
from umi.concurrency import run_owned_thread
from umi.pinned_artifact import PinnedArtifactError
from umi.runtime_metadata import RuntimeMetadataError, RuntimeMetadataExecutor

_EMPTY_REJECTION = "import sys; print('code_size_limit', file=sys.stderr); raise SystemExit(1)"


def binary(tmp_path, body=_EMPTY_REJECTION):
    path = tmp_path / "native-runtime"
    path.write_text(f"#!{sys.executable}\n{body}\n")
    path.chmod(0o500)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def executor(tmp_path, **kwargs):
    path, pin = binary(tmp_path, kwargs.pop("body", _EMPTY_REJECTION))
    return RuntimeMetadataExecutor(binary_path=path, expected_sha256=pin, **kwargs)


def test_runtime_probe_does_not_mint_execution_or_verification_cache(tmp_path):
    runtime = executor(tmp_path)
    assert runtime.preflight() is None
    assert not runtime._executed and runtime._executed_bytes == 0


@pytest.mark.parametrize("damage", ["placeholder", "changed", "nonexecutable", "missing"])
def test_runtime_probe_rejects_damaged_artifact_before_execution(tmp_path, damage):
    marker = tmp_path / "executed"
    runtime = executor(tmp_path, body=f"open({str(marker)!r}, 'w').close(); raise SystemExit(1)")
    path = runtime.binary_path
    path.chmod(0o600)
    if damage == "placeholder":
        path.write_bytes(b"")
    elif damage == "changed":
        path.write_bytes(path.read_bytes() + b"# changed\n")
        path.chmod(0o500)
    elif damage == "missing":
        path.unlink()
    with pytest.raises(RuntimeMetadataError):
        runtime.preflight()
    assert not marker.exists()
    assert not runtime._executed


@pytest.mark.parametrize(
    "body",
    [
        "raise SystemExit(0)",
        "raise SystemExit(1)",
        "raise SystemExit(127)",
        "import sys; print('resource_limit_failed', file=sys.stderr); raise SystemExit(1)",
        "import os, signal; os.kill(os.getpid(), signal.SIGTERM)",
    ],
)
def test_runtime_probe_requires_normal_empty_input_refusal(tmp_path, body):
    with pytest.raises(RuntimeMetadataError, match="runtime_preflight_response_invalid"):
        executor(tmp_path, body=body).preflight()


def test_runtime_probe_timeout_reaps_native_process(tmp_path):
    marker = tmp_path / "pid"
    runtime = executor(
        tmp_path,
        timeout_seconds=0.2,
        body=(
            f"import os, time\nopen({str(marker)!r}, 'w').write(str(os.getpid()))\ntime.sleep(60)"
        ),
    )
    with pytest.raises(RuntimeMetadataError, match="runtime_preflight_timeout"):
        runtime.preflight()
    pid = int(marker.read_text())
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


@pytest.mark.asyncio
async def test_cancel_waits_for_owned_probe_and_retains_no_execution_fact(tmp_path):
    started, finished = tmp_path / "started", tmp_path / "finished"
    runtime = executor(
        tmp_path,
        body=(
            f"import time\nopen({str(started)!r}, 'w').close()\ntime.sleep(0.2)\n"
            f"open({str(finished)!r}, 'w').close()\n{_EMPTY_REJECTION}"
        ),
    )
    task = asyncio.create_task(run_owned_thread(runtime.preflight))
    async with asyncio.timeout(5):
        while not started.exists():
            await asyncio.sleep(0.005)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert finished.exists()
    assert not runtime._executed


@pytest.fixture
def resources(tmp_path, monkeypatch):
    runtime, pin = binary(tmp_path)
    # Finality's own policy-pin tests cover its native constructor. This port
    # isolates orchestration while proof/runtime/static metadata checks stay real.
    monkeypatch.setattr(preflight.GrandpaFinalityObserver, "from_policy_pin", lambda *a, **k: None)
    paths = CompetitionChainResources(
        finality_binary=str(runtime),
        chain_spec=str(tmp_path / "chain-spec"),
        proof_binary=str(runtime),
        runtime_metadata_binary=str(runtime),
        state_directory=str(tmp_path / "state"),
    )
    config = SimpleNamespace(
        finality_pin=None,
        target_triple="x86_64-unknown-linux-gnu",
        proof_binary_sha256=pin,
        runtime_metadata_binary_sha256=pin,
        runtime_metadata_binary=str(runtime),
        storage_codec_metadata_path=None,
        chain_pin=SimpleNamespace(metadata_sha256="a" * 64),
    )
    return paths, config


def events(caplog):
    return [
        json.loads(record.message)
        for record in caplog.records
        if record.name == "umi.competition.progress"
    ]


@pytest.mark.asyncio
async def test_success_reports_complete_scoped_diagnostic_progress(resources, caplog):
    paths, config = resources
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    result = await preflight.preflight_chain_resources(config, paths)
    assert result == {"native_artifacts_checked": 4, "chain_submission_authorized": False}
    last = events(caplog)[-1]
    assert last["completed"] == last["total"] == 4
    assert last["state"] == "completed" and last["eta_seconds"] == 0
    assert last["eta_scope"] == "native_resource_preflight_only"


@pytest.mark.asyncio
async def test_late_runtime_placeholder_refuses_before_success(resources, tmp_path, caplog):
    paths, config = resources
    placeholder = tmp_path / "placeholder"
    placeholder.touch(mode=0o600)
    paths = paths.model_copy(update={"runtime_metadata_binary": str(placeholder)})
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    with pytest.raises(RuntimeMetadataError, match="binary_not_executable"):
        await preflight.preflight_chain_resources(config, paths)
    last = events(caplog)[-1]
    assert last["state"] == "interrupted" and last["completed"] == 3
    assert last["eta_seconds"] is None and last["planning_eta_seconds"] is None
    assert not any(event["state"] == "completed" for event in events(caplog))


@pytest.mark.asyncio
async def test_legacy_static_metadata_is_checked_without_runtime_mode(resources, tmp_path):
    paths, config = resources
    metadata = tmp_path / "metadata"
    metadata.write_bytes(b"retained static codec")
    metadata.chmod(0o600)
    config.runtime_metadata_binary = None
    config.storage_codec_metadata_path = str(metadata)
    config.chain_pin.metadata_sha256 = hashlib.sha256(metadata.read_bytes()).hexdigest()
    paths = paths.model_copy(
        update={
            "runtime_metadata_binary": None,
            "storage_codec_metadata_path": str(metadata),
        }
    )
    result = await preflight.preflight_chain_resources(config, paths)
    assert result["native_artifacts_checked"] == 4
    metadata.write_bytes(b"changed static codec")
    with pytest.raises(PinnedArtifactError, match="mismatch"):
        await preflight.preflight_chain_resources(config, paths)


@pytest.mark.asyncio
async def test_resource_override_cannot_switch_verification_mode(resources, monkeypatch):
    paths, config = resources
    paths = paths.model_copy(update={"runtime_metadata_binary": None})
    monkeypatch.setattr(
        preflight.GrandpaFinalityObserver,
        "from_policy_pin",
        lambda *a, **k: pytest.fail("started artifact work before mode validation"),
    )
    with pytest.raises(ValueError, match="verification mode"):
        await preflight.preflight_chain_resources(config, paths)


async def test_static_metadata_parent_symlink_fails_the_consumers_exact_path_rule(
    resources, tmp_path
):
    paths, config = resources
    directory = tmp_path / "real"
    directory.mkdir(mode=0o700)
    metadata = directory / "metadata"
    metadata.write_bytes(b"retained codec")
    metadata.chmod(0o600)
    alias = tmp_path / "alias"
    alias.symlink_to(directory, target_is_directory=True)
    config.runtime_metadata_binary = None
    config.storage_codec_metadata_path = str(alias / "metadata")
    config.chain_pin.metadata_sha256 = hashlib.sha256(metadata.read_bytes()).hexdigest()
    paths = paths.model_copy(
        update={
            "runtime_metadata_binary": None,
            "storage_codec_metadata_path": config.storage_codec_metadata_path,
        }
    )
    with pytest.raises(ValueError, match="must not traverse symlinks"):
        await preflight.preflight_chain_resources(config, paths)


async def test_stalled_preflight_withdraws_planning_eta_and_cancels_heartbeat(
    resources, monkeypatch, caplog
):
    paths, config = resources
    now, callbacks, timers = [0.0], [], []

    class Timer:
        cancelled = False

        def cancel(self):
            self.cancelled = True

    class Loop:
        def call_later(self, seconds, callback):
            assert seconds == 30
            callbacks.append(callback)
            timer = Timer()
            timers.append(timer)
            return timer

    monkeypatch.setattr(preflight, "time", SimpleNamespace(monotonic=lambda: now[0]))
    monkeypatch.setattr(preflight, "asyncio", SimpleNamespace(get_running_loop=Loop))

    def slow_local_read(*args, **kwargs):
        now[0] = 61
        callbacks.pop(0)()

    monkeypatch.setattr(preflight.GrandpaFinalityObserver, "from_policy_pin", slow_local_read)
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    await preflight.preflight_chain_resources(config, paths)
    values = [json.loads(record.message) for record in caplog.records]
    stalled = next(value for value in values if value["state"] == "stalled")
    assert stalled["planning_eta_seconds"] is None
    assert stalled["eta_seconds"] is None and stalled["eta_basis"] == "withdrawn"
    assert stalled["completed"] == 0 and stalled["stalled"] is True
    assert values[-1]["state"] == "completed" and values[-1]["eta_seconds"] == 0
    assert timers[-1].cancelled
