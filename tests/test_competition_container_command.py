"""Real pipe concurrency, bounded safe diagnostics and cancellation ownership."""

import asyncio
import json
import sys

import pytest

from umi import competition_container as containers
from umi import competition_progress as progress


@pytest.fixture
def command_case(monkeypatch):
    events, processes = [], []
    spawn = asyncio.create_subprocess_exec
    program = {}

    async def selected(*args, **kwargs):
        child = await spawn(sys.executable, "-c", program["code"], **kwargs)
        processes.append(child)
        return child

    monkeypatch.setattr(asyncio, "create_subprocess_exec", selected)
    monkeypatch.setattr(progress, "_emit", lambda body, **_: events.append(body))
    return program, events, processes


async def run_command(*, output=1024 * 1024, timeout=10):
    return await containers._run_command(
        ("/usr/bin/podman", containers.PODMAN_CGROUP_MANAGER_ARGUMENT, "start", "private-argv"),
        timeout_seconds=timeout,
        maximum_output_bytes=output,
    )


@pytest.mark.parametrize("exit_code", [0, 125])
async def test_real_concurrent_output_is_drained_and_only_classifications_escape(
    command_case, monkeypatch, exit_code
):
    program, events, processes = command_case
    monkeypatch.setenv("PRIVATE_CREDENTIAL", "private-environment")
    program["code"] = (
        "import os, threading\n"
        "assert 'PRIVATE_CREDENTIAL' not in os.environ\n"
        "def out():\n"
        " for _ in range(256): os.write(1, b'x' * 1024)\n"
        "def err():\n"
        " os.write(2, b'slirp4netns: cannot mount tmpfs on /tmp; create_sandbox failed; '"
        "b'Authorization: Bearer private-bearer; AWS_SECRET_ACCESS_KEY=private-key; '"
        "b'https://private-origin/?token=private-token; private-argv\\n')\n"
        " for _ in range(1024): os.write(2, b'z' * 1024)\n"
        "a=threading.Thread(target=out); b=threading.Thread(target=err)\n"
        "a.start(); b.start(); a.join(); b.join()\n"
        f"raise SystemExit({exit_code})\n"
    )
    if exit_code:
        with pytest.raises(containers.SuccessorContainerError, match="exit 125"):
            await run_command()
        event = events[-1]
        assert event["command"] == "start" and event["returncode"] == 125
        assert event["reason_codes"] == ["tmpfs_mount_failed", "network_sandbox_failed"]
        assert event["components"] == ["slirp4netns"]
        assert event["observed_bytes"] > 1024 * 1024
        assert event["classified_bytes"] == 16384 and event["truncated"]
        assert event["elapsed_ms"] >= 0
        assert "private-" not in json.dumps(events)
    else:
        assert await run_command() == b"x" * (256 * 1024)
        assert events == []
    assert processes[0].returncode == exit_code


@pytest.mark.parametrize("fault", ["stdout_bound", "timeout", "cancelled"])
async def test_real_child_and_reader_tasks_are_owned_through_failures(command_case, fault):
    program, events, processes = command_case
    before = asyncio.all_tasks()
    program["code"] = (
        "import os, time\n"
        "while True:\n"
        " os.write(1, b'x' * 4096); os.write(2, b'private-token' * 4096)\n"
        " time.sleep(0.001)\n"
    )
    task = asyncio.create_task(
        run_command(
            output=16 if fault == "stdout_bound" else 2**24,
            timeout=0.1 if fault == "timeout" else 10,
        )
    )
    if fault == "cancelled":
        while not processes:
            await asyncio.sleep(0.001)
        task.cancel("private-cancellation")
    expected = {
        "stdout_bound": containers.SuccessorContainerError,
        "timeout": asyncio.TimeoutError,
        "cancelled": asyncio.CancelledError,
    }[fault]
    with pytest.raises(expected):
        await task
    assert processes[0].returncode is not None
    assert asyncio.all_tasks() <= before
    assert events[-1]["outcome"] == ("failed" if fault == "stdout_bound" else fault)
    assert "private-" not in json.dumps(events)


async def test_repeated_cancellation_cannot_abandon_reaping(command_case, monkeypatch):
    program, events, processes = command_case
    program["code"] = "import time; time.sleep(60)"
    entered, release = asyncio.Event(), asyncio.Event()
    reap = containers.kill_and_reap

    async def delayed_reap(process):
        entered.set()
        await release.wait()
        return await reap(process)

    monkeypatch.setattr(containers, "kill_and_reap", delayed_reap)
    task = asyncio.create_task(run_command())
    while not processes:
        await asyncio.sleep(0.001)
    task.cancel()
    await entered.wait()
    task.cancel()
    await asyncio.sleep(0)
    assert not task.done()
    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert processes[0].returncode is not None
    assert events[-1]["outcome"] == "cancelled"


async def test_cancellation_before_collector_starts_still_reaps_child(command_case, monkeypatch):
    program, events, processes = command_case
    program["code"] = "import time; time.sleep(60)"

    async def cancelled_before_start(coroutine, **_):
        coroutine.close()
        raise asyncio.CancelledError

    monkeypatch.setattr(containers, "wait_for_owned", cancelled_before_start)
    with pytest.raises(asyncio.CancelledError):
        await run_command()
    assert processes[0].returncode is not None
    assert events[-1]["outcome"] == "cancelled"


async def test_broken_diagnostic_sink_cannot_replace_command_failure(command_case, monkeypatch):
    program, events, processes = command_case
    program["code"] = "raise SystemExit(125)"

    def unavailable(*_, **__):
        raise RuntimeError("private-diagnostic-error")

    monkeypatch.setattr(containers, "report_container_command_failure", unavailable)
    with pytest.raises(containers.SuccessorContainerError, match="exit 125"):
        await run_command()
    assert processes[0].returncode == 125
    assert events == []


async def test_cleanup_error_cannot_replace_original_command_failure(command_case, monkeypatch):
    program, events, processes = command_case
    program["code"] = "raise SystemExit(125)"

    async def unavailable(process):
        assert process.returncode == 125
        raise RuntimeError("private-cleanup-error")

    monkeypatch.setattr(containers, "kill_and_reap", unavailable)
    with pytest.raises(containers.SuccessorContainerError, match="exit 125"):
        await run_command()
    assert processes[0].returncode == 125
    assert events[-1]["returncode"] == 125
