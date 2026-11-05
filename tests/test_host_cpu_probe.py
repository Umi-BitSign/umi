"""Real fixed-work helpers, without touching production CPU partitions."""

import os
import signal
import time
from contextlib import suppress
from pathlib import Path

import pytest

from umi import host_cpu_probe as probe
from umi.competition_cpu_conditions import PROBE_RESULT


@pytest.mark.parametrize("executor", ["threads", "processes"])
def test_same_fixed_work_and_complete_worker_cleanup(executor):
    rows = probe.collect_workers(2, executor)
    assert [row["worker"] for row in rows] == [0, 1]
    assert all(row["result_sha256"] == PROBE_RESULT for row in rows)
    assert all(0 < row["thread_cpu_us"] <= row["wall_us"] for row in rows)
    with pytest.raises(ChildProcessError):
        os.waitpid(-1, os.WNOHANG)


def test_workers_die_with_probe_parent(tmp_path):
    """An abrupt parent exit cannot leave live CPU-consuming descendants."""
    path = tmp_path / "child"
    parent = os.fork()
    if parent == 0:
        child = os.fork()
        if child == 0:
            probe._process_start(None, os.getppid())
            path.write_text(str(os.getpid()))
            time.sleep(10)
            os._exit(99)
        time.sleep(10)
        os._exit(99)
    child = None
    try:
        deadline = time.monotonic() + 3
        while not path.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        child = int(path.read_text())
        os.kill(parent, signal.SIGKILL)
        os.waitpid(parent, 0)
        parent = None
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                status = Path(f"/proc/{child}/stat").read_text().rsplit(")", 1)[1].split()[0]
            except FileNotFoundError:
                return
            if status == "Z":
                return
            time.sleep(0.01)
        pytest.fail("probe child survived parent termination")
    finally:
        for pid in (child, parent):
            if pid is not None:
                with suppress(ProcessLookupError):
                    os.kill(pid, signal.SIGKILL)
        if parent is not None:
            os.waitpid(parent, 0)
