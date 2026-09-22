"""Bound only this task's child; never attach to an existing process."""

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
name, count = sys.argv[1:]
assert name.startswith("run-") and "/" not in name and count.isdecimal()
started = time.monotonic()
peak = 0
reason = None
maximum_rss = int(os.environ.get("SETTLEMENT_MAX_RSS_BYTES", str(12 * 1024**3)))
minimum_available = int(os.environ.get("SETTLEMENT_MIN_AVAILABLE_BYTES", "0"))
assert 0 < maximum_rss <= 12 * 1024**3 and minimum_available >= 0
command = (
    [sys.executable, str(root / "tools/probe_settlement_wire.py"), str(root / ("run-" + count))]
    if name.startswith("run-wire-")
    else [sys.executable, str(root / "tools/qualify_full_settlement.py"), str(root / name), count]
)
with (root / (name + ".log")).open("x") as log:
    child = subprocess.Popen(
        command,
        cwd=root,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    print(
        json.dumps(
            {
                "child_pid": child.pid,
                "wall_limit_seconds": 5400,
                "rss_limit_bytes": maximum_rss,
                "minimum_available_bytes": minimum_available,
            }
        ),
        flush=True,
    )
    while child.poll() is None:
        usage = subprocess.run(
            ["/bin/ps", "-axo", "pid=,pgid=,rss="],
            capture_output=True,
            text=True,
            timeout=3,
        )
        # start_new_session gives this task its own process group. Include its
        # fixture HTTPS server, but no unrelated services or qualification jobs.
        rows = [tuple(map(int, line.split())) for line in usage.stdout.splitlines()]
        rss = sum(size for _, group, size in rows if group == child.pid) * 1024
        peak = max(peak, rss)
        available = None
        if minimum_available and sys.platform == "linux":
            available = next(
                int(line.split()[1]) * 1024
                for line in Path("/proc/meminfo").read_text().splitlines()
                if line.startswith("MemAvailable:")
            )
        if (
            peak > maximum_rss
            or time.monotonic() - started > 5400
            or (available is not None and available < minimum_available)
        ):
            reason = (
                "rss_bound"
                if peak > maximum_rss
                else "available_memory_floor"
                if available is not None and available < minimum_available
                else "wall_bound"
            )
            os.killpg(child.pid, signal.SIGTERM)
            try:
                child.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(child.pid, signal.SIGKILL)
                child.wait(timeout=5)
            break
        time.sleep(2)
result = dict(
    exit_code=child.returncode,
    sampled_peak_rss_bytes=peak,
    total_wall_seconds=time.monotonic() - started,
    bound_exceeded=reason,
    maximum_rss_bytes=maximum_rss,
    minimum_available_bytes=minimum_available,
)
(root / (name + "-supervisor.json")).write_text(json.dumps(result, indent=2) + "\n")
print(json.dumps(result), flush=True)
sys.exit(child.returncode)
