"""Trusted bounded stdlib-only probe subprocess; never import model code.

Launched by the installed signed host with -I -B under its existing slot lease.
Startup provisioned the destination and common-ancestor migration permission.
No privileged broker, extra scheduler, affinity pinning or long-lived daemon.
"""

import argparse
import hashlib
import json
import os
import resource
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier


def run(cgroup, cpu_ids, profile, invocation, boundary):
    resource.setrlimit(resource.RLIMIT_AS, (128 * 1024**2, 128 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    if not 1 <= len(cpu_ids) <= 8 or cpu_ids != tuple(sorted(set(cpu_ids))):
        raise ValueError("invalid probe CPU allowance")
    if any(not 0 <= cpu <= 8191 for cpu in cpu_ids):
        raise ValueError("invalid probe CPU identity")
    for digest in (profile, invocation):
        if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
            raise ValueError("invalid probe invocation binding")
    if boundary not in {"before", "after"}:
        raise ValueError("invalid probe boundary")
    cgroup = Path(cgroup)
    if (
        not cgroup.is_absolute()
        or cgroup.resolve(strict=True) != cgroup
        or not cgroup.is_relative_to("/sys/fs/cgroup/umiexecution.slice")
        or cgroup.name != "probe"
    ):
        raise ValueError("probe needs its provisioned CPU leaf")
    descriptor = os.open(cgroup / "cgroup.procs", os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        value = f"{os.getpid()}\n".encode("ascii")
        if os.write(descriptor, value) != len(value):
            raise RuntimeError("probe migration was incomplete")
    finally:
        os.close(descriptor)
    if os.sched_getaffinity(0) != set(cpu_ids):
        raise RuntimeError("probe did not enter the qualified CPU slot")
    expected = "0::/" + str(cgroup.relative_to("/sys/fs/cgroup"))
    if Path("/proc/self/cgroup").read_text().strip() != expected:
        raise RuntimeError("probe migrated to another cgroup")
    rendezvous = Barrier(len(cpu_ids))
    started = time.monotonic_ns() // 1000

    def worker(index):
        value = bytes(65536)
        rendezvous.wait(timeout=1)
        start, cpu_start = time.monotonic_ns(), time.thread_time_ns()
        for _ in range(4096):
            result = hashlib.sha256(value).digest()
        cpu_finish, finish = time.thread_time_ns(), time.monotonic_ns()
        return dict(
            worker=index,
            wall_us=(finish - start + 999) // 1000,
            thread_cpu_us=(cpu_finish - cpu_start + 999) // 1000,
            result_sha256=result.hex(),
        )

    with ThreadPoolExecutor(max_workers=len(cpu_ids)) as pool:
        workers = tuple(pool.map(worker, range(len(cpu_ids))))
    return dict(
        schema="umi-fixed-cpu-condition-probe/1",
        rule="parallel_sha256_4096x65536_load_balanced/1",
        measurement_profile_sha256=profile,
        invocation_sha256=invocation,
        boundary=boundary,
        cpu_ids=cpu_ids,
        started_us=started,
        finished_us=time.monotonic_ns() // 1000,
        workers=workers,
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cgroup", required=True)
    parser.add_argument("--cpus", required=True)
    parser.add_argument("--profile", required=True)
    parser.add_argument("--invocation", required=True)
    parser.add_argument("--boundary", choices=("before", "after"), required=True)
    args = parser.parse_args()
    value = run(
        args.cgroup,
        tuple(int(cpu) for cpu in args.cpus.split(",")),
        args.profile,
        args.invocation,
        args.boundary,
    )
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


if __name__ == "__main__":
    main()
