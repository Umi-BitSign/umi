"""Startup restoration for qualified exclusive CPU execution. Drain C7 first.

The root-owned plan is produced only after native runtime/profile qualification.
This script restores kernel placement; it does not sign or select a cohort,
alter journals, create another admission pool, or qualify model-cache conditions.
"""

import argparse
import fcntl
import grp
import hashlib
import json
import os
import pwd
import resource
import stat
import subprocess
import time
from pathlib import Path

ROOT = Path("/sys/fs/cgroup")
DOMAIN = ROOT / "umiexecution.slice"
UNIT = DOMAIN / "umi-cpu-partition.service"
PARTITION = UNIT / "models"
ROLES = {
    "umi-c5-primary-reviewer-uid54.service": "umi-validator-uid54",
    "umi-c5-optional-reviewer-uid0.service": "umi-validator-uid0",
}


def read(path, limit=131072):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as stream:
        value = stream.read(limit + 1)
    if len(value) > limit:
        raise RuntimeError("bounded restoration metadata exceeded its limit")
    return value


def protected(path):
    info = Path(path).stat(follow_symlinks=False)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise RuntimeError("restoration metadata must be root-owned and protected")
    return read(path)


def cpus(raw):
    values = set()
    for item in raw.strip().split(","):
        numbers = item.split("-")
        if len(numbers) not in {1, 2} or any(not number.isdecimal() for number in numbers):
            raise RuntimeError("invalid CPU set")
        low, high = int(numbers[0]), int(numbers[-1])
        if not 0 <= low <= high <= 8191:
            raise RuntimeError("invalid CPU range")
        batch = set(range(low, high + 1))
        if values & batch:
            raise RuntimeError("repeated CPU")
        values.update(batch)
    return values


def write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        raw = (value + "\n").encode("ascii")
        if os.write(descriptor, raw) != len(raw):
            raise RuntimeError("incomplete cgroup control write")
    finally:
        os.close(descriptor)


def directory(path):
    if not path.is_relative_to(DOMAIN) or path == DOMAIN:
        raise RuntimeError("restorer escaped its dedicated CPU domain")
    path.mkdir(exist_ok=True)
    if path.resolve(strict=True) != path or not path.is_dir():
        raise RuntimeError("unexpected CPU directory alias")


def configure(path, *, allowed, nodes, controllers=True):
    directory(path)
    write(path / "cpuset.mems", nodes)
    write(path / "cpuset.cpus", allowed)
    if controllers:
        write(path / "cgroup.subtree_control", "+cpu +cpuset +memory +io +pids")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise RuntimeError("CPU restoration is root startup work")
    # Limit this metadata helper independently of the service cgroup, whose
    # descendants will later contain full-size model runtimes.
    resource.setrlimit(resource.RLIMIT_AS, (64 * 1024**2, 64 * 1024**2))
    resource.setrlimit(resource.RLIMIT_CPU, (10, 10))
    start = time.monotonic()

    def progress(stage, complete, total):
        print(
            json.dumps(
                dict(
                    schema="umi-cpu-partition-restoration-progress/1",
                    stage=stage,
                    completed=complete,
                    total=total,
                    elapsed_seconds=round(time.monotonic() - start, 3),
                    planning_eta_seconds=[0, 30],
                    eta_basis="bounded local metadata; no model work",
                    status="running",
                )
            ),
            flush=True,
        )

    plan = json.loads(protected(args.config))
    if plan.get("schema") != "umi-cpu-partition-restoration-plan/1":
        raise RuntimeError("unsupported restoration plan")
    # systemd must have placed this first root process in a separate leaf.
    own = read("/proc/self/cgroup", 4096).decode().strip()
    expected = "0::/" + str((UNIT / "setup").relative_to(ROOT))
    if own != expected:
        raise RuntimeError("restorer not in its supported delegated startup leaf")
    progress("preflight", 0, 1)
    for unit in ROLES:
        state = subprocess.check_output(
            ["/usr/bin/systemctl", "show", unit, "--property=ActiveState", "--value"],
            text=True,
            timeout=5,
        ).strip()
        if state not in {"inactive", "failed"}:
            raise RuntimeError("reviewer must be quiescent before CPU restoration: " + unit)
    if PARTITION.exists() and "populated 1" in read(PARTITION / "cgroup.events", 4096).decode():
        raise RuntimeError("retained model consumers must drain before CPU restoration")
    policy_raw = protected(Path(plan["existing_memory_policy_path"]))
    if hashlib.sha256(policy_raw).hexdigest() != plan["existing_memory_policy_sha256"]:
        raise RuntimeError("existing memory policy changed")
    policy = json.loads(policy_raw)
    identity = protected(Path("/etc/machine-id")).strip()
    if (
        len(identity) != 32
        or hashlib.sha256(identity).hexdigest() != policy["host_identity_sha256"]
    ):
        raise RuntimeError("memory policy belongs to another host")
    existing = {slot["name"]: slot for slot in policy["slots"] if slot["lane"] == "transient"}
    if any(Path(name).name != name or name in {".", ".."} for name in existing):
        raise RuntimeError("invalid existing admission slot path")
    directory_info = Path(policy["directory"]).stat(follow_symlinks=False)
    if (directory_info.st_dev, directory_info.st_ino) != (
        policy["directory_device"],
        policy["directory_inode"],
    ):
        raise RuntimeError("existing admission directory identity changed")
    active = plan["active_slots"]
    if not 1 <= len(active) <= len(existing) <= 32 or any(name not in existing for name in active):
        raise RuntimeError("timing slots must reuse selected existing lease files")
    selected = [cpu for value in active.values() for cpu in value]
    if any(type(cpu) is not int or not 0 <= cpu <= 8191 for cpu in selected):
        raise RuntimeError("CPU IDs must be bounded native integers")
    mode = plan["partition_mode"]
    if mode != "root":
        raise RuntimeError("CPU timing requires exclusive load-balanced root partition mode")
    background = cpus(plan["background_cpus"])
    online = cpus(read("/sys/devices/system/cpu/online", 4096).decode())
    if (
        len(selected) != len(set(selected))
        or set(selected) & background
        or set(selected) | background != online
    ):
        raise RuntimeError("CPU plan must partition online cores with explicit background capacity")
    if any(len(value) != plan["runtime_cpus"] for value in active.values()):
        raise RuntimeError("slot CPU count differs from qualified effective runtime")
    # Acquire every original transient file, including prospectively inactive
    # slots. This is the existing pool, not another scheduler or a new lock file.
    held = []
    try:
        for name, slot in sorted(existing.items()):
            descriptor = os.open(
                Path(policy["directory"]) / name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC
            )
            held.append(descriptor)
            info = os.fstat(descriptor)
            if (info.st_dev, info.st_ino) != (slot["device"], slot["inode"]):
                raise RuntimeError("existing admission lock identity changed")
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != 0
                or info.st_nlink != 1
                or info.st_mode & 0o022
            ):
                raise RuntimeError("existing admission lock protection changed")
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        gid = grp.getgrnam("umi-cpu-execution").gr_gid
        # This permission never reaches /sys/fs/cgroup/cgroup.procs or user.slice.
        os.chown(DOMAIN / "cgroup.procs", 0, gid, follow_symlinks=False)
        os.chmod(DOMAIN / "cgroup.procs", 0o660, follow_symlinks=False)
        all_cpus = ",".join(str(cpu) for cpu in sorted(online))
        write(UNIT / "cpuset.cpus", all_cpus)
        write(UNIT / "cpuset.mems", plan["numa_nodes"])
        write(UNIT / "cgroup.subtree_control", "+cpu +cpuset +memory +io +pids")
        write(UNIT / "setup/memory.max", str(64 * 1024**2))
        write(UNIT / "setup/memory.swap.max", "0")
        write(UNIT / "setup/cpuset.cpus", plan["background_cpus"])
        write(UNIT / "setup/cpuset.mems", plan["numa_nodes"])
        reserved = ",".join(str(cpu) for cpu in sorted(selected))
        # A remote partition needs explicit exclusivity propagated through
        # every member ancestor, not merely on the final models directory.
        write(DOMAIN / "cpuset.cpus.exclusive", reserved)
        write(UNIT / "cpuset.cpus.exclusive", reserved)
        configure(PARTITION, allowed=reserved, nodes=plan["numa_nodes"])
        write(PARTITION / "cpuset.cpus.exclusive", reserved)
        write(PARTITION / "cpuset.cpus.partition", mode)
        if read(PARTITION / "cpuset.cpus.partition", 4096).decode().strip() != mode:
            raise RuntimeError("kernel refused exclusive CPU partition")
        if cpus(read(PARTITION / "cpuset.cpus.exclusive.effective", 4096).decode()) != set(
            selected
        ):
            raise RuntimeError("exclusive CPU allocation differs from plan")
        for index, (name, selected_cpus) in enumerate(sorted(active.items()), 1):
            # Lock names are already validated by the selected native policy;
            # still forbid path syntax in an unqualified hand-written plan.
            if Path(name).name != name or name in {".", ".."}:
                raise RuntimeError("invalid retained slot name")
            slot_root = PARTITION / name
            allowed = ",".join(str(cpu) for cpu in selected_cpus)
            configure(slot_root, allowed=allowed, nodes=plan["numa_nodes"])
            memory = plan["runtime_memory_bytes"]
            if not 0 < memory <= existing[name]["reservation_bytes"]:
                raise RuntimeError("timed memory exceeds existing reservation")
            # The exclusive slot cpuset already bounds capacity. Keep shared
            # ancestors unlimited: only the leased UID parent and its payload
            # receive the exact quota, so extra ancestor throttling cannot bias
            # prospective speed measurements.
            write(slot_root / "cpu.max", "max 100000")
            write(slot_root / "memory.max", str(memory))
            write(slot_root / "memory.swap.max", "0")
            for user in ROLES.values():
                account = pwd.getpwnam(user)
                if plan["role_identities"].get(user) != {
                    "uid": account.pw_uid,
                    "gid": account.pw_gid,
                }:
                    raise RuntimeError("qualified reviewer account identity changed")
                parent = slot_root / ("uid" + str(account.pw_uid))
                configure(parent, allowed=allowed, nodes=plan["numa_nodes"])
                write(parent / "cpu.max", f"{plan['runtime_cpus'] * 100000} 100000")
                write(parent / "memory.max", str(memory))
                write(parent / "memory.swap.max", "0")
                os.chown(parent, account.pw_uid, account.pw_gid)
                for entry in read("/sys/kernel/cgroup/delegate", 4096).decode().splitlines():
                    if entry in {"cgroup.procs", "cgroup.threads", "cgroup.subtree_control"}:
                        os.chown(
                            parent / entry, account.pw_uid, account.pw_gid, follow_symlinks=False
                        )
                probe = parent / "probe"
                configure(probe, allowed=allowed, nodes=plan["numa_nodes"], controllers=False)
                write(probe / "cpu.max", f"{plan['runtime_cpus'] * 100000} 100000")
                write(probe / "memory.max", str(128 * 1024**2))
                write(probe / "memory.swap.max", "0")
                write(probe / "pids.max", "16")
                os.chown(
                    probe / "cgroup.procs", account.pw_uid, account.pw_gid, follow_symlinks=False
                )
                # Parent resource ceilings stay root-owned, not writable by the
                # delegate. It can manage only child payloads within those caps.
            progress("restore_slot", index, len(active))
    finally:
        for descriptor in held:
            os.close(descriptor)
    print(
        json.dumps(
            dict(
                schema="umi-cpu-partition-restoration-progress/1",
                stage="kernel_ready",
                status="completed",
                completed=len(active),
                total=len(active),
                elapsed_seconds=round(time.monotonic() - start, 3),
                eta_seconds=0,
                qualified=False,
                contract_selected=False,
            )
        ),
        flush=True,
    )


if __name__ == "__main__":
    main()
