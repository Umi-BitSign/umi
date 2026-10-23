"""Prepare rootless Podman before a hardened CPU reviewer needs its namespace.

Run as the review account, with its existing CPU storage environment and without
NoNewPrivileges. This never resets storage, migrates containers or runs a model.
Healthy, unchanged namespace metadata avoids repeating Podman inspection.
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path

PODMAN = Path("/usr/bin/podman")
PROC = Path("/proc")
MAX_OUTPUT = 256 * 1024
ENVIRONMENT = ("HOME", "CONTAINERS_STORAGE_CONF", "CONTAINERS_CONF_OVERRIDE", "XDG_RUNTIME_DIR")


def metadata(path):
    info = path.stat()
    return [
        getattr(info, "st_" + field)
        for field in ("dev", "ino", "uid", "mode", "size", "mtime_ns", "ctime_ns")
    ]


def selected_context(environment):
    if os.geteuid() == 0:
        raise ValueError("CPU namespace preparation must run as the review account")
    status = (PROC / "self/status").read_text()
    if any(line.split() == ["NoNewPrivs:", "1"] for line in status.splitlines()):
        raise ValueError("prepare the namespace outside the hardened reviewer")
    values = {key: environment[key] for key in ENVIRONMENT}
    for value in values.values():
        path = Path(value)
        if not path.is_absolute() or path.resolve(strict=True) != path:
            raise ValueError("CPU runtime paths must be existing canonical paths")
    runtime = Path(values["XDG_RUNTIME_DIR"])
    info = runtime.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or info.st_mode & 0o077:
        raise ValueError("CPU runtime directory must be private to the review account")
    return dict(
        environment=values,
        uid=os.geteuid(),
        boot=(PROC / "sys/kernel/random/boot_id").read_text().strip(),
        podman=metadata(PODMAN),
        configs={key: metadata(Path(values[key])) for key in ENVIRONMENT[1:3]},
    )


def namespace(runtime):
    try:
        pause = runtime / "libpod/tmp/pause.pid"
        if pause.is_symlink() or pause.stat().st_uid != os.geteuid():
            return None
        pid = pause.read_text().strip()
        if not pid.isdecimal() or len(pid) > 12:
            return None
        proc = PROC / pid
        if (
            proc.stat().st_uid != os.geteuid()
            or (proc / "comm").read_text().strip() != "podman pause"
        ):
            return None
        executable = os.readlink(proc / "exe")
        expected = str(PODMAN.resolve(strict=True))
        # A package upgrade can unlink the old sleeping executable while its
        # kernel namespace remains valid. It need not stop working containers.
        if executable not in (expected, expected + " (deleted)"):
            return None
        mapping = [line.split() for line in (proc / "uid_map").read_text().splitlines()]
        if not mapping or mapping[0] != ["0", str(os.geteuid()), "1"]:
            return None
        start = (proc / "stat").read_text().rsplit(")", 1)[1].split()[19]
        return dict(
            pid=pid,
            start_ticks=start,
            uid_map=mapping,
            user_namespace=os.readlink(proc / "ns/user"),
        )
    except (OSError, IndexError, ValueError):
        return None


def private_record(path):
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.geteuid()
            or info.st_nlink != 1
            or info.st_mode & 0o077
            or info.st_size > MAX_OUTPUT
        ):
            return None
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None


def publish(path, value):
    temporary = path.with_name(path.name + ".pending-" + str(os.getpid()))
    created = False
    try:
        descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        created = True
        with os.fdopen(descriptor, "w") as stream:
            json.dump(value, stream, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if created:
            temporary.unlink(missing_ok=True)


def ensure(environment=None, *, inspect=None):
    environment = os.environ if environment is None else environment
    context = selected_context(environment)
    runtime = Path(context["environment"]["XDG_RUNTIME_DIR"])
    record = runtime / "umi-cpu-namespace-ready.json"
    current = namespace(runtime)
    if current is not None and private_record(record) == dict(context=context, namespace=current):
        return dict(status="ready", changed=False, podman_inspected=False)
    if inspect is None:

        def inspect():
            return subprocess.run(
                [str(PODMAN), "info", "--format=json"], capture_output=True, timeout=60
            )

    result = inspect()
    if result.returncode or len(result.stdout) > MAX_OUTPUT or len(result.stderr) > MAX_OUTPUT:
        # Runtime diagnostics go to journald; never silently turn empty output
        # into a JSON parser exception or a model failure.
        raise RuntimeError(
            "rootless Podman inspection failed: exit="
            + str(result.returncode)
            + " stderr="
            + result.stderr[:4096].decode(errors="replace")
        )
    info = json.loads(result.stdout)
    if info["host"]["security"]["rootless"] is not True or str(
        info["host"]["cgroupVersion"]
    ).lower() not in ("v2", "2"):
        raise ValueError("rootless Podman with cgroup v2 is required")
    current = namespace(runtime)
    if current is None:
        raise ValueError("Podman did not retain a supported rootless namespace keeper")
    if selected_context(environment) != context:
        raise ValueError("CPU runtime configuration changed during preparation")
    publish(record, dict(context=context, namespace=current))
    return dict(status="ready", changed=True, podman_inspected=True)


def main():
    started = time.monotonic()
    print(
        json.dumps(
            dict(
                schema="umi-cpu-namespace-progress/1",
                stage="namespace_readiness",
                completed=0,
                total=1,
                elapsed_seconds=0,
                planning_eta_seconds=[0, 60],
                eta_basis="planning: local metadata or rootless Podman preparation",
            )
        ),
        flush=True,
    )
    try:
        result = ensure()
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.TimeoutExpired) as error:
        print(
            json.dumps(
                dict(
                    schema="umi-cpu-namespace-progress/1",
                    stage="namespace_readiness",
                    completed=0,
                    total=1,
                    elapsed_seconds=time.monotonic() - started,
                    eta_seconds=None,
                    eta_basis="withdrawn_repair_required",
                    status="retrying",
                    error=str(error)[:4096],
                )
            ),
            flush=True,
        )
        return 1
    print(
        json.dumps(
            dict(
                schema="umi-cpu-namespace-progress/1",
                stage="namespace_readiness",
                completed=1,
                total=1,
                elapsed_seconds=time.monotonic() - started,
                eta_seconds=0,
                eta_basis="completed",
                **result,
            )
        ),
        flush=True,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
