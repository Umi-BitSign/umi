"""Bind one hosted request, then observe its detached bounded service."""

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time

UNIT = "umi-selected-ci-v1"
SCRATCH = Path("/run/" + UNIT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("prepare", "execute"))
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not sys.flags.isolated or not sys.dont_write_bytecode or os.geteuid() == 0:
        raise ValueError("nonroot isolated controller required")
    source = Path(__file__).resolve().parents[1]
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    request = json.loads(args.request.read_text())
    runtime_seconds = request["service_runtime_seconds"]
    if runtime_seconds not in (300, 600, 900):
        raise ValueError("unreviewed runtime bound")
    observation_seconds = runtime_seconds + 60
    started = time.monotonic()

    def save(name, value):
        with (output / name).open("w") as stream:
            json.dump(value, stream, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

    def event(stage, **values):
        row = dict(
            schema="umi-targeted-selected-control-progress/1", stage=stage,
            observed_utc=datetime.now(timezone.utc).isoformat(),
            elapsed_seconds=round(time.monotonic() - started, 6),
            planning_eta_seconds=[0, max(0, observation_seconds - int(time.monotonic() - started))],
            eta_basis="planning; request-bound detached service and bounded observation",
            stalled_or_retrying=False,
        )
        row.update(values)
        with (output / "control-events.jsonl").open("a") as stream:
            stream.write(json.dumps(row) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        print(json.dumps(row), flush=True)

    def command(arguments, timeout=10):
        event("command_start", command=arguments[0])
        result = subprocess.run(arguments, cwd=source, capture_output=True, text=True, timeout=timeout)
        event("command_complete", command=arguments[0], exit_code=result.returncode)
        return result

    event("controller_entered", mode=args.mode, completed=0, total=1)
    if args.mode == "prepare":
        revision = command(["git", "rev-parse", "HEAD"]).stdout.strip()
        for path, expected in (("src", request["src_tree"]), ("tests", request["tests_tree"])):
            actual = command(["git", "rev-parse", "HEAD:" + path])
            if actual.returncode or actual.stdout.strip() != expected:
                raise ValueError("reviewed tree changed: " + path)
        for path, expected in (*request["module_sha256"].items(), ("uv.lock", request["uv_lock_sha256"]), ("src/umi/competition_verification_rules.json", request["manifest_sha256"])):
            if hashlib.sha256((source / path).read_bytes()).hexdigest() != expected:
                raise ValueError("reviewed bytes changed: " + path)
        if ".".join(map(str, sys.version_info[:3])) != request["python"]:
            raise ValueError("wrong interpreter")
        save("startup-receipt.json", dict(
            revision=revision, target_revision=request["target_revision"],
            interpreter=sys.version, request_sha256=hashlib.sha256(args.request.read_bytes()).hexdigest(),
            selections=request["selections"], expected_count=request["expected_count"], src_tree=request["src_tree"], tests_tree=request["tests_tree"],
            observed_utc=datetime.now(timezone.utc).isoformat(), service_not_started=True,
        ))
        event("startup_bound", completed=1, total=1)
        return 0

    startup = json.loads((output / "startup-receipt.json").read_text())
    if startup["request_sha256"] != hashlib.sha256(args.request.read_bytes()).hexdigest():
        raise ValueError("request changed after startup upload")
    if command(["git", "rev-parse", "HEAD"]).stdout.strip() != startup["revision"]:
        raise ValueError("source changed after startup upload")
    cases = output / "cases"
    cases.mkdir(exist_ok=False)
    stdout, stderr = output / "service-stdout.log", output / "service-stderr.log"
    for path in (stdout, stderr):
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        os.close(fd)
    import grp
    import pwd
    owner, group = pwd.getpwuid(os.getuid()).pw_name, grp.getgrgid(os.getgid()).gr_name
    properties = dict(
        Type="exec", User=owner, Group=group, MemoryMax="1536M", MemorySwapMax="0",
        TasksMax="96", CPUQuota="200%", RuntimeMaxSec=str(runtime_seconds) + "s", TimeoutStopSec="15s",
        KillMode="control-group", PrivateTmp="yes", RuntimeDirectory=UNIT,
        RuntimeDirectoryMode="0700", RuntimeDirectoryPreserve="no", RemainAfterExit="yes",
        WorkingDirectory=str(source), StandardOutput="append:" + str(stdout), StandardError="append:" + str(stderr),
    )
    args_run = ["sudo", "-n", "systemd-run", "--unit=" + UNIT, "--no-block"]
    args_run += ["--property=" + name + "=" + value for name, value in properties.items()]
    args_run += ["--setenv=PYTHONDONTWRITEBYTECODE=1", "--setenv=PYTEST_DISABLE_PLUGIN_AUTOLOAD=1", "--setenv=RAYON_NUM_THREADS=1", "--setenv=LANG=C.UTF-8"]
    args_run += ["--setenv=PATH=" + str(source / ".venv/bin") + os.pathsep + os.environ["PATH"]]
    args_run += [str(source / ".venv/bin/python"), "-I", "-B", "-u", str(source / "tools/run_selected_ci.py"), "--request", str(args.request.resolve()), "--scratch", str(SCRATCH), "--output", str(cases)]
    state, terminal = {}, False
    try:
        launched = command(args_run, timeout=20)
        save("launch.json", dict(exit_code=launched.returncode, stdout=launched.stdout, stderr=launched.stderr, properties=properties))
        if launched.returncode:
            raise ValueError("detached service launch failed")
        while time.monotonic() - started < observation_seconds:
            observed = command(["sudo", "-n", "systemctl", "show", UNIT + ".service", "--no-pager", "-p", "LoadState", "-p", "ActiveState", "-p", "SubState", "-p", "Result", "-p", "ExecMainStatus", "-p", "MemoryPeak", "-p", "MemorySwapPeak"], timeout=5)
            if observed.returncode:
                save("observation-error.json", dict(exit_code=observed.returncode, stdout=observed.stdout, stderr=observed.stderr))
                raise ValueError("service observation failed")
            current = dict(line.split("=", 1) for line in observed.stdout.splitlines() if "=" in line)
            if current != state:
                state = current
                event("service_state", state=state)
                save("service-state.json", state)
            if state.get("ActiveState") == "failed" or state.get("SubState") == "exited":
                terminal = True
                break
            time.sleep(2)
        if not terminal:
            event("observation_bound", stalled_or_retrying=True, state=state)
            raise TimeoutError("bounded service observation ended without terminal state")
        result_path = cases / "result.json"
        result = json.loads(result_path.read_text()) if result_path.is_file() else {}
        passed = state.get("ExecMainStatus") == "0" and result.get("passed") is True
        save("controller-result.json", dict(passed=passed, service_state=state, test_result_present=bool(result)))
        event("service_terminal", completed=request["expected_count"] if passed else len(result.get("completed", {})), total=request["expected_count"], passed=passed)
        return 0 if passed else 1
    finally:
        stopped = command(["sudo", "-n", "systemctl", "stop", UNIT + ".service"], timeout=25)
        save("cleanup.json", dict(stop_exit_code=stopped.returncode, scratch_absent=not SCRATCH.exists()))
        if SCRATCH.exists():
            raise ValueError("service-owned scratch remains")


if __name__ == "__main__":
    raise SystemExit(main())
