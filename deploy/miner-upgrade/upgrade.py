#!/usr/bin/python3
"""Upgrade the one running standard Linux UMI miner to the current recoverable cohort."""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import hashlib
import json
import os
import platform
import pwd
import re
import shlex
import shutil
import stat
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from contextlib import contextmanager, suppress
from dataclasses import dataclass, replace
from pathlib import Path

DEFAULT_MANIFEST = (
    "https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/current.json"
)
DEFAULT_STATUS = "https://api.umi.vision/v1/competition/status"
ROOT = Path("/var/lib/umi-miner-cohorts")
RUNTIME_ROOT = Path("/opt/umi-miner-runtimes")
LAUNCHER = Path("/usr/local/libexec/umi-miner-upgrade")
SYSTEMD_ROOT = Path("/etc/systemd/system")
SYSTEMD_RUNTIME_ROOT = Path("/run/systemd/system")
COOPERATIVE_SERVICE_SETTINGS = (
    "TimeoutStopSec=infinity\nSendSIGKILL=no\nKillMode=mixed\nKillSignal=SIGTERM\nSendSIGHUP=no\n"
)
ENROLLMENT_SERVICE = "umi-miner-cohort-enrollment.service"
ENROLLMENT_TIMER = "umi-miner-cohort-enrollment.timer"
SERVICE_CLAIM_TIMEOUT_SECONDS = 3600
UV_BOOTSTRAP_VERSION = "0.12.9"
HEX32 = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
SYSTEMD_UNIT = re.compile(r"^[A-Za-z0-9_.:@-]+\.service$")
PROGRESS = None
PACKAGE_RESTART_POLICY = (
    b"# UMI owners require ordered drainage, immutable consumer rebinding and native\n"
    b"# restart qualification. Keep reporting outdated processes; defer their restart\n"
    b"# to the UMI maintenance controller for C5 and all successor cohorts.\n"
    b"$nrconf{override_rc}->{qr(^umi-.*\\.service$)} = 0;\n"
)


def install_package_restart_policy(
    etc_directory: Path = Path("/etc"),
    *,
    owner: tuple[int, int] = (0, 0),
    service_name: str | None = None,
) -> dict:
    """Publish only our exact root-owned needrestart override, without a restart.

    The explicit base and owner are for isolated filesystem qualification. The
    installed CLI always uses /etc and root. Existing administrator content is
    never overwritten. Recover a completed pending publication only by checking
    its exact bytes, ownership and inode relationship to the final file.
    """
    started = time.monotonic()
    if service_name is not None and SYSTEMD_UNIT.fullmatch(service_name) is None:
        raise ValueError("package restart policy service name differs")
    content = (
        PACKAGE_RESTART_POLICY
        if service_name is None
        else (
            "# Explicit UMI-managed custom service; keep package-triggered restarts controlled.\n"
            "$nrconf{override_rc}->{qr(^"
            + re.escape(service_name).replace("@", r"\@")
            + "$)} = 0;\n"
        ).encode()
    )
    filename = (
        "90-umi-controlled-restarts.conf"
        if service_name is None
        else "91-umi-controlled-service-" + sha256(service_name.encode()) + ".conf"
    )
    if os.geteuid() != owner[0] or not etc_directory.is_absolute():
        raise ValueError("package restart policy needs its actual filesystem owner")
    directory = etc_directory / "needrestart" / "conf.d"
    for path in (etc_directory, etc_directory / "needrestart", directory):
        if path != etc_directory and not os.path.lexists(path):
            path.mkdir(mode=0o755)
            fsync_directory(path.parent)
        info = path.lstat()
        if (
            path.resolve(strict=True) != path
            or not stat.S_ISDIR(info.st_mode)
            or (info.st_uid, info.st_gid) != owner
            or info.st_mode & 0o022
        ):
            raise ValueError("unsafe package restart policy directory")
    target = directory / filename
    pending = directory / ("." + filename + ".pending")

    def checked(path: Path, links: tuple[int, ...] = (1,)):
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_nlink not in links
                or (before.st_uid, before.st_gid) != owner
                or before.st_mode & 0o022
                or before.st_size != len(content)
            ):
                raise ValueError("unsafe or incomplete package restart policy file")
            raw = stream.read(len(content) + 1)
            after = os.fstat(stream.fileno())
        fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        if (
            raw != content
            or any(getattr(before, k) != getattr(after, k) for k in fields)
            or (path.lstat().st_dev, path.lstat().st_ino) != (before.st_dev, before.st_ino)
        ):
            raise ValueError("existing package restart policy differs; services unchanged")
        return before

    repaired = False
    existed = os.path.lexists(target)
    if existed:
        if os.path.lexists(pending):
            a, b = checked(target, (2,)), checked(pending, (2,))
            if (a.st_dev, a.st_ino) != (b.st_dev, b.st_ino):
                raise ValueError("package restart policy has unrelated pending content")
            pending.unlink()
            fsync_directory(directory)
            repaired = True
        checked(target)
    else:
        if os.path.lexists(pending):
            checked(pending)
            repaired = True
        else:
            descriptor = os.open(
                pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o644
            )
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
        # A competing creator refuses instead of replacing its control file.
        os.link(pending, target, follow_symlinks=False)
        pending.unlink()
        fsync_directory(directory)
        checked(target)
    return {
        "schema": "umi-package-restart-policy-installation/1",
        "status": "repaired_interrupted_publish"
        if repaired
        else "reused"
        if existed
        else "installed",
        "path": str(target),
        "sha256": sha256(content),
        "services_restarted": False,
        "security_package_updates_enabled": True,
        "completed": 1,
        "total": 1,
        "elapsed_seconds": time.monotonic() - started,
        "eta_seconds": 0,
        "eta_basis": "exact policy installed; future UMI restarts require controlled maintenance",
    }


def qualify_package_restart_configuration(
    services: tuple[str, ...],
    config: Path = Path("/etc/needrestart/needrestart.conf"),
    *,
    owner: tuple[int, int] = (0, 0),
) -> None:
    """Refuse administrator overrides that would defeat these selected units."""
    if not os.path.lexists(config):
        return  # The installed conf.d policy also covers a future package install.
    for path in (config, *sorted(config.parent.glob("conf.d/*.conf"))):
        info = path.lstat()
        if (
            path.resolve(strict=True) != path
            or not stat.S_ISREG(info.st_mode)
            or (info.st_uid, info.st_gid) != owner
            or info.st_mode & 0o022
        ):
            raise ValueError("unsafe complete needrestart configuration; services unchanged")
    units = tuple(
        sorted(
            set(services)
            | {
                "umi-validator-supervisor.service",
                "umi-miner.service",
                "umi-reference-publication.service",
            }
        )
    )
    program = r"""our %nrconf; my $path=shift @ARGV; my $loaded=do $path;
    die $@ if $@; die $! unless defined $loaded;
    for my $unit (@ARGV) {
        my @matches=grep {$unit =~ $_} keys %{$nrconf{override_rc}};
        die "restart protection missing or conflicting for $unit"
            unless @matches && !grep {$nrconf{override_rc}->{$_} != 0} @matches;
    }"""
    run("perl", "-e", program, str(config), *units)


def package_restart_policy_command() -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise ValueError("package restart policy installation requires root on Linux")
    parser = argparse.ArgumentParser(
        description="Install restart protection without changing services"
    )
    parser.add_argument("--service", action="append", default=[])
    args = parser.parse_args(sys.argv[2:])
    services = tuple(sorted(set(args.service)))
    if any(SYSTEMD_UNIT.fullmatch(name) is None for name in services):
        raise ValueError("package restart policy service name differs")
    print(
        canonical(
            {
                "stage": "package_restart_policy_installation",
                "completed": 0,
                "total": 1,
                "elapsed_seconds": 0,
                "eta_seconds": None,
                "planning_eta_seconds": [1, 10],
                "eta_basis": "bounded local control publication; no service or package restart",
                "stalled": False,
                "retrying": False,
            }
        ).decode(),
        flush=True,
    )
    reports = [install_package_restart_policy()]
    reports.extend(
        install_package_restart_policy(service_name=name)
        for name in services
        if not name.startswith("umi-")
    )
    qualify_package_restart_configuration(services)
    for report in reports:
        print(canonical(report).decode(), flush=True)


class MigrationProgress:
    """Count completed stages and expose elapsed time without imposing a deadline."""

    def __init__(self):
        self.started = time.monotonic()
        self.stage_started = self.started
        self.current = None
        self.stages = [
            "manifest",
            "installed_layout",
            "inputs",
            "runtime",
            "startup_validation",
            "sidecar",
            "activation",
            "enrollment",
        ]
        self.durations = {}
        self.history = {}
        # Operator planning ranges, not timeout settings or guarantees. Replace
        # them with same-host measured stages when a successful receipt exists.
        self.planning = {
            "manifest": (1, 30),
            "installed_layout": (1, 10),
            "inputs": (1, 30),
            "runtime": (30, 900),
            "startup_validation": (1, 30),
            "sidecar": (1, 30),
            "activation": (10, 600),
            "enrollment": (1, 30),
            "client_install": (30, 900),
        }
        self.attempt = 1
        self.write_failures = 0
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self._heartbeat, daemon=True)
        self.lock_fd = None

    def _heartbeat(self):
        while not self.stop.wait(30):
            self.emit("waiting")

    def select(self, stages):
        with self.lock:
            self.stages = list(stages)

    def advance(self, name):
        with self.lock:
            now = time.monotonic()
            if self.current is not None:
                self.durations[self.current] = now - self.stage_started
            self.current = name
            self.stage_started = now
            self.emit("retrying" if self.attempt > 1 else "running")

    def snapshot(self, status="running"):
        with self.lock:
            now = time.monotonic()
            elapsed = max(0.0, now - self.stage_started)
            remaining = [name for name in self.stages if name not in self.durations]
            known = remaining and all(name in self.history for name in remaining)
            estimate = sum(self.history[name] for name in remaining) - elapsed if known else None
            stage_estimate = self.history.get(self.current)
            overdue = stage_estimate is not None and elapsed > stage_estimate
            valid_estimate = estimate is not None and estimate >= 0 and not overdue
            plan_known = remaining and all(name in self.planning for name in remaining)
            stage_plan = self.planning.get(self.current)
            plan_overdue = stage_plan is not None and elapsed > stage_plan[1]
            planned = (
                [
                    round(
                        max(0.0, sum(self.planning[name][bound] for name in remaining) - elapsed), 3
                    )
                    for bound in (0, 1)
                ]
                if plan_known and not plan_overdue
                else None
            )
            if not known and planned is not None:
                estimate = sum(planned) / 2
            completed = sum(name in self.durations for name in self.stages)
            done = status == "complete"
            return {
                "schema": "umi-miner-migration-progress/1",
                "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "status": "waiting_beyond_estimate"
                if status == "waiting" and (overdue or plan_overdue)
                else status,
                "stage": self.current,
                "attempt": self.attempt,
                "retrying": self.attempt > 1,
                "progress_write_failures": self.write_failures,
                "completed_stages": len(self.stages) if done else completed,
                "total_stages": len(self.stages),
                "percent": 100.0 if done else round(100 * completed / len(self.stages), 1),
                "percent_basis": "completed_stages_not_work_volume",
                "elapsed_seconds": round(max(0.0, now - self.started), 3),
                "stage_elapsed_seconds": round(elapsed, 3),
                "stage_eta_seconds": 0.0
                if done
                else round(stage_estimate - elapsed, 3)
                if stage_estimate is not None and not overdue
                else round(max(0.0, sum(stage_plan) / 2 - elapsed), 3)
                if stage_estimate is None and stage_plan is not None and not plan_overdue
                else None,
                "eta_seconds": 0.0
                if done
                else round(estimate, 3)
                if valid_estimate or (not known and planned is not None)
                else None,
                "planning_eta_range_seconds": [0.0, 0.0] if done else planned,
                "eta_confidence": "low" if not done else "observed_complete",
                "planning_assumptions": [
                    "network_and_package_mirror_available",
                    "no_prolonged_active_work_drain",
                    "no_additional_retries",
                ],
                "eta_basis": "complete"
                if done
                else "previous_completed_upgrade"
                if valid_estimate
                else "previous_duration_exceeded"
                if known
                else "planning_estimate_not_deadline"
                if planned is not None
                else "planning_range_exceeded"
                if plan_overdue
                else "no_comparable_completed_stage_timings",
                "stage_seconds": dict(self.durations),
            }

    def emit(self, status):
        try:
            print(canonical(self.snapshot(status)).decode(), file=sys.stderr, flush=True)
        except (OSError, ValueError):
            # A closed SSH/logging pipe is not a migration or rollback decision.
            self.write_failures += 1

    def finish(self, status):
        self.stop.set()
        if self.thread.is_alive():
            self.thread.join()
        with self.lock:
            if status == "complete" and self.current is not None:
                self.durations[self.current] = time.monotonic() - self.stage_started
            self.emit(status)


def progress_stage(name):
    if PROGRESS is not None:
        PROGRESS.advance(name)


def progress_plan(*stages):
    if PROGRESS is not None:
        PROGRESS.select(stages)


def progress_history(report):
    if PROGRESS is not None and isinstance(report, dict):
        history = report.get("migration_progress", {})
        value = history.get("stage_seconds", {}) if isinstance(history, dict) else {}
        if isinstance(value, dict):
            PROGRESS.history = {
                name: seconds
                for name, seconds in value.items()
                if isinstance(name, str)
                and type(seconds) in (int, float)
                and 0 <= seconds < float("inf")
            }


def progress_limits(limits):
    if PROGRESS is not None:
        PROGRESS.planning["activation"] = (
            10,
            max(600, limits["startup_seconds"] + limits["inference_seconds"]),
        )


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fetch(url: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept-Encoding": "identity", "User-Agent": "umi-miner-upgrade/1"},
    )
    with urllib.request.urlopen(request, timeout=120) as response:
        raw = response.read(maximum + 1)
        if response.status != 200 or not raw or len(raw) > maximum:
            raise ValueError("download size or status differs")
        return raw


def worker_read(path: Path, *, maximum: int = 4 * 1024 * 1024) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= maximum
        ):
            raise ValueError(f"unsafe private enrollment file: {path.name}")
        raw = stream.read(maximum + 1)
    if len(raw) > maximum:
        raise ValueError(f"private enrollment file is too large: {path.name}")
    return raw


def worker_write(path: Path, raw: bytes) -> None:
    parent = path.parent
    info = parent.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise ValueError("unsafe enrollment state directory")
    pending = path.with_name(path.name + ".pending")
    pending.unlink(missing_ok=True)
    descriptor = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
    )
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        pending.unlink(missing_ok=True)
        raise
    os.replace(pending, path)
    directory = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def document(raw: bytes, *, label: str) -> dict:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


def deployed_manifest(manifest: dict, status: dict) -> dict:
    """Select the exact runtime reported by the matching live deployment.

    The static manifest cannot name the commit that changes its own runtime
    pointer. The public status is already required to match its policy and track
    profile, so use that same deployment record for the runtime revision. A
    published maintenance release may instead bind its exact runtime revision
    to an existing deployment_revision, preserving that cohort's signed identity.
    """
    deployed = status.get("deployment") if isinstance(status, dict) else None
    policy = manifest.get("policy") if isinstance(manifest, dict) else None
    if (
        status.get("schema") == "umi-competition-status/2"
        and isinstance(deployed, dict)
        and deployed.get("repository") == "https://github.com/Umi-BitSign/umi"
        and deployed.get("eligible_tracks") == manifest.get("eligible_tracks")
        and isinstance(policy, dict)
        and status.get("policy_sha256") == policy.get("value_sha256")
        and GIT_REVISION.fullmatch(str(deployed.get("umi_git_revision")))
    ):
        selected = document(canonical(manifest), label="upgrade manifest")
        runtime = selected.get("runtime")
        if isinstance(runtime, dict) and "deployment_revision" not in runtime:
            runtime["revision"] = deployed["umi_git_revision"]
        return selected
    return manifest


def validate_manifest(manifest: dict, status: dict, public_track: str) -> None:
    required = {
        "schema",
        "cohort",
        "cohort_sha256",
        "eligible_tracks",
        "history_origin",
        "history_owner_hotkey",
        "maximum_recovery_assignments",
        "policy",
        "public_model_track_required",
        "runtime",
        "service_authority_sha256",
        "service_terms_sha256",
        "transport",
    }
    if set(manifest) != required or manifest.get("schema") != "umi-miner-upgrade-manifest/1":
        raise ValueError("upgrade manifest schema differs")
    for field in ("cohort_sha256", "service_authority_sha256", "service_terms_sha256"):
        if HEX32.fullmatch(str(manifest.get(field))) is None:
            raise ValueError(f"invalid {field}")
    for name in ("policy", "transport"):
        item = manifest.get(name)
        if not isinstance(item, dict) or set(item) != {"sha256", "url", "value_sha256"}:
            raise ValueError(f"invalid {name} input")
        if any(HEX32.fullmatch(str(item.get(k))) is None for k in ("sha256", "value_sha256")):
            raise ValueError(f"invalid {name} digest")
        if not str(item.get("url", "")).startswith("https://"):
            raise ValueError(f"invalid {name} URL")
    runtime = manifest.get("runtime")
    if (
        not isinstance(runtime, dict)
        or set(runtime)
        not in (
            {"repository", "revision"},
            {"repository", "revision", "deployment_revision"},
        )
        or runtime.get("repository") != "https://github.com/Umi-BitSign/umi.git"
        or GIT_REVISION.fullmatch(str(runtime.get("revision"))) is None
        or (
            "deployment_revision" in runtime
            and GIT_REVISION.fullmatch(str(runtime["deployment_revision"])) is None
        )
    ):
        raise ValueError("invalid runtime")
    tracks = manifest.get("eligible_tracks")
    if tracks not in (["endpoint"], ["endpoint", "model"], ["model"]):
        raise ValueError("invalid eligible tracks")
    deployed = status.get("deployment") if isinstance(status, dict) else None
    if (
        status.get("schema") != "umi-competition-status/2"
        or status.get("policy_sha256") != manifest["policy"]["value_sha256"]
        or not isinstance(deployed, dict)
        or deployed.get("umi_git_revision")
        != runtime.get("deployment_revision", runtime["revision"])
        or deployed.get("eligible_tracks") != tracks
    ):
        raise ValueError("public status differs from upgrade manifest")
    if public_track == "yes" and "model" not in tracks:
        raise ValueError("the current cohort has no public-model track")
    if public_track == "no" and "endpoint" not in tracks:
        raise ValueError("the current cohort requires the public-model track")
    if manifest["public_model_track_required"] is not (tracks == ["model"]):
        raise ValueError("public-model requirement differs from eligible tracks")
    if type(manifest["maximum_recovery_assignments"]) is not int or not (
        1 <= manifest["maximum_recovery_assignments"] <= 1_000_000
    ):
        raise ValueError("invalid recovery capacity")


def option(arguments: list[str], name: str, *, required: bool = True) -> str | None:
    positions = [index for index, value in enumerate(arguments) if value == name]
    if len(positions) > 1 or (positions and positions[0] + 1 == len(arguments)):
        raise ValueError(f"ambiguous option {name}")
    if not positions:
        if required:
            raise ValueError(f"running miner is missing {name}")
        return None
    return arguments[positions[0] + 1]


def replace_option(arguments: list[str], name: str, value: str) -> None:
    positions = [index for index, item in enumerate(arguments) if item == name]
    if len(positions) > 1:
        raise ValueError(f"ambiguous option {name}")
    if positions:
        if positions[0] + 1 == len(arguments):
            raise ValueError(f"missing value for {name}")
        arguments[positions[0] + 1] = value
    else:
        arguments.extend((name, value))


def remove_option(arguments: list[str], name: str, *, repeatable: bool = False) -> None:
    while name in arguments:
        index = arguments.index(name)
        if index + 1 == len(arguments):
            raise ValueError(f"missing value for {name}")
        del arguments[index : index + 2]
        if not repeatable:
            if name in arguments:
                raise ValueError(f"ambiguous option {name}")
            break


def miner_command(
    arguments: list[str], runtime_python: str, state: Path, manifest: dict
) -> list[str]:
    updated = list(arguments)
    if python_module_miner(updated):
        updated[0] = runtime_python
        module_index = updated.index("-m")
        flags = [flag for flag in ("-I", "-B") if flag not in updated[1:module_index]]
        updated[module_index:module_index] = flags
    elif Path(updated[0]).name == "umi-miner":
        updated = [runtime_python, "-I", "-B", "-m", "umi.miner", *updated[1:]]
    else:
        raise ValueError("unsupported miner entry point")
    existing_cohort = option(arguments, "--competition-cohort-config", required=False)
    for name in (
        "--competition-feed",
        "--competition-authorization",
    ):
        remove_option(updated, name)
    if existing_cohort is None:
        remove_option(updated, "--competition-chain-config")
    remove_option(updated, "--competition-predecessor-policy", repeatable=True)
    inputs = state / "inputs"
    protocol = state / "protocol"
    replacements = {
        "--policy": str(inputs / "transport-policy.json"),
        "--competition-policy": str(inputs / "competition-policy.json"),
        "--competition-cohort-config": str(inputs / "miner-startup.json"),
        "--nonce-db": str(protocol / "nonces.sqlite3"),
        "--assignment-db": str(protocol / "assignments.sqlite3"),
        "--finality-state": str(protocol / "finality.sqlite3"),
        "--max-recovery-assignments": str(manifest["maximum_recovery_assignments"]),
    }
    for name, value in replacements.items():
        if existing_cohort is not None and name in {
            "--nonce-db",
            "--assignment-db",
            "--finality-state",
        }:
            # These are required options in cohort miners. A runtime upgrade
            # retains the exact paths and the unit's working directory.
            option(arguments, name)
            continue
        replace_option(updated, name, value)
    return updated


def installed_path(value: str, working_directory: Path) -> Path:
    path = Path(value)
    return path if path.is_absolute() else working_directory / path


def miner_identity(
    arguments: list[str], user: str, working_directory: Path = Path("/")
) -> tuple[str, str, str]:
    model = option(arguments, "--model-revision")
    origin = option(arguments, "--serving-origin")
    config_path = option(arguments, "--competition-cohort-config", required=False)
    hotkey = None
    if config_path is not None:
        config = document(
            installed_path(config_path, working_directory).read_bytes(),
            label="existing cohort startup",
        )
        authority = config.get("authority") if isinstance(config, dict) else None
        hotkey = authority.get("miner_hotkey") if isinstance(authority, dict) else None
    if hotkey is None:
        wallet_name = option(arguments, "--wallet-name")
        hotkey_name = option(arguments, "--hotkey")
        wallet_path = option(arguments, "--wallet-path", required=False)
        code = (
            "import bittensor as bt,sys;"
            "w=bt.wallet(name=sys.argv[1],hotkey=sys.argv[2],path=sys.argv[3] or None);"
            "print(w.hotkey.ss58_address)"
        )
        result = run(
            "runuser",
            "--user",
            user,
            "--",
            miner_python(arguments),
            "-c",
            code,
            str(wallet_name),
            str(hotkey_name),
            str(installed_path(wallet_path, working_directory)) if wallet_path else "",
        )
        hotkey = result.stdout.strip()
    if not isinstance(hotkey, str) or not hotkey:
        raise ValueError("existing cohort startup does not identify the miner hotkey")
    if HEX32.fullmatch(str(model)) is None:
        raise ValueError("running miner model revision differs")
    if not str(origin).startswith("https://"):
        raise ValueError("running miner serving origin differs")
    return hotkey, str(model), str(origin)


def startup(manifest: dict, state: Path, hotkey: str, model: str, origin: str) -> bytes:
    return canonical(
        {
            "authority": {
                "cohorts": [
                    {
                        "authority_sha256": manifest["service_authority_sha256"],
                        "cohort_sha256": manifest["cohort_sha256"],
                    }
                ],
                "directory": str(state / "grants"),
                "miner_hotkey": hotkey,
                "model_revision": model,
                "policy_sha256": manifest["policy"]["value_sha256"],
                "schema": "umi-cohort-service-miner-config/1",
                "service_terms_sha256": manifest["service_terms_sha256"],
                "serving_origin": origin,
                "transport_policy_sha256": manifest["transport"]["value_sha256"],
            },
            "history_origin": manifest["history_origin"],
            "history_owner_hotkey": manifest["history_owner_hotkey"],
            "schema": "umi-cohort-miner-startup/1",
        }
    )


def migration_startup(
    arguments: list[str],
    manifest: dict,
    state: Path,
    hotkey: str,
    model: str,
    origin: str,
    working_directory: Path = Path("/"),
) -> tuple[bytes, str]:
    """Select a supported installed-config transition without touching journals."""
    existing_path = option(arguments, "--competition-cohort-config", required=False)
    proposed = startup(manifest, state, hotkey, model, origin)
    if existing_path is None:
        return proposed, "legacy_to_cohort"
    raw = installed_path(existing_path, working_directory).read_bytes()
    current = document(raw, label="installed cohort startup")
    expected = document(proposed, label="target cohort startup")
    if current.get("schema") != expected["schema"]:
        raise ValueError("unsupported installed cohort startup schema; miner unchanged")
    authority = current.get("authority")
    if not isinstance(authority, dict):
        raise ValueError("installed cohort authority is missing; miner unchanged")
    directory = authority.get("directory")
    if not isinstance(directory, str) or not directory:
        raise ValueError("installed grant directory is missing; miner unchanged")
    grant_path = Path(directory)
    if (
        not grant_path.is_absolute()
        or grant_path == Path(grant_path.anchor)
        or ".." in grant_path.parts
    ):
        raise ValueError("unsupported installed grant directory; miner unchanged")
    expected["authority"]["directory"] = directory
    # These are the optional local limits in the supported native /1 schema,
    # excluded from the grant journal's authority binding. Preserve each exact
    # supplied value and omission; never replace it with an updater default.
    local_limits = {
        "maximum_grants": (1, 65536),
        "maximum_bytes": (1024, 16 * 1024**3),
        "read_timeout_seconds": (1, 3600),
    }
    for name, (minimum, maximum) in local_limits.items():
        if name in authority:
            value = authority[name]
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError("unsupported installed cohort local limit; miner unchanged")
            expected["authority"][name] = value
    if current != expected:
        # The journal binds this authority, including its policy and roster.
        # A future cohort/policy transition needs its explicit native migration;
        # changing a directory or copying the database cannot authorize it.
        raise ValueError("unsupported installed cohort authority transition; miner unchanged")
    for name in ("--nonce-db", "--assignment-db", "--finality-state"):
        option(arguments, name)
    return raw, "cohort_runtime_in_place"


@dataclass(frozen=True)
class Service:
    name: str
    pid: int
    user: str
    arguments: list[str]
    working_directory: Path = Path("/")


def python_module_miner(arguments: list[str]) -> bool:
    modules = [
        index
        for index in range(1, len(arguments) - 1)
        if arguments[index : index + 2] == ["-m", "umi.miner"]
    ]
    return (
        len(modules) == 1
        and bool(arguments)
        and Path(arguments[0]).is_absolute()
        and Path(arguments[0]).name.startswith("python")
    )


def run(
    *arguments: str, check: bool = True, timeout: int | None = 300
) -> subprocess.CompletedProcess:
    result = subprocess.run(arguments, check=False, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "no command output").strip()[-2000:]
        command = Path(arguments[0]).name
        raise RuntimeError(f"{command} exited {result.returncode}: {detail}")
    return result


def cmdline(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return [os.fsdecode(value) for value in raw.rstrip(b"\0").split(b"\0")]


class ServiceNotRunning(ValueError):
    """The unit has no current process; malformed live layouts are separate errors."""


def service(name: str) -> Service:
    if SYSTEMD_UNIT.fullmatch(name) is None:
        raise ValueError("systemd unit name differs")
    values = {}
    result = run("systemctl", "show", name, "--property=MainPID", "--property=User")
    for line in result.stdout.splitlines():
        key, _, value = line.partition("=")
        values[key] = value
    pid = int(values.get("MainPID", "0"))
    user = values.get("User") or "root"
    if pid <= 0:
        raise ServiceNotRunning(f"{name} is not one running service")
    working_directory = Path(os.readlink(f"/proc/{pid}/cwd"))
    if not working_directory.is_absolute() or not working_directory.is_dir():
        raise ValueError("running service working directory is unavailable")
    return Service(
        name=name,
        pid=pid,
        user=user,
        arguments=cmdline(pid),
        working_directory=working_directory,
    )


def discover_miner() -> Service:
    units = run(
        "systemctl",
        "list-units",
        "--type=service",
        "--state=running",
        "--no-legend",
        "--plain",
    ).stdout.splitlines()
    matches = []
    for line in units:
        name = line.split(maxsplit=1)[0] if line.split() else ""
        if not name.endswith(".service"):
            continue
        try:
            candidate = service(name)
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
        args = candidate.arguments
        if python_module_miner(args) or (args and Path(args[0]).name == "umi-miner"):
            matches.append(candidate)
    if len(matches) != 1:
        raise ValueError(f"expected one running UMI miner service, found {len(matches)}")
    return matches[0]


def write_private(path: Path, raw: bytes, account: pwd.struct_passwd) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    pending.unlink(missing_ok=True)
    pending.write_bytes(raw)
    os.chown(pending, account.pw_uid, account.pw_gid)
    pending.chmod(0o600)
    with pending.open("rb") as stream:
        os.fsync(stream.fileno())
    os.replace(pending, path)
    fsync_directory(path.parent)


def fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def command_file(path: Path, arguments: list[str], account: pwd.struct_passwd) -> str:
    raw = canonical({"arguments": arguments, "schema": "umi-miner-upgrade-command/1"})
    write_private(path, raw, account)
    return sha256(raw)


def launch_command(path: Path, expected: str) -> None:
    if HEX32.fullmatch(expected) is None:
        raise ValueError("invalid command digest")
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
            or not 0 < info.st_size <= 1024 * 1024
        ):
            raise ValueError("unsafe command file")
        raw = stream.read(1024 * 1024 + 1)
    if sha256(raw) != expected:
        raise ValueError("command file digest differs")
    value = document(raw, label="service command")
    arguments = value.get("arguments")
    if (
        set(value) != {"arguments", "schema"}
        or value.get("schema") != "umi-miner-upgrade-command/1"
        or not isinstance(arguments, list)
        or not arguments
        or any(not isinstance(item, str) or "\x00" in item for item in arguments)
        or canonical(value) != raw
        or not Path(arguments[0]).is_absolute()
    ):
        raise ValueError("service command differs")
    os.execv(arguments[0], arguments)


def override(
    service_name: str,
    command_path: Path,
    command_sha256: str,
    launcher_python: Path,
    startup_seconds: float,
    working_directory: Path | None = None,
) -> Path:
    if not launcher_python.is_absolute():
        raise ValueError("launcher interpreter is not absolute")
    path = SYSTEMD_ROOT / f"{service_name}.d" / "90-umi-cohort-upgrade.conf"
    raw = override_bytes(
        command_path, command_sha256, launcher_python, startup_seconds, working_directory
    )
    _root_file(path, raw, 0o644)
    return path


def override_bytes(
    command_path, command_sha256, launcher_python, startup_seconds, working_directory=None
):
    directory = ""
    if working_directory is not None:
        value = str(working_directory)
        if (
            not Path(value).is_absolute()
            or any(ord(character) < 32 for character in value)
            or value != value.rstrip()
            or value.endswith("\\")
        ):
            raise ValueError("unsupported service working directory; services unchanged")
        # WorkingDirectory takes the entire literal value, not a shell-quoted
        # token. Quotes are filename characters; only systemd specifiers expand.
        directory = "WorkingDirectory=" + value.replace("%", "%%") + "\n"
    return (
        "[Service]\n"
        + COOPERATIVE_SERVICE_SETTINGS
        + directory
        + f"TimeoutStartSec={startup_seconds}s\nExecStart=\n"
        f"ExecStart={launcher_python} -I -B {LAUNCHER} --run-command "
        f"{command_path} {command_sha256}\n"
    ).encode()


def unit_for_pid(pid: int) -> str | None:
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        path = line.rpartition(":")[2]
        name = path.rsplit("/", 1)[-1]
        if name.endswith(".service"):
            return name
    return None


def runtime_limits(arguments: list[str], state: Path) -> dict:
    """Use the selected runtime's resolver, without wallets or service changes."""
    code = (
        "import json,sys; from pathlib import Path; "
        "from umi.config import Limits; from umi.open_competition import CompetitionPolicy; "
        "from umi.policy import ScoringPolicy; "
        "p=CompetitionPolicy.model_validate_json(Path(sys.argv[1]).read_bytes()); "
        "t=ScoringPolicy.model_validate_json(Path(sys.argv[2]).read_bytes()); "
        "override=None if not sys.argv[3] else float(sys.argv[3]); "
        "lifecycle=None if not sys.argv[4] else float(sys.argv[4]); "
        "v=Limits.from_policy(t,competition_policy=p,inference_timeout_seconds=override,"
        "backend_lifecycle_timeout_seconds=lifecycle); "
        "print(json.dumps({'inference_seconds':v.inference_timeout_seconds,"
        "'startup_seconds':2*v.backend_lifecycle_timeout_seconds}))"
    )
    result = run(
        arguments[0],
        "-I",
        "-B",
        "-c",
        code,
        str(state / "inputs/competition-policy.json"),
        str(state / "inputs/transport-policy.json"),
        option(arguments, "--inference-timeout", required=False) or "",
        option(arguments, "--backend-lifecycle-timeout", required=False) or "",
    )
    value = document(result.stdout.encode(), label="effective runtime limits")
    for key in ("inference_seconds", "startup_seconds"):
        budget = value.get(key)
        if (
            isinstance(budget, bool)
            or not isinstance(budget, (int, float))
            or not 0 < budget < float("inf")
        ):
            raise ValueError("selected runtime returned an invalid " + key)
    return value


def runtime_inference_seconds(arguments: list[str], state: Path) -> float:
    return runtime_limits(arguments, state)["inference_seconds"]


def validate_startup(
    arguments: list[str],
    account: pwd.struct_passwd,
    working_directory: Path,
    hotkey: str,
    manifest: dict,
) -> None:
    """Read and check native startup as the retained account, before service changes.

    No wallet, authority or journal is opened. The selected interpreter applies
    its own secure reader and schemas to the exact paths the service will use.
    """
    selected = {
        "cwd": str(working_directory),
        "hotkey": hotkey,
        "model": option(arguments, "--model-revision"),
        "origin": option(arguments, "--serving-origin"),
        "policy": option(arguments, "--competition-policy"),
        "policy_sha256": manifest["policy"]["sha256"],
        "transport": option(arguments, "--policy"),
        "transport_sha256": manifest["transport"]["sha256"],
        "startup": option(arguments, "--competition-cohort-config"),
        "state_files": [
            option(arguments, name)
            for name in ("--nonce-db", "--assignment-db", "--finality-state")
        ],
    }
    code = """
import hashlib,json,os,sys
from umi.miner import _read_startup_file
from umi.competition_authorization import validate_transport_cohort
from umi.competition_cohort_miner_startup import CohortMinerStartupConfig
from umi.open_competition import CompetitionPolicy
from umi.policy import ScoringPolicy
v=json.loads(sys.argv[1])
os.chdir(v['cwd'])
p=_read_startup_file(v['policy'],label='competition policy')
t=_read_startup_file(v['transport'],label='scoring policy')
if hashlib.sha256(p).hexdigest()!=v['policy_sha256']:
    raise ValueError('installed competition policy differs from selected manifest')
if hashlib.sha256(t).hexdigest()!=v['transport_sha256']:
    raise ValueError('installed scoring policy differs from selected manifest')
p=CompetitionPolicy.model_validate_json(p)
t=ScoringPolicy.model_validate_json(t)
validate_transport_cohort(p,t)
c=CohortMinerStartupConfig.model_validate_json(
    _read_startup_file(v['startup'],label='cohort miner configuration'))
c.check(policy=p,transport=t,miner_hotkey=v['hotkey'],model_revision=v['model'],
        serving_origin=v['origin'],state_files=v['state_files'])
"""
    run(
        "runuser",
        "--user",
        account.pw_name,
        "--",
        miner_python(arguments),
        "-I",
        "-B",
        "-c",
        code,
        canonical(selected).decode(),
    )


def prepare_sidecar(
    arguments: list[str], state: Path, account: pwd.struct_passwd, transport: str
) -> tuple[Service | None, list[str], Path | None]:
    socket = option(arguments, "--translator-unix-socket", required=False)
    if socket is None:
        return None, arguments, None
    capacity_path = Path(socket + ".capacity.json")
    capacity = document(capacity_path.read_bytes(), label="model capacity")
    inference_seconds = runtime_inference_seconds(arguments, state)
    if capacity.get("scoring_policy_sha256") == transport and capacity.get(
        "maximum_inference_milliseconds"
    ) == round(inference_seconds * 1000):
        return None, arguments, Path(socket)
    pid = capacity.get("process_id")
    if type(pid) is not int or pid <= 0:
        raise ValueError("model capacity does not identify its process")
    unit = unit_for_pid(pid)
    if unit is None:
        raise ValueError("model sidecar is not managed by systemd")
    sidecar = service(unit)
    if sidecar.user != account.pw_name:
        raise ValueError("miner and model sidecar use different service accounts")
    config_path = option(sidecar.arguments, "--config")
    expected = option(sidecar.arguments, "--expected-config-sha256")
    raw = installed_path(config_path, sidecar.working_directory).read_bytes()
    if sha256(raw) != expected:
        raise ValueError("model sidecar configuration differs from its command")
    config = document(raw, label="model sidecar configuration")
    if config.get("socket_path") != socket:
        raise ValueError("model sidecar socket differs")
    workers = config.get("workers")
    if (
        config.get("schema") != "umi-community-model-service/1"
        or not isinstance(workers, list)
        or not workers
        or any(not isinstance(w, dict) or "inference_seconds" not in w for w in workers)
    ):
        raise ValueError("model sidecar budget migration is unsupported; services unchanged")
    for worker in workers:
        worker["inference_seconds"] = inference_seconds
    scope = sha256(canonical([transport, inference_seconds, capacity.get("model_revision")]))[:16]
    new_socket = state / "model" / scope / "model.sock"
    service_directory(state / "model", account)
    service_directory(new_socket.parent, account)
    config["socket_path"] = str(new_socket)
    config["scoring_policy_sha256"] = transport
    config_raw = canonical(config)
    new_config = state / "inputs" / ("model-service-" + sha256(config_raw) + ".json")
    write_private(new_config, config_raw, account)
    updated_miner = list(arguments)
    replace_option(updated_miner, "--translator-unix-socket", str(new_socket))
    updated_sidecar = list(sidecar.arguments)
    replace_option(updated_sidecar, "--config", str(new_config))
    replace_option(updated_sidecar, "--expected-config-sha256", sha256(config_raw))
    return replace(sidecar, arguments=updated_sidecar), updated_miner, new_socket


def wait_health(port: int, policy: str, transport: str, model: str, *, seconds: float) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            raw = fetch(f"http://127.0.0.1:{port}/healthz", maximum=128 * 1024)
            value = document(raw, label="miner health")
            if (
                value.get("ok") is True
                and value.get("competition_policy_sha256") == policy
                and value.get("scoring_policy_sha256") == transport
                and value.get("model_revision") == model
                and value.get("finality_service") == "running"
            ):
                return value
        except (OSError, ValueError, urllib.error.URLError, json.JSONDecodeError):
            pass
        time.sleep(5)
    raise ValueError("miner startup timed out")


def wait_capacity(socket: Path, transport: str, model: str, *, seconds: float) -> dict:
    deadline = time.monotonic() + seconds
    capacity_path = socket.with_name(socket.name + ".capacity.json")
    while time.monotonic() < deadline:
        try:
            value = document(capacity_path.read_bytes(), label="model capacity")
            pid = value.get("process_id")
            socket_info = socket.lstat()
            if (
                type(pid) is int
                and pid > 0
                and stat.S_ISSOCK(socket_info.st_mode)
                and value.get("scoring_policy_sha256") == transport
                and value.get("model_revision") == model
                and value.get("socket_device") == socket_info.st_dev
                and value.get("socket_inode") == socket_info.st_ino
            ):
                os.kill(pid, 0)
                return value
        except (FileNotFoundError, OSError, TypeError, ValueError, json.JSONDecodeError):
            pass
        time.sleep(5)
    raise ValueError("model sidecar startup timed out")


def secure_root(path: Path) -> None:
    path.mkdir(mode=0o755, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or info.st_gid != 0
        or stat.S_IMODE(info.st_mode) not in {0o700, 0o755}
    ):
        raise ValueError(f"unsafe root directory: {path}")
    path.chmod(0o755)
    fsync_directory(path)
    fsync_directory(path.parent)


def acquire_upgrade_lock():
    secure_root(ROOT)
    fd = os.open(ROOT / "upgrade.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        metadata = os.fstat(fd)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("unsafe miner upgrade lock; services unchanged")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fd
    except BaseException:
        os.close(fd)
        raise


def service_directory(path: Path, account: pwd.struct_passwd) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
        raise ValueError(f"unsafe service directory: {path}")
    if (info.st_uid, info.st_gid) == (0, 0):
        os.chown(path, account.pw_uid, account.pw_gid)
    elif (info.st_uid, info.st_gid) != (account.pw_uid, account.pw_gid):
        raise ValueError(f"service directory owner differs: {path}")
    path.chmod(0o700)


def seal_tree(root: Path) -> None:
    for directory, names, files in os.walk(root, topdown=False, followlinks=False):
        for name in (*names, *files):
            os.chown(Path(directory) / name, 0, 0, follow_symlinks=False)
    os.chown(root, 0, 0)


def scoring_runtime_pins(transport_path: Path) -> dict:
    policy = document(transport_path.read_bytes(), label="transport policy")
    implementation = policy.get("implementation_pins", {})
    if not isinstance(implementation, dict):
        raise ValueError("the transport policy implementation pins are invalid")
    pins = implementation.get("scoring")
    variants = implementation.get("scoring_by_target")
    if variants is not None:
        if not isinstance(variants, dict):
            raise ValueError("the transport policy scoring targets are invalid")
        architecture = {"aarch64": "aarch64", "arm64": "aarch64", "x86_64": "x86_64"}.get(
            platform.machine().lower()
        )
        if (
            platform.system() != "Linux"
            or platform.libc_ver()[0] != "glibc"
            or architecture is None
        ):
            raise ValueError("the scoring runtime target is not supported")
        pins = variants.get(architecture + "-unknown-linux-gnu")
    if not isinstance(pins, dict) or pins.get("python_implementation") != "CPython":
        raise ValueError("the active transport policy has no scoring runtime pins for this host")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", str(pins.get("python_version", ""))):
        raise ValueError("the active scoring policy requires an unsupported Python version")
    for package in ("regex", "rfc8785", "pydantic", "pydantic_core"):
        version = pins.get(package + "_distribution_version")
        if not isinstance(version, str) or not re.fullmatch(
            r"[0-9][A-Za-z0-9.!+_-]{0,63}", version
        ):
            raise ValueError("the active scoring policy has an invalid package version")
    return pins


def runtime_directory(runtime: dict, transport_path: Path) -> Path:
    pins = scoring_runtime_pins(transport_path)
    return RUNTIME_ROOT / (runtime["revision"] + "-" + sha256(canonical(pins))[:16])


def policy_python(current_python: str, pins: dict) -> str:
    version = pins["python_version"]
    candidates = (
        current_python,
        shutil.which("python" + version),
        shutil.which("python" + version.rsplit(".", 1)[0]),
        "/usr/bin/python" + version.rsplit(".", 1)[0],
    )
    tried = set()
    for candidate in candidates:
        if not candidate or candidate in tried or not Path(candidate).is_absolute():
            continue
        tried.add(candidate)
        path = Path(candidate).resolve()
        if not path.is_file():
            continue
        info = path.stat()
        if info.st_uid != 0 or info.st_gid != 0 or stat.S_IMODE(info.st_mode) & 0o022:
            continue
        result = run(
            str(path),
            "-I",
            "-B",
            "-c",
            "import platform;raise SystemExit((platform.python_implementation(),"
            "platform.python_version()) != " + repr((pins["python_implementation"], version)) + ")",
            check=False,
        )
        if result.returncode == 0:
            return str(path)
    raise ValueError(
        "a root-owned CPython " + version + " is required by the active scoring policy"
    )


def install_runtime(
    current_python: str, runtime: dict, account: pwd.struct_passwd, transport_path: Path
) -> Path:
    secure_root(RUNTIME_ROOT)
    pins = scoring_runtime_pins(transport_path)
    target = runtime_directory(runtime, transport_path)
    python = target / "venv" / "bin" / "python"
    prefix = ["runuser", "--user", account.pw_name, "--"]
    verification = (
        "import importlib.metadata as m,json,sys;"
        "d=m.distribution('umi-subnet');"
        "p=next(d.locate_file(x) for x in d.files if str(x).endswith('direct_url.json'));"
        "v=json.loads(p.read_text())['vcs_info'];"
        f"assert v['commit_id']=='{runtime['revision']}';"
        "from umi.policy import ScoringPolicy,validate_scoring_runtime;"
        "from pathlib import Path;"
        "validate_scoring_runtime(ScoringPolicy.model_validate_json(Path(sys.argv[1]).read_bytes()));"
        "import umi;print(umi.__file__)"
    )
    if not target.exists():
        base_python = policy_python(current_python, pins)
        staging = target.with_name(target.name + ".pending")
        if staging.exists():
            info = staging.lstat()
            if (
                not stat.S_ISDIR(info.st_mode)
                or stat.S_ISLNK(info.st_mode)
                or info.st_uid != 0
                or info.st_gid != 0
            ):
                raise ValueError("incomplete runtime staging path differs")
            shutil.rmtree(staging)
        staging.mkdir(mode=0o755)
        staging_python = staging / "venv" / "bin" / "python"
        run(base_python, "-I", "-B", "-m", "venv", "--copies", str(staging / "venv"))
        requirements = [
            name + "==" + pins[key + "_distribution_version"]
            for name, key in (
                ("regex", "regex"),
                ("rfc8785", "rfc8785"),
                ("pydantic", "pydantic"),
                ("pydantic-core", "pydantic_core"),
            )
        ]
        environment = [
            "/usr/bin/env",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "PIP_CONFIG_FILE=/dev/null",
            "PIP_NO_CACHE_DIR=1",
            "PYTHONDONTWRITEBYTECODE=1",
            "UV_PYTHON_DOWNLOADS=never",
        ]
        # The installed-distribution hashes include INSTALLER metadata. Use the
        # same installer as the approved profile, not rewritten metadata from pip.
        run(
            *environment,
            str(staging_python),
            "-I",
            "-B",
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--index-url",
            "https://pypi.org/simple",
            "uv==" + UV_BOOTSTRAP_VERSION,
            timeout=3600,
        )
        run(
            *environment,
            str(staging_python),
            "-I",
            "-B",
            "-m",
            "uv",
            "--no-config",
            "--no-cache",
            "pip",
            "install",
            "--python",
            str(staging_python),
            "--default-index",
            "https://pypi.org/simple",
            f"git+{runtime['repository']}@{runtime['revision']}",
            *requirements,
            timeout=3600,
        )
        run(str(staging_python), "-I", "-B", "-m", "pip", "check")
        run(*prefix, str(staging_python), "-I", "-B", "-c", verification, str(transport_path))
        seal_tree(staging)
        os.replace(staging, target)
    else:
        info = target.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or info.st_gid != 0
        ):
            raise ValueError("existing runtime directory differs")
    if not python.exists():
        raise ValueError("runtime interpreter is missing")
    check = run(*prefix, str(python), "-I", "-B", "-c", verification, str(transport_path))
    if not check.stdout.strip():
        raise ValueError("installed runtime did not import")
    return python


def miner_python(arguments: list[str]) -> str:
    if python_module_miner(arguments):
        return arguments[0]
    if arguments and Path(arguments[0]).name == "umi-miner":
        first = Path(arguments[0]).read_bytes().splitlines()[0]
        if not first.startswith(b"#!"):
            raise ValueError("miner entry point has no interpreter")
        value = os.fsdecode(first[2:]).strip()
        if not Path(value).is_absolute() or " " in value:
            raise ValueError("miner entry point interpreter differs")
        return value
    raise ValueError("unsupported miner entry point")


def install_launcher(source: Path) -> None:
    raw = source.read_bytes()
    compile(raw, str(source), "exec")
    LAUNCHER.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    pending = LAUNCHER.with_name(LAUNCHER.name + ".pending")
    pending.write_bytes(raw)
    os.chown(pending, 0, 0)
    pending.chmod(0o755)
    os.replace(pending, LAUNCHER)


def model_client_run(*arguments: str) -> subprocess.CompletedProcess:
    """Keep a user's endpoint environment out of the separate client install."""
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(("PYTHON", "PIP_", "UV_", "GIT_")) and key != "VIRTUAL_ENV"
    }
    environment.update(
        PYTHONDONTWRITEBYTECODE="1",
        PIP_CONFIG_FILE=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_CONFIG_NOSYSTEM="1",
    )
    result = subprocess.run(arguments, text=True, capture_output=True, env=environment)
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()[-2000:]
        raise RuntimeError(f"model client installation failed: {detail}")
    return result


def ensure_model_client_python(*, running_version=None, candidate_paths=None) -> None:
    """Re-exec the model client installer before fetching a manifest on old Python."""
    version = sys.version_info[:2] if running_version is None else running_version
    if (3, 10) <= tuple(version) < (3, 15):
        return
    if sys.platform not in {"linux", "darwin"}:
        raise ValueError("the model client requires Linux/macOS and Python 3.10 through 3.14")
    requested = os.environ.get("UMI_MODEL_CLIENT_PYTHON")
    if candidate_paths is None:
        names = (
            "python3.12", "python3.13", "python3.14", "python3.11", "python3.10",
            "/opt/homebrew/bin/python3.12", "/opt/homebrew/bin/python3.13",
            "/opt/homebrew/bin/python3.14", "/opt/homebrew/bin/python3.11",
            "/opt/homebrew/bin/python3.10", "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3.12", "/usr/local/bin/python3.13",
            "/usr/local/bin/python3.14", "/usr/local/bin/python3.11",
            "/usr/local/bin/python3.10", "/usr/local/bin/python3", "python3",
        )
        candidate_paths = (requested,) if requested else names
    seen = set()
    for name in candidate_paths:
        candidate = shutil.which(name)
        if candidate is None or candidate in seen:
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-I", "-B", "-c",
                 "import sys; raise SystemExit(0 if sys.platform in ('linux', 'darwin') "
                 "and (3, 10) <= sys.version_info[:2] < (3, 15) else 1)"],
                capture_output=True, text=True, timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if probe.returncode == 0:
            os.execv(candidate, [candidate, "-I", "-B", *sys.argv])
            raise RuntimeError("supported Python re-exec unexpectedly returned")
    raise ValueError(
        "the model client requires Python 3.10 through 3.14; install one or set "
        "UMI_MODEL_CLIENT_PYTHON to its executable path"
    )


def model_client_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o022
    ):
        raise ValueError("model client directory ownership or mode differs")


def model_client_write(path: Path, raw: bytes, mode: int = 0o600) -> None:
    """Never truncate a selected command or receipt during a repeat installation."""
    pending = path.with_name(path.name + ".pending")
    pending.unlink(missing_ok=True)
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(pending, path)
    finally:
        pending.unlink(missing_ok=True)


def install_model_client(manifest: dict, directory: Path) -> dict:
    """Install a locked CLI without discovering or changing any endpoint service."""
    if sys.platform not in {"linux", "darwin"} or not (3, 10) <= sys.version_info[:2] < (3, 15):
        raise ValueError("the model client requires Linux/macOS and Python 3.10 through 3.14")
    if not directory.is_absolute() or directory.resolve() != directory:
        raise ValueError("the model client directory must be an absolute, non-symlink path")
    marker = directory / "model-client.json"
    marker_raw = canonical({"schema": "umi-model-client-installation/1"})
    if directory.exists() and not marker.exists() and any(directory.iterdir()):
        raise ValueError("refusing to reuse an unrelated model client directory")
    model_client_directory(directory)
    if marker.exists() and (marker.is_symlink() or marker.read_bytes() != marker_raw):
        raise ValueError("model client installation marker differs")
    descriptor = os.open(directory / "install.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        model_client_write(marker, marker_raw)
        return _install_model_client(manifest, directory)


def _install_model_client(manifest: dict, directory: Path) -> dict:
    revision = manifest["runtime"]["revision"]
    identity = revision + "-" + platform.python_implementation().lower() + platform.python_version()
    model_client_directory(directory / "releases")
    target = directory / "releases" / identity
    model_client_directory(target)
    source = target / "source"
    if not source.exists():
        staging = target / "source.pending"
        if staging.exists():
            model_client_directory(staging)
            shutil.rmtree(staging)
        model_client_directory(staging)
        print(
            "Installing the selected model client source and locked dependencies…", file=sys.stderr
        )
        model_client_run(
            "git",
            "clone",
            "--filter=blob:none",
            "--no-checkout",
            manifest["runtime"]["repository"],
            str(staging),
        )
        model_client_run("git", "-C", str(staging), "checkout", "--detach", revision)
        os.replace(staging, source)
    model_client_directory(source)
    if model_client_run("git", "-C", str(source), "rev-parse", "HEAD").stdout.strip() != revision:
        raise ValueError("model client source revision differs")
    if model_client_run("git", "-C", str(source), "status", "--porcelain").stdout.strip():
        raise ValueError("model client source has local changes")
    bootstrap = directory / ("installer-uv-" + UV_BOOTSTRAP_VERSION)
    model_client_directory(bootstrap)
    if not (bootstrap / "bin/python").exists():
        model_client_run(sys.executable, "-I", "-B", "-m", "venv", str(bootstrap))
    bootstrap_python = bootstrap / "bin/python"
    model_client_run(
        str(bootstrap_python),
        "-I",
        "-B",
        "-m",
        "pip",
        "install",
        "--disable-pip-version-check",
        "--no-cache-dir",
        "--no-input",
        "--index-url",
        "https://pypi.org/simple",
        "uv==" + UV_BOOTSTRAP_VERSION,
    )
    python = target / "venv/bin/python"
    sync = (
        str(bootstrap_python),
        "-I",
        "-B",
        "-m",
        "uv",
        "--no-config",
        "--no-cache",
        "sync",
        "--locked",
        "--no-editable",
        "--no-dev",
        "--no-default-groups",
        "--project",
        str(source),
        "--python",
        sys.executable,
        "--no-python-downloads",
    )
    # uv's explicit environment selection is scoped to this subprocess, never the
    # running endpoint's VIRTUAL_ENV. Keep the final venv path stable after install.
    sync = ("/usr/bin/env", "UV_PROJECT_ENVIRONMENT=" + str(target / "venv"), *sync)
    receipt = target / "installation.json"
    model_client_run(*sync, *(("--check",) if receipt.exists() else ()))
    model_client_run(
        str(bootstrap_python),
        "-I",
        "-B",
        "-m",
        "uv",
        "--no-config",
        "--no-cache",
        "pip",
        "check",
        "--python",
        str(python),
    )
    verification = (
        "import hashlib,importlib.metadata as m,json,sys;from pathlib import Path;import umi;"
        "root=Path(sys.argv[1]);installed=Path(umi.__file__).parent;"
        "assert installed.is_relative_to(Path(sys.prefix));"
        "files=list((root/'src/umi').rglob('*.py'));"
        "assert files and all((installed/p.relative_to(root/'src/umi')).read_bytes()"
        "==p.read_bytes() "
        "for p in files);"
        "url=json.loads(m.distribution('umi-subnet').read_text('direct_url.json'));"
        "assert not url.get('dir_info',{}).get('editable',False);"
        "print(json.dumps({'module':str(installed),'python':sys.version.split()[0],"
        "'source_files':len(files),'lock_sha256':hashlib.sha256((root/'uv.lock').read_bytes()).hexdigest()}))"
    )
    verified = document(
        model_client_run(str(python), "-I", "-B", "-c", verification, str(source)).stdout.encode(),
        label="installed model client verification",
    )
    model_client_run(
        str(python), "-I", "-B", "-m", "umi.competition_cli", "submit-cohort-model", "--help"
    )
    command = target / "umi-model-client"
    model_client_write(
        command,
        (
            "#!/bin/sh\nexec " + shlex.quote(str(python)) + ' -I -B -m umi.competition_cli "$@"\n'
        ).encode(),
        0o700,
    )
    report = {
        "schema": "umi-model-client-installation-receipt/1",
        "status": "model_client_installed",
        "runtime_revision": revision,
        "deployment_revision": manifest["runtime"].get("deployment_revision", revision),
        "policy_sha256": manifest["policy"]["value_sha256"],
        "endpoint_service_unchanged": True,
        "command": str(directory / "umi-model-client"),
        "runtime_python": str(python),
        "verification": verified,
    }
    model_client_write(receipt, canonical(report))
    selected = directory / "umi-model-client"
    if selected.exists() and not selected.is_symlink():
        raise ValueError("refusing to replace a non-client command")
    pending = directory / "umi-model-client.pending"
    pending.unlink(missing_ok=True)
    pending.symlink_to(command)
    os.replace(pending, selected)
    return report


@contextmanager
def cooperative_upgrade(services: tuple[Service, ...]):
    """Protect the installed version before its first stop, including rollback.

    A runtime drop-in survives an interrupted updater until reboot. It is only
    removed after systemd is no longer starting or draining any affected unit.
    The selected permanent override retains the same cooperative stop behavior.
    """
    paths = []
    raw = ("[Service]\n" + COOPERATIVE_SERVICE_SETTINGS + "TimeoutStartSec=infinity\n").encode()
    for entry in services:
        if SYSTEMD_UNIT.fullmatch(entry.name) is None:
            raise ValueError("systemd unit name differs")
        path = SYSTEMD_RUNTIME_ROOT / f"{entry.name}.d" / "zz-umi-cohort-upgrade-drain.conf"
        if path.exists() and (path.is_symlink() or path.read_bytes() != raw):
            raise ValueError("existing cooperative upgrade guard differs")
        paths.append(path)
    # Use this single-file distribution's standalone policy path before changing
    # any service. Older installed runtimes need no new module or state reset.
    policy = run(
        sys.executable,
        "-I",
        "-B",
        str(Path(__file__).resolve()),
        "--install-restart-policy",
        *(argument for entry in services for argument in ("--service", entry.name)),
    )
    if policy.stdout:
        print(policy.stdout, end="", flush=True)
    try:
        for path in paths:
            _root_file(path, raw, 0o644)
        run("systemctl", "daemon-reload")
        for entry in services:
            observed = run(
                "systemctl",
                "show",
                entry.name,
                "--property=TimeoutStopUSec,TimeoutStartUSec,SendSIGKILL,KillMode,KillSignal,SendSIGHUP",
            )
            expected = {
                "TimeoutStopUSec=infinity",
                "TimeoutStartUSec=infinity",
                "SendSIGKILL=no",
                "KillMode=mixed",
                "KillSignal=15",
                "SendSIGHUP=no",
            }
            if set(observed.stdout.splitlines()) != expected:
                raise ValueError("installed service does not support cooperative upgrade")
        yield
    finally:
        # Never remove protection while an interrupted command is still
        # draining. In particular, Ctrl-C must not restore a short kill timer.
        settled = True
        for entry in services:
            try:
                result = run(
                    "systemctl",
                    "show",
                    entry.name,
                    "--property=ActiveState,ControlGroup",
                    check=False,
                )
                values = dict(line.split("=", 1) for line in result.stdout.splitlines())
                state, group = values.get("ActiveState"), values.get("ControlGroup")
                drained = state == "active"
                if state in {"inactive", "failed"} and group is not None:
                    drained = not group
                    if group:
                        events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
                        drained = "populated 0" in events.read_text().splitlines()
                settled = settled and result.returncode == 0 and drained
            except Exception:
                settled = False
        if settled:
            for path in paths:
                path.unlink(missing_ok=True)
            run("systemctl", "daemon-reload", check=False)
        else:
            print(canonical({"status": "miner_upgrade_drain_guard_retained"}).decode(), flush=True)


def activate_services(
    *,
    miner: Service,
    sidecar: Service | None,
    miner_command_path: Path,
    miner_command_sha: str,
    sidecar_command_path: Path | None,
    sidecar_command_sha: str | None,
    launcher_python: Path,
    new_socket: Path | None,
    port: int,
    policy: str,
    transport: str,
    model: str,
    startup_seconds: float,
    previous_overrides: dict | None = None,
) -> dict:
    miner_dropin = SYSTEMD_ROOT / f"{miner.name}.d" / "90-umi-cohort-upgrade.conf"
    sidecar_dropin = (
        SYSTEMD_ROOT / f"{sidecar.name}.d" / "90-umi-cohort-upgrade.conf"
        if sidecar is not None
        else None
    )
    previous_miner = miner_dropin.read_bytes() if miner_dropin.exists() else None
    previous_sidecar = (
        sidecar_dropin.read_bytes()
        if sidecar_dropin is not None and sidecar_dropin.exists()
        else None
    )
    if previous_overrides is not None:
        value = previous_overrides[miner.name]
        previous_miner = bytes.fromhex(value) if value is not None else None
        if sidecar is not None:
            value = previous_overrides[sidecar.name]
            previous_sidecar = bytes.fromhex(value) if value is not None else None
    services = (miner,) if sidecar is None else (miner, sidecar)
    with cooperative_upgrade(services):
        try:
            run("systemctl", "stop", miner.name, timeout=None)
            if sidecar is not None:
                run("systemctl", "stop", sidecar.name, timeout=None)
            override(
                miner.name,
                miner_command_path,
                miner_command_sha,
                launcher_python,
                startup_seconds,
                miner.working_directory,
            )
            if (
                sidecar is not None
                and sidecar_command_path is not None
                and sidecar_command_sha is not None
            ):
                override(
                    sidecar.name,
                    sidecar_command_path,
                    sidecar_command_sha,
                    launcher_python,
                    startup_seconds,
                    sidecar.working_directory,
                )
            run("systemctl", "daemon-reload")
            if sidecar is not None:
                run("systemctl", "start", sidecar.name, timeout=None)
                if new_socket is None:
                    raise ValueError("prepared model socket is missing")
                wait_capacity(new_socket, transport, model, seconds=startup_seconds)
            run("systemctl", "start", miner.name, timeout=None)
            return wait_health(port, policy, transport, model, seconds=startup_seconds)
        except Exception:
            run("systemctl", "stop", miner.name, timeout=None)
            if sidecar is not None:
                run("systemctl", "stop", sidecar.name, timeout=None)
            for path, raw in ((miner_dropin, previous_miner), (sidecar_dropin, previous_sidecar)):
                if path is None:
                    continue
                if raw is None:
                    path.unlink(missing_ok=True)
                    if path.parent.exists():
                        fsync_directory(path.parent)
                else:
                    _root_file(path, raw, 0o644)
            run("systemctl", "daemon-reload", check=False)
            if sidecar is not None:
                run("systemctl", "start", sidecar.name, check=False, timeout=None)
            run("systemctl", "start", miner.name, check=False, timeout=None)
            raise


class EnrollmentRetry(RuntimeError):
    """A durable endpoint enrollment should be retried without changing its bytes."""


class ServiceClaimRetry(EnrollmentRetry):
    """A durable service claim should be retried without changing its bytes."""


def endpoint_enrollment_config(
    arguments: list[str],
    manifest: dict,
    hotkey: str,
    model: str,
    origin: str,
    public_model_track: bool,
    working_directory: Path = Path("/"),
) -> bytes:
    wallet_name = option(arguments, "--wallet-name")
    hotkey_name = option(arguments, "--hotkey")
    wallet_path = option(arguments, "--wallet-path", required=False)
    return canonical(
        {
            "cohort_sha256": manifest["cohort_sha256"],
            "endpoint_url": origin,
            "hotkey_name": hotkey_name,
            "intake_origin": manifest["history_origin"].rstrip("/"),
            "miner_hotkey": hotkey,
            "model_revision": model,
            "policy_sha256": manifest["policy"]["value_sha256"],
            "public_model_track": public_model_track,
            "schema": "umi-miner-cohort-enrollment/1",
            "service_authority_sha256": manifest["service_authority_sha256"],
            "wallet_name": wallet_name,
            "wallet_path": (
                str(installed_path(wallet_path, working_directory)) if wallet_path else None
            ),
        }
    )


def _worker_document(path: Path, *, label: str) -> dict:
    raw = worker_read(path)
    value = document(raw, label=label)
    if raw != canonical(value):
        raise ValueError(f"{label} is not canonical")
    return value


def _new_participation_request(config: dict, policy_raw: bytes, status: dict, history_raw: bytes):
    import bittensor as bt

    from umi.competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
    from umi.competition_cohort_intake import history_tip
    from umi.competition_cohort_participation import (
        CohortParticipationConsent,
        CohortParticipationRequest,
        SignedCohortParticipationConsent,
    )
    from umi.open_competition import (
        CompetitionPolicy,
        SignedSubmission,
        Submission,
        digest,
        identity,
        sign_object,
    )
    from umi.protocol import canonical_json_bytes

    policy = CompetitionPolicy.model_validate_json(policy_raw)
    if digest(policy) != config["policy_sha256"]:
        raise ValueError("enrollment policy digest differs")
    current_block = status.get("admission_checked_block")
    if (
        status.get("schema") != "umi-competition-status/2"
        or status.get("policy_sha256") != config["policy_sha256"]
        or status.get("admission_phase") != "open"
        or status.get("admission_accepting_new") is not True
        or type(current_block) is not int
        or not policy.valid_from_block <= current_block <= policy.valid_through_block
    ):
        raise EnrollmentRetry("public intake has no current open finalized observation")
    history = CohortRecoveryHistory.model_validate_json(history_raw)
    view = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        current_block=current_block,
    )
    if (
        view.state.phase != "intake"
        or current_block < view.state.not_before_block
        or view.state.cohort_sha256 != config["cohort_sha256"]
        or view.state.authority_sha256 != config["service_authority_sha256"]
    ):
        raise EnrollmentRetry("recoverable cohort intake is not open")
    # Finalized block numbers are monotonic across host rebuilds. The exact
    # signed request is retained before its first send, so uncertain retries
    # always reuse this sequence and these bytes.
    sequence = current_block
    if not 1 <= sequence <= 2**32 - 1:
        raise ValueError("endpoint sequence is exhausted")
    valid_through = min(
        policy.valid_through_block,
        current_block + policy.maximum_submission_lifetime_blocks,
    )
    if valid_through <= current_block:
        raise EnrollmentRetry("competition policy has no remaining submission interval")
    wallet = bt.Wallet(
        name=config["wallet_name"],
        hotkey=config["hotkey_name"],
        path=config["wallet_path"],
    )
    signer = bt.resolve_signer(wallet, role="hotkey")
    if identity(signer.ss58_address) != identity(config["miner_hotkey"]):
        raise ValueError("configured wallet does not control the running miner hotkey")
    submission = Submission(
        schema="umi-competition-submission/1",
        network=policy.network,
        netuid=policy.netuid,
        policy_sha256=digest(policy),
        hotkey=config["miner_hotkey"],
        track="endpoint",
        sequence=sequence,
        valid_from_block=current_block,
        valid_through_block=valid_through,
        model_revision=config["model_revision"],
        endpoint_url=config["endpoint_url"],
        model_bundle=None,
        accepted_terms_sha256=policy.contribution_terms_sha256,
    )
    signed = SignedSubmission(submission=submission, signature=sign_object(submission, wallet))
    consent = CohortParticipationConsent(
        schema="umi-cohort-participation-consent/1",
        cohort_sha256=config["cohort_sha256"],
        authority_sha256=config["service_authority_sha256"],
        submission_sha256=digest(submission),
        hotkey=config["miner_hotkey"],
        signed_at_block=current_block,
        lifetime="until_cohort_completed_or_revoked",
        timing_rule="quorum_recovery_history/1",
        original_submission_expiry_does_not_end_participation=True,
    )
    request = CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=consent,
            signature=sign_object(consent, wallet),
        ),
    )
    return policy, request, canonical_json_bytes(request)


def _new_service_claim(config: dict, request, catalog_sha256: str):
    import bittensor as bt

    from umi.competition_cohort_service_work import (
        ServiceWorkClaim,
        SignedServiceWorkClaim,
        verify_service_claim,
    )
    from umi.open_competition import digest, identity, sign_object
    from umi.protocol import canonical_json_bytes

    submission = request.signed_submission.submission
    if (
        not HEX32.fullmatch(catalog_sha256)
        or submission.track != "endpoint"
        or identity(submission.hotkey) != identity(config["miner_hotkey"])
        or digest(submission) != request.consent.consent.submission_sha256
    ):
        raise ValueError("service claim inputs differ from endpoint participation")
    nonce = sha256(
        canonical(
            {
                "catalog_sha256": catalog_sha256,
                "cohort_sha256": config["cohort_sha256"],
                "schema": "umi-miner-service-claim-nonce/1",
                "submission_sha256": digest(submission),
            }
        )
    )
    wallet = bt.Wallet(
        name=config["wallet_name"],
        hotkey=config["hotkey_name"],
        path=config["wallet_path"],
    )
    signer = bt.resolve_signer(wallet, role="hotkey")
    if identity(signer.ss58_address) != identity(config["miner_hotkey"]):
        raise ValueError("configured wallet does not control the enrolled miner hotkey")
    claim = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256=catalog_sha256,
        hotkey=config["miner_hotkey"],
        submission_sha256=digest(submission),
        nonce=nonce,
    )
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, wallet))
    return verify_service_claim(signed), canonical_json_bytes(signed)


def _service_catalog(config: dict) -> str:
    index = document(
        fetch(config["intake_origin"] + "/v1/competition/service-work"),
        label="service work catalog index",
    )
    catalogs = index.get("catalogs")
    if index.get("schema") != "umi-public-service-work-catalogs/1" or not isinstance(
        catalogs, list
    ):
        raise ValueError("service work catalog index differs")
    matching = [
        item
        for item in catalogs
        if isinstance(item, dict)
        and item.get("status") == "installed"
        and item.get("cohort_sha256") == config["cohort_sha256"]
        and item.get("policy_sha256") == config["policy_sha256"]
        and item.get("authority_sha256") == config["service_authority_sha256"]
        and HEX32.fullmatch(str(item.get("catalog_sha256")))
    ]
    if not matching:
        raise ServiceClaimRetry("selected service catalog is not installed yet")
    if len(matching) != 1:
        raise ValueError("service work catalog selection is ambiguous")
    return matching[0]["catalog_sha256"]


def service_claim_step(enrollment: Path, config: dict, request) -> dict:
    from umi.competition_client import CompetitionSubmissionError, post_intake_document
    from umi.competition_cohort_service_work import (
        SignedServiceWorkClaim,
        service_claim_key,
        verify_service_claim,
    )
    from umi.open_competition import digest, identity
    from umi.protocol import canonical_json_bytes

    catalog_sha256 = _service_catalog(config)
    claim_path = enrollment / "service-work-claim.json"
    if claim_path.exists():
        signed = verify_service_claim(
            SignedServiceWorkClaim.model_validate_json(worker_read(claim_path))
        )
        claim = signed.claim
        if (
            claim.catalog_sha256 != catalog_sha256
            or identity(claim.hotkey) != identity(config["miner_hotkey"])
            or claim.submission_sha256 != digest(request.signed_submission.submission)
        ):
            raise ValueError("retained service claim differs from selected participation")
    else:
        signed, raw = _new_service_claim(config, request, catalog_sha256)
        worker_write(claim_path, raw)
    receipt_path = enrollment / "service-work-admission.json"
    new_receipt = False
    if receipt_path.exists():
        receipt = _worker_document(receipt_path, label="service work admission")
    else:
        try:
            raw = asyncio.run(
                post_intake_document(
                    origin=config["intake_origin"],
                    path=("/v1/competition/service-work/" + catalog_sha256 + "/claims"),
                    body=canonical_json_bytes(signed),
                    timeout_seconds=SERVICE_CLAIM_TIMEOUT_SECONDS,
                )
            )
        except CompetitionSubmissionError as error:
            if error.status_code is None or error.status_code in {
                404,
                408,
                425,
                429,
                500,
                502,
                503,
                504,
            }:
                raise ServiceClaimRetry(
                    "service work admission is temporarily unavailable"
                ) from error
            raise
        receipt = document(raw, label="service work admission")
        new_receipt = True
    required = {
        "admission_sha256",
        "catalog_sha256",
        "chain_submission_authorized",
        "claim_sha256",
        "ordinal",
        "schema",
        "service_credit_authorized",
        "status",
        "work_sha256",
    }
    if (
        set(receipt) != required
        or receipt.get("schema") != "umi-public-service-work-admission/1"
        or receipt.get("status") != "accepted"
        or receipt.get("catalog_sha256") != catalog_sha256
        or receipt.get("claim_sha256") != service_claim_key(signed.claim)
        or any(
            HEX32.fullmatch(str(receipt.get(field))) is None
            for field in ("admission_sha256", "work_sha256")
        )
        or type(receipt.get("ordinal")) is not int
        or not 1 <= receipt["ordinal"] <= 8192
        or receipt.get("service_credit_authorized") is not False
        or receipt.get("chain_submission_authorized") is not False
    ):
        raise ValueError("service work admission receipt differs from its claim")
    if new_receipt:
        worker_write(receipt_path, canonical(receipt))
    return {
        "catalog_sha256": catalog_sha256,
        "ordinal": receipt["ordinal"],
        "status": "service_work_admission_accepted",
        "work_sha256": receipt["work_sha256"],
    }


def enrollment_step(enrollment: Path) -> dict:
    from umi.competition_client import CompetitionSubmissionError
    from umi.competition_cohort_client import (
        fetch_cohort_admission,
        submit_cohort_participation,
    )
    from umi.competition_cohort_participation import CohortParticipationRequest
    from umi.open_competition import CompetitionPolicy, digest, identity
    from umi.protocol import canonical_json_bytes

    config = _worker_document(enrollment / "config.json", label="enrollment configuration")
    required = {
        "cohort_sha256",
        "endpoint_url",
        "hotkey_name",
        "intake_origin",
        "miner_hotkey",
        "model_revision",
        "policy_sha256",
        "public_model_track",
        "schema",
        "service_authority_sha256",
        "wallet_name",
        "wallet_path",
    }
    if (
        set(config) != required
        or config.get("schema") != "umi-miner-cohort-enrollment/1"
        or any(
            HEX32.fullmatch(str(config.get(field))) is None
            for field in (
                "cohort_sha256",
                "model_revision",
                "policy_sha256",
                "service_authority_sha256",
            )
        )
        or not str(config.get("intake_origin", "")).startswith("https://")
        or not str(config.get("endpoint_url", "")).startswith("https://")
        or type(config.get("public_model_track")) is not bool
        or not isinstance(config.get("wallet_name"), str)
        or not isinstance(config.get("hotkey_name"), str)
        or (
            config.get("wallet_path") is not None and not isinstance(config.get("wallet_path"), str)
        )
    ):
        raise ValueError("enrollment configuration differs")
    policy_raw = worker_read(enrollment / "competition-policy.json")
    policy = CompetitionPolicy.model_validate_json(policy_raw)
    if digest(policy) != config["policy_sha256"]:
        raise ValueError("enrollment policy differs")
    request_path = enrollment / "participation-request.json"
    origin = config["intake_origin"]
    if request_path.exists():
        request = CohortParticipationRequest.model_validate_json(worker_read(request_path))
        sub, consent = request.signed_submission.submission, request.consent.consent
        if (
            sub.policy_sha256 != config["policy_sha256"]
            or sub.track != "endpoint"
            or identity(sub.hotkey) != identity(config["miner_hotkey"])
            or sub.model_revision != config["model_revision"]
            or sub.endpoint_url != config["endpoint_url"]
            or consent.cohort_sha256 != config["cohort_sha256"]
            or consent.authority_sha256 != config["service_authority_sha256"]
        ):
            raise ValueError("retained participation request differs")
    else:
        status = document(
            fetch(origin + "/v1/competition/status"), label="public competition status"
        )
        history_raw = fetch(
            origin + "/v1/competition/cohorts/" + config["cohort_sha256"] + "/history"
        )
        policy, request, request_raw = _new_participation_request(
            config, policy_raw, status, history_raw
        )
        worker_write(request_path, request_raw)
    receipt_path = enrollment / "participation-receipt.json"
    if not receipt_path.exists():
        try:
            receipt = asyncio.run(
                submit_cohort_participation(
                    origin=config["intake_origin"], policy=policy, request=request
                )
            )
        except CompetitionSubmissionError as error:
            status_code = error.status_code
            if status_code is None or status_code in {
                404,
                408,
                409,
                425,
                429,
                500,
                502,
                503,
                504,
            }:
                raise EnrollmentRetry("cohort participation is temporarily unavailable") from error
            raise
        worker_write(receipt_path, canonical_json_bytes(receipt))
    try:
        observed = asyncio.run(
            fetch_cohort_admission(origin=config["intake_origin"], policy=policy, request=request)
        )
    except CompetitionSubmissionError as error:
        status_code = error.status_code
        if status_code is None or status_code in {404, 408, 425, 429, 500, 502, 503, 504}:
            return {
                "cohort_sha256": config["cohort_sha256"],
                "policy_sha256": config["policy_sha256"],
                "status": "endpoint_enrollment_pending_attestation",
            }
        raise
    worker_write(enrollment / "admission-status.json", canonical_json_bytes(observed))
    if observed.status != "admission_certified":
        return {
            "cohort_sha256": config["cohort_sha256"],
            "policy_sha256": config["policy_sha256"],
            "status": "endpoint_enrollment_pending_attestation",
        }
    worker_write(enrollment / "admission-certificate.json", canonical_json_bytes(observed))
    service = service_claim_step(enrollment, config, request)
    return {
        "cohort_sha256": config["cohort_sha256"],
        "policy_sha256": config["policy_sha256"],
        "service_work": service,
        "status": "endpoint_enrollment_and_service_claim_certified",
    }


def run_enrollment(enrollment: Path) -> None:
    try:
        report = enrollment_step(enrollment)
    except ServiceClaimRetry as error:
        report = {
            "error_type": type(error).__name__,
            "retry_seconds": 900,
            "status": "service_work_claim_retry_scheduled",
        }
    except (EnrollmentRetry, urllib.error.URLError, TimeoutError) as error:
        report = {
            "error_type": type(error).__name__,
            "retry_seconds": 900,
            "status": "endpoint_enrollment_retry_scheduled",
        }
    except Exception as error:
        report = {
            "error_type": type(error).__name__,
            "retry_seconds": 900,
            "status": "endpoint_enrollment_held",
        }
    worker_write(enrollment / "last-status.json", canonical(report))
    print(canonical(report).decode(), flush=True)


def _root_file(path: Path, raw: bytes, mode: int) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    pending.unlink(missing_ok=True)
    pending.write_bytes(raw)
    os.chown(pending, 0, 0)
    pending.chmod(mode)
    with pending.open("rb") as stream:
        os.fsync(stream.fileno())
    os.replace(pending, path)
    fsync_directory(path.parent)


def service_record(entry: Service) -> dict:
    return {
        "name": entry.name,
        "pid": entry.pid,
        "user": entry.user,
        "arguments": entry.arguments,
        "working_directory": str(entry.working_directory),
    }


def record_service(value: dict) -> Service:
    if not isinstance(value, dict) or set(value) != {
        "name",
        "pid",
        "user",
        "arguments",
        "working_directory",
    }:
        raise ValueError("unsupported activation service record; services unchanged")
    if (
        SYSTEMD_UNIT.fullmatch(str(value["name"])) is None
        or type(value["pid"]) is not int
        or value["pid"] <= 0
        or not isinstance(value["user"], str)
        or not value["user"]
        or not isinstance(value["arguments"], list)
        or not value["arguments"]
        or any(not isinstance(item, str) or "\0" in item for item in value["arguments"])
        or not Path(value["working_directory"]).is_absolute()
        or not Path(value["working_directory"]).is_dir()
    ):
        raise ValueError("unsupported activation service layout; services unchanged")
    return Service(**{**value, "working_directory": Path(value["working_directory"])})


def unit_controls(entry):
    """Bind loaded unit source files, excluding only this updater's two overrides."""
    output = run(
        "systemctl", "show", entry.name, "--property=FragmentPath,DropInPaths,WorkingDirectory"
    ).stdout
    values = dict(line.split("=", 1) for line in output.splitlines())
    fragment = values.get("FragmentPath")
    if not fragment or not Path(fragment).is_absolute():
        raise ValueError("unsupported systemd unit source; services unchanged")
    paths = [Path(fragment), *(Path(value) for value in shlex.split(values.get("DropInPaths", "")))]
    ignored = {
        SYSTEMD_ROOT / (entry.name + ".d") / "90-umi-cohort-upgrade.conf",
        SYSTEMD_RUNTIME_ROOT / (entry.name + ".d") / "zz-umi-cohort-upgrade-drain.conf",
    }
    result = {}
    for path in paths:
        if path in ignored:
            continue
        if not path.is_absolute() or not path.is_file():
            raise ValueError("unsupported systemd control file; services unchanged")
        result[str(path)] = sha256(path.read_bytes())
    return {"files": result, "working_directory": values.get("WorkingDirectory") or "/"}


def retain_activation(state, manifest, account, summary, activation):
    path = state / "activation-recovery.json"
    if path.exists():
        raise ValueError(
            "an activation recovery already exists; resume it before preparing another"
        )
    saved = dict(activation)
    previous = {}
    controls = {}
    original_arguments = {}
    for key in ("miner", "sidecar"):
        entry = saved[key]
        if entry is None:
            continue
        controls[entry.name] = unit_controls(entry)
        override_bytes(
            activation[key + "_command_path"],
            activation[key + "_command_sha"],
            activation["launcher_python"],
            activation["startup_seconds"],
            entry.working_directory,
        )
        original = service(entry.name) if key == "sidecar" else entry
        original_arguments[entry.name] = original.arguments
        saved[key] = service_record(entry)
        dropin = SYSTEMD_ROOT / (entry.name + ".d") / "90-umi-cohort-upgrade.conf"
        if dropin.is_symlink():
            raise ValueError("unsupported symlink activation override; services unchanged")
        previous[entry.name] = dropin.read_bytes().hex() if dropin.exists() else None
    for key, value in saved.items():
        if isinstance(value, Path):
            saved[key] = str(value)
    record = {
        "schema": "umi-miner-activation-recovery/1",
        "manifest_sha256": sha256(canonical(manifest)),
        "uid": account.pw_uid,
        "gid": account.pw_gid,
        "summary": summary,
        "activation": saved,
        "previous_overrides": previous,
        "attempt": 1,
        "inputs_sha256": activation_input_hashes(activation),
        "unit_controls": controls,
        "original_arguments": original_arguments,
    }
    _root_file(path, canonical(record), 0o600)
    return record


def read_activation(state, manifest):
    path = state / "activation-recovery.json"
    if not path.exists() and not path.is_symlink():
        return None
    for parent in (ROOT, state):
        metadata = parent.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_gid != 0
            or metadata.st_mode & 0o022
        ):
            raise ValueError("unsafe activation recovery directory; services unchanged")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_size <= 0
        ):
            raise ValueError("unsafe activation recovery file; services unchanged")
        # This is root-owned local control metadata, never miner evidence. Read
        # its exact recorded size; do not introduce a cohort execution ceiling.
        raw = stream.read(metadata.st_size + 1)
        if (
            len(raw) != metadata.st_size
            or os.fstat(stream.fileno()).st_mtime_ns != metadata.st_mtime_ns
        ):
            raise ValueError("activation recovery changed while reading; services unchanged")
    record = document(raw, label="activation recovery")
    if (
        canonical(record) != raw
        or set(record)
        != {
            "schema",
            "manifest_sha256",
            "uid",
            "gid",
            "summary",
            "activation",
            "previous_overrides",
            "attempt",
            "inputs_sha256",
            "unit_controls",
            "original_arguments",
        }
        or record["schema"] != "umi-miner-activation-recovery/1"
        or record["manifest_sha256"] != sha256(canonical(manifest))
        or type(record["attempt"]) is not int
        or record["attempt"] <= 0
    ):
        raise ValueError("unsupported activation recovery binding; services unchanged")
    return record


def activation_arguments(record, state, account):
    saved = record["activation"]
    keys = {
        "miner",
        "sidecar",
        "miner_command_path",
        "miner_command_sha",
        "sidecar_command_path",
        "sidecar_command_sha",
        "launcher_python",
        "new_socket",
        "port",
        "policy",
        "transport",
        "model",
        "startup_seconds",
    }
    if not isinstance(saved, dict) or set(saved) != keys:
        raise ValueError("unsupported activation recovery arguments; services unchanged")
    if record["uid"] != account.pw_uid or record["gid"] != account.pw_gid:
        raise ValueError("activation service account changed; services unchanged")
    result = dict(saved)
    for key in ("miner", "sidecar"):
        if saved[key] is not None:
            result[key] = record_service(saved[key])
    for key in ("miner_command_path", "sidecar_command_path", "launcher_python", "new_socket"):
        if saved[key] is not None:
            result[key] = Path(saved[key])
    commands = {}
    for name in ("miner", "sidecar"):
        entry = result[name]
        if entry is None:
            continue
        if entry.user != account.pw_name:
            raise ValueError("activation service account differs; services unchanged")
        path = result[name + "_command_path"]
        if path is None or path.parent != state / "inputs":
            raise ValueError("activation command path differs; services unchanged")
        metadata = path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != account.pw_uid
            or metadata.st_nlink != 1
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ValueError("activation command file differs; services unchanged")
        raw = path.read_bytes()
        value = document(raw, label="activation command")
        if (
            sha256(raw) != result[name + "_command_sha"]
            or canonical(value) != raw
            or set(value) != {"schema", "arguments"}
            or value["schema"] != "umi-miner-upgrade-command/1"
            or not isinstance(value["arguments"], list)
            or not value["arguments"]
            or any(not isinstance(item, str) or "\0" in item for item in value["arguments"])
        ):
            raise ValueError("activation command binding differs; services unchanged")
        commands[name] = value["arguments"]
    if set(record["previous_overrides"]) != {
        entry.name for entry in (result["miner"], result["sidecar"]) if entry is not None
    }:
        raise ValueError("activation rollback bindings differ; services unchanged")
    result["previous_overrides"] = record["previous_overrides"]
    if activation_input_hashes(result) != record["inputs_sha256"]:
        raise ValueError("activation startup inputs changed; services unchanged")
    return result, commands


def activation_input_hashes(activation):
    result = {}
    for name in ("miner", "sidecar"):
        entry = activation[name]
        if entry is None:
            continue
        raw = activation[name + "_command_path"].read_bytes()
        arguments = document(raw, label="activation command")["arguments"]
        flags = (
            (
                "--policy",
                "--competition-policy",
                "--competition-cohort-config",
                "--competition-chain-config",
            )
            if name == "miner"
            else ("--config",)
        )
        for flag in flags:
            value = option(arguments, flag, required=False)
            if value is not None:
                path = installed_path(value, entry.working_directory)
                result[str(path)] = sha256(path.read_bytes())
    return result


def check_recovery_services(activation, record, commands):
    """Qualify unchanged account, cwd and original-or-selected override before writes."""
    for name in ("miner", "sidecar"):
        entry = activation[name]
        if entry is None:
            continue
        recorded_controls = record["unit_controls"][entry.name]
        if unit_controls(entry)["files"] != recorded_controls["files"]:
            raise ValueError("installed service controls changed; services unchanged")
        output = run("systemctl", "show", entry.name, "--property=User,WorkingDirectory").stdout
        values = dict(line.split("=", 1) for line in output.splitlines())
        if (values.get("User") or "root") != entry.user or (
            values.get("WorkingDirectory") or "/"
        ) not in {recorded_controls["working_directory"], str(entry.working_directory)}:
            raise ValueError(
                "installed activation account or working directory changed; services unchanged"
            )
        dropin = SYSTEMD_ROOT / (entry.name + ".d") / "90-umi-cohort-upgrade.conf"
        if dropin.is_symlink():
            raise ValueError("installed activation override is a symlink; services unchanged")
        actual = dropin.read_bytes() if dropin.exists() else None
        previous = activation["previous_overrides"][entry.name]
        previous = bytes.fromhex(previous) if previous is not None else None
        selected = override_bytes(
            activation[name + "_command_path"],
            activation[name + "_command_sha"],
            activation["launcher_python"],
            activation["startup_seconds"],
            entry.working_directory,
        )
        if actual not in (previous, selected):
            raise ValueError("installed activation override changed; services unchanged")
        try:
            current = service(entry.name)
        except ServiceNotRunning:
            continue
        if (
            current.user != entry.user
            or current.working_directory != entry.working_directory
            or current.arguments not in (record["original_arguments"][entry.name], commands[name])
        ):
            raise ValueError("running service command changed; services unchanged")


def observe_selected_activation(activation, commands):
    """Adopt an already selected healthy process after an interrupted observation."""
    for name in ("miner", "sidecar"):
        expected = activation[name]
        if expected is None:
            continue
        try:
            current = service(expected.name)
        except ServiceNotRunning:
            return None
        if (
            current.user != expected.user
            or current.working_directory != expected.working_directory
            or current.arguments != commands[name]
        ):
            return None
    if activation["sidecar"] is not None:
        wait_capacity(
            activation["new_socket"],
            activation["transport"],
            activation["model"],
            seconds=activation["startup_seconds"],
        )
    return wait_health(
        activation["port"],
        activation["policy"],
        activation["transport"],
        activation["model"],
        seconds=activation["startup_seconds"],
    )


def install_endpoint_enrollment(
    *,
    state: Path,
    account: pwd.struct_passwd,
    runtime_python: Path,
    config_raw: bytes,
    policy_raw: bytes,
) -> dict:
    enrollment = state / "enrollment"
    service_directory(enrollment, account)
    write_private(enrollment / "config.json", config_raw, account)
    write_private(enrollment / "competition-policy.json", policy_raw, account)
    service_path = SYSTEMD_ROOT / ENROLLMENT_SERVICE
    timer_path = SYSTEMD_ROOT / ENROLLMENT_TIMER
    service_raw = (
        "[Unit]\n"
        "Description=Durable UMI cohort endpoint enrollment\n"
        "After=network-online.target\n"
        "Wants=network-online.target\n"
        f"ConditionPathExists=!{enrollment / 'service-work-admission.json'}\n\n"
        "[Service]\n"
        "Type=oneshot\n"
        f"User={account.pw_name}\n"
        f"Environment=HOME={account.pw_dir}\n"
        f"ExecStart={runtime_python} -I -B {LAUNCHER} --run-enrollment {enrollment}\n"
        "TimeoutStartSec=70min\n"
        "NoNewPrivileges=yes\n"
        "PrivateTmp=yes\n"
        "ProtectHome=read-only\n"
        "ProtectSystem=strict\n"
        f"ReadWritePaths={enrollment}\n"
    ).encode()
    timer_raw = (
        "[Unit]\n"
        "Description=Retry UMI cohort endpoint enrollment\n\n"
        "[Timer]\n"
        "OnBootSec=2min\n"
        "OnUnitInactiveSec=15min\n"
        "AccuracySec=1min\n"
        "Persistent=true\n"
        f"Unit={ENROLLMENT_SERVICE}\n\n"
        "[Install]\n"
        "WantedBy=timers.target\n"
    ).encode()
    _root_file(service_path, service_raw, 0o644)
    _root_file(timer_path, timer_raw, 0o644)
    run("systemctl", "daemon-reload")
    run("systemctl", "enable", "--now", ENROLLMENT_TIMER)
    # The timer owns this retained operation. Do not make the interactive
    # updater wait for a slow coordinator or terminate its service-start client.
    run("systemctl", "start", "--no-block", ENROLLMENT_SERVICE, check=False, timeout=30)
    status_path = enrollment / "last-status.json"
    if status_path.exists():
        return document(status_path.read_bytes(), label="endpoint enrollment status")
    return {"retry_seconds": 900, "status": "endpoint_enrollment_retry_scheduled"}


def finish_upgrade(
    *,
    state,
    summary,
    manifest,
    account,
    miner,
    updated,
    observed,
    effective_limits,
    runtime_python,
    hotkey,
    model,
    origin,
    public_model_track,
):
    progress_stage("enrollment")
    report = {
        **summary,
        "health": observed,
        "effective_limits": effective_limits,
        "runtime_revision": manifest["runtime"]["revision"],
        "state_root": str(state),
        "status": "miner_upgrade_verified",
    }
    if PROGRESS is not None:
        report["migration_progress"] = PROGRESS.snapshot()
    receipt = state / "upgrade-receipt.json"
    # Durably record successful cutover before removing its recovery intent or
    # invoking enrollment. A restart then validates the live service and only
    # schedules the retained request again, without a second cutover.
    write_private(receipt, canonical(report), account)
    (state / "activation-recovery.json").unlink(missing_ok=True)
    fsync_directory(state)
    policy_raw = (state / "inputs/competition-policy.json").read_bytes()
    if sha256(policy_raw) != manifest["policy"]["sha256"]:
        raise ValueError("retained competition policy digest differs")
    report["endpoint_enrollment"] = install_endpoint_enrollment(
        state=state,
        account=account,
        runtime_python=runtime_python,
        config_raw=endpoint_enrollment_config(
            updated, manifest, hotkey, model, origin, public_model_track, miner.working_directory
        ),
        policy_raw=policy_raw,
    )
    if PROGRESS is not None:
        PROGRESS.durations["enrollment"] = time.monotonic() - PROGRESS.stage_started
        report["migration_progress"] = PROGRESS.snapshot("complete")
    write_private(receipt, canonical(report), account)
    print(canonical(report).decode())


def _main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-model-track", choices=("yes", "no"))
    parser.add_argument(
        "--install-model-client",
        action="store_true",
        help="install a separate model upload CLI without changing endpoint services",
    )
    parser.add_argument(
        "--model-client-directory",
        type=Path,
        default=Path.home() / ".local/share/umi/model-client",
        help="absolute, dedicated model client installation directory",
    )
    parser.add_argument("--manifest-url", default=DEFAULT_MANIFEST, help=argparse.SUPPRESS)
    parser.add_argument("--status-url", default=DEFAULT_STATUS, help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.install_model_client:
        if args.public_model_track == "no":
            parser.error("--install-model-client requires public-model participation")
        args.public_model_track = "yes"
        ensure_model_client_python()
    elif args.public_model_track is None:
        parser.error("--public-model-track is required for endpoint upgrades")
    progress_stage("manifest")
    manifest_raw = fetch(args.manifest_url)
    manifest = document(manifest_raw, label="upgrade manifest")
    if manifest_raw not in {canonical(manifest), canonical(manifest) + b"\n"}:
        raise ValueError("upgrade manifest is not canonical")
    status = document(fetch(args.status_url), label="public status")
    manifest = deployed_manifest(manifest, status)
    manifest_raw = canonical(manifest)
    validate_manifest(manifest, status, args.public_model_track)
    if args.install_model_client:
        progress_plan("manifest", "client_install")
        progress_stage("client_install")
        if args.dry_run:
            report = {
                "status": "model_client_preflight_passed",
                "runtime_revision": manifest["runtime"]["revision"],
                "endpoint_service_unchanged": True,
                "directory": str(args.model_client_directory),
                "installer_python": sys.executable,
                "installer_python_version": platform.python_version(),
            }
        else:
            report = install_model_client(manifest, args.model_client_directory)
        print(canonical(report).decode())
        return
    if sys.platform != "linux" or shutil.which("systemctl") is None:
        raise ValueError("the automatic upgrader requires a Linux systemd miner")
    if os.geteuid() != 0 and not args.dry_run:
        raise ValueError("run the upgrade with sudo")
    if not args.dry_run:
        PROGRESS.lock_fd = acquire_upgrade_lock()
    progress_stage("installed_layout")
    state = ROOT / (manifest["policy"]["value_sha256"][:16])
    recovery = read_activation(state, manifest)
    miner = record_service(recovery["activation"]["miner"]) if recovery else discover_miner()
    account = pwd.getpwnam(miner.user)
    hotkey, model, origin = miner_identity(miner.arguments, miner.user, miner.working_directory)
    receipt = state / "upgrade-receipt.json"
    port = int(option(miner.arguments, "--port"))
    model_only = manifest["eligible_tracks"] == ["model"]
    retained_startup, migration = (
        (None, "model_intent_endpoint_unchanged")
        if model_only
        else migration_startup(
            miner.arguments, manifest, state, hotkey, model, origin, miner.working_directory
        )
    )
    summary = {
        "migration": migration,
        "installed_runtime_python": miner_python(miner.arguments),
        "installed_cohort_startup": option(
            miner.arguments, "--competition-cohort-config", required=False
        )
        is not None,
        "target_runtime_revision": manifest["runtime"]["revision"],
        "cohort": manifest["cohort"],
        "endpoint_service_unchanged": model_only,
        "miner_service": miner.name,
        "policy_sha256": manifest["policy"]["value_sha256"],
        "public_model_track": args.public_model_track,
        "status": "upgrade_preflight_passed",
    }
    if args.dry_run:
        progress_plan("manifest", "installed_layout")
        summary["activation_recovery_pending"] = recovery is not None
        print(canonical(summary).decode())
        return
    if recovery is not None:
        activation, commands = activation_arguments(recovery, state, account)
        updated = commands["miner"]
        if activation["policy"] != manifest["policy"]["value_sha256"] or (
            activation["transport"] != manifest["transport"]["value_sha256"]
            or activation["model"] != model
            or activation["port"] != port
        ):
            raise ValueError("activation scope differs; services unchanged")
        progress_plan(
            "manifest",
            "installed_layout",
            "runtime",
            "startup_validation",
            "activation",
            "enrollment",
        )
        if PROGRESS is not None:
            PROGRESS.attempt = recovery["attempt"] + 1
        if receipt.exists():
            with suppress(OSError, ValueError):
                progress_history(document(receipt.read_bytes(), label="prior upgrade timings"))
        progress_stage("runtime")
        runtime_python = install_runtime(
            miner_python(miner.arguments),
            manifest["runtime"],
            account,
            state / "inputs/transport-policy.json",
        )
        if runtime_python != activation["launcher_python"] or miner_python(updated) != str(
            runtime_python
        ):
            raise ValueError("activation interpreter binding differs; services unchanged")
        progress_stage("startup_validation")
        validate_startup(updated, account, miner.working_directory, hotkey, manifest)
        effective_limits = runtime_limits(updated, state)
        progress_limits(effective_limits)
        if effective_limits["startup_seconds"] != activation["startup_seconds"]:
            raise ValueError("activation startup budget differs; services unchanged")
        check_recovery_services(activation, recovery, commands)
        recovery["attempt"] += 1
        _root_file(state / "activation-recovery.json", canonical(recovery), 0o600)
        install_launcher(Path(__file__))
        progress_stage("activation")
        observed = observe_selected_activation(activation, commands)
        if observed is None:
            observed = activate_services(**activation)
        else:
            services = tuple(
                entry for entry in (activation["miner"], activation["sidecar"]) if entry is not None
            )
            with cooperative_upgrade(services):
                pass
        finish_upgrade(
            state=state,
            summary={**summary, "activation_resumed": True},
            manifest=manifest,
            account=account,
            miner=miner,
            updated=updated,
            observed=observed,
            effective_limits=effective_limits,
            runtime_python=runtime_python,
            hotkey=hotkey,
            model=model,
            origin=origin,
            public_model_track=args.public_model_track == "yes",
        )
        return
    secure_root(ROOT)
    if model_only:
        progress_plan("manifest", "installed_layout", "inputs")
        progress_stage("inputs")
        if receipt.exists():
            prior = document(receipt.read_bytes(), label="upgrade receipt")
            if (
                prior.get("policy_sha256") == manifest["policy"]["value_sha256"]
                and prior.get("status") == "model_track_intent_recorded"
            ):
                print(canonical(prior).decode())
                return
        secure_root(state)
        inputs = state / "inputs"
        secure_root(inputs)
        write_private(inputs / "upgrade-manifest.json", manifest_raw, account)
        write_private(
            inputs / "track-intent.json",
            canonical(
                {
                    "cohort": manifest["cohort"],
                    "miner_hotkey": hotkey,
                    "model_revision": model,
                    "policy_sha256": manifest["policy"]["value_sha256"],
                    "public_model_track": True,
                    "schema": "umi-miner-track-intent/1",
                }
            ),
            account,
        )
        install_launcher(Path(__file__))
        report = {
            **summary,
            "miner_hotkey": hotkey,
            "model_revision": model,
            "status": "model_track_intent_recorded",
        }
        write_private(receipt, canonical(report), account)
        print(canonical(report).decode())
        return
    if receipt.exists():
        prior = document(receipt.read_bytes(), label="upgrade receipt")
        progress_history(prior)
        retained_transport = state / "inputs/transport-policy.json"
        selected_python = None
        if retained_transport.exists():
            if sha256(retained_transport.read_bytes()) != manifest["transport"]["sha256"]:
                raise ValueError("retained transport policy digest differs")
            selected_python = (
                runtime_directory(manifest["runtime"], retained_transport) / "venv/bin/python"
            )
        if (
            selected_python is not None
            and migration == "cohort_runtime_in_place"
            and prior.get("status") == "miner_upgrade_verified"
            and prior.get("policy_sha256") == manifest["policy"]["value_sha256"]
            and prior.get("runtime_revision") == manifest["runtime"]["revision"]
            and Path(miner_python(miner.arguments)).resolve() == selected_python.resolve()
            and python_module_miner(miner.arguments)
            and {"-I", "-B"}.issubset(miner.arguments[1 : miner.arguments.index("-m")])
        ):
            progress_plan("manifest", "installed_layout", "startup_validation", "enrollment")
            progress_stage("startup_validation")
            validate_startup(miner.arguments, account, miner.working_directory, hotkey, manifest)
            observed = wait_health(
                port,
                manifest["policy"]["value_sha256"],
                manifest["transport"]["value_sha256"],
                model,
                seconds=30,
            )
            policy_raw = (state / "inputs/competition-policy.json").read_bytes()
            if sha256(policy_raw) != manifest["policy"]["sha256"]:
                raise ValueError("retained competition policy digest differs")
            install_launcher(Path(__file__))
            progress_stage("enrollment")
            enrollment = install_endpoint_enrollment(
                state=state,
                account=account,
                runtime_python=Path(miner_python(miner.arguments)),
                config_raw=endpoint_enrollment_config(
                    miner.arguments,
                    manifest,
                    hotkey,
                    model,
                    origin,
                    args.public_model_track == "yes",
                    miner.working_directory,
                ),
                policy_raw=policy_raw,
            )
            write_private(
                receipt,
                canonical({**prior, "endpoint_enrollment": enrollment}),
                account,
            )
            print(
                canonical(
                    {
                        "endpoint_enrollment": enrollment,
                        "health": observed,
                        "status": "already_upgraded",
                    }
                ).decode()
            )
            return
    progress_stage("inputs")
    secure_root(state)
    secure_root(state / "inputs")
    for name in ("grants", "model", "protocol"):
        service_directory(state / name, account)
    inputs = state / "inputs"
    policy_files = (
        ("policy", "competition-policy.json"),
        ("transport", "transport-policy.json"),
    )
    for key, filename in policy_files:
        raw = fetch(manifest[key]["url"])
        if sha256(raw) != manifest[key]["sha256"]:
            raise ValueError(f"{key} file digest differs")
        write_private(inputs / filename, raw, account)
    write_private(inputs / "upgrade-manifest.json", manifest_raw, account)
    write_private(
        inputs / "miner-startup.json",
        retained_startup,
        account,
    )
    write_private(
        inputs / "track-intent.json",
        canonical(
            {
                "cohort": manifest["cohort"],
                "policy_sha256": manifest["policy"]["value_sha256"],
                "public_model_track": args.public_model_track == "yes",
                "schema": "umi-miner-track-intent/1",
            }
        ),
        account,
    )
    progress_stage("runtime")
    runtime_python = install_runtime(
        miner_python(miner.arguments),
        manifest["runtime"],
        account,
        inputs / "transport-policy.json",
    )
    updated = miner_command(miner.arguments, str(runtime_python), state, manifest)
    progress_stage("startup_validation")
    validate_startup(updated, account, miner.working_directory, hotkey, manifest)
    progress_stage("sidecar")
    sidecar, updated, new_socket = prepare_sidecar(
        updated, state, account, manifest["transport"]["value_sha256"]
    )
    effective_limits = runtime_limits(updated, state)
    progress_limits(effective_limits)
    miner_command_path = inputs / ("miner-command-" + sha256(canonical(updated)) + ".json")
    miner_command_sha = command_file(miner_command_path, updated, account)
    sidecar_command_path = None
    sidecar_command_sha = None
    if sidecar is not None:
        prepared = list(sidecar.arguments)
        sidecar_command_path = inputs / ("model-command-" + sha256(canonical(prepared)) + ".json")
        sidecar_command_sha = command_file(sidecar_command_path, prepared, account)
    install_launcher(Path(__file__))
    activation = dict(
        miner=miner,
        sidecar=sidecar,
        miner_command_path=miner_command_path,
        miner_command_sha=miner_command_sha,
        sidecar_command_path=sidecar_command_path,
        sidecar_command_sha=sidecar_command_sha,
        launcher_python=runtime_python,
        new_socket=new_socket,
        port=port,
        policy=manifest["policy"]["value_sha256"],
        transport=manifest["transport"]["value_sha256"],
        model=model,
        startup_seconds=effective_limits["startup_seconds"],
    )
    retained = retain_activation(state, manifest, account, summary, activation)
    progress_stage("activation")
    observed = activate_services(**activation, previous_overrides=retained["previous_overrides"])
    finish_upgrade(
        state=state,
        summary=summary,
        manifest=manifest,
        account=account,
        miner=miner,
        updated=updated,
        observed=observed,
        effective_limits=effective_limits,
        runtime_python=runtime_python,
        hotkey=hotkey,
        model=model,
        origin=origin,
        public_model_track=args.public_model_track == "yes",
    )


def main() -> None:
    global PROGRESS
    PROGRESS = MigrationProgress()
    PROGRESS.thread.start()
    try:
        _main()
    except BaseException:
        PROGRESS.finish("interrupted_or_failed")
        raise
    else:
        PROGRESS.finish("complete")
    finally:
        if PROGRESS.lock_fd is not None:
            os.close(PROGRESS.lock_fd)
        PROGRESS = None


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--run-command":
        launch_command(Path(sys.argv[2]), sys.argv[3])
    elif len(sys.argv) >= 2 and sys.argv[1] == "--install-restart-policy":
        package_restart_policy_command()
    elif len(sys.argv) == 3 and sys.argv[1] == "--run-enrollment":
        run_enrollment(Path(sys.argv[2]))
    else:
        main()
