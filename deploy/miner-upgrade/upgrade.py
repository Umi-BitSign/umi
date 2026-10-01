#!/usr/bin/python3
"""Upgrade the one running standard Linux UMI miner to the current recoverable cohort."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

DEFAULT_MANIFEST = (
    "https://raw.githubusercontent.com/Umi-BitSign/umi/main/deploy/miner-upgrade/current.json"
)
DEFAULT_STATUS = "https://api.umi.vision/v1/competition/status"
ROOT = Path("/var/lib/umi-miner-cohorts")
RUNTIME_ROOT = Path("/opt/umi-miner-runtimes")
LAUNCHER = Path("/usr/local/libexec/umi-miner-upgrade")
SYSTEMD_ROOT = Path("/etc/systemd/system")
HEX32 = re.compile(r"^[0-9a-f]{64}$")
GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
SYSTEMD_UNIT = re.compile(r"^[A-Za-z0-9_.:@-]+\.service$")


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def fetch(url: str, maximum: int = 4 * 1024 * 1024) -> bytes:
    request = urllib.request.Request(
        url,
        headers={"Accept-Encoding": "identity", "User-Agent": "umi-miner-upgrade/1"},
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read(maximum + 1)
        if response.status != 200 or not raw or len(raw) > maximum:
            raise ValueError("download size or status differs")
        return raw


def document(raw: bytes, *, label: str) -> dict:
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{label} is not an object")
    return value


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
        or set(runtime) != {"repository", "revision"}
        or runtime.get("repository") != "https://github.com/Umi-BitSign/umi.git"
        or GIT_REVISION.fullmatch(str(runtime.get("revision"))) is None
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
        or deployed.get("umi_git_revision") != runtime["revision"]
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
    elif Path(updated[0]).name == "umi-miner":
        updated[0] = str(Path(runtime_python).with_name("umi-miner"))
    else:
        raise ValueError("unsupported miner entry point")
    for name in (
        "--competition-feed",
        "--competition-authorization",
        "--competition-chain-config",
    ):
        remove_option(updated, name)
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
        replace_option(updated, name, value)
    return updated


def miner_identity(arguments: list[str], user: str) -> tuple[str, str, str]:
    model = option(arguments, "--model-revision")
    origin = option(arguments, "--serving-origin")
    config_path = option(arguments, "--competition-cohort-config", required=False)
    hotkey = None
    if config_path is not None:
        config = document(Path(config_path).read_bytes(), label="existing cohort startup")
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
            wallet_path or "",
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


@dataclass(frozen=True)
class Service:
    name: str
    pid: int
    user: str
    arguments: list[str]


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


def run(*arguments: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    result = subprocess.run(arguments, check=False, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout or "no command output").strip()[-2000:]
        command = Path(arguments[0]).name
        raise RuntimeError(f"{command} exited {result.returncode}: {detail}")
    return result


def cmdline(pid: int) -> list[str]:
    raw = Path(f"/proc/{pid}/cmdline").read_bytes()
    return [os.fsdecode(value) for value in raw.rstrip(b"\0").split(b"\0")]


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
    if pid <= 0 or user == "root":
        raise ValueError(f"{name} is not one running unprivileged service")
    return Service(name=name, pid=pid, user=user, arguments=cmdline(pid))


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
    os.replace(pending, path)


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
) -> Path:
    if not launcher_python.is_absolute():
        raise ValueError("launcher interpreter is not absolute")
    path = SYSTEMD_ROOT / f"{service_name}.d" / "90-umi-cohort-upgrade.conf"
    raw = (
        "[Service]\nExecStart=\n"
        f"ExecStart={launcher_python} -I -B {LAUNCHER} --run-command "
        f"{command_path} {command_sha256}\n"
    ).encode()
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    pending = path.with_name(path.name + ".pending")
    pending.write_bytes(raw)
    os.chown(pending, 0, 0)
    pending.chmod(0o644)
    os.replace(pending, path)
    return path


def unit_for_pid(pid: int) -> str | None:
    for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
        path = line.rpartition(":")[2]
        name = path.rsplit("/", 1)[-1]
        if name.endswith(".service"):
            return name
    return None


def prepare_sidecar(
    arguments: list[str], state: Path, account: pwd.struct_passwd, transport: str
) -> tuple[Service | None, list[str], Path | None]:
    socket = option(arguments, "--translator-unix-socket", required=False)
    if socket is None:
        return None, arguments, None
    capacity_path = Path(socket + ".capacity.json")
    capacity = document(capacity_path.read_bytes(), label="model capacity")
    if capacity.get("scoring_policy_sha256") == transport:
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
    raw = Path(config_path).read_bytes()
    if sha256(raw) != expected:
        raise ValueError("model sidecar configuration differs from its command")
    config = document(raw, label="model sidecar configuration")
    if config.get("socket_path") != socket:
        raise ValueError("model sidecar socket differs")
    new_socket = state / "model" / "model.sock"
    config["socket_path"] = str(new_socket)
    config["scoring_policy_sha256"] = transport
    config_raw = canonical(config)
    new_config = state / "inputs" / "model-service.json"
    write_private(new_config, config_raw, account)
    updated_miner = list(arguments)
    replace_option(updated_miner, "--translator-unix-socket", str(new_socket))
    return sidecar, updated_miner, new_socket


def wait_health(port: int, policy: str, transport: str, model: str, seconds: int = 600) -> dict:
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


def wait_capacity(socket: Path, transport: str, model: str, seconds: int = 600) -> dict:
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


def python312(current_python: str) -> str:
    candidates = (current_python, shutil.which("python3.12"), "/usr/bin/python3.12")
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
            "-c",
            "import sys;raise SystemExit(sys.version_info[:2] != (3, 12))",
            check=False,
        )
        if result.returncode == 0:
            return str(path)
    raise ValueError("a root-owned CPython 3.12 is required for the cohort runtime")


def install_runtime(current_python: str, runtime: dict, account: pwd.struct_passwd) -> Path:
    secure_root(RUNTIME_ROOT)
    target = RUNTIME_ROOT / runtime["revision"]
    python = target / "venv" / "bin" / "python"
    prefix = ["runuser", "--user", account.pw_name, "--"]
    if not target.exists():
        base_python = python312(current_python)
        staging = target.with_name(target.name + ".pending")
        if staging.exists():
            info = staging.lstat()
            if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
                raise ValueError("incomplete runtime staging path differs")
            shutil.rmtree(staging)
        staging.mkdir(mode=0o755)
        staging_python = staging / "venv" / "bin" / "python"
        run(
            base_python,
            "-m",
            "venv",
            "--copies",
            str(staging / "venv"),
        )
        run(
            "env",
            "GIT_CONFIG_GLOBAL=/dev/null",
            "GIT_CONFIG_NOSYSTEM=1",
            "PIP_CONFIG_FILE=/dev/null",
            "PIP_NO_CACHE_DIR=1",
            str(staging_python),
            "-m",
            "pip",
            "install",
            "--disable-pip-version-check",
            "--no-input",
            "--index-url",
            "https://pypi.org/simple",
            f"git+{runtime['repository']}@{runtime['revision']}",
            timeout=1800,
        )
        run(str(staging_python), "-m", "pip", "check")
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
    verification = (
        "import importlib.metadata as m,json,sys;"
        "d=m.distribution('umi-subnet');"
        "p=next(d.locate_file(x) for x in d.files if str(x).endswith('direct_url.json'));"
        "v=json.loads(p.read_text())['vcs_info'];"
        f"assert v['commit_id']=='{runtime['revision']}';"
        "assert sys.version_info[:2]==(3,12);"
        "import umi;print(umi.__file__)"
    )
    check = run(
        *prefix,
        str(python),
        "-c",
        verification,
    )
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
    try:
        run("systemctl", "stop", miner.name)
        if sidecar is not None:
            run("systemctl", "stop", sidecar.name)
        override(miner.name, miner_command_path, miner_command_sha, launcher_python)
        if (
            sidecar is not None
            and sidecar_command_path is not None
            and sidecar_command_sha is not None
        ):
            override(sidecar.name, sidecar_command_path, sidecar_command_sha, launcher_python)
        run("systemctl", "daemon-reload")
        if sidecar is not None:
            run("systemctl", "start", sidecar.name)
            if new_socket is None:
                raise ValueError("prepared model socket is missing")
            wait_capacity(new_socket, transport, model)
        run("systemctl", "start", miner.name)
        return wait_health(port, policy, transport, model)
    except Exception:
        run("systemctl", "stop", miner.name, check=False)
        if sidecar is not None:
            run("systemctl", "stop", sidecar.name, check=False)
        for path, raw in ((miner_dropin, previous_miner), (sidecar_dropin, previous_sidecar)):
            if path is None:
                continue
            if raw is None:
                path.unlink(missing_ok=True)
            else:
                path.write_bytes(raw)
                os.chown(path, 0, 0)
                path.chmod(0o644)
        run("systemctl", "daemon-reload", check=False)
        if sidecar is not None:
            run("systemctl", "start", sidecar.name, check=False)
        run("systemctl", "start", miner.name, check=False)
        raise


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public-model-track", required=True, choices=("yes", "no"))
    parser.add_argument("--manifest-url", default=DEFAULT_MANIFEST, help=argparse.SUPPRESS)
    parser.add_argument("--status-url", default=DEFAULT_STATUS, help=argparse.SUPPRESS)
    parser.add_argument("--dry-run", action="store_true", help=argparse.SUPPRESS)
    args = parser.parse_args()
    manifest_raw = fetch(args.manifest_url)
    manifest = document(manifest_raw, label="upgrade manifest")
    if manifest_raw not in {canonical(manifest), canonical(manifest) + b"\n"}:
        raise ValueError("upgrade manifest is not canonical")
    status = document(fetch(args.status_url), label="public status")
    validate_manifest(manifest, status, args.public_model_track)
    if sys.platform != "linux" or shutil.which("systemctl") is None:
        raise ValueError("the automatic upgrader requires a Linux systemd miner")
    if os.geteuid() != 0 and not args.dry_run:
        raise ValueError("run the upgrade with sudo")
    miner = discover_miner()
    account = pwd.getpwnam(miner.user)
    hotkey, model, origin = miner_identity(miner.arguments, miner.user)
    state = ROOT / (manifest["policy"]["value_sha256"][:16])
    receipt = state / "upgrade-receipt.json"
    port = int(option(miner.arguments, "--port"))
    model_only = manifest["eligible_tracks"] == ["model"]
    summary = {
        "cohort": manifest["cohort"],
        "endpoint_service_unchanged": model_only,
        "miner_service": miner.name,
        "policy_sha256": manifest["policy"]["value_sha256"],
        "public_model_track": args.public_model_track,
        "status": "upgrade_preflight_passed",
    }
    if args.dry_run:
        print(canonical(summary).decode())
        return
    secure_root(ROOT)
    if model_only:
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
        if prior.get("policy_sha256") == manifest["policy"]["value_sha256"]:
            observed = wait_health(
                port,
                manifest["policy"]["value_sha256"],
                manifest["transport"]["value_sha256"],
                model,
                seconds=30,
            )
            print(canonical({"health": observed, "status": "already_upgraded"}).decode())
            return
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
        startup(manifest, state, hotkey, model, origin),
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
    runtime_python = install_runtime(miner_python(miner.arguments), manifest["runtime"], account)
    updated = miner_command(miner.arguments, str(runtime_python), state, manifest)
    sidecar, updated, new_socket = prepare_sidecar(
        updated, state, account, manifest["transport"]["value_sha256"]
    )
    miner_command_path = inputs / "miner-command.json"
    miner_command_sha = command_file(miner_command_path, updated, account)
    sidecar_command_path = None
    sidecar_command_sha = None
    if sidecar is not None:
        sidecar_command_path = inputs / "model-command.json"
        config_path = inputs / "model-service.json"
        prepared = list(sidecar.arguments)
        replace_option(prepared, "--config", str(config_path))
        replace_option(prepared, "--expected-config-sha256", sha256(config_path.read_bytes()))
        sidecar_command_sha = command_file(sidecar_command_path, prepared, account)
    install_launcher(Path(__file__))
    observed = activate_services(
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
    )
    report = {
        **summary,
        "health": observed,
        "runtime_revision": manifest["runtime"]["revision"],
        "state_root": str(state),
        "status": "miner_upgrade_verified",
    }
    write_private(receipt, canonical(report), account)
    print(canonical(report).decode())


if __name__ == "__main__":
    if len(sys.argv) == 4 and sys.argv[1] == "--run-command":
        launch_command(Path(sys.argv[2]), sys.argv[3])
    else:
        main()
