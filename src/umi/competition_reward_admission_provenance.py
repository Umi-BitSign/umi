"""Prospective local selection of the original installed342 admission owner.

Capture reads source/configuration and process metadata, never journals, keys or
environment. Its output is not a successful history verdict. A host administrator
must seal it in a root-owned read-only file with root-only writable ancestors
while this exact original owner is running. The separate stopped-owner importer
must still validate the original native intent/vote and admission boundary.

This narrow migration accepts one reviewed installed release and launch. It is
not a portable proof, a general release assertion or a remote certificate.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import stat
import subprocess
import time
from contextlib import ExitStack, contextmanager
from pathlib import Path

from .open_competition import digest, identity

SCHEMA = "umi-original-admission-owner-selection/1"
SOURCE_SEMANTICS = "umi-installed342-native-initial-admission/1"
SOURCE_ROOT = Path("/opt/umi-competition-runtime-342c9b6c1e4a/src/umi")
SOURCE_MANIFEST_SHA256 = "d016c171d7a70a679fd3eb9b67c0c4679e2581e120ad95ed2753e76f2083db3e"
SOURCE_FILES = 627
SOURCE_BYTES = 12_183_245
CONFIG_PATH = Path("/etc/umi/c5-primary/reward-uid54.json")
SERVICE = "umi-standing-reward-uid54.service"
ORIGINAL_PID = 2302804
ORIGINAL_INVOCATION = "b801f8a1a091456686aa9f5ec96f7f16"
ORIGINAL_STARTED_NS = 1_791_862_094_000_000_000  # 2026-10-13T03:28:14Z
MAX_SELECTION_BYTES = 2 * 1024**2
_ROOT_UID = 0
_TRUST_ROOT = Path("/")
_PROC = Path("/proc")
_LAUNCH = (
    "import runpy,sys;sys.path.insert(0,"
    "'/opt/umi-competition-runtime-342c9b6c1e4a/src');"
    "runpy.run_module('umi.competition_reward_coordinator_cli',run_name='__main__')"
)


def _canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _sha(raw):
    return hashlib.sha256(raw).hexdigest()


def provenance_selection_digest(value):
    """Bind local physical metadata, including exact nanosecond timestamps.

    A selection is not a protocol object. Its integer filesystem timestamps
    deliberately use this module's lossless JSON encoding, not RFC 8785's
    interoperable integer range used by open_competition.digest.
    """
    return _sha(_canonical(value))


def _parse(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ValueError("selection repeats a JSON member")
            result[key] = value
        return result

    value = json.loads(raw, object_pairs_hook=pairs)
    if not isinstance(value, dict) or _canonical(value) != raw:
        raise ValueError("selection/configuration is not canonical")
    return value


def _absolute(path):
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts or path == _TRUST_ROOT:
        raise ValueError("original owner path is not explicit")
    if not path.is_relative_to(_TRUST_ROOT):
        raise ValueError("original owner path is outside selected host")
    return path


def _ancestors(path, *, owner):
    path = _absolute(path)
    for parent in reversed(path.parents):
        if not parent.is_relative_to(_TRUST_ROOT):
            continue
        info = parent.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid not in {_ROOT_UID, owner}
            or info.st_mode & 0o022
        ):
            raise ValueError("original owner ancestor is replaceable or a symlink")


def _metadata(path, *, owner, directory=False, immutable=False):
    path = _absolute(path)
    _ancestors(path, owner=owner)
    info = path.lstat()
    if (
        not (stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
        or info.st_uid != owner
        or info.st_mode & (0o022 if immutable else 0o077)
        or (not directory and info.st_nlink != 1)
    ):
        raise ValueError("original owner path has unsafe ownership, type or permissions")
    value = {
        "path": str(path),
        "dev": info.st_dev,
        "ino": info.st_ino,
        "uid": info.st_uid,
        "gid": info.st_gid,
        "mode": info.st_mode,
    }
    if not directory:
        value["nlink"] = info.st_nlink
    if immutable:
        value.update(size=info.st_size, mtime_ns=info.st_mtime_ns, ctime_ns=info.st_ctime_ns)
    return value


def _read_root(path, maximum, *, modes=None):
    before = _metadata(path, owner=_ROOT_UID, immutable=True)
    if modes is not None and stat.S_IMODE(before["mode"]) not in modes:
        raise ValueError("root selection is not read-only")
    if not 0 < before["size"] <= maximum:
        raise ValueError("root input exceeds its bounded size")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        actual = os.fstat(fd)
        if (actual.st_dev, actual.st_ino) != (before["dev"], before["ino"]):
            raise ValueError("root input replaced while opening")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(maximum + 1)
    finally:
        os.close(fd)
    if len(raw) != before["size"] or _metadata(path, owner=_ROOT_UID, immutable=True) != before:
        raise ValueError("root input changed during capture")
    return raw, {**before, "sha256": _sha(raw)}


def _installed_source():
    _metadata(SOURCE_ROOT, owner=_ROOT_UID, directory=True, immutable=True)
    hashes, identities, size = {}, {}, 0
    for path in sorted(SOURCE_ROOT.rglob("*.py")):
        raw, bound = _read_root(path, 2 * 1024**2)
        if max(bound["mtime_ns"], bound["ctime_ns"]) > ORIGINAL_STARTED_NS:
            raise ValueError("installed source changed after the original launch")
        relative = path.relative_to(SOURCE_ROOT).as_posix()
        hashes[relative], identities[relative] = bound["sha256"], bound
        size += len(raw)
        if len(hashes) > SOURCE_FILES or size > SOURCE_BYTES:
            raise ValueError("installed source exceeds the reviewed release")
    if (
        len(hashes) != SOURCE_FILES
        or size != SOURCE_BYTES
        or _sha(_canonical(hashes)) != SOURCE_MANIFEST_SHA256
    ):
        raise ValueError("installed source is not the reviewed342 release")
    return identities


def _systemd():
    fields = (
        "Id",
        "MainPID",
        "InvocationID",
        "ControlGroup",
        "FragmentPath",
        "DropInPaths",
        "ExecMainStartTimestampMonotonic",
        "ActiveState",
        "SubState",
    )
    raw = subprocess.run(
        ["/usr/bin/systemctl", "show", SERVICE, "--no-pager", "--property=" + ",".join(fields)],
        check=True,
        capture_output=True,
        timeout=10,
    ).stdout
    if len(raw) > 64 * 1024:
        raise ValueError("service metadata exceeds its bound")
    values = dict(line.split("=", 1) for line in raw.decode().splitlines())
    if set(values) != set(fields):
        raise ValueError("service metadata is incomplete")
    return values


def _process():
    root = _PROC / str(ORIGINAL_PID)
    before = (root / "stat").read_text()
    fields = before.rsplit(") ", 1)[1].split()
    status = dict(line.split(":", 1) for line in (root / "status").read_text().splitlines())
    uids, gids = [int(v) for v in status["Uid"].split()], [int(v) for v in status["Gid"].split()]
    argv = (root / "cmdline").read_bytes().rstrip(b"\0").decode().split("\0")
    if len(argv) != 8 or argv[1:] != [
        "-I",
        "-B",
        "-c",
        _LAUNCH,
        "run",
        "--config",
        str(CONFIG_PATH),
    ]:
        raise ValueError("original owner does not have the reviewed isolated launch")
    if len(set(uids)) != 1 or len(set(gids)) != 1 or uids[0] == _ROOT_UID:
        raise ValueError("original process credentials changed")
    result = {
        "pid": ORIGINAL_PID,
        "start_ticks": int(fields[19]),
        "uid": uids[0],
        "gid": gids[0],
        "argv_sha256": _sha(_canonical(argv)),
        "executable": os.readlink(root / "exe"),
        "cgroup": (root / "cgroup").read_text(),
        "boot_id": (_PROC / "sys/kernel/random/boot_id").read_text().strip(),
    }
    if (root / "stat").read_text().rsplit(") ", 1)[1].split()[19] != fields[19]:
        raise ValueError("original process changed during capture")
    return result


def _configuration():
    raw, bound = _read_root(CONFIG_PATH, 8 * 1024**2, modes={0o444})
    if max(bound["mtime_ns"], bound["ctime_ns"]) > ORIGINAL_STARTED_NS:
        raise ValueError("installed configuration changed after original launch")
    config = _parse(raw)
    if config.get("role") != "coordinator":
        raise ValueError("original owner is not the selected coordinator")
    return config, bound


def _state(config, owner):
    series = digest(config["series"])
    state = Path(config["state_directory"])
    root = state / series
    locations = {
        "service_root": root,
        "history_root": root / "history",
        "decisions_root": root / "decisions",
        "history_database": root / "history/rounds.sqlite3",
        "decisions_database": root / "decisions/rounds.sqlite3",
        "service_lock": root / "service.lock",
        "control_writer_lock": state / "control-writer.lock",
        "history_lock": root / "history/rounds.lock",
        "decisions_lock": root / "decisions/rounds.lock",
    }
    paths = {
        name: _metadata(path, owner=owner, directory=name.endswith("_root"))
        for name, path in locations.items()
    }
    return locations, paths


def capture_provenance():
    """Return an unsealed public selection; root must persist it before completion."""
    if os.geteuid() != _ROOT_UID:
        raise ValueError("original owner capture requires host root")
    process, service = _process(), _systemd()
    if (
        service["Id"] != SERVICE
        or int(service["MainPID"]) != ORIGINAL_PID
        or service["InvocationID"] != ORIGINAL_INVOCATION
        or service["ActiveState"] != "active"
        or service["SubState"] != "running"
        or process["cgroup"] != "0::" + service["ControlGroup"] + "\n"
        or abs(
            int(service["ExecMainStartTimestampMonotonic"]) / 1_000_000
            - process["start_ticks"] / os.sysconf("SC_CLK_TCK")
        )
        > 1
    ):
        raise ValueError("systemd does not select the original running owner")
    unit_paths = [service["FragmentPath"], *service["DropInPaths"].split()]
    units = {}
    for path in unit_paths:
        _, bound = _read_root(Path(path), 1024**2)
        if max(bound["mtime_ns"], bound["ctime_ns"]) > ORIGINAL_STARTED_NS:
            raise ValueError("systemd selection changed after original launch")
        units[path] = bound
    source_files = _installed_source()
    config, configuration = _configuration()
    locations, paths = _state(config, process["uid"])
    if _process() != process or _systemd() != service:
        raise ValueError("original owner changed during provenance capture")
    value = {
        "schema": SCHEMA,
        "captured_at_unix_ns": time.time_ns(),
        "source_semantics": SOURCE_SEMANTICS,
        "source_manifest_sha256": SOURCE_MANIFEST_SHA256,
        "source_files": source_files,
        "configuration": configuration,
        "systemd_files": units,
        "process": process,
        "service": service,
        "owner_uid": process["uid"],
        "signer_uid": process["uid"],
        "paths": {name: str(path) for name, path in locations.items()},
        "identities": paths,
        "series_sha256": digest(config["series"]),
        "policy_sha256": digest(config["policy"]),
        "manifest_sha256": digest(config["manifest"]),
        "chain_config_sha256": digest(config["chain"]),
        "signer": identity(config["signer_hotkey"]),
        "signer_hotkey": config["signer_hotkey"],
        "control_hotkey": config["series"]["control_hotkey"],
        "first_block": config["series"]["recovery"]["authority"]["issued_at_block"],
        "native_completion_claimed": False,
        **{name: str(path) for name, path in locations.items()},
        "signing_root": str(locations["decisions_root"]),
    }
    if len(_canonical(value)) > MAX_SELECTION_BYTES:
        raise ValueError("original owner selection exceeds its bound")
    return value


def load_provenance(path):
    """Load a root-sealed local selection, preserving its physical file identity."""
    raw, seal = _read_root(Path(path), MAX_SELECTION_BYTES, modes={0o444})
    value = _parse(raw)
    if (
        value.get("schema") != SCHEMA
        or value.get("source_semantics") != SOURCE_SEMANTICS
        or value.get("source_manifest_sha256") != SOURCE_MANIFEST_SHA256
        or value.get("native_completion_claimed") is not False
        or value.get("process", {}).get("pid") != ORIGINAL_PID
        or value.get("service", {}).get("InvocationID") != ORIGINAL_INVOCATION
    ):
        raise ValueError("unsupported original owner selection")
    return {**value, "_seal": seal}


def validate_state_identities(value):
    """Recheck the immutable local seal and original state after supported upgrades."""
    seal = value.get("_seal")
    if not isinstance(seal, dict) or load_provenance(Path(seal["path"])) != value:
        raise ValueError("original owner root seal changed")
    if set(value["paths"]) != set(value["identities"]):
        raise ValueError("original owner state inventory changed")
    for name, expected in value["identities"].items():
        if value["paths"][name] != expected["path"]:
            raise ValueError("original owner state path changed")
        if (
            _metadata(expected["path"], owner=value["owner_uid"], directory=name.endswith("_root"))
            != expected
        ):
            raise ValueError("original owner state identity changed")
    return value


def validate_provenance(value, *, require_stopped, check_original_installation=True):
    """Recheck original local ownership; no history completion is inferred."""
    validate_state_identities(value)
    if require_stopped:
        try:
            live = _process()
        except FileNotFoundError:
            live = None
        if live is not None and live["start_ticks"] == value["process"]["start_ticks"]:
            raise ValueError("original admission owner is still running")
        service = _systemd()
        if service["ActiveState"] not in {"inactive", "failed"} or int(service["MainPID"]) != 0:
            raise ValueError("selected admission service has not stopped")
    if check_original_installation:
        if _installed_source() != value["source_files"]:
            raise ValueError("original source installation changed")
        config, bound = _configuration()
        if (
            bound != value["configuration"]
            or _state(config, value["owner_uid"])[1] != value["identities"]
        ):
            raise ValueError("original configuration/state selection changed")
        for path, expected in value["systemd_files"].items():
            if _read_root(Path(path), 1024**2)[1] != expected:
                raise ValueError("original systemd installation changed")
    return value


@contextmanager
def open_existing_owner_locks(value):
    """Lock exact stopped-owner files; never create/reset state or a missing lock."""
    validate_provenance(value, require_stopped=True)
    with ExitStack() as stack:
        for name in ("service_lock", "control_writer_lock", "history_lock", "decisions_lock"):
            expected = value["identities"][name]
            fd = os.open(expected["path"], os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            stack.callback(os.close, fd)
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino) != (expected["dev"], expected["ino"]):
                raise ValueError("original owner lock replaced")
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stack.callback(fcntl.flock, fd, fcntl.LOCK_UN)
        validate_provenance(value, require_stopped=True)
        yield


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("capture", "check"))
    parser.add_argument("--selection", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "capture":
            if args.selection is not None:
                parser.error("capture writes public selection to stdout; root seals it separately")
            print(_canonical(capture_provenance()).decode(), end="")
        else:
            if args.selection is None:
                parser.error("check requires --selection")
            validate_provenance(load_provenance(args.selection), require_stopped=False)
            print('{"status":"original_selection_valid","native_completion_claimed":false}')
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        parser.exit(1, "original admission provenance check failed\n")


if __name__ == "__main__":
    main()
