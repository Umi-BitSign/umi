"""Root-owned mirrors of the configurations actually selected by cohort owners.

Mirrors carry existing configuration bytes, not new hold or signing authority.
An explicit admission compatibility selection omits only non-reward scheduling
fields after full native validation, retaining the exact source and its receipt.
Lifecycle hooks remove them before start and after stop. Publication follows the
system manager's command and brackets the copy with stable process/source checks.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import pwd
import re
import stat
import subprocess
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, model_serializer, model_validator

from . import competition_host_activation as root_files
from .competition_cohort_settlement_config import SettlementServiceConfig
from .competition_reward_transition_controls import MAX_CONFIG_BYTES, _identity
from .competition_service import CompetitionServiceConfig
from .competition_work_progress import WorkProgress
from .open_competition import digest
from .private_files import Directory, lock_private_file
from .protocol import StrictProtocolModel, canonical_json_bytes

MAX_METADATA_BYTES = 128 * 1024
ADMISSION_PROJECTION = "umi-reward-hold-admission-pre-scheduling/1"
MODULES = {
    "admission": ("umi.competition_cli", "umi-competition", "serve-intake"),
    "settlement": ("umi.competition_cohort_settlement_cli", "umi-cohort-settlement", "run"),
}


class RewardHoldMirrorConfig(StrictProtocolModel):
    schema_: Literal["umi-reward-hold-mirror/1"] = Field(alias="schema")
    unit: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.@-]+\.service$", max_length=255)]
    role: Literal["admission", "settlement"]
    service_user: Annotated[str, Field(pattern=r"^[a-z_][a-z0-9_-]*$", max_length=64)]
    target: Directory
    admission_compatibility: Literal["umi-reward-hold-admission-pre-scheduling/1"] | None = None

    @model_serializer(mode="wrap")
    def preserve_exact_default(self, handler):
        value = handler(self)
        if self.admission_compatibility is None:
            value.pop("admission_compatibility", None)
        return value

    @model_validator(mode="after")
    def admission_only(self):
        if self.admission_compatibility is not None and self.role != "admission":
            raise ValueError("admission compatibility projection cannot select settlement")
        return self


def load_mirror_config(path):
    raw = root_files._read_root_control_path(Path(path), 8192, modes={0o444})
    config = RewardHoldMirrorConfig.model_validate_json(raw)
    if canonical_json_bytes(config) != raw:
        raise ValueError("hold mirror owner configuration must be canonical")
    if Path(config.target) == Path(path):
        raise ValueError("hold mirror cannot replace its owner configuration")
    return config


def _bus(*args):
    result = subprocess.run(
        ["/usr/bin/busctl", "--system", "--json=short", *args],
        capture_output=True,
        check=True,
        timeout=5,
    )
    if len(result.stdout) > MAX_METADATA_BYTES:
        raise ValueError("system manager selection exceeds its metadata bound")
    return [json.loads(line)["data"] for line in result.stdout.splitlines()]


def selected_service(config):
    destination = "org.freedesktop.systemd1"
    reply = _bus(
        "call",
        destination,
        "/org/freedesktop/systemd1",
        destination + ".Manager",
        "GetUnit",
        "s",
        config.unit,
    )
    if len(reply) != 1 or not isinstance(reply[0], list) or len(reply[0]) != 1:
        raise ValueError("system manager returned an invalid unit identity")
    unit_path = reply[0][0]
    unit_names = ("Id", "LoadState", "ActiveState", "SubState")
    service_names = ("MainPID", "User", "ExecStart", "ControlGroup", "ExecMainStartTimestamp")
    unit = _bus("get-property", destination, unit_path, destination + ".Unit", *unit_names)
    service = _bus("get-property", destination, unit_path, destination + ".Service", *service_names)
    if len(unit) != len(unit_names) or len(service) != len(service_names):
        raise ValueError("system manager omitted selected owner metadata")
    state = dict(zip((*unit_names, *service_names), (*unit, *service), strict=True))
    if (
        state["Id"] != config.unit
        or state["LoadState"] != "loaded"
        or (state["ActiveState"], state["SubState"])
        not in {("active", "running"), ("activating", "start-post")}
        or type(state["MainPID"]) is not int
        or state["MainPID"] <= 1
        or state["User"] != config.service_user
        or type(state["ExecMainStartTimestamp"]) is not int
        or state["ExecMainStartTimestamp"] <= 0
        or not isinstance(state["ControlGroup"], str)
        or not state["ControlGroup"].startswith("/")
        or state["ControlGroup"] == "/"
    ):
        raise ValueError("hold mirror requires its exact running cohort owner")
    commands = state.pop("ExecStart")
    if not isinstance(commands, list) or len(commands) != 1 or len(commands[0]) != 10:
        raise ValueError("cohort owner requires one structured native command")
    executable, argv = commands[0][:2]
    if (
        not isinstance(executable, str)
        or not Path(executable).is_absolute()
        or not isinstance(argv, list)
        or not argv
        or argv[0] != executable
        or not all(isinstance(arg, str) and "\x00" not in arg for arg in argv)
    ):
        raise ValueError("cohort owner has an unsupported structured native command")
    state["argv"] = argv
    return state


def selected_config(argv, role):
    """Interpret supported native entry points without executing wrapper code."""
    module, entrypoint, verb = MODULES[role]
    if "-c" in argv:
        position = argv.index("-c")
        tree = ast.parse(argv[position + 1])
        calls = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "runpy"
            and node.func.attr == "run_module"
        ]
        if len(calls) != 1 or not calls[0].args or ast.literal_eval(calls[0].args[0]) != module:
            raise ValueError("cohort wrapper does not select its exact native module")
        assignments = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Attribute)
                and isinstance(target.value, ast.Name)
                and target.value.id == "sys"
                and target.attr == "argv"
                for target in node.targets
            )
        ]
        if assignments:
            if len(assignments) != 1:
                raise ValueError("cohort wrapper repeats its argument selection")
            effective = ast.literal_eval(assignments[0].value)
        else:
            effective = [module, *argv[position + 2 :]]
    elif "-m" in argv:
        effective = argv[argv.index("-m") + 1 :]
    elif Path(argv[0]).name == entrypoint:
        effective = [module, *argv[1:]]
    else:
        raise ValueError("cohort owner uses an unsupported native entry point")
    if (
        not isinstance(effective, list)
        or len(effective) < 4
        or not all(isinstance(arg, str) for arg in effective)
        or effective[0] != module
        or effective.count("--config") != 1
    ):
        raise ValueError("cohort command does not select one authoritative configuration")
    command_position = 1
    if role == "admission" and effective[1] == "--policy":
        root_files._canonical_absolute_path(Path(effective[2]), "admission policy")
        command_position = 3
    if effective[command_position] != verb or effective.count(verb) != 1:
        raise ValueError("cohort command does not select its authoritative owner role")
    position = effective.index("--config")
    if position <= command_position or position + 1 >= len(effective):
        raise ValueError("cohort command omitted its configuration path")
    return root_files._canonical_absolute_path(Path(effective[position + 1]), "cohort config")


def process_identity(state):
    pid = state["MainPID"]
    root = Path("/proc") / str(pid)
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if os.fstat(descriptor).st_uid != pwd.getpwnam(state["User"]).pw_uid:
            raise ValueError("cohort process changed its configured service account")

        def read(name):
            fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=descriptor)
            try:
                raw = os.read(fd, MAX_METADATA_BYTES + 1)
                if len(raw) > MAX_METADATA_BYTES:
                    raise ValueError("cohort process metadata exceeds its bound")
                return raw
            finally:
                os.close(fd)

        argv = [part.decode() for part in read("cmdline").split(b"\0") if part]
        expected = state["argv"]
        if argv != expected:
            # Kernel shebang invocation prepends the interpreter to an installed
            # console script. The manager-selected script remains authoritative.
            if argv[1:] != expected:
                raise ValueError("cohort process differs from system manager command")
            script = root_files._read_root_control_path(
                Path(expected[0]), MAX_METADATA_BYTES, modes={0o555, 0o755}
            )
            if script.splitlines()[0] != ("#!" + argv[0]).encode():
                raise ValueError("cohort process changed its installed script interpreter")
        groups = read("cgroup").decode().splitlines()
        if "0::" + state["ControlGroup"] not in groups:
            raise ValueError("cohort process is outside the selected service cgroup")
        info = read("stat").decode().rsplit(")", 1)[1].split()
        if len(info) < 20 or info[0] in {"Z", "X"}:
            raise ValueError("cohort process is no longer running")
        executable = os.stat("exe", dir_fd=descriptor)
        selected = os.stat(argv[0])
        if (executable.st_dev, executable.st_ino) != (selected.st_dev, selected.st_ino):
            raise ValueError("cohort process changed its executable")
        return [str(pid), info[19], str(executable.st_dev), str(executable.st_ino)]
    finally:
        os.close(descriptor)


def _validate_source(raw, role):
    if role == "admission":
        value = CompetitionServiceConfig.model_validate_json(raw)
        if (
            value.recoverable_intake is None
            or value.recoverable_service is None
            or value.recoverable_service.lifecycle is None
        ):
            raise ValueError("selected admission configuration has no progression owner")
    else:
        value = SettlementServiceConfig.model_validate_json(raw)
        if value.role != "coordinator" or canonical_json_bytes(value) != raw:
            raise ValueError("selected settlement configuration is not its canonical coordinator")


def _project_admission(raw):
    """After full native validation, omit only two non-reward scheduling fields.

    RewardTransitionControlReader consumes policy/series/intake authority and
    automatic_progression_hold_cohorts. Neither scheduling field participates
    in that decision. Preserve every other supplied value exactly, including
    unknown fields that the full native parser must already have rejected.
    This output is solely a hold-reader view, never an intake configuration.
    """
    value = json.loads(raw)
    lifecycle = value["recoverable_service"]["lifecycle"]
    lifecycle.pop("held_intake_sampling_cohorts", None)
    lifecycle["request_start"].pop("operator_start_overrides", None)
    return canonical_json_bytes(value)


def _projection_record(saved):
    value = saved.get("projection")
    if (
        not isinstance(value, dict)
        or saved["binding"].get("projection_policy") != ADMISSION_PROJECTION
        or set(value) != {"policy", "source_sha256", "output_sha256", "source_copy_identity"}
        or value["policy"] != ADMISSION_PROJECTION
        or any(
            not isinstance(value[k], str) or not re.fullmatch(r"[0-9a-f]{64}", value[k])
            for k in ("source_sha256", "output_sha256")
        )
        or not isinstance(value["source_copy_identity"], list)
        or len(value["source_copy_identity"]) != 5
        or not all(isinstance(v, str) and v.isdigit() for v in value["source_copy_identity"])
    ):
        raise ValueError("retained admission compatibility receipt requires repair")
    return value


def _stamp(path, maximum=MAX_CONFIG_BYTES):
    return [str(part) for part in _identity(path, maximum)]


def _remove(parent, name):
    try:
        info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    except FileNotFoundError:
        return
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != root_files._root_owner_uid()
        or info.st_nlink != 1
    ):
        raise ValueError("hold mirror path is not an independently root-owned regular file")
    os.unlink(name, dir_fd=parent)
    os.fsync(parent)


def _write(parent, name, raw):
    pending = name + ".pending"
    _remove(parent, pending)
    fd = os.open(
        pending,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
        dir_fd=parent,
    )
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(raw)
            stream.flush()
        os.fchmod(fd, 0o444)
        os.fsync(fd)
        os.replace(pending, name, src_dir_fd=parent, dst_dir_fd=parent)
        os.fsync(parent)
    finally:
        os.close(fd)
        _remove(parent, pending)


def update_hold_mirror(config, *, publish):
    if os.geteuid() != root_files._root_owner_uid():
        raise ValueError("hold mirror updates require the root owner")
    target = Path(config.target)
    parent = root_files._open_absolute_directory(target.parent)
    lease = None
    receipt = target.with_name(target.name + ".receipt.json")
    source_copy = target.with_name(target.name + ".source.json")
    projected = config.admission_compatibility is not None
    try:
        info = os.fstat(parent)
        if info.st_uid != root_files._root_owner_uid() or info.st_mode & 0o022:
            raise ValueError("hold mirror directory must be protected and root owned")
        lease = lock_private_file(target.with_name(target.name + ".lock"))
        with WorkProgress(
            "reward_hold_mirror",
            3 if publish else 1,
            unit="stages",
            estimate=False,
            planning_range_seconds=(0, 30),
            planning_basis="bounded service metadata, one changed configuration, atomic mirror",
        ) as progress:
            if not publish:
                _remove(parent, target.name)
                _remove(parent, target.name + ".pending")
                _remove(parent, receipt.name + ".pending")
                if projected:
                    _remove(parent, source_copy.name + ".pending")
                # Retain the bounded successful source check. A restarted owner
                # may select identical immutable bytes even though its old
                # process binding no longer authorizes a visible mirror.
                progress.advance()
                return {"status": "invalidated", "unit": config.unit, "role": config.role}
            try:
                state = selected_service(config)
                process = process_identity(state)
                source = selected_config(state["argv"], config.role)
                if source in {target, receipt, source_copy}:
                    raise ValueError("hold mirror cannot select itself as its source")
                stamp = _stamp(source)
                # The live process loaded its configuration at startup. A new
                # file at the same path needs a restart, not a mirror refresh.
                if int(stamp[-1]) > state["ExecMainStartTimestamp"] * 1000:
                    raise ValueError("selected configuration changed after the owner started")
                binding = {
                    "schema": "umi-reward-hold-mirror-receipt/2"
                    if projected
                    else "umi-reward-hold-mirror-receipt/1",
                    "config_sha256": digest(config),
                    "source": str(source),
                    "source_identity": stamp,
                    "service": {
                        key: value
                        for key, value in state.items()
                        if key not in {"ActiveState", "SubState"}
                    },
                    "process": process,
                }
                if projected:
                    binding["projection_policy"] = config.admission_compatibility
                progress.advance()
                saved = None
                if receipt.exists():
                    saved = json.loads(
                        root_files._read_root_control_path(
                            receipt, MAX_METADATA_BYTES, modes={0o444}
                        )
                    )
                    if (
                        not isinstance(saved, dict)
                        or not isinstance(saved.get("binding"), dict)
                        or saved["binding"].get("schema")
                        not in {
                            "umi-reward-hold-mirror-receipt/1",
                            "umi-reward-hold-mirror-receipt/2",
                        }
                    ):
                        raise ValueError("retained hold mirror receipt requires repair")
                    old_projected = saved["binding"]["schema"] == "umi-reward-hold-mirror-receipt/2"
                    expected_keys = {"binding", "mirror_identity"} | (
                        {"projection"} if old_projected else set()
                    )
                    if set(saved) != expected_keys:
                        raise ValueError("retained hold mirror receipt requires repair")
                    if old_projected:
                        _projection_record(saved)
                try:
                    mirror_stamp = _stamp(target)
                except FileNotFoundError:
                    mirror_stamp = None
                previous = {} if saved is None else saved.get("binding", {})
                source_unchanged = saved is not None and all(
                    previous.get(key) == binding[key]
                    for key in ("schema", "config_sha256", "source", "source_identity")
                )
                projection = None
                if projected and source_unchanged:
                    projection = _projection_record(saved)
                    if _stamp(source_copy) != projection["source_copy_identity"]:
                        raise ValueError("retained admission source copy requires repair")
                    if mirror_stamp is not None and saved["mirror_identity"] != mirror_stamp:
                        raise ValueError("retained admission projection requires repair")
                unchanged = (
                    saved is not None
                    and saved.get("binding") == binding
                    and saved.get("mirror_identity") == mirror_stamp
                )
                raw = None
                if not unchanged:
                    original = root_files._read_root_control_path(
                        source_copy if projected and source_unchanged else source,
                        MAX_CONFIG_BYTES,
                        modes={0o444},
                    )
                    if not source_unchanged:
                        _validate_source(original, config.role)
                    raw = original
                    if projected:
                        raw = _project_admission(original)
                        if source_unchanged:
                            if _stamp(source_copy) != projection["source_copy_identity"]:
                                raise ValueError("retained admission source changed during reuse")
                        else:
                            projection = {
                                "policy": config.admission_compatibility,
                                "source_sha256": hashlib.sha256(original).hexdigest(),
                                "output_sha256": hashlib.sha256(raw).hexdigest(),
                            }
                progress.advance()

                def stable():
                    if (
                        selected_service(config) != state
                        or process_identity(state) != process
                        or _stamp(source) != stamp
                        or os.fstat(parent)[:3] != os.stat(target.parent, follow_symlinks=False)[:3]
                    ):
                        raise ValueError("cohort owner or configuration changed during publication")

                stable()
                if not unchanged:
                    if projected and not source_unchanged:
                        _write(parent, source_copy.name, original)
                        projection["source_copy_identity"] = _stamp(source_copy)
                    _write(parent, target.name, raw)
                    stable()
                    _write(
                        parent,
                        receipt.name,
                        canonical_json_bytes(
                            {
                                "binding": binding,
                                "mirror_identity": _stamp(target),
                                **({"projection": projection} if projected else {}),
                            }
                        ),
                    )
                progress.advance()
                return {
                    "status": "unchanged" if unchanged else "published",
                    "unit": config.unit,
                    "role": config.role,
                    "pid": state["MainPID"],
                }
            except BaseException:
                # An old unheld view must never survive a failed refresh.
                _remove(parent, target.name)
                _remove(parent, receipt.name)
                raise
    finally:
        if lease is not None:
            os.close(lease)
        os.close(parent)


def mirror_drop_in(config_path, *, python, source_directory=None):
    """Render only; deployment explicitly selects and installs the named hooks."""
    load_mirror_config(config_path)
    for value in (str(config_path), python, source_directory):
        if value is not None and (
            not Path(value).is_absolute() or not re.fullmatch(r"/[A-Za-z0-9_./-]+", value)
        ):
            raise ValueError("hold mirror hook paths must be literal absolute paths")
    command = python + " -I -B"
    module = "umi.competition_reward_hold_mirror_cli"
    if source_directory is None:
        command += " -m " + module
    else:
        source = Path(source_directory)
        descriptor = root_files._open_absolute_directory(source)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != root_files._root_owner_uid() or info.st_mode & 0o022:
                raise ValueError("hook source directory must be protected and root owned")
        finally:
            os.close(descriptor)
        command += (
            " -c \"import runpy,sys;sys.path.insert(0,'"
            + source_directory
            + "');runpy.run_module('"
            + module
            + "',run_name='__main__')\""
        )
    return "[Service]\n" + "".join(
        f"{hook}=+{command} {action} --config {config_path}\n"
        for hook, action in (
            ("ExecStartPre", "invalidate"),
            ("ExecStartPost", "publish"),
            ("ExecStopPost", "invalidate"),
        )
    )
