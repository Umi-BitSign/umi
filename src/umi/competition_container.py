"""Low-level Podman operations for authenticated successor workers.

This module does not fetch directives, publish receipts, recover transactions,
or decide whether a completed attempt applied weights. Runtime integration must
inspect the durable worker result before treating completion as useful work.
The Finney network profile selects application clients, not an egress firewall.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import math
import os
import platform
import pwd
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .competition_host_activation import (
    AuthenticatedSuccessorActivation,
    validate_authenticated_successor_activation,
)
from .competition_release import (
    VerifiedSuccessorOCI,
    extract_successor_release_bundle,
    verify_staged_successor_release,
)
from .competition_supervisor import SuccessorSupervisorReleaseTarget
from .competition_worker import _open_directory_without_links
from .encoding import account_id32
from .protocol import canonical_json_bytes
from .validator_supervisor import ValidatorSupervisorConfig
from .validator_supervisor_adapters import (
    AsyncCommandRunner,
    ValidatorSupervisorAdapterError,
    _bind_mount,
    _require_safe_executable,
    _require_wallet_hotkey_identity,
    _safe_podman_source,
)

ACTIVATION_PATH = "/run/umi-successor-activation"
STATE_PATH = "/var/lib/umi-competition"
HOTKEY_PATH = "/run/umi-successor-hotkey/hotkey"
ENTRYPOINT = "/usr/local/bin/umi-competition-worker"
PYTHON = "/opt/umi/.venv/bin/python"
PODMAN_CGROUP_MANAGER_ARGUMENT = "--cgroup-manager=systemd"
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_ARCH = {"x86_64": "linux/amd64", "aarch64": "linux/arm64"}
_LABEL = "vision.umi.successor."
_CGROUP_ROOT = Path("/sys/fs/cgroup")


def _container_cgroup(container_id: str) -> str:
    if not _HEX64.fullmatch(container_id):
        raise SuccessorContainerError("invalid container cgroup identity")
    uid = os.geteuid()
    return f"/user.slice/user-{uid}.slice/user@{uid}.service/user.slice/libpod-{container_id}.scope"


def _require_empty_container_cgroup(container_id: str) -> None:
    """Check the fixed rootless systemd scope, including any child cgroups."""
    descriptor = _open_directory_without_links(_CGROUP_ROOT)
    try:
        for part in Path(_container_cgroup(container_id)).parts[1:]:
            try:
                child = os.open(
                    part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                )
            except FileNotFoundError:
                return  # The exact scope cannot exist below an absent ancestor.
            os.close(descriptor)
            descriptor = child
        pending = [(os.dup(descriptor), 0)]
        count = 0
        try:
            while pending:
                current, depth = pending.pop()
                try:
                    if depth > 16:
                        raise SuccessorContainerError(
                            "container cgroup depth exceeds inspection bound"
                        )
                    procs = os.open(
                        "cgroup.procs", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=current
                    )
                    try:
                        if not stat.S_ISREG(os.fstat(procs).st_mode):
                            raise SuccessorContainerError(
                                "container process list is not a kernel file"
                            )
                        if os.read(procs, 1):
                            raise SuccessorContainerError(
                                "container cgroup still contains processes"
                            )
                    finally:
                        os.close(procs)
                    with os.scandir(current) as entries:
                        for entry in entries:
                            count += 1
                            if count > 65536:
                                raise SuccessorContainerError(
                                    "container cgroup entry bound exceeded"
                                )
                            if entry.is_symlink():
                                raise SuccessorContainerError("container cgroup contains a symlink")
                            if entry.is_dir(follow_symlinks=False):
                                if len(pending) >= 1024:
                                    raise SuccessorContainerError(
                                        "container descendant bound exceeded"
                                    )
                                nested = os.open(
                                    entry.name,
                                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=current,
                                )
                                pending.append((nested, depth + 1))
                finally:
                    os.close(current)
        finally:
            for current, _ in pending:
                os.close(current)
    finally:
        os.close(descriptor)


# Fixed signed-image code: no model imports, network, wallet, or retained state.
_REHEARSAL = r"""
import json, os, pathlib, sys
def require(condition):
    if not condition:
        raise RuntimeError('successor sandbox contract failed')
lines = pathlib.Path('/proc/self/status').read_text().splitlines()
status = dict(line.split(':', 1) for line in lines if ':' in line)
group = pathlib.Path('/sys/fs/cgroup')
require(os.geteuid() == int(sys.argv[1]))
require(status['NoNewPrivs'].strip() == '1' and int(status['CapEff'].strip(), 16) == 0)
require(os.statvfs('/').f_flag & os.ST_RDONLY)
require(int((group / 'memory.max').read_text()) == int(sys.argv[2]))
require(int((group / 'memory.swap.max').read_text()) == 0)
require(int((group / 'pids.max').read_text()) == int(sys.argv[3]))
quota, period = (group / 'cpu.max').read_text().split()
require(int(quota) * 1000 == int(period) * int(sys.argv[4]))
devices = pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]
require({line.split(':')[0].strip() for line in devices} <= {'lo'})
require(not pathlib.Path('/run/umi-successor-hotkey').exists())
probe = pathlib.Path('/tmp/umi-inert-rehearsal')
probe.write_bytes(b'ok'); probe.unlink()
result = {'schema': 'umi-successor-sandbox-rehearsal/1', 'ok': True}
print(json.dumps(result, separators=(',', ':')))
""".strip()


class SuccessorContainerError(ValueError):
    pass


@dataclass(frozen=True)
class SuccessorContainerLimits:
    maximum_cache_entries: int
    maximum_cache_bytes: int
    maximum_input_entries: int
    maximum_input_bytes: int
    maximum_state_entries: int
    maximum_state_bytes: int
    maximum_tree_depth: int = 12
    maximum_command_output_bytes: int = 1024 * 1024
    command_timeout_seconds: float = 300
    stop_timeout_seconds: int = 30
    temporary_bytes: int = 64 * 1024 * 1024

    def __post_init__(self):
        for name in self.__dataclass_fields__:
            value = getattr(self, name)
            kind = (int, float) if name == "command_timeout_seconds" else (int,)
            if (
                isinstance(value, bool)
                or not isinstance(value, kind)
                or not math.isfinite(value)
                or value <= 0
            ):
                raise ValueError("container limits must be explicit positive bounds")
        if not 1 <= self.maximum_tree_depth <= 64 or self.command_timeout_seconds > 3600:
            raise ValueError("container depth or timeout exceeds supported bound")
        if self.maximum_command_output_bytes > 16 * 1024 * 1024:
            raise ValueError("container command output bound is too large")


@dataclass(frozen=True)
class SuccessorContainerStatus:
    phase: Literal["absent", "created", "running", "completed", "held", "failed"]
    container_id: str | None = None
    directive_sha256: str | None = None
    exit_code: int | None = None

    # Deliberately no `applied`, `healthy`, or chain-authority property.


def _digest(value) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _json(payload: bytes):
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, ValueError) as error:
        raise SuccessorContainerError("Podman returned invalid JSON") from error


def _one(payload: bytes) -> dict:
    value = _json(payload)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise SuccessorContainerError("Podman returned an ambiguous identity")
    return value[0]


def _private_directory(path: Path, owner: int) -> None:
    _safe_podman_source(path)
    descriptor = _open_directory_without_links(path)
    try:
        info = os.fstat(descriptor)
        if info.st_uid != owner or stat.S_IMODE(info.st_mode) != 0o700:
            raise SuccessorContainerError("private container directory has unsafe ownership")
    finally:
        os.close(descriptor)


def _bounded_tree(path: Path, owner: int, entries: int, size: int, depth: int) -> int:
    """Descriptor walk; never read contents or follow links, including ancestors."""
    _safe_podman_source(path)
    count = total = 0

    def walk(descriptor, level):
        nonlocal count, total
        info = os.fstat(descriptor)
        if info.st_uid != owner or info.st_mode & 0o022:
            raise SuccessorContainerError("container input ownership or permissions changed")
        if level > depth:
            raise SuccessorContainerError("container tree depth exceeded")
        with os.scandir(descriptor) as children:
            for child in children:
                count += 1
                if count > entries:
                    raise SuccessorContainerError("container tree entry bound exceeded")
                before = os.stat(child.name, dir_fd=descriptor, follow_symlinks=False)
                if before.st_uid != owner or before.st_mode & 0o022:
                    raise SuccessorContainerError(
                        "container input ownership or permissions changed"
                    )
                if stat.S_ISDIR(before.st_mode):
                    nested = os.open(
                        child.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor
                    )
                    try:
                        if os.fstat(nested).st_ino != before.st_ino:
                            raise SuccessorContainerError(
                                "container tree changed during inspection"
                            )
                        walk(nested, level + 1)
                    finally:
                        os.close(nested)
                elif stat.S_ISREG(before.st_mode) and before.st_nlink == 1:
                    total += before.st_size
                    if total > size:
                        raise SuccessorContainerError("container tree byte bound exceeded")
                else:
                    raise SuccessorContainerError("container tree contains a link or special file")

    descriptor = _open_directory_without_links(path)
    try:
        walk(descriptor, 0)
    finally:
        os.close(descriptor)
    return total


def _command_environment() -> dict[str, str]:
    # No wallet, cloud, Python, remote Podman, or loader variables are forwarded.
    identity = pwd.getpwuid(os.geteuid())
    return {
        "PATH": "/usr/bin:/bin",
        "HOME": identity.pw_dir,
        "USER": identity.pw_name,
        "LOGNAME": identity.pw_name,
        "LANG": "C.UTF-8",
        "XDG_RUNTIME_DIR": f"/run/user/{os.geteuid()}",
        "DBUS_SESSION_BUS_ADDRESS": f"unix:path=/run/user/{os.geteuid()}/bus",
    }


async def _run_command(arguments, *, timeout_seconds, maximum_output_bytes):
    if not arguments or any(not isinstance(arg, str) or "\0" in arg for arg in arguments):
        raise SuccessorContainerError("invalid Podman arguments")
    process = await asyncio.create_subprocess_exec(
        *arguments,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        env=_command_environment(),
    )

    async def collect():
        if process.stdout is None:
            raise SuccessorContainerError("Podman output pipe is absent")
        output = bytearray()
        while True:
            part = await process.stdout.read(min(65536, maximum_output_bytes + 1 - len(output)))
            if not part:
                break
            output.extend(part)
            if len(output) > maximum_output_bytes:
                raise SuccessorContainerError("Podman output bound exceeded")
        if await process.wait() != 0:
            raise SuccessorContainerError("Podman command failed")
        return bytes(output)

    try:
        return await asyncio.wait_for(collect(), timeout_seconds)
    except BaseException:
        if process.returncode is None:
            with contextlib.suppress(ProcessLookupError):
                process.kill()
        with contextlib.suppress(Exception):
            await process.wait()
        raise


class PodmanSuccessorContainer:
    """Own one successor container per configured hotkey, never a legacy unit.

    The runtime must hold its existing process lock while using this object.
    Cache/state checks are admission bounds, not kernel disk quotas. Workers
    separately enforce the signed execution limits for durable journals.
    """

    def __init__(
        self,
        config: ValidatorSupervisorConfig,
        *,
        limits: SuccessorContainerLimits,
        command_runner: AsyncCommandRunner | None = None,
    ):
        self.config = ValidatorSupervisorConfig.model_validate_json(canonical_json_bytes(config))
        self.limits = limits
        self._runner = command_runner or _run_command
        self._config_sha256 = _digest(self.config)
        self._hotkey_sha256 = hashlib.sha256(account_id32(config.validator_hotkey)).hexdigest()
        self.name = f"umi-successor-{self._hotkey_sha256[:32]}"
        self._rehearsed: set[str] = set()

    async def _command(self, *arguments):
        # Pin the manager even on the first rootless namespace creation. Host
        # /proc isolation can make Podman's default detection choose cgroupfs.
        result = await self._runner(
            (self.config.container_runtime, PODMAN_CGROUP_MANAGER_ARGUMENT, *arguments),
            timeout_seconds=self.limits.command_timeout_seconds,
            maximum_output_bytes=self.limits.maximum_command_output_bytes,
        )
        if not isinstance(result, bytes) or len(result) > self.limits.maximum_command_output_bytes:
            raise SuccessorContainerError("Podman output bound exceeded")
        return result

    async def check_host(self) -> None:
        if (
            platform.system() != "Linux"
            or _ARCH.get(platform.machine()) != self.config.target_platform
        ):
            raise SuccessorContainerError(
                "successor container requires its selected Linux platform"
            )
        if os.geteuid() == 0:
            raise SuccessorContainerError("successor Podman must run as the service user")
        _require_safe_executable(Path(self.config.container_runtime))
        info = _json(await self._command("info", "--format=json"))
        host = info.get("host", {}) if isinstance(info, dict) else {}
        if (
            host.get("security", {}).get("rootless") is not True
            or host.get("cgroupVersion") != "v2"
            or host.get("cgroupManager") != "systemd"
            or host.get("ociRuntime", {}).get("name") != "crun"
        ):
            raise SuccessorContainerError(
                "rootless Podman, systemd cgroup v2, and crun are required"
            )

    def stage_release(
        self, bundle: Path, target: SuccessorSupervisorReleaseTarget
    ) -> VerifiedSuccessorOCI:
        target = SuccessorSupervisorReleaseTarget.model_validate_json(canonical_json_bytes(target))
        root = Path(self.config.release_root)
        _private_directory(root, os.geteuid())
        parent = root / "successor"
        if not parent.exists():
            parent.mkdir(mode=0o700)
        _private_directory(parent, os.geteuid())
        used = _bounded_tree(
            parent,
            os.geteuid(),
            self.limits.maximum_cache_entries * 4,
            self.limits.maximum_cache_bytes,
            2,
        )
        destination = parent / target.release_bundle_sha256
        if destination.exists():
            return verify_staged_successor_release(destination, target=target, config=self.config)
        with os.scandir(parent) as children:
            count = sum(1 for _ in children)
        if (
            count >= self.limits.maximum_cache_entries
            or used + target.release_bundle_size_bytes > self.limits.maximum_cache_bytes
        ):
            raise SuccessorContainerError("successor release cache is full; no history was removed")
        destination.mkdir(mode=0o700)
        return extract_successor_release_bundle(
            bundle=bundle, destination=destination, target=target, config=self.config
        )

    @staticmethod
    def _image_reference(release):
        return f"{release.target.oci_repository}@sha256:{release.target.oci_manifest_sha256}"

    def _validate_release(self, release):
        if type(release) is not VerifiedSuccessorOCI:
            raise SuccessorContainerError("verified successor OCI capability required")
        release.recheck()
        verify_staged_successor_release(release.path, target=release.target, config=self.config)

    async def _inspect_image(self, release):
        record = _one(
            await self._command("image", "inspect", "--format=json", self._image_reference(release))
        )
        labels = record.get("Config", {}).get("Labels", {})
        target = release.target
        digest = f"sha256:{target.oci_manifest_sha256}"
        if (
            record.get("Architecture") != target.target_platform.split("/")[1]
            or record.get("Os", record.get("OS")) != "linux"
            or not (
                record.get("Digest") == digest
                or self._image_reference(release) in record.get("RepoDigests", [])
            )
            or labels.get("org.opencontainers.image.revision") != target.umi_git_revision
            or labels.get("vision.umi.source-tree-sha256") != target.umi_source_tree_sha256
            or labels.get("vision.umi.entrypoint-profile") != target.entrypoint_profile
        ):
            raise SuccessorContainerError("OCI image does not match its authenticated release")

    async def prepare_image(self, release: VerifiedSuccessorOCI) -> None:
        self._validate_release(release)
        await self.check_host()
        try:
            await self._inspect_image(release)
        except SuccessorContainerError:
            await self._command("load", "--input", str(release.archive_path))
            self._validate_release(release)
            await self._inspect_image(release)
        await self.rehearse(release)

    def _sandbox(self, network):
        cfg = self.config
        return (
            "--pull=never",
            "--image-volume=ignore",
            "--read-only",
            "--read-only-tmpfs=false",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--cgroups=enabled",
            "--cgroup-parent=user.slice",
            "--cgroupns=private",
            f"--network={network}",
            "--log-driver=none",
            f"--userns=keep-id:uid={cfg.worker_uid},gid={cfg.worker_gid}",
            f"--user={cfg.worker_uid}:{cfg.worker_gid}",
            f"--cpus={cfg.worker_cpu_millis / 1000:g}",
            f"--memory={cfg.worker_memory_bytes}",
            f"--memory-swap={cfg.worker_memory_bytes}",
            f"--pids-limit={cfg.worker_pids_limit}",
            f"--tmpfs=/tmp:rw,noexec,nosuid,nodev,size={self.limits.temporary_bytes},mode=1777",
        )

    async def rehearse(self, release: VerifiedSuccessorOCI) -> None:
        self._validate_release(release)
        await self.check_host()
        await self._inspect_image(release)
        name = self.name + "-rehearsal"
        if await self._find_container(name) is not None:
            raise SuccessorContainerError("an earlier sandbox rehearsal needs reconciliation")
        labels = {
            _LABEL + "config": self._config_sha256,
            _LABEL + "hotkey": self._hotkey_sha256,
            _LABEL + "purpose": "inert-rehearsal",
            _LABEL + "release": release.target.release_bundle_sha256,
        }
        args = ["create", "--name", name, *self._sandbox("none")]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        args.extend(
            (
                "--entrypoint",
                PYTHON,
                self._image_reference(release),
                "-I",
                "-c",
                _REHEARSAL,
                str(self.config.worker_uid),
                str(self.config.worker_memory_bytes),
                str(self.config.worker_pids_limit),
                str(self.config.worker_cpu_millis),
            )
        )
        try:
            encoded = await self._command(*args)
            container_id = encoded.decode("ascii").strip()
            await self._inspect_rehearsal(container_id, labels)
            output = await self._command("start", "--attach", container_id)
        finally:
            # Killing the Podman CLI does not establish container absence.
            # Resolve only this fixed name and require its exact ownership labels.
            container_id = await self._find_container(name)
            if container_id is not None:
                record = await self._inspect_rehearsal(container_id, labels)
                if record.get("State", {}).get("Running") is True:
                    await self._command(
                        "stop", f"--time={self.limits.stop_timeout_seconds}", container_id
                    )
                    record = await self._inspect_rehearsal(container_id, labels)
                if (
                    record.get("State", {}).get("Running") is not False
                    or record.get("State", {}).get("Pid") != 0
                ):
                    raise SuccessorContainerError("inert rehearsal process absence is unconfirmed")
                _require_empty_container_cgroup(container_id)
                await self._command("rm", container_id)
                if await self._find_container(name) is not None:
                    raise SuccessorContainerError("inert rehearsal removal is unconfirmed")
        if _json(output) != {"schema": "umi-successor-sandbox-rehearsal/1", "ok": True}:
            raise SuccessorContainerError("inert successor sandbox rehearsal failed")
        self._rehearsed.add(release.target.release_bundle_sha256)

    async def _inspect_rehearsal(self, container_id, expected_labels):
        if not _HEX64.fullmatch(container_id):
            raise SuccessorContainerError("invalid rehearsal container identity")
        record = _one(await self._command("container", "inspect", "--format=json", container_id))
        labels = record.get("Config", {}).get("Labels", {})
        own = {key: value for key, value in labels.items() if key.startswith(_LABEL)}
        if (
            record.get("Id") != container_id
            or record.get("Name", "").lstrip("/") != self.name + "-rehearsal"
            or own != expected_labels
        ):
            raise SuccessorContainerError("refusing unrelated rehearsal container")
        reported_cgroup = record.get("State", {}).get("CgroupPath")
        if reported_cgroup not in {None, "", _container_cgroup(container_id)}:
            raise SuccessorContainerError("rehearsal cgroup differs from its fixed systemd scope")
        return record

    async def _find_container(self, name):
        records = _json(
            await self._command("ps", "--all", f"--filter=name=^{name}$", "--format=json")
        )
        if records == []:
            return None
        if not isinstance(records, list) or len(records) != 1 or not isinstance(records[0], dict):
            raise SuccessorContainerError("ambiguous successor container listing")
        container_id = records[0].get("Id", records[0].get("ID", ""))
        if not isinstance(container_id, str) or not _HEX64.fullmatch(container_id):
            raise SuccessorContainerError("invalid listed container identity")
        return container_id

    def _activation_sources(self, activation):
        inputs = activation._inputs
        root = inputs.mount_root
        # The loader checks projected container owners. These are actual host owners.
        if root != Path(ACTIVATION_PATH):
            raise SuccessorContainerError("activation source is not the fixed installed mount")
        descriptor = _open_directory_without_links(root)
        try:
            info = os.fstat(descriptor)
            if info.st_uid != 0 or info.st_mode & 0o022:
                raise SuccessorContainerError("activation root lacks host root provenance")
            names = set()
            with os.scandir(descriptor) as children:
                for entry in children:
                    if len(names) == 2:
                        raise SuccessorContainerError("activation root has unexpected entries")
                    names.add(entry.name)
            if names != {"anchor", "current"}:
                raise SuccessorContainerError("activation root differs from its fixed subtrees")
        finally:
            os.close(descriptor)
        limit = self.limits
        for name, owner in (("anchor", 0), ("current", os.geteuid())):
            _bounded_tree(
                root / name,
                owner,
                limit.maximum_input_entries,
                limit.maximum_input_bytes,
                limit.maximum_tree_depth,
            )
        return root

    def _worker_mounts(self, activation):
        source = self._activation_sources(activation)
        # Mount the complete root read-only so the loader can verify statvfs(root).
        mounts = [_bind_mount(source, ACTIVATION_PATH, read_only=True)]
        root = Path(self.config.worker_state_root)
        _private_directory(root, os.geteuid())
        state = root / "competition"
        if not state.exists():
            state.mkdir(mode=0o700)
        _private_directory(state, os.geteuid())
        limits = self.limits
        _bounded_tree(
            state,
            os.geteuid(),
            limits.maximum_state_entries,
            limits.maximum_state_bytes,
            limits.maximum_tree_depth,
        )
        mounts.append(_bind_mount(state, STATE_PATH, read_only=False))
        if activation.profile == "competition_weights":
            wallet = self.config.wallet
            key = Path(wallet.path) / wallet.name / "hotkeys" / wallet.hotkey
            parent = _open_directory_without_links(key.parent)
            try:
                info = os.stat(key.name, dir_fd=parent, follow_symlinks=False)
                if (
                    not stat.S_ISREG(info.st_mode)
                    or info.st_nlink != 1
                    or info.st_uid != os.geteuid()
                    or stat.S_IMODE(info.st_mode) != 0o400
                ):
                    raise SuccessorContainerError(
                        "named validator hotkey must be a private read-only file"
                    )
                try:
                    _require_wallet_hotkey_identity(key, self.config.validator_hotkey)
                except ValidatorSupervisorAdapterError as error:
                    raise SuccessorContainerError(
                        "named validator hotkey identity is invalid"
                    ) from error
            finally:
                os.close(parent)
            mounts.append(_bind_mount(key, HOTKEY_PATH, read_only=True))
        return tuple(mounts)

    def _validate_activation(self, activation, release):
        if type(activation) is not AuthenticatedSuccessorActivation:
            raise SuccessorContainerError("authenticated successor activation required")
        validate_authenticated_successor_activation(
            activation,
            validator_hotkey=self.config.validator_hotkey,
            directive_sha256=activation.directive_sha256,
            package_sha256=activation.package_sha256,
            authorization_sha256=activation.authorization_sha256,
            expected_profile=activation.profile,
        )
        if (
            activation.config_sha256 != self._config_sha256
            or activation.directive.release != release.target
        ):
            raise SuccessorContainerError("activation and installed OCI configuration differ")

    def _labels(self, activation):
        return {
            _LABEL + "config": self._config_sha256,
            _LABEL + "hotkey": self._hotkey_sha256,
            _LABEL + "directive": activation.directive_sha256,
            _LABEL + "receipt": activation._inputs.receipt_sha256,
            _LABEL + "profile": activation.profile,
        }

    async def launch(
        self, activation: AuthenticatedSuccessorActivation, release: VerifiedSuccessorOCI
    ) -> SuccessorContainerStatus:
        self._validate_release(release)
        self._validate_activation(activation, release)
        if release.target.release_bundle_sha256 not in self._rehearsed:
            raise SuccessorContainerError(
                "exact successor release has not passed sandbox rehearsal"
            )
        if (await self.status()).phase != "absent":
            raise SuccessorContainerError(
                "previous successor container must be recovered and removed first"
            )
        await self.check_host()
        await self._inspect_image(release)
        mounts = self._worker_mounts(activation)
        labels = self._labels(activation)
        network = (
            "none"
            if activation.profile == "competition_replay"
            else "slirp4netns:allow_host_loopback=false"
        )
        args = ["create", "--name", self.name, *self._sandbox(network)]
        for key, value in sorted(labels.items()):
            args.extend(("--label", f"{key}={value}"))
        for mount in mounts:
            args.extend(("--mount", mount))
        args.extend(
            ("--entrypoint", ENTRYPOINT, self._image_reference(release), activation.profile)
        )
        container_id = (await self._command(*args)).decode("ascii").strip()
        if not _HEX64.fullmatch(container_id):
            raise SuccessorContainerError("Podman create did not return one exact container ID")
        # Never execute an image before checking the created object and sources again.
        record = await self._inspect_owned(container_id)
        managed_labels = {
            key: value
            for key, value in record.get("Config", {}).get("Labels", {}).items()
            if key.startswith(_LABEL)
        }
        if (
            managed_labels != labels
            or record.get("Config", {}).get("Cmd") != [activation.profile]
            or record.get("Config", {}).get("Entrypoint") not in ([ENTRYPOINT], ENTRYPOINT)
            or record.get("ImageName") != self._image_reference(release)
        ):
            raise SuccessorContainerError("created successor container identity differs")
        actual_mounts = {
            (item.get("Source"), item.get("Destination"), item.get("RW"))
            for item in record.get("Mounts", [])
        }
        expected_mounts = set()
        for encoded in mounts:
            fields = dict(item.split("=", 1) for item in encoded.split(","))
            expected_mounts.add((fields["src"], fields["dst"], fields["ro"] == "false"))
        if (
            actual_mounts != expected_mounts
            or record.get("HostConfig", {}).get("ReadonlyRootfs") is not True
        ):
            raise SuccessorContainerError("created successor mount sandbox differs")
        self._validate_release(release)
        self._validate_activation(activation, release)
        self._worker_mounts(activation)
        await self._command("start", container_id)
        return await self.status()

    async def _inspect_owned(self, container_id):
        if not _HEX64.fullmatch(container_id):
            raise SuccessorContainerError("invalid managed container identity")
        record = _one(await self._command("container", "inspect", "--format=json", container_id))
        labels = record.get("Config", {}).get("Labels", {})
        if (
            record.get("Id") != container_id
            or record.get("Name", "").lstrip("/") != self.name
            or labels.get(_LABEL + "config") != self._config_sha256
            or labels.get(_LABEL + "hotkey") != self._hotkey_sha256
            or labels.get(_LABEL + "profile") not in {"competition_replay", "competition_weights"}
            or not _HEX64.fullmatch(labels.get(_LABEL + "directive", ""))
            or not _HEX64.fullmatch(labels.get(_LABEL + "receipt", ""))
        ):
            raise SuccessorContainerError("refusing an unrelated container identity")
        reported_cgroup = record.get("State", {}).get("CgroupPath")
        if reported_cgroup not in {None, "", _container_cgroup(container_id)}:
            raise SuccessorContainerError("container cgroup differs from its fixed systemd scope")
        return record

    async def status(self) -> SuccessorContainerStatus:
        container_id = await self._find_container(self.name)
        if container_id is None:
            return SuccessorContainerStatus("absent")
        record = await self._inspect_owned(container_id)
        state = record.get("State", {})
        status, code = state.get("Status"), state.get("ExitCode")
        pid = state.get("Pid")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid < 0:
            raise SuccessorContainerError("successor container PID state is uncertain")
        if status == "running" and state.get("Running") is True and pid > 0:
            phase, code = "running", None
        elif status in {"created", "configured"} and state.get("Running") is False and pid == 0:
            phase, code = "created", None
        elif (
            status == "exited"
            and state.get("Running") is False
            and pid == 0
            and isinstance(code, int)
            and not isinstance(code, bool)
        ):
            phase = "completed" if code == 0 else "held" if code == 3 else "failed"
        else:
            raise SuccessorContainerError("successor container has an uncertain lifecycle state")
        return SuccessorContainerStatus(
            phase, container_id, record["Config"]["Labels"][_LABEL + "directive"], code
        )

    async def stop(self) -> SuccessorContainerStatus:
        """Stop exact ownership-checked ID; retain its results and metadata."""
        status = await self.status()
        if status.phase == "absent":
            return status
        await self._inspect_owned(status.container_id)
        if status.phase == "running":
            await self._command(
                "stop", f"--time={self.limits.stop_timeout_seconds}", status.container_id
            )
        final = await self.status()
        if final.phase == "running" or final.container_id != status.container_id:
            raise SuccessorContainerError("successor container absence was not established")
        _require_empty_container_cgroup(status.container_id)
        return final

    async def remove_stopped(self) -> None:
        """Remove only stopped container metadata, after caller transaction recovery.

        Bound state is never removed. This operation grants no permission to
        launch a replacement; the runtime must first reconcile durable effects.
        """
        status = await self.status()
        if status.phase == "absent":
            return
        if status.phase == "running":
            raise SuccessorContainerError("refusing to remove a running successor")
        await self._inspect_owned(status.container_id)
        _require_empty_container_cgroup(status.container_id)
        await self._command("rm", status.container_id)
        if (await self.status()).phase != "absent":
            raise SuccessorContainerError("successor container removal was not confirmed")
