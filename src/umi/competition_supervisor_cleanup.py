"""Wallet-free ExecStopPost cleanup for one configured successor worker.

This entrypoint does not load the activation mount, package, wallet or worker
journals. It needs the unchanged root-owned supervisor configuration, original
process-lock inode, and the service user's existing Podman metadata. It stops
only the exact configuration/hotkey-labelled successor container, retaining its
metadata and durable state for the next supervisor's transaction recovery.
"""

from __future__ import annotations

import argparse
import asyncio
import fcntl
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from .competition_container import (
    PODMAN_CGROUP_MANAGER_ARGUMENT,
    PodmanSuccessorContainer,
    SuccessorContainerLimits,
    _run_command,
)
from .competition_host_artifacts import _ancestor_identity, _ancestor_paths
from .competition_supervisor_cli import _root_control
from .competition_worker import (
    _open_directory_without_links,
    _open_private_regular_file,
    _verify_private_directory,
)
from .validator_supervisor import (
    MAX_SUPERVISOR_DOCUMENT_BYTES,
    parse_canonical_validator_supervisor_config,
)
from .validator_supervisor_adapters import _require_safe_executable

_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_COMMAND_TIMEOUT_SECONDS = 45
_STOP_TIMEOUT_SECONDS = 30
_MAX_COMMAND_OUTPUT_BYTES = 1024 * 1024
_TOTAL_TIMEOUT_SECONDS = 150


class SuccessorCleanupBusy(RuntimeError):
    """A supervisor already owns the original process lock; do not touch it."""


def _directory_identity(path):
    descriptor = _open_directory_without_links(path)
    try:
        info = os.fstat(descriptor)
        return info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_gid
    finally:
        os.close(descriptor)


class _CleanupLease:
    def __init__(self, config_path):
        self.path = config_path
        self.ancestors = {path: _ancestor_identity(path) for path in _ancestor_paths(config_path)}
        self.payload = _root_control(config_path, MAX_SUPERVISOR_DOCUMENT_BYTES)
        self.config = parse_canonical_validator_supervisor_config(self.payload)
        self.root = Path(self.config.state_root)
        _verify_private_directory(self.root, "supervisor state")
        self.root_identity = _directory_identity(self.root)
        self.lock_path = self.root / "supervisor-process.lock"
        self.descriptor = -1
        self.lock_identity = None

    def __enter__(self):
        descriptor = _open_private_regular_file(self.lock_path, "original supervisor lock")
        try:
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SuccessorCleanupBusy("supervisor owns its process lock") from None
            info = os.fstat(descriptor)
            self.descriptor = descriptor
            self.lock_identity = info.st_dev, info.st_ino
            self.recheck()
            return self
        except BaseException:
            self.descriptor = -1
            os.close(descriptor)
            raise

    def recheck(self):
        if self.descriptor < 0 or self.lock_identity is None:
            raise ValueError("cleanup lacks the original supervisor process lease")
        if any(_ancestor_identity(path) != identity for path, identity in self.ancestors.items()):
            raise ValueError("cleanup root configuration parent changed")
        if _root_control(self.path, MAX_SUPERVISOR_DOCUMENT_BYTES) != self.payload:
            raise ValueError("cleanup root configuration changed")
        _verify_private_directory(self.root, "supervisor state")
        if _directory_identity(self.root) != self.root_identity:
            raise ValueError("cleanup supervisor state directory changed")
        descriptor = _open_private_regular_file(self.lock_path, "original supervisor lock")
        try:
            named, held = os.fstat(descriptor), os.fstat(self.descriptor)
            if (named.st_dev, named.st_ino) != self.lock_identity or (
                held.st_dev,
                held.st_ino,
            ) != self.lock_identity:
                raise ValueError("cleanup supervisor process lock inode changed")
        finally:
            os.close(descriptor)

    def __exit__(self, *_args):
        descriptor, self.descriptor = self.descriptor, -1
        if descriptor >= 0:
            os.close(descriptor)


async def cleanup_successor(config_path: Path) -> str:
    if sys.platform != "linux" or os.geteuid() == 0:
        raise ValueError("cleanup requires the installed non-root Linux service user")
    if not config_path.is_absolute() or config_path != Path(os.path.normpath(config_path)):
        raise ValueError("cleanup configuration path is not canonical and absolute")
    with _CleanupLease(config_path) as lease:
        _require_safe_executable(Path(lease.config.container_runtime))

        async def stop_only_command(arguments, **bounds):
            # A future expansion of PodmanSuccessorContainer.stop must not turn
            # ExecStopPost into an image, wallet, start, prune or removal path.
            listing = (
                lease.config.container_runtime,
                PODMAN_CGROUP_MANAGER_ARGUMENT,
                "ps",
                "--all",
                f"--filter=name=^{container.name}$",
                "--format=json",
            )
            inspect = (
                len(arguments) == 6
                and arguments[:5]
                == (
                    lease.config.container_runtime,
                    PODMAN_CGROUP_MANAGER_ARGUMENT,
                    "container",
                    "inspect",
                    "--format=json",
                )
                and _HEX64.fullmatch(arguments[-1]) is not None
            )
            stop = (
                len(arguments) == 5
                and arguments[:4]
                == (
                    lease.config.container_runtime,
                    PODMAN_CGROUP_MANAGER_ARGUMENT,
                    "stop",
                    f"--time={_STOP_TIMEOUT_SECONDS}",
                )
                and _HEX64.fullmatch(arguments[-1]) is not None
            )
            if arguments != listing and not inspect and not stop:
                raise ValueError("cleanup attempted an operation outside its fixed stop profile")
            if bounds != {
                "timeout_seconds": _COMMAND_TIMEOUT_SECONDS,
                "maximum_output_bytes": _MAX_COMMAND_OUTPUT_BYTES,
            }:
                raise ValueError("cleanup command bounds changed")
            lease.recheck()
            result = await _run_command(arguments, **bounds)
            lease.recheck()
            return result

        container = PodmanSuccessorContainer(
            lease.config,
            limits=SuccessorContainerLimits(
                # Unused admission limits: this entrypoint never stages/loads.
                maximum_cache_entries=1,
                maximum_cache_bytes=1024,
                maximum_input_entries=1,
                maximum_input_bytes=1024,
                maximum_state_entries=1,
                maximum_state_bytes=1024,
                maximum_command_output_bytes=_MAX_COMMAND_OUTPUT_BYTES,
                command_timeout_seconds=_COMMAND_TIMEOUT_SECONDS,
                stop_timeout_seconds=_STOP_TIMEOUT_SECONDS,
            ),
            command_runner=stop_only_command,
        )
        status = await container.stop()
        lease.recheck()
        if status.phase == "running":
            raise ValueError("cleanup did not establish managed worker absence")
        return "absent" if status.phase == "absent" else "stopped"


async def _bounded_cleanup(config_path: Path) -> str:
    return await asyncio.wait_for(cleanup_successor(config_path), _TOTAL_TIMEOUT_SECONDS)


def run_cli(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    try:
        status = asyncio.run(_bounded_cleanup(args.config))
    except SuccessorCleanupBusy:
        print("successor_cleanup=busy", file=sys.stderr)
        return 3
    except (Exception, KeyboardInterrupt):
        print("successor_cleanup=unconfirmed", file=sys.stderr)
        return 1
    print("successor_cleanup=" + status)
    return 0


def main() -> None:
    raise SystemExit(run_cli())


if __name__ == "__main__":
    main()
