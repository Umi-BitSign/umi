"""Read-only ownership checks before repairing an empty rootless namespace."""

from __future__ import annotations

import os
from pathlib import Path

from .competition_worker import _open_private_regular_file


def require_supervisor_process_owner(state_root: Path) -> None:
    """Require this process's original flock; never acquire or replace it.

    The supervisor serializes container operations while holding this lease.
    Merely seeing another process's locked file does not authorize migration.
    Linux fdinfo supplies the owner of the actual held open-file description.
    """
    path = state_root / "supervisor-process.lock"
    named = _open_private_regular_file(path, "original supervisor process lock")
    try:
        identity = os.fstat(named)
        wanted = (
            "FLOCK",
            "ADVISORY",
            "WRITE",
            str(os.getpid()),
            f"{os.major(identity.st_dev):02x}:{os.minor(identity.st_dev):02x}:{identity.st_ino}",
            "0",
            "EOF",
        )
        with os.scandir("/proc/self/fd") as entries:
            for count, entry in enumerate(entries):
                if count >= 65536:
                    raise ValueError("supervisor descriptor inspection exceeds its bound")
                if not entry.name.isdecimal() or int(entry.name) == named:
                    continue
                descriptor = int(entry.name)
                try:
                    held = os.fstat(descriptor)
                except OSError:
                    continue  # An unrelated asynchronously closed descriptor.
                if (held.st_dev, held.st_ino) != (identity.st_dev, identity.st_ino):
                    continue
                with open(f"/proc/self/fdinfo/{descriptor}", "rb") as stream:
                    payload = stream.read(65537)
                if len(payload) > 65536:
                    raise ValueError("supervisor lock metadata exceeds its bound")
                for line in payload.decode("ascii").splitlines():
                    parts = line.split()
                    if len(parts) == 9 and parts[0] == "lock:" and tuple(parts[2:]) == wanted:
                        current = os.stat(path, follow_symlinks=False)
                        if (current.st_dev, current.st_ino) != (identity.st_dev, identity.st_ino):
                            raise ValueError("supervisor process lock inode changed")
                        return
    finally:
        os.close(named)
    raise ValueError("Podman namespace repair requires this supervisor process's original lock")
