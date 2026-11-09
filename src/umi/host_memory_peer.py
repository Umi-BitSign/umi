"""Kernel lifetime witnesses for native joint execution policy /2.

The trusted host runner places a read OFD lock at the exact cgroup inode on
the SAME open description as its existing slot flock. Neither file contents
nor permissions change. An independent reader can query this lock on the
read-only slot. Closing the last descriptor drops both locks, including after
process death. The runner retains the cgroup directory descriptor until it
clears the witness, preventing inode reuse during that binding.

This protocol requires every /2 slot consumer to check for a leftover witness
before granting a new lease. It does not infer ownership from a PID, UID, path
name, memory usage or an independently persisted record. Model sandboxes must
not receive the host's native lease descriptors or slot directory.
"""

import ctypes
import fcntl
import os
import platform
import sys


class _Flock(ctypes.Structure):
    _fields_ = [
        ("type", ctypes.c_short),
        ("whence", ctypes.c_short),
        ("start", ctypes.c_longlong),
        ("length", ctypes.c_longlong),
        ("pid", ctypes.c_int),
    ]


def _command(descriptor, command, kind, start=0, length=0):
    # Supported Linux 64-bit hosts use off_t64. Refuse an unqualified ABI
    # instead of silently changing lock geometry on another platform.
    if (
        sys.platform != "linux"
        or platform.machine() not in {"x86_64", "aarch64"}
        or ctypes.sizeof(ctypes.c_void_p) != 8
        or ctypes.sizeof(_Flock) != 32
    ):
        raise ValueError("peer lease witnesses require a supported Linux 64-bit host")
    # Some supported standalone CPython builds omit the GNU-header constants.
    # These are Linux UAPI fcntl command numbers on both supported ABIs, not
    # inferred kernel versions. The real call still must succeed on this host.
    operation = {"F_OFD_GETLK": 36, "F_OFD_SETLK": 37}[command]
    if getattr(fcntl, command, operation) != operation:
        raise ValueError("kernel OFD lease witness ABI differs")
    raw = fcntl.fcntl(descriptor, operation, bytes(_Flock(kind, os.SEEK_SET, start, length, 0)))
    return _Flock.from_buffer_copy(raw)


def observed_inode(descriptor):
    """Query another open description; never acquire or transfer its lease."""
    row = _command(descriptor, "F_OFD_GETLK", fcntl.F_WRLCK)
    if row.type == fcntl.F_UNLCK:
        return None
    if (
        row.type != fcntl.F_RDLCK
        or row.whence != os.SEEK_SET
        or row.pid != -1
        or row.length != 1
        or not 0 < row.start < 2**63 - 1
    ):
        raise ValueError("native peer lease witness has unsupported kernel geometry")
    return row.start


def bind(descriptor, inode):
    if type(inode) is not int or not 0 < inode < 2**63 - 1:
        raise ValueError("native peer cgroup inode exceeds witness range")
    _command(descriptor, "F_OFD_SETLK", fcntl.F_RDLCK, inode, 1)


def clear(descriptor):
    _command(descriptor, "F_OFD_SETLK", fcntl.F_UNLCK)
