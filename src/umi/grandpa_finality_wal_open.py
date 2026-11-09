"""Observe Linux WAL attribute changes during the native SQLite open only."""

import ctypes
import os
import struct
from contextlib import contextmanager


@contextmanager
def wal_open_attributes(path, identity):
    """Yield a one-shot check; an unsupported kernel grants no ctime exception.

    SQLite's root-only fchown changes WAL ctime even when ownership is unchanged.
    Watch the pinned inode before opening SQLite. Attribute-only events can
    explain that change; writes, replacement and lost events cannot.
    """
    library = ctypes.CDLL(None, use_errno=True)
    initialize = getattr(library, "inotify_init1", None)
    watch = getattr(library, "inotify_add_watch", None)
    if identity is None or initialize is None or watch is None:
        yield lambda: False
        return
    initialize.argtypes, initialize.restype = [ctypes.c_int], ctypes.c_int
    watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
    watch.restype = ctypes.c_int
    descriptor = initialize(os.O_CLOEXEC | os.O_NONBLOCK)
    if descriptor < 0:
        raise OSError(ctypes.get_errno(), "WAL open observation unavailable")
    pinned = None
    try:
        pinned = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(pinned)
        if (info.st_dev, info.st_ino) != tuple(map(int, identity[:2])):
            raise ValueError("wal_open_inode_changed")
        # MODIFY, ATTRIB, DELETE_SELF, MOVE_SELF and UNMOUNT. Overflow and
        # ignored-watch events are also rejected if the kernel reports them.
        selected = watch(descriptor, os.fsencode(f"/proc/self/fd/{pinned}"), 0x2C06)
        if selected < 0:
            raise OSError(ctypes.get_errno(), "WAL open watch unavailable")
        consumed = False

        def attribute_only():
            nonlocal consumed
            if consumed:
                raise ValueError("wal_open_observation_already_consumed")
            consumed = True
            attribute = False
            count = 0
            while True:
                try:
                    raw = os.read(descriptor, 65536)
                except BlockingIOError:
                    return attribute
                if not raw:
                    raise ValueError("wal_open_observation_closed")
                offset = 0
                while offset < len(raw):
                    if len(raw) - offset < 16:
                        raise ValueError("wal_open_observation_truncated")
                    owner, mask, _cookie, length = struct.unpack_from("iIII", raw, offset)
                    offset += 16 + length
                    count += 1
                    if (
                        owner != selected
                        or mask != 0x4
                        or length
                        or offset > len(raw)
                        or count > 4096
                    ):
                        raise ValueError("wal_changed_during_native_open")
                    attribute = True

        yield attribute_only
    finally:
        if pinned is not None:
            os.close(pinned)
        os.close(descriptor)
