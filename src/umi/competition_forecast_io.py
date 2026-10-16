"""Bounded snapshot hashing and copying, independent of payload caches."""

import hashlib
import os
import stat

CHUNK_BYTES = 64 * 1024


def stream_file(path, *, maximum_bytes, destination=None, sync=False):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    output = None
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or not 0 < before.st_size <= maximum_bytes:
            raise ValueError("forecast snapshot file is not bounded and regular")
        if destination is not None:
            output = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        checksum, total = hashlib.sha256(), 0
        while True:
            data = os.read(fd, CHUNK_BYTES)
            if not data:
                break
            total += len(data)
            if total > maximum_bytes:
                raise ValueError("forecast snapshot grew beyond its selected bound")
            checksum.update(data)
            if output is not None:
                view = memoryview(data)
                while view:
                    written = os.write(output, view)
                    if not written:
                        raise OSError("forecast snapshot copy made no write progress")
                    view = view[written:]
        if output is not None:
            os.fsync(output)
        if sync:
            os.fsync(fd)
        after = os.fstat(fd)
        current = path.lstat()
        if (
            (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
            != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
            or (before.st_dev, before.st_ino) != (current.st_dev, current.st_ino)
            or total != before.st_size
        ):
            raise ValueError("forecast snapshot identity changed during bounded transfer")
        return checksum.hexdigest(), total
    finally:
        if output is not None:
            os.close(output)
        os.close(fd)
