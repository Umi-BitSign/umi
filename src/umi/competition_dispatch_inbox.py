"""Shared bounded directory inventory for dispatch and admission checks."""

import os

MAXIMUM_INBOX_FILES = 1024


def publication_names(fd):
    """Count every entry, including temporary files, as the dispatcher does."""
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("publication inbox must be owned and private")
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= MAXIMUM_INBOX_FILES:
                raise ValueError("publication inbox exceeds its file capacity")
            names.append(entry.name)
    return names
