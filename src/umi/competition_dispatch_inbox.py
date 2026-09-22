"""Shared bounded directory inventory for dispatch and admission checks."""

import os

MAXIMUM_INBOX_FILES = 1024


def validate_inbox_capacity(maximum_files):
    if type(maximum_files) is not int or not 1 <= maximum_files <= 65536:
        raise ValueError("publication inbox capacity must be an integer from 1 to 65536")


def publication_names(fd, *, maximum_files=MAXIMUM_INBOX_FILES):
    """Count every entry, including temporary files, as the dispatcher does."""
    validate_inbox_capacity(maximum_files)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("publication inbox must be owned and private")
    names = []
    with os.scandir(fd) as entries:
        for entry in entries:
            if len(names) >= maximum_files:
                raise ValueError("publication inbox exceeds its file capacity")
            names.append(entry.name)
    return names
