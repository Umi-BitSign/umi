"""Reserved diagnostic coverage marker, independent of the bounded event DB."""

import hashlib
import json
import os
import time

HEALTH_BYTES = 4096


def new_health(*, legacy=False):
    return {
        "schema": "umi-forecast-accounting-health/1",
        "coverage_complete": not legacy,
        "session_open": False,
        "gap_count": int(legacy),
        "blocked_capacity_bytes": None,
        "first_gap": None,
        "last_gap": {"reason": "legacy_capacity_history_unknown"} if legacy else None,
    }


def read_health(path):
    if path.is_symlink() or path.stat().st_size != HEALTH_BYTES:
        raise ValueError("forecast accounting coverage marker requires repair")
    raw = path.read_bytes()
    checksum, body = raw[:64], raw[65:].rstrip(b" ")
    if raw[64:65] != b" " or hashlib.sha256(body).hexdigest().encode() != checksum:
        raise ValueError("forecast accounting coverage marker is damaged")
    value = json.loads(body)
    if value["schema"] != "umi-forecast-accounting-health/1":
        raise ValueError("unsupported forecast accounting coverage marker")
    return value


def write_health(path, value):
    body = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    raw = hashlib.sha256(body).hexdigest().encode() + b" " + body
    if len(raw) > HEALTH_BYTES:
        raise ValueError("forecast accounting coverage marker exceeds reserved space")
    # This fixed reserved allocation can be updated after the SQLite budget is
    # exhausted. Torn or externally changed markers require explicit repair;
    # reopening never silently falls back to a formerly healthy state.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        written = os.write(fd, raw.ljust(HEALTH_BYTES, b" "))
        if written != HEALTH_BYTES:
            raise OSError("forecast coverage marker write was incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def record_gap(health, *, reason, head, capacity_bytes=None, snapshot=None):
    gap = {
        "observed_unix_ms": time.time_ns() // 1_000_000,
        "reason": reason,
        "last_retained_head": list(head),
    }
    if snapshot is not None:
        gap["snapshot_sha256"] = snapshot["sha256"]
        gap["snapshot_head"] = snapshot["head"]
    return {
        **health,
        "coverage_complete": False,
        "gap_count": health["gap_count"] + 1,
        "first_gap": health["first_gap"] or gap,
        "last_gap": gap,
        "blocked_capacity_bytes": capacity_bytes or health["blocked_capacity_bytes"],
    }


def _preserve_marker(path, *, damaged_sha256):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > HEALTH_BYTES:
        raise ValueError("forecast repair marker is not bounded and regular")
    raw = path.read_bytes()
    checksum = hashlib.sha256(raw).hexdigest()
    if checksum != damaged_sha256:
        raise ValueError("forecast repair requires pinned damaged marker identity")
    preserved = path.with_name(path.name + ".damaged-" + checksum)
    if preserved.exists() or preserved.is_symlink():
        if (
            preserved.is_symlink()
            or not preserved.is_file()
            or preserved.stat().st_size != len(raw)
            or preserved.read_bytes() != raw
        ):
            raise ValueError("forecast repair marker preservation identity conflicts")
    else:
        fd = os.open(preserved, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        try:
            if os.write(fd, raw) != len(raw):
                raise OSError("forecast repair marker preservation write was incomplete")
            os.fsync(fd)
        finally:
            os.close(fd)


def health_for_restore(path, *, damaged_sha256=None):
    """Repair needs pinned damaged marker bytes; retain them before replacement."""
    if not path.exists():
        if path.is_symlink() or damaged_sha256 is not None:
            raise ValueError("forecast coverage repair original identity changed")
        return new_health(legacy=True), True
    try:
        return read_health(path), False
    except (OSError, ValueError, KeyError, TypeError):
        _preserve_marker(path, damaged_sha256=damaged_sha256)
        return new_health(legacy=True), True


def initialization_for_restore(path, *, damaged_sha256=None):
    if not path.exists():
        if path.is_symlink() or damaged_sha256 is not None:
            raise ValueError("forecast initialization repair original identity changed")
        return True
    if not path.is_symlink() and path.stat().st_size == 26:
        raw = path.read_bytes()
        if raw in {b"umi-forecast-accounting/1\n", b"umi-forecast-accounting/2\n"}:
            return raw != b"umi-forecast-accounting/2\n"
    _preserve_marker(path, damaged_sha256=damaged_sha256)
    return True


def write_initialization(path):
    raw = b"umi-forecast-accounting/2\n"
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    try:
        if os.write(fd, raw) != len(raw):
            raise OSError("forecast initialization repair write was incomplete")
        os.fsync(fd)
    finally:
        os.close(fd)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)
