"""Independent lifetime guard for one native sandbox process (stdlib only).

The controller holds stdin open. EOF or any byte requests cancellation. The
guard also enforces a wall-clock deadline after controller death. It never
loads model code. RSS and scratch checks are sampled ceilings, not hard OS
allocation limits; the signed native profile must describe them as such.
"""

from __future__ import annotations

import argparse
import contextlib
import os
import selectors
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path


def scratch_usage(root: Path, *, maximum_bytes: int, maximum_entries: int = 4096) -> int:
    """Never follow model-created links, and bound work even for tiny-file floods."""
    total = 0
    entries = 0

    def walk(directory: int) -> None:
        nonlocal total, entries
        # scandir is lazy; listdir would allocate the complete attacker-owned directory.
        with os.scandir(directory) as children:
            for child in children:
                entries += 1
                if entries > maximum_entries:
                    raise ValueError("native scratch entry ceiling exceeded")
                try:
                    info = child.stat(follow_symlinks=False)
                except FileNotFoundError:
                    continue  # Compilers atomically replace temporary files.
                if stat.S_ISDIR(info.st_mode):
                    try:
                        nested = os.open(
                            child.name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=directory,
                        )
                    except FileNotFoundError:
                        continue
                    try:
                        walk(nested)
                    finally:
                        os.close(nested)
                elif stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
                    # Count link storage, never its target. Seatbelt checks
                    # resolved accesses; target bytes in writable roots are
                    # counted independently there.
                    total += info.st_size
                    if total > maximum_bytes:
                        raise ValueError("native scratch byte ceiling exceeded")
                elif not (stat.S_ISFIFO(info.st_mode) or stat.S_ISSOCK(info.st_mode)):
                    raise ValueError("native scratch contains a device or unknown file")

    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        walk(descriptor)
    finally:
        os.close(descriptor)
    return total


def rss_bytes(pid: int) -> int:
    result = subprocess.run(
        ("/bin/ps", "-o", "rss=", "-p", str(pid)),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env={"PATH": "/usr/bin:/bin", "LANG": "C"},
        timeout=2,
        check=False,
    )
    if result.returncode or not result.stdout.strip().isdigit() or len(result.stdout) > 64:
        raise RuntimeError("native process resource observation failed")
    return int(result.stdout.strip()) * 1024


def run_guard(
    command: tuple[str, ...],
    *,
    control_fd: int,
    deadline_ms: int,
    scratch: Path,
    rss_ceiling: int,
    scratch_ceiling: int,
    extra_scratch: tuple[Path, ...] = (),
) -> int:
    """Return the model exit code, 124 on deadline, 137 on a resource ceiling.

    125 denotes guard infrastructure failure; it must not be scored as a miner
    failure. A guard kill is scoped to its newly allocated child process group.
    The sandbox must prohibit forking and signaling other processes.
    """
    if (
        not command
        or not Path(command[0]).is_absolute()
        or type(deadline_ms) is not int
        or not 1 <= deadline_ms <= 3_600_000
        or not 128 * 1024**2 <= rss_ceiling <= 64 * 1024**3
        or not 1024**2 <= scratch_ceiling <= 4 * 1024**3
        or not scratch.is_absolute()
        or scratch.resolve(strict=True) != scratch
    ):
        raise ValueError("invalid native guard inputs")
    info = scratch.stat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
        raise ValueError("native guard scratch must be owner-private")
    if len(extra_scratch) > 1:
        raise ValueError("native guard allows at most one private compiler cache")
    for path in extra_scratch:
        if (
            not path.is_absolute()
            or path.resolve(strict=True) != path
            or path == scratch
            or path.is_relative_to(scratch)
            or scratch.is_relative_to(path)
        ):
            raise ValueError("native guard writable roots overlap or are aliased")
        metadata = path.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077
        ):
            raise ValueError("native guard compiler cache must be owner-private")
    selector = selectors.DefaultSelector()
    process = None
    deadline = time.monotonic() + deadline_ms / 1000
    try:
        selector.register(control_fd, selectors.EVENT_READ)
        # Already-disconnected controllers must not launch a model.
        if selector.select(0):
            return 125
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True
        )
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return 124
            code = process.poll()
            if code is not None:
                return code if code >= 0 else 128 - code
            if selector.select(min(0.2, remaining)):
                return 125
            try:
                usage = rss_bytes(process.pid)
                used = scratch_usage(scratch, maximum_bytes=scratch_ceiling)
                for path in extra_scratch:
                    used += scratch_usage(path, maximum_bytes=scratch_ceiling - used)
                if usage > rss_ceiling:
                    print(f"native_guard_rss_limit: {usage}", file=sys.stderr, flush=True)
                    return 137
            except ValueError as error:
                print(f"native_guard_scratch_limit: {error}", file=sys.stderr, flush=True)
                return 137
            except OSError as error:
                print(
                    f"native_guard_scratch_observation: {type(error).__name__}",
                    file=sys.stderr,
                    flush=True,
                )
                return 137
            except (RuntimeError, subprocess.TimeoutExpired):
                # ps can lose a race with a normally exiting child.
                code = process.poll()
                return (code if code >= 0 else 128 - code) if code is not None else 125
    finally:
        selector.close()
        if process is not None:
            # poll may already have reaped the leader. With forking prohibited,
            # no descendant can survive a reaped leader; do not target a reused PID.
            if process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=5)


def main() -> int:
    def terminate(_number, _frame):
        raise SystemExit(125)

    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deadline-ms", type=int, required=True)
    parser.add_argument("--rss-ceiling", type=int, required=True)
    parser.add_argument("--scratch-ceiling", type=int, required=True)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--extra-scratch", type=Path, action="append", default=[])
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    try:
        return run_guard(
            tuple(command),
            control_fd=sys.stdin.fileno(),
            deadline_ms=args.deadline_ms,
            scratch=args.scratch,
            rss_ceiling=args.rss_ceiling,
            scratch_ceiling=args.scratch_ceiling,
            extra_scratch=tuple(args.extra_scratch),
        )
    except Exception:
        return 125


if __name__ == "__main__":
    raise SystemExit(main())
