"""Seatbelt profile construction for the experimental macOS evaluator.

File/network/process restrictions do not impose memory, storage or wall-clock
limits. A separate supervisor must enforce those before this becomes a runner.
No command in this module launches or imports model code.
"""

from __future__ import annotations

import json
from pathlib import Path


def _quoted(path: Path) -> str:
    if not path.is_absolute() or any(ord(char) < 32 for char in str(path)):
        raise ValueError("sandbox paths must be absolute and contain no control characters")
    if ".." in path.parts:
        raise ValueError("sandbox paths must not contain parent traversal")
    return json.dumps(str(path), ensure_ascii=True)


def native_profile(
    *,
    python: Path,
    readonly: tuple[Path, ...],
    readable_files: tuple[Path, ...],
    scratch: Path,
    metal_cache: Path,
) -> str:
    """Build a deny-by-default profile for a single non-forking model process.

    Callers must independently verify symlink-free roots and immutable files.
    Read-only roots must contain only the model and its reviewed dependencies,
    never an entire home directory or evaluator checkout with private inputs.
    """
    if not readonly or len(set(readonly)) != len(readonly):
        raise ValueError("sandbox needs distinct read-only dependency roots")
    paths = (*readonly, *readable_files, python, scratch, metal_cache)
    for path in paths:
        _quoted(path)
        if path in (Path("/"), Path("/Users"), Path("/Volumes"), Path("/private")):
            raise ValueError("sandbox root is too broad")
    roots = (*readonly, scratch, metal_cache)
    if any(
        a == b or a.is_relative_to(b) or b.is_relative_to(a)
        for index, a in enumerate(roots)
        for b in roots[index + 1 :]
    ):
        raise ValueError("sandbox read-only and writable roots must be disjoint")
    if any(
        path in (scratch, metal_cache)
        or path.is_relative_to(scratch)
        or path.is_relative_to(metal_cache)
        for path in (*readable_files, python)
    ):
        raise ValueError("sandbox executable or manifest is writable")
    if not any(python.is_relative_to(root) for root in readonly):
        raise ValueError("sandbox interpreter must be inside a reviewed read-only root")
    readable = "\n ".join(
        [f"(subpath {_quoted(root)})" for root in readonly]
        + [f"(literal {_quoted(path)})" for path in readable_files]
        + [f"(subpath {_quoted(scratch)})", f"(subpath {_quoted(metal_cache)})"]
    )
    extensions = "\n".join(
        "(allow file-issue-extension (require-all "
        '(extension-class "com.apple.app-sandbox.read-write") '
        f"(subpath {_quoted(metal_cache / name)})))"
        for name in ("com.apple.metalfe", "com.apple.gpuarchiver")
    )
    return f"""(version 1)
(deny default)
(allow process-exec)
(allow process-info* (target self))
(allow signal (target self))
(allow sysctl-read mach-lookup iokit-open)
(allow ipc-posix-shm ipc-posix-sem)
(allow file-read-metadata)
(allow file-read* file-map-executable
 (literal "/")
 (subpath "/System") (subpath "/usr/lib") (subpath "/usr/share")
 (subpath "/Library/Apple") (subpath "/Library/Preferences")
 (subpath "/private/var/db/dyld") (subpath "/private/var/db/timezone")
 (subpath "/private/preboot/Cryptexes")
 (literal "/dev/null") (literal "/dev/random") (literal "/dev/urandom")
 {readable})
(allow file-write* (subpath {_quoted(scratch)}) (subpath {_quoted(metal_cache)})
 (literal "/dev/null"))
{extensions}
"""
