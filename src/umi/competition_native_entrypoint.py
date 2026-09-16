"""Trusted prelude executed inside Seatbelt, before a declared model entrypoint.

This file intentionally uses only the standard library. It is launched by its
absolute file path, not through the evaluator package or its dependencies.
"""

from __future__ import annotations

import ctypes
import multiprocessing
import os
import resource
import runpy
import sys
from pathlib import Path


def main() -> None:
    if sys.platform != "darwin" or sys.version_info[:2] != (3, 10):
        raise RuntimeError("native evaluation requires the reviewed macOS Python ABI")
    if len(sys.argv) != 6:
        raise ValueError("native evaluator prelude arguments differ")
    entrypoint, video, overlay, suffix, scratch_bytes = sys.argv[1:]
    if not suffix.startswith("org.umi.evaluation-") or any(
        char not in "abcdefghijklmnopqrstuvwxyz0123456789.-" for char in suffix
    ):
        raise ValueError("native evaluator cache identity is invalid")
    limit = int(scratch_bytes)
    if not 1024**2 <= limit <= 4 * 1024**3:
        raise ValueError("native evaluator scratch ceiling is invalid")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
    resource.setrlimit(resource.RLIMIT_FSIZE, (limit, limit))
    # macOS's spawn-context Lock starts a resource-tracker child on import in
    # Fairseq and tqdm. The fork context unlinks semaphores in-process. Actual
    # process creation remains prohibited by Seatbelt for all models.
    multiprocessing.set_start_method("fork", force=True)
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    library._set_user_dir_suffix.argtypes = [ctypes.c_char_p]
    if library._set_user_dir_suffix(suffix.encode()) != 1:
        raise RuntimeError("native evaluator private Metal cache setup failed")
    if suffix not in os.confstr(65538):
        raise RuntimeError("native evaluator Metal cache binding differs")
    sys.path[:0] = [str(Path(entrypoint).parent), overlay]
    sys.argv = [entrypoint, video]
    runpy.run_path(entrypoint, run_name="__main__")


if __name__ == "__main__":
    main()
