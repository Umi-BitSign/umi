"""Host-derived target names for signed platform-specific runtime artifacts."""

from __future__ import annotations

import platform
from typing import Literal

ScoringRuntimeTarget = Literal[
    "aarch64-apple-darwin",
    "x86_64-apple-darwin",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
]


def scoring_runtime_target() -> ScoringRuntimeTarget:
    system, machine = platform.system(), platform.machine().lower()
    architecture = {"arm64": "aarch64", "aarch64": "aarch64", "x86_64": "x86_64"}.get(machine)
    if architecture is not None:
        if system == "Darwin":
            return "aarch64-apple-darwin" if architecture == "aarch64" else "x86_64-apple-darwin"
        if system == "Linux" and platform.libc_ver()[0] == "glibc":
            return (
                "aarch64-unknown-linux-gnu"
                if architecture == "aarch64"
                else "x86_64-unknown-linux-gnu"
            )
    raise RuntimeError("scoring runtime target is unsupported")
