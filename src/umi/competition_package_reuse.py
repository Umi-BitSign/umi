"""Process-local reuse of immutable package verification within one service.

No journal receipt, authorization, finality observation or transaction result is
retained here. Callers must read and hash the entire sealed package before lookup.
Restart drops the cache and requires a fresh complete verification.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from contextvars import ContextVar
from copy import deepcopy
from threading import RLock
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .competition_package import VerifiedCompetitionPackage


class PackageVerificationReuse:
    """Keep one private verified object; never expose it to callers for mutation."""

    def __init__(self, maximum_input_bytes: int = 512 * 1024**2):
        if type(maximum_input_bytes) is not int or maximum_input_bytes < 1:
            raise ValueError("package reuse requires a positive byte capacity")
        self.maximum_input_bytes = maximum_input_bytes
        self._pid = os.getpid()
        self._lock = RLock()
        self._key: tuple | None = None
        self._value: VerifiedCompetitionPackage | None = None

    def lookup(self, key: tuple) -> VerifiedCompetitionPackage | None:
        # A forked process must start with its own verification; do not take a
        # potentially inherited lock before rejecting that process identity.
        if os.getpid() != self._pid:
            return None
        with self._lock:
            return deepcopy(self._value) if key == self._key else None

    def remember(self, key: tuple, value: VerifiedCompetitionPackage, input_bytes: int) -> None:
        if os.getpid() != self._pid:
            return
        with self._lock:
            self._key, self._value = None, None
            if input_bytes <= self.maximum_input_bytes:
                private = deepcopy(value)
                self._key, self._value = key, private

    def clear(self) -> None:
        if os.getpid() != self._pid:
            return
        with self._lock:
            self._key, self._value = None, None


_REUSE: ContextVar[PackageVerificationReuse | None] = ContextVar(
    "competition_package_verification_reuse", default=None
)


def current_package_reuse() -> PackageVerificationReuse | None:
    return _REUSE.get()


@contextmanager
def package_verification_session(*, maximum_input_bytes: int = 512 * 1024**2):
    """Own a cache for this service scope, discarded on normal or failed exit."""
    reuse = PackageVerificationReuse(maximum_input_bytes)
    token = _REUSE.set(reuse)
    try:
        yield reuse
    finally:
        _REUSE.reset(token)
        reuse.clear()
