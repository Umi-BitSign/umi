"""Translation backend boundary.

The protocol does not prescribe a model.  A miner supplies a trusted Python
callable at startup; UMI never substitutes a canned hypothesis when it fails.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Protocol, TypeAlias, cast

from .protocol import TranslationRequest

TranslationResult: TypeAlias = str | Awaitable[str]
TranslationCallable: TypeAlias = Callable[[bytes, TranslationRequest], TranslationResult]


class Translator(Protocol):
    async def translate(self, video: bytes, request: TranslationRequest) -> str: ...


@dataclass(frozen=True)
class PythonPluginTranslator:
    """Adapter for a configured ``module:callable`` translation backend."""

    function: TranslationCallable
    executor: ThreadPoolExecutor | None = None

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        if inspect.iscoroutinefunction(self.function):
            result = self.function(video, request)
        else:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(self.executor, self.function, video, request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, str):
            raise TypeError("translation backend must return str")
        return result


def load_translator(
    spec: str,
    *,
    maximum_concurrency: int = 1,
    allow_synchronous: bool = False,
) -> PythonPluginTranslator:
    """Load a trusted backend named ``module:callable``.

    The callable receives verified video bytes and the validated request and must
    return an English string. Synchronous callables require explicit opt-in.
    """

    if isinstance(maximum_concurrency, bool) or maximum_concurrency <= 0:
        raise ValueError("maximum_concurrency must be a positive integer")
    if not isinstance(allow_synchronous, bool):
        raise TypeError("allow_synchronous must be boolean")
    module_name, separator, attribute = spec.partition(":")
    if not separator or not module_name or not attribute:
        raise ValueError("translator must be named as 'module:callable'")
    function = getattr(importlib.import_module(module_name), attribute, None)
    if not callable(function):
        raise ValueError(f"translator {spec!r} is not callable")
    if not inspect.iscoroutinefunction(function) and not allow_synchronous:
        raise ValueError(
            "synchronous translators require explicit unsafe opt-in because Python cannot "
            "terminate a hung worker thread"
        )
    executor = (
        None
        if inspect.iscoroutinefunction(function)
        else ThreadPoolExecutor(
            max_workers=maximum_concurrency,
            thread_name_prefix="umi-translator",
        )
    )
    return PythonPluginTranslator(cast(TranslationCallable, function), executor)
