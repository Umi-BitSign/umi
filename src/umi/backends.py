"""Translation backend boundary.

The protocol does not prescribe a model.  A miner supplies a trusted Python
callable at startup; UMI never substitutes a canned hypothesis when it fails.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import re
from collections.abc import Awaitable, Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Any, Protocol, TypeAlias, cast

from .protocol import TranslationRequest

TranslationResult: TypeAlias = str | Awaitable[str]
TranslationCallable: TypeAlias = Callable[[bytes, TranslationRequest], TranslationResult]
LifecycleCallable: TypeAlias = Callable[[], Awaitable[Any]]

_MODEL_REVISION_RE = re.compile(r"[0-9a-f]{64}")


class Translator(Protocol):
    async def translate(self, video: bytes, request: TranslationRequest) -> str: ...


def is_async_callable(function: object) -> bool:
    """Return whether a function or callable object's invocation is asynchronous."""

    return inspect.iscoroutinefunction(function) or inspect.iscoroutinefunction(
        type(function).__call__
    )


def backend_model_revision(backend: object) -> str | None:
    """Read and validate the optional model identity exposed by a backend."""

    revision = getattr(backend, "model_revision", None)
    if revision is None:
        return None
    if not isinstance(revision, str) or _MODEL_REVISION_RE.fullmatch(revision) is None:
        raise ValueError("backend model_revision must be a lowercase SHA-256 hex digest")
    return revision


def _optional_async_hook(backend: object, name: str) -> LifecycleCallable | None:
    hook = getattr(backend, name, None)
    if hook is None:
        return None
    if not callable(hook) or not is_async_callable(hook):
        raise ValueError(f"translation backend {name} hook must be asynchronous")
    return cast(LifecycleCallable, hook)


@dataclass(frozen=True)
class PythonPluginTranslator:
    """Adapter for a configured ``module:callable`` translation backend."""

    function: TranslationCallable
    asynchronous: bool
    model_revision: str | None = None
    startup_hook: LifecycleCallable | None = None
    shutdown_hook: LifecycleCallable | None = None
    executor: ThreadPoolExecutor | None = None

    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        if self.asynchronous:
            result = self.function(video, request)
        else:
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(self.executor, self.function, video, request)
        if inspect.isawaitable(result):
            result = await result
        if not isinstance(result, str):
            raise TypeError("translation backend must return str")
        return result

    async def startup(self) -> None:
        if self.startup_hook is not None:
            await self.startup_hook()

    async def shutdown(self) -> None:
        try:
            if self.shutdown_hook is not None:
                await self.shutdown_hook()
        finally:
            if self.executor is not None:
                self.executor.shutdown(wait=False, cancel_futures=True)


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
    asynchronous = is_async_callable(function)
    if not asynchronous and not allow_synchronous:
        raise ValueError(
            "synchronous translators require explicit unsafe opt-in because Python cannot "
            "terminate a hung worker thread"
        )
    model_revision = backend_model_revision(function)
    startup_hook = _optional_async_hook(function, "startup")
    shutdown_hook = _optional_async_hook(function, "shutdown")
    executor = (
        None
        if asynchronous
        else ThreadPoolExecutor(
            max_workers=maximum_concurrency,
            thread_name_prefix="umi-translator",
        )
    )
    return PythonPluginTranslator(
        function=cast(TranslationCallable, function),
        asynchronous=asynchronous,
        model_revision=model_revision,
        startup_hook=startup_hook,
        shutdown_hook=shutdown_hook,
        executor=executor,
    )
