from __future__ import annotations

import pytest

from umi.backends import load_translator

MODEL_REVISION = "ab" * 32


async def async_translator(_video, _request) -> str:
    return "translation"


class AsyncCallableTranslator:
    model_revision = MODEL_REVISION

    def __init__(self) -> None:
        self.events: list[str] = []

    async def __call__(self, _video, _request) -> str:
        return "callable object translation"

    async def startup(self) -> None:
        self.events.append("startup")

    async def shutdown(self) -> None:
        self.events.append("shutdown")


class InvalidLifecycleTranslator:
    async def __call__(self, _video, _request) -> str:
        return "translation"

    def startup(self) -> None:
        return None


class InvalidRevisionTranslator:
    model_revision = "not-a-sha256"

    async def __call__(self, _video, _request) -> str:
        return "translation"


async_callable_translator = AsyncCallableTranslator()
invalid_lifecycle_translator = InvalidLifecycleTranslator()
invalid_revision_translator = InvalidRevisionTranslator()


def test_asynchronous_translator_is_the_safe_default() -> None:
    translator = load_translator("tests.test_backends:async_translator")
    assert translator.function is async_translator
    assert translator.asynchronous is True
    assert translator.model_revision is None
    assert translator.executor is None


@pytest.mark.asyncio
async def test_async_callable_object_exposes_identity_and_lifecycle() -> None:
    async_callable_translator.events.clear()
    translator = load_translator("tests.test_backends:async_callable_translator")

    assert translator.asynchronous is True
    assert translator.executor is None
    assert translator.model_revision == MODEL_REVISION
    assert await translator.translate(b"video", None) == "callable object translation"
    await translator.startup()
    await translator.shutdown()
    assert async_callable_translator.events == ["startup", "shutdown"]


def test_backend_lifecycle_hooks_must_be_asynchronous() -> None:
    with pytest.raises(ValueError, match="startup hook must be asynchronous"):
        load_translator("tests.test_backends:invalid_lifecycle_translator")


def test_backend_model_revision_must_be_a_canonical_digest() -> None:
    with pytest.raises(ValueError, match="backend model_revision"):
        load_translator("tests.test_backends:invalid_revision_translator")


def test_synchronous_translator_requires_explicit_unsafe_opt_in() -> None:
    with pytest.raises(ValueError, match="explicit unsafe opt-in"):
        load_translator("hashlib:sha256")

    translator = load_translator("hashlib:sha256", allow_synchronous=True)
    assert translator.asynchronous is False
    assert translator.executor is not None
    translator.executor.shutdown(wait=True)
