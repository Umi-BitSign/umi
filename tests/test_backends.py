from __future__ import annotations

import pytest

from umi.backends import load_translator


async def async_translator(_video, _request) -> str:
    return "translation"


def test_asynchronous_translator_is_the_safe_default() -> None:
    translator = load_translator("tests.test_backends:async_translator")
    assert translator.function is async_translator
    assert translator.executor is None


def test_synchronous_translator_requires_explicit_unsafe_opt_in() -> None:
    with pytest.raises(ValueError, match="explicit unsafe opt-in"):
        load_translator("hashlib:sha256")

    translator = load_translator("hashlib:sha256", allow_synchronous=True)
    assert translator.executor is not None
    translator.executor.shutdown(wait=True)
