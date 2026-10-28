"""Only exact successfully decoded reservation bytes can borrow static facts."""

from collections import OrderedDict

import pytest

from umi import competition_round_reservation_reuse as reuse


@pytest.fixture(autouse=True)
def isolated_reuse(monkeypatch):
    monkeypatch.setattr(reuse, "_entries", OrderedDict())
    monkeypatch.setattr(reuse, "_bytes", 0)


def document(raw):
    return {"kind": "vote", "key": raw.decode(), "maximum_bytes": 1, "value_sha256": None}


def test_decoder_returns_owned_mapping_and_reuses_exact_success(monkeypatch):
    calls = []

    def decode(raw):
        calls.append(raw)
        return document(raw)

    assert reuse.decoded_reservation(b"one", decode) == document(b"one")
    result = reuse.decoded_reservation(b"one", decode)
    result["maximum_bytes"] = 999
    assert reuse.decoded_reservation(b"one", decode) == document(b"one")
    assert calls == [b"one"]
    assert reuse.decoded_reservation(b"two", decode) == document(b"two")
    assert calls == [b"one", b"two"]


def test_failure_is_never_cached_and_fork_revalidates(monkeypatch):
    def fails(raw):
        raise ValueError("invalid canonical reservation")

    for _ in range(2):
        with pytest.raises(ValueError, match="invalid canonical"):
            reuse.decoded_reservation(b"one", fails)
    assert not reuse._entries
    reuse.decoded_reservation(b"one", document)
    monkeypatch.setattr(reuse, "_pid", -1)
    with pytest.raises(ValueError, match="invalid canonical"):
        reuse.decoded_reservation(b"one", fails)
    assert not reuse._entries and reuse._bytes == 0


@pytest.mark.parametrize("budget", ["bytes", "entries"])
def test_decode_reuse_is_bounded_and_eviction_revalidates(monkeypatch, budget):
    monkeypatch.setattr(reuse, "_MAXIMUM_BYTES", 270 if budget == "bytes" else 1024)
    monkeypatch.setattr(reuse, "_MAXIMUM_ENTRIES", 1 if budget == "entries" else 10)
    reuse.decoded_reservation(b"one", document)
    reuse.decoded_reservation(b"two", document)
    assert len(reuse._entries) == 1 and reuse._bytes <= reuse._MAXIMUM_BYTES
    calls = []

    def decode(raw):
        calls.append(raw)
        return document(raw)

    reuse.decoded_reservation(b"one", decode)
    assert calls == [b"one"]


def test_concurrent_first_decode_has_one_owner():
    from concurrent.futures import ThreadPoolExecutor
    from threading import Event

    entered, release = Event(), Event()
    calls = []

    def decode(raw):
        calls.append(raw)
        entered.set()
        assert release.wait(10)
        return document(raw)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reuse.decoded_reservation, b"one", decode)
        try:
            assert entered.wait(10)
            second = pool.submit(reuse.decoded_reservation, b"one", decode)
        finally:
            release.set()
        assert first.result(timeout=10) == second.result(timeout=10) == document(b"one")
    assert calls == [b"one"]
