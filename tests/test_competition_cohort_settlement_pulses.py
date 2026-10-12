"""Native Quicknet/BLS, private-file durability and owned-worker boundaries."""

import asyncio
import hashlib
import os
import stat
import threading

import httpx
import pytest

from umi import competition_cohort_settlement_pulses as module
from umi.competition_cohort_settlement_pulses import SettlementPulseSource
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.concurrency import run_owned_thread
from umi.drand import DrandPulse, DrandVerificationError, QuicknetClient
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_drand import ROUND, info_record, json_response, pulse_record


def client_for(handler):
    return QuicknetClient(transport=httpx.MockTransport(handler))


def test_native_fetch_retains_exact_original_and_restart_needs_no_network(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        return json_response(
            info_record() if request.url.path.endswith("/info") else pulse_record()
        )

    source = SettlementPulseSource(tmp_path, client=client_for(handler))
    value = source(ROUND)
    path = tmp_path / (str(ROUND) + ".json")
    original = path.read_bytes()
    metadata = path.stat()
    assert original == canonical_json_bytes(RetainedRevealPulse(**pulse_record()))
    assert value.verified() == DrandPulse(**pulse_record())
    assert metadata.st_uid == os.getuid() and stat.S_IMODE(metadata.st_mode) == 0o600
    assert {r.url.path.rsplit("/", 1)[1] for r in calls} == {"info", str(ROUND)}
    assert all(
        r.extensions["timeout"] == dict.fromkeys(("connect", "read", "write", "pool"), 15.0)
        for r in calls
    )

    def offline(request):
        raise AssertionError("retained original must not use network")

    restarted = SettlementPulseSource(tmp_path, client=client_for(offline))
    assert restarted(ROUND) == value
    assert path.read_bytes() == original and path.stat().st_ino == metadata.st_ino


@pytest.mark.parametrize("fault", ["round", "signature", "randomness", "chain", "http", "timeout"])
def test_invalid_or_unavailable_pulse_remains_retryable_without_publication(tmp_path, fault):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        if fault == "http":
            return httpx.Response(503)
        if fault == "timeout":
            raise httpx.ReadTimeout("synthetic stalled endpoint")
        if request.url.path.endswith("/info"):
            info = info_record()
            if fault == "chain":
                info["hash"] = "00" * 32
            return json_response(info)
        value = pulse_record()
        if fault == "round":
            value["round"] += 1
        if fault == "signature":
            value["signature"] = "00" * 48
            value["randomness"] = hashlib.sha256(bytes(48)).hexdigest()
        if fault == "randomness":
            value["randomness"] = "00" * 32
        return json_response(value)

    with pytest.raises(DrandVerificationError):
        SettlementPulseSource(tmp_path, client=client_for(handler))(ROUND)
    assert len(calls) == 2  # One native /info + exact-round attempt, no inner retry loop.
    assert not list(tmp_path.glob("*.json"))


@pytest.mark.parametrize("damage", ["round", "signature", "noncanonical", "mode", "symlink"])
def test_bad_retained_file_is_never_overwritten_or_replaced_from_network(tmp_path, damage):
    path = tmp_path / (str(ROUND) + ".json")
    value = pulse_record()
    if damage == "round":
        value["round"] += 1
    if damage == "signature":
        value["signature"] = "00" * 48
        value["randomness"] = hashlib.sha256(bytes(48)).hexdigest()
    publish_private_model(path, RetainedRevealPulse(**value))
    if damage == "noncanonical":
        path.write_bytes(path.read_bytes() + b"\n")
    if damage == "mode":
        path.chmod(0o644)
    if damage == "symlink":
        target = tmp_path / "target.json"
        path.rename(target)
        path.symlink_to(target)
    original = path.read_bytes()

    def forbidden(request):
        raise AssertionError("invalid existing inputs must not trigger network")

    with pytest.raises((ValueError, DrandVerificationError)):
        SettlementPulseSource(tmp_path, client=client_for(forbidden))(ROUND)
    assert path.read_bytes() == original


def test_conflict_arriving_during_network_is_not_overwritten(tmp_path):
    path = tmp_path / (str(ROUND) + ".json")
    conflicting = RetainedRevealPulse(**{**pulse_record(), "round": ROUND + 1})

    def handler(request):
        if request.url.path.endswith("/info"):
            return json_response(info_record())
        publish_private_model(path, conflicting)
        return json_response(pulse_record())

    with pytest.raises(ValueError, match="different bytes"):
        SettlementPulseSource(tmp_path, client=client_for(handler))(ROUND)
    assert path.read_bytes() == canonical_json_bytes(conflicting)


def test_publication_acknowledgement_loss_retries_same_bytes_without_refetch(tmp_path, monkeypatch):
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return json_response(
            info_record() if request.url.path.endswith("/info") else pulse_record()
        )

    publish = module.publish_private_model

    def lost_ack(*args, **kwargs):
        publish(*args, **kwargs)
        raise OSError("publication acknowledgement lost")

    client = client_for(handler)
    with monkeypatch.context() as patch:
        patch.setattr(module, "publish_private_model", lost_ack)
        with pytest.raises(OSError):
            SettlementPulseSource(tmp_path, client=client)(ROUND)
    value = SettlementPulseSource(tmp_path, client=client)(ROUND)
    assert value == RetainedRevealPulse(**pulse_record()) and len(calls) == 2


@pytest.mark.parametrize("number", [True, 0, -1, 2**64, float(ROUND), "1000000"])
def test_invalid_round_cannot_choose_path_or_network(tmp_path, number):
    with pytest.raises(ValueError, match="exact original round"):
        SettlementPulseSource(tmp_path)(number)
    assert list(tmp_path.iterdir()) == []


async def test_owned_cancellation_drains_fetch_without_publication_or_next_round(tmp_path):
    entered, closing = threading.Event(), threading.Event()
    release, finished = threading.Event(), threading.Event()
    calls = []

    class Client:
        async def fetch(self, number):
            calls.append(number)
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                closing.set()
                while not release.is_set():
                    await asyncio.sleep(0.005)
                finished.set()

    source = SettlementPulseSource(tmp_path, client=Client())

    def assemble():
        source(ROUND)
        source(ROUND + 1)

    work = asyncio.create_task(run_owned_thread(assemble, on_cancel=source.cancel))
    try:
        while not entered.is_set():
            await asyncio.sleep(0.005)
        work.cancel()

        async def wait_for_close():
            while not closing.is_set():
                await asyncio.sleep(0.005)

        await asyncio.wait_for(wait_for_close(), timeout=5)
        work.cancel()
        await asyncio.sleep(0)
        assert not work.done()
    finally:
        release.set()
    with pytest.raises(asyncio.CancelledError):
        await work
    assert finished.is_set() and calls == [ROUND]
    assert not list(tmp_path.glob("*.json"))
    with pytest.raises(InterruptedError):
        source(ROUND)


async def test_cancellation_interrupts_native_trickling_quicknet_response(tmp_path):
    entered, closed = threading.Event(), threading.Event()

    class TricklingStream(httpx.AsyncByteStream):
        async def __aiter__(self):
            entered.set()
            while True:
                yield b" "  # Each read is active; HTTPX's idle timer cannot end this promptly.
                await asyncio.sleep(0.05)

        async def aclose(self):
            closed.set()

    def handler(request):
        if request.url.path.endswith("/info"):
            return json_response(info_record())
        return httpx.Response(200, stream=TricklingStream())

    source = SettlementPulseSource(tmp_path, client=client_for(handler))
    work = asyncio.create_task(run_owned_thread(source, ROUND, on_cancel=source.cancel))
    try:
        while not entered.is_set():
            await asyncio.sleep(0.005)
        work.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(work, timeout=5)
    finally:
        source.cancel()
    assert closed.is_set() and not list(tmp_path.glob("*.json"))
