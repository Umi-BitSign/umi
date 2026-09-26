"""Lost delivery must recover sealed bytes without reopening inference."""

from __future__ import annotations

import asyncio
import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace

import bittensor as bt
import httpx
import pytest
from fastapi import FastAPI

from umi.auth import HotkeyAuth, RequestAuthenticator
from umi.config import Limits
from umi.miner import RESPONSE_RECOVERY_PATH, TRANSLATE_PATH, create_app
from umi.miner_resources import (
    MinerAssignmentBinding,
    MinerResourceError,
    SQLiteMinerResourceLedger,
)
from umi.protocol import canonical_json_bytes

from .factories import challenge_request, dev_wallet
from .test_competition_authorization import build_authorization_fixture
from .test_competition_miner import authorized_runtime, post_assignment
from .test_miner_transport import (
    CoordinatedTranslator,
    CountingFetcher,
    CountingTranslator,
    RejectingWindowAuthority,
    StaticTranslator,
    runtime,
)
from .test_open_competition import policy as policy


def store(path=":memory:", capacity=2, limits=None):
    return SQLiteMinerResourceLedger(
        path,
        miner_hotkey=dev_wallet("//Bob").hotkey.ss58_address,
        scoring_policy_sha256="20" * 32,
        limits=limits or Limits(),
        maximum_recovery_assignments=capacity,
    )


def binding(request=None, validator="//Alice"):
    return MinerAssignmentBinding.from_request(
        request or challenge_request(),
        validator_hotkey=dev_wallet(validator).hotkey.ss58_address,
    )


def selected_runtime(path, capacity=2, **kwargs):
    selected = runtime(**kwargs)
    selected.resource_ledger.close()
    return replace(selected, resource_ledger=store(path, capacity, selected.limits))


def client(selected, app=None):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app or create_app(selected)),
        base_url="http://miner.test",
    )


async def post(client, selected, request, path=RESPONSE_RECOVERY_PATH, validator="//Alice"):
    return await client.post(
        path,
        content=canonical_json_bytes(request),
        auth=HotkeyAuth(dev_wallet(validator), selected.hotkey_ss58),
    )


@pytest.mark.parametrize("failure", [False, True])
async def test_completed_response_survives_expiry_pruning_restart_and_repeated_outages(
    tmp_path,
    monkeypatch,
    failure,
):
    path = tmp_path / "resources.sqlite"
    fetcher = CountingFetcher()
    selected = selected_runtime(path, fetcher=fetcher, translator=StaticTranslator(failure=failure))
    request = challenge_request()
    async with client(selected) as http:
        original = await post(http, selected, request, TRANSLATE_PATH)
        assert original.status_code == 200
    assert fetcher.calls == 1
    assert selected.resource_ledger.prune_closed_windows(request.response_close_round) == 1
    selected.resource_ledger.close()
    monkeypatch.setattr(bt.timelock, "current_round", lambda: request.reveal_round + 12000)
    for _ in range(3):
        authority = RejectingWindowAuthority()
        translator = CountingTranslator()
        fetcher = CountingFetcher()
        recovered = selected_runtime(
            path, capacity=0, translator=translator, fetcher=fetcher, window_authority=authority
        )
        app = create_app(recovered)
        # Retrieval still works while finality/feed supervision is unhealthy.
        app.state.background_failure = "finality"
        async with client(recovered, app) as http:
            for _ in range(4):
                result = await post(http, recovered, request)
                assert result.status_code == 200
                assert result.content == original.content
                assert result.headers["x-umi-signature"] == original.headers["x-umi-signature"]
                assert result.headers["cache-control"] == "no-store"
            app.state.background_failure = None
            assert (await post(http, recovered, request, TRANSLATE_PATH)).status_code == 422
        assert authority.calls == 1  # only the prohibited new inference route
        assert translator.calls == fetcher.calls == 0
        recovered.resource_ledger.close()


async def test_pending_recovery_does_not_wait_for_or_repeat_running_inference(tmp_path):
    translator = CoordinatedTranslator(asyncio.Event(), asyncio.Event())
    selected = selected_runtime(tmp_path / "resources.sqlite", translator=translator)
    request = challenge_request()
    async with client(selected) as http:
        work = asyncio.create_task(post(http, selected, request, TRANSLATE_PATH))
        await asyncio.wait_for(translator.started.wait(), 3)
        try:
            pending = await asyncio.wait_for(post(http, selected, request), 2)
            assert pending.status_code == 202
            assert pending.json() == {"status": "response_recovery_pending"}
            assert translator.calls == 1
        finally:
            translator.release.set()
        original = await asyncio.wait_for(work, 3)
        recovered = await post(http, selected, request)
        assert original.status_code == recovered.status_code == 200
        assert recovered.content == original.content
        snapshot = selected.resource_ledger.snapshot(binding(request))
        assert snapshot.request_transmissions == snapshot.response_bodies == 1
    selected.resource_ledger.close()


@pytest.mark.parametrize("capacity", [0, 2])
async def test_absent_response_does_not_create_work_or_admit_request(tmp_path, capacity):
    translator, fetcher = CountingTranslator(), CountingFetcher()
    selected = selected_runtime(
        tmp_path / "resources.sqlite", capacity, translator=translator, fetcher=fetcher
    )
    async with client(selected) as http:
        result = await post(http, selected, challenge_request())
        assert result.status_code == 404
        assert result.json()["detail"] == "response_recovery_not_retained"
    assert translator.calls == fetcher.calls == 0
    with pytest.raises(MinerResourceError, match="assignment_not_recorded"):
        selected.resource_ledger.snapshot(binding())
    selected.resource_ledger.close()


async def test_current_window_and_request_budget_still_apply_to_translate(tmp_path, monkeypatch):
    selected = selected_runtime(tmp_path / "resources.sqlite")
    request = challenge_request()
    async with client(selected) as http:
        assert (await post(http, selected, request, TRANSLATE_PATH)).status_code == 200
        assert (await post(http, selected, request, TRANSLATE_PATH)).status_code == 200
        assert (await post(http, selected, request, TRANSLATE_PATH)).status_code == 429
        assert (await post(http, selected, request)).status_code == 200
        monkeypatch.setattr(bt.timelock, "current_round", lambda: request.response_close_round)
        assert (await post(http, selected, request, TRANSLATE_PATH)).status_code == 429
        assert (await post(http, selected, request)).status_code == 200
    selected.resource_ledger.close()


async def test_recovery_is_bound_to_original_request_and_validator(tmp_path):
    selected = selected_runtime(
        tmp_path / "resources.sqlite",
        allowed_wallets=(
            dev_wallet("//Alice"),
            dev_wallet("//Charlie"),
        ),
    )
    request = challenge_request()
    async with client(selected) as http:
        assert (await post(http, selected, request, TRANSLATE_PATH)).status_code == 200
        assert (await post(http, selected, request, validator="//Charlie")).status_code == 404
        assert (await post(http, selected, request, validator="//Dave")).status_code == 403
        changed = request.model_copy(update={"issued_block_hash": "0x" + "01" * 32})
        assert (await post(http, selected, changed)).status_code == 409
        assert (await post(http, selected, request)).status_code == 200
    selected.resource_ledger.close()


async def test_fresh_auth_recovery_path_and_durable_nonce_are_required(tmp_path):
    miner, validator = dev_wallet("//Bob"), dev_wallet("//Alice")

    def authenticator():
        return RequestAuthenticator.sqlite(
            miner.hotkey.ss58_address,
            tmp_path / "nonces.sqlite",
            allowed_hotkeys=[validator.hotkey.ss58_address],
        )

    auth = authenticator()
    selected = selected_runtime(tmp_path / "resources.sqlite", authenticator=auth)
    request = challenge_request()
    body = canonical_json_bytes(request)
    async with client(selected) as http:
        original = await post(http, selected, request, TRANSLATE_PATH)
        assert original.status_code == 200
        signed = next(
            HotkeyAuth(validator, miner.hotkey.ss58_address).auth_flow(
                httpx.Request("POST", "http://miner.test" + RESPONSE_RECOVERY_PATH, content=body)
            )
        )
        assert (
            await http.post(TRANSLATE_PATH, content=body, headers=signed.headers)
        ).status_code == 401
        assert (
            await http.post(RESPONSE_RECOVERY_PATH, content=body, headers=signed.headers)
        ).status_code == 200
        assert (
            await http.post(RESPONSE_RECOVERY_PATH, content=body, headers=signed.headers)
        ).status_code == 401
    selected.resource_ledger.close()
    auth = authenticator()
    selected = selected_runtime(tmp_path / "resources.sqlite", authenticator=auth)
    async with client(selected) as http:
        assert (
            await http.post(RESPONSE_RECOVERY_PATH, content=body, headers=signed.headers)
        ).status_code == 401
        assert (await post(http, selected, request)).content == original.content
    selected.resource_ledger.close()


@pytest.mark.parametrize("corruption", ["body", "signature"])
async def test_recovery_revalidates_signed_bytes_before_transmission(tmp_path, corruption):
    selected = selected_runtime(tmp_path / "resources.sqlite")
    request = challenge_request()
    async with client(selected) as http:
        original = await post(http, selected, request, TRANSLATE_PATH)
        assert original.status_code == 200
        db = selected.resource_ledger._connection
        if corruption == "body":
            altered = original.content.replace(b'"serving_hotkey"', b'"unknown_field"')
            db.execute(
                "UPDATE response_recovery SET body=?, sha256=?",
                (altered, hashlib.sha256(altered).hexdigest()),
            )
        else:
            db.execute("UPDATE response_recovery SET signature=?", ("0x" + "00" * 64,))
        assert (await post(http, selected, request)).status_code == 503
    selected.resource_ledger.close()


def test_reservation_capacity_backpressures_new_work_but_growth_preserves_pending_and_sealed(
    tmp_path,
):
    path = tmp_path / "resources.sqlite"
    ledger = store(path, 1)
    first, second = binding(), binding(challenge_request(2))
    ledger.record_request(first, observed_wire_bytes=1)
    with pytest.raises(MinerResourceError, match="response_recovery_capacity"):
        ledger.record_request(second, observed_wire_bytes=1)
    with pytest.raises(MinerResourceError, match="assignment_not_recorded"):
        ledger.snapshot(second)
    assert (
        ledger.recovered_response(challenge_request(), validator_hotkey=first.validator_hotkey)
        is None
    )
    ledger.record_response(first, body=b"{}", signature="0x" + "11" * 64)
    ledger.prune_closed_windows(first.response_close_round)
    with pytest.raises(MinerResourceError, match="response_recovery_capacity"):
        ledger.record_request(second, observed_wire_bytes=1)
    ledger.close()
    ledger = store(path, 2)
    ledger.record_request(second, observed_wire_bytes=1)
    assert (
        ledger.recovered_response(challenge_request(), validator_hotkey=first.validator_hotkey).body
        == b"{}"
    )
    ledger.close()
    ledger = store(path, 0)
    assert (
        ledger.recovered_response(challenge_request(2), validator_hotkey=second.validator_hotkey)
        is None
    )
    ledger.record_response(second, body=b'{"error":true}', signature="0x" + "22" * 64)
    ledger.prune_closed_windows(second.response_close_round)
    assert (
        ledger.recovered_response(
            challenge_request(2), validator_hotkey=second.validator_hotkey
        ).body
        == b'{"error":true}'
    )
    ledger.close()


def test_concurrent_reservations_do_not_over_admit():
    ledger = store(capacity=2)

    def attempt(index):
        try:
            ledger.record_request(binding(challenge_request(index)), observed_wire_bytes=1)
            return "accepted"
        except MinerResourceError as error:
            return error.reason_code

    with ThreadPoolExecutor(max_workers=8) as pool:
        outcomes = list(pool.map(attempt, range(1, 9)))
    assert outcomes.count("accepted") == 2
    assert outcomes.count("response_recovery_capacity") == 6
    ledger.close()


def test_response_cache_and_archive_commit_atomically():
    ledger = store()
    assignment = binding()
    ledger.record_request(assignment, observed_wire_bytes=1)
    db = ledger._connection
    db.execute(
        "CREATE TRIGGER fail_archive BEFORE UPDATE ON response_recovery "
        "BEGIN SELECT RAISE(ABORT, 'disk failure'); END"
    )
    with pytest.raises(sqlite3.IntegrityError, match="disk failure"):
        ledger.record_response(assignment, body=b"{}", signature="0x" + "11" * 64)
    assert ledger.cached_response(assignment) is None
    assert ledger.snapshot(assignment).response_bodies == 0
    assert (
        ledger.recovered_response(challenge_request(), validator_hotkey=assignment.validator_hotkey)
        is None
    )
    db.execute("DROP TRIGGER fail_archive")
    ledger.record_response(assignment, body=b"{}", signature="0x" + "11" * 64)
    assert (
        ledger.recovered_response(
            challenge_request(), validator_hotkey=assignment.validator_hotkey
        ).body
        == b"{}"
    )
    ledger.close()


async def test_lost_delivery_recovers_without_a_second_inference(tmp_path):
    translator = CountingTranslator()
    selected = selected_runtime(tmp_path / "resources.sqlite", translator=translator)
    request = challenge_request()

    class LostReply(httpx.AsyncBaseTransport):
        sha256 = None

        async def handle_async_request(self, request):
            result = await httpx.ASGITransport(app=create_app(selected)).handle_async_request(
                request
            )
            assert result.status_code == 200
            self.sha256 = hashlib.sha256(await result.aread()).hexdigest()
            await result.aclose()
            raise httpx.ReadError("simulated reply lost after durable sealing", request=request)

    transport = LostReply()
    async with httpx.AsyncClient(transport=transport, base_url="http://miner.test") as http:
        with pytest.raises(httpx.ReadError):
            await post(http, selected, request, TRANSLATE_PATH)
    selected.resource_ledger.prune_closed_windows(request.response_close_round)
    selected.resource_ledger.close()
    selected = selected_runtime(tmp_path / "resources.sqlite", translator=translator)
    async with client(selected) as http:
        recovered = await post(http, selected, request)
        assert recovered.status_code == 200
        assert hashlib.sha256(recovered.content).hexdigest() == transport.sha256
    assert translator.calls == 1
    selected.resource_ledger.close()


@pytest.mark.parametrize("rejection", ["unsigned", "noncanonical", "oversize", "wrong_body"])
async def test_recovery_ingress_is_authenticated_and_bounded(tmp_path, rejection):
    selected = selected_runtime(tmp_path / "resources.sqlite")
    body = canonical_json_bytes(challenge_request())
    expected = {"unsigned": 401, "noncanonical": 422, "oversize": 413, "wrong_body": 401}
    if rejection == "noncanonical":
        body += b"\n"
    if rejection == "oversize":
        body = b"x" * (selected.limits.maximum_request_body_bytes + 1)
    async with client(selected) as http:
        signed = next(
            HotkeyAuth(dev_wallet("//Alice"), selected.hotkey_ss58).auth_flow(
                httpx.Request("POST", "http://miner.test" + RESPONSE_RECOVERY_PATH, content=body)
            )
        )
        headers = {} if rejection == "unsigned" else dict(signed.headers)
        if rejection == "wrong_body":
            body = body[:-1] + b" "
        result = await http.post(RESPONSE_RECOVERY_PATH, content=body, headers=headers)
        assert result.status_code == expected[rejection]
    assert (
        selected.resource_ledger._connection.execute(
            "SELECT COUNT(*) FROM response_recovery"
        ).fetchone()[0]
        == 0
    )
    selected.resource_ledger.close()


def test_rejected_request_does_not_leave_a_recovery_reservation():
    ledger = store(capacity=1, limits=Limits(maximum_assignment_wire_bytes=1))
    with pytest.raises(MinerResourceError):
        ledger.record_request(binding(), observed_wire_bytes=2)
    assert ledger._connection.execute("SELECT COUNT(*) FROM response_recovery").fetchone()[0] == 0
    assert ledger._connection.execute("SELECT COUNT(*) FROM assignments").fetchone()[0] == 0
    ledger.record_request(binding(), observed_wire_bytes=1)
    ledger.close()


async def test_mounted_recovery_route_cannot_admit_a_new_inference(tmp_path):
    translator = CountingTranslator()
    selected = selected_runtime(tmp_path / "resources.sqlite", translator=translator)
    outer = FastAPI()
    outer.mount("/miner", create_app(selected))
    async with client(selected, outer) as http:
        result = await post(http, selected, challenge_request(), "/miner" + RESPONSE_RECOVERY_PATH)
        assert result.status_code == 404
        assert result.json()["detail"] == "response_recovery_not_retained"
    assert translator.calls == 0
    selected.resource_ledger.close()


async def test_signed_competition_assignment_is_retrievable_after_authority_expires(
    policy,
    tmp_path,
    monkeypatch,
):
    case = build_authorization_fixture(policy)
    selected = authorized_runtime(case, tmp_path)
    selected.resource_ledger.close()
    selected = replace(
        selected,
        resource_ledger=SQLiteMinerResourceLedger(
            tmp_path / "assignments.sqlite3",
            miner_hotkey=selected.hotkey_ss58,
            scoring_policy_sha256=selected.scoring_policy_sha256,
            limits=selected.limits,
            maximum_recovery_assignments=2,
        ),
    )
    async with client(selected) as http:
        original = await post_assignment(http, case)
        assert original.status_code == 200
        selected.resource_ledger.prune_closed_windows(case.request.response_close_round)
        case.finalized_blocks.head = case.request.deadline_block + 1
        monkeypatch.setattr(bt.timelock, "current_round", lambda: case.request.reveal_round + 12000)
        assert (await post_assignment(http, case)).status_code == 422
        recovered = await http.post(
            RESPONSE_RECOVERY_PATH,
            content=canonical_json_bytes(case.request),
            auth=HotkeyAuth(case.validator_wallet, selected.hotkey_ss58),
        )
        assert recovered.status_code == 200
        assert recovered.content == original.content
        assert recovered.headers["x-umi-signature"] == original.headers["x-umi-signature"]
    assert selected.translator.calls == selected.video_fetcher.calls == 1
    selected.resource_ledger.close()


@pytest.mark.parametrize("capacity", [-1, True, 2**53, 1.1])
def test_capacity_must_be_an_operational_nonnegative_integer(capacity):
    with pytest.raises(ValueError, match="capacity"):
        store(capacity=capacity)


@pytest.mark.parametrize("corruption", ["signature", "sha256", "body", "request_digest"])
def test_damaged_archive_fails_startup(tmp_path, corruption):
    path = tmp_path / "resources.sqlite"
    ledger = store(path)
    assignment = binding()
    ledger.record_request(assignment, observed_wire_bytes=1)
    ledger.record_response(assignment, body=b"{}", signature="0x" + "11" * 64)
    ledger._connection.execute(f"UPDATE response_recovery SET {corruption} = ?", ("broken",))
    ledger.close()
    with pytest.raises(MinerResourceError, match="response_recovery_invalid"):
        store(path)
