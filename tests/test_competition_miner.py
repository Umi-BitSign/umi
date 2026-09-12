from __future__ import annotations

import asyncio
import hashlib
import os
import time
from dataclasses import replace
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

from umi.auth import REQUEST_BODY_SHA256_HEADER, RequestAuthenticator
from umi.competition_authorization import EndpointAuthorizationAuthority
from umi.config import Limits
from umi.miner import MinerRuntime, _read_startup_file, build_runtime, create_app
from umi.miner_admission import ProofBackedMinerWindowAuthority
from umi.miner_resources import (
    MinerAssignmentBinding,
    MinerResourceError,
    SQLiteMinerResourceLedger,
)
from umi.policy import scoring_policy_hash
from umi.validator import prepare_request_attempt, validate_response_envelope

from .test_competition_authorization import build_authorization_fixture
from .test_miner_transport import runtime
from .test_open_competition import policy as policy


@pytest.mark.parametrize(
    "values",
    [
        {"competition_policy": "policy.json"},
        {"competition_authorization": "authorization.json"},
        {"serving_origin": "https://miner.example"},
        {"competition_policy": "policy.json", "serving_origin": "https://miner.example"},
    ],
)
def test_partial_successor_cli_configuration_fails_before_wallet_access(monkeypatch, values):
    def forbidden(*args, **kwargs):
        raise AssertionError("invalid configuration must not open a wallet")

    monkeypatch.setattr(bt, "Wallet", forbidden)
    with pytest.raises(ValueError, match="together"):
        build_runtime(SimpleNamespace(**values))


def test_successor_cli_requires_model_revision_before_wallet_access(monkeypatch):
    monkeypatch.setattr(bt, "Wallet", lambda **kwargs: pytest.fail("wallet access"))
    with pytest.raises(ValueError, match="model revision"):
        build_runtime(
            SimpleNamespace(
                competition_policy="policy.json",
                competition_authorization="authorization.json",
                serving_origin="https://miner.example",
                model_revision=None,
            )
        )


def test_successor_mode_cannot_omit_authority_or_accept_a_duck_typed_authority():
    base = runtime()
    try:
        with pytest.raises(ValueError, match="explicit authorization"):
            replace(base, runtime_mode="competition_no_weight")
        with pytest.raises(ValueError, match="explicit authorization"):
            replace(base, competition_authority=object())
        with pytest.raises(TypeError, match="signed endpoint assignments"):
            replace(base, runtime_mode="competition_no_weight", competition_authority=object())
    finally:
        base.resource_ledger.close()


def test_startup_document_reader_is_bounded_and_canonical(tmp_path):
    path = tmp_path / "authorization.json"
    path.write_bytes(b'{"no_weight":true}')
    assert _read_startup_file(path, label="competition authorization") == path.read_bytes()
    with pytest.raises(RuntimeError, match="file size"):
        _read_startup_file(path, maximum_bytes=2)
    path.write_bytes(b'{ "no_weight": true }')
    with pytest.raises(RuntimeError, match="canonical"):
        _read_startup_file(path)
    path.write_bytes(b'{"no_weight":false,"no_weight":true}')
    with pytest.raises(RuntimeError, match="canonical"):
        _read_startup_file(path)
    path.write_bytes(b"null\n")
    with pytest.raises(RuntimeError, match="canonical"):
        _read_startup_file(path)


def test_startup_document_reader_rejects_links_and_nonregular_files(tmp_path):
    original = tmp_path / "original.json"
    original.write_bytes(b"{}")
    link = tmp_path / "linked.json"
    link.symlink_to(original)
    with pytest.raises(RuntimeError, match="opened safely"):
        _read_startup_file(link)
    fifo = tmp_path / "input.pipe"
    os.mkfifo(fifo, 0o600)
    with pytest.raises(RuntimeError, match="file is unsafe"):
        _read_startup_file(fifo)


def test_startup_document_reader_rejects_publicly_writable_inputs(tmp_path):
    path = tmp_path / "authorization.json"
    path.write_bytes(b"{}")
    path.chmod(0o666)
    with pytest.raises(RuntimeError, match="unsafe"):
        _read_startup_file(path)


class FetchProbe:
    def __init__(self, video):
        self.video = video
        self.calls = 0

    async def fetch(self, descriptor):
        self.calls += 1
        return self.video


class TranslateProbe:
    def __init__(self):
        self.calls = 0

    async def translate(self, video, request):
        self.calls += 1
        return "hello"


def authorized_runtime(case, state):
    policy, legacy = case.policy, case.legacy_policy
    miner = case.miner_wallet.hotkey.ss58_address
    validators = frozenset(v.validator_hotkey for v in legacy.validator_registry)
    limits = replace(
        Limits.from_policy(legacy),
        maximum_inference_concurrency=len(validators),
        inference_timeout_seconds=policy.maximum_inference_ms / 1000,
        maximum_hypothesis_utf8_bytes=policy.maximum_output_bytes,
    )
    authority = EndpointAuthorizationAuthority(
        policy=policy,
        legacy_policy=legacy,
        publication=case.publication,
        finalized_blocks=case.finalized_blocks,
        miner_hotkey=miner,
        model_revision=case.model_revision,
        serving_origin=case.serving_origin,
    )
    return MinerRuntime(
        wallet=case.miner_wallet,
        hotkey_ss58=miner,
        signature_scheme="sr25519",
        translator=TranslateProbe(),
        video_fetcher=FetchProbe(case.video_bytes),
        allowed_validator_hotkeys=validators,
        authenticator=RequestAuthenticator.sqlite(
            miner,
            state / "nonces.sqlite3",
            allowed_hotkeys=validators,
        ),
        limits=limits,
        scoring_policy_sha256=scoring_policy_hash(legacy),
        response_deadline_blocks=case.request.deadline_block - case.request.issued_block,
        resource_ledger=SQLiteMinerResourceLedger(
            state / "assignments.sqlite3",
            miner_hotkey=miner,
            scoring_policy_sha256=scoring_policy_hash(legacy),
            limits=limits,
        ),
        window_authority=ProofBackedMinerWindowAuthority(
            policy=legacy,
            finalized_blocks=case.finalized_blocks,
        ),
        model_revision=case.model_revision,
        runtime_mode="competition_no_weight",
        competition_authority=authority,
        inference_semaphore=asyncio.Semaphore(len(validators)),
        work_semaphore=asyncio.Semaphore(len(validators)),
    )


async def post_assignment(client, case, *, request=None, evaluator=None, nonce=None):
    prepared = prepare_request_attempt(
        request or case.request,
        wallet=evaluator or case.validator_wallet,
        miner_hotkey=case.miner_wallet.hotkey.ss58_address,
        nonce_ns=nonce or time.time_ns(),
    )
    return await client.post(
        "/v1/translate",
        content=prepared.request_bytes,
        headers={
            **dict(prepared.auth_headers),
            REQUEST_BODY_SHA256_HEADER: hashlib.sha256(prepared.request_bytes).hexdigest(),
            "Content-Type": "application/json",
        },
    )


@pytest.mark.asyncio
async def test_authorized_http_request_returns_real_signed_timelocked_response(policy, tmp_path):
    case = build_authorization_fixture(policy)
    miner = authorized_runtime(case, tmp_path)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(miner)),
            base_url=case.serving_origin,
        ) as client:
            result = await post_assignment(client, case)
            assert result.status_code == 200, result.text
            envelope, _ = validate_response_envelope(
                result.content,
                result.headers["X-UMI-Signature"],
                request=case.request,
                validator_hotkey=case.validator_wallet.hotkey.ss58_address,
                miner_hotkey=miner.hotkey_ss58,
            )
            assert envelope.response_reveal_round == case.request.reveal_round
            assert miner.translator.calls == miner.video_fetcher.calls == 1
            health = (await client.get("/healthz")).json()
            assert health["runtime_mode"] == "competition_no_weight"
            assert health["translation_weights_active"] is False
            assert health["chain_submission_authorized"] is False
            assert health["serving_origin_finality_verified"] is False
    finally:
        miner.resource_ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["wrong_evaluator", "unknown_request", "missing_finality"])
async def test_successor_http_rejection_precedes_fetch_inference_and_assignment_charge(
    policy, tmp_path, mutation
):
    case = build_authorization_fixture(policy)
    miner = authorized_runtime(case, tmp_path)
    kwargs = {}
    if mutation == "wrong_evaluator":
        kwargs["evaluator"] = case.evaluator_wallets[1]
    elif mutation == "unknown_request":
        kwargs["request"] = case.request.model_copy(
            update={"challenge_id": "EREREREREREREREREREREQ"}
        )
    else:
        case.finalized_blocks.blocks.pop(case.request.issued_block)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(miner)),
            base_url=case.serving_origin,
        ) as client:
            result = await post_assignment(client, case, **kwargs)
            assert result.status_code == (503 if mutation == "missing_finality" else 422)
            assert miner.translator.calls == miner.video_fetcher.calls == 0
            binding = MinerAssignmentBinding.from_request(
                kwargs.get("request", case.request),
                validator_hotkey=kwargs.get("evaluator", case.validator_wallet).hotkey.ss58_address,
            )
            with pytest.raises(MinerResourceError, match="assignment_not_recorded"):
                miner.resource_ledger.snapshot(binding)
    finally:
        miner.resource_ledger.close()


@pytest.mark.asyncio
async def test_successor_http_restart_reuses_cached_response_and_retains_nonce_and_retry_limits(
    policy, tmp_path
):
    case = build_authorization_fixture(policy)
    first = authorized_runtime(case, tmp_path)
    nonce = time.time_ns()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(first)),
            base_url=case.serving_origin,
        ) as client:
            original = await post_assignment(client, case, nonce=nonce)
            assert original.status_code == 200
    finally:
        first.resource_ledger.close()
    second = authorized_runtime(case, tmp_path)
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(second)),
            base_url=case.serving_origin,
        ) as client:
            replay = await post_assignment(client, case, nonce=nonce)
            assert replay.status_code == 401
            retry = await post_assignment(client, case)
            assert retry.status_code == 200
            assert retry.content == original.content
            assert retry.headers["X-UMI-Signature"] == original.headers["X-UMI-Signature"]
            exceeded = await post_assignment(client, case)
            assert exceeded.status_code == 429
            assert second.video_fetcher.calls == second.translator.calls == 0
            binding = MinerAssignmentBinding.from_request(
                case.request,
                validator_hotkey=case.validator_wallet.hotkey.ss58_address,
            )
            assert second.resource_ledger.snapshot(binding).request_transmissions == 2
    finally:
        second.resource_ledger.close()
