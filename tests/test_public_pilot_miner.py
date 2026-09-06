from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

import umi.public_pilot_miner as public_pilot
from umi.backends import Translator
from umi.component import prepare_case
from umi.miner import create_app
from umi.miner_admission import ExactComponentWindowAuthority
from umi.protocol import TranslationRequest, canonical_json_bytes
from umi.public_pilot_campaign import prepare_public_pilot_case

from .factories import dev_wallet, ground_truth, three_requests


class FixtureTranslator(Translator):
    async def translate(self, video: bytes, request: TranslationRequest) -> str:
        return "fixture"


def _prepared_case(root: Path) -> Path:
    requests = three_requests()
    requests_path = root / "requests.json"
    ground_truth_path = root / "ground-truth.json"
    requests_path.write_bytes(
        canonical_json_bytes(
            [request.model_dump(mode="json", by_alias=True) for request in requests]
        )
    )
    ground_truth_path.write_bytes(canonical_json_bytes(ground_truth(requests)))
    case = root / "case"
    prepare_case(requests_path, ground_truth_path, case)
    return case


def _public_campaign_case(
    root: Path,
    *,
    coordinator_hotkey: str,
    miner_hotkey: str,
) -> Path:
    case = root / "campaign-case"
    prepare_public_pilot_case(
        case,
        coordinator_hotkey=coordinator_hotkey,
        expected_miner_uid=236,
        expected_miner_hotkey=miner_hotkey,
        current_round=bt.timelock.current_round(),
    )
    return case


def _args(root: Path, case: Path) -> SimpleNamespace:
    state = root / "state"
    state.mkdir(mode=0o700)
    return SimpleNamespace(
        case=case,
        wallet_name="umi",
        hotkey="miner",
        wallet_path=str(root / "wallets"),
        translator="tests.test_public_pilot_miner:fixture_translator",
        translator_unix_socket=None,
        model_revision="ab" * 32,
        video_origin=["https://pub-bfe43425f6564cc98cb3ad43b9662ae3.r2.dev"],
        nonce_db=str(state / "nonces.sqlite3"),
        assignment_db=str(state / "assignments.sqlite3"),
        request_body_timeout=5.0,
        video_fetch_timeout=30.0,
        backend_lifecycle_timeout=60.0,
        inference_admission_timeout=10.0,
        inference_timeout=180.0,
    )


@pytest.mark.asyncio
async def test_builds_exact_public_component_runtime_and_health(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    miner_wallet = dev_wallet("//PublicPilotMiner")
    validator_wallet = dev_wallet("//PublicPilotValidator")
    case = _public_campaign_case(
        tmp_path,
        coordinator_hotkey=validator_wallet.hotkey.ss58_address,
        miner_hotkey=miner_wallet.hotkey.ss58_address,
    )
    args = _args(tmp_path, case)
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: miner_wallet)
    monkeypatch.setattr(
        public_pilot,
        "load_translator",
        lambda *args, **kwargs: FixtureTranslator(),
    )

    runtime = public_pilot.build_runtime(args)
    try:
        assert runtime.runtime_mode == "public_component_pilot"
        assert runtime.finality_service is None
        assert runtime.allowed_validator_hotkeys == frozenset(
            {validator_wallet.hotkey.ss58_address}
        )
        assert isinstance(runtime.window_authority, ExactComponentWindowAuthority)
        assert runtime.limits.maximum_inference_concurrency == 1

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(runtime)),
            base_url="http://pilot.test",
        ) as client:
            response = await client.get("/healthz")
        assert response.status_code == 200
        health = response.json()
        assert health["runtime_mode"] == "public_component_pilot"
        assert health["translation_weights_active"] is False
        assert health["protocol_conformance"] is False
        assert health["activation_evidence"] is False
        assert health["window_authority"] == "ExactComponentWindowAuthority"
        assert health["finality_service"] == "component_authority"
    finally:
        runtime.resource_ledger.close()


def test_rejects_video_origin_set_that_differs_from_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator = dev_wallet("//PublicPilotValidator")
    miner = dev_wallet("//PublicPilotMiner")
    case = _public_campaign_case(
        tmp_path,
        coordinator_hotkey=validator.hotkey.ss58_address,
        miner_hotkey=miner.hotkey.ss58_address,
    )
    args = _args(tmp_path, case)
    args.video_origin = ["https://another.example"]
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: miner)

    with pytest.raises(ValueError, match="exactly match"):
        public_pilot.build_runtime(args)


def test_rejects_plain_local_component_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    case = _prepared_case(tmp_path)
    args = _args(tmp_path, case)
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: dev_wallet("//PublicPilotMiner"))

    with pytest.raises(ValueError, match="lacks the exact public-pilot campaign"):
        public_pilot.build_runtime(args)


def test_rejects_wallet_other_than_campaign_miner(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    coordinator = dev_wallet("//PublicPilotValidator")
    expected_miner = dev_wallet("//PublicPilotMiner")
    case = _public_campaign_case(
        tmp_path,
        coordinator_hotkey=coordinator.hotkey.ss58_address,
        miner_hotkey=expected_miner.hotkey.ss58_address,
    )
    args = _args(tmp_path, case)
    monkeypatch.setattr(bt, "Wallet", lambda **_kwargs: dev_wallet("//OtherMiner"))

    with pytest.raises(ValueError, match="expected miner hotkey"):
        public_pilot.build_runtime(args)


@pytest.mark.parametrize("value", ["0.0.0.0", "::", "203.0.113.10", "localhost"])
def test_public_pilot_miner_refuses_nonliteral_or_public_listeners(value: str) -> None:
    with pytest.raises(ValueError, match="loopback"):
        public_pilot._require_loopback(value)


def test_public_pilot_miner_accepts_literal_loopback_listeners() -> None:
    assert public_pilot._require_loopback("127.0.0.1") == "127.0.0.1"
    assert public_pilot._require_loopback("::1") == "::1"


async def fixture_translator(video: bytes, request: TranslationRequest) -> str:
    return "fixture"


fixture_translator.model_revision = "ab" * 32  # type: ignore[attr-defined]
