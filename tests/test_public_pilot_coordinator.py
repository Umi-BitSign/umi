from __future__ import annotations

import hashlib
import json
import sys
from dataclasses import dataclass, replace
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest

import umi.public_pilot_coordinator as coordinator_module
import umi.validator as validator_module
from umi.audit import EvidenceStore
from umi.auth import RequestAuthenticator
from umi.backends import Translator
from umi.chain import FinalizedMinerEndpoint
from umi.config import Limits
from umi.miner import MinerRuntime, _identity, create_app
from umi.miner_admission import ExactComponentWindowAuthority
from umi.miner_resources import SQLiteMinerResourceLedger
from umi.protocol import (
    RESPONSE_PLAINTEXT_SCHEMA,
    ResponsePlaintext,
    TranslationRequest,
    canonical_json_bytes,
)
from umi.public_pilot_campaign import (
    ASSET_REFERENCES,
    ASSET_SHA256,
    CAMPAIGN_ID,
    build_public_pilot_inputs,
    load_public_pilot_campaign,
    prepare_public_pilot_case,
)
from umi.public_pilot_coordinator import (
    _coordinator_possession_challenge,
    _effective_reveal_timeout,
    _prove_coordinator_signer,
    _require_response_headroom,
    _validated_request_timeout,
    prepare_public_endpoint_pilot_case,
    replay_public_endpoint_pilot,
    run_public_endpoint_pilot,
)
from umi.public_pilot_journal import (
    ATTEMPT_JOURNAL_SCHEMA,
    PublicPilotAttemptJournal,
    load_attempt_journal,
)

from .factories import dev_wallet


def test_public_pilot_runbook_binds_r2_handoffs_to_the_archive_digest() -> None:
    runbook = Path(__file__).resolve().parents[1] / "docs" / "PUBLIC_ENDPOINT_MINER_PILOT.md"
    text = runbook.read_text(encoding="utf-8")

    assert "public-pilot-cases/ARCHIVE_SHA256/sealed-case.tar.gz" in text
    assert "MUST be new and MUST NOT be overwritten" in text
    assert "without repository or R2 credentials" in text


def test_coordinator_possession_preflight_accepts_the_expected_private_hotkey() -> None:
    wallet = dev_wallet("//PublicPilotCoordinatorPossession")
    hotkey = wallet.hotkey.ss58_address

    challenge = _coordinator_possession_challenge(hotkey)

    assert len(challenge) == 32
    assert (
        challenge
        == hashlib.sha256(
            b"umi-public-pilot-coordinator-possession-v1\0" + bytes(wallet.hotkey.public_key)
        ).digest()
    )
    assert _prove_coordinator_signer(wallet, hotkey) == hotkey


def test_prepare_creates_a_timed_case_after_coordinator_possession_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet = dev_wallet("//PublicPilotPreparedCoordinator")
    miner_wallet = dev_wallet("//PublicPilotPreparedMiner")
    output = tmp_path / "case"
    observed: dict[str, object] = {}

    def fake_prepare(case_root: Path, **kwargs: object) -> Path:
        observed.update(kwargs)
        case_root.mkdir()
        manifest = case_root / "manifest.json"
        manifest.write_bytes(b"{}")
        return manifest

    monkeypatch.setattr(bt.timelock, "current_round", lambda: 123_456)
    monkeypatch.setattr(coordinator_module, "prepare_public_pilot_case", fake_prepare)

    manifest = prepare_public_endpoint_pilot_case(
        output,
        wallet=wallet,
        expected_coordinator_hotkey=wallet.hotkey.ss58_address,
        expected_miner_uid=247,
        expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        setup_allowance_seconds=600,
        response_window_seconds=120,
        reveal_margin_seconds=90,
    )

    assert manifest == output / "manifest.json"
    assert observed == {
        "coordinator_hotkey": wallet.hotkey.ss58_address,
        "current_round": 123_456,
        "expected_miner_hotkey": miner_wallet.hotkey.ss58_address,
        "expected_miner_uid": 247,
        "response_window_seconds": 120,
        "reveal_margin_seconds": 90,
        "setup_allowance_seconds": 600,
    }


def test_prepare_rejects_an_address_only_coordinator_before_timing_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    private_wallet = dev_wallet("//PublicPilotAddressOnlyCoordinator")
    miner_wallet = dev_wallet("//PublicPilotAddressOnlyMiner")
    address_only_hotkey = bt.sp_core.Keypair(
        public_key=private_wallet.hotkey.public_key,
        crypto_type=private_wallet.hotkey.crypto_type,
    )
    address_only_wallet = SimpleNamespace(
        coldkey=private_wallet.coldkey,
        coldkeypub=private_wallet.coldkeypub,
        hotkey=address_only_hotkey,
    )
    timing_checked = False

    def should_not_read_current_round() -> int:
        nonlocal timing_checked
        timing_checked = True
        raise AssertionError("timelock round was read before signer possession was proved")

    monkeypatch.setattr(bt.timelock, "current_round", should_not_read_current_round)
    output = tmp_path / "case"
    with pytest.raises(RuntimeError, match="signing preflight failed"):
        prepare_public_endpoint_pilot_case(
            output,
            wallet=address_only_wallet,
            expected_coordinator_hotkey=address_only_hotkey.ss58_address,
            expected_miner_uid=247,
            expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        )

    assert timing_checked is False
    assert not output.exists()


def test_prepare_rejects_a_coordinator_mismatch_before_timing_or_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wallet = dev_wallet("//PublicPilotWrongCoordinator")
    expected_wallet = dev_wallet("//PublicPilotExpectedCoordinator")
    miner_wallet = dev_wallet("//PublicPilotMismatchMiner")
    timing_checked = False

    def should_not_read_current_round() -> int:
        nonlocal timing_checked
        timing_checked = True
        raise AssertionError("timelock round was read before coordinator identity was checked")

    monkeypatch.setattr(bt.timelock, "current_round", should_not_read_current_round)
    output = tmp_path / "case"
    with pytest.raises(ValueError, match="expected coordinator hotkey"):
        prepare_public_endpoint_pilot_case(
            output,
            wallet=wallet,
            expected_coordinator_hotkey=expected_wallet.hotkey.ss58_address,
            expected_miner_uid=247,
            expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        )

    assert timing_checked is False
    assert not output.exists()


def test_reveal_timeout_covers_the_prepared_case_schedule() -> None:
    reveal_round = bt.timelock.current_round() + 1_000
    reveal_time = bt.timelock.reveal_time(reveal_round).timestamp()

    assert (
        _effective_reveal_timeout(
            reveal_round,
            None,
            now_seconds=reveal_time - 1_000,
        )
        == 1_120
    )
    with pytest.raises(ValueError, match="expires before"):
        _effective_reveal_timeout(
            reveal_round,
            900,
            now_seconds=reveal_time - 1_000,
        )


def test_public_pilot_requires_five_minutes_before_response_close() -> None:
    response_close_round = bt.timelock.current_round() + 1_000
    close_time = bt.timelock.reveal_time(response_close_round).timestamp()

    assert (
        _require_response_headroom(
            response_close_round,
            now_seconds=close_time - 300,
        )
        == 300
    )
    with pytest.raises(ValueError, match="fewer than 300 seconds"):
        _require_response_headroom(
            response_close_round,
            now_seconds=close_time - 299.999,
        )


@pytest.mark.parametrize("value", (True, 0, -1, float("nan"), float("inf"), "240"))
def test_public_pilot_rejects_invalid_request_timeout(value: object) -> None:
    with pytest.raises(ValueError, match="finite and positive"):
        _validated_request_timeout(value, response_headroom_seconds=300)  # type: ignore[arg-type]


def test_public_pilot_request_timeout_preserves_post_request_margin() -> None:
    assert _validated_request_timeout(240, response_headroom_seconds=300) == 240
    with pytest.raises(ValueError, match="leave at least 60 seconds"):
        _validated_request_timeout(240.001, response_headroom_seconds=300)


@dataclass(frozen=True)
class _Translator(Translator):
    async def translate(self, video: bytes, request) -> str:
        return "book"


@dataclass(frozen=True)
class _Fetcher:
    video: bytes

    async def fetch(self, _descriptor) -> bytes:
        return self.video


@pytest.mark.asyncio
async def test_public_endpoint_pilot_runs_replays_and_binds_finalized_endpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_wallet = dev_wallet("//PublicPilotValidator")
    miner_wallet = dev_wallet("//PublicPilotMiner")
    current_round = bt.timelock.current_round()

    def entropy(size: int) -> bytes:
        return bytes([size]) * size

    request, truth = build_public_pilot_inputs(
        current_round=current_round,
        setup_allowance_seconds=360,
        response_window_seconds=60,
        reveal_margin_seconds=30,
        entropy=entropy,
    )
    case_root = tmp_path / "case"
    prepare_public_pilot_case(
        case_root,
        coordinator_hotkey=validator_wallet.hotkey.ss58_address,
        expected_miner_uid=236,
        expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        current_round=current_round,
        setup_allowance_seconds=360,
        response_window_seconds=60,
        reveal_margin_seconds=30,
        entropy=entropy,
    )
    campaign = load_public_pilot_campaign(case_root)
    assert campaign.response_close_round == request.response_close_round

    video = (Path(__file__).parents[1] / "docs" / "pilot-media" / "asl-book.mp4").read_bytes()
    assert hashlib.sha256(video).hexdigest() == ASSET_SHA256
    miner_hotkey, scheme = _identity(miner_wallet)
    limits = Limits()
    ledger = SQLiteMinerResourceLedger(
        ":memory:",
        miner_hotkey=miner_hotkey,
        scoring_policy_sha256=request.scoring_policy_hash,
        limits=limits,
    )
    runtime = MinerRuntime(
        wallet=miner_wallet,
        hotkey_ss58=miner_hotkey,
        signature_scheme=scheme,
        translator=_Translator(),
        video_fetcher=_Fetcher(video),
        allowed_validator_hotkeys=frozenset({validator_wallet.hotkey.ss58_address}),
        authenticator=RequestAuthenticator.in_memory(miner_hotkey),
        limits=limits,
        scoring_policy_sha256=request.scoring_policy_hash,
        response_deadline_blocks=1,
        resource_ledger=ledger,
        window_authority=ExactComponentWindowAuthority((request,)),
        model_revision="55" * 32,
        runtime_mode="public_component_pilot",
    )
    app = create_app(runtime)

    endpoint = FinalizedMinerEndpoint(
        hotkey=miner_hotkey,
        uid=236,
        origin="https://8.8.8.8:443",
        validator_permit=False,
        network="finney",
        genesis_block_hash="0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
        finalized_block_number=99,
        finalized_block_hash="0x" + "44" * 32,
        finalized_block_timestamp_ms=1_788_609_600_123,
    )

    async def fake_discovery(*_args, **_kwargs):
        return endpoint

    real_send = validator_module.send_prepared_request

    async def in_process_send(*args, **kwargs):
        return await real_send(
            *args,
            **kwargs,
            transport=httpx.ASGITransport(app=app),
        )

    response_plaintext = ResponsePlaintext.model_validate(
        {
            "schema": RESPONSE_PLAINTEXT_SCHEMA,
            "protocol": request.protocol,
            "window_id": request.window_id,
            "batch_id": request.batch_id,
            "challenge_id": request.challenge_id,
            "request_digest": validator_module.request_digest(request),
            "issued_block_hash": request.issued_block_hash,
            "validator_hotkey": validator_wallet.hotkey.ss58_address,
            "serving_hotkey": miner_hotkey,
            "status": "ok",
            "received_video_sha256": ASSET_SHA256,
            "hypothesis": "book",
            "model_revision": "55" * 32,
            "error_code": None,
        }
    )
    ground_truth_digest = validator_module.load_case(case_root).ground_truth.sha256_hex

    def fake_decrypt(sealed, **_kwargs):
        if sealed.sha256_hex == ground_truth_digest:
            return canonical_json_bytes(truth)
        return canonical_json_bytes(response_plaintext)

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    monkeypatch.setattr(coordinator_module, "send_prepared_request", in_process_send)
    monkeypatch.setattr(validator_module, "decrypt_response", fake_decrypt)
    output = tmp_path / "result"
    try:
        manifest = await run_public_endpoint_pilot(
            case_root,
            output,
            wallet=validator_wallet,
        )
        replay = replay_public_endpoint_pilot(output)
    finally:
        ledger.close()

    assert manifest == output / "manifest.json"
    assert replay["status"] == "public_endpoint_pilot_replay_ok"
    assert replay["miner_uid"] == 236
    assert replay["miner_hotkey"] == miner_hotkey
    assert replay["announced_origin"] == endpoint.origin
    assert replay["finalized_block_hash"] == endpoint.finalized_block_hash
    assert replay["outcome"] == "ok"
    assert replay["translation_weights_active"] is False
    assert not (tmp_path / "result.incomplete").exists()


@pytest.mark.asyncio
async def test_public_endpoint_pilot_rejects_uid_change_before_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_wallet = dev_wallet("//PublicPilotValidator")
    miner_wallet = dev_wallet("//PublicPilotMiner")
    case_root = tmp_path / "case"
    prepare_public_pilot_case(
        case_root,
        coordinator_hotkey=validator_wallet.hotkey.ss58_address,
        expected_miner_uid=236,
        expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        current_round=bt.timelock.current_round(),
    )

    async def fake_discovery(*_args, **_kwargs):
        return FinalizedMinerEndpoint(
            hotkey=miner_wallet.hotkey.ss58_address,
            uid=235,
            origin="https://8.8.8.8:443",
            validator_permit=False,
            network="finney",
            genesis_block_hash="0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03",
            finalized_block_number=99,
            finalized_block_hash="0x" + "44" * 32,
            finalized_block_timestamp_ms=1_788_609_600_123,
        )

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    with pytest.raises(ValueError, match="UID"):
        await run_public_endpoint_pilot(
            case_root,
            tmp_path / "result",
            wallet=validator_wallet,
        )


@pytest.mark.asyncio
async def test_public_endpoint_pilot_rejects_unsigned_case_or_origin_change_before_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_wallet = dev_wallet("//PublicPilotAuthorizedValidator")
    miner_wallet = dev_wallet("//PublicPilotAuthorizedMiner")
    case_root = tmp_path / "case"
    prepare_public_pilot_case(
        case_root,
        coordinator_hotkey=validator_wallet.hotkey.ss58_address,
        expected_miner_uid=236,
        expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        current_round=bt.timelock.current_round(),
    )
    _manifest, manifest_bytes = EvidenceStore(case_root).load_manifest_with_bytes()
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    endpoint = FinalizedMinerEndpoint(
        hotkey=miner_wallet.hotkey.ss58_address,
        uid=236,
        origin="https://8.8.8.8:443",
        validator_permit=False,
        network="finney",
        genesis_block_hash=("0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"),
        finalized_block_number=99,
        finalized_block_hash="0x" + "44" * 32,
        finalized_block_timestamp_ms=1_788_609_600_123,
    )
    contacted = False

    async def fake_discovery(*_args, **_kwargs):
        return endpoint

    async def should_not_contact(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("miner was contacted")

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    monkeypatch.setattr(coordinator_module, "send_prepared_request", should_not_contact)

    with pytest.raises(ValueError, match="authorized manifest digest"):
        await run_public_endpoint_pilot(
            case_root,
            tmp_path / "wrong-case-result",
            wallet=validator_wallet,
            expected_case_manifest_sha256="00" * 32,
            expected_origin=endpoint.origin,
        )
    with pytest.raises(ValueError, match="miner-authorized origin"):
        await run_public_endpoint_pilot(
            case_root,
            tmp_path / "wrong-origin-result",
            wallet=validator_wallet,
            expected_case_manifest_sha256=manifest_sha256,
            expected_origin="https://8.8.4.4:443",
        )

    assert contacted is False
    assert not (tmp_path / "wrong-case-result").exists()
    assert not (tmp_path / "wrong-origin-result").exists()


@pytest.mark.asyncio
async def test_response_headroom_guard_runs_before_journal_or_miner_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_wallet = dev_wallet("//PublicPilotHeadroomValidator")
    miner_wallet = dev_wallet("//PublicPilotHeadroomMiner")
    case_root = tmp_path / "case"
    prepare_public_pilot_case(
        case_root,
        coordinator_hotkey=validator_wallet.hotkey.ss58_address,
        expected_miner_uid=236,
        expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        current_round=bt.timelock.current_round(),
        setup_allowance_seconds=30,
        response_window_seconds=30,
        reveal_margin_seconds=30,
    )
    endpoint = FinalizedMinerEndpoint(
        hotkey=miner_wallet.hotkey.ss58_address,
        uid=236,
        origin="https://8.8.8.8:443",
        validator_permit=False,
        network="finney",
        genesis_block_hash=("0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"),
        finalized_block_number=99,
        finalized_block_hash="0x" + "44" * 32,
        finalized_block_timestamp_ms=1_788_609_600_123,
    )
    contacted = False

    async def fake_discovery(*_args, **_kwargs):
        return endpoint

    async def should_not_contact(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("miner was contacted")

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    monkeypatch.setattr(coordinator_module, "send_prepared_request", should_not_contact)
    output = tmp_path / "result"
    with pytest.raises(ValueError, match="fewer than 300 seconds"):
        await run_public_endpoint_pilot(case_root, output, wallet=validator_wallet)

    assert contacted is False
    assert not output.exists()
    assert not (tmp_path / "result.incomplete").exists()


@pytest.mark.asyncio
async def test_attempt_started_callback_is_durable_and_can_abort_before_contact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_wallet, _miner_wallet, case_root, _truth, endpoint = _prepared_failure_case(tmp_path)
    contacted = False

    async def fake_discovery(*_args, **_kwargs):
        return endpoint

    async def should_not_contact(*_args, **_kwargs):
        nonlocal contacted
        contacted = True
        raise AssertionError("miner was contacted")

    def abort_after_durable_start(journal: Path) -> None:
        assert load_attempt_journal(journal).manifest.phase == "attempt_started"
        raise RuntimeError("state transition failed")

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    monkeypatch.setattr(coordinator_module, "send_prepared_request", should_not_contact)
    output = tmp_path / "result"
    with pytest.raises(RuntimeError, match="state transition failed"):
        await run_public_endpoint_pilot(
            case_root,
            output,
            wallet=validator_wallet,
            on_attempt_started=abort_after_durable_start,
        )

    assert contacted is False
    assert not output.exists()
    assert not (tmp_path / "result.incomplete").exists()


def _prepared_failure_case(
    tmp_path: Path,
) -> tuple[object, object, Path, object, FinalizedMinerEndpoint]:
    validator_wallet = dev_wallet("//PublicPilotFailureValidator")
    miner_wallet = dev_wallet("//PublicPilotFailureMiner")
    current_round = bt.timelock.current_round()
    _request, truth = build_public_pilot_inputs(
        current_round=current_round,
        setup_allowance_seconds=360,
        response_window_seconds=60,
        reveal_margin_seconds=30,
        entropy=lambda size: bytes([size]) * size,
    )
    case_root = tmp_path / "case"
    prepare_public_pilot_case(
        case_root,
        coordinator_hotkey=validator_wallet.hotkey.ss58_address,
        expected_miner_uid=236,
        expected_miner_hotkey=miner_wallet.hotkey.ss58_address,
        current_round=current_round,
        setup_allowance_seconds=360,
        response_window_seconds=60,
        reveal_margin_seconds=30,
        entropy=lambda size: bytes([size]) * size,
    )
    endpoint = FinalizedMinerEndpoint(
        hotkey=miner_wallet.hotkey.ss58_address,
        uid=236,
        origin="https://8.8.8.8:443",
        validator_permit=False,
        network="finney",
        genesis_block_hash=("0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"),
        finalized_block_number=99,
        finalized_block_hash="0x" + "44" * 32,
        finalized_block_timestamp_ms=1_788_609_600_123,
    )
    return validator_wallet, miner_wallet, case_root, truth, endpoint


@pytest.mark.asyncio
async def test_post_send_reveal_failure_preserves_non_feed_attempt_journal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    validator_wallet, _miner_wallet, case_root, _truth, endpoint = _prepared_failure_case(tmp_path)

    async def fake_discovery(*_args, **_kwargs):
        return endpoint

    async def failed_query(prepared, **_kwargs):
        started = load_attempt_journal(tmp_path / "result.incomplete" / "attempt-journal")
        assert started.manifest.phase == "attempt_started"
        assert started.request == prepared.request
        assert started.authentication_record == dict(prepared.auth_headers)
        return validator_module.QueryOutcome(
            request=prepared.request,
            auth_headers=dict(prepared.auth_headers),
            received_at_unix_ns=None,
            envelope_bytes=None,
            envelope=None,
            response_signature=None,
            sealed_response=None,
            failure_code="transport_error",
        )

    async def failed_reveal(*_args, **_kwargs):
        raise RuntimeError("injected reveal failure")

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    monkeypatch.setattr(coordinator_module, "send_prepared_request", failed_query)
    monkeypatch.setattr(coordinator_module, "_decrypt", failed_reveal)
    output = tmp_path / "result"
    with pytest.raises(ValueError, match="request timeout must be finite"):
        await run_public_endpoint_pilot(
            case_root,
            output,
            wallet=validator_wallet,
            request_timeout_seconds=float("nan"),
        )
    assert not (tmp_path / "result.incomplete").exists()

    with pytest.raises(RuntimeError, match="injected reveal failure"):
        await run_public_endpoint_pilot(case_root, output, wallet=validator_wallet)

    incomplete = tmp_path / "result.incomplete"
    journal_root = incomplete / "attempt-journal"
    verified = load_attempt_journal(journal_root)
    assert not output.exists()
    assert verified.manifest.schema_ == ATTEMPT_JOURNAL_SCHEMA
    assert verified.manifest.phase == "incomplete"
    assert verified.manifest.completed_through == "outcome_recorded"
    assert verified.manifest.failure_stage == "reveal_and_scoring"
    assert verified.query_outcome is not None
    journal_bytes = b"".join(
        path.read_bytes() for path in journal_root.rglob("*") if path.is_file()
    )
    assert ASSET_REFERENCES[0].encode() not in journal_bytes
    with pytest.raises(ValueError, match="bundle safety field"):
        validator_module.replay_bundle_detailed(journal_root)
    with pytest.raises(FileExistsError, match="incomplete"):
        await run_public_endpoint_pilot(case_root, output, wallet=validator_wallet)

    monkeypatch.setattr(
        sys,
        "argv",
        ["umi-public-pilot", "inspect-attempt", "--journal", str(journal_root)],
    )
    coordinator_module.main()
    inspection = json.loads(capsys.readouterr().out)
    assert inspection == {
        "activation_evidence": False,
        "announced_origin": endpoint.origin,
        "attempt_count": 1,
        "campaign_id": CAMPAIGN_ID,
        "completed_through": "outcome_recorded",
        "coordinator_hotkey": validator_wallet.hotkey.ss58_address,
        "expected_miner_uid": endpoint.uid,
        "failure_stage": "reveal_and_scoring",
        "feed_eligible": False,
        "finalized_block_hash": endpoint.finalized_block_hash,
        "finalized_block_number": endpoint.finalized_block_number,
        "finalized_block_timestamp_ms": endpoint.finalized_block_timestamp_ms,
        "genesis_block_hash": endpoint.genesis_block_hash,
        "journal_manifest_sha256": verified.manifest_sha256,
        "miner_hotkey": endpoint.hotkey,
        "network": "finney",
        "phase": "incomplete",
        "protocol_conformance": False,
        "replayable_score": False,
        "request_digest": validator_module.request_digest(verified.request),
        "schema": ATTEMPT_JOURNAL_SCHEMA,
        "status": "public_endpoint_attempt_journal_ok",
        "translation_weights_active": False,
        "validator_input_eligible": False,
    }


@pytest.mark.asyncio
async def test_attachment_failure_preserves_replayable_base_component_bundle(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    validator_wallet, _miner_wallet, case_root, truth, endpoint = _prepared_failure_case(tmp_path)

    async def fake_discovery(*_args, **_kwargs):
        return endpoint

    async def failed_query(prepared, **_kwargs):
        return validator_module.QueryOutcome(
            request=prepared.request,
            auth_headers=dict(prepared.auth_headers),
            received_at_unix_ns=None,
            envelope_bytes=None,
            envelope=None,
            response_signature=None,
            sealed_response=None,
            failure_code="transport_error",
        )

    async def revealed_truth(*_args, **_kwargs):
        return canonical_json_bytes(truth)

    def failed_attachment(*_args, **_kwargs):
        raise RuntimeError("injected attachment failure")

    monkeypatch.setattr(coordinator_module, "discover_miner_finalized", fake_discovery)
    monkeypatch.setattr(coordinator_module, "send_prepared_request", failed_query)
    monkeypatch.setattr(coordinator_module, "_decrypt", revealed_truth)
    monkeypatch.setattr(
        validator_module,
        "decrypt_response",
        lambda *_args, **_kwargs: canonical_json_bytes(truth),
    )
    monkeypatch.setattr(coordinator_module, "attach_public_endpoint_pilot", failed_attachment)
    output = tmp_path / "result"
    with pytest.raises(RuntimeError, match="injected attachment failure"):
        await run_public_endpoint_pilot(case_root, output, wallet=validator_wallet)

    incomplete = tmp_path / "result.incomplete"
    journal = load_attempt_journal(incomplete / "attempt-journal")
    base_root = incomplete / "base-component-bundle"
    replay = validator_module.replay_bundle_detailed(base_root)
    base_manifest_bytes = (base_root / "manifest.json").read_bytes()
    assert not output.exists()
    assert replay.manifest.get("public_endpoint_pilot") is None
    assert journal.manifest.phase == "incomplete"
    assert journal.manifest.completed_through == "base_component_complete"
    assert journal.manifest.failure_stage == "attachment"
    assert (
        journal.manifest.base_component_manifest_sha256
        == hashlib.sha256(base_manifest_bytes).hexdigest()
    )


def test_attempt_journal_load_enforces_fixed_campaign_and_shared_origin_validation(
    tmp_path: Path,
) -> None:
    validator_wallet = dev_wallet("//PublicPilotJournalValidator")
    miner_wallet = dev_wallet("//PublicPilotJournalMiner")
    request, _truth = build_public_pilot_inputs(
        current_round=bt.timelock.current_round(),
        entropy=lambda size: bytes([size]) * size,
    )
    raw = request.model_dump(mode="json", by_alias=True)
    raw["task"]["stratum"] = "short_utterance"
    noncampaign = TranslationRequest.model_validate(raw)
    prepared = validator_module.prepare_request_attempt(
        noncampaign,
        wallet=validator_wallet,
        miner_hotkey=miner_wallet.hotkey.ss58_address,
    )
    endpoint = FinalizedMinerEndpoint(
        hotkey=miner_wallet.hotkey.ss58_address,
        uid=236,
        origin="https://8.8.8.8:443",
        validator_permit=False,
        network="finney",
        genesis_block_hash=("0x2f0555cc76fc2840a25a6ea3b9637146806f1f44b090c175ffde2a7e5ab36c03"),
        finalized_block_number=99,
        finalized_block_hash="0x" + "44" * 32,
        finalized_block_timestamp_ms=1_788_609_600_123,
    )
    with pytest.raises(ValueError, match="public-pilot request"):
        PublicPilotAttemptJournal.start(
            tmp_path / "bad-profile",
            prepared=prepared,
            endpoint=endpoint,
            case_manifest_sha256="55" * 32,
        )

    fixed_prepared = validator_module.prepare_request_attempt(
        request,
        wallet=validator_wallet,
        miner_hotkey=miner_wallet.hotkey.ss58_address,
    )
    nonpublic_endpoint = replace(endpoint, origin="https://miner.example:443")
    with pytest.raises(ValueError, match="public endpoint origin"):
        PublicPilotAttemptJournal.start(
            tmp_path / "bad-origin",
            prepared=fixed_prepared,
            endpoint=nonpublic_endpoint,
            case_manifest_sha256="55" * 32,
        )

    another_miner = dev_wallet("//PublicPilotJournalOtherMiner").hotkey.ss58_address
    with pytest.raises(ValueError, match="another miner hotkey"):
        PublicPilotAttemptJournal.start(
            tmp_path / "wrong-miner",
            prepared=fixed_prepared,
            endpoint=replace(endpoint, hotkey=another_miner),
            case_manifest_sha256="55" * 32,
        )
    assert not (tmp_path / "wrong-miner").exists()

    with pytest.raises(ValueError, match="Finney genesis"):
        PublicPilotAttemptJournal.start(
            tmp_path / "wrong-genesis",
            prepared=fixed_prepared,
            endpoint=replace(endpoint, genesis_block_hash="0x" + "99" * 32),
            case_manifest_sha256="55" * 32,
        )
    assert not (tmp_path / "wrong-genesis").exists()

    with pytest.raises(ValueError, match="finney"):
        PublicPilotAttemptJournal.start(
            tmp_path / "wrong-network",
            prepared=fixed_prepared,
            endpoint=replace(endpoint, network="test"),  # type: ignore[arg-type]
            case_manifest_sha256="55" * 32,
        )
    assert not (tmp_path / "wrong-network").exists()

    journal = PublicPilotAttemptJournal.start(
        tmp_path / "invalid-phase",
        prepared=fixed_prepared,
        endpoint=endpoint,
        case_manifest_sha256="55" * 32,
    )
    invalid_phase = journal.manifest.model_dump(mode="json", by_alias=True)
    invalid_phase["phase"] = "outcome_recorded"
    invalid_phase["completed_through"] = "outcome_recorded"
    EvidenceStore(journal.root).write_manifest(invalid_phase)
    with pytest.raises(ValueError, match="outcome-recorded journal"):
        load_attempt_journal(journal.root)

    (journal.root / "manifest.json").write_text(
        json.dumps(journal.manifest.model_dump(mode="json", by_alias=True), indent=2)
    )
    with pytest.raises(ValueError, match="RFC 8785 canonical JSON"):
        load_attempt_journal(journal.root)
