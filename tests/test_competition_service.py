from __future__ import annotations

from dataclasses import replace

import httpx
import pytest
from fastapi.testclient import TestClient

from umi.competition_chain import RegistrationCapture
from umi.competition_service import CompetitionServiceConfig, create_intake_app, serve_intake
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_chain import chain_config as chain_config
from .test_open_competition import policy as policy
from .test_open_competition import snapshot, submission


@pytest.fixture
def config(chain_config, tmp_path, policy):
    return CompetitionServiceConfig(
        schema="umi-competition-service-config/1",
        mode="intake_no_weight",
        policy_sha256=digest(policy),
        state_directory=str(tmp_path / "intake"),
        chain=chain_config,
    )


class Provider:
    def __init__(self, _config, _policy):
        self.started = False
        self.closed = False
        self.error = None
        snap = snapshot()
        self.capture = RegistrationCapture(
            snapshot=snap,
            provenance={
                "schema": "umi-competition-registration-provenance/1",
                "evidence_class": "verifier_attested_finality",
                "offline_finality_proof": False,
                "genesis_block_hash": "0x" + "11" * 32,
                "block": snap.block,
                "block_hash": snap.block_hash,
                "state_root": "0x" + "22" * 32,
                "timestamp_ms": 1800000000000,
                "snapshot_sha256": digest(snap),
                "evidence_sha256": "33" * 32,
                "metadata_sha256": "44" * 32,
                "finality_evidence_sha256": "55" * 32,
                "finality_verifier_sha256": "66" * 32,
                "storage_proof_verifier_sha256": "77" * 32,
                "chain_submission_authorized": False,
                "private_path": "/PRIVATE/STATE",
                "rpc_url": "wss://PRIVATE.example",
            },
        )

    async def start(self):
        self.started = True
        if self.error:
            raise self.error

    async def collect(self):
        assert self.started and not self.closed
        if self.error:
            raise self.error
        return self.capture

    async def __call__(self):
        return (await self.collect()).snapshot

    async def aclose(self):
        self.closed = True


def app_for(config, policy):
    provider = Provider(config.chain, policy)
    app = create_intake_app(config, policy, provider_factory=lambda *_: provider)
    assert not provider.started
    return app, provider


def test_lifecycle_readiness_and_real_admission(config, policy):
    app, provider = app_for(config, policy)
    with TestClient(app) as client:
        response = client.get("/v1/competition/readiness")
        assert response.status_code == 200
        data = response.json()
        assert data["ready_for"] == "signed_submission_rehearsal"
        assert not data["evaluation_ready"]
        assert not data["rewards_active"]
        assert not data["chain_submission_authorized"]
        assert data["registration_count"] == 2
        assert "PRIVATE" not in response.text
        signed = submission(policy)
        receipt = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert receipt.status_code == 200
        assert receipt.json()["registration_snapshot_sha256"] == digest(snapshot())
        assert receipt.json()["status"] == "accepted_no_weight"
        assert receipt.json()["registration_source"] == "verifier_attested_finality"
        status = client.get("/v1/competition/status").json()
        assert status["mode"] == "intake_no_weight"
    assert provider.closed


def test_startup_failure_closes_provider(config, policy):
    app, provider = app_for(config, policy)
    provider.error = RuntimeError("observer startup failed")
    with pytest.raises(RuntimeError, match="startup"), TestClient(app):
        pytest.fail("startup failure must not serve intake")
    assert provider.closed


@pytest.mark.parametrize("route", ["readiness", "submissions"])
def test_failed_proofs_never_accept_and_hide_private_details(config, policy, route):
    app, provider = app_for(config, policy)
    with TestClient(app) as client:
        provider.error = RuntimeError("PRIVATE RPC OR PATH")
        if route == "readiness":
            reply = client.get("/v1/competition/readiness")
        else:
            reply = client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(submission(policy)),
                headers={"content-type": "application/json"},
            )
        assert reply.status_code == 503
        assert "PRIVATE" not in reply.text


@pytest.mark.parametrize(
    "change",
    [
        {"snapshot_sha256": "00" * 32},
        {"block": 111},
        {"block_hash": "0x" + "00" * 32},
        {"offline_finality_proof": True},
        {"chain_submission_authorized": True},
        {"evidence_class": "rpc_finalized_label"},
        {"schema": "other"},
    ],
)
def test_readiness_rejects_bad_provenance(config, policy, change):
    app, provider = app_for(config, policy)
    provider.capture.provenance.update(change)
    with TestClient(app) as client:
        assert client.get("/v1/competition/readiness").status_code == 503


def test_readiness_requires_complete_provenance(config, policy):
    app, provider = app_for(config, policy)
    del provider.capture.provenance["evidence_sha256"]
    with TestClient(app) as client:
        assert client.get("/v1/competition/readiness").status_code == 503


def test_expired_policy_holds_readiness_and_admission(config, policy):
    app, provider = app_for(config, policy)
    provider.capture = replace(provider.capture, snapshot=snapshot(block=1001))
    with TestClient(app) as client:
        assert client.get("/v1/competition/readiness").status_code == 503
        assert (
            client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(submission(policy)),
                headers={"content-type": "application/json"},
            ).status_code
            == 503
        )


@pytest.mark.parametrize(
    "change",
    [
        {"host": "0.0.0.0"},
        {"state_directory": "/"},
        {"state_directory": "relative"},
        {"wallet_name": "forbidden"},
        {"mode": "live_weights"},
        {"port": 80},
        {"policy_sha256": "00" * 32},
    ],
)
def test_config_rejects_unsafe_or_unbound_fields(config, change):
    raw = config.model_dump(mode="json", by_alias=True)
    raw.update(change)
    with pytest.raises(ValueError):
        CompetitionServiceConfig.model_validate_json(canonical_json_bytes(raw))


@pytest.mark.parametrize("relative", [".", "inside", ".."])
def test_config_disallows_overlapping_state(config, relative):
    from pathlib import Path

    raw = config.model_dump(mode="json", by_alias=True)
    raw["state_directory"] = str((Path(config.chain.state_directory) / relative).resolve())
    with pytest.raises(ValueError, match="overlap"):
        CompetitionServiceConfig.model_validate_json(canonical_json_bytes(raw))


def test_config_proof_deadline_fits_request_timeout(config):
    raw = config.model_dump(mode="json", by_alias=True)
    raw["chain"]["collection_timeout_seconds"] = 16
    with pytest.raises(ValueError, match="15 seconds"):
        CompetitionServiceConfig.model_validate_json(canonical_json_bytes(raw))


def test_serve_intake_uses_one_loopback_worker_without_proxy_trust(config, policy, monkeypatch):
    calls = []
    app = object()
    monkeypatch.setattr("umi.competition_service.create_intake_app", lambda *_: app)
    monkeypatch.setattr(
        "umi.competition_service_supervision.serve_with_finality_supervision",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )
    serve_intake(config, policy)
    assert calls == [
        (
            (app,),
            {
                "host": "127.0.0.1",
                "port": 8098,
                "workers": 1,
                "proxy_headers": False,
                "access_log": False,
                "limit_concurrency": 64,
                "backlog": 128,
            },
        )
    ]


async def test_client_verified_service_retries_without_personal_credentials(config, policy):
    from umi.competition_client import submit_signed_submission

    app, provider = app_for(config, policy)
    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        signed = submission(policy)
        first = await submit_signed_submission(
            origin="https://intake.example", policy=policy, signed=signed, transport=transport
        )
        second = await submit_signed_submission(
            origin="https://intake.example", policy=policy, signed=signed, transport=transport
        )
        assert first == second
    assert provider.closed


def test_authenticated_historical_retry_survives_proof_outage(config, policy):
    app, provider = app_for(config, policy)
    signed = submission(policy)
    with TestClient(app) as client:
        original = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert original.status_code == 200
        provider.error = RuntimeError("PRIVATE PROOF FAILURE")
        retry = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(signed),
            headers={"content-type": "application/json"},
        )
        assert retry.status_code == 200
        assert retry.json() == original.json()
        assert client.get("/v1/competition/readiness").status_code == 503
        new_request = client.post(
            "/v1/competition/submissions",
            content=canonical_json_bytes(submission(policy, name="Bob")),
            headers={"content-type": "application/json"},
        )
        assert new_request.status_code == 503
        bad_signature = signed.model_copy(
            update={
                "signature": signed.signature.model_copy(update={"signature": "0x" + "00" * 64}),
            }
        )
        assert (
            client.post(
                "/v1/competition/submissions",
                content=canonical_json_bytes(bad_signature),
                headers={"content-type": "application/json"},
            ).status_code
            == 422
        )
