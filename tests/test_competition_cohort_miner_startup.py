"""CLI-built miner serving native grants through public history and durable recovery.

History/assignment preparation, finality, clip bytes and inference are fixtures.
The normal parser, startup, authority, HTTP authentication and ledgers are real.
"""

from types import SimpleNamespace

import bittensor as bt
import httpx
import pytest
from fastapi import FastAPI

from umi import miner
from umi.competition_cohort_history_http import CohortHistoryExporter
from umi.competition_cohort_miner import CohortServiceMinerConfig
from umi.competition_cohort_miner_startup import CohortMinerStartupConfig
from umi.competition_cohort_public_history import PublicCohortHistoryClient, public_history_routes
from umi.endpoint_protocol import RESPONSE_RECOVERY_PATH
from umi.open_competition import digest, sign_object
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_miner import base_policy as base_policy
from .test_competition_cohort_miner import chain as chain
from .test_competition_cohort_miner import chain_config as chain_config
from .test_competition_cohort_miner import endpoint as endpoint
from .test_competition_cohort_miner import execution as execution
from .test_competition_cohort_miner import grant, request, translate
from .test_competition_cohort_miner import granted as granted
from .test_competition_cohort_miner import harness as harness
from .test_competition_cohort_miner import known_video_bytes as known_video_bytes
from .test_competition_cohort_miner import legacy_scenario as legacy_scenario
from .test_competition_cohort_miner import policy as policy
from .test_competition_cohort_miner import receipt_scenario as receipt_scenario
from .test_competition_cohort_miner import recovery as recovery
from .test_competition_cohort_miner import recovery_case as recovery_case
from .test_competition_cohort_miner import relay as relay
from .test_competition_cohort_miner import runtime as runtime
from .test_competition_cohort_miner import scenario as scenario
from .test_open_competition import wallet


def startup(p):
    return CohortMinerStartupConfig(
        schema="umi-cohort-miner-startup/1",
        authority=p.miner_cfg,
        history_origin="https://intake.example",
        history_owner_hotkey=wallet("Charlie").hotkey.ss58_address,
    )


@pytest.fixture
def built(granted, tmp_path, monkeypatch):
    p = granted
    c = startup(p)
    files = {}
    for name, value in (("competition-policy", p.c.policy), ("competition-cohort-config", c)):
        path = tmp_path / (name + ".json")
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(0o600)
        files[name] = str(path)
    args = miner._parser().parse_args(
        [
            "--wallet-name",
            "miner",
            "--hotkey",
            "hk",
            "--policy",
            "transport.json",
            "--target-triple",
            "aarch64-apple-darwin",
            "--finality-verifier-binary",
            "fixture",
            "--finality-chain-spec",
            "fixture",
            "--finality-state",
            str(tmp_path / "finality"),
            "--translator",
            "fixture:translator",
            "--video-origin",
            "https://clips.example",
            "--model-revision",
            p.miner.model_revision,
            "--serving-origin",
            c.authority.serving_origin,
            "--nonce-db",
            str(tmp_path / "nonce.sqlite3"),
            "--assignment-db",
            str(tmp_path / "assignments.sqlite3"),
            "--max-recovery-assignments",
            "4096",
            *[arg for name, value in files.items() for arg in ("--" + name, value)],
        ]
    )

    class Finality(miner.DurableGrandpaFinalityPort):
        def __init__(self):
            self.stopped = False

        async def finalized_head_height(self):
            return await p.finality.finalized_head_height()

        async def verified_block_at(self, height):
            return await p.finality.verified_block_at(height)

        async def run(self, stop):
            await stop.wait()
            self.stopped = True

    monkeypatch.setattr(miner, "_load_policy", lambda _: p.transport_policy)
    monkeypatch.setattr(bt, "Wallet", lambda **_: p.miner.wallet)
    monkeypatch.setattr(
        miner.DurableGrandpaFinalityPort, "from_policy", lambda *a, **kw: Finality()
    )
    monkeypatch.setattr(miner, "_build_translator", lambda *a, **kw: p.model)
    monkeypatch.setattr(miner, "HttpVideoFetcher", lambda **_: p.fetcher)
    p.startup_config, p.args = c, args
    p.build = lambda: miner.build_runtime(args)
    return p


async def test_normal_startup_serves_and_recovers_without_private_history_token(built, monkeypatch):
    p = built
    original = p.miner

    async def sign(body):
        return sign_object(body, wallet("Charlie"))

    cohort = p.miner_cfg.cohorts[0].cohort_sha256
    exporter = CohortHistoryExporter(
        SimpleNamespace(policy=p.c.policy, bindings={cohort: "fixture"}),
        wallet("Charlie").hotkey.ss58_address,
        sign,
    )
    source = await p.e.box.history(cohort)
    exporter.read = lambda _: source  # Prepared signed history is the explicit fixture boundary.
    state = SimpleNamespace(exporter=exporter)
    intake_app = FastAPI()
    intake_app.include_router(public_history_routes(lambda: state.exporter))
    seen = []

    async def route(wire):
        seen.append(wire)
        assert "authorization" not in wire.headers
        return await httpx.ASGITransport(intake_app).handle_async_request(wire)

    actual = PublicCohortHistoryClient.__init__

    def selected(self, origin, **kw):
        actual(self, origin, **kw, transport=httpx.MockTransport(route))

    monkeypatch.setattr(PublicCohortHistoryClient, "__init__", selected)

    p.miner = p.build()
    try:
        assert type(p.miner.competition_authority).__name__ == "CohortMinerAuthorizationAuthority"
        app = miner.create_app(p.miner)
        async with app.router.lifespan_context(app):
            state.exporter = None
            assert (await grant(p)).status_code == 503
            assert p.model.calls == 0
            state.exporter = exporter
            ack = await grant(p)
            assert ack.status_code == 200, ack.text
            result = await translate(p)
            assert result.status_code == 200, result.text
            assert p.model.calls == 1
        assert p.miner.finality_service.stopped
        p.miner.resource_ledger.close()
        p.miner = p.build()
        state.exporter = None
        async with miner.create_app(p.miner).router.lifespan_context(None):
            assert (await grant(p)).content == ack.content
            recovered = await request(p, RESPONSE_RECOVERY_PATH, p.requests[0])
            assert recovered.status_code == 200 and recovered.content == result.content
            assert p.model.calls == 1
        assert seen
    finally:
        p.miner.resource_ledger.close()
        p.miner = original


@pytest.mark.parametrize(
    "fault", ["policy", "transport", "hotkey", "revision", "origin", "owner", "directory"]
)
def test_startup_rejects_mismatched_scope_before_creating_grant_store(built, fault):
    p = built
    cfg = p.startup_config
    fields = {
        "policy": ("policy_sha256", "00" * 32),
        "transport": ("transport_policy_sha256", "00" * 32),
        "hotkey": ("miner_hotkey", wallet("Alice").hotkey.ss58_address),
        "revision": ("model_revision", "00" * 32),
        "origin": ("serving_origin", "https://other.example"),
        "directory": ("directory", p.args.assignment_db),
    }
    if fault == "owner":
        cfg = cfg.model_copy(update={"history_owner_hotkey": wallet("Bob").hotkey.ss58_address})
    else:
        field, value = fields[fault]
        cfg = cfg.model_copy(update={"authority": cfg.authority.model_copy(update={field: value})})
    from pathlib import Path

    Path(p.args.competition_cohort_config).write_bytes(canonical_json_bytes(cfg))
    with pytest.raises(ValueError, match="cohort"):
        p.build()


def test_service_terms_configuration_and_cli_exclusivity(built):
    p = built
    authority = CohortServiceMinerConfig.model_validate_json(
        canonical_json_bytes(
            {
                **p.miner_cfg.model_dump(by_alias=True),
                "schema": "umi-cohort-service-miner-config/1",
                "service_terms_sha256": "01" * 32,
            }
        )
    )
    parsed = CohortMinerStartupConfig.model_validate_json(
        canonical_json_bytes(p.startup_config.model_copy(update={"authority": authority}))
    )
    assert parsed.authority.service_terms_sha256 == "01" * 32
    assert parsed.authority.transport_policy_sha256 == scoring_policy_hash(p.transport_policy)
    assert parsed.authority.policy_sha256 == digest(p.c.policy)
    p.args.competition_feed = "https://other.example"
    with pytest.raises(ValueError, match="choose"):
        p.build()
    p.args.competition_feed = None
    p.args.max_recovery_assignments = 0
    with pytest.raises(ValueError, match="recovery capacity"):
        p.build()
