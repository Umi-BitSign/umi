"""Actual intake startup and native preparation; synthetic registration proofs."""

import asyncio
import socket
from pathlib import Path
from unittest.mock import AsyncMock

import httpx
import pytest

import umi.competition_cohort_admission_host as admission_boot
from umi.competition_cohort_history_http import CohortHistoryReader
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_public_history import PublicCohortHistoryClient
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_host import ServiceAdmissionHost, ServiceAdmissionHostConfig
from umi.competition_cohort_service_work import ServiceWorkClaim, SignedServiceWorkClaim
from umi.competition_finality_cache import VerifiedRegistrationCache
from umi.competition_service import CompetitionServiceConfig, create_intake_app
from umi.open_competition import digest, sign_object
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_lifecycle import intake as intake
from .test_competition_cohort_lifecycle import legacy_scenario as legacy_scenario
from .test_competition_cohort_lifecycle import lifecycle as lifecycle
from .test_competition_cohort_lifecycle import lifecycle_before_intake as lifecycle_before_intake
from .test_competition_cohort_lifecycle import policy as policy
from .test_competition_cohort_lifecycle import precommit_service_inventory
from .test_competition_cohort_lifecycle import recovery as recovery
from .test_competition_cohort_lifecycle import scenario as scenario
from .test_competition_service import Provider
from .test_competition_service import chain_config as chain_config
from .test_competition_service import config as config
from .test_competition_service import public_deployment as public_deployment
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize(
    "lifecycle_before_intake", [precommit_service_inventory], indirect=True
)


def host_config(h, root):
    _, manifest, series = h.precommitted
    return ServiceAdmissionHostConfig(
        schema="umi-cohort-service-admission-host/1",
        series=series,
        manifest=manifest,
        queue_directory=str(root / "queues"),
        inputs_directory=str(root / "inputs"),
        poll_seconds=1,
    )


async def prepare(h):
    service = h.reopen()
    for worker in h.admissions:
        await worker.poll_once()
    for _ in range(100):
        if h.store.status(h.cohort)[0].phase == "requests":
            break
        await service.tick()
        h.block += 5
    assert h.store.status(h.cohort)[0].phase == "requests"
    return h.owner.retained(
        h.cohort,
        expected_tip_sha256=h.store.status(h.cohort)[0].tip_sha256,
        current_block=h.block,
    )


def signed_claim(h, prepared, nonce=1):
    member = prepared.roster.participants[0]
    body = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256=digest(h.precommitted[0].catalog),
        hotkey=member.record.request.signed_submission.submission.hotkey,
        submission_sha256=digest(member.record.request.signed_submission.submission),
        nonce=f"{nonce:064x}",
    )
    return SignedServiceWorkClaim(claim=body, signature=sign_object(body, wallet("Alice")))


async def test_host_waits_for_certified_preparation_then_recovers_original_queue(
    lifecycle, tmp_path
):
    h = lifecycle
    cfg = host_config(h, tmp_path / "host")

    def start():
        return ServiceAdmissionHost(
            cfg, h.intake, h.owner.promotion, h.provider.collect, h.provider.retained_archive
        )

    host = start()
    key = digest(h.precommitted[0].catalog)
    assert (await host.poll_once())["catalogs_pending"] == 1
    path = Path(cfg.inputs_directory) / "catalogs" / (key + ".json")
    publish_private_model(path, h.precommitted[0])
    assert (await host.poll_once())["catalogs_installed"] == 0
    assert not host.retained_registration_blocks()
    prepared = await prepare(h)
    assert (await host.poll_once())["catalogs_installed"] == 1
    claim = signed_claim(h, prepared)
    receipt = await host.api.admit(key, claim)
    assert receipt["status"] == "accepted"
    assert host.queues[key].assignment(claim).round == prepared.roster.round
    assert host.retained_registration_blocks() == frozenset({h.block})
    path.unlink()
    h.offline = True
    host = start()
    assert (await host.poll_once())["catalogs_installed"] == 1
    assert await host.api.admit(key, claim) == receipt
    assert h.precommitted_bytes == tuple(canonical_json_bytes(v) for v in h.precommitted)


async def test_host_coalesces_fresh_reads_and_delegates_historical_finality(lifecycle, tmp_path):
    h = lifecycle
    capture = AsyncMock(side_effect=h.provider.collect)
    host = ServiceAdmissionHost(
        host_config(h, tmp_path / "host"),
        h.intake,
        h.owner.promotion,
        capture,
        h.provider.retained_archive,
        provider=h.provider,
    )

    observed = await host.finality.collect()

    assert observed.snapshot.block == h.block
    capture.assert_awaited_once_with()
    assert host.finality.retained_archive.__self__ is h.provider


@pytest.mark.parametrize("automatic_admission", [False, True])
async def test_intake_startup_installs_catalog_and_serves_claims_without_another_process(
    lifecycle, config, tmp_path, monkeypatch, automatic_admission
):
    h = lifecycle
    cfg = host_config(h, tmp_path / "host")
    if automatic_admission:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        owner = admission_boot.AdmissionOwnerConfig(
            schema="umi-cohort-admission-owner/1",
            directory=str(tmp_path / "private-owner"),
            owner_hotkey=wallet("Charlie").hotkey.ss58_address,
            owner_key_file=str(tmp_path / "owner-key"),
            export_token_file=str(tmp_path / "export-token"),
            listen_port=port,
            reviewers=tuple(
                CohortReviewPeerConfig(
                    signer=wallet(name).hotkey.ss58_address,
                    origin=f"https://{name.lower()}.example",
                    token_file=str(tmp_path / f"{name}-token"),
                )
                for name in ("Charlie", "Dave")
            ),
        )
        cfg = cfg.model_copy(
            update={
                "schema_": "umi-cohort-service-admission-host/4",
                "admission_owner": owner,
            }
        )
        monkeypatch.setattr(admission_boot, "load_named_hotkey", lambda *_: wallet("Charlie"))
        monkeypatch.setattr(
            admission_boot,
            "_token",
            lambda p: "export-" * 10 if p == owner.export_token_file else "vote-" * 10,
        )
    config = config.model_copy(
        update={
            "schema_": "umi-competition-service-config/3",
            "recoverable_intake": h.intake.config,
            "recoverable_service": cfg,
        }
    )
    key = digest(h.precommitted[0].catalog)
    path = Path(cfg.inputs_directory) / "catalogs" / (key + ".json")
    publish_private_model(path, h.precommitted[0])
    prepared = await prepare(h)
    provider = Provider(config.chain, h.intake.policy)

    async def capture():
        assert provider.started and not provider.closed
        if h.offline:
            raise OSError("synthetic RPC offline")
        return h.capture(h.block)

    provider.collect = capture
    provider.policy = h.intake.policy
    provider.ensure_observer_running = lambda: None  # Synthetic finality provider.
    provider.retained_archive = h.provider.retained_archive
    app = create_intake_app(config, h.intake.policy, provider_factory=lambda *_: provider)
    async with app.router.lifespan_context(app):
        host = app.state.service_admission_host

        async def installed():
            while host.queues[key].journal.get("service_catalog", key) is None:
                await asyncio.sleep(0.01)

        await asyncio.wait_for(installed(), timeout=10)
        if automatic_admission:

            async def private_started():
                async with httpx.AsyncClient(trust_env=False) as client:
                    while True:
                        try:
                            response = await client.post(
                                f"http://127.0.0.1:{port}/internal/cohorts/admission-history",
                                json={},
                            )
                            assert response.status_code == 401
                            return
                        except httpx.ConnectError:
                            await asyncio.sleep(0.02)

            await asyncio.wait_for(private_started(), timeout=10)
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://intake.example"
        ) as client:
            authority_url = f"/v1/competition/cohorts/{h.cohort}/authority"
            if automatic_admission:

                async def public_started():
                    while host.history_exporter is None:
                        await asyncio.sleep(0.01)

                await asyncio.wait_for(public_started(), timeout=10)
                reader = CohortHistoryReader(
                    owner.owner_hotkey,
                    PublicCohortHistoryClient(
                        "https://intake.example",
                        timeout_seconds=10,
                        transport=httpx.ASGITransport(app=app),
                    ),
                )
                history = await reader(h.cohort)
                assert history_tip(history.history) == h.store.status(h.cohort)[0].tip_sha256
            else:
                response = await client.get(authority_url, params={"challenge": "01" * 32})
                assert response.status_code == 503
            index = await client.get("/v1/competition/service-work")
            assert index.status_code == 200, index.text
            assert len(index.json()["catalogs"]) == 1
            claim = signed_claim(h, prepared)
            url = f"/v1/competition/service-work/{key}/claims"
            reply = await client.post(
                url,
                content=canonical_json_bytes(claim),
                headers={"Content-Type": "application/json"},
            )
            assert reply.status_code == 200, reply.text
            receipt = reply.json()
            assert receipt["status"] == "accepted"
            h.offline = True
            again = await client.post(
                url,
                content=canonical_json_bytes(claim),
                headers={"Content-Type": "application/json"},
            )
            assert again.json() == receipt
    assert provider.closed
    assert host.history_exporter is None


@pytest.mark.parametrize("cache_error", [False, True])
async def test_failed_worker_still_closes_cache_and_provider(
    lifecycle, config, tmp_path, monkeypatch, cache_error
):
    h = lifecycle
    config = config.model_copy(
        update={
            "schema_": "umi-competition-service-config/3",
            "recoverable_intake": h.intake.config,
            "recoverable_service": host_config(h, tmp_path / "host"),
        }
    )
    provider = Provider(config.chain, h.intake.policy)
    provider.retained_archive = h.provider.retained_archive
    failed, closed = asyncio.Event(), asyncio.Event()
    original_close = VerifiedRegistrationCache.aclose

    async def fail_worker(self, stop):
        failed.set()
        raise RuntimeError("worker failed")

    async def close_cache(self):
        await original_close(self)
        closed.set()
        if cache_error:
            raise OSError("cache close failed")

    monkeypatch.setattr(ServiceAdmissionHost, "run", fail_worker)
    monkeypatch.setattr(VerifiedRegistrationCache, "aclose", close_cache)
    app = create_intake_app(config, h.intake.policy, provider_factory=lambda *_: provider)
    expected = OSError if cache_error else RuntimeError
    with pytest.raises(expected, match="cache close failed" if cache_error else "worker failed"):
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(failed.wait(), 5)
    assert closed.is_set() and provider.closed


async def test_service_routes_have_separate_claim_readiness_and_read_capacity(
    lifecycle, config, tmp_path, monkeypatch
):
    h = lifecycle
    config = config.model_copy(
        update={
            "schema_": "umi-competition-service-config/3",
            "recoverable_intake": h.intake.config,
            "recoverable_service": host_config(h, tmp_path / "host"),
            "api_limits": config.api_limits.model_copy(
                update={
                    "maximum_concurrent_submissions": 1,
                    "maximum_concurrent_readiness": 1,
                    "maximum_concurrent_reads": 1,
                    "capacity_wait_seconds": 0.02,
                }
            ),
        }
    )
    provider = Provider(config.chain, h.intake.policy)
    provider.retained_archive = h.provider.retained_archive
    app = create_intake_app(config, h.intake.policy, provider_factory=lambda *_: provider)
    api = app.state.service_admission_host.api
    key = digest(h.precommitted[0].catalog)
    ready_entered, claim_entered, release = (asyncio.Event() for _ in range(3))

    async def held_readiness(catalog, nonce):
        ready_entered.set()
        await release.wait()
        return {"ready": False}

    async def held_claim(catalog, signed):
        claim_entered.set()
        await release.wait()
        return {"status": "accepted"}

    monkeypatch.setattr(api, "readiness", held_readiness)
    monkeypatch.setattr(api, "admit", held_claim)
    body = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256=key,
        hotkey=wallet("Alice").hotkey.ss58_address,
        submission_sha256="00" * 32,
        nonce="01" * 32,
    )
    signed = SignedServiceWorkClaim(claim=body, signature=sign_object(body, wallet("Alice")))
    base = "/v1/competition/service-work"
    ready_url = f"{base}/{key}/readiness?nonce={'01' * 16}"
    claim_url = f"{base}/{key}/claims"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="https://intake.example",
        headers={"Content-Type": "application/json"},
    ) as client:
        tasks = [asyncio.create_task(client.get(ready_url))]
        try:
            await asyncio.wait_for(ready_entered.wait(), 5)
            assert (await client.get(ready_url)).status_code == 503
            assert (await client.get(base)).status_code == 200
            tasks.append(
                asyncio.create_task(client.post(claim_url, content=canonical_json_bytes(signed)))
            )
            await asyncio.wait_for(claim_entered.wait(), 5)
            assert (
                await client.post(claim_url, content=canonical_json_bytes(signed))
            ).status_code == 503
            assert (await client.get(base)).status_code == 200
        finally:
            release.set()
            replies = await asyncio.gather(*tasks)
        assert all(reply.status_code == 200 for reply in replies)


@pytest.mark.parametrize("damage", ["version", "missing_intake", "overlap", "policy"])
def test_service_startup_rejects_unbound_or_overlapping_selection(
    lifecycle, config, tmp_path, damage
):
    h = lifecycle
    cfg = host_config(h, tmp_path / "host")
    updates = dict(
        schema_="umi-competition-service-config/3",
        recoverable_intake=h.intake.config,
        recoverable_service=cfg,
    )
    if damage == "version":
        updates["schema_"] = "umi-competition-service-config/2"
    elif damage == "missing_intake":
        updates["recoverable_intake"] = None
    elif damage == "overlap":
        updates["recoverable_service"] = cfg.model_copy(
            update={"queue_directory": config.state_directory}
        )
    else:
        updates["recoverable_service"] = cfg.model_copy(
            update={"series": cfg.series.model_copy(update={"policy_sha256": "00" * 32})}
        )
    with pytest.raises(ValueError):
        CompetitionServiceConfig.model_validate_json(
            canonical_json_bytes(config.model_copy(update=updates))
        )
