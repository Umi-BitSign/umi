"""Host lifecycle and immutable selection; finality and key loading are substituted."""

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_cohort_review_boot as boot
from umi import competition_cohort_review_cli as cli
from umi.competition_cohort_admission_journal import CohortAdmissionSignerConfig
from umi.competition_cohort_benchmark_host import BenchmarkHostConfig
from umi.competition_cohort_clip_delivery import ClipDeliveryConfig
from umi.competition_cohort_endpoint_decision_signer import CohortEndpointDecisionConfig
from umi.competition_cohort_endpoint_host import EndpointHostConfig
from umi.competition_cohort_execution_journal import CohortExecutionConfig
from umi.competition_cohort_intake import CohortIntakeBinding
from umi.competition_cohort_model_review import ModelReviewConfig
from umi.competition_cohort_order_inbox import CohortOrderInboxConfig
from umi.competition_cohort_order_signer import CohortOrderSignerConfig
from umi.competition_cohort_progress_signer import CohortProgressSignerConfig
from umi.competition_cohort_request_signer import EndpointRequestSignerConfig
from umi.competition_cohort_review_config import PhaseReviewServiceConfig, load_phase_review_config
from umi.competition_cohort_review_http import CohortReviewPeerConfig
from umi.competition_cohort_service_review import ServiceReviewConfig
from umi.open_competition import digest, identity
from umi.private_files import lock_private_file
from umi.protocol import canonical_json_bytes

from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case
from .test_open_competition import wallet


def config_for(value, root):
    return PhaseReviewServiceConfig(
        schema="umi-cohort-phase-review-service/1",
        series=value.series,
        policy=value.policy,
        manifest=value.manifest,
        chain=value.chain,
        signing=CohortProgressSignerConfig(
            schema="umi-cohort-progress-signer-config/1",
            directory=str(root / "signing"),
            policy_sha256=digest(value.policy),
            signer=wallet("Dave").hotkey.ss58_address,
            cohorts=tuple(
                CohortIntakeBinding(
                    cohort_sha256=key, authority_sha256=digest(value.series.recovery.authority)
                )
                for key in sorted(digest(p) for p in value.series.cohorts)
            ),
        ),
        signer_key_file=str(root / "secrets" / "key"),
        owner_hotkey=wallet("Charlie").hotkey.ss58_address,
        owner_origin="https://coordinator.example",
        owner_token_file=str(root / "secrets" / "owner-token"),
        vote_token_file=str(root / "secrets" / "vote-token"),
        inputs_directory=str(root / "inputs"),
        promotion_directory=str(root / "promotions"),
        proof_import_directory=str(root / "proofs"),
        eligible_tracks=("endpoint",),
        listen_port=19578,
    )


@pytest.fixture
def selected(inputs, tmp_path):
    config = config_for(inputs.value, tmp_path / "review")
    Path(config.owner_token_file).parent.mkdir(parents=True)
    for path, token in (
        (config.owner_token_file, "owner-token" * 4),
        (config.vote_token_file, "vote-token" * 4),
    ):
        Path(path).write_text(token + "\n")
        Path(path).chmod(0o440)
    inputs.config = config
    inputs.save(inputs.path, canonical_json_bytes(config))
    return inputs


def test_exact_root_config_and_cli_check_without_loading_keys(selected, capsys):
    assert load_phase_review_config(selected.path) == selected.config
    cli.main(["check", "--config", str(selected.path)])
    assert json.loads(capsys.readouterr().out)["runtime_qualified"] is False
    selected.save(selected.path, b" " + canonical_json_bytes(selected.config))
    with pytest.raises(ValueError, match="canonical"):
        load_phase_review_config(selected.path)


def with_service(config):
    signing = ServiceReviewConfig(
        schema="umi-service-review-config/1",
        directory=config.signing.directory + "-service",
        policy_sha256=digest(config.policy),
        signer=config.signing.signer,
        owner=config.owner_hotkey,
        cohorts=config.signing.cohorts,
    )
    return PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            config.model_copy(
                update={"schema_": "umi-cohort-phase-review-service/2", "service_signing": signing}
            )
        )
    )


def with_admission(config):
    signing = CohortAdmissionSignerConfig(
        schema="umi-cohort-admission-signer-config/1",
        directory=config.signing.directory + "-admission",
        policy_sha256=digest(config.policy),
        signer=config.signing.signer,
        cohorts=config.signing.cohorts,
    )
    return PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            config.model_copy(
                update={
                    "schema_": "umi-cohort-phase-review-service/3",
                    "admission_signing": signing,
                },
            )
        )
    )


def with_models(config):
    config = with_admission(config)
    signing = ModelReviewConfig(
        schema="umi-cohort-model-review-config/1",
        directory=config.signing.directory + "-models",
        approvals_directory=config.signing.directory + "-approvals",
        archive_directory=config.signing.directory + "-artifacts",
        policy_sha256=digest(config.policy),
        signer=config.signing.signer,
        cohorts=config.signing.cohorts,
    )
    return PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            config.model_copy(
                update={
                    "schema_": "umi-cohort-phase-review-service/4",
                    "model_signing": signing,
                    "eligible_tracks": ("endpoint", "model"),
                }
            )
        )
    )


def with_benchmark(config):
    config = with_models(config)
    common = dict(
        policy_sha256=digest(config.policy),
        signer=config.signing.signer,
        cohorts=config.signing.cohorts,
    )
    base = config.signing.directory
    benchmark = BenchmarkHostConfig(
        schema="umi-cohort-benchmark-host/1",
        directory=base + "-benchmark",
        orders=CohortOrderSignerConfig(
            schema="umi-cohort-order-signer-config/1", directory=base + "-orders", **common
        ),
        inbox=CohortOrderInboxConfig(
            schema="umi-cohort-order-inbox-config/1", directory=base + "-inbox", **common
        ),
        execution=CohortExecutionConfig(
            schema="umi-cohort-execution-config/1", directory=base + "-execution", **common
        ),
        archive_directory=config.model_signing.archive_directory,
        videos_directory=base + "-videos",
        workspace_directory=base + "-workspace",
        request_export_directory=base + "-exports",
    )
    return PhaseReviewServiceConfig.model_validate_json(
        canonical_json_bytes(
            config.model_copy(
                update={"schema_": "umi-cohort-phase-review-service/5", "benchmark": benchmark}
            )
        )
    )


@pytest.mark.parametrize("fault", ["missing", "version", "signer", "scope", "overlap", "archive"])
def test_benchmark_host_binds_orders_execution_and_private_stores(selected, fault):
    c = with_benchmark(selected.config)
    if fault == "missing":
        c = c.model_copy(update={"benchmark": None})
    elif fault == "version":
        c = c.model_copy(update={"schema_": "umi-cohort-phase-review-service/4"})
    else:
        benchmark = c.benchmark
        if fault in ("signer", "scope"):
            changes = {"signer": c.owner_hotkey} if fault == "signer" else {"cohorts": ()}
            benchmark = benchmark.model_copy(
                update={"execution": benchmark.execution.model_copy(update=changes)}
            )
        elif fault == "overlap":
            benchmark = benchmark.model_copy(update={"videos_directory": c.signing.directory})
        else:
            benchmark = benchmark.model_copy(
                update={
                    "directory": c.model_signing.archive_directory,
                    "archive_directory": c.signing.directory + "-other-archive",
                }
            )
        c = c.model_copy(update={"benchmark": benchmark})
    with pytest.raises(ValueError):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(c))


async def test_benchmark_boot_routes_exclusive_execution_and_restart(selected, providers):
    c = with_benchmark(selected.config)
    for _ in range(2):
        async with boot.phase_review_app(c) as app:
            assert app.state.benchmark is not None
            with pytest.raises(BlockingIOError):
                os.close(lock_private_file(Path(c.benchmark.directory) / "service.lock"))
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://review.example"
            ) as client:
                for path in ("votes/lookup", "votes/attest", "inbox/lookup", "inbox/accept"):
                    assert (
                        await client.post("/internal/cohorts/orders/" + path, json={})
                    ).status_code == 401
    assert providers.events.count("started") == providers.events.count("closed") == 2
    os.close(lock_private_file(Path(c.benchmark.directory) / "service.lock"))


@pytest.mark.parametrize("fault", ["missing", "version", "signer", "policy", "tracks", "overlap"])
def test_model_review_host_preserves_signer_scope_and_private_stores(selected, fault):
    c = with_models(selected.config)
    if fault == "missing":
        c = c.model_copy(update={"model_signing": None})
    elif fault == "version":
        c = c.model_copy(update={"schema_": "umi-cohort-phase-review-service/3"})
    elif fault == "tracks":
        c = c.model_copy(update={"eligible_tracks": ("endpoint",)})
    else:
        update = {
            "signer": {"signer": c.owner_hotkey},
            "policy": {"policy_sha256": "ff" * 32},
            "overlap": {"directory": c.proof_import_directory},
        }[fault]
        c = c.model_copy(update={"model_signing": c.model_signing.model_copy(update=update)})
    with pytest.raises(ValueError):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(c))


async def test_configured_model_review_route_survives_host_restart(selected, providers):
    c = with_models(selected.config)
    for _ in range(2):
        async with (
            boot.phase_review_app(c) as app,
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app), base_url="https://review.example"
            ) as client,
        ):
            url = "/internal/cohorts/model-artifacts/votes"
            assert (await client.post(url, json={})).status_code == 401
            assert (
                await client.post(
                    url, json={}, headers={"authorization": "Bearer " + "vote-token" * 4}
                )
            ).status_code == 422
    assert providers.events.count("started") == providers.events.count("closed") == 2


@pytest.mark.parametrize("version", [1, 2])
def test_older_host_canonical_bytes_omit_admission_configuration(selected, version):
    c = selected.config if version == 1 else with_service(selected.config)
    raw = canonical_json_bytes(c)
    assert "admission_signing" not in json.loads(raw)
    assert "model_signing" not in json.loads(raw)
    assert canonical_json_bytes(PhaseReviewServiceConfig.model_validate_json(raw)) == raw


@pytest.mark.parametrize(
    "failure", ["version", "missing", "signer", "cohorts", "policy", "overlap"]
)
def test_admission_host_rejects_changed_authority_and_shared_state(selected, failure):
    c = with_admission(selected.config)
    if failure == "version":
        c = c.model_copy(update={"schema_": "umi-cohort-phase-review-service/1"})
    elif failure == "missing":
        c = c.model_copy(update={"admission_signing": None})
    else:
        changes = {
            "signer": {"signer": c.owner_hotkey},
            "cohorts": {"cohorts": c.signing.cohorts[:1]},
            "policy": {"policy_sha256": "ff" * 32},
            "overlap": {"directory": c.proof_import_directory},
        }
        c = c.model_copy(
            update={"admission_signing": c.admission_signing.model_copy(update=changes[failure])}
        )
    with pytest.raises(ValueError):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(c))


@pytest.mark.parametrize("service", [False, True])
async def test_admission_host_mounts_private_route_and_preserves_selection(
    selected, providers, service
):
    c = with_admission(with_service(selected.config) if service else selected.config)
    for _ in range(2):
        async with (
            boot.phase_review_app(c) as app,
            httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="https://local",
            ) as client,
        ):
            assert (
                await client.post("/internal/cohorts/admission/votes", json={})
            ).status_code == 401
            assert (
                await client.post(
                    "/internal/cohorts/admission/votes",
                    json={},
                    headers={"authorization": "Bearer " + "vote-token" * 4},
                )
            ).status_code == 422
    assert providers.events.count("started") == providers.events.count("closed") == 2


def test_v1_canonical_bytes_omit_new_optional_service_configuration(selected):
    raw = canonical_json_bytes(selected.config)
    assert "service_signing" not in json.loads(raw)
    assert canonical_json_bytes(PhaseReviewServiceConfig.model_validate_json(raw)) == raw


@pytest.mark.parametrize(
    "fault", ["version", "missing", "owner", "signer", "cohorts", "policy", "overlap"]
)
def test_service_review_configuration_keeps_original_host_authority(selected, fault):
    c = with_service(selected.config)
    if fault == "version":
        c = c.model_copy(update={"schema_": "umi-cohort-phase-review-service/1"})
    elif fault == "missing":
        c = c.model_copy(update={"service_signing": None})
    else:
        changed = {
            "owner": {"owner": wallet("Dave").hotkey.ss58_address},
            "signer": {"signer": wallet("Charlie").hotkey.ss58_address},
            "cohorts": {"cohorts": c.signing.cohorts[:1]},
            "policy": {"policy_sha256": "ff" * 32},
            "overlap": {"directory": c.signing.directory},
        }[fault]
        c = c.model_copy(update={"service_signing": c.service_signing.model_copy(update=changed)})
    with pytest.raises(ValueError):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(c))


async def test_service_review_boot_registers_private_routes_without_future_inputs(
    selected, providers
):
    c = with_service(selected.config)
    async with (
        boot.phase_review_app(c) as app,
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://local"
        ) as client,
    ):
        for kind in ("request", "retry"):
            path = f"/internal/cohorts/service/votes/{kind}"
            assert (await client.post(path, json={})).status_code == 401
            assert (
                await client.post(
                    path, json={}, headers={"authorization": "Bearer " + "vote-token" * 4}
                )
            ).status_code == 422
    assert providers.events[-1] == "closed"


def test_cli_reports_phase_failure_without_private_exception_text(selected, monkeypatch, capsys):
    from umi.competition_progress import progress_phase

    async def failed(config):
        with progress_phase("cohort_progress_vote"):
            raise ValueError("PRIVATE_EXCEPTION_TEXT")

    monkeypatch.setattr(cli, "_run", failed)
    with pytest.raises(SystemExit):
        cli.main(["run", "--config", str(selected.path)])
    captured = capsys.readouterr()
    assert json.loads(captured.out) == {"status": "failed", "error_type": "ValueError"}
    assert '"event":"failed"' in captured.err
    assert "PRIVATE_EXCEPTION_TEXT" not in captured.out + captured.err


@pytest.mark.parametrize(
    "fault",
    [
        "cohort",
        "signer",
        "owner",
        "rpc",
        "secret",
        "stores",
        "tracks",
        "http",
        "userinfo",
        "query",
        "path",
        "public_listener",
        "manifest",
    ],
)
def test_configuration_rejects_changed_authority_and_unsafe_placement(selected, fault):
    c = selected.config
    changes = {
        "cohort": {"signing": c.signing.model_copy(update={"cohorts": c.signing.cohorts[:1]})},
        "signer": {
            "signing": c.signing.model_copy(update={"signer": wallet("Alice").hotkey.ss58_address})
        },
        "owner": {"owner_hotkey": wallet("Alice").hotkey.ss58_address},
        "rpc": {"chain": c.chain.model_copy(update={"proof_rpc_fallback_urls": ()})},
        "secret": {"signer_key_file": c.inputs_directory + "/key"},
        "stores": {"proof_import_directory": c.promotion_directory},
        "tracks": {"eligible_tracks": ("model", "endpoint")},
        "http": {"owner_origin": "http://owner.example"},
        "userinfo": {"owner_origin": "https://user:secret@owner.example"},
        "query": {"owner_origin": "https://owner.example?secret=value"},
        "path": {"owner_origin": "https://owner.example/path"},
        "public_listener": {"listen_host": "0.0.0.0"},
        "manifest": {"series": c.series.model_copy(update={"manifest_sha256": "00" * 32})},
    }[fault]
    with pytest.raises(ValueError):
        PhaseReviewServiceConfig.model_validate_json(
            canonical_json_bytes(c.model_copy(update=changes))
        )


@pytest.mark.parametrize("fault", ["mode", "symlink", "shared", "short", "newline"])
async def test_private_credentials_fail_before_key_loading(selected, monkeypatch, fault):
    c = selected.config
    path = Path(c.vote_token_file)
    if fault == "mode":
        path.chmod(0o444)
    elif fault == "symlink":
        path.unlink()
        path.symlink_to(c.owner_token_file)
    else:
        path.chmod(0o600)
        path.write_text(
            {"shared": "owner-token" * 4, "short": "bad", "newline": "bad\n" * 20}[fault]
        )
        path.chmod(0o440)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *args: pytest.fail("key opened"))
    with pytest.raises(ValueError):
        async with boot.phase_review_app(c):
            pytest.fail("unsafe service started")


@pytest.fixture
def providers(selected, monkeypatch):
    events = []

    class Provider:
        def __init__(self, chain, policy):
            self.policy = policy
            events.append("provider")

        async def start(self):
            events.append("started")

        async def collect(self):
            raise AssertionError("unauthenticated host probes must not collect chain state")

        def ensure_observer_running(self):
            pass

        async def aclose(self):
            events.append("closed")

    monkeypatch.setattr(boot, "HistoricalRegistrationProvider", Provider)
    monkeypatch.setattr(boot, "load_named_hotkey", lambda *args: wallet("Dave"))
    return SimpleNamespace(events=events, provider=Provider)


async def test_boot_missing_future_inputs_authentication_and_exclusive_restart(selected, providers):
    c = selected.config
    async with boot.phase_review_app(c) as app:
        assert providers.events == ["provider", "started"]
        with pytest.raises(BlockingIOError):
            async with boot.phase_review_app(c):
                pytest.fail("second writer started")
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://local"
        ) as client:
            for phase in ("intake", "preparation", "requests"):
                for kind in ("progress", "decision"):
                    assert (
                        await client.post(f"/internal/cohorts/{phase}/votes/{kind}", json={})
                    ).status_code == 401
            assert (
                await client.post("/internal/cohorts/requests/votes/progress", json={})
            ).status_code == 401
            result = await client.post(
                "/internal/cohorts/requests/votes/progress",
                json={},
                headers={"authorization": "Bearer " + "vote-token" * 4},
            )
            assert result.status_code == 422
            assert (await client.get("/openapi.json")).status_code == 404
    assert providers.events[-1] == "closed"
    async with boot.phase_review_app(c):
        pass
    assert providers.events.count("started") == providers.events.count("closed") == 2


async def test_restart_retains_host_selection_and_allows_capacity_change(selected, providers):
    c = selected.config
    async with boot.phase_review_app(c):
        pass
    async with boot.phase_review_app(c.model_copy(update={"maximum_export_bytes": 128 * 1024**2})):
        pass
    with pytest.raises(ValueError):
        async with boot.phase_review_app(c.model_copy(update={"owner_hotkey": c.signing.signer})):
            pytest.fail("changed owner accepted")
    assert providers.events[-1] == "closed"


@pytest.mark.parametrize("failure", ["key", "start"])
async def test_failed_startup_closes_provider_and_releases_lease(
    selected, providers, monkeypatch, failure
):
    def fail(*args):
        raise ValueError("unavailable")

    async def start(*args):
        fail()

    if failure == "key":
        monkeypatch.setattr(boot, "load_named_hotkey", fail)
    else:
        monkeypatch.setattr(providers.provider, "start", start)
    with pytest.raises(ValueError, match="unavailable"):
        async with boot.phase_review_app(selected.config):
            pytest.fail("failed startup yielded listener")
    assert providers.events[-1] == "closed"
    os.close(lock_private_file(Path(selected.config.signing.directory) / "service.lock"))


@pytest.mark.parametrize("benchmark", [False, True, "endpoint"])
async def test_real_loopback_listener_starts_and_stops_with_owned_resources(
    selected, providers, benchmark, monkeypatch
):
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    config = (with_benchmark(selected.config) if benchmark else selected.config).model_copy(
        update={"listen_port": port}
    )
    if benchmark == "endpoint":
        config = with_endpoint(selected.config).model_copy(update={"listen_port": port})
        endpoint_credentials(config)
        monkeypatch.setattr(boot, "CohortEndpointFinalityProvider", providers.provider)
    if benchmark:

        async def unavailable(self):
            raise OSError("temporary finality outage")

        monkeypatch.setattr(providers.provider, "collect", unavailable)
    stop = asyncio.Event()
    task = asyncio.create_task(boot.run_phase_review_service(config, stop))
    try:
        async with httpx.AsyncClient(trust_env=False) as client:

            async def request():
                while True:
                    if task.done():
                        task.result()
                        pytest.fail("listener exited")
                    try:
                        return await client.post(
                            f"http://127.0.0.1:{port}/internal/cohorts/intake/votes/progress",
                            json={},
                        )
                    except httpx.ConnectError:
                        await asyncio.sleep(0.01)

            assert (await asyncio.wait_for(request(), 5)).status_code == 401
            assert "closed" not in providers.events
            if benchmark:
                # The actual configured workers start after listener startup,
                # even with no future orders or current chain observation.
                await asyncio.sleep(0.35)
                assert not task.done()
    finally:
        stop.set()
        await asyncio.wait_for(task, 5)
    assert providers.events[-1] == "closed"


@pytest.mark.parametrize(
    "error_type", [httpx.ConnectError, httpx.ReadTimeout, httpx.RemoteProtocolError]
)
async def test_transport_failures_are_retryable_without_exposing_error_details(
    selected, error_type
):
    from umi.competition_cohort_review_http import PhaseReviewHTTPClient

    def failed(request):
        raise error_type("private transport details", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(failed)) as client:
        transport = PhaseReviewHTTPClient(
            client,
            "https://owner.example",
            token="private-token" * 4,
            path="/internal/cohorts/intake-review",
        )
        with pytest.raises(OSError, match="retry unchanged") as error:
            await transport(selected.config.signing.cohorts[0])
    assert "private transport details" not in str(error.value)


@pytest.mark.parametrize("failure", ["stop", "cancel", "observer", "listener"])
async def test_host_drains_listener_before_provider_and_lease(
    selected, providers, monkeypatch, failure
):
    entered, finish, draining = asyncio.Event(), asyncio.Event(), asyncio.Event()
    stop, events = asyncio.Event(), providers.events

    class Server:
        should_exit = False
        started = False

        def __init__(self, config):
            assert config.timeout_graceful_shutdown is None
            assert not config.access_log

        async def serve(self):
            self.started = True
            entered.set()
            if failure == "listener":
                return
            while not self.should_exit:
                await asyncio.sleep(0.001)
            draining.set()
            await finish.wait()
            events.append("drained")

    monkeypatch.setattr(boot, "_Server", Server)
    task = asyncio.create_task(boot.run_phase_review_service(selected.config, stop))
    await asyncio.wait_for(entered.wait(), 3)
    if failure == "listener":
        with pytest.raises(RuntimeError, match="listener"):
            await task
        assert events[-1] == "closed"
        return
    if failure == "cancel":
        task.cancel()
    elif failure == "observer":

        def failed(_):
            raise RuntimeError("finality stopped")

        monkeypatch.setattr(providers.provider, "ensure_observer_running", failed)
    else:
        stop.set()
    await asyncio.wait_for(draining.wait(), 3)
    if failure == "cancel":
        task.cancel()  # A second cancellation cannot release an owned key/lock.
    assert "closed" not in events
    with pytest.raises(BlockingIOError):
        lock_private_file(Path(selected.config.signing.directory) / "service.lock")
    finish.set()
    if failure in ("cancel", "observer"):
        with pytest.raises(asyncio.CancelledError if failure == "cancel" else RuntimeError):
            await task
    else:
        await task
    assert events[-2:] == ["drained", "closed"]
    os.close(lock_private_file(Path(selected.config.signing.directory) / "service.lock"))


def with_endpoint(config):
    c = with_benchmark(with_service(config))
    base = c.signing.directory
    common = dict(
        policy_sha256=digest(c.policy), signer=c.signing.signer, cohorts=c.signing.cohorts
    )
    endpoint = EndpointHostConfig(
        schema="umi-cohort-endpoint-host/1",
        requests=EndpointRequestSignerConfig(
            schema="umi-cohort-endpoint-request-signer/1",
            directory=base + "-endpoint-requests",
            **common,
        ),
        decisions=CohortEndpointDecisionConfig(
            schema="umi-cohort-endpoint-decision-config/1",
            directory=base + "-endpoint-decisions",
            **common,
        ),
        origins=c.chain.model_copy(update={"state_directory": base + "-origins"}),
        clips=ClipDeliveryConfig(
            schema="umi-cohort-clip-delivery-config/1",
            directory=base + "-clips",
            videos_directory=c.benchmark.videos_directory,
            origin="https://clips.example",
            upload_token_file=base + "-clip-token",
        ),
        objects_directory=base + "-endpoint-objects",
        transport_directory=base + "-endpoint-transports",
        reviewers=tuple(
            CohortReviewPeerConfig(
                signer=e.hotkey,
                origin="https://peer-" + str(i) + ".example",
                token_file=base + "-peer-token-" + str(i),
            )
            for i, e in enumerate(sorted(c.policy.evaluators, key=lambda e: identity(e.hotkey)))
            if identity(e.hotkey) != identity(c.signing.signer)
        ),
    )
    c = c.model_copy(update={"schema_": "umi-cohort-phase-review-service/6", "endpoint": endpoint})
    return PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(c))


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "old_version",
        "policy",
        "cohorts",
        "signer",
        "backups",
        "peers",
        "overlap",
        "video_alias",
    ],
)
def test_endpoint_configuration_preserves_scope_and_private_stores(selected, fault):
    c = with_endpoint(selected.config)
    e = c.endpoint
    if fault == "missing":
        c = c.model_copy(update={"endpoint": None})
    elif fault == "old_version":
        c = c.model_copy(update={"schema_": "umi-cohort-phase-review-service/5"})
    elif fault in ("policy", "cohorts", "signer"):
        changes = {
            "policy": {"policy_sha256": "ff" * 32},
            "cohorts": {"cohorts": ()},
            "signer": {"signer": wallet("Charlie").hotkey.ss58_address},
        }
        e = e.model_copy(update={"requests": e.requests.model_copy(update=changes[fault])})
    elif fault == "backups":
        e = e.model_copy(
            update={"origins": e.origins.model_copy(update={"proof_rpc_fallback_urls": ()})}
        )
    elif fault == "peers":
        e = e.model_copy(update={"reviewers": e.reviewers[:0]})
    elif fault == "overlap":
        e = e.model_copy(update={"objects_directory": c.benchmark.execution.directory})
    else:
        e = e.model_copy(update={"objects_directory": c.benchmark.videos_directory})
    if fault not in ("missing", "old_version"):
        c = c.model_copy(update={"endpoint": e})
    with pytest.raises(ValueError):
        PhaseReviewServiceConfig.model_validate_json(canonical_json_bytes(c))


def endpoint_credentials(c):
    for path, token in [
        (c.endpoint.clips.upload_token_file, "ab" * 32),
        *((p.token_file, "peer-token" * 4) for p in c.endpoint.reviewers),
    ]:
        Path(path).write_text(token + "\n")
        Path(path).chmod(0o440)


async def test_endpoint_boot_owns_origin_provider_and_native_workers(
    selected, providers, monkeypatch
):
    c = with_endpoint(selected.config)
    endpoint_credentials(c)
    monkeypatch.setattr(boot, "CohortEndpointFinalityProvider", providers.provider)
    async with boot.phase_review_app(c) as app:
        assert app.state.endpoint is not None
        assert app.state.benchmark.workers["endpoints"] is app.state.endpoint.worker
        assert app.state.endpoint.recovery.journal is app.state.benchmark.execution
        assert providers.events.count("started") == 2
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app)) as client:
            for kind in ("request", "decision"):
                assert (
                    await client.post(
                        "http://local/internal/cohorts/endpoint/votes/" + kind, json={}
                    )
                ).status_code == 401
        with pytest.raises(BlockingIOError):
            async with boot.phase_review_app(c):
                pytest.fail("second endpoint writer")
    assert providers.events.count("closed") == 2


async def test_failed_endpoint_origin_start_closes_both_owned_providers(
    selected, providers, monkeypatch
):
    c = with_endpoint(selected.config)
    endpoint_credentials(c)

    class Broken(providers.provider):
        async def start(self):
            raise OSError("origin unavailable")

    monkeypatch.setattr(boot, "CohortEndpointFinalityProvider", Broken)
    with pytest.raises(OSError, match="origin unavailable"):
        async with boot.phase_review_app(c):
            pytest.fail("failed provider started")
    assert providers.events.count("closed") == 2
    os.close(lock_private_file(Path(c.signing.directory) / "service.lock"))
