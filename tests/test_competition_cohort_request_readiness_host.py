"""Native readiness HTTP and input checks; finality, process tasks and Podman are fixtures."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_endpoint_host as endpoint_module
from umi.competition_artifacts import preserve_bundle, preserved_bundle_available
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_request_probe import (
    PATH,
    RequestProbe,
    RequestReadinessPeer,
    evaluator_request_readiness_routes,
)
from umi.competition_cohort_request_readiness_host import (
    CombinedRequestReadiness,
    request_readiness_routes,
)
from umi.competition_execution import execution_boundary
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_endpoint_host import installed as installed
from .test_competition_cohort_endpoint_scheduler import base_policy as base_policy
from .test_competition_cohort_endpoint_scheduler import chain as chain
from .test_competition_cohort_endpoint_scheduler import chain_config as chain_config
from .test_competition_cohort_endpoint_scheduler import decisions as decisions
from .test_competition_cohort_endpoint_scheduler import delivery as delivery
from .test_competition_cohort_endpoint_scheduler import endpoint as endpoint
from .test_competition_cohort_endpoint_scheduler import execution as execution
from .test_competition_cohort_endpoint_scheduler import granted as granted
from .test_competition_cohort_endpoint_scheduler import harness as harness
from .test_competition_cohort_endpoint_scheduler import known_video_bytes as known_video_bytes
from .test_competition_cohort_endpoint_scheduler import legacy_scenario as legacy_scenario
from .test_competition_cohort_endpoint_scheduler import policy as policy
from .test_competition_cohort_endpoint_scheduler import receipt_scenario as receipt_scenario
from .test_competition_cohort_endpoint_scheduler import recovery as recovery
from .test_competition_cohort_endpoint_scheduler import recovery_case as recovery_case
from .test_competition_cohort_endpoint_scheduler import relay as relay
from .test_competition_cohort_endpoint_scheduler import retiring as retiring
from .test_competition_cohort_endpoint_scheduler import runtime as runtime
from .test_competition_cohort_endpoint_scheduler import scenario as scenario
from .test_competition_cohort_endpoint_scheduler import scheduled as scheduled
from .test_competition_cohort_endpoint_scheduler import signing as signing
from .test_open_competition import bundle_at


@pytest.fixture
async def ready(installed, tmp_path, monkeypatch):
    n, h = installed, installed.host
    order = n.q.p.e.assignment.certificate.order
    root = tmp_path / "ready-inputs"
    bundle = bundle_at(root / "source")
    assert bundle == order.incumbent
    archive, videos = root / "archive", root / "videos"
    preserve_bundle(bundle, root / "source", archive, h.policy)
    videos.mkdir()
    for case in order.cases:
        (videos / (case.video_sha256 + ".mp4")).write_bytes(("case-video-" + case.case_id).encode())

    async def runtime(value, policy):
        assert value == order.runtime and policy == h.policy

    monkeypatch.setattr(endpoint_module, "verify_runtime", runtime)
    tasks = []
    for name, host in n.hosts.items():
        b = host.benchmark
        b.provider.ensure_observer_running = lambda: None
        host.recovery.origin.provider.ensure_observer_running = lambda: None
        b.stop = asyncio.Event()
        b.tasks = {
            k: asyncio.create_task(b.stop.wait()) for k in ("execution", "endpoints", "exports")
        }
        tasks.extend(b.tasks.values())
        b.workers = dict.fromkeys(b.tasks)
        b.sandbox = SimpleNamespace(archive=archive, videos=videos)
        n.apps[name.lower() + ".example"].include_router(
            evaluator_request_readiness_routes(host, token="peer-" + name * 8)
        )
    source = await h.benchmark.history(order.round.cohort_sha256)
    probe = RequestProbe(
        schema="umi-cohort-request-probe/1",
        nonce="ab" * 16,
        policy_sha256=digest(h.policy),
        cohort_sha256=order.round.cohort_sha256,
        recovery_tip_sha256=history_tip(source.history),
        round_sha256=digest(order.round),
        catalog_sha256s=h.manifest.requirement(order.round.cohort_sha256).catalog_sha256s,
        order_sha256s=(digest(order),),
    )
    n.probe, n.order, n.source = probe, order, source
    n.archive, n.videos = archive, videos
    n.observation = execution_boundary(await h.benchmark.provider.collect())
    n.peer = RequestReadinessPeer(
        h.peers[next(iter(h.peers))].clients["request"].client,
        "https://" + n.q.s.own.lower() + ".example",
        "peer-" + n.q.s.own * 8,
    )
    try:
        yield n
    finally:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


async def test_evaluator_inputs_offline_then_recovered(ready):
    n = ready
    assert await n.peer.ready(n.probe, n.observation, 10)

    path = n.host.benchmark.inbox.journal.path
    parked = path.with_suffix(".parked")
    path.rename(parked)
    try:
        with pytest.raises(OSError):
            await n.peer.ready(n.probe, n.observation, 10)
    finally:
        parked.rename(path)
    assert await n.peer.ready(n.probe, n.observation, 10)
    assert not n.signatures and n.q.p.model.calls == 0
    path = n.videos / (n.order.cases[0].video_sha256 + ".mp4")
    original = path.read_bytes()
    path.unlink()
    with pytest.raises(OSError):
        await n.peer.ready(n.probe, n.observation, 10)
    path.write_bytes(original)
    n.media_fail = True
    with pytest.raises(OSError):
        await n.peer.ready(n.probe, n.observation, 10)
    n.media_fail = False
    assert await n.peer.ready(n.probe, n.observation, 10)
    n.host.benchmark.tasks["endpoints"].cancel()
    assert not await n.peer.ready(n.probe, n.observation, 10)


async def test_evaluator_reuses_assignments_without_retaining_other_probe_inputs(
    ready, monkeypatch
):
    n = ready
    assert await n.peer.ready(n.probe, n.observation, 10)
    assert len(n.host.readiness_assignments) == 1
    assert await n.peer.ready(n.probe.model_copy(update={"order_sha256s": ()}), n.observation, 10)
    assert not n.host.readiness_assignments
    assert await n.peer.ready(n.probe, n.observation, 10)

    async def missing_runtime(*_):
        raise OSError("pinned runtime unavailable")

    monkeypatch.setattr(endpoint_module, "verify_runtime", missing_runtime)
    with pytest.raises(OSError):
        await n.peer.ready(n.probe, n.observation, 10)


@pytest.mark.parametrize(
    "field",
    [
        "policy_sha256",
        "cohort_sha256",
        "recovery_tip_sha256",
        "round_sha256",
        "order_sha256s",
        "catalog_sha256s",
    ],
)
async def test_evaluator_rejects_wrong_scope_or_missing_order(ready, field):
    n = ready
    changed = ("ff" * 32,) if field.endswith("s") else "ff" * 32
    with pytest.raises(OSError):
        await n.peer.ready(n.probe.model_copy(update={field: changed}), n.observation, 10)
    assert not n.signatures


async def test_private_probe_authentication_precedes_parsing(ready):
    n = ready
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=n.apps[n.q.s.own.lower() + ".example"]),
        base_url="https://reviewer.example",
    ) as client:
        response = await client.post(PATH, content=b"invalid")
    assert response.status_code == 401


@pytest.mark.parametrize("fault", ["nonce", "head", "fork", "unready", "redirect", "oversize"])
async def test_peer_rejects_stale_corrupt_or_redirected_reply(ready, fault):
    n = ready
    value = await n.host.request_readiness(n.probe)
    if fault == "nonce":
        value = value.model_copy(update={"probe_sha256": "ff" * 32})
    if fault in {"head", "fork"}:
        observation = value.observation.model_copy(
            update={"block": value.observation.block + 11}
            if fault == "head"
            else {"state_root": "0x" + "ff" * 32}
        )
        value = value.model_copy(update={"observation": observation})
    if fault == "unready":
        value = value.model_copy(update={"ready": False})

    def respond(request):
        if fault == "redirect":
            return httpx.Response(302, headers={"location": "https://other.example"})
        return httpx.Response(
            200,
            content=b" " * 20000 if fault == "oversize" else canonical_json_bytes(value),
            headers={"content-type": "application/json"},
        )

    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
        peer = RequestReadinessPeer(client, "https://reviewer.example", "v" * 32)
        if fault in {"redirect", "oversize"}:
            with pytest.raises((OSError, ValueError)):
                await peer.ready(n.probe, n.observation, 10)
        else:
            assert not await peer.ready(n.probe, n.observation, 10)


async def test_public_clock_tracks_coordinator_and_evaluator_recovery(ready):
    n, h = ready, ready.host
    key, cohort = n.probe.catalog_sha256s[0], n.probe.cohort_sha256
    b = h.benchmark
    source = SimpleNamespace(
        cohort=cohort,
        roster=SimpleNamespace(round=n.order.round),
        gap=10,
        catalogs=(),
    )
    task = b.tasks["execution"]
    own = n.q.s.own
    peer = SimpleNamespace(
        signer=b.inbox.config.signer, origin="https://" + own.lower() + ".example"
    )
    service = SimpleNamespace(
        config=SimpleNamespace(
            manifest=h.manifest, admission_owner=SimpleNamespace(reviewers=(peer,))
        ),
        intake=SimpleNamespace(policy=h.policy, bindings={cohort}),
        runtime_tasks=(task,),
        provider=b.provider,
        capture=b.provider.collect,
        history=b.history,
    )
    dispatch = SimpleNamespace(
        origins=h.recovery.origin.provider,
        workers={key: h.worker},
        tasks={key: task},
        clips=h.clips,
    )
    # Selection is fixture supplied; the evaluator checks a real acknowledged
    # native assignment, transport and retained media/model inputs over HTTP.
    orders = SimpleNamespace(
        _retained=lambda _: 1,
        queue=SimpleNamespace(
            journal=SimpleNamespace(
                get=lambda *_: {"slots": ["slot"]},
                path=b.inbox.journal.path,
                _check_files=b.inbox.journal._check_files,
            ),
            intent=lambda _: SimpleNamespace(order=n.order),
        ),
    )
    combined = CombinedRequestReadiness(
        service,
        SimpleNamespace(requests={cohort: source}),
        dispatch,
        orders,
        n.peer.client.client,
        ("peer-" + own * 8,),
        lambda: True,
    )
    service.request_readiness = combined
    app = FastAPI()
    app.include_router(request_readiness_routes(service))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://public.example"
    ) as client:
        # Catalog identity is taken from selected manifest; use the observer's
        # native digest binding below with the returned public payload.
        path = f"/v1/competition/cohorts/{cohort}/requests/readiness"
        response = await client.get(path, params={"nonce": "12" * 16})
        assert response.status_code == 200 and response.json()["ready"]
        assert response.headers["cache-control"] == "no-store"
        combined.running = lambda: False
        assert not (await client.get(path, params={"nonce": "13" * 16})).json()["ready"]
        combined.running = lambda: True
        n.media_fail = True
        assert (await client.get(path, params={"nonce": "14" * 16})).status_code == 503
        n.media_fail = False
        assert (await client.get(path, params={"nonce": "15" * 16})).json()["ready"]
        service.request_readiness = None
        assert (await client.get(path, params={"nonce": "16" * 16})).status_code == 503


@pytest.mark.parametrize("fault", ["missing", "manifest", "symlink", "hardlink", "wrong_size"])
def test_model_availability_requires_bounded_readable_files(tmp_path, policy, fault):
    bundle = bundle_at(tmp_path / "model-input")
    archive = tmp_path / "model-archive"
    preserve_bundle(bundle, tmp_path / "model-input", archive, policy)
    preserved_bundle_available(bundle, archive, policy)
    target = archive / digest(bundle) / "model" / bundle.files[0].path
    if fault == "manifest":
        (archive / digest(bundle) / "manifest.json").unlink()
    elif fault in {"missing", "symlink"}:
        target.unlink()
        if fault == "symlink":
            target.symlink_to(tmp_path / "model-input" / bundle.files[0].path)
    elif fault == "hardlink":
        (tmp_path / "another-link").hardlink_to(target)
    else:
        target.chmod(0o600)
        target.write_bytes(b"broken")
    with pytest.raises((OSError, ValueError)):
        preserved_bundle_available(bundle, archive, policy)
