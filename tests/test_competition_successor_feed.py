"""Wallet-free feed routes, with synthetic signatures and real fixture replay."""

import asyncio
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_successor_publisher_cli as publisher_cli
from umi.competition_delivery import (
    HTTPSSuccessorArtifactDelivery,
    HTTPSSuccessorDirectiveFetcher,
    SuccessorDeliveryLimits,
)
from umi.competition_host_activation import SuccessorWorkerExecutionLimits
from umi.competition_successor_feed import (
    SuccessorFeedConfig,
    SuccessorPublicationFeed,
    create_successor_feed_app,
    main,
)
from umi.competition_successor_publication import SuccessorRoundPublicationBuilder
from umi.competition_supervisor import (
    parse_canonical_successor_supervisor_directive_history,
    parse_canonical_successor_supervisor_directive_page,
    successor_source_config_sha256,
)
from umi.competition_supervisor_runtime import SuccessorWorkerSelection
from umi.competition_worker_cli import (
    SuccessorWeightExecutionConfig,
    SuccessorWorkerExecutionConfig,
)
from umi.protocol import canonical_json_bytes
from umi.validator_supervisor_adapters import PinnedHTTPSClient

from .test_competition_chain import chain_config as chain_config
from .test_competition_delivery import _BUNDLE
from .test_competition_delivery import release_identity as release_identity
from .test_competition_successor_publication import build
from .test_competition_successor_publication import next_package as next_package
from .test_competition_successor_publication import package_case as package_case
from .test_competition_successor_publication import package_limits as package_limits
from .test_competition_successor_publication import policy as policy
from .test_competition_successor_publication import publication_case as publication_case
from .test_competition_successor_publication import replay_limits as replay_limits
from .test_competition_successor_publication import successor_case as successor_case
from .test_competition_successor_publication import successor_chain as successor_chain
from .test_competition_successor_publication import successor_release as successor_release
from .test_competition_successor_publication import v3_predecessor as v3_predecessor
from .test_competition_worker import worker_capacity as worker_capacity


@pytest.fixture
def feed_case(publication_case, chain_config, worker_capacity, tmp_path):
    case = publication_case
    (tmp_path / "consumer").mkdir(mode=0o700)
    config = case.plan.supervisor.model_copy(update={"state_root": str(tmp_path / "consumer")})
    consent = case.plan.consent.model_copy(
        update={"source_config_sha256": successor_source_config_sha256(config)}
    )
    plan = case.plan.model_copy(
        update={
            "supervisor": config,
            "consent": consent,
            "chain": case.plan.chain.model_copy(update={"chain_pin": chain_config.chain_pin}),
            "release": case.plan.release.model_copy(
                update={"release_bundle_size_bytes": len(_BUNDLE)}
            ),
        }
    )
    case.builder = SuccessorRoundPublicationBuilder(case.root.parent / "feed-signing", plan)
    case.plan = plan
    target = plan.release.replay_release_identity.target_triple
    chain = chain_config.model_copy(
        update={
            "chain_pin": plan.chain.chain_pin,
            "target_triple": target,
            "finality_pin": chain_config.finality_pin.model_copy(
                update={
                    "release_sha256_by_target": (
                        plan.weights.required_finality_verifier_sha256_by_target
                    ),
                }
            ),
            "proof_binary_sha256": plan.weights.required_storage_proof_verifier_sha256_by_target[
                target
            ],
            "finality_binary": "/opt/umi/bin/umi-grandpa-finality-observer",
            "proof_binary": "/opt/umi/bin/umi-substrate-proof-verifier",
            "chain_spec": "/opt/umi/raw_spec_finney.json",
            "state_directory": "/var/lib/umi-competition/finality",
        }
    )
    limits = SuccessorWorkerExecutionLimits(
        schema="umi-successor-worker-execution-limits/1",
        replay_capacity_ceiling=worker_capacity,
        maximum_weight_attempts=10,
        maximum_weight_evidence_bytes=1_000_000,
        maximum_submission_timeout_seconds=10,
    )
    execution = SuccessorWorkerExecutionConfig(
        schema="umi-successor-worker-execution-config/1",
        replay_capacity=worker_capacity,
        weights=SuccessorWeightExecutionConfig(
            maximum_attempts=10,
            maximum_evidence_bytes=1_000_000,
            submission_timeout_seconds=10,
            chain=chain,
        ),
    )
    feed_config = SuccessorFeedConfig(
        schema="umi-successor-feed-config/1",
        directory=str(tmp_path / "feed"),
        plan=plan,
        execution=execution,
        worker_limits=limits,
    )
    feed = SuccessorPublicationFeed(feed_config)
    return SimpleNamespace(feed=feed, signer=case, config=feed_config, limits=limits)


def _retain(case, package, block=160):
    signed = build(case.signer, package, block)
    case.feed.retain(signed, package.prepared)
    return signed


def _after(case, item=None):
    if item is None:
        c = case.config.plan.consent
        return f"after/3/{c.predecessor_sequence}/{c.predecessor_directive_sha256}.json"
    return f"after/4/{item.intent.sequence}/{item.signed.directive_sha256}.json"


def test_two_rounds_restart_exact_artifacts_and_no_private_descriptor(
    feed_case, package_case, next_package
):
    c = feed_case
    first = _retain(c, package_case)
    prefix = "directives/" + first.signed.directive_sha256
    first_page = c.feed.read(prefix + "/page.json")
    second = _retain(c, next_package, 245)
    c.feed = SuccessorPublicationFeed(c.config)
    c.feed.retain(first, package_case.prepared)
    assert c.feed.read(prefix + "/page.json") == first_page
    payload, immutable = c.feed.read(_after(c))
    page = parse_canonical_successor_supervisor_directive_page(payload)
    assert page.directives == [first.signed, second.signed] and not immutable
    payload, _ = c.feed.read(_after(c, second))
    assert parse_canonical_successor_supervisor_directive_page(payload).directives == []
    for package in (package_case, next_package):
        root = Path(package.prepared.package_path)
        for path in root.iterdir():
            body, immutable = c.feed.read(f"packages/{package.prepared.package_sha256}/{path.name}")
            assert body == path.read_bytes() and immutable
            assert b"package_path" not in body and str(root).encode() not in body
    authorization_id = first.signed.directive.chain_authorization.signed_authorization_sha256
    assert c.feed.read(f"authorizations/{authorization_id}.json")[0] == canonical_json_bytes(
        first.authorization
    )
    assert c.feed.read(prefix + "/execution.json")[0] == canonical_json_bytes(c.config.execution)


@pytest.mark.asyncio
async def test_relay_one_hop_links_and_empty_tail_collect_complete_initial_history(
    feed_case, package_case, next_package, v3_predecessor
):
    c = feed_case
    first = _retain(c, package_case)
    second = _retain(c, next_package, 245)
    objects = {}
    previous = _after(c)
    for item in (first, second):
        body, _ = c.feed.read(f"directives/{item.signed.directive_sha256}/page.json")
        page = parse_canonical_successor_supervisor_directive_page(body)
        # The relay changes only the unsigned page envelope. Its explicit empty
        # tail allows catch-up to continue past old, now-expired directives.
        objects[previous] = canonical_json_bytes(page.model_copy(update={"more": True}))
        previous = _after(c, item)
    objects[previous] = c.feed.read(previous)[0]
    requested = []
    base = c.config.plan.supervisor.directive_url + "/successor/"

    async def request(req):
        route = str(req.url).removeprefix(base)
        requested.append(route)
        return httpx.Response(200, stream=httpx.ByteStream(objects[route]))

    client = PinnedHTTPSClient(timeout_seconds=60, transport=httpx.MockTransport(request))
    fetcher = HTTPSSuccessorDirectiveFetcher(c.config.plan.supervisor, client=client)
    result = await fetcher.fetch_initial_history(
        legacy_signed_bytes=v3_predecessor.body,
        operator_consent=c.config.plan.consent,
        finalized_block=250,
    )
    history = parse_canonical_successor_supervisor_directive_history(result)
    assert history.directives == [first.signed, second.signed]
    assert history.head == second.signed
    assert requested == [_after(c), _after(c, first), _after(c, second)]


def test_missing_predecessor_and_unlisted_files_rejected(feed_case, package_case, next_package):
    c = feed_case
    first = build(c.signer, package_case)
    second = build(c.signer, next_package, 245)
    with pytest.raises(ValueError, match="skip or replace"):
        c.feed.retain(second, next_package.prepared)
    assert c.feed.journal.keys("delivery") == []
    c.feed.retain(first, package_case.prepared)
    for route in (
        "../rounds.sqlite3",
        "config.json",
        "wallets/hotkey",
        "packages/" + first.intent.package.package_sha256 + "/prepared-package.json",
        "after/4/2/" + "ff" * 32 + ".json",
        "authorizations/" + "ff" * 32 + ".json",
    ):
        with pytest.raises(KeyError):
            c.feed.read(route)


def test_unsigned_round_metadata_cannot_relabel_a_signed_package(feed_case, package_case):
    signed = build(feed_case.signer, package_case)
    changed = signed.model_copy(
        update={"intent": signed.intent.model_copy(update={"round_sequence": 99})}
    )
    with pytest.raises(ValueError, match="signing intent"):
        feed_case.feed.retain(changed, package_case.prepared)
    assert feed_case.feed.journal.keys("delivery") == []


def test_local_export_recovery_needs_no_wallet_or_new_signing_head(
    feed_case, package_case, tmp_path, capsys
):
    signed = build(feed_case.signer, package_case)
    inputs = tmp_path / "private-inputs"
    inputs.mkdir(mode=0o700)
    args = []
    for name, value in (
        ("config", feed_case.config),
        ("publication", signed),
        ("prepared-package", package_case.prepared),
    ):
        path = inputs / (name + ".json")
        path.write_bytes(canonical_json_bytes(value))
        path.chmod(0o600)
        args.extend(("--" + name, str(path)))
    main(args)
    assert capsys.readouterr().out == '{"status":"retained_signed_history"}\n'
    assert feed_case.feed.read(_after(feed_case))[0]


@pytest.mark.asyncio
@pytest.mark.parametrize("fail", [False, True])
async def test_signing_command_delivers_after_build_and_closes_provider(
    feed_case, package_case, tmp_path, monkeypatch, fail
):
    c, events = feed_case, []
    signed = build(c.signer, package_case)
    wallet = publisher_cli.AuthorityWallet(
        wallet_name="authority", hotkey_name="release", wallet_path=str(tmp_path / "wallets")
    )
    config = publisher_cli.SuccessorPublisherConfig(
        schema="umi-successor-publisher-config/1",
        plan=c.config.plan,
        chain=c.config.execution.weights.chain,
        intake_directory=str(package_case.scenario.store.directory),
        publication_directory=str(c.signer.builder.journal.root),
        replay_directory=str(tmp_path / "command-replay"),
        replay_capacity=c.config.execution.replay_capacity,
        authorization_wallet=wallet,
        directive_wallets=(wallet,),
    )

    class Provider:
        def __init__(self, *args):
            pass

        async def start(self):
            events.append("start")

        async def wait_ready(self):
            events.append("ready")

        async def aclose(self):
            events.append("close")

    class Publisher:
        def __init__(self, *args):
            pass

        async def build(self, prepared, **signers):
            assert prepared == package_case.prepared
            events.append("signed")
            return signed

    original = SuccessorPublicationFeed.retain_async

    async def retain(self, publication, prepared):
        assert events[-1] == "signed"
        events.append("delivery")
        if fail:
            raise ValueError("injected export failure")
        await original(self, publication, prepared)

    monkeypatch.setattr(publisher_cli, "FinalizedRegistrationProvider", Provider)
    monkeypatch.setattr(publisher_cli, "CurrentSuccessorRoundPublisher", Publisher)
    monkeypatch.setattr(publisher_cli.AuthorityWallet, "load", lambda _: "test-hotkey-port")
    monkeypatch.setattr(SuccessorPublicationFeed, "retain_async", retain)
    if fail:
        with pytest.raises(ValueError, match="export failure"):
            await publisher_cli.sign_round(
                config,
                package_case.scenario.store.policy,
                package_case.prepared,
                feed_config=c.config,
            )
        assert c.feed.journal.keys("delivery") == []
    else:
        assert (
            await publisher_cli.sign_round(
                config,
                package_case.scenario.store.policy,
                package_case.prepared,
                feed_config=c.config,
            )
            == signed
        )
        assert c.feed.read(_after(c))[0]
    assert events == ["start", "ready", "signed", "delivery", "close"]


def test_tampered_package_and_changed_execution_hold_delivery(feed_case, package_case):
    c = feed_case
    signed = _retain(c, package_case)
    path = package_case.path / "policy.json"
    path.chmod(0o600)
    original = path.read_bytes()
    try:
        path.write_bytes(original + b" ")
        path.chmod(0o400)
        with pytest.raises(ValueError, match=r"sealed|size|digest"):
            c.feed.read(f"packages/{signed.intent.package.package_sha256}/policy.json")
    finally:
        path.chmod(0o600)
        path.write_bytes(original)
        path.chmod(0o400)
    c.feed.config = c.config.model_copy(
        update={"execution": c.config.execution.model_copy(update={"weights": None})}
    )
    with pytest.raises(ValueError, match="configuration changed"):
        c.feed.read(_after(c))


@pytest.mark.asyncio
@pytest.mark.skipif(sys.platform != "linux", reason="artifact delivery uses renameat2")
async def test_existing_https_consumer_fetches_replayed_weight_package(feed_case, package_case):
    c = feed_case
    signed = _retain(c, package_case)
    app = create_successor_feed_app(c.feed)
    asgi = httpx.ASGITransport(app=app)

    async def request(req):
        if str(req.url) == c.config.plan.release.release_bundle_url:
            return httpx.Response(200, stream=httpx.ByteStream(_BUNDLE))
        response = await asgi.handle_async_request(req)
        body = await response.aread()
        await response.aclose()
        return httpx.Response(
            response.status_code, headers=response.headers, stream=httpx.ByteStream(body)
        )

    client = PinnedHTTPSClient(timeout_seconds=60, transport=httpx.MockTransport(request))
    config, consent = c.config.plan.supervisor, c.config.plan.consent
    fetcher = HTTPSSuccessorDirectiveFetcher(config, client=client)
    page = parse_canonical_successor_supervisor_directive_page(
        await fetcher.fetch_directive_page(
            after_version=3,
            after_sequence=consent.predecessor_sequence,
            after_directive_sha256=consent.predecessor_directive_sha256,
        )
    )
    assert page.head == signed.signed
    delivery = HTTPSSuccessorArtifactDelivery(
        config=config,
        operator_consent=consent,
        worker_limits=c.limits,
        client=client,
        limits=SuccessorDeliveryLimits(10, 100_000_000, 120),
    )
    result = await delivery.fetch(SuccessorWorkerSelection(signed.signed))
    assert result.authorization_bytes == canonical_json_bytes(signed.authorization)
    assert result.release_bundle_path.read_bytes() == _BUNDLE
    assert not (Path(config.state_root) / "successor-v4" / "activation-source").exists()
    base = config.directive_url + "/successor/"
    async with httpx.AsyncClient(transport=asgi, base_url=base) as http:
        for path, status in (("config.json", 404), (_after(c), 200)):
            response = await http.get(path)
            assert response.status_code == status
        assert response.headers["cache-control"] == "no-store"
        assert (await http.post(_after(c))).status_code == 405


@pytest.mark.asyncio
async def test_canceled_http_read_drains_before_accepting_another(feed_case, monkeypatch):
    started, release = threading.Event(), threading.Event()

    def read(route):
        started.set()
        release.wait(10)
        return b"{}", False

    monkeypatch.setattr(feed_case.feed, "read", read)
    app = create_successor_feed_app(feed_case.feed)
    base = feed_case.config.plan.supervisor.directive_url + "/successor/"
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=base) as client:
        task = asyncio.create_task(client.get("test"))
        try:
            assert await asyncio.to_thread(started.wait, 5)
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            assert (await client.get("another")).status_code == 503
        finally:
            release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert (await client.get("next")).status_code == 200
