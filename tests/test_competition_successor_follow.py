"""Automatic local publication with real replayed packages and synthetic keys."""

import asyncio
import json
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_successor_publication as publication_module
from umi import competition_successor_publisher_cli as cli
from umi.competition_evaluator import _publish
from umi.competition_successor_follow import (
    AutomaticSuccessorPublisher,
    CompletedRoundSource,
    SuccessorFollowConfig,
)
from umi.competition_successor_publisher import CurrentSuccessorRoundPublisher
from umi.protocol import canonical_json_bytes

from .test_competition_successor_feed import chain_config as chain_config
from .test_competition_successor_feed import feed_case as feed_case
from .test_competition_successor_feed import next_package as next_package
from .test_competition_successor_feed import package_case as package_case
from .test_competition_successor_feed import package_limits as package_limits
from .test_competition_successor_feed import policy as policy
from .test_competition_successor_feed import publication_case as publication_case
from .test_competition_successor_feed import release_identity as release_identity
from .test_competition_successor_feed import replay_limits as replay_limits
from .test_competition_successor_feed import successor_case as successor_case
from .test_competition_successor_feed import successor_chain as successor_chain
from .test_competition_successor_feed import successor_release as successor_release
from .test_competition_successor_feed import v3_predecessor as v3_predecessor
from .test_competition_successor_feed import worker_capacity as worker_capacity
from .test_competition_successor_publication import authority_wallets
from .test_competition_successor_publisher import guarded as guarded


def completed(case, package):
    prepared = package.prepared
    manifest = json.loads((Path(prepared.package_path) / "manifest.json").read_bytes())
    path = Path(case.config.certificate_directory) / (
        manifest["settlement_publication_sha256"] + ".package.json"
    )
    _publish(path, prepared)
    return path


@pytest.fixture
def automatic(feed_case, guarded, package_case, tmp_path):
    c, g = feed_case, guarded
    g.provider.config = c.config.execution.weights.chain
    publisher = CurrentSuccessorRoundPublisher(c.signer.builder, g.store, g.replay, g.provider)
    certificates = tmp_path / "completed-certificates"
    certificates.mkdir(mode=0o700)
    config = SuccessorFollowConfig(
        schema="umi-successor-follow-config/1",
        certificate_directory=str(certificates),
        package_directory=str(Path(package_case.prepared.package_path).parent),
        poll_interval_seconds=2,
    )
    signers = {
        "authorization_wallet": authority_wallets()[0],
        "directive_wallets": authority_wallets()[:2],
    }
    service = AutomaticSuccessorPublisher(publisher, c.feed, config, **signers)
    return SimpleNamespace(
        service=service,
        publisher=publisher,
        provider=g.provider,
        feed=c.feed,
        config=config,
        feed_config=c.config,
        guarded=g,
        signers=signers,
    )


@pytest.mark.asyncio
async def test_two_completed_rounds_publish_and_restart_without_resigning(
    automatic,
    package_case,
    next_package,
):
    c = automatic
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
    completed(c, package_case)
    assert (await c.service.tick())["status"] == "published"
    first = canonical_json_bytes(c.feed.history()[0])
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
    completed(c, next_package)
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2
    assert len(c.feed.history()) == 2
    c.service = AutomaticSuccessorPublisher(c.publisher, c.feed, c.config, **c.signers)
    assert (await c.service.tick())["status"] == "waiting_for_completed_round"
    assert canonical_json_bytes(c.feed.history()[0]) == first
    assert len(c.publisher.builder.journal.keys("authorization")) == 2


@pytest.mark.asyncio
async def test_latest_completed_round_selected_without_publishing_expired_older_round(
    automatic,
    package_case,
    next_package,
):
    c = automatic
    completed(c, package_case)
    completed(c, next_package)
    c.provider.block = 245
    result = await c.service.tick()
    assert result["status"] == "published" and result["round_sequence"] == 2
    assert [x.intent.round_sequence for x in c.feed.history()] == [2]


@pytest.mark.asyncio
async def test_expired_completed_round_waits_without_new_authorization(automatic, package_case):
    c = automatic
    completed(c, package_case)
    c.provider.block = 180
    assert (await c.service.tick())["status"] == "waiting_for_current_round"
    assert not c.publisher.builder.journal.keys("authorization")


@pytest.mark.asyncio
async def test_unfinished_round_resumes_before_a_newer_descriptor(
    automatic,
    package_case,
    next_package,
    monkeypatch,
):
    c = automatic
    completed(c, package_case)
    original = publication_module.sign_response_digest

    def fail(*args, **kwargs):
        raise RuntimeError("injected partial signature")

    monkeypatch.setattr(publication_module, "sign_response_digest", fail)
    with pytest.raises(RuntimeError, match="partial signature"):
        await c.service.tick()
    authorization = c.publisher.builder.journal.get("authorization", "2:1")
    assert authorization is not None
    completed(c, next_package)
    monkeypatch.setattr(publication_module, "sign_response_digest", original)
    assert (await c.service.tick())["round_sequence"] == 1
    assert c.publisher.builder.journal.get("authorization", "2:1") == authorization
    c.provider.block = 245
    assert (await c.service.tick())["round_sequence"] == 2


@pytest.mark.asyncio
async def test_cancellation_drains_descriptor_scan_before_unlocking(automatic, monkeypatch):
    c = automatic
    entered, release = threading.Event(), threading.Event()

    def scan():
        entered.set()
        if not release.wait(timeout=10):
            raise RuntimeError("test release timed out")
        return {}

    monkeypatch.setattr(c.service.source, "scan", scan)
    task = asyncio.create_task(c.service.tick())
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        task.cancel()
        await asyncio.sleep(0)
        assert not task.done() and c.service._serial.locked()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not c.service._serial.locked()
        assert not c.publisher.builder.journal.keys("intent")
    finally:
        release.set()


@pytest.mark.asyncio
async def test_failed_export_recovered_after_expiry_without_new_signatures_or_owned_head(
    automatic,
    package_case,
    monkeypatch,
):
    c = automatic
    completed(c, package_case)
    original = c.feed.retain_async

    async def fail(*args):
        raise OSError("injected delivery failure")

    monkeypatch.setattr(c.feed, "retain_async", fail)
    with pytest.raises(OSError, match="delivery failure"):
        await c.service.tick()
    signed = c.publisher.builder.history()
    assert len(signed) == 1 and not c.feed.history()
    calls = c.provider.calls
    c.provider.block = 180
    monkeypatch.setattr(c.feed, "retain_async", original)
    assert (await c.service.tick())["status"] == "recovered_signed_history"
    assert tuple(signed) == c.feed.history()
    assert c.provider.calls == calls
    assert len(c.publisher.builder.journal.keys("authorization")) == 1


@pytest.mark.asyncio
async def test_delivery_cannot_be_ahead_of_signing_history(automatic, package_case, monkeypatch):
    c = automatic
    completed(c, package_case)
    await c.service.tick()
    monkeypatch.setattr(c.publisher.builder, "history", lambda: [])
    with pytest.raises(ValueError, match="exact prefix"):
        await c.service.tick()


@pytest.mark.asyncio
async def test_new_conflict_at_signing_boundary_still_stops_automatic_publication(
    automatic,
    package_case,
):
    c = automatic
    completed(c, package_case)

    async def conflict(calls):
        if calls == 3:
            from umi.open_competition import digest

            with c.guarded.store._connection() as db:
                db.execute(
                    "INSERT INTO round_conflicts VALUES (?,?)",
                    (digest(package_case.scenario.round), 160),
                )

    c.provider.hook = conflict
    with pytest.raises(ValueError, match="conflicting quorum evidence"):
        await c.service.tick()
    assert not c.publisher.builder.journal.keys("authorization")
    assert not c.feed.history()


@pytest.mark.parametrize("mutation", ["path", "name", "symlink"])
def test_source_rejects_unbound_descriptor(automatic, package_case, mutation):
    c = automatic
    path = completed(c, package_case)
    if mutation == "path":
        changed = package_case.prepared.model_copy(
            update={"package_path": "/private/other-package"}
        )
        path.write_bytes(canonical_json_bytes(changed))
    elif mutation == "name":
        path.rename(path.parent / (("ff" * 32) + ".package.json"))
    else:
        target = path.with_suffix(".saved")
        path.rename(target)
        path.symlink_to(target)
    with pytest.raises(ValueError, match=r"fixed source|manifest differ|non-symlink"):
        c.service.source.scan()


def test_source_scan_is_bounded(automatic, package_case):
    c = automatic
    completed(c, package_case)
    source = CompletedRoundSource(
        c.config.model_copy(update={"maximum_rounds": 1}), c.publisher.builder.plan
    )
    root = Path(c.config.certificate_directory)
    for i in range(4):
        (root / f"unexpected-{i}").touch(mode=0o600)
    with pytest.raises(ValueError, match="scan bound"):
        source.scan()


@pytest.mark.asyncio
async def test_cli_follow_cancellation_closes_owned_provider(automatic, policy, monkeypatch):
    c = automatic
    events, reported = [], asyncio.Event()
    wallet = cli.AuthorityWallet(
        wallet_name="release",
        hotkey_name="authority",
        wallet_path=str(Path(c.config.certificate_directory).parent / "wallets"),
    )
    config = cli.SuccessorPublisherConfig(
        schema="umi-successor-publisher-config/1",
        plan=c.publisher.builder.plan,
        chain=c.provider.config,
        intake_directory=str(c.guarded.store.directory),
        publication_directory=str(c.publisher.builder.journal.root),
        replay_directory=str(c.guarded.replay.state_root),
        replay_capacity=c.guarded.replay.capacity,
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

    class Automatic:
        def __init__(self, *args, **kwargs):
            pass

        async def tick(self):
            return {"status": "waiting"}

    def load(self):
        assert events[-1] in {"ready", "wallet"}
        events.append("wallet")
        return object()

    monkeypatch.setattr(cli, "FinalizedRegistrationProvider", Provider)
    monkeypatch.setattr(cli, "CurrentSuccessorRoundPublisher", lambda *args: object())
    monkeypatch.setattr(cli, "AutomaticSuccessorPublisher", Automatic)
    monkeypatch.setattr(cli.AuthorityWallet, "load", load)
    task = asyncio.create_task(
        cli.follow_rounds(
            config, policy, c.config, feed_config=c.feed_config, report=lambda _: reported.set()
        )
    )
    await asyncio.wait_for(reported.wait(), timeout=10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert events == ["start", "ready", "wallet", "wallet", "close"]
