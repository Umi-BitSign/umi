from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_chain import CompetitionChainConfig
from umi.competition_dispatch import DispatchOrigin, EndpointDispatchConfig, EndpointDispatcher
from umi.competition_origin import EndpointOriginCapture
from umi.competition_scheduling import AssignmentPublicationJournal, assignment_key
from umi.miner import create_app
from umi.open_competition import digest
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes
from umi.validator import validate_response_envelope

from .test_competition_authorization import _live_policy, build_authorization_fixture
from .test_competition_feed import feed as feed
from .test_competition_miner_feed import dynamic_runtime
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def authorization(policy, request):
    from umi.grandpa_finality import FINNEY_GENESIS_HASH

    legacy = _live_policy(activation_block=1000)
    pins = legacy.implementation_pins
    legacy = legacy.model_copy(
        update={
            "implementation_pins": pins.model_copy(
                update={
                    "live_chain": pins.live_chain.model_copy(
                        update={"genesis_block_hash": FINNEY_GENESIS_HASH}
                    ),
                    "finality_verifier": pins.finality_verifier.model_copy(
                        update={"expected_genesis_hash": FINNEY_GENESIS_HASH}
                    ),
                }
            )
        }
    )
    return build_authorization_fixture(
        policy,
        legacy_policy=legacy,
        serving_origin=getattr(request, "param", "https://8.8.8.8:443"),
    )


@pytest.fixture
def dispatch(feed, tmp_path):
    item = feed.item
    pins = item.legacy_policy.implementation_pins
    target = next(iter(pins.finality_verifier.release_sha256_by_target))
    chain = CompetitionChainConfig(
        schema="umi-competition-chain-config/1",
        policy_sha256=digest(item.policy),
        rpc_url="wss://proofs.example.org",
        chain_pin=pins.live_chain,
        finality_pin=pins.finality_verifier,
        target_triple=target,
        finality_binary=str(tmp_path / "observer"),
        chain_spec=str(tmp_path / "chain.json"),
        proof_binary=str(tmp_path / "proof"),
        proof_binary_sha256="aa" * 32,
        state_directory=str(tmp_path / "origin"),
        minimum_finalized_block=pins.finality_verifier.bootstrap_block_number,
    )
    config = EndpointDispatchConfig(
        schema="umi-endpoint-dispatch-config/1",
        policy_sha256=digest(item.policy),
        legacy_policy_sha256=scoring_policy_hash(item.legacy_policy),
        chain=chain,
        journal_directory=str(feed.journal.path.parent),
        publication_directory=str(tmp_path / "publications"),
        wallet_name="evaluator",
        hotkey_name="sn78",
        wallet_path=str(tmp_path / "wallets"),
        evaluator_hotkey=item.validator_wallet.hotkey.ss58_address,
    )

    class TestOriginProvider:
        """Synthetic in-process owned-source port, never a production config option."""

        calls = 0
        invalid_origin = False
        fail = False

        async def verified_blocks(self, heights=()):
            if self.fail:
                raise ValueError("test unavailable proof source")
            block = item.finalized_blocks.blocks[item.request.issued_block]
            return block, tuple(item.finalized_blocks.blocks[h] for h in heights)

        async def dispatch_origin(self, signed, issued_block):
            self.calls += 1
            block = item.finalized_blocks.blocks[issued_block]
            capture = EndpointOriginCapture(
                digest(signed.submission),
                6,
                signed.submission.hotkey,
                "https://1.1.1.1:443" if self.invalid_origin else item.serving_origin,
                block.height,
                block.block_hash,
                block.state_root,
                block.timestamp_ms,
                b"test-proof",
                "https://8.8.8.8:443" if "example.org" in item.serving_origin else None,
            )
            return DispatchOrigin(capture, block, block)

    provider = TestOriginProvider()
    (tmp_path / "publications").mkdir(mode=0o700)
    miner = dynamic_runtime(feed, tmp_path / "miner")
    videos = {hashlib.sha256(data).hexdigest(): data for data in item.all_video_bytes}

    async def fetch_video(descriptor):
        miner.video_fetcher.calls += 1
        return videos[descriptor.sha256]

    miner.video_fetcher.fetch = fetch_video
    driver = EndpointDispatcher(
        config,
        feed.journal,
        provider,
        item.validator_wallet,
        transport=httpx.ASGITransport(app=create_app(miner)),
    )
    key = assignment_key(item.publication, item.publication.publication.assignments[0])
    result = SimpleNamespace(
        feed=feed,
        config=config,
        provider=provider,
        miner=miner,
        driver=driver,
        key=key,
    )
    yield result
    miner.resource_ledger.close()


async def ready(dispatch):
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.provider.calls == 0
    await dispatch.miner.competition_authority.poll_once()
    dispatch.feed.clock.ns += dispatch.config.discovery_grace_seconds * 1_000_000_000


async def test_real_dispatch_discovers_sends_authenticated_request_and_retains_result(dispatch):
    item = dispatch.feed.item
    await ready(dispatch)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "completed"
    transcript = json.loads(dispatch.feed.journal.outcome(dispatch.key))
    assert transcript["no_weight"] and not transcript["evidence_verified"]
    assert transcript["failure_code"] is None
    validate_response_envelope(
        bytes.fromhex(transcript["envelope_hex"]),
        transcript["response_signature"],
        request=item.request,
        validator_hotkey=item.validator_wallet.hotkey.ss58_address,
        miner_hotkey=item.miner_wallet.hotkey.ss58_address,
    )
    assert dispatch.miner.translator.calls == dispatch.miner.video_fetcher.calls == 1
    journal = AssignmentPublicationJournal(
        dispatch.feed.journal.path.parent,
        item.policy,
        item.legacy_policy,
    )
    restarted = EndpointDispatcher(
        dispatch.config,
        journal,
        dispatch.provider,
        item.validator_wallet,
        transport=dispatch.driver.transport,
    )
    assert await restarted.dispatch_one(dispatch.key) == "held"
    assert dispatch.miner.translator.calls == 1


async def test_invalid_origin_never_claims_or_signs(dispatch, monkeypatch):
    await ready(dispatch)
    dispatch.provider.invalid_origin = True
    monkeypatch.setattr(
        "umi.competition_dispatch.prepare_request_attempt", lambda *a, **kw: pytest.fail("signed")
    )
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "published"
    assert dispatch.miner.translator.calls == 0


@pytest.mark.parametrize("authorization", ["https://miner.example.org:443"], indirect=True)
async def test_hostname_dispatch_keeps_host_sni_and_authenticated_response(dispatch, monkeypatch):
    await ready(dispatch)
    transport = dispatch.driver.transport
    original = transport.handle_async_request
    requests = []

    async def record(request):
        requests.append(request)
        assert str(request.url).startswith("https://8.8.8.8/")
        assert request.headers["host"] == "miner.example.org"
        assert request.extensions["sni_hostname"] == "miner.example.org"
        return await original(request)

    async def forbidden(*args):
        pytest.fail("second DNS lookup")

    monkeypatch.setattr(transport, "handle_async_request", record)
    monkeypatch.setattr("umi.validator._system_origin_resolver", forbidden)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "completed"
    transcript = json.loads(dispatch.feed.journal.outcome(dispatch.key))
    assert transcript["failure_code"] is None
    item = dispatch.feed.item
    validate_response_envelope(
        bytes.fromhex(transcript["envelope_hex"]),
        transcript["response_signature"],
        request=item.request,
        validator_hotkey=item.validator_wallet.hotkey.ss58_address,
        miner_hotkey=item.miner_wallet.hotkey.ss58_address,
    )
    assert len(requests) == dispatch.miner.translator.calls == 1
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"


async def test_other_evaluator_never_claims(dispatch, monkeypatch):
    other = next(
        a
        for a in dispatch.feed.item.publication.publication.assignments
        if a.evaluator_hotkey != dispatch.config.evaluator_hotkey
    )
    key = assignment_key(dispatch.feed.item.publication, other)
    monkeypatch.setattr(
        "umi.competition_dispatch.prepare_request_attempt", lambda *a, **kw: pytest.fail("signed")
    )
    assert await dispatch.driver.dispatch_one(key) == "held"
    assert dispatch.feed.journal.status(key)["state"] == "published"


async def test_cancelled_transmission_stays_uncertain_across_restart(dispatch, monkeypatch):
    await ready(dispatch)
    entered = asyncio.Event()

    async def hanging(*a, **kw):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr("umi.competition_dispatch.send_prepared_request", hanging)
    task = asyncio.create_task(dispatch.driver.dispatch_one(dispatch.key))
    await asyncio.wait_for(entered.wait(), timeout=2)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "uncertain_dispatched"
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"


async def test_unavailable_origin_remains_unclaimed(dispatch):
    dispatch.provider.fail = True
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "published"


async def test_disk_failure_after_send_cannot_cause_retry(dispatch, monkeypatch):
    await ready(dispatch)

    def full(*a, **kw):
        raise OSError("test disk full")

    monkeypatch.setattr(dispatch.feed.journal, "complete", full)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "uncertain"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "uncertain_dispatched"
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert dispatch.miner.translator.calls == 1


async def test_expired_assignment_is_not_miner_failure(dispatch):
    page = dispatch.feed.journal.pending_dispatches(
        evaluator_hotkey=dispatch.config.evaluator_hotkey
    )
    dispatch.feed.clock.ns = max(i["issue_close_unix_ms"] for i in page["items"]) * 1_000_000
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    status = dispatch.feed.journal.status(dispatch.key)
    assert status["state"] == "expired" and status["miner_fault"] is False


async def test_competing_dispatchers_transmit_at_most_once(dispatch):
    await ready(dispatch)
    statuses = await asyncio.gather(*(dispatch.driver.dispatch_one(dispatch.key) for _ in range(2)))
    assert sorted(statuses) == ["completed", "held"]
    assert dispatch.miner.translator.calls == 1


def test_wrong_wallet_rejected(dispatch):
    with pytest.raises(ValueError, match="wallet"):
        EndpointDispatcher(dispatch.config, dispatch.feed.journal, dispatch.provider, wallet("Bob"))


@pytest.mark.parametrize(
    "change",
    [
        {"maximum_concurrency": 9},
        {"discovery_grace_seconds": 0},
        {"page_size": 101},
        {"wallet_path": "/"},
        {"wallet_path": "relative"},
        {"no_weight": False},
        {"request_timeout_seconds": 601},
        {"poll_seconds": 0},
        {"wallet_name": "../coldkey"},
    ],
)
def test_configuration_bounds(dispatch, change):
    with pytest.raises(ValueError):
        EndpointDispatchConfig.model_validate(
            {**dispatch.config.model_dump(by_alias=True), **change}
        )


def test_state_and_wallet_paths_must_be_separate(dispatch):
    with pytest.raises(ValueError, match="separate"):
        EndpointDispatchConfig.model_validate(
            {
                **dispatch.config.model_dump(by_alias=True),
                "wallet_path": dispatch.config.journal_directory,
            }
        )


def test_dispatch_queue_paginates_only_own_unclaimed_assignments(dispatch):
    journal = dispatch.feed.journal
    cursor, keys = None, []
    while True:
        page = journal.pending_dispatches(
            evaluator_hotkey=dispatch.config.evaluator_hotkey, after=cursor, limit=1
        )
        keys.extend(i["assignment_key"] for i in page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert len(keys) == len(set(keys)) == 3
    pub = dispatch.feed.item.publication
    assert set(keys) == {
        assignment_key(pub, a)
        for a in pub.publication.assignments
        if a.evaluator_hotkey == dispatch.config.evaluator_hotkey
    }


async def test_poll_concurrency_is_one_per_miner_and_close_cancels(dispatch, monkeypatch):
    entered = asyncio.Event()

    async def hanging(*a, **kw):
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(dispatch.driver, "dispatch_one", hanging)
    first = await dispatch.driver.poll_once()
    await asyncio.wait_for(entered.wait(), timeout=2)
    second = await dispatch.driver.poll_once()
    assert first["in_flight"] == second["in_flight"] == 1
    await dispatch.driver.aclose()
    assert not dispatch.driver._tasks


async def test_restart_restarts_discovery_grace_without_changing_signed_times(dispatch):
    await ready(dispatch)
    restarted = EndpointDispatcher(
        dispatch.config,
        dispatch.feed.journal,
        dispatch.provider,
        dispatch.feed.item.validator_wallet,
        transport=dispatch.driver.transport,
    )
    assert await restarted.dispatch_one(dispatch.key) == "held"
    assert dispatch.feed.journal.status(dispatch.key)["state"] == "published"
    assert dispatch.provider.calls == 0


def inbox_file(dispatch, publication=None):
    publication = publication or dispatch.feed.item.publication
    path = Path(dispatch.config.publication_directory) / (digest(publication.publication) + ".json")
    path.write_bytes(canonical_json_bytes(publication))
    path.chmod(0o600)
    return path


async def test_inbox_populates_empty_journal_idempotently_across_restart(dispatch, tmp_path):
    item = dispatch.feed.item
    directory = tmp_path / "new-journal"
    journal = AssignmentPublicationJournal(directory, item.policy, item.legacy_policy)
    config = dispatch.config.model_copy(update={"journal_directory": str(directory)})
    driver = EndpointDispatcher(config, journal, dispatch.provider, item.validator_wallet)
    inbox_file(dispatch)
    assert await driver.ingest_once() == "retained"
    original = journal.publication_status(digest(item.publication.publication))
    assert await driver.ingest_once() == "idle"
    restarted = EndpointDispatcher(config, journal, dispatch.provider, item.validator_wallet)
    assert await restarted.ingest_once() == "retained"
    assert journal.publication_status(digest(item.publication.publication)) == original


@pytest.mark.parametrize("mutation", ["signature", "noncanonical", "filename", "symlink", "public"])
async def test_invalid_inbox_bytes_never_reach_provider(dispatch, monkeypatch, mutation):
    path = inbox_file(dispatch)
    if mutation == "signature":
        document = json.loads(path.read_bytes())
        document["signatures"][0]["signature"] = "0x" + "00" * 64
        path.write_bytes(canonical_json_bytes(document))
    elif mutation == "noncanonical":
        path.write_bytes(b" " + path.read_bytes())
    elif mutation == "filename":
        path.rename(path.with_name("ff" * 32 + ".json"))
    elif mutation == "symlink":
        target = path.with_suffix(".retained")
        path.rename(target)
        path.symlink_to(target)
    elif mutation == "public":
        path.chmod(0o644)

    async def forbidden(*args, **kwargs):
        pytest.fail("provider accessed")

    monkeypatch.setattr(dispatch.provider, "verified_blocks", forbidden)
    with pytest.raises((OSError, ValueError)):
        await dispatch.driver.ingest_once()


async def test_inbox_rejection_does_not_prevent_pending_dispatch(dispatch):
    await ready(dispatch)
    (Path(dispatch.config.publication_directory) / "invalid.json").write_bytes(b"{}")
    status = await dispatch.driver.poll_once()
    assert status["publication_intake"] == "held" and status["in_flight"] == 1
    await dispatch.driver.drain()
    assert dispatch.miner.translator.calls == 1
    await dispatch.driver.aclose()


async def test_timeout_after_claim_is_not_retried(dispatch, monkeypatch):
    await ready(dispatch)
    calls = 0

    async def failed(*args, **kwargs):
        nonlocal calls
        calls += 1
        raise asyncio.TimeoutError

    monkeypatch.setattr("umi.competition_dispatch.send_prepared_request", failed)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "uncertain"
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert calls == 1


async def test_transport_deadline_retains_timeout_and_partial_bytes_without_retry(dispatch):
    await ready(dispatch)
    calls = 0

    class SlowBody(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"partial"
            await asyncio.Future()

    async def delayed(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, stream=SlowBody())

    dispatch.driver.config = dispatch.config.model_copy(update={"request_timeout_seconds": 1})
    dispatch.driver.transport = httpx.MockTransport(delayed)
    assert (
        await asyncio.wait_for(dispatch.driver.dispatch_one(dispatch.key), timeout=5) == "completed"
    )
    transcript = json.loads(dispatch.feed.journal.outcome(dispatch.key))
    assert transcript["failure_code"] == "transport_timeout"
    assert transcript["envelope_hex"] is None
    assert transcript["received_body_prefix_hex"] == b"partial".hex()
    assert transcript["received_bytes_sha256"] == hashlib.sha256(b"partial").hexdigest()
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert calls == 1


async def test_wrong_cli_wallet_never_starts_provider(dispatch, monkeypatch):
    from umi.competition_dispatch import run_dispatch

    monkeypatch.setattr("bittensor.Wallet", lambda **kwargs: wallet("Bob"))
    monkeypatch.setattr(
        "umi.competition_dispatch.DispatchFinalityProvider",
        lambda *a, **kw: pytest.fail("observer started"),
    )
    with pytest.raises(ValueError, match="hotkey"):
        await run_dispatch(
            dispatch.config, dispatch.feed.item.policy, dispatch.feed.item.legacy_policy, once=True
        )


async def test_signed_response_replay_needs_the_real_matching_reveal(dispatch):
    from umi.competition_dispatch_replay import replay_dispatch_transcript

    await ready(dispatch)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "completed"
    with pytest.raises(ValueError, match="reveal pulse"):
        replay_dispatch_transcript(
            dispatch.feed.journal, dispatch.key, suite=dispatch.feed.item.suite, reveal_pulse=None
        )


async def test_recorded_transport_failure_replays_as_infrastructure_without_resending(dispatch):
    from umi.competition_dispatch_replay import replay_dispatch_transcript

    await ready(dispatch)
    calls = 0

    async def unavailable(request):
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    dispatch.driver.transport = httpx.MockTransport(unavailable)
    assert await dispatch.driver.dispatch_one(dispatch.key) == "completed"
    replay = replay_dispatch_transcript(
        dispatch.feed.journal, dispatch.key, suite=dispatch.feed.item.suite, reveal_pulse=None
    )
    assert replay.output.status == "infrastructure_failure"
    assert calls == 1
    assert await dispatch.driver.dispatch_one(dispatch.key) == "held"
    assert calls == 1


async def test_continuous_polls_complete_all_cases_once_then_accept_next_round(dispatch):
    from .test_competition_scheduling import _new_sequence

    await ready(dispatch)
    for _ in range(5):
        await dispatch.driver.poll_once()
        await dispatch.driver.drain()
        dispatch.feed.clock.ns += 1
    assert dispatch.miner.translator.calls == 3
    assert dispatch.driver._counts["completed"] == 3
    second = _new_sequence(SimpleNamespace(authorization=dispatch.feed.item), 2)
    inbox_file(dispatch, second)
    await dispatch.driver.poll_once()
    await dispatch.driver.drain()
    await dispatch.miner.competition_authority.poll_once()
    dispatch.feed.clock.ns += dispatch.config.discovery_grace_seconds * 1_000_000_000
    for _ in range(5):
        await dispatch.driver.poll_once()
        await dispatch.driver.drain()
        dispatch.feed.clock.ns += 1
    assert dispatch.miner.translator.calls == 6
    assert dispatch.driver._counts["completed"] == 6
    assert not dispatch.driver._tasks
    await dispatch.driver.aclose()
