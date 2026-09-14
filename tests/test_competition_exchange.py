from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_exchange as exchange
from umi.competition_evaluator import ContinuousEvaluator, EvaluatorConfig, _read
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_endpoint_execution import authorization as authorization
from .test_competition_endpoint_execution import dispatch as dispatch
from .test_competition_endpoint_execution import feed as feed
from .test_competition_endpoint_execution import paired_setup as paired_setup
from .test_competition_evaluator import (
    Provider,
    completed,
    execute,
    make_driver,
    put,
    signed_order,
)
from .test_competition_evaluator import chain_config as chain_config
from .test_competition_evaluator import model_setup as model_setup
from .test_competition_evaluator import policy as base_policy
from .test_competition_evaluator import runtime as runtime
from .test_open_competition import wallet


@pytest.fixture
def policy():
    original = base_policy.__wrapped__()
    extra = original.evaluators[0].model_copy(
        update={"hotkey": wallet("Eve").hotkey.ss58_address, "control_group": "e"}
    )
    return original.model_copy(update={"evaluators": (*original.evaluators, extra)})


@pytest.fixture
def relay(model_setup, chain_config, tmp_path):
    policy, job, suite, archive, videos, calls = model_setup
    wallets = (wallet("Charlie"), wallet("Dave"))
    order = signed_order(job, wallets)
    config = exchange.ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(policy),
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(policy),
                "state_directory": str(tmp_path / "relay-chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "relay-state"),
        order_directory=str(tmp_path / "relay-orders"),
        reveal_directory=str(tmp_path / "relay-reveals"),
    )
    put(Path(config.order_directory) / (digest(order.order) + ".json"), order)
    put(Path(config.reveal_directory) / (digest(suite) + ".json"), suite)
    provider = Provider()
    app = exchange.create_exchange_app(config, policy, provider_factory=lambda *_: provider)
    transport = httpx.ASGITransport(app=app)
    drivers = tuple(
        make_driver(tmp_path / f"worker-{i}", chain_config, policy, archive, videos, w)
        for i, w in enumerate(wallets)
    )
    clients = tuple(
        exchange.EvaluatorExchangeClient(d, "https://relay.example", transport=transport)
        for d in drivers
    )
    return SimpleNamespace(
        config=config,
        policy=policy,
        job=job,
        suite=suite,
        order=order,
        provider=provider,
        app=app,
        transport=transport,
        drivers=drivers,
        clients=clients,
        wallets=wallets,
        calls=calls,
    )


def request(relay, signer=None, payload=None, **fields):
    signer = signer or relay.wallets[0]
    query = exchange.ExchangeQuery(
        schema="umi-evaluator-exchange-query/1",
        policy_sha256=digest(relay.policy),
        hotkey=signer.hotkey.ss58_address,
        nonce_unix_ns=str(time.time_ns()),
        operation="list",
    ).model_copy(update=fields)
    return exchange.ExchangeRequest(
        query=query, signature=sign_object(query, signer), payload=payload
    )


async def raw_post(relay, body, **kwargs):
    async with httpx.AsyncClient(
        transport=relay.transport, base_url="https://relay.example"
    ) as client:
        return await client.post(
            exchange.ROUTE, content=body, headers={"Content-Type": "application/json"}, **kwargs
        )


async def finish(relay):
    for c in relay.clients:
        await c.sync_once()
    await execute(relay.drivers)
    relay.provider.block = relay.order.order.round.reveal_block
    for d in relay.drivers:
        d.provider.block = relay.provider.block
    for _ in range(8):
        for c, d in zip(relay.clients, relay.drivers, strict=True):
            await c.sync_once()
            await d.poll_once()
    for c in relay.clients:
        await c.sync_once()


@pytest.mark.asyncio
async def test_two_evaluators_agree_over_authenticated_http_without_file_copy(relay):
    assert all(not list(Path(d.config.order_directory).glob("*.json")) for d in relay.drivers)
    await finish(relay)
    first, second = (completed(d)[0] for d in relay.drivers)
    assert first == second
    assert sum(isinstance(c, dict) for c in relay.calls) == 12
    journal = exchange.ExchangeJournal(relay.config, relay.policy)
    with journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM events WHERE kind='independent'").fetchone()[0] == 2
    for d in relay.drivers:
        await d.aclose()


@pytest.mark.asyncio
async def test_same_clients_advance_to_another_round_without_restart(relay):
    await finish(relay)
    suite = relay.suite.model_copy(
        update={
            "cases": tuple(
                c.model_copy(update={"references": ("hello again", "hi again", "greetings again")})
                for c in relay.suite.cases
            )
        }
    )
    round_ = relay.job.round.model_copy(
        update={
            "sequence": 2,
            "suite_sha256": digest(suite),
            "submission_close_block": 160,
            "evaluation_close_block": 180,
            "reveal_block": 190,
            "valid_through_block": 200,
        }
    )
    order = signed_order(relay.job.model_copy(update={"round": round_}), relay.wallets)
    put(Path(relay.config.order_directory) / (digest(order.order) + ".json"), order)
    put(Path(relay.config.reveal_directory) / (digest(suite) + ".json"), suite)
    relay.order = order
    relay.provider.block = 165
    for d in relay.drivers:
        d.provider.block = 165
    await finish(relay)
    assert all(len(completed(d)) == 2 for d in relay.drivers)
    assert sum(isinstance(c, dict) for c in relay.calls) == 24
    for d in relay.drivers:
        await d.aclose()


@pytest.mark.asyncio
async def test_reveal_is_withheld_until_owned_boundary_and_cursor_never_skips_it(relay):
    listing = await relay.clients[0].query("list")
    assert [e.kind for e in listing.items] == ["order"]
    assert "references" not in canonical_json_bytes(listing).decode()
    await relay.clients[0].sync_once()
    assert not list(Path(relay.drivers[0].config.reveal_directory).iterdir())
    relay.provider.block = relay.order.order.round.reveal_block
    # A dishonest/advanced relay cannot make the local worker publish early.
    with pytest.raises(ValueError, match="premature"):
        await relay.clients[0].sync_once()
    relay.drivers[0].provider.block = relay.provider.block
    await relay.clients[0].sync_once()
    assert (
        _read(
            Path(relay.drivers[0].config.reveal_directory) / (digest(relay.suite) + ".json"),
            exchange.EvaluationSuite,
        )
        == relay.suite
    )


@pytest.mark.asyncio
async def test_unknown_hotkey_cannot_read_or_consume_nonce_space(relay):
    response = await raw_post(relay, canonical_json_bytes(request(relay, signer=wallet("Bob"))))
    assert response.status_code == 401
    with sqlite3.connect(Path(relay.config.state_directory) / "nonces.sqlite3") as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_nonces").fetchone()[0] == 0
    assert relay.provider.calls == 0


@pytest.mark.asyncio
async def test_policy_evaluator_outside_order_audience_cannot_fetch_it(relay):
    # Alice is a configured evaluator but is not in this order's fixed pair.
    assigned = {identity(k) for k in relay.order.order.evaluators}
    other = next(
        wallet(n)
        for n in ("Alice", "Bob", "Eve")
        if identity(wallet(n).hotkey.ss58_address)
        in {identity(e.hotkey) for e in relay.policy.evaluators}
        and identity(wallet(n).hotkey.ss58_address) not in assigned
    )
    await relay.clients[0].query("list")
    response = await raw_post(
        relay, canonical_json_bytes(request(relay, signer=other, operation="item", event=1))
    )
    assert response.status_code != 200
    assert "incumbent" not in response.text and "video" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["signature", "stale", "future", "policy", "noncanonical"])
async def test_bad_request_cannot_disclose_data(relay, mutation):
    signed = request(relay)
    data = signed.model_dump(mode="json", by_alias=True)
    if mutation == "signature":
        data["signature"]["signature"] = "0x" + "00" * 64
    elif mutation in {"stale", "future"}:
        delta = -31_000_000_000 if mutation == "stale" else 6_000_000_000
        signed = request(relay, nonce_unix_ns=str(time.time_ns() + delta))
        data = signed.model_dump(mode="json", by_alias=True)
    elif mutation == "policy":
        data = request(relay, policy_sha256="00" * 32).model_dump(mode="json", by_alias=True)
    raw = canonical_json_bytes(data)
    if mutation == "noncanonical":
        raw = b" " + raw
    response = await raw_post(relay, raw)
    assert response.status_code == 401
    assert "order_sha256" not in response.text


@pytest.mark.asyncio
async def test_nonce_survives_server_restart(relay):
    raw = canonical_json_bytes(request(relay))
    assert (await raw_post(relay, raw)).status_code == 200
    relay.app = exchange.create_exchange_app(
        relay.config, relay.policy, provider_factory=lambda *_: relay.provider
    )
    relay.transport = httpx.ASGITransport(app=relay.app)
    assert (await raw_post(relay, raw)).status_code == 401


@pytest.mark.asyncio
async def test_restart_delivery_is_idempotent_and_preserves_output_bytes(relay):
    await finish(relay)
    before = tuple(canonical_json_bytes(completed(d)[0]) for d in relay.drivers)
    new = []
    for d in relay.drivers:
        await d.aclose()
        copy = ContinuousEvaluator(d.config, d.policy, d.wallet, d.provider)
        client = exchange.EvaluatorExchangeClient(
            copy, "https://relay.example", transport=relay.transport
        )
        await client.sync_once()
        await copy.poll_once()
        new.append(copy)
    assert tuple(canonical_json_bytes(completed(d)[0]) for d in new) == before
    assert sum(isinstance(c, dict) for c in relay.calls) == 12
    for d in new:
        await d.aclose()


@pytest.mark.asyncio
async def test_conflicting_signed_peer_retained_and_holds_only_its_order(relay):
    await finish(relay)
    source = relay.drivers[0]
    path = next(Path(source.config.outbox_directory).glob("*.execution.json"))
    original = _read(path, exchange.SignedExecutionAnnouncement)
    # Valid transport signature, changed execution timestamps. Body replay still
    # succeeds; agreement and the original retained bytes must remain held.
    body = original.announcement
    steps = body.evidence.steps
    changed_output = steps[0].execution.output.model_copy(update={"elapsed_ms": 11})
    changed_step = steps[0].model_copy(
        update={"execution": steps[0].execution.model_copy(update={"output": changed_output})}
    )
    changed = body.evidence.model_copy(update={"steps": (changed_step, *steps[1:])})
    body = body.model_copy(update={"evidence": changed})
    alternate = exchange.SignedExecutionAnnouncement(
        announcement=body, signature=sign_object(body, source.wallet)
    )
    await relay.clients[0].query(
        "put",
        payload=alternate.model_dump(mode="json", by_alias=True),
        order_sha256=digest(relay.order.order),
        kind="execution",
        payload_sha256=digest(alternate),
    )
    for _ in range(4):
        await relay.clients[1].sync_once()
    target = relay.drivers[1]
    assert target.journal.orders()[0][2] is True
    await target.poll_once()
    new = ContinuousEvaluator(target.config, target.policy, target.wallet, target.provider)
    assert new.journal.orders()[0][2] is True
    await new.aclose()


@pytest.mark.asyncio
async def test_server_refuses_upload_as_another_assigned_evaluator(relay):
    await finish(relay)
    path = next(Path(relay.drivers[0].config.outbox_directory).glob("*.execution.json"))
    value = _read(path, exchange.SignedExecutionAnnouncement)
    with pytest.raises(ValueError, match="rejected"):
        await relay.clients[1].query(
            "put",
            payload=value.model_dump(mode="json", by_alias=True),
            order_sha256=digest(relay.order.order),
            kind="execution",
            payload_sha256=digest(value),
        )


@pytest.mark.asyncio
async def test_transport_claim_cannot_replace_owned_finality(relay):
    await relay.clients[0].query("list")
    relay.provider.block -= 1
    with pytest.raises(ValueError, match="rejected"):
        await relay.clients[0].query("list")


def test_quota_and_database_permissions_preserve_retained_history(relay):
    config = relay.config.model_copy(update={"maximum_events": 1})
    journal = exchange.ExchangeJournal(config, relay.policy)
    journal.ingest(125)
    with pytest.raises(ValueError, match="capacity"):
        journal.append(digest(relay.order.order), "suite", None, relay.suite, 150)
    assert journal.object(digest(relay.order.order), "order") == relay.order
    journal.path.chmod(0o644)
    with pytest.raises(ValueError, match="private"):
        journal.object(digest(relay.order.order), "order")


@pytest.mark.asyncio
async def test_http_headers_size_and_response_binding(relay, monkeypatch):
    monkeypatch.setattr(exchange, "MAX_WIRE_BYTES", 100)
    response = await raw_post(relay, canonical_json_bytes(request(relay)))
    assert response.status_code == 413


def test_suite_reuse_across_rounds_is_rejected(relay):
    journal = exchange.ExchangeJournal(relay.config, relay.policy)
    journal.ingest(125)
    round_ = relay.job.round.model_copy(
        update={
            "sequence": 2,
            "submission_close_block": 160,
            "evaluation_close_block": 180,
            "reveal_block": 190,
            "valid_through_block": 200,
        }
    )
    order = signed_order(relay.job.model_copy(update={"round": round_}), relay.wallets)
    with pytest.raises(ValueError, match="suite cannot be reused"):
        journal.append(digest(order.order), "order", None, order, 165)


@pytest.mark.asyncio
async def test_worker_attaches_exchange_without_blocking_execution_or_shutdown(relay):
    d = relay.drivers[0]
    # Fresh state binds the exchange; no arbitrary wallet or provider factory
    # can be named through the production configuration.
    config = d.config.model_copy(
        update={
            "state_directory": str(Path(d.config.state_directory).parent / "attached-state"),
            "exchange_origin": "https://relay.example",
        }
    )
    driver = ContinuousEvaluator(config, d.policy, d.wallet, d.provider)
    driver.exchange.transport = relay.transport
    await driver.poll_once()
    await driver._exchange_task
    await driver.poll_once()
    assert driver._tasks
    await driver.aclose()
    assert driver._exchange_task is None and not driver._tasks


def test_configuration_rejects_wallet_overlap_and_plain_http(relay):
    config = relay.drivers[0].config
    for update in (
        {"exchange_origin": "http://relay.example"},
        {"assignment_directory": config.wallet_path, "exchange_origin": "https://relay.example"},
    ):
        with pytest.raises(ValueError):
            EvaluatorConfig.model_validate_json(
                canonical_json_bytes(config.model_copy(update=update))
            )


@pytest.mark.asyncio
@pytest.mark.parametrize("arrival", [150, 161])
async def test_collection_retains_actual_store_arrival_without_backdating(relay, tmp_path, arrival):
    from umi.competition_settlement import EvidenceCutoffSchedule
    from umi.competition_store import CompetitionStore

    from .test_open_competition import snapshot

    store = CompetitionStore(tmp_path / "intake", relay.policy)
    store.initialize_baseline(relay.job.incumbent, Path(relay.drivers[0].config.archive_directory))
    store.admit(relay.job.submission, snapshot(), 110)
    store.fix_evidence_cutoff(
        relay.job.round,
        EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(relay.policy),
            round_sha256=digest(relay.job.round),
            evidence_cutoff_block=160,
        ),
        observed_block=120,
    )
    store.close_round(relay.job.round, current_block=120)
    await finish(relay)
    journal = exchange.ExchangeJournal(relay.config, relay.policy)
    journal.collect(store, observed_block=arrival)
    with journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM collected").fetchone()[0] == 2
    with store._connection() as db:
        rows = db.execute(
            "SELECT first_observed_block FROM independent_evaluation_evidence"
        ).fetchall()
    assert rows == [(arrival,)]
    journal.collect(store, observed_block=arrival + 1)
    with journal.transaction() as db:
        assert db.execute("SELECT COUNT(*) FROM collected").fetchone()[0] == 2


@pytest.mark.asyncio
async def test_lost_ack_can_retry_exact_bytes_after_round_expiry(relay):
    await finish(relay)
    source = relay.drivers[0]
    value = _read(
        next(Path(source.config.outbox_directory).glob("*.execution.json")),
        exchange.SignedExecutionAnnouncement,
    )
    fields = dict(
        payload=value.model_dump(mode="json", by_alias=True),
        order_sha256=digest(relay.order.order),
        kind="execution",
        payload_sha256=digest(value),
    )
    first = await relay.clients[0].query("put", **fields)
    relay.provider.block = relay.job.round.valid_through_block + 1
    again = await relay.clients[0].query("put", **fields)
    assert first.items == again.items


@pytest.mark.asyncio
async def test_bad_list_or_download_cannot_advance_cursor(relay):
    query = request(relay)

    async def bad_reply(request):
        signed = exchange.ExchangeRequest.model_validate_json(request.content)
        body = exchange.ExchangeReply(
            query_sha256="00" * 32, policy_sha256=signed.query.policy_sha256, head=0
        )
        return httpx.Response(
            200, content=canonical_json_bytes(body), headers={"Content-Type": "application/json"}
        )

    with pytest.raises(ValueError, match="binding"):
        await exchange.request_exchange(
            "https://relay.example", query, transport=httpx.MockTransport(bad_reply)
        )


def test_loopback_service_cli_constructs_fixed_exchange(relay, tmp_path, monkeypatch):
    from umi.competition_cli import _parser
    from umi.competition_cli import execute as cli_execute

    policy_path, config_path = tmp_path / "policy.json", tmp_path / "config.json"
    put(policy_path, relay.policy)
    put(config_path, relay.config)
    calls = []
    monkeypatch.setattr(
        exchange,
        "serve_exchange",
        lambda config, policy, legacy: calls.append((config, policy, legacy)),
    )
    result = cli_execute(
        _parser().parse_args(
            ["--policy", str(policy_path), "serve-evaluator-exchange", "--config", str(config_path)]
        )
    )
    assert calls == [(relay.config, relay.policy, None)]
    assert result["chain_submission_authorized"] is False


@pytest.mark.asyncio
async def test_endpoint_order_delivery_populates_the_real_dispatch_inbox(
    paired_setup, chain_config, tmp_path
):
    from .test_competition_endpoint_execution import make_job

    item = paired_setup.dispatch.feed.item
    signers = item.evaluator_wallets[:2]
    order = signed_order(make_job(paired_setup), signers, publication=item.publication)
    config = exchange.ExchangeConfig(
        schema="umi-evaluator-exchange-config/1",
        policy_sha256=digest(item.policy),
        legacy_policy_sha256=exchange.scoring_policy_hash(item.legacy_policy),
        chain=chain_config.model_copy(
            update={
                "policy_sha256": digest(item.policy),
                "state_directory": str(tmp_path / "relay-chain"),
                "collection_timeout_seconds": 10,
            }
        ),
        state_directory=str(tmp_path / "relay-state"),
        order_directory=str(tmp_path / "relay-orders"),
        reveal_directory=str(tmp_path / "relay-reveals"),
    )
    provider = Provider(item.request.issued_block)
    app = exchange.create_exchange_app(
        config, item.policy, legacy=item.legacy_policy, provider_factory=lambda *_: provider
    )
    put(Path(config.order_directory) / (digest(order.order) + ".json"), order)
    for i, signer in enumerate(signers):
        first = make_driver(
            tmp_path / f"endpoint-{i}",
            chain_config,
            item.policy,
            paired_setup.archive,
            paired_setup.videos,
            signer,
            legacy=item.legacy_policy,
            dispatch=paired_setup.dispatch.feed.journal.path.parent,
        )
        updated = first.config.model_copy(
            update={
                "exchange_origin": "https://relay.example",
                "assignment_directory": str(tmp_path / f"dispatch-inbox-{i}"),
                "state_directory": str(tmp_path / f"attached-endpoint-{i}"),
            }
        )
        driver = ContinuousEvaluator(
            updated, item.policy, signer, provider, legacy=item.legacy_policy
        )
        driver.exchange.transport = httpx.ASGITransport(app=app)
        await driver.exchange.sync_once()
        destination = Path(updated.assignment_directory) / (
            digest(item.publication.publication) + ".json"
        )
        assert destination.read_bytes() == canonical_json_bytes(item.publication)
        assert destination.stat().st_mode & 0o077 == 0
        await driver.aclose()
