from __future__ import annotations

import asyncio
from dataclasses import replace
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_miner_feed import FeedEndpointAuthorizationAuthority
from umi.miner import build_runtime, create_app
from umi.miner_admission import MinerAdmissionError
from umi.open_competition import digest
from umi.window import QUICKNET_GENESIS_MS, QUICKNET_PERIOD_MS

from .test_competition_authorization import authorization as authorization
from .test_competition_feed import feed as feed
from .test_competition_miner import authorized_runtime, post_assignment
from .test_competition_scheduling import _new_sequence
from .test_open_competition import policy as policy


def dynamic_runtime(feed, tmp_path):
    case = feed.item
    base = authorized_runtime(case, tmp_path)
    authority = FeedEndpointAuthorizationAuthority(
        policy=case.policy,
        legacy_policy=case.legacy_policy,
        finalized_blocks=case.finalized_blocks,
        miner_hotkey=case.miner_wallet.hotkey.ss58_address,
        model_revision=case.model_revision,
        serving_origin=case.serving_origin,
        origin="https://assignments.example",
        wallet=case.miner_wallet,
        transport=httpx.ASGITransport(app=feed.client.app),
    )
    return replace(base, competition_authority=authority)


async def test_discovery_installs_authorization_into_running_miner_without_restart(feed, tmp_path):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(miner)), base_url=feed.item.serving_origin
        ) as client:
            before = await post_assignment(client, feed.item)
            assert before.status_code != 200
            assert miner.translator.calls == 0
            await authority.poll_once()
            assert authority.status()["cached_publications"] == 1
            # The same app now accepts the exact newly discovered assignment.
            feed.clock.ns += 1
            after = await post_assignment(client, feed.item)
            assert after.status_code == 200, after.text
            assert miner.translator.calls == 1
            first_authority = next(iter(authority._publications.values()))[0]
            await authority.poll_once()
            assert next(iter(authority._publications.values()))[0] is first_authority
            health = (await client.get("/healthz")).json()
            assert health["authorization_sha256"] is None
            assert not health["chain_submission_authorized"]
            assert health["assignment_discovery"]["no_weight"]
            assert "https://assignments" not in str(health)
    finally:
        miner.resource_ledger.close()


async def test_two_round_publications_coexist_without_revoking_earlier_assignments(feed, tmp_path):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    try:
        authority.install(feed.item.publication)
        second = _new_sequence(SimpleNamespace(authorization=feed.item), 2)
        authority.install(second)
        for publication in (feed.item.publication, second):
            assignment = publication.publication.assignments[0]
            await authority.authorize(
                assignment.request, validator_hotkey=assignment.evaluator_hotkey
            )
        assert authority.status()["cached_publications"] == 2
    finally:
        miner.resource_ledger.close()


@pytest.mark.parametrize("mutation", ["signature", "revision", "origin"])
def test_bad_publication_cannot_replace_working_authority(feed, tmp_path, mutation):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    try:
        authority.install(feed.item.publication)
        if mutation == "signature":
            pub = feed.item.publication.model_copy(update={"signatures": ()})
        else:
            pub = feed.item.publication
            setattr(
                authority,
                "model_revision" if mutation == "revision" else "serving_origin",
                "ff" * 32 if mutation == "revision" else "https://other.example",
            )
        with pytest.raises(ValueError):
            authority.install(pub)
        assert authority.status()["cached_publications"] == 1
    finally:
        miner.resource_ledger.close()


async def test_expired_and_rollback_assignments_cannot_authorize(feed, tmp_path):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    try:
        authority.install(feed.item.publication)
        original = feed.clock.ns
        feed.clock.ns = (
            QUICKNET_GENESIS_MS + (feed.item.request.response_close_round - 1) * QUICKNET_PERIOD_MS
        ) * 1_000_000
        with pytest.raises(MinerAdmissionError):
            await authority.authorize(
                feed.item.request, validator_hotkey=feed.item.validator_wallet.hotkey.ss58_address
            )
        assert not authority._publications
        feed.clock.ns = original
        with pytest.raises(ValueError, match="backwards"):
            authority.install(feed.item.publication)
        assert authority.status()["reason_code"] == "assignment_clock_rollback"
    finally:
        miner.resource_ledger.close()


def test_cache_is_bounded_and_duplicate_does_not_reset_first_observation(feed, tmp_path):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    try:
        for n in range(1, 5):
            authority.install(_new_sequence(SimpleNamespace(authorization=feed.item), n))
        original = dict(authority._publications)
        assert not authority.install(feed.item.publication)
        assert authority._publications == original
        with pytest.raises(ValueError, match="capacity"):
            authority.install(_new_sequence(SimpleNamespace(authorization=feed.item), 5))
        assert authority._publications == original
    finally:
        miner.resource_ledger.close()


async def test_unavailable_publication_does_not_starve_next_item(feed, tmp_path, monkeypatch):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    good = digest(feed.item.publication.publication)
    calls = []

    async def query(**args):
        calls.append(args)
        if args["operation"] == "list":
            return {
                "items": [{"publication_sha256": "00" * 32}, {"publication_sha256": good}],
                "next_cursor": None,
            }
        if args["publication_sha256"] != good:
            raise ValueError("expired")
        return {"publication": feed.item.publication.model_dump(mode="json", by_alias=True)}

    monkeypatch.setattr(authority, "_query", query)
    try:
        await authority.poll_once()
        assert len(calls) == 3
        assert good in authority._publications
        assert authority.status()["reason_code"] == "assignment_publication_unavailable"
    finally:
        miner.resource_ledger.close()


async def test_poll_task_is_cancelled_at_miner_shutdown(feed, tmp_path, monkeypatch):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    entered, cancelled = asyncio.Event(), asyncio.Event()

    async def run(stop):
        entered.set()
        try:
            await asyncio.Event().wait()
        finally:
            cancelled.set()

    monkeypatch.setattr(authority, "run", run)
    app = create_app(miner)
    try:
        async with app.router.lifespan_context(app):
            await asyncio.wait_for(entered.wait(), 1)
        assert cancelled.is_set()
    finally:
        miner.resource_ledger.close()


def test_mutually_exclusive_sources_fail_before_wallet_access():
    with pytest.raises(ValueError, match="either"):
        build_runtime(
            SimpleNamespace(
                competition_feed="https://feed.example",
                competition_authorization="publication.json",
            )
        )


async def test_restart_rediscovers_without_repeating_cached_inference(feed, tmp_path):
    original = dynamic_runtime(feed, tmp_path)
    try:
        await original.competition_authority.poll_once()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(original)),
            base_url=feed.item.serving_origin,
        ) as client:
            first = await post_assignment(client, feed.item)
            assert first.status_code == 200
            assert original.translator.calls == 1
    finally:
        original.resource_ledger.close()
    feed.clock.ns += 1000
    restarted = dynamic_runtime(feed, tmp_path)
    try:
        assert restarted.competition_authority.status()["cached_publications"] == 0
        await restarted.competition_authority.poll_once()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(restarted)),
            base_url=feed.item.serving_origin,
        ) as client:
            again = await post_assignment(client, feed.item)
            assert again.status_code == 200
            assert again.content == first.content
            assert restarted.translator.calls == 0
    finally:
        restarted.resource_ledger.close()


async def test_feed_outage_keeps_existing_exact_assignment_usable(feed, tmp_path, monkeypatch):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    authority.install(feed.item.publication)

    async def fail(**args):
        raise ValueError("unavailable")

    monkeypatch.setattr(authority, "_query", fail)
    try:
        with pytest.raises(ValueError):
            await authority.poll_once()
        await authority.authorize(
            feed.item.request, validator_hotkey=feed.item.validator_wallet.hotkey.ss58_address
        )
        assert len(authority._publications) == 1
    finally:
        miner.resource_ledger.close()


async def test_large_page_is_processed_with_bounded_requests_even_if_all_items_fail(
    feed, tmp_path, monkeypatch
):
    miner = dynamic_runtime(feed, tmp_path)
    authority = miner.competition_authority
    calls = []

    async def query(**args):
        calls.append(args)
        if args["operation"] == "list":
            return {
                "items": [{"publication_sha256": f"{n:064x}"} for n in range(100)],
                "next_cursor": "ff" * 32,
            }
        raise ValueError("not releasable")

    monkeypatch.setattr(authority, "_query", query)
    try:
        await authority.poll_once()
        assert len(calls) == 3
        assert len(authority._pending) == 98
        await authority.poll_once()
        assert len(calls) == 5
        assert calls[-1]["publication_sha256"] == f"{3:064x}"
        assert len(authority._pending) == 96
        assert not authority._publications
    finally:
        miner.resource_ledger.close()
