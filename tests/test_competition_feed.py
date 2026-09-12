from __future__ import annotations

import json
import sqlite3
import time
from types import SimpleNamespace

import httpx
import pytest
from fastapi.testclient import TestClient

from umi.competition_feed import (
    AssignmentFeedQuery,
    SignedAssignmentFeedQuery,
    create_assignment_feed,
    query_assignment_feed,
)
from umi.competition_scheduling import AssignmentPublicationJournal
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_authorization import authorization as authorization
from .test_open_competition import policy as policy
from .test_open_competition import wallet


@pytest.fixture
def feed(authorization, tmp_path, monkeypatch):
    item = authorization
    issuance = item.finalized_blocks.blocks[item.request.issued_block]
    clock = SimpleNamespace(ns=max(time.time_ns(), issuance.timestamp_ms * 1_000_000 + 1000))
    monkeypatch.setattr(time, "time_ns", lambda: clock.ns)
    journal = AssignmentPublicationJournal(tmp_path / "journal", item.policy, item.legacy_policy)
    journal.publish(
        item.publication, observed=issuance, announcements=(item.finalized_blocks.blocks[1000],)
    )
    nonce_path = tmp_path / "nonces" / "feed.sqlite3"
    app = create_assignment_feed(journal, nonce_path=nonce_path)
    return SimpleNamespace(
        item=item, journal=journal, clock=clock, nonce_path=nonce_path, client=TestClient(app)
    )


def query(feed, *, signer=None, **changes):
    signer = signer or feed.item.miner_wallet
    feed.clock.ns += 1
    body = AssignmentFeedQuery(
        schema="umi-assignment-feed-query/1",
        policy_sha256=digest(feed.item.policy),
        miner_hotkey=signer.hotkey.ss58_address,
        nonce_unix_ns=str(feed.clock.ns),
        operation="list",
    ).model_copy(update=changes)
    return canonical_json_bytes(
        SignedAssignmentFeedQuery(
            query=body,
            signature=sign_object(body, signer),
        )
    )


def post(feed, body, **kwargs):
    return feed.client.post(
        "/v1/competition/assignments/query",
        content=body,
        headers={"content-type": "application/json"},
        **kwargs,
    )


def test_feed_lists_only_summaries_then_returns_exact_owned_publication(feed):
    response = post(feed, query(feed, limit=2))
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    result = response.json()
    assert len(result["items"]) == 2 and result["next_cursor"]
    assert "video" not in response.text and "https://" not in response.text
    assert result["chain_submission_authorized"] is False
    second = post(feed, query(feed, after=result["next_cursor"], limit=2)).json()
    assert {i["assignment_key"] for i in result["items"]}.isdisjoint(
        {i["assignment_key"] for i in second["items"]}
    )
    response = post(
        feed,
        query(
            feed,
            operation="publication",
            publication_sha256=digest(feed.item.publication.publication),
        ),
    )
    assert response.status_code == 200, response.text
    assert canonical_json_bytes(response.json()["publication"]) == canonical_json_bytes(
        feed.item.publication
    )
    assert response.json()["status"]["publication_timing_proven"] is False


def test_feed_nonce_replay_survives_restart(feed):
    body = query(feed)
    assert post(feed, body).status_code == 200
    feed.client = TestClient(create_assignment_feed(feed.journal, nonce_path=feed.nonce_path))
    assert post(feed, body).status_code == 401


def test_unpublished_hotkey_cannot_consume_nonce_capacity(feed):
    response = post(feed, query(feed, signer=wallet("Bob")))
    assert response.status_code == 401
    with sqlite3.connect(feed.nonce_path) as db:
        assert db.execute("SELECT COUNT(*) FROM accepted_nonces").fetchone()[0] == 0


@pytest.mark.parametrize("mutation", ["signature", "policy", "old", "future", "noncanonical"])
def test_bad_feed_auth_rejected_before_disclosing_assignments(feed, mutation):
    changes = {}
    if mutation == "policy":
        changes["policy_sha256"] = "00" * 32
    if mutation == "old":
        changes["nonce_unix_ns"] = str(feed.clock.ns - 31_000_000_000)
    if mutation == "future":
        changes["nonce_unix_ns"] = str(feed.clock.ns + 6_000_000_000)
    body = query(feed, **changes)
    if mutation == "signature":
        value = json.loads(body)
        value["signature"]["signature"] = "0x" + "00" * 64
        body = canonical_json_bytes(value)
    elif mutation == "noncanonical":
        body = b" " + body
    response = post(feed, body)
    assert response.status_code == 401
    assert "assignment_key" not in response.text


def test_complete_publication_cannot_disclose_other_miner_urls(feed, monkeypatch):
    # The handler applies an audience check even if its local source supplies a
    # wider quorum-signed publication that is valid for other local uses.
    body = feed.item.publication.publication
    bob = feed.item.signed_submission.submission.model_copy(
        update={"hotkey": wallet("Bob").hotkey.ss58_address}
    )
    from umi.competition_authorization import SignedEndpointAuthorization
    from umi.open_competition import SignedSubmission

    bob_signed = SignedSubmission(submission=bob, signature=sign_object(bob, wallet("Bob")))
    wider = body.model_copy(update={"submissions": (*body.submissions, bob_signed)})
    wider_signed = SignedEndpointAuthorization(
        publication=wider,
        signatures=tuple(sign_object(wider, w) for w in feed.item.evaluator_wallets[:2]),
    )
    monkeypatch.setattr(feed.journal, "publication", lambda _key: wider_signed)
    response = post(feed, query(feed, operation="publication", publication_sha256=digest(wider)))
    assert response.status_code == 404
    assert "https://" not in response.text


def test_expired_assignments_do_not_reappear_as_available_work(feed):
    initial = post(feed, query(feed)).json()
    feed.clock.ns = max(i["issue_close_unix_ms"] for i in initial["items"]) * 1_000_000 + 1
    result = post(feed, query(feed))
    assert result.status_code == 200
    assert result.json()["items"] == []
    historical = post(feed, query(feed, include_history=True)).json()
    assert historical["items"]
    assert all(i["state"] == "expired" and i["miner_fault"] is False for i in historical["items"])


def test_feed_request_and_per_hotkey_capacity_are_bounded(feed):
    assert post(feed, b"x" * 4097).status_code == 413
    for _ in range(32):
        assert post(feed, query(feed)).status_code == 200
    assert post(feed, query(feed)).status_code == 503


def test_feed_has_no_public_get_or_publication_mutation_route(feed):
    assert feed.client.get("/v1/competition/assignments/query").status_code == 405
    assert feed.client.post("/v1/competition/assignments/publish", json={}).status_code == 404


def test_invalid_publication_queries_consume_budget_before_lookup(feed, monkeypatch):
    calls = []

    def missing(key):
        calls.append(key)
        raise ValueError("not found")

    monkeypatch.setattr(feed.journal, "publication", missing)
    body = query(feed, operation="publication", publication_sha256="00" * 32)
    assert post(feed, body).status_code == 404
    assert post(feed, body).status_code == 401
    assert calls == ["00" * 32]


@pytest.mark.parametrize("publication", [False, True])
async def test_client_checks_real_feed_and_signed_publication(feed, publication):
    changes = (
        {
            "operation": "publication",
            "publication_sha256": digest(feed.item.publication.publication),
        }
        if publication
        else {}
    )
    signed = SignedAssignmentFeedQuery.model_validate_json(query(feed, **changes))
    result = await query_assignment_feed(
        origin="https://assignments.example",
        signed=signed,
        policy=feed.item.policy,
        legacy_policy=feed.item.legacy_policy,
        transport=httpx.ASGITransport(app=feed.client.app),
    )
    assert result["query_sha256"] == digest(signed.query)
    assert result["policy_sha256"] == digest(feed.item.policy)
    if publication:
        assert canonical_json_bytes(result["publication"]) == canonical_json_bytes(
            feed.item.publication
        )
    else:
        assert result["items"]


@pytest.mark.parametrize("mutation", ["redirect", "encoded", "binding", "authority", "signature"])
async def test_client_rejects_bad_feed_reply_without_installing_anything(feed, mutation):
    signed_bytes = query(
        feed, operation="publication", publication_sha256=digest(feed.item.publication.publication)
    )
    valid = post(feed, signed_bytes)
    assert valid.status_code == 200
    data = valid.json()
    if mutation == "binding":
        data["query_sha256"] = "00" * 32
    elif mutation == "authority":
        data["status"]["chain_submission_authorized"] = True
    elif mutation == "signature":
        data["publication"]["signatures"][0]["signature"] = "0x" + "00" * 64
    calls = []

    def reply(request):
        calls.append(request)
        if mutation == "redirect":
            return httpx.Response(307, headers={"location": "https://another.example"})
        return httpx.Response(
            200,
            content=canonical_json_bytes(data),
            headers={
                "content-type": "application/json",
                "content-encoding": "gzip" if mutation == "encoded" else "identity",
            },
        )

    with pytest.raises(ValueError):
        await query_assignment_feed(
            origin="https://assignments.example",
            signed=SignedAssignmentFeedQuery.model_validate_json(signed_bytes),
            policy=feed.item.policy,
            legacy_policy=feed.item.legacy_policy,
            transport=httpx.MockTransport(reply),
        )
    assert len(calls) == 1


async def test_discovery_claim_miner_response_and_restart_are_one_bounded_flow(feed, tmp_path):
    from umi.competition_authorization import SignedEndpointAuthorization
    from umi.competition_scheduling import assignment_key
    from umi.miner import create_app
    from umi.validator import validate_response_envelope

    from .test_competition_miner import authorized_runtime, post_assignment

    query_bytes = query(
        feed, operation="publication", publication_sha256=digest(feed.item.publication.publication)
    )
    fetched = await query_assignment_feed(
        origin="https://assignments.example",
        signed=SignedAssignmentFeedQuery.model_validate_json(query_bytes),
        policy=feed.item.policy,
        legacy_policy=feed.item.legacy_policy,
        transport=httpx.ASGITransport(app=feed.client.app),
    )
    publication = SignedEndpointAuthorization.model_validate_json(
        canonical_json_bytes(fetched["publication"])
    )
    case = SimpleNamespace(**{**vars(feed.item), "publication": publication})
    first = publication.publication.assignments[0]
    key = assignment_key(publication, first)
    issuance = case.finalized_blocks.blocks[case.request.issued_block]
    claim = feed.journal.claim(key, observed=issuance, issuance=issuance)
    assert claim is not None
    miner = authorized_runtime(case, tmp_path / "miner")
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app(miner)), base_url=case.serving_origin
        ) as client:
            response = await post_assignment(client, case)
        assert response.status_code == 200, response.text
        validate_response_envelope(
            response.content,
            response.headers["X-UMI-Signature"],
            request=case.request,
            validator_hotkey=case.validator_wallet.hotkey.ss58_address,
            miner_hotkey=case.miner_wallet.hotkey.ss58_address,
        )
        transcript = canonical_json_bytes(
            {"envelope": response.json(), "signature": response.headers["X-UMI-Signature"]}
        )
        assert feed.journal.complete(claim, evidence=transcript)["state"] == "completed"
        restarted = AssignmentPublicationJournal(
            feed.journal.path.parent, case.policy, case.legacy_policy
        )
        with pytest.raises(ValueError, match="already dispatched"):
            restarted.claim(key, observed=issuance, issuance=issuance)
        assert restarted.status(key)["chain_submission_authorized"] is False
        assert miner.translator.calls == miner.video_fetcher.calls == 1
    finally:
        miner.resource_ledger.close()
