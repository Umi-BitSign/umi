from __future__ import annotations

import sqlite3

import httpx
import pytest

from umi import competition_round_discovery as discovery
from umi.competition_api import CompetitionApiLimits, create_app
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_round_preparation import setup as setup
from .test_competition_settlement import _record_all, _scenario, _settle
from .test_open_competition import policy as policy

ROUTE = "/v1/competition/rounds/index"


async def unavailable_snapshot():
    raise AssertionError("round discovery must not collect finality")


def client_for(store, **options):
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(store, unavailable_snapshot, **options)),
        base_url="http://test",
    )


async def test_empty_and_prepared_real_ledger(setup):
    async with client_for(setup.store) as client:
        empty = await client.get(ROUTE)
        assert empty.status_code == 200
        assert empty.headers["cache-control"] == "no-store"
        assert empty.json() == {
            "schema": "umi-competition-round-index/1",
            "source": "configured_intake_store",
            "policy_sha256": digest(setup.policy),
            "items": [],
            "limit": 20,
            "before_sequence": None,
            "next_before_sequence": None,
            "chain_submission_authorized": False,
        }
        prepared = setup.store.prepare_round(**setup.options)
        response = await client.get(ROUTE)
        item = response.json()["items"][0]
        round_id = prepared["cutoff_receipt"]["round_sha256"]
        assert item["round_sha256"] == round_id
        assert item["state"] == "prepared"
        assert item["roster_count"] == 2
        assert item["outcome_count"] == item["independent_result_count"] == item["void_count"] == 0
        assert item["settlement_sha256"] is item["settlement_url"] is None
        assert item["certification"] == "not_checked"
        assert not item["chain_submission_authorized"]
        assert (await client.get(item["round_url"])).json() == setup.store.round_status(
            round_id, limit=20
        )


async def test_real_evidence_and_settlement_never_imply_certification(policy, tmp_path):
    scenario = _scenario(policy, tmp_path)
    store = scenario.store
    round_id = digest(scenario.round)
    async with client_for(store) as client:
        status_before = (await client.get("/v1/competition/status")).json()
        assert (await client.get(f"/v1/competition/settlements/{round_id}")).status_code == 404
        _record_all(scenario)
        item = (await client.get(ROUTE)).json()["items"][0]
        assert item["state"] == "evaluating"
        assert item["independent_result_count"] == item["outcome_count"] == 2
        assert item["void_count"] == 0
        assert item["settlement_url"] is None
        _settle(scenario)
        item = (await client.get(ROUTE)).json()["items"][0]
        assert item["state"] == "closed_computed_uncertified"
        assert item["certification"] == "not_checked"
        assert not item["chain_submission_authorized"]
        assert item["settlement_url"].endswith(round_id)
        assert (await client.get(item["settlement_url"])).json() == store.settlement_status(
            round_id
        )
        assert item["settlement_sha256"] == store.settlement_status(round_id)["settlement_sha256"]
        assert (await client.get(item["round_url"])).json() == store.round_status(
            round_id, limit=20
        )
        assert (await client.get("/v1/competition/status")).json() == status_before


def insert_round(store, template, sequence, *, policy_id=None):
    """Synthetic SQL fixture for paging; not a certificate or a scored round."""
    changes = {"sequence": sequence}
    if policy_id is not None:
        changes["policy_sha256"] = policy_id
    round_ = template.model_copy(update=changes)
    with store._transaction() as db:
        db.execute(
            "INSERT INTO rounds VALUES (?, ?, ?)",
            (
                digest(round_),
                sequence,
                canonical_json_bytes(round_),
            ),
        )
    return round_


async def test_cursor_survives_appends_and_retains_historical_policy(policy, tmp_path):
    scenario = _scenario(policy, tmp_path)
    for sequence in range(2, 6):
        insert_round(scenario.store, scenario.round, sequence, policy_id="ab" * 32)
    async with client_for(scenario.store) as client:
        first = (await client.get(ROUTE, params={"limit": 2})).json()
        assert [item["sequence"] for item in first["items"]] == [5, 4]
        assert first["policy_sha256"] == digest(scenario.policy)
        assert first["items"][0]["policy_sha256"] == "ab" * 32
        insert_round(scenario.store, scenario.round, 6)
        second = (
            await client.get(
                ROUTE,
                params={
                    "limit": 2,
                    "before_sequence": first["next_before_sequence"],
                },
            )
        ).json()
        assert [item["sequence"] for item in second["items"]] == [3, 2]
        third = (
            await client.get(
                ROUTE,
                params={
                    "limit": 2,
                    "before_sequence": second["next_before_sequence"],
                },
            )
        ).json()
        assert [item["sequence"] for item in third["items"]] == [1]
        assert third["next_before_sequence"] is None
        assert (await client.get(ROUTE, params={"before_sequence": 1})).json()["items"] == []
        assert (await client.get(ROUTE)).json()["items"][0]["sequence"] == 6


async def test_c3_shaped_counts_deduplicate_and_exclude_private_bodies(
    policy, tmp_path, monkeypatch
):
    scenario = _scenario(policy, tmp_path)
    store = scenario.store
    round_id = digest(scenario.round)
    secret = b"PRIVATE reference, https://private/video.mp4, model hypothesis"
    # SQL counting fixture with C3's 70 independent + 104 void distribution.
    with store._transaction() as db:
        for i in range(174):
            if i < 70:
                db.execute(
                    "INSERT INTO independent_evaluation_evidence VALUES (?, ?, ?, ?, ?, ?)",
                    (f"{i:064x}", round_id, f"{i:064x}", f"{i:064x}", secret, 150),
                )
            else:
                db.execute(
                    "INSERT INTO void_evaluation_evidence VALUES (?, ?, ?, ?, ?, ?)",
                    (f"{i:064x}", round_id, f"{i:064x}", f"{i:064x}", secret, 150),
                )
        db.execute(
            "INSERT INTO independent_evaluation_evidence VALUES (?, ?, ?, ?, ?, ?)",
            ("aa" * 32, round_id, "0" * 64, "bb" * 32, secret, 151),
        )
        db.execute(
            "INSERT INTO competition_settlements VALUES (?, ?, ?)", (round_id, "cc" * 32, secret)
        )
    original_connect = sqlite3.connect
    reads = []

    def connect(*args, **kwargs):
        assert args[0] == store.path.resolve().as_uri() + "?mode=ro"
        db = original_connect(*args, **kwargs)

        def authorize(action, table, column, *_):
            if action == sqlite3.SQLITE_READ:
                reads.append((table, column))
                if column == "body" and table != "rounds":
                    return sqlite3.SQLITE_DENY
            if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        return db

    monkeypatch.setattr(discovery.sqlite3, "connect", connect)
    async with client_for(store) as client:
        response = await client.get(ROUTE, params={"state_directory": str(tmp_path / "untrusted")})
    assert response.status_code == 200
    item = response.json()["items"][0]
    assert item["independent_result_count"] == 70
    assert item["void_count"] == 104
    assert item["outcome_count"] == 174
    assert item["state"] == "closed_computed_uncertified"
    assert item["certification"] == "not_checked"
    assert secret not in response.content
    for private_key in ("references", "video_sha256", "hypothesis", "suite", "roster", "results"):
        assert private_key not in item
    assert ("independent_evaluation_evidence", "submission") in reads
    assert not (tmp_path / "untrusted").exists()


@pytest.mark.parametrize("conflict_table", ["round_conflicts", "settlement_disputes"])
async def test_conflicts_remain_visible(policy, tmp_path, conflict_table):
    scenario = _scenario(policy, tmp_path)
    _record_all(scenario)
    _settle(scenario)
    with scenario.store._transaction() as db:
        db.execute(f"INSERT INTO {conflict_table} VALUES (?, ?)", (digest(scenario.round), 170))
    async with client_for(scenario.store) as client:
        item = (await client.get(ROUTE)).json()["items"][0]
    assert item["conflicted"] == (conflict_table == "round_conflicts")
    assert item["disputed"]
    assert item["state"] == "closed_computed_uncertified"
    assert item["certification"] == "not_checked"


@pytest.mark.parametrize(
    "query",
    [
        "limit=0",
        "limit=-1",
        "limit=101",
        "limit=abc",
        "before_sequence=0",
        "before_sequence=-1",
        "before_sequence=4294967296",
        "before_sequence=abc",
    ],
)
async def test_invalid_paging_is_rejected(policy, tmp_path, query):
    async with client_for(CompetitionStore(tmp_path, policy)) as client:
        assert (await client.get(ROUTE + "?" + query)).status_code == 422


async def test_page_limit_uses_config_and_default(policy, tmp_path):
    async with client_for(
        CompetitionStore(tmp_path, policy),
        limits=CompetitionApiLimits(
            maximum_page_size=1,
        ),
    ) as client:
        assert (await client.get(ROUTE)).json()["limit"] == 1
        assert (await client.get(ROUTE + "?limit=2")).status_code == 422


@pytest.mark.parametrize(
    "body", [b"PRIVATE invalid JSON", b"x" * (discovery.MAXIMUM_ROUND_BYTES + 1)]
)
async def test_corrupt_metadata_fails_without_echo(policy, tmp_path, body):
    store = CompetitionStore(tmp_path, policy)
    with store._transaction() as db:
        db.execute("INSERT INTO rounds VALUES (?, ?, ?)", ("ab" * 32, 1, body))
    async with client_for(store) as client:
        response = await client.get(ROUTE)
    assert response.status_code == 503
    assert response.json() == {"detail": "round index unavailable"}


async def test_missing_database_is_not_created(policy, tmp_path):
    store = CompetitionStore(tmp_path / "configured", policy)
    store.path = tmp_path / "absent.sqlite3"
    async with client_for(store) as client:
        response = await client.get(ROUTE)
    assert response.status_code == 503
    assert not store.path.exists()


async def test_page_keeps_one_sql_snapshot_during_concurrent_write(policy, tmp_path, monkeypatch):
    scenario = _scenario(policy, tmp_path)
    original_connect = sqlite3.connect
    mutated = False

    def connect(*args, **kwargs):
        db = original_connect(*args, **kwargs)
        if kwargs.get("uri"):

            def trace(sql):
                nonlocal mutated
                if not mutated and "COUNT(DISTINCT submission)" in sql:
                    mutated = True
                    with scenario.store._transaction() as writer:
                        writer.execute(
                            "INSERT INTO round_conflicts VALUES (?, ?)",
                            (digest(scenario.round), 170),
                        )

            db.set_trace_callback(trace)
        return db

    monkeypatch.setattr(sqlite3, "connect", connect)
    async with client_for(scenario.store) as client:
        first = (await client.get(ROUTE)).json()["items"][0]
        assert mutated and not first["conflicted"]
        assert (await client.get(ROUTE)).json()["items"][0]["conflicted"]
