from __future__ import annotations

from umi.open_competition import digest

from .test_competition_execution import policy as policy
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_public_results import cohort3_asset, public_fixture, retain_artifact
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_round_discovery import client_for
from .test_competition_void_settlement import mixed as mixed
from .test_open_competition import snapshot


async def test_native_mixed_round_void_is_unranked_with_null_metrics(mixed, tmp_path):
    store, round_, suite, _, pairs, void, _ = mixed
    store.record_void_evaluation(evidence=void, suite=suite, observed_block=150)
    settlement = store.settle(
        round_=round_, suite=suite, evidence=pairs, snapshot=snapshot(160), current_block=160
    )
    artifact = public_fixture(store, round_, suite, pairs, settlement)
    source = retain_artifact(tmp_path, artifact)
    async with client_for(store, public_results_sources=(source,)) as client:
        response = await client.get(f"/v1/competition/rounds/{digest(round_)}/results")
    assert response.status_code == 200
    rows = response.json()["items"]
    assert len(rows) == 3
    void_row = next(row for row in rows if row["status"] == "void")
    assert void_row["candidate"] is void_row["incumbent"] is void_row["score_rank"] is None
    assert void_row["result_sha256"] is None
    scored = [row for row in rows if row["status"] == "scored"]
    assert {row["track"] for row in scored} == {"endpoint", "model"}
    assert all(row["score_rank"] == 1 for row in scored)
    for private_name in (
        "references",
        "hypothesis",
        "video_sha256",
        "case_id",
        "candidate_outputs",
    ):
        assert private_name not in response.text
    source = retain_artifact(tmp_path, cohort3_asset(artifact))
    async with client_for(store, public_results_sources=(source,)) as client:
        response = await client.get(f"/v1/competition/rounds/{digest(round_)}/results")
    assert response.status_code == 200
    assert response.json()["items"] == rows
