from __future__ import annotations

import hashlib
import json
import sqlite3
from fractions import Fraction
from pathlib import Path

import pytest

from umi import open_competition
from umi.competition_public_results import PublicQuality, PublicResultsSource, PublicRoundResults
from umi.open_competition import aggregate_quality, digest, identity, replay_evaluation
from umi.protocol import canonical_json_bytes

from .test_competition_round_discovery import client_for
from .test_competition_settlement import _record_all, _scenario, _settle
from .test_open_competition import policy as policy


def quality(value):
    return {
        "numerator": str(value.numerator),
        "denominator": str(value.denominator),
        "decimal": float(value),
    }


def metrics(strata, policy):
    return {
        "aggregate": quality(aggregate_quality(strata, policy)),
        "by_stratum": {name: quality(value) for name, value in strata.items()},
    }


def public_fixture(store, round_, suite, pairs, settlement):
    """Test-only offline native calculation, never called by the API."""
    rows = []
    bindings = {item["submission_sha256"]: item for item in settlement["results"]}
    registrations = {
        identity(item["hotkey"]): item["uid"]
        for item in settlement["registration_snapshot"]["registrations"]
    }
    for signed, evidence in pairs:
        binding = bindings[digest(signed.submission)]
        scored = "result_sha256" in binding
        candidate = incumbent = None
        if scored:
            candidate, incumbent = replay_evaluation(
                evidence.attested_result,
                signed,
                round_,
                suite,
                store.policy,
                current_block=settlement["observed_block"],
            )
        rows.append(
            {
                "submission_sha256": digest(signed.submission),
                "hotkey": signed.submission.hotkey,
                "uid": registrations.get(identity(signed.submission.hotkey)),
                "track": signed.submission.track,
                "status": "scored" if scored else "void",
                "result_sha256": binding.get("result_sha256"),
                "independent_evidence_sha256": binding.get("independent_evidence_sha256"),
                "void_decision_sha256": binding.get("void_decision_sha256"),
                "void_evidence_sha256": binding.get("void_evidence_sha256"),
                "first_observed_block": binding["first_observed_block"],
                "candidate": None if candidate is None else metrics(candidate, store.policy),
                "incumbent": None if incumbent is None else metrics(incumbent, store.policy),
                "score_rank": None,
            }
        )
    for row in rows:
        if row["candidate"] is not None:
            row["score_rank"] = 1 + sum(
                other["track"] == row["track"]
                and other["candidate"] is not None
                and PublicQuality(**other["candidate"]["aggregate"]).fraction()
                > PublicQuality(**row["candidate"]["aggregate"]).fraction()
                for other in rows
            )
    return {
        "schema": "umi-competition-public-results/1",
        "round_sha256": digest(round_),
        "policy_sha256": digest(store.policy),
        "settlement_sha256": store.settlement_status(digest(round_))["settlement_sha256"],
        "observed_block": settlement["observed_block"],
        "scoring_method": "native_replay_evaluation_at_settlement_observed_block",
        "provisional": True,
        "certified": False,
        "rewards_active": False,
        "chain_submission_authorized": False,
        "items": sorted(rows, key=lambda row: row["submission_sha256"]),
    }


def retain_artifact(tmp_path, artifact):
    raw = canonical_json_bytes(artifact)
    path = tmp_path / "public.json"
    path.write_bytes(raw)
    return PublicResultsSource(
        round_sha256=artifact["round_sha256"],
        artifact_sha256=hashlib.sha256(raw).hexdigest(),
        path=str(path),
    )


@pytest.fixture
def published(policy, tmp_path):
    scenario = _scenario(policy, tmp_path)
    _record_all(scenario)
    settlement = _settle(scenario)
    artifact = public_fixture(
        scenario.store, scenario.round, scenario.suite, scenario.evidence, settlement
    )
    source = retain_artifact(tmp_path, artifact)
    return scenario, artifact, source


async def test_native_scores_paging_ties_and_no_replay_on_get(published, monkeypatch):
    scenario, artifact, source = published

    def forbidden(*args, **kwargs):
        raise AssertionError("no score calculation or evidence replay during public reads")

    monkeypatch.setattr(open_competition, "replay_evaluation", forbidden)
    monkeypatch.setattr(open_competition, "_quality", forbidden)
    path = f"/v1/competition/rounds/{digest(scenario.round)}/results"
    async with client_for(scenario.store, public_results_sources=(source,)) as client:
        first = await client.get(path, params={"limit": 1})
        assert first.status_code == 200
        page = first.json()
        assert first.headers["cache-control"] == "no-store"
        assert page["items"] == artifact["items"][:1]
        assert page["next_offset"] == 1
        second = (await client.get(path, params={"limit": 1, "offset": 1})).json()
        assert second["items"] == artifact["items"][1:]
        assert second["next_offset"] is None
        assert [row["score_rank"] for row in artifact["items"]] == [1, 1]
        assert page["provisional"] and not page["certified"]
        assert not page["rewards_active"] and not page["chain_submission_authorized"]
        assert page["state"] == "closed_computed_uncertified"
        assert (await client.get(path, params={"offset": 2})).json()["items"] == []
        index = (await client.get("/v1/competition/rounds/index")).json()
        assert index["items"][0]["results_url"] == path
        assert (await client.get(path, params={"limit": 101})).status_code == 422
        assert (await client.get(path, params={"offset": -1})).status_code == 422
        # Live disputes supersede the clean artifact without rewriting its score history.
        with scenario.store._transaction() as db:
            db.execute("INSERT INTO round_conflicts VALUES (?, ?)", (digest(scenario.round), 170))
        disputed = (await client.get(path)).json()
        assert disputed["conflicted"] and disputed["disputed"]
        assert disputed["items"] == artifact["items"]


async def test_unconfigured_results_are_404_and_not_discovered(published):
    scenario, _, _ = published
    async with client_for(scenario.store) as client:
        assert (
            await client.get(f"/v1/competition/rounds/{digest(scenario.round)}/results")
        ).status_code == 404
        assert (await client.get("/v1/competition/rounds/index")).json()["items"][0][
            "results_url"
        ] is None


@pytest.mark.parametrize(
    "mutation",
    [
        "private_fields",
        "certified",
        "rank",
        "uid",
        "hotkey",
        "result",
        "evidence",
        "round",
        "policy",
        "settlement",
        "observation",
        "missing_row",
        "void_score",
    ],
)
async def test_rejects_unbound_or_private_artifacts(published, tmp_path, mutation):
    scenario, artifact, _ = published
    row = artifact["items"][0]
    if mutation == "private_fields":
        row["hypothesis"] = "PRIVATE model output"
    elif mutation == "certified":
        artifact["certified"] = True
    elif mutation == "rank":
        row["score_rank"] = 2
    elif mutation == "uid":
        row["uid"] = (row["uid"] + 1) % 256
    elif mutation == "hotkey":
        row["hotkey"] = artifact["items"][1]["hotkey"]
    elif mutation == "result":
        row["result_sha256"] = "ab" * 32
    elif mutation == "evidence":
        row["independent_evidence_sha256"] = "ab" * 32
    elif mutation in {"round", "policy", "settlement"}:
        artifact[mutation + "_sha256"] = "ab" * 32
    elif mutation == "observation":
        artifact["observed_block"] += 1
    elif mutation == "missing_row":
        artifact["items"].pop()
    else:
        row["status"] = "void"
    source = retain_artifact(tmp_path, artifact)
    async with client_for(scenario.store, public_results_sources=(source,)) as client:
        response = await client.get(f"/v1/competition/rounds/{source.round_sha256}/results")
    assert response.status_code == 503
    assert response.json() == {"detail": "public results unavailable"}


async def test_digest_pin_and_symlink_reject_replacement(published, tmp_path):
    scenario, _, source = published

    path = Path(source.path)
    raw = path.read_bytes()
    async with client_for(scenario.store, public_results_sources=(source,)) as client:
        url = f"/v1/competition/rounds/{source.round_sha256}/results"
        path.write_bytes(raw + b" ")
        assert (await client.get(url)).status_code == 503
        replacement = tmp_path / "replacement.json"
        replacement.write_bytes(raw)
        path.unlink()
        path.symlink_to(replacement)
        assert (await client.get(url)).status_code == 503


def test_rank_compares_exact_fractions_not_rounded_decimals_or_other_tracks(published):
    _, artifact, _ = published
    first, second = artifact["items"]
    first["candidate"]["aggregate"] = quality(Fraction(1, 2))
    second["candidate"]["aggregate"] = quality(Fraction(1, 2) + Fraction(1, 10**18))
    assert first["candidate"]["aggregate"]["decimal"] == second["candidate"]["aggregate"]["decimal"]
    first["score_rank"] = 2
    assert PublicRoundResults.model_validate_json(json.dumps(artifact))
    first["track"] = "model"
    first["score_rank"] = 1
    assert PublicRoundResults.model_validate_json(json.dumps(artifact))


async def test_results_read_no_private_evidence_bodies(published, monkeypatch):
    scenario, _, source = published
    original_connect = sqlite3.connect

    def connect(*args, **kwargs):
        assert args[0].endswith("?mode=ro")
        db = original_connect(*args, **kwargs)

        def authorize(action, table, column, *_):
            if (
                action == sqlite3.SQLITE_READ
                and table
                in {
                    "evaluation_results",
                    "independent_evaluation_evidence",
                    "void_evaluation_evidence",
                    "submissions",
                }
                and column == "body"
            ):
                return sqlite3.SQLITE_DENY
            if action in (sqlite3.SQLITE_INSERT, sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        return db

    monkeypatch.setattr(sqlite3, "connect", connect)
    async with client_for(scenario.store, public_results_sources=(source,)) as client:
        response = await client.get(f"/v1/competition/rounds/{source.round_sha256}/results")
    assert response.status_code == 200


def test_duplicate_sources_and_relative_paths_are_rejected(published):
    scenario, _, source = published
    with pytest.raises(ValueError, match="unique rounds"):
        client_for(scenario.store, public_results_sources=(source, source))
    with pytest.raises(ValueError, match="absolute file"):
        PublicResultsSource(
            round_sha256=source.round_sha256,
            artifact_sha256=source.artifact_sha256,
            path="relative.json",
        )


def cohort3_asset(artifact):
    """Synthetic fixture of the external static publication's wire format."""
    results = []
    for item in reversed(artifact["items"]):
        row = {
            key: item[key]
            for key in (
                "submission_sha256",
                "hotkey",
                "track",
                "first_observed_block",
                "score_rank",
            )
        }
        row.update({"uid_at_settlement": item["uid"], "outcome": item["status"]})
        for role in ("candidate", "incumbent"):
            row[role + "_score"] = item[role]["aggregate"] if item[role] else None
            row[role + "_stratum_scores"] = item[role]["by_stratum"] if item[role] else None
        if item["status"] == "scored":
            row.update(
                {
                    "result_sha256": item["result_sha256"],
                    "independent_evidence_sha256": item["independent_evidence_sha256"],
                    "total_cases": 3,
                    "candidate_case_status_counts": {"ok": 3},
                }
            )
        else:
            row.update(
                {
                    "void_decision_sha256": item["void_decision_sha256"],
                    "void_evidence_sha256": item["void_evidence_sha256"],
                    "reason": "infrastructure_failure",
                }
            )
        results.append(row)
    return {
        "schema": "umi-cohort3-provisional-results/1",
        "cohort": 3,
        "round_sha256": artifact["round_sha256"],
        "policy_sha256": artifact["policy_sha256"],
        "settlement_sha256": artifact["settlement_sha256"],
        "generated_at": "2026-09-22T00:00:00Z",
        "round_valid_through_block": 200,
        "historical_score_replay_block": artifact["observed_block"],
        "status": "closed_uncertified",
        "certification_status": "deadline_missed",
        "provisional": True,
        "settlement_certified": False,
        "rewards_status": "not_activated",
        "chain_submission_authorized": False,
        "publication_scope": "Test fixture",
        "score_semantics": "Native quality fractions",
        "scoring_environment": {
            "schema": "umi-component-scoring-environment/1",
            "bittensor_distribution_version": "11.1.0",
            "python_implementation": "CPython",
            "python_version": "3.12.14",
            "regex_distribution_version": "2026.9.3",
            "scoring_source_sha256": "ab" * 32,
            "unicode_data_version": "15.0.0",
        },
        "scoring_runtime_verified": True,
        "counts": {
            "miners": len(results),
            "scored": sum(row["outcome"] == "scored" for row in results),
            "void": sum(row["outcome"] == "void" for row in results),
        },
        "results": results,
    }


async def test_static_release_asset_is_normalized_without_rescoring(published, tmp_path):
    scenario, artifact, _ = published
    source = retain_artifact(tmp_path, cohort3_asset(artifact))
    async with client_for(scenario.store, public_results_sources=(source,)) as client:
        response = await client.get(f"/v1/competition/rounds/{source.round_sha256}/results")
    assert response.status_code == 200
    assert response.json()["items"] == artifact["items"]
    assert response.json()["artifact_sha256"] == source.artifact_sha256


@pytest.mark.parametrize("field", ["extra", "flags", "counts", "row", "runtime"])
async def test_static_asset_rejects_changed_schema_or_claims(published, tmp_path, field):
    scenario, artifact, _ = published
    legacy = cohort3_asset(artifact)
    if field == "extra":
        legacy["private_references"] = ["SECRET"]
    elif field == "flags":
        legacy["settlement_certified"] = True
    elif field == "counts":
        legacy["counts"]["scored"] = 999
    elif field == "runtime":
        legacy["scoring_runtime_verified"] = False
    else:
        legacy["results"][0]["hypothesis"] = "SECRET"
    source = retain_artifact(tmp_path, legacy)
    async with client_for(scenario.store, public_results_sources=(source,)) as client:
        response = await client.get(f"/v1/competition/rounds/{source.round_sha256}/results")
    assert response.status_code == 503 and "SECRET" not in response.text
