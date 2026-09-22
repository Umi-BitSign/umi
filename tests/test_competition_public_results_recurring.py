"""Native small settlements, persistent publication, and reads without replay."""

from __future__ import annotations

import hashlib
import json
import os
import select
import signal
import sqlite3
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import pytest

from umi import competition_public_results_export as exporter
from umi import competition_public_results_publisher as publisher_module
from umi.competition_public_results import PublicSettlementScores
from umi.competition_public_results_directory import (
    PublicResultsDirectory,
    atomic_write,
    discover_source,
    publish_scores,
    resolve_source,
)
from umi.competition_public_results_export import PublicResultsExportLimits, export_round
from umi.competition_public_results_publisher import (
    PublicResultsPublisher,
    PublicResultsPublisherConfig,
    publisher_lease,
)
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.open_competition import digest
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes

from .test_competition_public_results import public_fixture
from .test_competition_round_discovery import client_for
from .test_competition_settlement import _independent, _record_all, _scenario, _settle
from .test_open_competition import attested, result_for, snapshot
from .test_open_competition import policy as policy
from .test_policy import make_policy


@pytest.fixture
def prepared(policy, tmp_path):
    scenario = _scenario(policy, tmp_path)
    _record_all(scenario)
    settlement = _settle(scenario)
    scoring = make_policy()
    policy_path, scoring_path = tmp_path / "policy.json", tmp_path / "scoring.json"
    policy_path.write_bytes(canonical_json_bytes(scenario.policy))
    scoring_path.write_bytes(canonical_json_bytes(scoring))
    config = PublicResultsPublisherConfig(
        schema="umi-public-results-publisher-config/1",
        database=str(scenario.store.path),
        policy_path=str(policy_path),
        policy_sha256=digest(scenario.policy),
        scoring_policy_path=str(scoring_path),
        scoring_policy_sha256=scoring_policy_hash(scoring),
        public_results_directory=PublicResultsDirectory(directory=str(tmp_path / "public")),
    )
    return SimpleNamespace(s=scenario, settlement=settlement, scoring=scoring, config=config)


def export(p):
    return export_round(
        p.s.store.path, digest(p.s.round), policy=p.s.policy, scoring_policy=p.scoring
    )


def add_round(p):
    s = p.s
    suite = s.suite.model_copy(
        update={
            "cases": tuple(
                case.model_copy(update={"video_sha256": f"{i + 1000:064x}"})
                for i, case in enumerate(s.suite.cases)
            )
        }
    )
    schedule = s.round.public_schedule.model_copy(
        update={
            key: value + 60
            for key, value in s.round.public_schedule.model_dump().items()
            if key.endswith("_block") and key != "intake_opened_block"
        }
    )
    round_ = s.round.model_copy(
        update={
            "sequence": 2,
            "suite_sha256": digest(suite),
            "public_schedule": schedule,
            "submission_close_block": 180,
            "evaluation_close_block": 200,
            "reveal_block": 210,
            "valid_through_block": 260,
        }
    )
    cutoff = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(s.policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=220,
    )
    s.store.fix_evidence_cutoff(round_, cutoff, observed_block=180)
    s.store.close_round(round_, current_block=180)
    evidence = tuple(
        (
            signed,
            _independent(
                s.policy,
                signed,
                round_,
                suite,
                attested(
                    result_for(signed, round_, suite).result.model_copy(
                        update={"finished_block": 190}
                    )
                ),
            ),
        )
        for signed in s.submissions
    )
    s.store.settle(
        round_=round_, suite=suite, evidence=evidence, snapshot=snapshot(220), current_block=220
    )
    return round_


def test_native_export_exact_scores_no_private_fields_or_payment_claims(prepared):
    p = prepared
    result = export(p)
    expected = public_fixture(p.s.store, p.s.round, p.s.suite, p.s.evidence, p.settlement)
    body = result.model_dump(mode="json", by_alias=True)
    assert body["items"] == expected["items"]
    assert body["certification"] == body["rewards"] == "not_checked"
    assert "certified" not in body and "rewards_active" not in body
    assert not body["chain_submission_authorized"]
    for field in ("hypothesis", "references", "case_id", "video_sha256", "allocations", "endpoint"):
        assert f'"{field}":' not in canonical_json_bytes(result).decode()


async def test_running_api_discovers_two_native_rounds_without_restart(prepared, monkeypatch):
    p = prepared
    pub = PublicResultsPublisher(p.config)
    async with client_for(
        p.s.store, public_results_directory=p.config.public_results_directory
    ) as client:
        url = f"/v1/competition/rounds/{digest(p.s.round)}/results"
        assert (await client.get(url)).status_code == 404
        assert pub.poll_once()["published"] == [digest(p.s.round)]
        first = await client.get(url)
        assert first.status_code == 200 and first.json()["state"] == "closed_computed"
        second = add_round(p)
        # A late row may sort before the cursor; wrap must find it too.
        reports = [pub.poll_once() for _ in range(3)]
        assert digest(second) in [round_id for r in reports for round_id in r["published"]]

        def forbidden(*a, **k):
            raise AssertionError("GET replayed private evidence")

        monkeypatch.setattr(exporter, "replay_outcome", forbidden)
        monkeypatch.setattr(publisher_module, "export_round", forbidden)
        index = (await client.get("/v1/competition/rounds/index")).json()
        assert len(index["items"]) == 2
        for item in index["items"]:
            assert item["results_url"]
            response = await client.get(item["results_url"])
            assert response.status_code == 200
            assert response.json()["certification"] == "not_checked"
            assert response.json()["rewards"] == "not_checked"
        # Existing publications are metadata-validated without replay on restart.
        reopened = PublicResultsPublisher(p.config)
        assert not reopened.poll_once()["held"]


def test_restart_lost_cursor_and_lost_descriptor_are_idempotent(prepared):
    p = prepared
    pub = PublicResultsPublisher(p.config)
    root = Path(p.config.public_results_directory.directory)
    assert pub.poll_once()["published"]
    source = discover_source(p.config.public_results_directory, digest(p.s.round))
    original = Path(source.path).read_bytes()
    (root / "cursor.json").unlink()
    report = PublicResultsPublisher(p.config).poll_once()
    assert report["retained"] and not report["published"]
    (root / "rounds" / (digest(p.s.round) + ".json")).unlink()
    (root / "cursor.json").unlink()
    assert PublicResultsPublisher(p.config).poll_once()["published"]
    assert Path(source.path).read_bytes() == original
    assert len(list((root / "artifacts").iterdir())) == 1
    # Descriptor survived, but artifact was lost: exact native regeneration repairs it.
    Path(source.path).unlink()
    (root / "cursor.json").unlink()
    assert PublicResultsPublisher(p.config).poll_once()["published"]
    assert Path(source.path).read_bytes() == original


@pytest.mark.parametrize(
    "damage", ["evidence", "observation", "settlement", "cutoff", "submission"]
)
def test_export_rejects_tampered_retained_inputs(prepared, damage):
    p = prepared
    with p.s.store._transaction() as db:
        if damage == "evidence":
            db.execute("UPDATE independent_evaluation_evidence SET body=?", (b"{}",))
        elif damage == "observation":
            db.execute("UPDATE independent_evaluation_evidence SET first_observed_block=151")
        elif damage == "settlement":
            db.execute("UPDATE competition_settlements SET digest=?", ("ab" * 32,))
        elif damage == "cutoff":
            db.execute("UPDATE evidence_cutoff_schedules SET body=?", (b"{}",))
        else:
            db.execute("UPDATE submissions SET body=?", (b"{}",))
    with pytest.raises(ValueError):
        export(p)
    result = PublicResultsPublisher(p.config).poll_once()
    assert result["held"] and not result["published"]
    assert not (Path(p.config.public_results_directory.directory) / "rounds").exists()


def test_bad_round_does_not_starve_next_round(prepared):
    p = prepared
    second = add_round(p)
    with p.s.store._transaction() as db:
        db.execute(
            "UPDATE competition_settlements SET body=? WHERE round=?", (b"{}", digest(p.s.round))
        )
    report = PublicResultsPublisher(p.config).poll_once()
    assert report["published"] == [digest(second)]
    assert report["held"] == [{"round_sha256": digest(p.s.round), "error_type": "ValidationError"}]


def test_export_bound_and_runtime_pin_fail_closed(prepared):
    p = prepared
    with pytest.raises(ValueError, match="byte bound"):
        export_round(
            p.s.store.path,
            digest(p.s.round),
            policy=p.s.policy,
            scoring_policy=p.scoring,
            limits=PublicResultsExportLimits(maximum_record_bytes=1024),
        )
    pins = p.scoring.implementation_pins.scoring.model_copy(
        update={"scoring_source_sha256": "ab" * 32}
    )
    wrong = p.scoring.model_copy(
        update={
            "implementation_pins": p.scoring.implementation_pins.model_copy(
                update={"scoring": pins}
            )
        }
    )
    with pytest.raises(RuntimeError, match="scoring_source"):
        export_round(p.s.store.path, digest(p.s.round), policy=p.s.policy, scoring_policy=wrong)


def test_export_opens_only_query_only_database(prepared, monkeypatch):
    original = sqlite3.connect

    def connect(*a, **k):
        assert a[0].endswith("?mode=ro")
        db = original(*a, **k)

        def authorize(action, *_):
            if action in (
                sqlite3.SQLITE_INSERT,
                sqlite3.SQLITE_UPDATE,
                sqlite3.SQLITE_DELETE,
                sqlite3.SQLITE_CREATE_TABLE,
            ):
                return sqlite3.SQLITE_DENY
            return sqlite3.SQLITE_OK

        db.set_authorizer(authorize)
        return db

    monkeypatch.setattr(sqlite3, "connect", connect)
    assert export(prepared).items


@pytest.mark.parametrize(
    "damage", ["artifact", "symlink", "hardlink", "descriptor", "private_field", "payment"]
)
async def test_dynamic_artifact_damage_is_closed_and_not_leaked(prepared, damage):
    p = prepared
    PublicResultsPublisher(p.config).poll_once()
    config = p.config.public_results_directory
    source = discover_source(config, digest(p.s.round))
    path = Path(source.path)
    if damage == "artifact":
        path.write_bytes(path.read_bytes() + b" ")
    elif damage == "symlink":
        dest = path.with_suffix(".original")
        path.rename(dest)
        path.symlink_to(dest)
    elif damage == "hardlink":
        os.link(path, path.with_suffix(".link"))
    else:
        descriptor = Path(config.directory) / "rounds" / (digest(p.s.round) + ".json")
        if damage == "descriptor":
            value = json.loads(descriptor.read_bytes())
            value["round_sha256"] = "ab" * 32
        else:
            value = json.loads(path.read_bytes())
            value["hypothesis" if damage == "private_field" else "rewards"] = "PRIVATE_UNTRUSTED"
            raw = canonical_json_bytes(value)
            artifact_id = hashlib.sha256(raw).hexdigest()
            atomic_write(path.parent / (artifact_id + ".json"), raw)
            value = dict(
                schema="umi-public-results-descriptor/1",
                round_sha256=digest(p.s.round),
                artifact_sha256=artifact_id,
            )
        descriptor.write_bytes(canonical_json_bytes(value))
    async with client_for(p.s.store, public_results_directory=config) as client:
        response = await client.get(f"/v1/competition/rounds/{digest(p.s.round)}/results")
        assert response.status_code == 503
        assert "PRIVATE" not in response.text


def test_descriptor_conflicts_and_publisher_lease(prepared):
    p = prepared
    pub = PublicResultsPublisher(p.config)
    pub.poll_once()
    source = discover_source(p.config.public_results_directory, digest(p.s.round))
    with pytest.raises(ValueError, match="conflict"):
        resolve_source(
            p.config.public_results_directory,
            {digest(p.s.round): source.model_copy(update={"artifact_sha256": "ab" * 32})},
            digest(p.s.round),
        )
    with publisher_lease(Path(p.config.public_results_directory.directory)):
        with pytest.raises(BlockingIOError):
            pub.poll_once()
        changed = export(p).model_copy(update={"observed_block": 161})
        with pytest.raises(ValueError, match="conflict"):
            publish_scores(p.config.public_results_directory, changed)


async def test_live_dispute_is_visible_without_rewriting_artifact(prepared):
    p = prepared
    PublicResultsPublisher(p.config).poll_once()
    with p.s.store._transaction() as db:
        db.execute("INSERT INTO settlement_disputes VALUES (?,?)", (digest(p.s.round), 170))
    async with client_for(
        p.s.store, public_results_directory=p.config.public_results_directory
    ) as client:
        response = await client.get(f"/v1/competition/rounds/{digest(p.s.round)}/results")
        assert response.status_code == 200 and response.json()["disputed"]
        assert response.json()["rewards"] == "not_checked"


def test_new_schema_rejects_invented_authority(prepared):
    body = export(prepared).model_dump(mode="json", by_alias=True)
    PublicSettlementScores.model_validate_json(canonical_json_bytes(body))
    for field, value in (
        ("certification", "certified"),
        ("rewards", "active"),
        ("chain_submission_authorized", True),
    ):
        with pytest.raises(ValueError):
            PublicSettlementScores.model_validate_json(canonical_json_bytes({**body, field: value}))


def test_export_snapshot_does_not_hold_wal_writer(prepared, monkeypatch):
    entered, release = threading.Event(), threading.Event()
    original = exporter.replay_outcome

    def paused(*args, **kwargs):
        entered.set()
        assert release.wait(5)
        return original(*args, **kwargs)

    monkeypatch.setattr(exporter, "replay_outcome", paused)
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(export, prepared)
        try:
            assert entered.wait(5)
            # Replay still owns its original snapshot while another native writer commits.
            with prepared.s.store._transaction() as db:
                assert db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
                db.execute(
                    "INSERT INTO settlement_disputes VALUES (?,?)", (digest(prepared.s.round), 170)
                )
        finally:
            release.set()
        assert future.result(timeout=5).items


def test_coherent_digest_rewrite_still_rejects_forged_evaluator_signature(prepared):
    from umi.competition_evidence import independent_evidence_digest
    from umi.competition_settlement import CompetitionSettlement, competition_settlement_digest

    p = prepared
    signed, evidence = p.s.evidence[0]
    old_id = independent_evidence_digest(evidence)
    run = evidence.evaluator_runs[0]
    signature = run.signature.signature
    forged_signature = signature[:-2] + ("00" if signature[-2:] != "00" else "01")
    forged_run = run.model_copy(
        update={"signature": run.signature.model_copy(update={"signature": forged_signature})}
    )
    evidence = evidence.model_copy(
        update={"evaluator_runs": (forged_run, *evidence.evaluator_runs[1:])}
    )
    new_id = independent_evidence_digest(evidence)
    settlement = CompetitionSettlement.model_validate_json(canonical_json_bytes(p.settlement))
    settlement = settlement.model_copy(
        update={
            "results": tuple(
                binding.model_copy(update={"independent_evidence_sha256": new_id})
                if binding.submission_sha256 == digest(signed.submission)
                else binding
                for binding in settlement.results
            )
        }
    )
    with p.s.store._transaction() as db:
        db.execute(
            "UPDATE independent_evaluation_evidence SET digest=?,body=? WHERE digest=?",
            (new_id, canonical_json_bytes(evidence), old_id),
        )
        db.execute(
            "UPDATE competition_settlements SET digest=?,body=?",
            (competition_settlement_digest(settlement), canonical_json_bytes(settlement)),
        )
    with pytest.raises(ValueError, match="signature"):
        export(p)


def test_malformed_round_body_does_not_block_other_exports(prepared):
    second = add_round(prepared)
    with prepared.s.store._transaction() as db:
        db.execute(
            "UPDATE rounds SET body=? WHERE digest=?", (b"not-json", digest(prepared.s.round))
        )
    report = PublicResultsPublisher(prepared.config).poll_once()
    assert report["published"] == [digest(second)]
    assert len(report["held"]) == 1


def test_batch_cursor_wrap_and_repair_retry(prepared):
    p = prepared
    second = add_round(p)
    config = p.config.model_copy(update={"maximum_rounds_per_poll": 1})
    publisher = PublicResultsPublisher(config)
    report = publisher.poll_once()
    assert len(report["published"]) == 1
    # Reopen after every poll: cursor survives process exit without skipping work.
    report2 = PublicResultsPublisher(config).poll_once()
    assert {report["published"][0], report2["published"][0]} == {digest(p.s.round), digest(second)}
    assert not PublicResultsPublisher(config).poll_once()["published"]
    assert PublicResultsPublisher(config).poll_once()["retained"]


def test_real_cli_exports_without_wallet_or_source_database_mutation(prepared, tmp_path):
    p = prepared
    config_path = tmp_path / "publisher.json"
    config_path.write_bytes(canonical_json_bytes(p.config))
    command = [
        sys.executable,
        "-B",
        "-m",
        "umi.competition_public_results_cli",
        "--config",
        str(config_path),
    ]
    result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["published"] == [digest(p.s.round)]
    config_path.write_bytes(b'{"schema":"PRIVATE_BAD_CONFIG"}')
    result = subprocess.run(command, text=True, capture_output=True, timeout=30, check=False)
    assert result.returncode == 1
    assert "PRIVATE" not in result.stdout + result.stderr
    assert json.loads(result.stdout)["error_type"] == "ValidationError"


def test_wrong_policy_pin_and_predecessor_chain_are_rejected(prepared):
    p = prepared
    with pytest.raises(ValueError, match="digest"):
        PublicResultsPublisher(p.config.model_copy(update={"policy_sha256": "ab" * 32}))
    with pytest.raises(ValueError, match="predecessor"):
        export_round(
            p.s.store.path,
            digest(p.s.round),
            policy=p.s.policy,
            scoring_policy=p.scoring,
            predecessors=(p.s.policy,),
        )


@pytest.mark.parametrize("part", ["root", "artifacts", "rounds"])
def test_registry_directory_symlinks_are_rejected(prepared, part):
    p = prepared
    PublicResultsPublisher(p.config).poll_once()
    root = Path(p.config.public_results_directory.directory)
    path = root if part == "root" else root / part
    other = path.with_name(path.name + "-original")
    path.rename(other)
    path.symlink_to(other, target_is_directory=True)
    with pytest.raises(ValueError, match="symlink"):
        resolve_source(p.config.public_results_directory, {}, digest(p.s.round))


def test_real_watch_sigterm_releases_lease_and_exits(prepared, tmp_path):
    path = tmp_path / "watch.json"
    path.write_bytes(canonical_json_bytes(prepared.config))
    process = subprocess.Popen(
        [
            sys.executable,
            "-B",
            "-m",
            "umi.competition_public_results_cli",
            "--config",
            str(path),
            "--watch",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        assert select.select([process.stdout], [], [], 10)[0]
        report = json.loads(process.stdout.readline())
        assert report["published"] == [digest(prepared.s.round)]
        process.send_signal(signal.SIGTERM)
        _, errors = process.communicate(timeout=5)
        assert process.returncode == 0, errors
        with publisher_lease(Path(prepared.config.public_results_directory.directory)):
            pass
    finally:
        if process.poll() is None:
            process.kill()
            process.communicate(timeout=5)
