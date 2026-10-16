"""Signed native grants and retirements through the stopped diagnostic reader.

RPC, model/video and finality are fixtures. This does not qualify installed
runtime switching, remote enrollment selection or a four-cohort transaction.
"""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys
from contextlib import closing
from dataclasses import replace
from pathlib import Path

import bittensor as bt
import pytest

from umi import competition_miner_transition as transition
from umi.competition_cohort_miner_startup import CohortMinerStartupConfig
from umi.competition_miner_transition import (
    MinerRevisionPreflightRequest,
    TransitionEnrollmentDirectory,
    preflight_revision_transition,
)
from umi.competition_miner_transition_io import TransitionPreflightRefused
from umi.config import Limits
from umi.endpoint_protocol import COHORT_RETIRE_PATH
from umi.miner_resources import SQLiteMinerResourceLedger
from umi.policy import scoring_policy_hash
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_miner import (
    base_policy as base_policy,
)
from .test_competition_cohort_miner import (
    chain as chain,
)
from .test_competition_cohort_miner import (
    chain_config as chain_config,
)
from .test_competition_cohort_miner import (
    endpoint as endpoint,
)
from .test_competition_cohort_miner import (
    execution as execution,
)
from .test_competition_cohort_miner import grant, request, translate
from .test_competition_cohort_miner import (
    granted as granted,
)
from .test_competition_cohort_miner import (
    harness as harness,
)
from .test_competition_cohort_miner import (
    known_video_bytes as known_video_bytes,
)
from .test_competition_cohort_miner import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_miner import (
    policy as policy,
)
from .test_competition_cohort_miner import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_miner import (
    recovery as recovery,
)
from .test_competition_cohort_miner import (
    recovery_case as recovery_case,
)
from .test_competition_cohort_miner import (
    relay as relay,
)
from .test_competition_cohort_miner import (
    runtime as runtime,
)
from .test_competition_cohort_miner import (
    scenario as scenario,
)


def write(path, value):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(canonical_json_bytes(value))
    path.chmod(0o600)
    return str(path)


@pytest.fixture
async def retained(granted, tmp_path, monkeypatch):
    p = granted
    bindings = list(p.miner_cfg.cohorts)
    for n in range(4):
        bindings.append(bindings[0].model_copy(update={"cohort_sha256": f"{n + 100:064x}"}))
    p.miner_cfg = p.miner_cfg.model_copy(
        update={
            "directory": str(tmp_path / "grants-c5c10"),
            "cohorts": tuple(sorted(bindings, key=lambda c: c.cohort_sha256)),
            "read_timeout_seconds": 1200,
        }
    )
    p.miner = p.rebuild()
    p.miner.resource_ledger.close()
    limits = Limits.from_policy(
        p.transport_policy,
        competition_policy=p.c.policy,
        maximum_inference_concurrency=len(p.c.policy.evaluators),
    )
    ledger_path = tmp_path / "protocol" / "assignments.sqlite3"
    ledger = SQLiteMinerResourceLedger(
        ledger_path,
        miner_hotkey=p.miner.hotkey_ss58,
        scoring_policy_sha256=scoring_policy_hash(p.transport_policy),
        limits=limits,
        maximum_recovery_assignments=4096,
    )
    p.miner = replace(p.miner, resource_ledger=ledger, limits=limits)
    startup = CohortMinerStartupConfig(
        schema="umi-cohort-miner-startup/1",
        authority=p.miner_cfg,
        history_origin="https://example.com/",
        history_owner_hotkey=p.c.policy.evaluators[0].hotkey,
    )
    new = startup.model_copy(
        update={"authority": startup.authority.model_copy(update={"model_revision": "ab" * 32})}
    )
    config_path = write(tmp_path / "inputs" / "old.json", startup)
    proposed_path = write(tmp_path / "inputs" / "proposed.json", new)
    policy_path = write(tmp_path / "inputs" / "competition.json", p.c.policy)
    transport_path = write(tmp_path / "inputs" / "transport.json", p.transport_policy)
    for name in ("nonces.sqlite3", "finality.sqlite3"):
        path = tmp_path / "protocol" / name
        path.write_bytes(b"fixture-state-not-a-consumed-database")
        path.chmod(0o600)
    command = (
        "/root/umi-runtime/e4b0fa14/venv/bin/umi-miner",
        "--wallet-name",
        "fixture",
        "--hotkey",
        "fixture",
        "--wallet-path",
        "/fixture/wallets",
        "--policy",
        transport_path,
        "--competition-policy",
        policy_path,
        "--competition-cohort-config",
        config_path,
        "--model-revision",
        p.miner.model_revision,
        "--serving-origin",
        startup.authority.serving_origin,
        "--target-triple",
        "x86_64-unknown-linux-gnu",
        "--finality-verifier-binary",
        "/fixture/verifier",
        "--finality-chain-spec",
        "/fixture/spec",
        "--finality-state",
        str(tmp_path / "protocol" / "finality.sqlite3"),
        "--nonce-db",
        str(tmp_path / "protocol" / "nonces.sqlite3"),
        "--assignment-db",
        str(ledger_path),
        "--translator-unix-socket",
        "/fixture/model.sock",
        "--video-origin",
        "https://example.com/",
        "--max-recovery-assignments",
        "4096",
    )
    proposed = tuple(
        proposed_path if x == config_path else "ab" * 32 if x == p.miner.model_revision else x
        for x in command
    )
    enrollments = []
    for entry in bindings:
        path = tmp_path / "enrollment" / entry.cohort_sha256
        path.mkdir(parents=True, mode=0o700)
        enrollments.append(
            TransitionEnrollmentDirectory(cohort_sha256=entry.cohort_sha256, directory=str(path))
        )
    selection = MinerRevisionPreflightRequest(
        schema="umi-miner-revision-preflight-request/1",
        original_argv=command,
        proposed_argv=proposed,
        service_uid=os.getuid(),
        launch_kind="systemd",
        enrollments=tuple(enrollments),
        verification_directory=str(tmp_path / "verification"),
    )
    ack = await grant(p)
    assert ack.status_code == 200, ack.text
    # Exercise both actual response-retained and signed absence retirement paths.
    response = await translate(p)
    assert response.status_code == 200, response.text
    p.finality.head = max(item.deadline_block for item in p.requests) + 1
    monkeypatch.setattr(
        bt.timelock,
        "current_round",
        lambda: max(item.response_close_round for item in p.requests) + 1,
    )
    for item in p.requests:
        result = await request(p, COHORT_RETIRE_PATH, item)
        assert result.status_code == 200, result.text
    ledger.close()
    return p, selection, ledger_path


def inventory(root):
    return {
        str(p.relative_to(root)): (p.stat().st_mode, hashlib.sha256(p.read_bytes()).hexdigest())
        for p in root.rglob("*")
        if p.is_file() and "verification" not in p.parts
    }


async def test_retained_native_requests_repeat_and_preserve_originals(
    retained, tmp_path, monkeypatch
):
    p, selection, _ = retained
    before = inventory(tmp_path)
    result = preflight_revision_transition(selection)
    assert result["known_requests_retired"]
    assert result["local_inventory_complete"]
    assert result["counts"]["requests"] == len(p.requests)
    assert result["counts"]["retired"] == len(p.requests)
    assert len(result["cohorts"]) == 5
    assert not result["runtime_migration_authorized"]
    assert not result["native_startup_compatibility_verified"]
    assert not result["enrollment_authority_verified"]
    assert {x["retirement_result"] for x in result["requests"]} == {
        "response_retained",
        "no_response_retained",
    }
    assert inventory(tmp_path) == before
    monkeypatch.setattr(
        transition, "_grant_fact", lambda *a, **kw: pytest.fail("reverified unchanged grant")
    )
    monkeypatch.setattr(
        transition, "_retirement", lambda *a, **kw: pytest.fail("reverified unchanged retirement")
    )
    again = preflight_revision_transition(selection)
    assert again == {**result, "verification_reused": True}
    request_path = write(Path(selection.verification_directory) / "request.json", selection)
    restarted = subprocess.run(
        [sys.executable, "-m", "umi.competition_miner_transition_cli", "--request", request_path],
        capture_output=True,
        check=True,
    )
    assert json.loads(restarted.stdout) == again
    assert inventory(tmp_path) == before


@pytest.mark.parametrize("damage", ["intent", "schema", "retirement_signature", "index"])
async def test_damaged_retained_state_refuses(retained, damage):
    p, selection, ledger = retained
    path = (
        Path(p.miner_cfg.directory) / "rounds.sqlite3" if damage in {"intent", "index"} else ledger
    )
    with closing(sqlite3.connect(path)) as db, db:
        if damage == "intent":
            db.execute("DELETE FROM records WHERE kind='miner_grant_receipt_intent'")
        elif damage == "index":
            db.execute("DELETE FROM miner_grant_requests")
        elif damage == "schema":
            db.execute("UPDATE metadata SET value='umi-miner-resource-ledger/1' WHERE key='schema'")
        else:
            raw = db.execute("SELECT receipt FROM request_retirements LIMIT 1").fetchone()[0]
            value = json.loads(raw)
            value["receipt"]["request_digest"] = "ff" * 32
            db.execute("UPDATE request_retirements SET receipt=?", (canonical_json_bytes(value),))
    expected = {
        "intent": "receipt_intent_missing",
        "schema": "retirement_schema_invalid",
        "retirement_signature": "retirement_intent_changed",
        "index": "request_index",
    }[damage]
    with pytest.raises(ValueError, match=expected):
        preflight_revision_transition(selection)


async def test_missing_enrollment_is_explicit_and_never_authorizes(retained):
    _, selection, _ = retained
    selection = selection.model_copy(update={"enrollments": selection.enrollments[:-1]})
    result = preflight_revision_transition(selection)
    assert result["known_requests_retired"]
    assert not result["local_inventory_complete"]
    assert len(result["missing_enrollment_cohorts"]) == 1
    assert not result["runtime_migration_authorized"]


@pytest.mark.parametrize("kind", ["roster", "directory", "model_only"])
async def test_no_implicit_journal_rebind_or_roster_drop(retained, kind):
    _, selection, _ = retained
    config_path = Path(
        selection.proposed_argv[selection.proposed_argv.index("--competition-cohort-config") + 1]
    )
    value = json.loads(config_path.read_bytes())
    if kind == "roster":
        value["authority"]["cohorts"] = value["authority"]["cohorts"][1:]
    elif kind == "directory":
        value["authority"]["directory"] += "/new"
    else:
        value["authority"]["model_revision"] = "cd" * 32
    write(config_path, value)
    with pytest.raises(ValueError):
        preflight_revision_transition(selection)


async def test_enrollment_addition_during_pass_refuses(retained, monkeypatch):
    _, selection, _ = retained
    original = transition._grant_fact

    def alter(*a, **kw):
        value = original(*a, **kw)
        write(Path(selection.enrollments[0].directory) / "late.json", {"admission": "unverified"})
        return value

    monkeypatch.setattr(transition, "_grant_fact", alter)
    with pytest.raises(TransitionPreflightRefused, match="source_changed"):
        preflight_revision_transition(selection)


@pytest.mark.parametrize("launch", ["script", "python_script", "module"])
async def test_supported_launch_shapes(retained, launch):
    _, selection, _ = retained

    def command(argv):
        if launch == "python_script":
            return ("/root/umi-runtime/e4/venv/bin/python", *argv)
        if launch == "module":
            return ("/root/umi-runtime/e4/venv/bin/python", "-m", "umi.miner", *argv[1:])
        return argv

    result = preflight_revision_transition(
        selection.model_copy(
            update={
                "original_argv": command(selection.original_argv),
                "proposed_argv": command(selection.proposed_argv),
                "launch_kind": "container",
            }
        )
    )
    assert result["known_requests_retired"] and not result["runtime_migration_authorized"]


async def test_historical_grant_layout_without_new_capacity_metadata(retained, tmp_path):
    """e4b0fa14 has records_capacity_lengths but none of the later counter tables."""
    p, selection, _ = retained
    database = Path(p.miner_cfg.directory) / "rounds.sqlite3"
    with closing(sqlite3.connect(database)) as db, db:
        for (name,) in db.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' "
            "AND name LIKE 'round_record_capacity_%'"
        ).fetchall():
            assert name.replace("_", "").isalnum()
            db.execute("DROP TRIGGER " + name)
        db.execute("DROP TABLE round_record_capacity_kinds")
        db.execute("DROP TABLE round_record_capacity")
    before = inventory(tmp_path)
    result = preflight_revision_transition(selection)
    assert result["known_requests_retired"]
    assert inventory(tmp_path) == before
    with closing(sqlite3.connect(database)) as db, db:
        assert not db.execute(
            "SELECT 1 FROM sqlite_master WHERE name='round_record_capacity'"
        ).fetchone()


async def test_interrupted_pass_reuses_completed_grants(retained, monkeypatch):
    _, selection, _ = retained
    original = transition._retirement

    def interrupt(*a, **kw):
        raise RuntimeError("fixture interruption after grant verification")

    monkeypatch.setattr(transition, "_retirement", interrupt)
    with pytest.raises(RuntimeError, match="fixture interruption"):
        preflight_revision_transition(selection)
    monkeypatch.setattr(transition, "_retirement", original)
    monkeypatch.setattr(
        transition, "_grant_fact", lambda *a, **kw: pytest.fail("completed grant repeated")
    )
    assert preflight_revision_transition(selection)["known_requests_retired"]


async def test_preflight_semantics_change_does_not_borrow_old_verdicts(retained, monkeypatch):
    _, selection, _ = retained
    assert not preflight_revision_transition(selection)["verification_reused"]
    monkeypatch.setattr(transition, "TRANSITION_VERIFIER_SEMANTICS", "fixture-new-semantics")
    original = transition._grant_fact
    calls = []

    def record(*a, **kw):
        calls.append(True)
        return original(*a, **kw)

    monkeypatch.setattr(transition, "_grant_fact", record)
    assert not preflight_revision_transition(selection)["verification_reused"]
    assert calls


async def test_derived_complete_missing_requires_explicit_repair(retained):
    _, selection, _ = retained
    assert preflight_revision_transition(selection)["known_requests_retired"]
    cache = Path(selection.verification_directory)
    for path in cache.glob("*.json"):
        if (
            json.loads(path.read_bytes())["result"].get("schema")
            == "umi-miner-revision-transition-preflight/1"
        ):
            path.unlink()
    with pytest.raises(TransitionPreflightRefused, match="verification_metadata_repair_required"):
        preflight_revision_transition(selection)
    result = preflight_revision_transition(
        selection, repair_reason="fixture missing derived completion"
    )
    assert result["known_requests_retired"]


async def test_changed_known_assignment_is_not_reported_as_startup_ready(retained):
    _, selection, ledger = retained
    with closing(sqlite3.connect(ledger)) as db, db:
        db.execute("UPDATE operations SET status='invalid' WHERE status='completed'")
    result = preflight_revision_transition(selection)
    assert result["known_requests_retired"]
    assert result["native_startup_compatibility_verified"] is False
    assert result["runtime_migration_authorized"] is False
    assert "local_archive_ready" not in result


def test_cli_refusal_has_elapsed_eta_and_status(tmp_path, capsys):
    from umi.competition_miner_transition_cli import main

    assert main(["--request", str(tmp_path / "missing.json")]) == 2
    output = json.loads(capsys.readouterr().err)
    assert output["state"] == "refused" and output["stalled"]
    assert output["elapsed_seconds"] >= 0 and output["eta_seconds"] is None
    assert not output["retrying"] and not output["runtime_migration_authorized"]


async def test_new_proposed_revision_reuses_original_claim_grant_and_retirement_checks(
    retained, monkeypatch
):
    from umi.competition_cohort_service_work import ServiceWorkClaim, SignedServiceWorkClaim
    from umi.open_competition import digest, sign_object

    p, selection, _ = retained
    cohort = p.grant.attempt.order.job.round.cohort_sha256
    directory = Path(
        next(item.directory for item in selection.enrollments if item.cohort_sha256 == cohort)
    )
    claim = ServiceWorkClaim(
        schema="umi-cohort-service-work-claim/1",
        catalog_sha256="ac" * 32,
        hotkey=p.miner.hotkey_ss58,
        submission_sha256=digest(p.grant.attempt.order.job.submission.submission),
        nonce="bd" * 32,
    )
    signed = SignedServiceWorkClaim(claim=claim, signature=sign_object(claim, p.miner.wallet))
    write(directory / "paid-claim.json", signed)
    first = preflight_revision_transition(selection)
    assert first["claims"][0]["local_grant_slots"] == []
    assert first["claims"][0]["remote_disposition_verified"] is False
    path = Path(
        selection.proposed_argv[selection.proposed_argv.index("--competition-cohort-config") + 1]
    )
    value = json.loads(path.read_bytes())
    value["authority"]["model_revision"] = "cd" * 32
    write(path, value)
    changed = selection.model_copy(
        update={
            "proposed_argv": tuple(
                "cd" * 32 if item == "ab" * 32 else item for item in selection.proposed_argv
            )
        }
    )

    def repeated(*a, **kw):
        pytest.fail("unchanged original verification repeated for new proposal")

    for name in ("_grant_fact", "_retirement", "_lineage", "_enrollment_fact"):
        monkeypatch.setattr(transition, name, repeated)
    second = preflight_revision_transition(changed)
    assert second["known_requests_retired"] and second["new_revision"] == "cd" * 32
    assert second["claims"] == first["claims"]
    assert not second["verification_reused"] and not second["runtime_migration_authorized"]
