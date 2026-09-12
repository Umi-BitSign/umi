from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest

from umi.competition_api import create_app
from umi.competition_cli import _parser, execute
from umi.competition_evidence import IndependentEvaluationEvidence
from umi.competition_settlement import CompetitionSettlement, EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_evidence import attested_result, outputs, run_record, signed_run
from .test_open_competition import bundle_at, round_for, snapshot, submission, suite_for
from .test_open_competition import policy as policy


@pytest.fixture
def workflow(policy, tmp_path):
    # Endpoint-only is an inert fixture choice, not a successor launch allocation.
    policy = policy.model_copy(update={"endpoint_reward_bps": 10000, "model_reward_bps": 0})
    baseline = bundle_at(tmp_path / "baseline")
    signed = submission(policy)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (signed,), digest(baseline))
    common = attested_result(signed, round_, suite)
    evidence = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=common,
        evaluator_runs=tuple(
            signed_run(
                run_record(name, policy, signed, round_, suite, common, elapsed_ms=10 + index),
                name,
            )
            for index, name in enumerate(("Charlie", "Dave"))
        ),
    )
    cutoff = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    inputs = {
        "round": round_,
        "suite": suite,
        "entries": [{"submission": signed, "evidence": evidence}],
    }
    files = {}
    for name, value in {
        "policy": policy,
        "manifest": baseline,
        "submission": signed,
        "suite": suite,
        "round": round_,
        "evaluation": evidence,
        "snapshot": snapshot(160),
        "schedule": cutoff,
    }.items():
        path = tmp_path / (name + ".json")
        path.write_bytes(canonical_json_bytes(value))
        files[name] = str(path)
    inputs_path = tmp_path / "inputs.json"
    inputs_path.write_bytes(
        canonical_json_bytes(
            {
                "round": round_.model_dump(mode="json", by_alias=True),
                "suite": suite.model_dump(mode="json", by_alias=True),
                "entries": [
                    {
                        "submission": signed.model_dump(mode="json", by_alias=True),
                        "evidence": evidence.model_dump(mode="json", by_alias=True),
                    }
                ],
            }
        )
    )
    files["inputs"] = str(inputs_path)
    files["archive"] = str(tmp_path / "archive")
    files["source"] = str(tmp_path / "baseline")
    files["state"] = str(tmp_path / "state")

    def command(name, *file_options, **literal_options):
        argv = ["--policy", files["policy"], name]
        for option in file_options:
            argv.extend(("--" + option, files[option]))
        for option, value in literal_options.items():
            argv.extend(("--" + option.replace("_", "-"), str(value)))
        return execute(_parser().parse_args(argv))

    command("preserve-bundle", "manifest", "source", "archive")
    command("initialize-baseline", "state", "manifest", "archive")
    store = CompetitionStore(tmp_path / "state", policy)
    store.admit(signed, snapshot(), 110)
    command("fix-evidence-cutoff", "state", "round", "schedule", observed_block=115)
    command("close-round", "state", "round", current_block=120)
    return SimpleNamespace(
        policy=policy,
        signed=signed,
        suite=suite,
        round=round_,
        common=common,
        evidence=evidence,
        command=command,
        store=store,
        inputs=inputs,
        files=files,
    )


async def test_cli_settlement_roundtrip_and_public_late_conflict(workflow):
    s = workflow
    scores = s.command(
        "replay-independent-evaluation",
        "submission",
        "evaluation",
        "round",
        "suite",
        current_block=150,
    )
    assert scores["candidate_quality"] == "1"
    assert not scores["chain_submission_authorized"]
    receipt = s.command(
        "record-independent-evaluation",
        "state",
        "submission",
        "evaluation",
        "round",
        "suite",
        observed_block=150,
    )
    assert receipt["first_observed_block"] == 150
    original = s.command("settle-round", "state", "inputs", "snapshot", current_block=160)
    settlement = CompetitionSettlement.model_validate_json(canonical_json_bytes(original))
    assert settlement.results[0].first_observed_block == 150
    assert not settlement.chain_submission_authorized
    # CLI constructs a new store each time: retries exercise the persisted record.
    assert s.command("settle-round", "state", "inputs", "snapshot", current_block=161) == original

    async def current_snapshot():
        return snapshot(170)

    app = create_app(CompetitionStore(s.store.directory, s.policy), current_snapshot)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        path = "/v1/competition/settlements/" + digest(s.round)
        published = (await client.get(path)).json()
        assert published["settlement"] == original
        assert not published["disputed"]
        conflict = attested_result(
            s.signed,
            s.round,
            s.suite,
            candidate=outputs(s.suite, hypothesis="hi", elapsed_ms=7),
        )
        s.store.record_evaluation(
            signed=s.signed,
            attested=conflict,
            round_=s.round,
            suite=s.suite,
            observed_block=170,
        )
        disputed = (await client.get(path)).json()
        assert disputed["settlement"] == original
        assert disputed["settlement_sha256"] == published["settlement_sha256"]
        assert disputed["disputed"]
        assert disputed["dispute_detected_block"] == 170
        assert (await client.get("/v1/competition/settlements/not-a-digest")).status_code == 404
        assert (await client.get("/v1/competition/settlements/" + "ff" * 32)).status_code == 404
        assert (await client.post(path, json={})).status_code == 405
    with pytest.raises(ValueError, match="conflict"):
        s.command("settle-round", "state", "inputs", "snapshot", current_block=170)
    status = s.command("settlement-status", "state", round_sha256=digest(s.round))
    assert status["status"]["disputed"]
    assert not status["chain_submission_authorized"]


def test_cli_cannot_backdate_evidence_at_settlement(workflow):
    s = workflow
    with pytest.raises(ValueError, match="recorded by cutoff"):
        s.command("settle-round", "state", "inputs", "snapshot", current_block=161)
    # A late receipt can be retained, but it never becomes evidence observed on time.
    receipt = s.command(
        "record-independent-evaluation",
        "state",
        "submission",
        "evaluation",
        "round",
        "suite",
        observed_block=162,
    )
    assert receipt["first_observed_block"] == 162
    with pytest.raises(ValueError, match="after cutoff"):
        s.command("settle-round", "state", "inputs", "snapshot", current_block=163)


def test_cli_has_no_weight_submit_or_conflict_clear_command():
    parser = _parser()
    for command in ("set-weights", "submit-weights", "clear-hold", "activate"):
        with pytest.raises(SystemExit):
            parser.parse_args(["--policy", "policy.json", command])
