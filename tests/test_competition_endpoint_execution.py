from __future__ import annotations

import asyncio
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest

from umi import competition_execution as execution
from umi.competition_artifacts import preserve_bundle
from umi.competition_dispatch import EndpointDispatcher
from umi.competition_endpoint_execution import (
    EndpointPairedEvidence,
    RetainedRevealPulse,
    assemble_endpoint_evidence,
    endpoint_evaluation_view,
)
from umi.competition_evidence import (
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    replay_independent_evaluation,
    sign_evaluator_run,
)
from umi.competition_runner import OfflineCaseExecution
from umi.open_competition import AttestedResult, CaseOutput, aggregate_quality, digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_authorization import build_authorization_fixture
from .test_competition_dispatch import dispatch as dispatch
from .test_competition_dispatch import dispatch_legacy_policy
from .test_competition_execution import boundary
from .test_competition_feed import feed as feed
from .test_competition_runner import runtime as runtime
from .test_drand import ROUND, pulse_record
from .test_open_competition import bundle_at
from .test_open_competition import policy as policy


@pytest.fixture
def authorization(policy, runtime, tmp_path, monkeypatch):
    import time

    import bittensor as bt

    from umi.window import QUICKNET_PERIOD_MS

    baseline = bundle_at(tmp_path / "baseline")
    policy = policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})
    legacy = dispatch_legacy_policy()
    now = 1789300000000000000
    monkeypatch.setattr("time.time_ns", lambda: now)
    monkeypatch.setattr(time, "time", lambda: time.time_ns() / 1_000_000_000)
    initial = build_authorization_fixture(policy, legacy_policy=legacy)
    # Freeze the synthetic schedule at an existing public Quicknet test vector.
    # Its signature verification and ciphertext decryption are not mocked.
    now += (ROUND - initial.request.reveal_round) * QUICKNET_PERIOD_MS * 1_000_000
    item = build_authorization_fixture(
        policy, legacy_policy=legacy, incumbent_sha256=digest(baseline)
    )
    assert item.request.reveal_round == ROUND
    from umi.window import QUICKNET_GENESIS_MS

    monkeypatch.setattr(
        bt.timelock,
        "current_round",
        lambda: (time.time_ns() // 1_000_000 - QUICKNET_GENESIS_MS) // QUICKNET_PERIOD_MS + 1,
    )
    item.baseline, item.runtime = baseline, runtime
    return item


@pytest.fixture
def paired_setup(dispatch, tmp_path, monkeypatch):
    item = dispatch.feed.item
    archive = tmp_path / "archive"
    preserve_bundle(item.baseline, tmp_path / "baseline", archive, item.policy)
    videos = tmp_path / "videos"
    videos.mkdir()
    for data in item.all_video_bytes:
        (videos / (hashlib.sha256(data).hexdigest() + ".mp4")).write_bytes(data)
    calls = []
    original = dispatch.driver.transport.handle_async_request
    errors = []

    async def capture_response(request):
        response = await original(request)
        if response.status_code != 200:
            errors.append((response.status_code, await response.aread()))
        return response

    monkeypatch.setattr(dispatch.driver.transport, "handle_async_request", capture_response)
    dispatch.test_errors = errors

    async def preflight(*args):
        calls.append("preflight")

    async def run(**kwargs):
        calls.append(kwargs)
        return OfflineCaseExecution(
            schema="umi-offline-case-execution/1",
            model_sha256=digest(kwargs["bundle"]),
            runtime_sha256=digest(item.runtime),
            video_sha256=kwargs["video_sha256"],
            output=CaseOutput(case_id=kwargs["case_id"], status="ok", hypothesis="", elapsed_ms=10),
            stdout_hex="0a",
            reason="ok",
            returncode=0,
        )

    monkeypatch.setattr(execution, "verify_runtime", preflight)
    monkeypatch.setattr(execution, "execute_offline_case", run)
    return SimpleNamespace(dispatch=dispatch, archive=archive, videos=videos, calls=calls)


def make_job(setup, evaluator=0):
    item = setup.dispatch.feed.item
    return execution.EndpointIncumbentJob(
        schema="umi-endpoint-incumbent-job/1",
        round=item.round,
        submission=item.signed_submission,
        incumbent=item.baseline,
        runtime=item.runtime,
        evaluator_hotkey=item.evaluator_wallets[evaluator].hotkey.ss58_address,
        cases=tuple(
            execution.ExecutionCase(
                case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum
            )
            for c in item.suite.cases
        ),
    )


async def run_incumbent(setup, tmp_path, *, evaluator=0, source=None, **limits):
    item = setup.dispatch.feed.item
    job = make_job(setup, evaluator)
    journal = execution.ExecutionJournal(tmp_path / f"incumbent-{evaluator}", item.policy, **limits)

    async def capture():
        return boundary(item.request.issued_block)

    result = await execution.run_endpoint_incumbent(
        job=job,
        policy=item.policy,
        archive=setup.archive,
        videos=setup.videos,
        journal=journal,
        boundary_provider=source or capture,
    )
    return result, journal


async def pair(setup, tmp_path, *, evaluator=0, assemble=assemble_endpoint_evidence):
    dispatch = setup.dispatch
    item = dispatch.feed.item
    incumbent, _ = await run_incumbent(setup, tmp_path, evaluator=evaluator)
    driver = dispatch.driver
    if evaluator:
        config = dispatch.config.model_copy(
            update={"evaluator_hotkey": item.evaluator_wallets[evaluator].hotkey.ss58_address}
        )
        driver = EndpointDispatcher(
            config,
            dispatch.feed.journal,
            dispatch.provider,
            item.evaluator_wallets[evaluator],
            transport=dispatch.driver.transport,
        )
    for _ in range(6):
        await driver.poll_once()
        await driver.drain()
        await dispatch.miner.competition_authority.poll_once()
        dispatch.feed.clock.ns += 1
        if _ == 0:
            dispatch.feed.clock.ns += dispatch.config.discovery_grace_seconds * 1_000_000_000
    await driver.aclose()
    assert driver._counts["completed"] == 3
    return assemble(
        incumbent=incumbent,
        journal=dispatch.feed.journal,
        publication_sha256=digest(item.publication.publication),
        suite=item.suite,
        pulses={ROUND: RetainedRevealPulse(**pulse_record())},
        current_block=item.round.reveal_block,
    )


async def test_real_endpoint_transport_and_baseline_runs_reach_independent_evidence(
    paired_setup, tmp_path
):
    setup = paired_setup
    item = setup.dispatch.feed.item
    first = await pair(setup, tmp_path)
    second = await pair(setup, tmp_path, evaluator=1)
    common = execution.common_execution_result(
        (first, second), item.suite, item.policy, current_block=item.round.reveal_block
    )
    runs = []
    for evidence, wallet in zip((first, second), item.evaluator_wallets, strict=False):
        record = execution.run_record_from_execution(
            evidence, common, item.suite, item.policy, current_block=item.round.reveal_block
        )
        assert record.execution_evidence_sha256 == digest(evidence)
        assert record.finished_block >= evidence.incumbent.steps[-1].finished.block
        runs.append(
            SignedEvaluatorRunRecord(run=record, signature=sign_evaluator_run(record, wallet))
        )
    independent = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=AttestedResult(
            result=common,
            signatures=tuple(sign_object(common, w) for w in item.evaluator_wallets[:2]),
        ),
        evaluator_runs=tuple(runs),
    )
    candidate, baseline = replay_independent_evaluation(
        independent,
        item.signed_submission,
        item.round,
        item.suite,
        item.policy,
        current_block=item.round.reveal_block,
    )
    assert aggregate_quality(candidate) == 1 and aggregate_quality(baseline) == 0
    assert setup.dispatch.miner.translator.calls == 6
    offline = [c for c in setup.calls if isinstance(c, dict)]
    assert len(offline) == 6
    assert all(c["bundle"] == item.baseline for c in offline)
    assert all("references" not in c and "wallet" not in c for c in offline)
    assert all(s.role == "incumbent" for s in first.incumbent.steps)
    assert b"references" not in canonical_json_bytes(first.incumbent)
    assert not first.chain_submission_authorized


async def test_completed_incumbent_retry_never_reruns_or_reads_finality(
    paired_setup, tmp_path, monkeypatch
):
    first, _ = await run_incumbent(paired_setup, tmp_path, maximum_jobs=1)

    async def forbidden(*args, **kwargs):
        pytest.fail("completed recovery performed external work")

    monkeypatch.setattr(execution, "execute_offline_case", forbidden)
    monkeypatch.setattr(execution, "verify_runtime", forbidden)
    second, _ = await run_incumbent(
        paired_setup, tmp_path, source=forbidden, maximum_jobs=1, maximum_bytes=1024
    )
    assert second == first


async def test_finality_failure_retains_observation_and_refuses_rerun(paired_setup, tmp_path):
    calls = 0

    async def failed_finish():
        nonlocal calls
        calls += 1
        if calls > 1:
            raise ValueError("test finality unavailable")
        return boundary(paired_setup.dispatch.feed.item.request.issued_block)

    with pytest.raises(ValueError, match="unavailable"):
        await run_incumbent(paired_setup, tmp_path, source=failed_finish)
    job = make_job(paired_setup)
    journal = execution.ExecutionJournal(
        tmp_path / "incumbent-0", paired_setup.dispatch.feed.item.policy
    )
    assert journal.status(execution.execution_key(job))["pending_observations"] == 1
    with pytest.raises(ValueError, match="automatic rerun refused"):
        await run_incumbent(paired_setup, tmp_path)
    assert len(paired_setup.calls) == 2


async def test_incomplete_dispatch_is_not_scored_as_miner_failure(paired_setup, tmp_path):
    item = paired_setup.dispatch.feed.item
    incumbent, _ = await run_incumbent(paired_setup, tmp_path)
    with pytest.raises(ValueError, match="incomplete"):
        assemble_endpoint_evidence(
            incumbent=incumbent,
            journal=paired_setup.dispatch.feed.journal,
            publication_sha256=digest(item.publication.publication),
            suite=item.suite,
            pulses={},
            current_block=item.round.reveal_block,
        )


@pytest.mark.parametrize(
    "mutation",
    ["order", "missing", "key", "pulse", "incumbent", "origin", "request", "policy", "publication"],
)
async def test_paired_evidence_tampering_is_rejected(paired_setup, tmp_path, mutation):
    evidence = await pair(paired_setup, tmp_path)
    item = paired_setup.dispatch.feed.item
    doc = evidence.model_dump(mode="json", by_alias=True)
    if mutation == "order":
        doc["dispatches"].reverse()
    elif mutation == "missing":
        doc["dispatches"].pop()
    elif mutation == "key":
        doc["dispatches"][0]["assignment_key"] = "ab" * 32
    elif mutation == "pulse":
        doc["dispatches"][0]["reveal_pulse"]["signature"] = "00" * 48
    elif mutation == "incumbent":
        doc["incumbent"]["steps"][0]["execution"]["output"]["hypothesis"] = "invented"
    elif mutation in {"origin", "request"}:
        transcript = json.loads(bytes.fromhex(doc["dispatches"][0]["transcript_hex"]))
        transcript["origin_block" if mutation == "origin" else "request_hex"] = (
            0 if mutation == "origin" else "7b7d"
        )
        doc["dispatches"][0]["transcript_hex"] = canonical_json_bytes(transcript).hex()
    elif mutation == "policy":
        doc["legacy_policy"]["activation_block"] += 1
    else:
        doc["publication"]["signatures"][0]["signature"] = "0x" + "00" * 64
    with pytest.raises((ValueError, RuntimeError)):
        changed = EndpointPairedEvidence.model_validate(doc)
        endpoint_evaluation_view(
            changed, item.suite, item.policy, current_block=item.round.reveal_block
        )


async def test_premature_expired_and_same_operator_evidence_cannot_settle(paired_setup, tmp_path):
    evidence = await pair(paired_setup, tmp_path)
    item = paired_setup.dispatch.feed.item
    for block in (item.round.reveal_block - 1, item.round.valid_through_block + 1, True):
        with pytest.raises(ValueError, match=r"premature|expired"):
            endpoint_evaluation_view(evidence, item.suite, item.policy, current_block=block)
    with pytest.raises(ValueError, match="insufficient independent"):
        execution.common_execution_result(
            (evidence,), item.suite, item.policy, current_block=item.round.reveal_block
        )
    with pytest.raises(ValueError, match="duplicate evaluator group"):
        execution.common_execution_result(
            (evidence, evidence), item.suite, item.policy, current_block=item.round.reveal_block
        )


async def test_transport_outage_stays_infrastructure_failure(paired_setup, tmp_path):
    paired_setup.dispatch.driver.transport = httpx.MockTransport(
        lambda request: httpx.Response(503)
    )
    with pytest.raises(ValueError, match="infrastructure failure voids evaluation"):
        await pair(paired_setup, tmp_path)
    assert paired_setup.dispatch.miner.translator.calls == 0


async def test_cancelled_incumbent_keeps_reservation(paired_setup, tmp_path, monkeypatch):
    entered = asyncio.Event()

    async def waiting(**kwargs):
        entered.set()
        await asyncio.Future()

    monkeypatch.setattr(execution, "execute_offline_case", waiting)
    task = asyncio.create_task(run_incumbent(paired_setup, tmp_path))
    await entered.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    with pytest.raises(ValueError, match="automatic rerun refused"):
        await run_incumbent(paired_setup, tmp_path)


async def test_assigned_job_cannot_change_after_first_execution(paired_setup, tmp_path):
    result, journal = await run_incumbent(paired_setup, tmp_path)
    changed = result.job.model_copy(update={"cases": tuple(reversed(result.job.cases))})
    with pytest.raises(ValueError, match="different assignment"):
        journal.reserve(changed)
    with pytest.raises(ValueError):
        execution.validate_job(result.job, paired_setup.dispatch.feed.item.policy)
    with pytest.raises(ValueError):
        execution.ModelExecutionEvidence.model_validate_json(canonical_json_bytes(result))


def test_job_preparation_uses_signed_publication_and_rejects_unassigned_evaluator(paired_setup):
    from umi.competition_endpoint_execution import prepare_incumbent_job

    item = paired_setup.dispatch.feed.item
    args = dict(
        publication=item.publication,
        submission_sha256=digest(item.signed_submission.submission),
        incumbent=item.baseline,
        runtime=item.runtime,
        evaluator_hotkey=item.evaluator_wallets[0].hotkey.ss58_address,
        policy=item.policy,
        legacy_policy=item.legacy_policy,
    )
    assert prepare_incumbent_job(**args) == make_job(paired_setup)
    args["evaluator_hotkey"] = item.evaluator_wallets[3].hotkey.ss58_address
    with pytest.raises(ValueError, match="all paired assignments"):
        prepare_incumbent_job(**args)


async def test_endpoint_cli_assembly_and_shared_record_do_not_sign(paired_setup, tmp_path):
    from umi import competition_cli

    item = paired_setup.dispatch.feed.item
    first = await pair(paired_setup, tmp_path)
    second = await pair(paired_setup, tmp_path, evaluator=1)
    for name, document in (
        ("policy", item.policy),
        ("suite", item.suite),
        ("legacy", item.legacy_policy),
        ("incumbent", first.incumbent),
        ("pulses", {"pulses": [pulse_record()]}),
        ("inputs", competition_cli.ExecutionInputs(executions=(first, second))),
    ):
        (tmp_path / f"{name}.json").write_bytes(canonical_json_bytes(document))

    def command(name, **kwargs):
        argv = ["--policy", str(tmp_path / "policy.json"), name]
        for key, value in kwargs.items():
            argv.extend(["--" + key.replace("_", "-"), str(value)])
        return competition_cli.execute(competition_cli._parser().parse_args(argv))

    assembled = command(
        "assemble-endpoint-execution",
        incumbent_execution=tmp_path / "incumbent.json",
        dispatch_state=paired_setup.dispatch.feed.journal.path.parent,
        publication_sha256=digest(item.publication.publication),
        legacy_policy=tmp_path / "legacy.json",
        suite=tmp_path / "suite.json",
        reveal_pulses=tmp_path / "pulses.json",
        current_block=item.round.reveal_block,
    )
    assert canonical_json_bytes(assembled) == canonical_json_bytes(first)
    common = command(
        "propose-execution-result",
        inputs=tmp_path / "inputs.json",
        suite=tmp_path / "suite.json",
        current_block=item.round.reveal_block,
    )
    (tmp_path / "result.json").write_bytes(canonical_json_bytes(common["object"]))
    (tmp_path / "execution.json").write_bytes(canonical_json_bytes(assembled))
    record = command(
        "prepare-execution-record",
        execution=tmp_path / "execution.json",
        result=tmp_path / "result.json",
        suite=tmp_path / "suite.json",
        current_block=item.round.reveal_block,
    )
    assert not common["signed"] and not record["signed"]
    assert not record["chain_submission_authorized"]
    assert record["object"]["execution_evidence_sha256"] == digest(first)


def test_endpoint_incumbent_cli_owns_finality_provider(paired_setup, tmp_path, monkeypatch):
    from umi import competition_chain, competition_cli
    from umi.competition_chain import RegistrationCapture

    from .test_open_competition import snapshot

    item = paired_setup.dispatch.feed.item
    config = paired_setup.dispatch.config.chain
    for name, document in (
        ("policy", item.policy),
        ("job", make_job(paired_setup)),
        ("chain", config),
    ):
        (tmp_path / f"{name}.json").write_bytes(canonical_json_bytes(document))
    calls = []

    class Provider:
        def __init__(self, supplied_config, supplied_policy):
            assert supplied_config == config and supplied_policy == item.policy

        async def start(self):
            calls.append("start")

        async def wait_ready(self):
            calls.append("ready")

        async def collect(self):
            calls.append("collect")
            snap = snapshot(item.request.issued_block)
            return RegistrationCapture(
                snapshot=snap,
                provenance={
                    "schema": "umi-competition-registration-provenance/1",
                    "evidence_class": "verifier_attested_finality",
                    "offline_finality_proof": False,
                    "chain_submission_authorized": False,
                    "snapshot_sha256": digest(snap),
                    "block": snap.block,
                    "block_hash": snap.block_hash,
                    "state_root": "0x" + "aa" * 32,
                    "evidence_sha256": "bb" * 32,
                },
            )

        async def aclose(self):
            calls.append("close")

    monkeypatch.setattr(competition_chain, "FinalizedRegistrationProvider", Provider)
    argv = [
        "--policy",
        str(tmp_path / "policy.json"),
        "run-endpoint-incumbent",
        "--job",
        str(tmp_path / "job.json"),
        "--chain-config",
        str(tmp_path / "chain.json"),
        "--archive",
        str(paired_setup.archive),
        "--videos",
        str(paired_setup.videos),
        "--state",
        str(tmp_path / "cli-incumbent"),
    ]
    args = competition_cli._parser().parse_args(argv)
    value = competition_cli.execute(args)
    assert len(value["steps"]) == 3
    assert calls == ["start", "ready", *(["collect"] * 6), "close"]
    calls.clear()
    assert competition_cli.execute(args) == value and calls == []
