from __future__ import annotations

import asyncio
import hashlib
import sqlite3

import pytest

from tests.test_competition_chain import chain_config as chain_config_fixture
from tests.test_competition_runner import runtime as runtime_fixture
from tests.test_open_competition import (
    bundle_at,
    round_for,
    submission,
    wallet,
)
from tests.test_open_competition import (
    policy as policy_fixture,
)
from umi import competition_execution as execution
from umi.competition_artifacts import preserve_bundle
from umi.competition_evidence import (
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    replay_independent_evaluation,
    sign_evaluator_run,
)
from umi.competition_runner import OfflineCaseExecution, validate_case_execution
from umi.open_competition import (
    AttestedResult,
    CaseOutput,
    EvaluationCase,
    EvaluationSuite,
    SingleReferenceEvaluationCase,
    aggregate_quality,
    digest,
    sign_object,
)
from umi.protocol import canonical_json_bytes

policy = policy_fixture
runtime = runtime_fixture
chain_config = chain_config_fixture


@pytest.fixture(params=("umi-open-competition-policy/1", "umi-open-competition-policy/2"))
def setup(policy, runtime, tmp_path, monkeypatch, request):
    policy = policy.model_copy(
        update={"schema_": request.param, "evaluation_runtime_sha256": digest(runtime)}
    )
    two_task = request.param == "umi-open-competition-policy/2"
    strata = (
        ("fingerspelling", "continuous", "continuous")
        if two_task
        else ("fingerspelling", "short_utterance", "continuous")
    )
    case_type = SingleReferenceEvaluationCase if two_task else EvaluationCase
    incumbent = bundle_at(tmp_path / "incumbent")
    candidate = bundle_at(tmp_path / "candidate", "candidate", digest(incumbent))
    signed = submission(policy, bundle=candidate)
    videos = tmp_path / "videos"
    videos.mkdir()
    cases = []
    for i, stratum in enumerate(strata):
        video = f"inert-video-{i}".encode()
        video_sha = hashlib.sha256(video).hexdigest()
        (videos / (video_sha + ".mp4")).write_bytes(video)
        cases.append(
            case_type(
                case_id=f"{i:064x}",
                video_sha256=video_sha,
                stratum=stratum,
                references=("hello",) if two_task else ("hello", "hi", "greetings"),
            )
        )
    suite = EvaluationSuite(
        schema="umi-competition-suite/2" if two_task else "umi-competition-suite/1",
        policy_sha256=digest(policy),
        cases=tuple(cases),
    )
    round_ = round_for(policy, suite, (signed,), incumbent=digest(incumbent))
    job = execution.ModelEvaluationJob(
        schema="umi-model-evaluation-job/1",
        round=round_,
        submission=signed,
        incumbent=incumbent,
        runtime=runtime,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        cases=tuple(
            execution.ExecutionCase(
                case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum
            )
            for c in suite.cases
        ),
    )
    archive = tmp_path / "archive"
    preserve_bundle(incumbent, tmp_path / "incumbent", archive, policy)
    preserve_bundle(candidate, tmp_path / "candidate", archive, policy)
    calls = []

    async def preflight(*args):
        calls.append("runtime-preflight")

    async def run(**kwargs):
        calls.append(kwargs)
        model = kwargs["bundle"]
        hypothesis = "hello" if digest(model) == digest(candidate) else ""
        return OfflineCaseExecution(
            schema="umi-offline-case-execution/1",
            model_sha256=digest(model),
            runtime_sha256=digest(runtime),
            video_sha256=kwargs["video_sha256"],
            output=CaseOutput(
                case_id=kwargs["case_id"], status="ok", hypothesis=hypothesis, elapsed_ms=10
            ),
            stdout_hex=(hypothesis + "\n").encode().hex(),
            reason="ok",
            returncode=0,
        )

    monkeypatch.setattr(execution, "verify_runtime", preflight)
    monkeypatch.setattr(execution, "execute_offline_case", run)
    return policy, job, suite, archive, videos, calls


def boundary(block=125):
    return execution.ExecutionBoundary(
        source="verifier_attested_finality",
        block=block,
        block_hash="0x" + f"{block:064x}",
        state_root="0x" + "cc" * 32,
        snapshot_sha256="dd" * 32,
        evidence_sha256="ee" * 32,
    )


async def run_job(setup, tmp_path, *, name="journal", job=None, source=None, **limits):
    policy, original, _suite, archive, videos, _ = setup
    journal = execution.ExecutionJournal(tmp_path / name, policy, **limits)

    async def capture():
        return boundary()

    evidence = await execution.run_model_evaluation(
        job=job or original,
        policy=policy,
        archive=archive,
        videos=videos,
        journal=journal,
        boundary_provider=source or capture,
    )
    return evidence, journal


@pytest.mark.asyncio
async def test_paired_execution_retains_outputs_and_replays_into_independent_evidence(
    setup, tmp_path
):
    policy, job, suite, _, _, calls = setup
    first, journal = await run_job(setup, tmp_path)
    second, _ = await run_job(
        setup,
        tmp_path,
        name="independent-journal",
        job=job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address}),
    )
    assert len(first.steps) == 6
    assert journal.status(execution.execution_key(job))["status"] == "complete"
    common = execution.common_execution_result((first, second), suite, policy, current_block=150)
    assert (
        execution.common_execution_result((second, first), suite, policy, current_block=150)
        == common
    )
    runs = []
    for item, name in ((first, "Charlie"), (second, "Dave")):
        run = execution.run_record_from_execution(item, common, suite, policy, current_block=150)
        assert run.execution_evidence_sha256 == digest(item)
        runs.append(
            SignedEvaluatorRunRecord(run=run, signature=sign_evaluator_run(run, wallet(name)))
        )
    evidence = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=AttestedResult(
            result=common,
            signatures=tuple(sign_object(common, wallet(n)) for n in ("Charlie", "Dave")),
        ),
        evaluator_runs=tuple(runs),
    )
    quality, incumbent = replay_independent_evaluation(
        evidence, job.submission, job.round, suite, policy, current_block=150
    )
    assert aggregate_quality(quality, policy) == 1
    assert aggregate_quality(incumbent, policy) == 0
    # No references or wallet is passed to the execution adapter or retained job.
    for call in calls:
        if isinstance(call, dict):
            assert set(call) == {
                "bundle",
                "archive",
                "runtime",
                "policy",
                "case_id",
                "video_sha256",
                "video",
            }
    assert b"references" not in canonical_json_bytes(first)
    assert b"/Users/" not in canonical_json_bytes(first)


@pytest.mark.asyncio
async def test_completed_retry_does_not_touch_provider_or_models_even_when_full(
    setup, tmp_path, monkeypatch
):
    first, _ = await run_job(setup, tmp_path, maximum_jobs=1)

    async def forbidden(*args, **kwargs):
        raise AssertionError("retry performed external work")

    monkeypatch.setattr(execution, "verify_runtime", forbidden)
    second, _ = await run_job(setup, tmp_path, maximum_jobs=1, maximum_bytes=1024, source=forbidden)
    assert canonical_json_bytes(first) == canonical_json_bytes(second)


@pytest.mark.asyncio
async def test_same_identity_cannot_rerun_with_another_assignment(setup, tmp_path):
    _, job, _, _, _, _ = setup
    await run_job(setup, tmp_path)
    with pytest.raises(ValueError, match="different assignment"):
        await run_job(
            setup, tmp_path, job=job.model_copy(update={"cases": tuple(reversed(job.cases))})
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["exception", "cancelled", "late", "rollback", "changed-root"])
async def test_interrupted_jobs_hold_without_rerun_and_keep_prior_steps(setup, tmp_path, mode):
    count = 0

    async def source():
        nonlocal count
        count += 1
        if count < 3:
            return boundary()
        if mode == "cancelled":
            raise asyncio.CancelledError()
        if mode == "exception":
            raise RuntimeError("private provider error")
        if mode == "late":
            return boundary(141)
        if mode == "rollback":
            return boundary(124)
        return boundary().model_copy(update={"state_root": "0x" + "a1" * 32})

    with pytest.raises((ValueError, RuntimeError, asyncio.CancelledError)):
        await run_job(setup, tmp_path, source=source)
    policy, job, _, _, _, calls = setup
    before = len(calls)
    journal = execution.ExecutionJournal(tmp_path / "journal", policy)
    status = journal.status(execution.execution_key(job))
    assert status["status"] == "failed"
    assert status["retained_steps"] == 1
    assert "private" not in str(status)
    with pytest.raises(ValueError, match="automatic rerun refused"):
        await run_job(setup, tmp_path)
    assert len(calls) == before


@pytest.mark.asyncio
async def test_unknown_crash_never_retries_reserved_job(setup, tmp_path):
    policy, job, _, _, _, calls = setup
    journal = execution.ExecutionJournal(tmp_path / "journal", policy)
    journal.reserve(job)
    with pytest.raises(ValueError, match="automatic rerun refused"):
        await run_job(setup, tmp_path)
    assert calls == []
    assert journal.status(execution.execution_key(job))["status"] == "running"


@pytest.mark.asyncio
async def test_corrupted_completed_execution_cannot_be_recovered(setup, tmp_path):
    _, journal = await run_job(setup, tmp_path)
    with sqlite3.connect(journal.path) as db:
        db.execute("DELETE FROM steps WHERE ordinal=0")
    with pytest.raises(ValueError):
        await run_job(setup, tmp_path)


@pytest.mark.asyncio
async def test_journal_policy_and_capacity_are_enforced_before_run(setup, tmp_path):
    policy, job, _, _, _, calls = setup
    with pytest.raises(ValueError, match="capacity exhausted"):
        await run_job(setup, tmp_path, maximum_bytes=1024)
    assert calls == []
    with pytest.raises(ValueError, match="another policy"):
        execution.ExecutionJournal(tmp_path / "journal", policy.model_copy(update={"sequence": 2}))
    await run_job(setup, tmp_path, maximum_jobs=1)
    with pytest.raises(ValueError, match="capacity exhausted"):
        await run_job(
            setup,
            tmp_path,
            maximum_jobs=1,
            job=job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address}),
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["symlink", "hardlink", "fifo", "corrupt", "too-large"])
async def test_bad_video_is_infrastructure_failure_not_miner_fault(setup, tmp_path, mode):
    _, job, _, _, videos, calls = setup
    path = videos / (job.cases[0].video_sha256 + ".mp4")
    if mode in {"symlink", "hardlink", "fifo"}:
        path.unlink()
        import os

        other = tmp_path / "other"
        other.write_bytes(b"video")
        if mode == "symlink":
            path.symlink_to(other)
        elif mode == "hardlink":
            os.link(other, path)
        else:
            os.mkfifo(path)
    else:
        path.write_bytes(b"wrong" if mode == "corrupt" else b"x" * 1025)
    with pytest.raises((OSError, ValueError)):
        await run_job(setup, tmp_path)
    assert not any(isinstance(c, dict) for c in calls)


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["early", "expired", "case-order", "suite", "self", "runtime"])
async def test_assignment_and_reveal_bindings(setup, tmp_path, mode):
    policy, job, suite, _, _, calls = setup
    if mode in {"self", "runtime"}:
        changed = (
            job.model_copy(update={"evaluator_hotkey": job.submission.submission.hotkey})
            if mode == "self"
            else job.model_copy(update={"runtime": job.runtime.model_copy(update={"cpus": 3})})
        )
        with pytest.raises(ValueError):
            await run_job(setup, tmp_path, job=changed)
        assert calls == []
        return
    evidence, _ = await run_job(setup, tmp_path)
    current = 149 if mode == "early" else 201 if mode == "expired" else 150
    if mode == "case-order":
        evidence = evidence.model_copy(
            update={"job": job.model_copy(update={"cases": tuple(reversed(job.cases))})}
        )
    if mode == "suite":
        suite = suite.model_copy(update={"cases": tuple(reversed(suite.cases))})
    with pytest.raises(ValueError):
        execution.validate_revealed_execution(evidence, suite, policy, current_block=current)


@pytest.mark.asyncio
async def test_no_quorum_from_duplicate_group_or_disagreeing_observations(setup, tmp_path):
    policy, job, suite, _, _, _ = setup
    first, _ = await run_job(setup, tmp_path)
    with pytest.raises(ValueError, match="insufficient"):
        execution.common_execution_result((first,), suite, policy, current_block=150)
    with pytest.raises(ValueError, match="duplicate"):
        execution.common_execution_result((first, first), suite, policy, current_block=150)
    second, _ = await run_job(
        setup,
        tmp_path,
        name="dave",
        job=job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address}),
    )
    step = second.steps[0]
    bad = step.execution.model_copy(
        update={
            "stdout_hex": b"different".hex(),
            "output": step.execution.output.model_copy(update={"hypothesis": "different"}),
        }
    )
    second = second.model_copy(
        update={"steps": (step.model_copy(update={"execution": bad}), *second.steps[1:])}
    )
    with pytest.raises(ValueError, match="disagree"):
        execution.common_execution_result((first, second), suite, policy, current_block=150)


@pytest.mark.parametrize("reason", ["deadline", "process_failed", "invalid_utf8", "output_limit"])
def test_failure_classification_cannot_lie_about_raw_stdout(policy, reason):
    record = OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256="aa" * 32,
        runtime_sha256=policy.evaluation_runtime_sha256,
        video_sha256="bb" * 32,
        output=CaseOutput(case_id="cc" * 32, status="miner_failure", hypothesis="", elapsed_ms=1),
        stdout_hex=b"hello".hex(),
        reason=reason,
        returncode=0,
    )
    with pytest.raises(ValueError):
        validate_case_execution(record, policy)


@pytest.mark.parametrize("reason", ["deadline", "output_limit", "invalid_utf8", "process_failed"])
def test_reserved_runtime_exits_are_never_miner_failures(policy, reason):
    record = OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256="aa" * 32,
        runtime_sha256=policy.evaluation_runtime_sha256,
        video_sha256="bb" * 32,
        output=CaseOutput(
            case_id="cc" * 32, status="miner_failure", hypothesis="", elapsed_ms=1000
        ),
        stdout_hex="",
        reason=reason,
        returncode=125,
    )
    with pytest.raises(ValueError, match="runtime failures"):
        validate_case_execution(record, policy)


@pytest.mark.asyncio
async def test_completed_stdout_is_retained_even_if_post_run_finality_fails(setup, tmp_path):
    count = 0

    async def source():
        nonlocal count
        count += 1
        if count == 2:
            raise RuntimeError("observer unavailable")
        return boundary()

    with pytest.raises(RuntimeError):
        await run_job(setup, tmp_path, source=source)
    policy, job, *_ = setup
    journal = execution.ExecutionJournal(tmp_path / "journal", policy)
    status = journal.status(execution.execution_key(job))
    assert status["retained_steps"] == 0
    assert status["pending_observations"] == 1
    with sqlite3.connect(journal.path) as db:
        raw = db.execute("SELECT body FROM pending_steps").fetchone()[0]
    pending = execution.PendingExecutionStep.model_validate_json(raw)
    assert bytes.fromhex(pending.execution.stdout_hex) == b"hello\n"
    assert pending.execution.output.hypothesis == "hello"
    assert status["status"] == "failed"


@pytest.mark.asyncio
@pytest.mark.parametrize("stale_at", [1, 2, 3, 4])
async def test_temporary_stale_finality_waits_without_repeating_model_runs(
    setup, tmp_path, monkeypatch, stale_at
):
    monkeypatch.setattr(execution, "_FRESH_BOUNDARY_POLL_SECONDS", 0)
    calls = 0

    async def source():
        nonlocal calls
        calls += 1
        if stale_at <= calls < stale_at + 3:
            raise execution.OwnedFinalityStale("owned finalized head is stale")
        return boundary()

    evidence, journal = await run_job(setup, tmp_path, source=source)
    assert len(evidence.steps) == 6
    assert len([call for call in setup[-1] if isinstance(call, dict)]) == 6
    assert calls == 15  # Two successful boundaries per invocation plus three waits.
    assert journal.status(execution.execution_key(setup[1]))["status"] == "complete"


@pytest.mark.asyncio
async def test_stale_finality_wait_is_bounded_and_retains_pending_output(
    setup, tmp_path, monkeypatch
):
    monkeypatch.setattr(execution, "_FRESH_BOUNDARY_WAIT_SECONDS", 0.02)
    monkeypatch.setattr(execution, "_FRESH_BOUNDARY_POLL_SECONDS", 0)
    calls = 0

    async def source():
        nonlocal calls
        calls += 1
        assert calls < 10_000, "deadline failed to stop stale provider retries"
        if calls > 1:
            raise execution.OwnedFinalityStale("owned finalized head is stale")
        return boundary()

    with pytest.raises(asyncio.TimeoutError):
        await run_job(setup, tmp_path, source=source)
    journal = execution.ExecutionJournal(tmp_path / "journal", setup[0])
    status = journal.status(execution.execution_key(setup[1]))
    assert status["status"] == "failed"
    assert status["retained_steps"] == 0
    assert status["pending_observations"] == 1
    assert len([call for call in setup[-1] if isinstance(call, dict)]) == 1
    with pytest.raises(ValueError, match="automatic rerun refused"):
        await run_job(setup, tmp_path, source=source)


@pytest.mark.asyncio
async def test_boundary_cancellation_survives_simultaneous_provider_completion():
    async def source():
        task.cancel()
        return boundary()

    task = asyncio.create_task(execution._fresh_execution_boundary(source))
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel", [False, True])
async def test_boundary_cleans_up_pending_provider_on_timeout_or_cancellation(monkeypatch, cancel):
    monkeypatch.setattr(execution, "_FRESH_BOUNDARY_WAIT_SECONDS", 0.02)
    started = asyncio.Event()
    stopped = asyncio.Event()

    async def source():
        started.set()
        try:
            await asyncio.Future()
        finally:
            stopped.set()

    task = asyncio.create_task(execution._fresh_execution_boundary(source))
    await started.wait()
    if cancel:
        task.cancel()
    with pytest.raises(asyncio.CancelledError if cancel else asyncio.TimeoutError):
        await task
    assert stopped.is_set()


@pytest.mark.asyncio
@pytest.mark.parametrize("recovered_block", [124, 141])
async def test_freshness_recovery_still_rejects_rollback_or_closed_round(
    setup, tmp_path, monkeypatch, recovered_block
):
    monkeypatch.setattr(execution, "_FRESH_BOUNDARY_POLL_SECONDS", 0)
    calls = 0

    async def source():
        nonlocal calls
        calls += 1
        if calls == 1:
            return boundary()
        if calls == 2:
            raise execution.OwnedFinalityStale("owned finalized head is stale")
        return boundary(recovered_block)

    with pytest.raises(ValueError):
        await run_job(setup, tmp_path, source=source)
    assert len([call for call in setup[-1] if isinstance(call, dict)]) == 1


@pytest.mark.asyncio
async def test_json_escaped_stdout_fits_reserved_capacity(setup, tmp_path):
    policy, job, *_ = setup
    policy = policy.model_copy(update={"maximum_output_bytes": 4096})
    # Rebind the local job to this explicit test policy and re-sign the submission.
    sub = job.submission.submission.model_copy(update={"policy_sha256": digest(policy)})
    signed = job.submission.model_copy(
        update={"submission": sub, "signature": sign_object(sub, wallet("Alice"))}
    )
    job = job.model_copy(
        update={
            "submission": signed,
            "round": job.round.model_copy(
                update={"policy_sha256": digest(policy), "roster": (digest(sub),)}
            ),
        }
    )
    journal = execution.ExecutionJournal(tmp_path / "escaped-journal", policy)
    journal.reserve(job)
    observed = OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256=sub.model_revision,
        runtime_sha256=policy.evaluation_runtime_sha256,
        video_sha256=job.cases[0].video_sha256,
        output=CaseOutput(
            case_id=job.cases[0].case_id, status="ok", hypothesis="\x01" * 4096, elapsed_ms=10
        ),
        stdout_hex=(b"\x01" * 4096).hex(),
        reason="ok",
        returncode=0,
    )
    pending = execution.PendingExecutionStep(
        role="candidate", started=boundary(), execution=observed
    )
    assert len(canonical_json_bytes(pending)) > 24 * 1024
    journal.observe(job, pending)
    journal.append(
        job,
        execution.ExecutionStep(
            role="candidate", started=boundary(), finished=boundary(), execution=observed
        ),
    )
    assert journal.status(execution.execution_key(job))["retained_steps"] == 1


def test_execution_cli_owns_provider_lifecycle_and_complete_retry_has_no_external_work(
    setup, chain_config, tmp_path, monkeypatch
):
    from tests.test_open_competition import snapshot
    from umi import competition_chain, competition_cli
    from umi.competition_chain import RegistrationCapture

    policy, job, _, archive, videos, _ = setup
    config = chain_config.model_copy(update={"policy_sha256": digest(policy)})
    for name, item in (("policy", policy), ("job", job), ("chain", config)):
        (tmp_path / (name + ".json")).write_bytes(canonical_json_bytes(item))
    calls = []

    class Provider:
        def __init__(self, supplied_config, supplied_policy):
            assert supplied_config == config and supplied_policy == policy

        async def start(self):
            calls.append("start")

        async def wait_ready(self):
            calls.append("ready")

        async def collect(self):
            calls.append("collect")
            snap = snapshot(125)
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
    args = competition_cli._parser().parse_args(
        [
            "--policy",
            str(tmp_path / "policy.json"),
            "run-model-evaluation",
            "--job",
            str(tmp_path / "job.json"),
            "--chain-config",
            str(tmp_path / "chain.json"),
            "--archive",
            str(archive),
            "--videos",
            str(videos),
            "--state",
            str(tmp_path / "cli-journal"),
        ]
    )
    value = competition_cli.execute(args)
    assert value["chain_submission_authorized"] is False
    assert len(value["steps"]) == 6
    assert calls == ["start", "ready", *(["collect"] * 12), "close"]
    calls.clear()
    assert competition_cli.execute(args) == value
    assert calls == []

    def forbidden(*args, **kwargs):
        raise AssertionError("must not construct provider for completed retry")

    monkeypatch.setattr(competition_chain, "FinalizedRegistrationProvider", forbidden)
    assert competition_cli.execute(args) == value


@pytest.mark.asyncio
async def test_local_execution_cli_proposal_never_signs_or_activates(setup, tmp_path):
    from umi import competition_cli

    policy, job, suite, *_ = setup
    first, _ = await run_job(setup, tmp_path)
    second, _ = await run_job(
        setup,
        tmp_path,
        name="dave",
        job=job.model_copy(update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address}),
    )
    inputs = competition_cli.ExecutionInputs(executions=(first, second))
    for name, item in (
        ("policy", policy),
        ("suite", suite),
        ("inputs", inputs),
        ("execution", first),
    ):
        (tmp_path / (name + ".json")).write_bytes(canonical_json_bytes(item))
    args = competition_cli._parser().parse_args(
        [
            "--policy",
            str(tmp_path / "policy.json"),
            "propose-execution-result",
            "--inputs",
            str(tmp_path / "inputs.json"),
            "--suite",
            str(tmp_path / "suite.json"),
            "--current-block",
            "150",
        ]
    )
    value = competition_cli.execute(args)
    assert value["signed"] is False and value["chain_submission_authorized"] is False
    (tmp_path / "result.json").write_bytes(canonical_json_bytes(value["object"]))
    args = competition_cli._parser().parse_args(
        [
            "--policy",
            str(tmp_path / "policy.json"),
            "prepare-execution-record",
            "--execution",
            str(tmp_path / "execution.json"),
            "--result",
            str(tmp_path / "result.json"),
            "--suite",
            str(tmp_path / "suite.json"),
            "--current-block",
            "150",
        ]
    )
    record = competition_cli.execute(args)
    assert record["signed"] is False and record["chain_submission_authorized"] is False
    assert record["object"]["execution_evidence_sha256"] == digest(first)


@pytest.mark.asyncio
async def test_only_atomic_reservation_winner_can_start_provider(setup, tmp_path):
    policy, job, _, archive, videos, _ = setup
    entered, release = asyncio.Event(), asyncio.Event()
    starts = []

    async def prepare():
        starts.append(True)
        entered.set()
        await release.wait()

    async def source():
        return boundary()

    journal = execution.ExecutionJournal(tmp_path / "concurrent", policy)
    kwargs = dict(
        job=job,
        policy=policy,
        archive=archive,
        videos=videos,
        journal=journal,
        boundary_provider=source,
        prepare_boundaries=prepare,
    )
    first = asyncio.create_task(execution.run_model_evaluation(**kwargs))
    await entered.wait()
    with pytest.raises(ValueError, match="automatic rerun refused"):
        await execution.run_model_evaluation(**kwargs)
    assert starts == [True]
    release.set()
    completed = await first
    assert await execution.run_model_evaluation(**kwargs) == completed
    assert starts == [True]
