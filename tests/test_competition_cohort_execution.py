"""Recoverable artifact replay uses raw evidence, not agreement alone."""

from fractions import Fraction

import pytest

from umi.competition_cohort_evaluation import RecoverableRoundParticipant
from umi.competition_cohort_execution import (
    RecoverableExecutionEvidence,
    RecoverableExecutionJob,
    recoverable_execution_observations,
    recoverable_run_record_from_execution,
)
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_outcomes import (
    RecoverableExecutedEvaluation,
    replay_recoverable_executed_evaluation,
)
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
    admit_recovery_participant,
)
from umi.competition_evidence import IndependentEvaluationEvidence
from umi.competition_execution import ExecutionCase, ExecutionStep, ModelExecutionEvidence
from umi.competition_runner import OfflineCaseExecution
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_evidence as receipt_fixtures
from . import test_open_competition as policy_fixtures
from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_evidence import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_evidence import run_record, signed_run
from .test_competition_execution import boundary
from .test_competition_runner import runtime as runtime
from .test_open_competition import attested, bundle_at, result_for, submission, wallet

base_policy = policy_fixtures.policy
receipt_scenario = receipt_fixtures.scenario


@pytest.fixture
def policy(base_policy, runtime):
    return base_policy.model_copy(update={"evaluation_runtime_sha256": digest(runtime)})


def setup_scenario(original, tmp_path, runtime, *, mode="paired_model"):
    s = original.copy()
    incumbent = bundle_at(tmp_path / "incumbent")
    bundle = (
        bundle_at(tmp_path / "candidate", "candidate", digest(incumbent))
        if mode == "paired_model"
        else None
    )
    s["signed"] = submission(s["policy"], bundle=bundle)
    body = s["consent"].consent.model_copy(
        update={"submission_sha256": digest(s["signed"].submission)}
    )
    s["consent"] = SignedCohortParticipationConsent(
        consent=body, signature=sign_object(body, wallet("Alice"))
    )
    admission = admit_recovery_participant(
        s["signed"],
        s["consent"],
        s["intake_history"],
        s["policy"],
        s["admission_snapshot"],
        expected_tip_sha256=tip(s["intake_history"]),
        current_block=210,
    )
    s["admission"] = AttestedCohortParticipantAdmission(
        admission=admission, signatures=signatures(admission)
    )
    s["round_"] = s["round_"].model_copy(
        update={
            "incumbent_model_sha256": digest(incumbent),
            "participants": (
                RecoverableRoundParticipant(
                    submission_sha256=digest(s["signed"].submission),
                    admission_sha256=digest(admission),
                ),
            ),
        }
    )
    common = result_for(s["signed"], s["round_"], s["suite"]).result.model_copy(
        update={"finished_block": 1600}
    )
    s["attested"] = attested(common)
    view = verify_cohort_history(
        s["history"], s["policy"], expected_tip_sha256=tip(s["history"]), current_block=5000
    )
    artifacts = []
    for name in ("Charlie", "Dave"):
        job = RecoverableExecutionJob(
            schema="umi-recoverable-execution-job/1",
            mode=mode,
            round=s["round_"],
            submission=s["signed"],
            incumbent=incumbent,
            runtime=runtime,
            preparation_closure_sha256=digest(view.closure("preparation")),
            evaluator_hotkey=wallet(name).hotkey.ss58_address,
            cases=tuple(
                ExecutionCase(case_id=c.case_id, video_sha256=c.video_sha256, stratum=c.stratum)
                for c in s["suite"].cases
            ),
        )
        steps = []
        for index, case in enumerate(job.cases):
            for role in ("candidate", "incumbent") if mode == "paired_model" else ("incumbent",):
                output = getattr(common, role)[index]
                steps.append(
                    ExecutionStep(
                        role=role,
                        started=boundary(1500 + len(steps)),
                        finished=boundary(1501 + len(steps)),
                        execution=OfflineCaseExecution(
                            schema="umi-offline-case-execution/1",
                            model_sha256=s["signed"].submission.model_revision
                            if role == "candidate"
                            else digest(incumbent),
                            runtime_sha256=digest(runtime),
                            video_sha256=case.video_sha256,
                            output=output,
                            stdout_hex=(output.hypothesis + "\n").encode().hex(),
                            reason="ok",
                            returncode=0,
                        ),
                    )
                )
        artifacts.append(
            RecoverableExecutionEvidence(
                schema="umi-recoverable-execution-evidence/1", job=job, steps=tuple(steps)
            )
        )
    s["artifacts"] = tuple(artifacts)
    return s


@pytest.fixture
def scenario(receipt_scenario, tmp_path, runtime):
    return setup_scenario(receipt_scenario, tmp_path, runtime)


def bundle_evidence(s, artifacts=None):
    artifacts = s["artifacts"] if artifacts is None else artifacts
    runs = []
    for artifact, name in zip(artifacts, ("Charlie", "Dave"), strict=True):
        body = run_record(
            name,
            s["policy"],
            s["signed"],
            s["round_"],
            s["suite"],
            s["attested"],
            elapsed_ms=5,
            started_block=artifact.steps[0].started.block,
            finished_block=artifact.steps[-1].finished.block,
        ).model_copy(
            update={
                "execution_evidence_sha256": digest(artifact),
                "candidate": tuple(
                    x.execution.output for x in artifact.steps if x.role == "candidate"
                ),
                "incumbent": tuple(
                    x.execution.output for x in artifact.steps if x.role == "incumbent"
                ),
            }
        )
        runs.append(signed_run(body, name))
    return RecoverableExecutedEvaluation(
        schema="umi-recoverable-executed-evaluation/1",
        receipts=IndependentEvaluationEvidence(
            schema="umi-competition-independent-evaluation/1",
            attested_result=s["attested"],
            evaluator_runs=tuple(runs),
        ),
        executions=artifacts,
    )


def replay(s, evidence=None, **updates):
    kwargs = {
        k: s[k]
        for k in (
            "signed",
            "round_",
            "suite",
            "policy",
            "consent",
            "admission",
            "admission_snapshot",
            "history",
        )
    }
    kwargs.update(current_block=5000, expected_tip_sha256=tip(s["history"]))
    kwargs.update(updates)
    return replay_recoverable_executed_evaluation(evidence or bundle_evidence(s), **kwargs)


def observe(s, artifact=None, **updates):
    kwargs = {
        k: s[k]
        for k in ("suite", "policy", "consent", "admission", "admission_snapshot", "history")
    }
    kwargs.update(current_block=5000, expected_tip_sha256=tip(s["history"]))
    kwargs.update(updates)
    return recoverable_execution_observations(artifact or s["artifacts"][0], **kwargs)


def test_complete_artifacts_replay_after_old_expiry_without_rewriting_evidence(scenario):
    evidence = bundle_evidence(scenario)
    raw = canonical_json_bytes(evidence)
    for block in (5000, 10**6, 2**53 - 1):
        candidate, incumbent = replay(scenario, evidence, current_block=block)
        assert set(candidate.values()) == {Fraction(1)}
        assert set(incumbent.values()) == {Fraction(0)}
    assert canonical_json_bytes(evidence) == raw
    # Legacy consumers cannot silently reinterpret the new authority.
    with pytest.raises(ValueError):
        ModelExecutionEvidence.model_validate_json(canonical_json_bytes(evidence.executions[0]))


@pytest.mark.parametrize(
    "damage",
    [
        "stdout",
        "runtime",
        "video",
        "model",
        "role",
        "missing_step",
        "extra_step",
        "case_order",
        "preparation",
        "incumbent_bundle",
        "runtime_config",
        "evaluator",
        "early",
        "late",
        "rollback",
        "same_block_hash",
        "same_block_root",
        "same_block_snapshot",
        "historical_boundary",
        "runtime_failure",
        "failure_as_zero",
        "authorization",
    ],
)
def test_resigned_receipts_cannot_hide_corrupt_execution(scenario, damage):
    artifact = scenario["artifacts"][0]
    steps = list(artifact.steps)
    step = steps[0]
    if damage in ("stdout", "runtime", "video", "model", "runtime_failure", "failure_as_zero"):
        changes = {
            "stdout": {"stdout_hex": b"forged".hex()},
            "runtime": {"runtime_sha256": "f1" * 32},
            "video": {"video_sha256": "f1" * 32},
            "model": {"model_sha256": "f1" * 32},
            "runtime_failure": {"reason": "process_failed", "returncode": 125},
            "failure_as_zero": {"reason": "process_failed", "returncode": 1},
        }[damage]
        steps[0] = step.model_copy(update={"execution": step.execution.model_copy(update=changes)})
    elif damage == "role":
        steps[0] = step.model_copy(update={"role": "incumbent"})
    elif damage == "missing_step":
        steps = steps[:-2]
    elif damage == "extra_step":
        steps.extend(steps[-2:])
    elif damage == "case_order":
        job = artifact.job.model_copy(update={"cases": tuple(reversed(artifact.job.cases))})
        artifact = artifact.model_copy(update={"job": job})
    elif damage in ("preparation", "incumbent_bundle", "runtime_config", "evaluator"):
        job = artifact.job
        changes = {
            "preparation": {"preparation_closure_sha256": "f1" * 32},
            "incumbent_bundle": {
                "incumbent": job.incumbent.model_copy(update={"parent_baseline_sha256": "f1" * 32})
            },
            "runtime_config": {"runtime": job.runtime.model_copy(update={"cpus": 3})},
            "evaluator": {"evaluator_hotkey": wallet("Alice").hotkey.ss58_address},
        }[damage]
        artifact = artifact.model_copy(update={"job": job.model_copy(update=changes)})
    elif damage in ("early", "late", "rollback"):
        if damage == "early":
            steps[0] = step.model_copy(update={"started": boundary(390)})
        elif damage == "late":
            steps[-1] = steps[-1].model_copy(update={"finished": boundary(1681)})
        else:
            steps[1] = steps[1].model_copy(update={"started": boundary(1499)})
    elif damage.startswith("same_block"):
        field = {
            "same_block_hash": "block_hash",
            "same_block_root": "state_root",
            "same_block_snapshot": "snapshot_sha256",
        }[damage]
        value = ("0x" if field != "snapshot_sha256" else "") + "ff" * 32
        steps[1] = steps[1].model_copy(
            update={"started": steps[1].started.model_copy(update={field: value})}
        )
    elif damage == "historical_boundary":
        steps[0] = step.model_copy(
            update={
                "started": step.started.model_copy(update={"source": "verified_finalized_ancestry"})
            }
        )
    elif damage == "authorization":
        artifact = artifact.model_copy(update={"chain_submission_authorized": True})
    artifact = artifact.model_copy(update={"steps": tuple(steps)})
    with pytest.raises(ValueError):
        observe(scenario, artifact)
    with pytest.raises(ValueError):
        # Even newly valid signatures over the changed artifact cannot bypass replay.
        replay(scenario, bundle_evidence(scenario, (artifact, scenario["artifacts"][1])))


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "duplicate",
        "extra",
        "digest",
        "receipt_elapsed",
        "receipt_finish",
        "another_round",
    ],
)
def test_complete_artifact_set_and_exact_receipt_bindings(scenario, damage):
    evidence = bundle_evidence(scenario)
    items = list(evidence.executions)
    if damage == "missing":
        items.pop()
    elif damage == "duplicate":
        items[1] = items[0]
    elif damage == "extra":
        items.append(items[0])
    elif damage == "another_round":
        job = items[0].job
        items[0] = items[0].model_copy(
            update={
                "job": job.model_copy(
                    update={"round": job.round.model_copy(update={"prepared_at_block": 351})}
                )
            }
        )
    else:
        runs = list(evidence.receipts.evaluator_runs)
        body = runs[0].run
        if damage == "digest":
            body = body.model_copy(update={"execution_evidence_sha256": "f1" * 32})
        elif damage == "receipt_finish":
            body = body.model_copy(update={"finished_block": body.finished_block + 1})
        else:
            body = body.model_copy(
                update={
                    "candidate": tuple(
                        o.model_copy(update={"elapsed_ms": 4}) for o in body.candidate
                    )
                }
            )
        runs[0] = signed_run(body, "Charlie")
        evidence = evidence.model_copy(
            update={
                "receipts": evidence.receipts.model_copy(update={"evaluator_runs": tuple(runs)})
            }
        )
    with pytest.raises(ValueError):
        replay(scenario, evidence.model_copy(update={"executions": tuple(items)}))


def test_no_reveal_no_current_history_and_revocation_all_hold_replay(scenario):
    h = scenario["history"]
    pending = h.model_copy(update={"transitions": h.transitions[:-1]})
    with pytest.raises(ValueError, match="closure"):
        observe(scenario, history=pending, expected_tip_sha256=tip(pending))
    with pytest.raises(ValueError, match="current tip"):
        replay(scenario, expected_tip_sha256=tip(pending))
    with pytest.raises(ValueError, match="ahead"):
        observe(scenario, current_block=1700)
    revoked = transition(h, scenario["policy"], "revoke", 1800)
    with pytest.raises(ValueError, match="revoked"):
        replay(scenario, history=revoked, expected_tip_sha256=tip(revoked))


def test_failed_incumbent_is_retained_but_cannot_be_scored(scenario):
    artifacts = []
    for artifact in scenario["artifacts"]:
        steps = list(artifact.steps)
        step = steps[1]
        failed = step.execution.output.model_copy(
            update={"status": "miner_failure", "hypothesis": ""}
        )
        steps[1] = step.model_copy(
            update={
                "execution": step.execution.model_copy(
                    update={
                        "reason": "process_failed",
                        "returncode": 1,
                        "stdout_hex": "",
                        "output": failed,
                    }
                )
            }
        )
        artifacts.append(artifact.model_copy(update={"steps": tuple(steps)}))
    assert observe(scenario, artifacts[0]).incumbent[0].status == "miner_failure"
    common = scenario["attested"].result
    outputs = list(common.incumbent)
    outputs[0] = artifacts[0].steps[1].execution.output
    s = {**scenario, "attested": attested(common.model_copy(update={"incumbent": tuple(outputs)}))}
    with pytest.raises(ValueError):
        replay(s, bundle_evidence(s, tuple(artifacts)))


def test_native_receipt_preparation_matches_retained_execution_and_replays(scenario):
    s = scenario
    evidence = bundle_evidence(s)
    runs = []
    for artifact, name, expected in zip(
        s["artifacts"], ("Charlie", "Dave"), evidence.receipts.evaluator_runs, strict=True
    ):
        body = recoverable_run_record_from_execution(
            artifact,
            s["attested"].result,
            s["suite"],
            s["policy"],
            s["consent"],
            s["admission"],
            s["admission_snapshot"],
            s["history"],
            expected_tip_sha256=tip(s["history"]),
            current_block=5000,
        )
        assert body == expected.run
        runs.append(signed_run(body, name))
    assert (
        replay(
            s,
            evidence.model_copy(
                update={
                    "receipts": evidence.receipts.model_copy(update={"evaluator_runs": tuple(runs)})
                }
            ),
        )[0]["continuous"]
        == 1
    )


def test_common_result_cannot_understate_retained_case_time(scenario):
    s = scenario
    common = s["attested"].result
    changed = common.model_copy(
        update={
            "candidate": tuple(o.model_copy(update={"elapsed_ms": 4}) for o in common.candidate)
        }
    )
    s = {**s, "attested": attested(changed)}
    with pytest.raises(ValueError, match="disagrees with retained execution"):
        replay(s)


def test_attested_candidate_process_failure_scores_zero_only_with_valid_raw_evidence(scenario):
    artifacts = []
    for artifact in scenario["artifacts"]:
        steps = []
        for step in artifact.steps:
            if step.role == "candidate":
                step = step.model_copy(
                    update={
                        "execution": step.execution.model_copy(
                            update={
                                "reason": "process_failed",
                                "returncode": 1,
                                "stdout_hex": "",
                                "output": step.execution.output.model_copy(
                                    update={
                                        "status": "miner_failure",
                                        "hypothesis": "",
                                    }
                                ),
                            }
                        )
                    }
                )
            steps.append(step)
        artifacts.append(artifact.model_copy(update={"steps": tuple(steps)}))
    common = scenario["attested"].result.model_copy(
        update={
            "candidate": tuple(
                x.execution.output for x in artifacts[0].steps if x.role == "candidate"
            )
        }
    )
    s = {**scenario, "attested": attested(common)}
    quality, _ = replay(s, bundle_evidence(s, tuple(artifacts)))
    assert set(quality.values()) == {Fraction(0)}


def test_endpoint_incumbent_observations_do_not_invent_endpoint_outputs(
    receipt_scenario, tmp_path, runtime
):
    s = setup_scenario(receipt_scenario, tmp_path, runtime, mode="endpoint_incumbent")
    view = observe(s)
    assert view.candidate == ()
    assert len(view.incumbent) == len(s["suite"].cases)
    with pytest.raises(ValueError):
        replay(s, bundle_evidence(s))
