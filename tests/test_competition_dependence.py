import hashlib
import json
from fractions import Fraction

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cli import _parser, execute
from umi.competition_dependence_execution import (
    DependenceCalibrationExecution,
    prepare_dependence_calibration,
    run_dependence_calibration,
)
from umi.competition_evidence import (
    EvaluatorRunRecord,
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    sign_evaluator_run,
)
from umi.competition_execution import ExecutionBoundary
from umi.competition_runner import OfflineCaseExecution, OfflineCpuRuntime, validate_case_execution
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore
from umi.open_competition import (
    AttestedDependenceCalibration,
    AttestedResult,
    BurnDestination,
    CaseOutput,
    CompetitionPolicy,
    DependenceCalibration,
    DependenceEvaluationCase,
    EvaluationResult,
    EvaluationSuite,
    Evaluator,
    MatchedSwapPair,
    Registration,
    RegistrationSnapshot,
    _quality,
    continuous_dependence_report,
    digest,
    has_case_coverage,
    replay_evaluation,
    sign_object,
    validate_dependence_calibration,
    validate_suite_profile,
)
from umi.protocol import canonical_json_bytes

from .test_open_competition import bundle_at, round_for, submission, wallet


def dependence_policy() -> CompetitionPolicy:
    return CompetitionPolicy(
        schema="umi-open-competition-policy/4",
        network="finney",
        netuid=78,
        sequence=5,
        predecessor_sha256="01" * 32,
        valid_from_block=100,
        valid_through_block=1000,
        endpoint_reward_bps=7000,
        model_reward_bps=3000,
        minimum_score_bps=1000,
        promotion_margin_bps=100,
        minimum_cases_per_stratum=3,
        maximum_inference_ms=120_000,
        maximum_output_bytes=4096,
        maximum_bundle_bytes=10_000,
        maximum_bundle_files=20,
        minimum_submission_interval_blocks=5,
        maximum_submission_lifetime_blocks=900,
        maximum_snapshot_age_blocks=10,
        maximum_uids=256,
        evaluators=(
            Evaluator(hotkey=wallet("Charlie").hotkey.ss58_address, control_group="operator"),
        ),
        required_evaluator_groups=1,
        contribution_terms_sha256="a1" * 32,
        accepted_model_licenses=("CC-BY-SA-4.0",),
        evaluation_runtime_sha256="a2" * 32,
        unallocated_model_burn=BurnDestination(uid=0, hotkey=wallet("Bob").hotkey.ss58_address),
        minimum_continuous_observed_margin_bps=31,
        continuous_dependence_lower_bound_floor_bps=0,
        minimum_continuous_dependence_pairs=12,
        continuous_dependence_duration_bins=6,
        maximum_counterfactual_duration_delta_ms=500,
        continuous_dependence_bootstrap_replicates=512,
        continuous_dependence_confidence_bps=9500,
        positive_control_model_sha256="a3" * 32,
        minimum_positive_control_dependence_bps=5000,
    )


def dependence_suite(policy: CompetitionPolicy) -> EvaluationSuite:
    fingerspelling = [
        DependenceEvaluationCase(
            case_id=f"{index:064x}",
            video_sha256=f"{1000 + index:064x}",
            stratum="fingerspelling",
            references=(f"letters {index}",),
            duration_ms=1000 + index,
            role="scored",
        )
        for index in range(1, 4)
    ]
    scored = [
        DependenceEvaluationCase(
            case_id=f"{100 + index:064x}",
            video_sha256=f"{2000 + index:064x}",
            stratum="continuous",
            references=(f"token{index}",),
            duration_ms=2000 + (index // 2) * 100 + index % 2,
            role="scored",
        )
        for index in range(12)
    ]
    controls = []
    pairs = []
    for index, anchor in enumerate(scored):
        source = scored[index + 1 if index % 2 == 0 else index - 1]
        control = DependenceEvaluationCase(
            case_id=f"{300 + index:064x}",
            video_sha256=source.video_sha256,
            stratum="continuous",
            references=anchor.references,
            duration_ms=source.duration_ms,
            role="matched_swap",
        )
        controls.append(control)
        pairs.append(
            MatchedSwapPair(
                case_id=anchor.case_id,
                control_case_id=control.case_id,
                source_case_id=source.case_id,
            )
        )
    return EvaluationSuite(
        schema="umi-competition-suite/3",
        policy_sha256=digest(policy),
        cases=tuple([*fingerspelling, *scored, *controls]),
        matched_swap_pairs=tuple(sorted(pairs, key=lambda pair: pair.case_id)),
    )


def outputs_for(suite: EvaluationSuite, *, blind: bool) -> tuple[CaseOutput, ...]:
    by_id = {case.case_id: case for case in suite.cases}
    source_by_control = {
        pair.control_case_id: by_id[pair.source_case_id] for pair in suite.matched_swap_pairs or ()
    }
    outputs = []
    for case in suite.cases:
        if blind:
            hypothesis = "guess alpha" if case.role == "scored" else "guess beta"
        elif case.role == "matched_swap":
            hypothesis = source_by_control[case.case_id].references[0]
        else:
            hypothesis = case.references[0]
        outputs.append(
            CaseOutput(case_id=case.case_id, status="ok", hypothesis=hypothesis, elapsed_ms=10)
        )
    return tuple(outputs)


def calibration_preparation(policy: CompetitionPolicy, suite: EvaluationSuite):
    outputs = outputs_for(suite, blind=False)
    boundary = ExecutionBoundary(
        source="verifier_attested_finality",
        block=200,
        block_hash="0x" + "a5" * 32,
        state_root="0x" + "a6" * 32,
        snapshot_sha256="a7" * 32,
        evidence_sha256="a8" * 32,
    )
    execution = DependenceCalibrationExecution(
        schema="umi-dependence-calibration-execution/1",
        policy_sha256=digest(policy),
        suite_sha256=digest(suite),
        runtime_sha256=policy.evaluation_runtime_sha256,
        model_sha256=policy.positive_control_model_sha256,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        started=boundary,
        finished=boundary,
        executions=tuple(
            OfflineCaseExecution(
                schema="umi-offline-case-execution/1",
                model_sha256=policy.positive_control_model_sha256,
                runtime_sha256=policy.evaluation_runtime_sha256,
                video_sha256=case.video_sha256,
                output=output,
                stdout_hex=output.hypothesis.encode().hex(),
                reason="ok",
                returncode=0,
            )
            for case, output in zip(suite.cases, outputs, strict=True)
        ),
    )
    return prepare_dependence_calibration(execution, suite, policy)


def test_matched_swap_gate_uses_score_loss_not_output_change():
    policy = dependence_policy()
    suite = dependence_suite(policy)
    validate_suite_profile(suite, policy)

    dependent = outputs_for(suite, blind=False)
    report = continuous_dependence_report(dependent, suite, policy)
    assert report.complete is True
    assert report.correct_score == 1
    assert report.swapped_score == 0
    assert report.bootstrap_lower_bound == 1
    assert _quality(dependent, suite, policy) == {
        "fingerspelling": Fraction(1),
        "continuous": Fraction(1),
    }

    changing_but_blind = outputs_for(suite, blind=True)
    report = continuous_dependence_report(changing_but_blind, suite, policy)
    assert report.byte_identical_fraction == 0
    assert report.observed_margin == 0
    assert report.bootstrap_lower_bound == 0
    assert _quality(changing_but_blind, suite, policy) == {
        "fingerspelling": Fraction(0),
        "continuous": Fraction(0),
    }


def _replace_output(outputs, case_id, **changes):
    return tuple(
        CaseOutput.model_validate(output.model_dump() | changes)
        if output.case_id == case_id
        else output
        for output in outputs
    )


def _replay_outputs(policy, suite, candidate, incumbent):
    signed = submission(policy)
    round_ = round_for(policy, suite, (signed,))
    result = EvaluationResult(
        schema="umi-competition-result/1",
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        model_revision=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        runtime_sha256=round_.runtime_sha256,
        finished_block=round_.evaluation_close_block,
        candidate=candidate,
        incumbent=incumbent,
    )
    attested = AttestedResult(
        result=result,
        signatures=(sign_object(result, wallet("Charlie")),),
    )
    return replay_evaluation(
        attested, signed, round_, suite, policy, current_block=round_.reveal_block
    )


@pytest.mark.parametrize("role", ["candidate", "incumbent"])
def test_missing_control_evidence_cannot_be_omitted_from_scoring(role):
    policy = dependence_policy()
    suite = dependence_suite(policy)
    complete = outputs_for(suite, blind=False)
    control = suite.matched_swap_pairs[0].control_case_id
    missing = tuple(output for output in complete if output.case_id != control)

    with pytest.raises(ValueError, match="complete suite"):
        continuous_dependence_report(missing, suite, policy)
    with pytest.raises(ValueError, match="complete suite"):
        _quality(missing, suite, policy, incumbent=role == "incumbent")
    with pytest.raises(ValueError, match="paired outputs"):
        _replay_outputs(
            policy,
            suite,
            missing if role == "candidate" else complete,
            missing if role == "incumbent" else complete,
        )


@pytest.mark.parametrize("failure", ["miner_failure", "late", "oversized"])
def test_failed_control_is_incomplete_even_when_other_pairs_prove_dependence(failure):
    policy = dependence_policy()
    suite = dependence_suite(policy)
    complete = outputs_for(suite, blind=False)
    control = suite.matched_swap_pairs[0].control_case_id
    changes = {
        "miner_failure": {"status": "miner_failure", "hypothesis": ""},
        "late": {"elapsed_ms": policy.maximum_inference_ms + 1},
        # Below the CaseOutput character bound, above the policy's UTF-8 byte bound.
        "oversized": {"hypothesis": "é" * (policy.maximum_output_bytes // 2 + 1)},
    }[failure]
    failed = _replace_output(complete, control, **changes)
    report = continuous_dependence_report(failed, suite, policy)
    assert report.complete is False
    assert report.observed_margin > Fraction(policy.minimum_continuous_observed_margin_bps, 10_000)
    candidate, incumbent = _replay_outputs(policy, suite, failed, complete)
    assert candidate == {stratum: Fraction(0) for stratum in policy.stratum_weights}
    assert incumbent == {stratum: Fraction(1) for stratum in policy.stratum_weights}
    with pytest.raises(ValueError, match="incumbent execution failed"):
        _replay_outputs(policy, suite, complete, failed)


@pytest.mark.parametrize("bound", ["time", "utf8_bytes"])
def test_control_resource_boundaries_are_inclusive(bound):
    policy = dependence_policy()
    suite = dependence_suite(policy)
    outputs = outputs_for(suite, blind=False)
    control = suite.matched_swap_pairs[0].control_case_id
    changes = (
        {"elapsed_ms": policy.maximum_inference_ms}
        if bound == "time"
        else {"hypothesis": "é" * (policy.maximum_output_bytes // 2)}
    )
    outputs = _replace_output(outputs, control, **changes)
    report = continuous_dependence_report(outputs, suite, policy)
    assert report.complete is True
    assert report.observed_margin == 1
    candidate, incumbent = _replay_outputs(policy, suite, outputs, outputs)
    assert candidate == incumbent == {stratum: Fraction(1) for stratum in policy.stratum_weights}


@pytest.mark.parametrize("role", ["candidate", "incumbent"])
def test_control_infrastructure_failure_voids_evaluation_instead_of_scoring_zero(role):
    policy = dependence_policy()
    suite = dependence_suite(policy)
    complete = outputs_for(suite, blind=False)
    failed = _replace_output(
        complete,
        suite.matched_swap_pairs[0].control_case_id,
        status="infrastructure_failure",
        hypothesis="",
    )
    with pytest.raises(ValueError, match="infrastructure failure voids evaluation"):
        continuous_dependence_report(failed, suite, policy)
    with pytest.raises(ValueError, match="infrastructure failure voids evaluation"):
        _replay_outputs(
            policy,
            suite,
            failed if role == "candidate" else complete,
            failed if role == "incumbent" else complete,
        )


@pytest.mark.parametrize("failure", ["missing", "late", "oversized"])
def test_positive_control_preparation_rejects_incomplete_retained_control(failure):
    policy = dependence_policy()
    suite = dependence_suite(policy)
    execution = calibration_preparation(policy, suite).execution
    control = suite.matched_swap_pairs[0].control_case_id
    if failure == "missing":
        records = tuple(item for item in execution.executions if item.output.case_id != control)
        message = "omits suite cases"
    else:
        records = []
        for item in execution.executions:
            if item.output.case_id == control:
                item = item.model_copy(
                    update={
                        "output": CaseOutput(
                            case_id=control,
                            status="miner_failure",
                            hypothesis="",
                            elapsed_ms=policy.maximum_inference_ms + 1 if failure == "late" else 10,
                        ),
                        "reason": "deadline" if failure == "late" else "output_limit",
                        "stdout_hex": ""
                        if failure == "late"
                        else (b"x" * (policy.maximum_output_bytes + 1)).hex(),
                        "returncode": None,
                    }
                )
                validate_case_execution(item, policy)
            records.append(item)
        records = tuple(records)
        message = "positive control did not prove"
    changed = execution.model_copy(update={"executions": records})
    with pytest.raises(ValueError, match=message):
        prepare_dependence_calibration(changed, suite, policy)


def test_observed_effect_and_confidence_floor_are_independent_gates():
    policy = dependence_policy()
    suite = dependence_suite(policy)
    mostly_blind = list(outputs_for(suite, blind=True))
    first_pair = (suite.matched_swap_pairs or ())[0]
    by_id = {case.case_id: case for case in suite.cases}
    output_index = {output.case_id: index for index, output in enumerate(mostly_blind)}
    anchor_index = output_index[first_pair.case_id]
    control_index = output_index[first_pair.control_case_id]
    mostly_blind[anchor_index] = mostly_blind[anchor_index].model_copy(
        update={"hypothesis": by_id[first_pair.case_id].references[0]}
    )
    mostly_blind[control_index] = mostly_blind[control_index].model_copy(
        update={"hypothesis": "unrelated"}
    )

    report = continuous_dependence_report(tuple(mostly_blind), suite, policy)
    assert report.observed_margin > Fraction(policy.minimum_continuous_observed_margin_bps, 10_000)
    assert report.bootstrap_lower_bound == 0
    assert _quality(tuple(mostly_blind), suite, policy) == {
        "fingerspelling": Fraction(0),
        "continuous": Fraction(0),
    }


def test_matched_swap_profile_rejects_cross_bin_or_malformed_controls():
    policy = dependence_policy()
    suite = dependence_suite(policy)
    pairs = list(suite.matched_swap_pairs or ())
    pairs[0] = pairs[0].model_copy(update={"source_case_id": pairs[-1].source_case_id})
    changed = suite.model_copy(update={"matched_swap_pairs": tuple(pairs)})
    with pytest.raises(ValueError, match=r"permute|duration bin"):
        validate_suite_profile(changed, policy)

    cases = list(suite.cases)
    cases[-1] = cases[-1].model_copy(update={"references": ("wrong reference",)})
    changed = suite.model_copy(update={"cases": tuple(cases)})
    with pytest.raises(ValueError, match="preserve reference"):
        validate_suite_profile(changed, policy)

    controls_without_scored_continuous = tuple(
        case for case in suite.cases if case.stratum != "continuous" or case.role == "matched_swap"
    )
    assert not has_case_coverage(controls_without_scored_continuous, policy)


def test_policy_v4_fields_are_explicit_and_legacy_bytes_stay_unchanged():
    policy = dependence_policy()
    body = json.loads(canonical_json_bytes(policy))
    for name in (
        "minimum_continuous_observed_margin_bps",
        "continuous_dependence_lower_bound_floor_bps",
        "minimum_continuous_dependence_pairs",
        "continuous_dependence_duration_bins",
        "maximum_counterfactual_duration_delta_ms",
        "continuous_dependence_bootstrap_replicates",
        "continuous_dependence_confidence_bps",
        "positive_control_model_sha256",
        "minimum_positive_control_dependence_bps",
    ):
        changed = dict(body)
        changed.pop(name)
        with pytest.raises(ValueError, match="dependence controls"):
            CompetitionPolicy.model_validate_json(canonical_json_bytes(changed))

    changed = body | {"continuous_dependence_lower_bound_floor_bps": 31}
    with pytest.raises(ValueError, match="strictly positive lower bound"):
        CompetitionPolicy.model_validate_json(canonical_json_bytes(changed))

    legacy = body | {"schema": "umi-open-competition-policy/3"}
    for name in tuple(body):
        if "dependence" in name or name == "maximum_counterfactual_duration_delta_ms":
            legacy.pop(name, None)
    parsed = CompetitionPolicy.model_validate_json(canonical_json_bytes(legacy))
    assert canonical_json_bytes(parsed) == canonical_json_bytes(legacy)


def test_positive_control_is_quorum_signed_replayed_and_thresholded():
    policy = dependence_policy()
    suite = dependence_suite(policy)
    calibration = DependenceCalibration(
        schema="umi-continuous-dependence-calibration/1",
        policy_sha256=digest(policy),
        suite_sha256=digest(suite),
        runtime_sha256=policy.evaluation_runtime_sha256,
        model_sha256=policy.positive_control_model_sha256,
        execution_evidence_sha256="a4" * 32,
        evaluated_block=200,
        outputs=outputs_for(suite, blind=False),
    )
    attested = AttestedDependenceCalibration(
        calibration=calibration,
        signatures=(sign_object(calibration, wallet("Charlie")),),
    )
    report = validate_dependence_calibration(attested, suite, policy, latest_block=500)
    assert report.bootstrap_lower_bound == 1
    with pytest.raises(ValueError, match="outside its usable window"):
        validate_dependence_calibration(attested, suite, policy, latest_block=199)

    blind = calibration.model_copy(update={"outputs": outputs_for(suite, blind=True)})
    blind = AttestedDependenceCalibration(
        calibration=blind,
        signatures=(sign_object(blind, wallet("Charlie")),),
    )
    with pytest.raises(ValueError, match="did not prove"):
        validate_dependence_calibration(blind, suite, policy, latest_block=500)

    wrong_model = calibration.model_copy(update={"model_sha256": "ff" * 32})
    wrong_model = AttestedDependenceCalibration(
        calibration=wrong_model,
        signatures=(sign_object(wrong_model, wallet("Charlie")),),
    )
    with pytest.raises(ValueError, match="binding mismatch"):
        validate_dependence_calibration(wrong_model, suite, policy, latest_block=500)


@pytest.mark.asyncio
async def test_positive_control_runner_retains_boundaries_and_exact_case_receipts(
    tmp_path, monkeypatch
):
    bundle = bundle_at(tmp_path / "model", marker="positive-control")
    runtime = OfflineCpuRuntime(
        schema="umi-offline-cpu-runtime/1",
        image="ghcr.io/example/evaluator@sha256:" + "ab" * 32,
        cpus=2,
        memory_bytes=1024**3,
        scratch_bytes=16 * 1024**2,
        pids_limit=64,
        maximum_video_bytes=1024,
    )
    policy = dependence_policy().model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "positive_control_model_sha256": digest(bundle),
        }
    )
    policy = CompetitionPolicy.model_validate_json(canonical_json_bytes(policy))
    suite = dependence_suite(policy)
    outputs = {output.case_id: output for output in outputs_for(suite, blind=False)}
    cases = {case.case_id: case for case in suite.cases}
    calls = []

    monkeypatch.setattr("umi.competition_dependence_execution.read_case_video", lambda *_: b"video")

    async def execute(**kwargs):
        calls.append(kwargs["case_id"])
        output = outputs[kwargs["case_id"]]
        return OfflineCaseExecution(
            schema="umi-offline-case-execution/1",
            model_sha256=digest(bundle),
            runtime_sha256=digest(runtime),
            video_sha256=cases[kwargs["case_id"]].video_sha256,
            output=output,
            stdout_hex=output.hypothesis.encode().hex(),
            reason="ok",
            returncode=0,
        )

    monkeypatch.setattr("umi.competition_dependence_execution.execute_offline_case", execute)
    boundaries = iter(
        ExecutionBoundary(
            source="verifier_attested_finality",
            block=200 + offset,
            block_hash="0x" + f"{0xA5 + offset:02x}" * 32,
            state_root="0x" + f"{0xB5 + offset:02x}" * 32,
            snapshot_sha256=f"{0xC5 + offset:02x}" * 32,
            evidence_sha256=f"{0xD5 + offset:02x}" * 32,
        )
        for offset in range(2)
    )

    async def boundary():
        return next(boundaries)

    preparation = await run_dependence_calibration(
        suite=suite,
        policy=policy,
        bundle=bundle,
        runtime=runtime,
        evaluator_hotkey=wallet("Charlie").hotkey.ss58_address,
        archive=tmp_path / "archive",
        videos=tmp_path / "videos",
        boundary_provider=boundary,
    )
    assert calls == [case.case_id for case in suite.cases]
    assert preparation.execution.started.block == 200
    assert preparation.execution.finished.block == 201
    assert preparation.calibration.evaluated_block == 201
    assert preparation.calibration.execution_evidence_sha256 == digest(preparation.execution)
    assert preparation.calibration.outputs == tuple(outputs[case.case_id] for case in suite.cases)


def test_calibration_cli_validates_signs_and_assembles_exact_body(tmp_path, monkeypatch):
    policy = dependence_policy()
    suite = dependence_suite(policy)
    preparation = calibration_preparation(policy, suite)
    calibration = preparation.calibration

    def put(name, value):
        path = tmp_path / name
        path.write_bytes(canonical_json_bytes(value))
        return str(path)

    policy_path = put("policy.json", policy)
    suite_path = put("suite.json", suite)
    preparation_path = put("calibration-preparation.json", preparation)
    monkeypatch.setattr("bittensor.Wallet", lambda **_: wallet("Charlie"))
    signed = execute(
        _parser().parse_args(
            [
                "--policy",
                policy_path,
                "sign-dependence-calibration",
                "--preparation",
                preparation_path,
                "--suite",
                suite_path,
                "--latest-block",
                "500",
                "--wallet-name",
                "validator",
                "--hotkey-name",
                "default",
                "--wallet-path",
                str(tmp_path / "wallets"),
            ]
        )
    )
    attested = AttestedDependenceCalibration.model_validate_json(canonical_json_bytes(signed))
    assert attested.calibration == calibration
    assert attested.signatures[0].hotkey == wallet("Charlie").hotkey.ss58_address

    assembled = execute(
        _parser().parse_args(
            [
                "--policy",
                policy_path,
                "assemble-dependence-calibration",
                "--attestation",
                put("attestation.json", attested),
                "--suite",
                suite_path,
                "--latest-block",
                "500",
            ]
        )
    )
    assert (
        AttestedDependenceCalibration.model_validate_json(canonical_json_bytes(assembled))
        == attested
    )

    tampered = preparation.model_copy(
        update={
            "calibration": preparation.calibration.model_copy(
                update={"evaluated_block": preparation.calibration.evaluated_block + 1}
            )
        }
    )
    tampered_path = put("tampered-preparation.json", tampered)
    with pytest.raises(ValueError, match="differs from retained execution evidence"):
        execute(
            _parser().parse_args(
                [
                    "--policy",
                    policy_path,
                    "sign-dependence-calibration",
                    "--preparation",
                    tampered_path,
                    "--suite",
                    suite_path,
                    "--latest-block",
                    "500",
                    "--wallet-name",
                    "validator",
                    "--hotkey-name",
                    "default",
                    "--wallet-path",
                    str(tmp_path / "wallets"),
                ]
            )
        )

    changed_body = calibration.model_copy(update={"evaluated_block": 201})
    changed = AttestedDependenceCalibration(
        calibration=changed_body,
        signatures=(sign_object(changed_body, wallet("Charlie")),),
    )
    with pytest.raises(ValueError, match="do not cover the same body"):
        execute(
            _parser().parse_args(
                [
                    "--policy",
                    policy_path,
                    "assemble-dependence-calibration",
                    "--attestation",
                    put("first-attestation.json", attested),
                    "--attestation",
                    put("changed-attestation.json", changed),
                    "--suite",
                    suite_path,
                    "--latest-block",
                    "500",
                ]
            )
        )

    monkeypatch.setattr("bittensor.Wallet", lambda **_: wallet("Eve"))
    with pytest.raises(ValueError, match="not a nominated evaluator"):
        execute(
            _parser().parse_args(
                [
                    "--policy",
                    policy_path,
                    "sign-dependence-calibration",
                    "--preparation",
                    preparation_path,
                    "--suite",
                    suite_path,
                    "--latest-block",
                    "500",
                    "--wallet-name",
                    "validator",
                    "--hotkey-name",
                    "default",
                    "--wallet-path",
                    str(tmp_path / "wallets"),
                ]
            )
        )


def test_dependence_settlement_requires_and_retains_exact_positive_control(tmp_path):
    policy = dependence_policy()
    baseline_source = tmp_path / "baseline"
    archive = tmp_path / "archive"
    baseline = bundle_at(baseline_source)
    preserve_bundle(baseline, baseline_source, archive, policy)
    store = CompetitionStore(tmp_path / "state", policy)
    store.initialize_baseline(baseline, archive)

    signed = submission(policy)
    burn = policy.unallocated_model_burn
    assert burn is not None

    def chain_snapshot(block: int) -> RegistrationSnapshot:
        return RegistrationSnapshot(
            network="finney",
            netuid=78,
            block=block,
            block_hash="0x" + f"{block:064x}",
            registrations=(
                Registration(uid=0, hotkey=burn.hotkey),
                Registration(uid=6, hotkey=wallet("Alice").hotkey.ss58_address),
            ),
            burn_destination=burn,
        )

    store.admit(signed, chain_snapshot(110), 110)
    suite = dependence_suite(policy)
    round_ = round_for(policy, suite, (signed,), digest(baseline))
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    store.fix_evidence_cutoff(round_, schedule, observed_block=120)
    store.close_round(round_, current_block=120)

    candidate = outputs_for(suite, blind=False)
    incumbent = tuple(
        CaseOutput(case_id=case.case_id, status="ok", hypothesis="", elapsed_ms=10)
        for case in suite.cases
    )
    result = EvaluationResult(
        schema="umi-competition-result/1",
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        model_revision=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        runtime_sha256=round_.runtime_sha256,
        finished_block=130,
        candidate=candidate,
        incumbent=incumbent,
    )
    evaluator = wallet("Charlie")
    attested = AttestedResult(result=result, signatures=(sign_object(result, evaluator),))
    run = EvaluatorRunRecord(
        schema="umi-competition-evaluator-run/1",
        evaluator_hotkey=evaluator.hotkey.ss58_address,
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        common_result_sha256=digest(result),
        suite_sha256=digest(suite),
        model_revision=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        runtime_sha256=round_.runtime_sha256,
        started_block=121,
        finished_block=130,
        candidate=candidate,
        incumbent=incumbent,
        execution_evidence_sha256=hashlib.sha256(b"dependence-e2e-run").hexdigest(),
    )
    evidence = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=attested,
        evaluator_runs=(
            SignedEvaluatorRunRecord(run=run, signature=sign_evaluator_run(run, evaluator)),
        ),
    )
    store.record_independent_evaluation(
        signed=signed,
        evidence=evidence,
        round_=round_,
        suite=suite,
        observed_block=150,
    )

    calibration_body = DependenceCalibration(
        schema="umi-continuous-dependence-calibration/1",
        policy_sha256=digest(policy),
        suite_sha256=digest(suite),
        runtime_sha256=policy.evaluation_runtime_sha256,
        model_sha256=policy.positive_control_model_sha256,
        execution_evidence_sha256="a4" * 32,
        evaluated_block=140,
        outputs=candidate,
    )
    calibration = AttestedDependenceCalibration(
        calibration=calibration_body,
        signatures=(sign_object(calibration_body, evaluator),),
    )
    request = {
        "round_": round_,
        "suite": suite,
        "evidence": ((signed, evidence),),
        "snapshot": chain_snapshot(160),
        "current_block": 160,
    }
    with pytest.raises(ValueError, match="lacks its positive control"):
        store.settle(**request)

    settlement = store.settle(**request, dependence_calibration=calibration)
    assert settlement["schema"] == "umi-competition-settlement/3"
    assert settlement["dependence_calibration"] == calibration.model_dump(
        mode="json", by_alias=True
    )
    allocations = {
        item["uid"]: Fraction(int(item["numerator"]), int(item["denominator"]))
        for item in settlement["projection"]["allocations"]
    }
    assert allocations == {0: Fraction(3, 10), 6: Fraction(7, 10)}
    assert store.settle(**request, dependence_calibration=calibration) == settlement

    changed = calibration_body.model_copy(update={"evaluated_block": 139})
    changed = AttestedDependenceCalibration(
        calibration=changed,
        signatures=(sign_object(changed, evaluator),),
    )
    with pytest.raises(ValueError, match="different inputs"):
        store.settle(**request, dependence_calibration=changed)
