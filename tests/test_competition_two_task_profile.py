import hashlib
import re
from fractions import Fraction
from pathlib import Path

import pytest

from umi import scoring
from umi.competition_scoring import score_single_reference
from umi.open_competition import (
    CompetitionPolicy,
    EvaluationCase,
    EvaluationSuite,
    SingleReferenceEvaluationCase,
    aggregate_quality,
    digest,
    has_case_coverage,
    project_weights,
    qualifies_for_promotion,
    replay_evaluation,
    validate_suite_profile,
)
from umi.protocol import canonical_json_bytes
from umi.scoring import score_cer, score_wer

from .test_open_competition import (
    attested,
    bundle_at,
    result_for,
    round_for,
    snapshot,
    submission,
    suite_for,
    wallet,
)
from .test_open_competition import policy as policy


def launch_policy(legacy):
    body = legacy.model_dump(mode="json", by_alias=True)
    body["schema"] = "umi-open-competition-policy/2"
    body["maximum_inference_ms"] = 120_000
    return CompetitionPolicy.model_validate_json(canonical_json_bytes(body))


def launch_suite(policy):
    return EvaluationSuite(
        schema="umi-competition-suite/2",
        policy_sha256=digest(policy),
        cases=tuple(
            SingleReferenceEvaluationCase(
                case_id=f"{i:064x}",
                video_sha256=f"{100 + i:064x}",
                stratum=stratum,
                references=("hello",),
            )
            for i, stratum in enumerate(("fingerspelling", "continuous", "continuous"), 1)
        ),
    )


def test_legacy_serialization_and_reference_contract_remain_strict(policy):
    raw = canonical_json_bytes(policy)
    assert canonical_json_bytes(CompetitionPolicy.model_validate_json(raw)) == raw
    assert "stratum_weights" not in policy.model_dump()
    suite = suite_for(policy)
    raw_suite = canonical_json_bytes(suite)
    assert canonical_json_bytes(EvaluationSuite.model_validate_json(raw_suite)) == raw_suite
    for score in (score_cer, score_wer):
        with pytest.raises(ValueError, match="3 and 5"):
            score("hello", ("hello",))
    with pytest.raises(ValueError):
        EvaluationCase(
            case_id="01" * 32, video_sha256="02" * 32, stratum="continuous", references=("hello",)
        )


def test_legacy_bootstrap_scoring_source_pin_is_preserved():
    root = Path(__file__).resolve().parents[1]
    recipe = (root / "deploy/bootstrap-validator/Dockerfile").read_text()
    expected = re.search(r'"scoring_source_sha256": "([0-9a-f]{64})"', recipe)
    assert expected is not None
    assert hashlib.sha256(Path(scoring.__file__).read_bytes()).hexdigest() == expected.group(1)


def test_profile_is_signed_and_suite_versions_cannot_be_mixed(policy):
    launch = launch_policy(policy)
    assert digest(launch) != digest(policy)
    suite = launch_suite(launch)
    assert canonical_json_bytes(
        EvaluationSuite.model_validate_json(canonical_json_bytes(suite))
    ) == (canonical_json_bytes(suite))
    validate_suite_profile(suite, launch)
    for p, s in ((policy, suite), (launch, suite_for(policy))):
        with pytest.raises(ValueError, match=r"profile|binding"):
            validate_suite_profile(s, p)
    body = suite.model_dump(mode="json", by_alias=True)
    body["schema"] = "umi-competition-suite/1"
    with pytest.raises(ValueError, match="three to five"):
        EvaluationSuite.model_validate_json(canonical_json_bytes(body))
    body = suite_for(policy).model_dump(mode="json", by_alias=True)
    body["schema"] = "umi-competition-suite/2"
    with pytest.raises(ValueError, match="one reference"):
        EvaluationSuite.model_validate_json(canonical_json_bytes(body))


def test_exact_task_weights_and_single_reference_metrics(policy):
    launch = launch_policy(policy)
    assert launch.stratum_weights == {
        "fingerspelling": Fraction(3, 13),
        "continuous": Fraction(10, 13),
    }
    assert aggregate_quality(
        {"fingerspelling": Fraction(1), "continuous": Fraction(0)}, launch
    ) == (Fraction(3, 13))
    assert aggregate_quality(
        {"fingerspelling": Fraction(0), "continuous": Fraction(1)}, launch
    ) == (Fraction(10, 13))
    assert score_single_reference("cer", "abc", "abcd") == Fraction(3, 4)
    assert score_single_reference("wer", "hello", "hello world") == Fraction(1, 2)
    assert score_single_reference("wer", "HELLO!", "hello") == 1
    with pytest.raises(ValueError):
        score_single_reference("wer", "hello", "!!!")
    with pytest.raises(ValueError):
        score_single_reference("bogus", "hello", "hello")
    with pytest.raises(ValueError, match="strata"):
        aggregate_quality({"fingerspelling": Fraction(1), "continuous": Fraction(1)})


def test_coverage_and_no_regression_apply_to_both_launch_tasks(policy):
    launch = launch_policy(policy)
    suite = launch_suite(launch)
    assert has_case_coverage(suite.cases, launch)
    assert not has_case_coverage(suite.cases[1:], launch)
    assert not has_case_coverage(suite_for(policy).cases, launch)
    assert not has_case_coverage(
        suite.cases, launch.model_copy(update={"minimum_cases_per_stratum": 2})
    )
    candidate = {"fingerspelling": Fraction(1, 2), "continuous": Fraction(1)}
    incumbent = {"fingerspelling": Fraction(1), "continuous": Fraction(0)}
    assert aggregate_quality(candidate, launch) > aggregate_quality(incumbent, launch)
    assert not qualifies_for_promotion(candidate, incumbent, launch)


def test_launch_replay_timeout_and_exact_70_30_projection(policy, tmp_path):
    launch = launch_policy(policy)
    endpoint = submission(launch)
    bundle = bundle_at(tmp_path / "model")
    model = submission(launch, bundle=bundle, name="Bob")
    suite = launch_suite(launch)
    round_ = round_for(launch, suite, (endpoint, model))
    evaluations = tuple((s, result_for(s, round_, suite)) for s in (endpoint, model))
    candidate, incumbent = replay_evaluation(
        evaluations[0][1], endpoint, round_, suite, launch, current_block=150
    )
    assert aggregate_quality(candidate, launch) == 1
    assert aggregate_quality(incumbent, launch) == 0
    assert qualifies_for_promotion(candidate, incumbent, launch)
    row = project_weights(
        policy=launch,
        round_=round_,
        suite=suite,
        evaluations=evaluations,
        snapshot=snapshot(150),
        current_block=150,
        promoted_model_sha256=digest(bundle),
        promoted_hotkey=wallet("Bob").hotkey.ss58_address,
    )
    assert sum(row.weights) == 65535
    assert [Fraction(a.numerator) / Fraction(a.denominator) for a in row.allocations] == [
        Fraction(7, 10),
        Fraction(3, 10),
    ]
    assert row.chain_submission_authorized is False

    result = evaluations[0][1].result
    late_candidate = result.model_copy(
        update={
            "candidate": tuple(
                o.model_copy(update={"elapsed_ms": 120_001}) for o in result.candidate
            )
        }
    )
    candidate, _ = replay_evaluation(
        attested(late_candidate), endpoint, round_, suite, launch, current_block=150
    )
    assert aggregate_quality(candidate, launch) == 0
    late_incumbent = result.model_copy(
        update={
            "incumbent": tuple(
                o.model_copy(update={"elapsed_ms": 120_001}) for o in result.incumbent
            )
        }
    )
    with pytest.raises(ValueError, match="incumbent execution failed"):
        replay_evaluation(
            attested(late_incumbent), endpoint, round_, suite, launch, current_block=150
        )
