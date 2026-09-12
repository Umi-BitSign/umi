from __future__ import annotations

import json
from fractions import Fraction
from types import SimpleNamespace

import bittensor as bt
import pytest
from pydantic import ValidationError

from umi.competition_evidence import (
    EvaluatorRunRecord,
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    evaluator_run_digest,
    independent_evidence_digest,
    replay_independent_evaluation,
    sign_evaluator_run,
    verify_evaluator_run,
)
from umi.open_competition import (
    AttestedResult,
    CaseOutput,
    CompetitionPolicy,
    EvaluationCase,
    EvaluationResult,
    EvaluationRound,
    EvaluationSuite,
    Evaluator,
    SignedSubmission,
    Submission,
    authenticate_evaluation,
    digest,
    sign_object,
)
from umi.protocol import canonical_json_bytes


def wallet(name: str):
    key = bt.sp_core.Keypair.create_from_uri(
        "//" + name,
        crypto_type=bt.sp_core.CRYPTO_SR25519,
    )
    return SimpleNamespace(hotkey=key, coldkey=key, coldkeypub=key)


@pytest.fixture
def policy() -> CompetitionPolicy:
    # All values and development identities in this file are inert test fixtures.
    return CompetitionPolicy(
        schema="umi-open-competition-policy/1",
        network="finney",
        netuid=78,
        sequence=7,
        predecessor_sha256=None,
        valid_from_block=100,
        valid_through_block=1000,
        endpoint_reward_bps=7000,
        model_reward_bps=3000,
        minimum_score_bps=1000,
        promotion_margin_bps=100,
        minimum_cases_per_stratum=1,
        maximum_inference_ms=1000,
        maximum_output_bytes=100,
        maximum_bundle_bytes=10_000,
        maximum_bundle_files=20,
        minimum_submission_interval_blocks=5,
        maximum_submission_lifetime_blocks=900,
        maximum_snapshot_age_blocks=10,
        maximum_uids=256,
        evaluators=tuple(
            Evaluator(hotkey=wallet(name).hotkey.ss58_address, control_group=group)
            for name, group in (("Charlie", "c"), ("Dave", "d"), ("Eve", "e"))
        ),
        required_evaluator_groups=2,
        contribution_terms_sha256="a1" * 32,
        accepted_model_licenses=("CC-BY-SA-4.0",),
        evaluation_runtime_sha256="a2" * 32,
    )


def signed_submission(policy: CompetitionPolicy, *, name: str = "Alice") -> SignedSubmission:
    submission = Submission(
        schema="umi-competition-submission/1",
        network="finney",
        netuid=78,
        policy_sha256=digest(policy),
        hotkey=wallet(name).hotkey.ss58_address,
        track="endpoint",
        sequence=1,
        valid_from_block=100,
        valid_through_block=900,
        model_revision="b1" * 32,
        endpoint_url="https://example.com",
        model_bundle=None,
        accepted_terms_sha256=policy.contribution_terms_sha256,
    )
    return SignedSubmission(submission=submission, signature=sign_object(submission, wallet(name)))


def evaluation_suite(policy: CompetitionPolicy) -> EvaluationSuite:
    return EvaluationSuite(
        schema="umi-competition-suite/1",
        policy_sha256=digest(policy),
        cases=tuple(
            EvaluationCase(
                case_id=f"{index:064x}",
                video_sha256=f"{index + 100:064x}",
                stratum=stratum,
                references=("hello", "hi", "greetings"),
            )
            for index, stratum in enumerate(
                ("fingerspelling", "short_utterance", "continuous"),
                1,
            )
        ),
    )


def evaluation_round(
    policy: CompetitionPolicy,
    suite: EvaluationSuite,
    signed: SignedSubmission,
) -> EvaluationRound:
    return EvaluationRound(
        schema="umi-competition-round/1",
        policy_sha256=digest(policy),
        sequence=9,
        suite_sha256=digest(suite),
        incumbent_model_sha256="b2" * 32,
        runtime_sha256=policy.evaluation_runtime_sha256,
        roster=(digest(signed.submission),),
        submission_close_block=120,
        evaluation_close_block=140,
        reveal_block=150,
        valid_through_block=200,
    )


def outputs(
    suite: EvaluationSuite,
    *,
    hypothesis: str,
    elapsed_ms: int,
    status: str = "ok",
) -> tuple[CaseOutput, ...]:
    return tuple(
        CaseOutput(
            case_id=case.case_id,
            status=status,
            hypothesis=hypothesis,
            elapsed_ms=elapsed_ms,
        )
        for case in suite.cases
    )


def attested_result(
    signed: SignedSubmission,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    *,
    candidate: tuple[CaseOutput, ...] | None = None,
    signers: tuple[str, ...] = ("Charlie", "Dave"),
) -> AttestedResult:
    result = EvaluationResult(
        schema="umi-competition-result/1",
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        model_revision=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        runtime_sha256=round_.runtime_sha256,
        finished_block=138,
        candidate=candidate or outputs(suite, hypothesis="hello", elapsed_ms=5),
        incumbent=outputs(suite, hypothesis="", elapsed_ms=5),
    )
    return AttestedResult(
        result=result,
        signatures=tuple(sign_object(result, wallet(name)) for name in signers),
    )


def run_record(
    name: str,
    policy: CompetitionPolicy,
    signed: SignedSubmission,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    common: AttestedResult,
    *,
    elapsed_ms: int,
    started_block: int = 121,
    finished_block: int = 130,
) -> EvaluatorRunRecord:
    return EvaluatorRunRecord(
        schema="umi-competition-evaluator-run/1",
        evaluator_hotkey=wallet(name).hotkey.ss58_address,
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        common_result_sha256=digest(common.result),
        suite_sha256=digest(suite),
        model_revision=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        runtime_sha256=round_.runtime_sha256,
        started_block=started_block,
        finished_block=finished_block,
        candidate=tuple(
            output.model_copy(update={"elapsed_ms": elapsed_ms})
            for output in common.result.candidate
        ),
        incumbent=tuple(
            output.model_copy(update={"elapsed_ms": elapsed_ms + 1})
            for output in common.result.incumbent
        ),
        execution_evidence_sha256=("c1" if name == "Charlie" else "d1") * 32,
    )


def signed_run(run: EvaluatorRunRecord, name: str) -> SignedEvaluatorRunRecord:
    return SignedEvaluatorRunRecord(run=run, signature=sign_evaluator_run(run, wallet(name)))


def fixture_evidence(
    policy: CompetitionPolicy,
) -> tuple[
    IndependentEvaluationEvidence,
    SignedSubmission,
    EvaluationRound,
    EvaluationSuite,
]:
    signed = signed_submission(policy)
    suite = evaluation_suite(policy)
    round_ = evaluation_round(policy, suite, signed)
    common = attested_result(signed, round_, suite)
    runs = (
        signed_run(
            run_record("Charlie", policy, signed, round_, suite, common, elapsed_ms=11),
            "Charlie",
        ),
        signed_run(
            run_record(
                "Dave",
                policy,
                signed,
                round_,
                suite,
                common,
                elapsed_ms=37,
                finished_block=132,
            ),
            "Dave",
        ),
    )
    return (
        IndependentEvaluationEvidence(
            schema="umi-competition-independent-evaluation/1",
            attested_result=common,
            evaluator_runs=runs,
        ),
        signed,
        round_,
        suite,
    )


def replay(
    evidence: IndependentEvaluationEvidence,
    signed: SignedSubmission,
    round_: EvaluationRound,
    suite: EvaluationSuite,
    policy: CompetitionPolicy,
):
    return replay_independent_evaluation(
        evidence,
        signed,
        round_,
        suite,
        policy,
        current_block=150,
    )


def replace_run(
    evidence: IndependentEvaluationEvidence,
    index: int,
    run: EvaluatorRunRecord,
    name: str,
) -> IndependentEvaluationEvidence:
    runs = list(evidence.evaluator_runs)
    runs[index] = signed_run(run, name)
    return evidence.model_copy(update={"evaluator_runs": tuple(runs)})


def test_independent_runs_replay_with_distinct_valid_timings(policy: CompetitionPolicy):
    evidence, signed, round_, suite = fixture_evidence(policy)
    candidate, incumbent = replay(evidence, signed, round_, suite, policy)

    assert candidate == {
        "fingerspelling": Fraction(1),
        "short_utterance": Fraction(1),
        "continuous": Fraction(1),
    }
    assert incumbent == {
        "fingerspelling": Fraction(0),
        "short_utterance": Fraction(0),
        "continuous": Fraction(0),
    }
    assert evidence.evaluator_runs[0].run.candidate[0].elapsed_ms == 11
    assert evidence.evaluator_runs[1].run.candidate[0].elapsed_ms == 37
    assert evaluator_run_digest(evidence.evaluator_runs[0].run) != digest(
        evidence.evaluator_runs[0].run
    )
    encoded = canonical_json_bytes(evidence)
    decoded = IndependentEvaluationEvidence.model_validate_json(encoded, strict=True)
    assert decoded == evidence
    assert independent_evidence_digest(decoded) == independent_evidence_digest(evidence)


def test_signer_must_control_named_evaluator(policy: CompetitionPolicy):
    evidence, _, _, _ = fixture_evidence(policy)
    run = evidence.evaluator_runs[0].run

    with pytest.raises(ValueError, match="does not control"):
        sign_evaluator_run(run, wallet("Dave"))


def test_run_signature_and_domain_are_enforced(policy: CompetitionPolicy):
    evidence, signed, round_, suite = fixture_evidence(policy)
    original = evidence.evaluator_runs[0]
    replacement = "0" if original.signature.signature[-1] != "0" else "1"
    bad_signature = original.signature.model_copy(
        update={"signature": original.signature.signature[:-1] + replacement}
    )
    bad_run = original.model_copy(update={"signature": bad_signature})
    tampered = evidence.model_copy(update={"evaluator_runs": (bad_run, evidence.evaluator_runs[1])})

    with pytest.raises(ValueError, match="invalid evaluator run signature"):
        verify_evaluator_run(bad_run)
    with pytest.raises(ValueError, match="invalid evaluator run signature"):
        replay(tampered, signed, round_, suite, policy)

    # The signature covers evaluator-specific timing and execution evidence too.
    changed_output = original.run.candidate[0].model_copy(update={"elapsed_ms": 12})
    changed_run = original.run.model_copy(
        update={
            "candidate": (changed_output, *original.run.candidate[1:]),
            "execution_evidence_sha256": "ab" * 32,
        }
    )
    unsigned_tamper = original.model_copy(update={"run": changed_run})
    with pytest.raises(ValueError, match="invalid evaluator run signature"):
        verify_evaluator_run(unsigned_tamper)


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("policy_sha256", "e1" * 32),
        ("round_sha256", "e2" * 32),
        ("submission_sha256", "e3" * 32),
        ("common_result_sha256", "e4" * 32),
        ("suite_sha256", "e5" * 32),
        ("model_revision", "e6" * 32),
        ("incumbent_model_sha256", "e7" * 32),
        ("runtime_sha256", "e8" * 32),
    ),
)
def test_every_run_identity_binding_is_enforced(
    policy: CompetitionPolicy,
    field: str,
    value: str,
):
    evidence, signed, round_, suite = fixture_evidence(policy)
    changed = evidence.evaluator_runs[0].run.model_copy(update={field: value})
    tampered = replace_run(evidence, 0, changed, "Charlie")

    with pytest.raises(ValueError, match="identity, model or runtime binding"):
        replay(tampered, signed, round_, suite, policy)


def test_output_status_and_order_must_match_common_result(policy: CompetitionPolicy):
    evidence, signed, round_, suite = fixture_evidence(policy)
    run = evidence.evaluator_runs[0].run
    changed_output = run.candidate[0].model_copy(update={"hypothesis": "different"})
    changed = run.model_copy(update={"candidate": (changed_output, *run.candidate[1:])})

    with pytest.raises(ValueError, match="output disagrees"):
        replay(replace_run(evidence, 0, changed, "Charlie"), signed, round_, suite, policy)

    reordered = run.model_copy(
        update={
            "candidate": tuple(reversed(run.candidate)),
            "incumbent": tuple(reversed(run.incumbent)),
        }
    )
    with pytest.raises(ValueError, match="canonical order"):
        replay(replace_run(evidence, 0, reordered, "Charlie"), signed, round_, suite, policy)

    failed = run.candidate[0].model_copy(update={"status": "miner_failure", "hypothesis": ""})
    changed_status = run.model_copy(update={"candidate": (failed, *run.candidate[1:])})
    with pytest.raises(ValueError, match="output disagrees"):
        replay(
            replace_run(evidence, 0, changed_status, "Charlie"),
            signed,
            round_,
            suite,
            policy,
        )


def test_per_case_timeout_cannot_hide_behind_same_zero_score(policy: CompetitionPolicy):
    signed = signed_submission(policy)
    suite = evaluation_suite(policy)
    round_ = evaluation_round(policy, suite, signed)
    zero_outputs = outputs(suite, hypothesis="unrelated", elapsed_ms=5)
    common = attested_result(signed, round_, suite, candidate=zero_outputs)
    charlie = run_record("Charlie", policy, signed, round_, suite, common, elapsed_ms=7)
    timed_out = charlie.candidate[0].model_copy(
        update={"elapsed_ms": policy.maximum_inference_ms + 1}
    )
    charlie = charlie.model_copy(update={"candidate": (timed_out, *charlie.candidate[1:])})
    dave = run_record("Dave", policy, signed, round_, suite, common, elapsed_ms=9)
    evidence = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=common,
        evaluator_runs=(signed_run(charlie, "Charlie"), signed_run(dave, "Dave")),
    )

    with pytest.raises(ValueError, match="resource eligibility disagrees by case"):
        replay(evidence, signed, round_, suite, policy)


@pytest.mark.parametrize(
    ("started", "finished"),
    ((120, 130), (121, 139), (141, 141)),
)
def test_each_run_interval_is_inside_frozen_evaluation_window(
    policy: CompetitionPolicy,
    started: int,
    finished: int,
):
    evidence, signed, round_, suite = fixture_evidence(policy)
    changed = evidence.evaluator_runs[0].run.model_copy(
        update={"started_block": started, "finished_block": finished}
    )

    with pytest.raises(ValueError, match="outside the frozen evaluation window"):
        replay(replace_run(evidence, 0, changed, "Charlie"), signed, round_, suite, policy)


def test_run_shape_bounds_and_canonical_input_are_enforced(policy: CompetitionPolicy):
    evidence, signed, round_, suite = fixture_evidence(policy)
    data = evidence.evaluator_runs[0].run.model_dump(mode="json", by_alias=True)
    data["execution_evidence_sha256"] = "0" * 64
    with pytest.raises(ValidationError, match="execution-evidence"):
        EvaluatorRunRecord.model_validate_json(json.dumps(data))

    data = evidence.evaluator_runs[0].run.model_dump(mode="json", by_alias=True)
    data["candidate"] = data["candidate"][:2]
    data["incumbent"] = data["incumbent"][:2]
    with pytest.raises(ValidationError):
        EvaluatorRunRecord.model_validate_json(json.dumps(data))

    encoded = json.loads(canonical_json_bytes(evidence))
    encoded["unexpected"] = True
    with pytest.raises(ValidationError, match="Extra inputs"):
        IndependentEvaluationEvidence.model_validate_json(json.dumps(encoded))

    # Unsafe construction cannot bypass canonical validation at the replay boundary.
    unsafe = EvaluatorRunRecord.model_construct(
        **{
            **evidence.evaluator_runs[0].run.__dict__,
            "execution_evidence_sha256": "0" * 64,
        }
    )
    broken = evidence.model_copy(
        update={
            "evaluator_runs": (
                SignedEvaluatorRunRecord.model_construct(
                    run=unsafe,
                    signature=evidence.evaluator_runs[0].signature,
                ),
                evidence.evaluator_runs[1],
            )
        }
    )
    with pytest.raises(ValidationError, match="execution-evidence"):
        replay(broken, signed, round_, suite, policy)


def test_runs_must_exactly_match_common_signers_and_groups(policy: CompetitionPolicy):
    evidence, signed, round_, suite = fixture_evidence(policy)
    duplicate = evidence.model_copy(update={"evaluator_runs": (evidence.evaluator_runs[0],) * 2})
    with pytest.raises(ValueError, match="duplicate evaluator run"):
        replay(duplicate, signed, round_, suite, policy)

    missing = evidence.model_copy(update={"evaluator_runs": evidence.evaluator_runs[:1]})
    with pytest.raises(ValueError, match="signers and evaluator runs do not match"):
        replay(missing, signed, round_, suite, policy)

    unauthorized_run = run_record(
        "Eve",
        policy,
        signed,
        round_,
        suite,
        evidence.attested_result,
        elapsed_ms=9,
    )
    outsider = unauthorized_run.model_copy(
        update={"evaluator_hotkey": wallet("Ferdie").hotkey.ss58_address}
    )
    outsider_signed = signed_run(outsider, "Ferdie")
    extra = evidence.model_copy(
        update={"evaluator_runs": (*evidence.evaluator_runs, outsider_signed)}
    )
    with pytest.raises(ValueError, match="unauthorized evaluator run signer"):
        replay(extra, signed, round_, suite, policy)


def test_submitter_cannot_be_an_evaluator(policy: CompetitionPolicy):
    data = policy.model_dump(mode="json", by_alias=True)
    data["evaluators"] = [
        {
            "hotkey": wallet("Alice").hotkey.ss58_address,
            "control_group": "submitter",
        },
        {
            "hotkey": wallet("Dave").hotkey.ss58_address,
            "control_group": "d",
        },
    ]
    self_policy = CompetitionPolicy.model_validate_json(json.dumps(data))
    signed = signed_submission(self_policy)
    suite = evaluation_suite(self_policy)
    round_ = evaluation_round(self_policy, suite, signed)
    common = attested_result(signed, round_, suite, signers=("Alice", "Dave"))
    evidence = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=common,
        evaluator_runs=(
            signed_run(
                run_record("Alice", self_policy, signed, round_, suite, common, elapsed_ms=8),
                "Alice",
            ),
            signed_run(
                run_record("Dave", self_policy, signed, round_, suite, common, elapsed_ms=9),
                "Dave",
            ),
        ),
    )

    with pytest.raises(ValueError, match="cannot attest its own"):
        replay(evidence, signed, round_, suite, self_policy)


def test_invalid_independent_run_does_not_erase_legacy_conflict_evidence(
    policy: CompetitionPolicy,
):
    evidence, signed, round_, suite = fixture_evidence(policy)
    changed = evidence.evaluator_runs[0].run.model_copy(update={"runtime_sha256": "ff" * 32})
    invalid_runs = replace_run(evidence, 0, changed, "Charlie")

    # Historical conflict intake authenticates the unchanged common transcript.
    authenticate_evaluation(evidence.attested_result, signed, round_, policy)
    with pytest.raises(ValueError, match="identity, model or runtime binding"):
        replay(invalid_runs, signed, round_, suite, policy)


def test_common_scores_are_recomputed_not_trusted(policy: CompetitionPolicy):
    evidence, signed, round_, suite = fixture_evidence(policy)
    changed = (
        evidence.evaluator_runs[0].run.candidate[0].model_copy(update={"hypothesis": "greetings"})
    )
    changed_run = evidence.evaluator_runs[0].run.model_copy(
        update={"candidate": (changed, *evidence.evaluator_runs[0].run.candidate[1:])}
    )

    with pytest.raises(ValueError, match="output disagrees"):
        replay(
            replace_run(evidence, 0, changed_run, "Charlie"),
            signed,
            round_,
            suite,
            policy,
        )
