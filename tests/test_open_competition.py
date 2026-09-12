from __future__ import annotations

import hashlib
import json
import os
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace

import bittensor as bt
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from umi.competition_api import MAX_SUBMISSION_BYTES, create_app
from umi.competition_artifacts import (
    preserve_bundle,
    verify_bundle_directory,
    verify_preserved_bundle,
)
from umi.competition_cli import main
from umi.competition_store import AttestedPromotionReview, CompetitionStore, PromotionReview
from umi.open_competition import (
    AttestedResult,
    BundleFile,
    CaseOutput,
    CompetitionPolicy,
    EvaluationCase,
    EvaluationResult,
    EvaluationRound,
    EvaluationSuite,
    Evaluator,
    ModelBundle,
    Registration,
    RegistrationSnapshot,
    SignedSubmission,
    Submission,
    aggregate_quality,
    digest,
    project_weights,
    qualifies_for_promotion,
    replay_evaluation,
    sign_object,
    validate_admission,
    verify_quorum,
)
from umi.protocol import canonical_json_bytes


def wallet(name: str):
    key = bt.sp_core.Keypair.create_from_uri("//" + name, crypto_type=bt.sp_core.CRYPTO_SR25519)
    return SimpleNamespace(hotkey=key, coldkey=key, coldkeypub=key)


@pytest.fixture
def policy():
    # These allocations and identities are test fixtures, never release defaults.
    return CompetitionPolicy(
        schema="umi-open-competition-policy/1",
        network="finney",
        netuid=78,
        sequence=1,
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
        evaluators=(
            Evaluator(hotkey=wallet("Charlie").hotkey.ss58_address, control_group="c"),
            Evaluator(hotkey=wallet("Dave").hotkey.ss58_address, control_group="d"),
        ),
        required_evaluator_groups=2,
        contribution_terms_sha256="a1" * 32,
        accepted_model_licenses=("CC-BY-SA-4.0",),
        evaluation_runtime_sha256="a2" * 32,
    )


def snapshot(block: int = 110):
    return RegistrationSnapshot(
        network="finney",
        netuid=78,
        block=block,
        block_hash="0x" + f"{block:064x}",
        registrations=(
            Registration(uid=6, hotkey=wallet("Alice").hotkey.ss58_address),
            Registration(uid=247, hotkey=wallet("Bob").hotkey.ss58_address),
        ),
    )


def bundle_at(root: Path, marker: str = "baseline", parent=None):
    root.mkdir(parents=True)
    records = []
    for role in (
        "weights",
        "config",
        "processor",
        "inference",
        "environment",
        "license",
        "provenance",
    ):
        data = f"INERT TEST DATA {marker} {role}".encode()
        (root / f"{role}.txt").write_bytes(data)
        records.append(
            BundleFile(
                path=f"{role}.txt",
                role=role,
                sha256=hashlib.sha256(data).hexdigest(),
                size_bytes=len(data),
            )
        )
    return ModelBundle(
        schema="umi-model-bundle/1",
        profile="offline_bundle/1",
        parent_baseline_sha256=parent,
        license_id="CC-BY-SA-4.0",
        files=tuple(sorted(records, key=lambda f: f.path)),
    )


def submission(policy, *, bundle=None, name="Alice", sequence=1, start=100, end=900):
    sub = Submission(
        schema="umi-competition-submission/1",
        network="finney",
        netuid=78,
        policy_sha256=digest(policy),
        hotkey=wallet(name).hotkey.ss58_address,
        track="endpoint" if bundle is None else "model",
        sequence=sequence,
        valid_from_block=start,
        valid_through_block=end,
        model_revision="b1" * 32 if bundle is None else digest(bundle),
        endpoint_url="https://example.com" if bundle is None else None,
        model_bundle=bundle,
        accepted_terms_sha256=policy.contribution_terms_sha256,
    )
    return SignedSubmission(submission=sub, signature=sign_object(sub, wallet(name)))


def suite_for(policy):
    return EvaluationSuite(
        schema="umi-competition-suite/1",
        policy_sha256=digest(policy),
        cases=tuple(
            EvaluationCase(
                case_id=f"{i:064x}",
                video_sha256=f"{i + 100:064x}",
                stratum=stratum,
                references=("hello", "hi", "greetings"),
            )
            for i, stratum in enumerate(("fingerspelling", "short_utterance", "continuous"), 1)
        ),
    )


def round_for(policy, suite, signed_submissions, incumbent="b2" * 32):
    return EvaluationRound(
        schema="umi-competition-round/1",
        policy_sha256=digest(policy),
        sequence=1,
        suite_sha256=digest(suite),
        incumbent_model_sha256=incumbent,
        runtime_sha256=policy.evaluation_runtime_sha256,
        roster=tuple(sorted(digest(s.submission) for s in signed_submissions)),
        submission_close_block=120,
        evaluation_close_block=140,
        reveal_block=150,
        valid_through_block=200,
    )


def result_for(signed, round_, suite, *, hypothesis="hello", baseline="", status="ok"):
    result = EvaluationResult(
        schema="umi-competition-result/1",
        round_sha256=digest(round_),
        submission_sha256=digest(signed.submission),
        model_revision=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        runtime_sha256=round_.runtime_sha256,
        finished_block=130,
        candidate=tuple(
            CaseOutput(case_id=c.case_id, status=status, hypothesis=hypothesis, elapsed_ms=5)
            for c in suite.cases
        ),
        incumbent=tuple(
            CaseOutput(case_id=c.case_id, status="ok", hypothesis=baseline, elapsed_ms=5)
            for c in suite.cases
        ),
    )
    return attested(result)


def attested(result):
    return AttestedResult(
        result=result, signatures=tuple(sign_object(result, wallet(n)) for n in ("Charlie", "Dave"))
    )


def review_for(policy, signed, round_, evaluation):
    body = PromotionReview(
        schema="umi-model-promotion-review/1",
        policy_sha256=digest(policy),
        model_sha256=signed.submission.model_revision,
        incumbent_model_sha256=round_.incumbent_model_sha256,
        evaluation_result_sha256=digest(evaluation.result),
        reconstruction_evidence_sha256="c1" * 32,
        rights_review_sha256="c2" * 32,
        offline_reconstruction_passed=True,
        rights_review_passed=True,
    )
    return AttestedPromotionReview(
        review=body, signatures=tuple(sign_object(body, wallet(n)) for n in ("Charlie", "Dave"))
    )


def test_reward_split_is_required_and_exact(policy):
    data = policy.model_dump(mode="json", by_alias=True)
    del data["model_reward_bps"]
    with pytest.raises(ValidationError):
        CompetitionPolicy.model_validate_json(json.dumps(data))
    data["model_reward_bps"] = 2999
    with pytest.raises(ValidationError, match="sum"):
        CompetitionPolicy.model_validate_json(json.dumps(data))


def test_signed_admission_has_no_pilot_requirement(policy):
    signed = submission(policy)
    assert validate_admission(signed, policy, snapshot(), 110) == 6
    bad = signed.model_dump(mode="json", by_alias=True)
    bad["submission"]["sequence"] += 1
    with pytest.raises(ValidationError, match="signature"):
        SignedSubmission.model_validate_json(json.dumps(bad))
    with pytest.raises(ValueError, match="stale"):
        validate_admission(signed, policy, snapshot(99), 110)
    with pytest.raises(ValueError, match="not current"):
        validate_admission(signed, policy, snapshot(901), 901)


def test_replacement_and_retries_survive_restart(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy)
    signed = submission(policy)
    receipt = store.admit(signed, snapshot(), 110)
    assert receipt["status"] == "accepted_no_weight"
    restarted = CompetitionStore(tmp_path / "state", policy)
    assert restarted.admit(signed, snapshot(950), 950) == receipt
    assert len(restarted.submissions()) == 1
    with pytest.raises(ValueError, match="rate limited"):
        restarted.admit(submission(policy, sequence=2), snapshot(112), 112)
    restarted.admit(submission(policy, sequence=2), snapshot(115), 115)
    with pytest.raises(ValueError, match="sequence"):
        restarted.admit(submission(policy, sequence=1, end=800), snapshot(121), 121)
    assert len(restarted.submissions()) == 2
    assert len(restarted.submissions(limit=1, offset=1)) == 1


def test_state_cannot_be_rebound_to_another_policy(policy, tmp_path):
    CompetitionStore(tmp_path / "state", policy)
    other = policy.model_copy(update={"sequence": 2})
    with pytest.raises(ValueError, match="different competition policy"):
        CompetitionStore(tmp_path / "state", other)


@pytest.mark.parametrize(
    "path", ["../weights", "/weights", "x/../w", "a//b", "a\\b", "a/./b", ".secret", "a\nb", "a:b"]
)
def test_artifact_paths_are_safe(path):
    with pytest.raises(ValidationError):
        BundleFile(path=path, role="weights", sha256="a1" * 32, size_bytes=0)


def test_archive_preserves_every_byte_and_is_idempotent(policy, tmp_path):
    bundle = bundle_at(tmp_path / "source")
    archive = tmp_path / "archive"
    path = preserve_bundle(bundle, tmp_path / "source", archive, policy)
    assert verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    assert preserve_bundle(bundle, tmp_path / "source", archive, policy) == path
    # A destroyed miner/source does not affect the retained copy.
    (tmp_path / "source" / "weights.txt").unlink()
    assert verify_preserved_bundle(bundle, archive, policy) == digest(bundle)
    target = path / "model" / "weights.txt"
    target.chmod(0o600)
    target.write_bytes(b"wrong")
    with pytest.raises(ValueError):
        verify_preserved_bundle(bundle, archive, policy)


@pytest.mark.parametrize(
    "mutation", ["extra", "missing", "symlink", "hardlink", "tampered", "fifo"]
)
def test_bad_bundle_cannot_be_preserved(policy, tmp_path, mutation):
    source = tmp_path / "source"
    bundle = bundle_at(source)
    target = source / "weights.txt"
    if mutation == "extra":
        (source / "unexpected").write_bytes(b"not in manifest")
    elif mutation == "tampered":
        target.write_bytes(b"x" * target.stat().st_size)
    else:
        saved = target.read_bytes()
        target.unlink()
        if mutation == "symlink":
            (tmp_path / "outside").write_bytes(saved)
            target.symlink_to(tmp_path / "outside")
        elif mutation == "hardlink":
            (tmp_path / "outside").write_bytes(saved)
            os.link(tmp_path / "outside", target)
        elif mutation == "fifo":
            os.mkfifo(target)
    with pytest.raises((ValueError, OSError)):
        preserve_bundle(bundle, source, tmp_path / "archive", policy)
    assert not (tmp_path / "archive" / digest(bundle)).exists()
    assert not list((tmp_path / "archive").glob(".pending-*"))


def test_policy_bundle_limits_are_enforced(policy, tmp_path):
    bundle = bundle_at(tmp_path / "source")
    tiny = policy.model_copy(update={"maximum_bundle_bytes": 1})
    with pytest.raises(ValueError, match="resource limits"):
        verify_bundle_directory(bundle, tmp_path / "source", tiny)


def test_paired_quality_and_quorum(policy):
    sub = submission(policy)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (sub,))
    evaluation = result_for(sub, round_, suite)
    candidate, incumbent = replay_evaluation(
        evaluation, sub, round_, suite, policy, current_block=150
    )
    assert aggregate_quality(candidate) == 1
    assert aggregate_quality(incumbent) == 0
    assert qualifies_for_promotion(candidate, incumbent, policy)
    tied = result_for(sub, round_, suite, baseline="hello")
    c, b = replay_evaluation(tied, sub, round_, suite, policy, current_block=150)
    assert not qualifies_for_promotion(c, b, policy)
    with pytest.raises(ValueError, match="insufficient"):
        verify_quorum(
            evaluation.model_copy(update={"signatures": evaluation.signatures[:1]}), policy
        )
    with pytest.raises(ValueError, match="duplicate"):
        verify_quorum(
            evaluation.model_copy(update={"signatures": (evaluation.signatures[0],) * 2}), policy
        )


def test_same_control_group_does_not_count_twice(policy):
    data = policy.model_dump(mode="json", by_alias=True)
    data["evaluators"][1]["control_group"] = "c"
    with pytest.raises(ValidationError, match="control groups"):
        CompetitionPolicy.model_validate_json(json.dumps(data))


@pytest.mark.parametrize(
    "mutation",
    [
        "suite",
        "round",
        "runtime",
        "model",
        "omission",
        "late",
        "before_reveal",
        "expired",
        "signature",
    ],
)
def test_evaluation_bindings_fail_closed(policy, mutation):
    sub = submission(policy)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (sub,))
    evaluation = result_for(sub, round_, suite)
    result = evaluation.result
    current_block = 150
    if mutation == "suite":
        suite = suite.model_copy(update={"cases": tuple(reversed(suite.cases))})
    elif mutation == "round":
        round_ = round_.model_copy(update={"sequence": 2})
    elif mutation == "runtime":
        result = result.model_copy(update={"runtime_sha256": "d1" * 32})
    elif mutation == "model":
        result = result.model_copy(update={"model_revision": "d2" * 32})
    elif mutation == "omission":
        result = result.model_copy(update={"candidate": result.candidate[:-1]})
    elif mutation == "late":
        result = result.model_copy(update={"finished_block": 141})
    elif mutation == "before_reveal":
        current_block = 149
    elif mutation == "expired":
        current_block = 201
    elif mutation == "signature":
        evaluation = evaluation.model_copy(
            update={"result": result.model_copy(update={"finished_block": 131})}
        )
    if mutation != "signature":
        evaluation = attested(result)
    with pytest.raises(ValueError):
        replay_evaluation(evaluation, sub, round_, suite, policy, current_block=current_block)


def test_miner_failures_score_zero_but_infrastructure_voids(policy):
    sub = submission(policy)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (sub,))
    failed = result_for(sub, round_, suite, hypothesis="", status="miner_failure")
    c, _ = replay_evaluation(failed, sub, round_, suite, policy, current_block=150)
    assert aggregate_quality(c) == 0
    infrastructure = result_for(sub, round_, suite, hypothesis="", status="infrastructure_failure")
    with pytest.raises(ValueError, match="infrastructure"):
        replay_evaluation(infrastructure, sub, round_, suite, policy, current_block=150)


@pytest.fixture
def scenario(policy, tmp_path):
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    candidate = bundle_at(tmp_path / "candidate", "candidate", digest(baseline))
    preserve_bundle(candidate, tmp_path / "candidate", archive, policy)
    store = CompetitionStore(tmp_path / "state", policy)
    store.initialize_baseline(baseline, archive)
    model = submission(policy, bundle=candidate)
    endpoint = submission(policy, name="Bob")
    for sub in (model, endpoint):
        store.admit(sub, snapshot(), 110)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (model, endpoint), digest(baseline))
    store.close_round(round_, current_block=120)
    evaluation = result_for(model, round_, suite)
    return SimpleNamespace(
        policy=policy,
        archive=archive,
        baseline=baseline,
        candidate=candidate,
        store=store,
        model=model,
        endpoint=endpoint,
        suite=suite,
        round=round_,
        evaluation=evaluation,
        review=review_for(policy, model, round_, evaluation),
    )


def promote(s):
    return s.store.promote(
        signed=s.model,
        attested=s.evaluation,
        round_=s.round,
        suite=s.suite,
        review=s.review,
        archive=s.archive,
        snapshot=snapshot(150),
        current_block=150,
    )


def test_end_to_end_admit_preserve_promote_restart_project(scenario):
    s = scenario
    record = promote(s)
    assert record["sequence"] == 1
    assert record["model_sha256"] == digest(s.candidate)
    assert promote(s) == record
    assert CompetitionStore(s.store.directory, s.policy).baseline() == record
    row = project_weights(
        policy=s.policy,
        round_=s.round,
        suite=s.suite,
        evaluations=(
            (s.model, s.evaluation),
            (s.endpoint, result_for(s.endpoint, s.round, s.suite)),
        ),
        snapshot=snapshot(150),
        current_block=150,
        promoted_model_sha256=record["model_sha256"],
        promoted_hotkey=record["contributor_hotkey"],
    )
    assert row.chain_submission_authorized is False
    assert len(row.weights) == 256
    assert sum(row.weights) == 65535
    assert sum(w > 0 for w in row.weights) == 2
    assert [(a.uid, Fraction(int(a.numerator), int(a.denominator))) for a in row.allocations] == [
        (6, Fraction(3, 10)),
        (247, Fraction(7, 10)),
    ]
    # Original baseline remains available after promotion.
    assert verify_preserved_bundle(s.baseline, s.archive, s.policy) == digest(s.baseline)


def test_failed_rights_review_does_not_change_baseline(scenario):
    s = scenario
    before = s.store.baseline()
    s.review = s.review.model_copy(update={"signatures": s.review.signatures[:1]})
    with pytest.raises(ValueError, match="insufficient"):
        promote(s)
    assert s.store.baseline() == before


def test_store_projection_requires_closed_round_and_current_history(scenario):
    s = scenario
    promote(s)
    evaluations = (
        (s.model, s.evaluation),
        (s.endpoint, result_for(s.endpoint, s.round, s.suite)),
    )
    row = s.store.project(
        round_=s.round,
        suite=s.suite,
        evaluations=evaluations,
        snapshot=snapshot(150),
        current_block=150,
    )
    assert sum(row.weights) == 65535
    assert row.chain_submission_authorized is False
    with pytest.raises(ValueError, match=r"not been closed|binding mismatch"):
        s.store.project(
            round_=s.round.model_copy(update={"sequence": 2}),
            suite=s.suite,
            evaluations=evaluations,
            snapshot=snapshot(150),
            current_block=150,
        )
    with pytest.raises(ValueError, match=r"earlier finalized block|at or after reveal"):
        s.store.project(
            round_=s.round,
            suite=s.suite,
            evaluations=evaluations,
            snapshot=snapshot(149),
            current_block=149,
        )


def test_cli_projection_uses_durable_admission_and_promotion(scenario, tmp_path, capsys):
    s = scenario
    promote(s)
    inputs = {
        "round": s.round.model_dump(mode="json", by_alias=True),
        "suite": s.suite.model_dump(mode="json", by_alias=True),
        "entries": [
            {
                "submission": sub.model_dump(mode="json", by_alias=True),
                "evaluation": evaluation.model_dump(mode="json", by_alias=True),
            }
            for sub, evaluation in (
                (s.model, s.evaluation),
                (s.endpoint, result_for(s.endpoint, s.round, s.suite)),
            )
        ],
    }
    for name, obj in (("policy", s.policy), ("snapshot", snapshot(150)), ("inputs", inputs)):
        (tmp_path / (name + ".json")).write_bytes(canonical_json_bytes(obj))
    argv = [
        "--policy",
        str(tmp_path / "policy.json"),
        "project-weights",
        "--state",
        str(s.store.directory),
        "--snapshot",
        str(tmp_path / "snapshot.json"),
        "--inputs",
        str(tmp_path / "inputs.json"),
        "--current-block",
        "150",
    ]
    main(argv)
    output = json.loads(capsys.readouterr().out)
    assert sum(output["weights"]) == 65535
    assert output["chain_submission_authorized"] is False
    # A complete, signed roster without a durable close is not enough.
    inputs["round"]["sequence"] = 2
    (tmp_path / "inputs.json").write_bytes(canonical_json_bytes(inputs))
    with pytest.raises(SystemExit) as failure:
        main(argv)
    assert failure.value.code == 2
    assert "rejected" in capsys.readouterr().err


def test_failed_archive_does_not_change_baseline(scenario):
    s = scenario
    before = s.store.baseline()
    path = s.archive / digest(s.candidate) / "model" / "weights.txt"
    path.chmod(0o600)
    path.write_bytes(b"corrupt")
    with pytest.raises(ValueError):
        promote(s)
    assert s.store.baseline() == before


def test_round_cannot_omit_enrollments_or_publish_late(scenario):
    s = scenario
    with pytest.raises(ValueError, match="unusable"):
        s.store.close_round(s.round.model_copy(update={"sequence": 2}), current_block=141)
    with pytest.raises(ValueError, match="omits"):
        s.store.close_round(
            s.round.model_copy(
                update={"sequence": 2, "roster": s.round.roster[:1], "suite_sha256": "e1" * 32}
            ),
            current_block=120,
        )


def test_missing_model_pool_recipient_does_not_redistribute(scenario):
    s = scenario
    with pytest.raises(ValueError, match="promoted contributor"):
        project_weights(
            policy=s.policy,
            round_=s.round,
            suite=s.suite,
            evaluations=(
                (s.model, s.evaluation),
                (s.endpoint, result_for(s.endpoint, s.round, s.suite)),
            ),
            snapshot=snapshot(150),
            current_block=150,
            promoted_model_sha256=None,
            promoted_hotkey=None,
        )


def test_uid_reuse_cannot_inherit_rewards(scenario):
    s = scenario
    record = promote(s)
    swapped = snapshot(150).model_copy(
        update={
            "registrations": (
                Registration(uid=6, hotkey=wallet("Eve").hotkey.ss58_address),
                Registration(uid=247, hotkey=wallet("Bob").hotkey.ss58_address),
            )
        }
    )
    with pytest.raises(ValueError, match="promoted contributor"):
        project_weights(
            policy=s.policy,
            round_=s.round,
            suite=s.suite,
            evaluations=(
                (s.model, s.evaluation),
                (s.endpoint, result_for(s.endpoint, s.round, s.suite)),
            ),
            snapshot=swapped,
            current_block=150,
            promoted_model_sha256=record["model_sha256"],
            promoted_hotkey=record["contributor_hotkey"],
        )


def test_api_signed_intake_and_safe_error_responses(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy)

    async def current_snapshot():
        return snapshot()

    with TestClient(create_app(store, current_snapshot)) as client:
        body = json.loads(canonical_json_bytes(submission(policy)))
        first = client.post("/v1/competition/submissions", json=body)
        assert first.status_code == 200
        assert client.post("/v1/competition/submissions", json=body).json() == first.json()
        assert len(client.get("/v1/competition/submissions").json()["items"]) == 1
        entry = client.get("/v1/competition/submissions/" + first.json()["submission_sha256"])
        assert entry.status_code == 200
        assert entry.json()["receipt"] == first.json()
        assert client.get("/v1/competition/status").json()["mode"] == "rehearsal_no_weight"
        assert client.get("/v1/competition/submissions?limit=101").status_code == 422
        bad = client.post("/v1/competition/submissions", json={"seed": "PRIVATE SECRET"})
        assert bad.status_code == 422
        assert "PRIVATE SECRET" not in bad.text
        huge = client.post(
            "/v1/competition/submissions",
            content=b"x" * (MAX_SUBMISSION_BYTES + 1),
            headers={"content-type": "application/json"},
        )
        assert huge.status_code == 413


def test_api_unavailable_chain_does_not_consume_submission(policy, tmp_path):
    store = CompetitionStore(tmp_path / "state", policy)

    async def missing():
        raise RuntimeError("private provider details")

    with TestClient(create_app(store, missing)) as client:
        response = client.post(
            "/v1/competition/submissions", json=json.loads(canonical_json_bytes(submission(policy)))
        )
        assert response.status_code == 503
        assert "private provider" not in response.text
    assert store.submissions() == []


def test_cli_policy_rehearsal_has_no_weight_authority(policy, tmp_path, capsys):
    path = tmp_path / "policy.json"
    path.write_bytes(canonical_json_bytes(policy))
    main(["--policy", str(path), "inspect-policy"])
    output = json.loads(capsys.readouterr().out)
    assert output["policy_sha256"] == digest(policy)
    assert output["chain_submission_authorized"] is False


def test_conflict_evidence_cli_and_status_api(scenario, tmp_path, capsys):
    s = scenario
    promote(s)
    for name, value in (
        ("policy", s.policy),
        ("submission", s.model),
        ("round", s.round),
        ("suite", s.suite),
        ("evaluation", s.evaluation),
    ):
        (tmp_path / (name + ".json")).write_bytes(canonical_json_bytes(value))
    prefix = ["--policy", str(tmp_path / "policy.json")]
    command = [*prefix, "record-evaluation", "--state", str(s.store.directory)]
    for name in ("submission", "round", "suite", "evaluation"):
        command.extend(["--" + name, str(tmp_path / (name + ".json"))])
    command.extend(["--observed-block", "150"])
    main(command)
    assert json.loads(capsys.readouterr().out)["conflicted"] is False
    conflicting = result_for(s.model, s.round, s.suite, hypothesis="", status="miner_failure")
    (tmp_path / "evaluation.json").write_bytes(canonical_json_bytes(conflicting))
    main(command)
    receipt = json.loads(capsys.readouterr().out)
    assert receipt["conflicted"] is True
    assert receipt["chain_submission_authorized"] is False
    main(
        [
            *prefix,
            "round-status",
            "--state",
            str(s.store.directory),
            "--round-sha256",
            digest(s.round),
        ]
    )
    status = json.loads(capsys.readouterr().out)
    assert status["conflicted"] is True
    assert len(status["results"]) == 2

    async def current_snapshot():
        return snapshot(150)

    with TestClient(create_app(s.store, current_snapshot)) as client:
        response = client.get("/v1/competition/rounds/" + digest(s.round))
        assert response.status_code == 200
        assert response.json()["conflicted"] is True
        assert client.get("/v1/competition/rounds/" + "0" * 64).status_code == 404
        assert (
            client.get("/v1/competition/rounds/" + digest(s.round) + "?limit=101").status_code
            == 422
        )
        baseline = client.get("/v1/competition/status").json()["baseline"]
        assert baseline["held_for_conflict"] is True
        assert baseline["model_sha256"] == digest(s.candidate)


def test_preserved_incumbent_earns_without_a_new_upload(policy):
    endpoint = submission(policy, name="Bob")
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (endpoint,))
    evaluation = result_for(endpoint, round_, suite, baseline="hello")
    projection = project_weights(
        policy=policy,
        round_=round_,
        suite=suite,
        evaluations=((endpoint, evaluation),),
        snapshot=snapshot(150),
        current_block=150,
        promoted_model_sha256=round_.incumbent_model_sha256,
        promoted_hotkey=wallet("Alice").hotkey.ss58_address,
    )
    assert projection.weights[6] > 0
    assert projection.weights[247] > 0


def test_evaluator_cannot_attest_its_own_miner_output(policy):
    sub = submission(policy, name="Charlie")
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (sub,))
    with pytest.raises(ValueError, match="own evaluation"):
        replay_evaluation(
            result_for(sub, round_, suite), sub, round_, suite, policy, current_block=150
        )


def test_per_stratum_regression_prevents_promotion(policy):
    incumbent = {
        "fingerspelling": Fraction(1),
        "short_utterance": Fraction(0),
        "continuous": Fraction(0),
    }
    candidate = {
        "fingerspelling": Fraction(0),
        "short_utterance": Fraction(1),
        "continuous": Fraction(1),
    }
    assert aggregate_quality(candidate) > aggregate_quality(incumbent)
    assert not qualifies_for_promotion(candidate, incumbent, policy)


def test_closed_admission_boundary_cannot_be_backdated(scenario):
    s = scenario
    newer = submission(s.policy, sequence=2)
    with pytest.raises(ValueError, match="earlier finalized block"):
        s.store.admit(newer, snapshot(115), 115)
    with pytest.raises(ValueError, match="already closed"):
        s.store.admit(newer, snapshot(120), 120)
    assert s.store.admit(newer, snapshot(121), 121)["accepted_block"] == 121


@pytest.mark.parametrize("same_content", [True, False])
def test_copied_baseline_and_stale_incumbent_cannot_be_promoted(scenario, tmp_path, same_content):
    s = scenario
    if same_content:
        bundle = s.baseline.model_copy(update={"parent_baseline_sha256": digest(s.baseline)})
        source = tmp_path / "baseline"
    else:
        source = tmp_path / "challenger"
        bundle = bundle_at(source, "different challenger", digest(s.baseline))
    preserve_bundle(bundle, source, s.archive, s.policy)
    challenger = submission(s.policy, bundle=bundle, name="Bob")
    s.store.admit(challenger, snapshot(121), 121)
    cases = tuple(
        c.model_copy(update={"video_sha256": f"{i + 1000:064x}"})
        for i, c in enumerate(s.suite.cases)
    )
    suite = s.suite.model_copy(update={"cases": cases})
    round_ = round_for(s.policy, suite, (s.model, s.endpoint, challenger), digest(s.baseline))
    round_ = round_.model_copy(update={"sequence": 2, "submission_close_block": 125})
    s.store.close_round(round_, current_block=125)
    evaluation = result_for(challenger, round_, suite)
    review = review_for(s.policy, challenger, round_, evaluation)
    if not same_content:
        promote(s)
    before = s.store.baseline()
    with pytest.raises(
        ValueError, match="content was already" if same_content else "baseline changed"
    ):
        s.store.promote(
            signed=challenger,
            attested=evaluation,
            round_=round_,
            suite=suite,
            review=review,
            archive=s.archive,
            snapshot=snapshot(150),
            current_block=150,
        )
    assert s.store.baseline() == before
