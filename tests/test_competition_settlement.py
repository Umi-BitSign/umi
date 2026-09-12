from __future__ import annotations

import hashlib
import sqlite3
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import pytest

from umi import competition_store
from umi.competition_artifacts import preserve_bundle
from umi.competition_evidence import (
    EvaluatorRunRecord,
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    independent_evidence_digest,
    sign_evaluator_run,
)
from umi.competition_settlement import EvidenceCutoffSchedule
from umi.competition_store import CompetitionStore
from umi.open_competition import CompetitionPolicy, digest

from .test_open_competition import (
    attested,
    bundle_at,
    result_for,
    review_for,
    round_for,
    snapshot,
    submission,
    suite_for,
    wallet,
)
from .test_open_competition import policy as policy


def _independent(policy, signed, round_, suite, attested):
    runs = []
    for index, name in enumerate(("Charlie", "Dave"), 1):
        evaluator = wallet(name)
        common = attested.result
        run = EvaluatorRunRecord(
            schema="umi-competition-evaluator-run/1",
            evaluator_hotkey=evaluator.hotkey.ss58_address,
            policy_sha256=digest(policy),
            round_sha256=digest(round_),
            submission_sha256=digest(signed.submission),
            common_result_sha256=digest(common),
            suite_sha256=digest(suite),
            model_revision=signed.submission.model_revision,
            incumbent_model_sha256=round_.incumbent_model_sha256,
            runtime_sha256=round_.runtime_sha256,
            started_block=round_.submission_close_block + index,
            finished_block=common.finished_block,
            candidate=tuple(
                output.model_copy(update={"elapsed_ms": output.elapsed_ms + index})
                for output in common.candidate
            ),
            incumbent=tuple(
                output.model_copy(update={"elapsed_ms": output.elapsed_ms + index})
                for output in common.incumbent
            ),
            execution_evidence_sha256=hashlib.sha256(
                f"{name}:{digest(common)}".encode()
            ).hexdigest(),
        )
        runs.append(SignedEvaluatorRunRecord(run=run, signature=sign_evaluator_run(run, evaluator)))
    return IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=attested,
        evaluator_runs=tuple(runs),
    )


def _scenario(policy, root, *, cutoff_block=160):
    policy = policy.model_copy(update={"endpoint_reward_bps": 10_000, "model_reward_bps": 0})
    archive = root / "archive"
    baseline = bundle_at(root / "baseline")
    preserve_bundle(baseline, root / "baseline", archive, policy)
    store = CompetitionStore(root / "state", policy)
    store.initialize_baseline(baseline, archive)
    submissions = (submission(policy), submission(policy, name="Bob"))
    for signed in submissions:
        store.admit(signed, snapshot(), 110)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, submissions, digest(baseline))
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=cutoff_block,
    )
    cutoff_receipt = store.fix_evidence_cutoff(round_, schedule, observed_block=120)
    store.close_round(round_, current_block=120)
    attested = tuple(result_for(signed, round_, suite) for signed in submissions)
    evidence = tuple(
        (signed, _independent(policy, signed, round_, suite, result))
        for signed, result in zip(submissions, attested, strict=True)
    )
    return SimpleNamespace(
        policy=policy,
        store=store,
        round=round_,
        suite=suite,
        schedule=schedule,
        cutoff_receipt=cutoff_receipt,
        submissions=submissions,
        attested=attested,
        evidence=evidence,
    )


def _record_all(s, *, observed_block=150):
    return tuple(
        s.store.record_independent_evaluation(
            signed=signed,
            evidence=evidence,
            round_=s.round,
            suite=s.suite,
            observed_block=observed_block,
        )
        for signed, evidence in s.evidence
    )


def _settle(s, *, current_block=160, evidence=None, snapshot_block=None):
    return s.store.settle(
        round_=s.round,
        suite=s.suite,
        evidence=s.evidence if evidence is None else evidence,
        snapshot=snapshot(current_block if snapshot_block is None else snapshot_block),
        current_block=current_block,
    )


def test_cutoff_is_explicit_policy_bound_and_fixed_before_round_close(policy, tmp_path):
    assert "evidence_cutoff_block" not in CompetitionPolicy.model_fields
    s = _scenario(policy, tmp_path)
    assert s.cutoff_receipt["evidence_cutoff_block"] == 160
    assert s.cutoff_receipt["fixed_observed_block"] == 120
    assert s.cutoff_receipt["chain_submission_authorized"] is False
    assert s.store.fix_evidence_cutoff(s.round, s.schedule, observed_block=190) == s.cutoff_receipt

    changed = s.schedule.model_copy(update={"evidence_cutoff_block": 170})
    with pytest.raises(ValueError, match="different evidence cutoff"):
        s.store.fix_evidence_cutoff(s.round, changed, observed_block=120)

    other = _scenario(policy, tmp_path / "other")
    too_late = other.schedule.model_copy(update={"round_sha256": "11" * 32})
    with pytest.raises(ValueError, match="binding mismatch"):
        other.store.fix_evidence_cutoff(other.round, too_late, observed_block=120)


def test_round_without_prefixed_cutoff_cannot_settle_or_add_one_late(policy, tmp_path):
    policy = policy.model_copy(update={"endpoint_reward_bps": 10_000, "model_reward_bps": 0})
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    store = CompetitionStore(tmp_path / "state", policy)
    store.initialize_baseline(baseline, archive)
    signed = submission(policy)
    store.admit(signed, snapshot(), 110)
    suite = suite_for(policy)
    round_ = round_for(policy, suite, (signed,), digest(baseline))
    store.close_round(round_, current_block=120)
    result = result_for(signed, round_, suite)
    evidence = ((signed, _independent(policy, signed, round_, suite, result)),)
    with pytest.raises(ValueError, match="no pre-fixed"):
        store.settle(
            round_=round_,
            suite=suite,
            evidence=evidence,
            snapshot=snapshot(160),
            current_block=160,
        )
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    with pytest.raises(ValueError, match="before its round closes"):
        store.fix_evidence_cutoff(round_, schedule, observed_block=120)


def test_settlement_is_immutable_idempotent_and_survives_restart(policy, tmp_path):
    s = _scenario(policy, tmp_path)
    receipts = _record_all(s)
    settlement = _settle(s)
    assert settlement["schema"] == "umi-competition-settlement/1"
    assert settlement["observed_block"] == 160
    assert settlement["roster"] == list(s.round.roster)
    assert [item["first_observed_block"] for item in settlement["results"]] == [150, 150]
    assert sum(settlement["projection"]["weights"]) == 65_535
    assert settlement["projection"]["chain_submission_authorized"] is False
    assert settlement["chain_submission_authorized"] is False
    assert {item["independent_evidence_sha256"] for item in settlement["results"]} == {
        independent_evidence_digest(evidence) for _signed, evidence in s.evidence
    }
    assert {receipt["first_observed_block"] for receipt in receipts} == {150}

    status = s.store.settlement_status(digest(s.round))
    assert status is not None and status["disputed"] is False
    settlement_id = status["settlement_sha256"]
    s.store = CompetitionStore(s.store.directory, s.policy)
    assert _settle(s, current_block=170, snapshot_block=160) == settlement
    restarted = s.store.settlement_status(digest(s.round))
    assert restarted is not None
    assert restarted["settlement_sha256"] == settlement_id
    assert restarted["settlement"] == settlement
    with pytest.raises(ValueError, match="different inputs"):
        _settle(s, current_block=170, snapshot_block=170)
    assert s.store.settlement_status(digest(s.round))["settlement"] == settlement


def test_fresh_post_cutoff_evidence_is_retained_but_ineligible(policy, tmp_path):
    s = _scenario(policy, tmp_path)
    with pytest.raises(ValueError, match="durably recorded by cutoff"):
        _settle(s, current_block=170)
    assert len(s.store.round_status(digest(s.round))["results"]) == 2
    receipts = _record_all(s, observed_block=170)
    assert {receipt["first_observed_block"] for receipt in receipts} == {170}
    with pytest.raises(ValueError, match="first observed after cutoff"):
        _settle(s, current_block=170)
    assert s.store.settlement_status(digest(s.round)) is None


def test_invalid_late_run_retains_conflict_and_disputes_without_rewrite(policy, tmp_path):
    s = _scenario(policy, tmp_path)
    _record_all(s)
    original = _settle(s)
    signed = s.submissions[0]
    conflicting_attested = result_for(signed, s.round, s.suite, hypothesis="hell")
    conflicting = _independent(s.policy, signed, s.round, s.suite, conflicting_attested)
    first = conflicting.evaluator_runs[0]
    tampered_run = first.run.model_copy(update={"execution_evidence_sha256": "ef" * 32})
    conflicting = conflicting.model_copy(
        update={
            "evaluator_runs": (
                first.model_copy(update={"run": tampered_run}),
                conflicting.evaluator_runs[1],
            )
        }
    )
    with pytest.raises(ValueError, match="signature"):
        s.store.record_independent_evaluation(
            signed=signed,
            evidence=conflicting,
            round_=s.round,
            suite=s.suite,
            observed_block=170,
        )
    round_status = s.store.round_status(digest(s.round))
    assert round_status["conflicted"] is True
    assert len(round_status["results"]) == 3
    status = s.store.settlement_status(digest(s.round))
    assert status is not None
    assert status["disputed"] is True
    assert status["dispute_detected_block"] == 170
    assert status["settlement"] == original
    with pytest.raises(ValueError, match="conflict"):
        _settle(s, current_block=170)
    assert s.store.settlement_status(digest(s.round))["settlement"] == original


def test_source_conflict_disputes_only_downstream_settlement_heads(policy, tmp_path):
    policy = policy.model_copy(update={"endpoint_reward_bps": 10_000, "model_reward_bps": 0})
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    candidate = bundle_at(tmp_path / "candidate", "candidate", digest(baseline))
    preserve_bundle(baseline, tmp_path / "baseline", archive, policy)
    preserve_bundle(candidate, tmp_path / "candidate", archive, policy)
    store = CompetitionStore(tmp_path / "state", policy)
    store.initialize_baseline(baseline, archive)
    model = submission(policy, bundle=candidate)
    endpoint = submission(policy, name="Bob")
    for signed in (model, endpoint):
        store.admit(signed, snapshot(), 110)
    source_suite = suite_for(policy)
    source_round = round_for(policy, source_suite, (model, endpoint), digest(baseline))
    store.close_round(source_round, current_block=120)
    source_evaluation = result_for(model, source_round, source_suite)
    s = SimpleNamespace(
        policy=policy,
        archive=archive,
        baseline=baseline,
        store=store,
        model=model,
        endpoint=endpoint,
        suite=source_suite,
        round=source_round,
        evaluation=source_evaluation,
    )

    def unique_suite(offset):
        return s.suite.model_copy(
            update={
                "cases": tuple(
                    case.model_copy(update={"video_sha256": f"{index + offset:064x}"})
                    for index, case in enumerate(s.suite.cases)
                )
            }
        )

    def close_and_settle(round_, suite, *, fixed_block, result_block, cutoff_block):
        schedule = EvidenceCutoffSchedule(
            schema="umi-competition-evidence-cutoff/1",
            policy_sha256=digest(s.policy),
            round_sha256=digest(round_),
            evidence_cutoff_block=cutoff_block,
        )
        s.store.fix_evidence_cutoff(round_, schedule, observed_block=fixed_block)
        s.store.close_round(round_, current_block=fixed_block)
        entries = tuple(
            (
                signed,
                _independent(
                    s.policy,
                    signed,
                    round_,
                    suite,
                    attested(
                        result_for(signed, round_, suite).result.model_copy(
                            update={"finished_block": result_block}
                        )
                    ),
                ),
            )
            for signed in (s.model, s.endpoint)
        )
        for signed, independent in entries:
            s.store.record_independent_evaluation(
                signed=signed,
                evidence=independent,
                round_=round_,
                suite=suite,
                observed_block=round_.reveal_block,
            )
        return s.store.settle(
            round_=round_,
            suite=suite,
            evidence=entries,
            snapshot=snapshot(cutoff_block),
            current_block=cutoff_block,
        )

    older_suite = unique_suite(1_000)
    older_round = round_for(
        s.policy, older_suite, (s.model, s.endpoint), digest(s.baseline)
    ).model_copy(
        update={
            "sequence": 2,
            "submission_close_block": 130,
            "evaluation_close_block": 145,
            "reveal_block": 150,
            "valid_through_block": 200,
        }
    )
    older = close_and_settle(
        older_round,
        older_suite,
        fixed_block=130,
        result_block=140,
        cutoff_block=160,
    )
    assert older["promotion_head"]["sequence"] == 0

    promotion = s.store.promote(
        signed=s.model,
        attested=s.evaluation,
        round_=s.round,
        suite=s.suite,
        review=review_for(s.policy, s.model, s.round, s.evaluation),
        archive=s.archive,
        snapshot=snapshot(160),
        current_block=160,
    )
    downstream_suite = unique_suite(2_000)
    downstream_round = round_for(
        s.policy, downstream_suite, (s.model, s.endpoint), promotion["model_sha256"]
    ).model_copy(
        update={
            "sequence": 3,
            "submission_close_block": 170,
            "evaluation_close_block": 190,
            "reveal_block": 200,
            "valid_through_block": 250,
        }
    )
    downstream = close_and_settle(
        downstream_round,
        downstream_suite,
        fixed_block=170,
        result_block=180,
        cutoff_block=220,
    )
    assert downstream["promotion_head"]["sequence"] == promotion["sequence"] == 1

    conflict = result_for(s.model, s.round, s.suite, hypothesis="hell")
    assert (
        s.store.record_evaluation(
            signed=s.model,
            attested=conflict,
            round_=s.round,
            suite=s.suite,
            observed_block=221,
        )["conflicted"]
        is True
    )
    older_status = s.store.settlement_status(digest(older_round))
    downstream_status = s.store.settlement_status(digest(downstream_round))
    assert older_status is not None and older_status["disputed"] is False
    assert older_status["settlement"] == older
    assert downstream_status is not None and downstream_status["disputed"] is True
    assert downstream_status["dispute_detected_block"] == 221
    assert downstream_status["settlement"] == downstream

    s.store = CompetitionStore(s.store.directory, s.policy)
    assert s.store.settlement_status(digest(older_round))["disputed"] is False
    assert s.store.settlement_status(digest(downstream_round))["settlement"] == downstream


def test_settlement_transaction_failure_keeps_evidence_and_no_partial_record(
    policy, tmp_path, monkeypatch
):
    s = _scenario(policy, tmp_path)
    _record_all(s)
    original_project = competition_store.project_weights

    def fail_projection(**_kwargs):
        raise RuntimeError("injected projection failure")

    monkeypatch.setattr(competition_store, "project_weights", fail_projection)
    with pytest.raises(RuntimeError, match="injected"):
        _settle(s)
    assert s.store.settlement_status(digest(s.round)) is None
    with sqlite3.connect(s.store.path) as connection:
        assert connection.execute(
            "SELECT COUNT(*) FROM independent_evaluation_evidence"
        ).fetchone() == (2,)
        assert connection.execute("SELECT COUNT(*) FROM competition_settlements").fetchone() == (0,)
    monkeypatch.setattr(competition_store, "project_weights", original_project)
    assert _settle(s)["observed_block"] == 160


def test_simultaneous_settlement_retries_commit_one_identical_record(policy, tmp_path):
    s = _scenario(policy, tmp_path)
    _record_all(s)
    barrier = Barrier(2)

    def settle_together(_index):
        barrier.wait(timeout=10)
        return _settle(s)

    with ThreadPoolExecutor(max_workers=2) as executor:
        replies = list(executor.map(settle_together, range(2)))
    assert replies[0] == replies[1]
    with sqlite3.connect(s.store.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM competition_settlements").fetchone() == (1,)


def test_conflict_racing_settlement_is_blocked_or_marks_commit_disputed(policy, tmp_path):
    s = _scenario(policy, tmp_path)
    _record_all(s)
    signed = s.submissions[0]
    conflicting_attested = result_for(signed, s.round, s.suite, hypothesis="hell")
    conflicting = _independent(s.policy, signed, s.round, s.suite, conflicting_attested)
    barrier = Barrier(2)

    def try_settle():
        barrier.wait(timeout=10)
        try:
            return _settle(s)
        except ValueError as error:
            assert "conflict" in str(error)
            return None

    def record_conflict():
        barrier.wait(timeout=10)
        return s.store.record_independent_evaluation(
            signed=signed,
            evidence=conflicting,
            round_=s.round,
            suite=s.suite,
            observed_block=160,
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        settlement_future = executor.submit(try_settle)
        conflict_future = executor.submit(record_conflict)
        settlement = settlement_future.result(timeout=20)
        assert conflict_future.result(timeout=20)["result_sha256"] == digest(
            conflicting_attested.result
        )
    assert s.store.round_status(digest(s.round))["conflicted"] is True
    status = s.store.settlement_status(digest(s.round))
    if settlement is None:
        assert status is None
    else:
        assert status is not None and status["disputed"] is True
