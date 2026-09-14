"""Mixed-outcome settlement fixtures, never production scores or rights approval."""

from __future__ import annotations

from fractions import Fraction

import pytest

from umi import competition_execution as execution
from umi.competition_artifacts import preserve_bundle
from umi.competition_package import CompetitionPackageEvidence, _evidence
from umi.competition_publication import build_cutoff_publication, build_settlement_publication
from umi.competition_settlement import CompetitionSettlement, EvidenceCutoffSchedule
from umi.competition_settlement_preparation import SettlementPreparation, validate_preparation
from umi.competition_store import CompetitionStore, SettlementNotReadyError
from umi.competition_void import VoidEvaluationEvidence
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import signed_order
from .test_competition_execution import policy as policy
from .test_competition_execution import run_job
from .test_competition_execution import runtime as runtime
from .test_competition_execution import setup as setup
from .test_competition_publication import _certificate, _independent
from .test_competition_publication import replay_limits as replay_limits
from .test_competition_void import announce, certify
from .test_open_competition import (
    bundle_at,
    result_for,
    review_for,
    round_for,
    snapshot,
    submission,
    wallet,
)


@pytest.fixture
async def mixed(setup, tmp_path, monkeypatch, replay_limits):
    policy, job, suite, archive, _, _ = setup
    winner = bundle_at(tmp_path / "winner", "winner", digest(job.incumbent))
    preserve_bundle(winner, tmp_path / "winner", archive, policy)
    model = submission(policy, name="Bob", bundle=winner)
    endpoint = submission(policy)
    submissions = tuple(
        sorted((job.submission, model, endpoint), key=lambda s: digest(s.submission))
    )
    round_ = round_for(policy, suite, submissions, digest(job.incumbent))
    job = job.model_copy(update={"round": round_})
    signers = (wallet("Charlie"), wallet("Dave"))
    order = signed_order(job, signers)
    original = execution.execute_offline_case

    async def failure(**kwargs):
        value = await original(**kwargs)
        if digest(kwargs["bundle"]) == digest(job.incumbent):
            return value.model_copy(
                update={
                    "reason": "process_failed",
                    "returncode": 1,
                    "stdout_hex": "",
                    "output": value.output.model_copy(
                        update={"status": "miner_failure", "hypothesis": ""}
                    ),
                }
            )
        return value

    monkeypatch.setattr(execution, "execute_offline_case", failure)
    observations = []
    for i, signer in enumerate(signers):
        attempt = job.model_copy(update={"evaluator_hotkey": signer.hotkey.ss58_address})
        evidence, _ = await run_job(setup, tmp_path, name=f"void-{i}", job=attempt)
        observations.append(announce(evidence, order, signer))
    context = dict(signed_order=order, suite=suite, policy=policy, current_block=150)
    void = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/1",
        order=order,
        legacy_policy=None,
        certificate=certify(context, tuple(observations), signers),
    )
    store = CompetitionStore(tmp_path / "intake", policy)
    store.initialize_baseline(job.incumbent, archive)
    for s in submissions:
        store.admit(s, snapshot(), 110)
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    store.fix_evidence_cutoff(round_, schedule, observed_block=120)
    store.close_round(round_, current_block=120)
    pairs = [(job.submission, void)]
    for s in (endpoint, model):
        result = result_for(s, round_, suite)
        evidence = _independent(policy, s, round_, suite, result)
        store.record_independent_evaluation(
            signed=s, evidence=evidence, round_=round_, suite=suite, observed_block=150
        )
        pairs.append((s, evidence))
    model_result = pairs[-1][1].attested_result
    store.promote(
        signed=model,
        attested=model_result,
        round_=round_,
        suite=suite,
        review=review_for(policy, model, round_, model_result),
        archive=archive,
        snapshot=snapshot(150),
        current_block=150,
    )
    pairs.sort(key=lambda pair: digest(pair[0].submission))
    cutoff = _certificate(
        build_cutoff_publication(
            round_=round_,
            cutoff_schedule=schedule,
            registration_snapshot=snapshot(120),
            submissions=submissions,
            policy=policy,
            limits=replay_limits,
        )
    )
    return store, round_, suite, submissions, tuple(pairs), void, cutoff


async def test_full_roster_with_void_preserves_70_30_and_replays_package(mixed, replay_limits):
    from umi.competition_package import CompetitionPackageRoster

    store, round_, suite, submissions, pairs, void, cutoff = mixed
    receipt = store.record_void_evaluation(evidence=void, suite=suite, observed_block=150)
    material = store.settlement_material(round_, limits=replay_limits)
    assert material["evidence"] == pairs
    result = store.settle(
        round_=round_, suite=suite, evidence=pairs, snapshot=snapshot(160), current_block=160
    )
    settlement = CompetitionSettlement.model_validate_json(canonical_json_bytes(result))
    assert settlement.schema_ == "umi-competition-settlement/2"
    assert settlement.roster == round_.roster and len(settlement.results) == 3
    shares = {
        a.uid: Fraction(int(a.numerator), int(a.denominator))
        for a in settlement.projection.allocations
    }
    assert shares == {6: Fraction(7, 10), 247: Fraction(3, 10)}
    bound = next(
        b
        for b in settlement.results
        if b.submission_sha256 == digest(void.order.order.submission.submission)
    )
    assert bound.void_evidence_sha256 == receipt["void_evidence_sha256"]
    assert not settlement.chain_submission_authorized
    prepared = SettlementPreparation(
        schema="umi-settlement-preparation/1",
        cutoff=cutoff,
        publication=build_settlement_publication(
            cutoff_certificate=cutoff,
            retained_settlement=settlement,
            submissions=submissions,
            evidence=pairs,
            policy=store.policy,
            limits=replay_limits,
        ),
        roster=CompetitionPackageRoster(
            schema="umi-competition-replay-roster/1", submissions=submissions
        ),
        evidence=_evidence(pairs),
    )
    assert prepared.evidence.schema_ == "umi-competition-replay-evidence/2"
    assert validate_preparation(prepared, store.policy, replay_limits) == prepared
    old = prepared.evidence.model_copy(update={"schema_": "umi-competition-replay-evidence/1"})
    with pytest.raises(ValueError, match="version 2"):
        CompetitionPackageEvidence.model_validate_json(canonical_json_bytes(old))
    restored = CompetitionStore(store.directory, store.policy)
    assert (
        restored.settle(
            round_=round_, suite=suite, evidence=pairs, snapshot=snapshot(160), current_block=170
        )
        == result
    )
    assert (
        restored.settlement_material(round_, limits=replay_limits)["retained_settlement"]
        == settlement
    )


@pytest.mark.parametrize("late", [False, True])
async def test_missing_or_late_void_cannot_shrink_the_roster(mixed, replay_limits, late):
    store, round_, suite, _, pairs, void, _ = mixed
    if late:
        store.record_void_evaluation(evidence=void, suite=suite, observed_block=161)
    with pytest.raises(SettlementNotReadyError):
        store.settlement_material(round_, limits=replay_limits)
    with pytest.raises(ValueError, match="first observed after cutoff"):
        store.settle(
            round_=round_, suite=suite, evidence=pairs, snapshot=snapshot(170), current_block=170
        )
    assert store.settlement_status(digest(round_)) is None


@pytest.mark.parametrize("void_first", [False, True])
async def test_scored_and_void_for_same_slot_hold_settlement_in_either_order(mixed, void_first):
    store, round_, suite, _, _, void, _ = mixed
    signed = void.order.order.submission
    scored = result_for(signed, round_, suite)
    operations = [
        lambda: store.record_void_evaluation(evidence=void, suite=suite, observed_block=150),
        lambda: store.record_evaluation(
            signed=signed, attested=scored, round_=round_, suite=suite, observed_block=150
        ),
    ]
    if not void_first:
        operations.reverse()
    first, second = (op() for op in operations)
    assert not first["conflicted"] and second["conflicted"]
