from __future__ import annotations

import hashlib
import sqlite3
from types import SimpleNamespace

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_evidence import (
    EvaluatorRunRecord,
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
    sign_evaluator_run,
)
from umi.competition_publication import (
    PublicationCapacityError,
    PublicationJournal,
    PublicationJournalCapacity,
    PublicationReplayLimits,
    SettlementPublication,
    SignedCutoffPublication,
    SignedSettlementPublication,
    build_cutoff_publication,
    build_settlement_publication,
    cutoff_publication_digest,
    sign_cutoff_publication,
    sign_settlement_publication,
    verify_cutoff_publication,
    verify_settlement_publication,
)
from umi.competition_settlement import (
    CompetitionSettlement,
    EvidenceCutoffSchedule,
    competition_settlement_digest,
)
from umi.competition_store import CompetitionStore
from umi.open_competition import Evaluator, digest
from umi.protocol import canonical_json_bytes

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


@pytest.fixture
def replay_limits():
    return PublicationReplayLimits(
        maximum_roster_bytes=1_000_000,
        maximum_evidence_bytes=5_000_000,
        maximum_certificate_bytes=10_000_000,
    )


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


def _certificate(publication):
    if publication.schema_ == "umi-competition-cutoff-publication/1":
        signatures = tuple(
            sign_cutoff_publication(publication, wallet(name)) for name in ("Charlie", "Dave")
        )
        return SignedCutoffPublication(publication=publication, signatures=signatures)
    signatures = tuple(
        sign_settlement_publication(publication, wallet(name)) for name in ("Charlie", "Dave")
    )
    return SignedSettlementPublication(publication=publication, signatures=signatures)


def _scenario(
    policy,
    root,
    limits,
    *,
    settle=True,
    promote_model=True,
    snapshot_factory=snapshot,
    suite_factory=suite_for,
):
    archive = root / "archive"
    baseline = bundle_at(root / "baseline")
    candidate = bundle_at(root / "candidate", "candidate", digest(baseline))
    preserve_bundle(baseline, root / "baseline", archive, policy)
    preserve_bundle(candidate, root / "candidate", archive, policy)
    store = CompetitionStore(root / "state", policy)
    store.initialize_baseline(baseline, archive)

    model = submission(policy, bundle=candidate)
    endpoint = submission(policy, name="Bob")
    submissions = tuple(sorted((model, endpoint), key=lambda item: digest(item.submission)))
    for signed in submissions:
        store.admit(signed, snapshot_factory(), 110)

    suite = suite_factory(policy)
    round_ = round_for(policy, suite, submissions, digest(baseline))
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    store.fix_evidence_cutoff(round_, schedule, observed_block=120)
    store.close_round(round_, current_block=120)

    attested = tuple(result_for(signed, round_, suite) for signed in submissions)
    evidence = tuple(
        (signed, _independent(policy, signed, round_, suite, result))
        for signed, result in zip(submissions, attested, strict=True)
    )
    for signed, independent in evidence:
        store.record_independent_evaluation(
            signed=signed,
            evidence=independent,
            round_=round_,
            suite=suite,
            observed_block=150,
        )

    model_result = attested[submissions.index(model)]
    promotion = (
        store.promote(
            signed=model,
            attested=model_result,
            round_=round_,
            suite=suite,
            review=review_for(policy, model, round_, model_result),
            archive=archive,
            snapshot=snapshot_factory(150),
            current_block=150,
        )
        if promote_model
        else store.baseline()
    )
    cutoff_publication = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=schedule,
        registration_snapshot=snapshot_factory(round_.submission_close_block),
        submissions=submissions,
        policy=policy,
        limits=limits,
    )
    cutoff_certificate = _certificate(cutoff_publication)
    if not settle:
        return SimpleNamespace(
            policy=policy,
            store=store,
            round=round_,
            schedule=schedule,
            submissions=submissions,
            suite=suite,
            evidence=evidence,
            promotion=promotion,
            cutoff_certificate=cutoff_certificate,
        )
    settlement = CompetitionSettlement.model_validate_json(
        canonical_json_bytes(
            store.settle(
                round_=round_,
                suite=suite,
                evidence=evidence,
                snapshot=snapshot_factory(160),
                current_block=160,
            )
        ),
        strict=True,
    )
    settlement_publication = build_settlement_publication(
        cutoff_certificate=cutoff_certificate,
        retained_settlement=settlement,
        submissions=submissions,
        evidence=evidence,
        policy=policy,
        limits=limits,
    )
    settlement_certificate = _certificate(settlement_publication)
    return SimpleNamespace(
        policy=policy,
        store=store,
        round=round_,
        schedule=schedule,
        submissions=submissions,
        suite=suite,
        evidence=evidence,
        promotion=promotion,
        settlement=settlement,
        cutoff_publication=cutoff_publication,
        cutoff_certificate=cutoff_certificate,
        settlement_publication=settlement_publication,
        settlement_certificate=settlement_certificate,
    )


def _alternate_cutoff_certificate(scenario, policy, limits, *, cutoff_block, round_=None):
    round_ = scenario.round if round_ is None else round_
    schedule = scenario.schedule.model_copy(
        update={
            "round_sha256": digest(round_),
        }
    )
    alternate_snapshot = snapshot(round_.submission_close_block).model_copy(
        update={"block_hash": "0x" + f"{cutoff_block:064x}"}
    )
    publication = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=schedule,
        registration_snapshot=alternate_snapshot,
        submissions=scenario.submissions,
        policy=policy,
        limits=limits,
    )
    return _certificate(publication)


def test_real_store_promotion_and_70_30_settlement_replay(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)

    verified_cutoff = verify_cutoff_publication(
        scenario.cutoff_certificate,
        policy=policy,
        submissions=tuple(reversed(scenario.submissions)),
        limits=replay_limits,
    )
    verified_settlement = verify_settlement_publication(
        scenario.settlement_certificate,
        cutoff_certificate=scenario.cutoff_certificate,
        policy=policy,
        submissions=tuple(reversed(scenario.submissions)),
        evidence=tuple(reversed(scenario.evidence)),
        retained_settlement=scenario.settlement,
        limits=replay_limits,
    )

    assert verified_cutoff == scenario.cutoff_publication
    assert verified_settlement == scenario.settlement_publication
    assert scenario.round.incumbent_model_sha256 != scenario.promotion["model_sha256"]
    assert scenario.settlement.promotion_head.sequence == 1
    assert scenario.settlement.promotion_head.model_sha256 == scenario.promotion["model_sha256"]
    allocations = {item.uid: item.raw_weight for item in scenario.settlement.projection.allocations}
    assert allocations == {6: 19_661, 247: 45_874}
    assert verified_settlement.chain_submission_authorized is False
    assert verified_settlement.finalized_receipt_timing_proven is False
    assert verified_settlement.global_conflict_absence_proven is False


def test_modified_body_cannot_reuse_valid_signatures(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)
    alternate_snapshot = snapshot(120).model_copy(update={"block_hash": "0x" + "11" * 32})
    alternate_publication = build_cutoff_publication(
        round_=scenario.round,
        cutoff_schedule=scenario.schedule,
        registration_snapshot=alternate_snapshot,
        submissions=scenario.submissions,
        policy=policy,
        limits=replay_limits,
    )
    forged = SignedCutoffPublication(
        publication=alternate_publication,
        signatures=scenario.cutoff_certificate.signatures,
    )
    with pytest.raises(ValueError, match="invalid publication signature"):
        verify_cutoff_publication(
            forged,
            policy=policy,
            submissions=scenario.submissions,
            limits=replay_limits,
        )


def test_publication_signers_must_form_independent_nonself_quorum(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)
    duplicate = SignedCutoffPublication(
        publication=scenario.cutoff_publication,
        signatures=(
            sign_cutoff_publication(scenario.cutoff_publication, wallet("Charlie")),
            sign_cutoff_publication(scenario.cutoff_publication, wallet("Charlie")),
        ),
    )
    with pytest.raises(ValueError, match="duplicate publication signer"):
        verify_cutoff_publication(
            duplicate,
            policy=policy,
            submissions=scenario.submissions,
            limits=replay_limits,
        )

    unauthorized = SignedCutoffPublication(
        publication=scenario.cutoff_publication,
        signatures=(
            sign_cutoff_publication(scenario.cutoff_publication, wallet("Charlie")),
            sign_cutoff_publication(scenario.cutoff_publication, wallet("Mallory")),
        ),
    )
    with pytest.raises(ValueError, match="unauthorized"):
        verify_cutoff_publication(
            unauthorized,
            policy=policy,
            submissions=scenario.submissions,
            limits=replay_limits,
        )


def test_same_control_group_and_roster_signer_cannot_form_publication_quorum(policy, replay_limits):
    grouped_policy = policy.model_copy(
        update={
            "evaluators": (
                Evaluator(
                    hotkey=wallet("Charlie").hotkey.ss58_address,
                    control_group="shared",
                ),
                Evaluator(
                    hotkey=wallet("Eve").hotkey.ss58_address,
                    control_group="shared",
                ),
                Evaluator(
                    hotkey=wallet("Dave").hotkey.ss58_address,
                    control_group="other",
                ),
            )
        }
    )
    submissions = tuple(
        sorted(
            (submission(grouped_policy), submission(grouped_policy, name="Bob")),
            key=lambda item: digest(item.submission),
        )
    )
    suite = suite_for(grouped_policy)
    round_ = round_for(grouped_policy, suite, submissions)
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(grouped_policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=160,
    )
    publication = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=schedule,
        registration_snapshot=snapshot(round_.submission_close_block),
        submissions=submissions,
        policy=grouped_policy,
        limits=replay_limits,
    )
    grouped = SignedCutoffPublication(
        publication=publication,
        signatures=tuple(
            sign_cutoff_publication(publication, wallet(name)) for name in ("Charlie", "Eve")
        ),
    )
    with pytest.raises(ValueError, match="duplicate publication signer"):
        verify_cutoff_publication(
            grouped,
            policy=grouped_policy,
            submissions=submissions,
            limits=replay_limits,
        )

    self_policy = policy.model_copy(
        update={
            "evaluators": (
                Evaluator(
                    hotkey=wallet("Alice").hotkey.ss58_address,
                    control_group="submitter",
                ),
                Evaluator(
                    hotkey=wallet("Dave").hotkey.ss58_address,
                    control_group="other",
                ),
            )
        }
    )
    self_submissions = tuple(
        sorted(
            (submission(self_policy), submission(self_policy, name="Bob")),
            key=lambda item: digest(item.submission),
        )
    )
    self_suite = suite_for(self_policy)
    self_round = round_for(self_policy, self_suite, self_submissions)
    self_schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(self_policy),
        round_sha256=digest(self_round),
        evidence_cutoff_block=160,
    )
    self_publication = build_cutoff_publication(
        round_=self_round,
        cutoff_schedule=self_schedule,
        registration_snapshot=snapshot(self_round.submission_close_block),
        submissions=self_submissions,
        policy=self_policy,
        limits=replay_limits,
    )
    self_signed = SignedCutoffPublication(
        publication=self_publication,
        signatures=tuple(
            sign_cutoff_publication(self_publication, wallet(name)) for name in ("Alice", "Dave")
        ),
    )
    with pytest.raises(ValueError, match="self-interested"):
        verify_cutoff_publication(
            self_signed,
            policy=self_policy,
            submissions=self_submissions,
            limits=replay_limits,
        )


def test_settlement_quorum_excludes_absent_incumbent_beneficiary_group(
    policy, replay_limits, tmp_path
):
    beneficiary_policy = policy.model_copy(
        update={
            "evaluators": (
                Evaluator(
                    hotkey=wallet("Alice").hotkey.ss58_address,
                    control_group="beneficiary",
                ),
                Evaluator(
                    hotkey=wallet("Eve").hotkey.ss58_address,
                    control_group="beneficiary",
                ),
                Evaluator(
                    hotkey=wallet("Charlie").hotkey.ss58_address,
                    control_group="independent-c",
                ),
                Evaluator(
                    hotkey=wallet("Dave").hotkey.ss58_address,
                    control_group="independent-d",
                ),
            )
        }
    )
    archive = tmp_path / "archive"
    baseline = bundle_at(tmp_path / "baseline")
    candidate = bundle_at(tmp_path / "candidate", "candidate", digest(baseline))
    preserve_bundle(baseline, tmp_path / "baseline", archive, beneficiary_policy)
    preserve_bundle(candidate, tmp_path / "candidate", archive, beneficiary_policy)
    store = CompetitionStore(tmp_path / "state", beneficiary_policy)
    store.initialize_baseline(baseline, archive)
    model = submission(beneficiary_policy, bundle=candidate)
    endpoint = submission(beneficiary_policy, name="Bob")
    for signed in (model, endpoint):
        store.admit(signed, snapshot(), 110)

    promotion_suite = suite_for(beneficiary_policy)
    promotion_round = round_for(
        beneficiary_policy,
        promotion_suite,
        (model, endpoint),
        digest(baseline),
    )
    store.close_round(promotion_round, current_block=120)
    promotion_result = result_for(model, promotion_round, promotion_suite)
    promotion = store.promote(
        signed=model,
        attested=promotion_result,
        round_=promotion_round,
        suite=promotion_suite,
        review=review_for(
            beneficiary_policy,
            model,
            promotion_round,
            promotion_result,
        ),
        archive=archive,
        snapshot=snapshot(150),
        current_block=150,
    )
    retired_model = submission(
        beneficiary_policy,
        bundle=candidate,
        sequence=2,
        start=155,
        end=175,
    )
    store.admit(retired_model, snapshot(155), 155)

    suite = promotion_suite.model_copy(
        update={
            "cases": tuple(
                case.model_copy(update={"video_sha256": f"{index + 1_000:064x}"})
                for index, case in enumerate(promotion_suite.cases)
            )
        }
    )
    round_ = round_for(
        beneficiary_policy,
        suite,
        (endpoint,),
        promotion["model_sha256"],
    ).model_copy(
        update={
            "sequence": 2,
            "public_schedule": round_for(
                beneficiary_policy,
                suite,
                (endpoint,),
                promotion["model_sha256"],
            ).public_schedule.model_copy(
                update={
                    "roster_close_earliest_block": 170,
                    "roster_close_latest_block": 170,
                    "work_signing_close_block": 180,
                    "evaluation_close_block": 190,
                    "protected_reference_reveal_block": 200,
                    "evidence_cutoff_block": 220,
                    "round_valid_through_block": 250,
                }
            ),
            "submission_close_block": 170,
            "evaluation_close_block": 190,
            "reveal_block": 200,
            "valid_through_block": 250,
        }
    )
    schedule = EvidenceCutoffSchedule(
        schema="umi-competition-evidence-cutoff/1",
        policy_sha256=digest(beneficiary_policy),
        round_sha256=digest(round_),
        evidence_cutoff_block=220,
    )
    store.fix_evidence_cutoff(round_, schedule, observed_block=170)
    store.close_round(round_, current_block=170)
    common_result = result_for(endpoint, round_, suite, baseline="hello").result.model_copy(
        update={"finished_block": 180}
    )
    common = attested(common_result)
    evidence = ((endpoint, _independent(beneficiary_policy, endpoint, round_, suite, common)),)
    store.record_independent_evaluation(
        signed=endpoint,
        evidence=evidence[0][1],
        round_=round_,
        suite=suite,
        observed_block=200,
    )
    settlement = CompetitionSettlement.model_validate_json(
        canonical_json_bytes(
            store.settle(
                round_=round_,
                suite=suite,
                evidence=evidence,
                snapshot=snapshot(220),
                current_block=220,
            )
        ),
        strict=True,
    )
    assert {item.hotkey for item in settlement.projection.allocations} == {
        wallet("Alice").hotkey.ss58_address,
        wallet("Bob").hotkey.ss58_address,
    }
    cutoff_publication = build_cutoff_publication(
        round_=round_,
        cutoff_schedule=schedule,
        registration_snapshot=snapshot(170),
        submissions=(endpoint,),
        policy=beneficiary_policy,
        limits=replay_limits,
    )
    cutoff_certificate = SignedCutoffPublication(
        publication=cutoff_publication,
        signatures=tuple(
            sign_cutoff_publication(cutoff_publication, wallet(name)) for name in ("Eve", "Dave")
        ),
    )
    verify_cutoff_publication(
        cutoff_certificate,
        policy=beneficiary_policy,
        submissions=(endpoint,),
        limits=replay_limits,
    )
    settlement_publication = build_settlement_publication(
        cutoff_certificate=cutoff_certificate,
        retained_settlement=settlement,
        submissions=(endpoint,),
        evidence=evidence,
        policy=beneficiary_policy,
        limits=replay_limits,
    )
    independent_certificate = SignedSettlementPublication(
        publication=settlement_publication,
        signatures=tuple(
            sign_settlement_publication(settlement_publication, wallet(name))
            for name in ("Charlie", "Dave")
        ),
    )
    verify_settlement_publication(
        independent_certificate,
        cutoff_certificate=cutoff_certificate,
        policy=beneficiary_policy,
        submissions=(endpoint,),
        evidence=evidence,
        retained_settlement=settlement,
        limits=replay_limits,
    )

    beneficiary_group_certificate = SignedSettlementPublication(
        publication=settlement_publication,
        signatures=tuple(
            sign_settlement_publication(settlement_publication, wallet(name))
            for name in ("Eve", "Dave")
        ),
    )
    with pytest.raises(ValueError, match="self-interested"):
        verify_settlement_publication(
            beneficiary_group_certificate,
            cutoff_certificate=cutoff_certificate,
            policy=beneficiary_policy,
            submissions=(endpoint,),
            evidence=evidence,
            retained_settlement=settlement,
            limits=replay_limits,
        )


def test_exact_roster_registration_and_evidence_are_required(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)
    with pytest.raises(ValueError, match="exact complete round roster"):
        verify_cutoff_publication(
            scenario.cutoff_certificate,
            policy=policy,
            submissions=scenario.submissions[:1],
            limits=replay_limits,
        )
    with pytest.raises(ValueError, match="complete roster"):
        verify_settlement_publication(
            scenario.settlement_certificate,
            cutoff_certificate=scenario.cutoff_certificate,
            policy=policy,
            submissions=scenario.submissions,
            evidence=scenario.evidence[:1],
            retained_settlement=scenario.settlement,
            limits=replay_limits,
        )

    unknown_snapshot = snapshot(scenario.round.submission_close_block).model_copy(
        update={"registrations": ()}
    )
    with pytest.raises(ValueError, match="not registered"):
        build_cutoff_publication(
            round_=scenario.round,
            cutoff_schedule=scenario.schedule,
            registration_snapshot=unknown_snapshot,
            submissions=scenario.submissions,
            policy=policy,
            limits=replay_limits,
        )


def test_arbitrary_projection_is_not_verified_as_retained_state(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)
    projection = scenario.settlement.projection.model_copy(
        update={"weights": tuple(reversed(scenario.settlement.projection.weights))}
    )
    altered_settlement = scenario.settlement.model_copy(update={"projection": projection})
    altered_publication = SettlementPublication(
        schema="umi-competition-settlement-publication/1",
        policy_sha256=digest(policy),
        round_sha256=digest(scenario.round),
        runtime_sha256=scenario.round.runtime_sha256,
        round=scenario.round,
        settlement_sha256=competition_settlement_digest(altered_settlement),
        settlement=altered_settlement,
        cutoff_publication_sha256=cutoff_publication_digest(scenario.cutoff_publication),
        authenticated_roster_sha256=(scenario.settlement_publication.authenticated_roster_sha256),
        independent_evidence_set_sha256=(
            scenario.settlement_publication.independent_evidence_set_sha256
        ),
        projection_sha256=digest(projection),
        promotion_head_sha256=digest(altered_settlement.promotion_head),
    )
    altered_certificate = _certificate(altered_publication)
    with pytest.raises(ValueError, match="deterministic replay"):
        verify_settlement_publication(
            altered_certificate,
            cutoff_certificate=scenario.cutoff_certificate,
            policy=policy,
            submissions=scenario.submissions,
            evidence=scenario.evidence,
            retained_settlement=altered_settlement,
            limits=replay_limits,
        )


def test_replay_input_limits_are_enforced_before_acceptance(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)
    tiny = replay_limits.model_copy(
        update={
            "maximum_roster_bytes": 1,
            "maximum_evidence_bytes": 1,
            "maximum_certificate_bytes": 1,
        }
    )
    with pytest.raises(ValueError, match="certificate exceeds"):
        verify_cutoff_publication(
            scenario.cutoff_certificate,
            policy=policy,
            submissions=scenario.submissions,
            limits=tiny,
        )


def test_journal_is_idempotent_and_conflict_hold_survives_restart(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    directory = tmp_path / "publication"
    capacity = PublicationJournalCapacity(
        maximum_certificates=20,
        maximum_bytes=50_000_000,
    )
    journal = PublicationJournal(directory, policy, capacity=capacity)
    first = journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    assert first["held"] is False
    assert (
        journal.record_cutoff(
            scenario.cutoff_certificate,
            submissions=scenario.submissions,
            limits=replay_limits,
        )
        == first
    )
    settled = journal.record_settlement(
        scenario.settlement_certificate,
        cutoff_certificate=scenario.cutoff_certificate,
        submissions=scenario.submissions,
        evidence=scenario.evidence,
        retained_settlement=scenario.settlement,
        limits=replay_limits,
    )
    assert settled["held"] is False

    reversed_signatures = SignedCutoffPublication(
        publication=scenario.cutoff_publication,
        signatures=tuple(reversed(scenario.cutoff_certificate.signatures)),
    )
    same_body = journal.record_cutoff(
        reversed_signatures,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    assert same_body["held"] is False

    equivalent_settlement = build_settlement_publication(
        cutoff_certificate=reversed_signatures,
        retained_settlement=scenario.settlement,
        submissions=scenario.submissions,
        evidence=scenario.evidence,
        policy=policy,
        limits=replay_limits,
    )
    assert equivalent_settlement == scenario.settlement_publication
    equivalent_settlement_certificate = SignedSettlementPublication(
        publication=equivalent_settlement,
        signatures=tuple(reversed(scenario.settlement_certificate.signatures)),
    )
    equivalent_status = journal.record_settlement(
        equivalent_settlement_certificate,
        cutoff_certificate=reversed_signatures,
        submissions=scenario.submissions,
        evidence=scenario.evidence,
        retained_settlement=scenario.settlement,
        limits=replay_limits,
    )
    assert equivalent_status["held"] is False
    assert equivalent_status["conflicts"] == []

    alternate_snapshot = snapshot(scenario.round.submission_close_block).model_copy(
        update={"block_hash": "0x" + "ab" * 32}
    )
    alternate_publication = build_cutoff_publication(
        round_=scenario.round,
        cutoff_schedule=scenario.schedule,
        registration_snapshot=alternate_snapshot,
        submissions=scenario.submissions,
        policy=policy,
        limits=replay_limits,
    )
    alternate_certificate = _certificate(alternate_publication)
    conflict = journal.record_cutoff(
        alternate_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    assert conflict["held"] is True
    assert conflict["halt_reason"] is None
    assert len(conflict["conflicts"]) == 1
    assert conflict["chain_submission_authorized"] is False

    restarted = PublicationJournal(directory, policy, capacity=capacity)
    status = restarted.round_status(digest(scenario.round))
    assert status["held"] is True
    assert status["conflicts"] == conflict["conflicts"]
    assert status["usage"] == conflict["usage"]


def test_journal_requires_retained_cutoff_and_halts_durably_at_capacity(
    policy, replay_limits, tmp_path
):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    no_cutoff = PublicationJournal(
        tmp_path / "empty",
        policy,
        capacity=PublicationJournalCapacity(
            maximum_certificates=10,
            maximum_bytes=50_000_000,
        ),
    )
    with pytest.raises(ValueError, match="cutoff publication is not retained"):
        no_cutoff.record_settlement(
            scenario.settlement_certificate,
            cutoff_certificate=scenario.cutoff_certificate,
            submissions=scenario.submissions,
            evidence=scenario.evidence,
            retained_settlement=scenario.settlement,
            limits=replay_limits,
        )

    directory = tmp_path / "full"
    capacity = PublicationJournalCapacity(maximum_certificates=1, maximum_bytes=50_000_000)
    journal = PublicationJournal(directory, policy, capacity=capacity)
    original = journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    with pytest.raises(PublicationCapacityError, match="capacity"):
        journal.record_cutoff(
            SignedCutoffPublication(
                publication=scenario.cutoff_publication,
                signatures=tuple(reversed(scenario.cutoff_certificate.signatures)),
            ),
            submissions=scenario.submissions,
            limits=replay_limits,
        )
    assert (
        journal.record_cutoff(
            scenario.cutoff_certificate,
            submissions=scenario.submissions,
            limits=replay_limits,
        )["usage"]
        == original["usage"]
    )
    restarted = PublicationJournal(directory, policy, capacity=capacity)
    status = restarted.round_status(digest(scenario.round))
    assert status["held"] is True
    assert status["halt_reason"] == "capacity_exhausted"
    assert status["usage"]["certificates"] == 1


def test_journal_holds_both_rounds_on_same_sequence_equivocation(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    directory = tmp_path / "publication"
    capacity = PublicationJournalCapacity(
        maximum_certificates=20,
        maximum_bytes=50_000_000,
    )
    journal = PublicationJournal(directory, policy, capacity=capacity)
    journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )

    alternate_round = scenario.round.model_copy(update={"incumbent_model_sha256": "ef" * 32})
    alternate_schedule = scenario.schedule.model_copy(
        update={"round_sha256": digest(alternate_round)}
    )
    alternate_publication = build_cutoff_publication(
        round_=alternate_round,
        cutoff_schedule=alternate_schedule,
        registration_snapshot=snapshot(alternate_round.submission_close_block),
        submissions=scenario.submissions,
        policy=policy,
        limits=replay_limits,
    )
    alternate_certificate = _certificate(alternate_publication)
    alternate_status = journal.record_cutoff(
        alternate_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    original_status = journal.round_status(digest(scenario.round))
    assert alternate_status["held"] is True
    assert original_status["held"] is True
    assert (
        alternate_status["round_sequence_conflicts"]
        == (original_status["round_sequence_conflicts"])
    )
    assert len(original_status["round_sequence_conflicts"]) == 1
    assert original_status["round_sequence_conflicts"][0]["round_sequence"] == 1

    restarted = PublicationJournal(directory, policy, capacity=capacity)
    assert restarted.round_status(digest(scenario.round))["held"] is True
    assert restarted.round_status(digest(alternate_round))["held"] is True


def test_journal_repairs_missing_head_before_live_conflicting_record(
    policy, replay_limits, tmp_path
):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    directory = tmp_path / "publication"
    capacity = PublicationJournalCapacity(
        maximum_certificates=20,
        maximum_bytes=50_000_000,
    )
    journal = PublicationJournal(directory, policy, capacity=capacity)
    journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    original_publication = cutoff_publication_digest(scenario.cutoff_publication)
    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM publication_heads WHERE kind='cutoff'")

    alternate = _alternate_cutoff_certificate(
        scenario,
        policy,
        replay_limits,
        cutoff_block=170,
    )
    status = journal.record_cutoff(
        alternate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    assert status["held"] is True
    assert len(status["conflicts"]) == 1
    assert status["conflicts"][0]["first_publication_sha256"] == original_publication

    # The retained conflict summary recovers the original choice on restart.
    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM publication_heads WHERE kind='cutoff'")
    restarted = PublicationJournal(directory, policy, capacity=capacity)
    assert restarted.round_status(digest(scenario.round))["conflicts"] == status["conflicts"]


def test_journal_repairs_missing_round_binding_and_conflict_summary(
    policy, replay_limits, tmp_path
):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    directory = tmp_path / "publication"
    capacity = PublicationJournalCapacity(
        maximum_certificates=20,
        maximum_bytes=50_000_000,
    )
    journal = PublicationJournal(directory, policy, capacity=capacity)
    journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM round_bindings WHERE round_sequence=1")

    alternate_round = scenario.round.model_copy(update={"incumbent_model_sha256": "ef" * 32})
    alternate = _alternate_cutoff_certificate(
        scenario,
        policy,
        replay_limits,
        cutoff_block=160,
        round_=alternate_round,
    )
    alternate_status = journal.record_cutoff(
        alternate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    assert alternate_status["held"] is True
    assert len(alternate_status["round_sequence_conflicts"]) == 1

    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM round_sequence_conflicts WHERE round_sequence=1")
    original_status = journal.round_status(digest(scenario.round))
    assert original_status["held"] is True
    assert len(original_status["round_sequence_conflicts"]) == 1

    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM round_bindings WHERE round_sequence=1")
    restarted = PublicationJournal(directory, policy, capacity=capacity)
    assert (
        restarted.round_status(digest(scenario.round))["round_sequence_conflicts"]
        == (original_status["round_sequence_conflicts"])
    )
    assert restarted.round_status(digest(alternate_round))["held"] is True


def test_journal_rehydrates_complete_conflict_summary_live_and_on_restart(
    policy, replay_limits, tmp_path
):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    directory = tmp_path / "publication"
    capacity = PublicationJournalCapacity(
        maximum_certificates=20,
        maximum_bytes=50_000_000,
    )
    journal = PublicationJournal(directory, policy, capacity=capacity)
    for certificate in (
        scenario.cutoff_certificate,
        _alternate_cutoff_certificate(
            scenario,
            policy,
            replay_limits,
            cutoff_block=170,
        ),
        _alternate_cutoff_certificate(
            scenario,
            policy,
            replay_limits,
            cutoff_block=180,
        ),
    ):
        expected = journal.record_cutoff(
            certificate,
            submissions=scenario.submissions,
            limits=replay_limits,
        )
    assert len(expected["conflicts"]) == 2

    missing_other = expected["conflicts"][0]["other_publication_sha256"]
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "DELETE FROM publication_conflicts WHERE kind='cutoff' AND other_publication=?",
            (missing_other,),
        )
    live = journal.round_status(digest(scenario.round))
    assert live["held"] is True
    assert live["conflicts"] == expected["conflicts"]

    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM publication_conflicts WHERE kind='cutoff'")
    assert journal.round_status(digest(scenario.round))["conflicts"] == expected["conflicts"]

    with sqlite3.connect(journal.path) as connection:
        connection.execute("DELETE FROM publication_conflicts WHERE kind='cutoff'")
    restarted = PublicationJournal(directory, policy, capacity=capacity)
    assert restarted.round_status(digest(scenario.round))["conflicts"] == expected["conflicts"]


def test_journal_rejects_live_usage_ledger_mismatch_before_append(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    journal = PublicationJournal(
        tmp_path / "publication",
        policy,
        capacity=PublicationJournalCapacity(
            maximum_certificates=20,
            maximum_bytes=50_000_000,
        ),
    )
    journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    with sqlite3.connect(journal.path) as connection:
        connection.execute(
            "UPDATE publication_usage SET records=0, payload_bytes=0 WHERE singleton=1"
        )

    alternate = _alternate_cutoff_certificate(
        scenario,
        policy,
        replay_limits,
        cutoff_block=170,
    )
    with pytest.raises(ValueError, match="usage ledger is corrupt"):
        journal.record_cutoff(
            alternate,
            submissions=scenario.submissions,
            limits=replay_limits,
        )
    with sqlite3.connect(journal.path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM certificates").fetchone()[0] == 1


def test_journal_detects_retained_body_corruption(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path / "scenario", replay_limits)
    directory = tmp_path / "publication"
    journal = PublicationJournal(
        directory,
        policy,
        capacity=PublicationJournalCapacity(
            maximum_certificates=10,
            maximum_bytes=50_000_000,
        ),
    )
    journal.record_cutoff(
        scenario.cutoff_certificate,
        submissions=scenario.submissions,
        limits=replay_limits,
    )
    with sqlite3.connect(journal.path) as connection:
        connection.execute("UPDATE certificates SET body=?", (canonical_json_bytes({"x": 1}),))
    with pytest.raises(ValueError):
        journal.round_status(digest(scenario.round))


def test_publication_digest_is_domain_separated(policy, replay_limits, tmp_path):
    scenario = _scenario(policy, tmp_path, replay_limits)
    assert cutoff_publication_digest(scenario.cutoff_publication) != digest(
        scenario.cutoff_publication
    )
