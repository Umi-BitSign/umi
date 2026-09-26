"""A complete round must retain the original sealed participant set."""

from fractions import Fraction

import pytest

from umi.competition_cohort_coordinator import (
    AttestedCohortPhaseProgress,
    CohortDecisionInput,
    CohortPhaseProgress,
)
from umi.competition_cohort_disposition import RecoverableOrderedOutcome, RecoverableVoidEvidence
from umi.competition_cohort_evaluation import RecoverableRoundParticipant
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_intake_records import RetainedCohortParticipation
from umi.competition_cohort_intake_seal import build_intake_seal
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
    admit_recovery_participant,
)
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.competition_cohort_roster import (
    IncompleteRecoverableCohort,
    RecoverableRosterEvidence,
    RecoverableRosterParticipant,
    replay_recoverable_roster_outcomes,
    verify_recoverable_roster,
)
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_disposition import certificate, order
from .test_competition_cohort_execution import base_policy as base_policy
from .test_competition_cohort_execution import bundle_evidence
from .test_competition_cohort_execution import legacy_scenario as legacy_scenario
from .test_competition_cohort_execution import policy as policy
from .test_competition_cohort_execution import receipt_scenario as receipt_scenario
from .test_competition_cohort_execution import recovery as recovery
from .test_competition_cohort_execution import runtime as runtime
from .test_competition_cohort_execution import scenario as scenario
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_execution import boundary
from .test_open_competition import attested, result_for, snapshot, submission, wallet


def close(history, policy, decisions, block, result_hash, *, unavailable=0):
    state = verify_cohort_history(
        history, policy, expected_tip_sha256=tip(history), current_block=block
    ).state
    progress = CohortPhaseProgress(
        schema="umi-cohort-phase-progress/1",
        cohort_sha256=digest(history.plan),
        recovery_tip_sha256=tip(history),
        phase=state.phase,
        observed_at_block=block,
        unavailable_blocks=unavailable,
        completion="complete",
        phase_result_sha256=result_hash,
        evidence_sha256=result_hash,
    )
    evidence = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress)),
        observation=boundary(block),
    )
    decision = propose_recovery_transition(
        state,
        history.authority.authority,
        operation="close_phase",
        observed_at_block=block,
        evidence_sha256=digest(evidence),
    )
    decisions[digest(evidence)] = evidence
    return history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(decision))}
    )


def retained(s, name, sequence):
    signed = submission(
        s["policy"], bundle=s["signed"].submission.model_bundle, name=name, sequence=sequence
    )
    body = s["consent"].consent.model_copy(
        update={"submission_sha256": digest(signed.submission), "hotkey": signed.submission.hotkey}
    )
    consent = SignedCohortParticipationConsent(
        consent=body, signature=sign_object(body, wallet(name))
    )
    snap = snapshot(210)
    admission = admit_recovery_participant(
        signed,
        consent,
        s["intake_history"],
        s["policy"],
        snap,
        expected_tip_sha256=tip(s["intake_history"]),
        current_block=210,
    )
    record = RetainedCohortParticipation(
        schema="umi-retained-cohort-participation/1",
        request=CohortParticipationRequest(signed_submission=signed, consent=consent),
        proposed_admission=admission,
        snapshot=snap,
        observation=boundary(210).model_copy(update={"snapshot_sha256": digest(snap)}),
    )
    return RecoverableRosterParticipant(
        record=record,
        admission=AttestedCohortParticipantAdmission(
            admission=admission, signatures=signatures(admission)
        ),
    )


def make_round(s, *, omit_prepared_member=False, unavailable=1200, preparation_hash=None):
    # The replaced submission is still in the original inventory. A consumer
    # cannot delete it merely because the seal selects a newer submission.
    prior = retained(s, "Alice", 1)
    members = (retained(s, "Alice", 2), retained(s, "Bob", 1))
    records = tuple(
        sorted(
            (digest(p.record.request.consent.consent), canonical_json_bytes(p.record))
            for p in (prior, *members)
        )
    )
    seal = build_intake_seal(
        s["intake_history"],
        s["policy"],
        boundary(300).model_copy(update={"snapshot_sha256": digest(snapshot(300))}),
        snapshot(300),
        records,
        expected_tip_sha256=tip(s["intake_history"]),
    )
    decisions = {}
    h = close(s["intake_history"], s["policy"], decisions, 300, digest(seal))
    members = tuple(
        sorted(members, key=lambda p: digest(p.record.request.signed_submission.submission))
    )
    selected = members[:1] if omit_prepared_member else members
    round_ = s["round_"].model_copy(
        update={
            "intake_closure_sha256": tip(h),
            "participants": tuple(
                RecoverableRoundParticipant(
                    submission_sha256=digest(p.record.request.signed_submission.submission),
                    admission_sha256=digest(p.admission.admission),
                )
                for p in selected
            ),
        }
    )
    h = close(h, s["policy"], decisions, 390, preparation_hash or digest(round_))
    preparation_hash = tip(h)
    h = close(h, s["policy"], decisions, 1680, "ab" * 32, unavailable=unavailable)
    h = close(h, s["policy"], decisions, 1770, "ac" * 32)
    scenarios = []
    for p in selected:
        m = s.copy()
        m.update(
            signed=p.record.request.signed_submission,
            consent=p.record.request.consent,
            admission=p.admission,
            admission_snapshot=p.record.snapshot,
            history=h,
            round_=round_,
        )
        m["attested"] = attested(
            result_for(m["signed"], round_, s["suite"]).result.model_copy(
                update={"finished_block": 1600}
            )
        )
        m["artifacts"] = tuple(
            a.model_copy(
                update={
                    "job": a.job.model_copy(
                        update={
                            "submission": m["signed"],
                            "round": round_,
                            "preparation_closure_sha256": preparation_hash,
                        }
                    )
                }
            )
            for a in s["artifacts"]
        )
        scenarios.append(m)
    roster = RecoverableRosterEvidence(
        schema="umi-recoverable-roster-evidence/1",
        round=round_,
        intake_seal=seal,
        participants=selected,
    )
    outcomes = tuple(
        RecoverableOrderedOutcome(
            schema="umi-recoverable-ordered-outcome/1",
            order=order(m),
            evidence=bundle_evidence(m),
        )
        for m in scenarios
    )
    return dict(
        roster=roster,
        outcomes=outcomes,
        policy=s["policy"],
        suite=s["suite"],
        history=h,
        records=records,
        decisions=decisions,
        scenarios=scenarios,
    )


@pytest.fixture
def batch(scenario):
    return make_round(scenario)


def replay(batch, *, outcomes=None, verify_only=False, **changes):
    args = {k: batch[k] for k in ("roster", "policy", "suite", "history")}
    args.update(
        decision_source=batch["decisions"].__getitem__,
        intake_records=iter(batch["records"]),
        expected_tip_sha256=tip(batch["history"]),
        current_block=5000,
    )
    args.update(changes)
    if verify_only:
        return verify_recoverable_roster(**args)
    return replay_recoverable_roster_outcomes(
        outcomes=batch["outcomes"] if outcomes is None else outcomes, **args
    )


def test_entire_original_roster_replays_after_long_delay(batch):
    original = canonical_json_bytes(batch["roster"])
    assert batch["roster"].intake_seal.record_count == 3
    for block in (5000, 10**6, 2**53 - 1):
        decisions = replay(batch, current_block=block)
        assert len(decisions) == 2
        assert all(
            d.void_reason is None and set(d.candidate_quality.values()) == {Fraction(1)}
            for d in decisions
        )
    assert canonical_json_bytes(batch["roster"]) == original


@pytest.mark.parametrize("count", [0, 1])
def test_missing_outcomes_are_explicitly_pending_until_replayed(batch, count):
    with pytest.raises(IncompleteRecoverableCohort) as caught:
        replay(batch, outcomes=batch["outcomes"][:count], current_block=10**6)
    expected = tuple(p.submission_sha256 for p in batch["roster"].round.participants[count:])
    assert caught.value.missing_submissions == expected
    assert len(replay(batch, current_block=10**6 + 1)) == 2


def test_a_signed_prepared_round_cannot_drop_an_intake_member(scenario):
    b = make_round(scenario, omit_prepared_member=True)
    with pytest.raises(ValueError, match="exactly the sealed intake"):
        replay(b)


def test_outage_compensation_replayed_before_accepting_closure(scenario):
    b = make_round(scenario, unavailable=1201)
    with pytest.raises(ValueError, match="before restoring unavailable service"):
        replay(b)


def test_round_requires_actual_preparation_result(scenario):
    b = make_round(scenario, preparation_hash="be" * 32)
    with pytest.raises(ValueError, match="certified preparation"):
        replay(b)


@pytest.mark.parametrize("damage", ["missing", "duplicate", "reorder", "body"])
def test_missing_or_changed_original_intake_is_not_a_smaller_valid_roster(batch, damage):
    records = list(batch["records"])
    if damage == "missing":
        records.pop()
    elif damage == "duplicate":
        records.append(records[-1])
    elif damage == "reorder":
        records.reverse()
    else:
        records[0] = (records[0][0], records[0][1] + b" ")
    with pytest.raises(ValueError):
        replay(batch, intake_records=iter(records))


@pytest.mark.parametrize(
    "damage",
    [
        "member_missing",
        "member_duplicate",
        "member_order",
        "round_missing",
        "admission",
        "record",
        "suite",
        "tip",
        "revoke",
    ],
)
def test_roster_bindings_cannot_be_substituted(batch, damage):
    r = batch["roster"]
    changes = {}
    if damage.startswith("member_"):
        members = (
            r.participants[:1]
            if damage == "member_missing"
            else (
                (r.participants[0], r.participants[0])
                if damage == "member_duplicate"
                else tuple(reversed(r.participants))
            )
        )
        changes["roster"] = r.model_copy(update={"participants": members})
    elif damage == "round_missing":
        changes["roster"] = r.model_copy(
            update={"round": r.round.model_copy(update={"participants": r.round.participants[:1]})}
        )
    elif damage in ("admission", "record"):
        first = r.participants[0]
        if damage == "admission":
            first = first.model_copy(
                update={
                    "admission": first.admission.model_copy(
                        update={"signatures": first.admission.signatures[:1]}
                    )
                }
            )
        else:
            first = first.model_copy(
                update={"record": first.record.model_copy(update={"observation": boundary(211)})}
            )
        changes["roster"] = r.model_copy(update={"participants": (first, *r.participants[1:])})
    elif damage == "suite":
        changes["suite"] = batch["suite"].model_copy(update={"policy_sha256": "ba" * 32})
    elif damage == "tip":
        changes["expected_tip_sha256"] = "be" * 32
    else:
        h = transition(batch["history"], batch["policy"], "revoke", 1800)
        changes.update(history=h, expected_tip_sha256=tip(h))
    with pytest.raises(ValueError):
        replay(batch, **changes)


def test_unavailable_original_decisions_remain_a_retryable_source_failure(batch):
    def unavailable(_key):
        raise FileNotFoundError("retained decision temporarily unavailable")

    with pytest.raises(FileNotFoundError):
        replay(batch, decision_source=unavailable)
    assert len(replay(batch)) == 2


def test_decision_source_cannot_return_another_valid_signed_input(batch):
    wrong = next(iter(batch["decisions"].values()))
    with pytest.raises(ValueError, match="requested identity"):
        replay(batch, decision_source=lambda _: wrong)


def test_duplicate_outcome_is_not_completion(batch):
    with pytest.raises(ValueError, match="duplicate"):
        replay(batch, outcomes=(batch["outcomes"][0], batch["outcomes"][0]))


def test_complete_mixed_score_and_void_stays_distinct(batch):
    m = batch["scenarios"][1]
    void = RecoverableOrderedOutcome(
        schema="umi-recoverable-ordered-outcome/1",
        order=order(m),
        evidence=RecoverableVoidEvidence(
            schema="umi-recoverable-void-evidence/1", certificate=certificate(m)
        ),
    )
    decisions = replay(batch, outcomes=(void, batch["outcomes"][0]))
    assert decisions[0].void_reason is None
    assert decisions[1].void_reason == "incumbent_failure"
    assert decisions[1].candidate_quality is decisions[1].incumbent_quality is None


@pytest.mark.parametrize("damage", ["foreign", "round", "stdout", "signer"])
def test_complete_outcome_count_does_not_hide_bad_evidence(batch, damage):
    first, second = batch["outcomes"]
    if damage == "foreign":
        # An old, superseded submission is validly signed but no longer selected.
        old = next(
            RetainedCohortParticipation.model_validate_json(raw).request.signed_submission
            for _, raw in batch["records"]
            if RetainedCohortParticipation.model_validate_json(
                raw
            ).request.signed_submission.submission.sequence
            == 1
            and RetainedCohortParticipation.model_validate_json(
                raw
            ).request.signed_submission.submission.hotkey
            == wallet("Alice").hotkey.ss58_address
        )
        first = first.model_copy(
            update={
                "order": first.order.model_copy(
                    update={"order": first.order.order.model_copy(update={"submission": old})}
                )
            }
        )
    elif damage == "round":
        order_body = first.order.order.model_copy(
            update={"round": first.order.order.round.model_copy(update={"sequence": 99})}
        )
        first = first.model_copy(
            update={"order": first.order.model_copy(update={"order": order_body})}
        )
    elif damage == "stdout":
        artifact = first.evidence.executions[0]
        step = artifact.steps[0]
        step = step.model_copy(
            update={
                "execution": step.execution.model_copy(update={"stdout_hex": b"corrupt\n".hex()})
            }
        )
        artifact = artifact.model_copy(update={"steps": (step, *artifact.steps[1:])})
        first = first.model_copy(
            update={
                "evidence": first.evidence.model_copy(
                    update={"executions": (artifact, *first.evidence.executions[1:])}
                )
            }
        )
    else:
        receipts = first.evidence.receipts.model_copy(
            update={"evaluator_runs": first.evidence.receipts.evaluator_runs[:1]}
        )
        first = first.model_copy(
            update={"evidence": first.evidence.model_copy(update={"receipts": receipts})}
        )
    with pytest.raises(ValueError):
        replay(batch, outcomes=(first, second))


def test_original_inventory_io_failure_cannot_complete_a_partial_cohort(batch):
    def unavailable():
        yield batch["records"][0]
        raise FileNotFoundError("intake archive unavailable")

    with pytest.raises(FileNotFoundError):
        replay(batch, intake_records=unavailable())
    assert len(replay(batch)) == 2
