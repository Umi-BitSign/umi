"""Receipt replay across cohort delays, retaining legacy evidence checks."""

from fractions import Fraction

import pytest

from umi.competition_cohort_evaluation import (
    RecoverableRoundParticipant,
    replay_recoverable_independent_evaluation,
)
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_participation import (
    AttestedCohortParticipantAdmission,
    SignedCohortParticipationConsent,
    admit_recovery_participant,
)
from umi.competition_evidence import IndependentEvaluationEvidence, replay_independent_evaluation
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from . import test_competition_cohort_consumers as consumers
from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures
from .test_competition_cohort_standing_phases import standing
from .test_competition_evidence import run_record, signed_run
from .test_open_competition import attested, wallet
from .test_open_competition import policy as policy

legacy_scenario = consumers.scenario


@pytest.fixture(params=["extensions", "standing"])
def scenario(legacy_scenario, request):
    s = legacy_scenario.copy()
    if request.param == "extensions":
        return s
    p = s["policy"]
    old = s["intake_history"]
    authority, genesis, _ = standing(old.plan, p)
    h = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=old.plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    body = s["consent"].consent.model_copy(update={"authority_sha256": digest(authority.authority)})
    s["consent"] = SignedCohortParticipationConsent(
        consent=body, signature=sign_object(body, wallet("Alice"))
    )
    admission = admit_recovery_participant(
        s["signed"],
        s["consent"],
        h,
        p,
        s["admission_snapshot"],
        expected_tip_sha256=tip(h),
        current_block=210,
    )
    s["admission"] = AttestedCohortParticipantAdmission(
        admission=admission, signatures=signatures(admission)
    )
    s["intake_history"] = h
    h = transition(h, p, "close_phase", 300)
    s["round_"] = s["round_"].model_copy(
        update={
            "intake_closure_sha256": tip(h),
            "participants": (
                RecoverableRoundParticipant(
                    submission_sha256=digest(s["signed"].submission),
                    admission_sha256=digest(admission),
                ),
            ),
        }
    )
    for block in (390, 1680, 1770):
        h = transition(h, p, "close_phase", block)
    s["history"] = h
    s["attested"] = attested(
        s["attested"].result.model_copy(update={"round_sha256": digest(s["round_"])})
    )
    return s


def receipts(s, *, started=400, finished=1590):
    runs = tuple(
        signed_run(
            run_record(
                name,
                s["policy"],
                s["signed"],
                s["round_"],
                s["suite"],
                s["attested"],
                elapsed_ms=5,
                started_block=started,
                finished_block=finished,
            ),
            name,
        )
        for name in ("Charlie", "Dave")
    )
    return IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=s["attested"],
        evaluator_runs=runs,
    )


def replay(s, evidence=None, **changes):
    values = {k: v for k, v in s.items() if k not in ("intake_history", "attested")}
    values.update(
        evidence=evidence or receipts(s), current_block=5000, expected_tip_sha256=tip(s["history"])
    )
    values.update(changes)
    return replay_recoverable_independent_evaluation(**values)


def test_native_receipts_survive_delayed_replay_without_changing_signed_inputs(scenario):
    evidence = receipts(scenario)
    original = canonical_json_bytes(evidence)
    for block in (5000, 1000000, 2**53 - 1):
        candidate, incumbent = replay(scenario, evidence, current_block=block)
        assert set(candidate.values()) == {Fraction(1)}
        assert set(incumbent.values()) == {Fraction(0)}
    assert canonical_json_bytes(evidence) == original
    with pytest.raises(ValueError):
        replay_independent_evaluation(
            evidence,
            scenario["signed"],
            scenario["round_"],
            scenario["suite"],
            scenario["policy"],
            current_block=5000,
        )


@pytest.mark.parametrize("started,finished", [(300, 1500), (390, 1500), (400, 1601)])
def test_valid_signatures_cannot_move_runs_outside_certified_interval(scenario, started, finished):
    with pytest.raises(ValueError, match="run interval"):
        replay(scenario, receipts(scenario, started=started, finished=finished))


@pytest.mark.parametrize(
    "damage",
    [
        "round_sha256",
        "policy_sha256",
        "submission_sha256",
        "common_result_sha256",
        "suite_sha256",
        "model_revision",
        "incumbent_model_sha256",
        "runtime_sha256",
        "hypothesis",
        "candidate_resource",
        "incumbent_resource",
        "case_order",
        "case_missing",
        "missing_run",
        "duplicate_run",
        "extra_signer",
        "signature",
        "common_signature",
        "execution_missing",
    ],
)
def test_receipt_checks_still_reject_corruption_after_old_expiry(scenario, damage):
    evidence = receipts(scenario)
    runs = list(evidence.evaluator_runs)
    body = runs[0].run
    if damage.endswith("sha256") or damage == "model_revision":
        body = body.model_copy(update={damage: "f1" * 32})
    elif damage == "hypothesis":
        outputs = list(body.candidate)
        outputs[0] = outputs[0].model_copy(update={"hypothesis": "wrong"})
        body = body.model_copy(update={"candidate": tuple(outputs)})
    elif damage in ("candidate_resource", "incumbent_resource"):
        field = damage.split("_")[0]
        outputs = tuple(o.model_copy(update={"elapsed_ms": 1001}) for o in getattr(body, field))
        body = body.model_copy(update={field: outputs})
    elif damage == "case_order":
        body = body.model_copy(
            update={
                "candidate": tuple(reversed(body.candidate)),
                "incumbent": tuple(reversed(body.incumbent)),
            }
        )
    elif damage == "case_missing":
        body = body.model_copy(
            update={"candidate": body.candidate[:-1], "incumbent": body.incumbent[:-1]}
        )
    elif damage == "execution_missing":
        body = body.model_copy(update={"execution_evidence_sha256": "0" * 64})
    with pytest.raises(ValueError):
        runs[0] = signed_run(body, "Charlie")
        if damage == "missing_run":
            runs = runs[:1]
        elif damage == "duplicate_run":
            runs.append(runs[0])
        elif damage == "extra_signer":
            extra = body.model_copy(update={"evaluator_hotkey": wallet("Eve").hotkey.ss58_address})
            runs.append(signed_run(extra, "Eve"))
        elif damage == "signature":
            runs[0] = runs[0].model_copy(update={"signature": runs[1].signature})
        elif damage == "common_signature":
            common = evidence.attested_result.model_copy(
                update={
                    "signatures": evidence.attested_result.signatures[:1],
                }
            )
            evidence = evidence.model_copy(update={"attested_result": common})
        replay(scenario, evidence.model_copy(update={"evaluator_runs": tuple(runs)}))


@pytest.mark.parametrize("damage", ["old_tip", "revoked", "unrevealed", "wrong_consent"])
def test_receipts_do_not_bypass_current_history_or_consent(scenario, damage):
    h = scenario["history"]
    changes = {}
    if damage == "old_tip":
        changes["expected_tip_sha256"] = tip(scenario["intake_history"])
    elif damage == "revoked":
        h = transition(h, scenario["policy"], "revoke", 4000)
        changes.update(history=h, expected_tip_sha256=tip(h))
    elif damage == "unrevealed":
        h = h.model_copy(update={"transitions": h.transitions[:-1]})
        changes.update(history=h, expected_tip_sha256=tip(h))
    elif damage == "wrong_consent":
        body = scenario["consent"].consent.model_copy(update={"cohort_sha256": "f1" * 32})
        changes["consent"] = SignedCohortParticipationConsent(
            consent=body, signature=sign_object(body, wallet("Alice"))
        )
    with pytest.raises(ValueError):
        replay(scenario, **changes)
