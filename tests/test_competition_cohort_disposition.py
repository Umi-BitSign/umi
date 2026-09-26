"""Complete-set outcome review survives delay without converting absence to failure."""

from dataclasses import replace
from fractions import Fraction

import pytest

from umi.competition_cohort_disposition import (
    AttestedRecoverableEvaluationVoid,
    RecoverableExecutionAnnouncement,
    RecoverableOrderedOutcome,
    RecoverableReviewContext,
    RecoverableVoidEvidence,
    SignedRecoverableExecutionAnnouncement,
    propose_recoverable_void,
    recoverable_void_decision_sha256,
    replay_recoverable_ordered_outcome,
    validate_own_recoverable_void,
    verify_recoverable_void,
)
from umi.competition_cohort_endpoint import RecoverableEndpointPairedEvidence
from umi.competition_cohort_orders import (
    RecoverableEvaluationOrder,
    SignedRecoverableEvaluationOrder,
)
from umi.competition_outcome_classification import ScorableObservations
from umi.open_competition import Evaluator, digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_endpoint import endpoint as endpoint
from .test_competition_cohort_endpoint import receipt_bundle
from .test_competition_cohort_execution import base_policy as base_policy
from .test_competition_cohort_execution import bundle_evidence, setup_scenario
from .test_competition_cohort_execution import legacy_scenario as legacy_scenario
from .test_competition_cohort_execution import receipt_scenario as receipt_scenario
from .test_competition_cohort_execution import recovery as recovery
from .test_competition_cohort_execution import runtime as runtime
from .test_competition_cohort_recovery import signatures
from .test_open_competition import wallet


@pytest.fixture
def policy(base_policy, runtime):
    return base_policy.model_copy(
        update={
            "evaluation_runtime_sha256": digest(runtime),
            "evaluators": (
                *base_policy.evaluators,
                Evaluator(hotkey=wallet("Eve").hotkey.ss58_address, control_group="e"),
            ),
        }
    )


@pytest.fixture(params=["model", "endpoint"])
def scenario(request, receipt_scenario, tmp_path, runtime):
    if request.param == "endpoint":
        return request.getfixturevalue("endpoint")
    return setup_scenario(receipt_scenario, tmp_path, runtime)


def context(s):
    return RecoverableReviewContext(
        **{
            k: s[k]
            for k in ("policy", "suite", "consent", "admission", "admission_snapshot", "history")
        },
        expected_tip_sha256=tip(s["history"]),
        current_block=5000,
    )


def artifacts(s):
    return s.get("endpoints", s["artifacts"])


def job(a):
    return a.incumbent.job if isinstance(a, RecoverableEndpointPairedEvidence) else a.job


def order(s):
    entries = artifacts(s)
    first = job(entries[0])
    body = RecoverableEvaluationOrder(
        schema="umi-recoverable-evaluation-order/1",
        **{
            k: getattr(first, k)
            for k in (
                "round",
                "preparation_closure_sha256",
                "submission",
                "incumbent",
                "runtime",
                "cases",
            )
        },
        evaluators=tuple(sorted((job(a).evaluator_hotkey for a in entries), key=identity)),
    )
    return SignedRecoverableEvaluationOrder(order=body, signatures=signatures(body))


def announcements(s, entries=None, selected=None):
    selected = selected or order(s)
    result = []
    for a, name in zip(entries or artifacts(s), ("Charlie", "Dave"), strict=True):
        body = RecoverableExecutionAnnouncement(
            schema="umi-recoverable-execution-announcement/1",
            order_sha256=digest(selected.order),
            evaluator_hotkey=wallet(name).hotkey.ss58_address,
            evidence=a,
        )
        result.append(
            SignedRecoverableExecutionAnnouncement(
                announcement=body, signature=sign_object(body, wallet(name))
            )
        )
    return tuple(result)


def failed_steps(a, role="incumbent", *, disagree=False):
    baseline = a.incumbent if isinstance(a, RecoverableEndpointPairedEvidence) else a
    steps = list(baseline.steps)
    i = next(i for i, s in enumerate(steps) if s.role == role)
    step = steps[i]
    execution = step.execution
    if disagree:
        output = execution.output.model_copy(update={"hypothesis": "different"})
        execution = execution.model_copy(
            update={"output": output, "stdout_hex": b"different\n".hex()}
        )
    else:
        output = execution.output.model_copy(update={"hypothesis": "", "status": "miner_failure"})
        execution = execution.model_copy(
            update={"output": output, "stdout_hex": "", "reason": "process_failed", "returncode": 1}
        )
    steps[i] = step.model_copy(update={"execution": execution})
    baseline = baseline.model_copy(update={"steps": tuple(steps)})
    return (
        a.model_copy(update={"incumbent": baseline})
        if isinstance(a, RecoverableEndpointPairedEvidence)
        else baseline
    )


def void_rows(s, *, disagree=False):
    entries = list(artifacts(s))
    entries[0] = failed_steps(entries[0], disagree=disagree)
    return announcements(s, tuple(entries))


def certificate(s, rows=None):
    selected = order(s)
    ctx = context(s)
    rows = void_rows(s) if rows is None else rows
    proposal = propose_recoverable_void(selected, rows, ctx)
    for own in rows:
        assert (
            validate_own_recoverable_void(
                proposal, selected, own, own.announcement.evaluator_hotkey, ctx
            )
            == proposal
        )
    return AttestedRecoverableEvaluationVoid(void=proposal, signatures=signatures(proposal))


@pytest.mark.parametrize("disagree", [False, True])
def test_complete_void_review_preserves_original_signed_bytes_after_long_delays(scenario, disagree):
    selected = order(scenario)
    ctx = context(scenario)
    cert = certificate(scenario, void_rows(scenario, disagree=disagree))
    expected = "observation_disagreement" if disagree else "incumbent_failure"
    assert cert.void.reason == expected
    assert (
        propose_recoverable_void(selected, tuple(reversed(cert.void.observations)), ctx)
        == cert.void
    )
    original = canonical_json_bytes(cert)
    outcome = RecoverableOrderedOutcome(
        schema="umi-recoverable-ordered-outcome/1",
        order=selected,
        evidence=RecoverableVoidEvidence(
            schema="umi-recoverable-void-evidence/1", certificate=cert
        ),
    )
    for block in (5000, 10**6, 2**53 - 1):
        result = replay_recoverable_ordered_outcome(outcome, replace(ctx, current_block=block))
        assert result.void_reason == expected
        assert result.candidate_quality is result.incumbent_quality is None
    assert canonical_json_bytes(cert) == original


def test_scored_outcome_is_bound_to_every_assigned_evaluator(scenario):
    evidence = receipt_bundle(scenario) if "endpoints" in scenario else bundle_evidence(scenario)
    selected = order(scenario)
    outcome = RecoverableOrderedOutcome(
        schema="umi-recoverable-ordered-outcome/1", order=selected, evidence=evidence
    )
    result = replay_recoverable_ordered_outcome(outcome, context(scenario))
    assert result.void_reason is None
    assert set(result.candidate_quality.values()) == {Fraction(1)}
    # The common result still has a valid two-group quorum. It must not hide a
    # third assigned evaluator whose observations have not arrived.
    body = selected.order.model_copy(
        update={
            "evaluators": tuple(
                sorted(
                    (*selected.order.evaluators, wallet("Eve").hotkey.ss58_address), key=identity
                )
            )
        }
    )
    selected = SignedRecoverableEvaluationOrder(order=body, signatures=signatures(body))
    with pytest.raises(ValueError, match="exactly all assigned"):
        replay_recoverable_ordered_outcome(
            outcome.model_copy(update={"order": selected}), context(scenario)
        )


def test_agreeing_scores_cannot_be_voided(scenario):
    with pytest.raises(ScorableObservations):
        propose_recoverable_void(order(scenario), announcements(scenario), context(scenario))


@pytest.mark.parametrize(
    "damage",
    [
        "missing",
        "duplicate",
        "signature",
        "order",
        "evaluator",
        "artifact",
        "stdout",
        "case_missing",
        "history_tip",
        "before_reveal",
        "revoked",
    ],
)
def test_missing_or_corrupt_evidence_cannot_authorize_exclusion(scenario, damage):
    selected = order(scenario)
    ctx = context(scenario)
    rows = list(void_rows(scenario))
    if damage == "missing":
        rows.pop()
    elif damage == "duplicate":
        rows[1] = rows[0]
    elif damage in ("history_tip", "before_reveal", "revoked"):
        pending = ctx.history.model_copy(update={"transitions": ctx.history.transitions[:-1]})
        if damage == "history_tip":
            ctx = replace(ctx, expected_tip_sha256=tip(pending))
        elif damage == "before_reveal":
            ctx = replace(ctx, history=pending, expected_tip_sha256=tip(pending))
        else:
            h = transition(ctx.history, ctx.policy, "revoke", 1800)
            ctx = replace(ctx, history=h, expected_tip_sha256=tip(h))
    else:
        body = rows[0].announcement
        if damage == "signature":
            rows[0] = rows[0].model_copy(update={"signature": sign_object(body, wallet("Eve"))})
        else:
            if damage == "order":
                body = body.model_copy(update={"order_sha256": "ff" * 32})
            elif damage == "evaluator":
                body = body.model_copy(
                    update={"evaluator_hotkey": wallet("Dave").hotkey.ss58_address}
                )
            elif damage == "artifact":
                body = body.model_copy(update={"evidence": rows[1].announcement.evidence})
            else:
                a = body.evidence
                baseline = a.incumbent if isinstance(a, RecoverableEndpointPairedEvidence) else a
                steps = list(baseline.steps)
                if damage == "case_missing":
                    steps.pop()
                else:
                    index = next(i for i, step in enumerate(steps) if step.execution.reason == "ok")
                    steps[index] = steps[index].model_copy(
                        update={
                            "execution": steps[index].execution.model_copy(
                                update={"stdout_hex": b"fabricated".hex()}
                            )
                        }
                    )
                baseline = baseline.model_copy(update={"steps": tuple(steps)})
                a = (
                    a.model_copy(update={"incumbent": baseline})
                    if isinstance(a, RecoverableEndpointPairedEvidence)
                    else baseline
                )
                body = body.model_copy(update={"evidence": a})
            rows[0] = SignedRecoverableExecutionAnnouncement(
                announcement=body, signature=sign_object(body, wallet("Charlie"))
            )
    with pytest.raises(ValueError):
        propose_recoverable_void(selected, tuple(rows), ctx)


@pytest.mark.parametrize("damage", ["missing", "duplicate", "foreign", "reason", "own_observation"])
def test_void_votes_require_exact_observations_and_every_assigned_signer(scenario, damage):
    selected = order(scenario)
    ctx = context(scenario)
    cert = certificate(scenario)
    if damage == "own_observation":
        own = cert.void.observations[0]
        bad = own.model_copy(update={"signature": sign_object(own.announcement, wallet("Eve"))})
        with pytest.raises(ValueError, match="exact local"):
            validate_own_recoverable_void(
                cert.void, selected, bad, own.announcement.evaluator_hotkey, ctx
            )
        return
    if damage == "reason":
        body = cert.void.model_copy(update={"reason": "observation_disagreement"})
        cert = cert.model_copy(update={"void": body, "signatures": signatures(body)})
    else:
        sigs = list(cert.signatures)
        if damage == "missing":
            sigs.pop()
        elif damage == "duplicate":
            sigs[1] = sigs[0]
        else:
            sigs[1] = sign_object(cert.void, wallet("Eve"))
        cert = cert.model_copy(update={"signatures": tuple(sigs)})
    with pytest.raises(ValueError):
        verify_recoverable_void(cert, selected, ctx)


def test_transport_failure_carries_no_score_and_keeps_the_original_signed_transcript(endpoint):
    s = endpoint
    entries = list(artifacts(s))
    a = entries[0]
    row = a.transcripts[0].model_copy(
        update={
            "received_at_unix_ns": None,
            "envelope_hex": None,
            "response_signature": None,
            "received_body_prefix_hex": None,
            "received_bytes_sha256": None,
            "failure_code": "request_transport_failed",
            "reveal_pulse": None,
        }
    )
    entries[0] = a.model_copy(update={"transcripts": (row, *a.transcripts[1:])})
    cert = certificate(s, announcements(s, tuple(entries)))
    assert cert.void.reason == "infrastructure_failure"
    assert not cert.void.chain_submission_authorized
    assert any(o.announcement.evidence == entries[0] for o in cert.void.observations)


def test_agreed_miner_failures_are_scored_and_not_voided(receipt_scenario, tmp_path, runtime):
    s = setup_scenario(receipt_scenario, tmp_path, runtime)
    entries = tuple(failed_steps(a, "candidate") for a in artifacts(s))
    with pytest.raises(ScorableObservations):
        propose_recoverable_void(order(s), announcements(s, entries), context(s))


def test_repeated_signing_preserves_void_decision_identity(scenario):
    original = certificate(scenario)
    by_key = {
        identity(wallet(name).hotkey.ss58_address): wallet(name) for name in ("Charlie", "Dave")
    }
    rows = tuple(
        s.model_copy(
            update={
                "signature": sign_object(
                    s.announcement, by_key[identity(s.announcement.evaluator_hotkey)]
                )
            }
        )
        for s in original.void.observations
    )
    proposal = propose_recoverable_void(order(scenario), rows, context(scenario))
    repeated = original.model_copy(update={"void": proposal, "signatures": signatures(proposal)})
    verify_recoverable_void(repeated, order(scenario), context(scenario))
    assert recoverable_void_decision_sha256(proposal) == recoverable_void_decision_sha256(
        original.void
    )
    changed = proposal.model_copy(update={"reason": "observation_disagreement"})
    assert recoverable_void_decision_sha256(changed) != recoverable_void_decision_sha256(proposal)


@pytest.mark.parametrize(
    "damage",
    [
        "missing_quorum",
        "duplicate_evaluator",
        "reverse_evaluators",
        "unauthorized_evaluator",
        "preparation",
        "incumbent",
        "runtime",
        "duplicate_case",
    ],
)
def test_signed_orders_preserve_complete_scope(receipt_scenario, tmp_path, runtime, damage):
    s = setup_scenario(receipt_scenario, tmp_path, runtime)
    selected = order(s)
    body = selected.order
    if damage == "duplicate_evaluator":
        body = body.model_copy(update={"evaluators": (body.evaluators[0],) * 2})
    elif damage == "reverse_evaluators":
        body = body.model_copy(update={"evaluators": tuple(reversed(body.evaluators))})
    elif damage == "unauthorized_evaluator":
        body = body.model_copy(
            update={
                "evaluators": tuple(
                    sorted((body.evaluators[0], wallet("Bob").hotkey.ss58_address), key=identity)
                )
            }
        )
    elif damage == "preparation":
        body = body.model_copy(update={"preparation_closure_sha256": "ff" * 32})
    elif damage == "incumbent":
        body = body.model_copy(
            update={
                "incumbent": body.incumbent.model_copy(update={"parent_baseline_sha256": "ff" * 32})
            }
        )
    elif damage == "runtime":
        body = body.model_copy(
            update={"round": body.round.model_copy(update={"runtime_sha256": "ff" * 32})}
        )
    elif damage == "duplicate_case":
        body = body.model_copy(update={"cases": (body.cases[0],) * len(body.cases)})
    sigs = signatures(body)
    if damage == "missing_quorum":
        sigs = sigs[:1]
    with pytest.raises(ValueError):
        context(s).verify_order(SignedRecoverableEvaluationOrder(order=body, signatures=sigs))
