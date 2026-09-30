"""Certified original observations, untimed content, and recoverable score votes."""

import json
from fractions import Fraction

import pytest

from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_execution_journal import CohortExecutionJournal
from umi.competition_cohort_order_signer import order_slot
from umi.competition_cohort_quality import (
    ClosedQualityReview,
    QualityObservation,
    quality_totals,
)
from umi.competition_cohort_quality_signing import (
    CertifiedClosedQuality,
    PendingQualityCertificates,
    build_quality_manifest,
    collect_quality_certificate,
    retained_quality_vote,
    review_quality_manifest,
    sign_closed_quality,
    verify_quality_certificate,
)
from umi.competition_cohort_request_terminal import RequestExecutionArchive, SignedRequestTerminal
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.competition_round_journal import RoundJournal
from umi.open_competition import _quality, digest, identity, quality_from_hypotheses, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_request_closure import base_policy as base_policy
from .test_competition_cohort_request_closure import certified_history, put, replace_terminal
from .test_competition_cohort_request_closure import closed as closed
from .test_competition_cohort_request_closure import endpoint as endpoint
from .test_competition_cohort_request_closure import legacy_scenario as legacy_scenario
from .test_competition_cohort_request_closure import policy as policy
from .test_competition_cohort_request_closure import receipt_scenario as receipt_scenario
from .test_competition_cohort_request_closure import recovery as recovery
from .test_competition_cohort_request_closure import runtime as runtime
from .test_competition_cohort_request_closure import scenario as scenario
from .test_competition_dependence import dependence_policy, dependence_suite, outputs_for
from .test_drand import pulse_record
from .test_open_competition import wallet


def reviewer(b, **changes):
    history = b.get("quality_history")
    if history is None:
        history = b["quality_history"] = certified_history(b)
    args = dict(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        suite=b["suite"],
        policy=b["policy"],
        history=history,
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        pulses=lambda _: RetainedRevealPulse(**pulse_record()),
        expected_tip_sha256=tip(history),
        current_block=1000000,
    )
    args.update(changes)
    return ClosedQualityReview(**args)


def signer_name(hotkey):
    return next(
        n
        for n in ("Charlie", "Dave")
        if identity(wallet(n).hotkey.ss58_address) == identity(hotkey)
    )


async def votes_for(b, review, order):
    votes = []
    for evaluator in order.order.evaluators:
        owner = b["owners"][(digest(order), identity(evaluator))]

        async def sign(body, evaluator=evaluator):
            return sign_object(body, wallet(signer_name(evaluator)))

        votes.append(await sign_closed_quality(owner, order_slot(order.order), review, sign))
    return tuple(votes)


def collector(tmp_path):
    return RoundJournal(tmp_path / "quality-collection", {"scope": "quality-test"})


async def certificates_for(b, review, tmp_path):
    journal = collector(tmp_path)
    certificates = {}
    for order in b["orders"]:
        key = digest(order.order.submission.submission)
        votes = await votes_for(b, review, order)
        certificate = collect_quality_certificate(journal, review, key, votes)
        assert certificate is not None
        b["objects"][digest(certificate)] = JournalEndpointObjects(journal)(digest(certificate))
        certificates[key] = certificate
    return certificates


async def test_complete_certified_quality_preserves_all_participants_and_assigned_runs(
    closed, tmp_path
):
    b = closed
    review = reviewer(b)
    certificates = await certificates_for(b, review, tmp_path)
    manifest = build_quality_manifest(review, certificates.get)
    outcomes = review_quality_manifest(manifest, reviewer(b, current_block=2**53 - 1))
    assert len(outcomes) == len(b["closure"].participants) == 2
    assert all(len(r.runs) == 2 for r in outcomes)
    assert all(r.reason is None for r in outcomes)
    for result in outcomes:
        assert result.request_closure_sha256 == digest(b["closure"])
        assert result.candidate.aggregate.numerator == result.candidate.aggregate.denominator
        basis = (
            "endpoint_content_only" if result.track == "endpoint" else "measured_model_execution"
        )
        assert all(r.candidate_basis == basis for r in result.runs)
        assert not result.service_credit_authorized and not result.promotion_authorized
        assert not result.chain_submission_authorized
    assert not manifest.service_credit_authorized and not manifest.chain_submission_authorized
    assert outcomes == review_quality_manifest(manifest, review)


async def test_missing_certificate_or_roster_entry_cannot_be_silently_dropped(closed, tmp_path):
    b = closed
    review = reviewer(b)
    certificates = await certificates_for(b, review, tmp_path)
    missing = next(iter(certificates))
    saved = certificates.pop(missing)
    with pytest.raises(PendingQualityCertificates) as caught:
        build_quality_manifest(review, certificates.get)
    assert caught.value.submissions == (missing,)
    certificates[missing] = saved
    manifest = build_quality_manifest(review, certificates.get)
    for members in (
        manifest.participants[:1],
        tuple(reversed(manifest.participants)),
        (manifest.participants[0],) * 2,
    ):
        with pytest.raises(ValueError):
            review_quality_manifest(manifest.model_copy(update={"participants": members}), review)
    key = manifest.participants[-1].certificate_sha256
    raw = b["objects"].pop(key)
    with pytest.raises(KeyError):
        review_quality_manifest(manifest, review)
    b["objects"][key] = raw
    assert len(review_quality_manifest(manifest, review)) == 2


@pytest.mark.parametrize(
    "damage",
    [
        "missing_signer",
        "repeated_signer",
        "foreign_signer",
        "score",
        "terminal",
        "closure",
        "basis",
        "reason",
    ],
)
async def test_valid_signatures_cannot_certify_changed_scores_or_sources(closed, tmp_path, damage):
    b = closed
    review = reviewer(b)
    certificates = await certificates_for(b, review, tmp_path)
    original = next(iter(certificates.values()))
    result = original.result
    if damage == "score":
        score = result.candidate.model_copy(
            update={"aggregate": {"numerator": "0", "denominator": "1"}}
        )
        result = result.model_copy(update={"candidate": score})
    elif damage in {"terminal", "basis"}:
        change = (
            {"terminal_sha256": "ac" * 32}
            if damage == "terminal"
            else {
                "candidate_basis": "measured_model_execution"
                if result.track == "endpoint"
                else "endpoint_content_only"
            }
        )
        result = result.model_copy(
            update={"runs": (result.runs[0].model_copy(update=change), *result.runs[1:])}
        )
    elif damage == "closure":
        result = result.model_copy(update={"request_closure_sha256": "ae" * 32})
    elif damage == "reason":
        result = result.model_copy(
            update={"reason": "observation_disagreement", "candidate": None, "incumbent": None}
        )
    names = [signer_name(r.evaluator_hotkey) for r in result.runs]
    if damage == "missing_signer":
        names = names[:1]
    if damage == "repeated_signer":
        names = names[:1] * 2
    if damage == "foreign_signer":
        names[-1] = "Eve"
    certificate = CertifiedClosedQuality(
        result=result, signatures=tuple(sign_object(result, wallet(n)) for n in names)
    )
    with pytest.raises(ValueError):
        verify_quality_certificate(certificate, review)


@pytest.mark.parametrize("damage", ["unrevealed", "revoked", "wrong_suite", "missing_other_miner"])
def test_quality_requires_certified_full_closure_reveal_and_current_authority(closed, damage):
    b = closed
    h = certified_history(b)
    b["quality_history"] = h
    args = {}
    if damage == "unrevealed":
        h = h.model_copy(update={"transitions": h.transitions[:-1]})
        args.update(history=h, expected_tip_sha256=tip(h))
    elif damage == "revoked":
        h = transition(h, b["policy"], "revoke", 1800)
        args.update(history=h, expected_tip_sha256=tip(h))
    elif damage == "wrong_suite":
        args["suite"] = b["suite"].model_copy(update={"policy_sha256": "cd" * 32})
    else:
        b["objects"].pop(b["closure"].participants[-1].evaluators[-1].terminal_sha256)
    with pytest.raises((ValueError, KeyError)):
        reviewer(b, **args)


async def test_partial_quorum_and_archived_own_vote_recover_without_reexecution(closed, tmp_path):
    b = closed
    review = reviewer(b)
    order = b["orders"][0]
    key = digest(order.order.submission.submission)
    votes = await votes_for(b, review, order)
    journal = collector(tmp_path)
    assert collect_quality_certificate(journal, review, key, votes[:1]) is None
    journal = collector(tmp_path)
    certificate = collect_quality_certificate(journal, review, key, votes[1:])
    assert certificate is not None
    assert collect_quality_certificate(collector(tmp_path), review, key, ()) == certificate
    b["objects"].clear()
    for evaluator, expected in zip(order.order.evaluators, votes, strict=True):
        old = b["owners"][(digest(order), identity(evaluator))]
        restored = CohortExecutionJournal(old.config, b["policy"])
        assert retained_quality_vote(restored, order_slot(order.order)) == expected


@pytest.mark.parametrize(
    "kind,after",
    [
        (k, a)
        for k in ("closed_quality_intent", "closed_quality_vote", "endpoint_replay_object")
        for a in (False, True)
    ],
)
async def test_score_signing_recovers_interrupted_commit_and_acknowledgement(closed, kind, after):
    b = closed
    review = reviewer(b)
    order = b["orders"][0]
    evaluator = order.order.evaluators[0]
    owner = b["owners"][(digest(order), identity(evaluator))]
    original_put = owner.journal.put
    tripped = False
    signatures = []

    def interrupted(record_kind, record_key, value):
        nonlocal tripped
        if record_kind == kind and not tripped:
            tripped = True
            if after:
                original_put(record_kind, record_key, value)
            raise OSError("injected storage interruption")
        return original_put(record_kind, record_key, value)

    owner.journal.put = interrupted

    async def sign(body):
        signatures.append(digest(body))
        return sign_object(body, wallet(signer_name(evaluator)))

    with pytest.raises(OSError):
        await sign_closed_quality(owner, order_slot(order.order), review, sign)
    restored = CohortExecutionJournal(owner.config, b["policy"])
    vote = await sign_closed_quality(restored, order_slot(order.order), review, sign)
    assert retained_quality_vote(restored, order_slot(order.order)) == vote
    assert len(set(signatures)) == 1
    if kind == "endpoint_replay_object" or (kind == "closed_quality_vote" and after):
        assert len(signatures) == 1
    assert vote.result == review.outcome(digest(order.order.submission.submission))


@pytest.mark.parametrize(
    "kind,after",
    [
        (k, a)
        for k in ("closed_quality_peer", "closed_quality_certificate", "endpoint_replay_object")
        for a in (False, True)
    ],
)
async def test_certificate_collection_recovers_storage_failures(closed, tmp_path, kind, after):
    b = closed
    review = reviewer(b)
    order = b["orders"][0]
    key = digest(order.order.submission.submission)
    votes = await votes_for(b, review, order)
    journal = collector(tmp_path)
    put = journal.put
    tripped = False

    def interrupted(record_kind, record_key, value):
        nonlocal tripped
        if record_kind == kind and not tripped:
            tripped = True
            if after:
                put(record_kind, record_key, value)
            raise OSError("injected acknowledgement loss")
        return put(record_kind, record_key, value)

    journal.put = interrupted
    with pytest.raises(OSError):
        collect_quality_certificate(journal, review, key, votes)
    journal = collector(tmp_path)
    certificate = collect_quality_certificate(journal, review, key, votes)
    assert certificate is not None
    assert verify_quality_certificate(certificate, review) == review.outcome(key)
    assert JournalEndpointObjects(journal)(digest(certificate)) == canonical_json_bytes(certificate)


@pytest.mark.parametrize("blind", [False, True])
def test_shared_profile_preserves_dependence_and_legacy_eligibility(blind):
    p = dependence_policy()
    suite = dependence_suite(p)
    outputs = outputs_for(suite, blind=blind)
    hypotheses = tuple((o.case_id, o.hypothesis) for o in outputs)
    expected = _quality(outputs, suite, p)
    assert quality_from_hypotheses(hypotheses, suite, p) == expected
    raw = tuple(QualityObservation(o.case_id, o.status, o.hypothesis, None) for o in outputs)
    totals = quality_totals(raw, suite, p)
    assert {
        s.stratum: Fraction(s.quality.numerator + "/" + s.quality.denominator)
        for s in totals.strata
    } == expected
    assert totals.aggregate.numerator == ("0" if blind else "1")
    late = tuple(o.model_copy(update={"elapsed_ms": p.maximum_inference_ms + 1}) for o in outputs)
    assert all(v == 0 for v in _quality(late, suite, p).values())
    assert quality_totals(raw, suite, p) == totals


def test_quality_profile_rejects_incomplete_duplicate_or_oversized_content():
    p = dependence_policy()
    suite = dependence_suite(p)
    outputs = outputs_for(suite, blind=False)
    observations = tuple((o.case_id, o.hypothesis) for o in outputs)
    for malformed in (
        observations[:-1],
        tuple(reversed(observations)),
        (observations[0],) * len(observations),
        ((observations[0][0], "a" * (p.maximum_output_bytes + 1)), *observations[1:]),
    ):
        with pytest.raises(ValueError):
            quality_from_hypotheses(malformed, suite, p)
    with pytest.raises(ValueError):
        quality_from_hypotheses(tuple((k, None) for k, _ in observations), suite, p, incumbent=True)


@pytest.mark.parametrize("condition", ["disagreement", "incumbent_failure", "runtime_failure"])
def test_original_execution_failures_are_distinct_from_missing_evidence(closed, condition):
    b = closed
    ref = b["closure"].participants[0].evaluators[0]
    signed = SignedRequestTerminal.model_validate_json(b["objects"][ref.terminal_sha256])
    execution = RequestExecutionArchive.model_validate_json(
        b["objects"][signed.terminal.execution_archive_sha256]
    )
    steps = list(execution.steps)
    index = next(
        i for i, key in enumerate(steps) if json.loads(b["objects"][key])["role"] == "incumbent"
    )
    step = json.loads(b["objects"][steps[index]])
    record = step["execution"]
    if condition == "disagreement":
        record["output"]["hypothesis"] = "different"
        record["stdout_hex"] = b"different\n".hex()
    else:
        record["output"].update(status="miner_failure", hypothesis="")
        record.update(
            reason="process_failed",
            stdout_hex="",
            returncode=125 if condition == "runtime_failure" else 1,
        )
    steps[index] = put(b, step)
    archive = execution.model_copy(update={"steps": tuple(steps)})
    body = signed.terminal.model_copy(update={"execution_archive_sha256": put(b, archive)})
    altered = SignedRequestTerminal(
        terminal=body, signature=sign_object(body, wallet(signer_name(ref.evaluator_hotkey)))
    )
    replace_terminal(b, 0, 0, altered)
    if condition == "runtime_failure":
        with pytest.raises(ValueError):
            reviewer(b)
        return
    review = reviewer(b)
    result = review.outcome(b["closure"].participants[0].submission_sha256)
    assert result.reason == (
        "observation_disagreement" if condition == "disagreement" else "incumbent_failure"
    )
    assert result.candidate is None and result.incumbent is None
    assert review.outcome(b["closure"].participants[1].submission_sha256).reason is None


def test_signed_failures_contribute_zero_content_quality_without_time_invention():
    policy = dependence_policy()
    suite = dependence_suite(policy)
    observations = tuple(
        QualityObservation(c.case_id, "miner_failure", "", None) for c in suite.cases
    )
    result = quality_totals(observations, suite, policy)
    assert result.aggregate.numerator == "0"
    assert all(s.quality.numerator == "0" for s in result.strata)
