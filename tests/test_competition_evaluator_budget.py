from __future__ import annotations

from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from umi import competition_evaluator_budget as budget
from umi import competition_work_plans as plans
from umi.competition_endpoint_execution import (
    EndpointDispatchEvidence,
    EndpointPairedEvidence,
    RetainedRevealPulse,
)
from umi.competition_evaluator import (
    EvaluationVote,
    IndependentEvidenceObservation,
    SignedEvaluationOrder,
    VoidEvidenceObservation,
)
from umi.competition_evaluator_capacity import order_binding
from umi.competition_evidence import (
    EvaluatorRunRecord,
    IndependentEvaluationEvidence,
    SignedEvaluatorRunRecord,
)
from umi.competition_execution import (
    EndpointIncumbentEvidence,
    ExecutionBoundary,
    ExecutionStep,
    ModelExecutionEvidence,
    execution_key,
)
from umi.competition_native import OfflineMpsRuntime
from umi.competition_observations import ExecutionAnnouncement, SignedExecutionAnnouncement
from umi.competition_runner import OfflineCaseExecution
from umi.competition_void import (
    AttestedEvaluationVoid,
    EvaluationVoid,
    EvaluationVoidVote,
    VoidEvaluationEvidence,
)
from umi.config import Limits
from umi.open_competition import (
    AttestedResult,
    CaseOutput,
    EvaluationResult,
    Signature,
    digest,
    identity,
    sign_object,
)
from umi.protocol import canonical_json_bytes

from .test_competition_evaluator import make_driver
from .test_competition_evaluator_capacity import limit, used
from .test_competition_execution import chain_config as chain_config
from .test_competition_runner import runtime as _cpu_runtime
from .test_competition_work_plans import policy as policy
from .test_competition_work_plans import setup as work_fixture
from .test_competition_work_plans import sign_publications

work = work_fixture
cpu_runtime = _cpu_runtime


@pytest.fixture(params=("cpu", "mps"))
def runtime(cpu_runtime, request):
    if request.param == "cpu":
        return cpu_runtime
    return OfflineMpsRuntime(
        schema="umi-offline-mps-runtime/1",
        installation_sha256="ab" * 32,
        os_build="24A335",
        python_abi="cp310",
        cpu_threads=2,
        maximum_video_bytes=1024,
        rss_watchdog_bytes=1024**3,
        scratch_watchdog_bytes=16 * 1024**2,
        cold_start_in_deadline=True,
    )


def prepared(work, track, *, review=True):
    submission = next(s for s in work.plan.submissions if s.submission.track == track)
    proposals = plans.endpoint_proposals(**work.options) if track == "endpoint" else ()
    result = budget.evaluator_order_budget(
        plan=work.plan,
        submission=submission,
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
        endpoint_publication_body=proposals[0] if proposals else None,
        legacy_policy=work.item.legacy_policy if proposals else None,
        retain_settlement_review=review,
    )
    publications = sign_publications(work, proposals)
    orders = plans.evaluation_order_proposals(
        plan=work.plan,
        policy=work.policy,
        publications=publications,
        legacy=work.item.legacy_policy if publications else None,
    )
    order = next(o for o in orders if o.submission == submission)
    signed = SignedEvaluationOrder(
        order=order,
        signatures=tuple(
            # Real fixture signatures are produced only after budgeting.
            sign_object(order, w)
            for w in work.signers
        ),
    )
    return result, signed


def allowances(result):
    return {item.kind: item.maximum_bytes for item in result.reservation.artifacts}


def boundary():
    return ExecutionBoundary(
        source="verifier_attested_finality",
        block=2**53 - 1,
        block_hash="0x" + "ab" * 32,
        state_root="0x" + "cd" * 32,
        snapshot_sha256="ef" * 32,
        evidence_sha256="12" * 32,
    )


def signature(hotkey):
    # Structural serialization fixture, never sent to an authorization parser.
    return Signature(hotkey=hotkey, scheme="ed25519", signature="0x" + "ab" * 64)


def transcript(assignment, limits):
    maximum = limits.maximum_response_body_bytes
    # Eight pairs with exactly H UTF-8 bytes, maximizing JSON control escapes.
    headers = {str(i): "" for i in range(8)}
    headers["0"] = "\x00" * (limits.maximum_http_header_bytes - 8)
    return {
        "schema": "umi-endpoint-dispatch-transcript/1",
        "assignment_key": "ab" * 32,
        "publication_sha256": "cd" * 32,
        "case_id": "ef" * 32,
        "origin_evidence_sha256": "12" * 32,
        "origin_block": 2**53 - 1,
        "request_hex": canonical_json_bytes(assignment.request).hex(),
        "auth_headers": headers,
        "limits": asdict(limits),
        "started_at_unix_ns": "9" * 20,
        "finished_at_unix_ns": "9" * 20,
        "received_at_unix_ns": "9" * 20,
        "envelope_hex": "ab" * maximum,
        "response_signature": "\x00" * 130,
        "received_body_prefix_hex": "ab" * maximum,
        "received_bytes_sha256": "34" * 32,
        "failure_code": "\x00" * 128,
        "no_weight": True,
        "evidence_verified": False,
        "chain_submission_authorized": False,
    }


def artifact_shapes(work, result, signed):
    """Real schema instances with maximum structural fields, no crypto claims."""
    order = signed.order
    output = tuple(
        CaseOutput(
            case_id=c.case_id,
            status="ok",
            hypothesis="\x00" * work.policy.maximum_output_bytes,
            elapsed_ms=86_400_000,
        )
        for c in result.job.cases
    )
    common = EvaluationResult(
        schema="umi-competition-result/1",
        round_sha256=digest(order.round),
        submission_sha256=digest(order.submission.submission),
        model_revision="ab" * 32,
        incumbent_model_sha256=digest(order.incumbent),
        runtime_sha256=digest(order.runtime),
        finished_block=2**53 - 1,
        candidate=output,
        incumbent=output,
    )
    announcements, votes, runs, pulses = {}, {}, [], {}
    for evaluator in order.evaluators:
        key = identity(evaluator)
        job = result.job.model_copy(update={"evaluator_hotkey": evaluator})
        roles = ("incumbent",) if order.publication is not None else ("candidate", "incumbent")
        steps = tuple(
            ExecutionStep(
                role=role,
                started=boundary(),
                finished=boundary(),
                execution=OfflineCaseExecution(
                    schema="umi-offline-case-execution/1",
                    model_sha256="ab" * 32,
                    runtime_sha256=digest(job.runtime),
                    video_sha256=case.video_sha256,
                    output=out,
                    stdout_hex="00" * (work.policy.maximum_output_bytes + 1),
                    reason="process_failed",
                    returncode=-65536,
                ),
            )
            for case, out in zip(job.cases, output, strict=True)
            for role in roles
        )
        if order.publication is None:
            evidence = ModelExecutionEvidence(
                schema="umi-model-execution-evidence/1", job=job, steps=steps
            )
        else:
            limits = Limits.from_policy(work.item.legacy_policy)
            dispatches = []
            for assignment in order.publication.publication.assignments:
                if identity(assignment.evaluator_hotkey) != key:
                    continue
                pulse = RetainedRevealPulse(
                    round=assignment.request.reveal_round, randomness="ab" * 32, signature="ab" * 48
                )
                dispatches.append(
                    EndpointDispatchEvidence(
                        assignment_key="ab" * 32,
                        transcript_hex=canonical_json_bytes(transcript(assignment, limits)).hex(),
                        reveal_pulse=pulse,
                    )
                )
                if key == identity(result.job.evaluator_hotkey):
                    pulses["pulse:" + str(pulse.round)] = pulse
            evidence = EndpointPairedEvidence(
                schema="umi-endpoint-paired-evidence/1",
                incumbent=EndpointIncumbentEvidence(
                    schema="umi-endpoint-incumbent-evidence/1",
                    job=job,
                    steps=steps,
                ),
                publication=order.publication,
                legacy_policy=work.item.legacy_policy,
                dispatches=tuple(dispatches),
            )
        announcement = ExecutionAnnouncement(
            schema="umi-execution-announcement/1",
            order_sha256=digest(order),
            evaluator_hotkey=evaluator,
            evidence=evidence,
        )
        announcements[key] = SignedExecutionAnnouncement(
            announcement=announcement, signature=signature(evaluator)
        )
        run = EvaluatorRunRecord(
            schema="umi-competition-evaluator-run/1",
            evaluator_hotkey=evaluator,
            policy_sha256=digest(work.policy),
            round_sha256=digest(order.round),
            submission_sha256=digest(order.submission.submission),
            common_result_sha256=digest(common),
            suite_sha256=order.round.suite_sha256,
            model_revision=common.model_revision,
            incumbent_model_sha256=common.incumbent_model_sha256,
            runtime_sha256=common.runtime_sha256,
            started_block=2**53 - 1,
            finished_block=2**53 - 1,
            candidate=output,
            incumbent=output,
            execution_evidence_sha256=digest(evidence),
        )
        signed_run = SignedEvaluatorRunRecord(run=run, signature=signature(evaluator))
        runs.append(signed_run)
        votes[key] = EvaluationVote(
            schema="umi-evaluation-vote/1",
            order_sha256=digest(order),
            result=common,
            result_signature=signature(evaluator),
            run=signed_run,
        )
    independent = IndependentEvaluationEvidence(
        schema="umi-competition-independent-evaluation/1",
        attested_result=AttestedResult(
            result=common, signatures=tuple(signature(e) for e in order.evaluators)
        ),
        evaluator_runs=tuple(runs),
    )
    void = EvaluationVoid(
        schema="umi-competition-evaluation-void/1",
        policy_sha256=digest(work.policy),
        round_sha256=digest(order.round),
        order_sha256=digest(order),
        submission_sha256=digest(order.submission.submission),
        suite_sha256=order.round.suite_sha256,
        reason="observation_disagreement",
        observations=tuple(announcements.values()),
    )
    void_vote = EvaluationVoidVote(void=void, signature=signature(result.job.evaluator_hotkey))
    void_evidence = VoidEvaluationEvidence(
        schema="umi-competition-void-evidence/1",
        order=signed,
        certificate=AttestedEvaluationVoid(
            void=void, signatures=tuple(signature(e) for e in order.evaluators)
        ),
        legacy_policy=work.item.legacy_policy if order.publication is not None else None,
    )
    observed = dict(
        evaluator_hotkey=result.job.evaluator_hotkey,
        policy_sha256=digest(work.policy),
        round_sha256=digest(order.round),
        order_sha256=digest(order),
        submission_sha256=digest(order.submission.submission),
        evidence_sha256=digest(independent),
        observed=boundary(),
    )
    observation = IndependentEvidenceObservation(
        schema="umi-independent-evidence-observation/1", **observed
    )
    void_observation = VoidEvidenceObservation(schema="umi-void-evidence-observation/1", **observed)
    local = identity(result.job.evaluator_hotkey)
    return {
        **pulses,
        "announcement_intent": announcements[local].announcement,
        "announcement": announcements[local],
        **{"peer_execution:" + key: value for key, value in announcements.items()},
        "result_intent": common,
        "run_intent": votes[local].run.run,
        "vote": votes[local],
        **{"peer_vote:" + key: value for key, value in votes.items()},
        "independent": independent,
        "independent_observation": observation,
        "review_retention": observation,
        "void_intent": void,
        "void_vote": void_vote,
        **{"peer_void_vote:" + key: void_vote for key in announcements},
        "void": void_evidence,
        "void_observation": void_observation,
        "void_review_retention": void_observation,
    }


@pytest.mark.parametrize(
    "value", [None, False, 123, '\x00\n\\"é', [1, "\x00"], {"x\n": [False, None]}]
)
def test_canonical_integer_algebra(value):
    values = [value, value, value]
    assert budget.array_bound(map(budget.json_size, values)) == len(canonical_json_bytes(values))
    assert budget.repeated_array_bound(budget.json_size(value), 3) == budget.json_size(values)
    fields = {"one\n": value, "two": values}
    assert budget.object_bound(
        {k: budget.json_size(v) for k, v in fields.items()}
    ) == budget.json_size(fields)
    assert budget.array_bound(()) == budget.repeated_array_bound(0, 0) == 2
    assert budget.object_bound({}) == 2


@pytest.mark.parametrize("maximum", [1, 100, 4096])
@pytest.mark.parametrize("status", ["ok", "miner_failure", "infrastructure_failure"])
def test_output_escaping_full_elapsed_and_failure_shapes(maximum, status):
    output = CaseOutput(
        case_id="ab" * 32,
        status=status,
        hypothesis="\x00" * maximum if status == "ok" else "",
        elapsed_ms=86_400_000,
    )
    assert budget.json_size(output) <= budget._case_output_bound(maximum)
    assert budget.json_size(boundary()) == budget._boundary_bound()


@pytest.mark.parametrize("track", ["model", "endpoint"])
def test_every_native_artifact_fits_structural_bound(work, track):
    result, signed = prepared(work, track)
    actual = artifact_shapes(work, result, signed)
    limits = allowances(result)
    assert set(actual) == set(limits)
    for kind, value in actual.items():
        assert budget.json_size(value) <= limits[kind], kind
    assert result.reservation.slot == execution_key(result.job)
    assert result.reservation.order_sha256 == order_binding(signed.order)
    assert budget.json_size(signed.order) <= result.order_body_bytes
    assert budget.json_size(signed) <= result.reservation.maximum_bytes
    assert result.maximum_independent_bytes == limits["independent"]
    assert result.maximum_void_bytes == limits["void"]
    assert max(limits.values()) < 64 * 1024**2
    assert limits["result_intent"] < 100_000  # Small profiles do not reserve the global ceiling.
    certificate = AttestedResult(
        result=actual["result_intent"],
        signatures=tuple(signature(e.hotkey) for e in work.policy.evaluators),
    )
    assert budget.json_size(certificate) <= result.maximum_certificate_bytes


def test_policy_signature_envelope_exceeds_nominated_peer_count(work):
    result, signed = prepared(work, "endpoint")
    groups = len({e.control_group for e in work.policy.evaluators})
    assert groups > len(work.plan.evaluators)
    assert result.reservation.maximum_bytes == budget.object_bound(
        {
            "order": result.order_body_bytes,
            "signatures": budget.repeated_array_bound(budget.signature_bound(), groups),
        }
    )
    assert budget.json_size(signature(work.plan.evaluators[0])) <= budget.signature_bound()
    own = "peer_execution:" + identity(result.job.evaluator_hotkey)
    assert own in allowances(result)
    assert signed.order.publication is not None


def test_endpoint_transcript_charges_both_response_copies_and_outer_hex(work):
    body = plans.endpoint_proposals(**work.options)[0]
    assignment = body.assignments[0]
    limits = Limits.from_policy(work.item.legacy_policy)
    raw = canonical_json_bytes(transcript(assignment, limits))
    calculated = budget._transcript_bound(assignment, limits)
    assert len(raw) <= calculated < 1024**2
    assert calculated > 4 * limits.maximum_response_body_bytes + 2 * budget.json_size(
        assignment.request
    )
    assert budget._dispatch_bound(assignment, limits) > 2 * calculated
    enlarged = replace(limits, maximum_response_body_bytes=limits.maximum_response_body_bytes + 1)
    # Two response hex copies gain four bytes; the serialized limits may gain digits.
    assert budget._transcript_bound(assignment, enlarged) - calculated >= 4


def test_review_retention_is_explicit_and_pulse_rounds_are_deduplicated(work):
    without, _ = prepared(work, "endpoint", review=False)
    with_review, signed = prepared(work, "endpoint", review=True)
    base, review = allowances(without), allowances(with_review)
    assert set(review) - set(base) == {"review_retention", "void_review_retention"}
    rounds = {
        a.request.reveal_round
        for a in signed.order.publication.publication.assignments
        if identity(a.evaluator_hotkey) == identity(without.job.evaluator_hotkey)
    }
    assert {k for k in base if k.startswith("pulse:")} == {f"pulse:{n}" for n in rounds}


def test_combined_worker_model_void_retains_its_configured_legacy_policy(work):
    model_only, signed = prepared(work, "model")
    combined = budget.evaluator_order_budget(
        plan=work.plan,
        submission=signed.order.submission,
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
        legacy_policy=work.item.legacy_policy,
        retain_settlement_review=True,
    )
    increase = budget.json_size(work.item.legacy_policy) - budget.json_size(None)
    assert combined.maximum_void_bytes == model_only.maximum_void_bytes + increase
    prior = allowances(model_only)
    assert allowances(combined) == {**prior, "void": prior["void"] + increase}
    assert combined.order_body_bytes == model_only.order_body_bytes
    assert combined.reservation.order_sha256 == model_only.reservation.order_sha256
    evidence = artifact_shapes(work, model_only, signed)["void"].model_copy(
        update={"legacy_policy": work.item.legacy_policy}
    )
    assert budget.json_size(evidence) <= combined.maximum_void_bytes


def test_budget_does_not_sign_or_construct_fake_models(work, monkeypatch):
    submission = next(s for s in work.plan.submissions if s.submission.track == "model")

    def forbidden(*args, **kwargs):
        raise AssertionError("budget attempted to manufacture signed evidence")

    monkeypatch.setattr("umi.open_competition.sign_object", forbidden)
    monkeypatch.setattr("umi.protocol.StrictProtocolModel.model_construct", forbidden)
    result = budget.evaluator_order_budget(
        plan=work.plan,
        submission=submission,
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
    )
    assert result.reservation.artifacts


def test_cohort_path_reuses_one_authenticated_plan(work, monkeypatch):
    body = plans.endpoint_proposals(**work.options)[0]
    calls = []
    original = budget.validate_work_plan

    def record_validation(plan, policy):
        calls.append(digest(plan))
        return original(plan, policy)

    monkeypatch.setattr(budget, "validate_work_plan", record_validation)
    submission = next(s for s in work.plan.submissions if s.submission.track == "model")
    standalone = budget.evaluator_order_budget(
        plan=work.plan,
        submission=submission,
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
    )
    assert calls == [digest(work.plan)]
    validated = original(work.plan, work.policy)
    for item in validated.submissions:
        endpoint = item.submission.track == "endpoint"
        result = budget.order_budget_for_validated_plan(
            plan=validated,
            submission=item,
            policy=work.policy,
            evaluator_hotkey=validated.evaluators[0],
            endpoint_publication_body=body if endpoint else None,
            legacy_policy=work.item.legacy_policy if endpoint else None,
        )
        if not endpoint:
            assert result == standalone
    assert calls == [digest(work.plan)]


@pytest.mark.parametrize(
    "fault",
    ["missing_publication", "missing_legacy", "not_nominated", "changed_case", "bad_cutoff"],
)
def test_unsigned_input_binding_errors_refuse_a_budget(work, fault):
    options = dict(
        plan=work.plan,
        submission=next(s for s in work.plan.submissions if s.submission.track == "endpoint"),
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
        endpoint_publication_body=plans.endpoint_proposals(**work.options)[0],
        legacy_policy=work.item.legacy_policy,
    )
    if fault == "missing_publication":
        options["endpoint_publication_body"] = None
    elif fault == "missing_legacy":
        options["legacy_policy"] = None
    elif fault == "not_nominated":
        options["evaluator_hotkey"] = work.plan.submissions[0].submission.hotkey
    elif fault == "changed_case":
        first, *others = work.plan.cases
        options["plan"] = work.plan.model_copy(
            update={"cases": (first.model_copy(update={"video_sha256": "ab" * 32}), *others)}
        )
    else:
        options["plan"] = work.plan.model_copy(
            update={"cutoff": work.plan.cutoff.model_copy(update={"signatures": ()})}
        )
    with pytest.raises((ValueError, TypeError)):
        budget.evaluator_order_budget(**options)


def test_native_exact_capacity_preserves_other_order_obligations(work, chain_config, tmp_path):
    result, signed = prepared(work, "model")
    driver = make_driver(
        tmp_path / "native",
        chain_config,
        work.policy,
        tmp_path / "archive",
        tmp_path / "videos",
        work.signers[0],
    )
    journal = driver.journal
    other = replace(result.reservation, slot="ff" * 32)
    journal.reserve_orders("ab" * 32, (result.reservation, other))
    ceiling = used(journal)
    limit(journal, size=ceiling)
    with pytest.raises(ValueError, match="capacity"):
        journal.put("cd" * 32, "unrelated", {})
    journal.admit(signed, result.reservation.slot)
    shapes = artifact_shapes(work, result, signed)
    journal.put(result.reservation.slot, "announcement_intent", shapes["announcement_intent"])
    assert used(journal) <= ceiling
    with journal.transaction() as db:
        pending = db.execute(
            "SELECT kind,maximum_bytes,consumed FROM capacity_artifacts WHERE slot=?", (other.slot,)
        ).fetchall()
    assert {kind: size for kind, size, consumed in pending if not consumed} == allowances(result)


def expanded_work(work, count):
    originals = work.plan.cases
    cases = tuple(
        originals[i % len(originals)].model_copy(
            update={
                "case_id": f"{i + 1:064x}",
                "video_sha256": f"{i + 10000:064x}",
            }
        )
        for i in range(count)
    )
    plan = plans.validate_work_plan(work.plan.model_copy(update={"cases": cases}), work.policy)
    template = work.options["videos"][0]
    videos = tuple(template.model_copy(update={"sha256": c.video_sha256}) for c in cases)
    return plan, {**work.options, "plan": plan, "videos": videos}


def test_endpoint_void_aggregate_rejects_one_byte_short_before_signing(work, monkeypatch):
    # The legacy transport caps this fixture at 28 cases/window. Keep it valid
    # and exercise the byte boundary without changing that signed policy.
    plan, options = expanded_work(work, 24)
    body = plans.endpoint_proposals(**options)[0]
    arguments = dict(
        plan=plan,
        submission=body.submissions[0],
        policy=work.policy,
        evaluator_hotkey=plan.evaluators[0],
        endpoint_publication_body=body,
        legacy_policy=work.item.legacy_policy,
    )
    result = budget.evaluator_order_budget(**arguments)
    monkeypatch.setattr(budget, "MAX_VOID_BYTES", allowances(result)["void_intent"] - 1)

    def forbidden(*args, **kwargs):
        raise AssertionError("oversized profile reached signing")

    monkeypatch.setattr("umi.open_competition.sign_object", forbidden)
    with pytest.raises(ValueError, match="evaluation void proposal structural capacity"):
        budget.evaluator_order_budget(**arguments)


def test_large_output_profile_rejects_independent_aggregate(policy, runtime, tmp_path):
    # Authenticate a real fixture cutoff under the larger output profile.
    work = work_fixture.__wrapped__(
        policy.model_copy(update={"maximum_output_bytes": 4096}),
        runtime,
        tmp_path,
        SimpleNamespace(param="umi-open-competition-policy/2"),
    )
    plan, _ = expanded_work(work, 480)
    submission = next(s for s in plan.submissions if s.submission.track == "model")
    with pytest.raises(ValueError, match="independent evaluation evidence structural capacity"):
        budget.evaluator_order_budget(
            plan=plan,
            submission=submission,
            policy=work.policy,
            evaluator_hotkey=plan.evaluators[0],
        )


def test_paired_evidence_bound_rejects_one_byte_short_before_outer_artifacts(work, monkeypatch):
    plan, options = expanded_work(work, 24)
    body = plans.endpoint_proposals(**options)[0]
    arguments = dict(
        plan=plan,
        submission=body.submissions[0],
        policy=work.policy,
        evaluator_hotkey=plan.evaluators[0],
        endpoint_publication_body=body,
        legacy_policy=work.item.legacy_policy,
    )
    result = budget.evaluator_order_budget(**arguments)
    announcement_overhead = budget.object_bound(
        {
            "schema": budget.json_size("umi-execution-announcement/1"),
            "order_sha256": 66,
            "evaluator_hotkey": 66,
            "evidence": 0,
        }
    )
    paired_size = allowances(result)["announcement_intent"] - announcement_overhead
    monkeypatch.setattr(budget, "MAX_PAIRED_BYTES", paired_size - 1)
    with pytest.raises(ValueError, match="paired endpoint evidence structural capacity"):
        budget.evaluator_order_budget(**arguments)


def test_transcript_bound_is_not_clamped_at_protocol_cap(work):
    assignment = plans.endpoint_proposals(**work.options)[0].assignments[0]
    limits = replace(
        Limits.from_policy(work.item.legacy_policy), maximum_response_body_bytes=1024**2
    )
    with pytest.raises(ValueError, match="endpoint transcript structural capacity"):
        budget._dispatch_bound(assignment, limits)


def test_signature_publication_and_void_certificate_caps_are_checked(work, monkeypatch):
    result, signed = prepared(work, "endpoint")
    body = signed.order.publication.publication
    groups = len({e.control_group for e in work.policy.evaluators})
    publication_size = budget.object_bound(
        {
            "publication": budget.json_size(body),
            "signatures": budget.repeated_array_bound(budget.signature_bound(), groups),
        }
    )
    options = dict(
        plan=work.plan,
        submission=body.submissions[0],
        policy=work.policy,
        evaluator_hotkey=work.plan.evaluators[0],
        endpoint_publication_body=body,
        legacy_policy=work.item.legacy_policy,
    )
    with monkeypatch.context() as patched:
        patched.setattr(budget, "MAX_AUTHORIZATION_BYTES", publication_size - 1)
        with pytest.raises(ValueError, match="signed endpoint publication structural capacity"):
            budget.evaluator_order_budget(**options)
    void_size = allowances(result)["void_intent"]
    monkeypatch.setattr(budget, "MAX_VOID_BYTES", void_size)
    with pytest.raises(ValueError, match="evaluation void certificate structural capacity"):
        budget.evaluator_order_budget(**options)


@pytest.mark.parametrize("maximum", [1, 4096])
@pytest.mark.parametrize(
    "reason", ["ok", "deadline", "output_limit", "invalid_utf8", "process_failed"]
)
@pytest.mark.parametrize("returncode", [-65536, 65536, None])
def test_full_execution_receipt_fields_fit(maximum, reason, returncode):
    receipt = OfflineCaseExecution(
        schema="umi-offline-case-execution/1",
        model_sha256="ab" * 32,
        runtime_sha256="cd" * 32,
        video_sha256="ef" * 32,
        output=CaseOutput(
            case_id="12" * 32, status="ok", hypothesis="\x00" * maximum, elapsed_ms=86_400_000
        ),
        stdout_hex="00" * (maximum + 1),
        reason=reason,
        returncode=returncode,
    )
    step = ExecutionStep(
        role="incumbent", started=boundary(), finished=boundary(), execution=receipt
    )
    assert budget.json_size(step) <= budget._step_bound(maximum)


@pytest.mark.parametrize("track", ["model", "endpoint"])
def test_structural_formulas_cover_current_model_field_sets(work, track, monkeypatch):
    fields = set()
    original = budget.object_bound

    def record_sizes(sizes):
        fields.add(frozenset(sizes))
        return original(sizes)

    monkeypatch.setattr(budget, "object_bound", record_sizes)
    prepared(work, track)
    models = [
        CaseOutput,
        OfflineCaseExecution,
        ExecutionStep,
        ExecutionBoundary,
        ExecutionAnnouncement,
        SignedExecutionAnnouncement,
        EvaluationResult,
        EvaluatorRunRecord,
        SignedEvaluatorRunRecord,
        EvaluationVote,
        IndependentEvaluationEvidence,
        AttestedResult,
        EvaluationVoid,
        AttestedEvaluationVoid,
        EvaluationVoidVote,
        VoidEvaluationEvidence,
        IndependentEvidenceObservation,
        VoidEvidenceObservation,
        Signature,
        SignedEvaluationOrder,
    ]
    if track == "endpoint":
        models.extend(
            [
                EndpointIncumbentEvidence,
                EndpointPairedEvidence,
                EndpointDispatchEvidence,
                RetainedRevealPulse,
            ]
        )
    else:
        models.append(ModelExecutionEvidence)
    for model in models:
        expected = frozenset(field.alias or name for name, field in model.model_fields.items())
        assert expected in fields, model.__name__
