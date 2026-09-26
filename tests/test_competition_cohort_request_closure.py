"""Complete native closure, delayed certification and evaluator recovery."""

import json

import pytest

from umi.competition_cohort_availability import CohortAvailabilityObservation
from umi.competition_cohort_closed_endpoint import replay_closed_endpoint_quality
from umi.competition_cohort_coordinator import AttestedCohortPhaseProgress, CohortDecisionInput
from umi.competition_cohort_endpoint_archive import JournalEndpointObjects
from umi.competition_cohort_execution_journal import CohortExecutionJournal
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_order_signer import CohortOrderHistory, order_slot
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.competition_cohort_request_closure import (
    PendingRequestClosure,
    review_request_closure,
    verify_certified_request_closure,
)
from umi.competition_cohort_request_progress import (
    request_closure_progress,
    retain_request_closure_progress,
)
from umi.competition_cohort_request_terminal import (
    RequestExecutionArchive,
    SignedRequestTerminal,
    seal_request_terminal,
)
from umi.competition_endpoint_execution import RetainedRevealPulse
from umi.open_competition import digest, identity, sign_object
from umi.protocol import canonical_json_bytes

from .cohort_request_closure_fixture import build, closure_fixture
from .test_competition_cohort_consumers import tip, transition
from .test_competition_cohort_disposition import base_policy as base_policy
from .test_competition_cohort_disposition import endpoint as endpoint
from .test_competition_cohort_disposition import legacy_scenario as legacy_scenario
from .test_competition_cohort_disposition import policy as policy
from .test_competition_cohort_disposition import receipt_scenario as receipt_scenario
from .test_competition_cohort_disposition import recovery as recovery
from .test_competition_cohort_disposition import runtime as runtime
from .test_competition_cohort_disposition import scenario as scenario
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_roster import close
from .test_competition_execution import boundary
from .test_drand import pulse_record
from .test_open_competition import wallet


@pytest.fixture
async def closed(scenario, tmp_path):
    return await closure_fixture(scenario, tmp_path)


def review(b, *, certified=False, **changes):
    args = dict(
        closure=b["closure"],
        roster=b["roster"],
        objects=b["objects"].__getitem__,
        policy=b["policy"],
        history=b["history"],
        decision_source=b["decisions"].__getitem__,
        intake_records=iter(b["records"]),
        expected_tip_sha256=tip(b["history"]),
        current_block=1680,
    )
    args.update(changes)
    fn = verify_certified_request_closure if certified else review_request_closure
    return fn(**args)


def certified_history(b, *, result=None, unavailable=1200):
    state = verify_cohort_history(
        b["history"], b["policy"], expected_tip_sha256=tip(b["history"]), current_block=1680
    ).state
    service = CohortAvailabilityObservation(
        schema="umi-cohort-service-observation/1",
        cohort_sha256=state.cohort_sha256,
        recovery_tip_sha256=state.tip_sha256,
        phase="requests",
        phase_started_block=390,
        sequence=1,
        predecessor_sha256=None,
        process_epoch="12" * 16,
        observation=boundary(1680),
        serving=True,
        unavailable_blocks=unavailable,
    )
    progress, evidence = request_closure_progress(b["closure"], service, state)
    put(b, evidence)
    if result is not None:
        progress = progress.model_copy(update={"phase_result_sha256": result})
    decision = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress)),
        observation=boundary(1680),
    )
    b["decisions"][digest(decision)] = decision
    proposed = propose_recovery_transition(
        state,
        b["history"].authority.authority,
        operation="close_phase",
        observed_at_block=1680,
        evidence_sha256=digest(decision),
    )
    h = b["history"].model_copy(
        update={"transitions": (*b["history"].transitions, signed_transition(proposed))}
    )
    return close(h, b["policy"], b["decisions"], 1770, "ab" * 32)


def put(b, value):
    key = digest(value)
    b["objects"][key] = canonical_json_bytes(value)
    return key


def replace_terminal(b, member_index, evaluator_index, terminal):
    member = b["closure"].participants[member_index]
    refs = list(member.evaluators)
    refs[evaluator_index] = refs[evaluator_index].model_copy(
        update={"terminal_sha256": put(b, terminal)}
    )
    members = list(b["closure"].participants)
    members[member_index] = member.model_copy(update={"evaluators": tuple(refs)})
    b["closure"] = b["closure"].model_copy(update={"participants": tuple(members)})


def test_complete_reference_free_closure_covers_all_miners_and_evaluators(closed):
    b = closed
    assert len(b["closure"].participants) == 2
    assert all(len(p.evaluators) == 2 for p in b["closure"].participants)
    assert review(b) == b["closure"]
    assert all(b'"references"' not in raw for raw in b["objects"].values())
    h = certified_history(b)
    original = canonical_json_bytes(b["closure"])
    for block in (1770, 1000000, 2**53 - 1):
        assert (
            review(b, certified=True, history=h, expected_tip_sha256=tip(h), current_block=block)
            == b["closure"]
        )
    assert canonical_json_bytes(b["closure"]) == original
    assert not b["closure"].chain_submission_authorized


async def test_completed_terminal_recovers_with_endpoint_peer_and_signer_offline(closed):
    b = closed
    for key, old in b["owners"].items():
        order = next(o for o in b["orders"] if digest(o) == key[0])
        owner = CohortExecutionJournal(old.config, b["policy"])

        async def unavailable_sign(_):
            raise OSError("signer offline")

        def unavailable_objects(_):
            raise FileNotFoundError("old endpoint service offline")

        saved = await seal_request_terminal(
            owner, order_slot(order.order), unavailable_sign, endpoint_objects=unavailable_objects
        )
        assert saved == b["terminals"][key]


@pytest.mark.parametrize("missing", ["order", "evaluator"])
def test_missing_member_or_evaluator_is_pending_then_resumes(closed, missing):
    b = closed
    if missing == "order":
        changes = dict(orders=b["orders"][:1])
    else:
        changes = dict(terminal_source=lambda order, who: None)
    with pytest.raises(PendingRequestClosure) as caught:
        build(b, **changes)
    assert caught.value.obligations
    assert build(b) == b["closure"]


@pytest.mark.parametrize(
    "damage",
    [
        "participant_missing",
        "participant_repeated",
        "evaluator_missing",
        "evaluator_repeated",
        "evaluator_reordered",
    ],
)
def test_counts_cannot_replace_exact_complete_coverage(closed, damage):
    b = closed
    members = b["closure"].participants
    if damage == "participant_missing":
        members = members[:1]
    elif damage == "participant_repeated":
        members = (members[0], members[0])
    else:
        first = members[0]
        refs = first.evaluators
        refs = (
            refs[:1]
            if damage.endswith("missing")
            else ((refs[0], refs[0]) if damage.endswith("repeated") else tuple(reversed(refs)))
        )
        members = (first.model_copy(update={"evaluators": refs}), *members[1:])
    with pytest.raises(ValueError):
        review(b, closure=b["closure"].model_copy(update={"participants": members}))


@pytest.mark.parametrize("kind", ["order", "terminal", "execution", "step"])
def test_missing_archive_object_cannot_become_a_valid_partial_closure(closed, kind):
    b = closed
    member = b["closure"].participants[0]
    terminal = SignedRequestTerminal.model_validate_json(
        b["objects"][member.evaluators[0].terminal_sha256]
    )
    execution = RequestExecutionArchive.model_validate_json(
        b["objects"][terminal.terminal.execution_archive_sha256]
    )
    key = {
        "order": member.order_sha256,
        "terminal": member.evaluators[0].terminal_sha256,
        "execution": terminal.terminal.execution_archive_sha256,
        "step": execution.steps[0],
    }[kind]
    raw = b["objects"].pop(key)
    with pytest.raises(KeyError):
        review(b)
    b["objects"][key] = raw
    assert review(b) == b["closure"]


@pytest.mark.parametrize(
    "damage", ["signer", "missing_step", "runtime", "late_step", "bad_output", "role"]
)
def test_signed_terminal_does_not_hide_incomplete_or_invalid_execution(closed, damage):
    b = closed
    ref = b["closure"].participants[0].evaluators[0]
    signed = SignedRequestTerminal.model_validate_json(b["objects"][ref.terminal_sha256])
    name = next(
        n
        for n in ("Charlie", "Dave")
        if identity(wallet(n).hotkey.ss58_address) == identity(ref.evaluator_hotkey)
    )
    if damage != "signer":
        execution = RequestExecutionArchive.model_validate_json(
            b["objects"][signed.terminal.execution_archive_sha256]
        )
        steps = list(execution.steps)
        if damage == "missing_step":
            steps.pop()
        else:
            raw = json.loads(b["objects"][steps[0]])
            if damage == "runtime":
                raw["execution"]["runtime_sha256"] = "ff" * 32
            elif damage == "late_step":
                raw["finished"] = boundary(1681).model_dump(mode="json", by_alias=True)
            elif damage == "bad_output":
                raw["execution"]["stdout_hex"] = b"different\n".hex()
            else:
                raw["role"] = "candidate" if raw["role"] == "incumbent" else "incumbent"
            steps[0] = put(b, raw)
        execution = execution.model_copy(update={"steps": tuple(steps)})
        body = signed.terminal.model_copy(update={"execution_archive_sha256": put(b, execution)})
    else:
        body, name = signed.terminal, "Eve"
    signed = SignedRequestTerminal(terminal=body, signature=sign_object(body, wallet(name)))
    replace_terminal(b, 0, 0, signed)
    with pytest.raises(ValueError):
        review(b)


@pytest.mark.parametrize("damage", ["result", "window", "revoked", "observation"])
def test_native_phase_certificate_must_bind_exact_closure_and_compensated_window(closed, damage):
    b = closed
    h = certified_history(
        b,
        result="ce" * 32 if damage == "result" else None,
        unavailable=1201 if damage == "window" else 1200,
    )
    if damage == "revoked":
        h = transition(h, b["policy"], "revoke", 1800)
    root = b["closure"]
    if damage == "observation":
        root = root.model_copy(update={"observation": boundary(1681)})
    with pytest.raises(ValueError):
        review(
            b,
            certified=True,
            closure=root,
            history=h,
            expected_tip_sha256=tip(h),
            current_block=1000000,
        )


def test_endpoint_quality_consumes_certified_whole_roster_closure(closed):
    b = closed
    roots = [r for r in b["endpoint_archives"].values() if r is not None]
    if not roots:
        assert all(o.order.submission.submission.track == "model" for o in b["orders"])
        return
    h = certified_history(b)

    def replay():
        return replay_closed_endpoint_quality(
            roots[0],
            b["closure"],
            b["roster"],
            b["objects"].__getitem__,
            b["suite"],
            b["policy"],
            h,
            decision_source=b["decisions"].__getitem__,
            intake_records=iter(b["records"]),
            pulses=lambda _: RetainedRevealPulse(**pulse_record()),
            expected_tip_sha256=tip(h),
            current_block=1000000,
        )

    result = replay()
    assert result.request_closure_sha256 == digest(b["closure"])
    assert all(c.numerator == c.denominator for c in result.quality.cases)
    assert all(c.elapsed_ms is None for c in result.quality.cases)
    assert not result.chain_submission_authorized and not result.service_credit_authorized
    # A different miner's missing terminal prevents even this miner's bound view.
    b["objects"].pop(b["closure"].participants[-1].evaluators[-1].terminal_sha256)
    with pytest.raises(KeyError):
        replay()


@pytest.mark.parametrize("after", [False, True])
def test_progress_retention_recovers_without_changing_closure_or_service(closed, after):
    b = closed
    h = certified_history(b)
    progress = b["decisions"][h.transitions[-2].transition.evidence_sha256].progress.progress
    from umi.competition_cohort_request_progress import RequestClosureProgressEvidence

    evidence = RequestClosureProgressEvidence.model_validate_json(
        b["objects"][progress.evidence_sha256]
    )
    state = verify_cohort_history(
        b["history"], b["policy"], expected_tip_sha256=tip(b["history"]), current_block=1680
    ).state
    owner = next(iter(b["owners"].values()))
    objects = JournalEndpointObjects(owner.journal)
    original_put = objects.put
    count = 0

    def interrupted(value):
        nonlocal count
        count += 1
        if count == 2:
            if after:
                original_put(value)
            raise OSError("progress evidence acknowledgement lost")
        return original_put(value)

    objects.put = interrupted
    with pytest.raises(OSError):
        retain_request_closure_progress(b["closure"], evidence.service, state, objects)
    objects = JournalEndpointObjects(CohortExecutionJournal(owner.config, b["policy"]).journal)
    assert (
        retain_request_closure_progress(b["closure"], evidence.service, state, objects) == progress
    )
    assert objects(digest(b["closure"])) == canonical_json_bytes(b["closure"])
    assert objects(digest(evidence)) == canonical_json_bytes(evidence)
    for update in (
        {"serving": False},
        {"observation": boundary(1681)},
        {"unavailable_blocks": 1199},
    ):
        service = evidence.service.model_copy(update=update)
        if "unavailable_blocks" in update:
            assert request_closure_progress(b["closure"], service, state)[0] != progress
        else:
            with pytest.raises(ValueError):
                request_closure_progress(b["closure"], service, state)


@pytest.mark.parametrize(
    "kind,after",
    [
        (k, a)
        for k in ("endpoint_replay_object", "request_terminal_intent", "request_terminal")
        for a in (False, True)
    ],
)
async def test_terminal_export_recovers_interrupted_writes_without_rerunning_execution(
    closed, tmp_path, kind, after
):
    b = closed
    key, old = next(iter(b["owners"].items()))
    order = next(o for o in b["orders"] if digest(o) == key[0])
    slot = order_slot(order.order)
    assignment, evidence = old.assignment(slot), old.evidence(slot)
    cfg = old.config.model_copy(update={"directory": str(tmp_path / "retry")})
    owner = CohortExecutionJournal(cfg, b["policy"])
    source = CohortOrderHistory(
        history=b["history"],
        decisions=tuple(
            b["decisions"][t.transition.evidence_sha256] for t in b["history"].transitions
        ),
    )
    job = owner.retain(assignment, source, 1500)
    for index, step in enumerate(evidence.steps):
        attempt = owner.begin(job, index, source, step.started)
        owner.observe(job, attempt, step.execution)
        owner.finish(job, attempt, step.finished)
    original = canonical_json_bytes(owner.evidence(slot))
    name = next(n for n in ("Charlie", "Dave") if identity(wallet(n).hotkey.ss58_address) == key[1])
    signed_bodies = []

    async def sign(body):
        assert owner.journal.get("request_terminal_intent", slot) is not None
        signed_bodies.append(canonical_json_bytes(body))
        return sign_object(body, wallet(name))

    put_record = owner.journal.put
    failed = False

    def interrupted(record_kind, *args, **kwargs):
        nonlocal failed
        if record_kind == kind and not failed:
            failed = True
            if after:
                put_record(record_kind, *args, **kwargs)
            raise OSError("lost commit acknowledgement")
        return put_record(record_kind, *args, **kwargs)

    owner.journal.put = interrupted
    kwargs = dict(
        endpoint_archive=b["endpoint_archives"][key], endpoint_objects=b["objects"].__getitem__
    )
    with pytest.raises(OSError):
        await seal_request_terminal(owner, slot, sign, **kwargs)
    assert failed
    owner = CohortExecutionJournal(cfg, b["policy"])
    result = await seal_request_terminal(owner, slot, sign, **kwargs)
    again = await seal_request_terminal(owner, slot, sign, **kwargs)
    assert again == result
    assert len(set(signed_bodies)) == 1
    assert canonical_json_bytes(owner.evidence(slot)) == original
    assert JournalEndpointObjects(owner.journal)(digest(result)) == canonical_json_bytes(result)
