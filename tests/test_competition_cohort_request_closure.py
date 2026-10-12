"""Complete native closure, delayed certification and evaluator recovery."""

import json

import pytest

from umi.competition_cohort_availability import CohortAvailabilityObservation
from umi.competition_cohort_closed_endpoint import replay_closed_endpoint_quality
from umi.competition_cohort_coordinator import AttestedCohortPhaseProgress, CohortDecisionInput
from umi.competition_cohort_endpoint_archive import EndpointReplayArchive, JournalEndpointObjects
from umi.competition_cohort_endpoint_decision import parse_case_review
from umi.competition_cohort_endpoint_terminal import EndpointTerminalSelection
from umi.competition_cohort_execution_journal import (
    CohortExecutionAssignment,
    CohortExecutionJournal,
)
from umi.competition_cohort_history import verify_cohort_history
from umi.competition_cohort_order_signer import CohortOrderHistory, order_slot
from umi.competition_cohort_recovery import propose_recovery_transition
from umi.competition_cohort_request_closure import (
    CohortRequestClosure,
    PendingRequestCertification,
    PendingRequestClosure,
    review_request_closure,
    unfinished_request_miners,
    verify_certified_request_closure,
)
from umi.competition_cohort_request_inventory import SignedRequestInventory
from umi.competition_cohort_request_partial import (
    PartialEndpointResponse,
    PartialExecutionStep,
    PartialRequestManifest,
)
from umi.competition_cohort_request_progress import (
    RequestClosureProgressEvidence,
    request_closure_progress,
    retain_request_closure_progress,
)
from umi.competition_cohort_request_tail import (
    MINIMUM_REQUEST_OPEN_MS,
    RequestTailObservation,
    original_request_miners,
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
from .test_competition_cohort_roster import close, make_round
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


def certified_history(b, *, result=None, unavailable=1200, reveal_result="ab" * 32, serving=True):
    observation = b["closure"].observation
    block = observation.block
    state = verify_cohort_history(
        b["history"], b["policy"], expected_tip_sha256=tip(b["history"]), current_block=block
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
        observation=observation,
        serving=serving,
        unavailable_blocks=unavailable,
    )
    benchmark = b["closure"]
    if hasattr(benchmark, "benchmark_closure_sha256"):
        benchmark = CohortRequestClosure.model_validate_json(
            b["objects"][benchmark.benchmark_closure_sha256]
        )
    progress, evidence = request_closure_progress(b["closure"], service, state, tail=benchmark.tail)
    put(b, evidence)
    if result is not None:
        progress = progress.model_copy(update={"phase_result_sha256": result})
    decision = CohortDecisionInput(
        schema="umi-cohort-decision-input/1",
        progress=AttestedCohortPhaseProgress(progress=progress, signatures=signatures(progress)),
        observation=observation,
    )
    b["decisions"][digest(decision)] = decision
    proposed = propose_recovery_transition(
        state,
        b["history"].authority.authority,
        operation="close_phase",
        observed_at_block=block,
        evidence_sha256=digest(decision),
        request_tail_sha256=progress.request_tail_sha256,
    )
    h = b["history"].model_copy(
        update={"transitions": (*b["history"].transitions, signed_transition(proposed))}
    )
    return close(h, b["policy"], b["decisions"], block + 90, reveal_result)


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


async def test_tail_preserves_genuine_complete_and_partial_originals(scenario, tmp_path):
    prepared = make_round(
        scenario,
        include_outcomes=False,
        participant_names=("Alice", "Bob", *(f"Tail{i}" for i in range(9))),
    )
    b = await closure_fixture(scenario, tmp_path, prepared=prepared)
    original = b["closure"]
    legacy_bytes = canonical_json_bytes(original)
    assert b'"tail"' not in legacy_bytes and b'"skipped"' not in legacy_bytes
    assert (
        canonical_json_bytes(CohortRequestClosure.model_validate_json(legacy_bytes)) == legacy_bytes
    )
    order = b["orders"][0]
    missing = (digest(order), identity(order.order.evaluators[-1]))
    who = identity(order.order.submission.submission.hotkey)
    opened = next(
        t.transition for t in b["history"].transitions if t.transition.phase == "preparation"
    )
    tail = RequestTailObservation(
        schema="umi-cohort-request-tail-observation/1",
        opened_observation=b["decisions"][opened.evidence_sha256].observation,
        opened_timestamp_ms=1000,
        selected_observation=boundary(original.observation.block - 1),
        selected_timestamp_ms=1000 + MINIMUM_REQUEST_OPEN_MS,
        observation=original.observation,
        observed_timestamp_ms=1001 + MINIMUM_REQUEST_OPEN_MS,
        original_hotkeys=original_request_miners(b["roster"]),
        unfinished_hotkeys=(who,),
    )

    def terminals(selected, evaluator):
        key = digest(selected), identity(evaluator)
        return None if key == missing else b["terminals"][key]

    def partial_manifest(terminal_key, *, count=1):
        terminal = b["terminals"][terminal_key].terminal
        archive = RequestExecutionArchive.model_validate_json(
            b["objects"][terminal.execution_archive_sha256]
        )
        manifest = PartialRequestManifest(
            schema="umi-cohort-partial-request/1",
            assignment_sha256=terminal.assignment_sha256,
            steps=tuple(
                PartialExecutionStep(index=i, sha256=sha)
                for i, sha in enumerate(archive.steps[:count])
            ),
            cases=(),
            responses=(),
        )
        return put(b, manifest), manifest

    partial_sha, manifest = partial_manifest(missing)
    result = build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (partial_sha,))
    assert result.schema_ == "umi-cohort-request-closure/3"
    assert len(result.participants) == 10
    assert len(result.skipped) == 1 and len(result.skipped[0].evaluators) == 1
    assert unfinished_request_miners(result, b["roster"]) == (who,)
    omitted = digest(order.order.submission.submission)
    assert result.participants == tuple(
        p for p in original.participants if p.submission_sha256 != omitted
    )
    partial = next(p for p in original.participants if p.submission_sha256 == omitted)
    assert result.skipped[0].evaluators == partial.evaluators[:-1]
    assert review(b, closure=result) == result

    # A raw partial, a stale authentic snapshot, or a forged snapshot cannot
    # establish what the original evaluator retained after the selected cutoff.
    from .cohort_tail_settlement_fixture import inventory_original

    with pytest.raises(PendingRequestClosure) as unsigned:
        build(
            b,
            terminal_source=terminals,
            tail=tail,
            partial_source=lambda _: (partial_sha,),
            inventory_source=None,
        )
    assert unsigned.value.obligations == ((omitted, "authenticated_inventory"),)
    signed_inventory = SignedRequestInventory.model_validate_json(
        b["objects"][result.skipped[0].inventory_sha256s[0]]
    )
    forged = put(
        b,
        signed_inventory.model_copy(
            update={
                "inventory": signed_inventory.inventory.model_copy(
                    update={"observation": boundary(original.observation.block - 1)}
                )
            }
        ),
    )
    for invalid in (
        forged,
        inventory_original(b, partial_sha, tail.selected_observation),
        inventory_original(b, partial_sha, boundary(original.observation.block + 1)),
    ):
        changed = result.skipped[0].model_copy(update={"inventory_sha256s": (invalid,)})
        with pytest.raises(ValueError):
            review(b, closure=result.model_copy(update={"skipped": (changed,)}))
    signature = signed_inventory.signature.model_copy(update={"signature": "0x" + "00" * 64})
    forged = put(b, signed_inventory.model_copy(update={"signature": signature}))
    changed = result.skipped[0].model_copy(update={"inventory_sha256s": (forged,)})
    with pytest.raises(ValueError):
        review(b, closure=result.model_copy(update={"skipped": (changed,)}))

    # Missing delivery cannot establish that no completed original work exists.
    with pytest.raises(PendingRequestClosure) as inventory:
        build(b, terminal_source=terminals, tail=tail)
    assert inventory.value.obligations == ((omitted, f"partial_inventory:{missing[1]}"),)
    changed = result.skipped[0].model_copy(update={"retained_objects": ()})
    with pytest.raises(PendingRequestClosure):
        review(b, closure=result.model_copy(update={"skipped": (changed,)}))
    with pytest.raises(PendingRequestClosure) as order_inventory:
        build(b, orders=b["orders"][1:], tail=tail)
    assert order_inventory.value.obligations == ((omitted, "order_inventory"),)
    empty_sha, _ = partial_manifest(missing, count=0)
    empty = build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (empty_sha,))
    assert empty.skipped[0].retained_objects == (empty_sha,)

    # Original completed work survives; the actual cutoff is this observation,
    # not a retrospectively imposed earlier 12-hour deadline.
    assert build(b, tail=tail).participants == original.participants
    damaged = result.skipped[0].model_copy(update={"evaluators": partial.evaluators})
    with pytest.raises(ValueError, match="strict original evaluator subset"):
        review(b, closure=result.model_copy(update={"skipped": (damaged,)}))
    with pytest.raises(ValueError, match="complete accepted roster"):
        review(b, closure=result.model_copy(update={"skipped": ()}))
    shifted = tail.model_copy(update={"opened_observation": boundary(391)})
    with pytest.raises(ValueError, match="original preparation"):
        review(b, closure=result.model_copy(update={"tail": shifted}))

    # Neither a corrupt source nor a missing referenced object becomes absence.
    def corrupt(selected, evaluator):
        if (digest(selected), identity(evaluator)) == missing:
            raise ValueError("damaged signed original")
        return terminals(selected, evaluator)

    with pytest.raises(ValueError, match="damaged signed original"):
        build(b, terminal_source=corrupt, tail=tail)
    with pytest.raises((KeyError, FileNotFoundError)):
        build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: ("ff" * 32,))
    wrong = result.skipped[0].evaluators[0].model_copy(update={"terminal_sha256": "ff" * 32})
    damaged = result.skipped[0].model_copy(update={"evaluators": (wrong,)})
    with pytest.raises((KeyError, FileNotFoundError)):
        review(b, closure=result.model_copy(update={"skipped": (damaged,)}))

    assert result.skipped[0].retained_objects == (partial_sha,)
    assert review(b, closure=result) == result
    duplicate, _ = partial_manifest(missing, count=2)
    with pytest.raises(ValueError, match="repeats an evaluator"):
        build(
            b,
            terminal_source=terminals,
            tail=tail,
            partial_source=lambda _: (partial_sha, duplicate),
        )
    full_key = digest(order), identity(order.order.evaluators[0])
    overlapping, _ = partial_manifest(full_key)
    with pytest.raises(ValueError, match="repeats an evaluator"):
        build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (overlapping,))
    other_key = next(key for key in b["terminals"] if key[0] != digest(order))
    other_sha, _ = partial_manifest(other_key)
    with pytest.raises(ValueError, match="exact original order"):
        build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (other_sha,))
    assignment = CohortExecutionAssignment.model_validate_json(
        b["objects"][manifest.assignment_sha256]
    )
    other_assignment = CohortExecutionAssignment.model_validate_json(
        b["objects"][b["terminals"][other_key].terminal.assignment_sha256]
    )
    changed = assignment.model_copy(update={"participant": other_assignment.participant})
    altered = put(b, manifest.model_copy(update={"assignment_sha256": put(b, changed)}))
    with pytest.raises(ValueError, match="original participant"):
        build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (altered,))

    # Completion certificates themselves are never eligible for the tail rule.
    complete_sha, complete = partial_manifest(missing, count=4096)
    endpoint_sha = b["terminals"][missing].terminal.endpoint_archive_sha256
    if endpoint_sha is not None:
        endpoint = EndpointReplayArchive.model_validate_json(b["objects"][endpoint_sha])
        case_terminals = EndpointTerminalSelection.model_validate_json(
            b["objects"][endpoint.terminal_sha256]
        )
        complete_sha = put(b, complete.model_copy(update={"cases": case_terminals.cases}))
        case = case_terminals.cases[0]
        case_review = parse_case_review(b["objects"][case.review_sha256])
        assert case_review.recovered is not None
        response = PartialEndpointResponse(
            case_id=case.case_id,
            selection_sha256=put(b, case_review.selection),
            response_sha256=put(b, case_review.recovered),
        )
        response_only = manifest.model_copy(update={"responses": (response,)})
        response_sha = put(b, response_only)
        # This signed response cannot finish native case certification without
        # a miner-signed retirement. Preserve it as authenticated partial work;
        # an offline miner must not defeat the selected tail cutoff.
        response_closure = build(
            b, terminal_source=terminals, tail=tail, partial_source=lambda _: (response_sha,)
        )
        assert response_closure.skipped[0].retained_objects == (response_sha,)
        assert review(b, closure=response_closure) == response_closure
        response = response.model_copy(update={"retirement_sha256": put(b, case_review.retirement)})
        ready_case = manifest.model_copy(update={"responses": (response,)})
        ready_sha = put(b, ready_case)
        with pytest.raises(PendingRequestCertification) as case_certification:
            build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (ready_sha,))
        assert case_certification.value.obligations == (
            (omitted, f"case_certification:{missing[1]}:{case.case_id}"),
        )
        certified_case_sha = put(b, ready_case.model_copy(update={"cases": (case,)}))
        assert build(
            b,
            terminal_source=terminals,
            tail=tail,
            partial_source=lambda _: (certified_case_sha,),
        ).skipped[0].retained_objects == (certified_case_sha,)
    with pytest.raises(PendingRequestCertification) as certification:
        build(b, terminal_source=terminals, tail=tail, partial_source=lambda _: (complete_sha,))
    assert certification.value.obligations[0][1].startswith("terminal_certification:")

    # Existing phase signatures certify the new exact manifest and retain the
    # original history. No zero, retirement, or replacement cohort is created.
    b["closure"] = result
    h = certified_history(b, unavailable=1_000_000, serving=False)
    closed_requests = h.transitions[2].transition
    decision = b["decisions"][closed_requests.evidence_sha256]
    progress = decision.progress.progress
    assert progress.schema_ == "umi-cohort-phase-progress/2"
    assert progress.unavailable_blocks == 1_000_000
    assert progress.request_tail_sha256 == digest(result.tail)
    assert closed_requests.request_tail_sha256 == digest(result.tail)
    evidence = RequestClosureProgressEvidence.model_validate_json(
        b["objects"][progress.evidence_sha256]
    )
    assert not evidence.service.serving
    assert evidence.request_tail_sha256 == digest(result.tail)
    assert (
        review(b, certified=True, history=h, expected_tip_sha256=tip(h), current_block=1770)
        == result
    )
    forged = result.model_copy(
        update={
            "tail": result.tail.model_copy(
                update={"observed_timestamp_ms": result.tail.observed_timestamp_ms + 1}
            )
        }
    )
    with pytest.raises(ValueError, match="exact closure manifest"):
        review(
            b,
            closure=forged,
            certified=True,
            history=h,
            expected_tip_sha256=tip(h),
            current_block=1770,
        )


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
