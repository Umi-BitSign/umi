"""Append-only adoption over original native intake/history; chain ports are fixtures."""

import sqlite3

import pytest

from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_order_signer import CohortOrderHistory
from umi.competition_cohort_participation import (
    CohortParticipationConsent,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_recovery import (
    CohortRequestTailAdoption,
    RecoverableCohortPlan,
    apply_recovery_transition,
    cohort_model_delivery,
    propose_recovery_transition,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_request_rule import (
    authenticated_request_tail_rule,
    prepare_request_tail_adoption,
)
from umi.competition_cohort_request_tail import review_request_tail
from umi.competition_cohort_request_tail_owner import select_request_tail
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_coordinator import Harness
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_request_tail_owner import inventory
from .test_competition_cohort_standing_phases import standing
from .test_competition_execution import boundary
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as policy

HARD = "original_request_12h_with_completed_miner/1"
LEGACY = "original_request_12h_at_most_tenth/1"


@pytest.fixture
def original(recovery, policy):
    old, _, _ = recovery
    plan = RecoverableCohortPlan.model_validate(
        old.model_dump(by_alias=True)
        | {
            "schema": "umi-recoverable-cohort-plan/2",
            "sequence": 6,
            "eligible_tracks": ("model",),
            "service_pool_bps": 0,
        }
    )
    authority, genesis, state = standing(plan, policy, model_rewards=True)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    return history, state


def adopt(history, policy, block=450):
    proposal = prepare_request_tail_adoption(history, policy, boundary(block))
    return history.model_copy(
        update={"transitions": (*history.transitions, signed_transition(proposal))}
    )


def test_reserved_adoption_status_uses_native_readonly_snapshot(original, policy, tmp_path):
    history, state = original
    cohort = digest(history.plan)
    path = tmp_path / "consumer.sqlite3"
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.publish_history(history, policy, current_block=220)
    proposal = prepare_request_tail_adoption(history, policy, boundary(220))
    store.reserve_exact(proposal)
    db.close()
    db = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        db.execute("PRAGMA query_only=ON")
        store = CohortRecoveryStore(db)
        with store.read_snapshot():
            assert store.status(cohort) == (state, proposal)
            assert store.published_history(cohort) == history
        assert not db.in_transaction
    finally:
        db.close()


@pytest.mark.parametrize("incoming", ["older", "conflicting", "ordinary_pending"])
def test_consumer_publication_preserves_unmatched_pending_bytes(original, policy, incoming):
    history, state = original
    cohort = digest(history.plan)
    db = sqlite3.connect(":memory:")
    try:
        store = CohortRecoveryStore(db)
        store.publish_history(history, policy, current_block=300)
        proposal = prepare_request_tail_adoption(history, policy, boundary(220))
        updated = adopt(history, policy, block=220)
        if incoming == "older":
            updated = history
        elif incoming == "conflicting":
            updated = adopt(history, policy, block=221)
        else:
            proposal = propose_recovery_transition(
                state,
                history.authority.authority,
                operation="close_phase",
                observed_at_block=300,
                evidence_sha256="e1" * 32,
            )
            updated = history.model_copy(update={"transitions": (signed_transition(proposal),)})
        store.reserve_exact(proposal)
        before = tuple(db.iterdump())
        with pytest.raises(ValueError, match="cannot replace a pending signing decision"):
            store.publish_history(updated, policy, current_block=300)
        assert tuple(db.iterdump()) == before
        assert store.status(cohort) == (state, proposal)
    finally:
        db.close()


def test_reserved_adoption_and_history_suffix_publish_atomically(original, policy):
    history, state = original
    cohort = digest(history.plan)
    updated = adopt(history, policy, block=220)
    adoption = updated.transitions[0]
    adopted = apply_recovery_transition(state, adoption, history.authority, policy)
    close = signed_transition(
        propose_recovery_transition(
            adopted,
            history.authority.authority,
            operation="close_phase",
            observed_at_block=300,
            evidence_sha256="e2" * 32,
        )
    )
    updated = updated.model_copy(update={"transitions": (adoption, close)})
    db = sqlite3.connect(":memory:")
    try:
        store = CohortRecoveryStore(db)
        store.publish_history(history, policy, current_block=300)
        store.reserve_exact(adoption.transition)
        db.execute(
            "CREATE TRIGGER refuse_suffix BEFORE INSERT ON cohort_recovery_decisions "
            "WHEN NEW.sequence=2 BEGIN SELECT RAISE(ABORT, 'lost publication'); END"
        )
        before = tuple(db.iterdump())
        with pytest.raises(sqlite3.IntegrityError, match="lost publication"):
            store.publish_history(updated, policy, current_block=300)
        assert tuple(db.iterdump()) == before
        assert store.status(cohort) == (state, adoption.transition)
        db.execute("DROP TRIGGER refuse_suffix")
        published = store.publish_history(updated, policy, current_block=300)
        assert published.phase == "preparation"
        assert store.status(cohort) == (published, None)
        assert store.published_history(cohort) == updated
        retained = tuple(db.iterdump())
        assert store.publish_history(updated, policy, current_block=300) == published
        assert tuple(db.iterdump()) == retained
    finally:
        db.close()


def test_native_six_retained_model_submissions_keep_original_bytes_and_binding(
    original, policy, tmp_path
):
    history, _ = original
    cohort = digest(history.plan)
    config = CohortIntakeConfig(
        directory=str(tmp_path / "intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=cohort, authority_sha256=digest(history.authority.authority)
            ),
        ),
    )
    intake = CohortIntake(config, policy, eligible_tracks=("model",), initialize=True)
    intake.publish(history, capture_at(210))
    requests, receipts = [], []
    for i in range(6):
        block = 210 + 40 * i
        signed = submission(policy, bundle=bundle_at(tmp_path / f"model{i}"), sequence=i + 1)
        consent = CohortParticipationConsent(
            schema="umi-cohort-participation-consent/1",
            cohort_sha256=cohort,
            authority_sha256=digest(history.authority.authority),
            submission_sha256=digest(signed.submission),
            hotkey=signed.submission.hotkey,
            signed_at_block=block,
            lifetime="until_cohort_completed_or_revoked",
            timing_rule="quorum_recovery_history/1",
            original_submission_expiry_does_not_end_participation=True,
        )
        request = CohortParticipationRequest(
            signed_submission=signed,
            consent=SignedCohortParticipationConsent(
                consent=consent, signature=sign_object(consent, wallet("Alice"))
            ),
        )
        requests.append(request)
        receipts.append(intake.retain(request, capture_at(block)))
    records = intake.export_records(cohort, maximum_bytes=8 * 1024**2, maximum_records=6)
    assert len(records) == 6
    with intake._connection() as (db, _):
        binding = db.execute("SELECT body FROM intake_binding").fetchall()
    old_plan = canonical_json_bytes(history.plan)
    old_history = canonical_json_bytes(history)
    # The operator fences fresh receipts in the native intake before reserving
    # its separate lifecycle controller. Exact accepted retries remain readable.
    proposal = prepare_request_tail_adoption(history, policy, boundary(450))
    stale = prepare_request_tail_adoption(history, policy, boundary(409))
    with pytest.raises(ValueError, match="predates retained participation"):
        intake.reserve_request_tail_adoption(stale)
    with intake._connection() as (_, store):
        assert store.status(cohort)[1] is None
    assert intake.reserve_request_tail_adoption(proposal) == proposal
    intake = CohortIntake(config, policy, eligible_tracks=("model",))
    assert intake.reserve_request_tail_adoption(proposal) == proposal
    assert intake.retain(requests[-1], capture_at(451)) == receipts[-1]
    seventh = submission(policy, bundle=bundle_at(tmp_path / "model6"), sequence=7)
    seventh_consent = requests[-1].consent.consent.model_copy(
        update={
            "submission_sha256": digest(seventh.submission),
            "signed_at_block": 451,
        }
    )
    new_request = CohortParticipationRequest(
        signed_submission=seventh,
        consent=SignedCohortParticipationConsent(
            consent=seventh_consent,
            signature=sign_object(seventh_consent, wallet("Alice")),
        ),
    )
    with pytest.raises(OSError, match="reserved request-rule adoption"):
        intake.retain(new_request, capture_at(451))
    updated = adopt(history, policy)
    intake.publish(updated, capture_at(450))
    intake = CohortIntake(config, policy, eligible_tracks=("model",))
    assert intake.history(cohort) == updated
    assert canonical_json_bytes(updated.plan) == old_plan
    assert canonical_json_bytes(history) == old_history
    assert updated.authority == history.authority and updated.genesis == history.genesis
    assert cohort_model_delivery(updated.plan).mechanism == "coordinator_chunked_v1"
    assert intake.export_records(cohort, maximum_bytes=8 * 1024**2, maximum_records=6) == records
    assert [intake.receipt(request) for request in requests] == receipts
    with intake._connection() as (db, _):
        assert db.execute("SELECT body FROM intake_binding").fetchall() == binding
    exported = CohortOrderHistory(history=updated, decisions=())
    assert exported.inputs() == {}
    state, restored, unavailable = replay_cohort_decisions(
        updated, policy, exported.inputs().__getitem__
    )
    assert state.phase == "intake" and state.targets == original[1].targets
    assert restored == unavailable == 0 and state.request_tail_rule == HARD
    assert authenticated_request_tail_rule(updated, policy) == HARD
    # Publication commits the existing reservation; the next receipt uses the
    # adopted tip without changing any of the original six records.
    newest = intake.retain(new_request, capture_at(451))
    assert newest["proposed_admission"]["recovery_tip_sha256"] == digest(proposal)


def test_native_reservation_restart_and_subsequent_original_request_opening(
    original, policy, tmp_path
):
    history, state = original
    h = Harness(tmp_path, (history.plan, history.authority, state), policy)
    try:
        original_plan = canonical_json_bytes(h.plan)
        before = h.state
        proposal = prepare_request_tail_adoption(history, policy, boundary(220))
        reserved = h.store.reserve(
            h.cohort,
            phase=before.phase,
            operation=proposal.operation,
            observed_at_block=proposal.observed_at_block,
            evidence_sha256=proposal.evidence_sha256,
            request_tail_adoption=proposal.request_tail_adoption,
        )
        assert reserved == proposal
        assert h.tick(h.restart())["status"] == "awaiting_request_tail_adoption_certificate"
        assert h.collects == 0
        signed = signed_transition(reserved)
        h.store.commit(signed)
        h.restart()
        assert h.store.commit(signed) == h.state
        assert h.state.phase == before.phase and h.state.targets == before.targets
        assert canonical_json_bytes(h.plan) == original_plan
        h.advance_to("requests")
        opened = h.publications[-1].transitions[-1].transition
        assert opened.phase == "preparation" and opened.operation == "close_phase"
        expected_clock = opened.observed_at_block
        original_decisions = h.publications[-1].transitions
        h.restart()
        assert h.state.phase == "requests" and h.state.observed_at_block == expected_clock
        assert (
            h.store.export_history(h.cohort, genesis_signatures=h.genesis_signatures).transitions
            == original_decisions
        )
        with pytest.raises(ValueError, match="unavailable or conflicts"):
            prepare_request_tail_adoption(h.publications[-1], policy, boundary(expected_clock + 1))
    finally:
        h.db.close()


@pytest.mark.parametrize("fault", ["signature", "missing", "duplicate", "wrong_plan", "evidence"])
def test_missing_changed_or_conflicting_adoption_cannot_authorize_new_rule(original, policy, fault):
    history, state = original
    proposal = prepare_request_tail_adoption(history, policy, boundary(220))
    signed = signed_transition(proposal)
    if fault == "missing":
        assert authenticated_request_tail_rule(history, policy) == LEGACY
        return
    if fault == "signature":
        signed = signed.model_copy(update={"signatures": history.genesis_signatures})
    elif fault == "duplicate":
        changed = apply_recovery_transition(state, signed, history.authority, policy)
        with pytest.raises(ValueError, match="unavailable or conflicts"):
            propose_recovery_transition(
                changed,
                history.authority.authority,
                operation="adopt_request_tail_rule",
                observed_at_block=221,
                evidence_sha256=proposal.evidence_sha256,
                request_tail_adoption=proposal.request_tail_adoption,
            )
        return
    elif fault == "wrong_plan":
        payload = proposal.request_tail_adoption.model_copy(
            update={"original_plan": history.plan.model_copy(update={"suite_sha256": "ee" * 32})}
        )
        proposal = proposal.model_copy(
            update={"request_tail_adoption": payload, "evidence_sha256": digest(payload)}
        )
    else:
        proposal = proposal.model_copy(update={"evidence_sha256": "ee" * 32})
    if fault in {"wrong_plan", "evidence"}:
        # Native envelope parsing rejects the changed intent before history
        # resolution; no invalid signed transition can cross that boundary.
        with pytest.raises(ValueError, match="differs from original pre-request cohort"):
            signed_transition(proposal)
        return
    changed = history.model_copy(update={"transitions": (signed,)})
    with pytest.raises(ValueError):
        authenticated_request_tail_rule(changed, policy)


def test_c5_and_explicit_plan_override_are_refused(original, recovery):
    history, _ = original
    with pytest.raises(ValueError, match="after C5"):
        CohortRequestTailAdoption(
            schema="umi-cohort-request-tail-adoption/1", original_plan=recovery[0], rule=HARD
        )
    plan = history.plan.model_copy(
        update={
            "request_tail_rule": HARD,
            "schema_": "umi-recoverable-cohort-plan/4",
            "model_delivery": cohort_model_delivery(history.plan),
        }
    )
    with pytest.raises(ValueError, match="after C5"):
        CohortRequestTailAdoption(
            schema="umi-cohort-request-tail-adoption/1", original_plan=plan, rule=HARD
        )


@pytest.mark.parametrize("miners,missing", [(10, 9), (10, 10), (1, 1), (1, 0)])
def test_owner_uses_authenticated_adoption_and_all_miners_exception(
    original, policy, monkeypatch, miners, missing
):
    history, _ = original
    args = inventory(monkeypatch, miners=miners, benchmark_missing=tuple(range(missing)))
    args.update(plan=history.plan, history=adopt(history, policy), policy=policy)
    result = select_request_tail(**args)
    if miners == missing:
        assert result is None
    else:
        assert result.rule == HARD and len(result.unfinished_hotkeys) == missing
    args["history"] = history
    legacy = select_request_tail(**args)
    assert (legacy is None) == (missing * 10 > miners)


def test_independent_review_refuses_hard_rule_without_adoption(original, policy, monkeypatch):
    history, _ = original
    args = inventory(monkeypatch, miners=10, benchmark_missing=tuple(range(9)))
    args.update(plan=history.plan, history=adopt(history, policy), policy=policy)
    tail = select_request_tail(**args)
    with pytest.raises(ValueError, match="original signed cohort plan"):
        review_request_tail(
            tail,
            roster=None,
            history=history,
            policy=policy,
            decision_source=None,
            observation=tail.observation,
        )


def test_preparation_adoption_restarts_lifecycle_without_fake_progress(original, policy, tmp_path):
    from umi.competition_cohort_lifecycle import PHASES, CohortLifecycleService

    history, state = original
    h = Harness(tmp_path, (history.plan, history.authority, state), policy)
    try:
        h.advance_to("preparation")
        history = h.store.export_history(h.cohort, genesis_signatures=h.genesis_signatures)
        proposal = prepare_request_tail_adoption(history, policy, boundary(h.block + 1))
        h.store.commit(signed_transition(proposal))

        async def unavailable():
            pytest.fail("construction must not open a phase driver")

        service = CohortLifecycleService(
            h.store,
            h.cohort,
            policy,
            h.genesis_signatures,
            h,
            h.publish,
            {phase: unavailable for phase in PHASES},
        )
        assert service.phase == "preparation" and service.expected_round_sha256 is None
        h.advance_to("requests")
        service = CohortLifecycleService(
            h.store,
            h.cohort,
            policy,
            h.genesis_signatures,
            h,
            h.publish,
            {phase: unavailable for phase in PHASES},
        )
        assert service.phase == "requests" and service.expected_round_sha256 == "c1" * 32
    finally:
        h.db.close()


def test_adoption_preserves_native_service_outage_chain(original, policy, tmp_path):
    from umi.competition_cohort_availability import CohortServiceAvailability

    history, state = original
    h = Harness(tmp_path, (history.plan, history.authority, state), policy)
    try:
        observer = CohortServiceAvailability(h.store, policy)

        def observe(block, serving):
            return observer.observe(
                h.cohort,
                capture_at(block),
                serving=serving,
                genesis_signatures=h.genesis_signatures,
            )

        first = observe(200, True)
        unavailable = observe(205, False)
        assert unavailable.unavailable_blocks == 5
        proposal = prepare_request_tail_adoption(history, policy, boundary(205))
        h.store.commit(signed_transition(proposal))
        after = observe(210, True)
        assert after.phase_started_block == first.phase_started_block == 200
        assert after.predecessor_sha256 == digest(unavailable)
        assert after.unavailable_blocks == 10
        assert after.recovery_tip_sha256 == digest(proposal)
        assert h.state.targets == state.targets
        h.restart()
        reopened = CohortServiceAvailability(h.store, policy)
        assert reopened._last(h.cohort, "intake") == after
    finally:
        h.db.close()
