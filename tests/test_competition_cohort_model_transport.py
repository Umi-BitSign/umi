"""Signed transport history preserves original plan bytes and durable decisions."""

import sqlite3

import httpx
import pytest

from umi.competition_cohort_coordinator import replay_cohort_decisions
from umi.competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from umi.competition_cohort_model_client import fetch_model_delivery_profile
from umi.competition_cohort_model_transport import (
    authenticated_model_delivery,
    prepare_model_delivery_adoption,
)
from umi.competition_cohort_recovery import (
    CohortModelDeliveryAdoption,
    ModelDeliveryProfile,
    RecoverableCohortPlan,
    apply_recovery_transition,
    cohort_model_delivery,
    propose_recovery_transition,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_coordinator import Harness
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_request_rule_adoption import original as original
from .test_competition_cohort_standing_phases import standing
from .test_open_competition import policy as policy


@pytest.fixture
def delivery():
    return ModelDeliveryProfile(
        schema="umi-model-delivery-profile/1",
        mechanism="direct_r2_multipart_v1",
        part_size_bytes=64 * 1024**2,
        maximum_concurrent_parts=4,
        capability_ttl_seconds=3600,
    )


def prepare(history, policy, delivery, **updates):
    return prepare_model_delivery_adoption(
        history,
        policy,
        **(
            {
                "expected_tip_sha256": digest(history.genesis),
                "current_block": 220,
                "delivery": delivery,
                "legacy_inventory_sha256": "31" * 32,
                "preservation_inventory_sha256": "32" * 32,
            }
            | updates
        ),
    )


def test_effective_profile_preserves_original_signed_plan_and_clocks(original, policy, delivery):
    history, state = original
    plan_bytes, before_bytes = canonical_json_bytes(history.plan), canonical_json_bytes(history)
    proposal = prepare(history, policy, delivery)
    signed = signed_transition(proposal)
    amended = history.model_copy(update={"transitions": (signed,)})
    applied = apply_recovery_transition(state, signed, history.authority, policy)
    assert applied.phase == state.phase == "intake"
    assert applied.targets == state.targets
    assert applied.not_before_block == state.not_before_block
    assert applied.cohort_sha256 == digest(history.plan)
    assert canonical_json_bytes(amended.plan) == plan_bytes
    assert canonical_json_bytes(history) == before_bytes
    assert cohort_model_delivery(amended.plan).mechanism == "coordinator_chunked_v1"
    assert (
        authenticated_model_delivery(
            amended, policy, expected_tip_sha256=digest(proposal), current_block=220
        )
        == delivery
    )
    assert (
        authenticated_model_delivery(
            history, policy, expected_tip_sha256=digest(history.genesis), current_block=220
        ).mechanism
        == "coordinator_chunked_v1"
    )
    assert b"model_delivery_adoption" not in canonical_json_bytes(state)
    assert proposal.schema_ == "umi-cohort-recovery-transition/4"

    def no_progress(_):
        pytest.fail("transport amendment is not fabricated phase progress")

    replayed, restored, unavailable = replay_cohort_decisions(amended, policy, no_progress)
    assert replayed == applied and restored == unavailable == 0


def test_native_store_restart_lost_ack_repeat_and_unchanged_binding(
    original, policy, delivery, tmp_path
):
    history, state = original
    cohort = digest(history.plan)
    path = tmp_path / "native.sqlite3"
    proposal = prepare(history, policy, delivery)
    signed = signed_transition(proposal)
    amended = history.model_copy(update={"transitions": (signed,)})
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.publish_history(history, policy, current_block=220)
    old_binding = db.execute("SELECT body FROM cohort_recovery_bindings").fetchall()
    assert store.reserve_exact(proposal) == proposal
    db.close()
    db = sqlite3.connect(path)
    try:
        store = CohortRecoveryStore(db)
        assert store.status(cohort) == (state, proposal)
        assert store.reserve_exact(proposal) == proposal
        applied = store.commit(signed)
        assert store.commit(signed) == applied
        assert store.publish_history(amended, policy, current_block=220) == applied
        assert db.execute("SELECT body FROM cohort_recovery_bindings").fetchall() == old_binding
        assert store.published_history(cohort) == amended
        assert store.status(cohort) == (applied, None)
        retained = tuple(db.iterdump())
        assert store.reserve_exact(proposal) == proposal
        assert store.commit(signed) == applied
        assert tuple(db.iterdump()) == retained
    finally:
        db.close()


def test_pending_publication_commits_only_exact_transport_adoption(original, policy, delivery):
    history, _ = original
    cohort = digest(history.plan)
    proposal = prepare(history, policy, delivery)
    signed = signed_transition(proposal)
    amended = history.model_copy(update={"transitions": (signed,)})
    db = sqlite3.connect(":memory:")
    try:
        store = CohortRecoveryStore(db)
        store.publish_history(history, policy, current_block=220)
        store.reserve_exact(proposal)
        before = tuple(db.iterdump())
        with pytest.raises(ValueError, match="cannot replace a pending signing decision"):
            store.publish_history(history, policy, current_block=220)
        assert tuple(db.iterdump()) == before
        published = store.publish_history(amended, policy, current_block=220)
        assert store.status(cohort) == (published, None)
        assert store.published_history(cohort) == amended
    finally:
        db.close()


def test_pending_coordinator_reports_transport_hold_without_restart_or_phase_work(
    original, policy, delivery, tmp_path
):
    history, state = original
    h = Harness(tmp_path, (history.plan, history.authority, state), policy)
    try:
        proposal = prepare(history, policy, delivery)
        h.store.reserve_exact(proposal)
        result = h.tick(h.restart())
        assert result["status"] == "awaiting_model_delivery_adoption_certificate"
        assert h.collects == 0
        assert h.state == state
    finally:
        h.db.close()


@pytest.mark.parametrize("fault", ["signature", "wrong_tip", "future", "changed_inventory"])
def test_invalid_history_cannot_select_direct_transport(original, policy, delivery, fault):
    history, _ = original
    proposal = prepare(history, policy, delivery)
    signed = signed_transition(proposal)
    tip, block = digest(proposal), 220
    if fault == "signature":
        signed = signed.model_copy(update={"signatures": history.genesis_signatures})
    elif fault == "wrong_tip":
        tip = digest(history.genesis)
    elif fault == "future":
        block = 219
    else:
        changed = proposal.model_delivery_adoption.model_copy(
            update={"preservation_inventory_sha256": "33" * 32}
        )
        proposal = proposal.model_copy(
            update={"model_delivery_adoption": changed, "evidence_sha256": digest(changed)}
        )
        signed = signed.model_copy(update={"transition": proposal})
        tip = digest(proposal)
    amended = history.model_copy(update={"transitions": (signed,)})
    with pytest.raises(ValueError):
        authenticated_model_delivery(amended, policy, expected_tip_sha256=tip, current_block=block)


@pytest.mark.parametrize("fault", ["duplicate", "preparation", "missing_inventory", "downgrade"])
def test_unsupported_transport_adoption_is_refused(original, policy, delivery, fault):
    history, state = original
    if fault == "missing_inventory":
        with pytest.raises(ValueError, match="complete retained inventories"):
            prepare(history, policy, delivery, legacy_inventory_sha256="0" * 64)
        return
    if fault == "downgrade":
        with pytest.raises(ValueError, match="legacy model cohort after C5"):
            prepare(history, policy, cohort_model_delivery(history.plan))
        return
    proposal = prepare(history, policy, delivery)
    if fault == "duplicate":
        state = apply_recovery_transition(
            state, signed_transition(proposal), history.authority, policy
        )
    else:
        state = state.model_copy(update={"phase": "preparation"})
    with pytest.raises(ValueError, match="unavailable or conflicts"):
        propose_recovery_transition(
            state,
            history.authority.authority,
            operation="adopt_model_delivery",
            observed_at_block=221,
            evidence_sha256=proposal.evidence_sha256,
            model_delivery_adoption=proposal.model_delivery_adoption,
        )


def test_c5_transport_cannot_be_amended(recovery, delivery):
    with pytest.raises(ValueError, match="after C5"):
        CohortModelDeliveryAdoption(
            schema="umi-cohort-model-delivery-adoption/1",
            original_plan=recovery[0],
            delivery=delivery,
            legacy_inventory_sha256="31" * 32,
            preservation_inventory_sha256="32" * 32,
        )


def test_later_closure_retains_transport_without_changing_phase_budgets(original, policy, delivery):
    history, state = original
    proposal = prepare(history, policy, delivery)
    signed = signed_transition(proposal)
    amended_state = apply_recovery_transition(state, signed, history.authority, policy)
    closing = signed_transition(
        propose_recovery_transition(
            amended_state,
            history.authority.authority,
            operation="close_phase",
            observed_at_block=300,
            evidence_sha256="35" * 32,
        )
    )
    amended = history.model_copy(update={"transitions": (signed, closing)})
    view = verify_cohort_history(
        amended, policy, expected_tip_sha256=digest(closing.transition), current_block=300
    )
    assert view.state.phase == "preparation"
    assert view.state.model_delivery_adoption == proposal.model_delivery_adoption
    assert (
        authenticated_model_delivery(
            amended, policy, expected_tip_sha256=digest(closing.transition), current_block=300
        )
        == delivery
    )


@pytest.mark.asyncio
async def test_client_discovers_amendment_from_signed_history(original, policy, delivery):
    history, _ = original
    proposal = prepare(history, policy, delivery)
    amended = history.model_copy(update={"transitions": (signed_transition(proposal),)})
    requests, events = [], []

    def handle(request):
        requests.append((request.method, request.url.path))
        return httpx.Response(
            200,
            content=canonical_json_bytes(amended),
            headers={"content-type": "application/json"},
        )

    result = await fetch_model_delivery_profile(
        origin="https://intake.example",
        policy=policy,
        cohort_sha256=digest(history.plan),
        transport=httpx.MockTransport(handle),
        retry_seconds=0.001,
        report=events.append,
    )
    assert result == delivery
    assert requests == [("GET", f"/v1/competition/cohorts/{digest(history.plan)}/history")]
    assert events


@pytest.mark.parametrize("at_block", [160, 210, 219, 220, 221])
def test_historical_transport_does_not_retroactively_authorize_direct(
    original, policy, delivery, at_block
):
    history, _ = original
    proposal = prepare(history, policy, delivery)
    amended = history.model_copy(update={"transitions": (signed_transition(proposal),)})
    before = canonical_json_bytes(amended)
    result = authenticated_model_delivery(
        amended,
        policy,
        expected_tip_sha256=digest(proposal),
        current_block=230,
        at_block=at_block,
    )
    assert result == (delivery if at_block >= 220 else cohort_model_delivery(history.plan))
    assert canonical_json_bytes(amended) == before


@pytest.mark.parametrize("at_block", [True, 159, 231, 220.0])
def test_historical_transport_requires_a_block_in_the_authenticated_interval(
    original, policy, delivery, at_block
):
    history, _ = original
    proposal = prepare(history, policy, delivery)
    amended = history.model_copy(update={"transitions": (signed_transition(proposal),)})
    with pytest.raises(ValueError, match="historical block"):
        authenticated_model_delivery(
            amended,
            policy,
            expected_tip_sha256=digest(proposal),
            current_block=230,
            at_block=at_block,
        )


def test_historical_selection_authenticates_later_prefix_before_using_old_mode(
    original, policy, delivery
):
    history, _ = original
    proposal = prepare(history, policy, delivery)
    signed = signed_transition(proposal).model_copy(
        update={"signatures": history.genesis_signatures}
    )
    amended = history.model_copy(update={"transitions": (signed,)})
    with pytest.raises(ValueError):
        authenticated_model_delivery(
            amended,
            policy,
            expected_tip_sha256=digest(proposal),
            current_block=230,
            at_block=210,
        )


def test_original_direct_plan_resolves_without_an_amendment(original, policy, delivery):
    old, _ = original
    plan = RecoverableCohortPlan.model_validate(
        old.plan.model_dump(by_alias=True)
        | {"schema": "umi-recoverable-cohort-plan/3", "model_delivery": delivery}
    )
    authority, genesis, _ = standing(plan, policy, model_rewards=True)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    assert (
        authenticated_model_delivery(
            history,
            policy,
            expected_tip_sha256=digest(genesis),
            current_block=230,
            at_block=220,
        )
        == delivery
    )
