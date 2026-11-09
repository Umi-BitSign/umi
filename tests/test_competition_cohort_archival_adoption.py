"""Post-request storage selection preserves original C5 authority and clocks."""

import sqlite3
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from umi.competition_cohort_intake import history_tip
from umi.competition_cohort_model_client import fetch_model_delivery_profile
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_model_transport_selection import (
    committed_model_delivery_selection,
    effective_model_deliveries,
    requires_direct_model_review,
)
from umi.competition_cohort_recovery import (
    PHASES,
    CohortModelDeliveryAdoption,
    apply_recovery_transition,
    cohort_model_delivery,
    propose_recovery_transition,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_standing_phases import standing
from .test_open_competition import policy as policy


def closed_history(plan, policy, *, phase="reference_reveal"):
    authority, genesis, _ = standing(plan, policy)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    return advance_history(history, policy, phase=phase)


def advance_history(history, policy, *, phase="reference_reveal"):
    authority = history.authority
    state = verify_cohort_history(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        current_block=history.genesis.admitted_at_block,
    ).state
    transitions = list(history.transitions)
    while state.phase != phase:
        target = next(t.target_block for t in state.targets if t.phase == state.phase)
        signed = signed_transition(
            propose_recovery_transition(
                state,
                authority.authority,
                operation="close_phase",
                observed_at_block=target,
                evidence_sha256="41" * 32,
            )
        )
        state = apply_recovery_transition(state, signed, authority, policy)
        transitions.append(signed)
    history = history.model_copy(update={"transitions": tuple(transitions)})
    return history, state


def prepare(history, state, policy):
    return prepare_model_delivery_adoption(
        history,
        policy,
        expected_tip_sha256=history_tip(history),
        current_block=state.observed_at_block + 1,
        delivery=cohort_model_delivery(history.plan),
        storage_only=True,
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
    )


@pytest.mark.parametrize("phase", PHASES[3:])
def test_c5_archive_preserves_signed_history_clocks_tracks_and_transport(recovery, policy, phase):
    history, state = closed_history(recovery[0], policy, phase=phase)
    original = canonical_json_bytes(history)
    proposal = prepare(history, state, policy)
    assert proposal.model_delivery_adoption.schema_ == "umi-cohort-model-delivery-adoption/3"
    amended = history.model_copy(
        update={
            "transitions": (*history.transitions, signed_transition(proposal)),
        }
    )
    view = verify_cohort_history(
        amended,
        policy,
        expected_tip_sha256=digest(proposal),
        current_block=proposal.observed_at_block,
    )
    assert view.state.phase == state.phase
    assert view.state.targets == state.targets
    assert view.state.not_before_block == state.not_before_block
    assert canonical_json_bytes(history) == original
    assert amended.plan == history.plan and amended.authority == history.authority
    assert proposal.model_delivery_adoption.delivery == cohort_model_delivery(history.plan)
    assert proposal.model_delivery_adoption.eligible_tracks is None
    assert proposal.model_delivery_adoption.service_pool_bps is None
    with pytest.raises(ValueError, match="unavailable or conflicts"):
        prepare(amended, view.state, policy)


@pytest.mark.parametrize("phase", [*PHASES[:3], "complete", "revoked"])
def test_archival_adoption_cannot_reopen_windows_or_extend_authority(recovery, policy, phase):
    history, state = closed_history(recovery[0], policy)
    adoption = prepare(history, state, policy).model_delivery_adoption
    with pytest.raises(ValueError):
        propose_recovery_transition(
            state.model_copy(update={"phase": phase}),
            history.authority.authority,
            operation="adopt_model_delivery",
            observed_at_block=state.observed_at_block + 1,
            evidence_sha256=digest(adoption),
            model_delivery_adoption=adoption,
        )


@pytest.mark.parametrize("fault", ["direct", "tracks", "split", "old_authority"])
def test_archival_scope_cannot_change_transport_rewards_or_legacy_authority(
    recovery, policy, fault
):
    history, state = closed_history(recovery[0], policy)
    adoption = prepare(history, state, policy).model_delivery_adoption
    data = adoption.model_dump(by_alias=True)
    if fault == "direct":
        data["delivery"] = dict(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=64 * 1024**2,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        )
    elif fault == "tracks":
        data["eligible_tracks"] = ("model",)
    elif fault == "split":
        data["service_pool_bps"] = 0
    else:
        with pytest.raises(ValueError):
            propose_recovery_transition(
                recovery[2].model_copy(update={"phase": "reference_reveal"}),
                recovery[1].authority,
                operation="adopt_model_delivery",
                observed_at_block=500,
                evidence_sha256=digest(adoption),
                model_delivery_adoption=adoption,
            )
        return
    with pytest.raises(ValueError):
        CohortModelDeliveryAdoption.model_validate(data)


def test_c5_archival_restart_repeat_and_boot_selection(recovery, policy, tmp_path):
    history, state = closed_history(recovery[0], policy)
    proposal = prepare(history, state, policy)
    signed = signed_transition(proposal)
    cohort = digest(history.plan)
    path = tmp_path / "native.sqlite3"
    with sqlite3.connect(path) as db:
        store = CohortRecoveryStore(db)
        store.publish_history(history, policy, current_block=proposal.observed_at_block)
        binding = db.execute("SELECT body FROM cohort_recovery_bindings").fetchall()
        store.reserve_exact(proposal)
    with sqlite3.connect(path) as db:
        store = CohortRecoveryStore(db)
        assert store.status(cohort) == (state, proposal)
        with pytest.raises(ValueError, match="awaits the committed"):
            committed_model_delivery_selection(store, cohort, policy)
        applied = store.commit(signed)
        assert store.commit(signed) == applied
        assert store.reserve_exact(proposal) == proposal
        assert db.execute("SELECT body FROM cohort_recovery_bindings").fetchall() == binding
        selection = committed_model_delivery_selection(store, cohort, policy)
        series = SimpleNamespace(cohorts=(history.plan,), recovery=history.authority)
        assert effective_model_deliveries(series, policy, (selection,)) == {
            cohort: cohort_model_delivery(history.plan),
        }
        assert requires_direct_model_review(series, policy, (selection,))
        assert store.published_history(cohort).transitions[:-1] == history.transitions


async def test_miner_reads_archival_history_without_switching_upload_transport(recovery, policy):
    history, state = closed_history(recovery[0], policy)
    proposal = prepare(history, state, policy)
    amended = history.model_copy(
        update={
            "transitions": (*history.transitions, signed_transition(proposal)),
        }
    )
    requests, events = [], []

    def handle(request):
        requests.append(request.url.path)
        return httpx.Response(
            200, content=canonical_json_bytes(amended), headers={"content-type": "application/json"}
        )

    profile = await fetch_model_delivery_profile(
        origin="https://intake.example",
        policy=policy,
        cohort_sha256=digest(history.plan),
        transport=httpx.MockTransport(handle),
        retry_seconds=0.001,
        report=events.append,
    )
    assert profile == cohort_model_delivery(history.plan)
    assert profile.mechanism == "coordinator_chunked_v1"
    assert requests == [f"/v1/competition/cohorts/{digest(history.plan)}/history"]
    assert events
