"""Reward consumers select committed C6 transport without rewriting signed plans."""

import asyncio
import sqlite3
from types import SimpleNamespace

import pytest

from umi import competition_cohort_settlement_boot as settlement
from umi import competition_reward_boot as writer
from umi import competition_reward_coordinator_boot as coordinator
from umi.competition_cohort_history import CohortRecoveryHistory
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_model_transport_selection import (
    committed_model_delivery_selection,
    effective_model_deliveries,
    selected_direct_model_review,
)
from umi.competition_cohort_recovery import (
    ModelDeliveryProfile,
    ModelRewardCohortAuthority,
    SignedCohortRecoveryAuthority,
    admit_recoverable_cohort,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_supervisor_adapters import ProductionSuccessorRuntimeAdapter
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_settlement_boot import selected as selected
from .test_competition_reward_boot import chain as chain
from .test_competition_reward_boot import chain_config as chain_config
from .test_competition_reward_boot import control as control
from .test_competition_reward_boot import direct_reward_config
from .test_competition_reward_boot import inputs as inputs
from .test_competition_reward_boot import policy as policy
from .test_competition_reward_boot import series_case as series_case
from .test_competition_reward_coordinator_boot import config_case as config_case
from .test_open_competition import wallet


@pytest.fixture(params=["writer", "coordinator", "settlement"])
def adopted_case(request, inputs, config_case, selected, tmp_path):
    base = {
        "writer": inputs.value,
        "coordinator": config_case.config,
        "settlement": selected.config,
    }[request.param]
    original_bytes = canonical_json_bytes(base)
    # This fixture explicitly signs its model-reward authority before admission.
    # Production selection never changes any originally installed authority.
    authority = ModelRewardCohortAuthority.model_validate_json(
        canonical_json_bytes(
            {
                **base.series.recovery.authority.model_dump(by_alias=True),
                "schema": "umi-cohort-recovery-authority/3",
                "model_reward_rule": "baseline_or_better_best_score_first_complete/1",
            }
        )
    )
    recovery = SignedCohortRecoveryAuthority(authority=authority, signatures=signatures(authority))
    series = base.series.model_copy(update={"recovery": recovery})
    before = base.model_copy(update={"series": series})
    if request.param == "settlement":
        before = before.model_copy(
            update={
                "executions": tuple(
                    e.model_copy(
                        update={
                            "cohorts": tuple(
                                c.model_copy(update={"authority_sha256": digest(authority)})
                                for c in e.cohorts
                            )
                        }
                    )
                    for e in before.executions
                )
            }
        )
    else:
        before = before.model_copy(
            update={"handoff": before.handoff.model_copy(update={"series_sha256": digest(series)})}
        )
    before = type(before).model_validate_json(canonical_json_bytes(before))
    plan = next(p for p in series.cohorts if p.sequence == 6)
    genesis, _ = admit_recoverable_cohort(plan, recovery, base.policy, admitted_at_block=160)
    history = CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=recovery,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    )
    proposal = prepare_model_delivery_adoption(
        history,
        before.policy,
        expected_tip_sha256=digest(genesis),
        current_block=220,
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=64 * 1024**2,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        ),
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
    )
    signed = signed_transition(proposal)
    amended = history.model_copy(update={"transitions": (signed,)})
    db = sqlite3.connect(tmp_path / "native-adoption.sqlite3")
    store = CohortRecoveryStore(db)
    store.publish_history(history, before.policy, current_block=220)
    store.reserve_exact(proposal)
    pending_dump = tuple(db.iterdump())
    with pytest.raises(ValueError, match="committed owner decision"):
        committed_model_delivery_selection(store, digest(plan), before.policy)
    assert tuple(db.iterdump()) == pending_dump
    store.commit(signed)
    assert committed_model_delivery_selection(store, digest(plan), before.policy).history == amended
    store.publish_history(amended, before.policy, current_block=220)
    committed_dump = tuple(db.iterdump())
    selection = committed_model_delivery_selection(store, digest(plan), before.policy)
    assert tuple(db.iterdump()) == committed_dump
    db.close()
    db = sqlite3.connect(tmp_path / "native-adoption.sqlite3")
    try:
        assert (
            committed_model_delivery_selection(CohortRecoveryStore(db), digest(plan), before.policy)
            == selection
        )
    finally:
        db.close()
    source = direct_reward_config(
        inputs.value, tmp_path, "umi-standing-reward-boot/2"
    ).direct_model_review
    updates = {
        "schema_": {
            "writer": "umi-standing-reward-boot/2",
            "coordinator": "umi-reward-coordinator-config/2",
            "settlement": "umi-cohort-settlement-config/4",
        }[request.param],
        "model_delivery_adoptions": (selection,),
        "direct_model_review": source,
    }
    if request.param == "settlement":
        updates["request_export_directory"] = str(tmp_path / "request-export")
    candidate = type(before).model_validate_json(
        canonical_json_bytes(before.model_copy(update=updates))
    )
    return SimpleNamespace(
        kind=request.param,
        base=base,
        original_bytes=original_bytes,
        before=before,
        candidate=candidate,
        selection=selection,
        history=history,
        amended=amended,
        source=source,
        inputs=inputs,
    )


def test_boot_selects_committed_transport_without_rewriting_original_series(adopted_case):
    h = adopted_case
    assert b'"model_delivery_adoptions"' not in h.original_bytes
    assert (
        canonical_json_bytes(type(h.base).model_validate_json(h.original_bytes)) == h.original_bytes
    )
    assert canonical_json_bytes(h.candidate.series) == canonical_json_bytes(h.before.series)
    assert canonical_json_bytes(h.candidate.manifest) == canonical_json_bytes(h.before.manifest)
    profiles = effective_model_deliveries(
        h.candidate.series, h.candidate.policy, h.candidate.model_delivery_adoptions
    )
    assert profiles[digest(h.history.plan)].mechanism == "direct_r2_multipart_v1"
    assert profiles[digest(h.before.series.cohorts[0])].mechanism == "coordinator_chunked_v1"
    assert h.history.plan.initial_targets == h.amended.plan.initial_targets
    assert h.history.plan.not_before_block == h.amended.plan.not_before_block
    assert selected_direct_model_review(h.candidate) == h.source
    assert selected_direct_model_review(h.before) is None


@pytest.mark.parametrize(
    "fault",
    [
        "missing",
        "uncommitted",
        "signature",
        "wrong_tip",
        "future",
        "authority",
        "plan",
        "duplicate",
        "no_source",
    ],
)
def test_unselected_or_invalid_history_cannot_upgrade_reward_transport(adopted_case, fault):
    h = adopted_case
    selection = h.selection
    if fault == "uncommitted":
        selection = selection.model_copy(
            update={"history": h.history, "committed_tip_sha256": digest(h.history.genesis)}
        )
    elif fault == "signature":
        transition = h.amended.transitions[0].model_copy(
            update={"signatures": h.history.genesis_signatures}
        )
        selection = selection.model_copy(
            update={"history": h.amended.model_copy(update={"transitions": (transition,)})}
        )
    elif fault == "wrong_tip":
        selection = selection.model_copy(update={"committed_tip_sha256": "ab" * 32})
    elif fault == "future":
        selection = selection.model_copy(update={"observed_at_block": 219})
    elif fault == "authority":
        selection = selection.model_copy(
            update={"history": h.amended.model_copy(update={"authority": h.base.series.recovery})}
        )
    elif fault == "plan":
        selection = selection.model_copy(
            update={"history": h.amended.model_copy(update={"plan": h.before.series.cohorts[0]})}
        )
    selections = (
        ()
        if fault == "missing"
        else (selection, selection)
        if fault == "duplicate"
        else (selection,)
    )
    changes = {"model_delivery_adoptions": selections}
    if fault == "no_source":
        changes["direct_model_review"] = None
    value = h.candidate.model_copy(update=changes)
    with pytest.raises(ValueError):
        type(value).model_validate_json(canonical_json_bytes(value))
    # The runtime boundary also refuses model_copy bypasses before constructing
    # an R2 credentialed verifier, independently of configuration validation.
    with pytest.raises(ValueError):
        selected_direct_model_review(value)


async def test_actual_boot_constructs_selected_direct_verifier_and_preserves_state_paths(
    adopted_case, monkeypatch, tmp_path
):
    h = adopted_case
    boot = {"writer": writer, "coordinator": coordinator, "settlement": settlement}[h.kind]
    constructed = []

    class ReachedVerifier(Exception):
        pass

    def direct(config, policy, owner, *, verification_root):
        assert config == h.source
        assert policy == h.candidate.policy
        assert verification_root.name == "direct-model-byte-verification"
        constructed.append((owner, verification_root))
        raise ReachedVerifier

    class Provider:
        def __init__(self, *args, **kwargs):
            self.policy = h.candidate.policy

        async def start(self):
            pass

        async def aclose(self):
            pass

    monkeypatch.setattr(boot, "DirectModelArtifactReviewer", direct)
    if h.kind == "writer":
        runtime = SimpleNamespace(
            config=h.inputs.anchor.config,
            adapter=object.__new__(ProductionSuccessorRuntimeAdapter),
            _require_lease=lambda: None,
        )

        def operation():
            return writer.run_installed_standing_rewards(runtime, h.candidate, asyncio.Event())
    else:
        monkeypatch.setattr(boot, "load_named_hotkey", lambda *args: wallet("Charlie"))
        monkeypatch.setattr(
            boot,
            "HistoricalRewardControlProvider"
            if h.kind == "coordinator"
            else "HistoricalRegistrationProvider",
            Provider,
        )

        def operation():
            return (
                coordinator.run_reward_coordinator(h.candidate, asyncio.Event())
                if h.kind == "coordinator"
                else settlement.run_settlement_service(h.candidate, asyncio.Event())
            )

    for _ in range(2):
        with pytest.raises(ReachedVerifier):
            await operation()
    assert len(constructed) == 2 and constructed[0] == constructed[1]
    if h.kind == "settlement":
        assert constructed[0][0] == h.candidate.proposer_hotkey
    else:
        assert constructed[0][0] is None
