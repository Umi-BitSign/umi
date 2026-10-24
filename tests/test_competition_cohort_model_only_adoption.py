"""Quorum model-only selection preserves admitted mixed-plan bytes and clocks."""

import sqlite3

import pytest

from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_history import CohortRecoveryHistory, verify_cohort_history
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_intake_seal import build_intake_seal
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_participation import (
    CohortParticipationConsent,
    CohortParticipationRequest,
    SignedCohortParticipationConsent,
)
from umi.competition_cohort_participation_status import (
    CohortParticipationStatus,
    participation_status,
)
from umi.competition_cohort_recovery import (
    CohortModelDeliveryAdoption,
    RecoverableCohortPlan,
    apply_recovery_transition,
    cohort_service_pool,
    cohort_tracks,
    verify_cohort_tracks,
)
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_service_allocation import allocate_service_quality
from umi.competition_cohort_service_quality import (
    ClosedServiceQuality,
    ServiceTerms,
    _selected_service_quality,
)
from umi.competition_execution import execution_boundary
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_transport import delivery as delivery
from .test_competition_cohort_participation_status import certify
from .test_competition_cohort_recovery import recovery as recovery
from .test_competition_cohort_recovery import signatures, signed_transition
from .test_competition_cohort_standing_phases import standing
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as policy


@pytest.fixture
def mixed_history(recovery, policy):
    old, _, _ = recovery
    plan = RecoverableCohortPlan.model_validate(
        old.model_dump(by_alias=True)
        | dict(
            schema="umi-recoverable-cohort-plan/2",
            sequence=7,
            eligible_tracks=("endpoint", "model"),
            service_pool_bps=5000,
        )
    )
    authority, genesis, state = standing(plan, policy, model_rewards=True)
    return CohortRecoveryHistory(
        schema="umi-cohort-recovery-history/1",
        plan=plan,
        authority=authority,
        genesis=genesis,
        genesis_signatures=signatures(genesis),
        transitions=(),
    ), state


def proposal(history, policy, delivery, *, model_only=True):
    return prepare_model_delivery_adoption(
        history,
        policy,
        expected_tip_sha256=digest(history.genesis),
        current_block=220,
        delivery=delivery,
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
        model_only=model_only,
    )


def test_model_only_adoption_preserves_original_identity_and_every_clock(
    mixed_history, policy, delivery
):
    history, state = mixed_history
    original = canonical_json_bytes(history)
    transition = proposal(history, policy, delivery)
    signed = signed_transition(transition)
    amended = history.model_copy(update={"transitions": (signed,)})
    applied = apply_recovery_transition(state, signed, history.authority, policy)
    verified = verify_cohort_history(
        amended, policy, expected_tip_sha256=digest(transition), current_block=220
    ).state
    assert applied == verified
    assert applied.cohort_sha256 == digest(history.plan)
    assert applied.targets == state.targets and applied.not_before_block == state.not_before_block
    assert applied.phase == state.phase == "intake"
    assert canonical_json_bytes(history) == original
    assert canonical_json_bytes(amended.plan) == canonical_json_bytes(history.plan)
    adoption = applied.model_delivery_adoption
    assert adoption.schema_ == "umi-cohort-model-delivery-adoption/2"
    assert cohort_tracks(history.plan, ("endpoint", "model"), adoption=adoption) == ("model",)
    assert cohort_tracks(history.plan, ("model",), adoption=adoption) == ("model",)
    verify_cohort_tracks(history.plan, ("model",), adoption=adoption)
    assert cohort_service_pool(history.plan, 5000, adoption=adoption) == 0
    assert history.plan.eligible_tracks == ("endpoint", "model")
    assert history.plan.service_pool_bps == 5000
    with pytest.raises(ValueError, match="reward split"):
        cohort_service_pool(history.plan, 4000, adoption=adoption)


def test_transport_only_amendment_keeps_its_original_bytes_and_pool(
    mixed_history, policy, delivery
):
    history, _ = mixed_history
    transition = proposal(history, policy, delivery, model_only=False)
    adoption = transition.model_delivery_adoption
    raw = canonical_json_bytes(adoption)
    assert b"eligible_tracks" not in raw.split(b'"original_plan"')[0]
    assert set(adoption.model_dump(mode="json", by_alias=True)) == {
        "schema",
        "original_plan",
        "delivery",
        "legacy_inventory_sha256",
        "preservation_inventory_sha256",
    }
    assert cohort_tracks(history.plan, ("endpoint", "model"), adoption=adoption) == (
        "endpoint",
        "model",
    )
    assert cohort_service_pool(history.plan, 5000, adoption=adoption) == 5000


@pytest.mark.parametrize("fault", ["missing_tracks", "missing_pool", "service_pool", "old_version"])
def test_profile_version_refuses_partial_or_unexpected_selection(
    mixed_history, policy, delivery, fault
):
    history, _ = mixed_history
    value = proposal(history, policy, delivery).model_delivery_adoption.model_dump(by_alias=True)
    if fault == "missing_tracks":
        value.pop("eligible_tracks")
    elif fault == "missing_pool":
        value.pop("service_pool_bps")
    elif fault == "service_pool":
        value["service_pool_bps"] = 5000
    else:
        value["schema"] = "umi-cohort-model-delivery-adoption/1"
    with pytest.raises(ValueError):
        CohortModelDeliveryAdoption.model_validate(value)


def test_profile_cannot_be_borrowed_by_a_different_original_plan(mixed_history, policy, delivery):
    history, _ = mixed_history
    adoption = proposal(history, policy, delivery).model_delivery_adoption
    different = history.plan.model_copy(update={"sequence": 8})
    with pytest.raises(ValueError, match="original signed plan"):
        cohort_tracks(different, ("endpoint", "model"), adoption=adoption)


def test_native_commit_restart_preserves_original_binding_and_exact_profile(
    mixed_history, policy, delivery, tmp_path
):
    history, state = mixed_history
    transition = proposal(history, policy, delivery)
    signed = signed_transition(transition)
    path = tmp_path / "history.sqlite3"
    db = sqlite3.connect(path)
    store = CohortRecoveryStore(db)
    store.publish_history(history, policy, current_block=220)
    original_binding = db.execute("SELECT body FROM cohort_recovery_bindings").fetchall()
    store.reserve_exact(transition)
    store.commit(signed)
    db.close()
    db = sqlite3.connect(path)
    try:
        store = CohortRecoveryStore(db)
        current, pending = store.status(digest(history.plan))
        assert pending is None and current.targets == state.targets
        assert current.model_delivery_adoption == transition.model_delivery_adoption
        assert (
            db.execute("SELECT body FROM cohort_recovery_bindings").fetchall() == original_binding
        )
        assert store.commit(signed) == current
    finally:
        db.close()


def participation(history, policy, *, bundle=None, sequence=1):
    signed = submission(policy, bundle=bundle, sequence=sequence)
    consent = CohortParticipationConsent(
        schema="umi-cohort-participation-consent/1",
        cohort_sha256=digest(history.plan),
        authority_sha256=digest(history.authority.authority),
        submission_sha256=digest(signed.submission),
        hotkey=signed.submission.hotkey,
        signed_at_block=200,
        lifetime="until_cohort_completed_or_revoked",
        timing_rule="quorum_recovery_history/1",
        original_submission_expiry_does_not_end_participation=True,
    )
    return CohortParticipationRequest(
        signed_submission=signed,
        consent=SignedCohortParticipationConsent(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )


def test_intake_amendment_preserves_receipts_and_selects_only_models(
    mixed_history, policy, delivery, tmp_path
):
    history, _ = mixed_history
    cohort = digest(history.plan)
    config = CohortIntakeConfig(
        directory=str(tmp_path / "intake"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=cohort, authority_sha256=digest(history.authority.authority)
            ),
        ),
    )
    intake = CohortIntake(config, policy, eligible_tracks=("endpoint", "model"), initialize=True)
    intake.publish(history, capture_at(210))
    endpoint = participation(history, policy)
    retained = intake.retain(endpoint, capture_at(210))
    queue = CohortAdmissionQueue(intake)
    certify(queue, endpoint, block=210)
    before = participation_status(
        queue,
        cohort,
        wallet("Alice").hotkey.ss58_address,
        "endpoint",
        capture_at(210),
        nonce="ab" * 16,
    )
    original_status = before.model_dump(mode="json", by_alias=True)
    assert before.schema_ == "umi-cohort-participation-status/1"
    assert "profile_tracks" not in original_status
    assert "profile_service_pool_bps" not in original_status
    assert CohortParticipationStatus.model_validate_json(canonical_json_bytes(before)) == before

    transition = proposal(history, policy, delivery)
    amended = history.model_copy(update={"transitions": (signed_transition(transition),)})
    intake.publish(amended, capture_at(220))
    # Recovery of an existing signed obligation precedes the new-track fence.
    assert intake.retain(endpoint, capture_at(221)) == retained
    assert intake.receipt(endpoint)["proposed_admission"] == retained["proposed_admission"]
    with pytest.raises(ValueError, match="cohort consent"):
        intake.retain(participation(history, policy, sequence=2), capture_at(221))
    model = participation(history, policy, bundle=bundle_at(tmp_path / "model"))
    intake.retain(model, capture_at(221))

    reopened = CohortIntake(config, policy, eligible_tracks=("endpoint", "model"))
    for track in ("endpoint", "model"):
        value = participation_status(
            CohortAdmissionQueue(reopened),
            cohort,
            wallet("Alice").hotkey.ss58_address,
            track,
            capture_at(230),
            nonce="cd" * 16,
        )
        assert value.schema_ == "umi-cohort-participation-status/2"
        assert value.profile_tracks == ("model",) and value.profile_service_pool_bps == 0
        assert CohortParticipationStatus.model_validate_json(canonical_json_bytes(value)) == value
        enabled = track == "model"
        assert value.intake_fenced == (not enabled)
        assert (value.minimum_next_sequence is not None) == enabled
        assert value.latest is not None
        if track == "endpoint":
            assert value.latest.admission.status == "admission_certified"
    capture = capture_at(300)
    seal = build_intake_seal(
        amended,
        policy,
        execution_boundary(capture),
        capture.snapshot,
        intake.export_records(cohort, maximum_bytes=1024**2, maximum_records=8),
        expected_tip_sha256=digest(transition),
    )
    assert seal.record_count == 2
    assert len(seal.selected) == 1 and seal.selected[0].track == "model"
    assert seal.selected[0].consent_sha256 == digest(model.consent.consent)
    assert intake.receipt(endpoint)["proposed_admission"] == retained["proposed_admission"]


@pytest.mark.parametrize("host_tracks", [("endpoint",), ("model",)])
def test_profile_status_respects_older_host_capabilities_without_rebinding_state(
    mixed_history, policy, delivery, tmp_path, host_tracks
):
    history, _ = mixed_history
    transition = proposal(history, policy, delivery)
    amended = history.model_copy(update={"transitions": (signed_transition(transition),)})
    cohort = digest(history.plan)
    config = CohortIntakeConfig(
        directory=str(tmp_path / "older-host"),
        cohorts=(
            CohortIntakeBinding(
                cohort_sha256=cohort, authority_sha256=digest(history.authority.authority)
            ),
        ),
    )
    intake = CohortIntake(config, policy, eligible_tracks=host_tracks, initialize=True)
    intake.publish(amended, capture_at(220))
    for track in ("endpoint", "model"):
        value = participation_status(
            CohortAdmissionQueue(intake),
            cohort,
            wallet("Alice").hotkey.ss58_address,
            track,
            capture_at(230),
            nonce="ab" * 16,
        )
        enabled = track == "model" and track in host_tracks
        assert value.intake_fenced == (not enabled)
        assert (value.minimum_next_sequence is not None) == enabled
        assert value.latest is None and value.profile_tracks == ("model",)


def test_adopted_budget_uses_original_terms_without_paid_credit(mixed_history, policy, delivery):
    history, _ = mixed_history
    profile = proposal(history, policy, delivery).model_delivery_adoption
    terms = ServiceTerms(
        schema="umi-cohort-service-terms/1",
        policy_sha256=digest(policy),
        transport_policy_sha256="44" * 32,
        service_pool_bps=5000,
        stratum_weights={"fingerspelling": 3, "continuous": 10},
    )
    original_terms = canonical_json_bytes(terms)
    old = ClosedServiceQuality(
        schema="umi-cohort-service-quality/1",
        terms_sha256=digest(terms),
        request_closure_sha256="45" * 32,
        reference_reveal_sha256="46" * 32,
        work=(),
    )
    assert set(old.model_dump(by_alias=True)) == {
        "schema",
        "terms_sha256",
        "request_closure_sha256",
        "reference_reveal_sha256",
        "work",
        "chain_submission_authorized",
    }
    # Exercise the native replay's derived-result boundary after decoding the
    # same JSON shape restored from a completed verification receipt.
    restored = ClosedServiceQuality.model_validate_json(canonical_json_bytes(old))
    adopted = _selected_service_quality(restored, history.plan, terms, adoption=profile)
    assert adopted.schema_ == "umi-cohort-service-quality/3"
    assert adopted.model_profile_sha256 == digest(profile)
    assert _selected_service_quality(restored, history.plan, terms) is restored
    assert allocate_service_quality(old, terms).service_budget > 0
    amounts = allocate_service_quality(adopted, terms)
    assert amounts.model_budget == 65535
    assert amounts.service_budget == amounts.burn_weight == 0
    assert amounts.recipients == ()
    assert canonical_json_bytes(terms) == original_terms
    for key in ("adopted_service_pool_bps", "model_profile_sha256"):
        malformed = adopted.model_dump(by_alias=True)
        malformed.pop(key)
        with pytest.raises(ValueError, match="explicit profile"):
            ClosedServiceQuality.model_validate(malformed)
    from .test_competition_cohort_service_allocation import work

    with pytest.raises(ValueError, match="completed paid work"):
        ClosedServiceQuality.model_validate(
            adopted.model_dump(by_alias=True)
            | {"work": (work(1, wallet("Alice").hotkey.ss58_address),)}
        )
