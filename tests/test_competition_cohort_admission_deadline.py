"""Deadline admission fencing keeps accepted work and signed history intact."""

import pytest

from umi.competition_cohort_admission_deadline import OperatorAdmissionDeadline
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadReservation,
    SignedDirectModelUploadReservation,
)
from umi.competition_cohort_intake import CohortIntake, CohortIntakeFenced, history_tip
from umi.competition_cohort_participation import CohortParticipationRequest
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at, request_for
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import bundle_at, submission, wallet
from .test_open_competition import policy as policy

DEADLINE_MS = 1_800_000_000_000


def selection_for(intake, scenario, **changes):
    history = scenario["intake_history"]
    return OperatorAdmissionDeadline.model_validate(
        {
            "schema": "umi-cohort-operator-admission-deadline/1",
            "cohort_sha256": digest(history.plan),
            "authority_sha256": digest(history.authority.authority),
            "authorized_history_tip_sha256": history_tip(history),
            "close_new_admissions_at_unix_ms": DEADLINE_MS,
            "source_sha256": "a1" * 32,
            "operator_plan_sha256": "b2" * 32,
            "reason": "Explicit operator decision to close new admissions",
        }
        | changes
    )


def selected(intake, scenario, **changes):
    config = intake.config.model_copy(
        update={"admission_deadlines": (selection_for(intake, scenario, **changes),)}
    )
    return CohortIntake(config, intake.policy, eligible_tracks=intake.tracks)


def clock(monkeypatch, milliseconds):
    monkeypatch.setattr(
        "umi.competition_cohort_intake.time.time_ns", lambda: milliseconds * 1_000_000
    )


@pytest.mark.parametrize("offset", [-1, 0, 1])
def test_new_admission_has_exact_wallclock_boundary(intake, scenario, monkeypatch, offset):
    owner = selected(intake, scenario)
    clock(monkeypatch, DEADLINE_MS + offset)
    request = request_for(scenario)
    before = canonical_json_bytes(owner.history(request.consent.consent.cohort_sha256))
    if offset < 0:
        assert owner.retain(request, capture_at(210))["certified"] is False
    else:
        with pytest.raises(CohortIntakeFenced, match="operator deadline"):
            owner.retain(request, capture_at(210))
    assert canonical_json_bytes(owner.history(request.consent.consent.cohort_sha256)) == before


def test_accepted_exact_receipt_retry_survives_deadline(intake, scenario, monkeypatch):
    owner = selected(intake, scenario)
    request = request_for(scenario)
    clock(monkeypatch, DEADLINE_MS - 1)
    receipt = owner.retain(request, capture_at(210))
    clock(monkeypatch, DEADLINE_MS + 1)
    assert owner.retain(request, capture_at(230)) == receipt
    with pytest.raises(CohortIntakeFenced, match="operator deadline"):
        owner.retain(request_for(scenario, sequence=2), capture_at(230))


def test_reserved_exact_request_finishes_after_deadline_and_restart(intake, scenario, monkeypatch):
    owner = selected(intake, scenario)
    request = request_for(scenario)
    clock(monkeypatch, DEADLINE_MS - 1)
    with owner._connection() as (db, store):
        owner.require_new_admission(
            db, store.published_history(request.consent.consent.cohort_sha256), request
        )
    # Removing the config entry cannot reopen a retained cutoff; the exact
    # accepted reservation remains usable by the restarted process.
    restarted = CohortIntake(intake.config, intake.policy)
    clock(monkeypatch, DEADLINE_MS + 1)
    assert restarted.retain(request, capture_at(210))["certified"] is False
    with pytest.raises(CohortIntakeFenced, match="operator deadline"):
        restarted.retain(request_for(scenario, sequence=2), capture_at(230))


def test_direct_selection_reuses_retained_deadline_and_authorization_without_replay(
    intake, scenario, monkeypatch
):
    from umi.competition_cohort_recovery_store import CohortRecoveryStore

    owner = selected(intake, scenario)
    request = request_for(scenario)
    cohort = request.consent.consent.cohort_sha256
    clock(monkeypatch, DEADLINE_MS - 1)
    with owner._connection() as (db, store):
        owner.require_new_admission(db, store.published_history(cohort), request)
    restarted = CohortIntake(intake.config, intake.policy)

    def no_replay(*args, **kwargs):
        raise AssertionError("selection must not replay signed cohort history")

    monkeypatch.setattr(CohortRecoveryStore, "published_history", no_replay)
    clock(monkeypatch, DEADLINE_MS + 1)
    with restarted.direct_upload_selection_context(cohort) as (deadline, permitted):
        assert deadline == selection_for(intake, scenario)
        assert permitted == {digest(request)}


@pytest.mark.parametrize("offset", [0, 1])
def test_new_delivery_reservation_cannot_create_late_permit(intake, scenario, monkeypatch, offset):
    owner = selected(intake, scenario)
    clock(monkeypatch, DEADLINE_MS + offset)
    request = request_for(scenario)
    with owner._connection() as (db, store):
        with pytest.raises(CohortIntakeFenced, match="operator deadline"):
            owner.require_new_admission(
                db, store.published_history(request.consent.consent.cohort_sha256), request
            )
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_reservations").fetchone() == (0,)


@pytest.mark.parametrize(
    "field",
    ["authority_sha256", "authorized_history_tip_sha256", "source_sha256", "operator_plan_sha256"],
)
def test_wrong_deadline_bindings_refuse_selection(intake, scenario, field):
    with pytest.raises(ValueError, match="operator authority"):
        selected(intake, scenario, **{field: "0" * 64})


def test_restart_cannot_replace_retained_cutoff(intake, scenario):
    selected(intake, scenario)
    with pytest.raises(ValueError, match="cannot be replaced"):
        selected(intake, scenario, close_new_admissions_at_unix_ms=DEADLINE_MS + 1)


def model_request(scenario, tmp_path):
    signed = submission(scenario["policy"], bundle=bundle_at(tmp_path / "model"))
    body = scenario["consent"].consent.model_copy(
        update={"submission_sha256": digest(signed.submission), "hotkey": signed.submission.hotkey}
    )
    consent = type(scenario["consent"])(consent=body, signature=sign_object(body, wallet("Alice")))
    return CohortParticipationRequest(signed_submission=signed, consent=consent)


def reservation_for(request, *, created_at=DEADLINE_MS - 1, signer="Charlie", **changes):
    bundle = request.signed_submission.submission.model_bundle
    total = sum(record.size_bytes for record in bundle.files)
    part_size = 5 * 1024**2
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(request),
        model_sha256=digest(bundle),
        payload_sha256="c3" * 32,
        total_bytes=total,
        file_count=len(bundle.files),
        part_size_bytes=part_size,
        total_parts=(total + part_size - 1) // part_size,
    )
    body = DirectModelUploadReservation.model_validate(
        {
            "schema": "umi-direct-model-upload-reservation/1",
            "cohort_sha256": request.consent.consent.cohort_sha256,
            "hotkey": request.signed_submission.submission.hotkey,
            "payload": payload,
            "attempt_id": "d4" * 32,
            "generation": 1,
            "object_key_sha256": "e5" * 32,
            "provider_upload_id_sha256": "f6" * 32,
            "created_at_unix_ms": created_at,
        }
        | changes
    )
    return SignedDirectModelUploadReservation(
        schema="umi-signed-direct-model-upload-reservation/1",
        reservation=body,
        signature=sign_object(body, wallet(signer)),
    )


def test_preexisting_signed_direct_reservation_completes_after_deadline(
    intake, scenario, monkeypatch, tmp_path
):
    # Prior releases had no admission-permit table: the exact owner-signed
    # reservation is the compatible evidence for their accepted uploads.
    owner = selected(intake, scenario)
    request = model_request(scenario, tmp_path)
    clock(monkeypatch, DEADLINE_MS + 1)
    with owner._connection() as (db, store):
        owner._require_retained_admission(
            db,
            store.published_history(request.consent.consent.cohort_sha256),
            request,
            reservation_for(request),
        )


@pytest.mark.parametrize("change", ["deadline", "signer", "cohort", "hotkey", "request"])
def test_direct_reservation_cannot_authorize_different_or_late_admission(
    intake, scenario, monkeypatch, tmp_path, change
):
    owner = selected(intake, scenario)
    request = model_request(scenario, tmp_path)
    kwargs = {
        "deadline": {"created_at": DEADLINE_MS},
        "signer": {"signer": "Alice"},
        "cohort": {"cohort_sha256": "9a" * 32},
        "hotkey": {"hotkey": wallet("Bob").hotkey.ss58_address},
        "request": {},
    }[change]
    reservation = reservation_for(request, **kwargs)
    if change == "request":
        request = request_for(scenario, sequence=2)
    clock(monkeypatch, DEADLINE_MS + 1)
    with (
        owner._connection() as (db, store),
        pytest.raises(ValueError, match="does not authorize"),
    ):
        owner._require_retained_admission(
            db,
            store.published_history(request.consent.consent.cohort_sha256),
            request,
            reservation,
        )


@pytest.mark.parametrize("offset", [5425, 5426])
def test_retained_ingress_bridge_preserves_only_earlier_signed_reservations(
    intake, scenario, monkeypatch, tmp_path, offset
):
    owner = selected(
        intake,
        scenario,
        legacy_reservations_before_unix_ms=DEADLINE_MS + 5426,
        ingress_cutoff_receipt_sha256="7b" * 32,
    )
    request = model_request(scenario, tmp_path)
    reservation = reservation_for(request, created_at=DEADLINE_MS + offset)
    clock(monkeypatch, DEADLINE_MS + 6000)
    with owner._connection() as (db, store):
        history = store.published_history(request.consent.consent.cohort_sha256)
        if offset < 5426:
            owner._require_retained_admission(db, history, request, reservation)
        else:
            with pytest.raises(ValueError, match="does not authorize"):
                owner._require_retained_admission(db, history, request, reservation)


def test_ingress_bridge_never_extends_new_admission_deadline(intake, scenario, monkeypatch):
    owner = selected(
        intake,
        scenario,
        legacy_reservations_before_unix_ms=DEADLINE_MS + 5426,
        ingress_cutoff_receipt_sha256="7b" * 32,
    )
    request = request_for(scenario)
    clock(monkeypatch, DEADLINE_MS)
    with (
        owner._connection() as (db, store),
        pytest.raises(CohortIntakeFenced, match="operator deadline"),
    ):
        owner.require_new_admission(
            db, store.published_history(request.consent.consent.cohort_sha256), request
        )


@pytest.mark.parametrize(
    "changes",
    [
        {"legacy_reservations_before_unix_ms": DEADLINE_MS + 5426},
        {"ingress_cutoff_receipt_sha256": "7b" * 32},
        {
            "legacy_reservations_before_unix_ms": DEADLINE_MS + 5426,
            "ingress_cutoff_receipt_sha256": "0" * 64,
        },
        {
            "legacy_reservations_before_unix_ms": DEADLINE_MS - 1,
            "ingress_cutoff_receipt_sha256": "7b" * 32,
        },
    ],
)
def test_ingress_bridge_requires_complete_retained_evidence(intake, scenario, changes):
    with pytest.raises(ValueError, match="legacy admission bridge"):
        selection_for(intake, scenario, **changes)


def test_fresh_install_retains_configured_deadline_on_first_history_publication(
    intake, scenario, monkeypatch, tmp_path
):
    config = intake.config.model_copy(
        update={
            "directory": str(tmp_path / "new-intake"),
            "admission_deadlines": (selection_for(intake, scenario),),
        }
    )
    fresh = CohortIntake(config, intake.policy, initialize=True)
    fresh.publish(scenario["intake_history"], capture_at(210))
    restarted = CohortIntake(config.model_copy(update={"admission_deadlines": ()}), intake.policy)
    clock(monkeypatch, DEADLINE_MS)
    with pytest.raises(CohortIntakeFenced, match="operator deadline"):
        restarted.retain(request_for(scenario), capture_at(210))


def test_deadline_status_uses_cached_selection_without_native_io(intake, scenario, monkeypatch):
    owner = selected(intake, scenario)
    cohort = digest(scenario["intake_history"].plan)
    monkeypatch.setattr(owner, "_connection", lambda *a, **kw: pytest.fail("status opened state"))
    clock(monkeypatch, DEADLINE_MS - 2000)
    pending = owner.admission_status(cohort)
    assert pending["new_admissions_open"] is True
    assert pending["eta_seconds"] == 2
    clock(monkeypatch, DEADLINE_MS + 1000)
    closed = owner.admission_status(cohort)
    assert closed["new_admissions_open"] is False
    assert closed["accepted_uploads_may_finish"] is True
    assert closed["percent"] == 100
    assert closed["elapsed_seconds"] == 1
    assert closed["eta_seconds"] == 0
    assert closed["eta_scope"] == "new_admissions_only"


def test_reservation_metadata_capacity_preserves_existing_exact_permit(
    intake, scenario, monkeypatch
):
    from umi.competition_store import AdmissionCapacity, AdmissionCapacityError

    owner = selected(intake, scenario)
    owner.capacity = AdmissionCapacity(maximum_records=1)
    request = request_for(scenario)
    clock(monkeypatch, DEADLINE_MS - 1)
    with owner._connection() as (db, store):
        history = store.published_history(request.consent.consent.cohort_sha256)
        owner.require_new_admission(db, history, request)
        owner.require_new_admission(db, history, request)
        with pytest.raises(AdmissionCapacityError, match="metadata capacity"):
            owner.require_new_admission(db, history, request_for(scenario, sequence=2))
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_reservations").fetchone() == (1,)
