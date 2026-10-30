"""Issued uploads finish through the real router without recursively locking intake.

Only finality and R2 use fixture ports. The signed transport adoption, upload
owner, acceptance owner, routing and participation retention are production code.
"""

import fcntl
import hashlib
import os
from types import SimpleNamespace

import pytest

from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
    DirectModelUploadOwners,
)
from umi.competition_cohort_direct_model_upload import DirectModelPayload, SignedDirectModelPayload
from umi.competition_cohort_intake import CohortIntake
from umi.competition_cohort_model_acceptance_store import CohortModelAcceptances
from umi.competition_cohort_model_upload import authorize_model_delivery, owned_model_delivery
from umi.competition_cohort_recovery_store import CohortRecoveryStore
from umi.competition_cohort_service_host import CohortModelPayloadRouter
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_admission_deadline import DEADLINE_MS, clock, selection_for
from .test_competition_cohort_direct_model_owner import Multipart
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import adopt_direct_transport
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_model_upload import delivery as delivery
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
async def reserved_router(delivery, tmp_path, monkeypatch, request):
    h = delivery
    clock(monkeypatch, DEADLINE_MS - 1)
    history = adopt_direct_transport(h.intake, h.cohort)
    deadline = selection_for(h.intake, {"intake_history": history})
    intake = CohortIntake(
        h.intake.config.model_copy(update={"admission_deadlines": (deadline,)}),
        h.intake.policy,
        eligible_tracks=h.intake.tracks,
    )
    profile = owned_model_delivery(intake, h.cohort)
    bundle = h.request.signed_submission.submission.model_bundle
    payload_bytes = b"".join((h.source / entry.path).read_bytes() for entry in bundle.files)
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(h.request),
        model_sha256=digest(bundle),
        payload_sha256=hashlib.sha256(payload_bytes).hexdigest(),
        total_bytes=len(payload_bytes),
        file_count=len(bundle.files),
        part_size_bytes=profile.part_size_bytes,
        total_parts=(len(payload_bytes) + profile.part_size_bytes - 1) // profile.part_size_bytes,
    )

    async def authorize(value):
        authorize_model_delivery(intake, value, capture_at(212), mechanism="direct_r2_multipart_v1")

    async def sign(value):
        return sign_object(value, wallet("Charlie"))

    direct = DirectModelUploadOwner(
        DirectModelUploadOwnerConfig(
            schema="umi-direct-model-upload-owner-config/1",
            directory=str(tmp_path / "direct"),
            cohort_sha256=h.cohort,
            owner_hotkey=wallet("Charlie").hotkey.ss58_address,
            delivery=profile,
            maximum_uploads=8,
        ),
        Multipart(payload_bytes),
        authorize=authorize,
        sign=sign,
    )
    signed = await direct.reserve(
        h.request,
        SignedDirectModelPayload(
            schema="umi-signed-direct-model-payload/1",
            payload=payload,
            signature=sign_object(payload, wallet("Alice")),
        ),
        now_unix_ms=DEADLINE_MS + getattr(request, "param", -1),
    )
    # Reproduce an older issuer: its exact signed request and reservation exist,
    # but the newer intake permit table has no corresponding authorization.
    with intake._connection() as (db, _):
        db.execute(
            "DELETE FROM cohort_admission_reservations WHERE request=?", (digest(h.request),)
        )
        assert db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone() == (0,)
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_reservations").fetchone() == (0,)
    acceptances = CohortModelAcceptances(intake, tmp_path / "acceptance-archive")
    router = CohortModelPayloadRouter(
        (history.plan,),
        legacy=h.owner,
        direct=DirectModelUploadOwners({h.cohort: direct}),
        intake=intake,
        acceptances=acceptances,
    )
    return SimpleNamespace(
        intake=intake,
        request=h.request,
        router=router,
        direct=direct,
        reservation=signed,
        history=history,
    )


def forbid_nested_intake_flock(monkeypatch, intake):
    """Exercise the real lock, failing immediately instead of waiting ten seconds."""
    info = (intake.directory / "intake.lock").stat()
    identity = info.st_dev, info.st_ino
    original = fcntl.flock

    def bounded(descriptor, operation):
        try:
            return original(descriptor, operation)
        except BlockingIOError:
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) == identity:
                raise AssertionError(
                    "reservation routing recursively acquired intake.lock"
                ) from None
            raise

    monkeypatch.setattr(fcntl, "flock", bounded)


@pytest.mark.parametrize("competing_receipt", [False, True])
async def test_issued_upload_uses_real_router_outside_intake_lock(
    reserved_router, monkeypatch, competing_receipt
):
    h = reserved_router
    clock(monkeypatch, DEADLINE_MS + 1)
    forbid_nested_intake_flock(monkeypatch, h.intake)
    published_history = CohortRecoveryStore.published_history
    lookups, concurrent, events = [], [], []

    def record_history(store, *args, **kwargs):
        events.append("history")
        return published_history(store, *args, **kwargs)

    monkeypatch.setattr(CohortRecoveryStore, "published_history", record_history)

    def original_reservation(value):
        events.append("reservation")
        lookups.append(value)
        original = h.router.admission_reservation(value)
        if competing_receipt:
            concurrent.append(h.intake.retain(value, capture_at(212), reservation=original))
        return original

    receipt = h.intake.retain(h.request, capture_at(220), reservation_provider=original_reservation)
    assert lookups == [h.request]
    assert events[0] == "reservation", "post-cutoff deferral needlessly replayed history"
    assert receipt["certified"] is False
    if competing_receipt:
        assert concurrent == [receipt]

    def unnecessary_lookup(_):
        pytest.fail("an exact retained receipt must not call the reservation provider")

    assert (
        h.intake.retain(h.request, capture_at(230), reservation_provider=unnecessary_lookup)
        == receipt
    )
    assert h.direct.admission_reservation(h.request) == h.reservation
    with h.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone() == (1,)
        assert db.execute("SELECT COUNT(*) FROM cohort_admission_reservations").fetchone() == (0,)
    assert canonical_json_bytes(h.intake.history(digest(h.history.plan))) == canonical_json_bytes(
        h.history
    )


@pytest.mark.parametrize("permit", [False, True])
async def test_router_lookup_is_not_eager_before_cutoff_or_with_existing_permit(
    reserved_router, monkeypatch, permit
):
    h = reserved_router
    clock(monkeypatch, DEADLINE_MS - 1)
    if permit:
        with h.intake._connection() as (db, store):
            h.intake.require_new_admission(
                db, store.published_history(digest(h.history.plan)), h.request
            )
        clock(monkeypatch, DEADLINE_MS + 1)

    def unnecessary_lookup(_):
        pytest.fail("this admission already has authority without reservation-provider lookup")

    monkeypatch.setattr(h.router, "admission_reservation", unnecessary_lookup)
    receipt = h.intake.retain(
        h.request, capture_at(220), reservation_provider=h.router.admission_reservation
    )
    assert receipt["certified"] is False
    with h.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone() == (1,)


async def test_cutoff_crossed_during_native_history_read_defers_router_lookup(
    reserved_router, monkeypatch
):
    h = reserved_router
    clock(monkeypatch, DEADLINE_MS - 1)
    forbid_nested_intake_flock(monkeypatch, h.intake)
    published_history = CohortRecoveryStore.published_history
    reads, lookups = [], []

    def crossing(store, *args, **kwargs):
        result = published_history(store, *args, **kwargs)
        reads.append(True)
        if len(reads) == 1:
            clock(monkeypatch, DEADLINE_MS + 1)
        return result

    def original_reservation(value):
        lookups.append(value)
        return h.router.admission_reservation(value)

    monkeypatch.setattr(CohortRecoveryStore, "published_history", crossing)
    receipt = h.intake.retain(h.request, capture_at(220), reservation_provider=original_reservation)
    assert receipt["certified"] is False
    assert lookups == [h.request]
    with h.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone() == (1,)


@pytest.mark.parametrize("reserved_router", [0], indirect=True)
async def test_router_cannot_authorize_an_issued_reservation_at_the_cutoff(
    reserved_router, monkeypatch
):
    h = reserved_router
    clock(monkeypatch, DEADLINE_MS + 1)
    forbid_nested_intake_flock(monkeypatch, h.intake)
    with pytest.raises(ValueError, match="does not authorize"):
        h.intake.retain(
            h.request, capture_at(220), reservation_provider=h.router.admission_reservation
        )
    with h.intake._connection() as (db, _):
        assert db.execute("SELECT COUNT(*) FROM cohort_consents").fetchone() == (0,)
