"""Owned transport routing and exact retries across a signed C6 amendment.

Finality and R2 are synthetic ports. Intake/history, authorization, payload
journals and acceptance reservations are the native production implementations.
"""

import fcntl
import os
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_model_acceptance_store import CohortModelAcceptances
from umi.competition_cohort_model_transport import prepare_model_delivery_adoption
from umi.competition_cohort_model_upload import (
    CohortModelUploads,
    authorize_model_delivery,
    owned_model_delivery,
)
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_cohort_service_host import CohortModelPayloadRouter, _startup_model_delivery
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import adopt_direct_transport, certify
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_model_upload import delivery as delivery
from .test_competition_cohort_model_upload import upload_all
from .test_competition_cohort_recovery import signed_transition

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def proposal_for(intake, cohort, block=211):
    history = intake.history(cohort)
    return prepare_model_delivery_adoption(
        history,
        intake.policy,
        expected_tip_sha256=digest(
            history.transitions[-1].transition if history.transitions else history.genesis
        ),
        current_block=block,
        delivery=ModelDeliveryProfile(
            schema="umi-model-delivery-profile/1",
            mechanism="direct_r2_multipart_v1",
            part_size_bytes=5 * 1024**2,
            maximum_concurrent_parts=4,
            capability_ttl_seconds=3600,
        ),
        legacy_inventory_sha256="31" * 32,
        preservation_inventory_sha256="32" * 32,
    )


def reserve_adoption(intake, cohort):
    proposal = proposal_for(intake, cohort)
    with intake._connection() as (_, store):
        store.reserve_exact(proposal)
    return proposal


class Payloads:
    def __init__(self):
        self.requests = []
        self.config = SimpleNamespace(maximum_concurrent_uploads=1)

    def require_payload(self, request):
        self.requests.append(request)

    def review_artifact(self, request):
        return ("direct", request)


def test_new_transport_requires_committed_owner_history_and_fresh_finality(delivery):
    h = delivery
    original = canonical_json_bytes(h.intake.history(h.cohort).plan)
    with pytest.raises(ValueError, match="authenticated transport"):
        authorize_model_delivery(
            h.intake, h.request, capture_at(210), mechanism="direct_r2_multipart_v1"
        )
    pending = reserve_adoption(h.intake, h.cohort)
    for mechanism in ("coordinator_chunked_v1", "direct_r2_multipart_v1"):
        with pytest.raises(OSError, match="reserved policy adoption"):
            authorize_model_delivery(h.intake, h.request, capture_at(211), mechanism=mechanism)
    assert not h.owner.journal.keys("upload")
    history = h.intake.history(h.cohort)
    amended = history.model_copy(update={"transitions": (signed_transition(pending),)})
    h.intake.publish(amended, capture_at(211))
    with pytest.raises(ValueError, match="finalized observation"):
        authorize_model_delivery(
            h.intake, h.request, capture_at(210), mechanism="direct_r2_multipart_v1"
        )
    authorized = authorize_model_delivery(
        h.intake, h.request, capture_at(211), mechanism="direct_r2_multipart_v1"
    )
    assert authorized[1] == digest(h.request)
    with pytest.raises(ValueError, match="authenticated transport"):
        h.owner.reserve(h.request, capture_at(211))
    assert not h.owner.journal.keys("upload")
    assert canonical_json_bytes(h.intake.history(h.cohort).plan) == original


def test_retained_legacy_upload_restarts_and_finishes_without_new_authority(delivery):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    raw = h.owner.journal.get_raw("upload", key)
    reserve_adoption(h.intake, h.cohort)
    resumed = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    assert resumed.reserve(h.request, None) == key
    assert resumed.retry(h.request) == key
    upload_all(h, resumed, key)
    adopt_direct_transport(h.intake, h.cohort)
    assert resumed.reserve(h.request, None) == key
    assert resumed.journal.get_raw("upload", key) == raw
    assert resumed.status(key)["payload_preserved"] is True


def test_legacy_reservation_holds_native_intake_fence_through_journal_commit(delivery, monkeypatch):
    h = delivery
    original = h.owner.journal.put_many
    calls = []

    def commit(records):
        fd = os.open(h.intake.directory / "intake.lock", os.O_RDWR)
        try:
            with pytest.raises(BlockingIOError):
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            calls.append(True)
        finally:
            os.close(fd)
        return original(records)

    monkeypatch.setattr(h.owner.journal, "put_many", commit)
    assert h.owner.reserve(h.request, capture_at(210)) == digest(h.request)
    assert calls == [True]


def test_live_router_uses_published_adoption_and_requires_matching_deployment(delivery):
    h = delivery
    plan = h.intake.history(h.cohort).plan
    router = CohortModelPayloadRouter((plan,), legacy=h.owner, intake=h.intake)
    assert "model_upload_url" in router.delivery_route(h.cohort)
    reserve_adoption(h.intake, h.cohort)
    with pytest.raises(OSError, match="reserved policy adoption"):
        router.delivery_route(h.cohort)
    amended = adopt_direct_transport(h.intake, h.cohort)
    with pytest.raises(OSError, match="supported host deployment"):
        router.delivery_route(h.cohort)
    direct = Payloads()
    resumed = CohortModelPayloadRouter((plan,), legacy=h.owner, direct=direct, intake=h.intake)
    assert "direct_model_upload_url" in resumed.delivery_route(h.cohort)
    resumed.require_payload(h.request)
    assert direct.requests == [h.request]
    assert (
        _startup_model_delivery(h.intake, plan)
        == amended.transitions[-1].transition.model_delivery_adoption.delivery
    )
    assert h.intake.history(h.cohort).plan == plan


async def test_discovery_holds_during_adoption_then_advertises_effective_route(delivery):
    h = delivery
    plan = h.intake.history(h.cohort).plan
    router = CohortModelPayloadRouter((plan,), legacy=h.owner, intake=h.intake)
    app = FastAPI()
    app.include_router(
        cohort_routes(h.intake, h.capture, maximum_body_bytes=4 * 1024**2, models=router)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.get("/v1/competition/cohorts")
        assert response.status_code == 200
        assert "model_upload_url" in response.json()["cohorts"][0]
        reserve_adoption(h.intake, h.cohort)
        response = await client.get("/v1/competition/cohorts")
        assert response.status_code == 503
        adopt_direct_transport(h.intake, h.cohort)
        router.direct = Payloads()
        response = await client.get("/v1/competition/cohorts")
        assert response.status_code == 200
        entry = response.json()["cohorts"][0]
        assert entry["cohort_sha256"] == digest(plan)
        assert "direct_model_upload_url" in entry
        assert "model_upload_url" not in entry


def test_retained_acceptance_retry_keeps_legacy_bytes_without_current_artifact(prepared, tmp_path):
    owner, cohort, subs, inputs = prepared
    publication = certify(owner, cohort, subs[0], inputs, block=210)
    body = canonical_json_bytes(publication.certificate.acceptance)
    reserve_adoption(owner.intake, cohort)

    def offline(*args):
        pytest.fail("retained intent retry touched current upload or payload")

    resumed = CohortModelAcceptances(
        owner.intake,
        tmp_path / "offline",
        verify_request=offline,
        review_artifact=offline,
    )
    assert canonical_json_bytes(resumed.prepare(cohort, digest(subs[0]), inputs, None)) == body
    adopt_direct_transport(owner.intake, cohort)
    assert canonical_json_bytes(resumed.prepare(cohort, digest(subs[0]), inputs, None)) == body
    assert resumed.intent(cohort, digest(subs[0])).acceptance.direct_artifact is None
    with pytest.raises(ValueError, match="original review"):
        resumed.prepare(
            cohort,
            digest(subs[0]),
            inputs.model_copy(update={"rights_evidence": {"changed": True}}),
            None,
        )


@pytest.mark.parametrize("gate", ["pending_before", "pending_during", "published_during"])
def test_new_acceptance_fenced_at_start_and_final_reservation(prepared, gate):
    owner, cohort, subs, inputs = prepared
    if gate == "pending_during":
        owner.verify_request = lambda _: reserve_adoption(owner.intake, cohort)
    elif gate == "published_during":
        owner.verify_request = lambda _: adopt_direct_transport(owner.intake, cohort)
    else:
        reserve_adoption(owner.intake, cohort)
    expected = "intake changed" if gate == "published_during" else "reserved policy adoption"
    with pytest.raises(OSError, match=expected):
        owner.prepare(cohort, digest(subs[0]), inputs, capture_at(212))
    assert owner.intent(cohort, digest(subs[0])) is None


def test_new_legacy_acceptance_rejected_after_adoption(prepared):
    owner, cohort, subs, inputs = prepared
    adopt_direct_transport(owner.intake, cohort)

    def unnecessary_payload_read(_):
        pytest.fail("mismatched transport performed payload verification")

    owner.verify_request = unnecessary_payload_read
    with pytest.raises(ValueError, match="authenticated transport"):
        owner.prepare(cohort, digest(subs[0]), inputs, capture_at(212))
    assert owner.intent(cohort, digest(subs[0])) is None


def test_retained_legacy_acceptance_publication_uses_its_original_source(prepared):
    owner, cohort, subs, inputs = prepared
    publication = certify(owner, cohort, subs[0], inputs, block=210)
    request = owner.review_request(cohort, digest(subs[0])).record.request
    plan = owner.intake.history(cohort).plan
    adopt_direct_transport(owner.intake, cohort)
    legacy, direct = Payloads(), Payloads()
    router = CohortModelPayloadRouter(
        (plan,), legacy=legacy, direct=direct, intake=owner.intake, acceptances=owner
    )
    owner.verify_request = router.require_payload
    owner.review_artifact = router.review_artifact
    assert router.review_artifact(request) is None
    assert owner.publish(publication, capture_at(212)) == publication
    assert legacy.requests == [request]
    assert direct.requests == []
    assert "direct_model_upload_url" in router.delivery_route(cohort)


@pytest.mark.parametrize("damage", ["genesis", "binding"])
def test_missing_history_never_falls_back_to_original_transport(delivery, damage):
    h = delivery
    plan = h.intake.history(h.cohort).plan
    adopt_direct_transport(h.intake, h.cohort)
    with h.intake._connection() as (db, _):
        table = "cohort_published_genesis" if damage == "genesis" else "cohort_recovery_bindings"
        db.execute(f"DELETE FROM {table} WHERE cohort=?", (h.cohort,))
    with pytest.raises(ValueError, match="admission"):
        _startup_model_delivery(h.intake, plan)
    with pytest.raises(ValueError, match="admission"):
        owned_model_delivery(h.intake, h.cohort)
