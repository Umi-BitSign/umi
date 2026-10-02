from __future__ import annotations

import hashlib
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
    DirectModelUploadPending,
)
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadCompletion,
    DirectModelUploadPart,
    DirectModelUploadPartCapabilities,
    DirectModelUploadPartRequest,
    DirectModelUploadReservationRequest,
    SignedDirectModelPayload,
    SignedDirectModelUploadCompletion,
    SignedDirectModelUploadPartRequest,
    SignedDirectModelUploadReservation,
)
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_cohort_service_host import CohortModelPayloadRouter
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes
from umi.r2_sigv4 import R2Credentials, R2SigV4

from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_roster import retained
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


class Multipart:
    def __init__(self, payload_bytes):
        self.signer = R2SigV4(
            endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
            bucket="umi-model-artifacts",
            credentials=R2Credentials("0123456789ABCDEF", "secret-access-key-value"),
        )
        self.payload_bytes = payload_bytes
        self.total_bytes = len(payload_bytes)
        self.create_calls = []
        self.complete_calls = []
        self.read_calls = 0
        self.objects = {}
        self.fail_creates = 0
        self.fail_after_complete = False

    async def create(self, key, *, at=None):
        self.create_calls.append((key, at))
        if self.fail_creates:
            self.fail_creates -= 1
            raise OSError("provider offline")
        return f"provider-id-{len(self.create_calls)}"

    async def head(self, key, *, at=None):
        value = self.objects.get(key)
        return None if value is None else SimpleNamespace(size_bytes=value[0], etag=value[1])

    async def complete(self, key, *, upload_id, parts, at=None):
        self.complete_calls.append((key, upload_id, parts, at))
        self.objects[key] = (self.total_bytes, "completed-etag-1")
        if self.fail_after_complete:
            raise OSError("response lost after completion")
        return "completed-etag-1"

    async def read_range(self, key, *, offset, size_bytes, at=None):
        assert key in self.objects
        self.read_calls += 1
        return self.payload_bytes[offset : offset + size_bytes]


@pytest.fixture
def direct(tmp_path, receipt_scenario, runtime):
    source = tmp_path / "source"
    scenario = setup_scenario(receipt_scenario, source, runtime)
    request = retained(scenario, "Alice", 1).record.request
    bundle = request.signed_submission.submission.model_bundle
    candidate = source / "candidate"
    payload_bytes = bytearray()
    for record in bundle.files:
        payload_bytes.extend((candidate / record.path).read_bytes())
    stream_hash = hashlib.sha256(payload_bytes)
    total = sum(record.size_bytes for record in bundle.files)
    part_size = 5 * 1024**2
    payload = DirectModelPayload(
        schema="umi-direct-model-payload/1",
        upload_sha256=digest(request),
        model_sha256=digest(bundle),
        payload_sha256=stream_hash.hexdigest(),
        total_bytes=total,
        file_count=len(bundle.files),
        part_size_bytes=part_size,
        total_parts=(total + part_size - 1) // part_size,
    )
    signed_payload = SignedDirectModelPayload(
        schema="umi-signed-direct-model-payload/1",
        payload=payload,
        signature=sign_object(payload, wallet("Alice")),
    )
    multipart = Multipart(bytes(payload_bytes))
    authorizations = []

    async def authorize(value):
        authorizations.append(value)

    async def sign(value):
        return sign_object(value, wallet("Charlie"))

    ids = iter(("a1" * 32, "b2" * 32, "c3" * 32))
    owner = DirectModelUploadOwner(
        DirectModelUploadOwnerConfig(
            schema="umi-direct-model-upload-owner-config/1",
            directory=str(tmp_path / "direct"),
            cohort_sha256=request.consent.consent.cohort_sha256,
            owner_hotkey=wallet("Charlie").hotkey.ss58_address,
            delivery=ModelDeliveryProfile(
                schema="umi-model-delivery-profile/1",
                mechanism="direct_r2_multipart_v1",
                part_size_bytes=part_size,
                maximum_concurrent_parts=2,
                capability_ttl_seconds=900,
            ),
            maximum_uploads=8,
        ),
        multipart,
        authorize=authorize,
        sign=sign,
        new_attempt_id=lambda: next(ids),
    )
    return SimpleNamespace(
        owner=owner,
        request=request,
        payload=signed_payload,
        multipart=multipart,
        authorizations=authorizations,
        plan=scenario["intake_history"].plan,
    )


def signed_completion(reservation, payload):
    parts = tuple(
        DirectModelUploadPart(
            part_number=number,
            size_bytes=min(
                payload.part_size_bytes,
                payload.total_bytes - (number - 1) * payload.part_size_bytes,
            ),
            etag=f"{number:032x}",
        )
        for number in range(1, payload.total_parts + 1)
    )
    completion = DirectModelUploadCompletion(
        schema="umi-direct-model-upload-completion/1",
        reservation_sha256=digest(reservation.reservation),
        generation=reservation.reservation.generation,
        parts=parts,
    )
    return SignedDirectModelUploadCompletion(
        schema="umi-signed-direct-model-upload-completion/1",
        completion=completion,
        signature=sign_object(completion, wallet("Alice")),
    )


@pytest.mark.asyncio
async def test_reservation_is_durable_idempotent_and_capabilities_are_transient(direct):
    signed = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    assert signed.reservation.generation == 1
    assert len(direct.authorizations) == 1
    assert len(direct.multipart.create_calls) == 1

    retry = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_001_000
    )
    assert retry == signed
    assert len(direct.authorizations) == 1
    assert len(direct.multipart.create_calls) == 1

    requested = tuple(range(1, min(2, direct.payload.payload.total_parts) + 1))
    capabilities = direct.owner.capabilities(signed, requested, now_unix_ms=1_800_000_002_000)
    assert tuple(value.part_number for value in capabilities) == requested
    assert capabilities[-1].size_bytes == min(
        direct.payload.payload.part_size_bytes,
        direct.payload.payload.total_bytes
        - (requested[-1] - 1) * direct.payload.payload.part_size_bytes,
    )
    assert all("provider-id-1" in value.url for value in capabilities)
    assert all(value.expires_at_unix_ms == 1_800_000_902_000 for value in capabilities)
    retained = direct.owner.journal.get("direct-reservation", signed.reservation.attempt_id)
    assert "X-Amz-Signature" not in str(retained)
    index = direct.owner.journal.get("direct-reservation-index", digest(signed.reservation))
    assert index["attempt_id"] == signed.reservation.attempt_id


@pytest.mark.asyncio
async def test_reservation_retry_does_not_scan_other_upload_attempts(direct, monkeypatch):
    signed = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    native_keys = direct.owner.journal.keys

    def keys(kind):
        if kind == "direct-intent":
            pytest.fail("reservation retry scanned every cohort attempt")
        return native_keys(kind)

    monkeypatch.setattr(direct.owner.journal, "keys", keys)
    retry = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_001_000
    )
    assert retry == signed


def test_unknown_reservation_status_is_constant_time(direct, monkeypatch):
    monkeypatch.setattr(
        direct.owner.journal,
        "keys",
        lambda kind: pytest.fail(f"unexpected journal scan for {kind}"),
    )
    with pytest.raises(FileNotFoundError, match="reservation is unavailable"):
        direct.owner.status("ff" * 32)


@pytest.mark.asyncio
async def test_distinct_upload_capacity_is_enforced_before_authorization(direct):
    for index in range(direct.owner.config.maximum_uploads):
        direct.owner.journal.put(
            "direct-request", f"{index + 1:064x}", {"retained_distinct_upload": index + 1}
        )

    with pytest.raises(OSError, match="upload capacity exhausted"):
        await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=1_800_000_000_000)

    assert direct.authorizations == []
    assert direct.multipart.create_calls == []


@pytest.mark.asyncio
async def test_failed_creation_waits_for_lease_then_advances_generation(direct):
    direct.multipart.fail_creates = 1
    with pytest.raises(OSError, match="provider offline"):
        await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=1_800_000_000_000)
    with pytest.raises(DirectModelUploadPending):
        await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=1_800_000_030_000)
    signed = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_121_000
    )
    assert signed.reservation.generation == 2
    assert len(direct.authorizations) == 1
    assert len(direct.multipart.create_calls) == 2


@pytest.mark.asyncio
async def test_completion_reconciles_lost_provider_response_and_is_idempotent(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    signed = signed_completion(reservation, direct.payload.payload)
    direct.multipart.fail_after_complete = True
    result = await direct.owner.complete(signed, now_unix_ms=1_800_000_010_000)
    assert result.provider_etag == "completed-etag-1"
    assert len(direct.multipart.complete_calls) == 1
    verified = await direct.owner.verify(result.reservation_sha256, now_unix_ms=1_800_000_012_000)
    assert verified.payload_sha256 == direct.payload.payload.payload_sha256
    assert (
        await direct.owner.verify(result.reservation_sha256, now_unix_ms=1_800_000_013_000)
        == verified
    )
    assert await direct.owner.complete(signed, now_unix_ms=1_800_000_011_000) == result
    assert len(direct.multipart.complete_calls) == 1
    direct.owner.require_payload(direct.request)


@pytest.mark.asyncio
async def test_reservation_reconciles_completed_object_after_owner_restart_boundary(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completion = signed_completion(reservation, direct.payload.payload)
    reservation_sha256 = digest(reservation.reservation)
    direct.owner.journal.put("direct-completion", reservation_sha256, completion)
    intent = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)
    direct.multipart.objects[intent["object_key"]] = (
        direct.multipart.total_bytes,
        "completed-after-owner-exit",
    )

    retry = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_020_000
    )

    assert retry == reservation
    assert direct.multipart.complete_calls == []
    status = direct.owner.status(reservation_sha256)
    assert status.object_complete is True
    assert status.payload_verified is False


@pytest.mark.asyncio
async def test_verification_rejects_completed_object_replacement(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    key = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)[
        "object_key"
    ]
    direct.multipart.objects[key] = (direct.multipart.total_bytes, "replacement-etag")

    with pytest.raises(ValueError, match="metadata changed"):
        await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)


@pytest.mark.asyncio
async def test_poll_retains_terminal_verification_hold_without_rereading(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    changed = bytearray(direct.multipart.payload_bytes)
    changed[0] ^= 1
    direct.multipart.payload_bytes = bytes(changed)

    first = await direct.owner.poll_once(now_unix_ms=1_800_000_011_000)
    reads_after_failure = direct.multipart.read_calls
    second = await direct.owner.poll_once(now_unix_ms=1_800_000_012_000)

    assert first["objects_failed"] == 1
    assert first["last_error_type"] == "direct_model_verification_failed"
    assert second["objects_failed"] == 1
    assert second["last_error_type"] == "direct_model_verification_failed"
    assert reads_after_failure > 0
    assert direct.multipart.read_calls == reads_after_failure
    status = direct.owner.status(completed.reservation_sha256)
    assert status.hold_reason_code == "direct_model_verification_failed"
    assert status.payload_verified is False
    assert status.model_dump(mode="json", by_alias=True)["hold_reason_code"] == (
        "direct_model_verification_failed"
    )


@pytest.mark.asyncio
async def test_participation_requires_complete_verified_object(direct):
    with pytest.raises(DirectModelUploadPending):
        direct.owner.require_payload(direct.request)
    await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=1_800_000_000_000)
    with pytest.raises(DirectModelUploadPending):
        direct.owner.require_payload(direct.request)


@pytest.mark.asyncio
async def test_completion_rejects_wrong_part_size(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    payload = direct.payload.payload
    parts = tuple(
        DirectModelUploadPart(
            part_number=number,
            size_bytes=(
                min(
                    payload.part_size_bytes,
                    payload.total_bytes - (number - 1) * payload.part_size_bytes,
                )
                + (1 if number == payload.total_parts else 0)
            ),
            etag=f"{number:032x}",
        )
        for number in range(1, payload.total_parts + 1)
    )
    completion = DirectModelUploadCompletion(
        schema="umi-direct-model-upload-completion/1",
        reservation_sha256=digest(reservation.reservation),
        generation=reservation.reservation.generation,
        parts=parts,
    )
    signed = SignedDirectModelUploadCompletion(
        schema="umi-signed-direct-model-upload-completion/1",
        completion=completion,
        signature=sign_object(completion, wallet("Alice")),
    )
    with pytest.raises(ValueError, match="differs from its reservation"):
        await direct.owner.complete(signed, now_unix_ms=1_800_000_010_000)


@pytest.mark.asyncio
async def test_http_routes_exchange_only_metadata_and_require_miner_signature(direct):
    app = FastAPI()
    app.include_router(
        direct_model_upload_routes(direct.owner, now_unix_ms=lambda: 1_800_000_000_000)
    )
    transport = httpx.ASGITransport(app=app)
    reservation_request = DirectModelUploadReservationRequest(
        schema="umi-direct-model-upload-reservation-request/1",
        request=direct.request,
        payload=direct.payload,
    )
    async with httpx.AsyncClient(transport=transport, base_url="https://intake.test") as client:
        response = await client.post(
            f"/v1/competition/cohorts/{direct.request.consent.consent.cohort_sha256}"
            "/direct-model-uploads",
            content=canonical_json_bytes(reservation_request),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        reservation = SignedDirectModelUploadReservation.model_validate_json(response.content)
        reservation_sha256 = digest(reservation.reservation)

        part_request = DirectModelUploadPartRequest(
            schema="umi-direct-model-upload-part-request/1",
            reservation_sha256=reservation_sha256,
            generation=reservation.reservation.generation,
            part_numbers=(1,),
        )
        signed_part_request = SignedDirectModelUploadPartRequest(
            schema="umi-signed-direct-model-upload-part-request/1",
            request=part_request,
            signature=sign_object(part_request, wallet("Alice")),
        )
        response = await client.post(
            f"/v1/competition/cohorts/{direct.request.consent.consent.cohort_sha256}"
            f"/direct-model-uploads/{reservation_sha256}/parts",
            content=canonical_json_bytes(signed_part_request),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 200
        capabilities = DirectModelUploadPartCapabilities.model_validate_json(response.content)
        assert capabilities.capabilities[0].url.startswith("https://")

        wrong = signed_part_request.model_copy(
            update={"signature": sign_object(part_request, wallet("Bob"))}
        )
        response = await client.post(
            f"/v1/competition/cohorts/{direct.request.consent.consent.cohort_sha256}"
            f"/direct-model-uploads/{reservation_sha256}/parts",
            content=canonical_json_bytes(wrong),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 422

        response = await client.get(
            f"/v1/competition/cohorts/{direct.request.consent.consent.cohort_sha256}"
            f"/direct-model-uploads/{reservation_sha256}"
        )
        assert response.status_code == 200
        assert response.json()["payload_verified"] is False
        assert response.json()["object_complete"] is False
        assert "hold_reason_code" not in response.json()

        response = await client.get(
            f"/v1/competition/cohorts/{direct.request.consent.consent.cohort_sha256}"
            "/direct-model-uploads/not-a-digest"
        )
        assert response.status_code == 404


def test_mixed_series_routes_each_request_to_its_signed_delivery_profile(direct):
    class Payloads:
        def __init__(self):
            self.requests = []

        def require_payload(self, request):
            self.requests.append(request)

        def review_artifact(self, request):
            return ("direct", request)

    legacy_plan = direct.plan.model_copy(
        update={
            "schema_": "umi-recoverable-cohort-plan/2",
            "sequence": direct.plan.sequence + 1,
            "eligible_tracks": ("model",),
            "service_pool_bps": 0,
            "model_delivery": None,
        }
    )
    direct_plan = direct.plan.model_copy(
        update={
            "schema_": "umi-recoverable-cohort-plan/3",
            "sequence": direct.plan.sequence + 2,
            "eligible_tracks": ("model",),
            "service_pool_bps": 0,
            "model_delivery": direct.owner.config.delivery,
        }
    )
    legacy, direct_payloads = Payloads(), Payloads()
    router = CohortModelPayloadRouter(
        (legacy_plan, direct_plan), legacy=legacy, direct=direct_payloads
    )
    legacy_request = SimpleNamespace(
        consent=SimpleNamespace(consent=SimpleNamespace(cohort_sha256=digest(legacy_plan)))
    )
    direct_request = SimpleNamespace(
        consent=SimpleNamespace(consent=SimpleNamespace(cohort_sha256=digest(direct_plan)))
    )

    router.require_payload(legacy_request)
    router.require_payload(direct_request)

    assert legacy.requests == [legacy_request]
    assert direct_payloads.requests == [direct_request]
    assert router.review_artifact(legacy_request) is None
    assert router.review_artifact(direct_request) == ("direct", direct_request)
    assert "model_upload_url" in router.delivery_route(digest(legacy_plan))
    assert "direct_model_upload_url" in router.delivery_route(digest(direct_plan))
