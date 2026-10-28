from __future__ import annotations

import asyncio
import hashlib
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
    DirectModelUploadOwners,
    DirectModelUploadPending,
    _copy_promotion_parts,
)
from umi.competition_cohort_direct_model_upload import (
    DirectModelPayload,
    DirectModelUploadCompletion,
    DirectModelUploadPart,
    DirectModelUploadPartCapabilities,
    DirectModelUploadPartRequest,
    DirectModelUploadReservationRequest,
    DirectModelUploadRestartRequest,
    SignedDirectModelPayload,
    SignedDirectModelUploadCompletion,
    SignedDirectModelUploadPartRequest,
    SignedDirectModelUploadReservation,
    SignedDirectModelUploadRestartRequest,
    preserved_model_object_key,
)
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_model_acceptance import (
    CertifiedModelArtifactAcceptance,
    ModelAcceptancePublication,
    ModelArtifactAcceptance,
    ModelArtifactReviewInputs,
)
from umi.competition_cohort_promotion_copy import multipart_etag
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.competition_cohort_service_host import CohortModelPayloadRouter
from umi.open_competition import digest, model_content_digest, sign_object
from umi.private_files import publish_private_model
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
        self.copy_calls = []
        self.delete_calls = []
        self.abort_calls = []
        self.read_calls = 0
        self.objects = {}
        self.multipart_uploads = set()
        self.fail_creates = 0
        self.fail_after_complete = False
        self.fail_deletes = 0

    async def create(self, key, *, at=None):
        self.create_calls.append((key, at))
        if self.fail_creates:
            self.fail_creates -= 1
            raise OSError("provider offline")
        provider = f"provider-id-{len(self.create_calls)}"
        self.multipart_uploads.add((key, provider))
        return provider

    async def head(self, key, *, at=None):
        value = self.objects.get(key)
        return None if value is None else SimpleNamespace(size_bytes=value[0], etag=value[1])

    async def complete(self, key, *, upload_id, parts, at=None):
        self.complete_calls.append((key, upload_id, parts, at))
        etag = multipart_etag(parts)
        self.objects[key] = (self.total_bytes, etag)
        if self.fail_after_complete:
            raise OSError("response lost after completion")
        return etag

    async def copy_part(
        self,
        key,
        *,
        source_key,
        upload_id,
        part_number,
        offset,
        size_bytes,
        source_size_bytes,
        at=None,
    ):
        assert source_key in self.objects
        assert source_size_bytes == self.total_bytes
        self.copy_calls.append((key, source_key, upload_id, part_number, offset, size_bytes, at))
        return DirectModelUploadPart(
            part_number=part_number,
            size_bytes=size_bytes,
            etag=f"{part_number:032x}",
        )

    async def delete_object(self, key, *, at=None):
        self.delete_calls.append((key, at))
        if self.fail_deletes:
            self.fail_deletes -= 1
            raise OSError("delete response lost")
        self.objects.pop(key, None)

    async def abort(self, key, *, upload_id, at=None):
        self.abort_calls.append((key, upload_id, at))
        self.multipart_uploads.discard((key, upload_id))

    async def multipart_exists(self, key, *, upload_id, at=None):
        return (key, upload_id) in self.multipart_uploads

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
async def test_deadline_preserves_exact_retry_restart_and_original_admission_proof(direct):
    from umi.competition_cohort_intake import CohortIntakeFenced

    deadline = 1_800_000_001_000
    now = deadline - 1
    calls = []

    async def authorize(request):
        calls.append(request)
        if now >= deadline:
            raise CohortIntakeFenced("operator deadline")

    direct.owner.authorize = authorize
    original = await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=now)
    now = deadline + 1
    assert await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=now) == original
    assert len(calls) == 1

    sub = direct.request.signed_submission.submission.model_copy(update={"sequence": 2})
    signed = type(direct.request.signed_submission)(
        submission=sub, signature=sign_object(sub, wallet("Alice"))
    )
    consent = direct.request.consent.consent.model_copy(update={"submission_sha256": digest(sub)})
    replacement = type(direct.request)(
        signed_submission=signed,
        consent=type(direct.request.consent)(
            consent=consent, signature=sign_object(consent, wallet("Alice"))
        ),
    )
    payload = direct.payload.payload.model_copy(update={"upload_sha256": digest(replacement)})
    signed_payload = type(direct.payload)(
        schema=direct.payload.schema_,
        payload=payload,
        signature=sign_object(payload, wallet("Alice")),
    )
    with pytest.raises(CohortIntakeFenced, match="operator deadline"):
        await direct.owner.reserve(replacement, signed_payload, now_unix_ms=now)
    assert len(direct.multipart.create_calls) == 1

    direct.multipart.multipart_uploads.clear()
    now += direct.owner.config.attempt_lease_seconds * 1000
    request = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=digest(original.reservation),
        generation=1,
        reason_code="provider_upload_unavailable",
    )
    restart = SignedDirectModelUploadRestartRequest(
        schema="umi-signed-direct-model-upload-restart-request/1",
        request=request,
        signature=sign_object(request, wallet("Alice")),
    )
    successor = await direct.owner.restart(restart, now_unix_ms=now)
    assert successor.reservation.generation == 2
    assert successor.reservation.created_at_unix_ms >= deadline
    assert direct.owner.admission_reservation(direct.request) == original
    restarted = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=authorize,
        sign=direct.owner.sign,
    )
    assert restarted.admission_reservation(direct.request) == original
    completed = await restarted.complete(
        signed_completion(successor, direct.payload.payload), now_unix_ms=now + 1
    )
    assert completed.reservation_sha256 == digest(successor.reservation)
    assert restarted.admission_reservation(direct.request) == original


@pytest.mark.asyncio
async def test_deadline_http_rejects_new_reservation_but_exact_retry_remains_200(direct):
    from umi.competition_cohort_intake import CohortAdmissionClosed

    closed = True

    async def authorize(request):
        if closed:
            raise CohortAdmissionClosed("operator deadline")

    direct.owner.authorize = authorize
    app = FastAPI()
    app.include_router(
        direct_model_upload_routes(direct.owner, now_unix_ms=lambda: 1_800_000_000_000)
    )
    body = DirectModelUploadReservationRequest(
        schema="umi-direct-model-upload-reservation-request/1",
        request=direct.request,
        payload=direct.payload,
    )
    path = f"/v1/competition/cohorts/{direct.owner.config.cohort_sha256}/direct-model-uploads"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://intake.test"
    ) as client:
        response = await client.post(
            path, content=canonical_json_bytes(body), headers={"Content-Type": "application/json"}
        )
        assert response.status_code == 409
        assert response.headers["X-UMI-Reason-Code"] == "cohort_intake_closed"
        assert direct.multipart.create_calls == []
        closed = False
        accepted = await client.post(
            path, content=canonical_json_bytes(body), headers={"Content-Type": "application/json"}
        )
        assert accepted.status_code == 200
        closed = True
        retry = await client.post(
            path, content=canonical_json_bytes(body), headers={"Content-Type": "application/json"}
        )
        assert retry.status_code == 200
        assert retry.json() == accepted.json()


@pytest.mark.asyncio
async def test_deadline_by_upload_status_recovers_reservation_without_verification(
    direct, monkeypatch
):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )

    def forbidden(*args, **kwargs):
        pytest.fail("read-only upload lookup attempted payload work")

    monkeypatch.setattr(direct.owner, "verify", forbidden)
    monkeypatch.setattr(direct.multipart, "read_range", forbidden)
    expected = direct.owner.status(digest(reservation.reservation))
    assert direct.owner.status_by_upload(digest(direct.request)) == expected
    app = FastAPI()
    app.include_router(direct_model_upload_routes(direct.owner))
    path = (
        f"/v1/competition/cohorts/{direct.owner.config.cohort_sha256}/"
        "direct-model-uploads/by-upload/"
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://intake.test"
    ) as client:
        response = await client.get(path + digest(direct.request))
        assert response.status_code == 200
        assert response.json() == expected.model_dump(mode="json", by_alias=True)
        absent = await client.get(path + "ff" * 32)
        assert absent.status_code == 404
    assert direct.multipart.read_calls == 0


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
async def test_expired_provider_generation_is_signed_fenced_and_replaced(direct):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    first_sha256 = digest(first.reservation)
    attempt = direct.owner.journal.get("direct-intent", first.reservation.attempt_id)
    provider = direct.owner.journal.get("direct-provider", first.reservation.attempt_id)
    direct.multipart.multipart_uploads.remove(
        (attempt["object_key"], provider["provider_upload_id"])
    )
    restart = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=first_sha256,
        generation=first.reservation.generation,
        reason_code="provider_upload_unavailable",
    )
    signed = SignedDirectModelUploadRestartRequest(
        schema="umi-signed-direct-model-upload-restart-request/1",
        request=restart,
        signature=sign_object(restart, wallet("Alice")),
    )

    second = await direct.owner.restart(signed, now_unix_ms=1_800_000_121_000)

    assert second.reservation.generation == 2
    assert second.reservation.payload == first.reservation.payload
    assert direct.owner.journal.get("direct-superseded", first_sha256)["reason_code"] == (
        "provider_upload_unavailable"
    )
    assert len(direct.multipart.create_calls) == 2
    assert len(direct.multipart.abort_calls) == 1
    assert await direct.owner.restart(signed, now_unix_ms=1_800_000_122_000) == second
    assert len(direct.multipart.create_calls) == 2
    with pytest.raises(ValueError, match="superseded"):
        direct.owner.capabilities(first, (1,), now_unix_ms=1_800_000_123_000)


@pytest.mark.asyncio
async def test_expired_generation_recovery_survives_replacement_creation_failure(direct):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    first_sha256 = digest(first.reservation)
    attempt = direct.owner.journal.get("direct-intent", first.reservation.attempt_id)
    provider = direct.owner.journal.get("direct-provider", first.reservation.attempt_id)
    direct.multipart.multipart_uploads.remove(
        (attempt["object_key"], provider["provider_upload_id"])
    )
    request = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=first_sha256,
        generation=first.reservation.generation,
        reason_code="provider_upload_unavailable",
    )
    signed = SignedDirectModelUploadRestartRequest(
        schema="umi-signed-direct-model-upload-restart-request/1",
        request=request,
        signature=sign_object(request, wallet("Alice")),
    )
    direct.multipart.fail_creates = 1

    with pytest.raises(OSError, match="provider offline"):
        await direct.owner.restart(signed, now_unix_ms=1_800_000_121_000)

    assert direct.owner.journal.get("direct-restart-request", first_sha256)
    assert direct.owner.journal.get("direct-superseded", first_sha256)
    with pytest.raises(ValueError, match="superseded"):
        direct.owner.capabilities(first, (1,), now_unix_ms=1_800_000_122_000)
    with pytest.raises(DirectModelUploadPending):
        await direct.owner.restart(signed, now_unix_ms=1_800_000_150_000)

    replacement = await direct.owner.restart(signed, now_unix_ms=1_800_000_242_000)
    assert replacement.reservation.generation == 3
    assert len(direct.multipart.create_calls) == 3


@pytest.mark.asyncio
async def test_restart_requires_original_signer_expired_lease_and_absent_provider(direct):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    request = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=digest(first.reservation),
        generation=first.reservation.generation,
        reason_code="provider_upload_unavailable",
    )
    wrong = SignedDirectModelUploadRestartRequest(
        schema="umi-signed-direct-model-upload-restart-request/1",
        request=request,
        signature=sign_object(request, wallet("Bob")),
    )
    signed = wrong.model_copy(update={"signature": sign_object(request, wallet("Alice"))})

    with pytest.raises(ValueError, match="signer"):
        await direct.owner.restart(wrong, now_unix_ms=1_800_000_121_000)
    with pytest.raises(DirectModelUploadPending, match="lease"):
        await direct.owner.restart(signed, now_unix_ms=1_800_000_030_000)
    with pytest.raises(DirectModelUploadPending, match="remains available"):
        await direct.owner.restart(signed, now_unix_ms=1_800_000_121_000)

    assert direct.owner.journal.get("direct-superseded", digest(first.reservation)) is None
    assert len(direct.multipart.create_calls) == 1


@pytest.mark.asyncio
async def test_fenced_generation_rejects_capabilities_and_completion_before_replacement(direct):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    first_sha256 = digest(first.reservation)
    direct.owner.journal.put(
        "direct-superseded",
        first_sha256,
        {
            "reason_code": "provider_upload_unavailable",
            "superseded_at_unix_ms": 1_800_000_121_000,
        },
    )

    with pytest.raises(ValueError, match="superseded"):
        direct.owner.capabilities(first, (1,), now_unix_ms=1_800_000_122_000)
    with pytest.raises(ValueError, match="superseded"):
        await direct.owner.complete(
            signed_completion(first, direct.payload.payload),
            now_unix_ms=1_800_000_122_000,
        )

    assert direct.owner.journal.get("direct-object", first_sha256) is None


@pytest.mark.asyncio
async def test_completion_reconciles_lost_provider_response_and_is_idempotent(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    signed = signed_completion(reservation, direct.payload.payload)
    direct.multipart.fail_after_complete = True
    result = await direct.owner.complete(signed, now_unix_ms=1_800_000_010_000)
    assert result.provider_etag == multipart_etag(signed.completion.parts)
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


async def complete_poll_uploads(direct):
    reservations = []
    for offset in range(3):
        consent = direct.request.consent.consent.model_copy(
            update={"signed_at_block": direct.request.consent.consent.signed_at_block + offset}
        )
        request = direct.request.model_copy(
            update={
                "consent": direct.request.consent.model_copy(
                    update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))}
                )
            }
        )
        payload = direct.payload.payload.model_copy(update={"upload_sha256": digest(request)})
        signed = direct.payload.model_copy(
            update={"payload": payload, "signature": sign_object(payload, wallet("Alice"))}
        )
        reservation = await direct.owner.reserve(request, signed, now_unix_ms=1_800_000_000_000)
        completed = await direct.owner.complete(
            signed_completion(reservation, payload), now_unix_ms=1_800_000_010_000
        )
        reservations.append(completed.reservation_sha256)
    return sorted(reservations)


def assert_poll_inventory(report, *, ready, pending, retrying, terminal, total):
    assert report["objects_ready"] == ready
    assert report["objects_pending"] == pending
    assert report["objects_retrying"] == retrying
    assert report["objects_terminal"] == terminal
    assert report["objects_total"] == total == ready + pending + retrying + terminal
    assert report["object_count_scope"] == (
        "retained_completed_upload_objects_including_replaced_generations"
    )


@pytest.mark.asyncio
async def test_poll_rotates_transient_verification_failures_across_restart(direct, monkeypatch):
    keys = await complete_poll_uploads(direct)
    calls = []

    def inject_transient_failures(owner):
        verify = owner.verify

        async def unreliable(key, **kwargs):
            calls.append(key)
            if key in keys[:2]:
                raise OSError("provider temporarily unavailable")
            return await verify(key, **kwargs)

        monkeypatch.setattr(owner, "verify", unreliable)

    inject_transient_failures(direct.owner)
    cohort = direct.owner.config.cohort_sha256
    manager = DirectModelUploadOwners({cohort: direct.owner}, priority_cohorts=(cohort,))
    first = (await manager.poll_once(now_unix_ms=1_800_000_011_000))["cohorts"][cohort]
    assert first["objects_failed"] == 2 and first["objects_pending"] == 1
    assert first["objects_retrying"] == 2
    assert_poll_inventory(first, ready=0, pending=1, retrying=2, terminal=0, total=3)
    assert calls == keys[:2]
    resumed = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )
    inject_transient_failures(resumed)
    manager = DirectModelUploadOwners({cohort: resumed}, priority_cohorts=(cohort,))
    second = (await manager.poll_once(now_unix_ms=1_800_000_012_000))["cohorts"][cohort]
    assert second["objects_verified"] == 1
    assert_poll_inventory(second, ready=1, pending=1, retrying=1, terminal=0, total=3)
    assert calls == [*keys[:2], keys[2], keys[0]]
    reads = direct.multipart.read_calls
    third = (await manager.poll_once(now_unix_ms=1_800_000_013_000))["cohorts"][cohort]
    assert third["objects_verified"] == 1
    assert calls[-2:] == [keys[1], keys[0]]
    assert direct.multipart.read_calls == reads, "completed payload must not be reverified"
    assert all(resumed.journal.get("direct-verification-hold", key) is None for key in keys)


@pytest.mark.asyncio
async def test_poll_reports_retry_cause_separately_from_later_terminal_hold(direct, monkeypatch):
    from umi import competition_cohort_direct_model_owner as module
    from umi.competition_cohort_public_progress import CohortProgressSnapshots

    keys = await complete_poll_uploads(direct)

    async def mixed_failure(key, **kwargs):
        if key == keys[0]:
            raise OSError("temporary provider failure")
        assert key == keys[1]
        raise ValueError("terminal content failure")

    monkeypatch.setattr(direct.owner, "verify", mixed_failure)
    snapshots = CohortProgressSnapshots()
    monkeypatch.setattr(module, "PUBLIC_COHORT_PROGRESS", snapshots)
    cohort = direct.owner.config.cohort_sha256
    manager = DirectModelUploadOwners({cohort: direct.owner}, priority_cohorts=(cohort,))
    report = (await manager.poll_once(now_unix_ms=1_800_000_011_000))["cohorts"][cohort]
    assert_poll_inventory(report, ready=0, pending=1, retrying=1, terminal=1, total=3)
    assert report["last_error_type"] == "direct_model_verification_failed"
    assert report["last_retry_error_type"] == "OSError"
    public = snapshots.snapshot(cohort)["components"]["direct_uploads"]
    assert public["stalled_or_retrying"] is True
    assert public["error_type"] == "OSError"


@pytest.mark.asyncio
async def test_interrupted_poll_yields_to_later_uploads_after_restart(direct, monkeypatch):
    keys = await complete_poll_uploads(direct)

    async def interrupted(key, **kwargs):
        assert key == keys[0]
        raise asyncio.CancelledError

    monkeypatch.setattr(direct.owner, "verify", interrupted)
    with pytest.raises(asyncio.CancelledError):
        await direct.owner.poll_once(now_unix_ms=1_800_000_011_000)
    resumed = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )
    result = await resumed.poll_once(now_unix_ms=1_800_000_012_000)
    assert result["objects_verified"] == 2 and result["objects_pending"] == 1
    assert resumed.journal.get("direct-verification", keys[0]) is None
    assert all(resumed.journal.get("direct-verification", key) for key in keys[1:])
    result = await resumed.poll_once(now_unix_ms=1_800_000_013_000)
    assert result["objects_verified"] == 3 and result["objects_attempted"] == 1


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
    assert first["objects_retrying"] == second["objects_retrying"] == 0
    assert_poll_inventory(first, ready=0, pending=0, retrying=0, terminal=1, total=1)
    assert_poll_inventory(second, ready=0, pending=0, retrying=0, terminal=1, total=1)
    assert second["last_error_type"] == "direct_model_verification_failed"
    assert reads_after_failure > 0
    assert direct.multipart.read_calls == reads_after_failure
    assert (
        direct.owner.journal.get("direct-rejected-cleanup-intent", completed.reservation_sha256)[
            "reason_code"
        ]
        == "direct_model_verification_failed"
    )
    status = direct.owner.status(completed.reservation_sha256)
    assert status.hold_reason_code == "direct_model_verification_failed"
    assert status.payload_verified is False
    assert status.model_dump(mode="json", by_alias=True)["hold_reason_code"] == (
        "direct_model_verification_failed"
    )


def configure_poll_review(direct, tmp_path, policy):
    from umi.competition_cohort_model_static_review import StandingModelReviewPolicy

    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(policy),
        contribution_terms_sha256=policy.contribution_terms_sha256,
        standing_approval_record_sha256="cd" * 32,
        approved_by="fixture operator",
        approved_at_utc="2026-10-23T00:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )

    config = direct.owner.config.model_copy(
        update={
            "admission_reviews_directory": str(tmp_path / "reviews"),
            "directory": str(tmp_path / "reviewed-direct"),
            "standing_review_policy": standing,
        }
    )
    direct.owner = DirectModelUploadOwner(
        config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
        policy=policy,
    )
    return config


@pytest.mark.asyncio
async def test_poll_rotates_transient_review_failures_reusing_verification(
    direct, tmp_path, monkeypatch, policy
):
    config = configure_poll_review(direct, tmp_path, policy)
    keys = await complete_poll_uploads(direct)
    calls = []

    async def unreliable_review(key, **kwargs):
        calls.append(key)
        if key in keys[:2]:
            raise OSError("review document temporarily unavailable")
        return ModelArtifactReviewInputs(
            model_sha256=direct.payload.payload.model_sha256,
            rights_evidence={"license": "MIT"},
            reconstruction_evidence={"complete": True},
        )

    monkeypatch.setattr(direct.owner, "review", unreliable_review)
    first = await direct.owner.poll_once(now_unix_ms=1_800_000_011_000)
    assert first["objects_verified"] == 2 and first["objects_failed"] == 2
    assert first["objects_retrying"] == 2
    assert_poll_inventory(first, ready=0, pending=1, retrying=2, terminal=0, total=3)
    assert calls == keys[:2]
    resumed = DirectModelUploadOwner(
        config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
        policy=policy,
    )
    monkeypatch.setattr(resumed, "review", unreliable_review)
    verify = resumed.verify
    verified = []

    async def verify_only_unfinished(key, **kwargs):
        verified.append(key)
        assert key == keys[2], "successful verification must survive restart and review retries"
        return await verify(key, **kwargs)

    monkeypatch.setattr(resumed, "verify", verify_only_unfinished)
    second = await resumed.poll_once(now_unix_ms=1_800_000_012_000)
    assert second["reviews_ready"] == 1 and second["objects_attempted"] == 2
    assert calls == [*keys[:2], keys[2], keys[0]]
    reads = direct.multipart.read_calls
    await resumed.poll_once(now_unix_ms=1_800_000_013_000)
    assert verified == [keys[2]] and direct.multipart.read_calls == reads


@pytest.mark.asyncio
async def test_poll_reuses_review_file_after_restart_without_blocking_event_loop(
    direct, tmp_path, monkeypatch, policy
):
    import threading

    from umi import competition_model_review_file as review_file

    config = configure_poll_review(direct, tmp_path, policy)
    reservation = await direct.owner.reserve(
        direct.request,
        direct.payload,
        now_unix_ms=1_800_000_000_000,
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    model = direct.payload.payload.model_sha256
    path = tmp_path / "reviews" / (model + ".json")
    publish_private_model(
        path,
        ModelArtifactReviewInputs(
            model_sha256=model,
            rights_evidence={"license": "MIT"},
            reconstruction_evidence={"complete": True},
        ),
    )
    loop_thread = threading.get_ident()
    original = review_file.read_private_model

    def owned_read(*args, **kwargs):
        assert threading.get_ident() != loop_thread
        return original(*args, **kwargs)

    monkeypatch.setattr(review_file, "read_private_model", owned_read)
    assert (await direct.owner.poll_once(now_unix_ms=1_800_000_012_000))["reviews_ready"] == 1
    reads = direct.multipart.read_calls
    resumed = DirectModelUploadOwner(
        config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
        policy=policy,
    )

    def fail(*_args, **_kwargs):
        raise AssertionError("completed review must not be reread after restart")

    monkeypatch.setattr(review_file, "read_private_model", fail)
    assert (await resumed.poll_once(now_unix_ms=1_800_000_013_000))["reviews_ready"] == 1
    assert direct.multipart.read_calls == reads
    path.unlink()
    damaged = await resumed.poll_once(now_unix_ms=1_800_000_014_000)
    assert damaged["objects_failed"] == 1 and damaged["reviews_ready"] == 0
    assert_poll_inventory(damaged, ready=0, pending=0, retrying=1, terminal=0, total=1)


@pytest.mark.asyncio
async def test_terminal_rejection_cleanup_retries_and_preserves_evidence(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    source_key = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)[
        "object_key"
    ]
    changed = bytearray(direct.multipart.payload_bytes)
    changed[0] ^= 1
    direct.multipart.payload_bytes = bytes(changed)
    held_at = 1_800_000_011_000

    first = await direct.owner.poll_once(now_unix_ms=held_at)
    before_expiry = await direct.owner.poll_once(
        now_unix_ms=held_at + direct.owner.config.rejected_object_retention_seconds * 1000 - 1
    )
    direct.multipart.fail_deletes = 1
    failed_cleanup = await direct.owner.poll_once(
        now_unix_ms=held_at + direct.owner.config.rejected_object_retention_seconds * 1000
    )
    after_expiry = await direct.owner.poll_once(
        now_unix_ms=held_at + direct.owner.config.rejected_object_retention_seconds * 1000 + 1
    )
    settled = await direct.owner.poll_once(
        now_unix_ms=held_at + direct.owner.config.rejected_object_retention_seconds * 1000 + 2
    )

    assert first["objects_retained_for_cleanup"] == 1
    assert before_expiry["objects_retained_for_cleanup"] == 1
    assert failed_cleanup["objects_retained_for_cleanup"] == 1
    assert failed_cleanup["last_error_type"] == "OSError"
    assert source_key not in direct.multipart.objects
    assert after_expiry["objects_cleaned"] == 1
    assert settled["objects_cleaned"] == 0
    assert settled["objects_retained_for_cleanup"] == 0
    receipt = direct.owner.journal.get(
        "direct-rejected-cleanup-receipt", completed.reservation_sha256
    )
    assert receipt["reservation_sha256"] == completed.reservation_sha256
    assert direct.owner.journal.get("direct-verification-hold", completed.reservation_sha256)


def promotion_publication(direct, reservation):
    submission = direct.request.signed_submission.submission
    bundle = submission.model_bundle
    inputs = ModelArtifactReviewInputs(
        model_sha256=digest(bundle),
        rights_evidence={"license": "reviewed"},
        reconstruction_evidence={"reconstruction": "verified"},
    )
    acceptance = ModelArtifactAcceptance(
        schema="umi-cohort-model-artifact-acceptance/2",
        policy_sha256="11" * 32,
        cohort_sha256=direct.request.consent.consent.cohort_sha256,
        authority_sha256="22" * 32,
        submission_sha256=digest(submission),
        model_sha256=digest(bundle),
        content_sha256=model_content_digest(bundle),
        recipient_hotkey=submission.hotkey,
        rights_evidence_sha256=digest(inputs.rights_evidence),
        reconstruction_evidence_sha256=digest(inputs.reconstruction_evidence),
        accepted_at_block=220,
        accepted_ordinal=1,
        rights_and_reconstruction_passed=True,
        direct_artifact=reservation,
    )
    return ModelAcceptancePublication(
        certificate=CertifiedModelArtifactAcceptance(
            acceptance=acceptance,
            signatures=(sign_object(acceptance, wallet("Charlie")),),
        ),
        inputs=inputs,
    )


@pytest.mark.asyncio
async def test_promotion_verifies_canonical_copy_before_resumable_staging_cleanup(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    publication = promotion_publication(direct, reservation)
    payload = reservation.reservation.payload
    source_key = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)[
        "object_key"
    ]
    preserved_key = preserved_model_object_key(
        reservation.reservation.cohort_sha256,
        payload.model_sha256,
        payload.payload_sha256,
    )
    direct.multipart.fail_deletes = 1

    with pytest.raises(OSError, match="delete response lost"):
        await direct.owner.promote(publication, now_unix_ms=1_800_000_012_000)

    assert source_key in direct.multipart.objects
    assert preserved_key in direct.multipart.objects
    assert (
        direct.owner.journal.get("direct-promotion", digest(publication.certificate.acceptance))
        is not None
    )
    copies = tuple(direct.multipart.copy_calls)

    receipt = await direct.owner.promote(publication, now_unix_ms=1_800_000_013_000)

    assert receipt.model_sha256 == payload.model_sha256
    assert tuple(direct.multipart.copy_calls) == copies
    assert source_key not in direct.multipart.objects
    assert preserved_key in direct.multipart.objects
    assert await direct.owner.promote(publication, now_unix_ms=1_800_000_014_000) == receipt

    direct.multipart.objects[preserved_key] = (payload.total_bytes, "replacement-etag")
    with pytest.raises(ValueError, match="changed after promotion"):
        await direct.owner.promote(publication, now_unix_ms=1_800_000_015_000)


@pytest.mark.asyncio
async def test_promotion_copy_bounds_parallel_parts_and_preserves_completion_order(
    receipt_scenario,
):
    class MultipartCopy:
        active = peak = 0

        async def copy_part(self, _, *, part_number, size_bytes, **kwargs):
            self.active += 1
            self.peak = max(self.peak, self.active)
            try:
                await asyncio.sleep(0.002 * (5 - (part_number % 4)))
                return DirectModelUploadPart(
                    part_number=part_number,
                    size_bytes=size_bytes,
                    etag=f"{part_number:032x}",
                )
            finally:
                self.active -= 1

    class Progress:
        completed = 0

        def advance(self):
            self.completed += 1

    size = 5 * 1024**2
    multipart, progress = MultipartCopy(), Progress()
    payload = SimpleNamespace(total_parts=9, part_size_bytes=size, total_bytes=9 * size)
    parts = await _copy_promotion_parts(
        multipart, "preserved", "staging", "upload", payload, 4, progress
    )

    assert multipart.peak == 4 and multipart.active == 0
    assert [part.part_number for part in parts] == list(range(1, 10))
    assert progress.completed == len(parts) == 9


@pytest.mark.asyncio
async def test_promotion_copy_retries_lost_reply_in_same_slot_without_duplicate_progress(
    monkeypatch,
    receipt_scenario,
):
    from umi import r2_multipart

    requests, waits, closed = [], [], []
    slots, attempts = {}, {}
    size = 5 * 1024**2

    class LostReply(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"<CopyPartResult>"
            raise httpx.RemoteProtocolError("response lost after server copied part")

        async def aclose(self):
            closed.append(True)

    async def pause(seconds):
        waits.append(seconds)

    def send(request):
        requests.append(request)
        assert request.method == "PUT"
        number = int(request.url.params["partNumber"])
        assert request.url.params["uploadId"] == "existing-upload"
        assert request.headers["x-amz-copy-source"] == "/umi-model-artifacts/staging"
        expected_range = f"bytes={(number - 1) * size}-{number * size - 1}"
        assert request.headers["x-amz-copy-source-range"] == expected_range
        slot = (request.url.path, request.url.params["uploadId"], number)
        value = (request.headers["x-amz-copy-source"], expected_range, f"{number:032x}")
        if slot in slots:
            assert slots[slot] == value
        slots[slot] = value  # Server commits before the first part-2 response is lost.
        attempts[number] = attempts.get(number, 0) + 1
        if number == 2 and attempts[number] == 1:
            return httpx.Response(200, stream=LostReply())
        return httpx.Response(
            200, content=f'<CopyPartResult><ETag>"{value[2]}"</ETag></CopyPartResult>'.encode()
        )

    class Progress:
        completed = 0

        def advance(self):
            self.completed += 1

    signer = R2SigV4(
        endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
        bucket="umi-model-artifacts",
        credentials=R2Credentials("0123456789ABCDEF", "secret-access-key-value"),
    )
    monkeypatch.setattr(r2_multipart.asyncio, "sleep", pause)
    client = r2_multipart.R2MultipartClient(signer, transport=httpx.MockTransport(send))
    payload = SimpleNamespace(total_parts=3, part_size_bytes=size, total_bytes=3 * size)
    progress = Progress()
    async with client.connection_scope():
        parts = await _copy_promotion_parts(
            client, "preserved", "staging", "existing-upload", payload, 2, progress
        )
    assert attempts == {1: 1, 2: 2, 3: 1}
    assert len(slots) == len(parts) == progress.completed == 3
    assert len(requests) == 4 and waits == [0.25] and closed == [True]
    assert [part.part_number for part in parts] == [1, 2, 3]
    assert [part.etag for part in parts] == [f"{number:032x}" for number in range(1, 4)]
    retried = [request for request in requests if request.url.params["partNumber"] == "2"]
    assert retried[0].url == retried[1].url
    for header in ("x-amz-copy-source", "x-amz-copy-source-range", "x-amz-content-sha256"):
        assert retried[0].headers[header] == retried[1].headers[header]


@pytest.mark.asyncio
async def test_promotion_copy_drains_failed_wave_before_aborting(receipt_scenario):
    class MultipartCopy:
        def __init__(self):
            self.active = 0
            self.started = []

        async def copy_part(self, _, *, part_number, size_bytes, **kwargs):
            self.active += 1
            self.started.append(part_number)
            try:
                await asyncio.sleep(0.01 if part_number != 2 else 0.001)
                if part_number == 2:
                    raise OSError("copy failed")
                return DirectModelUploadPart(
                    part_number=part_number,
                    size_bytes=size_bytes,
                    etag=f"{part_number:032x}",
                )
            finally:
                self.active -= 1

    class Progress:
        completed = 0

        def advance(self):
            self.completed += 1

    size = 5 * 1024**2
    multipart, progress = MultipartCopy(), Progress()
    payload = SimpleNamespace(total_parts=8, part_size_bytes=size, total_bytes=8 * size)
    with pytest.raises(OSError, match="copy failed"):
        await _copy_promotion_parts(
            multipart, "preserved", "staging", "upload", payload, 4, progress
        )
    assert multipart.active == 0
    assert multipart.started == [1, 2, 3, 4]
    assert progress.completed == 3


@pytest.mark.asyncio
async def test_promotion_copy_failure_retains_and_retries_original_upload(direct, monkeypatch):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    publication = promotion_publication(direct, reservation)
    source_key = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)[
        "object_key"
    ]
    original = direct.multipart.copy_part
    completed_uploads = len(direct.multipart.complete_calls)

    async def failed_copy(*args, **kwargs):
        raise OSError("part copy unavailable")

    monkeypatch.setattr(direct.multipart, "copy_part", failed_copy)
    with pytest.raises(OSError, match="part copy unavailable"):
        await direct.owner.promote(publication, now_unix_ms=1_800_000_012_000)
    assert len(direct.multipart.abort_calls) == 0
    creates = len(direct.multipart.create_calls)
    assert len(direct.multipart.complete_calls) == completed_uploads
    assert source_key in direct.multipart.objects

    monkeypatch.setattr(direct.multipart, "copy_part", original)
    receipt = await direct.owner.promote(publication, now_unix_ms=1_800_000_013_000)
    assert receipt.model_sha256 == direct.payload.payload.model_sha256
    assert len(direct.multipart.abort_calls) == 0
    assert len(direct.multipart.create_calls) == creates


@pytest.mark.asyncio
async def test_promotion_refuses_to_overwrite_an_existing_unverified_object(direct):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    publication = promotion_publication(direct, reservation)
    payload = reservation.reservation.payload
    preserved_key = preserved_model_object_key(
        reservation.reservation.cohort_sha256,
        payload.model_sha256,
        payload.payload_sha256,
    )
    direct.multipart.objects[preserved_key] = (payload.total_bytes + 1, "unexpected-object")

    with pytest.raises(ValueError, match="metadata changed"):
        await direct.owner.promote(publication, now_unix_ms=1_800_000_012_000)

    assert len(direct.multipart.create_calls) == 1
    assert direct.multipart.copy_calls == []
    source_key = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)[
        "object_key"
    ]
    assert source_key in direct.multipart.objects


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
        def __init__(self, maximum_concurrent_uploads=1):
            self.requests = []
            self.config = SimpleNamespace(maximum_concurrent_uploads=maximum_concurrent_uploads)

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
    legacy, direct_payloads = Payloads(7), Payloads()
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
    assert router.maximum_concurrent_uploads == 7
    assert "model_upload_url" in router.delivery_route(digest(legacy_plan))
    assert "direct_model_upload_url" in router.delivery_route(digest(direct_plan))

    direct_only = CohortModelPayloadRouter((direct_plan,), direct=direct_payloads)
    assert direct_only.maximum_concurrent_uploads == 1


async def test_owner_lost_verification_ack_reuses_durable_bytes_after_restart(direct, monkeypatch):
    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload), now_unix_ms=1_800_000_010_000
    )
    original = direct.owner.journal.put

    def interrupted(kind, key, body, **kwargs):
        if kind == "direct-verification":
            raise OSError("lost owner acknowledgement")
        return original(kind, key, body, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(direct.owner.journal, "put", interrupted)
        with pytest.raises(OSError, match="lost owner acknowledgement"):
            await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    reads = direct.multipart.read_calls
    restarted = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )
    verified = await restarted.verify(completed.reservation_sha256, now_unix_ms=1_800_000_012_000)
    assert verified.payload_sha256 == direct.payload.payload.payload_sha256
    assert direct.multipart.read_calls == reads


@pytest.mark.parametrize(
    "damage", ["missing_result", "corrupt_result", "missing_receipt", "changed_etag"]
)
async def test_remote_completed_verification_repairs_are_visible(direct, damage):
    import json
    from pathlib import Path

    from umi.competition_remote_model_verification import verify_remote_model
    from umi.competition_transport_verification import _sha

    bundle = direct.request.signed_submission.submission.model_bundle
    payload = direct.payload.payload
    key = "preservation/test-object"
    direct.multipart.objects[key] = (payload.total_bytes, "version-one")
    root = Path(direct.owner.config.directory) / "remote-test"
    events = []

    async def verify():
        return await verify_remote_model(
            direct.multipart,
            key,
            bundle,
            payload,
            root=root,
            context={"policy": "a" * 64, "authority": "b" * 64},
            report=events.append,
        )

    await verify()
    reads = direct.multipart.read_calls
    await verify()
    assert direct.multipart.read_calls == reads
    assert events[-1]["restored_bytes"] == payload.total_bytes
    directory = root / hashlib.sha256(key.encode()).hexdigest()
    if damage == "missing_result":
        (directory / "result.json").unlink()
    elif damage == "corrupt_result":
        (directory / "result.json").write_text('{"bad": true}')
    elif damage == "missing_receipt":
        (directory / (_sha("object") + ".json")).unlink()
    else:
        direct.multipart.objects[key] = (payload.total_bytes, "version-two")
    events.clear()
    await verify()
    assert direct.multipart.read_calls > reads
    assert any(event["status"] == "repair_required" for event in events)
    assert events[-1]["status"] == "completed" and events[-1]["eta_seconds"] == 0
    assert (
        json.loads((directory / "result.json").read_bytes())["payload_sha256"]
        == payload.payload_sha256
    )
    reads = direct.multipart.read_calls
    await verify()
    assert direct.multipart.read_calls == reads


async def test_remote_incomplete_stream_keeps_completed_file_checkpoints(direct, monkeypatch):
    from pathlib import Path

    from umi import competition_remote_model_verification as remote
    from umi.competition_remote_model_verification import verify_remote_model
    from umi.competition_transport_verification import ByteCheckpoints

    bundle = direct.request.signed_submission.submission.model_bundle
    payload = direct.payload.payload
    assert len(bundle.files) > 1
    key = "preservation/interrupted-object"
    direct.multipart.objects[key] = (payload.total_bytes, "version-one")
    root = Path(direct.owner.config.directory) / "remote-test"
    original_read = direct.multipart.read_range
    boundary = bundle.files[0].size_bytes
    # Inject interruption at an actual range boundary, independently of the
    # production read geometry, which now spans adjacent small files.
    monkeypatch.setattr(remote, "MAXIMUM_RANGE_BYTES", boundary)
    remembered = []
    original_remember = ByteCheckpoints.remember

    def remember(self, slot, identity, result):
        remembered.append(slot)
        return original_remember(self, slot, identity, result)

    async def interrupted(key, *, offset, size_bytes):
        if offset >= boundary:
            raise OSError("interrupted second file")
        return await original_read(key, offset=offset, size_bytes=size_bytes)

    monkeypatch.setattr(ByteCheckpoints, "remember", remember)
    with monkeypatch.context() as patch:
        patch.setattr(direct.multipart, "read_range", interrupted)
        with pytest.raises(OSError, match="interrupted second file"):
            await verify_remote_model(direct.multipart, key, bundle, payload, root=root, context={})
    assert ["file", bundle.files[0].path] in remembered
    remembered.clear()
    await verify_remote_model(direct.multipart, key, bundle, payload, root=root, context={})
    assert ["file", bundle.files[0].path] not in remembered
    assert "object" in remembered


@pytest.mark.parametrize("change", ["policy", "authority", "bucket", "semantics"])
async def test_remote_verification_rechecks_only_changed_context(direct, monkeypatch, change):
    from pathlib import Path

    from umi import competition_remote_model_verification as remote
    from umi.r2_sigv4 import R2SigV4

    bundle = direct.request.signed_submission.submission.model_bundle
    payload = direct.payload.payload
    key = "preservation/context-object"
    direct.multipart.objects[key] = (payload.total_bytes, "version-one")
    root = Path(direct.owner.config.directory) / "remote-test"
    context = {"policy": "a" * 64, "authority": "b" * 64}
    await remote.verify_remote_model(
        direct.multipart, key, bundle, payload, root=root, context=context
    )
    reads = direct.multipart.read_calls
    if change in {"policy", "authority"}:
        context[change] = "c" * 64
    elif change == "bucket":
        signer = direct.multipart.signer
        direct.multipart.signer = R2SigV4(
            signer.endpoint, "another-model-bucket", signer.credentials
        )
    else:
        monkeypatch.setattr(remote, "verifier_semantics", lambda: ["new-reviewed-semantics"])
    await remote.verify_remote_model(
        direct.multipart, key, bundle, payload, root=root, context=context
    )
    assert direct.multipart.read_calls > reads


async def test_remote_range_retry_preserves_live_hash_and_completed_restart(
    direct, tmp_path, monkeypatch
):
    from umi import competition_remote_model_verification as remote
    from umi import r2_multipart as multipart

    bundle = direct.request.signed_submission.submission.model_bundle
    payload = direct.payload.payload
    data = direct.multipart.payload_bytes
    range_bytes = 31
    assert len(data) > range_bytes * 2
    calls, waits, failures, events = [], [], [], []
    real_sleep = asyncio.sleep

    async def pause(seconds):
        if seconds:
            waits.append(seconds)
        else:
            await real_sleep(0)

    def send(request):
        if request.method == "HEAD":
            return httpx.Response(200, headers={"Content-Length": str(len(data)), "ETag": "v1"})
        byte_range = request.headers["Range"]
        calls.append(byte_range)
        start, end = (int(value) for value in byte_range.removeprefix("bytes=").split("-"))
        if start == range_bytes and len(failures) < 5:
            failures.append(True)
            return httpx.Response(500)
        return httpx.Response(
            206,
            headers={"Content-Range": f"bytes {start}-{end}/{len(data)}"},
            content=data[start : end + 1],
        )

    monkeypatch.setattr(multipart.asyncio, "sleep", pause)
    monkeypatch.setattr(remote, "MAXIMUM_RANGE_BYTES", range_bytes)
    arguments = dict(
        root=tmp_path / "retained-range-retry",
        context={"cohort": "same-authenticated-owner"},
        document_paths=(bundle.files[0].path,),
        report=events.append,
    )
    client = multipart.R2MultipartClient(
        direct.multipart.signer, transport=httpx.MockTransport(send)
    )
    async with client.connection_scope():
        documents, _ = await remote.verify_remote_model(
            client, "immutable/model/payload", bundle, payload, **arguments
        )
    assert waits == [1, 2, 4, 8, 16]
    expected = [
        f"bytes={offset}-{min(offset + range_bytes, len(data)) - 1}"
        for offset in range(0, len(data), range_bytes)
    ]
    assert calls == expected[:1] + [expected[1]] * 5 + expected[1:]
    assert documents[bundle.files[0].path] == data[: bundle.files[0].size_bytes]
    assert events[-1]["status"] == "completed"
    assert events[-1]["native_units"] == payload.total_bytes
    # A fresh client reuses the completed object fact without another range GET.
    reopened = multipart.R2MultipartClient(
        direct.multipart.signer, transport=httpx.MockTransport(send)
    )
    before = list(calls)
    restored, _ = await remote.verify_remote_model(
        reopened, "immutable/model/payload", bundle, payload, **arguments
    )
    assert restored == documents and calls == before
    assert events[-1]["restored_units"] == payload.total_bytes


@pytest.mark.parametrize("range_bytes", [1, 17, 64, 4096])
async def test_remote_ranges_span_files_and_reuse_completed_verification(
    direct, monkeypatch, tmp_path, range_bytes
):
    from umi import competition_remote_model_verification as remote

    bundle = direct.request.signed_submission.submission.model_bundle
    payload = direct.payload.payload
    key = "preservation/coalesced-object"
    direct.multipart.objects[key] = (payload.total_bytes, "version-one")
    reads = []
    original = direct.multipart.read_range

    async def read(key, *, offset, size_bytes):
        reads.append((offset, size_bytes))
        return await original(key, offset=offset, size_bytes=size_bytes)

    monkeypatch.setattr(remote, "MAXIMUM_RANGE_BYTES", range_bytes)
    monkeypatch.setattr(direct.multipart, "read_range", read)
    docs = (bundle.files[0].path, bundle.files[-1].path)
    arguments = dict(root=tmp_path / "ranges", context={"authority": "a" * 64}, document_paths=docs)
    documents, _ = await remote.verify_remote_model(
        direct.multipart, key, bundle, payload, **arguments
    )
    assert reads == [
        (offset, min(range_bytes, payload.total_bytes - offset))
        for offset in range(0, payload.total_bytes, range_bytes)
    ]
    offset = 0
    for record in bundle.files:
        if record.path in docs:
            assert (
                documents[record.path]
                == direct.multipart.payload_bytes[offset : offset + record.size_bytes]
            )
        offset += record.size_bytes
    # Read geometry changes do not change native byte semantics or require a
    # second payload pass after a completed immutable-object verification.
    reads.clear()
    monkeypatch.setattr(remote, "MAXIMUM_RANGE_BYTES", range_bytes + 1)
    restored, _ = await remote.verify_remote_model(
        direct.multipart, key, bundle, payload, **arguments
    )
    assert restored == documents and not reads


@pytest.mark.parametrize("damage", ["short_range", "changed_second_file"])
async def test_coalesced_remote_ranges_preserve_integrity_failures(
    direct, monkeypatch, tmp_path, damage
):
    from umi.competition_remote_model_verification import verify_remote_model

    bundle = direct.request.signed_submission.submission.model_bundle
    payload = direct.payload.payload
    key = "preservation/damaged-coalesced-object"
    direct.multipart.objects[key] = (payload.total_bytes, "version-one")
    original = direct.multipart.read_range
    boundary = bundle.files[0].size_bytes

    async def read(key, *, offset, size_bytes):
        raw = await original(key, offset=offset, size_bytes=size_bytes)
        if damage == "short_range":
            return raw[:-1]
        if offset <= boundary < offset + len(raw):
            position = boundary - offset
            raw = raw[:position] + bytes([raw[position] ^ 1]) + raw[position + 1 :]
        return raw

    monkeypatch.setattr(direct.multipart, "read_range", read)
    with pytest.raises(ValueError, match=r"range differs|file differs"):
        await verify_remote_model(
            direct.multipart, key, bundle, payload, root=tmp_path / "damaged", context={}
        )


@pytest.mark.asyncio
async def test_more_than_legacy_generation_limit_resumes_original_signed_upload(direct):
    import itertools

    counter = itertools.count(1)
    direct.owner.new_attempt_id = lambda: f"{next(counter):064x}"
    direct.multipart.fail_creates = 70
    original_request = canonical_json_bytes(direct.request)
    original_payload = canonical_json_bytes(direct.payload)
    epoch = 1_800_000_000_000
    for generation in range(70):
        with pytest.raises(OSError, match="provider offline"):
            await direct.owner.reserve(
                direct.request, direct.payload, now_unix_ms=epoch + generation * 121_000
            )
    signed = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=epoch + 70 * 121_000
    )
    assert signed.reservation.generation == 71
    assert len(direct.authorizations) == 1
    assert canonical_json_bytes(direct.request) == original_request
    assert canonical_json_bytes(direct.payload) == original_payload
    reopened = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )
    retry = await reopened.reserve(direct.request, direct.payload, now_unix_ms=epoch + 71 * 121_000)
    assert retry == signed
    assert len(direct.multipart.create_calls) == 71
    await reopened.complete(
        signed_completion(signed, direct.payload.payload), now_unix_ms=epoch + 72 * 121_000
    )
    verified = await reopened.verify(digest(signed.reservation), now_unix_ms=epoch + 73 * 121_000)
    assert verified.reservation_sha256 == digest(signed.reservation)
    reads = direct.multipart.read_calls
    assert (
        await reopened.verify(digest(signed.reservation), now_unix_ms=epoch + 73 * 121_000)
        == verified
    )
    assert direct.multipart.read_calls == reads
    snapshot = reopened.journal.metadata_snapshot()
    assert snapshot["retained_uploads"] == 1
    assert snapshot["retained_attempts"] == 71
    assert snapshot["highest_generation"] == 71
    assert snapshot["metadata_bytes"] < snapshot["maximum_metadata_bytes"]


@pytest.mark.asyncio
async def test_http_metadata_damage_is_retryable_and_repair_preserves_reservation(direct):
    signed = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    with direct.owner.journal.transaction() as db:
        db.execute("DELETE FROM direct_upload_attempt_heads")
    app = FastAPI()
    app.include_router(
        direct_model_upload_routes(direct.owner, now_unix_ms=lambda: 1_800_000_200_000)
    )
    request = DirectModelUploadReservationRequest(
        schema="umi-direct-model-upload-reservation-request/1",
        request=direct.request,
        payload=direct.payload,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="https://intake.test"
    ) as client:
        response = await client.post(
            f"/v1/competition/cohorts/{direct.owner.config.cohort_sha256}/direct-model-uploads",
            content=canonical_json_bytes(request),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 503
    assert response.headers["X-UMI-Reason-Code"] == "model_upload_metadata_repair_required"
    fixed = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
        repair_attempt_index=True,
    )
    assert (
        await fixed.reserve(direct.request, direct.payload, now_unix_ms=1_800_000_200_000) == signed
    )
    assert len(direct.authorizations) == 1
    assert len(direct.multipart.create_calls) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_replacement", [False, True])
async def test_expired_provider_after_retained_completion_intent_resumes_same_upload(
    direct, monkeypatch, fail_replacement
):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completion = signed_completion(first, direct.payload.payload)

    async def provider_unavailable(*args, **kwargs):
        raise OSError("completion failed before provider commit")

    with monkeypatch.context() as patch:
        patch.setattr(direct.multipart, "complete", provider_unavailable)
        with pytest.raises(OSError, match="before provider commit"):
            await direct.owner.complete(completion, now_unix_ms=1_800_000_010_000)
    first_sha = digest(first.reservation)
    original = direct.owner.journal.get("direct-completion", first_sha)
    assert original is not None
    attempt = direct.owner.journal.get("direct-intent", first.reservation.attempt_id)
    provider = direct.owner.journal.get("direct-provider", first.reservation.attempt_id)
    direct.multipart.multipart_uploads.remove(
        (attempt["object_key"], provider["provider_upload_id"])
    )
    restart = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=first_sha,
        generation=first.reservation.generation,
        reason_code="provider_upload_unavailable",
    )
    signed_restart = SignedDirectModelUploadRestartRequest(
        schema="umi-signed-direct-model-upload-restart-request/1",
        request=restart,
        signature=sign_object(restart, wallet("Alice")),
    )
    now = 1_800_000_121_000
    if fail_replacement:
        direct.multipart.fail_creates = 1
        with pytest.raises(OSError, match="provider offline"):
            await direct.owner.restart(signed_restart, now_unix_ms=now)
        assert direct.owner.journal.get("direct-completion", first_sha) == original
        with pytest.raises(DirectModelUploadPending):
            await direct.owner.restart(signed_restart, now_unix_ms=now + 1)
        now += 121_000
    second = await direct.owner.restart(signed_restart, now_unix_ms=now)
    assert second.reservation.generation == (3 if fail_replacement else 2)
    assert second.reservation.payload == first.reservation.payload
    assert direct.owner.journal.get("direct-completion", first_sha) == original
    assert await direct.owner.restart(signed_restart, now_unix_ms=now + 1) == second
    assert len(direct.authorizations) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("remote_object", [False, True])
async def test_completion_intent_recovery_requires_absent_provider_and_object(
    direct, remote_object
):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    first_sha = digest(first.reservation)
    direct.owner.journal.put(
        "direct-completion", first_sha, signed_completion(first, direct.payload.payload)
    )
    attempt = direct.owner.journal.get("direct-intent", first.reservation.attempt_id)
    if remote_object:
        direct.multipart.multipart_uploads.clear()
        direct.multipart.objects[attempt["object_key"]] = (
            direct.multipart.total_bytes,
            "committed",
        )
    request = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=first_sha,
        generation=first.reservation.generation,
        reason_code="provider_upload_unavailable",
    )
    wrong = SignedDirectModelUploadRestartRequest(
        schema="umi-signed-direct-model-upload-restart-request/1",
        request=request,
        signature=sign_object(request, wallet("Bob")),
    )
    with pytest.raises(ValueError, match="signer"):
        await direct.owner.restart(wrong, now_unix_ms=1_800_000_121_000)
    signed = wrong.model_copy(update={"signature": sign_object(request, wallet("Alice"))})
    if remote_object:
        with pytest.raises(ValueError, match="completed"):
            await direct.owner.restart(signed, now_unix_ms=1_800_000_121_000)
    else:
        with pytest.raises(DirectModelUploadPending, match="remains available"):
            await direct.owner.restart(signed, now_unix_ms=1_800_000_121_000)
    assert direct.owner.journal.get("direct-superseded", first_sha) is None
    assert len(direct.multipart.create_calls) == 1


@pytest.mark.asyncio
async def test_completion_expiry_http_reports_signed_restart_reason(direct, monkeypatch):
    first = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completion = signed_completion(first, direct.payload.payload)
    direct.multipart.multipart_uploads.clear()

    async def expired(*args, **kwargs):
        raise OSError("NoSuchUpload")

    monkeypatch.setattr(direct.multipart, "complete", expired)
    app = FastAPI()
    app.include_router(
        direct_model_upload_routes(direct.owner, now_unix_ms=lambda: 1_800_000_121_000)
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app), base_url="https://intake.example"
    ) as client:
        response = await client.post(
            f"/v1/competition/cohorts/{direct.owner.config.cohort_sha256}/direct-model-uploads/{digest(first.reservation)}/complete",
            content=canonical_json_bytes(completion),
            headers={"Content-Type": "application/json"},
        )
    assert response.status_code == 503
    assert response.headers["X-UMI-Reason-Code"] == "model_upload_provider_generation_unavailable"
    assert direct.owner.journal.get(
        "direct-completion", digest(first.reservation)
    ) == completion.model_dump(mode="json", by_alias=True)


async def test_direct_empty_supporting_file_repairs_retained_hold_without_zero_byte_R2_read(
    direct, tmp_path, policy
):
    from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
    from umi.open_competition import BundleFile

    old_sub = direct.request.signed_submission.submission
    empty = BundleFile(
        path="zz-empty.txt", role="provenance", size_bytes=0, sha256=hashlib.sha256(b"").hexdigest()
    )
    bundle = old_sub.model_bundle.model_copy(update={"files": (*old_sub.model_bundle.files, empty)})
    sub = old_sub.model_copy(update={"model_bundle": bundle, "model_revision": digest(bundle)})
    signed = direct.request.signed_submission.model_copy(
        update={
            "submission": sub,
            "signature": sign_object(sub, wallet("Alice")),
        }
    )
    consent = direct.request.consent.consent.model_copy(update={"submission_sha256": digest(sub)})
    request = direct.request.model_copy(
        update={
            "signed_submission": signed,
            "consent": direct.request.consent.model_copy(
                update={
                    "consent": consent,
                    "signature": sign_object(consent, wallet("Alice")),
                }
            ),
        }
    )
    payload = direct.payload.payload.model_copy(
        update={
            "upload_sha256": digest(request),
            "model_sha256": digest(bundle),
            "file_count": len(bundle.files),
        }
    )
    signed_payload = direct.payload.model_copy(
        update={
            "payload": payload,
            "signature": sign_object(payload, wallet("Alice")),
        }
    )
    standing = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(policy),
        contribution_terms_sha256=policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="fixture operator",
        approved_at_utc="2026-10-01T00:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    owner = DirectModelUploadOwner(
        direct.owner.config.model_copy(
            update={
                "directory": str(tmp_path / "empty-direct"),
                "admission_reviews_directory": str(tmp_path / "empty-reviews"),
                "standing_review_policy": standing,
            }
        ),
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
        policy=policy,
    )
    reservation = await owner.reserve(request, signed_payload, now_unix_ms=1_800_000_000_000)
    completed = await owner.complete(
        signed_completion(reservation, payload), now_unix_ms=1_800_000_010_000
    )
    await owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    hold = {
        "reason_code": "review_document_size_outside_policy",
        "review_policy_sha256": digest(standing),
    }
    owner.journal.put("direct-review-hold", digest(bundle), hold)
    assert owner.status(completed.reservation_sha256).hold_reason_code is None
    old_read = direct.multipart.read_range

    async def bounded(*args, **kwargs):
        assert kwargs["size_bytes"] > 0
        return await old_read(*args, **kwargs)

    direct.multipart.read_range = bounded
    result = await owner.poll_once(now_unix_ms=1_800_000_012_000)
    assert result["reviews_held"] == result["objects_failed"] == 0
    assert owner.journal.get("direct-review-hold", digest(bundle)) == hold
    assert (tmp_path / "empty-reviews" / (digest(bundle) + ".json")).exists()


async def test_poll_input_uses_one_transaction_and_rechecks_conflict_holds(direct, monkeypatch):
    from contextlib import contextmanager

    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    key = digest(reservation.reservation)
    original = direct.owner.journal.read_transaction
    calls = []

    @contextmanager
    def counted(*args, **kwargs):
        calls.append(1)
        with original(*args, **kwargs) as db:
            yield db

    monkeypatch.setattr(direct.owner.journal, "read_transaction", counted)
    verified, retained, hold = direct.owner._poll_input(key)
    assert not verified and retained == reservation and hold is None
    assert len(calls) == 1
    # This is the native fixture's conflict fence, not a production database.
    with direct.owner.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (key,))
    with pytest.raises(ValueError, match="conflict held"):
        direct.owner._poll_input(key)
    assert len(calls) == 2, "each poll must open a fresh fenced snapshot"


async def test_completed_poll_journal_reads_are_off_event_loop(direct, monkeypatch):
    import threading

    reservation = await direct.owner.reserve(
        direct.request, direct.payload, now_unix_ms=1_800_000_000_000
    )
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload),
        now_unix_ms=1_800_000_010_000,
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=1_800_000_011_000)
    event_loop_thread = threading.get_ident()
    original = direct.owner.journal.read_transaction
    from contextlib import contextmanager

    threads = []

    @contextmanager
    def off_loop(*args, **kwargs):
        current = threading.get_ident()
        assert current != event_loop_thread, "completed upload polling must not block async traffic"
        threads.append(current)
        with original(*args, **kwargs) as db:
            yield db

    monkeypatch.setattr(direct.owner.journal, "read_transaction", off_loop)
    reads_before = direct.multipart.read_calls
    result = await direct.owner.poll_once(now_unix_ms=1_800_000_012_000)
    assert result["objects_verified"] == 1
    assert threads and direct.multipart.read_calls == reads_before
