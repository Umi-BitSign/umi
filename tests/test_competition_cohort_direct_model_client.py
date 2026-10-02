"""Miner-to-R2 multipart delivery followed by native cohort participation."""

from __future__ import annotations

import asyncio
import hashlib
from contextlib import suppress
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_direct_model_client as direct_client
from umi import competition_cohort_model_client as model_client
from umi.competition_client import CompetitionSubmissionError
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwnerConfig,
)
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_model_client import submit_cohort_model
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_model_upload import authorize_model_delivery
from umi.competition_cohort_recovery import ModelDeliveryProfile
from umi.open_competition import digest, sign_object
from umi.r2_sigv4 import R2Credentials, R2SigV4

from .test_competition_cohort_model_upload import base_policy as base_policy
from .test_competition_cohort_model_upload import delivery as delivery
from .test_competition_cohort_model_upload import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_upload import policy as policy
from .test_competition_cohort_model_upload import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_upload import recovery as recovery
from .test_competition_cohort_model_upload import runtime as runtime
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


class Multipart:
    def __init__(self):
        self.signer = R2SigV4(
            endpoint="https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com",
            bucket="umi-model-artifacts",
            credentials=R2Credentials("0123456789ABCDEF", "secret-access-key-value"),
        )
        self.parts: dict[int, bytes] = {}
        self.complete_bytes: bytes | None = None

    async def create(self, key, *, at=None):
        return "provider-upload-1"

    async def head(self, key, *, at=None):
        if self.complete_bytes is None:
            return None
        return SimpleNamespace(size_bytes=len(self.complete_bytes), etag="object-etag-1")

    async def complete(self, key, *, upload_id, parts, at=None):
        assert upload_id == "provider-upload-1"
        assert tuple(part.part_number for part in parts) == tuple(range(1, len(parts) + 1))
        for part in parts:
            data = self.parts[part.part_number]
            assert len(data) == part.size_bytes
            assert hashlib.md5(data, usedforsecurity=False).hexdigest() == part.etag
        self.complete_bytes = b"".join(self.parts[number] for number in range(1, len(parts) + 1))
        return "object-etag-1"

    async def read_range(self, key, *, offset, size_bytes, at=None):
        assert self.complete_bytes is not None
        return self.complete_bytes[offset : offset + size_bytes]


@pytest.mark.asyncio
async def test_part_upload_stops_at_response_byte_bound(delivery):
    submission = delivery.request.signed_submission.submission
    bundle = submission.model_bundle
    assert bundle is not None
    fingerprints = direct_client._snapshot(delivery.source, bundle)
    total = sum(record.size_bytes for record in bundle.files)
    size = min(total, 5 * 1024**2)
    chunks_read = 0

    class Oversized(httpx.AsyncByteStream):
        async def __aiter__(self):
            nonlocal chunks_read
            for _ in range(3):
                chunks_read += 1
                yield b"x" * (32 * 1024)

    async def send(request):
        await request.aread()
        return httpx.Response(200, headers={"ETag": "ab" * 16}, stream=Oversized())

    async with httpx.AsyncClient(transport=httpx.MockTransport(send)) as client:
        with pytest.raises(CompetitionSubmissionError, match="model_upload_status_too_large"):
            await direct_client._upload_part(
                client,
                SimpleNamespace(part_number=1, size_bytes=size, url="https://r2.invalid/part"),
                delivery.source,
                bundle,
                fingerprints,
                direct_client._offsets(bundle),
                SimpleNamespace(part_size_bytes=5 * 1024**2),
            )
    assert chunks_read == 3


@pytest.mark.asyncio
async def test_direct_upload_bypasses_coordinator_payload_disk_and_enrolls(delivery, monkeypatch):
    h = delivery
    profile = ModelDeliveryProfile(
        schema="umi-model-delivery-profile/1",
        mechanism="direct_r2_multipart_v1",
        part_size_bytes=5 * 1024**2,
        maximum_concurrent_parts=2,
        capability_ttl_seconds=900,
    )
    multipart = Multipart()
    review_policy = StandingModelReviewPolicy(
        schema="umi-standing-model-artifact-review-policy/1",
        competition_policy_sha256=digest(h.intake.policy),
        contribution_terms_sha256=h.intake.policy.contribution_terms_sha256,
        standing_approval_record_sha256="ab" * 32,
        approved_by="operator@example.test",
        approved_at_utc="2026-10-02T12:00:00Z",
        complete_declared_bundle_rights_approved=True,
        licenses_and_notices_reviewed=True,
        public_redistribution_and_evaluation_approved=True,
    )
    reviews = h.source.parent / "direct-reviews"

    async def authorize(request):
        capture = await h.capture()
        authorize_model_delivery(h.intake, request, capture)

    async def sign(value):
        return sign_object(value, wallet("Charlie"))

    owner = DirectModelUploadOwner(
        DirectModelUploadOwnerConfig(
            schema="umi-direct-model-upload-owner-config/1",
            directory=str(h.source.parent / "direct-owner"),
            cohort_sha256=h.cohort,
            owner_hotkey=wallet("Charlie").hotkey.ss58_address,
            delivery=profile,
            maximum_uploads=8,
            admission_reviews_directory=str(reviews),
            standing_review_policy=review_policy,
        ),
        multipart,
        authorize=authorize,
        sign=sign,
        policy=h.intake.policy,
        new_attempt_id=lambda: "a1" * 32,
    )
    app = FastAPI()
    app.include_router(
        cohort_routes(h.intake, h.capture, maximum_body_bytes=4 * 1024**2, models=owner)
    )
    app.include_router(direct_model_upload_routes(owner, now_unix_ms=lambda: 1_800_000_000_000))

    discovered = []

    async def discover(**values):
        discovered.append(values["cohort_sha256"])
        return profile

    monkeypatch.setattr(model_client, "fetch_model_delivery_profile", discover)

    put_requests = 0

    async def put_part(request):
        nonlocal put_requests
        put_requests += 1
        number = int(request.url.params["partNumber"])
        data = await request.aread()
        multipart.parts[number] = data
        return httpx.Response(
            200,
            headers={"ETag": hashlib.md5(data, usedforsecurity=False).hexdigest()},
        )

    async def verifier():
        while True:
            await owner.poll_once(now_unix_ms=1_800_000_000_000)
            await asyncio.sleep(0.005)

    task = asyncio.create_task(verifier())
    try:
        receipt = await asyncio.wait_for(
            submit_cohort_model(
                origin="https://intake.example",
                policy=h.intake.policy,
                request=h.request,
                source=h.source,
                wallet=wallet("Alice"),
                transport=httpx.ASGITransport(app),
                object_transport=httpx.MockTransport(put_part),
                retry_seconds=0.001,
            ),
            20,
        )
        uploaded_parts = put_requests
        retry_receipt = await asyncio.wait_for(
            submit_cohort_model(
                origin="https://intake.example",
                policy=h.intake.policy,
                request=h.request,
                source=h.source,
                wallet=wallet("Alice"),
                transport=httpx.ASGITransport(app),
                object_transport=httpx.MockTransport(put_part),
                retry_seconds=0.001,
            ),
            20,
        )
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task

    assert receipt.status == "pending_attestation"
    assert retry_receipt == receipt
    assert discovered == [h.cohort, h.cohort]
    assert put_requests == uploaded_parts
    assert multipart.complete_bytes == b"".join(
        (h.source / record.path).read_bytes()
        for record in h.request.signed_submission.submission.model_bundle.files
    )
    assert h.intake.receipt(h.request) == receipt.model_dump(mode="json", by_alias=True)
    assert not (h.source.parent / "direct-owner" / "files").exists()
    model = h.request.signed_submission.submission.model_revision
    assert (reviews / (model + ".json")).is_file()
