"""Native retained upload HTTP retries after synthetic accounting release.

R2 and finality are fixtures. Native owner history/admission, original journal,
allocation fencing and signatures are real. This does not qualify deletion or
issue consumer-release authority; no production payload is accessed.
"""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_model_client import _status, submit_cohort_model
from umi.competition_cohort_model_upload import CohortModelUploads, ModelUploadConfig
from umi.competition_cohort_model_upload_delivery import ModelUploadDelivery
from umi.competition_cohort_model_upload_http import model_upload_routes
from umi.competition_cohort_service_host import ServiceAdmissionHost
from umi.open_competition import digest
from umi.private_files import ensure_private_directory, publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_legacy_model_admission import frozen as frozen
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_model_upload import signed_chunk
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


@pytest.fixture
def released(frozen, tmp_path, request):
    f = frozen
    original = f.case.requests[0]
    bundle = original.signed_submission.submission.model_bundle
    key, model = digest(original), digest(bundle)
    owner = CohortModelUploads(
        ModelUploadConfig(
            directory=str(tmp_path / "legacy-uploads"), maximum_reserved_bytes=1024**3
        ),
        f.owner.intake,
        f.owner.archive,
    )
    # Reconstruct the original upload journal alongside its native frozen
    # participation. The fixture predates the storage adoption, not a new reserve.
    with owner.journal.locked():
        owner.journal.put_many(
            (
                ("bundle", model, bundle),
                ("upload", key, original),
                owner.allocations.reservation_record(bundle),
            ),
            index=lambda db: owner.allocations.index_reserved(db, bundle),
        )
        for phase in ("remote_qualified", "release_prepared"):
            owner.allocations._transition(model, phase, evidence={"fixture": phase})
    ensure_private_directory(owner.root / "files" / model)
    ensure_private_directory(owner.archive / model)
    if getattr(request, "param", "released") == "released":
        with owner.journal.locked():
            owner.allocations._complete_release(model)
    f.uploads, f.request, f.key, f.model = owner, original, key, model
    return f


def app_for(f, *, remote=True):
    async def forbidden_capture():
        raise AssertionError("an original retry must not acquire new finality")

    app = FastAPI()
    app.include_router(
        model_upload_routes(
            f.uploads,
            forbidden_capture,
            remote_payloads=f.owner.legacy_payloads if remote else None,
        )
    )
    return app


def chunk(f, *, changed=False, signer="Alice"):
    file = f.request.signed_submission.submission.model_bundle.files[0]
    data = f.remote.objects["chunks/sha256/" + file.sha256]
    if changed:
        data = bytes([data[0] ^ 1]) + data[1:]
    signed, signature = signed_chunk(f.key, 0, data, signer=signer)
    return data, {
        "content-type": "application/octet-stream",
        "content-length": str(len(data)),
        "x-umi-chunk-sha256": signed.sha256,
        "x-umi-signature": canonical_json_bytes(signature).decode(),
    }


def assert_no_payloads(f):
    assert not (f.uploads.root / "files" / f.model / "model").exists()
    assert not list((f.uploads.root / "files" / f.model).glob("partial-*"))
    assert not (f.uploads.archive / f.model / "model").exists()


async def test_certified_original_refuses_new_direct_continuation(released):
    f = released
    allocation = f.uploads.allocations.snapshot()
    original = f.uploads.journal.get_raw("upload", f.key)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app_for(f)), base_url="https://intake.example"
    ) as client:
        response = await client.get(f"/v1/competition/model-uploads/{f.key}/continuation")
    assert response.status_code == 404
    assert not f.remote.reads
    assert f.uploads.journal.get_raw("upload", f.key) == original
    assert f.uploads.allocations.snapshot() == allocation
    assert_no_payloads(f)


async def test_upgraded_client_retries_released_original_without_uploading_again(
    released, monkeypatch, tmp_path
):
    f = released
    monkeypatch.setenv("UMI_MODEL_VERIFICATION_DIRECTORY", str(tmp_path / "client-verification"))
    original = f.uploads.journal.get_raw("upload", f.key)
    allocation = f.uploads.allocations.snapshot()

    async def forbidden_capture():
        raise AssertionError("retained original requires no new registration capture")

    receipts = []
    for attempt in range(2):
        if attempt:
            f.uploads = CohortModelUploads(f.uploads.config, f.uploads.intake, f.uploads.archive)
            f.owner, f.router = f.create()
        app = app_for(f)
        app.include_router(
            cohort_routes(f.uploads.intake, forbidden_capture, maximum_body_bytes=4 * 1024**2)
        )
        native, requests = httpx.ASGITransport(app), []

        async def send(wire, native=native, requests=requests):
            assert wire.method != "PUT" and "direct-model-uploads" not in wire.url.path
            requests.append((wire.method, wire.url.path, wire.content))
            return await native.handle_async_request(wire)

        f.remote.reads.clear()
        receipts.append(
            await asyncio.wait_for(
                submit_cohort_model(
                    origin="https://intake.example",
                    policy=f.uploads.intake.policy,
                    request=f.request,
                    source=tmp_path / "offline-original" / "model",
                    wallet=wallet("Alice"),
                    transport=httpx.MockTransport(send),
                    retry_seconds=0.001,
                ),
                20,
            )
        )
        assert ("GET", f"/v1/competition/model-uploads/{f.key}", b"") in requests
        assert [row[2] for row in requests if row[0] == "POST"] == [original, original]
        if attempt:
            assert not f.remote.reads
        assert f.uploads.journal.get_raw("upload", f.key) == original
        assert f.uploads.allocations.snapshot() == allocation
        assert_no_payloads(f)
    assert receipts[0] == receipts[1]


@pytest.mark.parametrize("frozen", ["unadmitted"], indirect=True)
async def test_preserved_unadmitted_upload_keeps_delivery_retries_without_admission(released):
    f = released
    original = f.uploads.journal.get_raw("upload", f.key)
    allocation = f.uploads.allocations.snapshot()
    resolution = f.sources.resolve(f.case.cohort, request_sha256=digest(f.request))
    await f.sources.reader(resolution).verify()
    assert not f.owner.legacy_payloads.contains(f.request)
    for attempt in range(2):
        if attempt:
            f.uploads = CohortModelUploads(f.uploads.config, f.uploads.intake, f.uploads.archive)
            f.owner, f.router = f.create()
        f.remote.reads.clear()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app_for(f)), base_url="https://intake.example"
        ) as client:
            response = await client.post(
                f"/v1/competition/cohorts/{f.case.cohort}/model-uploads",
                content=original,
                headers={"content-type": "application/json"},
            )
            assert response.status_code == 200, response.text
            status = response.json()
            assert status["payload_preserved"] is True
            assert status["participation_admitted"] is False
            assert status["artifact_review_certified"] is False
            if attempt:
                assert not f.remote.reads, "completed byte checks survive restart"
            data, headers = chunk(f)
            response = await client.put(
                f"/v1/competition/model-uploads/{f.key}/files/0", content=data, headers=headers
            )
            assert response.status_code == 200 and response.json() == status
        delivery = ModelUploadDelivery(f.uploads, remote_payloads=f.owner.legacy_payloads)
        assert delivery._payload_owner(f.request) is delivery.preserved
        with pytest.raises(ValueError, match="cannot qualify model admission"):
            delivery.preserved.qualify(None, record=None, admission=None)
        assert not f.owner.legacy_payloads.contains(f.request)
        assert f.uploads.journal.get_raw("upload", f.key) == original
        assert f.uploads.allocations.snapshot() == allocation
        assert_no_payloads(f)


@pytest.mark.parametrize("frozen", ["incomplete"], indirect=True)
async def test_unpreserved_original_cannot_claim_delivery_from_backup(released):
    f = released
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app_for(f)), base_url="https://intake.example"
    ) as client:
        response = await client.get(f"/v1/competition/model-uploads/{f.key}")
    assert response.status_code == 503
    assert not f.remote.reads
    assert_no_payloads(f)


@pytest.mark.parametrize("released", ["release_prepared", "released"], indirect=True)
async def test_recurring_host_poll_reuses_remote_original_without_recreating_payloads(released):
    f = released
    original = f.uploads.journal.get_raw("upload", f.key)
    allocation = f.uploads.allocations.snapshot()
    for attempt in range(2):
        if attempt:
            f.uploads = CohortModelUploads(f.uploads.config, f.uploads.intake, f.uploads.archive)
            f.owner, f.router = f.create()
        host = SimpleNamespace(
            uploads=f.uploads, legacy_payloads=f.owner.legacy_payloads, continued_payloads=None
        )
        f.remote.reads.clear()
        result = await ServiceAdmissionHost._poll_legacy_uploads(host)
        assert result["models_preserved"] == 1 and result["models_pending"] == 0
        assert result["storage_allocations"] == allocation
        assert result["artifact_review_certified"] is False
        assert not result["last_error_type"]
        if attempt:
            assert not f.remote.reads
        assert f.uploads.journal.get_raw("upload", f.key) == original
        assert_no_payloads(f)


@pytest.mark.parametrize("failure", ["missing_owner", "missing_chunk", "corrupt_admission"])
async def test_recurring_remote_poll_keeps_unverified_storage_pending(released, failure):
    f = released
    if failure == "missing_chunk":
        f.remote.objects.clear()
    elif failure == "corrupt_admission":
        with f.uploads.intake._connection() as (db, _):
            db.execute("UPDATE cohort_admission_certificates SET body=?", (b"{}",))
    events = []
    result = await ModelUploadDelivery(
        f.uploads, remote_payloads=f.owner.legacy_payloads if failure != "missing_owner" else None
    ).poll_once(report=events.append)
    assert result["models_preserved"] == 0 and result["models_pending"] == 1
    assert result["last_error_type"]
    assert any(row["status"] == "retrying" and row["eta_seconds"] is None for row in events)
    assert_no_payloads(f)


async def test_released_poll_uses_only_retained_review_and_recovers_after_metadata_repair(
    released, tmp_path
):
    f = released
    config = f.uploads.config.model_copy(
        update={"admission_reviews_directory": str(tmp_path / "original-reviews")}
    )
    f.uploads = CohortModelUploads(config, f.uploads.intake, f.uploads.archive)
    poller = ModelUploadDelivery(f.uploads, remote_payloads=f.owner.legacy_payloads)
    first = await poller.poll_once()
    assert first["models_pending"] == 1 and first["model_reviews_ready"] == 0
    assert first["last_error_type"] == "OSError"
    assert_no_payloads(f)
    target = tmp_path / "original-reviews" / (f.model + ".json")
    publish_private_model(target, f.inputs, maximum_bytes=33 * 1024**2)
    original = target.read_bytes()
    f.remote.reads.clear()
    second = await poller.poll_once()
    assert second["models_pending"] == 0 and second["model_reviews_ready"] == 1
    assert not f.remote.reads and target.read_bytes() == original
    assert_no_payloads(f)


@pytest.mark.parametrize("frozen", ["incomplete"], indirect=True)
async def test_recurring_remote_poll_refuses_original_outside_authenticated_selection(released):
    f = released
    result = await ModelUploadDelivery(
        f.uploads, remote_payloads=f.owner.legacy_payloads
    ).poll_once()
    assert result["models_preserved"] == 0 and result["models_pending"] == 1
    assert not f.remote.reads
    assert_no_payloads(f)


@pytest.mark.parametrize("released", ["release_prepared", "released"], indirect=True)
async def test_original_http_retry_survives_restart_without_local_payloads(released):
    f = released
    original = f.uploads.journal.get_raw("upload", f.key)
    allocation = f.uploads.allocations.snapshot()
    for attempt in range(2):
        if attempt:
            f.uploads = CohortModelUploads(f.uploads.config, f.uploads.intake, f.uploads.archive)
            f.owner, f.router = f.create()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app_for(f)), base_url="http://test"
        ) as client:
            f.remote.reads.clear()
            response = await client.post(
                f"/v1/competition/cohorts/{f.case.cohort}/model-uploads",
                content=canonical_json_bytes(f.request),
                headers={"content-type": "application/json"},
            )
            assert response.status_code == 200, response.text
            status = response.json()
            assert status["upload_sha256"] == f.key
            assert status["payload_preserved"]
            assert _status(response.content, f.key, f.sub.model_bundle).payload_preserved
            assert not status["participation_admitted"] and not status["artifact_review_certified"]
            if attempt:
                assert not f.remote.reads
            f.remote.reads.clear()
            response = await client.get(f"/v1/competition/model-uploads/{f.key}")
            assert response.status_code == 200 and response.json() == status
            assert not f.remote.reads
            data, headers = chunk(f)
            response = await client.put(
                f"/v1/competition/model-uploads/{f.key}/files/0", content=data, headers=headers
            )
            assert response.status_code == 200 and response.json() == status
            assert len(f.remote.reads) == 1
        assert_no_payloads(f)
        assert f.uploads.journal.get_raw("upload", f.key) == original
        assert f.uploads.allocations.snapshot() == allocation


@pytest.mark.parametrize("failure", ["wrong_signer", "wrong_bytes", "body_differs"])
async def test_remote_put_preserves_original_signature_and_bytes_checks(released, failure):
    f = released
    data, headers = chunk(
        f, changed=failure == "wrong_bytes", signer="Bob" if failure == "wrong_signer" else "Alice"
    )
    if failure == "body_differs":
        data = bytes([data[0] ^ 1]) + data[1:]
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_for(f)), base_url="http://test"
    ) as client:
        response = await client.put(
            f"/v1/competition/model-uploads/{f.key}/files/0", content=data, headers=headers
        )
    assert response.status_code == 422
    if failure != "wrong_bytes":
        assert not f.remote.reads
    assert_no_payloads(f)


@pytest.mark.parametrize("failure", ["missing_owner", "missing_chunk", "corrupt_admission"])
async def test_original_remote_retry_storage_failure_is_retryable(released, failure):
    f = released
    data, headers = chunk(f)
    if failure == "missing_chunk":
        f.remote.objects.clear()
    elif failure == "corrupt_admission":
        with f.uploads.intake._connection() as (db, _):
            db.execute("UPDATE cohort_admission_certificates SET body=?", (b"{}",))
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_for(f, remote=failure != "missing_owner")),
        base_url="http://test",
    ) as client:
        responses = [
            await client.post(
                f"/v1/competition/cohorts/{f.case.cohort}/model-uploads",
                content=canonical_json_bytes(f.request),
                headers={"content-type": "application/json"},
            ),
            await client.get(f"/v1/competition/model-uploads/{f.key}"),
            await client.put(
                f"/v1/competition/model-uploads/{f.key}/files/0", content=data, headers=headers
            ),
        ]
    assert [response.status_code for response in responses] == [503, 503, 503]
    assert_no_payloads(f)


@pytest.mark.parametrize("frozen", ["incomplete"], indirect=True)
async def test_unpreserved_original_cannot_inherit_remote_retry(released):
    f = released
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_for(f)), base_url="http://test"
    ) as client:
        response = await client.get(f"/v1/competition/model-uploads/{f.key}")
    assert response.status_code == 503
    assert not f.remote.reads
    assert_no_payloads(f)
