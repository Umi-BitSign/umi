"""Native retained upload HTTP retries after synthetic accounting release.

R2 and finality are fixtures. Native owner history/admission, original journal,
allocation fencing and signatures are real. This does not qualify deletion or
issue consumer-release authority; no production payload is accessed.
"""

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_model_client import _status
from umi.competition_cohort_model_upload import CohortModelUploads, ModelUploadConfig
from umi.competition_cohort_model_upload_http import model_upload_routes
from umi.open_competition import digest
from umi.private_files import ensure_private_directory
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


@pytest.mark.parametrize("frozen", ["unadmitted", "incomplete"], indirect=True)
async def test_unadmitted_original_cannot_inherit_remote_retry(released):
    f = released
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app_for(f)), base_url="http://test"
    ) as client:
        response = await client.get(f"/v1/competition/model-uploads/{f.key}")
    assert response.status_code == 503
    assert not f.remote.reads
    assert_no_payloads(f)
