"""Native /2 continuation, real R2 promotion and synthetic legacy release.

Finality/R2 are isolated ports. The synthetic accounting transition grants no
production deletion authority and does not qualify the still-missing release owner.
"""

import asyncio
import hashlib
import json
import shutil
from contextlib import suppress
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from umi.competition_cohort_admission_journal import CohortAdmissionVote
from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_cohort_model_client import submit_cohort_model
from umi.competition_cohort_model_upload_delivery import ModelUploadDelivery
from umi.competition_cohort_service_host import ServiceAdmissionHost
from umi.open_competition import sign_object
from umi.private_files import ensure_private_directory, read_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_acceptance import certify
from .test_competition_cohort_model_upload import signed_chunk
from .test_competition_cohort_model_upload_continuation import base_policy as base_policy
from .test_competition_cohort_model_upload_continuation import continuation as continuation
from .test_competition_cohort_model_upload_continuation import delivery as delivery
from .test_competition_cohort_model_upload_continuation import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_upload_continuation import policy as policy
from .test_competition_cohort_model_upload_continuation import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_upload_continuation import recovery as recovery
from .test_competition_cohort_model_upload_continuation import runtime as runtime
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


def delivery_for(f):
    return ModelUploadDelivery(
        f.h.owner, remote_payloads=f.state.remote, continued_payloads=f.state.continued
    )


@pytest.fixture
async def promoted(continuation, request):
    f, h = continuation, continuation.h
    state = f.start()

    async def upload(wire):
        raw = await wire.aread()
        f.multipart.parts[int(wire.url.params["partNumber"])] = raw
        return httpx.Response(
            200, headers={"ETag": hashlib.md5(raw, usedforsecurity=False).hexdigest()}
        )

    async def worker():
        while True:
            await state.direct.poll_once(now_unix_ms=1_800_000_000_000)
            await asyncio.sleep(0.005)

    task = asyncio.create_task(worker())
    try:
        receipt = await asyncio.wait_for(
            submit_cohort_model(
                origin="https://intake.example",
                policy=h.intake.policy,
                request=h.request,
                source=h.source,
                wallet=wallet("Alice"),
                transport=httpx.ASGITransport(state.app),
                object_transport=httpx.MockTransport(upload),
                retry_seconds=0.001,
            ),
            20,
        )
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
    queue = CohortAdmissionQueue(h.intake)
    for name in ("Charlie", "Dave"):
        queue.publish_vote(
            CohortAdmissionVote(
                admission=receipt.proposed_admission,
                signature=sign_object(receipt.proposed_admission, wallet(name)),
            ),
            capture_at(213),
        )
    sub = h.request.signed_submission.submission
    inputs = read_private_model(
        Path(state.direct.config.admission_reviews_directory) / (sub.model_revision + ".json"),
        ModelArtifactReviewInputs,
        maximum_bytes=33 * 1024**2,
    )
    publication = certify(state.acceptances, h.cohort, sub, inputs, block=214)
    promotion = await state.direct.promote(publication, now_unix_ms=1_800_000_000_100)
    state.acceptances.publish(publication, capture_at(215))
    # Only the fixture performs this accounting transition and removes its own
    # local bytes. The reader under test has no such authority.
    with h.owner.journal.locked():
        for phase in ("remote_qualified", "release_prepared"):
            h.owner.allocations._transition(sub.model_revision, phase, evidence={"fixture": phase})
        for path in (
            h.owner.root / "files" / sub.model_revision,
            h.owner.archive / sub.model_revision,
        ):
            ensure_private_directory(path)
            if (path / "model").exists():
                shutil.rmtree(path / "model")
            for partial in path.glob("partial-*"):
                partial.unlink()
        if getattr(request, "param", "released") == "released":
            h.owner.allocations._complete_release(sub.model_revision)
    f.state, f.publication, f.promotion, f.receipt = state, publication, promotion, receipt
    f.object_key = next(iter(f.multipart.objects))
    f.before = (
        h.owner.allocations.snapshot(),
        h.owner.journal.get_raw("upload", f.key),
        canonical_json_bytes(f.legacy),
        canonical_json_bytes(f.preservation),
        canonical_json_bytes(h.intake.history(h.cohort).plan),
        list(f.multipart.copies),
        list(f.multipart.deletes),
    )
    f.multipart.reads.clear()
    return f


def assert_unchanged(f):
    h = f.h
    assert (
        h.owner.allocations.snapshot(),
        h.owner.journal.get_raw("upload", f.key),
        canonical_json_bytes(f.legacy),
        canonical_json_bytes(f.preservation),
        canonical_json_bytes(h.intake.history(h.cohort).plan),
        f.multipart.copies,
        f.multipart.deletes,
    ) == f.before
    model = h.request.signed_submission.submission.model_revision
    assert not (h.owner.root / "files" / model / "model").exists()
    assert not list((h.owner.root / "files" / model).glob("partial-*"))
    assert not (h.owner.archive / model / "model").exists()
    assert h.owner.journal.keys("bundle") == [model]


@pytest.mark.parametrize("continuation", ["incomplete", "preserved", "uncertified"], indirect=True)
@pytest.mark.parametrize("promoted", ["release_prepared", "released"], indirect=True)
async def test_old_routes_poll_and_upgraded_client_repeat_after_continuation_release(promoted):
    f, h = promoted, promoted.h
    for attempt in range(2):
        if attempt:
            f.state = f.start()
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(f.state.app), base_url="https://intake.example"
        ) as client:
            response = await client.get(f"/v1/competition/model-uploads/{f.key}")
            assert response.status_code == 200, response.text
            status = response.json()
            assert status["payload_preserved"] and not status["participation_admitted"]
            assert not status["artifact_review_certified"]
            reserved = await client.post(
                f"/v1/competition/cohorts/{h.cohort}/model-uploads",
                content=canonical_json_bytes(h.request),
                headers={"content-type": "application/json"},
            )
            assert reserved.status_code == 200 and reserved.json() == status
            assert not f.multipart.reads
            files = h.request.signed_submission.submission.model_bundle.files
            index = len(files) - 1
            raw = (h.source / files[index].path).read_bytes()
            offset, raw = 1 if len(raw) > 1 else 0, raw[1:] if len(raw) > 1 else raw
            signed, signature = signed_chunk(f.key, index, raw, offset=offset)
            response = await client.put(
                f"/v1/competition/model-uploads/{f.key}/files/{index}?offset={offset}",
                content=raw,
                headers={
                    "content-type": "application/octet-stream",
                    "x-umi-chunk-sha256": signed.sha256,
                    "x-umi-signature": canonical_json_bytes(signature).decode(),
                },
            )
            assert response.status_code == 200 and response.json() == status
            assert f.multipart.reads == [
                (f.object_key, sum(file.size_bytes for file in files[:index]) + offset, len(raw))
            ]
        f.multipart.reads.clear()

        async def no_upload(wire):
            raise AssertionError("completed continuation must not upload bytes again")

        receipt = await asyncio.wait_for(
            submit_cohort_model(
                origin="https://intake.example",
                policy=h.intake.policy,
                request=h.request,
                source=h.source,
                wallet=wallet("Alice"),
                transport=httpx.ASGITransport(f.state.app),
                object_transport=httpx.MockTransport(no_upload),
                retry_seconds=0.001,
            ),
            20,
        )
        assert receipt == f.receipt
        host = SimpleNamespace(
            uploads=h.owner, legacy_payloads=f.state.remote, continued_payloads=f.state.continued
        )
        poll = await ServiceAdmissionHost._poll_legacy_uploads(host)
        assert poll["models_preserved"] == 1 and poll["models_pending"] == 0
        assert poll["model_reviews_ready"] == 1 and not poll["last_error_type"]
        assert not f.multipart.reads
        assert_unchanged(f)


@pytest.mark.parametrize(
    "fault",
    [
        "missing_publication",
        "bad_acceptance_quorum",
        "missing_admission",
        "bad_admission_quorum",
        "missing_promotion",
        "changed_promotion",
        "missing_byte_result",
        "damaged_byte_result",
        "missing_byte_receipt",
        "changed_generation",
        "missing_object",
        "missing_direct_owner",
        "wrong_owner",
        "pending_authority",
    ],
)
async def test_continued_retry_refuses_missing_or_changed_owned_facts_without_payload_reads(
    promoted, fault, caplog
):
    f, h = promoted, promoted.h
    adapter = delivery_for(f)
    await adapter.status(f.key)
    direct = f.state.direct
    if fault in {"missing_publication", "bad_acceptance_quorum"}:
        with h.intake._connection() as (db, _):
            if fault == "missing_publication":
                db.execute("DELETE FROM cohort_model_acceptances")
            else:
                body = json.loads(canonical_json_bytes(f.publication))
                body["certificate"]["signatures"] = body["certificate"]["signatures"][:1]
                db.execute(
                    "UPDATE cohort_model_acceptances SET body=?", (canonical_json_bytes(body),)
                )
    elif fault in {"missing_admission", "bad_admission_quorum"}:
        with h.intake._connection() as (db, _):
            if fault == "missing_admission":
                db.execute("DELETE FROM cohort_admission_certificates")
            else:
                raw = db.execute("SELECT body FROM cohort_admission_certificates").fetchone()[0]
                body = json.loads(raw)
                body["signatures"] = body["signatures"][:1]
                db.execute(
                    "UPDATE cohort_admission_certificates SET body=?", (canonical_json_bytes(body),)
                )
    elif fault in {"missing_promotion", "changed_promotion"}:
        with direct.journal.transaction() as db:
            if fault == "missing_promotion":
                db.execute("DELETE FROM records WHERE kind='direct-promotion'")
            else:
                body = json.loads(canonical_json_bytes(f.promotion))
                body["reservation_sha256"] = "ab" * 32
                db.execute(
                    "UPDATE records SET body=? WHERE kind='direct-promotion'",
                    (canonical_json_bytes(body),),
                )
    elif fault in {"missing_byte_result", "damaged_byte_result", "missing_byte_receipt"}:
        root = (
            Path(direct.config.directory)
            / "byte-verification"
            / hashlib.sha256(f.object_key.encode()).hexdigest()
        )
        if fault == "missing_byte_receipt":
            path = root / (hashlib.sha256(canonical_json_bytes("object")).hexdigest() + ".json")
            path.unlink()
        else:
            path = root / "result.json"
            if fault == "missing_byte_result":
                path.unlink()
            else:
                path.write_bytes(b"{}")
    elif fault == "changed_generation":
        raw = f.multipart.objects[f.object_key]
        f.multipart.objects[f.object_key] = bytes([raw[0] ^ 1]) + raw[1:]
    elif fault == "missing_object":
        f.multipart.objects.pop(f.object_key)
    elif fault == "missing_direct_owner":
        f.state.continued.direct.owners.clear()
    elif fault == "wrong_owner":
        direct.config = direct.config.model_copy(
            update={"owner_hotkey": wallet("Dave").hotkey.ss58_address}
        )
    else:
        with h.intake._connection() as (_, store):
            store.reserve(
                h.cohort,
                phase="intake",
                operation="revoke",
                observed_at_block=216,
                evidence_sha256="fa" * 32,
            )
    with caplog.at_level("INFO"), pytest.raises(OSError):
        await adapter.status(f.key)
    assert f.key not in f.state.continued.verified
    assert not f.multipart.reads
    assert_unchanged(f)
    if "byte_" in fault:
        events = [json.loads(row.message) for row in caplog.records if row.message.startswith("{")]
        assert any(row["status"] == "repair_required" for row in events)
        assert all("eta_basis" in row and "elapsed_seconds" in row for row in events)


@pytest.mark.parametrize("boundary", ["head", "range"])
@pytest.mark.parametrize("failure", ["cancel", "authority_change", "generation_change"])
async def test_remote_await_failure_revokes_continued_capability(
    promoted, monkeypatch, boundary, failure
):
    f, h = promoted, promoted.h
    bridge = f.state.continued
    await bridge.ensure_owned(h.request)
    original = getattr(f.multipart, "head" if boundary == "head" else "read_range")
    touched = False

    async def interrupt(*args, **kwargs):
        nonlocal touched
        result = await original(*args, **kwargs)
        if not touched:
            touched = True
            if failure == "cancel":
                raise asyncio.CancelledError()
            if failure == "authority_change":
                with h.intake._connection() as (_, store):
                    store.reserve(
                        h.cohort,
                        phase="intake",
                        operation="revoke",
                        observed_at_block=216,
                        evidence_sha256="fa" * 32,
                    )
            else:
                raw = f.multipart.objects[f.object_key]
                f.multipart.objects[f.object_key] = bytes([raw[0] ^ 1]) + raw[1:]
        return result

    monkeypatch.setattr(f.multipart, "head" if boundary == "head" else "read_range", interrupt)
    file = h.request.signed_submission.submission.model_bundle.files[0]
    data = (h.source / file.path).read_bytes()[:1]
    with pytest.raises(asyncio.CancelledError if failure == "cancel" else (OSError, ValueError)):
        await bridge.compare_retry(h.request, file_index=0, offset=0, data=data)
    assert f.key not in bridge.verified
    assert_unchanged(f)


async def test_changed_signed_retry_never_replaces_preserved_continuation(promoted):
    f, h = promoted, promoted.h
    file = h.request.signed_submission.submission.model_bundle.files[0]
    raw = (h.source / file.path).read_bytes()[:1]
    changed = bytes([raw[0] ^ 1])
    chunk, signature = signed_chunk(f.key, 0, changed)
    with pytest.raises(ValueError, match="retry differs"):
        await delivery_for(f).put_chunk(chunk, signature, changed)
    assert f.key not in f.state.continued.verified
    assert f.multipart.reads == [(f.object_key, 0, 1)]
    assert_unchanged(f)


async def test_poll_authority_change_does_not_count_pending_model_as_preserved(
    promoted, monkeypatch
):
    f, h = promoted, promoted.h
    adapter = delivery_for(f)
    original = adapter._remote_review

    def changed(request):
        with h.intake._connection() as (_, store):
            store.reserve(
                h.cohort,
                phase="intake",
                operation="revoke",
                observed_at_block=216,
                evidence_sha256="fa" * 32,
            )
        return original(request)

    monkeypatch.setattr(adapter, "_remote_review", changed)
    poll = await adapter.poll_once()
    assert poll["models_preserved"] == 0 and poll["models_pending"] == 1
    assert poll["model_reviews_ready"] == 0 and poll["last_error_type"]
    assert f.key not in f.state.continued.verified
    assert not f.multipart.reads
    assert_unchanged(f)


async def test_missing_byte_completion_marker_repairs_without_reading_model(promoted, caplog):
    f = promoted
    root = (
        Path(f.state.direct.config.directory)
        / "byte-verification"
        / hashlib.sha256(f.object_key.encode()).hexdigest()
    )
    marker = root / (hashlib.sha256(canonical_json_bytes("object")).hexdigest() + ".complete")
    original = marker.read_bytes()
    marker.unlink()
    with caplog.at_level("INFO"):
        assert (await delivery_for(f).status(f.key))["payload_preserved"]
    assert marker.read_bytes() == original
    assert not f.multipart.reads
    events = [json.loads(row.message) for row in caplog.records if row.message.startswith("{")]
    assert any(row["status"] == "repair_required" for row in events)
    assert any(
        row["reason_code"] == "byte_completion_marker_restored_from_receipt" for row in events
    )
    completed = [row for row in events if row["stage"] == "continued_model_remote_reconciliation"]
    assert completed[-1]["status"] == "completed" and completed[-1]["percent"] == 100
    assert completed[-1]["restored_units"] == 1 and completed[-1]["native_units"] == 0
    assert completed[-1]["eta_seconds"] == 0 and completed[-1]["eta_basis"] == "completed_scope"
    assert_unchanged(f)
