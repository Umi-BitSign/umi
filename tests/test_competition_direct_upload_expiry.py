"""Expiry preserves accepted completion and only releases drain after durable cleanup."""

import asyncio
from contextlib import nullcontext
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_cohort_direct_model_expiry import expire_selected_uploads
from umi.competition_cohort_direct_model_owner import DirectModelUploadOwner, _at
from umi.competition_cohort_direct_model_upload_http import direct_model_upload_routes
from umi.competition_cohort_upload_completion_policy import DirectUploadCompletionClosed
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_direct_model_owner import (
    base_policy as base_policy,
)
from .test_competition_cohort_direct_model_owner import (
    direct as direct,
)
from .test_competition_cohort_direct_model_owner import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_direct_model_owner import (
    policy as policy,
)
from .test_competition_cohort_direct_model_owner import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_direct_model_owner import (
    recovery as recovery,
)
from .test_competition_cohort_direct_model_owner import (
    runtime as runtime,
)
from .test_competition_cohort_direct_model_owner import (
    signed_completion,
)
from .test_competition_upload_completion_policy import policy as selected_policy

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
NOW = 1_800_000_000_000


def activate(direct, selected=None):
    old = direct.owner
    if selected is None:
        selected = selected_policy()
        deadline = selected.admission_deadline.model_copy(
            update={
                "cohort_sha256": old.config.cohort_sha256,
                "close_new_admissions_at_unix_ms": NOW + 1000,
            }
        )
        selected = selected.model_copy(update={"admission_deadline": deadline})
    direct.owner = DirectModelUploadOwner(
        old.config,
        direct.multipart,
        authorize=old.authorize,
        sign=old.sign,
        completion_policy=selected,
        selection_authority=lambda cohort: digest(selected.admission_deadline),
        selection_context=lambda cohort: nullcontext((selected.admission_deadline, frozenset())),
    )
    return selected


async def reserve(direct):
    return await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=NOW)


async def expire(direct, at=None, *, items=None):
    selected = direct.owner.completion_policy
    if at is None:
        at = selected.close_completion_at_unix_ms
    items = items or (SimpleNamespace(upload=digest(direct.request)),)
    return await expire_selected_uploads(direct.owner, items, now_unix_ms=at, at=_at(at))


async def test_boundary_then_restart_reuses_cleanup_receipt_and_exact_retry(direct):
    signed = await reserve(direct)
    selected = activate(direct)
    before = await expire(direct, selected.close_completion_at_unix_ms - 1)
    assert before["upload_expiry_attempted"] == 0 and not direct.multipart.abort_calls
    assert before["upload_expiry_eta_seconds"] == 0.001
    result = await expire(direct)
    assert result["upload_expiry_completed"] == 1 and result["upload_expiry_pending"] == 0
    upload = digest(direct.request)
    assert direct.owner.upload_expired(upload)
    receipt = direct.owner.journal.get_raw("direct-expiry-receipt", upload)
    activate(direct, selected)
    assert (await expire(direct))["upload_expiry_attempted"] == 0
    assert len(direct.multipart.abort_calls) == 1
    assert direct.owner.journal.get_raw("direct-expiry-receipt", upload) == receipt
    assert (
        await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=NOW + 9_000_000)
        == signed
    )
    with pytest.raises(DirectUploadCompletionClosed):
        await direct.owner.complete(
            signed_completion(signed, direct.payload.payload), now_unix_ms=NOW + 9_000_000
        )


@pytest.mark.parametrize("completed", [False, True])
async def test_accepted_completions_keep_recovery_and_original_signed_bytes(direct, completed):
    signed = await reserve(direct)
    completion = signed_completion(signed, direct.payload.payload)
    key = digest(signed.reservation)
    direct.owner.journal.put("direct-completion", key, completion)
    if completed:
        await direct.owner.complete(completion, now_unix_ms=NOW)
    selected = activate(direct)
    result = await expire(direct)
    assert not direct.multipart.abort_calls
    assert result["upload_expiry_accepted_completions"] == (0 if completed else 1)
    assert not direct.owner.upload_expired(digest(direct.request))
    await direct.owner.complete(completion, now_unix_ms=selected.close_completion_at_unix_ms)
    assert direct.owner.journal.get_raw("direct-completion", key) == canonical_json_bytes(
        completion
    )
    assert direct.owner.journal.get("direct-object", key)


@pytest.mark.parametrize("failure", ["before_abort", "after_abort", "before_receipt"])
async def test_interrupted_cleanup_retains_intent_and_resumes(direct, monkeypatch, failure):
    await reserve(direct)
    selected = activate(direct)
    original = direct.multipart.abort

    async def interrupt(*args, **kwargs):
        if failure == "after_abort":
            await original(*args, **kwargs)
        raise OSError("temporary provider outage")

    if failure != "before_receipt":
        monkeypatch.setattr(direct.multipart, "abort", interrupt)
    else:
        put_many = direct.owner.journal.put_many

        def interrupt_receipt(records, **kwargs):
            records = tuple(records)
            if any(kind == "direct-expiry-receipt" for kind, _, _ in records):
                raise OSError("interrupted after remote cleanup")
            return put_many(records, **kwargs)

        monkeypatch.setattr(direct.owner.journal, "put_many", interrupt_receipt)
    result = await expire(direct)
    upload = digest(direct.request)
    assert result["upload_expiry_retrying"] == 1 and result["upload_expiry_pending"] == 1
    assert direct.owner.journal.get("direct-expiry-intent", upload)
    assert not direct.owner.upload_expired(upload)
    activate(direct, selected)
    monkeypatch.setattr(direct.multipart, "abort", original)
    assert (await expire(direct))["upload_expiry_completed"] == 1


async def test_unexpected_object_requires_repair_without_deletion(direct):
    signed = await reserve(direct)
    activate(direct)
    attempt = direct.owner._latest_attempt(digest(direct.request))
    direct.multipart.objects[attempt.object_key] = (direct.multipart.total_bytes, "done")
    result = await expire(direct)
    assert result["upload_expiry_repair_required"] and result["upload_expiry_pending"] == 1
    assert not direct.multipart.abort_calls and not direct.multipart.delete_calls
    assert not direct.owner.upload_expired(digest(direct.request))
    assert direct.owner.status(digest(signed.reservation))


async def test_completion_holding_owner_mutex_finishes_before_expiry(direct, monkeypatch):
    signed = await reserve(direct)
    selected = activate(direct)
    entered, release = asyncio.Event(), asyncio.Event()
    complete = direct.multipart.complete

    async def held(*args, **kwargs):
        entered.set()
        await release.wait()
        return await complete(*args, **kwargs)

    monkeypatch.setattr(direct.multipart, "complete", held)
    task = asyncio.create_task(
        direct.owner.complete(
            signed_completion(signed, direct.payload.payload),
            now_unix_ms=selected.close_completion_at_unix_ms - 1,
        )
    )
    await asyncio.wait_for(entered.wait(), 5)
    expiry = asyncio.create_task(expire(direct))
    release.set()
    await asyncio.wait_for(asyncio.gather(task, expiry), 5)
    assert not direct.multipart.abort_calls
    assert not direct.owner.upload_expired(digest(direct.request))


async def test_http_expiry_is_terminal_and_does_not_hide_metadata_errors(direct, monkeypatch):
    from umi.competition_cohort_direct_model_attempts import DirectModelAttemptRepairRequired

    signed = await reserve(direct)
    activate(direct)
    await expire(direct)
    app = FastAPI()
    app.include_router(direct_model_upload_routes(direct.owner))
    path = f"/v1/competition/cohorts/{direct.owner.config.cohort_sha256}/direct-model-uploads"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        for suffix in (f"/{digest(signed.reservation)}", f"/by-upload/{digest(direct.request)}"):
            response = await client.get(path + suffix)
            assert response.status_code == 410
            assert response.headers["X-UMI-Reason-Code"] == "model_upload_completion_closed"

        def damaged(_):
            raise DirectModelAttemptRepairRequired("repair needed")

        monkeypatch.setattr(direct.owner, "status", damaged)
        response = await client.get(path + f"/{digest(signed.reservation)}")
        assert response.status_code == 503
        assert response.headers["X-UMI-Reason-Code"] == "model_upload_metadata_repair_required"


async def test_receipt_cannot_resolve_another_intent(direct):
    await reserve(direct)
    activate(direct)
    await expire(direct)
    upload = digest(direct.request)
    with direct.owner.journal.transaction() as db:
        raw = direct.owner.journal.get("direct-expiry-receipt", upload, db=db)
        raw["intent_sha256"] = "99" * 32
        db.execute(
            "UPDATE records SET body=? WHERE kind='direct-expiry-receipt' AND id=?",
            (canonical_json_bytes(raw), upload),
        )
    with pytest.raises(ValueError, match="receipt differs"):
        direct.owner.upload_expired(upload)


async def test_public_poll_expires_selected_upload_and_reports_completion_deadline(direct):
    await reserve(direct)
    selected = activate(direct)
    updates = []
    report = await direct.owner.poll_once(
        now_unix_ms=selected.close_completion_at_unix_ms, report=updates.append
    )
    assert report["upload_expiry_completed"] == 1
    assert report["objects_total"] == 0
    assert report["upload_completion_deadline_unix_ms"] == selected.close_completion_at_unix_ms
    assert any(value.get("active_object_stage") == "upload_expiry" for value in updates)
    assert report["upload_expiry_eta_seconds"] == 0


async def test_expiry_rotation_survives_failed_first_upload_and_restart(direct, monkeypatch):
    from .test_competition_direct_upload_completion_recovery import retain_completion

    # These requests are issued but no completion is sent by the client.
    uploads = []
    for offset in (0, 1, 2):
        key, signed, _ = await retain_completion(direct, offset)
        uploads.append(signed.reservation.payload.upload_sha256)
        with direct.owner.journal.transaction() as db:
            db.execute("DELETE FROM records WHERE kind='direct-completion' AND id=?", (key,))
    selected = activate(direct)
    direct.owner.config = direct.owner.config.model_copy(update={"cleanup_batch_size": 1})
    uploads.sort()
    first = direct.owner._latest_attempt(uploads[0])
    original = direct.multipart.abort

    async def fail_one(key, **kwargs):
        if key == first.object_key:
            raise OSError("temporary provider failure")
        return await original(key, **kwargs)

    monkeypatch.setattr(direct.multipart, "abort", fail_one)
    items = tuple(SimpleNamespace(upload=upload) for upload in uploads)
    assert (await expire(direct, items=items))["upload_expiry_retrying"] == 1
    activate(direct, selected)
    assert (await expire(direct, items=items))["upload_expiry_completed"] == 1
    assert direct.owner.upload_expired(uploads[1])
    assert (await expire(direct, items=items))["upload_expiry_completed"] == 2
    assert direct.owner.upload_expired(uploads[2])


async def test_provider_object_appearing_after_abort_is_preserved_for_repair(direct, monkeypatch):
    await reserve(direct)
    activate(direct)
    original = direct.multipart.abort

    async def raced(key, **kwargs):
        await original(key, **kwargs)
        direct.multipart.objects[key] = (direct.multipart.total_bytes, "unexpected")

    monkeypatch.setattr(direct.multipart, "abort", raced)
    result = await expire(direct)
    assert result["upload_expiry_repair_required"]
    assert not direct.owner.upload_expired(digest(direct.request))
    assert len(direct.multipart.objects) == 1 and not direct.multipart.delete_calls


async def test_policy_authority_change_stops_cleanup(direct):
    await reserve(direct)
    activate(direct)
    direct.owner.selection_authority = lambda _: "00" * 32
    with pytest.raises(ValueError, match="authority changed"):
        await expire(direct)
    assert not direct.multipart.abort_calls


async def test_absent_provider_identity_requires_repair(direct):
    signed = await reserve(direct)
    activate(direct)
    with direct.owner.journal.transaction() as db:
        db.execute(
            "DELETE FROM records WHERE kind='direct-provider' AND id=?",
            (signed.reservation.attempt_id,),
        )
    report = await expire(direct)
    assert report["upload_expiry_repair_required"]
    assert not direct.multipart.abort_calls


async def test_lost_accepted_completion_becomes_terminal_without_losing_signed_request(
    direct, monkeypatch
):
    signed = await reserve(direct)
    key = digest(signed.reservation)
    completion = signed_completion(signed, direct.payload.payload)
    direct.owner.journal.put("direct-completion", key, completion)
    original = direct.owner.journal.get_raw("direct-completion", key)
    selected = activate(direct)
    direct.multipart.multipart_uploads.clear()

    async def gone(*args, **kwargs):
        raise OSError("provider upload no longer exists")

    monkeypatch.setattr(direct.multipart, "complete", gone)
    report = await direct.owner.poll_once(now_unix_ms=selected.close_completion_at_unix_ms)
    assert report["upload_expiry_completed"] == 1
    assert direct.owner.upload_expired(digest(direct.request))
    assert direct.owner.journal.get_raw("direct-completion", key) == original
    assert direct.owner.journal.pending_completion_keys() == []
    activate(direct, selected)
    assert direct.owner.upload_expired(digest(direct.request))
    repeated = await direct.owner.poll_once(now_unix_ms=selected.close_completion_at_unix_ms + 1)
    assert repeated["completion_recovery_total"] == 0
    assert repeated["upload_expiry_pending"] == 0
    with direct.owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='direct-completion-expired' AND id=?", (key,))
    with pytest.raises(ValueError, match="recovery marker"):
        direct.owner.upload_expired(digest(direct.request))


async def test_incomplete_provider_abort_cannot_resolve_drain(direct, monkeypatch):
    await reserve(direct)
    activate(direct)

    async def accepted_but_not_finished(*args, **kwargs):
        return None

    monkeypatch.setattr(direct.multipart, "abort", accepted_but_not_finished)
    result = await expire(direct)
    assert result["upload_expiry_retrying"] == 1
    assert not direct.owner.upload_expired(digest(direct.request))


async def test_lost_completion_requires_both_provider_absence_checks(direct, monkeypatch):
    signed = await reserve(direct)
    direct.owner.journal.put(
        "direct-completion",
        digest(signed.reservation),
        signed_completion(signed, direct.payload.payload),
    )
    activate(direct)

    async def unavailable(*args, **kwargs):
        raise OSError("provider unavailable")

    monkeypatch.setattr(direct.multipart, "multipart_exists", unavailable)
    result = await expire(direct)
    assert result["upload_expiry_retrying"] == 1
    assert not direct.owner.upload_expired(digest(direct.request))
    assert not direct.multipart.abort_calls
