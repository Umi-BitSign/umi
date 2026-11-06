"""Standing owner recovery must finish accepted requests without another client."""

import asyncio

import pytest

from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwners,
)
from umi.open_competition import digest, sign_object

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
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
NOW = 1_800_000_000_000


def reopen(direct):
    return DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )


async def retain_completion(direct, offset=0):
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
    signed_payload = direct.payload.model_copy(
        update={"payload": payload, "signature": sign_object(payload, wallet("Alice"))}
    )
    reservation = await direct.owner.reserve(request, signed_payload, now_unix_ms=NOW)
    completion = signed_completion(reservation, payload)
    key = digest(reservation.reservation)
    direct.owner.journal.put("direct-completion", key, completion)
    return key, reservation, completion


@pytest.mark.parametrize("provider_completed", [False, True])
async def test_restarted_owner_finishes_and_verifies_retained_completion(
    direct, provider_completed
):
    key, reservation, _ = await retain_completion(direct)
    original = direct.owner.journal.get_raw("direct-completion", key)
    if provider_completed:
        attempt = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)
        direct.multipart.objects[attempt["object_key"]] = (direct.multipart.total_bytes, "done")
    owner = reopen(direct)
    updates = []
    report = await owner.poll_once(now_unix_ms=NOW + 1000, report=updates.append)
    assert report["completion_recovery_completed"] == 1
    assert report["completion_recovery_pending"] == 0
    assert report["objects_verified"] == report["objects_total"] == 1
    assert owner.status(key).payload_verified
    assert len(direct.multipart.complete_calls) == (0 if provider_completed else 1)
    assert owner.journal.get_raw("direct-completion", key) == original
    assert updates[0]["active_object_stage"] == "completion_recovery"
    assert updates[0]["completion_recovery_total"] == 1
    assert report["completion_recovery_eta_seconds"] == 0
    reads, completions = direct.multipart.read_calls, len(direct.multipart.complete_calls)
    repeated = await reopen(direct).poll_once(now_unix_ms=NOW + 2000)
    assert repeated["completion_recovery_total"] == 0
    assert direct.multipart.read_calls == reads
    assert len(direct.multipart.complete_calls) == completions


async def test_unsigned_unfinished_reservation_is_never_completed_by_poll(direct):
    reservation = await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=NOW)
    report = await reopen(direct).poll_once(now_unix_ms=NOW + 1000)
    assert report["completion_recovery_total"] == report["objects_total"] == 0
    assert not direct.owner.status(digest(reservation.reservation)).object_complete
    assert direct.multipart.complete_calls == []


async def test_provider_retry_does_not_become_a_terminal_upload_failure(direct, monkeypatch):
    key, _, _ = await retain_completion(direct)
    complete = direct.multipart.complete

    async def unavailable(*args, **kwargs):
        raise OSError("temporary provider failure")

    monkeypatch.setattr(direct.multipart, "complete", unavailable)
    owner = reopen(direct)
    cohort = owner.config.cohort_sha256
    manager = DirectModelUploadOwners({cohort: owner}, priority_cohorts=(cohort,))
    result = await manager.poll_once(now_unix_ms=NOW + 1000)
    report = result["cohorts"][cohort]
    assert result["stalled_or_retrying"]
    assert report["completion_recovery_retrying"] == report["completion_recovery_pending"] == 1
    assert report["completion_recovery_error_type"] == "OSError"
    assert report["completion_recovery_eta_seconds"] is None
    assert report["objects_terminal"] == 0
    assert owner.status(key).hold_reason_code is None
    monkeypatch.setattr(direct.multipart, "complete", complete)
    recovered = await reopen(direct).poll_once(now_unix_ms=NOW + 2000)
    assert recovered["completion_recovery_completed"] == recovered["objects_verified"] == 1


async def test_interrupted_recovery_yields_to_next_completion_after_restart(direct, monkeypatch):
    pending = [await retain_completion(direct, offset) for offset in range(3)]
    keys = sorted(item[0] for item in pending)
    calls = []

    async def interrupted(signed, **kwargs):
        calls.append(signed.completion.reservation_sha256)
        raise asyncio.CancelledError

    owner = reopen(direct)
    monkeypatch.setattr(owner, "complete", interrupted)
    with pytest.raises(asyncio.CancelledError):
        await owner.poll_once(now_unix_ms=NOW + 1000)
    assert calls == keys[:1]
    resumed = reopen(direct)
    complete = resumed.complete

    async def observed(signed, **kwargs):
        calls.append(signed.completion.reservation_sha256)
        return await complete(signed, **kwargs)

    monkeypatch.setattr(resumed, "complete", observed)
    report = await resumed.poll_once(now_unix_ms=NOW + 2000)
    assert calls == keys
    assert report["completion_recovery_attempted"] == 2
    assert report["completion_recovery_pending"] == 1
    last = await reopen(direct).poll_once(now_unix_ms=NOW + 3000)
    assert last["completion_recovery_completed"] == 1
    assert last["completion_recovery_pending"] == 0


async def test_wrong_completed_object_requires_repair_and_preserves_signed_request(direct):
    key, reservation, _ = await retain_completion(direct)
    raw = direct.owner.journal.get_raw("direct-completion", key)
    attempt = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)
    direct.multipart.objects[attempt["object_key"]] = (direct.multipart.total_bytes + 1, "wrong")
    report = await reopen(direct).poll_once(now_unix_ms=NOW + 1000)
    assert report["completion_recovery_repair_required"]
    assert report["completion_recovery_pending"] == 1
    assert report["objects_terminal"] == report["objects_total"] == 0
    assert direct.owner.journal.get_raw("direct-completion", key) == raw
    assert direct.multipart.delete_calls == direct.multipart.abort_calls == []
