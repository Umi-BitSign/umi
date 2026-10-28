"""Replacement selection must precede expensive work and preserve exact evidence."""

from contextlib import contextmanager
from pathlib import Path

import httpx
import pytest

from umi.competition_client import CompetitionSubmissionError
from umi.competition_cohort_admission_deadline import OperatorAdmissionDeadline
from umi.competition_cohort_direct_model_owner import DirectModelUploadOwner
from umi.open_competition import digest, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_direct_model_owner import (
    base_policy as base_policy,
)
from .test_competition_cohort_direct_model_owner import (
    complete_poll_uploads,
    signed_completion,
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
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
NOW = 1_800_000_000_000


async def upload(direct, sequence, *, at=NOW, complete=True):
    sub = direct.request.signed_submission.submission.model_copy(update={"sequence": sequence})
    signed = direct.request.signed_submission.model_copy(
        update={"submission": sub, "signature": sign_object(sub, wallet("Alice"))}
    )
    consent = direct.request.consent.consent.model_copy(update={"submission_sha256": digest(sub)})
    request = direct.request.model_copy(
        update={
            "signed_submission": signed,
            "consent": direct.request.consent.model_copy(
                update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))}
            ),
        }
    )
    payload = direct.payload.payload.model_copy(update={"upload_sha256": digest(request)})
    signed_payload = direct.payload.model_copy(
        update={"payload": payload, "signature": sign_object(payload, wallet("Alice"))}
    )
    reservation = await direct.owner.reserve(request, signed_payload, now_unix_ms=at)
    key = digest(reservation.reservation)
    if complete:
        await direct.owner.complete(signed_completion(reservation, payload), now_unix_ms=at + 1)
    return request, key


def reopened(direct):
    return DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
        selection_context=direct.owner.selection_context,
        selection_authority=direct.owner.selection_authority,
    )


async def test_latest_issued_sequence_skips_old_source_without_deleting_evidence(direct):
    old_request, old = await upload(direct, 1)
    new_request, new = await upload(direct, 2)
    before = direct.owner.journal.get_raw("direct-request", digest(old_request))
    report = await direct.owner.poll_once(now_unix_ms=NOW + 2)
    assert report["objects_selected"] == report["objects_superseded"] == 1
    assert report["objects_ready"] == report["objects_terminal"] == 1
    assert report["objects_attempted"] == 1 and report["objects_failed"] == 0
    assert report["selected_source_bytes_total"] == direct.payload.payload.total_bytes
    assert report["selected_source_bytes_remaining"] == 0
    assert report["selected_objects_pending_verification"] == 0
    assert direct.owner.journal.get("direct-verification", old) is None
    assert direct.owner.journal.get("direct-verification", new) is not None
    status = direct.owner.status(old)
    assert status.object_complete and not status.payload_verified
    assert status.hold_reason_code == "direct_model_submission_superseded"
    assert direct.owner.journal.get_raw("direct-request", digest(old_request)) == before
    assert direct.owner.journal.get("direct-verification-hold", old) is None
    assert direct.multipart.delete_calls == []
    # The exact current request still passes the native admission gate.
    direct.owner.require_payload(new_request)
    reads = direct.multipart.read_calls
    restarted = reopened(direct)
    repeated = await restarted.poll_once(now_unix_ms=NOW + 3)
    assert repeated["objects_superseded"] == 1 and repeated["objects_attempted"] == 0
    assert direct.multipart.read_calls == reads
    assert restarted.status(old).hold_reason_code == status.hold_reason_code


async def test_completed_old_verification_still_supports_signed_historical_consumer(direct):
    request, old = await upload(direct, 1)
    await direct.owner.verify(old, now_unix_ms=NOW + 2)
    evidence = canonical_json_bytes(direct.owner.journal.get("direct-verification", old))
    await upload(direct, 2)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    assert canonical_json_bytes(direct.owner.journal.get("direct-verification", old)) == evidence
    direct.owner.require_payload(request)
    assert digest(direct.owner.review_artifact(request).reservation) == old
    assert direct.owner.status(old).payload_verified


async def test_newer_issued_incomplete_upload_supersedes_old_but_does_not_fake_completion(direct):
    _, old = await upload(direct, 1)
    _, new = await upload(direct, 2, complete=False)
    report = await direct.owner.poll_once(now_unix_ms=NOW + 3)
    assert report["objects_superseded"] == 1 and report["objects_selected"] == 0
    assert report["objects_ready"] == report["objects_attempted"] == 0
    assert direct.multipart.read_calls == 0
    assert not direct.owner.status(new).object_complete
    assert not direct.owner.status(old).payload_verified


async def test_same_sequence_ties_are_not_arbitrarily_superseded(direct):
    await complete_poll_uploads(direct)
    result = await direct.owner.poll_once(now_unix_ms=NOW + 12_000)
    assert result["objects_selected"] == 3 and result["objects_superseded"] == 0
    assert result["objects_attempted"] == 2 and result["objects_pending"] == 1
    assert result["selected_objects_pending_verification"] == 1


@pytest.mark.parametrize("timely_authorization", [False, True])
async def test_post_cutoff_issuance_only_supersedes_with_timely_authorization(
    direct, timely_authorization
):
    _, old = await upload(direct, 1)
    newer, new = await upload(direct, 2, at=NOW + 2)
    deadline = OperatorAdmissionDeadline(
        schema="umi-cohort-operator-admission-deadline/1",
        authority_sha256="a1" * 32,
        authorized_history_tip_sha256="b2" * 32,
        source_sha256="c3" * 32,
        operator_plan_sha256="d4" * 32,
        reason="Retained operator test deadline",
        cohort_sha256=direct.owner.config.cohort_sha256,
        close_new_admissions_at_unix_ms=NOW + 1,
        legacy_reservations_before_unix_ms=None,
    )

    @contextmanager
    def context(cohort):
        assert cohort == deadline.cohort_sha256
        yield deadline, {digest(newer)} if timely_authorization else set()

    direct.owner.selection_context = context
    report = await direct.owner.poll_once(now_unix_ms=NOW + 4)
    assert report["objects_selected"] == 1
    assert report["objects_superseded"] == int(timely_authorization)
    assert report["objects_ineligible"] == int(not timely_authorization)
    checked, skipped = (new, old) if timely_authorization else (old, new)
    assert direct.owner.journal.get("direct-verification", checked) is not None
    assert direct.owner.journal.get("direct-verification", skipped) is None


async def test_replacement_during_payload_stops_next_obsolete_hash_and_refreshes_once(
    direct, monkeypatch
):
    keys = await complete_poll_uploads(direct)
    direct.owner.new_attempt_id = lambda: "d4" * 32
    original = direct.owner.verify
    calls, replacement = [], []

    async def replace_during_verify(key, **kwargs):
        calls.append(key)
        result = await original(key, **kwargs)
        if not replacement:
            replacement.append(await upload(direct, 2, at=NOW + 12_000))
        return result

    monkeypatch.setattr(direct.owner, "verify", replace_during_verify)
    report = await direct.owner.poll_once(now_unix_ms=NOW + 11_000)
    assert calls == [keys[0]], "do not start the next old hash after new authenticated issuance"
    assert report["selection_refresh_required"] is True
    assert report["objects_ready"] == 1 and report["objects_pending"] == 2
    next_report = await direct.owner.poll_once(now_unix_ms=NOW + 13_000)
    assert calls == [keys[0], replacement[0][1]]
    assert next_report["objects_superseded"] == 3
    assert next_report["objects_selected"] == next_report["objects_ready"] == 1
    assert next_report["selection_refresh_required"] is False


async def test_conflicted_selection_fails_before_any_payload_or_cached_terminal_hint(
    direct,
):
    older, _ = await upload(direct, 1)
    await upload(direct, 2)
    # Native fixture conflict, never an edit to production state.
    with direct.owner.journal.transaction() as db:
        db.execute("INSERT INTO holds VALUES (?)", (digest(older),))
    with pytest.raises(ValueError, match="conflict held"):
        await direct.owner.poll_once(now_unix_ms=NOW + 3)
    assert direct.multipart.read_calls == 0
    assert direct.owner._selection_holds == {}


async def test_deadline_change_fences_next_hash_and_stale_status_without_roster_scan(
    direct, monkeypatch
):
    keys = await complete_poll_uploads(direct)
    authority = [None]
    direct.owner.selection_authority = lambda _: authority[0]
    verify = direct.owner.verify
    calls = []

    async def changed(key, **kwargs):
        calls.append(key)
        result = await verify(key, **kwargs)
        authority[0] = "e5" * 32
        return result

    monkeypatch.setattr(direct.owner, "verify", changed)
    report = await direct.owner.poll_once(now_unix_ms=NOW + 12_000)
    assert calls == keys[:1]
    assert report["selection_refresh_required"]
    # A former projection must not turn a changed-authority hint into a
    # terminal client response. Native signed verification remains exact.
    direct.owner._selection_holds[digest(direct.request)] = "direct_model_submission_superseded"
    assert direct.owner.status(keys[0]).hold_reason_code is None


async def test_superseded_rejection_keeps_existing_bounded_cleanup_authority(direct):
    _, old = await upload(direct, 1)
    direct.owner.journal.put(
        "direct-verification-hold", old, {"reason_code": "direct_model_verification_failed"}
    )
    await upload(direct, 2)
    initial = await direct.owner.poll_once(now_unix_ms=NOW + 3)
    assert initial["objects_superseded"] == 1
    assert initial["objects_retained_for_cleanup"] == 1
    assert direct.multipart.delete_calls == []
    intent = direct.owner.journal.get("direct-rejected-cleanup-intent", old)
    assert intent is not None
    later = await direct.owner.poll_once(now_unix_ms=intent["retain_until_unix_ms"])
    assert later["objects_cleaned"] == 1
    assert len(direct.multipart.delete_calls) == 1
    assert direct.owner.journal.get("direct-rejected-cleanup-receipt", old) is not None


async def test_unsigned_provider_intent_cannot_supersede_issued_request(direct):
    _, old = await upload(direct, 1)
    direct.multipart.fail_creates = 1
    with pytest.raises(OSError, match="provider offline"):
        await upload(direct, 2)
    report = await direct.owner.poll_once(now_unix_ms=NOW + 2)
    assert report["objects_selected"] == 1 and report["objects_superseded"] == 0
    assert direct.owner.journal.get("direct-verification", old) is not None


async def test_supported_model_client_stops_on_existing_terminal_status_field(
    direct, policy, monkeypatch
):
    from umi import competition_cohort_direct_model_client as client

    request, old = await upload(direct, 1)
    await upload(direct, 2)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    status = direct.owner.status(old)
    requests = []

    async def exchange(http_request):
        requests.append(http_request.method)
        value = status.reservation if http_request.method == "POST" else status
        return httpx.Response(
            200, content=canonical_json_bytes(value), headers={"Content-Type": "application/json"}
        )

    async def no_payload(_):
        raise AssertionError("a superseded client must not transfer or submit consent")

    source = Path(direct.owner.config.directory).parent / "source" / "candidate"
    monkeypatch.setattr(
        client, "_payload_digest", lambda *args: direct.payload.payload.payload_sha256
    )
    with pytest.raises(CompetitionSubmissionError, match="direct_model_submission_superseded"):
        await client.submit_direct_cohort_model(
            origin="https://intake.example.test",
            policy=policy,
            request=request,
            source=source,
            wallet=wallet("Alice"),
            delivery=direct.owner.config.delivery,
            fingerprints=client._snapshot(
                source, request.signed_submission.submission.model_bundle
            ),
            transport=httpx.MockTransport(exchange),
            object_transport=httpx.MockTransport(no_payload),
        )
    assert requests == ["POST", "GET"]
