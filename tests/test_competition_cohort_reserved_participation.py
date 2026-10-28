"""Real direct-upload journals feed the native participation continuation lane."""

import asyncio
import sqlite3
import threading
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwners,
)
from umi.competition_cohort_direct_model_upload import (
    DirectModelUploadRestartRequest,
    SignedDirectModelUploadRestartRequest,
)
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_cohort_participation_delivery import ParticipationUnavailable
from umi.competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS
from umi.competition_cohort_reserved_participation import (
    ReservedParticipationWorker,
    queue_ready_participation,
)
from umi.open_competition import digest, sign_object
from umi.private_files import publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_direct_model_owner import (
    base_policy as base_policy,
)
from .test_competition_cohort_direct_model_owner import (
    complete_poll_uploads,
    configure_poll_review,
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


async def _complete(direct):
    reservation = await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=NOW)
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload), now_unix_ms=NOW + 1
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=NOW + 2)
    return reservation


def _worker(owner, retain=None):
    async def accept(request, *, before_retain, admission_lock):
        before_retain()
        return {"record_sha256": "c1" * 32}

    delivery = SimpleNamespace(
        capture_timeout_seconds=120,
        retain=retain or AsyncMock(side_effect=accept, return_value={"record_sha256": "c1" * 32}),
    )
    owners = DirectModelUploadOwners(
        {owner.config.cohort_sha256: owner}, intake_phase=lambda _: "intake"
    )
    return ReservedParticipationWorker(owners, delivery), delivery


async def test_preupgrade_ready_reservation_backfills_without_payload_reads(direct):
    reservation = await _complete(direct)
    original = canonical_json_bytes(direct.request)
    upload = digest(direct.request)
    assert direct.owner.journal.get("direct-participation-ready", upload) is None
    reads = direct.multipart.read_calls
    previous = direct.owner
    owner = DirectModelUploadOwner(
        previous.config,
        direct.multipart,
        authorize=previous.authorize,
        sign=previous.sign,
        participation_ready=queue_ready_participation,
    )
    worker, delivery = _worker(owner)
    # Before the verifier restores its original native selection, unknown is
    # explicitly waiting; it is never treated as a zero-work completed queue.
    assert (await worker.poll_once())["total"] is None
    report = await owner.poll_once(now_unix_ms=NOW + 3)
    assert report["objects_ready"] == 1
    assert owner.journal.get("direct-participation-ready", upload) is not None
    result = await worker.poll_once()
    assert (result["completed"], result["total"], result["eta_seconds"]) == (1, 1, 0)
    delivery.retain.assert_awaited_once()
    assert canonical_json_bytes(delivery.retain.await_args.args[0]) == original
    assert owner.status(digest(reservation.reservation)).payload_verified
    assert direct.multipart.read_calls == reads
    # The marker is only written after native participation and evidence return.
    assert owner.journal.get("direct-participation-completed", upload)["record_sha256"] == "c1" * 32
    restarted, no_delivery = _worker(owner)
    assert (await restarted.poll_once())["completed"] == 1
    no_delivery.retain.assert_not_called()
    assert direct.multipart.read_calls == reads
    view = PUBLIC_COHORT_PROGRESS.snapshot(owner.config.cohort_sha256)
    assert view["components"]["reserved_participation"]["percent"] == 100
    assert (
        view["components"]["reserved_participation"]["eta_scope"]
        == "selected_ready_participation_checkpoints"
    )


async def test_verified_object_without_standing_review_is_not_queued(
    direct, tmp_path, policy, monkeypatch
):
    configure_poll_review(direct, tmp_path, policy)
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    monkeypatch.setattr(direct.owner, "review", AsyncMock(side_effect=OSError("review pending")))
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    upload = digest(direct.request)
    assert direct.owner.journal.get("direct-participation-ready", upload) is None
    publish_private_model(
        tmp_path / "reviews" / (direct.payload.payload.model_sha256 + ".json"),
        ModelArtifactReviewInputs(
            model_sha256=direct.payload.payload.model_sha256,
            rights_evidence={"license": "MIT"},
            reconstruction_evidence={"complete": True},
        ),
    )
    reads = direct.multipart.read_calls
    await direct.owner.poll_once(now_unix_ms=NOW + 4)
    assert direct.owner.journal.get("direct-participation-ready", upload) is not None
    assert direct.multipart.read_calls == reads


@pytest.mark.parametrize("change", ["superseded", "new_issuance", "authority"])
async def test_ready_hint_never_overrides_current_selection(direct, monkeypatch, change):
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    owner, upload = direct.owner, digest(direct.request)
    worker, delivery = _worker(owner)
    if change == "superseded":
        owner._selection_holds[upload] = "direct_model_submission_superseded"
        owner._continuation_selection = (owner._continuation_selection[0], frozenset({upload}))
    elif change == "new_issuance":
        monkeypatch.setattr(owner.journal, "selection_fence", lambda db: (999, 999, 999))
    else:
        monkeypatch.setattr(owner, "_selection_authority_current", lambda fence: False)
    result = await worker.poll_once()
    delivery.retain.assert_awaited_once()
    assert owner.journal.get("direct-participation-completed", upload) is None
    assert result["total"] == (0 if change == "superseded" else 1)
    assert owner.journal.get("direct-request", upload) is not None


async def test_server_failure_and_lost_ack_resume_without_disqualifying_upload(direct, monkeypatch):
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    owner, upload = direct.owner, digest(direct.request)
    worker, delivery = _worker(owner)
    delivery.retain.side_effect = OSError("registration unavailable")
    result = await worker.poll_once()
    assert result["completed"] == 0 and result["stalled_or_retrying"]
    assert result["eta_seconds"] is None
    assert owner.journal.get("direct-participation-completed", upload) is None
    delivery.retain.side_effect = None
    original_put = owner.journal.put

    def lose_ack(kind, key, value):
        if kind == "direct-participation-completed":
            raise OSError("interrupted after native receipt")
        return original_put(kind, key, value)

    monkeypatch.setattr(owner.journal, "put", lose_ack)
    assert (await worker.poll_once())["completed"] == 0
    monkeypatch.setattr(owner.journal, "put", original_put)
    restarted, resumed = _worker(owner, delivery.retain)
    assert (await restarted.poll_once())["completed"] == 1
    assert resumed.retain.await_count == 3
    # The delivery helper's own native receipt supplies idempotence across this
    # boundary; its corresponding test uses the real intake and evidence store.
    assert owner.status_by_upload(upload).hold_reason_code is None


async def test_enqueue_failure_never_marks_valid_payload_as_bad(direct, monkeypatch):
    await _complete(direct)

    def fail_queue(*_args):
        raise OSError("metadata capacity unavailable")

    direct.owner.participation_ready = fail_queue
    result = await direct.owner.poll_once(now_unix_ms=NOW + 3)
    assert result["objects_ready"] == 1
    assert result["objects_terminal"] == 0
    assert result["participation_enqueue_retrying"] == 1
    assert direct.owner.status_by_upload(digest(direct.request)).hold_reason_code is None


async def test_backfill_does_not_wait_for_earlier_source_stream(direct, monkeypatch):
    keys = await complete_poll_uploads(direct)
    await direct.owner.verify(keys[-1], now_unix_ms=NOW + 2)
    reads = direct.multipart.read_calls
    owner = direct.owner
    owner.participation_ready = queue_ready_participation
    entered = asyncio.Event()

    async def blocked_verify(key, **kwargs):
        assert key == keys[0]
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(owner, "verify", blocked_verify)
    polling = asyncio.create_task(owner.poll_once(now_unix_ms=NOW + 3))
    try:
        await asyncio.wait_for(entered.wait(), 30)
        ready = owner._reservation_by_digest(keys[-1]).reservation.payload.upload_sha256
        assert owner.journal.get("direct-participation-ready", ready) is not None
        worker, delivery = _worker(owner)
        assert (await worker.poll_once())["completed"] == 1
        delivery.retain.assert_awaited_once()
        assert direct.multipart.read_calls == reads
    finally:
        polling.cancel()
        with pytest.raises(asyncio.CancelledError):
            await polling


async def test_signed_completion_recovers_provider_success_without_client_or_payload_read(
    direct, monkeypatch
):
    owner = direct.owner
    signed = await owner.reserve(direct.request, direct.payload, now_unix_ms=NOW)
    completion = signed_completion(signed, direct.payload.payload)
    original_put = owner.journal.put

    def interrupted(kind, key, value):
        if kind == "direct-object":
            raise OSError("receipt interrupted after provider success")
        return original_put(kind, key, value)

    monkeypatch.setattr(owner.journal, "put", interrupted)
    with pytest.raises(OSError, match="receipt interrupted"):
        await owner.complete(completion, now_unix_ms=NOW + 1)
    monkeypatch.setattr(owner.journal, "put", original_put)
    key = digest(signed.reservation)
    assert owner.journal.get("direct-completion", key) is not None
    assert owner.journal.get("direct-object", key) is None
    assert len(direct.multipart.complete_calls) == 1
    await owner.poll_once(now_unix_ms=NOW + 2)
    worker, delivery = _worker(owner)
    result = await worker.poll_once()
    assert result["stage"] == "completed_upload_receipt_recovery"
    assert result["completed"] == result["total"] == 1
    assert owner.journal.get("direct-object", key) is not None
    assert len(direct.multipart.complete_calls) == 1
    assert direct.multipart.read_calls == 0
    delivery.retain.assert_not_called()


async def test_completion_recovery_yields_after_transient_failures(direct, monkeypatch):
    owner = direct.owner
    original_put = owner.journal.put

    def lose_receipt(kind, key, value):
        if kind != "direct-object":
            return original_put(kind, key, value)

    monkeypatch.setattr(owner.journal, "put", lose_receipt)
    keys = await complete_poll_uploads(direct)
    monkeypatch.setattr(owner.journal, "put", original_put)
    await owner.poll_once(now_unix_ms=NOW + 2)
    complete = owner.complete

    async def fail_first_two(signed, **kwargs):
        if signed.completion.reservation_sha256 in keys[:2]:
            raise OSError("provider temporarily unavailable")
        return await complete(signed, **kwargs)

    monkeypatch.setattr(owner, "complete", fail_first_two)
    worker, _ = _worker(owner)
    assert (await worker.poll_once())["completed"] == 0
    assert (await worker.poll_once())["completed"] == 1
    assert owner.journal.get("direct-object", keys[-1]) is not None
    assert direct.multipart.read_calls == 0


async def test_current_completion_recovery_is_bounded_by_uploads_not_generations(
    direct, monkeypatch
):
    previous = direct.owner
    owner = DirectModelUploadOwner(
        previous.config.model_copy(update={"maximum_uploads": 1}),
        direct.multipart,
        authorize=previous.authorize,
        sign=previous.sign,
    )
    direct.owner = owner
    first = await owner.reserve(direct.request, direct.payload, now_unix_ms=NOW)
    with monkeypatch.context() as patch:
        patch.setattr(direct.multipart, "complete", AsyncMock(side_effect=OSError("provider down")))
        with pytest.raises(OSError):
            await owner.complete(
                signed_completion(first, direct.payload.payload), now_unix_ms=NOW + 1
            )
    attempt = owner.journal.get("direct-intent", first.reservation.attempt_id)
    provider = owner.journal.get("direct-provider", first.reservation.attempt_id)
    direct.multipart.multipart_uploads.remove(
        (attempt["object_key"], provider["provider_upload_id"])
    )
    restart = DirectModelUploadRestartRequest(
        schema="umi-direct-model-upload-restart-request/1",
        reservation_sha256=digest(first.reservation),
        generation=1,
        reason_code="provider_upload_unavailable",
    )
    second = await owner.restart(
        SignedDirectModelUploadRestartRequest(
            schema="umi-signed-direct-model-upload-restart-request/1",
            request=restart,
            signature=sign_object(restart, wallet("Alice")),
        ),
        now_unix_ms=NOW + 121_000,
    )
    original_put = owner.journal.put

    def lose_receipt(kind, key, value):
        if kind != "direct-object":
            return original_put(kind, key, value)

    monkeypatch.setattr(owner.journal, "put", lose_receipt)
    await owner.complete(
        signed_completion(second, direct.payload.payload), now_unix_ms=NOW + 121_001
    )
    monkeypatch.setattr(owner.journal, "put", original_put)
    await owner.poll_once(now_unix_ms=NOW + 121_002)
    worker, _ = _worker(owner)
    result = await worker.poll_once()
    assert result["completed"] == result["total"] == 1
    assert owner.journal.get("direct-object", digest(second.reservation)) is not None
    assert owner.journal.get("direct-object", digest(first.reservation)) is None
    assert direct.multipart.read_calls == 0


async def test_cached_completed_participation_still_respects_new_native_hold(direct):
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    worker, _ = _worker(direct.owner)
    assert (await worker.poll_once())["completed"] == 1
    assert (await worker.poll_once())["completed"] == 1
    upload = digest(direct.request)
    with pytest.raises(ValueError):
        direct.owner.journal.put("direct-participation-ready", upload, {"conflicting": True})
    result = await worker.poll_once()
    assert result["repair_required"]
    assert result["total"] is None


async def test_prior_native_receipt_can_finish_after_phase_advance(direct):
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    delivery = AsyncMock(return_value={"record_sha256": "c1" * 32})
    worker, _ = _worker(direct.owner, delivery)
    worker.owners.intake_phase = lambda _: "requests"
    assert (await worker.poll_once())["completed"] == 1
    delivery.assert_awaited_once()


@pytest.mark.parametrize("stage", ["selection", "ready_inventory"])
async def test_paused_metadata_parsing_does_not_hold_up_journal_writer(direct, monkeypatch, stage):
    from umi import competition_cohort_direct_model_owner as owner_module
    from umi import competition_cohort_reserved_participation as continuation_module

    await _complete(direct)
    owner = direct.owner
    owner.participation_ready = queue_ready_participation
    await owner.poll_once(now_unix_ms=NOW + 3)
    entered, release = threading.Event(), threading.Event()
    first = True
    if stage == "selection":
        original = owner_module.select_issued_model_uploads
        module, name = owner_module, "select_issued_model_uploads"
        operation = owner._poll_projection
    else:
        original = continuation_module._hex32
        module, name = continuation_module, "_hex32"
        worker, _ = _worker(owner)

        def operation():
            return worker._inventory(owner)

    def paused(*args, **kwargs):
        nonlocal first
        if first:
            first = False
            entered.set()
            assert release.wait(20)
        return original(*args, **kwargs)

    monkeypatch.setattr(module, name, paused)
    reading = asyncio.create_task(asyncio.to_thread(operation))
    try:
        assert await asyncio.to_thread(entered.wait, 10)
        # The parse remains deliberately paused until this independent native
        # write commits. An outer rollback-mode reader would prevent that commit.
        await asyncio.wait_for(
            asyncio.to_thread(
                owner.journal.put, "writer-progress-fixture", "ed" * 32, {"committed": True}
            ),
            3,
        )
    finally:
        release.set()
        await asyncio.wait_for(reading, 30)


async def test_projection_retries_when_new_reservation_arrives_mid_selection(direct, monkeypatch):
    from umi import competition_cohort_direct_model_owner as module

    from .test_competition_cohort_admission_drain import _replacement

    await _complete(direct)
    replacement = _replacement(direct.request, sequence=2)
    payload = direct.payload.payload.model_copy(update={"upload_sha256": digest(replacement)})
    signed_payload = direct.payload.model_copy(
        update={"payload": payload, "signature": sign_object(payload, wallet("Alice"))}
    )
    original = module.select_issued_model_uploads
    calls = 0

    def issue_during_selection(*args, **kwargs):
        nonlocal calls
        selected = original(*args, **kwargs)
        calls += 1
        if calls == 1:
            asyncio.run(direct.owner.reserve(replacement, signed_payload, now_unix_ms=NOW + 3))
        return selected

    monkeypatch.setattr(module, "select_issued_model_uploads", issue_during_selection)
    result = await asyncio.to_thread(direct.owner._poll_projection)
    assert calls == 2
    assert result[1][digest(direct.request)] == "direct_model_submission_superseded"
    assert result[3]["objects_selected"] == 0


async def test_repeated_projection_change_yields_with_bounded_retry(direct, monkeypatch):
    from umi.competition_cohort_direct_model_owner import DirectModelSelectionChanged

    await _complete(direct)
    calls = 0

    def moving_fence(db):
        nonlocal calls
        calls += 1
        return (calls, 0, 0)

    monkeypatch.setattr(direct.owner.journal, "selection_fence", moving_fence)
    with pytest.raises(DirectModelSelectionChanged):
        await asyncio.to_thread(direct.owner._poll_projection)
    assert calls == 4


async def test_continuation_uses_paired_holds_during_diagnostic_refresh(direct):
    from umi.competition_cohort_reserved_participation import _UnselectedReservation

    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    owner, upload = direct.owner, digest(direct.request)
    selection = (owner._continuation_selection[0], frozenset({upload}))
    owner._continuation_selection = selection
    worker, _ = _worker(owner)
    captured, *_ = worker._inventory(owner)
    # The verifier clears these diagnostic fields while refreshing. It cannot
    # erase exclusions from a previously published continuation selection.
    owner._selection_holds = {}
    owner._selection_hold_fence = None
    with pytest.raises(_UnselectedReservation):
        worker._eligible(owner, upload, captured)


async def test_projection_releases_intake_snapshot_before_selection_parse(direct, monkeypatch):
    from contextlib import contextmanager

    from umi import competition_cohort_direct_model_owner as module

    await _complete(direct)
    held = False
    counts = []

    @contextmanager
    def context(cohort):
        nonlocal held
        held = True
        try:
            yield None, frozenset()
        finally:
            held = False

    original_fence = direct.owner.journal.selection_fence
    original_select = module.select_issued_model_uploads

    def fence(db):
        counts.append(held)
        return original_fence(db)

    def select(*args, **kwargs):
        assert not held
        return original_select(*args, **kwargs)

    direct.owner.selection_context = context
    monkeypatch.setattr(direct.owner.journal, "selection_fence", fence)
    monkeypatch.setattr(module, "select_issued_model_uploads", select)
    await asyncio.to_thread(direct.owner._poll_projection)
    assert counts == [True, False]


async def test_projection_rechecks_deadline_authority_after_snapshot_release(direct, monkeypatch):
    from umi.competition_cohort_direct_model_owner import DirectModelSelectionChanged

    await _complete(direct)
    direct.owner.selection_authority = lambda cohort: "dd" * 32
    with pytest.raises(DirectModelSelectionChanged):
        await asyncio.to_thread(direct.owner._poll_projection)


async def _ready_with_historical_predecessors(direct):
    owner = direct.owner
    owner.participation_ready = queue_ready_participation
    keys = await complete_poll_uploads(direct)
    for key in keys:
        await owner.verify(key, now_unix_ms=NOW + 2)
    await owner.poll_once(now_unix_ms=NOW + 3)
    uploads = owner.journal.keys("direct-participation-ready")
    owner._continuation_selection = (owner._continuation_selection[0], frozenset(uploads[:-1]))
    return uploads


async def test_selected_work_does_not_wait_for_historical_queue_or_inherit_its_total(direct):
    uploads = await _ready_with_historical_predecessors(direct)
    worker, delivery = _worker(direct.owner)
    first = await worker.poll_once()
    assert [digest(call.args[0]) for call in delivery.retain.await_args_list] == [
        uploads[-1],
        uploads[0],
    ]
    assert (first["completed"], first["total"]) == (1, 1)
    assert (first["queue_completed"], first["queue_total"]) == (1, 3)
    history = first["historical_recovery"]
    assert (history["completed"], history["total"], history["eta_samples"]) == (0, 2, 0)
    assert history["excluded_without_receipt_this_poll"] == 1
    assert history["eta_seconds"] is None
    assert first["eta_samples"] == 1
    second = await worker.poll_once()
    assert (second["completed"], second["total"]) == (1, 1)
    assert second["historical_recovery"]["total"] == 2
    assert second["historical_recovery"]["excluded_without_receipt_this_poll"] == 2
    assert delivery.retain.await_count == 4
    # No synthetic completion is written for an excluded request without a receipt.
    assert direct.owner.journal.get("direct-participation-completed", uploads[0]) is None


async def test_batch_one_alternates_selected_failures_and_historical_receipt_recovery(direct):
    uploads = await _ready_with_historical_predecessors(direct)
    calls = []

    async def retain(request, *, before_retain, admission_lock):
        upload = digest(request)
        calls.append(upload)
        if upload == uploads[-1]:
            before_retain()
            raise OSError("selected registration temporarily unavailable")
        # Model an existing native receipt: the shared delivery test exercises
        # this recovery against the real intake and evidence journal.
        return {"record_sha256": "c1" * 32}

    worker, _ = _worker(direct.owner, AsyncMock(side_effect=retain))
    worker.batch_size = 1
    results = [await worker.poll_once() for _ in range(4)]
    assert calls == [uploads[-1], uploads[0], uploads[-1], uploads[1]]
    assert all((r["completed"], r["total"]) == (0, 1) for r in results)
    assert results[-1]["eta_samples"] == 0
    assert results[-1]["historical_recovery"]["eta_samples"] == 2
    assert results[-1]["historical_recovery"]["completed"] == 2


async def test_unknown_selection_keeps_receipt_recovery_and_unknown_selected_denominator(direct):
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    direct.owner._continuation_selection = None
    delivery = AsyncMock(return_value={"record_sha256": "c1" * 32})
    worker, _ = _worker(direct.owner, delivery)
    result = await worker.poll_once()
    assert result["total"] is None
    assert (result["queue_completed"], result["queue_total"]) == (1, 1)
    assert result["historical_recovery"]["scope"] == "unclassified_ready_receipt_checkpoints"
    assert result["historical_recovery"]["completed"] == 1
    delivery.assert_awaited_once()


@pytest.mark.parametrize("repair", [False, True])
async def test_worker_and_public_progress_preserve_typed_retry_cause_without_private_text(
    direct, repair
):
    direct.owner.participation_ready = queue_ready_participation
    await _complete(direct)
    await direct.owner.poll_once(now_unix_ms=NOW + 3)
    cause = (
        ValueError("private /path https://secret.invalid")
        if repair
        else sqlite3.OperationalError("private /path https://secret.invalid")
    )
    if not repair:
        cause.sqlite_errorcode, cause.sqlite_errorname = sqlite3.SQLITE_BUSY, "SQLITE_BUSY"
    error = ParticipationUnavailable("private wrapper text", stage="evidence_preservation")
    error.__cause__ = cause
    worker, _ = _worker(direct.owner, AsyncMock(side_effect=error))
    result = await worker.poll_once()
    public = PUBLIC_COHORT_PROGRESS.snapshot(direct.owner.config.cohort_sha256)["components"][
        "reserved_participation"
    ]
    for value in (result, public):
        assert value["error_type"] == "ParticipationUnavailable"
        assert value["cause_type"] == type(cause).__name__
        assert value["error_stage"] == "evidence_preservation"
        assert value["reason_code"] == "participation_evidence_unavailable"
        assert value["repair_required"] is repair
        if not repair:
            assert value["sqlite_errorcode"] == sqlite3.SQLITE_BUSY
            assert value["sqlite_errorname"] == "SQLITE_BUSY"
        assert "secret.invalid" not in str(value)
        assert "private wrapper" not in str(value)
