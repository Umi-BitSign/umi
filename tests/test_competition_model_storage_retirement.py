"""Native background retirement with actual signed, live consumer leases."""

from contextlib import AsyncExitStack
from typing import Any

import pytest

from umi.competition_artifacts import preserve_bundle
from umi.competition_cohort_model_retirement import ModelUploadRetirement
from umi.competition_cohort_model_upload import CohortModelUploads, ModelUploadConfig
from umi.competition_cohort_model_upload_delivery import ModelUploadDelivery
from umi.competition_model_storage_leases import (
    ModelStorageConsumerBinding,
    ModelStorageConsumerConfig,
    ModelUploadRetirementConfig,
    model_storage_consumer,
)
from umi.open_competition import digest, identity, sign_object
from umi.private_files import ensure_private_directory
from umi.protocol import StrictProtocolModel

from .test_competition_cohort_legacy_model_admission import frozen as frozen
from .test_competition_cohort_model_acceptance import prepared as prepared
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_open_competition import wallet

pytestmark = [
    pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True),
    pytest.mark.parametrize("recovery", ["legacy6"], indirect=True),
]


class _Series(StrictProtocolModel):
    recovery: Any


@pytest.fixture
async def retirement(frozen, tmp_path):
    f = frozen
    series = _Series(recovery=f.case.history.authority)
    consumers = []
    for kind in ("reviewer", "settlement"):
        for index, evaluator in enumerate(f.owner.intake.policy.evaluators):
            directory = tmp_path / f"consumer-{kind}-{index}"
            directory.mkdir(mode=0o700)
            consumers.append(
                ModelStorageConsumerBinding(
                    directory=str(directory), kind=kind, hotkey=evaluator.hotkey
                )
            )
    uploads = CohortModelUploads(
        ModelUploadConfig(
            directory=str(tmp_path / "uploads"),
            maximum_reserved_bytes=1024**3,
            retirement=ModelUploadRetirementConfig(consumers=tuple(consumers)),
        ),
        f.owner.intake,
        tmp_path / "local-archive",
    )
    request = f.case.requests[0]
    bundle = request.signed_submission.submission.model_bundle
    model = digest(bundle)
    with uploads.journal.locked():
        uploads.journal.put_many(
            (
                ("bundle", model, bundle),
                ("upload", digest(request), request),
                uploads.allocations.reservation_record(bundle),
            ),
            index=lambda db: uploads.allocations.index_reserved(db, bundle),
        )
    preserve_bundle(
        bundle, tmp_path / "offline-original/model", uploads.archive, uploads.intake.policy
    )
    ensure_private_directory(uploads.root / "files" / model / "model")
    delivery = ModelUploadDelivery(uploads, remote_payloads=f.owner.legacy_payloads)
    delivery.retirement = ModelUploadRetirement(uploads, delivery, series=series)
    f.uploads, f.delivery, f.series, f.model = uploads, delivery, series, model
    f.request = request
    resolution = f.sources.resolve(f.case.cohort, request_sha256=digest(request))
    await f.sources.reader(resolution).verify()
    f.remote.reads.clear()
    return f


async def consumers(f, stack):
    keys = {
        identity(wallet(name).hotkey.ss58_address): wallet(name)
        for name in ("Alice", "Bob", "Charlie", "Dave", "Eve", "Ferdie")
    }
    for consumer in f.uploads.config.retirement.consumers:
        key = keys[identity(consumer.hotkey)]

        async def sign(body, key=key):
            return sign_object(body, key)

        await stack.enter_async_context(
            model_storage_consumer(
                ModelStorageConsumerConfig(directory=consumer.directory),
                kind=consumer.kind,
                hotkey=consumer.hotkey,
                policy=f.uploads.intake.policy,
                series=f.series,
                sources=f.sources,
                sign=sign,
            )
        )


async def test_background_poll_retires_then_restarts_and_reuses_original_requests(retirement):
    f = retirement
    original = f.uploads.journal.get_raw("upload", digest(f.request))
    manifest = (f.uploads.archive / f.model / "manifest.json").read_bytes()
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        await f.delivery.poll_once()
        assert f.uploads.allocations.state(f.model) == "released"
        assert not (f.uploads.archive / f.model / "model").exists()
        assert not (f.uploads.root / "files" / f.model / "model").exists()
        assert (f.uploads.archive / f.model / "manifest.json").read_bytes() == manifest
        assert f.uploads.journal.get_raw("upload", digest(f.request)) == original
        f.uploads = CohortModelUploads(f.uploads.config, f.uploads.intake, f.uploads.archive)
        f.delivery = ModelUploadDelivery(f.uploads, remote_payloads=f.owner.legacy_payloads)
        f.delivery.retirement = ModelUploadRetirement(f.uploads, f.delivery, series=f.series)
        result = await f.delivery.poll_once()
        assert result["models_preserved"] == 1
        assert f.uploads.allocations.state(f.model) == "released"
        assert not (f.uploads.archive / f.model / "model").exists()


async def test_absent_consumer_never_fences_or_unlinks_native_payload(retirement):
    f = retirement
    await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()
    assert f.delivery.retirement.latest["stalled_or_retrying"]


async def test_closed_consumer_lease_cannot_authorize_retirement_after_restart(retirement):
    f = retirement
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
    # PID alone still exists in this fixture. Closing a live declaration must
    # be separately detected even before PID reuse or consumer restart.
    await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()


@pytest.mark.parametrize("boundary", ["unlink_done", "payload_removed", "release_completed"])
async def test_interrupted_retirement_resumes_without_payload_reverification(
    retirement, monkeypatch, boundary
):
    f = retirement
    journal = f.delivery.retirement.journal
    original_put = journal.put
    original_complete = f.uploads.allocations._complete_release
    interrupted = False

    def put(kind, key, value, **kwargs):
        nonlocal interrupted
        if kind == boundary and not interrupted:
            interrupted = True
            raise OSError("injected power loss after unlink, before checkpoint")
        return original_put(kind, key, value, **kwargs)

    def complete(model):
        nonlocal interrupted
        if boundary == "release_completed" and not interrupted:
            interrupted = True
            raise OSError("injected interruption before allocation credit")
        return original_complete(model)

    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        with monkeypatch.context() as patch:
            patch.setattr(journal, "put", put)
            patch.setattr(f.uploads.allocations, "_complete_release", complete)
            await f.delivery.poll_once()
        assert interrupted
        assert f.uploads.allocations.state(f.model) == "release_prepared"
        # Retained originals and remote verification survive a new owner.
        f.uploads = CohortModelUploads(f.uploads.config, f.uploads.intake, f.uploads.archive)
        f.delivery = ModelUploadDelivery(f.uploads, remote_payloads=f.owner.legacy_payloads)
        f.delivery.retirement = ModelUploadRetirement(f.uploads, f.delivery, series=f.series)
        f.remote.reads.clear()
        await f.delivery.poll_once()
        assert f.uploads.allocations.state(f.model) == "released"
        assert not (f.uploads.archive / f.model / "model").exists()
        assert not f.remote.reads, "restart must reuse completed R2 byte verification"


async def test_protected_model_is_never_retired(retirement):
    f = retirement
    config = f.uploads.config.model_copy(
        update={
            "retirement": f.uploads.config.retirement.model_copy(
                update={"protected_models": (f.model,)}
            )
        }
    )
    f.uploads = CohortModelUploads(config, f.uploads.intake, f.uploads.archive)
    f.delivery = ModelUploadDelivery(f.uploads, remote_payloads=f.owner.legacy_payloads)
    f.delivery.retirement = ModelUploadRetirement(f.uploads, f.delivery, series=f.series)
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()
    assert not f.remote.reads


async def test_changed_original_inventory_prevents_release(retirement, monkeypatch):
    f = retirement
    native = f.delivery.retirement._retire

    def changed(model, requests, generation):
        # Simulate a concurrent new original before acquiring the owner lock.
        return native(model, requests, ("different-inventory",))

    monkeypatch.setattr(f.delivery.retirement, "_retire", changed)
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()


async def test_missing_completed_remote_receipt_requires_repair(retirement, monkeypatch):
    f = retirement

    async def missing(*args, **kwargs):
        assert kwargs.get("completed_only"), "retirement must not start a payload verification pass"
        raise OSError("completed receipt damaged; explicit repair required")

    monkeypatch.setattr(f.owner.legacy_payloads, "ensure_owned", missing)
    f.owner.legacy_payloads.verified.clear()
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()
    assert f.delivery.retirement.latest["stalled_or_retrying"]
    assert not f.remote.reads


async def test_missing_required_consumer_prevents_release(retirement):
    f = retirement
    configured = f.uploads.config.retirement
    f.delivery.retirement.config = configured.model_copy(
        update={"consumers": configured.consumers[:-1]}
    )
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()
    assert f.delivery.retirement.latest["stalled_or_retrying"]


async def test_local_open_intake_blocks_retirement_with_public_waiting_progress(retirement):
    f = retirement
    f.sources.authenticated.clear()
    await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()
    assert f.delivery.retirement.latest["stalled_or_retrying"]
    assert f.delivery.retirement.latest["reason_code"].startswith("local_membership_unavailable_")
    assert not f.remote.reads


async def test_unexpected_archive_file_is_retained_without_capacity_credit(retirement, monkeypatch):
    f = retirement
    native = f.delivery.retirement._layout
    extra = f.uploads.archive / f.model / "model" / "unlisted-preserve.txt"

    def layout(*args):
        result = native(*args)
        extra.write_bytes(b"unrecognized user data must survive")
        return result

    monkeypatch.setattr(f.delivery.retirement, "_layout", layout)
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        await f.delivery.poll_once()
    assert f.uploads.allocations.state(f.model) == "release_prepared"
    assert extra.read_bytes() == b"unrecognized user data must survive"
    assert f.delivery.retirement.latest["stalled_or_retrying"]


async def test_retirement_inventory_reuses_references_without_decoding_all_requests(
    retirement, monkeypatch
):
    f = retirement
    key = digest(f.request)
    assert f.uploads.retained_model(key) == f.model
    generation = f.uploads._model_references.versions.inventory_identity()
    seen = []

    class InventoryOnly:
        async def poll_once(self, groups, actual):
            assert groups == {f.model: [key]}
            assert actual == generation
            seen.append("retirement")
            return {"status": "fixture_inventory_observed"}

    def no_full_request(*args, **kwargs):
        raise AssertionError("inventory must not materialize full historical requests")

    def ordinary_poll(**kwargs):
        assert seen == ["retirement"], "cleanup must not wait for unrelated model polling"
        return {"status": "fixture_normal_poll"}

    f.delivery.retirement = InventoryOnly()
    monkeypatch.setattr(f.uploads, "retained", no_full_request)
    monkeypatch.setattr(f.uploads, "poll_once", ordinary_poll)
    original = f.uploads.journal.get_raw

    def no_original(kind, identity, **kwargs):
        assert kind != "upload", "unchanged source-version references must not reread originals"
        return original(kind, identity, **kwargs)

    monkeypatch.setattr(f.uploads.journal, "get_raw", no_original)
    result = await f.delivery.poll_once()
    assert result["local_retirement"]["status"] == "fixture_inventory_observed"


async def test_retirement_completes_before_unrelated_remote_retry(retirement, monkeypatch):
    import asyncio
    import threading

    f = retirement
    entered, release = threading.Event(), threading.Event()
    native = f.delivery._remote_request
    reference = f.uploads.retained_model
    looked_up = []

    def lookup(key):
        looked_up.append(key)
        return reference(key)

    def slow_remote(key, *, model=None):
        entered.set()
        assert release.wait(5), "test remote retry was not released"
        return native(key, model=model)

    monkeypatch.setattr(f.uploads, "retained_model", lookup)
    monkeypatch.setattr(f.delivery, "_remote_request", slow_remote)
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        task = asyncio.create_task(f.delivery.poll_once())
        try:
            assert await asyncio.to_thread(entered.wait, 5)
            assert f.uploads.allocations.state(f.model) == "released"
            assert not (f.uploads.archive / f.model / "model").exists()
            # Reconciliation reuses the inventory's immutable reference while
            # checking fresh allocation state after the deletion.
            assert looked_up == [digest(f.request)]
        finally:
            release.set()
            await task


async def test_incomplete_local_inventory_blocks_retirement_before_remote_poll(
    retirement, monkeypatch
):
    f = retirement
    seen = []

    def missing_reference(key):
        raise OSError("retained reference requires explicit repair")

    def remote(key, *, model=None):
        assert f.delivery.retirement.latest["reason_code"] == "original_upload_inventory_incomplete"
        seen.append(key)
        return None

    monkeypatch.setattr(f.uploads, "retained_model", missing_reference)
    monkeypatch.setattr(f.delivery, "_remote_request", remote)
    monkeypatch.setattr(f.uploads, "poll_once", lambda **kwargs: {})
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        result = await f.delivery.poll_once()
    assert seen == [digest(f.request)]
    assert result["local_retirement"]["reason_code"] == "original_upload_inventory_incomplete"
    assert f.uploads.allocations.state(f.model) == "local_reserved"
    assert (f.uploads.archive / f.model / "model").is_dir()
    assert not f.remote.reads


async def test_wait_reports_exact_model_operation_and_safe_reason(retirement, monkeypatch, caplog):
    import logging

    from umi.competition_cohort_public_progress import PUBLIC_COHORT_PROGRESS

    f = retirement
    f.owner.legacy_payloads.verified.clear()

    async def missing(*args, **kwargs):
        raise OSError("shared file migration requires completed native bytes and documents")

    monkeypatch.setattr(f.owner.legacy_payloads, "ensure_owned", missing)
    async with AsyncExitStack() as stack:
        await consumers(f, stack)
        with caplog.at_level(logging.INFO, logger="umi.competition.progress"):
            await f.delivery.poll_once()
    latest = f.delivery.retirement.latest
    assert latest["model_sha256"] == f.model
    assert latest["operation"] == "remote_payload_ownership"
    assert latest["reason_code"] == "completed_remote_bytes_missing"
    assert latest["error_type"] == "OSError"
    cohort = f.request.consent.consent.cohort_sha256
    public = PUBLIC_COHORT_PROGRESS.snapshot(cohort)["components"]["storage_retirement"]
    assert public["model_sha256"] == f.model and public["reason_code"] == latest["reason_code"]
    assert "completed_remote_bytes_missing" in caplog.text
    assert f.uploads.allocations.state(f.model) == "local_reserved"


def test_retirement_reason_does_not_publish_private_exception_text(receipt_scenario, recovery):
    from umi.competition_cohort_model_retirement import retirement_failure_reason

    reason = retirement_failure_reason("remote_payload_ownership", OSError("SECRET /private/key"))
    assert reason == "remote_payload_ownership_OSError"
    assert "SECRET" not in reason and "private" not in reason
