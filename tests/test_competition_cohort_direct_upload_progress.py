"""The native upload loop exposes partial inventory without new verification."""

import asyncio
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi import competition_cohort_api as api
from umi import competition_cohort_direct_model_owner as owner_module
from umi import competition_transport_verification as transport
from umi.competition_cohort_direct_model_owner import (
    DirectModelUploadOwner,
    DirectModelUploadOwners,
)
from umi.competition_cohort_public_progress import PUBLIC_COHORT_SCOPE, CohortProgressSnapshots

from .test_competition_cohort_direct_model_owner import (
    base_policy as base_policy,
)
from .test_competition_cohort_direct_model_owner import (
    complete_poll_uploads,
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

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)
NOW = 1_800_000_011_000


@pytest.fixture
def snapshots(monkeypatch):
    value = CohortProgressSnapshots()
    for module in (api, owner_module, transport):
        monkeypatch.setattr(module, "PUBLIC_COHORT_PROGRESS", value)
    return value


async def reached(task, event):
    """Surface an early task failure instead of hanging the qualification."""
    waiter = asyncio.create_task(event.wait())
    try:
        await asyncio.wait((task, waiter), return_when=asyncio.FIRST_COMPLETED)
        if task.done():
            await task
            raise AssertionError("poll unexpectedly completed before its controlled wait")
    finally:
        waiter.cancel()
        await asyncio.gather(waiter, return_exceptions=True)


def cached_app(cohort):
    async def forbidden():
        raise AssertionError("progress GET must not call native finality")

    app = FastAPI()
    app.include_router(
        api.cohort_routes(
            SimpleNamespace(
                bindings={cohort: "authority"},
                admission_status=lambda _: {"accepted_uploads": None},
            ),
            forbidden,
            maximum_body_bytes=1024,
        )
    )
    return app


async def test_blocked_first_read_publishes_denominator_and_native_work_to_cached_api(
    direct, snapshots, monkeypatch
):
    keys = await complete_poll_uploads(direct)
    cohort = direct.owner.config.cohort_sha256
    entered, release = asyncio.Event(), asyncio.Event()
    original_read, original_keys = direct.multipart.read_range, direct.owner.journal.keys
    scans = []

    def keys_once(kind):
        scans.append(kind)
        return original_keys(kind)

    async def blocked(*args, **kwargs):
        assert PUBLIC_COHORT_SCOPE.get() == cohort
        entered.set()
        await release.wait()
        return await original_read(*args, **kwargs)

    monkeypatch.setattr(direct.owner.journal, "keys", keys_once)
    monkeypatch.setattr(direct.multipart, "read_range", blocked)
    monkeypatch.setattr(api, "CohortAdmissionQueue", lambda _: None)
    manager = DirectModelUploadOwners({cohort: direct.owner}, priority_cohorts=(cohort,))
    task = asyncio.create_task(manager.poll_once(now_unix_ms=NOW))
    try:
        await reached(task, entered)
        assert scans == ["direct-object"]
        assert manager._reports == {} and manager._pending(cohort) is None
        assert direct.multipart.read_calls == 0
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(cached_app(cohort)), base_url="http://test"
        ) as client:
            for _ in range(2):
                response = await client.get(f"/v1/competition/cohorts/{cohort}/progress")
                assert response.status_code == 200
                body = response.json()
                observed = body["components"]["direct_uploads"]
                assert observed["objects_total"] == 3
                assert observed["objects_classified"] == 0
                assert observed["objects_unclassified"] == 3
                assert observed["object_count_status"] == "partial"
                assert observed["active_object_position"] == 1
                assert observed["active_object_sha256"] == keys[0]
                assert observed["model_sha256"] == direct.payload.payload.model_sha256
                assert observed["active_object_stage"] == "source_verification"
                assert observed["owner_report_observed_unix_ms"] is None
                work = body["components"]["work"]
                assert work["stage"] == "remote_model_verification"
                assert work["total"] == direct.payload.payload.total_bytes
                assert work["completed"] == 0
                assert work["model_sha256"] == observed["model_sha256"]
                assert work["object_role"] == "source"
                assert work["eta_basis"].startswith("planning_")
                assert body["admission"]["accepted_uploads"] is None
                assert body["certification_authority"] is False
        assert scans == ["direct-object"] and direct.multipart.read_calls == 0
    finally:
        release.set()
        await task
    final = snapshots.snapshot(cohort)["components"]["direct_uploads"]
    assert final["object_count_status"] == "complete"
    assert final["objects_classified"] == 3 and final["objects_unclassified"] == 0
    assert final["objects_ready"] == 2 and final["objects_pending"] == 1
    assert final["active_object_position"] is None and final["model_sha256"] is None
    assert manager._pending(cohort) == 1 and manager._progress_reports == {}
    assert PUBLIC_COHORT_SCOPE.get() is None
    assert scans == ["direct-object"]


async def test_partial_inventory_never_replaces_scheduler_report_and_restart_rebuilds_once(
    direct, snapshots, monkeypatch
):
    keys = await complete_poll_uploads(direct)
    cohort = direct.owner.config.cohort_sha256
    entered, release = asyncio.Event(), asyncio.Event()
    original = direct.owner.verify

    async def blocked(*args, **kwargs):
        entered.set()
        await release.wait()
        return await original(*args, **kwargs)

    monkeypatch.setattr(direct.owner, "verify", blocked)
    manager = DirectModelUploadOwners({cohort: direct.owner}, priority_cohorts=(cohort,))
    previous = dict(objects_pending=0, objects_retrying=0, objects_ready=2, objects_total=2)
    manager._reports[cohort] = previous
    task = asyncio.create_task(manager.poll_once(now_unix_ms=NOW))
    await reached(task, entered)
    assert manager._reports[cohort] is previous and manager._pending(cohort) == 0
    partial = snapshots.snapshot(cohort)["components"]["direct_uploads"]
    assert partial["objects_total"] == 3 and partial["object_count_status"] == "partial"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    interrupted = snapshots.snapshot(cohort)["components"]["direct_uploads"]
    assert interrupted["object_count_status"] == "interrupted"
    assert interrupted["active_object_stage"] == "interrupted"
    assert interrupted["objects_unclassified"] == 3
    assert interrupted["error_type"] == "CancelledError"
    assert manager._pending(cohort) is None and manager._reports == {}
    assert PUBLIC_COHORT_SCOPE.get() is None

    resumed = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )
    manager = DirectModelUploadOwners({cohort: resumed}, priority_cohorts=(cohort,))
    manager._publish_scheduling()
    assert snapshots.snapshot(cohort)["components"]["direct_uploads"]["objects_total"] is None
    entered.clear()
    native_verify = resumed.verify
    visits = []

    async def continuing(key, **kwargs):
        visits.append(key)
        entered.set()
        await release.wait()
        return await native_verify(key, **kwargs)

    monkeypatch.setattr(resumed, "verify", continuing)
    task = asyncio.create_task(manager.poll_once(now_unix_ms=NOW + 1))
    try:
        await reached(task, entered)
        current = snapshots.snapshot(cohort)["components"]["direct_uploads"]
        assert current["active_object_sha256"] == keys[1]
        assert current["active_object_position"] == 1
        assert current["objects_total"] == 3 and current["objects_unclassified"] == 3
        assert visits == [keys[1]]
    finally:
        release.set()
        await task


async def test_completed_metadata_is_classified_without_repeating_its_byte_check(
    direct, snapshots, monkeypatch
):
    keys = await complete_poll_uploads(direct)
    await direct.owner.verify(keys[0], now_unix_ms=NOW)
    before = direct.multipart.read_calls
    entered, release = asyncio.Event(), asyncio.Event()
    original = direct.owner.verify
    visits = []

    async def blocked(key, **kwargs):
        visits.append(key)
        entered.set()
        await release.wait()
        return await original(key, **kwargs)

    monkeypatch.setattr(direct.owner, "verify", blocked)
    cohort = direct.owner.config.cohort_sha256
    manager = DirectModelUploadOwners({cohort: direct.owner})
    task = asyncio.create_task(manager.poll_once(now_unix_ms=NOW + 1))
    try:
        await reached(task, entered)
        value = snapshots.snapshot(cohort)["components"]["direct_uploads"]
        assert value["objects_ready"] == value["objects_classified"] == 1
        assert value["objects_unclassified"] == 2 and value["active_object_position"] == 2
        assert value["active_object_sha256"] == keys[1]
        assert visits == [keys[1]] and direct.multipart.read_calls == before
    finally:
        release.set()
        await task


async def test_partial_retry_cause_visible_while_following_object_is_blocked(
    direct, snapshots, monkeypatch
):
    keys = await complete_poll_uploads(direct)
    entered, release = asyncio.Event(), asyncio.Event()
    original = direct.owner.verify

    async def retry_then_wait(key, **kwargs):
        if key == keys[0]:
            raise OSError("transient fixture failure")
        entered.set()
        await release.wait()
        return await original(key, **kwargs)

    monkeypatch.setattr(direct.owner, "verify", retry_then_wait)
    cohort = direct.owner.config.cohort_sha256
    manager = DirectModelUploadOwners({cohort: direct.owner})
    task = asyncio.create_task(manager.poll_once(now_unix_ms=NOW))
    try:
        await reached(task, entered)
        value = snapshots.snapshot(cohort)["components"]["direct_uploads"]
        assert value["objects_retrying"] == value["objects_classified"] == 1
        assert value["objects_unclassified"] == 2
        assert value["stalled_or_retrying"] and value["error_type"] == "OSError"
        assert manager._pending(cohort) is None
    finally:
        release.set()
        await task


async def test_empty_and_failed_inventory_have_distinct_truthful_status(
    direct, snapshots, monkeypatch
):
    cohort = direct.owner.config.cohort_sha256
    manager = DirectModelUploadOwners({cohort: direct.owner})
    await manager.poll_once(now_unix_ms=NOW)
    empty = snapshots.snapshot(cohort)["components"]["direct_uploads"]
    assert empty["objects_total"] == empty["objects_classified"] == 0
    assert empty["object_count_status"] == "complete"

    def broken(_):
        raise ValueError("damaged native metadata")

    monkeypatch.setattr(direct.owner.journal, "keys", broken)
    with pytest.raises(ValueError, match="damaged native metadata"):
        await manager.poll_once(now_unix_ms=NOW + 1)
    failed = snapshots.snapshot(cohort)["components"]["direct_uploads"]
    assert failed["objects_total"] is None and failed["object_count_status"] is None
    assert failed["error_type"] == "ValueError" and failed["stalled_or_retrying"]
    assert manager._pending(cohort) is None
