"""Native model file delivery before enrollment, with synthetic finality only."""

import asyncio
import hashlib
import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import httpx
import pytest
from fastapi import FastAPI

from umi.competition_artifacts import verify_preserved_bundle
from umi.competition_cohort_api import cohort_routes
from umi.competition_cohort_intake import CohortIntake, CohortIntakeBinding, CohortIntakeConfig
from umi.competition_cohort_model_acceptance import ModelArtifactReviewInputs
from umi.competition_cohort_model_reservations import (
    ModelAllocationRepairRequired,
    repair_model_allocation_index,
)
from umi.competition_cohort_model_static_review import StandingModelReviewPolicy
from umi.competition_cohort_model_upload import (
    CohortModelUploads,
    ModelUploadChunk,
    ModelUploadConfig,
    PendingModelReview,
)
from umi.competition_cohort_model_upload_http import model_upload_routes
from umi.open_competition import digest, sign_object
from umi.private_files import lock_private_file, publish_private_model
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_execution import setup_scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_award import base_policy as base_policy
from .test_competition_cohort_model_award import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_award import policy as policy
from .test_competition_cohort_model_award import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_award import recovery as recovery
from .test_competition_cohort_model_award import runtime as runtime
from .test_competition_cohort_roster import retained
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture
def delivery(tmp_path, receipt_scenario, runtime):
    s = setup_scenario(receipt_scenario, tmp_path / "source", runtime)
    history = s["intake_history"]
    intake = CohortIntake(
        CohortIntakeConfig(
            directory=str(tmp_path / "intake"),
            cohorts=(
                CohortIntakeBinding(
                    cohort_sha256=digest(history.plan),
                    authority_sha256=digest(history.authority.authority),
                ),
            ),
        ),
        s["policy"],
        eligible_tracks=("endpoint", "model"),
        initialize=True,
    )
    intake.publish(history, capture_at(210))
    request = retained(s, "Alice", 1).record.request
    config = ModelUploadConfig(directory=str(tmp_path / "delivery"), maximum_reserved_bytes=1024**3)
    owner = CohortModelUploads(config, intake, tmp_path / "archive")
    state = SimpleNamespace(
        owner=owner,
        request=request,
        intake=intake,
        source=tmp_path / "source/candidate",
        cohort=digest(history.plan),
        online=True,
        captures=0,
    )

    async def capture():
        state.captures += 1
        if not state.online:
            raise OSError("finality offline")
        return capture_at(210)

    state.capture = capture
    app = FastAPI()
    app.include_router(cohort_routes(intake, capture, maximum_body_bytes=4 * 1024**2, models=owner))
    app.include_router(model_upload_routes(owner, capture))
    state.app = app
    return state


def signed_chunk(key, index, data, offset=0, signer="Alice"):
    chunk = ModelUploadChunk(
        schema="umi-cohort-model-upload-chunk/1",
        upload_sha256=key,
        file_index=index,
        offset=offset,
        size_bytes=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
    )
    signature = sign_object(chunk, wallet(signer))
    return chunk, signature


def chunk_headers(key, index, data, offset=0):
    chunk, signature = signed_chunk(key, index, data, offset)
    return {
        "content-type": "application/octet-stream",
        "content-length": str(len(data)),
        "x-umi-chunk-sha256": chunk.sha256,
        "x-umi-signature": canonical_json_bytes(signature).decode(),
    }


def put(owner, key, index, data, offset=0):
    owner.put_chunk(*signed_chunk(key, index, data, offset), data)


def upload_all(h, owner, key):
    for index, record in enumerate(h.request.signed_submission.submission.model_bundle.files):
        put(owner, key, index, (h.source / record.path).read_bytes())
    assert owner.poll_once()["models_preserved"] == 1


def test_completed_upload_prefix_is_not_rehashed_after_restart(delivery, monkeypatch):
    from umi import competition_cohort_model_upload as upload

    h = delivery
    owner = h.owner
    key = owner.reserve(h.request, capture_at(210))
    bundle = h.request.signed_submission.submission.model_bundle
    first = bundle.files[0]
    put(owner, key, 0, (h.source / first.path).read_bytes())
    assert not owner.complete(key)

    def rehash_forbidden(*args, **kwargs):
        raise AssertionError("completed upload prefix was hashed again")

    monkeypatch.setattr(upload, "_copy_verified", rehash_forbidden)
    # A new uploader instance has no in-memory state to trust.
    restarted = CohortModelUploads(owner.config, owner.intake, owner.archive)
    assert not restarted.complete(key)
    assert not restarted.complete(key)


def test_changed_completed_upload_prefix_cannot_reuse_verification(delivery, monkeypatch):
    from umi import competition_cohort_model_upload as upload

    h = delivery
    owner = h.owner
    key = owner.reserve(h.request, capture_at(210))
    bundle = h.request.signed_submission.submission.model_bundle
    first = bundle.files[0]
    put(owner, key, 0, (h.source / first.path).read_bytes())
    assert not owner.complete(key)
    _, staging = owner._paths(key)
    target = staging / "model" / first.path
    target.chmod(0o600)
    target.write_bytes(b"x" * target.stat().st_size)
    target.chmod(0o400)

    def rehash_forbidden(*args, **kwargs):
        raise AssertionError("changed content was hashed instead of held")

    monkeypatch.setattr(upload, "_copy_verified", rehash_forbidden)
    with pytest.raises(ValueError, match="changed after verification"):
        owner.complete(key)


def assert_staging_released(owner, key):
    _, staging = owner._paths(key)
    assert list((staging / "model").iterdir()) == []


def standing_review_policy(h, **changes):
    value = StandingModelReviewPolicy(
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
    return value.model_copy(update=changes)


def test_delivery_resumes_original_prefix_and_is_not_enrollment(delivery):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    record = h.request.signed_submission.submission.model_bundle.files[0]
    data = (h.source / record.path).read_bytes()
    assert len(data) > 2
    put(h.owner, key, 0, data[:2])
    assert h.intake.receipt(h.request) is None
    reopened = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    assert reopened.retry(h.request) == key
    assert reopened.status(key)["file_offsets"][0] == 2
    # Identical and partially overlapping retries retain the original prefix.
    put(reopened, key, 0, data[:2])
    put(reopened, key, 0, data[1:], 1)
    assert reopened.status(key)["file_offsets"][0] == len(data)
    assert not reopened.complete(key)
    assert reopened.status(key)["complete_files"] == [0]
    upload_all(h, reopened, key)
    reopened.require_payload(h.request)
    assert h.intake.receipt(h.request) is None
    sub = h.request.signed_submission.submission
    assert (
        verify_preserved_bundle(sub.model_bundle, h.owner.archive, h.intake.policy)
        == sub.model_revision
    )
    assert_staging_released(reopened, key)
    put(reopened, key, 0, data)  # No archive rewrite.
    assert_staging_released(reopened, key)


def test_configured_pre_admission_review_gates_model_enrollment(delivery, tmp_path):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    upload_all(h, h.owner, key)
    sub = h.request.signed_submission.submission
    reviews = tmp_path / "admission-reviews"
    gated = CohortModelUploads(
        h.owner.config.model_copy(
            update={
                "directory": str(tmp_path / "gated-delivery"),
                "admission_reviews_directory": str(reviews),
            }
        ),
        h.intake,
        h.owner.archive,
    )
    with pytest.raises(PendingModelReview):
        gated.require_payload(h.request)
    publish_private_model(
        reviews / (sub.model_revision + ".json"),
        ModelArtifactReviewInputs(
            model_sha256=sub.model_revision,
            rights_evidence={"review": "passed"},
            reconstruction_evidence={"review": "passed"},
        ),
    )
    gated.require_payload(h.request)


def test_standing_policy_automatically_reviews_complete_bundle_once(delivery, tmp_path):
    h = delivery
    reviews = tmp_path / "automatic-reviews"
    owner = CohortModelUploads(
        ModelUploadConfig(
            directory=str(tmp_path / "automatic-delivery"),
            admission_reviews_directory=str(reviews),
            standing_review_policy=standing_review_policy(h),
            maximum_reserved_bytes=1024**3,
        ),
        h.intake,
        h.owner.archive,
    )
    key = owner.reserve(h.request, capture_at(210))
    upload_all(h, owner, key)
    sub = h.request.signed_submission.submission
    target = reviews / (sub.model_revision + ".json")
    first = target.read_bytes()
    review = ModelArtifactReviewInputs.model_validate_json(first)
    assert review.model_sha256 == sub.model_revision
    assert review.rights_evidence["decision"]["approval_basis"] == (
        "standing_operator_policy_for_complete_declared_bundles"
    )
    assert review.reconstruction_evidence["complete_bundle_hash_verification"] == {
        "status": "complete_bundle_verified",
        "file_count": len(sub.model_bundle.files),
        "total_bytes": sum(record.size_bytes for record in sub.model_bundle.files),
        "model_code_executed": False,
        "network_used": False,
    }
    owner.require_payload(h.request)
    reopened = CohortModelUploads(owner.config, h.intake, owner.archive)
    report = reopened.poll_once()
    assert report["model_reviews_ready"] == 1
    assert target.read_bytes() == first


def test_standing_policy_retains_machine_readable_document_hold(delivery, tmp_path):
    h = delivery
    reviews = tmp_path / "held-reviews"
    owner = CohortModelUploads(
        ModelUploadConfig(
            directory=str(tmp_path / "held-delivery"),
            admission_reviews_directory=str(reviews),
            standing_review_policy=standing_review_policy(
                h, maximum_document_bytes=1, maximum_total_document_bytes=1
            ),
            maximum_reserved_bytes=1024**3,
        ),
        h.intake,
        h.owner.archive,
    )
    key = owner.reserve(h.request, capture_at(210))
    upload_all(h, owner, key)
    report = owner.poll_once()
    assert report["model_reviews_held"] == 1
    assert report["last_review_hold_reason"] == "review_document_size_outside_policy"
    assert len(owner.journal.keys("review_hold")) == 1
    with pytest.raises(PendingModelReview, match="review_document_size_outside_policy"):
        owner.require_payload(h.request)


def test_standing_policy_must_bind_live_policy_and_review_store(delivery, tmp_path):
    h = delivery
    standing = standing_review_policy(h)
    with pytest.raises(ValueError, match="review directory"):
        ModelUploadConfig(
            directory=str(tmp_path / "delivery-without-review-store"),
            standing_review_policy=standing,
            maximum_reserved_bytes=1024**3,
        )
    with pytest.raises(ValueError, match="another competition policy"):
        CohortModelUploads(
            ModelUploadConfig(
                directory=str(tmp_path / "wrong-policy-delivery"),
                admission_reviews_directory=str(tmp_path / "wrong-policy-reviews"),
                standing_review_policy=standing.model_copy(
                    update={"competition_policy_sha256": "cd" * 32}
                ),
                maximum_reserved_bytes=1024**3,
            ),
            h.intake,
            h.owner.archive,
        )


def test_historical_model_upload_config_omits_new_review_field(delivery, tmp_path):
    del delivery
    config = ModelUploadConfig(directory=str(tmp_path / "delivery"), maximum_reserved_bytes=1024**3)
    assert "admission_reviews_directory" not in canonical_json_bytes(config).decode()
    assert "standing_review_policy" not in canonical_json_bytes(config).decode()


@pytest.mark.parametrize("failure", ["length", "digest", "signer", "oversize", "gap", "prefix"])
def test_invalid_chunk_keeps_retained_prefix(delivery, failure):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    record = h.request.signed_submission.submission.model_bundle.files[0]
    data = (h.source / record.path).read_bytes()
    put(h.owner, key, 0, data[:1])
    candidate = data
    offset = 0
    if failure == "oversize":
        candidate += b"x"
    if failure == "gap":
        candidate, offset = data[2:], 2
    if failure == "prefix":
        candidate = bytes([data[0] ^ 1]) + data[1:]
    chunk, signature = signed_chunk(
        key, 0, candidate, offset, "Bob" if failure == "signer" else "Alice"
    )
    if failure == "length":
        candidate = candidate[:-1]
    if failure == "digest":
        candidate = b"x" * len(candidate)
    with pytest.raises(ValueError):
        h.owner.put_chunk(chunk, signature, candidate)
    assert h.owner.status(key)["file_offsets"][0] == 1
    upload_all(h, h.owner, key)


def test_full_hash_failure_resets_only_bad_file_and_can_retry(delivery):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    records = h.request.signed_submission.submission.model_bundle.files
    put(h.owner, key, 0, (h.source / records[0].path).read_bytes())
    put(h.owner, key, 1, b"x" * records[1].size_bytes)
    report = h.owner.poll_once()
    assert report["last_error_type"] == "ValueError"
    status = h.owner.status(key)
    assert status["complete_files"] == [0] and status["file_offsets"][1] == 0
    upload_all(h, h.owner, key)


def test_capacity_reservation_can_be_increased_without_state_reset(delivery):
    h = delivery
    bounded = CohortModelUploads(
        h.owner.config.model_copy(update={"maximum_reserved_bytes": 1}), h.intake, h.owner.archive
    )
    with pytest.raises(OSError, match="capacity"):
        bounded.reserve(h.request, capture_at(210))
    assert bounded.journal.keys("upload") == []
    key = h.owner.reserve(h.request, capture_at(210))
    assert h.owner.retained(key) == h.request


def test_links_and_concurrent_writers_cannot_replace_originals(delivery, tmp_path):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    bundle, stage = h.owner._paths(key)
    data = (h.source / bundle.files[0].path).read_bytes()
    lease = lock_private_file(stage / "upload.lock")
    try:
        with pytest.raises(BlockingIOError):
            put(h.owner, key, 0, data)
    finally:
        os.close(lease)
    outside = tmp_path / "outside"
    outside.write_bytes(b"keep")
    (stage / "partial-0").symlink_to(outside)
    with pytest.raises(OSError):
        put(h.owner, key, 0, data)
    assert outside.read_bytes() == b"keep"
    (stage / "partial-0").unlink()
    upload_all(h, h.owner, key)
    path = stage / "model" / bundle.files[0].path
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(b"x" * len(data))
    path.chmod(0o600)
    put(h.owner, key, 0, data)  # Original archive wins over local staging.
    assert path.exists()
    assert h.owner.poll_once()["models_preserved"] == 1
    assert_staging_released(h.owner, key)
    h.owner.require_payload(h.request)


def test_restart_after_verified_file_rename_before_permissions(delivery):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    bundle, stage = h.owner._paths(key)
    data = (h.source / bundle.files[0].path).read_bytes()
    put(h.owner, key, 0, data)
    (stage / "partial-0").rename(stage / "model" / bundle.files[0].path)
    reopened = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    assert reopened.status(key)["file_offsets"][0] == len(data)
    upload_all(h, reopened, key)
    assert_staging_released(reopened, key)


def test_killed_archive_copy_is_retried_without_orphan_accumulation(delivery):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    for i, record in enumerate(h.request.signed_submission.submission.model_bundle.files):
        put(h.owner, key, i, (h.source / record.path).read_bytes())
    # Kill a real child during the copy, bypassing Python finally cleanup.
    script = """
import os, sys
from pathlib import Path
import umi.competition_artifacts as a
from umi.competition_cohort_intake import CohortIntake, CohortIntakeConfig
from umi.competition_cohort_model_upload import CohortModelUploads, ModelUploadConfig
from umi.open_competition import CompetitionPolicy
root=Path(sys.argv[1])
policy=CompetitionPolicy.model_validate_json((root/'policy.json').read_bytes())
intake=CohortIntake(CohortIntakeConfig.model_validate_json((root/'intake.json').read_bytes()),policy,eligible_tracks=('endpoint','model'))
uploads=CohortModelUploads(ModelUploadConfig.model_validate_json((root/'uploads.json').read_bytes()),intake,Path(sys.argv[2]))
a._copy_verified=lambda *args: os._exit(73)
uploads.complete(sys.argv[3])
"""
    root = h.source.parent.parent / "child"
    root.mkdir()
    for name, value in (
        ("policy", h.intake.policy),
        ("intake", h.intake.config),
        ("uploads", h.owner.config),
    ):
        (root / (name + ".json")).write_bytes(canonical_json_bytes(value))
    child = subprocess.run(
        [sys.executable, "-B", "-c", script, str(root), str(h.owner.archive), key],
        capture_output=True,
        timeout=30,
    )
    assert child.returncode == 73, child.stderr.decode()
    assert len(list(h.owner.archive.glob(".pending-*"))) == 1
    assert not h.owner.status(key)["payload_preserved"]
    assert h.owner.poll_once()["models_preserved"] == 1
    assert not list(h.owner.archive.glob(".pending-*"))
    h.owner.require_payload(h.request)


@pytest.mark.asyncio
async def test_public_delivery_retries_offline_then_enrolls_only_complete_model(delivery):
    h = delivery
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://intake.example"
    ) as client:
        body = canonical_json_bytes(h.request)
        enroll = f"/v1/competition/cohorts/{h.cohort}/participation"
        reserve = f"/v1/competition/cohorts/{h.cohort}/model-uploads"
        r = await client.post(enroll, content=body, headers={"content-type": "application/json"})
        assert r.status_code == 503
        r = await client.post(reserve, content=body, headers={"content-type": "application/json"})
        assert r.status_code == 200, r.text
        key = r.json()["upload_sha256"]
        h.online = False
        captured = h.captures
        r = await client.post(reserve, content=body, headers={"content-type": "application/json"})
        assert r.status_code == 200 and h.captures == captured
        for i, record in enumerate(h.request.signed_submission.submission.model_bundle.files):
            data = (h.source / record.path).read_bytes()
            r = await client.put(
                f"/v1/competition/model-uploads/{key}/files/{i}",
                content=data,
                headers=chunk_headers(key, i, data),
            )
            assert r.status_code == 200, r.text
        assert r.json()["payload_preserved"] is False
        assert h.owner.poll_once()["models_preserved"] == 1
        r = await client.get(f"/v1/competition/model-uploads/{key}")
        assert r.json()["payload_preserved"] is True
        assert h.intake.receipt(h.request) is None
        h.online = True
        r = await client.post(enroll, content=body, headers={"content-type": "application/json"})
        assert r.status_code == 200, r.text
        assert h.intake.receipt(h.request) is not None


@pytest.mark.asyncio
async def test_cancelled_http_body_keeps_previously_committed_chunk(delivery):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    record = h.request.signed_submission.submission.model_bundle.files[0]
    data = (h.source / record.path).read_bytes()
    put(h.owner, key, 0, data[:1])
    entered = asyncio.Event()
    waiting = asyncio.Event()

    async def body():
        yield data[1:2]
        entered.set()
        await waiting.wait()

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://intake.example"
    ) as client:
        task = asyncio.create_task(
            client.put(
                f"/v1/competition/model-uploads/{key}/files/0?offset=1",
                content=body(),
                headers=chunk_headers(key, 0, data[1:], 1),
            )
        )
        await asyncio.wait_for(entered.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    assert h.owner.status(key)["file_offsets"][0] == 1
    upload_all(h, h.owner, key)


@pytest.mark.asyncio
async def test_delivery_http_reports_native_failure_stage_and_preserves_reservation(
    delivery, monkeypatch
):
    from umi import competition_progress as progress

    h = delivery
    reports = []
    monkeypatch.setattr(progress, "_emit", lambda body, **_kwargs: reports.append(body))
    original = h.owner.status
    secret = "private model data https://private.example/?token=hidden"

    def unavailable(_key):
        raise OSError(secret)

    monkeypatch.setattr(h.owner, "status", unavailable)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=h.app), base_url="https://intake.example"
    ) as client:
        response = await client.post(
            f"/v1/competition/cohorts/{h.cohort}/model-uploads",
            content=canonical_json_bytes(h.request),
            headers={"Content-Type": "application/json"},
        )
        assert response.status_code == 503
        assert reports[-1]["stage"] == "status"
        assert reports[-1]["operation"] == "model_delivery"
        assert secret not in str(reports) and secret not in response.text
        key = h.owner.retry(h.request)
        assert key is not None
        monkeypatch.setattr(h.owner, "status", original)
        retry = await client.post(
            f"/v1/competition/cohorts/{h.cohort}/model-uploads",
            content=canonical_json_bytes(h.request),
            headers={"Content-Type": "application/json"},
        )
        assert retry.status_code == 200
        assert h.owner.retry(h.request) == key


@pytest.fixture
def retained_decode(delivery, monkeypatch):
    h = delivery
    key = h.owner.reserve(h.request, capture_at(210))
    original = type(h.request).model_validate_json
    calls = []

    def counted(cls, raw):
        calls.append(raw)
        return original(raw)

    monkeypatch.setattr(type(h.request), "model_validate_json", classmethod(counted))
    return h, key, calls


def test_retained_upload_decode_reuse_keeps_private_results(retained_decode):
    h, key, calls = retained_decode
    expected = h.owner.retained(key)
    caller = h.owner.retained(key)
    object.__setattr__(caller.signed_submission.submission, "model_revision", "f" * 64)
    assert h.owner.retained(key) == expected
    assert len(calls) == 1


@pytest.mark.parametrize("change", ["hold", "delete", "replace", "noncanonical"])
def test_retained_upload_decode_reads_current_journal_fence(retained_decode, change):
    h, key, calls = retained_decode
    h.owner.retained(key)
    with h.owner.journal.transaction() as db:
        if change == "hold":
            db.execute("INSERT INTO holds VALUES (?)", (key,))
        elif change == "delete":
            db.execute("DELETE FROM records WHERE kind='upload' AND id=?", (key,))
        elif change == "replace":
            changed = h.request.model_copy(
                update={
                    "signed_submission": h.request.signed_submission.model_copy(
                        update={
                            "submission": h.request.signed_submission.submission.model_copy(
                                update={
                                    "model_revision": "f" * 64,
                                }
                            ),
                        }
                    ),
                }
            )
            db.execute(
                "UPDATE records SET body=? WHERE kind='upload' AND id=?",
                (canonical_json_bytes(changed), key),
            )
        else:
            raw = db.execute(
                "SELECT body FROM records WHERE kind='upload' AND id=?", (key,)
            ).fetchone()[0]
            db.execute("UPDATE records SET body=? WHERE kind='upload' AND id=?", (raw + b" ", key))
    for _ in range(2):
        with pytest.raises((ValueError, FileNotFoundError)):
            h.owner.retained(key)
    # Replacement schema failures/identity failures never enter reuse.
    assert len(calls) == (3 if change == "replace" else 1)


def test_retained_upload_decode_refuses_inherited_process_results(retained_decode):
    h, key, calls = retained_decode
    expected = h.owner.retained(key)
    h.owner._retained_reuse._pid = -1
    assert h.owner.retained(key) == expected
    assert len(calls) == 2


def test_retained_upload_decode_eviction_preserves_native_result(retained_decode):
    h, key, calls = retained_decode
    h.owner._retained_reuse.maximum_bytes = 1
    assert h.owner.retained(key) == h.request
    assert h.owner.retained(key) == h.request
    assert len(calls) == 2


def test_original_journal_allocation_migration_is_atomic_and_preserves_signed_bytes(delivery):
    h, owner = delivery, delivery.owner
    key = owner.reserve(h.request, capture_at(210))
    originals = {
        kind: {key: owner.journal.get_raw(kind, key) for key in owner.journal.keys(kind)}
        for kind in ("upload", "bundle")
    }
    # Reconstruct the supported pre-ledger layout, leaving original bytes exact.
    with owner.journal.transaction() as db:
        db.execute("DROP TABLE model_allocation_state")
        db.execute("DROP TABLE model_allocation_identity")
        db.execute("DELETE FROM records WHERE kind='model_allocation'")
    for _ in range(2):
        owner = CohortModelUploads(owner.config, h.intake, owner.archive)
        expected = 2 * sum(
            f.size_bytes for f in h.request.signed_submission.submission.model_bundle.files
        )
        assert owner.allocations.snapshot()["active_reserved_bytes"] == expected
        assert owner.reserve(h.request, capture_at(210)) == key
        for kind, entries in originals.items():
            assert {
                key: owner.journal.get_raw(kind, key) for key in owner.journal.keys(kind)
            } == entries


@pytest.mark.parametrize("damage", ["allocation", "index", "schema", "version"])
def test_missing_model_allocation_requires_explicit_repair(delivery, damage):
    h, owner = delivery, delivery.owner
    key = owner.reserve(h.request, capture_at(210))
    with owner.journal.transaction() as db:
        if damage == "allocation":
            db.execute("DELETE FROM records WHERE kind='model_allocation'")
        elif damage == "index":
            db.execute("DELETE FROM model_allocation_state")
        elif damage == "schema":
            db.execute("DROP TABLE model_allocation_state")
        else:
            db.execute("UPDATE model_allocation_identity SET schema='unsupported'")
    with pytest.raises(ModelAllocationRepairRequired):
        owner.status(key)
    with pytest.raises(ModelAllocationRepairRequired):
        CohortModelUploads(owner.config, h.intake, owner.archive)


def _prepare_accounting_release(owner, model):
    # Exercise private accounting ports only. This is not remote verification or
    # consumer-release authority; no configured production caller issues these.
    with owner.journal.locked():
        owner.allocations._transition(model, "remote_qualified", evidence={"fixture": "qualified"})
        owner.allocations._transition(model, "release_prepared", evidence={"fixture": "released"})


def test_reservation_refund_requires_full_unlink_and_survives_restart(delivery):
    h, owner = delivery, delivery.owner
    key = owner.reserve(h.request, capture_at(210))
    upload_all(h, owner, key)
    model = h.request.signed_submission.submission.model_revision
    expected = owner.allocations.snapshot()["active_reserved_bytes"]
    stage, archive = owner.root / "files" / model, owner.archive / model
    originals = {
        kind: owner.journal.get_raw(kind, key if kind == "upload" else model)
        for kind in ("upload", "bundle", "preserved")
    }
    _prepare_accounting_release(owner, model)
    assert owner.allocations.snapshot()["active_reserved_bytes"] == expected
    with pytest.raises(OSError, match="local payloads"):
        owner.allocations._complete_release(model)
    shutil.rmtree(archive / "model")
    restarted = CohortModelUploads(owner.config, h.intake, owner.archive)
    assert restarted.allocations.snapshot()["active_reserved_bytes"] == expected
    with pytest.raises(OSError, match="local payloads"):
        restarted.allocations._complete_release(model)
    shutil.rmtree(stage / "model")
    (stage / "partial-0").write_bytes(b"interrupted")
    with pytest.raises(OSError, match="interrupted upload"):
        restarted.allocations._complete_release(model)
    assert restarted.allocations.snapshot()["active_reserved_bytes"] == expected
    (stage / "partial-0").unlink()
    pending = owner.archive / (".pending-" + model)
    pending.mkdir(mode=0o700)
    (pending / "uncommitted").write_bytes(b"copied before process death")
    with pytest.raises(OSError, match="interrupted archive"):
        restarted.allocations._complete_release(model)
    assert restarted.allocations.snapshot()["active_reserved_bytes"] == expected
    shutil.rmtree(pending)
    with restarted.journal.locked():
        restarted.allocations._complete_release(model)
        restarted.allocations._complete_release(model)
    reopened = CohortModelUploads(owner.config, h.intake, owner.archive)
    assert reopened.allocations.snapshot()["active_reserved_bytes"] == 0
    assert reopened.allocations.snapshot()["released_reserved_bytes"] == expected
    assert (archive / "manifest.json").exists()
    for kind, raw in originals.items():
        assert reopened.journal.get_raw(kind, key if kind == "upload" else model) == raw


@pytest.mark.parametrize("phase", ["release_prepared", "released"])
def test_every_stale_retry_is_fenced_before_local_payload_recreation(delivery, phase):
    h, owner = delivery, delivery.owner
    key = owner.reserve(h.request, capture_at(210))
    upload_all(h, owner, key)
    bundle = h.request.signed_submission.submission.model_bundle
    model = digest(bundle)
    stage = owner.root / "files" / model
    _prepare_accounting_release(owner, model)
    shutil.rmtree(owner.archive / model / "model")
    shutil.rmtree(stage / "model")
    if phase == "released":
        with owner.journal.locked():
            owner.allocations._complete_release(model)
    restarted = CohortModelUploads(owner.config, h.intake, owner.archive)
    assert restarted.reserve(h.request, None) == key
    assert restarted.retry(h.request) == key
    for _ in range(2):
        with pytest.raises(OSError, match="fenced"):
            restarted.status(key)
        with pytest.raises(OSError, match="fenced"):
            restarted.complete(key)
        with pytest.raises(OSError, match="fenced"):
            put(restarted, key, 0, (h.source / bundle.files[0].path).read_bytes())
        assert restarted.poll_once()["models_pending"] == 1
        assert not (stage / "model").exists()
        assert not (owner.archive / model / "model").exists()
        assert not list(stage.glob("partial-*"))


@pytest.mark.parametrize("failure", ["commit", "archive_fsync"])
def test_refund_failure_before_commit_keeps_charge_and_can_resume(delivery, monkeypatch, failure):
    h, owner = delivery, delivery.owner
    key = owner.reserve(h.request, capture_at(210))
    upload_all(h, owner, key)
    model = h.request.signed_submission.submission.model_revision
    _prepare_accounting_release(owner, model)
    charged = owner.allocations.snapshot()["active_reserved_bytes"]
    shutil.rmtree(owner.archive / model / "model")
    shutil.rmtree(owner.root / "files" / model / "model")
    original = owner.journal.put_many

    def fail_before_commit(records, *, index=None):
        def interrupted(db):
            index(db)
            raise OSError("interrupted before accounting commit")

        return original(records, index=interrupted)

    with monkeypatch.context() as patch:
        if failure == "commit":
            patch.setattr(owner.journal, "put_many", fail_before_commit)
        else:
            original_sync = os.fsync
            archive_info = owner.archive.stat()

            def interrupted_archive_sync(descriptor):
                info = os.fstat(descriptor)
                if (info.st_dev, info.st_ino) == (archive_info.st_dev, archive_info.st_ino):
                    raise OSError("interrupted archive directory fsync")
                return original_sync(descriptor)

            patch.setattr(os, "fsync", interrupted_archive_sync)
        with pytest.raises(OSError, match="interrupted"):
            owner.allocations._complete_release(model)
    assert owner.allocations.snapshot()["active_reserved_bytes"] == charged
    assert owner.allocations.state(model) == "release_prepared"
    assert owner.journal.get("model_release_completed", model) is None
    owner.allocations._complete_release(model)
    assert owner.allocations.snapshot()["active_reserved_bytes"] == 0


@pytest.mark.parametrize("missing", ["row", "table"])
def test_allocation_index_repair_preserves_release_fence_and_reports_progress(delivery, missing):
    h, owner = delivery, delivery.owner
    key = owner.reserve(h.request, capture_at(210))
    model = h.request.signed_submission.submission.model_revision
    _prepare_accounting_release(owner, model)
    expected = owner.allocations.snapshot()
    with owner.journal.transaction() as db:
        db.execute(
            "DELETE FROM model_allocation_state"
            if missing == "row"
            else "DROP TABLE model_allocation_state"
        )
    reports = []
    repair_model_allocation_index(owner.journal, report=reports.append)
    assert owner.allocations.snapshot() == expected
    repair_model_allocation_index(owner.journal, report=reports.append)
    assert owner.allocations.snapshot() == expected
    with pytest.raises(OSError, match="fenced"):
        owner.status(key)
    assert reports[-1]["status"] == "completed"
    assert reports[-1]["eta_seconds"] == 0
    assert any(report["planning_eta_seconds"] is not None for report in reports)


def test_allocation_repair_never_downgrades_a_lost_release_transition(delivery):
    h, owner = delivery, delivery.owner
    owner.reserve(h.request, capture_at(210))
    model = h.request.signed_submission.submission.model_revision
    _prepare_accounting_release(owner, model)
    with owner.journal.transaction() as db:
        db.execute("DELETE FROM records WHERE kind='model_release_prepared'")
    with pytest.raises(ModelAllocationRepairRequired, match="lost allocation transition"):
        repair_model_allocation_index(owner.journal)
    with pytest.raises(ModelAllocationRepairRequired):
        owner.allocations.snapshot()


def test_distinct_signed_requests_share_one_charge_and_cannot_inherit_a_refund(delivery):
    h, owner = delivery, delivery.owner
    original_key = owner.reserve(h.request, capture_at(210))
    original_charge = owner.allocations.snapshot()["active_reserved_bytes"]

    def request_at(block):
        consent = h.request.consent.consent.model_copy(update={"signed_at_block": block})
        return h.request.model_copy(
            update={
                "consent": h.request.consent.model_copy(
                    update={
                        "consent": consent,
                        "signature": sign_object(consent, wallet("Alice")),
                    }
                )
            }
        )

    second = request_at(211)
    second_key = owner.reserve(second, capture_at(211))
    assert second_key != original_key
    assert owner.allocations.snapshot()["active_reserved_bytes"] == original_charge
    assert owner.allocations.snapshot()["models"] == 1
    assert owner.retained(original_key) == h.request
    assert owner.retained(second_key) == second
    _prepare_accounting_release(owner, h.request.signed_submission.submission.model_revision)
    with pytest.raises(OSError, match="fenced"):
        owner.reserve(request_at(212), capture_at(212))
    assert owner.journal.keys("upload") == sorted([original_key, second_key])
