"""A provider copy reuses bytes only through retained immutable source lineage."""

import asyncio
import hashlib
import json
from pathlib import Path

import pytest

from umi import competition_cohort_promotion_copy as copy
from umi.competition_cohort_direct_model_owner import DirectModelUploadOwner
from umi.competition_cohort_direct_model_upload import (
    SignedDirectModelUploadCompletion,
    preserved_model_object_key,
)
from umi.open_competition import digest, sign_object
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
    promotion_publication,
    signed_completion,
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


async def ready(direct):
    reservation = await direct.owner.reserve(direct.request, direct.payload, now_unix_ms=NOW)
    completed = await direct.owner.complete(
        signed_completion(reservation, direct.payload.payload), now_unix_ms=NOW + 1
    )
    await direct.owner.verify(completed.reservation_sha256, now_unix_ms=NOW + 2)
    publication = promotion_publication(direct, reservation)
    source = direct.owner.journal.get("direct-intent", reservation.reservation.attempt_id)[
        "object_key"
    ]
    payload = reservation.reservation.payload
    target = preserved_model_object_key(
        reservation.reservation.cohort_sha256, payload.model_sha256, payload.payload_sha256
    )
    return publication, source, target


def restart(direct):
    direct.owner = DirectModelUploadOwner(
        direct.owner.config,
        direct.multipart,
        authorize=direct.owner.authorize,
        sign=direct.owner.sign,
    )


def bytes_root(direct, key):
    return (
        Path(direct.owner.config.directory)
        / "byte-verification"
        / hashlib.sha256(key.encode()).hexdigest()
    )


async def test_copy_retains_proof_before_bytes_and_downstream_reuses_without_reads(
    direct, monkeypatch, caplog
):
    publication, source, target = await ready(direct)
    before = direct.multipart.read_calls
    original = copy.remember_model_bytes
    observed = []

    def persist(saved, remote, payload, documents):
        assert direct.owner.journal.get(
            "direct-copy-proof", digest(publication.certificate.acceptance)
        )
        assert source in direct.multipart.objects
        observed.append(remote["key_sha256"])
        return original(saved, remote, payload, documents)

    monkeypatch.setattr(copy, "remember_model_bytes", persist)
    with caplog.at_level("INFO"):
        receipt = await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert observed == [hashlib.sha256(target.encode()).hexdigest()]
    restart(direct)
    assert direct.owner.promoted_payload(publication)[2] == receipt
    assert await direct.owner.promote(publication, now_unix_ms=NOW + 4) == receipt
    assert direct.multipart.read_calls == before
    assert source not in direct.multipart.objects
    assert '"restored_units":1' in caplog.text


@pytest.mark.parametrize("stage", ["part", "manifest", "proof", "bytes", "promotion"])
async def test_copy_resumes_at_each_durable_boundary(direct, monkeypatch, stage):
    publication, source, target = await ready(direct)
    before = direct.multipart.read_calls
    original_put, original_remember = direct.owner.journal.put, copy.remember_model_bytes
    tripped = False

    def put(kind, key, value):
        nonlocal tripped
        result = original_put(kind, key, value)
        wanted = "direct-promotion" if stage == "promotion" else "direct-copy-" + stage
        if kind == wanted and not tripped:
            tripped = True
            raise OSError("interrupted durable boundary")
        return result

    def remember(*args):
        nonlocal tripped
        original_remember(*args)
        if stage == "bytes" and not tripped:
            tripped = True
            raise OSError("interrupted durable boundary")

    monkeypatch.setattr(direct.owner.journal, "put", put)
    monkeypatch.setattr(copy, "remember_model_bytes", remember)
    with pytest.raises(OSError, match="interrupted durable boundary"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert source in direct.multipart.objects
    copied, created = len(direct.multipart.copy_calls), len(direct.multipart.create_calls)
    restart(direct)
    receipt = await direct.owner.promote(publication, now_unix_ms=NOW + 4)
    assert direct.owner.promoted_payload(publication)[2] == receipt
    assert direct.multipart.read_calls == before
    assert len(direct.multipart.copy_calls) == copied
    assert len(direct.multipart.create_calls) == created
    assert source not in direct.multipart.objects and target in direct.multipart.objects


async def test_lost_complete_reply_uses_manifest_and_exact_provider_identity(direct):
    publication, source, _ = await ready(direct)
    before = direct.multipart.read_calls
    direct.multipart.fail_after_complete = True
    receipt = await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert direct.owner.promoted_payload(publication)[2] == receipt
    assert direct.multipart.read_calls == before
    assert source not in direct.multipart.objects


@pytest.mark.parametrize("damage", ["missing", "malformed"])
async def test_copy_requires_undamaged_completed_source_byte_fact(direct, damage):
    publication, source, target = await ready(direct)
    result = bytes_root(direct, source) / "result.json"
    if damage == "missing":
        result.unlink()
    else:
        result.write_bytes(b"{}")
    with pytest.raises(OSError, match="requires repair"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert not direct.multipart.copy_calls
    assert source in direct.multipart.objects and target not in direct.multipart.objects


async def test_copy_refuses_provider_part_mismatch(direct, monkeypatch):
    publication, source, target = await ready(direct)
    original = direct.multipart.copy_part

    async def wrong(*args, **kwargs):
        part = await original(*args, **kwargs)
        return part.model_copy(update={"etag": "f" * 32})

    monkeypatch.setattr(direct.multipart, "copy_part", wrong)
    with pytest.raises(ValueError, match="provider part differs"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert source in direct.multipart.objects and target not in direct.multipart.objects


@pytest.mark.parametrize("changed", ["source", "destination"])
async def test_copy_fences_both_provider_generations(direct, monkeypatch, changed):
    publication, source, target = await ready(direct)
    original = direct.multipart.complete

    async def complete(*args, **kwargs):
        etag = await original(*args, **kwargs)
        key = source if changed == "source" else target
        direct.multipart.objects[key] = (direct.multipart.total_bytes, "changed-etag")
        return etag

    monkeypatch.setattr(direct.multipart, "complete", complete)
    with pytest.raises(ValueError, match=r"copy (source|destination) changed"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert (
        direct.owner.journal.get("direct-copy-proof", digest(publication.certificate.acceptance))
        is None
    )
    assert source in direct.multipart.objects
    assert not (bytes_root(direct, target) / "result.json").exists()


@pytest.mark.parametrize("kind", ["intent", "upload", "part", "manifest", "proof"])
async def test_damaged_completed_copy_metadata_cannot_stamp_bytes(direct, monkeypatch, kind):
    publication, source, target = await ready(direct)
    original_remember = copy.remember_model_bytes

    def stop(*args):
        raise OSError("stop before byte facts")

    monkeypatch.setattr(copy, "remember_model_bytes", stop)
    with pytest.raises(OSError, match="stop before byte facts"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    # Owned test journal corruption, never a production mutation.
    with direct.owner.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=?",
            (
                canonical_json_bytes({"damaged": True}),
                "direct-copy-" + kind,
            ),
        )
    monkeypatch.setattr(copy, "remember_model_bytes", original_remember)
    restart(direct)
    with pytest.raises((ValueError, OSError)):
        await direct.owner.promote(publication, now_unix_ms=NOW + 4)
    assert source in direct.multipart.objects
    assert not (bytes_root(direct, target) / "result.json").exists()


@pytest.mark.parametrize("verified", [False, True])
async def test_existing_destination_keeps_legacy_native_or_cached_path(direct, verified):
    publication, source, target = await ready(direct)
    direct.multipart.objects[target] = (direct.multipart.total_bytes, "legacy-etag")
    if verified:
        bundle = direct.request.signed_submission.submission.model_bundle
        await direct.owner._verify_object(target, bundle, direct.payload.payload)
    before = direct.multipart.read_calls
    receipt = await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert direct.multipart.read_calls == before + (0 if verified else 1)
    assert not direct.multipart.copy_calls
    assert (
        direct.owner.journal.get("direct-copy-proof", digest(publication.certificate.acceptance))
        is None
    )
    assert direct.owner.promoted_payload(publication)[2] == receipt
    assert source not in direct.multipart.objects


async def test_retained_promotion_never_cleans_source_with_missing_destination_bytes(direct):
    publication, source, target = await ready(direct)
    direct.multipart.fail_deletes = 1
    with pytest.raises(OSError, match="delete response lost"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    (bytes_root(direct, target) / "result.json").unlink()
    restart(direct)
    with pytest.raises(OSError, match="requires repair"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 4)
    assert source in direct.multipart.objects


async def test_cancelled_copy_drains_workers_and_resumes_same_provider(direct, monkeypatch):
    publication, source, _ = await ready(direct)
    original = direct.multipart.copy_part
    started, ended = asyncio.Event(), asyncio.Event()

    async def interrupted(*args, **kwargs):
        started.set()
        try:
            await asyncio.Future()
        finally:
            ended.set()

    monkeypatch.setattr(direct.multipart, "copy_part", interrupted)
    task = asyncio.create_task(direct.owner.promote(publication, now_unix_ms=NOW + 3))
    waiting = asyncio.create_task(started.wait())
    await asyncio.wait((task, waiting), return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        waiting.cancel()
        await asyncio.gather(waiting, return_exceptions=True)
        await task
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert ended.is_set() and source in direct.multipart.objects
    creates = len(direct.multipart.create_calls)
    monkeypatch.setattr(direct.multipart, "copy_part", original)
    restart(direct)
    await direct.owner.promote(publication, now_unix_ms=NOW + 4)
    assert len(direct.multipart.create_calls) == creates


async def test_missing_retained_provider_upload_reports_specific_repair(
    direct, monkeypatch, caplog
):
    publication, source, _ = await ready(direct)
    original = direct.multipart.copy_part

    async def interrupted(*args, **kwargs):
        raise OSError("copy transient")

    monkeypatch.setattr(direct.multipart, "copy_part", interrupted)
    with pytest.raises(OSError, match="copy transient"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    direct.multipart.multipart_uploads.clear()
    creates = len(direct.multipart.create_calls)
    monkeypatch.setattr(direct.multipart, "copy_part", original)
    with caplog.at_level("INFO"), pytest.raises(OSError, match="lineage requires repair"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 4)
    assert '"reason_code":"promotion_copy_provider_upload_missing"' in caplog.text
    assert source in direct.multipart.objects
    assert len(direct.multipart.create_calls) == creates


@pytest.mark.parametrize("changed", ["generation", "part_size", "signer"])
async def test_source_completion_exact_generation_geometry_and_signer(direct, changed):
    publication, source, target = await ready(direct)
    reservation = digest(publication.certificate.acceptance.direct_artifact.reservation)
    original = SignedDirectModelUploadCompletion.model_validate_json(
        canonical_json_bytes(direct.owner.journal.get("direct-completion", reservation))
    )
    body = original.completion
    if changed == "generation":
        body = body.model_copy(update={"generation": body.generation + 1})
    elif changed == "part_size":
        part = body.parts[0].model_copy(update={"size_bytes": body.parts[0].size_bytes - 1})
        body = body.model_copy(update={"parts": (part, *body.parts[1:])})
    signed = original.model_copy(
        update={
            "completion": body,
            "signature": sign_object(body, wallet("Bob" if changed == "signer" else "Alice")),
        }
    )
    with direct.owner.journal.transaction() as db:
        db.execute(
            "UPDATE records SET body=? WHERE kind=? AND id=?",
            (
                canonical_json_bytes(signed),
                "direct-completion",
                reservation,
            ),
        )
    with pytest.raises(ValueError, match=r"source completion differs|part geometry differs"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert not direct.multipart.copy_calls
    assert source in direct.multipart.objects and target not in direct.multipart.objects


async def test_nonstandard_source_provider_etag_cannot_enter_copy_reuse(direct, monkeypatch):
    original = direct.multipart.complete

    async def opaque(*args, **kwargs):
        await original(*args, **kwargs)
        direct.multipart.objects[args[0]] = (direct.multipart.total_bytes, "opaque-provider-etag")
        return "opaque-provider-etag"

    monkeypatch.setattr(direct.multipart, "complete", opaque)
    publication, source, target = await ready(direct)
    with pytest.raises(ValueError, match="source provider completion differs"):
        await direct.owner.promote(publication, now_unix_ms=NOW + 3)
    assert not direct.multipart.copy_calls
    assert source in direct.multipart.objects and target not in direct.multipart.objects


async def test_remote_verification_progress_identifies_object_without_key(direct, caplog):
    with caplog.at_level("INFO"):
        _, source, _ = await ready(direct)
    events = [
        json.loads(record.message)
        for record in caplog.records
        if record.message.startswith('{"source_object_key_sha256"')
    ]
    assert events
    assert all(event["model_sha256"] == direct.payload.payload.model_sha256 for event in events)
    assert all(event["object_role"] == "source" for event in events)
    assert all(
        event["source_object_key_sha256"] == hashlib.sha256(source.encode()).hexdigest()
        for event in events
    )
    assert source not in caplog.text
