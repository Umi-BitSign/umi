"""Model retries preserve completed native checks without changing signed bytes."""

import hashlib
import json

import pytest

from umi import competition_cohort_model_client as client
from umi import competition_model_source_verification as source_verification

from .test_competition_cohort_model_upload import base_policy as base_policy
from .test_competition_cohort_model_upload import delivery as delivery
from .test_competition_cohort_model_upload import legacy_scenario as legacy_scenario
from .test_competition_cohort_model_upload import policy as policy
from .test_competition_cohort_model_upload import receipt_scenario as receipt_scenario
from .test_competition_cohort_model_upload import recovery as recovery
from .test_competition_cohort_model_upload import runtime as runtime

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


@pytest.fixture(autouse=True)
def private_source_receipts(tmp_path, monkeypatch):
    monkeypatch.setenv("UMI_MODEL_VERIFICATION_DIRECTORY", str(tmp_path / "verification"))


def verify(h, report=None):
    return client._verify_source(
        h.source, h.request.signed_submission.submission.model_bundle, h.intake.policy, report
    )


def test_restart_restores_every_file_without_payload_reads(delivery, monkeypatch):
    h = delivery
    first = verify(h)

    def forbidden(*_):
        pytest.fail("unchanged verified source was reread")

    monkeypatch.setattr(source_verification, "_copy_verified", forbidden)
    events = []
    assert verify(h, events.append) == first
    assert events[-1]["restored_bytes"] == events[-1]["total_bytes"]
    assert events[-1]["native_bytes"] == 0


def test_interruption_preserves_completed_files_and_rechecks_only_remaining(delivery, monkeypatch):
    h = delivery
    native = source_verification._copy_verified
    checked = []

    def interrupt(stream, record, output):
        checked.append(record.path)
        if len(checked) == 2:
            raise KeyboardInterrupt
        return native(stream, record, output)

    monkeypatch.setattr(source_verification, "_copy_verified", interrupt)
    with pytest.raises(KeyboardInterrupt):
        verify(h)
    first = checked[0]
    checked.clear()

    def resume(stream, record, output):
        checked.append(record.path)
        return native(stream, record, output)

    monkeypatch.setattr(source_verification, "_copy_verified", resume)
    verify(h)
    assert first not in checked
    assert len(checked) == len(h.request.signed_submission.submission.model_bundle.files) - 1


@pytest.mark.parametrize("fault", ["missing", "damaged", "changed_identity"])
def test_scoped_repair_reuses_other_files(delivery, monkeypatch, fault):
    h = delivery
    bundle = h.request.signed_submission.submission.model_bundle
    verify(h)
    root = source_verification.source_checkpoint_root(h.source, bundle)
    slot = hashlib.sha256(
        json.dumps(bundle.files[0].path, separators=(",", ":")).encode()
    ).hexdigest()
    receipt = root / (slot + ".json")
    if fault == "missing":
        receipt.unlink()
    elif fault == "damaged":
        receipt.write_bytes(b"[]")
    else:
        original = h.source / bundle.files[0].path
        original.write_bytes(original.read_bytes())
    native = source_verification._copy_verified
    checked = []

    def counted(stream, record, output):
        checked.append(record.path)
        return native(stream, record, output)

    monkeypatch.setattr(source_verification, "_copy_verified", counted)
    events = []
    verify(h, events.append)
    assert checked == [bundle.files[0].path]
    assert any(event["status"] == "repair_required" for event in events)
    assert any(event["status"] == "repair_completed" for event in events)


def test_source_changed_after_earlier_check_is_refused(delivery, monkeypatch):
    h = delivery
    bundle = h.request.signed_submission.submission.model_bundle
    native = source_verification._copy_verified

    def changed(stream, record, output):
        native(stream, record, output)
        if record.path == bundle.files[-1].path:
            original = h.source / bundle.files[0].path
            original.write_bytes(original.read_bytes() + b"changed")

    monkeypatch.setattr(source_verification, "_copy_verified", changed)
    with pytest.raises(ValueError, match=r"declared size|changed"):
        verify(h)


def test_direct_payload_digest_restarts_without_reading_files(delivery, monkeypatch):
    h = delivery
    bundle = h.request.signed_submission.submission.model_bundle
    fingerprints = verify(h)
    expected = hashlib.sha256(
        b"".join((h.source / record.path).read_bytes() for record in bundle.files)
    ).hexdigest()
    assert (
        source_verification.model_payload_digest(
            h.source, bundle, fingerprints, client._fingerprint, h.intake.policy
        )
        == expected
    )
    native = source_verification._artifact
    from contextlib import contextmanager

    @contextmanager
    def no_read(*args):
        with native(*args) as (_stream, info):

            class Reader:
                def read(self, *_):
                    pytest.fail("completed direct payload hash reread local payload")

            yield Reader(), info

    monkeypatch.setattr(source_verification, "_artifact", no_read)
    assert (
        source_verification.model_payload_digest(
            h.source, bundle, fingerprints, client._fingerprint, h.intake.policy
        )
        == expected
    )


def test_checksum_refusal_never_persists_failed_file(delivery):
    h = delivery
    bundle = h.request.signed_submission.submission.model_bundle
    path = h.source / bundle.files[0].path
    raw = path.read_bytes()
    path.write_bytes(bytes([raw[0] ^ 1]) + raw[1:])
    with pytest.raises(ValueError, match="immutable manifest"):
        verify(h)
    assert not list(source_verification.source_checkpoint_root(h.source, bundle).glob("*.json"))


async def test_waiting_source_owner_is_cancellable_and_keeps_checkpoint_state(delivery):
    import asyncio
    import os

    from umi.private_files import ensure_private_directory, lock_private_file

    h = delivery
    bundle = h.request.signed_submission.submission.model_bundle
    root = source_verification.source_checkpoint_root(h.source, bundle)
    ensure_private_directory(root)
    descriptor = lock_private_file(root / ".verification.lock")
    events = []
    task = asyncio.create_task(
        client._verify_source_owned(h.source, bundle, h.intake.policy, events.append, 0.01)
    )
    try:
        for _ in range(100):
            if any(event["reason_code"] == "verification_owner_busy" for event in events):
                break
            await asyncio.sleep(0.01)
        assert any(event["status"] == "waiting" for event in events)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    finally:
        os.close(descriptor)
        if not task.done():
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    assert verify(h)
