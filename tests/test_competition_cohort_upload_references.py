"""Exercise native legacy polling beyond the full-request memory cache."""

import json
import logging

import pytest

from umi.competition_assignment_reuse import AssignmentVerificationReuse
from umi.competition_cohort_model_upload import CohortModelUploads
from umi.competition_cohort_participation import CohortParticipationRequest
from umi.open_competition import digest, digest_canonical_bytes, sign_object
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_model_upload import (
    base_policy as base_policy,
)
from .test_competition_cohort_model_upload import delivery as delivery
from .test_competition_cohort_model_upload import (
    legacy_scenario as legacy_scenario,
)
from .test_competition_cohort_model_upload import (
    policy as policy,
)
from .test_competition_cohort_model_upload import (
    receipt_scenario as receipt_scenario,
)
from .test_competition_cohort_model_upload import (
    recovery as recovery,
)
from .test_competition_cohort_model_upload import (
    runtime as runtime,
)
from .test_open_competition import wallet

pytestmark = pytest.mark.parametrize("receipt_scenario", ["model-awards"], indirect=True)


def duplicates(h, count=6):
    h.owner.reserve(h.request, capture_at(210))
    records = []
    for index in range(count):
        consent = h.request.consent.consent.model_copy(update={"signed_at_block": 210 + index})
        signed = h.request.consent.model_copy(
            update={"consent": consent, "signature": sign_object(consent, wallet("Alice"))}
        )
        request = h.request.model_copy(update={"consent": signed})
        records.append(("upload", digest(request), request))
    with h.owner.journal.locked():
        h.owner.journal.put_many(records)
    return h.owner.journal.keys("upload")


def decode_counter(monkeypatch):
    original = CohortParticipationRequest.model_validate_json
    calls = []

    def counted(raw, *args, **kwargs):
        calls.append(raw)
        return original(raw, *args, **kwargs)

    monkeypatch.setattr(CohortParticipationRequest, "model_validate_json", counted)
    return calls


def test_poll_deduplicates_before_decoding_beyond_cache_and_restart(delivery, monkeypatch):
    h = delivery
    keys = duplicates(h)
    h.owner._retained_reuse = AssignmentVerificationReuse(maximum_entries=2)
    calls = decode_counter(monkeypatch)
    reports = []
    assert h.owner.poll_once(report=reports.append)["models_pending"] == 1
    native = [r for r in reports if r.get("stage") == "native_model_upload_poll"]
    assert native[-1]["status"] == "completed"
    assert native[-1]["completed_units"] == len(keys)
    assert native[-1]["native_units"] == 1
    assert native[-1]["restored_units"] == len(keys) - 1
    assert len(calls) <= len(keys) + 1  # first-pass validation, then one representative
    calls.clear()
    assert h.owner.poll_once()["models_pending"] == 1
    assert len(calls) <= 1
    calls.clear()
    restarted = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    restarted._retained_reuse = AssignmentVerificationReuse(maximum_entries=2)
    assert restarted.poll_once()["models_pending"] == 1
    assert len(calls) == 1
    calls.clear()
    assert restarted.poll_once()["models_pending"] == 1
    assert not calls


def test_local_retry_reconciliation_reuses_references_after_restart(delivery, monkeypatch):
    from umi.competition_cohort_model_upload_delivery import ModelUploadDelivery

    h = delivery
    keys = duplicates(h)
    for key in keys:
        assert h.owner.retained_model(key) == h.request.signed_submission.submission.model_revision
    restarted = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    restarted._retained_reuse = AssignmentVerificationReuse(maximum_entries=2)
    calls = decode_counter(monkeypatch)
    delivery = ModelUploadDelivery(restarted)
    for _ in range(2):
        for key in keys:
            assert delivery._remote_request(key) is None
    assert not calls


def test_actual_retry_and_allocation_paths_reuse_without_full_row_reads(delivery, monkeypatch):
    from umi.competition_cohort_model_upload_delivery import ModelUploadDelivery

    h = delivery
    keys = duplicates(h)
    for key in keys:
        h.owner.retained_model(key)
    expected = h.owner.allocations.snapshot()
    restarted = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)
    original = restarted.journal.get_raw

    def no_originals(kind, key, **kwargs):
        assert kind not in {"upload", "bundle"}, "unchanged original metadata was read again"
        return original(kind, key, **kwargs)

    monkeypatch.setattr(restarted.journal, "get_raw", no_originals)
    reconciler = ModelUploadDelivery(restarted)
    for _ in range(2):
        for key in keys:
            assert reconciler._remote_request(key) is None
        assert restarted.allocations.snapshot() == expected


@pytest.mark.parametrize("damage", ["missing", "corrupt", "binding"])
def test_reference_damage_is_explicit_and_scoped_repair(delivery, monkeypatch, caplog, damage):
    h = delivery
    keys = duplicates(h)
    h.owner.poll_once()
    versions = h.owner._model_references.versions
    active_reuse = versions._reuse["umi-upload-model-reference/1"]
    receipts = list(active_reuse.directory.glob("*.json"))
    assert len(receipts) == len(keys)
    target = receipts[0]
    value = json.loads(target.read_bytes())
    damaged_key = json.loads(value["result_json"])["upload_sha256"]
    assert damaged_key in keys
    if damage == "missing":
        target.unlink()
    elif damage == "corrupt":
        target.write_bytes(b"{}")
    else:
        from umi.competition_verification_reuse import VerificationReuse

        # Publish a correctly checksummed receipt with the wrong result binding.
        for reuse in versions._reuse.values():
            if reuse.directory == target.parent:
                result = json.loads(value["result_json"])
                result["upload_sha256"] = "f" * 64
                VerificationReuse.remember(
                    reuse, value["identity"], (), canonical_json_bytes(result).decode()
                )
                break
    caplog.set_level(logging.INFO, logger="umi.competition.progress")
    calls = decode_counter(monkeypatch)
    result = h.owner.poll_once()
    assert result["last_error_type"] == "UploadReferenceRepairRequired"
    decoded_keys = [digest_canonical_bytes(raw) for raw in calls]
    assert damaged_key not in decoded_keys
    # Healthy duplicates may supply one representative after a damaged reference.
    assert len(decoded_keys) <= 1
    assert set(decoded_keys) <= set(keys) - {damaged_key}
    assert "repair_required" in caplog.text
    reports = []
    assert h.owner.repair_retained_references(report=reports.append) == {
        "status": "completed",
        "verification_receipts_repaired": 1,
    }
    assert any(r["status"] == "completed" and r["eta_seconds"] == 0 for r in reports)
    assert h.owner.poll_once()["last_error_type"] == ""


@pytest.mark.parametrize("change", ["hold", "replace", "noncanonical"])
def test_duplicate_rows_keep_current_conflict_and_exact_byte_fences(delivery, change):
    h = delivery
    keys = duplicates(h)
    h.owner.poll_once()
    # A nonrepresentative row must still be checked on every pass.
    key = keys[-1]
    with h.owner.journal.transaction() as db:
        if change == "hold":
            db.execute("INSERT INTO holds VALUES (?)", (key,))
        else:
            raw = h.owner.journal.get_raw("upload", key, db=db)
            if change == "replace":
                raw = canonical_json_bytes(h.request)
            else:
                raw += b" "
            db.execute("UPDATE records SET body=? WHERE kind='upload' AND id=?", (raw, key))
    assert h.owner.poll_once()["last_error_type"] == "ValueError"


def test_completed_reference_survives_interrupted_first_pass(delivery, monkeypatch):
    from umi.competition_verification_reuse import VerificationReuse

    h = delivery
    keys = duplicates(h)
    first = keys[0]
    raw = h.owner.journal.get_raw("upload", first)
    model = digest(h.request.signed_submission.submission.model_bundle)
    original = VerificationReuse.remember

    def lost_ack(*args):
        original(*args)
        raise OSError("lost completion acknowledgement")

    with monkeypatch.context() as interrupted:
        interrupted.setattr(VerificationReuse, "remember", lost_ack)
        with pytest.raises(OSError, match="lost completion"):
            h.owner._model_references.model(first, raw, h.owner._decode_retained)
    restarted = CohortModelUploads(h.owner.config, h.intake, h.owner.archive)

    def forbidden(*args):
        raise AssertionError("completed reference was decoded again")

    assert restarted._model_references.model(first, raw, forbidden) == (model, False)
