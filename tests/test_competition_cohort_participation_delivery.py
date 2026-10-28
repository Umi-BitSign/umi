"""Native participation/evidence recovery with synthetic provider ports."""

import asyncio
import hashlib
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest

from umi.competition_cohort_admission_queue import CohortAdmissionQueue
from umi.competition_cohort_intake import CohortIntake
from umi.competition_cohort_intake_records import read_participation
from umi.competition_cohort_participation_delivery import (
    ParticipationDelivery,
    ParticipationUnavailable,
)
from umi.competition_execution import execution_boundary
from umi.open_competition import digest
from umi.protocol import canonical_json_bytes

from .test_competition_cohort_admission_deadline import (
    DEADLINE_MS,
    clock,
    model_request,
    reservation_for,
    selected,
)
from .test_competition_cohort_consumers import scenario as scenario
from .test_competition_cohort_intake import capture_at
from .test_competition_cohort_intake import intake as intake
from .test_competition_cohort_recovery import recovery as recovery
from .test_open_competition import policy as policy


def _archive_for(capture):
    # This is an archive-envelope fixture, not a finality proof. The native
    # admission queue checks its snapshot/digest binding; independent signing
    # remains unperformed and the tests assert that no certificate is produced.
    metadata = b"participation-delivery-test-metadata"
    metadata_sha256 = hashlib.sha256(metadata).hexdigest()
    evidence = canonical_json_bytes(
        {
            "schema": "umi-competition-registration-evidence/1",
            "snapshot": capture.snapshot.model_dump(mode="json"),
            "finality": {"fixture": "not-a-finality-proof"},
            "runtime_metadata_sha256": metadata_sha256,
            "runtime_version": {},
            "storage_batches": [
                {
                    "state_root": capture.provenance["state_root"],
                    "claims": [{"key": f"0x{index:02x}", "value": "0x00"}],
                    "proof": [],
                }
                for index in range(1, 4)
            ],
        }
    )
    capture.provenance.update(
        evidence_sha256=hashlib.sha256(evidence).hexdigest(),
        metadata_sha256=metadata_sha256,
    )
    return evidence, metadata


@pytest.fixture
def delivery_case(intake, scenario, tmp_path, monkeypatch):
    config = intake.config.model_copy(update={"directory": str(tmp_path / "model-intake")})
    owner = CohortIntake(
        config, intake.policy, eligible_tracks=("endpoint", "model"), initialize=True
    )
    owner.publish(scenario["intake_history"], capture_at(210))
    owner = selected(owner, scenario)
    signed = model_request(scenario, tmp_path)
    reservation = reservation_for(signed)
    current = capture_at(210)
    evidence, metadata = _archive_for(current)
    models = SimpleNamespace(
        require_payload=Mock(),
        admission_reservation=Mock(return_value=reservation),
    )
    capture = AsyncMock(return_value=current)
    archive = AsyncMock(return_value=(evidence, metadata))
    clock(monkeypatch, DEADLINE_MS + 1)
    return SimpleNamespace(
        intake=owner,
        signed=signed,
        reservation=reservation,
        current=current,
        evidence=evidence,
        metadata=metadata,
        models=models,
        capture=capture,
        archive=archive,
        cohort=signed.consent.consent.cohort_sha256,
        consent=digest(signed.consent.consent),
    )


def _delivery(case, *, intake=None, capture=None, archive=None, models=None):
    return ParticipationDelivery(
        case.intake if intake is None else intake,
        case.capture if capture is None else capture,
        archive=case.archive if archive is None else archive,
        models=case.models if models is None else models,
    )


def _records(case, intake=None):
    return (case.intake if intake is None else intake).export_records(
        case.cohort, maximum_bytes=1024**2, maximum_records=8
    )


async def test_exact_issued_request_finishes_after_cutoff_without_another_signature(delivery_case):
    case = delivery_case
    original = canonical_json_bytes(case.signed)
    receipt = await _delivery(case).retain(case.signed)

    case.models.require_payload.assert_called_once_with(case.signed)
    case.models.admission_reservation.assert_called_once_with(case.signed)
    case.capture.assert_awaited_once_with()
    case.archive.assert_awaited_once_with(execution_boundary(case.current))
    assert canonical_json_bytes(case.signed) == original
    ((_, raw),) = _records(case)
    assert canonical_json_bytes(read_participation(raw).request) == original
    queue = CohortAdmissionQueue(case.intake)
    assert queue.evidence(case.cohort, case.consent) == (raw, case.evidence, case.metadata)
    assert queue.certificate(case.cohort, case.consent) is None
    assert receipt["status"] == "pending_attestation"
    assert receipt["certified"] is receipt["rewards_active"] is False
    assert receipt["chain_submission_authorized"] is False


async def test_evidence_failure_resumes_original_receipt_after_restart(delivery_case):
    case = delivery_case
    case.archive.side_effect = OSError("archive temporarily unavailable")
    with pytest.raises(
        ParticipationUnavailable, match="admission evidence unavailable; retry unchanged"
    ):
        await _delivery(case).retain(case.signed)
    receipt = case.intake.receipt(case.signed)
    ((_, original_raw),) = _records(case)
    assert receipt is not None

    restarted = CohortIntake(
        case.intake.config, case.intake.policy, eligible_tracks=case.intake.tracks
    )
    no_capture = AsyncMock(side_effect=AssertionError("must reuse original registration"))
    no_models = SimpleNamespace(
        require_payload=Mock(side_effect=AssertionError("must reuse preserved payload")),
        admission_reservation=Mock(side_effect=AssertionError("must reuse retained receipt")),
    )
    recovered_archive = AsyncMock(return_value=(case.evidence, case.metadata))
    delivery = _delivery(
        case, intake=restarted, capture=no_capture, archive=recovered_archive, models=no_models
    )
    assert await delivery.retain(case.signed) == receipt
    recovered_archive.assert_awaited_once_with(execution_boundary(case.current))
    assert _records(case, restarted) == ((case.consent, original_raw),)

    # A later process uses the completed evidence, even when every external port
    # is unavailable. No new registration, payload check or archive read occurs.
    no_archive = AsyncMock(side_effect=AssertionError("completed archive must be reused"))
    again = _delivery(
        case, intake=restarted, capture=no_capture, archive=no_archive, models=no_models
    )
    assert await again.retain(case.signed) == receipt
    no_capture.assert_not_called()
    no_models.require_payload.assert_not_called()
    no_models.admission_reservation.assert_not_called()
    no_archive.assert_not_called()
    assert CohortAdmissionQueue(restarted).certificate(case.cohort, case.consent) is None


async def test_concurrent_client_and_owner_continuation_retain_one_consent(delivery_case):
    case = delivery_case
    arrived = 0
    both_capturing = asyncio.Event()

    async def capture():
        nonlocal arrived
        arrived += 1
        if arrived == 2:
            both_capturing.set()
        await both_capturing.wait()
        return case.current

    client = _delivery(case, capture=capture)
    continuation = _delivery(case, capture=capture)
    first, second = await asyncio.wait_for(
        asyncio.gather(client.retain(case.signed), continuation.retain(case.signed)), timeout=30
    )
    assert first == second
    ((_, raw),) = _records(case)
    assert read_participation(raw).request == case.signed
    queue = CohortAdmissionQueue(case.intake)
    assert queue.evidence(case.cohort, case.consent) == (raw, case.evidence, case.metadata)
    assert queue.certificate(case.cohort, case.consent) is None


async def test_superseded_participation_finishes_its_original_missing_evidence(delivery_case):
    case = delivery_case
    case.archive.side_effect = OSError("archive unavailable")
    with pytest.raises(ParticipationUnavailable):
        await _delivery(case).retain(case.signed)
    case.archive.side_effect = None
    case.capture.reset_mock()
    case.models.require_payload.reset_mock()
    guard = Mock(side_effect=ValueError("newer issued replacement now selected"))
    receipt = await _delivery(case).retain(case.signed, before_retain=guard)
    assert receipt == case.intake.receipt(case.signed)
    guard.assert_not_called()
    case.capture.assert_not_called()
    case.models.require_payload.assert_not_called()
    assert CohortAdmissionQueue(case.intake).evidence(case.cohort, case.consent)


async def test_replacement_during_capture_prevents_stale_new_participation(delivery_case):
    case = delivery_case
    guard = Mock(side_effect=[None, ValueError("newer reservation issued during capture")])
    with pytest.raises(ValueError, match="newer reservation issued"):
        await _delivery(case).retain(
            case.signed, before_retain=guard, admission_lock=asyncio.Lock()
        )
    assert case.intake.receipt(case.signed) is None
    assert not _records(case)
    case.archive.assert_not_called()


async def test_issuance_lock_covers_only_native_retention(delivery_case, monkeypatch):
    case = delivery_case
    lock = asyncio.Lock()
    original = case.intake.retain

    async def capture():
        assert not lock.locked()
        return case.current

    async def archive(boundary):
        assert not lock.locked()
        return case.evidence, case.metadata

    def retain(*args, **kwargs):
        assert lock.locked()
        return original(*args, **kwargs)

    monkeypatch.setattr(case.intake, "retain", retain)
    await _delivery(case, capture=capture, archive=archive).retain(
        case.signed, before_retain=lambda: None, admission_lock=lock
    )
    assert not lock.locked()


@pytest.mark.parametrize("blocked_stage", ["payload", "review", "capture"])
async def test_server_delay_preserves_timely_request_for_unchanged_retry(
    delivery_case, monkeypatch, blocked_stage
):
    case = delivery_case
    if blocked_stage == "capture":
        case.capture.side_effect = TimeoutError("registration unavailable")
        message = "registration observation unavailable; retry unchanged"
    else:
        case.models.require_payload.side_effect = OSError(
            "direct model verification is incomplete"
            if blocked_stage == "payload"
            else "direct model awaits its bounded rights review"
        )
        message = "cohort intake unavailable; retry unchanged"
    with pytest.raises(ParticipationUnavailable, match=message):
        await _delivery(case).retain(case.signed)
    assert case.intake.receipt(case.signed) is None
    assert _records(case) == ()
    case.archive.assert_not_called()
    if blocked_stage != "capture":
        case.capture.assert_not_called()

    # Neither elapsed wall time nor the failed server operation creates a new
    # admission, expires the reservation or requires changed signed bytes.
    clock(monkeypatch, DEADLINE_MS + 2 * 24 * 60 * 60 * 1000)
    case.models.require_payload.side_effect = None
    case.capture.side_effect = None
    receipt = await _delivery(case).retain(case.signed)
    assert receipt["status"] == "pending_attestation"
    assert len(_records(case)) == 1
    assert case.models.admission_reservation.call_count == 1


async def test_late_reservation_does_not_gain_admission_from_continuation(delivery_case):
    case = delivery_case
    case.models.admission_reservation.return_value = reservation_for(
        case.signed, created_at=DEADLINE_MS
    )
    with pytest.raises(ValueError, match="does not authorize admission after the deadline"):
        await _delivery(case).retain(case.signed)
    assert case.intake.receipt(case.signed) is None
    assert _records(case) == ()
    case.archive.assert_not_called()
